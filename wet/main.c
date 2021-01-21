#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <syscall.h>


pid_t run_target(const char* program_name) {

    pid_t pid = fork();
    if (pid > 0) {
        return pid;
    } else if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace");
            exit(1);
        }
        execl(program_name, program_name, NULL); // Why two times programe_name??
    } else {
        // fork error
        perror("fork");
        exit(1);
    }
}


void debug(void* char_addr, char* flag, const char* output_file_name, pid_t program_pid,
            char* program_name, int program_argc, char** program_argv){

    int wait_status;
    wait(&wait_status);
    struct user_regs_struct regs;
	struct user_regs_struct old_regs;
	FILE* fp = fopen(output_file_name, "w");
	unsigned long addr = (unsigned long)strtol(char_addr, NULL, 16);

    int fd = fileno(fp);
    unsigned long data = ptrace(PTRACE_PEEKTEXT, program_pid, (void *) addr, NULL);
    //write int 3 to the address
//    unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    unsigned long data_trap = (data & 0xFFFFFF00) | 0xCC; //this is a 32 bit system!

    ptrace(PTRACE_POKETEXT, program_pid, (void *) (addr), (void *) (data_trap));

    unsigned long return_data;
    unsigned long return_data_trap;
    printf("func address in char is %s\n", char_addr);
    printf("func address in int is 0x%llx\n", addr);


    while (1){ //debugged program has not exited, iterating breakpints
        //let the child run with the breakpoint and wait for it to reach it
        puts("reached first while");

        long res = ptrace(PTRACE_CONT, program_pid, NULL, NULL);
        if(res < 0){
            puts("ptrace did not get to the breakpoint");
            perror("ptrace");
            return;
        }
//----------------tets code------
//        wait(&wait_status);
//        while (WIFSTOPPED(wait_status) && regs.rip != addr){
//            ptrace(PTRACE_SINGLESTEP, program_pid, NULL, NULL);
//            wait(&wait_status);
//            ptrace(PTRACE_GETREGS, program_pid, 0, &regs);
//
//            printf("curr address is 0x%llx\n", regs.rip);
//
//        }
//--------------------------------
        // reached breakpoint
        // check if the program did not stop because of the breakpoint but for a different reason
        if(!WIFSTOPPED(wait_status)){
            puts("WIFSTOPPED poped me out");
            break;
        }
        puts("on beginning of func");
        ptrace(PTRACE_GETREGS, program_pid, 0, &regs);
        printf("rip is 0x%llx\n", regs.rip);

        //remove the breakpoint by restoring the previous data
        ptrace(PTRACE_POKETEXT, program_pid, (void *) addr, (void *) data);
        regs.rip -= 1;
        ptrace(PTRACE_SETREGS, program_pid, 0, &regs);

        //perform single step in order to place the brake point back on the command we fixed
        if (ptrace(PTRACE_SINGLESTEP, program_pid, NULL, NULL) < 0){
            puts("failed at single step");
            perror("ptrace");
            return;
        }
//        ptrace(PTRACE_SINGLESTEP, program_pid, NULL, NULL);
        wait(&wait_status);
//        if(!WIFSTOPPED(wait_status)){
//            puts("WIFSTOPPED poped me out");
//            break;
//        }
        //write int 3 to the address
        //no need to use rip-1 because it's a fixed (constant) address - only one breakpoint per program
        //data_trap is set because there's only one, no need to calc again
        ptrace(PTRACE_POKETEXT, program_pid, (void *) (addr), (void *) (data_trap));
        //now we are in the selected function code (2nd command), with breakpoint set for next time

        //we will add a breakpoint to the func's return address so we'll know when to stop looking for sys-write
        //TODO - (make sure works) add breakpoint to the return address of this frame using %rbp
        ptrace(PTRACE_GETREGS, program_pid, 0, &regs);
        //get the return address from %rbp+8 (%rbp points to caller %rbp, and above that is ret val)
        return_data = ptrace(PTRACE_PEEKTEXT, program_pid, (void *)(regs.rbp+8), NULL);
        //write int3 to the return address
        return_data_trap = (return_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, program_pid, (void *)(regs.rbp+8), (void *) (return_data_trap));
        //we are all set to start iterating the func's syscall in pursuit of sys-write

        while(1){ //find syscalls within the func
            puts("reached second while");
            ptrace(PTRACE_SYSCALL, program_pid, NULL, NULL);
            wait(&wait_status);
            ptrace(PTRACE_GETREGS, program_pid, 0, &regs);

            if (WIFSTOPPED(wait_status) && regs.rip == return_data){ //the program stopped because of int3 trap and not syscall
                //we've reached the func's return, this call is over.
                //remove breakpoint from return address
                ptrace(PTRACE_POKETEXT, program_pid, (void *) regs.rip, (void *) return_data);
                regs.rip -= 1;
                ptrace(PTRACE_SETREGS, program_pid, 0, &regs);
                puts("returning from func");
                break;
            }
            //if we got here, that means we are right before a syscall
            if (regs.orig_rax != 1) { //not sys write TODO - check if we need orig or not
                //perform the syscall
                ptrace(PTRACE_SYSCALL, program_pid, NULL, NULL);
                wait(&wait_status);
                //we are after the irrelevant syscall
                puts("reached syscall in func that is not sys write");
                continue; //search next syscall in func
            }
            //if we got here that means we are right before a sys write!!!


            puts("reached holder-code");
            printf("rax is %lld (supposed to be 1)\n", regs.rax);
            printf("the string to print is %s and it's length is %lld", regs.rsi, regs.rdx);
            ptrace(PTRACE_CONT, program_pid, NULL, NULL);
//            ptrace(PTRACE_GETREGS, program_pid, 0, &old_regs);
//            regs.rdi = fd;
//            ptrace(PTRACE_SETREGS, program_pid, 0, &regs);
//            if (strcmp(flag, (char*)'c') == 0) {
//                //before writing at all, right before writing to file
//                ptrace(PTRACE_SYSCALL, program_pid, NULL, NULL);
//                wait(&wait_status);
//                //right after write to file
//                //setting params for syswrite to screen with old regs
//                ptrace(PTRACE_SETREGS, program_pid, 0, &old_regs);
//                ptrace(PTRACE_SYSCALL, program_pid, NULL, NULL);
//                wait(&wait_status);
//                //right before write to screen
//            }
//            ptrace(PTRACE_SYSCALL, program_pid, NULL, NULL);
//            wait(&wait_status);
//            fprintf(fp, "out test"); //TODO remove
//            //right after syswrite to screen


        }
    }
    fclose(fp);
    puts("reached close file");


    if (WIFEXITED(wait_status)) {
        return; //means child exited by exit()
    }
    else {
        printf("ERROR");
    }

}

int main(int argc, char** argv) {
    // Read arguments
    char* addr = argv[1];
    char* flag = argv[2];
    char* output_file_name = argv[3];
//    char* program_name = argv[4]; //TODO - fix this
    char* program_name = "/home/student/Desktop/ATAM_HW4/wet/debugee";

    pid_t program_pid;

    program_pid = run_target(program_name);
    debug(addr, flag, output_file_name, program_pid, program_name, argc-4, argv+4); // TODO add all arguments

    return 0;
}