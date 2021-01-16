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
    pid_t pid;

    pid = fork();
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


void debug(void* addr, char* flag, const char* output_file_name, pid_t program_pid,
           char* program_name, int program_argc, char** program_argv){

    int wait_status;
    wait(&wait_status);

    struct user_regs_struct regs;
    struct user_regs_struct old_regs;
    FILE* fp = fopen(output_file_name, "w");

    int fd = fileno(fp);
//    long data = ptrace(PTRACE_PEEKTEXT, program_pid, (void *) addr, NULL);
//    //write int 3 to the address
//    unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
//    ptrace(PTRACE_POKETEXT, program_pid, (void *) (addr), (void *) (data_trap));
//
//
//
//    ptrace(PTRACE_CONT, program_pid, NULL, NULL);
//    wait(&wait_status);
//    //reached breakpoint
//    //check if the program did not stop because of the breakpoint but for a different reason
//
//    //remove the breakpoint by restoring the previous data
//    ptrace(PTRACE_GETREGS, program_pid, 0, &regs);
//    ptrace(PTRACE_POKETEXT, program_pid, (void *) addr, (void *) data);
//    regs.rip -= 1;
//    ptrace(PTRACE_SETREGS, program_pid, 0, &regs);
    int counter = 1;
    while(1) {

        ptrace(PTRACE_SYSCALL, program_pid, NULL, NULL);
        wait(&wait_status);

        ptrace(PTRACE_GETREGS, program_pid, 0, &regs);
        ptrace(PTRACE_GETREGS, program_pid, 0, &old_regs);
        if (regs.rax != 1){
            printf("iteration %d, rax is %lld\n", counter, regs.rax);
            counter++;
            ptrace(PTRACE_SYSCALL, program_pid, NULL, NULL);
            wait(&wait_status);

            continue;
        }
        printf("rdi before is %lld\n", regs.rdi);
        printf("rax is %lld\n", regs.rax);

        regs.rdi = fd;
        printf("rdi after is %lld\n", regs.rdi);
        printf("num of chars to print is %lld\n", regs.rdx);

        ptrace(PTRACE_SETREGS, program_pid, 0, &regs);
        puts("reached holder-code");


        if (*flag == 'c') {
            puts("mode == c");

            //before writing at all, right before writing to file
            ptrace(PTRACE_SYSCALL, program_pid, NULL, NULL);
            wait(&wait_status);
            puts("after write to file");

            //right after write to file
            //setting params for syswrite to screen with old regs
            ptrace(PTRACE_SETREGS, program_pid, 0, &old_regs);
            ptrace(PTRACE_SYSCALL, program_pid, NULL, NULL);
            wait(&wait_status);
            puts("before write to file");
            //right before write to screen
        }
        puts("after if");
        ptrace(PTRACE_SYSCALL, program_pid, NULL, NULL);
        wait(&wait_status);
        puts("after write to file");
        //right after syswrite to screen

        fclose(fp);
        puts("reached close file");
        ptrace(PTRACE_CONT, program_pid, 0, 0);
        wait(&wait_status);
        break;
    }
    if (WIFEXITED(wait_status)) {
        puts("sub program exited properly");
        return; //means child exited by exit()
    }
    else {
        puts("ERROR");
    }

}

int main(int argc, char** argv) {
    // Read arguments
    char* addr = argv[1];
//    char* addr = (char*)malloc(sizeof(char)*strlen(argv[1]));
//    strcpy(addr, argv[1]);
    char* flag = argv[2];
    char* output_file_name = argv[3];
    char* program_name = argv[4];

    pid_t program_pid;

    program_pid = run_target(program_name);
    debug(addr, flag, output_file_name, program_pid, program_name, argc-4, argv+4); // TODO add all arguments

    return 0;
}