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
           char* program_name, int program_argc, char** program_argv, FILE* fp, int fd){

    int wait_status;
    struct user_regs_struct regs;
    struct user_regs_struct old_regs;
    long return_data, data;
    unsigned long return_data_trap, data_trap;

    //write int 3 to the address
    data = ptrace(PTRACE_PEEKTEXT, program_pid, (void *) addr, NULL);
    data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, program_pid, (void *) (addr), (void *) (data_trap));
//    FILE* fp = fopen(output_file_name, "w");
// ----------------------------------------------passed from main
//    int fd = fileno(fp);


    while (1){
        p_trace_cont_and_wait(&wait_status, program_pid);
        if(!WIFSTOPPED(wait_status)){ //check if the program did not stop because of the breakpoint but for a different reason
            break;
        }
        restore_command_that_had_breakpoint_on_it(program_pid, &regs, addr, data);
        p_trace_single_step_and_wait(&wait_status, program_pid); //perform single step in order to place the brake point back on the command we fixed
        if(!WIFSTOPPED(wait_status)){
            break;
        }
        //write int 3 to the address
        ptrace(PTRACE_POKETEXT, program_pid, (void *) (addr), (void *) (data_trap));

        get_regs(program_pid, &regs);
        return_data = ptrace(PTRACE_PEEKTEXT, program_pid, (void *)(regs.rbp+8), NULL);
        //write int3 to the return address
        return_data_trap = (return_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, program_pid, (void *)(regs.rbp+8), (void *) (return_data_trap));

        while(1){ //find syscalls within the func
            p_trace_syscall_and_wait(&wait_status, program_pid);
            get_regs(program_pid, &regs);

            if (WIFSTOPPED(wait_status)){ //the program stopped because of int3 trap and not syscall
                //case - recursive call (rip == data)
                //TODO - find out if this could happen and if so, implement
                if (regs.rip == return_data) {
                    //we've reached the func's return, this call is over.
                    //remove breakpoint from return address
                    ptrace(PTRACE_POKETEXT, program_pid, (void *) regs.rip, (void *) return_data);
                    regs.rip -= 1;
                    ptrace(PTRACE_SETREGS, program_pid, 0, &regs);
                    break;
                }
            }
            if (regs.rax != 1) { //not sys write
                p_trace_syscall_and_wait(&wait_status, program_pid);
                continue; //search next syscall in func
            }
            get_regs(program_pid, &regs);
            regs.rdi = fd;
            ptrace(PTRACE_SETREGS, program_pid, 0, &regs);

            holder_func()
        }
    }
    fclose(fp);

    if (WIFEXITED(wait_status)) {
        return; //means child exited by exit()
    }
    else {
        printf("ERROR");
    }

}

static restore_command_that_had_breakpoint_on_it(pid_t program_pid, struct user_regs_struct* regs,
                                                void* addr, long data){
    ptrace(PTRACE_GETREGS, program_pid, 0, regs);
    ptrace(PTRACE_POKETEXT, program_pid, (void *) addr, (void *) data);
    regs.rip -= 1;
    ptrace(PTRACE_SETREGS, program_pid, 0, &regs);
}

static void p_trace_syscall_and_wait(int* wait_status, pid_t program_pid){
    if(ptrace(PTRACE_SYSCALL, program_pid, NULL, NULL) < 0){
        perror("ptrace");
        exit(1);
    }
    wait(wait_status);
}

static void p_trace_single_step_and_wait(int* wait_status, pid_t program_pid){
    if (ptrace(PTRACE_SINGLESTEP, program_pid, NULL, NULL) < 0){
        perror("ptrace");
        exit(1);
    }
    wait(wait_status);
}

static void p_trace_cont_and_wait(int* wait_status, pid_t program_pid){
    if (ptrace(PTRACE_CONT, program_pid, NULL, NULL) < 0){
        perror("ptrace");
        exit(1);
    }
    wait(wait_status);
}

static void get_regs(pid_t program_pidm struct user_regs_struct* regs){
    if (ptrace(PTRACE_GETREGS, program_pid, 0, regs) < 0){
        perror("ptrace");
        exit(1);
    }
}

static void holder_func(int* wait_status, FILE* fp, char* flag, pid_t program_pid, struct user_regs_struct* old_regs){
    if (*flag == 'c') {
        //before writing at all, right before writing to file
        ptrace(PTRACE_SYSCALL, program_pid, NULL, NULL);
        wait(&wait_status);
        //right after write to file
        //setting params for syswrite to screen with old regs
        ptrace(PTRACE_SETREGS, program_pid, 0, old_regs);
        ptrace(PTRACE_SYSCALL, program_pid, NULL, NULL);
        wait(&wait_status);
        //right before write to screen
    }
    ptrace(PTRACE_SYSCALL, program_pid, NULL, NULL);
    wait(&wait_status);
    fprintf(fp, "out test"); //TODO remove
    //right after syswrite to screen
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

    FILE* fp = fopen(output_file_name, "w");
    int fd = fileno(fp); // TODO - pass this to run_target and debugger

    program_pid = run_target(program_name);
    debug(addr, flag, output_file_name, program_pid, program_name, argc-4, argv+4, fp, fd); // TODO add all arguments

    return 0;
}
