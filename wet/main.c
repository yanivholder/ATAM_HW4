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
#include <sys/syscall.h>
#include <fcntl.h>
#include <stdbool.h>




pid_t run_target(char** argv) {
    pid_t pid;

    pid = fork();
    if (pid > 0) {
        return pid;
    } else if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace (trace me)");
            exit(1);
        }
        if (execv(argv[0], argv) < 0) {
            perror("execv");
            exit(1);
        }
    } else {
        // fork error
        perror("fork");
        exit(1);
    }
}

void restore_command_that_had_breakpoint_on_it(pid_t program_pid, struct user_regs_struct* regs,
                                               unsigned long addr, unsigned long data){
    ptrace(PTRACE_GETREGS, program_pid, 0, regs);
    ptrace(PTRACE_POKETEXT, program_pid, (void *) addr, (void *) data);
    regs->rip -= 1;
    ptrace(PTRACE_SETREGS, program_pid, 0, &regs);
}

void p_trace_syscall_and_wait(int* wait_status, pid_t program_pid){
    if(ptrace(PTRACE_SYSCALL, program_pid, NULL, NULL) < 0){
        perror("ptrace syscall");
        exit(1);
    }
    wait(wait_status);
}

void p_trace_single_step_and_wait(int* wait_status, pid_t program_pid){
    if (ptrace(PTRACE_SINGLESTEP, program_pid, NULL, NULL) < 0){
        perror("ptrace single step");
        exit(1);
    }
    wait(wait_status);
}

void p_trace_cont_and_wait(int* wait_status, pid_t program_pid){
    if (ptrace(PTRACE_CONT, program_pid, NULL, NULL) < 0){
        perror("ptrace cont");
        exit(1);
    }
    wait(wait_status);
}

void get_regs(pid_t program_pid, struct user_regs_struct* regs){
    if (ptrace(PTRACE_GETREGS, program_pid, 0, regs) < 0){
        perror("ptrace get regs");
        exit(1);
    }
}

void set_regs(pid_t program_pid, struct user_regs_struct* regs){
    if (ptrace(PTRACE_SETREGS, program_pid, 0, regs) < 0){
        perror("ptrace set regs");
        exit(1);
    }
}

void holder_func(int* wait_status, bool copy, int fd, pid_t program_pid,
                 struct user_regs_struct* regs) {

    if(write(fd, "PRF:: ", 6) < 0) {
        perror("write");
        exit(1);
    }
    // Changing the output fd to the file
    regs->rdi = fd;
    set_regs(program_pid, regs);
    // Make the actual writing to file
    p_trace_syscall_and_wait(wait_status, program_pid);

    // If the program should also print to the screen
    if (copy) {
        // Getting back to the stage before the current func
        get_regs(program_pid, regs);
        regs->rip -= 2;
        regs->rdi = 1;
        regs->rax = 1;
        set_regs(program_pid, regs);
        // First, entering the kernel for the write syscall
        p_trace_syscall_and_wait(wait_status, program_pid);
        // Now actually writing
        p_trace_syscall_and_wait(wait_status, program_pid);
    }
    get_regs(program_pid, regs);
}

void debug(unsigned long addr, char* flag, pid_t program_pid, int fd){

    int wait_status;
    wait(&wait_status);

    struct user_regs_struct regs;
    struct user_regs_struct old_regs;
    unsigned long return_data, data;
    unsigned long return_data_trap, data_trap;

    //write int 3 to the address
    data = ptrace(PTRACE_PEEKTEXT, program_pid, (void *) addr, NULL);
    data_trap = (data & 0xFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, program_pid, (void *) (addr), (void *) (data_trap));
//    FILE* fp = fopen(output_file_name, "w");
// ----------------------------------------------passed from main
//    int fd = fileno(fp);

    if(!WIFSTOPPED(wait_status)){
        int x;
    }
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
        return_data_trap = (return_data & 0xFFFFFF00) | 0xCC;
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
            puts("before holder func");
            holder_func(&wait_status, flag, program_pid, &old_regs);
        }
    }
    if (WIFEXITED(wait_status)) {
        return; //means child exited by exit()
    }
    else {
        printf("ERROR");
    }

}

int main(int argc, char** argv) {
    // Read arguments
    unsigned long addr = strtoul(argv[1], NULL, 16);
    char* flag = argv[2];
    char* output_file_name = argv[3];

    pid_t program_pid;

    int fd = open(output_file_name, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (fd < 0){
        perror("open");
        exit(1);
    }

    program_pid = run_target(argv + 4);
    debug(addr, flag, program_pid, fd);

    if (close(fd) < 0) {
        perror("close");
        exit(1);
    }
    return 0;
}
