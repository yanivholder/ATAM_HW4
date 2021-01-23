#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdbool.h>


pid_t run_target(char *const argv[]) {
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
    return -1;
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
void poke_text(pid_t program_pid, unsigned long addr, unsigned long data) {
    if (ptrace(PTRACE_POKETEXT, program_pid, (void *) addr, (void *) data) < 0){
        perror("ptrace poke text");
        exit(1);
    }
}

unsigned long peek_text(pid_t program_pid, unsigned long addr){
    unsigned long data = ptrace(PTRACE_PEEKTEXT, program_pid, (void *) addr, NULL);
    if (data < 0){
        perror("ptrace poke text");
        exit(1);
    }
    return data;
}

unsigned long peek_data(pid_t program_pid, unsigned long addr){
    unsigned long data = ptrace(PTRACE_PEEKDATA, program_pid, (void *) addr, NULL);
    if (data < 0){
        perror("ptrace poke text");
        exit(1);
    }
    return data;
}

// this func restores command, executes it and then restores the breakpoint
void breakpoint_remover(int* wait_status, pid_t program_pid, struct user_regs_struct* regs,
                        unsigned long addr, unsigned long data){

    unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    get_regs(program_pid, regs);
    poke_text(program_pid, addr, data);
    regs->rip -= 1;
    ptrace(PTRACE_SETREGS, program_pid, 0, &regs);
    p_trace_single_step_and_wait(wait_status, program_pid); //perform single step in order to place the brake point back on the command we fixed
    poke_text(program_pid, addr, data_trap);
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
void debug(void* addr, char* flag, const char* output_file_name, pid_t program_pid,
           const char* program_name, int program_argc, char** program_argv){


    int wait_status;
    wait(&wait_status);

    struct user_regs_struct regs;
    unsigned long return_data, data, return_data_trap, data_trap;

    //write int 3 to the address
    if(!WIFSTOPPED(wait_status)){
        return;
    }

    data = peek_text(program_pid, addr);
    data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    poke_text(program_pid, addr, data_trap);

    p_trace_syscall_and_wait(&wait_status, program_pid);

    get_regs(program_pid, &regs);
    if(regs.rip == return_address+1){
        // remove breakpoint
        poke_text(program_pid, return_address, return_data);
        regs.rip -= 1;
        set_regs(program_pid, &regs);
        return;
    }

    if ((regs.orig_rax == 1) && (regs.rdi == 1))
    {
        puts("got to syswrite to screen");
        holder_func(&wait_status, is_the_flag_c, fd, program_pid, &regs);
    }
    else
    {
//                puts("go to a non write syscall or write not to screen");
        p_trace_syscall_and_wait(&wait_status, program_pid);
    }

}

int main(int argc, char** argv) {
    // Read arguments
    char* addr = argv[1];
    char* flag = argv[2];
    char* output_file_name = argv[3];
    const char* program_name = argv[4];

    pid_t program_pid;

    program_pid = run_target(program_name);
    debug(addr, flag, output_file_name, program_pid, program_name, argc-4, argv+4); // TODO add all arguments

    return 0;
}