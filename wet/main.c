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

long peek_text(pid_t program_pid, unsigned long addr){
    unsigned long data = ptrace(PTRACE_PEEKTEXT, program_pid, (void *) addr, NULL);
    if (data < 0){
        perror("ptrace poke text");
        exit(1);
    }
    return data;
}

unsigned long get_ret_address(pid_t program_pid, struct user_regs_struct* regs){

    get_regs(program_pid, regs);
    unsigned long data = ptrace(PTRACE_PEEKDATA, program_pid, regs->rsp, NULL);
    if (data < 0){
        perror("ptrace peek data");
        exit(1);
    }
    return data;
}

long set_trap_return_original_coding(unsigned long address, pid_t program_pid)
{
    long func_coding = peek_text(program_pid, address);
    unsigned long func_coding_trap = (func_coding & 0xFFFFFFFFFFFFFF00) | 0xCC;
    poke_text(program_pid, address, func_coding_trap); // place trap
    return func_coding;
}

void remove_trap_and_rewind_rip(pid_t program_pid, unsigned long address, unsigned long original_coding)
{
    struct user_regs_struct regs;
    get_regs(program_pid, &regs);
    regs.rip -= 1;
    set_regs(program_pid, &regs);

    poke_text(program_pid, address, original_coding);
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
    } else {
        // set output stream back to being screen
        regs->rdi = 1;
        set_regs(program_pid, regs);
    }

}

void debug(pid_t program_pid, int fd, bool copy, unsigned long bug_func_address)
{
    int wait_status;
    wait(&wait_status);

    struct user_regs_struct regs;
    unsigned long return_address, return_data_coding, bug_func_coding;
    bool debug_func_call_ongoing = true;


    while (!WIFEXITED(wait_status)) //looking for calls to the bug func
    {
        bug_func_coding = set_trap_return_original_coding(bug_func_address, program_pid);
        p_trace_cont_and_wait(&wait_status, program_pid);
        if (WIFEXITED(wait_status))
        {
            return;
        }
        remove_trap_and_rewind_rip(program_pid, bug_func_address, bug_func_coding);

        return_address = get_ret_address(program_pid, &regs);
        return_data_coding = set_trap_return_original_coding(return_address, program_pid);

        debug_func_call_ongoing = true;
        while (debug_func_call_ongoing) // looking for syscalls in a single call to bug func
        {
            p_trace_syscall_and_wait(&wait_status, program_pid);
            get_regs(program_pid, &regs);
            if(regs.rip == return_address + 1){ //this bug func call is over
                remove_trap_and_rewind_rip(program_pid, return_address, return_data_coding);
                debug_func_call_ongoing = false;
            }
            else if ((regs.orig_rax == 1) && (regs.rdi == 1))
            {
                holder_func(&wait_status, copy, fd, program_pid, &regs);
            }
            else
            {
                p_trace_syscall_and_wait(&wait_status, program_pid);
            }
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

    int fd = open(output_file_name, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (fd < 0){
        perror("open");
        exit(1);
    }

    pid_t program_pid = run_target(argv + 4);

    bool is_the_flag_c = *flag == 'c';
//    debug(addr, is_the_flag_c, program_pid, fd);
    debug(program_pid, fd, is_the_flag_c, addr);

    if (close(fd) < 0) {
        perror("close");
        exit(1);
    }
    return 0;
}

