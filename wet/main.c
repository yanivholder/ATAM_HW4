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

int main(int argc, char** argv) {
    // Read arguments
    void* addr = argv[1];
    char* flag = argv[2];
    char* output_file_name = argv[3];
    char* program_name = argv[4];

    pid_t program_pid;

    program_pid = run_target(program_name); // TODO change to the right location in argv
    debug(addr, flag, output_file_name, program_pid, program_name, argc-4, argv+4); // TODO add all arguments

    return 0;
}

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

void debug(void* addr, char* flag, char* output_file_name, pid_t program_pid, char* program_name,
           int program_argc, char** program_argv)
{
    int wait_status;
    struct user_regs_struct regs;

    wait(&wait_status);

    long data = ptrace(PTRACE_PEEKTEXT, program_pid, addr, NULL);

    unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_CONT, program_pid, NULL, NULL);

    wait(&wait_status);
    ptrace(PTRACE_GETREGS, program_pid, 0, &regs);

    ptrace(PTRACE_POKETEXT, program_pid, adrr, (void*) data);

    FILE* fp;
    fp = fopen(output_file_name, (char*)'w');
    int fd = fileno(fp);

    regs.
    if (strcmp(flag, (char*)'c') == 0) {
        
    }

    regs.rip -= 1;
    ptrace(PTRACE_SETREGS, program_pid, 0, &regs);

    ptrace(PTRACE_CONT, program_pid, 0, 0);

    wait(&wait_status);
    if (WIFEXITED(wait_status)) {
        return;
    }
    else {
        printf("ERROR");
    }
}