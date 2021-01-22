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
            perror("ptrace (trace me)");
            exit(1);
        }
        execl(program_name, program_name, NULL); // Why two times programe_name??
    } else {
        // fork error
        perror("fork");
        exit(1);
    }
}

void p_trace_cont_and_wait(int* wait_status, pid_t program_pid){
    if (ptrace(PTRACE_CONT, program_pid, NULL, NULL) < 0){
        perror("ptrace (cont)");
        exit(1);
    }
    wait(wait_status);
}


void debug(void* addr, char* flag, const char* output_file_name, pid_t program_pid,
           const char* program_name, int program_argc, char** program_argv){


    int wait_status;
    if (ptrace(PTRACE_CONT, program_pid, NULL, NULL) < 0){
        perror("ptrace (cont)");
        exit(1);
    }
    wait(&wait_status);

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