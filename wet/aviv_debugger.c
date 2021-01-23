#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <stdarg.h>
#include <signal.h>
#include <sys/reg.h>
#include <errno.h>

/* Function declarations */
void traceSyscalls(pid_t child_pid, char **argv, unsigned long ret_addr, long ret_data);
pid_t run_target(const char *programname, char **debugged_argv);
void run_debugger(pid_t child_pid, char **argv);
void removeBreakPoint(unsigned long func_addr, pid_t child_pid, long func_data);
long setBreakPoint(unsigned long func_addr, pid_t child_pid);
long getReturnAddress(pid_t child_pid);
void print_prefix(int fd);


int fd = 0;
int main(int argc, char **argv)
{
    fd = open(argv[3], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    pid_t child_pid;
    child_pid = run_target(argv[4], argv + 4); // maybe , argv+5
    run_debugger(child_pid, argv);
    close(fd);
    return 0;
}

pid_t run_target(const char *programname, char **debugged_argv)
{
    pid_t pid;
    pid = fork();
    if (pid > 0)
    {
        return pid;
    }
    else if (pid == 0)
    {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
        {
            perror("ptrace");
            exit(1);
        }
        execv(programname, debugged_argv);
    }
    else
    {
        perror("fork");
        exit(1);
    }
}

void run_debugger(pid_t child_pid, char **argv)
{
    long ret_addr = 0;
    int wait_status;

    unsigned long func_addr = strtoull(argv[1], NULL, 16); // args in argv are passed as char*, attempt to convert
    // Wait for child to stop on its first instruction
    wait(&wait_status);
    long func_data = 0;
    
    while (!WIFEXITED(wait_status))
    {
        // Set breakpoint at beggining of func
        func_data = setBreakPoint(func_addr, child_pid);
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        wait(&wait_status);
        //printf("func_data: 0x%x\n",func_data);
        if (WIFEXITED(wait_status))
        {
            return;
        }
        // Now you are the beggining, remove breakpoint
        removeBreakPoint(func_addr,child_pid,func_data);

        // Put breakpoint in the end of the func
        long ret_addr = getReturnAddress(child_pid);
        //printf("ret_addr: 0x%x\n",ret_addr);
        long ret_data = setBreakPoint(ret_addr,child_pid);
        //printf("ret_data: 0x%x\n",ret_data);
        traceSyscalls(child_pid, argv,ret_addr,ret_data);
    }
}





long getReturnAddress(pid_t child_pid){
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
    return ptrace(PTRACE_PEEKDATA, child_pid, regs.rsp, NULL);
}


long setBreakPoint(unsigned long func_addr, pid_t child_pid)
{
    long func_data = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)func_addr, NULL);
    unsigned long func_data_trap = (func_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void *)func_addr, (void *)func_data_trap);
    return func_data;
}

//Use this only if you are now landed on breakpoint
void removeBreakPoint(unsigned long func_addr, pid_t child_pid, long func_data)
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
    regs.rip -= 1;
    ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
    ptrace(PTRACE_POKETEXT, child_pid, (void *)func_addr, (void *)func_data);
}



void traceSyscalls(pid_t child_pid, char **argv, unsigned long ret_addr, long ret_data)
{
    struct user_regs_struct regs;
    int wait_status;
    while (true)
    {
        ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
        wait(&wait_status);

        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        if(regs.rip == ret_addr+1){
            removeBreakPoint(ret_addr,child_pid,ret_data);
            return;
        }

        if ((regs.orig_rax == 1) && (regs.rdi == 1))
        {
            regs.rdi = fd;
            ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
            print_prefix(fd);
            ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
            wait(&wait_status);
            ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
			// if c flag, do the syscall again but with stdout fd:
            if (argv[2][0] == 'c')
            {
                ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
                regs.rip -= 2;
                regs.rax = 1;
                regs.rdi = 1;
                ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
                ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
                wait(&wait_status);
                ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
                wait(&wait_status);
            }
        }
        else
        {
            ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
            wait(&wait_status);
        }
    }
}


void print_prefix(int fd){
    const char prefix[] = "PRF:: ";
    write(fd, prefix, sizeof(prefix)-1);
}







