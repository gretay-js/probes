#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/wait.h>

int main(int argc, char *argv[]) {
  char *app_filename = "./t.exe";
  size_t addr = 0x400078;
  pid_t cpid = fork();
  if(cpid==-1) {
    fprintf(stderr, "error doing fork\n");
    return 1;
  }
  if(cpid==0) {
    if(ptrace(PTRACE_TRACEME, 0, NULL, NULL)) {
      fprintf(stderr, "ptrace traceme error\n");
      return 1;
    }
    execl(app_filename, app_filename, NULL);
    fprintf(stderr, "error running exec\n");
    return 1;
  }

  int status = 0;
  wait(&status);
  if(!WIFSTOPPED(status)) {
    fprintf(stderr, "not stopped %d\n", status);
    return 1;
  }

  int data = ptrace(PTRACE_PEEKTEXT, cpid, addr, NULL);
  fprintf (stderr, "%x\n", data);
  data = (data & ~0xff) | 0xe8;
  fprintf (stderr, "%x\n", data);
  ptrace(PTRACE_POKETEXT, cpid, addr, data);

  if(ptrace(PTRACE_CONT, cpid, NULL, NULL)==-1) {
    fprintf(stderr, "could not continue, errno=%d\n", errno);
    return 1;
  }

  wait(&status);
  if(!WIFEXITED(status)) {
    fprintf(stderr, "child did not exit\n");

    int signum = WSTOPSIG(status);
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, cpid, NULL, &regs);
    printf ("signal: %d, eip: 0x%08llx\n", signum, regs.rip);
    return status;
  }
  return 0;
}
