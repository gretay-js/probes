#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/user.h>

int main(int argc, char *argv[]) {
  size_t addr = 0x400078;
  pid_t cpid = -1; // pid to attach ptrace to
  if(argc!=2) {
    fprintf(stderr, "Missing arguments\n");
    return 1;
  }
  if (sscanf(argv[1], "%d", &cpid) != 1) {
    fprintf(stderr, "Cannot read pid %s\n", argv[1]);
    return 1;
  };

  if(ptrace(PTRACE_ATTACH, cpid, NULL, NULL)) {
    fprintf(stderr, "ptrace attach error\n");
    return 1;
  }

  int status = 0;
  pid_t res = waitpid(cpid, &status, WUNTRACED);
  if ((res != cpid) || !(WIFSTOPPED(status)) ) {
    printf("Unexpected wait result res %d stat %x\n",res,status);
    exit(1);
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
    printf ("signal: %d, eip: 0x%08lx\n", signum, regs.rip);
    return status;
  }
  return 0;
}
