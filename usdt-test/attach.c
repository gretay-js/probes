#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/wait.h>


int main(int argc, char *argv[]) {
  unsigned long addr;
  pid_t cpid = -1; // pid to attach ptrace to
  if(argc!=3) {
    fprintf(stderr,
            "Missing arguments.\n\
             Usage: attach %s <pid> <hex-addr-to-rewrite>\n",
            argv[0]
            );
    return 1;
  }
  if (sscanf(argv[1], "%d", &cpid) != 1) {
    fprintf(stderr, "Cannot read pid %s\n", argv[1]);
    return 1;
  };

  if (sscanf(argv[2], "%lx", &addr) != 1) {
    fprintf(stderr, "Cannot read hexadecimal address to rewrite %s\n", argv[1]);
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

  fprintf(stderr, "Modifying address %lx in running process %d\n", addr, cpid);
  unsigned int data = ptrace(PTRACE_PEEKTEXT, cpid, addr, NULL);
  fprintf (stderr, "before: %x\n", data);
  if ((data & 0xff) != 0x3d) {
    fprintf(stderr, "Unexpected instruction! %x\n", (data & 0xff));
    return 1;
  }
  data = (data & ~0xff) | 0xe8;
  fprintf (stderr, "after:  %x\n", data);
  ptrace(PTRACE_POKETEXT, cpid, addr, data);

  if(ptrace(PTRACE_CONT, cpid, NULL, NULL)==-1) {
    fprintf(stderr, "could not continue, errno=%d\n", errno);
    return 1;
  }

  wait(&status);
  if(!WIFEXITED(status)) {
    int signum = WSTOPSIG(status);
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, cpid, NULL, &regs);
    printf ("signal: %d, eip: 0x%08llx\n", signum, regs.rip);
    return status;
  }
  else {
    fprintf(stderr, "child exited\n");
  }
  return 0;
}
