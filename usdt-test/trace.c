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
  if(argc<3) {
    fprintf(stderr,
            "Missing arguments.\n\
             Usage: trace %s <hex-addr-to-rewrite> <prog.exe> <arg> <arg> ...\n",
            argv[0]
            );
    return 1;
  }
  if (sscanf(argv[1], "%lx", &addr) != 1) {
    fprintf(stderr, "Cannot read hexadecimal address to rewrite %s\n", argv[1]);
    return 1;
  };

  char *app_filename = argv[2];
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
    int i = 2;
    for (; i < argc; i++) argv[i-2] = argv[i];
    argv[i-2] = NULL;
    execv(app_filename, argv);
    fprintf(stderr, "error running exec\n");
    return 1;
  }

  int status = 0;
  wait(&status);
  if(!WIFSTOPPED(status)) {
    fprintf(stderr, "not stopped %d\n", status);
    return 1;
  }

  unsigned long data = ptrace(PTRACE_PEEKTEXT, cpid, addr, NULL);
  fprintf (stderr, "%lx\n", data);
  data = (data & ~0xff) | 0xe8;
  fprintf (stderr, "%lx\n", data);
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
