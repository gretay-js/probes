#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "read_note.h"


#define CMP_OPCODE 0x3d
#define CALL_OPCODE 0xe8

int modify_probe(pid_t cpid, unsigned long addr, bool enable) {
  unsigned long data;
  unsigned long cur;
  unsigned long new;
  errno = 0;
  addr = addr - 5;
  data = ptrace(PTRACE_PEEKTEXT, cpid, addr, NULL);
  if (errno != 0) {
    fprintf (stderr, "Modify probe: read from %lx failed\n", addr);
    return 1;
  }
  if (enable) {
    cur = CMP_OPCODE; new = CALL_OPCODE;
  } else {
    cur = CALL_OPCODE; new = CMP_OPCODE;
  }
  fprintf (stderr, "cur at %lx: %lx\n", addr, data);
  if ((data & 0xff) != cur) {
    fprintf(stderr, "Warning: unexpected instruction at %lx! %lx instead of %lx\n",
            addr, (data & 0xff), cur);
  }
  data = (data & ~0xff) | new;
  fprintf (stderr, "new at %lx: %lx\n", addr, data);
  return ptrace(PTRACE_POKETEXT, cpid, addr, data);
}

int modify_semaphore(pid_t cpid, int delta, size_t addr) {
  errno = 0;
  unsigned long data = ptrace(PTRACE_PEEKDATA, cpid, addr, NULL);
  if (errno != 0) {
    fprintf (stderr, "cur at %lx: %lx\n", addr, data);
    return 1;
  }
  data = data+delta;
  fprintf (stderr, "new at %lx: %lx\n", addr, data);
  return ptrace(PTRACE_POKEDATA, cpid, addr, data);
}

int main(int argc, char *argv[]) {
  int stay_attached = 0;
  unsigned long addr = 0;
  if(argc<3) {
    fprintf(stderr,
"Missing arguments.\n\
Usage: trace %s <addr> <prog.exe> <arg> <arg> ...\n\n\
If <addr> is 0, read probe descriptions from elf notes,\n       \
enable all probes and update their semaphores.\n\
Othewise, rewrite instruction at <addr>, without reading elf notes.\n\
It's possible to specify <addr> as hex, for example: 0x423512.\n",
            argv[0]
            );
    return 1;
  }
  if (sscanf(argv[1], "%lx", &addr) != 1) {
    fprintf(stderr, "Cannot read hexadecimal address to rewrite %s\n", argv[1]);
    return 1;
  };

  char *app_filename = argv[2];

  struct note_result note_result;
  if (addr == 0) {
    if(read_notes(app_filename, &note_result)) {
      fprintf(stderr, "could not parse probe notes\n");
      return 1;
    }

    if(note_result.num_probes<1) {
      fprintf(stderr, "probe notes not found\n");
      return 1;
    }
  }

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
    goto signal_and_error;
  }


  if (stay_attached) {
      if (ptrace(PTRACE_SETOPTIONS, cpid, 0, PTRACE_O_EXITKILL)) {
        fprintf(stderr, "cannot jail %d\n", status);
      }
  }

  int enable = true;
  if (addr == 0) {
    fprintf(stderr, "Enabling all probes specified in elf notes\n");
    for(int i = 0; i < note_result.num_probes; ++i) {
      struct probe_note *note = note_result.probe_notes[i];
      unsigned long addr = note->offset;
      fprintf(stderr, "probe %d: \"%s\" at %lx with semaphore at %lx\n",
              i, note->name, addr, note->semaphore);

      if (modify_probe(cpid, addr, enable)) {
        fprintf(stderr, "could not rewrite probe at address %lx to %s\n",
                addr, (enable?"enabled":"disabled"));
        goto signal_and_error;
      }

      if (modify_semaphore(cpid, 1, note->semaphore)) {
        fprintf(stderr, "error modifying semaphore\n");
        goto signal_and_error;
      }
    }
  } else {
    if (modify_probe(cpid, addr, enable)) {
      fprintf(stderr, "could not rewrite probe at address %lx to %s\n",
              addr, (enable?"enabled":"disabled"));
      goto signal_and_error;
    }
  }

  if (stay_attached) {
    errno = 0;
    if(ptrace(PTRACE_CONT, cpid, NULL, NULL)==-1) {
      fprintf(stderr, "could not continue, errno=%d\n", errno);
      goto signal_and_error;
    }

    wait(&status);
    if(!WIFEXITED(status)) {
      fprintf(stderr, "child did not exit\n");

      int signum = WSTOPSIG(status);
      struct user_regs_struct regs;
      ptrace(PTRACE_GETREGS, cpid, NULL, &regs);
      fprintf (stderr, "signal: %d, eip: 0x%08llx\n", signum, regs.rip);
      return status;
    }
  } else {
    if (ptrace(PTRACE_DETACH, cpid, NULL, NULL)) {
      fprintf(stderr, "could not detach, errno=%d\n", errno);
    }
  }

  return 0;
  signal_and_error:
  ptrace(PTRACE_KILL, cpid, NULL, NULL);
  wait(NULL);
  return 1;
}
