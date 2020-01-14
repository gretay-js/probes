#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <signal.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/ioctl.h>

#include <linux/bpf.h>
#include <linux/perf_event.h>

#include "bpf_elf.h"
#include "bpf_syscall_helpers.h"
#include "perf_buffer.h"
#include "read_note.h"
#include "uid.h"

// outputs to /sys/kernel/debug/tracing/trace_pipe

#define LOG_BUF_SIZE 2000000
char bpf_log_buf[LOG_BUF_SIZE];

int read_file(char *filename, FILE **reader) {
  *reader = fopen(filename, "r");
  if(!*reader) {
    fprintf(stderr, "%s: No such file or directory\n", filename);
    return 1;
  }
  return 0;
}

int probe_offset(char *app_filename, size_t *probe_offset) {
  FILE *reader = NULL;
  if(read_file(app_filename, &reader)) {
    return 1;
  }
  *probe_offset = 0x10326;
  return 0;
}

int get_uprobe_event_type() {
  // found in /sys/bus/event_source/devices/uprobe/type
  return 7;
}

int get_perf_event(size_t offset, char *app_filename, int pid, bool retprobe) {
  // see /sys/bus/event_source/devices/uprobe/format/retprobe
  int retprobe_bit = 0;
  int config = retprobe?1<<retprobe_bit:0;
  struct perf_event_attr attr =
    { .type=get_uprobe_event_type(),
      .size=sizeof(struct perf_event_attr),
      .config=config,
      .sample_period=1,
      .wakeup_events=1,
      .uprobe_path=(__u64)((void*)app_filename),
      .probe_offset=offset
    };
  return syscall(__NR_perf_event_open, &attr, pid, -1, -1, PERF_FLAG_FD_CLOEXEC);
}

#define MAX_SIZE 1024
#define MAX_ARGS 12
struct __attribute__((packed)) result {
  __u64 time;
  int num_args;
  char is_string[MAX_ARGS];
  char is_integer[MAX_ARGS];
  int arg_offset[MAX_ARGS];
  int data_used;
  char data[MAX_SIZE];
};

int context;

void callback(void *ctx, int cpu, void *data, __u32 size) {
  struct result *result = data;
  int context = *(int*)ctx;
  printf("context=%d, cpu=%d, time=%llu\n", context, cpu, result->time);
  for(int i=0; i<result->num_args; ++i) {
    char *value = result->data + result->arg_offset[i];
    if(result->is_integer[i]) {
      printf("integer: %llu\n", *(__u64*)value);
    }
    else if(result->is_string[i]) {
      printf("string: %s\n", value);
    }
    else {
      printf("other value at address: %llu\n", *(__u64*)value);
    }
  }
}

int get_map_fds(size_t map_count, struct bpf_map *maps,
                int *from_trace_fd, int *perf_event_array_fd) {
  struct bpf_map *from_trace = NULL, *perf_event_array = NULL;
  for(size_t i = 0; i<map_count; ++i) {
    if(!strcmp("from_trace", maps[i].name)) {
      from_trace = &maps[i];
    }
    if(!strcmp("perf_event_array", maps[i].name)) {
      perf_event_array = &maps[i];
    }
  }
  if(!perf_event_array) {
    fprintf(stderr, "could not find map 'perf_event_array'\n");
    return 1;
  }
  if(!from_trace) {
    fprintf(stderr, "could not find map 'from_trace'\n");
    return 1;
  }
  *from_trace_fd = from_trace->fd;
  *perf_event_array_fd = perf_event_array->fd;
  return 0;
}

struct probe_info {
  char name[100];
  int num_args;
  int registers[12];
};

int before_running(size_t map_count, struct bpf_map *maps, struct perf_buffer **pb,
                   struct note_result *note_result) {
  int from_trace_fd = 0, perf_event_array_fd = 0;
  if(get_map_fds(map_count, maps, &from_trace_fd, &perf_event_array_fd)) {
    fprintf(stderr, "error getting map fds\n");
    return 1;
  }
  char *register_names[] =
    { "%rax",
      "%rdx",
      "%rcx",
      "%rbx",
      "rsi",
      "%rdi",
      "%rbp",
      "%rsp",
      "%r8",
      "%r9",
      "%r10",
      "%r11",
      "%r12",
      "%r13",
      "%r14",
      "%r15",
    };

  context = 99;
  struct perf_buffer_opts opts =
    { .sample_cb = callback,
      .ctx = &context,
    };
  *pb = perf_buffer_create(perf_event_array_fd, 8, &opts);
  if(!*pb) {
    fprintf(stderr, "error creating perf buffer\n");
    return 1;
  }

  for(size_t note_index = 0; note_index < note_result->num_probes; ++note_index) {
    struct probe_note *note = note_result->probe_notes[note_index];
    if(note->num_args>12) {
      fprintf(stderr, "too many args\n");
      return 1;
    }
    struct probe_info probe_info =
      { .num_args = note->num_args,
      };
    strncpy(probe_info.name, note->name, 100);
    for(int j=0; j<probe_info.num_args; ++j) {
      for(int i=0; i<16; ++i) {
        if(!strcmp(note->args[j].reg, register_names[i])) {
          probe_info.registers[j] = i;
          break;
        }
      }
    }
    __u64 key = note->offset;
    int err = bpf_map_update_elem(from_trace_fd, &key, &probe_info, BPF_NOEXIST);
    if(err) {
      fprintf(stderr, "error trying to update map 'from_trace'\n");
      return 1;
    }
  }
  return 0;
}

int during_running(struct perf_buffer *pb) {
  for(int i=0; i<2; ++i) {
    if(perf_buffer_poll(pb, 50)<0) {
      fprintf(stderr, "error in poll\n");
      perf_buffer_free(pb);
      return 1;
    }
  }
  perf_buffer_free(pb);
  return 0;
}

int after_running(size_t map_count, struct bpf_map *maps) {
  return 0;
}

int modify_semaphore(pid_t pid, int delta, size_t addr) {
  __u16 data = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
  ptrace(PTRACE_POKETEXT, pid, addr, data+delta);
  return 0;
}

int main(int argc, char *argv[]) {
  uid_init ();
  if(argc!=2) {
    fprintf(stderr, "usage: %s app\n", argv[0]);
    return 1;
  }
  char *program_name = argv[0];
  char *app_filename = argv[1];

  struct bpf_elf_result bpf_elf_result;
  struct bpf_elf_params bpf_elf_params =
    { .bpf_filename = "handler.o",
      .bpf_section_name = "handler",
      .map_section_name = "maps",
    };
  if(parse_bpf(&bpf_elf_params, &bpf_elf_result)) {
    fprintf(stderr, "error parsing bpf elf\n");
    return 1;
  }
  // apparently there is code that checks for the license string to be "GPL"
  int bpf_fd = bpf_prog_load(BPF_PROG_TYPE_KPROBE, bpf_elf_result.insns,
                             bpf_elf_result.insn_count, "GPL",
                             bpf_log_buf, LOG_BUF_SIZE);

  free(bpf_elf_result.insns);
  if(bpf_fd == -1) {
    fprintf(stderr, "%s: failed to load eBPF code: errno=%d\n", program_name, errno);
    fprintf(stderr, "%s\n", bpf_log_buf);
    goto free_maps_and_error;
  }

  struct note_result note_result;
  if(read_notes(app_filename, &note_result)) {
    fprintf(stderr, "could not parse notes\n");
    goto free_notes_and_error;
  }
  if(note_result.num_probes<1) {
    fprintf(stderr, "no USDT probe found\n");
    goto free_notes_and_error;
  }

  struct perf_buffer *pb = NULL;
  if(before_running(bpf_elf_result.map_count, bpf_elf_result.maps, &pb, &note_result)) {
    fprintf(stderr, "error before running\n");
    goto signal_and_error;
  }

  /* if (setuid(getuid()) < 0) {
   *   fprintf(stderr, "error setuid\n");
   *   goto signal_and_error;
   * } */

  pid_t cpid = fork();
  if(cpid==-1) {
    fprintf(stderr, "error doing fork\n");
    goto free_notes_and_error;
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
    goto signal_and_error;
  }


  for(int i = 0; i < note_result.num_probes; ++i) {
    struct probe_note *note = note_result.probe_notes[i];
    //printf("probe %d: \"%s\"\n", i, note->name);
    size_t offset = note->offset - 0x400000;

    if(modify_semaphore(cpid, 1, note->semaphore)) {
      fprintf(stderr, "error modifying semaphore\n");
      goto signal_and_error;
    }

    // CR rcummings: this fails without root
    int perf_event_fd = get_perf_event(offset, app_filename, cpid, false);
    if(perf_event_fd==-1) {
      fprintf(stderr, "could not get uprobe perf event: errno=%d\n", errno);
      goto signal_and_error;
    }
    if(ioctl(perf_event_fd, PERF_EVENT_IOC_SET_BPF, bpf_fd)==-1) {
      fprintf(stderr, "could not attach bpf to uprobe: errno=%d\n", errno);
      close(perf_event_fd);
      goto signal_and_error;
    }

    if(ioctl(perf_event_fd, PERF_EVENT_IOC_ENABLE, 0)==-1) {
      fprintf(stderr, "could not enable perf event: errno=%d\n", errno);
      close(perf_event_fd);
      goto signal_and_error;
    }
  }

  if(ptrace(PTRACE_CONT, cpid, NULL, NULL)==-1) {
    fprintf(stderr, "could not continue, errno=%d\n", errno);
    goto signal_and_error;
  }

  if(during_running(pb)) {
    fprintf(stderr, "error during running\n");
    goto signal_and_error;
  }

  wait(&status);
  if(!WIFEXITED(status)) {
    fprintf(stderr, "child did not exit\n");
    goto signal_and_error;
  }

  if(after_running(bpf_elf_result.map_count, bpf_elf_result.maps)) {
    goto free_notes_and_error;
  }
  // CR rcummings: free notes
  free_maps(&bpf_elf_result);
  return 0;
 signal_and_error:
  wait(NULL);
 free_notes_and_error:
  // CR rcummings: free notes
 free_maps_and_error:
  free_maps(&bpf_elf_result);
  return 1;
}
