#include <linux/ptrace.h>
#include <linux/bpf.h>
#include "bpf_helpers.h"
#include "caml/mlvalues.h"

#ifndef printk
#define printk(fmt, ...) \
  do { \
    char ___fmt[] = fmt; \
    bpf_trace_printk(___fmt, sizeof(___fmt), ##__VA_ARGS__); \
  } while(0)
#endif

inline __attribute__((always_inline))
void *get_big(void *map, __u64 index) {
  return bpf_map_lookup_elem(map, &index);
}

inline __attribute__((always_inline))
void *get(void *map, int index) {
  return bpf_map_lookup_elem(map, &index);
}

inline __attribute__((always_inline))
int set(void *map, int index, void *value) {
  return bpf_map_update_elem(map, &index, value, BPF_EXIST);
}

#define MAX_NAME 100
#define MAX_SIZE 1024
#define MAX_ARGS 12
struct probe_info {
  char name[MAX_NAME];
  int num_args;
  int registers[MAX_ARGS];
};
enum type = { INTEGER, STRING, FLOAT, CUSTOM, HEADER };
struct __attribute__((packed)) result {
  __u64 time;
  int num_args;
  enum type type[MAX_ARGS];
  int arg_offset[MAX_ARGS];
  int data_used;
  char data[MAX_SIZE];
};

#define MAX_SINGLE 256
struct bpf_map_def SEC("maps") perf_event_array =
  { .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(__u32),
    .max_entries = 64,
  };

struct bpf_map_def SEC("maps") from_trace =
  { .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u64),
    .value_size = sizeof(struct probe_info),
    .max_entries = 100,
  };

struct bpf_map_def SEC("maps") scratch =
  { .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(struct result),
    .max_entries = 1,
  };

__attribute__((noinline))
int loop_body(int i, struct probe_info *arg_info,
              struct result *result, struct pt_regs * const ctx) {
  if(i >= arg_info->num_args) return 0;
  __u64 value;
  switch(arg_info->registers[i]) {
  case 0: value = ctx->rax; break;
  case 1: value = ctx->rdx; break;
  case 2: value = ctx->rcx; break;
  case 3: value = ctx->rbx; break;
  case 4: value = ctx->rsi; break;
  case 5: value = ctx->rdi; break;
  case 6: value = ctx->rbp; break;
  case 7: value = ctx->rsp; break;
  case 8: value = ctx->r8; break;
  case 9: value = ctx->r9; break;
  case 10: value = ctx->r10; break;
  case 11: value = ctx->r11; break;
  case 12: value = ctx->r12; break;
  case 13: value = ctx->r13; break;
  case 14: value = ctx->r14; break;
  case 15: value = ctx->r15; break;
  default:
    printk("unknown register\n");
    return 1;
  }
  if(result->data_used<0) {
    printk("data used somehow became negative\n");
    return 1;
  }
  // we need at least 8 bytes of space to record this value
  if(result->data_used>MAX_SIZE-8) {
    printk("out of space\n");
    return 1;
  }
  char *data = result->data + result->data_used;
  result->arg_offset[i] = result->data_used;
  if(Is_long(value)) {
    result->is_integer[i] = 1;
    *(__u64*)data = Long_val(value);
    result->data_used += 8;
  }
  else {
    header_t header;
    if(bpf_probe_read(&header, 8, (char*)(value - 8))) {
      printk("error reading header\n");
      return 1;
    }
    switch (Tag_hd(header)) {
    case String_tag: {
      result->type = String;
      int len = bpf_probe_read_str
        ((char*)data,
         (MAX_SIZE - result->data_used),
         (char*)value);
      if(len<0) {
        printk("error copying string: %d\n", len);
        return 1;
      }
      result->data_used += len;
    } break;
    case Double_tag:
      result->type = Float;
      int len = Double_wosize * 8;
      if(bpf_probe_read((char*)data, MAX_SIZE - len, (char*)(value - len))) {
        printk("error reading float\n");
        return 1;
      }
      break;
    case Custom_tag:
      int size = Wosize_hd(header);
      __u64 val = Val_hp(header);
      if (size = 1) then
      result->type = Integer;
      break;
    default:
      *(__u64*)data = value;
      result->data_used += 8;
    }
  }
  return 0;
}

SEC("handler")
int _handler(struct pt_regs *ctx) {
  struct probe_info *arg_info = get_big(&from_trace, ctx->rip);
  if(!arg_info) {
    printk("no argument info\n");
    return 1;
  }
  // CR rcummings: do something with the probe name
  printk("activated at probe \"%s\"\n", arg_info->name);

  struct result *result = get(&scratch, 0);
  if(!result) {
    printk("no scratch space\n");
    return 1;
  }
  result->time = bpf_ktime_get_ns();
  result->num_args = arg_info->num_args;
  result->data_used = 0;

  struct pt_regs pt_regs = *ctx;
#pragma clang loop unroll(full)
  for(int i=0; i<12; ++i) {
    if(loop_body(i, arg_info, result, &pt_regs)) return 1;
  }

  int result_size = sizeof(struct result) - MAX_SIZE + result->data_used;
  if(result_size<0) {
    printk("invalid result size\n");
    return 1;
  }
  if(result_size>MAX_SIZE) {
    printk("invalid result size\n");
    return 1;
  }
  int err = bpf_perf_event_output(ctx, &perf_event_array, BPF_F_CURRENT_CPU,
                                  result, result_size);
  if(err) {
    printk("perf event output error: %d\n", err);
    return 1;
  }
  return 0;
}

