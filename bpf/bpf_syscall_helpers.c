#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include "bpf_syscall_helpers.h"
#include "uid.h"

long syscall_bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
  uid_up ();
  long res = syscall(SYS_bpf, cmd, attr, size);
  uid_down ();
  return res;
}

int bpf_prog_load (enum bpf_prog_type type, const struct bpf_insn *insns,
                   int insn_cnt, const char *license,
                   char *bpf_log_buf, size_t log_buf_size)
{
  union bpf_attr attr =
    { .prog_type = type,
      .insns     = (__u64)(insns),
      .insn_cnt  = insn_cnt,
      .license   = (__u64)(license),
      .log_buf   = (__u64)(bpf_log_buf),
      .log_size  = log_buf_size,
      .log_level = 1,
      .kern_version = LINUX_VERSION_CODE,
    };
  return syscall_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

int bpf_map_lookup_elem(int fd, const void *key, void *value) {
  union bpf_attr attr =
    { .map_fd = fd,
      .key = (__u64)key,
      .value = (__u64)value,
    };
  return syscall_bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags) {
  union bpf_attr attr =
    { .map_fd = fd,
      .key = (__u64)key,
      .value = (__u64)value,
      .flags = flags,
    };
  return syscall_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

int bpf_map_delete_elem(int fd, const void *key) {
  union bpf_attr attr =
    { .map_fd = fd,
      .key = (__u64)key,
    };
  return syscall_bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

int bpf_obj_get_info_by_fd(int fd, const void *info, __u32 *info_len) {
  union bpf_attr attr =
    { .info =
      { .bpf_fd = fd,
        .info_len = *info_len,
        .info = (__u64)info,
      },
    };
  int err = syscall_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
  if(!err) {
    *info_len = attr.info.info_len;
  }
  return err;
}
