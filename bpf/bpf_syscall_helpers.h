#include <linux/bpf.h>

int bpf_prog_load (enum bpf_prog_type type, const struct bpf_insn *insns,
                   int insn_cnt, const char *license,
                   char *bpf_log, size_t log_buf_size);

int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags);

int bpf_map_lookup_elem(int fd, const void *key, void *value);

int bpf_map_delete_elem(int fd, const void *key);

int bpf_obj_get_info_by_fd(int fd, const void *info, __u32 *info_len);

int bpf_map_create();
