#include <stdlib.h>

struct bpf_map {
  int fd;
  char *name;
};

struct bpf_elf_result {
  size_t insn_count;
  struct bpf_insn *insns;
  size_t map_count;
  struct bpf_map *maps;
};

struct bpf_elf_params {
  char *bpf_filename;
  char *bpf_section_name;
  char *map_section_name;
};

void free_maps(struct bpf_elf_result *result);

int parse_bpf(struct bpf_elf_params *params, struct bpf_elf_result *result);
