#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>

#include <linux/types.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <linux/bpf.h>
#include "bpf_elf.h"
#include "uid.h"

#define DUMP_PROGRAM false

struct whole_elf {
  size_t size;
  char *data;
};

static void destroy(struct whole_elf *whole_elf) {
  if(!whole_elf) return;
  free(whole_elf->data);
  whole_elf->data = NULL;
}

struct section {
  size_t offset;
  size_t size;
  size_t type;
  size_t entsize;
  size_t index;
  char *name;
};

static char *section_data(struct whole_elf *whole_elf, struct section *section) {
  return whole_elf->data + section->offset;
}

struct section_table {
  size_t offset;
  size_t entry_size;
  size_t num_headers;
};

static int read_section_details(struct whole_elf *whole_elf, struct section_table *section_table,
                         size_t index, struct section *strings, struct section *result) {
  if(!whole_elf ||!section_table || !strings || !result) return 1;
  char *base = whole_elf->data + section_table->offset + index * section_table->entry_size;
  size_t name_offset = *(__u32*)base;
  result->offset = *(__u64*)(base+0x18);
  result->size = *(__u64*)(base+0x20);
  result->type = *(__u32*)(base+0x04);
  result->entsize = *(__u64*)(base+0x38);
  result->name = section_data(whole_elf, strings) + name_offset;
  result->index = index;
  return 0;
}

struct main_sections {
  struct section text;
  struct section bpf;
  struct section maps;
  struct section strings;
  struct section symbols;
  struct section rels;
};

/* a helper structure used by eBPF C program
 * to describe map attributes to elf_bpf loader
 */
struct bpf_map_def {
  unsigned int type;
  unsigned int key_size;
  unsigned int value_size;
  unsigned int max_entries;
  unsigned int map_flags;
  unsigned int inner_map_idx;
  unsigned int numa_node;
};

static int get_main_sections(struct bpf_elf_params *params, struct whole_elf *whole_elf,
                      struct main_sections *result) {
  if(whole_elf->data[4]!=2) {
    fprintf(stderr, "elf not in 64-bit format\n");
    return 1;
  }
  struct section_table section_table =
    { .offset = *(__u64*)(whole_elf->data+0x28),
      .entry_size =  *(__u8*)(whole_elf->data+0x3A),
      .num_headers = *(__u8*)(whole_elf->data+0x3C),
    };
  size_t string_section_index = *(__u8*)(whole_elf->data+0x3E);
  if(!result) {
    fprintf(stderr, "invalid argument 'result\n");
    return 1;
  }
  read_section_details(whole_elf, &section_table, string_section_index,
                       &result->strings, &result->strings);
  struct section current;
  bool found_bpf = false, found_maps = false, found_rels = false,
    found_symbols = false, found_text = false;
  for(size_t i = 0; i<section_table.num_headers; ++i) {
    read_section_details(whole_elf, &section_table, i, &result->strings, &current);
    if(!strcmp(current.name, params->bpf_section_name)) {
      result->bpf = current;
      if(found_bpf) {
        fprintf(stderr, "duplicate bpf sections\n");
        return 1;
      }
      found_bpf = true;
    }
    if(!strcmp(current.name, ".text")) {
      result->text = current;
      if(found_text) {
        fprintf(stderr, "duplicate .text sections\n");
        return 1;
      }
      found_text = true;
    }
    if(!strcmp(current.name, params->map_section_name)) {
      result->maps = current;
      result->maps.entsize = sizeof(struct bpf_map_def);
      if(found_maps) {
        fprintf(stderr, "duplicate maps section\n");
        return 1;
      }
      found_maps = true;
    }
    if(current.type == 4 || current.type == 9) {
      if(found_rels) {
        fprintf(stderr, "duplicate rels section\n");
        return 1;
      }
      result->rels = current;
      found_rels = true;
    }
    if(current.type == 2) {
      if(found_symbols) {
        fprintf(stderr, "duplicate symbols sections\n");
        return 1;
      }
      result->symbols = current;
      found_symbols = true;
    }
  }
  if(!found_bpf) {
    fprintf(stderr, "bpf section not found\n");
    return 1;
  }
  if(!found_maps) {
    fprintf(stderr, "maps section not found\n");
    return 1;
  }
  if(!found_rels) {
    fprintf(stderr, "rels section not found\n");
    return 1;
  }
  if(!found_symbols) {
    fprintf(stderr, "symbols section not found\n");
    return 1;
  }
  if(!found_text) {
    fprintf(stderr, "text section not found\n");
    return 1;
  }
  if((result->bpf).size % sizeof(struct bpf_insn) != 0) {
    fprintf(stderr, "bpf section not made up of whole number of instructions\n");
    return 1;
  }
  if((result->text).size % sizeof(struct bpf_insn) != 0) {
    fprintf(stderr, "text section not made up of whole number of instructions\n");
    return 1;
  }
  return 0;
};

int bpf_create_map(struct bpf_map_def *bpf_map_def, int *result)
{
  if(!bpf_map_def) {
    fprintf(stderr, "bpf_map_def is null\n");
    return 1;
  }
  if(!result) {
    fprintf(stderr, "result is null\n");
    return 1;
  }
  union bpf_attr attr =
    { .map_type    = bpf_map_def->type,
      .key_size    = bpf_map_def->key_size,
      .value_size  = bpf_map_def->value_size,
      .max_entries = bpf_map_def->max_entries
    };
  uid_up ();
  *result = syscall(SYS_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
  uid_down ();
  if(*result==-1) {
    fprintf(stderr, "error trying to create bpf map: errno=%d\n", errno);
    return 1;
  }
  return 0;
}

void free_maps(struct bpf_elf_result *result) {
  for(size_t i = 0; i < result->map_count; ++i) {
    free(result->maps[i].name);
  }
  free(result->maps);
  result->maps = NULL;
  result->map_count = 0;
}

int parse_bpf(struct bpf_elf_params *params, struct bpf_elf_result *result) {
  if(!params) {
    fprintf(stderr, "params is null\n");
    return 1;
  }
  if(!result)  {
    fprintf(stderr, "result is null\n");
  }
  struct whole_elf whole_elf =
    { .size = 0,
      .data = NULL,
    };
  { // one pass to count bytes, another to copy them
    FILE *file = fopen(params->bpf_filename, "r");
    if(!file) {
      fprintf(stderr, "bpf file not found\n");
      return 1;
    }
    while(fgetc(file)!=EOF) ++whole_elf.size;
    fseek(file, 0, SEEK_SET);
    whole_elf.data = malloc(whole_elf.size);
    if(!whole_elf.data) {
      fclose(file);
      fprintf(stderr, "could not alloc bpf file\n");
      return 1;
    }
    int c;
    for(size_t i=0; (c=fgetc(file))!=EOF; ++i) whole_elf.data[i] = c;
    fclose(file);
  }
  struct main_sections ms;
  if(get_main_sections(params, &whole_elf, &ms)) {
    fprintf(stderr, "error getting main sections\n");
    goto error;
  }

  struct bpf_insn *insns = malloc(ms.bpf.size + ms.text.size);
  if(!insns) {
    fprintf(stderr, "could not alloc bpf insns\n");
    goto error;
  }
  memcpy(insns,
         (struct bpf_insn*)(whole_elf.data+ms.bpf.offset),
         ms.bpf.size);
  size_t bpf_section_insn_count = ms.bpf.size / sizeof(struct bpf_insn);
  memcpy(insns + bpf_section_insn_count,
         (struct bpf_insn*)(whole_elf.data+ms.text.offset),
         ms.text.size);
  // create map fds
  result->map_count = ms.maps.size/ms.maps.entsize;
  result->maps = malloc(result->map_count * sizeof(struct bpf_map));
  if(!result->maps) {
    fprintf(stderr, "could not alloc bpf map info\n");
    goto error;
  }
  for(size_t i = 0; i < result->map_count; ++i) {
    result->maps[i].name = NULL;
  }
  // declared here to make the goto error work
  int *symbol_index_mapping = NULL;
  size_t *text_symbol_mapping = NULL;
  for(size_t i = 0; i < result->map_count; ++i) {
    struct bpf_map_def *map_def =
      (struct bpf_map_def*)(section_data(&whole_elf, &ms.maps) + ms.maps.entsize * i);
    if(bpf_create_map(map_def, &result->maps[i].fd)) {
      fprintf(stderr, "error creating bpf map\n");
      goto error2;
    }
  }
  // create symbol table index to map index mapping
  size_t num_symbols = ms.symbols.size / ms.symbols.entsize;
  symbol_index_mapping = malloc(num_symbols * sizeof(int));
  if(!symbol_index_mapping) {
    fprintf(stderr, "could not alloc symbol index mapping\n");
    goto error2;
  }
  text_symbol_mapping = malloc(num_symbols * sizeof(size_t));
  if(!text_symbol_mapping) {
    fprintf(stderr, "could not alloc text symbol mapping\n");
    goto error2;
  }
  for(size_t i = 0; i < num_symbols; ++i) {
    symbol_index_mapping[i] = -1;
    text_symbol_mapping[i] = -1;
    char *entry = section_data(&whole_elf, &ms.symbols) + ms.symbols.entsize * i;
    size_t name_offset = *(__u32*)entry;
    size_t section = *(__u16*)(entry+0x6);
    size_t value = *(__u64*)(entry+0x8);
    if(section == ms.maps.index) {
      int j = value / ms.maps.entsize;
      char *name = section_data(&whole_elf, &ms.strings) + name_offset;
      size_t name_len = strlen(name);
      result->maps[j].name = malloc(name_len + 1);
      if(!result->maps[j].name) {
        fprintf(stderr, "could not alloc map name\n");
        goto error2;
      }
      memcpy(result->maps[j].name, name, name_len + 1);
      symbol_index_mapping[i] = j;
    }
    else if(section == ms.text.index) {
      text_symbol_mapping[i] = value / sizeof(struct bpf_insn);
    }
  }
  for(size_t rel_entry = 0; rel_entry < ms.rels.size; rel_entry += ms.rels.entsize) {
    char *entry = section_data(&whole_elf, &ms.rels) + rel_entry;
    size_t instr_offset = *(__u64*)entry;
    size_t symbol_index = *(__u32*)(entry+0xc);
    if(symbol_index_mapping[symbol_index]!= -1) {
      int i = symbol_index_mapping[symbol_index];
      size_t j = instr_offset / sizeof(struct bpf_insn);
      if(insns[j].code != (BPF_LD | BPF_IMM | BPF_DW)) {
        fprintf(stderr, "unexpected opcode for loading map fd\n");
        goto error2;
      }
      insns[j].src_reg = BPF_PSEUDO_MAP_FD;
      insns[j].imm = result->maps[i].fd;
    }
    else if(text_symbol_mapping[symbol_index]!=-1) {
      size_t i = text_symbol_mapping[symbol_index];
      size_t j = instr_offset / sizeof(struct bpf_insn);
      if(insns[j].code != (BPF_JMP | BPF_CALL) || insns[j].src_reg!=BPF_PSEUDO_CALL) {
        fprintf(stderr, "relocation is not a BPF function call\n");
        goto error2;
      }
      insns[j].imm = bpf_section_insn_count + i - j - 1;
    }
    else {
      fprintf(stderr, "unexpected rel entry\n");
      goto error2;
    }
  }
  free(symbol_index_mapping);
  destroy(&whole_elf);
  result->insn_count = (ms.bpf.size + ms.text.size)/sizeof(struct bpf_insn);
  if(DUMP_PROGRAM) {
    printf("bpf size=%zx text size=%zx\n", ms.bpf.size/8, ms.text.size/8);
    for(size_t i = 0; i<result->insn_count; ++i) {
      printf("%3zx: ", i);
      for(int j=0; j<8; ++j) {
        printf("%02hhx ", ((char*)insns)[8*i+j]);
      }
      printf("\n");
    }
  }
  result->insns = insns;
  return 0;
 error2:
  free(symbol_index_mapping);
  free(text_symbol_mapping);
  free_maps(result);
 error:
  destroy(&whole_elf);
  return 1;
}
