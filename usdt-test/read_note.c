#include <linux/types.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include "read_note.h"

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
  struct section stapsdt;
  struct section strings;
};

static int get_main_sections(struct whole_elf *whole_elf,
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
  bool found_stapsdt = false;
  for(size_t i = 0; i<section_table.num_headers; ++i) {
    read_section_details(whole_elf, &section_table, i, &result->strings, &current);
    if(!strcmp(current.name, ".note.stapsdt") && current.type == 7) {
      result->stapsdt = current;
      if(found_stapsdt) {
        fprintf(stderr, "duplicate .note.stapsdt sections\n");
        return 1;
      }
      found_stapsdt = true;
    }
  }
  if(!found_stapsdt) {
    fprintf(stderr, "stapsdt note section not found\n");
    return 1;
  }
  return 0;
};

int parse_arguments(struct probe_note *note, char *argstring) {
  int n = strlen(argstring);
  int count = 0;
  if(n>0) ++count;
  for(int i=0; i<n; ++i) {
    if(argstring[i]==' ') ++count;
  }
  note->num_args = count;
  note->args = calloc(count, sizeof(struct argument));
  if(!note->args) {
    fprintf(stderr, "could not alloc arguments\n");
    return 1;
  }
  int l = 0, r = 0, i = 0;
  while(l<n) {
    r = l+1;
    while(r<n && argstring[r]!=' ') ++r;
    note->args[i].is_signed = argstring[l] == '-';
    while(argstring[l]!='@') ++l;
    ++l;
    note->args[i].reg = malloc(r-l+1);
    if(!note->args[i].reg) return 1;
    memcpy(note->args[i].reg, (argstring+l), r-l);
    note->args[i].reg[r-l] = 0;
    l = r+1;
    ++i;
  }
  return 0;
}

int read_notes(char *filename, struct note_result *result) {
  struct whole_elf whole_elf =
    { .size = 0,
      .data = NULL,
    };
  { // one pass to count bytes, another to copy them
    FILE *file = fopen(filename, "r");
    if(!file) {
      fprintf(stderr, "elf file not found\n");
      return 1;
    }
    while(fgetc(file)!=EOF) ++whole_elf.size;
    fseek(file, 0, SEEK_SET);
    whole_elf.data = malloc(whole_elf.size);
    if(!whole_elf.data) {
      fclose(file);
      fprintf(stderr, "could not alloc elf file\n");
      return 1;
    }
    int c;
    for(size_t i=0; (c=fgetc(file))!=EOF; ++i) whole_elf.data[i] = c;
    fclose(file);
  }
  struct main_sections ms;
  if(get_main_sections(&whole_elf, &ms)) {
    fprintf(stderr, "error getting main sections\n");
    goto error1;
  }
  char *data = section_data(&whole_elf, &ms.stapsdt);
  size_t offset = 0;
  struct probe_note *notes[100];
  size_t num_notes = 0;
  while(offset < ms.stapsdt.size && num_notes<100) {
    int owner_size = *(int*)data;
    int data_size = *(int*)(data+4);
    int type = *(int*)(data+8);
    if(type!=3) {
      fprintf(stderr, "wrong type: %d\n", type);
      goto error2;
    }
    if(owner_size!=8) {
      fprintf(stderr, "owner string size is wrong\n");
      goto error2;
    }
    data += 0xc;
    offset += 0xc;
    if(strncmp("stapsdt", data, owner_size)) {
      fprintf(stderr, "owner is not stapsdt\n");
      goto error2;
    }
    data += 0x8;
    offset += 0x8;
    notes[num_notes] = malloc(sizeof(struct probe_note));
    struct probe_note *current = notes[num_notes];
    ++num_notes;
    if(!current) {
      fprintf(stderr, "could not alloc note info\n");
      goto error2;
    }
    current->offset = *(__u64*)data;
    current->semaphore = *(__u64*)(data+0x10);
    char *provider = data+0x18;
    // CR rcummings: do something with provider, like check if it is 'ocaml'
    char *name = provider + strlen(provider) + 1;
    size_t name_len = strlen(name);
    current->name = malloc(name_len+1);
    if(!current->name) {
      fprintf(stderr, "could not alloc note name\n");
      goto error2;
    }
    memcpy(current->name, name, name_len+1);
    char *argstring = name + name_len + 1;
    /* printf("offset=0x%zx, semaphore=0x%zx args=\"%s\"\n",
     *        current->offset, current->semaphore, argstring); */
    if(parse_arguments(current, argstring)) {
      fprintf(stderr, "error parsing argument string\n");
      goto error2;
    }
    offset += data_size;
    data += data_size;
    while(offset&3) {
      ++offset;
      ++data;
    }
  }
  result->num_probes = num_notes;
  result->probe_notes = malloc(sizeof(struct probe_note*) * num_notes);
  if(!result->probe_notes) {
    fprintf(stderr, "could not alloc probe note pointers\n");
    goto error2;
  }
  for(size_t i = 0; i<num_notes; ++i) {
    result->probe_notes[i] = notes[i];
  }
  destroy(&whole_elf);
  return 0;
 error2:
  // CR rcummings: free a bunch of stuff
 error1:
  destroy(&whole_elf);
  return 1;
}
