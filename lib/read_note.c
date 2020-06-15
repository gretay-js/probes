#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#if defined(__GNUC__) && defined (__ELF__)
#include <linux/types.h>
#elif defined (__APPLE__)
typedef uint8_t __u8;
typedef uint32_t __u32;
typedef uint64_t __u64;
#include <mach/mach_types.h>
#endif

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include "read_note.h"

static bool verbose = false;

struct whole_elf {
  size_t size;
  char *data;
  bool pie;
};

static void destroy(struct whole_elf *whole_elf) {
  if(!whole_elf) return;
  free(whole_elf->data);
  whole_elf->data = NULL;
}

struct section {
  __u64 addr;
  __u64 offset;
  __u64 size;
  __u32 type;
  /* __u64 entsize; */
  /* __u32 index; */
  char *name;
};

static char *section_data(struct whole_elf *whole_elf, struct section *section)
{
  return whole_elf->data + section->offset;
}

struct section_table {
  size_t offset;
  size_t entry_size;
  size_t num_headers;
};

static int read_section_details(struct whole_elf *whole_elf,
                                struct section_table *section_table,
                                size_t index, struct section *strings,
                                struct section *result)
{
  if(!whole_elf ||!section_table || !strings || !result) return 1;
  char *base = whole_elf->data + section_table->offset +
    index * section_table->entry_size;
  size_t name_offset = *(__u32*)base;
  result->addr = *(__u64*)(base+0x10);
  result->offset = *(__u64*)(base+0x18);
  result->size = *(__u32*)(base+0x20);
  result->type = *(__u32*)(base+0x04);
  /* result->entsize = *(__u32*)(base+0x38); */
  result->name = section_data(whole_elf, strings) + name_offset;
  /* result->index = index; */
  return 0;
}

struct main_sections {
  struct section stapsdt;
  struct section strings;
  struct section text;
  struct section data; // not used
  struct section probes;
};

#define ET_EXEC 2
#define ET_DYN  3
#define SHT_PROGBITS 1
#define SHT_NOTE 7
static int get_main_sections(struct whole_elf *whole_elf,
                      struct main_sections *result) {
  if(whole_elf->data[4]!=2) {
    fprintf(stderr, "elf not in 64-bit format\n");
    return 1;
  }
  __u16 e_type = *(__u16*)(whole_elf->data+16);
  switch (e_type) {
  case ET_EXEC: whole_elf->pie = false; break;
  case ET_DYN:  whole_elf->pie = true;  break;
  default:
    fprintf(stderr, "unexpected type of elf executable %d", e_type);
    return 1;
  };
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
  bool found_text = false;
  bool found_probes = false;
  for(size_t i = 0; i<section_table.num_headers; ++i) {
    read_section_details(whole_elf, &section_table, i, &result->strings,
                         &current);
    if ((!strcmp(current.name, ".note.stapsdt") && current.type == SHT_NOTE) ||
       (!strcmp(current.name, "__note_stapsdt") )) {
      result->stapsdt = current;
      if(found_stapsdt) {
        fprintf(stderr, "duplicate .note.stapsdt sections\n");
        return 1;
      }
      found_stapsdt = true;
    }
    else if (!strcmp(current.name, ".text") && current.type == SHT_PROGBITS) {
      result->text = current;
      if(found_text) {
        fprintf(stderr, "duplicate .text sections\n");
        return 1;
      }
      found_text = true;
    } else if (!strcmp(current.name, ".probes") && current.type == SHT_PROGBITS) {
      result->probes = current;
      if(found_probes) {
        fprintf(stderr, "duplicate .probes sections\n");
        return 1;
      }
      found_probes = true;
    }
  }
  if(!found_text) {
    fprintf(stderr, ".text section not found\n");
    return 1;
  }
  if(!found_stapsdt) {
    if (verbose) fprintf(stderr, "stapsdt note section not found\n");
    return -1;
  }
  if(!found_probes) {
    if (verbose) fprintf(stderr, ".probes section not found\n");
    return -2;
  }
  return 0;
}

int parse_arguments(struct probe_note *note, char *argstring)
{
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

int parse_notes(char *data,
                struct main_sections *ms,
                struct probe_notes *result,
                bool found_probes_section)
{
  size_t num_notes = 0;
  size_t offset = 0;
  struct probe_note **notes = NULL;
  size_t len_notes = 0;
  while(offset < ms->stapsdt.size) {
    if (num_notes >= len_notes) {
      len_notes = (len_notes == 0? 64 : len_notes * 2);
      notes = (struct probe_note **)
        realloc(notes, sizeof(struct probe_note *) * len_notes);
      if (!notes) {
        // we could just return what was read so far, instead of failing.
        fprintf(stderr, "could not allocate space for all notes.\n");
        goto error2;
      }
    }
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
    struct probe_note *current = malloc(sizeof(struct probe_note));
    if(!current) {
      fprintf(stderr, "could not alloc note info\n");
      goto error2;
    }
    notes[num_notes] = current;
    ++num_notes;
    current->offset = *(__u64*)data;
    if (!((ms->text.addr <= current->offset) &&
          (current->offset <= ms->text.addr+ms->text.size))) {
      fprintf (stderr, "probe offset outside of .text section: %lx\n",
               current->offset);
      goto error2;
    }
    current->semaphore = *(__u64*)(data+0x10);
    if ((current->semaphore == 0) // no semaphore
        || !found_probes_section // no semaphore section
        || !((ms->probes.addr <= current->semaphore) &&
             (current->semaphore <= ms->probes.addr+ms->probes.size))) {
      fprintf (stderr, "probe semaphore's offset is missing or outside "
               "of .probes section: probe=%lx,semaphore=%lx\n",
               current->offset, current->semaphore);
      current->semaphore = 0;
    }
    char *provider = data+0x18;
    // CR-soon rcummings: do something with provider, check if it is 'ocaml'
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
  result->probe_notes = malloc(sizeof(struct probe_note*) * (num_notes));
  if(!result->probe_notes) {
    fprintf(stderr, "could not alloc probe note pointers\n");
    goto error2;
  }
  for(size_t i = 0; i<num_notes; ++i) {
    result->probe_notes[i] = notes[i];
  }
  if (notes) free(notes);
  return 0;
 error2:
  if (notes) {
    for(size_t i = 0; i<num_notes; ++i) {
      if (notes[i]) {
        if (notes[i]->name) free(notes[i]->name);
        free(notes[i]);
      }
    }
    free(notes);
  }
  return 1;
}

int read_notes(const char *filename, struct probe_notes *result, bool v)
{
  verbose = v;
  struct whole_elf whole_elf =
    { .size = 0,
      .data = NULL,
      .pie = false,
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
  // initialize just to suppress warnings
  struct main_sections ms = {.stapsdt = {0},
                             .strings = {0},
                             .text = {0},
                             .data = {0},
                             .probes = {0}};
  switch (get_main_sections(&whole_elf, &ms)) {
  case 0:
    if (parse_notes(section_data(&whole_elf, &ms.stapsdt),&ms,result,true))
      goto error1;
    break;
  case -1: // not found stapsdt section
    result->num_probes = 0;
    break;
  case -2: // not found .probes section - semaphores not emitted
    if (parse_notes(section_data(&whole_elf, &ms.stapsdt),&ms,result,false))
      goto error1;
    break;
  default:
    fprintf(stderr, "error getting main sections\n");
    goto error1;
  }
  result->pie = whole_elf.pie;
  result->text_addr = ms.text.addr;
  result->text_offset = ms.text.offset;
  result->data_addr = ms.probes.addr;
  result->data_offset = ms.probes.offset;
  /* fprintf (stderr, "text section: (%lx,%lx)", text_start, text_finish);
   * fprintf (stderr, "data section: (%lx,%lx)", data_start, data_finish); */
  destroy(&whole_elf);
  return 0;
 error1:
  destroy(&whole_elf);
  return 1;
}
