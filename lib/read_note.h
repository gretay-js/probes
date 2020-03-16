#include <stdlib.h>
#include <stdbool.h>

struct argument {
  char *reg;
  bool is_signed;
};

// Offsets are relative to the beginning of the text section.
/* CR-someday gyrsh: probe updates won't work if text section is loaded
   (mapped) to a different address in memory, for example in the presence of
   address space randomization. */
struct probe_note {
  char *name;
  unsigned long offset;
  unsigned long semaphore;
  int num_args;
  struct argument *args;
};

struct probe_notes {
  size_t num_probes;
  struct probe_note **probe_notes;
};

int read_notes(char *file, struct probe_notes *result);

// CR rcummings: need functions to conveniently free these structs
