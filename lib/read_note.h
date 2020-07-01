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
  int num_probes;
  struct probe_note **probe_notes;
  // The following fields are used in position independent executables
  // to find the dynamic addresses of probes and semaphores
  bool pie;
  unsigned long text_addr;
  unsigned long text_offset;
  unsigned long data_addr;
  unsigned long data_offset;
};

int read_notes(const char *file, struct probe_notes *result, bool verbose);

// CR-someday rcummings: need functions to conveniently free these structs
