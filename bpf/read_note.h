#include <stdlib.h>
#include <stdbool.h>

struct argument {
  char *reg;
  bool is_signed;
};

struct probe_note {
  char *name;
  size_t offset;
  size_t semaphore;
  int num_args;
  struct argument *args;
};

struct note_result {
  size_t num_probes;
  struct probe_note **probe_notes;
};

int read_notes(char *file, struct note_result *result);

// CR rcummings: need functions to conveniently free these structs
