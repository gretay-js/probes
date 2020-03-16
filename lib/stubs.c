#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ptrace.h>

/* #ifdef OCAML_OS_TYPE == "Unix" */
#if defined(__GNUC__) && (defined (__ELF__))
#include <linux/ptrace.h>
#elif defined(__APPLE__)
#include "apples.h"
#include <mach/mach_types.h>
#endif
#include <sys/user.h>
#include <sys/wait.h>
#include "read_note.h"

#define CAML_NAME_SPACE
#include <caml/fail.h>
#include <caml/callback.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/custom.h>


#define CMP_OPCODE 0x3d
#define CALL_OPCODE 0xe8


#define DEBUG(stmt) stmt

static inline void v_raise_error(const char *fmt, va_list argp) {

  int n = 256;
  char buf[n];
  vsnprintf(buf,n,fmt,argp);
  DEBUG(fprintf(stderr,"Error: %s\n", buf));
  caml_raise_with_string(*caml_named_value("caml_probes_lib_stub_exception"), buf);
}

static inline void raise_error(const char * msg, ...) {
  va_list args;
  va_start (args, msg);
  v_raise_error(msg, args);
  va_end (args);
}

static bool kill_child_on_error = false;

static inline void signal_and_error(pid_t cpid, const char * msg, ...)  {
  if (kill_child_on_error) {
    ptrace(PTRACE_KILL, cpid, NULL, NULL);
    wait(NULL);
  }
  va_list args;
  va_start (args, msg);
  v_raise_error(msg, args);
  va_end (args);
}

static inline void modify_probe(pid_t cpid, unsigned long addr, bool enable) __attribute__((always_inline)) {
  unsigned long data;
  unsigned long cur;
  unsigned long new;
  errno = 0;
  addr = addr - 5;
  data = ptrace(PTRACE_PEEKTEXT, cpid, addr, NULL);
  if (errno != 0) {
    signal_and_error(cpid,
                     "modify_probe in pid %d: failed to PEEKTEXT at %lx with errno %d\n",
                     cpid, addr, errno);
  }
  if (enable) {
    cur = CMP_OPCODE; new = CALL_OPCODE;
  } else {
    cur = CALL_OPCODE; new = CMP_OPCODE;
  }
  DEBUG(fprintf (stderr, "cur at %lx: %lx\n", addr, data));
  if ((data & 0xff) != cur) {
    fprintf(stderr, "Warning: unexpected instruction at %lx! %lx instead of %lx\n",
            addr, (data & 0xff), cur);
  }
  data = (data & ~0xff) | new;
  DEBUG(fprintf (stderr, "new at %lx: %lx\n", addr, data));
  if (!ptrace(PTRACE_POKETEXT, cpid, addr, data)) {
    signal_and_error(cpid, sprintf("modify_probe in pid %d:\n\
                                    failed to POKETEXT at %lx new val=%lx with errno %d\n",
                                    cpid, addr, data, errno));  
  };
}

static inline void modify_semaphore(pid_t cpid, signed long delta, size_t addr) __attribute__((always_inline)) {
  errno = 0;
  unsigned long data = ptrace(PTRACE_PEEKDATA, cpid, addr, NULL);
  if (errno != 0) {
    signal_and_error(cpid, sprintf("modify_semaphore for probe in pid %d:\n\
                                   failed to PEEKDATA at %lx with errno %d\n",
                                   cpid, addr, errno));       
  }
  data = (unsigned long)(((signed long)data)+delta);
  DEBUG(fprintf (stderr, "new at %lx: %lx\n", addr, data));
  return ptrace(PTRACE_POKEDATA, cpid, addr, data);
}

static inline int is_enabled(pid_t cpid, struct probe_note *notes) __attribute__((always_inline)) {
  unsigned long addr = note->semaphore;
  errno = 0;
  unsigned long data = ptrace(PTRACE_PEEKDATA, cpid, addr, NULL);
  if (errno != 0) {
    signal_and_error(cpid, sprintf("is_enabled probe %s in pid %d: failed to PEEKDATA at %lx with errno %d\n",
                                   note->name, cpid, addr, errno));    
  }
  DEBUG(fprintf (stderr, "semaphore at %lx = %lx\n", addr, data));
  return (((signed long) data) > 0);
}

static inline void update_probe(pid_t cpid, struct probe_note *note, bool enable) __attribute__((always_inline)) {
  modify_probe(cpid, note->offset, enable);
  modify_semaphore(cpid, (enable?1:-1), note->semaphore);
}

static inline void set_all (struct probe_notes *notes, pid_t cpid, int enable) __attribute__((always_inline)) {
  for (int i = 0; i < notes->num_notes; i++) {
      update_probe(cpid, notes->probe_notes[i], enable);
  }
}

/* ptrace calls, nothing specific to probes */
static inline pid_t start (char **argv) __attribute__((always_inline)) {
  pid_t cpid = fork();
  if(cpid==-1) {
    raise_error("error doing fork\n");
  }

  if(cpid==0) {
    if(ptrace(PTRACE_TRACEME, 0, NULL, NULL)) {
      raise_error("ptrace traceme error\n");
    }
    execv(argv[0], argv);
    raise_error("error running exec\n");
  }

  int status = 0;
  wait(&status);
  if(!WIFSTOPPED(status)) {
    signal_and_error(cpid, sprintf("not stopped %d\n", status));
  }
}

static inline void attach (pid_t cpid) __attribute__((always_inline)) {
  if(ptrace(PTRACE_ATTACH, cpid, NULL, NULL)) {
    raise_error(sprintf ("ptrace attach %d, error=%d\n" cpid, errno));
  }

  int status = 0;
  pid_t res = waitpid(cpid, &status, WUNTRACED);
  if ((res != cpid) || !(WIFSTOPPED(status)) ) {
    raise_error (sprintf("Unexpected wait result res %d stat %x\n",res,status));
  }
}

static inline void detach (pid_t cpid) __attribute__((always_inline)) {
  if(ptrace(PTRACE_CONT, cpid, NULL, NULL)==-1) {
    signal_and_error(cpid,
                     sprintf("could not continue, errno=%d\n", errno));
  }
  if (ptrace(PTRACE_DETACH, cpid, NULL, NULL)) {
    signal_and_error(cpid,
                     sprintf ("could not detach %d, errno=%d\n", cpid, errno);
  }
}

/*  OCaml interface: manipulate ocaml values, mind the GC,
    and call regular C functions */

CAMLprim value caml_probes_lib_start (value v_argv)
{
  CAMLparam1(v_argv); /* string list */
  int argc = Wosize_val(v_argv);

  if (argc < 1) {
    raise_error("Missing executable name\n");
  }
  const char ** argv =
    (const char **) caml_stat_alloc((argc + 1 /* for NULL */)
                                    * sizeof(const char *));
  for (i = 0; i < argc; i++) argv[i] = String_val(Field(v_argv, i));
  argv[argc] = NULL;

  pid_t cpid = start(argv);

  caml_stat_free(argv);
  CAMLreturn(Val_long(cpid));
}


CAMLprim value caml_probes_lib_attach (value v_pid)
{
  pid_t cpid = Long_val(v_pid);
  attach(cpid);
  return Val_unit;
}

CAMLprim value caml_probes_lib_detach (value v_pid)
{
  pid_t cpid = Long_val(v_pid);
  detach(cpid);
  return Val_unit;
}

/* Encapsulation of probe notes as OCaml custom blocks. */
static struct custom_operations probe_notes_ops = {
  "com.janestreet.ocaml.probes",
  custom_finalize_default,
  custom_compare_default,
  custom_hash_default,
  custom_serialize_default,
  custom_deserialize_default,
  custom_compare_ext_default,
  custom_fixed_length_default
};

/* Accessing the note part of an OCaml custom block */
#define Probe_notes_val(v) (*((probe_notes **) Data_custom_val(v)))

CAMLprim value caml_probes_lib_read_notes (value v_filename) {
  CAMLparam1(v_filename);
  char *filename = String_val(v_filename);

  struct probe_notes *res = malloc(sizeof(struct probe_notes));
  if(read_notes(filename, res)) {
    raise_error (sprintf ("could not parse probe notes from %s\n" filename));
  }

  /* Allocating an OCaml custom block to hold the notes */
  value v_internal = caml_alloc_custom(&probe_notes_ops, sizeof(probe_notes *), 0, 1);
  Probe_notes_val(v_internal) = res;
  CAMLreturn(v_internal);
}

CAMLprim value caml_probes_lib_get_names (value v_internal) {
  CAMLparam1(v_internal);
  CAMLlocal2(v_names, v_name);

  struct probe_notes *notes = Probe_notes_val(v_internal);
  size_t n = notes->num_notes;
  v_names = caml_alloc(n,0);
  for (int i = 0; i < n; i++) {
    v_name = caml_copy_string(notes->probe_notes[i]->name);
    Store_field(v_names, i, v_name);
  }
  CAMLreturn(v_names);
}

CAMLprim value caml_probes_lib_get_states (value v_internal, value v_pid) {
  CAMLparam1(v_internal);
  CAMLlocal2(v_states);
  pid_t cpid = Long_val(v_pid);

  struct probe_notes *notes = Probe_notes_val(v_internal);
  size_t n = notes->num_notes;
  v_states = caml_alloc(n,0);
  int b;
  for (int i = 0; i < n; i++) {
    b = is_enabled(cpid, notes->probe_notes[i]);
    Store_field(v_states, i, Val_bool(b));
  }
  CAMLreturn(v_states);
}

CAMLprim value caml_probes_lib_update (value v_internal, value v_pid,
                                       value v_name, value v_enable) {
  // This function doesn't allocate, but update_probe may raise
  // we still need to register these values with the GC.
  CAMLparam2(v_internal, v_name);
  pid_t cpid = Long_val(v_pid);
  int enable = Bool_val(v_enable);
  char *name = String_val(v_name);
  struct probe_notes *notes = Probe_notes_val(v_internal);
  for (int i = 0; i < notes->num_notes; i++) {
    if (!strcmp(name, notes->probe_notes[i]->name)) {
      update_probe(cpid, notes->probe_notes[i], enable);
    }
  }
  CAMLreturn(Val_unit);
}

CAMLprim value caml_probes_lib_set_all (value v_internal, value v_pid,
                                        value v_enable) {
  // This function doesn't allocate, but set_all may raise
  // we still need to register these values with the GC.
  CAMLparam1(v_internal);
  pid_t cpid = Long_val(v_pid);
  int enable = Bool_val(v_enable);
  struct probe_notes *notes = Probe_notes_val(v_internal);
  set_all(notes, cpid, enable);
  CAMLreturn(Val_unit);
}

CAMLprim value caml_probes_lib_attach_set_all_detach (value v_internal, value v_pid,
                                        value v_enable)
{
  CAMLparam1(v_internal);
  pid_t cpid = Long_val(v_pid);
  int enable = Bool_val(v_enable);
  struct probe_notes *notes = Probe_notes_val(v_internal);
  attach(cpid);
  set_all(notes, cpid, enable);
  detach(cpid);
  CAMLreturn(Val_unit);
}

CAMLprim value stub_trace_all (value v_internal, value v_argv)
{
  CAMLparam2(v_internal,v_argv);
  
  int argc = Wosize_val(v_argv);
  if (argc < 1) {
    raise_error("Missing executable name\n");
  }
  const char ** argv =
    (const char **) caml_stat_alloc((argc + 1 /* for NULL */)
                                    * sizeof(const char *));
  for (i = 0; i < argc; i++) argv[i] = String_val(Field(v_argv, i));
  argv[argc] = NULL;
  pid_t cpid = start(argv);
  caml_stat_free(argv);
  set_all(notes, cpid, true);
  detach(cpid);
  CAMLreturn(Val_unit);
}
