#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ptrace.h>

/* #ifdef OCAML_OS_TYPE == "Unix" */
#if defined(__GNUC__) && (defined (__ELF__))
#include <linux/ptrace.h>

static inline long ptrace_traceme()
{ return ptrace(PTRACE_TRACEME, 0, NULL, NULL); }

static inline long ptrace_attach(pid_t pid)
{ return ptrace(PTRACE_ATTACH, pid, NULL, NULL); }

/* static inline long ptrace_cont(pid_t pid) */
/* { return ptrace(PTRACE_CONT, pid, NULL, NULL); } */

static inline long ptrace_detach(pid_t pid)
{ return ptrace(PTRACE_DETACH, pid, NULL, NULL); }

static inline long ptrace_kill(pid_t pid)
{ return ptrace(PTRACE_KILL, pid, NULL, NULL); }

static inline long ptrace_get_text(pid_t pid, void *addr)
{ return ptrace(PTRACE_PEEKTEXT, pid, addr, NULL); }

static inline long ptrace_set_text(pid_t pid, void *addr, void *data)
{ return ptrace(PTRACE_POKETEXT, pid, addr, data); }

static inline long ptrace_get_data(pid_t pid, void *addr)
{ return ptrace(PTRACE_PEEKDATA, pid, addr, NULL); }

static inline long ptrace_set_data(pid_t pid, void *addr, void *data)
{ return ptrace(PTRACE_POKEDATA, pid, addr, data); }

#elif defined(__APPLE__)

#include <mach/mach_types.h>
#include <mach/mach.h>

static inline long ptrace_traceme()
{ return ptrace(PT_TRACE_ME, 0, (caddr_t)1, 0); }

static inline long ptrace_attach(pid_t pid)
{ return ptrace(PT_ATTACHEXC, pid, (caddr_t)1, 0); }

/* static inline long ptrace_cont(pid_t pid) */
/* { return ptrace(PT_CONTINUE, pid, (caddr_t)1, 0); } */

static inline long ptrace_detach(pid_t pid)
{ return ptrace(PT_DETACH, pid, (caddr_t)1, 0); }

static inline long ptrace_kill(pid_t pid)
{ return ptrace(PT_KILL, pid, (caddr_t)1, 0); }

// CR-soon gyorsh: test peek/poke on mac
static inline long get_mem(pid_t pid, void *addr, vm_prot_t prot)
{
  kern_return_t kret;
  mach_port_t task;
  unsigned long res;
  pointer_t buffer;
  uint32_t size;

  kret = task_for_pid(mach_task_self(), pid, &task);
  if ((kret!=KERN_SUCCESS) || !MACH_PORT_VALID(task))
    {
      fprintf(stderr, "task_for_pid failed: %s!\n",mach_error_string(kret));
      exit(2);
    }

  kret = vm_protect(task, (vm_address_t) addr, sizeof (unsigned long),
                    FALSE, prot);
  if (kret!=KERN_SUCCESS)
  {
    fprintf(stderr, "vm_protect failed: %s!\n", mach_error_string(kret));
    exit(2);
  }

  kret = vm_read(task, (vm_address_t) addr, sizeof(unsigned long), &buffer,
                 &size);
  if (kret!=KERN_SUCCESS)
  {
    fprintf(stderr, "vm_read failed: %s!\n",mach_error_string(kret));
    exit(2);
  }
  res = *((unsigned long *) buffer);
  return res;
}

static inline long set_mem(pid_t pid, void *addr, void *data, vm_prot_t prot)
{
  kern_return_t kret;
  mach_port_t task;

  kret = task_for_pid(mach_task_self(), pid, &task);
  if ((kret!=KERN_SUCCESS) || !MACH_PORT_VALID(task))
    {
      fprintf(stderr, "task_for_pid failed: %s!\n",mach_error_string(kret));
      exit(2);
    }

  kret = vm_protect(task, (vm_address_t) addr, sizeof (unsigned long), FALSE,
                    prot);
  if (kret!=KERN_SUCCESS)
  {
    fprintf(stderr, "vm_protect failed: %s!\n", mach_error_string(kret));
    exit(2);
  }

  kret = vm_write(task, (vm_address_t) addr, (vm_address_t) data,
                  sizeof(unsigned long));
  if (kret!=KERN_SUCCESS)
  {
    fprintf(stderr, "vm_write failed: %s!\n", mach_error_string(kret));
    exit(2);
  }
  return 0;
}

static inline long ptrace_get_text(pid_t pid, void *addr)
{ return get_mem(pid,addr, VM_PROT_READ | VM_PROT_EXECUTE); }

static inline long ptrace_set_text(pid_t pid, void *addr, void *data)
{
  return set_mem(pid,addr,data,VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
}

static inline long ptrace_get_data(pid_t pid, void *addr)
{ return get_mem(pid,addr, VM_PROT_READ); }

static inline long ptrace_set_data(pid_t pid, void *addr, void *data)
{ return set_mem(pid,addr,data,VM_PROT_READ | VM_PROT_WRITE); }

#endif
#include <sys/user.h>
#include <sys/wait.h>
#include "read_note.h"

#include <caml/fail.h>
#include <caml/callback.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/custom.h>

// Error handling
static bool verbose;

static inline void v_raise_error(const char *fmt, va_list argp)
{
  int n = 256;
  char buf[n];
  vsnprintf(buf,n,fmt,argp);
  if (verbose) fprintf(stderr,"Error: %s\n", buf);
  const value *ex = caml_named_value("caml_probes_lib_stub_exception");
  if (ex == NULL) {
    fprintf(stderr, "Fatal error: exception "
            "caml_probes_lib_stub_exception ");
    vfprintf(stderr, fmt, argp);
    exit(2);
  }
  caml_raise_with_string(*ex, buf);
}

static inline void raise_error(const char * msg, ...) {
  va_list args;
  va_start (args, msg);
  v_raise_error(msg, args);
  va_end (args);
}

static bool kill_child_on_error = false;

static inline void signal_and_error(pid_t cpid, const char * msg, ...)
{
  if (kill_child_on_error) {
    ptrace_kill(cpid);
    wait(NULL);
  }
  va_list args;
  va_start (args, msg);
  v_raise_error(msg, args);
  va_end (args);
}

// The crux: update probes and semaphores

#define CMP_OPCODE 0x3d
#define CALL_OPCODE 0xe8

static inline void modify_probe(pid_t cpid, unsigned long addr, bool enable)
{
  unsigned long data;
  unsigned long cur;
  unsigned long new;
  errno = 0;
  addr = addr - 5;
  data = ptrace_get_text(cpid, (void *) addr);
  if (errno != 0) {
    signal_and_error(cpid,
                     "modify_probe in pid %d:"
                     "failed to PEEKTEXT at %lx with errno %d\n",
                     cpid, addr, errno);
  }
  if (enable) {
    cur = CMP_OPCODE; new = CALL_OPCODE;
  } else {
    cur = CALL_OPCODE; new = CMP_OPCODE;
  }
  if (verbose) fprintf (stderr, "cur at %lx: %lx\n", addr, data);
  if ((data & 0xff) == new) {
    if (verbose) fprintf(stderr, "cur is already set as required.\n");
    return;
  }
  if ((data & 0xff) != cur) {
    signal_and_error(cpid, "modify probe: unexpected instruction at %lx!"
                     "%lx instead of %lx\n",
                     addr, (data & 0xff), cur);
  }
  data = (data & ~0xff) | new;
  if (verbose) fprintf (stderr, "new at %lx: %lx\n", addr, data);
  if (ptrace_set_text(cpid, (void *) addr, (void *) data)) {
    signal_and_error(cpid, "modify_probe in pid %d: "
                     "failed to POKETEXT at %lx new val=%lx with errno %d\n",
                     cpid, addr, data, errno);
  };
}

static inline bool is_enabled(signed long data)
{
  return (data > 0);
}

// returns true if and only if "is_enabled" state changes
static inline bool modify_semaphore(pid_t cpid, bool enable,
                                            unsigned long addr)
{
  errno = 0;
  signed long cur_data = ptrace_get_data(cpid, (void *) addr);
  if (errno != 0) {
    signal_and_error(cpid, "modify_semaphore for probe in pid %d:\n\
                                   failed to PEEKDATA at %lx with errno %d\n",
                     cpid, addr, errno);
  }
  if (cur_data < 0)
    raise_error("Negative value %lx of semaphore at %lx in pid %d\n",
                cur_data, addr, cpid);
  if (verbose) fprintf (stderr, "old at %lx: %lx\n", addr, cur_data);
  signed long delta = enable ? 1: -1;
  signed long new_data = cur_data+delta;
  if (verbose) fprintf (stderr, "new at %lx: %lx\n", addr, new_data);
  if (new_data < 0)
    raise_error("modify_semaphore for probe in pid %d:"
                "Someone tried to disable a probe that is already disabled."
                "Cannot set negative value %lx for semaphore at %lx.\n",
                cpid, new_data, addr);
  if (ptrace_set_data(cpid, (void *) addr, (void *) new_data)) {
    signal_and_error(cpid, "modify_semaphore for probe in pid %d:"
                     "failed to POKEDATA at %lx new val=%lx with errno %d\n",
                     cpid, addr, new_data, errno);
  }
  return (is_enabled(cur_data) != is_enabled(new_data));
}

static inline int get_semaphore(pid_t cpid, struct probe_note *note)
{
  unsigned long addr = note->semaphore;
  errno = 0;
  signed long data = ptrace_get_data(cpid, (void *) addr);
  if (errno != 0) {
    signal_and_error(cpid, "is_enabled probe %s in pid %d: "
                     "failed to PEEKDATA at %lx with errno %d\n",
                     note->name, cpid, addr, errno);
  }
  if (verbose) fprintf (stderr, "semaphore at %lx = %lx\n", addr, data);
  if (data < 0)
    raise_error("Negative value %lx of semaphore at %lx in pid %d\n",
                data, addr, cpid);
  return is_enabled(data);
}

static inline void update_probe(pid_t cpid, struct probe_note *note,
                                bool enable)
{
  if (modify_semaphore(cpid, enable, note->semaphore))
    modify_probe(cpid, note->offset, enable);
}

static inline void set_all (struct probe_notes *notes, pid_t cpid, int enable)
{
  for (int i = 0; i < notes->num_probes; i++) {
      update_probe(cpid, notes->probe_notes[i], enable);
  }
}

/* ptrace calls, nothing specific to probes */
static inline pid_t start (char **argv)
{
  pid_t cpid = fork();
  if(cpid==-1) {
    raise_error("error doing fork\n");
  }

  if(cpid==0) {
    if (ptrace_traceme()) {
      raise_error("ptrace traceme error\n");
    }
    errno = 0;
    execv(argv[0], argv);

    /* only get here on an exec error */
    if (errno == ENOENT)
      raise_error("error running exec: program not found\n");
    else if (errno == ENOMEM)
      raise_error("error running exec: not enough memory\n");
    else
      raise_error("error running exec\n");
  }

  int status = 0;
  wait(&status);
  if(!WIFSTOPPED(status)) {
    signal_and_error(cpid, "not stopped %d\n", status);
  }
  return cpid;
}

static inline void attach (pid_t cpid)
{
  if(ptrace_attach(cpid)) {
    raise_error("ptrace attach %d, error=%d\n", cpid, errno);
  }

  int status = 0;
  pid_t res = waitpid(cpid, &status, WUNTRACED);
  if ((res != cpid) || !(WIFSTOPPED(status)) ) {
    raise_error ("Unexpected wait result res %d stat %x\n",res,status);
  }
}

static inline void detach (pid_t cpid)
{
  /*
  if(ptrace_cont(cpid)==-1) {
    signal_and_error(cpid,
                     "could not continue, errno=%d\n", errno);
  }
  */
  if (ptrace_detach(cpid)) {
    signal_and_error(cpid, "could not detach %d, errno=%d\n", cpid, errno);
  }
}

/*  OCaml interface: manipulate ocaml values, mind the GC,
    and call regular C functions */

CAMLprim value caml_probes_lib_start (value v_argv)
{
  CAMLparam1(v_argv); /* string array */
  int argc = Wosize_val(v_argv);
  if (verbose) fprintf(stderr, "start: argc=%d\n", argc);

  if (argc < 1) {
    raise_error("Missing executable name\n");
  }
  char ** argv = (char **) malloc ((argc + 1 /* for NULL */)
                                   * sizeof(char *));
  for (int i = 0; i < argc; i++) {
    argv[i] = strdup(String_val(Field(v_argv, i)));
    if (verbose) fprintf(stderr, "start: argv[%d]=%s\n", i, argv[i]);
  }
  argv[argc] = NULL;

  /* CR-soon mshinwell: We should think about whether we should release the
     runtime lock here */

  pid_t cpid = start(argv);

  for (int i = 0; i < argc; i++) {
    free(argv[i]);
  }
  free (argv);
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
#define Probe_notes_val(v) (*((struct probe_notes **) Data_custom_val(v)))

CAMLprim value caml_probes_lib_read_notes (value v_filename)
{
  CAMLparam1(v_filename);
  char *filename = String_val(v_filename);

  struct probe_notes *res = malloc(sizeof(struct probe_notes));
  if(read_notes(filename, res)) {
    free(res);
    raise_error ("could not parse probe notes from %s\n", filename);
  }

  /* Allocating an OCaml custom block to hold the notes */
  value v_internal = caml_alloc_custom(&probe_notes_ops,
                                       sizeof(struct probe_notes *), 0, 1);
  Probe_notes_val(v_internal) = res;
  CAMLreturn(v_internal);
}

CAMLprim value caml_probes_lib_get_names (value v_internal)
{
  CAMLparam1(v_internal);
  CAMLlocal2(v_names, v_name);

  struct probe_notes *notes = Probe_notes_val(v_internal);
  size_t n = notes->num_probes;
  v_names = caml_alloc(n,0);
  for (int i = 0; i < n; i++) {
    v_name = caml_copy_string(notes->probe_notes[i]->name);
    Store_field(v_names, i, v_name);
  }
  CAMLreturn(v_names);
}

CAMLprim value caml_probes_lib_get_states (value v_internal, value v_pid)
{
  CAMLparam1(v_internal);
  CAMLlocal1(v_states);
  pid_t cpid = Long_val(v_pid);

  struct probe_notes *notes = Probe_notes_val(v_internal);
  size_t n = notes->num_probes;
  v_states = caml_alloc(n,0);
  int b;
  for (int i = 0; i < n; i++) {
    b = get_semaphore(cpid, notes->probe_notes[i]);
    Store_field(v_states, i, Val_bool(b));
  }
  CAMLreturn(v_states);
}

CAMLprim value caml_probes_lib_update (value v_internal, value v_pid,
                                       value v_name, value v_enable)
{
  CAMLparam2(v_internal, v_name);
  pid_t cpid = Long_val(v_pid);
  int enable = Bool_val(v_enable);
  char *name = String_val(v_name);
  struct probe_notes *notes = Probe_notes_val(v_internal);
  // CR-soon gyorsh: update by index, not name, to avoid scanning probe_notes
  // array for each name.
  // For it to be efficient, avoid multiple calls to this stub (a call per index
  // with the same name) unless the call can be made very cheap,
  // and avoid allocation of another array for the indexes just for the update.
  // Approach: when creating
  // It matter if there are many probes that are enabled/disabled often while
  // the tracer remains attached (i.e., use  seize + interrupt
  // instead of traceme/attach ptrace calls).
  for (int i = 0; i < notes->num_probes; i++) {
    bool found = false;
    if (!strcmp(name, notes->probe_notes[i]->name)) {
      found = true;
      update_probe(cpid, notes->probe_notes[i], enable);
    }
    if (!found)
      if (verbose)
        fprintf(stderr, "update probe failed: probe named %s is not found\n",
                    name);
  }
  CAMLreturn(Val_unit);
}

CAMLprim value caml_probes_lib_set_all (value v_internal, value v_pid,
                                        value v_enable)
{
  CAMLparam1(v_internal);
  pid_t cpid = Long_val(v_pid);
  int enable = Bool_val(v_enable);
  struct probe_notes *notes = Probe_notes_val(v_internal);
  set_all(notes, cpid, enable);
  CAMLreturn(Val_unit);
}

CAMLprim value caml_probes_lib_attach_set_all_detach (value v_internal,
                                                      value v_pid,
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

CAMLprim value caml_probes_lib_trace_all (value v_internal, value v_argv)
{
  CAMLparam2(v_internal,v_argv);
  value v_pid = caml_probes_lib_start(v_argv);
  struct probe_notes *notes = Probe_notes_val(v_internal);
  pid_t cpid = Long_val(v_pid);
  set_all(notes, cpid, true);
  detach(cpid);
  CAMLreturn(Val_unit);
}

CAMLprim value caml_probes_lib_set_verbose(value v_bool)
{
  verbose = Bool_val(v_bool);
  return Val_unit;
}
