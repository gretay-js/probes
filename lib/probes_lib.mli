type t
(** Mutable representation of probes in the traced program. Not thread safe.
    Use with only one tracer thread. *)

(* A simple state machine checks that the process is stopped before trying to
   update the probes:

   (start | attach) . (update | get_probe_names | get_status )* . detach

   (attach . (update | get_probe_names | get_status )* . detach)*

   Not known *)

exception Error of string

type pid = int

(* CR mshinwell: I would add "type probe_name = string", it will help with
   legibility for types such as [actions] below *)

type probe_desc =
  { name : string;
    enabled : bool
  }

type action =
  | Enable
  | Disable

type actions =
  | All of action
  | Selected of (action * string) list

val create : prog:string -> bpf:bool -> t
(** Reads the entire elf binary [prog] and extracts probes descriptions from
    its stapstd .notes section. Memory and time are linear in the size of the
    binary, so can be slow for large binaries. Does not require the program
    to be running. *)

val attach : t -> pid -> check_prog:bool -> unit
(** Attach to the process with [pid], and stop it to allow probe update. If
    [check_prog] is true, raise if [get_exe pid] and the program name used to
    construct [t] do not match. *)

val start : t -> prog:string -> args:string list -> check_prog:bool -> unit
(** Execute the program using ptrace, but stop the process immediately as
    soon as it starts running, so that [update] can be called before any
    code runs that contains probes (to avoid a race condition). If [check_prog]
    is true, raise if [prog] and [t] do not match. *)

val update : t -> actions:actions -> unit
(** Enable/disable probes. Raise if not attached to any process. [update]
    writes to memory of the process that must have been already stopped by
    [attach] or [start]. [update] does not continue process execution and
    can be invoked more than once. Invoke [detach] to continue process
    execution after all updates are done. *)

val detach : t -> unit
(* CR mshinwell: I would move the explanatory paragraph here into the
   .ml file.  Most users won't need to know about that. *)
(** Let the process continue its execution and detach from it.

    After sending PTRACE_CONT signal to the child process, the parent needs
    to stop the child process again to make updates to probes, and the only
    way to stop is to send PTRACE_ATTACH. It means it is not useful to stay
    attached after continue, because the tracer cannot do anything with the
    probes. An alternative is to use PTRACE_SEIZE instead of PTRACE_ATTACH
    and then explicitly interrupt to stop the process. This way the tracer
    can remain attached to the child. (Is it required for bpf?) The advantage
    of detaching is that it allows another tool such as gdb to attach. Only
    one parent can be attached at any give time. *)

val trace_all : t -> prog:string -> args:string list -> unit
(* CR mshinwell: Say what the "." means or use OCaml notation *)
(** Equivalent to [start . update (All Enable) . detach] but only one C call
    and no allocation on the OCaml heap. *)

val attach_update_all_detach : t -> pid -> enable:bool -> unit
(** Equivalent to [attach pid . update (All enable) . detach pid] but only
    one C call and no allocation on the OCaml heap. *)

val verbose : bool ref
(* CR mshinwell: missing comment *)

val get_probe_names : t -> string array
(** Returns the names of probes available in the program associated with [t]. *)

val get_probe_states : t -> probe_desc array
(* CR mshinwell: Again, move the implementation paragraph into the .ml *)
(** Check which probes are enabled in the current process. Raise if not
    attached.

    Reads the value of probe semaphores in current process's memory. An
    alternative implementation (for example, if semaphores aren't in use),
    could be to check the instruction at the probe in the text section. *)

val get_exe : pid -> string
(** Utility to get the name of the binary executed by process [pid]. Read from
    /proc/pid/exe *)

val get_pid : t -> pid option
(* CR mshinwell: missing comment *)
