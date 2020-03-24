type t
(** Mutable representation of probes in the traced program. Not thread safe.
    Use with only one tracer thread. *)

(* A simple state machine checks that the process is stopped before trying to
   update the probes:

   (start | attach) . (update | get_probe_names | get_status )* . detach

   (attach . (update | get_probe_names | get_status )* . detach)*

   The state of the probes is not known after re-attaching, because another
   tracer process could have changed it. *)

exception Error of string

type pid = int

type probe_name = string

type probe_desc =
  { name : probe_name;
    enabled : bool
  }

type action =
  | Enable
  | Disable

type actions =
  | All of action
  | Selected of (action * probe_name) list

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
    soon as it starts running, so that [update] can be called before any code
    runs that contains probes (to avoid a race condition). If [check_prog] is
    true, raise if [prog] and [t] do not match. *)

val update : t -> actions:actions -> unit
(** Enable/disable probes. Raise if not attached to any process. [update]
    writes to memory of the process that must have been already stopped by
    [attach] or [start]. [update] does not continue process execution and can
    be invoked more than once. Invoke [detach] to continue process execution
    after all updates are done. *)

val detach : t -> unit
(** Let the process continue its execution and detach from it. *)

val trace_all : t -> prog:string -> args:string list -> unit
(** Equivalent to [start . update (All Enable) . detach] but only one C call
    and no allocation on the OCaml heap. *)

val attach_update_all_detach : t -> pid -> enable:bool -> unit
(** Equivalent to [attach pid ; update (All enable) ; detach pid] but only
    one C call and no allocation on the OCaml heap. *)

val set_verbose : bool -> unit
(** Control debug printing. *)

val get_probe_names : t -> probe_name array
(** Returns the names of probes available in the program associated with [t]. *)

val get_probe_states : t -> probe_desc array
(** Check which probes are enabled in the current process. Raise if not
    attached. *)

val get_exe : pid -> string
(** Utility to get the name of the binary executed by process [pid]. Read
    from /proc/pid/exe *)

val get_pid : t -> pid option
(** Return the id of the process associated with [t] if there is any, or
    None. *)
