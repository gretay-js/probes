type t
(** Mutable representation of probes in the traced program *)
(** Not thread safe. Use with only one tracer thread. *)

exception Error of string

type state =
  | Enabled
  | Disabled
  | Unknown

type probe_desc =
  { name : string;
    state : state
  }

type action =
  | Enable
  | Disable
  | Toggle
  | Skip

type actions =
  | All of action
  | Selected of (action * string) list

val attach : t -> pid:int -> check_prog:bool -> unit
(** Attach to the process with [pid], and stop it to allow probe update.
    If [check_prog] is true, ensures that
    [get_prog pid] and the program name used to construct [t] match,
    before trying to attach.
*)

val start : t -> prog:string -> args:string list -> check_prog:bool -> unit
(** Execute the program using ptrace, but stop the process to update the probes.
    If [check_prog] is true, ensure that prog and [t] match.
*)

val update_and_detach : t -> actions:actions -> unit
(** Enable/disable probes, continue the process, *)

val verbose : bool ref

val create : prog:string ->  bpf:bool -> t
(** Reads the entire elf binary [prog] and extracts probes descriptions from
    its stapstd .notes section. Memory and time are linear in the size of the
    binary, so can be slow for large binaries. Does not require the program
    to be running. *)

val get_probe_names : t -> probe_desc array
(** Returns probe description  *)

val get_status_probes : t -> probe_desc array
(** Check the current process which probes are enabled. *)

val prog : pid:int -> string
(** Utility to get the name of the binary executed by proces [pid]. Read from
    /proc/pid/exe *)
