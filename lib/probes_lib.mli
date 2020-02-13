type t

type action =
  | Enable
  | Disable

type actions =
  | All of action
  | Selected of (action * string) list

val attach : t -> pid:int -> t

val start : t -> argv:string list -> t

val update : t -> actions:actions -> t
(** enable/disable probes *)

val detach : t -> unit

val verbose : bool ref

val create : filename:string -> bpf:bool -> t
(** read probe notes from elf binary [filename] *)
