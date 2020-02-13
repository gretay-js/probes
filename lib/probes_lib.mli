type t

type action =
  | Enable
  | Disable

type actions =
  | All of action
  | Selected of (action * string) list

val attach : prog:Core.Filename.t -> pid:int -> bpf:bool -> t

val start : prog:Core.Filename.t -> args:string list -> bpf:bool -> t

val update : t -> actions:actions -> t

val detach : t -> unit

val verbose : bool ref
