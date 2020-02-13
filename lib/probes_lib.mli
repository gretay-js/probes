type t

type action = Enable | Disable

type actions = All of action | Selected of (action * string) list

val attach : pid:int -> t
val start : prog:string -> args:string list -> t
val update : t -> actions -> unit
val detach : t -> unit

