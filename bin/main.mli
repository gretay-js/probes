val attach : pid:int -> bpf:bool -> enable:bool -> unit

val trace : prog:string -> args:string list -> bpf:bool -> unit

val info : pid:int -> bpf:bool -> unit
