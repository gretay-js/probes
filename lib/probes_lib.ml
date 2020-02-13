open Core

let verbose = ref false

type t =
  { pid : int;
    prog : Filename.t;
    bpf : bool
  }

type action =
  | Enable
  | Disable

type actions =
  | All of action
  | Selected of (action * string) list

let user_error fmt =
  Format.kfprintf
    (fun _ -> exit 321)
    Format.err_formatter
    ("@?Error: " ^^ fmt ^^ "@.")

let attach ~prog ~pid ~bpf =
  if !verbose then
    printf "attach to pid %d and update probes in %s\n" pid prog;
  if bpf then user_error "Not implemented";
  { pid; prog; bpf }

let start ~prog ~args ~bpf =
  printf !"trace %s %{sexp:string list}\n" prog args;
  if bpf then user_error "Not implemented";
  { pid = 0; prog; bpf }

let update _t ~actions:_ = user_error "Not implemented"

let detach _t = user_error "Not implemented"
