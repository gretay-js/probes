let verbose = ref false

external probe_trace : string list -> int = "caml_probe_trace"

external probe_attach : int -> int = "caml_probe_attach"

external probe_read_notes : string -> unit = "caml_probe_read_notes"

type t =
  { pid : int;
    prog : string;
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

let create ~filename ~bpf =
  if bpf then user_error "Not implemented";
  { pid = None; prog = filename; bpf }

let attach ~prog ~pid ~bpf =
  if !verbose then
    printf "attach to pid %d and update probes in %s\n" pid prog;

  { pid; prog; bpf }

let start ~prog ~args ~bpf =
  printf !"trace %s %{sexp:string list}\n" prog args;
  if bpf then user_error "Not implemented";
  { pid = 0; prog; bpf }

let update _t ~actions:_ = user_error "Not implemented"

let detach _t = user_error "Not implemented"
