let verbose = ref false

exception Error of string

let _ =
  Callback.register_exception "caml_probes_lib_stub_exception"
    (Error "any string")

type pid = int

type internal
  (** custom block, includes information such as
      probe offset, semaphore offset, and the location of arguments
      for the bpf handler.*)


external stub_start : string list -> pid = "caml_probes_lib_start"

external stub_attach : pid -> unit = "caml_probes_lib_attach"

external stub_detach : pid -> unit = "caml_probes_lib_detach"

external stub_read_notes : string -> internal
  = "caml_probes_lib_read_notes"

external stub_get_names : internal -> string array = "caml_probes_lib_get_names"

external stub_update : pid -> string -> unit
  = "caml_probes_lib_detach"

type t =
  { pid : int option; (** [None] means not attached *)
    prog : string;
    bpf : bool;
    probes : probe_desc array;
    internal : internal;
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

let create ~prog ~bpf =
  if bpf then user_error "Not implemented";
  if !verbose then printf "create: read probe notes from %d\n" prog;
  let internal = stub_read_notes prog in
  let probes = Array.map (fun name -> {name;state=Unknown})
                 (stub_get_names internal)
  in
  if !verbose then
    Array.iteri (fun i p -> printf "%d:%s\n" i p.name) t.probes;
  { pid=None; prog; bpf; probes; internal }

let attach t ~pid ~check_prog =
  if !verbose then printf "attach to pid %d\n" pid;
  if check_prog then (
    let exe = (get_exe pid) in
    if not ( String.equal exe t.prog) then
      raise (Error (sprintf "Attach: exe of pid=%d is %s but probe notes come from %s\n"
                      pid exe t.prog));
  );
  if !verbose then printf "pid %d executing %s\n" pid prog;
  match t.pid with
  | Some existing_pid ->
    if existing_pid = pid then
      raise (Error (sprintf "Already attached to %d" pid))
    else
      raise (Error (sprintf "Cannot attach to %d, already attached to %d")
               pid existing_pid)
  | None ->
    stub_attach pid;
    t.pid = Some pid;   (* Update [t.pid] after stub to ensure it didn't raise *)
    ()

let start ~prog ~args ~bpf =
  if !verbose then printf !"start %s %{sexp:string list}\n" prog args;
  let pid = stub_start prog :: args in
  create ~prog ~bpf ~pid

(* CR-soon gyorsh: avoid unnecessary writes to memory when the
   current state of the probe is *)
let update t ~actions =
  match pid with
  | None -> raise (Error "update failed: no pid\n")
  | Some pid ->
    let update_p newval p =
      if !verbose then (
        if p.is_enabled = newval t
      );
      p.is_enabled <- enable
    in
    match actions with
    | All action ->
      let is_enabled = match action with
        | Enable -> true
        | Disable -> false
      in
      Array.iter (update_p is_enabled) t.probes
    | Selected of (action * string) list

                    stub_update t.pid probes

let detach t =
  match t.pid with
  | Some pid -> stub_detach t.pid; t.pid <- None
  | None -> raise (Error "detach failed: no pid\n")

let get_probes t = t.probes

let get_exe ~pid = Unix.readlink (sprintf "/proc/%d/exe" pid)
