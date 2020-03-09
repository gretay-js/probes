let verbose = ref false

exception Error of string

let (_ : unit) =
  Callback.register_exception "caml_probes_lib_stub_exception"
    (Error "any string")

type pid = int

type internal
(** custom block, includes information such as probe offset, semaphore
    offset, and the location of arguments for the bpf handler.*)

external stub_start : string list -> pid = "caml_probes_lib_start"

external stub_attach : pid -> unit = "caml_probes_lib_attach"

external stub_detach : pid -> unit = "caml_probes_lib_detach"

external stub_read_notes : elf_filename:string -> internal
  = "caml_probes_lib_read_notes"

external stub_get_names : internal -> string array
  = "caml_probes_lib_get_names"

external stub_get_states : internal -> pid -> bool array
  = "caml_probes_lib_get_states"

external stub_set_all : internal -> pid -> enabled:bool -> unit
  = "caml_probes_lib_set_all"

external stub_set_one : internal -> pid -> string -> enable:bool -> unit
  = "caml_probes_lib_update"

type probe_desc =
  { name : string;
    enabled : bool
  }

type prog_status =
  | Attached of pid
  | Not_attached

type t =
  { status : prog_status;
    prog : string;
    bpf : bool;
    probe_names : string array;
    internal : internal  (** probe details *)
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
  if bpf then user_error "Not implemented: bpf";
  if !verbose then Printf.printf "create: read probe notes from %d\n" prog;
  let internal = stub_read_notes ~elf_filename:prog in
  let probe_names = stub_get_names internal in
  if !verbose then
    Array.iteri (fun i p -> printf "%d:%s\n" i p.name) t.probes;
  { pid = Not_attached; prog; bpf; probe_names; internal }

let attach t ~pid ~check_prog =
  if !verbose then printf "attach to pid %d\n" pid;
  ( if check_prog then
    let exe = get_exe pid in
    if not (String.equal exe t.prog) then
      raise
        (Error
           (sprintf
              "Attach: exe of pid=%d is %s but probe notes come from %s\n"
              pid exe t.prog)) );
  if !verbose then printf "pid %d executing %s\n" pid prog;
  match t.pid with
  | Attached existing_pid ->
      if existing_pid = pid then
        raise (Error (sprintf "Already attached to %d" pid))
      else
        raise
          (Error
             (sprintf "Cannot attach to %d, already attached to %d" pid
                existing_pid))
  | Not_attached ->
      stub_attach pid;
      t.pid = Attached pid;
      (* Update [t.pid] after stub to ensure stub didn't raise *)
      ()

let start t ~prog ~args ~bpf ~check_prog =
  if !verbose then printf !"start %s %{sexp:string list}\n" prog args;
  if check_prog then
    if not (String.equal prog t.prog) then
      raise
        (Error
           (sprintf "Start: prog is %s but probe notes come from %s\n" prog
              t.prog));
  match t.pid with
  | Attached existing_pid ->
      raise
        (Error
           (sprintf "Cannot start %s, already attached to %d" prog
              existing_pid))
  | Not_attached ->
      let pid = stub_start prog :: args in
      t.pid = Attached pid;
      (* Update [t.pid] after stub to ensure stub didn't raise *)
      ()

(* CR-soon gyorsh: avoid unnecessary writes to memory when the current state
   of the probe is already as needed. *)
(* CR-soon gyorsh: avoid multiple C calls by passing all probes that need to
   be modified at once array, but then we need to avoid extra allocation. *)
(* CR-soon gyorsh: do we need a setting to configure how to respond if the
   state does not change? *)
let update t ~actions =
  match pid with
  | Not_attached -> raise (Error "update failed: no pid\n")
  | Attached pid -> (
      let enable a = function
        | Enable -> true
        | Disable -> false
      in
      match actions with
      | All action -> stub_set_all t.internal pid (enable action)
      | Selected l ->
          List.iter l ~f:(fun (action, name) ->
              stub_set_one t.internal pid name (enable action)) )

(* CR-soon gyorsh: avoid unnecessary writes to memory when the current state
   of the probe is arleady as needed. *)
let get_probe_states t ~actions =
  match pid with
  | Not_attached -> raise (Error "cannot get probe states: no pid\n")
  | Attached pid ->
      Array.map t.probe_names (stub_get_states t.internal pid)
        ~f:(fun (name, enabled) -> { name; enabled })

let detach t =
  match t.pid with
  | Not_attached -> raise (Error "detach failed: no pid\n")
  | Attached pid ->
      stub_detach t.pid;
      t.pid <- Not Attached

let get_probe_names t = t.probe_names

let get_exe ~pid = Unix.readlink (sprintf "/proc/%d/exe" pid)
