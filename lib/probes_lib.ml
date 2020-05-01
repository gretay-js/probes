exception Error of string

let (_ : unit) =
  Callback.register_exception "caml_probes_lib_stub_exception"
    (Error "any string")

type pid = int

(** custom block, includes information such as probe offset, semaphore
    offset, and the location of arguments for the bpf handler. *)
type internal

type probe_name = string

(** Start addresses of the segments *)
type mmap =
  { text : int64;
    data : int64
  }

external stub_realpath : string -> string = "caml_probes_lib_realpath"

external stub_start : argv:string array -> pid = "caml_probes_lib_start"

external stub_attach : pid -> unit = "caml_probes_lib_attach"

external stub_detach : pid -> unit = "caml_probes_lib_detach"

external stub_read_notes : elf_filename:string -> internal
  = "caml_probes_lib_read_notes"

external stub_get_names : internal -> probe_name array
  = "caml_probes_lib_get_names"

external stub_pie : internal -> bool = "caml_probes_lib_pie" [@@noalloc]

external stub_get_states :
  internal -> pid -> mmap option -> probe_name array -> bool array
  = "caml_probes_lib_get_states"

external stub_set_all :
  internal -> pid -> mmap option -> probe_name array -> enable:bool -> unit
  = "caml_probes_lib_set_all"

external stub_set_one :
  internal -> pid -> mmap option -> probe_name -> enable:bool -> unit
  = "caml_probes_lib_update"

external stub_trace_all :
  internal -> argv:string array -> probe_name array -> unit
  = "caml_probes_lib_trace_all"

external stub_attach_set_all_detach :
  internal -> pid -> probe_name array -> enable:bool -> unit
  = "caml_probes_lib_attach_set_all_detach"

external stub_verbose : bool -> unit = "caml_probes_lib_set_verbose"

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

type process =
  { id : pid;
    mmap : mmap option
        (** Some memory map for a position independent executable, None
            otherwise *)
  }

type status =
  | Attached of process
  | Not_attached

type t =
  { mutable status : status;
    prog : string;
    bpf : bool;
    probe_names : probe_name array;
    pie : bool;
    internal : internal  (** probe details *)
  }

let verbose = ref false

let set_verbose b =
  verbose := b;
  stub_verbose b;
  ()

let user_error fmt =
  Format.kfprintf
    (fun _ -> exit 321)
    Format.err_formatter
    ("@?Error: " ^^ fmt ^^ "@.")

let get_exe pid = Unix.readlink (Printf.sprintf "/proc/%d/exe" pid)

let (_ : unit) =
  Callback.register_exception "caml_probes_lib_stub_exception"
    (Error "any string")

let create ~prog ~bpf =
  let prog = stub_realpath prog in
  if bpf then user_error "Not implemented: bpf";
  if !verbose then Printf.printf "create: read probe notes from %s\n" prog;
  let internal = stub_read_notes ~elf_filename:prog in
  let probe_names =
    stub_get_names internal
    (* dedup *)
    |> Array.to_list
    |> List.sort_uniq String.compare
    |> Array.of_list
  in
  let pie = stub_pie internal in
  if !verbose then
    Array.iteri (fun i name -> Printf.printf "%d:%s\n" i name) probe_names;
  { status = Not_attached; prog; bpf; probe_names; pie; internal }

(* Read memory map of pid from /proc/pid/maps file, parse it, and find the
   offset of text and data sections of prog. The tracer must be attach to the
   process and the process must be stopped. *)
let read_mmap pid prog =
  let filename = "/proc/" ^ string_of_int pid ^ "/maps" in
  let oc = open_in filename in
  let text = ref None in
  let data = ref None in
  let update p s =
    match Int64.of_string_opt ("0x" ^ s) with
    | None ->
        raise
          (Error (Printf.sprintf "Unexpected format of %s: %s" filename s))
    | Some _ as a -> (
        match !p with
        | None -> p := a
        | Some _ ->
            raise
              (Error
                 (Printf.sprintf
                    "Unexpected format of %s: duplicate segment at %s"
                    filename s)) )
  in
  let parse line =
    (* parse lines in the format: start-end rwxp offset xx:yy fd name *)
    if !verbose then Printf.printf "[mmap] %s" line;
    let len_line = String.length line in
    let len_prog = String.length prog in
    if len_line < len_prog then ()
    else
      let name = String.sub line (len_line - len_prog) len_prog in
      if !verbose then Printf.printf "%s\nname:%s\n" line name;
      if String.equal prog name then
        match (String.index_opt line '-', String.index_opt line ' ') with
        | None, _ | _, None ->
            raise
              (Error
                 (Printf.sprintf "Unexpectedd format of %s:\n%s" filename
                    line))
        | Some i, Some j -> (
            let start = String.sub line 0 i in
            let perm = String.sub line (j + 1) 4 in
            if !verbose then Printf.printf "start:%s\nperm=%s\n" start perm;
            match perm with
            | "r-xp" -> update text start
            | "rw-p" -> update data start
            | _ -> () )
  in
  ( try
      while true do
        parse (input_line oc)
      done
    with
  | End_of_file -> close_in oc
  | e ->
      close_in oc;
      raise e );
  match (!text, !data) with
  | Some text, Some data -> { text; data }
  | None, _ ->
      raise
        (Error
           (Printf.sprintf
              "Unexpected format of %s: missing text segment start" filename))
  | _, None ->
      raise
        (Error
           (Printf.sprintf
              "Unexpected format of %s: missing data segment start" filename))

(* Updates [t.status] after stub to ensure stub didn't raise *)
let set_status t id =
  let mmap =
    match t.pie with
    | false -> None
    | true -> Some (read_mmap id t.prog)
  in
  t.status <- Attached { id; mmap }

let attach t pid ~check_prog =
  if !verbose then Printf.printf "attach to pid %d\n" pid;
  ( if check_prog then
    let exe = get_exe pid in
    if not (String.equal exe t.prog) then
      raise
        (Error
           (Printf.sprintf
              "Attach: exe of pid=%d is %s but probe notes come from %s\n"
              pid exe t.prog)) );
  if !verbose then Printf.printf "pid %d executing %s\n" pid t.prog;
  match t.status with
  | Attached existing_p ->
      if existing_p.id = pid then
        raise (Error (Printf.sprintf "Already attached to %d" pid))
      else
        raise
          (Error
             (Printf.sprintf "Cannot attach to %d, already attached to %d"
                pid existing_p.id))
  | Not_attached ->
      stub_attach pid;
      set_status t pid;
      ()

let start t ~prog ~args ~check_prog =
  if !verbose then (
    Printf.printf "start";
    List.iter (fun s -> Printf.printf " %s" s) (prog :: args);
    Printf.printf "\n" );
  if check_prog then
    if not (String.equal prog t.prog) then
      raise
        (Error
           (Printf.sprintf "Start: prog is %s but probe notes come from %s\n"
              prog t.prog));
  match t.status with
  | Attached existing_p ->
      raise
        (Error
           (Printf.sprintf "Cannot start %s, already attached to %d" prog
              existing_p.id))
  | Not_attached ->
      let pid = stub_start ~argv:(Array.of_list (prog :: args)) in
      set_status t pid;
      ()

(* CR-soon gyorsh: avoid unnecessary writes to memory when the current state
   of the probe is already as needed. *)
(* CR-soon gyorsh: avoid multiple C calls by passing all probes that need to
   be modified at once array, but then we need to avoid extra allocation. *)
(* CR-soon gyorsh: do we need a setting to configure how to respond if the
   state does not change? *)
let enable = function
  | Enable -> true
  | Disable -> false

let update t ~actions =
  match t.status with
  | Not_attached -> raise (Error "update failed: no pid\n")
  | Attached p -> (
      match actions with
      | All action ->
          if !verbose then
            Printf.printf "stub_set_all %d %b\n" p.id (enable action);
          stub_set_all t.internal p.id p.mmap t.probe_names
            ~enable:(enable action)
      | Selected l ->
          List.iter
            (fun (action, name) ->
              stub_set_one t.internal p.id p.mmap name
                ~enable:(enable action))
            l )

(* Reads the value of probe semaphores in current process's memory. An
   alternative implementation (for example, if semaphores aren't in use),
   could be to check the instruction at the probe in the text section. *)
(* CR-soon gyorsh: avoid unnecessary writes to memory when the current state
   of the probe is arleady as needed. *)
let get_probe_states t =
  match t.status with
  | Not_attached -> raise (Error "cannot get probe states: no pid\n")
  | Attached p ->
      Array.map2
        (fun name enabled -> { name; enabled })
        t.probe_names
        (stub_get_states t.internal p.id p.mmap t.probe_names)

(* We use PTRACE_DETACH and not PTRACE_CONT: After sending PTRACE_CONT signal
   to the child process, the parent needs to stop the child process again to
   make updates to probes, and the only way to stop is to send PTRACE_ATTACH.
   It means it is not useful to stay attached after continue, because the
   tracer cannot do anything with the probes. An alternative is to use
   PTRACE_SEIZE instead of PTRACE_ATTACH and then explicitly interrupt to
   stop the process. This way the tracer can remain attached to the child.
   (Is it required for bpf?) The advantage of detaching is that it allows
   another tool such as gdb to attach. Only one parent can be attached at any
   give time. *)
let detach t =
  match t.status with
  | Not_attached -> raise (Error "detach failed: no pid\n")
  | Attached p ->
      stub_detach p.id;
      t.status <- Not_attached

let get_probe_names t = t.probe_names

let get_pid t =
  match t.status with
  | Not_attached -> None
  | Attached p -> Some p.id

let trace_all t ~prog ~args =
  let argv = prog :: args in
  match t.status with
  | Attached existing_p ->
      raise
        (Error
           (Printf.sprintf "trace_all %s:\n already attached to %d \n"
              (String.concat " " argv) existing_p.id))
  | Not_attached ->
      if t.pie then (
        start t ~prog ~args ~check_prog:false;
        update t ~actions:(All Enable);
        detach t )
      else (
        if !verbose then
          Printf.printf "stub_trace_all %s\n" (String.concat " " argv);
        stub_trace_all t.internal ~argv:(Array.of_list argv) t.probe_names )

let attach_update_all_detach t pid ~enable =
  match t.status with
  | Attached existing_p ->
      raise
        (Error
           (Printf.sprintf
              "attach_and_set_all pid=%d: already attached to %d \n" pid
              existing_p.id))
  | Not_attached ->
      if t.pie then (
        attach t pid ~check_prog:false;
        update t ~actions:(All (if enable then Enable else Disable));
        detach t )
      else (
        if !verbose then
          Printf.printf "stub_attach_set_all_detach %d %b\n" pid enable;
        stub_attach_set_all_detach t.internal pid t.probe_names ~enable )
