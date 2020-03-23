open Core
module P = Probes_lib

let set_verbose v = Probes_lib.verbose := v

(* CR-someday gyorsh: read from file what to enable and disable *)

let flag_actions =
  let to_string = function
    | P.Disable -> "disable"
    | P.Enable -> "enable"
  in
  let open Command.Param in
  let flag_all a =
    let s = to_string a in
    let name = sprintf "-%s-all" s in
    let doc = sprintf " %s all probes" s in
    flag ~full_flag_required:() name no_arg ~doc
    |> map ~f:(function
         | true -> Some (P.All a)
         | false -> None)
  in
  let check ~name = function
    | [] -> String.Set.empty
    | sl ->
        List.map ~f:(String.split ~on:',') sl
        |> List.concat
        |> List.fold ~init:String.Set.empty ~f:(fun acc x ->
               if String.Set.mem acc x then
                 failwithf
                   "Probe name %s appears more than once as an argument of \
                    %s"
                   x name ();
               String.Set.add acc x)
  in
  let flag_list a =
    let s = to_string a in
    let name = "-" ^ s in
    let doc =
      sprintf
        "name %s probes specified by name (or a comma separated list of \
         names)"
        s
    in
    flag ~full_flag_required:() name (listed string) ~doc
    |> map ~f:(check ~name)
  in
  let check_disjoint enable disable =
    (* Detect when the same probe name appears twice under incompatible
       actions Enable and Disable. *)
    let both = String.Set.inter enable disable in
    if not (Set.is_empty both) then
      failwith
        (sprintf "Probe names appear in both -enable and -disable: %s"
           (String.concat ~sep:" " (String.Set.to_list both)))
  in
  let map_action a names =
    String.Set.to_list names |> List.map ~f:(fun s -> (a, s))
  in
  let flag_selected =
    Command.Let_syntax.(
      let%map enable = flag_list P.Enable
      and disable = flag_list P.Disable in
      if String.Set.is_empty enable && String.Set.is_empty disable then None
      else (
        check_disjoint enable disable;
        let actions =
          map_action P.Enable enable @ map_action P.Disable disable
        in
        Some (P.Selected actions) ))
  in
  choose_one
    [flag_all P.Enable; flag_all P.Disable; flag_selected]
    ~if_nothing_chosen:(Default_to (P.All P.Enable))

(* CR gyorsh: the functionality for bpf is in, but the command line interface
   isn't implemented yet. Requires setuid privilleages on this tool to run. *)
(* CR mshinwell: Don't show the BPF stuff to the user yet, we can expose that
   in due course when we decide how to proceed on that front. *)
let flag_bpf =
  Command.Param.(
    flag "-bpf" no_arg
      ~doc:
        " kernel-space tracing using a predefined eBPF handler (requires \
         setuid)")

let flag_v =
  Command.Param.(
    flag "-verbose" ~aliases:["-v"] no_arg
      ~doc:" print lots of info for debug")

let flag_q =
  Command.Param.(
    flag "-quiet" ~aliases:["-q"] no_arg ~doc:" don't print anything")

let flag_prog =
  Command.Param.(
    flag "prog"
      (required Filename.arg_type)
      ~doc:"filename executable with statically-defined probes")

let flag_pid =
  Command.Param.(flag "-pid" (required int) ~doc:"int process id")

let attach_command =
  Command.basic
    ~summary:
      "Attach to a running process and enable/disable specified probes"
    ~readme:(fun () ->
      "After updating the probes, detach from the process and return,\n\
       letting the process continue normally.\n\
       If '-bpf' is specified, detaching TBD.") (* CR mshinwell: same here *)
    Command.Let_syntax.(
      let%map v = flag_v
      and q = flag_q
      and pid = flag_pid
      and actions = flag_actions
      and bpf = flag_bpf in
      if v then set_verbose true;
      if q then set_verbose false;
      fun () -> Main.attach ~pid ~bpf ~actions)

let info_command =
  Command.basic
    ~summary:
      "Attach to a running process and print for each probe whether it is \
       enabled/disabled"
    Command.Let_syntax.(
      let%map v = flag_v
      and q = flag_q
      and pid = flag_pid
      and bpf = flag_bpf in
      if v then set_verbose true;
      if q then set_verbose false;
      fun () -> Main.info ~pid ~bpf)

let trace_command =
  Command.basic  (* CR mshinwell: remove BPF reference here too *)
    ~summary:"Execute the program with probes enabled as specified"
    ~readme:(fun () ->
      "Guarantees that all specified probes are enabled before the program \
       starts.\n\
       Start execution of the program in a separate child process with \n\
       probes enabled as specified. \n\
       Then, detach from the child process and return, while the child \
       process continues program execution normally.\n\
       If '-bpf' is specified, detaching is TBD.\n\
       User can call 'attach' on the running process to enable/disable \
       probes again. \n\
       The need for 'trace' command arises when tracing probes right at the \
       program start.\n\
       Note that if the program invokes `exec` on the same binary,\n\
       the resulting process will not have any probes enabled.\n\
       All threads created by the program will have the same probes enabled.\n")
    Command.Let_syntax.(
      let%map v = flag_v
      and q = flag_q
      and prog = flag_prog
      and bpf = flag_bpf
      and actions = flag_actions
      and args =
        Command.Param.(
          flag "--" escape ~doc:"args pass the rest to the program")
      in
      let args = Option.value ~default:[] args in
      if v then set_verbose true;
      if q then set_verbose false;
      fun () -> Main.trace ~prog ~args ~bpf ~actions)

let main_command =
  Command.group
    ~summary:"Statically-defined probes for tracing native OCaml programs"
    [ ("trace", trace_command);
      ("attach", attach_command);
      ("info", info_command) ]

let run ?version ?build_info () =
  set_verbose false;
  Command.run ?version ?build_info main_command
