open Core

let set_verbose v = Probes_lib.verbose := v

(* CR gyorsh: more than once -enable -disable flags *)
(* CR gyorsh: read from file what to enable and disable *)

(* let flag_enable_all =
 *     flag "-enable-all" no_arg ~doc:" enable all probes"
 *     |> map ~f:(function
 *       | true -> Some (All Enable)
 *       | false -> None)
 *
 * let flag_disable_all =
 *   flag "-disable-all" no_arg
 *     ~doc:" disable all probes"
 *   |> map ~f:(function
 *     | true -> Some (All Disable)
 *     | false -> None) *)

(* let flag_enable =
 *   Command.Param.(
 *     flag "-enable" (optional string)
 *       ~doc:"name enable probes specified by name (or a comma separated list of names)"
 *     |> map ~f:String.split ~sep:','
 *     |> map ~f:(List.map ~f:(fun name -> (Enable name)) list_of_names))
 *
 * let flag_disable =
 *   Command.Param.(
 *     flag "-disable" (optional string)
 *       ~doc:"name disable probes specified by name (or a comma separated list of names)"
 *     |> map ~f:(function
 *       | None -> None
 *       | Some s ->
 *         String.split ~sep:',' s
 *         |> List.map ~f:(fun name -> (Disable name)) list_of_names
 *         |> Some))
 *
 * let flag_actions =
 *   let open Command.Param in
 *
 *   let flag_selected =
 *     Command.Let_syntax.(
 *       let%map enable = flag_enable
 *       and disable = flag_disable
 *       in
 *       (Selected (Option.both enable @ disable)))
 *   in
 *   let flag_selected =
 *     flag "-enable" arg_string
 *       ~doc:" use md5 per compilation unit only to detect source changes"
 *     |> map ~f:(function
 *       | true -> Some (Crcs.Config.mk ~func:false ~unit:true)
 *       | false -> None)
 *   in
 *   choose_one
 *     [flag_enable_all; flag_disable_all; flag_selected]
 *     ~if_nothing_chosen:(Default_to (All Enable)) *)

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

(* CR gyorsh: the functionality for bpf is in, but the command line interface
   isn't implemented yet. Requires setuid privilleages on this tool to run. *)

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
       If '-bpf' is specified, detaching TBD.")
    Command.Let_syntax.(
      let%map v = flag_v
      and q = flag_q
      and pid = flag_pid
      and bpf = flag_bpf in
      if v then set_verbose true;
      if q then set_verbose false;
      fun () -> Main.attach ~pid ~bpf)

let trace_command =
  Command.basic
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
      and args =
        Command.Param.(
          flag "--" escape ~doc:"args pass the rest to the program")
      in
      let args = Option.value ~default:[] args in
      if v then set_verbose true;
      if q then set_verbose false;
      fun () -> Main.trace ~prog ~args ~bpf)

let main_command =
  Command.group
    ~summary:"Statically-defined probes for tracing native OCaml programs"
    [("trace", trace_command); ("attach", attach_command)]

let run ?version ?build_info () =
  set_verbose false;
  Command.run ?version ?build_info main_command
