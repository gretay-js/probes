open Core

let verbose = ref false

let set_verbose v = verbose := v

(* CR gyorsh: more than once -enable -disable flags *)
(* CR gyorsh: read from file what to enable and disable *)

(* type support = Bpf | Ocaml
 * let flag_bpf =
 *   let of_string = function
 *     | "bpf" -> Bpf
 *     | "ocaml" -> Ocaml
 *     | _ -> failwith "unknown argument"
 *   in
 *   Command.Param.(
 *     flag "-support" (optional_with_default Ocaml
 *                    (Command.Arg_type.create of_string))
 *       ~doc:"tracing supprt:\n\
 *             ocaml \tuser-space tracing with OCaml handlers (default)\n\
 *             bpf \tkernel-space tracing using a predefined eBPF handler, requires setuid\n\
 *             \t\t NOT IMPLEMENTED") *)

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
      "The command returns after updating the probes, letting the process \
       continue normally.")
    Command.Let_syntax.(
      let%map v = flag_v
      and q = flag_q
      and prog = flag_prog
      and pid = flag_pid in
      if v then set_verbose true;
      if q then set_verbose false;
      fun () -> printf "attach to pid %d and update probes in %s" pid prog)

let trace_command =
  Command.basic
    ~summary:"Execute the program with probes enabled as specified"
    ~readme:(fun () ->
      "Guarantees that all specified probes are enabled before the program \
       starts.\n\
       Start execution of the program in a separate child process with \n\
       probes enabled as specified, and detach from it. \n\
       The command returns while the child process continues program \
       execution normally.\n\
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
      and args =
        Command.Param.(
          flag "--" escape ~doc:"args pass the rest to the program")
      in
      if v then set_verbose true;
      if q then set_verbose false;
      fun () -> printf !"trace %s %{sexp:string list option}\n" prog args)

let main_command =
  Command.group
    ~summary:"Statically-defined probes for tracing native OCaml programs"
    [("trace", trace_command); ("attach", attach_command)]

let run ?version ?build_info () =
  set_verbose false;
  Command.run ?version ?build_info main_command
