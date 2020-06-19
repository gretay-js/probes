module P = Probes_lib

let bpf = false

let print_info t ~pid =
  P.attach t pid ~check_prog:false;
  let probes = P.get_probe_states t in
  Array.iter
    (fun (p : P.probe_desc) ->
      Printf.printf "%s %s\n" p.name
        (if p.enabled then "enabled" else "disabled"))
    probes;
  P.detach t

let attach_test_lib_actions t ~pid ~actions =
  P.attach t pid ~check_prog:false;
  P.update t ~actions;
  P.detach t

let attach_test_lib t ~pid  ~enable =
  let actions = P.All (if enable then P.Enable else P.Disable) in
  attach_test_lib_actions t ~pid ~actions

let trace_test_lib ~prog ~args =
  let actions = P.All P.Enable in
  let t = P.create ~prog ~bpf in
  P.start t ~prog ~args ~check_prog:false;
  let pid = Option.get (P.get_pid t) in
  P.update t ~actions;
  P.detach t;
  (t,pid)


let trace_test_lib_actions ~prog ~args ~actions =
  let t = P.create ~prog ~bpf in
  P.start t ~prog ~args ~check_prog:false;
  let pid = Option.get (P.get_pid t) in
  (* All probes are disabled initially,
     only enable actions matter at start. *)
  (match actions with
   | P.All P.Disable -> ()
   | P.All P.Enable -> P.update t ~actions
   | Selected list ->
     let res =
       List.filter (fun (action, _) ->
         match action with
         | P.Disable -> false
         | P.Enable -> true
       ) list
     in P.update t ~actions:(Selected res));
  P.detach t;
  (t,pid)

let wait pid ~prog =
  match Unix.waitpid [] pid with
  | (p, WEXITED 0) when p = pid -> ()
  | (p, status) ->
    let desc, code =
      match status with
      | WEXITED n -> "exited with code", n
      | WSIGNALED n -> "killed with signal", n
      | WSTOPPED n -> "stopped with signal", n
    in
    failwith (Printf.sprintf
                "Tracing %s with process id %d failed. \
                 Process %d %s %d.\n" prog pid p desc code)
