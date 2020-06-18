module P = Probes_lib

let attach_test_lib_actions ~pid ~bpf ~actions =
  let prog = P.get_exe pid in
  let t = P.create ~prog ~bpf in
  P.attach t pid ~check_prog:false;
  P.update t ~actions;
  P.detach t;
  ()

let attach_test_lib ~pid ~bpf ~enable =
  let actions = P.All (if enable then P.Enable else P.Disable) in
  attach_test_lib_actions ~pid ~bpf ~actions

let trace_test_lib ~prog ~args ~bpf =
  let actions = P.All P.Enable in
  let t = P.create ~prog ~bpf in
  P.start t ~prog ~args ~check_prog:false;
  let pid = Option.get (P.get_pid t) in
  P.update t ~actions;
  P.detach t;
  pid

let wait ~prog pid =
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
