module P = Probes_lib

let trace_test_lib ~prog ~args ~bpf =
  let actions = P.All P.Enable in
  let t = P.create ~prog ~bpf in
  P.start t ~prog ~args ~check_prog:false;
  let pid = Option.get (P.get_pid t) in
  P.update t ~actions;
  P.detach t;
  pid

let test_trace prog =
  Printf.printf "Running %s..." prog;
  let pid = trace_test_lib ~prog ~args:[] ~bpf:false in
  let res =
    match Unix.waitpid [] pid with
    | (p, WEXITED 0) when p = pid -> true
    | _ -> false
  in
  Printf.printf "%s\n" (if res then "PASS" else "FAIL")

let () =
  Array.iter test_trace Sys.argv
