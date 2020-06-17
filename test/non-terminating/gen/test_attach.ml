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

let test_attach prog =
  let bpf = false in
  let pid = trace_test_lib ~prog ~args:[] ~bpf in
  Unix.sleep 1;
  attach_test_lib ~pid ~bpf ~actions:(P.Selected (P.Enable "fooia"));
  Unix.sleep 1;
  attach_test_lib ~pid ~bpf ~enable:true;
  Unix.kill pid Sys.sigkill;
  true

let () =
  Array.iteri (fun i prog -> if i <> 0 then test_attach prog) Sys.argv

