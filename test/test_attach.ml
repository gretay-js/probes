module T = Probes_lib_test
module P = Probes_lib

let test prog =
  let bpf = false in
  let pid = T.trace_test_lib_actions ~prog ~args:[] ~bpf ~actions:(P.All P.Disable) in
  Unix.sleep 1;
  T.attach_test_lib_actions ~pid ~bpf ~actions:(P.Selected [(P.Enable, "fooia")]);
  Unix.sleep 1;
  T.attach_test_lib_actions ~pid ~bpf ~actions:(P.Selected [(P.Disable, "fooia")]);
  Unix.sleep 1;
  T.attach_test_lib ~pid ~bpf ~enable:true;
  Unix.sleep 1;
  Unix.kill pid Sys.sigkill;
  T.wait pid ~prog

let () =
  test Sys.argv.(1)
