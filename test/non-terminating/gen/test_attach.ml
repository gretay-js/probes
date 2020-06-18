module P = Probes_lib_test

let test prog =
  let bpf = false in
  let pid = P.trace_test_lib ~prog ~args:[] ~bpf in
  Unix.sleep 1;
  P.attach_test_lib ~pid ~bpf ~actions:(P.Selected (P.Enable "fooia"));
  Unix.sleep 1;
  P.attach_test_lib ~pid ~bpf ~enable:true;
  Unix.kill pid Sys.sigkill;
  P.wait pid

let () =
  test Sys.argv.(1)
