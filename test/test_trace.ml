module T = Probes_lib_test
let () =
  let prog = Sys.argv.(1) in
  let (_,pid) = T.trace_test_lib ~prog ~args:[] in
  T.wait pid ~prog
