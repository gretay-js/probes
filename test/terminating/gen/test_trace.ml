let () =
  let prog = Sys.argv.(1) in
  Probes_lib_test.(trace_test_lib ~prog ~args:[] ~bpf:false |> wait ~prog)
