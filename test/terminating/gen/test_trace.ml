let test prog =
  Printf.printf "Running %s..." prog;
  let pid = Probes_lib_test.trace_test_lib ~prog ~args:[] ~bpf:false in
  match Unix.waitpid [] pid with
  | (p, WEXITED 0) when p = pid -> ()
  | (p, status) ->
    let desc, code =
      match status with
       | WEXITED n -> "exited with code", n
       | WSIGNALED n -> "killed with signal", n
       | WSTOPPED n -> "stopped with signal", Int.to_string n
    in
    failwithf "Tracing %s with process id %d failed. \
               Process %d %s %d.\n" prog pid p desc code

let () =
  test Sys.argv.(1)
