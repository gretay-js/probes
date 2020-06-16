let test prog =
  try
  Printf.printf "Running %s..." prog;
  let pid = Probes_lib_test.trace_test_lib ~prog ~args:[] ~bpf:false in
  let res =
    match Unix.waitpid [] pid with
    | (p, WEXITED 0) when p = pid -> true
    | _ -> false
  in
  Printf.printf "%s\n" (if res then "PASS" else "FAIL")
  with  _ ->
  Printf.printf "FAIL\n"

let%expect_test _ =
  let progs = Array.sub Sys.argv 1 ((Array.length Sys.argv) - 1) in
  Array.sort String.compare progs;
  Array.iteri test progs

