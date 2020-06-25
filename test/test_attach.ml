module T = Probes_lib_test
module P = Probes_lib

let test prog =
  let t, pid =
    T.trace_test_lib_actions ~prog ~args:[] ~actions:(P.All P.Disable)
  in
  let names = P.get_probe_names t in
  Array.iteri (fun i name -> Printf.printf "%d:%s\n" i name) names;
  Unix.sleep 1;
  T.print_info t ~pid;
  Array.iteri
    (fun i name ->
      if i < 2 then (
        Printf.printf "Test %s\n" name;
        T.attach_test_lib_actions t ~pid
          ~actions:(P.Selected [(P.Enable, name)]);
        Unix.sleep 1;
        T.print_info t ~pid;
        T.attach_test_lib_actions t ~pid
          ~actions:(P.Selected [(P.Disable, name)]);
        Unix.sleep 1;
        T.print_info t ~pid ))
    names;
  T.attach_test_lib t ~pid ~enable:true;
  Unix.sleep 1;
  T.print_info t ~pid;
  let actions =
    P.Selected (Array.map (fun n -> (P.Disable, n)) names |> Array.to_list)
  in
  T.attach_test_lib_actions t ~pid ~actions;
  Unix.sleep 1;
  T.print_info t ~pid;
  try
    Unix.kill pid Sys.sigkill;
    T.wait pid ~prog
  with Failure s ->
    Printf.printf "%s\n" s;
    (* ignore failure caused by kill *)
    ()

let () = test Sys.argv.(1)
