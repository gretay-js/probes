let () =
  let open Version in
  [%probe "in_probes_main" (Printf.printf "handler in main!\n")];
  if [%probe_is_enabled "in_probes_main"] then
    Printf.printf "probe_is_enabled = true in main!\n"
  else Printf.printf "probe_is_enabled = false in main!\n";
  Cli.run ~version ~build_info ()
