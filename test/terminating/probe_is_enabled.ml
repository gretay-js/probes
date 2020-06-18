let () =
  [%probe "boo" (Printf.printf "BOO!\n")];
  let boo_enabled = [%probe_is_enabled "boo"] in
  Printf.printf (if Sys.opaque_identity boo_enabled then "spooky\n" else "quiet\n")
