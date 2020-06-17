let () =
  [%probe "boo" (Printf.printf "BOO!\n")];
  let boo_enabled = [%probe_is_enabled "boo"] in
  if boo_enabled then Printf.printf "spooky\n" else "quiet\n"
