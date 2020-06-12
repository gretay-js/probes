let () =
  [%probe "boo" (Printf.printf "BOO!\n")];
  let boo_enabled = [%probe_is_enabled "boo"] in
  assert (not boo_enabled)
