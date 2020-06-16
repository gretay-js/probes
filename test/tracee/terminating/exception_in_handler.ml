exception Boom

let foo n =
  if n = (Sys.opaque_identity 1) then raise Boom
  else Printf.printf "Bong\n"

let () =
  try
    Printf.printf "before\n";
    [%probe "can_raise" (foo 1)];
    Printf.printf "between\n";
  with Boom -> Printf.printf "Boom!!\n";
  [%probe "can_raise" (foo 2)];
  Printf.printf "after\n"
