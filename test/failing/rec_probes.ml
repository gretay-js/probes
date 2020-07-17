let rec g x =
  [%probe "g" (f (x-1))];
  Printf.printf "g:%d\n" x

and f x =
  if x > 0 then
    [%probe "f" (g x)];
  Printf.printf "f:%d\n" x

let () =
  f (Sys.opaque_identity 10)
