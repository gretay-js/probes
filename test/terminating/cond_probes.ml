let g x =
  Printf.printf "g:%d\n" (x-1)

let f x =
  if x > 0 then
    [%probe "foo" (g x)];
  Printf.printf "f:%d\n" x

let () =
  f (Sys.opaque_identity 10)
