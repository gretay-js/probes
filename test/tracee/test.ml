(* simple example *)
let f x y z = Printf.printf "f: %d %f %s\n" x y z

let foo a b c =
  [%probe "fooia" (f a b c)];
  Printf.printf "from foo %d %f\n" a b

let rec fib i j =
  if i mod 6000 = 0 then foo (i + j) Float.(of_int i /. of_int j) "myau";
  fib j (i + j)

let () = fib 0 1
