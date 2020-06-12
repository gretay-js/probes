(* too probes with the same name, many arguments *)
let h2 name x0 x1 x2 x3 x4 x5 x6 x7 x8 x9 x10 x11 x12 x13 x14 x15 x16 x =
  Printf.printf "handler %s:%d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n"
    name x0 x1 x2 x3 x4 x5 x6 x7 x8 x9 x10 x11 x12 x13 x14 x15 x16 x

let h1 name x = Printf.printf "handler %s:%d\n" name x

let test1 x =
  [%probe "a" (h1 "test1" x)];
  Printf.printf "test %d\n" x

let f x n =
  x * (Sys.opaque_identity n)

let test2 x =
  let x0 = f x 0 in
  let x1 = f x 1 in
  let x2 = f x 2 in
  let x3 = f x 3 in
  let x4 = f x 4 in
  let x5 = f x 5 in
  let x6 = f x 6 in
  let x7 = f x 7 in
  let x8 = f x 8 in
  let x9 = f x 9 in
  let x10 = f x 10 in
  let x11 = f x 11 in
  let x12 = f x 12 in
  let x13 = f x 13 in
  let x14 = f x 14 in
  let x15 = f x 15 in
  let x16 = f x 16 in
  [%probe "a" (h2 "inside" x0 x1 x2 x3 x4 x5 x6 x7 x8 x9 x10 x11 x12 x13 x14 x15 x16 x)];
  (* keep some of the args live after probe *)
  (h2 "outside" x0 x1 x2 x2 x4 x4 x6 x6 x8 x8 x8 x10 x10 x12 x12 x14 x14 x);
  Printf.printf "test %d\n" x

let () =
    test1 (Sys.opaque_identity 25);
    test2 (Sys.opaque_identity 1)
