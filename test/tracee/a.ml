(* too probes with the same name, many arguments *)
let h2 name x0 x1 x2 x3 x4 x5 x6 x7 x8 x9 x =
  Printf.printf "handler %s:%d %d %d %d %d %d %d %d %d %d %d\n" name x0 x1 x2
    x3 x4 x5 x6 x7 x8 x9 x

let h1 name x = Printf.printf "handler %s:%d\n" name x

let test1 x =
  [%probe "a" (h1 "test1" x)];
  Printf.printf "test %d\n" x

let test2 x =
  [%probe
    "a"
      (h2 "test2" (x * 0) (x * 1) (x * 2) (x * 3) (x * 4) (x * 5) (x * 6)
         (x * 7) (x * 8) (x * 9) (x * 10))];
  Printf.printf "test %d\n" x

let () =
  while true do
    test1 25;
    test2 1
  done
