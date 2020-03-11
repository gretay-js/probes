let h1 name x =
  Printf.printf "handler %s:%d\n" name x

let h2 name x0 x1 x2 x3 x4 x5 x6 x7 x8 x9 =
  Printf.printf "handler %s:%d %d %d %d %d %d %d %d %d %d\n"
    name x0 x1 x2 x3 x4 x5 x6 x7 x8 x9

let test1 x =
  (h1 "a" x);
  Printf.printf "test %d\n" x

let test2 x =
  (h2 "a" (x*0) (x*1) (x*2) (x*3) (x*4) (x*5) (x*6) (x*7) (x*8) (x*9));
  Printf.printf "test %d\n" x

let () =
  test1 25;
  test2 1;

