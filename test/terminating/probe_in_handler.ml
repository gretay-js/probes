let bar () =
  Printf.printf "inside bar\n"

let foo () =
  Printf.printf "inside foo\n";
  [%probe "b" (bar ())];
  Printf.printf "inside foo after probe\n"

let () =
  [%probe "a" (foo ())];
  Printf.printf "after\n"
