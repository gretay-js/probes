(* handlers *)
let h0 () =
  Printf.printf "h0:noarg\n"

let h1 name n fl ls o =
  Printf.printf "h0:%s:%d:%f:%s:%s\n" name n fl
    (String.concat "" (List.map Int.to_string ls))
    (Option.value (Option.map (Printf.sprintf "Some %d") o) ~default:"None")

let h2 name x str =
  Printf.printf "h0:%s:%d:%s\n" name x str

let h3 name x =
  Printf.printf "h0:%s:0x%Lx\n" name x

let h4 name x y =
  Printf.printf "h0:%s:%d:%d\n" name x y

(* code *)
let test1 x y =
  [%probe "test1" (h4 "test1" x y)];
  let z =
    if x > y  then
      ([%probe "test_arg" (h2 "test_arg" (x+y) "true_branch")];
       x - y)
    else
      ([%probe "test_arg" (h2 "test_arg" x "false_branch")];
       y - x)
  in
  assert (not (y = 0));
  let fl = ((float_of_int x) /. (float_of_int y)) in
  [%probe "test_manyarg" (h1 "test_manyarg" x fl [x;y;z] (Some z))];
  z

let () =
  [%probe "main" (h3 "main" 0x45L)];
  let r =
    if ((Array.length Sys.argv) = 3) then
      ([%probe "test_noarg" (h0 ())];
        test1 (int_of_string Sys.argv.(1)) (int_of_string Sys.argv.(2)))
    else Int.max_int
  in
    Printf.printf "res=%d\n" r;
  ()


