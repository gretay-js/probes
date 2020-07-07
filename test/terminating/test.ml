let f x y z lst =
  let s = lst |> List.map string_of_int |> String.concat " " in
  Printf.printf "f: %d %f %s\n%s\n" x y z s

let foo a b c lst =
  [%probe "fooia" (f a b c lst)];
  Printf.printf "from foo %d %f\n" a b

let () =
  [%probe "boo" (Printf.printf "BOO!\n")];
  foo 1 5.9 "myau" (List.init 1000 (fun i -> i)) ;
  let boo_enabled = [%probe_is_enabled "boo"] in
  if boo_enabled then Printf.printf "BOO was enabled\n"
  else Printf.printf "BOO wasn't enabled\n";
