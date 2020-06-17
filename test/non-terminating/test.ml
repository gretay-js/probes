(* simple example *)
let outside = ref true

let f x y z =
  outside := true;
  Printf.printf "f: %d %f %s\n" x y z

let [@inline never] g _p _q =
  if !outside then  begin
    Printf.printf "outside\n";
    outside := false;
  end


let foo a b c =
  [%probe "fooia" (f a b c)];
  ((Sys.opaque_identity g) a b)

let rec fib i j =
  if i < 0 then
    fib 0 1
  else
    begin
    if i mod 2 = 0 then
      foo (i + j) Float.(of_int i /. of_int j) "myau";
    fib j (i + j);
  end

let () = fib 0 1
