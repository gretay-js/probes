(* Example with a probe that allocates and calls a gc *)

let h x y z =
  Printf.printf "h: %d %f %s\n" x y z;
  let len = if x < 0 || x > Sys.max_array_length / 40 then 10000 else 0 in
  let arr = Array.make len y in
  let total = Array.fold_right (fun v acc -> v +. acc) arr 0. in
  Printf.printf "total = %f" total;
  Gc.full_major ();
  ()

let foo a b c =
  [%probe "fooia" (h a b c)];
  (a, b, Float.of_int a +. b)

let rec fib i j =
  if (i >= 0) then begin
    if (i mod 2 = 0) then begin
      let (a, b, c) = foo (i + j) Float.(of_int i /. of_int j) "myau" in
      Printf.printf "after foo %d %f %f\n" a b c;
    end;
    fib j (i + j)
  end

let () = fib 0 1
