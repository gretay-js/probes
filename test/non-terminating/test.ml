(* simple example: run forever, print something once,
   when a probe is hit for the first time after being enabled. *)

type state = Init | Print of int*int | Done
let enabled = ref Init

let f x y =
  match !enabled with
  | Init ->
    enabled := Print (x,y)
  | Print _ | Done -> ()

let [@inline never] g i j =
  match !enabled with
  | Init | Done -> ()
  | Print (x,y) ->
    Printf.printf "g: %d %d %d %d\n" i j x y;
    enabled := Done

let foo i j =
  [%probe "fooia" (f i j)];
  ((Sys.opaque_identity g) i j)

let rec fib i j =
  if i < 0 then begin
    [%probe "reset" (
      match !enabled with
      | Init | Print _ -> ()
      | Done -> enabled := Print (0,1))];
    fib 0 1
  end else begin
    if i mod 2 = 0 then foo i j;
    fib j (i + j);
  end

let () = fib 0 1
