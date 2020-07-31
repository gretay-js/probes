(* Example with a probe that allocates and calls a gc *)

let h b =
  print_float b;
  print_newline ();
  Gc.full_major ();
  print_float b;
  print_newline ();
  ()

let[@inline never] g b =
  print_float b;
  print_newline ();
  Gc.full_major ();
  print_float b;
  print_newline ();
  ()


let foo b =
  [%probe "fooia" (h b)];
  g b;
  ()

let () =
  foo (Float.of_int (Sys.opaque_identity 1));
  ()
