(* Example with a probe that allocates and calls a gc *)

let h b =
  prerr_float b;
  prerr_newline ();
  Gc.full_major ();
  prerr_float b;
  prerr_newline ();
  ()

let[@inline never] g b =
  prerr_float b;
  prerr_newline ();
  Gc.full_major ();
  prerr_float b;
  prerr_newline ();
  ()

let foo b =
  [%probe "fooia" (h b)];
  g b;
  ()

let () =
  foo (Float.of_int (Sys.opaque_identity 1)) |> ignore;
  ()
