(* Example with a probe that raises and has live regs *)

exception My_exn

let h b =
  print_float b;
  print_newline ();
  raise My_exn

let[@inline never] foo b =
  let must_be_live = Sys.opaque_identity 2 in
  try
    [%probe "fooia" (h b)];
  with My_exn -> begin
      print_int must_be_live;
      print_newline ()
  end

let () =
  foo (Float.of_int (Sys.opaque_identity 1));
  ()
