(* Example with a probe that raises and has live regs *)

exception My_exn

let h b =
  prerr_float b;
  prerr_newline ();
  raise My_exn

let[@inline never] foo b =
  let must_be_live = Sys.opaque_identity 2 in
  try
    [%probe "fooia" (h b)];
  with My_exn -> begin
      prerr_int must_be_live;
      prerr_newline ()
  end

let () =
  foo (Float.of_int (Sys.opaque_identity 1)) |> ignore;
  ()
