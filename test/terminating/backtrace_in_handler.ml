let bt s =
  Printf.printf "%s:\n" s;
  Printexc.print_raw_backtrace stdout (Printexc.get_callstack 9999)

let () =
  bt "Before";
  [%probe "backtrace" (bt "Inside")];
  bt "After"

