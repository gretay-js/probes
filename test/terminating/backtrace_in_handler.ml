let bt title =
  Printexc.get_callstack 9999
  |> Printexc.raw_backtrace_to_string
  |> Str.global_replace (Str.regexp_string " (inlined)") ""
  |> Printf.printf "%s:\n%s" title

let () =
  bt "Before";
  [%probe "backtrace" (bt "Inside")];
  bt "After"
