let bt title =
  (* Inlining and dbg info in the trace depends on the optimization settings
     such as flambda, so we don't print the backtrace. *)
  let len = Printexc.(get_callstack 9999
                      |> raw_backtrace_length) in
  Printf.printf "%s is backtrace length >= 2? %b\n" title (len >= 2)

let () =
  bt "Before";
  [%probe "backtrace" (bt "Inside")];
  bt "After"
