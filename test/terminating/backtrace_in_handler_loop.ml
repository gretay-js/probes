let bt n =
  (* Inlining and dbg info in the trace depends on the optimization settings
     such as flambda, so we don't print the backtrace. *)
  let len = Printexc.(get_callstack 9999
                      |> raw_backtrace_length) in
  if n = 0 then
    Printf.printf "is backtrace length > 10? %b\n" (len > 10)

let () =
  let rec loop n =
    if n = 0 then
      [%probe "backtrace" (bt 0)]
    else begin
      loop (n - 1);
      bt n
    end
  in
  loop 10

