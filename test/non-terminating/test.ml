(* simple example: run forever, print something once, when a probe is hit for
   the first time. *)

let p1_hit = ref false

let p2_hit = ref false

let p3_hit = ref false

let on_p name hit =
  if not !hit then (
    hit := true;
    Printf.printf "Hit %s\n" name;
    flush stdout
  )

let () =
  while true do
    [%probe "p1" (on_p "p1" p1_hit)];
    [%probe "p2" (on_p "p2" p2_hit)];
    [%probe "p3" (on_p "p3" p3_hit)];
  done
