open Core
module P = Probe_lib

let actions = P.(All Enable)

let attach ~pid ~bpf =
  let pid = P.get_exe pid in
  let t = P.create ~prog ~bpf in
  P.attach t ~pid ~check_prog:false;
  P.update t ~actions;
  P.detach t;
  ()

let trace ~prog ~args ~bpf =
  let t = P.create ~prog ~bpf in
  P.start t (prog :: args) ~check:false;
  P.update t ~actions;
  P.detach t;
  ()

let info ~pid =
  let pid = P.get_exe pid in
  let t = P.create ~prog ~bpf in
  P.attach t ~pid ~check_prog:false;
  List.iter (P.get_probe_states t) ~f:(fun p ->
      printf "%s %s\n" p.name (if p.enabled then "enabled" else "disabled"));
  P.detach t
