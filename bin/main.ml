module P = Probes_lib

let info ~pid ~bpf =
  let prog = P.get_exe pid in
  let t = P.create ~prog ~bpf in
  P.attach t pid ~check_prog:false;
  let probes = P.get_probe_states t in
  Array.iter
    (fun (p : P.probe_desc) ->
      Printf.printf "%s %s\n" p.name
        (if p.enabled then "enabled" else "disabled"))
    probes;
  P.detach t

let attach ~pid ~bpf ~(actions : P.actions) =
  let prog = P.get_exe pid in
  let t = P.create ~prog ~bpf in
  match actions with
  | All a ->
      let enable =
        match a with
        | Enable -> true
        | Disable -> false
      in
      P.attach_update_all_detach t pid ~enable
  | Selected _ ->
      P.attach t pid ~check_prog:false;
      P.update t ~actions;
      P.detach t

let trace ~prog ~args ~bpf ~(actions : P.actions) =
  let t = P.create ~prog ~bpf in
  match actions with
  | All Enable -> P.trace_all t ~prog ~args
  | All Disable | Selected _ ->
      P.start t ~prog ~args ~check_prog:false;
      P.update t ~actions;
      P.detach t
