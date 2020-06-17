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
      (* All probes are disabled initially, only enable actions matter at
         start. *)
      ( match actions with
      | All Disable ->
          Printf.printf
            "Ignoring -disable-all with trace: all probes start as disabled\n"
      | All Enable -> assert false
      | Selected x -> (
          let y =
            List.filter
              (fun (action, name) ->
                match action with
                | P.Disable ->
                    Printf.printf
                      "Ignoring -disable %s with trace: all probes start as \
                       disabled.\n"
                      name;
                    false
                | P.Enable -> true)
              x
          in
          match y with
          | [] -> ()
          | _ -> P.update t ~actions:(Selected y) ) );
      P.detach t
