type t = int

type action = Enable | Disable

type actions = All of action | Selected of (action * string) list

let user_error fmt =
  Format.kfprintf
    (fun _ -> exit 321)
    Format.err_formatter
    ("@?Error: " ^^ fmt ^^ "@.")

let attach ~pid:_ = user_error "Not implemented"
let start ~prog:_ ~args:_ = user_error "Not implemented"
let update _t _actions = user_error "Not implemented"
let detach _t = user_error "Not implemented"
