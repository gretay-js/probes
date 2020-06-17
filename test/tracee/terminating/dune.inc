(executable
 (name printf_in_handler)
 (modules printf_in_handler))

(rule
 (deps printf_in_handler.exe)
 (action
   (with-outputs-to printf_in_handler.output
     (run probes trace -prog %{dep:printf_in_handler.exe}))))

(rule
 (alias runtest)
 (action (diff printf_in_handler.expected printf_in_handler.output)))


