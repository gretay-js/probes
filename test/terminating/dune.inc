

(executable
 (name assorted_handlers)
 (modules assorted_handlers))

(rule
 (deps assorted_handlers.exe)
 (action
   (with-outputs-to assorted_handlers.output
     (run probes trace -prog %{dep:assorted_handlers.exe}))))

(rule
 (alias runtest)
 (action (diff assorted_handlers.expected assorted_handlers.output)))


(executable
 (name backtrace_in_handler)
 (modules backtrace_in_handler))

(rule
 (deps backtrace_in_handler.exe)
 (action
   (with-outputs-to backtrace_in_handler.output
     (run probes trace -prog %{dep:backtrace_in_handler.exe}))))

(rule
 (alias runtest)
 (action (diff backtrace_in_handler.expected backtrace_in_handler.output)))


(executable
 (name backtrace_in_handler_loop)
 (modules backtrace_in_handler_loop))

(rule
 (deps backtrace_in_handler_loop.exe)
 (action
   (with-outputs-to backtrace_in_handler_loop.output
     (run probes trace -prog %{dep:backtrace_in_handler_loop.exe}))))

(rule
 (alias runtest)
 (action (diff backtrace_in_handler_loop.expected backtrace_in_handler_loop.output)))


(executable
 (name exception_in_handler)
 (modules exception_in_handler))

(rule
 (deps exception_in_handler.exe)
 (action
   (with-outputs-to exception_in_handler.output
     (run probes trace -prog %{dep:exception_in_handler.exe}))))

(rule
 (alias runtest)
 (action (diff exception_in_handler.expected exception_in_handler.output)))


(executable
 (name gc_in_handler)
 (modules gc_in_handler))

(rule
 (deps gc_in_handler.exe)
 (action
   (with-outputs-to gc_in_handler.output
     (run probes trace -prog %{dep:gc_in_handler.exe}))))

(rule
 (alias runtest)
 (action (diff gc_in_handler.expected gc_in_handler.output)))


(executable
 (name gc_in_handler_deep_stack)
 (modules gc_in_handler_deep_stack))

(rule
 (deps gc_in_handler_deep_stack.exe)
 (action
   (with-outputs-to gc_in_handler_deep_stack.output
     (run probes trace -prog %{dep:gc_in_handler_deep_stack.exe}))))

(rule
 (alias runtest)
 (action (diff gc_in_handler_deep_stack.expected gc_in_handler_deep_stack.output)))


(executable
 (name many_free_vars_in_handler)
 (modules many_free_vars_in_handler))

(rule
 (deps many_free_vars_in_handler.exe)
 (action
   (with-outputs-to many_free_vars_in_handler.output
     (run probes trace -prog %{dep:many_free_vars_in_handler.exe}))))

(rule
 (alias runtest)
 (action (diff many_free_vars_in_handler.expected many_free_vars_in_handler.output)))


(executable
 (name no_probe_option)
 (ocamlopt_flags (:standard -no-probes))
 (modules no_probe_option))

(rule
 (deps no_probe_option.exe)
 (action
   (with-outputs-to no_probe_option.output
     (run probes trace -prog %{dep:no_probe_option.exe}))))

(rule
 (alias runtest)
 (action (diff no_probe_option.expected no_probe_option.output)))


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


(executable
 (name probe_in_handler)
 (modules probe_in_handler))

(rule
 (deps probe_in_handler.exe)
 (action
   (with-outputs-to probe_in_handler.output
     (run probes trace -prog %{dep:probe_in_handler.exe}))))

(rule
 (alias runtest)
 (action (diff probe_in_handler.expected probe_in_handler.output)))