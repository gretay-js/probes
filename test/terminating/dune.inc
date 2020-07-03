
;;;; Test assorted_handlers.ml with probes

(executable
 (name assorted_handlers)
 (modules assorted_handlers))

(rule
 (action
   (with-outputs-to assorted_handlers.output
     (run ../test_trace.exe %{dep:assorted_handlers.exe}))))

(rule
 (alias runtest)
 (action (diff assorted_handlers.expected assorted_handlers.output)))

;;;; Test assorted_handlers.ml without probes

(rule (copy assorted_handlers.ml assorted_handlers_no_probes.ml))

(executable
 (name assorted_handlers_no_probes)
 (ocamlopt_flags (:standard -no-probes))
 (modules assorted_handlers_no_probes))

(rule
 (action
   (with-outputs-to assorted_handlers_no_probes.output
     (run ../test_trace.exe %{dep:assorted_handlers_no_probes.exe}))))

(rule
 (alias runtest)
 (action (diff assorted_handlers_no_probes.expected assorted_handlers_no_probes.output)))

;;;; Test backtrace_in_handler.ml with probes

(executable
 (name backtrace_in_handler)
 (modules backtrace_in_handler))

(rule
 (action
   (with-outputs-to backtrace_in_handler.output
     (run ../test_trace.exe %{dep:backtrace_in_handler.exe}))))

(rule
 (alias runtest)
 (action (diff backtrace_in_handler.expected backtrace_in_handler.output)))

;;;; Test backtrace_in_handler.ml without probes

(rule (copy backtrace_in_handler.ml backtrace_in_handler_no_probes.ml))

(executable
 (name backtrace_in_handler_no_probes)
 (ocamlopt_flags (:standard -no-probes))
 (modules backtrace_in_handler_no_probes))

(rule
 (action
   (with-outputs-to backtrace_in_handler_no_probes.output
     (run ../test_trace.exe %{dep:backtrace_in_handler_no_probes.exe}))))

(rule
 (alias runtest)
 (action (diff backtrace_in_handler_no_probes.expected backtrace_in_handler_no_probes.output)))

;;;; Test backtrace_in_handler_loop.ml with probes

(executable
 (name backtrace_in_handler_loop)
 (modules backtrace_in_handler_loop))

(rule
 (action
   (with-outputs-to backtrace_in_handler_loop.output
     (run ../test_trace.exe %{dep:backtrace_in_handler_loop.exe}))))

(rule
 (alias runtest)
 (action (diff backtrace_in_handler_loop.expected backtrace_in_handler_loop.output)))

;;;; Test backtrace_in_handler_loop.ml without probes

(rule (copy backtrace_in_handler_loop.ml backtrace_in_handler_loop_no_probes.ml))

(executable
 (name backtrace_in_handler_loop_no_probes)
 (ocamlopt_flags (:standard -no-probes))
 (modules backtrace_in_handler_loop_no_probes))

(rule
 (action
   (with-outputs-to backtrace_in_handler_loop_no_probes.output
     (run ../test_trace.exe %{dep:backtrace_in_handler_loop_no_probes.exe}))))

(rule
 (alias runtest)
 (action (diff backtrace_in_handler_loop_no_probes.expected backtrace_in_handler_loop_no_probes.output)))

;;;; Test exception_in_handler.ml with probes

(executable
 (name exception_in_handler)
 (modules exception_in_handler))

(rule
 (action
   (with-outputs-to exception_in_handler.output
     (run ../test_trace.exe %{dep:exception_in_handler.exe}))))

(rule
 (alias runtest)
 (action (diff exception_in_handler.expected exception_in_handler.output)))

;;;; Test exception_in_handler.ml without probes

(rule (copy exception_in_handler.ml exception_in_handler_no_probes.ml))

(executable
 (name exception_in_handler_no_probes)
 (ocamlopt_flags (:standard -no-probes))
 (modules exception_in_handler_no_probes))

(rule
 (action
   (with-outputs-to exception_in_handler_no_probes.output
     (run ../test_trace.exe %{dep:exception_in_handler_no_probes.exe}))))

(rule
 (alias runtest)
 (action (diff exception_in_handler_no_probes.expected exception_in_handler_no_probes.output)))

;;;; Test gc_in_handler.ml with probes

(executable
 (name gc_in_handler)
 (modules gc_in_handler))

(rule
 (action
   (with-outputs-to gc_in_handler.output
     (run ../test_trace.exe %{dep:gc_in_handler.exe}))))

(rule
 (alias runtest)
 (action (diff gc_in_handler.expected gc_in_handler.output)))

;;;; Test gc_in_handler.ml without probes

(rule (copy gc_in_handler.ml gc_in_handler_no_probes.ml))

(executable
 (name gc_in_handler_no_probes)
 (ocamlopt_flags (:standard -no-probes))
 (modules gc_in_handler_no_probes))

(rule
 (action
   (with-outputs-to gc_in_handler_no_probes.output
     (run ../test_trace.exe %{dep:gc_in_handler_no_probes.exe}))))

(rule
 (alias runtest)
 (action (diff gc_in_handler_no_probes.expected gc_in_handler_no_probes.output)))

;;;; Test gc_in_handler_deep_stack.ml with probes

(executable
 (name gc_in_handler_deep_stack)
 (modules gc_in_handler_deep_stack))

(rule
 (action
   (with-outputs-to gc_in_handler_deep_stack.output
     (run ../test_trace.exe %{dep:gc_in_handler_deep_stack.exe}))))

(rule
 (alias runtest)
 (action (diff gc_in_handler_deep_stack.expected gc_in_handler_deep_stack.output)))

;;;; Test gc_in_handler_deep_stack.ml without probes

(rule (copy gc_in_handler_deep_stack.ml gc_in_handler_deep_stack_no_probes.ml))

(executable
 (name gc_in_handler_deep_stack_no_probes)
 (ocamlopt_flags (:standard -no-probes))
 (modules gc_in_handler_deep_stack_no_probes))

(rule
 (action
   (with-outputs-to gc_in_handler_deep_stack_no_probes.output
     (run ../test_trace.exe %{dep:gc_in_handler_deep_stack_no_probes.exe}))))

(rule
 (alias runtest)
 (action (diff gc_in_handler_deep_stack_no_probes.expected gc_in_handler_deep_stack_no_probes.output)))

;;;; Test many_free_vars_in_handler.ml with probes

(executable
 (name many_free_vars_in_handler)
 (modules many_free_vars_in_handler))

(rule
 (action
   (with-outputs-to many_free_vars_in_handler.output
     (run ../test_trace.exe %{dep:many_free_vars_in_handler.exe}))))

(rule
 (alias runtest)
 (action (diff many_free_vars_in_handler.expected many_free_vars_in_handler.output)))

;;;; Test many_free_vars_in_handler.ml without probes

(rule (copy many_free_vars_in_handler.ml many_free_vars_in_handler_no_probes.ml))

(executable
 (name many_free_vars_in_handler_no_probes)
 (ocamlopt_flags (:standard -no-probes))
 (modules many_free_vars_in_handler_no_probes))

(rule
 (action
   (with-outputs-to many_free_vars_in_handler_no_probes.output
     (run ../test_trace.exe %{dep:many_free_vars_in_handler_no_probes.exe}))))

(rule
 (alias runtest)
 (action (diff many_free_vars_in_handler_no_probes.expected many_free_vars_in_handler_no_probes.output)))

;;;; Test printf_in_handler.ml with probes

(executable
 (name printf_in_handler)
 (modules printf_in_handler))

(rule
 (action
   (with-outputs-to printf_in_handler.output
     (run ../test_trace.exe %{dep:printf_in_handler.exe}))))

(rule
 (alias runtest)
 (action (diff printf_in_handler.expected printf_in_handler.output)))

;;;; Test printf_in_handler.ml without probes

(rule (copy printf_in_handler.ml printf_in_handler_no_probes.ml))

(executable
 (name printf_in_handler_no_probes)
 (ocamlopt_flags (:standard -no-probes))
 (modules printf_in_handler_no_probes))

(rule
 (action
   (with-outputs-to printf_in_handler_no_probes.output
     (run ../test_trace.exe %{dep:printf_in_handler_no_probes.exe}))))

(rule
 (alias runtest)
 (action (diff printf_in_handler_no_probes.expected printf_in_handler_no_probes.output)))

;;;; Test probe_in_handler.ml with probes

(executable
 (name probe_in_handler)
 (modules probe_in_handler))

(rule
 (action
   (with-outputs-to probe_in_handler.output
     (run ../test_trace.exe %{dep:probe_in_handler.exe}))))

(rule
 (alias runtest)
 (action (diff probe_in_handler.expected probe_in_handler.output)))

;;;; Test probe_in_handler.ml without probes

(rule (copy probe_in_handler.ml probe_in_handler_no_probes.ml))

(executable
 (name probe_in_handler_no_probes)
 (ocamlopt_flags (:standard -no-probes))
 (modules probe_in_handler_no_probes))

(rule
 (action
   (with-outputs-to probe_in_handler_no_probes.output
     (run ../test_trace.exe %{dep:probe_in_handler_no_probes.exe}))))

(rule
 (alias runtest)
 (action (diff probe_in_handler_no_probes.expected probe_in_handler_no_probes.output)))

;;;; Test probe_is_enabled.ml with probes

(executable
 (name probe_is_enabled)
 (modules probe_is_enabled))

(rule
 (action
   (with-outputs-to probe_is_enabled.output
     (run ../test_trace.exe %{dep:probe_is_enabled.exe}))))

(rule
 (alias runtest)
 (action (diff probe_is_enabled.expected probe_is_enabled.output)))

;;;; Test probe_is_enabled.ml without probes

(rule (copy probe_is_enabled.ml probe_is_enabled_no_probes.ml))

(executable
 (name probe_is_enabled_no_probes)
 (ocamlopt_flags (:standard -no-probes))
 (modules probe_is_enabled_no_probes))

(rule
 (action
   (with-outputs-to probe_is_enabled_no_probes.output
     (run ../test_trace.exe %{dep:probe_is_enabled_no_probes.exe}))))

(rule
 (alias runtest)
 (action (diff probe_is_enabled_no_probes.expected probe_is_enabled_no_probes.output)))

;;;; Test rec_probes.ml with probes

(executable
 (name rec_probes)
 (modules rec_probes))

(rule
 (action
   (with-outputs-to rec_probes.output
     (run ../test_trace.exe %{dep:rec_probes.exe}))))

(rule
 (alias runtest)
 (action (diff rec_probes.expected rec_probes.output)))

;;;; Test rec_probes.ml without probes

(rule (copy rec_probes.ml rec_probes_no_probes.ml))

(executable
 (name rec_probes_no_probes)
 (ocamlopt_flags (:standard -no-probes))
 (modules rec_probes_no_probes))

(rule
 (action
   (with-outputs-to rec_probes_no_probes.output
     (run ../test_trace.exe %{dep:rec_probes_no_probes.exe}))))

(rule
 (alias runtest)
 (action (diff rec_probes_no_probes.expected rec_probes_no_probes.output)))
