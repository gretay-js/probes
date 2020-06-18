
;;;; Test test.ml with probes

(executable
 (name test)
 (modules test))

(rule
 (action
   (with-outputs-to test.output
     (run ../test_attach.exe %{dep:test.exe}))))

(rule
 (alias runtest)
 (action (diff test.expected test.output)))

;;;; Test test.ml without probes

(rule (copy test.ml test_no_probes.ml))

(executable
 (name test_no_probes)
 (ocamlopt_flags (:standard -no-probes))
 (modules test_no_probes))

(rule
 (action
   (with-outputs-to test_no_probes.output
     (run ../test_attach.exe %{dep:test_no_probes.exe}))))

(rule
 (alias runtest)
 (action (diff test_no_probes.expected test_no_probes.output)))
