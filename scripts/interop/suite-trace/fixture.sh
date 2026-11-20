# shellcheck shell=bash
# Plan 2 todo 6 (WP-18, trace diagnostics): the `trace` suite. It drives the
# redacted trace events of the exchange engine and the Tokio client against the
# MIT fixture's existing principals (the base user, the requires_preauth user
# and the HTTP service) and asserts that no secret of the run's inventory
# reaches a sink; it adds no drop-in, port or secret. The directory name
# `suite-trace` sorts after every fixture directory, so mit-kdc is registered
# already.
interop_suite trace interop_trace mit-kdc
