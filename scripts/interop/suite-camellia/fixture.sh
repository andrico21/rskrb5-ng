# shellcheck shell=bash
# Plan 2 todo 5 (WP-03, Camellia): the `camellia` suite. It needs only the MIT
# fixture, whose Camellia principals and self-check are the 55-camellia
# drop-ins under scripts/interop/mit/. The directory name `suite-camellia`
# sorts after every fixture directory, so mit-kdc is registered already.
interop_suite camellia interop_camellia mit-kdc
