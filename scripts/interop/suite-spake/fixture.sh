# shellcheck shell=bash
# Plan 2 todo 9 (WP-07, SPAKE): the `spake` suite. It reuses the SPAKE principals
# and groups of the MIT fixture (lane 1D-a: provision.d/30-spake.sh,
# krb5.conf.d/30-spake.conf, kdc.conf.d/30-spake.conf); it adds no drop-in, port
# or secret. The directory name `suite-spake` sorts after every fixture
# directory, so mit-kdc is registered already.
interop_suite spake interop_spake mit-kdc
