# shellcheck shell=bash
# Plan 2 todo 10 (WP-08, OTP inside FAST): the `otp` suite. It reuses the MIT
# realm's OTP module and its principals (lane 1D-a: provision.d/40-otp.sh,
# kdc.conf.d/40-otp.conf) and the `radius` fixture the module authenticates
# against; it adds no drop-in, port or secret (prefix 60 and ports 19600-19609
# stay reserved for this todo). The directory name `suite-otp` sorts after every
# fixture directory, so mit-kdc and radius are registered already. This is the
# first suite to register `radius`, so the end-of-run liveness check also asks
# radiusd for a protocol answer (interop_probe_radius, FU-IOP-P21).
interop_suite otp interop_otp mit-kdc radius
