# shellcheck shell=bash
# Plan 2 todo 4 (WP-04, stepwise exchange engine): the `exchange` suite. It
# reuses the fixtures' existing principals and the direct TEST.RSKRB5 <->
# OTHER.RSKRB5 trust; it adds no drop-in, port or secret. The directory name
# `suite-exchange` sorts after every fixture directory, so mit-kdc and
# mit-other are registered already.
interop_suite exchange interop_exchange mit-kdc mit-other
