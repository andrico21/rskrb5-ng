# shellcheck shell=bash
# Plan 2 todo 26 (WP-19, HTTP client and session parity, the `http-client`
# leaf): the `http-client` suite. It drives the crate's NegotiateHttpClient
# (redirects, the 401 Negotiate round, mutual authentication on the final
# response) against the MIT-backed Apache fixture `httpd` of lane 1D-b
# (scripts/interop/net-httpd/, service HTTP/httpd.test.rskrb5, plain HTTP), and
# the crate's session manager behind a Rust acceptor that holds the very keytab
# Apache holds, so a ticket the MIT KDC issued is accepted by this crate's
# service and continued through a sealed session cookie. It adds no drop-in,
# port or secret of its own (the host ports of httpd and mit-kdc are the
# fixtures'). The redirect scenario answers a same-origin 302 in the test's own
# exchange and sends the rest to Apache: the fixture's docroot denies everything
# outside /whoami/, so Apache's mod_dir redirect of /whoami is a 403 and the
# fixture is left unchanged. The directory name
# `suite-http-client` sorts after every fixture directory, so mit-kdc and
# httpd are registered already.
interop_suite http-client interop_http_client mit-kdc httpd
