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

# Plan 2 todo 28 (wave 11 lane F, FU-HTC-P07): the `http-client-cbt` suite. The
# crate's NegotiateHttpClient over the built-in rustls transport (the
# `kkdcp-rustls` leaf) binds its token to the TLS connection that carries it
# (RFC 5929 `tls-server-end-point`) and authenticates with a ticket the MIT KDC
# issued for HTTP/http.test.rskrb5 to an HTTPS service the test itself serves on
# 127.0.0.1 (todo 28's host ports 19780-19782, `INTEROP_HTTP_CBT_PORT` moves
# them) with the crate's SPNEGO acceptor, the realm's http.keytab and the test
# PKI of tests/kkdcp/. That service REQUIRES the bindings of its certificate:
# it accepts the bound token and refuses a token bound to another certificate
# and an unbound one (Apache's mod_auth_gssapi cannot check bindings,
# FU-IOP-P03). No drop-in, secret or container of its own; the realm is
# unchanged.
interop_suite http-client-cbt interop_http_client_cbt mit-kdc
