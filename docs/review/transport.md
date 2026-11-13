# Transport review dispositions

All eleven dispositions are implemented. Each row identifies its atomic commit
by subject suffix. Red/green runs, independent scratch fix-reversal failures,
and final acceptance at `cb2651a` are recorded in the task-35 execution evidence.
STRICT (all 36 closures), Windows Clippy, full tests, doctests, stable/nightly
rustdoc, nightly formatting, lint gates and exact-once ID validation passed.

| ID | Status | Tests / commit | Behaviour change for CHANGELOG | Dismissal evidence |
|---|---|---|---|---|
| RSK-03EDCC7E | fixed | `configured_endpoint_preserves_bare_ipv6`; commit suffix `(RSK-03EDCC7E)` | Complete bare IP literals retain their complete host and service default port; explicit IPv6 ports require brackets. | — |
| RSK-3F13B5FE | fixed | `kpasswd_admin_fallback_preserves_ipv6`; commit suffix `(RSK-3F13B5FE)` | Configured administration fallback retains complete IPv6 hosts and replaces administration ports with 464, including bare and bracketed literals. | — |
| RSK-0D8D7D97 | fixed | `udp_transport_reaches_ipv6_loopback`; commit suffix `(RSK-0D8D7D97)` | Resolve UDP candidates before binding a matching IPv4/IPv6 wildcard socket; try alternative candidates on bind/connect failure within the existing timeout. No post-send retry is introduced. | — |
| RSK-484961E9 | fixed | `udp_transport_rejects_truncated_datagram`; commit suffix `(RSK-484961E9)` | UDP response limits reject oversized datagrams with `Client::UdpResponseTooLarge`, never return a truncated prefix. | — |
| ambient input `RSKRB5_DNS_SERVER` | fixed | `transport_dns_has_no_ambient_environment_reads`; commit suffix `(ambient-DNS)` | Transport no longer reads environment DNS overrides; applications explicitly call `Tokio::with_dns_server`. The gated integration test reads the variable itself. | — |
| RSK-4AD555A5 | fixed | `kpasswd_dns_admin_fallback_uses_port_464`; commit suffix `(RSK-4AD555A5)` | DNS administration fallback retains discovered hosts but uses kpasswd port 464; actual `_kpasswd` service ports remain authoritative. | — |
| RSK-DF8D47BE | fixed | `kpasswd_dns_unavailable_stops_fallback`; commit suffix `(RSK-DF8D47BE)` | A root SRV target returns `Client::DnsServiceUnavailable` and stops administration fallback. | — |
| RSK-521F824C | fixed | `kpasswd_dns_retains_all_target_addresses`; commit suffix `(RSK-521F824C)` | Explicit DNS resolution retains every returned address for each SRV target, preserving its advertised port. | — |
| RSK-DBD57F3E | fixed | `srv_zero_draw_selects_zero_weight`; commit suffix `(RSK-DBD57F3E)` | SRV selection draws without replacement within ascending priority groups; zero-weight entries participate in zero draws and all-zero groups are uniformly ordered. | — |
| RSK-351DC798 | fixed | `kdc_tcp_rejects_reserved_bit_before_body_read`, `tcp_lengths_are_service_specific`; commit suffix `(RSK-351DC798)` | KDC TCP enforces 31-bit request lengths and rejects reserved response bits before allocation. Kpasswd retains RFC 3244 unsigned framing. | — |
| RSK-4DB854C8 / upstream issue #7 / run-2 lead `send_to_endpoints/post-send-mutation-retry` | fixed | `kpasswd_lost_reply_does_not_retry_endpoint`, `kpasswd_udp_timeout_does_not_retry_tcp`; commit suffix `(RSK-4DB854C8)` | Password transport permits failover only before possible delivery. Send/read failures and timeouts after that boundary return `Client::KpasswdOutcomeUnknown`, with no endpoint or protocol retry. `Auto` is TCP first and UDP only after a definite TCP failure, never after an uncertain TCP outcome (FU-CLI-R24); a UDP refusal is definite. | — |
