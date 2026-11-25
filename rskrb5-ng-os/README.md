# rskrb5-ng-os

Platform credential stores for [`rskrb5-ng`](../README.md), kept out of the
main crate so that it stays free of `unsafe` code (owner decision D11):

- Windows: `MSLSA:`, the logon session's LSA Kerberos ticket cache;
- macOS: `API:`, the native cache of Kerberos.framework (CCAPI), and the
  Mach RPC transport of the built-in `KCM:` store, for the service
  `kcm_mach_service` names.

Call `rskrb5_ng_os::register(&mut registry)` and `registry.install_stores()`:
`MSLSA:` (read-only) and `API:` names then resolve through the name routes of
`rskrb5-ng` (`CCache::load_name`, `ccache::file_store::resolve`, the client's
default cache). `KCM:` is built into `rskrb5-ng`; on macOS, call
`rskrb5_ng_os::install_kcm_transport()` once, before any `KCM:` cache is
reached, and every configured `KCM:` route (`ccache::configured`, the client's
cache-name routes) then reaches the Mach service its configuration names, with
the Unix socket `kcm_socket` names as MIT's fallback. Without that call a
configuration that names another Mach service is refused with
`rskrb5_ng::error::Kcm::NoMachTransport`. The crate is not published
(`publish = false`).
