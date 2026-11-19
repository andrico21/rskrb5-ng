# rskrb5-ng-os

Platform credential stores for [`rskrb5-ng`](../README.md), kept out of the
main crate so that it stays free of `unsafe` code (owner decision D11):

- Windows: `MSLSA:`, the logon session's LSA Kerberos ticket cache;
- macOS: `API:`, the native cache of Kerberos.framework (CCAPI), and `KCM:`
  over Mach RPC to the service `kcm_mach_service` names.

Call `rskrb5_ng_os::register(&mut registry)` and resolve cache names with
`Registry::resolve_cache`. The crate is not published (`publish = false`).
