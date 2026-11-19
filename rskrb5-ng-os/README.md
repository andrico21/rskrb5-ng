# rskrb5-ng-os

Platform credential stores for [`rskrb5-ng`](../README.md), kept out of the
main crate so that it stays free of `unsafe` code (owner decision D11):

- Windows: `MSLSA:`, the logon session's LSA Kerberos ticket cache;
- macOS: `API:`, the native cache of Kerberos.framework (CCAPI), and `KCM:`
  over Mach RPC to the service `kcm_mach_service` names.

Call `rskrb5_ng_os::register(&mut registry)` and `registry.install_stores()`:
`MSLSA:` (read-only) and `API:` names then resolve through the name routes of
`rskrb5-ng` (`CCache::load_name`, `ccache::file_store::resolve`, the client's
default cache). `KCM:` is built into `rskrb5-ng`; `macos::KcmMachStore` is its
Mach backend. The crate is not published (`publish = false`).
