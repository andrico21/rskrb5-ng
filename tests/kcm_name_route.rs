//! The cache-name route reaches the built-in `KCM` type (register row
//! FU-KEY-P04): [`CCache::save_name`], [`CCache::load_name`] and, with
//! `tokio`, the client's default-cache lookup and write-back go through the
//! KCM store, here served by an installed [`KcmTransport`].
//!
//! The installation is process-wide and the first one wins, so this target
//! has its own process and every test shares the one daemon.

#![cfg(unix)]

/// Name-route tests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    extern crate alloc;

    use alloc::sync::Arc;
    use core::error;
    use std::{
        collections::HashMap,
        path::Path,
        sync::{Mutex, OnceLock, PoisonError},
    };

    use rskrb5_ng::{
        ccache::{
            CCache,
            kcm::seam::{KcmTransport, install_transport},
        },
        error::Kcm,
    };

    /// Error type of the `Result`-returning tests.
    type TestError = Box<dyn error::Error>;

    /// `KCM_OP_GET_PRINCIPAL`.
    const GET_PRINCIPAL: u16 = 8;
    /// `KCM_OP_GET_KDC_OFFSET`.
    const GET_KDC_OFFSET: u16 = 22;
    /// `KCM_OP_GET_CRED_LIST`.
    const GET_CRED_LIST: u16 = 13_001;
    /// `KCM_OP_REPLACE`.
    const REPLACE: u16 = 13_002;
    /// `KRB5_FCC_NOFILE`, the status of an unknown cache.
    const NOFILE: i32 = -1_765_328_189;
    /// `KRB5_FCC_INTERNAL`, the status of an opcode this daemon does not expect.
    const INTERNAL: i32 = -1_765_328_188;

    /// A daemon that keeps each cache as the payload of its last `REPLACE`
    /// (KDC offset, principal, counted credentials) and records every call.
    #[derive(Debug, Default)]
    struct Daemon {
        /// The caches by name.
        caches: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
        /// The opcode and cache name of every request, in arrival order.
        calls: Mutex<Vec<(u16, Vec<u8>)>>,
    }

    impl Daemon {
        /// How often `opcode` named the cache `name`.
        fn count(&self, opcode: u16, name: &str) -> usize {
            let wanted = (opcode, name.as_bytes());
            self.calls
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .filter(|call| (call.0, call.1.as_slice()) == wanted)
                .count()
        }
    }

    /// A big-endian 32-bit length at the front of `bytes`.
    fn be32(bytes: &[u8]) -> Option<(usize, &[u8])> {
        let (head, rest) = bytes.split_first_chunk::<4>()?;
        Some((usize::try_from(u32::from_be_bytes(*head)).ok()?, rest))
    }

    /// The length of the principal at the front of `bytes`: name type,
    /// component count, realm and components, each string counted.
    fn principal_length(bytes: &[u8]) -> Option<usize> {
        let (_name_type, after_type) = bytes.split_first_chunk::<4>()?;
        let (count, mut cursor) = be32(after_type)?;
        for _ in 0..=count {
            let (size, tail) = be32(cursor)?;
            cursor = tail.get(size..)?;
        }
        bytes.len().checked_sub(cursor.len())
    }

    /// A reply with status 0 and `payload`.
    fn ok(payload: &[u8]) -> Vec<u8> {
        [&[0_u8; 4][..], payload].concat()
    }

    impl KcmTransport for Daemon {
        fn call(&self, request: &[u8]) -> Result<Vec<u8>, Kcm> {
            let opcode = request
                .get(2..4)
                .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
                .map_or(0, u16::from_be_bytes);
            let body = request.get(4..).unwrap_or_default();
            let end = body
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(body.len());
            let (name, rest) = (
                body.get(..end).unwrap_or_default(),
                body.get(end.saturating_add(1)..).unwrap_or_default(),
            );
            self.calls
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((opcode, name.to_vec()));
            if opcode == REPLACE {
                drop(
                    self.caches
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .insert(name.to_vec(), rest.to_vec()),
                );
                return Ok(ok(&[]));
            }
            let Some(held) = self
                .caches
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(name)
                .cloned()
            else {
                return Ok(NOFILE.to_be_bytes().to_vec());
            };
            let split = held.get(4..).and_then(|after| {
                principal_length(after).map(|length| after.split_at_checked(length))
            });
            Ok(match (opcode, split) {
                (GET_PRINCIPAL, Some(Some((principal, _)))) => ok(principal),
                (GET_CRED_LIST, Some(Some((_, credentials)))) => ok(credentials),
                (GET_KDC_OFFSET, _) => ok(held.get(..4).unwrap_or_default()),
                _ => INTERNAL.to_be_bytes().to_vec(),
            })
        }
    }

    /// The daemon, installed by the first test that needs it.
    fn daemon() -> Result<&'static Arc<Daemon>, TestError> {
        static INSTALLED: OnceLock<Result<Arc<Daemon>, String>> = OnceLock::new();
        INSTALLED
            .get_or_init(|| {
                let daemon = Arc::new(Daemon::default());
                install_transport(Arc::<Daemon>::clone(&daemon))
                    .map(|()| daemon)
                    .map_err(|error| error.to_string())
            })
            .as_ref()
            .map_err(|message| message.clone().into())
    }

    /// The MIT 1.22.2 `kinit` cache of `testuser1@TEST.RSKRB5` (format 4).
    fn mit_cache() -> Result<CCache, TestError> {
        Ok(CCache::load(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ccache-mit/mit-v4"),
        )?)
    }

    /// `CCache::save_name` and `CCache::load_name` reach the built-in KCM
    /// store: the cache arrives with `REPLACE` and is read back with
    /// `GET_PRINCIPAL` and `GET_CRED_LIST`.
    #[test]
    fn cache_names_reach_the_built_in_kcm_store() -> Result<(), TestError> {
        let daemon = daemon()?;
        let cache = mit_cache()?;
        cache.save_name("KCM:route-ccache")?;
        let loaded = CCache::load_name("KCM:route-ccache")?;
        assert_eq!(loaded.default_principal(), cache.default_principal());
        assert_eq!(loaded.credentials(), cache.credentials());
        assert_eq!(daemon.count(REPLACE, "route-ccache"), 1);
        assert_eq!(daemon.count(GET_PRINCIPAL, "route-ccache"), 1);
        Ok(())
    }

    /// The client's default cache, named `KCM:` by the configuration, is
    /// loaded from the KCM store and written back to it.
    #[cfg(feature = "tokio")]
    #[test]
    fn the_default_cache_of_the_client_reaches_the_built_in_kcm_store() -> Result<(), TestError> {
        use rskrb5_ng::{
            Config,
            client::{Tokio, transport::KdcProtocol},
        };

        let daemon = daemon()?;
        mit_cache()?.save_name("KCM:route-client")?;
        let config = Config::parse("[libdefaults]\n default_ccache_name = KCM:route-client\n")?;
        let client = Tokio::from_default_ccache_name(config, KdcProtocol::Tcp)?;
        assert_eq!(daemon.count(GET_PRINCIPAL, "route-client"), 1);
        client.save_default_ccache_name()?;
        assert_eq!(daemon.count(REPLACE, "route-client"), 2);
        assert_eq!(
            CCache::load_name("KCM:route-client")?.default_principal(),
            mit_cache()?.default_principal()
        );
        Ok(())
    }
}
