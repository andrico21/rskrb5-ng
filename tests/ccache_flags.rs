//! Ticket flags in credential-cache versions 1 and 2 are stored in host byte
//! order, as MIT 1.22.2 reads and writes them through `get32`/`put32`
//! (`src/lib/krb5/ccache/ccmarshal.c:118-122, 301, 349-358, 443`); versions 3
//! and 4 store them big-endian (supervisor validation Y4-03).

/// Ticket flag byte-order tests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error;
    use std::{fs, path::Path};

    use rskrb5_ng::ccache::{
        CCache, Credential, CredentialTimes, EncryptionKey, Principal, stores::CacheVersion,
    };

    /// Error type of the `Result`-returning tests.
    type TestError = Box<dyn error::Error>;

    /// MIT `TKT_FLG_INITIAL | TKT_FLG_ENC_PA_REP`
    /// (`src/include/krb5/krb5.hin:1726, 1731`).
    const INITIAL_ENC_PA_REP: u32 = 0x0041_0000;
    /// MIT `TKT_FLG_FORWARDABLE | TKT_FLG_RENEWABLE | TKT_FLG_INITIAL |
    /// TKT_FLG_PRE_AUTH` (`krb5.hin:1718-1727`).
    const FORWARDABLE_RENEWABLE_INITIAL_PREAUTH: u32 = 0x40E0_0000;
    /// The ticket bytes of the synthetic credential.
    const TICKET: [u8; 5] = [7; 5];
    /// Bytes from the flags to the end of that credential: the flags (4), the
    /// address and authorization-data counts (4 + 4), the counted ticket
    /// (4 + 5) and the counted empty second ticket (4).
    const FLAGS_TO_END: usize = 25;

    /// The flag bytes a version stores for `flags`: host order before
    /// version 3, big-endian from version 3 on.
    fn stored(flags: u32, version: u8) -> [u8; 4] {
        if version < 3 && cfg!(target_endian = "little") {
            flags.to_le_bytes()
        } else {
            flags.to_be_bytes()
        }
    }

    /// The flag bytes of the last credential of a serialized cache.
    ///
    /// The last credential has no addresses or authorization data, the 5-byte
    /// [`TICKET`] and an empty second ticket.
    fn last_flags(bytes: &[u8]) -> Option<[u8; 4]> {
        let start = bytes.len().checked_sub(FLAGS_TO_END)?;
        bytes.get(start..start.checked_add(4)?)?.try_into().ok()
    }

    /// The caches MIT `kinit` wrote with `ccache_type` 1 to 4 carry the same flags.
    ///
    /// They are `INITIAL`, the one flag MIT `klist -f` 1.22.1 shows for each
    /// file (`Flags: I`), and `ENC_PA_REP`, which `klist` has no letter for
    /// (`src/clients/klist/klist.c:606-640`). The API reports them in network
    /// order.
    #[test]
    fn mit_written_caches_decode_their_flags() -> Result<(), TestError> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ccache-mit");
        for number in 1_u8..=4 {
            let bytes = fs::read(root.join(format!("mit-v{number}")))?;
            let cache = CCache::parse(&bytes)?;
            let tgt = cache
                .get_entry(&["krbtgt", "TEST.RSKRB5"])
                .ok_or("the fixture holds a TGT")?;
            assert_eq!(
                tgt.ticket_flags(),
                INITIAL_ENC_PA_REP.to_be_bytes(),
                "version {number}"
            );
            assert_eq!(cache.to_bytes()?, bytes, "version {number} round trip");
        }
        Ok(())
    }

    /// Every version writes the flags in its byte order and reads them back
    /// unchanged, including a version 4 cache converted to version 2. The
    /// principals use name type 0, which version 1 can represent.
    #[test]
    fn every_version_writes_flags_in_its_byte_order() -> Result<(), TestError> {
        let client = Principal::new("TEST", 0, vec!["alice".to_owned()]);
        let mut times = CredentialTimes::default();
        times.auth_time = 1;
        times.end_time = 2;
        let credential = Credential::new(
            client.clone(),
            Principal::new("TEST", 0, vec!["krbtgt".to_owned(), "TEST".to_owned()]),
            EncryptionKey::new(18, vec![9; 32]),
            times,
            FORWARDABLE_RENEWABLE_INITIAL_PREAUTH.to_be_bytes(),
            TICKET.to_vec().into(),
        );
        let mut cache = CCache::new(client);
        drop(cache.upsert_credential(credential));
        for number in [4_u8, 3, 2, 1] {
            cache.set_version(CacheVersion::new(i32::from(number))?);
            let bytes = cache.to_bytes()?;
            assert_eq!(
                last_flags(&bytes),
                Some(stored(FORWARDABLE_RENEWABLE_INITIAL_PREAUTH, number)),
                "version {number}"
            );
            let reread = CCache::parse(&bytes)?;
            let flags = reread.credentials().first().map(Credential::ticket_flags);
            assert_eq!(
                flags,
                Some(FORWARDABLE_RENEWABLE_INITIAL_PREAUTH.to_be_bytes()),
                "version {number}"
            );
        }
        Ok(())
    }
}
