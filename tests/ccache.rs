//! Credential cache parsing, round-trip and environment tests.

#[path = "support/env.rs"]
mod env;

/// Credential cache parsing, round-trip and environment tests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{
        error,
        fmt::{Display, Write as _},
    };
    use std::{
        env::{VarError, temp_dir, var},
        fs::{create_dir_all, read_to_string, remove_dir, remove_file, write},
        io,
        path::PathBuf,
        process,
        time::{SystemTime, UNIX_EPOCH},
    };

    use pretty_assertions::assert_eq;
    use proptest::{
        collection,
        prelude::{Strategy, TestCaseError, any},
        prop_assert, prop_assert_eq, prop_oneof, proptest,
    };
    use rskrb5_ng::{
        ccache::{
            AuthorizationDataEntry, CCache, CacheName, Credential, CredentialTimes, EncryptionKey,
            HeaderField, HostAddress, Principal,
        },
        error::Ccache as Error,
    };

    use super::env;

    /// Error type of the `Result`-returning tests.
    type TestError = Box<dyn error::Error>;

    /// Cache, credential, config and authorization diagnostics hide all payload bytes.
    #[test]
    fn cache_debug_redacts_payloads() {
        let principal = Principal::new("R", 1, vec!["alice".to_owned()]);
        let mut credential = Credential::config_entry(
            principal.clone(),
            "metadata",
            None,
            vec![201, 202, 203, 204],
        );
        credential.second_ticket = vec![211, 212, 213, 214];
        credential
            .auth_data
            .push(AuthorizationDataEntry::new(1, vec![221, 222, 223, 224]));
        let mut cache = CCache::new(principal);
        cache.credentials_mut().push(credential.clone());
        let rendered = format!(
            "{cache:?} {credential:?} {:?} {:?}",
            cache.config_entries(),
            credential.auth_data
        );
        for marker in [
            "201, 202, 203, 204",
            "211, 212, 213, 214",
            "221, 222, 223, 224",
        ] {
            assert!(!rendered.contains(marker), "credential payload disclosed");
        }
        assert!(rendered.contains("alice") && rendered.contains("len"));
    }

    /// External callers can construct validated headers and both IP families without serde.
    #[test]
    fn constructs_header_and_ip_addresses() -> Result<(), TestError> {
        // Given explicit metadata and IP addresses.
        let value = vec![0; 8];
        // When constructing through the public input API.
        let field = HeaderField::new(1, value.clone())?;
        let ipv4 = HostAddress::ipv4([192, 0, 2, 1]);
        let ipv6 = HostAddress::ipv6([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // Then metadata is preserved and malformed offset headers are rejected.
        assert_eq!(field.value, value);
        assert_eq!((ipv4.addr_type, ipv4.address), (2_i32, vec![192, 0, 2, 1]));
        assert_eq!(ipv6.addr_type, 24_i32);
        assert_eq!(ipv6.address.len(), 16);
        assert!(HeaderField::new(1, vec![0; 7]).err().is_some());
        Ok(())
    }

    /// Manual key formatting explicitly accounts for every field before redaction.
    #[test]
    fn key_debug_has_exhaustive_field_audit() -> Result<(), TestError> {
        // Given the actual manual formatting implementation.
        let source = read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/ccache.rs"))?;
        // When selecting its field-audit pattern.
        let audited = source.contains("let Self { etype, value } = self;");
        // Then no rest pattern can swallow future secret fields.
        assert!(audited);
        Ok(())
    }

    /// Save failures have operation-neutral wording and preserve the I/O cause.
    #[test]
    fn io_display_covers_write_failures_and_retains_source() -> Result<(), TestError> {
        // Given a representative failed rename or symlink rejection.
        let failure = Error::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "save denied",
        ));
        // When formatting and traversing the public error.
        let display = failure.to_string();
        let source = error::Error::source(&failure).context("I/O cause retained")?;
        // Then writes are not described as read-only failures.
        assert!(display.contains("read or written"));
        assert_eq!(
            source
                .downcast_ref::<io::Error>()
                .context("I/O error")?
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        Ok(())
    }

    /// Attaches a description to a failure, as `expect` would, but as an error
    /// that `?` propagates.
    trait Context<T> {
        /// Returns the value, or an error that names `what`.
        fn context(self, what: &str) -> Result<T, TestError>;
    }

    impl<T, E: Display> Context<T> for Result<T, E> {
        fn context(self, what: &str) -> Result<T, TestError> {
            self.map_err(|cause| format!("{what}: {cause}").into())
        }
    }

    impl<T> Context<T> for Option<T> {
        fn context(self, what: &str) -> Result<T, TestError> {
            self.ok_or_else(|| what.into())
        }
    }

    /// The gokrb5 v4 ccache fixture: a TGT, a config entry and an HTTP service ticket.
    const CCACHE_TEST: &str = concat!(
        "0504000c00010008000000060000000000000001000000010000000b544553542e474f4b524235000000097465737475",
        "7365723100000001000000010000000b544553542e474f4b524235000000097465737475736572310000000200000002",
        "0000000b544553542e474f4b524235000000066b72627467740000000b544553542e474f4b52423500120000002088b9",
        "4319f2dcd1de20ebd3bf3174778769323bce76ef71fb37a8ba4be93c38df59665b8e59665b8e5967044e5967ad080040",
        "c1000000000000000000000000015a6182015630820152a003020105a10d1b0b544553542e474f4b524235a220301ea0",
        "03020102a11730151b066b72627467741b0b544553542e474f4b524235a382011830820114a003020112a103020101a2",
        "82010604820102ee32bb7e27ad6f71869be098c4002b291f370d26302c87ffa3eb670345a11fc113a9e5ab9e26ea6591",
        "04b29e2a60c07dda559654c58aaf5f48bbb3bb9a238745861be336a0672554dac9b38126b2929ce9df2add185d1043c6",
        "dd89c7308b9def7b98ba7bcdcd1c00eeb5d99e273e1fe53b88c057106ec3dbcf2a86c38a4c1372418f1afb0227975747",
        "edf2172e23716ab5f6fa9a2ee5c0d94e9f66936df767498677861926812d1f887de6f44e5ebd93b63fd8313a499372ea",
        "9e889620bd0842bc8a8f8a17e5dea328c77b771cfcd49ac7afa4a9c7236efa30fec1b2072255543aee48cd935ece367e",
        "08d24f51bea4b407ace8ed7e67a8d5e1cb528eb16c7ebe7ac50000000000000001000000010000000b544553542e474f",
        "4b5242350000000974657374757365723100000000000000030000000c582d4341434845434f4e463a000000156b7262",
        "355f6363616368655f636f6e665f646174610000000a666173745f617661696c0000001e6b72627467742f544553542e",
        "474f4b52423540544553542e474f4b524235000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000037965730000000000000001000000010000000b544553542e474f4b524235000000097465737475",
        "7365723100000001000000020000000b544553542e474f4b524235000000044854545000000010686f73742e74657374",
        "2e676f6b726235001200000020fd325da3f905d743894e828de41b21af7876b6281b66d9e4bb2eefd64078b47659665b",
        "8e59665bce5967044e5967ad0800408900000000000000000000000001706182016c30820168a003020105a10d1b0b54",
        "4553542e474f4b524235a2233021a003020101a11a30181b04485454501b10686f73742e746573742e676f6b726235a3",
        "82012b30820127a003020112a103020101a282011904820115ad55d79858ce41647e835769b40540bc32ff4debe10121",
        "7a7a024016697ee5ff758829940ca576905a260732c43c2996d96b83f9bff010fdbfc8f3bff51cef202a956f8d73d18c",
        "2c8865553f55229075270f42dca23d7618ff35e578a972d40746398efd478cf4f1094d99371273b3fbe5b95707011b44",
        "6ff605ea8cb0e6631ea0ffdd7b562b5aa2de5dd455388e1aa18d8a3a8e81dab058e1b223410a752e5ec82797164dabaf",
        "dbec8eeef7b072304e46d7d15b575f44cce69a368a9004612ba179b41d4655964933f7eb114a457aa1127291fc6d63de",
        "b271e5504de6fccca33260645ef5bd1ea301d74a8dbf751aa181ed92f5edb493d68222e1a34892035b88b6fb0ce104db",
        "23f7da22a8e73359d9c322b8e1cc00000000"
    );

    /// Pins the header, default principal and credentials of the gokrb5 ccache fixture.
    #[test]
    fn parses_gokrb5_ccache_fixture() -> Result<(), TestError> {
        let bytes = hex::decode(CCACHE_TEST)?;
        let cache = CCache::parse(&bytes).context("ccache fixture parses")?;

        assert_eq!(cache.version(), 4);
        assert_eq!(cache.header().fields.len(), 1);
        let field = cache
            .header()
            .fields
            .first()
            .context("header has a first field")?;
        assert_eq!(field.tag, 1);
        assert_eq!(field.value.len(), 8);
        assert_eq!(cache.default_principal().realm, "TEST.GOKRB5");
        assert_eq!(cache.default_principal().name_type, 1_i32);
        assert_eq!(cache.default_principal().components, ["testuser1"]);
        assert_eq!(cache.client_realm(), "TEST.GOKRB5");
        assert_eq!(cache.client_name(), "testuser1");
        assert_eq!(cache.credentials().len(), 3);

        assert!(
            cache.contains_server(&["krbtgt", "TEST.GOKRB5"]),
            "the cache holds the TGT"
        );
        assert!(
            cache.contains_server(&["HTTP", "host.test.gokrb5"]),
            "the cache holds the HTTP service ticket"
        );
        Ok(())
    }

    /// Pins that the gokrb5 ccache fixture serializes back byte for byte.
    #[test]
    fn roundtrips_gokrb5_ccache_fixture() -> Result<(), TestError> {
        let bytes = hex::decode(CCACHE_TEST)?;
        let cache = CCache::parse(&bytes).context("ccache fixture parses")?;
        assert_eq!(cache.to_bytes().context("ccache serializes")?, bytes);
        Ok(())
    }

    /// Pins that a ccache saved to a file path loads back unchanged.
    #[test]
    fn saves_and_loads_ccache_file() -> Result<(), TestError> {
        let bytes = hex::decode(CCACHE_TEST)?;
        let cache = CCache::parse(&bytes).context("ccache fixture parses")?;
        let path = temp_file("save-load")?;

        cache.save(&path).context("ccache saves")?;
        let loaded = CCache::load(&path).context("ccache loads")?;
        remove_file(&path).context("the test ccache is removed")?;

        assert_eq!(loaded, cache);
        Ok(())
    }

    /// Cache saves create private files and never widen existing owner modes.
    #[cfg(unix)]
    #[test]
    fn saves_cache_with_private_permissions() -> Result<(), TestError> {
        use std::{
            fs::{Permissions, metadata, set_permissions},
            os::unix::fs::PermissionsExt as _,
        };
        // Given a fresh destination and preexisting broad/restrictive files.
        let cache = CCache::parse(&hex::decode(CCACHE_TEST)?)?;
        for mode in [None, Some(0o644), Some(0o400)] {
            let path = temp_file("private-mode")?;
            if let Some(bits) = mode {
                write(&path, b"old content")?;
                set_permissions(&path, Permissions::from_mode(bits))?;
            }

            // When saving secret-bearing credentials.
            cache.save(&path)?;

            // Then permissions are owner-only and existing rights never widen.
            let actual = metadata(&path)?.permissions().mode() & 0o777;
            remove_file(&path)?;
            assert_eq!(actual, mode.unwrap_or(0o600) & 0o600);
        }
        Ok(())
    }

    /// Symlinked final destinations and dangling DIR primaries are rejected.
    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_cache_destinations_and_primary() -> Result<(), TestError> {
        use std::{
            fs::{read, remove_dir_all},
            os::unix::fs::symlink,
        };
        // Given a private tree with a linked cache and dangling primary.
        let directory = temp_file("symlink")?;
        create_dir_all(&directory)?;
        let target = directory.join("outside");
        write(&target, b"unchanged")?;
        let link = directory.join("tktLINK");
        symlink(&target, &link)?;
        symlink(directory.join("missing"), directory.join("primary"))?;
        let cache = CCache::parse(&hex::decode(CCACHE_TEST)?)?;

        // When saving through links or resolving a dangling primary.
        let saved = cache.save(&link);
        let resolved = CCache::file_path_from_cache_name(&format!("DIR:{}", directory.display()));

        // Then neither operation accepts the symlink or touches its referent.
        assert!(matches!(saved, Err(Error::Io(_))));
        assert!(matches!(resolved, Err(Error::Io(_))));
        assert_eq!(read(&target)?, b"unchanged");
        assert!(!directory.join("missing").exists());
        remove_dir_all(directory)?;
        Ok(())
    }

    /// Parent-directory links remain supported, including macOS temporary paths.
    #[cfg(unix)]
    #[test]
    fn saves_cache_through_symlinked_parent() -> Result<(), TestError> {
        use std::{fs::remove_dir_all, os::unix::fs::symlink};
        // Given a linked parent directory and regular final destination.
        let directory = temp_file("linked-parent")?;
        create_dir_all(directory.join("actual"))?;
        symlink(directory.join("actual"), directory.join("alias"))?;
        let cache = CCache::parse(&hex::decode(CCACHE_TEST)?)?;

        // When saving through the directory alias.
        cache.save(directory.join("alias/tkt"))?;

        // Then the real cache is readable from the actual parent.
        assert_eq!(CCache::load(directory.join("actual/tkt"))?, cache);
        remove_dir_all(directory)?;
        Ok(())
    }

    /// Pins that a ccache saved under the `KRB5CCNAME` file name loads back unchanged.
    #[test]
    fn saves_and_loads_ccache_from_env() -> Result<(), TestError> {
        const TEST_PATH: &str = "tests::saves_and_loads_ccache_from_env";
        if !env::in_child(TEST_PATH) {
            let path = temp_file("save-load-env")?;
            let name = format!("FILE:{}", path.display());
            env::run_in_child(TEST_PATH, &[("KRB5CCNAME", Some(name.as_ref()))]);
            return Ok(());
        }
        let bytes = hex::decode(CCACHE_TEST)?;
        let cache = CCache::parse(&bytes).context("ccache fixture parses")?;
        let name = var("KRB5CCNAME").context("the parent test sets KRB5CCNAME")?;
        let path = PathBuf::from(
            name.strip_prefix("FILE:")
                .context("KRB5CCNAME names a FILE: path")?,
        );

        cache.save_to_env().context("ccache saves to env name")?;
        let loaded = CCache::load_from_env().context("ccache loads from env name")?;
        remove_file(&path).context("the test ccache is removed")?;

        assert_eq!(loaded, cache);
        Ok(())
    }

    /// Pins that loading or saving without `KRB5CCNAME` names the missing variable.
    #[test]
    fn rejects_missing_ccache_env_name() -> Result<(), TestError> {
        const TEST_PATH: &str = "tests::rejects_missing_ccache_env_name";
        if !env::in_child(TEST_PATH) {
            env::try_run_in_child(TEST_PATH, &[("KRB5CCNAME", None)])?;
            return Ok(());
        }
        assert!(matches!(
            CCache::load_from_env()
                .err()
                .context("missing KRB5CCNAME rejected on load")?,
            Error::DefaultCacheName(VarError::NotPresent)
        ));
        assert!(matches!(
            CCache::new(Principal::new(
                "TEST.GOKRB5",
                1,
                vec!["testuser1".to_owned()],
            ))
            .save_to_env()
            .err()
            .context("missing KRB5CCNAME rejected on save")?,
            Error::DefaultCacheName(VarError::NotPresent)
        ));
        Ok(())
    }

    /// Pins the file paths that bare, `FILE:`, `WRFILE:`, `DIR::`, Windows and `%{uid}`
    /// cache names resolve to.
    #[test]
    fn resolves_file_cache_names() -> Result<(), TestError> {
        assert_eq!(
            CCache::file_path_from_cache_name("/tmp/krb5cc_1000").context("bare path resolves")?,
            PathBuf::from("/tmp/krb5cc_1000")
        );
        assert_eq!(
            CCache::file_path_from_cache_name("FILE:/tmp/krb5cc_1000")
                .context("FILE path resolves")?,
            PathBuf::from("/tmp/krb5cc_1000")
        );
        assert_eq!(
            CCache::file_path_from_cache_name("file:/tmp/krb5cc_1000")
                .context("lowercase FILE path resolves")?,
            PathBuf::from("/tmp/krb5cc_1000")
        );
        assert_eq!(
            CCache::file_path_from_cache_name("WRFILE:relative-cache")
                .context("WRFILE path resolves")?,
            PathBuf::from("relative-cache")
        );
        assert_eq!(
            CCache::file_path_from_cache_name("DIR::/run/user/1000/krb5cc/tktABC")
                .context("DIR subsidiary path resolves")?,
            PathBuf::from("/run/user/1000/krb5cc/tktABC")
        );
        assert_eq!(
            CCache::file_path_from_cache_name("dir::relative/tktABC")
                .context("lowercase DIR subsidiary path resolves")?,
            PathBuf::from("relative/tktABC")
        );
        assert_eq!(
            CCache::file_path_from_cache_name("C:\\temp\\krb5cc")
                .context("Windows path resolves")?,
            PathBuf::from("C:\\temp\\krb5cc")
        );

        Ok(())
    }

    /// Linux identity expansion ignores an inherited path-like UID value.
    #[cfg(target_os = "linux")]
    #[test]
    fn resolves_process_identity_tokens_without_uid_environment() -> Result<(), TestError> {
        const TEST_PATH: &str = "tests::resolves_process_identity_tokens_without_uid_environment";
        if !env::in_child(TEST_PATH) {
            env::try_run_in_child(TEST_PATH, &[("UID", Some("../../wrong-user".as_ref()))])?;
            return Ok(());
        }
        // Given real and effective identities independently reported by procfs.
        let status = read_to_string("/proc/self/status")?;
        let mut ids = status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .context("kernel reports identities")?
            .split_whitespace();
        let user_id = ids.next().context("real identity")?;
        let effective_id = ids.next().context("effective identity")?;

        // When resolving every file-backed cache name form.
        assert_eq!(
            CCache::file_path_from_cache_name("FILE:/tmp/krb5cc_%{uid}")
                .context("uid path token resolves")?,
            PathBuf::from(format!("/tmp/krb5cc_{user_id}"))
        );
        assert_eq!(
            CCache::file_path_from_cache_name("WRFILE:/tmp/krb5cc_%{euid}")
                .context("euid path token resolves")?,
            PathBuf::from(format!("/tmp/krb5cc_{effective_id}"))
        );
        assert_eq!(
            CCache::file_path_from_cache_name("DIR::relative/tkt_%{uid}")
                .context("DIR subsidiary uid path token resolves")?,
            PathBuf::from(format!("relative/tkt_{user_id}"))
        );
        Ok(())
    }

    /// Unsupported platforms reject UID tokens instead of inventing an identity.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn identity_tokens_require_linux_procfs() {
        for name in [
            "FILE:cache_%{uid}",
            "WRFILE:cache_%{euid}",
            "DIR::collection/tkt_%{uid}",
            "DIR:collection_%{euid}",
        ] {
            assert!(matches!(
                CCache::file_path_from_cache_name(name),
                Err(Error::IdentityUnavailable)
            ));
        }
    }

    /// Pins the file paths of typed cache names, and that a `DIR:` collection
    /// name is not a typed file name.
    #[test]
    fn parses_typed_file_cache_names() -> Result<(), TestError> {
        let parsed = CacheName::parse("FILE:/tmp/krb5cc_1000").context("FILE cache name parses")?;
        assert_eq!(parsed.file_path(), PathBuf::from("/tmp/krb5cc_1000"));
        assert_eq!(parsed.into_file_path(), PathBuf::from("/tmp/krb5cc_1000"));

        let wrfile: CacheName = "WRFILE:relative-cache"
            .parse()
            .context("WRFILE cache name parses through FromStr")?;
        assert_eq!(wrfile.file_path(), PathBuf::from("relative-cache"));

        let subsidiary =
            CacheName::parse("DIR::relative/tktABC").context("DIR subsidiary name parses")?;
        assert_eq!(subsidiary.file_path(), PathBuf::from("relative/tktABC"));

        assert!(matches!(
            CacheName::parse("DIR:relative-collection")
                .err()
                .context("DIR primary collection needs ccache resolution")?,
            Error::UnsupportedCacheType { cache_type } if cache_type == "DIR"
        ));

        let windows = CacheName::parse("C:\\temp\\krb5cc").context("Windows path parses")?;
        assert_eq!(windows.file_path(), PathBuf::from("C:\\temp\\krb5cc"));
        Ok(())
    }

    /// Pins that empty and malformed names and the API, KCM, KEYRING and MSLSA
    /// cache types are rejected.
    #[test]
    fn rejects_unsupported_cache_names() -> Result<(), TestError> {
        for (cache_name, why) in [
            ("", "empty name rejected"),
            ("FILE:", "empty FILE path rejected"),
            ("DIR:", "empty DIR collection rejected"),
            ("DIR::", "empty DIR subsidiary rejected"),
            ("DIR::tktABC", "DIR subsidiary without parent rejected"),
            (
                "DIR::relative/not-cache",
                "DIR subsidiary filename rejected",
            ),
        ] {
            assert!(
                matches!(
                    CCache::file_path_from_cache_name(cache_name)
                        .err()
                        .context(why)?,
                    Error::InvalidCacheName
                ),
                "{why}"
            );
        }
        for cache_name in ["API:", "KCM:", "KEYRING:", "MSLSA:"] {
            let expected_type = cache_name.trim_end_matches(':');
            assert!(
                matches!(
                    CCache::file_path_from_cache_name(cache_name)
                        .err()
                        .context("unsupported cache rejected")?,
                    Error::UnsupportedCacheType { cache_type } if cache_type == expected_type
                ),
                "{cache_name}"
            );
        }
        Ok(())
    }

    /// Pins that the `Debug` output of a key shows its length, not its bytes.
    #[test]
    fn encryption_key_debug_redacts_value() -> Result<(), TestError> {
        let key = EncryptionKey::new(18, vec![1, 2, 3, 4]);
        let mut debug = String::new();
        debug.write_fmt(format_args!("{key:?}"))?;

        assert_eq!(debug, "EncryptionKey { etype: 18, value_len: 4 }");
        assert!(
            !debug.contains("1, 2, 3, 4"),
            "the key bytes are not rendered"
        );
        Ok(())
    }

    /// Pins that credential metadata and its JSON carry lengths but neither key
    /// material nor ticket DER.
    #[cfg(feature = "serde")]
    #[test]
    fn ccache_metadata_json_redacts_key_and_ticket_values() -> Result<(), TestError> {
        let bytes = hex::decode(CCACHE_TEST)?;
        let cache = CCache::parse(&bytes).context("ccache parses")?;
        let metadata = cache.credential_metadata();

        assert_eq!(metadata.len(), 3);
        let first = metadata.first().context("metadata has a first entry")?;
        assert_eq!(first.client, "testuser1@TEST.GOKRB5");
        assert_eq!(first.server, "krbtgt/TEST.GOKRB5@TEST.GOKRB5");
        assert_eq!(first.etype, 18_i32);
        assert_eq!(first.key_length, 32);
        assert_eq!(first.ticket_length, 346);
        assert!(
            metadata
                .get(1)
                .context("metadata has a second entry")?
                .is_config_entry,
            "the second entry is a config entry"
        );

        let json = cache.credentials_json().context("ccache JSON renders")?;
        assert!(
            json.contains(r#""Server": "HTTP/host.test.gokrb5@TEST.GOKRB5""#),
            "{json}"
        );
        assert!(json.contains(r#""KeyLength": 32"#), "{json}");
        assert!(json.contains(r#""TicketLength": 368"#), "{json}");
        assert!(
            !json.contains("88b94319f2dcd1de20ebd3bf3174778769323bce76ef71fb37a8ba4be93c38df"),
            "raw key material is not rendered"
        );
        assert!(
            !json.contains("6182015630820152a003020105"),
            "ticket DER is not rendered"
        );
        Ok(())
    }

    /// Pins that a ccache saved by `FILE:` name loads back unchanged.
    #[test]
    fn saves_and_loads_file_cache_name() -> Result<(), TestError> {
        let bytes = hex::decode(CCACHE_TEST)?;
        let cache = CCache::parse(&bytes).context("ccache fixture parses")?;
        let path = temp_file("save-load-name")?;
        let name = format!("FILE:{}", path.display());

        cache.save_name(&name).context("ccache saves by name")?;
        let loaded = CCache::load_name(&name).context("ccache loads by name")?;
        remove_file(&path).context("the test ccache is removed")?;

        assert_eq!(loaded, cache);
        Ok(())
    }

    /// Pins that a ccache saved by `DIR::` subsidiary name loads back unchanged.
    #[test]
    fn saves_and_loads_dir_subsidiary_cache_name() -> Result<(), TestError> {
        let bytes = hex::decode(CCACHE_TEST)?;
        let cache = CCache::parse(&bytes).context("ccache fixture parses")?;
        let directory = temp_file("save-load-dir-subsidiary")?;
        create_dir_all(&directory).context("temp DIR collection is created")?;
        let path = directory.join("tktABC");
        let name = format!("DIR::{}", path.display());

        cache
            .save_name(&name)
            .context("ccache saves by DIR subsidiary name")?;
        let loaded = CCache::load_name(&name).context("ccache loads by DIR subsidiary name")?;
        remove_file(&path).context("the test ccache is removed")?;
        remove_dir(&directory).context("the test DIR collection is removed")?;

        assert_eq!(loaded, cache);
        Ok(())
    }

    /// Pins that saving by `DIR:` collection name writes the `primary` file and
    /// loads back unchanged.
    #[test]
    fn saves_and_loads_dir_primary_collection_cache_name() -> Result<(), TestError> {
        let bytes = hex::decode(CCACHE_TEST)?;
        let cache = CCache::parse(&bytes).context("ccache fixture parses")?;
        let directory = temp_file("save-load-dir-primary")?;
        create_dir_all(&directory).context("temp DIR collection is created")?;
        let name = format!("DIR:{}", directory.display());

        cache
            .save_name(&name)
            .context("ccache saves by DIR primary collection name")?;
        assert_eq!(
            read_to_string(directory.join("primary")).context("primary file is written")?,
            "tkt\n"
        );
        let loaded =
            CCache::load_name(&name).context("ccache loads by DIR primary collection name")?;
        assert_eq!(loaded, cache);

        remove_file(directory.join("tkt")).context("the test ccache is removed")?;
        remove_file(directory.join("primary")).context("the primary file is removed")?;
        remove_dir(&directory).context("the test DIR collection is removed")?;
        Ok(())
    }

    /// Pins that a `DIR:` collection saves to and loads from the cache its
    /// existing `primary` file names.
    #[test]
    fn dir_primary_collection_uses_existing_primary_file() -> Result<(), TestError> {
        let bytes = hex::decode(CCACHE_TEST)?;
        let cache = CCache::parse(&bytes).context("ccache fixture parses")?;
        let directory = temp_file("existing-dir-primary")?;
        create_dir_all(&directory).context("temp DIR collection is created")?;
        write(directory.join("primary"), b"tktABC\n").context("primary file is written")?;
        let name = format!("DIR:{}", directory.display());

        cache
            .save_name(&name)
            .context("ccache saves to existing DIR primary")?;
        assert!(
            directory.join("tktABC").exists(),
            "the cache is saved under the primary name"
        );
        let loaded = CCache::load_name(&name).context("ccache loads existing DIR primary")?;
        assert_eq!(loaded, cache);

        remove_file(directory.join("tktABC")).context("the test ccache is removed")?;
        remove_file(directory.join("primary")).context("the primary file is removed")?;
        remove_dir(&directory).context("the test DIR collection is removed")?;
        Ok(())
    }

    /// Pins that a `primary` file that names no cache file is rejected.
    #[test]
    fn dir_primary_collection_rejects_invalid_primary_file() -> Result<(), TestError> {
        let directory = temp_file("invalid-dir-primary")?;
        create_dir_all(&directory).context("temp DIR collection is created")?;
        write(directory.join("primary"), b"not-a-cache\n").context("primary file is written")?;
        let name = format!("DIR:{}", directory.display());

        assert!(matches!(
            CCache::file_path_from_cache_name(&name)
                .err()
                .context("invalid primary file rejected")?,
            Error::InvalidCacheName
        ));

        remove_file(directory.join("primary")).context("the primary file is removed")?;
        remove_dir(&directory).context("the test DIR collection is removed")?;
        Ok(())
    }

    /// Pins the client, server, key and flags of the HTTP service entry.
    #[test]
    fn gets_client_and_server_entries() -> Result<(), TestError> {
        let bytes = hex::decode(CCACHE_TEST)?;
        let cache = CCache::parse(&bytes).context("ccache fixture parses")?;

        let entry = cache
            .get_entry(&["HTTP", "host.test.gokrb5"])
            .context("HTTP service entry exists")?;
        assert_eq!(entry.server.realm, "TEST.GOKRB5");
        assert_eq!(entry.server.name_type, 1_i32);
        assert_eq!(entry.server.name_string(), "HTTP/host.test.gokrb5");
        assert_eq!(entry.client.realm, "TEST.GOKRB5");
        assert_eq!(entry.client.name_string(), "testuser1");
        assert_eq!(entry.key.etype, 18_i32);
        assert_eq!(entry.key.value.len(), 32);
        assert_eq!(entry.ticket_flags, [0x40, 0x89, 0x00, 0x00]);
        assert_eq!(entry.addresses.len(), 0);
        assert_eq!(entry.auth_data.len(), 0);
        assert_eq!(entry.second_ticket.len(), 0);
        Ok(())
    }

    /// Pins that `X-CACHECONF:` credentials are config entries, not ticket entries.
    #[test]
    fn entries_filter_out_x_cacheconf_credentials() -> Result<(), TestError> {
        let bytes = hex::decode(CCACHE_TEST)?;
        let cache = CCache::parse(&bytes).context("ccache fixture parses")?;

        let entries = cache.entries();
        assert_eq!(entries.len(), 2);
        let config_entries = cache.config_entries();
        assert_eq!(config_entries.len(), 1);
        let config_entry = config_entries
            .first()
            .context("the cache has a config entry")?;
        assert_eq!(config_entry.key, "fast_avail");
        assert_eq!(
            config_entry.principal,
            Some("krbtgt/TEST.GOKRB5@TEST.GOKRB5")
        );
        assert_eq!(config_entry.value, b"yes");
        assert_eq!(
            cache.config_entry_value("fast_avail", Some("krbtgt/TEST.GOKRB5@TEST.GOKRB5")),
            Some(b"yes".as_slice())
        );
        assert!(
            cache
                .config_entry_value("fast_avail", Some("krbtgt/OTHER.GOKRB5@OTHER.GOKRB5"))
                .is_none(),
            "no config entry exists for another principal"
        );
        assert!(
            cache
                .credentials()
                .iter()
                .any(|entry| entry.server.realm.starts_with("X-CACHECONF")),
            "the raw credentials keep the config entry"
        );
        Ok(())
    }

    /// Pins the shape of a built `X-CACHECONF:` entry, and that an upsert
    /// replaces it and returns the old one.
    #[test]
    fn builds_and_upserts_x_cacheconf_entries() -> Result<(), TestError> {
        let client = Principal::new("TEST.GOKRB5", 1, vec!["testuser1".to_owned()]);
        let credential =
            Credential::config_entry(client.clone(), "start_realm", None, b"TEST.GOKRB5".to_vec());

        assert_eq!(credential.client, client);
        assert_eq!(credential.server.realm, "X-CACHECONF:");
        assert_eq!(
            credential.server.components,
            ["krb5_ccache_conf_data", "start_realm"]
        );
        assert_eq!(credential.ticket, b"TEST.GOKRB5");
        assert_eq!(credential.key.etype, 0_i32);
        assert!(credential.key.value.is_empty(), "a config entry has no key");

        let mut cache = CCache::new(credential.client);
        assert!(
            cache
                .upsert_config_entry("start_realm", None, b"TEST.GOKRB5".to_vec())
                .is_none(),
            "the first upsert replaces nothing"
        );
        assert_eq!(cache.entries().len(), 0);
        assert_eq!(
            cache.config_entry_value("start_realm", None),
            Some(b"TEST.GOKRB5".as_slice())
        );

        let replaced = cache
            .upsert_config_entry("start_realm", None, b"OTHER.GOKRB5".to_vec())
            .context("config entry is replaced")?;
        assert_eq!(replaced.ticket, b"TEST.GOKRB5");
        assert_eq!(
            cache.config_entry_value("start_realm", None),
            Some(b"OTHER.GOKRB5".as_slice())
        );
        Ok(())
    }

    /// Pins that a credential upsert replaces the matching entry and that
    /// removing a client's entries keeps the config entry.
    #[test]
    fn upserts_and_removes_client_entries_without_dropping_config() -> Result<(), TestError> {
        let bytes = hex::decode(CCACHE_TEST)?;
        let mut cache = CCache::parse(&bytes).context("ccache fixture parses")?;
        let mut client = cache.default_principal().clone();
        client.name_type = 0_i32;
        let mut replacement = cache
            .get_entry(&["HTTP", "host.test.gokrb5"])
            .context("HTTP service entry exists")?
            .clone();
        replacement.key.value = vec![1, 2, 3, 4];

        let replaced = cache.upsert_credential(replacement.clone());
        assert!(replaced.is_some(), "the upsert replaces the HTTP entry");
        assert_eq!(cache.credentials().len(), 3);
        assert_eq!(
            cache
                .get_entry(&["HTTP", "host.test.gokrb5"])
                .context("HTTP service entry still exists")?
                .key
                .value,
            replacement.key.value
        );

        let removed = cache.remove_entries_for_client(&client);
        assert_eq!(removed.len(), 2);
        assert_eq!(cache.credentials().len(), 1);
        assert!(
            cache
                .credentials()
                .first()
                .context("one credential is left")?
                .server
                .realm
                .starts_with("X-CACHECONF"),
            "the config entry is kept"
        );
        Ok(())
    }

    /// Name-type hints do not create a second credential for the same identity.
    #[test]
    fn upsert_replaces_principal_identity_despite_name_type() -> Result<(), TestError> {
        // Given a cached service ticket and replacement hints for each principal.
        for (client_type, server_type) in [(0_i32, 1_i32), (1_i32, 2_i32), (0_i32, 2_i32)] {
            let mut cache = CCache::parse(&hex::decode(CCACHE_TEST)?)?;
            let mut replacement = cache
                .get_entry(&["HTTP", "host.test.gokrb5"])
                .context("service ticket exists")?
                .clone();
            replacement.client.name_type = client_type;
            replacement.server.name_type = server_type;
            replacement.ticket = b"replacement ticket".to_vec();

            // When upserting the replacement.
            let previous = cache.upsert_credential(replacement.clone());

            // Then lookup observes the new ticket, without a duplicate entry.
            assert!(previous.is_some());
            assert_eq!(cache.credentials().len(), 3);
            assert_eq!(
                cache.get_entry(&["HTTP", "host.test.gokrb5"]),
                Some(&replacement)
            );
        }
        Ok(())
    }

    /// Realms and component boundaries remain significant for replacement.
    #[test]
    fn upsert_preserves_distinct_principal_identities() -> Result<(), TestError> {
        // Given credentials that differ in a client realm or server components.
        let mut cache = CCache::parse(&hex::decode(CCACHE_TEST)?)?;
        let original = cache
            .get_entry(&["HTTP", "host.test.gokrb5"])
            .context("service ticket exists")?
            .clone();
        let mut other_client = original.clone();
        other_client.client.realm = "OTHER.REALM".to_owned();
        let mut other_server = original;
        other_server.server.components = vec!["HTTP/host.test.gokrb5".to_owned()];

        // When inserting the distinct identities.
        let replaced_client = cache.upsert_credential(other_client);
        let replaced_server = cache.upsert_credential(other_server);

        // Then neither replaces an existing record.
        assert!(replaced_client.is_none());
        assert!(replaced_server.is_none());
        assert_eq!(cache.credentials().len(), 5);
        Ok(())
    }

    /// Serde cannot bypass the binary format's version allowlist.
    #[cfg(feature = "serde")]
    #[test]
    fn serde_rejects_unsupported_ccache_versions() -> Result<(), TestError> {
        // Given a structurally valid cache with an unsupported version.
        let cache = CCache::new(Principal::new("EXAMPLE.ORG", 0, vec!["user".to_owned()]));
        for version in [0_u8, 5, 9, u8::MAX] {
            let mut value = serde_json::to_value(&cache)?;
            *value
                .get_mut("version")
                .context("serialized version exists")? = version.into();

            // When deserializing the cache.
            let result = serde_json::from_value::<CCache>(value);

            // Then the version is rejected before an invalid cache exists.
            assert!(
                result.is_err(),
                "unsupported version {version} was admitted"
            );
        }
        Ok(())
    }

    /// Supported serde versions retain binary serialize/parse compatibility.
    #[cfg(feature = "serde")]
    #[test]
    fn serde_supported_ccache_versions_roundtrip() -> Result<(), TestError> {
        // Given each supported format and a principal representable in version one.
        let cache = CCache::new(Principal::new("EXAMPLE.ORG", 0, vec!["user".to_owned()]));
        for version in 1_u8..=4 {
            let mut value = serde_json::to_value(&cache)?;
            *value
                .get_mut("version")
                .context("serialized version exists")? = version.into();
            let decoded: CCache = serde_json::from_value(value)?;

            // When serializing and parsing the admitted value.
            let reparsed = CCache::parse(&decoded.to_bytes()?)?;

            // Then the original admitted cache survives unchanged.
            assert_eq!(reparsed, decoded);
        }
        Ok(())
    }

    /// Legacy output rejects fields that its version cannot represent.
    #[cfg(feature = "serde")]
    #[test]
    fn legacy_ccaches_reject_unrepresentable_fields() -> Result<(), TestError> {
        // Given legacy versions with a nonempty v4 header or v1 name type.
        let cache = CCache::new(Principal::new("EXAMPLE.ORG", 1, vec!["user".to_owned()]));
        for version in 1_u8..=3 {
            let mut value = serde_json::to_value(&cache)?;
            *value.get_mut("version").context("version")? = version.into();
            if version != 1 {
                *value
                    .get_mut("header")
                    .and_then(|header| header.get_mut("fields"))
                    .context("header fields")? = serde_json::json!([{"tag":2_u16,"value":[42_u8]}]);
            }
            let decoded: CCache = serde_json::from_value(value)?;
            // When trying to serialize a value that would lose fields.
            let result = decoded.to_bytes();
            // Then reject instead of successfully writing a different object.
            assert!(result.err().is_some());
        }
        Ok(())
    }

    /// Pins the errors for empty, misversioned, truncated and negative-count ccaches.
    #[test]
    fn rejects_invalid_ccache_inputs() -> Result<(), TestError> {
        assert!(matches!(
            CCache::parse(&[]).err().context("empty ccache rejected")?,
            Error::TooShort { actual: _ }
        ));
        assert!(matches!(
            CCache::parse(&[4, 4])
                .err()
                .context("first byte rejected")?,
            Error::InvalidFirstByte(4)
        ));
        assert!(matches!(
            CCache::parse(&[5, 5]).err().context("version rejected")?,
            Error::InvalidVersion(5)
        ));
        assert!(matches!(
            CCache::parse(&[5, 4, 0, 12])
                .err()
                .context("truncated header rejected")?,
            Error::Truncated {
                offset: _,
                needed: _,
                remaining: _
            }
        ));

        let mut negative_component_count = vec![0x05, 0x04, 0x00, 0x00];
        negative_component_count.extend_from_slice(&0_i32.to_be_bytes());
        negative_component_count.extend_from_slice(&(-1_i32).to_be_bytes());
        assert!(matches!(
            CCache::parse(&negative_component_count)
                .err()
                .context("negative component count rejected")?,
            Error::NegativeLength(-1_i32)
        ));

        let mut negative_address_count = ccache_prefix_before_address_count();
        negative_address_count.extend_from_slice(&(-1_i32).to_be_bytes());
        assert!(matches!(
            CCache::parse(&negative_address_count)
                .err()
                .context("negative address count rejected")?,
            Error::NegativeLength(-1_i32)
        ));
        Ok(())
    }

    /// Pins that an impossible principal component count fails before any allocation.
    #[test]
    fn rejects_impossible_component_count() -> Result<(), TestError> {
        let mut bytes = vec![0x05, 0x04, 0x00, 0x00];
        bytes.extend_from_slice(&0_i32.to_be_bytes()); // name type
        bytes.extend_from_slice(&i32::MAX.to_be_bytes()); // component count
        bytes.extend_from_slice(&0_i32.to_be_bytes()); // realm length

        let error = CCache::parse(&bytes)
            .err()
            .context("impossible component count rejected")?;
        #[cfg(target_pointer_width = "64")]
        assert!(matches!(
            error,
            Error::Truncated {
                offset: 12,
                needed: 0x0001_FFFF_FFFC,
                remaining: 4,
            }
        ));
        #[cfg(target_pointer_width = "32")]
        assert!(matches!(error, Error::LengthOverflow));
        Ok(())
    }

    /// Pins that an impossible address count fails before any allocation.
    #[test]
    fn rejects_impossible_address_count() -> Result<(), TestError> {
        let mut bytes = ccache_prefix_before_address_count();
        bytes.extend_from_slice(&i32::MAX.to_be_bytes());

        let error = CCache::parse(&bytes)
            .err()
            .context("impossible address count rejected")?;
        #[cfg(target_pointer_width = "64")]
        assert!(matches!(
            error,
            Error::Truncated {
                offset: 71,
                needed: 12_884_901_882,
                remaining: 0,
            }
        ));
        #[cfg(target_pointer_width = "32")]
        assert!(matches!(error, Error::LengthOverflow));
        Ok(())
    }

    /// Pins that an impossible auth-data count fails before any allocation.
    #[test]
    fn rejects_impossible_auth_data_count() -> Result<(), TestError> {
        let mut bytes = ccache_prefix_before_address_count();
        bytes.extend_from_slice(&0_i32.to_be_bytes()); // no addresses
        bytes.extend_from_slice(&i32::MAX.to_be_bytes());

        let error = CCache::parse(&bytes)
            .err()
            .context("impossible auth-data count rejected")?;
        #[cfg(target_pointer_width = "64")]
        assert!(matches!(
            error,
            Error::Truncated {
                offset: 75,
                needed: 12_884_901_882,
                remaining: 0,
            }
        ));
        #[cfg(target_pointer_width = "32")]
        assert!(matches!(error, Error::LengthOverflow));
        Ok(())
    }

    /// A v4 cache prefix up to a credential's address count: empty header,
    /// empty default/client/server principals, no key, zero times and flags.
    fn ccache_prefix_before_address_count() -> Vec<u8> {
        let mut bytes = vec![0x05, 0x04, 0x00, 0x00];
        bytes.extend_from_slice(&[0_u8; 12]); // default principal
        bytes.extend_from_slice(&[0_u8; 12]); // client principal
        bytes.extend_from_slice(&[0_u8; 12]); // server principal
        bytes.extend_from_slice(&[0, 0]); // key type
        bytes.extend_from_slice(&[0_u8; 4]); // key length
        bytes.extend_from_slice(&[0_u8; 16]); // times
        bytes.push(0); // is_skey
        bytes.extend_from_slice(&[0_u8; 4]); // ticket flags
        bytes
    }

    /// Returns a unique path in the temporary directory for the test `name`.
    fn temp_file(name: &str) -> Result<PathBuf, TestError> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("current time is after unix epoch")?
            .as_nanos();
        Ok(temp_dir().join(format!("rskrb5-ccache-{name}-{}-{nanos}", process::id())))
    }

    /// A v4 cache header with an empty header-field block.
    const V4_EMPTY_HEADER: [u8; 4] = [0x05, 0x04, 0x00, 0x00];

    /// The ccache magic first byte.
    const CCACHE_MAGIC: u8 = 0x05;

    /// Offset right after the default principal's component count: the
    /// header, the name type and the count field.
    const COUNT_END: usize = 12;

    /// Minimum encoded size of one principal component: a four-byte length.
    const MIN_COMPONENT_LEN: usize = 4;

    /// Largest generated input: 4 KiB.
    const MAX_INPUT_LEN: usize = 4096;

    /// Largest tail after the two-byte magic and version prefix, so the whole
    /// input stays within [`MAX_INPUT_LEN`].
    const MAX_TAIL_LEN: usize = 4094;

    /// Arbitrary inputs up to [`MAX_INPUT_LEN`]: half fully random, half
    /// behind the ccache magic byte and a supported version, so the parser
    /// gets past its first checks.
    fn arbitrary_input() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            collection::vec(any::<u8>(), 0..=MAX_INPUT_LEN),
            (1_u8..=4_u8, collection::vec(any::<u8>(), 0..=MAX_TAIL_LEN)).prop_map(
                |(version, tail)| [CCACHE_MAGIC, version].into_iter().chain(tail).collect()
            ),
        ]
    }

    proptest! {
        /// Any component count, with the input cut right after the count
        /// field, is rejected before allocation and never panics: on 64-bit
        /// targets as `Truncated` with `needed == count * 4`, on 32-bit
        /// targets as `Truncated` or `LengthOverflow`.
        #[test]
        fn component_count_is_bounded_by_remaining_input(
            name_type in any::<i32>(),
            count in 1_i32..=i32::MAX,
        ) {
            let bytes: Vec<u8> = V4_EMPTY_HEADER
                .into_iter()
                .chain(name_type.to_be_bytes())
                .chain(count.to_be_bytes())
                .collect();
            let expected_needed = usize::try_from(count)?.checked_mul(MIN_COMPONENT_LEN);

            let parsed = CCache::parse(&bytes);
            if let Err(Error::Truncated { offset, needed, remaining }) = parsed {
                prop_assert_eq!(offset, COUNT_END);
                prop_assert_eq!(remaining, 0);
                prop_assert_eq!(Some(needed), expected_needed);
            } else if matches!(parsed, Err(Error::LengthOverflow)) {
                prop_assert!(
                    cfg!(target_pointer_width = "32") && expected_needed.is_none(),
                    "LengthOverflow only when count * 4 overflows a 32-bit usize"
                );
            } else {
                return Err(TestCaseError::fail(format!(
                    "count {count} was not rejected as truncated: {parsed:?}"
                )));
            }
        }

        /// Arbitrary input up to 4 KiB never panics the parser, and every
        /// rejection renders a non-empty diagnostic.
        #[test]
        fn parse_never_panics_on_arbitrary_input(bytes in arbitrary_input()) {
            if let Err(error) = CCache::parse(&bytes) {
                prop_assert!(!error.to_string().is_empty(), "empty diagnostic for {error:?}");
            }
        }
    }

    /// One generated credential: principal names, key, times, flags,
    /// addresses, authorization data and tickets.
    type CredentialParts = (
        (String, i32, Vec<String>),
        (i16, Vec<u8>, [u32; 4], bool, [u8; 4]),
        (Vec<(i16, Vec<u8>)>, Vec<(i16, Vec<u8>)>, Vec<u8>, Vec<u8>),
    );

    /// A principal of the representable shape: UTF-8 realm and components.
    fn principal_parts() -> impl Strategy<Value = (String, i32, Vec<String>)> {
        (
            "[a-zA-Z0-9.@/:-]{0,24}",
            any::<i32>(),
            collection::vec("[a-zA-Z0-9.@/:-]{0,24}", 0..4),
        )
    }

    /// Every field of a credential the ccache format can carry.
    fn credential_parts() -> impl Strategy<Value = CredentialParts> {
        let counted = || collection::vec((any::<i16>(), collection::vec(any::<u8>(), 0..24)), 0..3);
        (
            principal_parts(),
            (
                any::<i16>(),
                collection::vec(any::<u8>(), 0..40),
                any::<[u32; 4]>(),
                any::<bool>(),
                any::<[u8; 4]>(),
            ),
            (
                counted(),
                counted(),
                collection::vec(any::<u8>(), 0..64),
                collection::vec(any::<u8>(), 0..16),
            ),
        )
    }

    /// Builds the credential `parts` describes.
    fn credential(parts: CredentialParts) -> Credential {
        let (
            (realm, name_type, components),
            (etype, key, [auth_time, start_time, end_time, renew_till], is_skey, flags),
            (addresses, auth_data, ticket, second_ticket),
        ) = parts;
        let mut times = CredentialTimes::default();
        times.auth_time = auth_time;
        times.start_time = start_time;
        times.end_time = end_time;
        times.renew_till = renew_till;
        let client = Principal::new(realm.clone(), name_type, components.clone());
        let mut server_components = components;
        server_components.push("service".to_owned());
        Credential::new(
            client,
            Principal::new(realm, name_type, server_components),
            EncryptionKey::new(i32::from(etype), key),
            times,
            flags,
            ticket,
        )
        .with_is_skey(is_skey)
        .with_addresses(
            addresses
                .into_iter()
                .map(|(addr_type, address)| HostAddress::new(addr_type, address))
                .collect(),
        )
        .with_auth_data(
            auth_data
                .into_iter()
                .map(|(ad_type, data)| AuthorizationDataEntry::new(i32::from(ad_type), data))
                .collect(),
        )
        .with_second_ticket(second_ticket)
    }

    proptest! {
        /// Every cache built through the API survives serialization and
        /// parsing unchanged, and its serialization is a fixed point.
        #[test]
        fn serialized_ccache_roundtrips(
            (realm, name_type, components) in principal_parts(),
            credentials in collection::vec(credential_parts(), 0..4),
        ) {
            let mut cache = CCache::new(Principal::new(realm, name_type, components));
            for parts in credentials {
                cache.credentials_mut().push(credential(parts));
            }
            let bytes = cache.to_bytes()?;
            let parsed = CCache::parse(&bytes)?;
            prop_assert_eq!(&parsed, &cache);
            prop_assert_eq!(parsed.to_bytes()?, bytes);
        }
    }
}
