//! Keytab parsing, round-trip and environment tests.

#[path = "support/env.rs"]
mod env;

/// Keytab parsing, round-trip and environment tests.
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
        fs::{read_to_string, remove_file},
        path::PathBuf,
        process,
        time::{SystemTime, UNIX_EPOCH},
    };

    use proptest::{collection, prelude::any, prop_assert_eq, proptest};
    use rskrb5_ng::{
        error::Keytab as Error,
        keytab::{EncryptionKey, Entry, Keytab, Name, Principal},
    };

    use super::env;

    /// Error type of the `Result`-returning tests.
    type TestError = Box<dyn error::Error>;

    /// Owning keytab input retains its original allocation inside a zeroizing owner.
    #[test]
    fn moved_password_owner_erasure_probe() -> Result<(), TestError> {
        use zeroize::Zeroizing;
        let bytes = b"password".to_vec();
        let address = bytes.as_ptr();
        let password = Zeroizing::new(bytes);
        assert_eq!(password.as_ptr(), address);
        let mut keys = Keytab::new();
        keys.add_entry_from_password(
            Principal::new("R", 1, ["alice"]),
            password,
            UNIX_EPOCH,
            1,
            17,
        )?;
        assert_eq!(keys.entries().len(), 1);
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

    /// The gokrb5 `testuser1@TEST.GOKRB5` keytab with twelve entries.
    const KEYTAB_TESTUSER1_TEST_GOKRB5: &str = "05020000003b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d80100110010698c4df8e9f60e7eea5a21bf4526ad25000000010000004b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d80100120020bbdc430aab7e2d4622a0b6951481453b0962e9db8e2f168942ad175cda6d9de9000000010000003b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d80200110010698c4df8e9f60e7eea5a21bf4526ad25000000020000004b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d80200120020bbdc430aab7e2d4622a0b6951481453b0962e9db8e2f168942ad175cda6d9de9000000020000003b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d801001300102eb8501967a7886e1f0c63ac9be8c4a0000000010000003b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d802001300102eb8501967a7886e1f0c63ac9be8c4a0000000020000004b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d801001400208ad66f209bb07daa186f8a229830f5ba06a3a2a33638f4ec66e1d29324e417ee000000010000004b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d802001400208ad66f209bb07daa186f8a229830f5ba06a3a2a33638f4ec66e1d29324e417ee00000002000000430001000b544553542e474f4b52423500097465737475736572310000000159beb1d801001000184580fb91760dabe6f808c22c26494f644cb35d61d32c79e300000001000000430001000b544553542e474f4b52423500097465737475736572310000000159beb1d802001000184580fb91760dabe6f808c22c26494f644cb35d61d32c79e3000000020000003b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d80100170010084768c373663b3bef1f6385883cf7ff000000010000003b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d80200170010084768c373663b3bef1f6385883cf7ff00000002";
    /// A ktutil user keytab for `user@EXAMPLE.ORG`, password `hello123`, kvno 31.
    const KTUTIL_USER_KEYTAB: &str = "0502000000460001000b4558414d504c452e4f5247000475736572000000015e5e3d001f001200206e88eb2b3931ef17c92e780a4ee421f1411ff5b104e3f75b50dd13f9ed04f9c60000001f000000360001000b4558414d504c452e4f5247000475736572000000015e5e3d001f001100109bb7d5ba0f554412558441a31f2377120000001f000000360001000b4558414d504c452e4f5247000475736572000000015e5e3d001f00170010110d0c51e144d36fb7e4f9e012fbb8880000001f";
    /// A ktutil service keytab for `HTTP/www.example.org@EXAMPLE.ORG`, password `hello456`, kvno 10.
    const KTUTIL_SERVICE_KEYTAB: &str = "0502000000570002000b4558414d504c452e4f5247000448545450000f7777772e6578616d706c652e6f7267000000015e5e3d820a001200203824a933909d899427d7ead4b4bb6deac4eb83949ac350d724c6a2eef0d627440000000a000000470002000b4558414d504c452e4f5247000448545450000f7777772e6578616d706c652e6f7267000000015e5e3d820a001100103a5cce80f2111d63b1ccf445691384230000000a000000470002000b4558414d504c452e4f5247000448545450000f7777772e6578616d706c652e6f7267000000015e5e3d820a00170010b3f6ed87c7d13879ac3f86b4991099740000000a";

    /// Pins the version, entry count and first entry of the gokrb5 keytab fixture.
    #[test]
    fn parses_gokrb5_keytab_fixture() -> Result<(), TestError> {
        let bytes = hex::decode(KEYTAB_TESTUSER1_TEST_GOKRB5)?;
        let keytab = Keytab::parse(&bytes).context("keytab fixture parses")?;

        assert_eq!(keytab.version(), 2);
        assert_eq!(keytab.entries().len(), 12);

        let first = keytab
            .entries()
            .first()
            .context("keytab has a first entry")?;
        assert_eq!(first.kvno, 1);
        assert_eq!(first.kvno8, 1);
        assert_eq!(first.timestamp, 1_505_669_592);
        assert_eq!(first.key.etype, 17_i32);
        assert_eq!(
            hex::encode(&first.key.value),
            "698c4df8e9f60e7eea5a21bf4526ad25"
        );
        assert_eq!(first.principal.realm, "TEST.GOKRB5");
        assert_eq!(first.principal.components, ["testuser1"]);
        assert_eq!(first.principal.name_type, 1_i32);
        Ok(())
    }

    /// Pins that the gokrb5 keytab fixture serializes back byte for byte.
    #[test]
    fn roundtrips_gokrb5_keytab_fixture() -> Result<(), TestError> {
        let bytes = hex::decode(KEYTAB_TESTUSER1_TEST_GOKRB5)?;
        let keytab = Keytab::parse(&bytes).context("keytab fixture parses")?;
        assert_eq!(keytab.to_bytes().context("keytab serializes")?, bytes);
        Ok(())
    }

    /// Pins that password-derived user entries match the ktutil keytab byte for byte.
    #[test]
    fn generates_gokrb5_user_keytab_entries_from_password() -> Result<(), TestError> {
        let expected = hex::decode(KTUTIL_USER_KEYTAB)?;
        let expected_keytab = Keytab::parse(&expected).context("ktutil keytab parses")?;
        let timestamp = expected_keytab
            .entries()
            .first()
            .context("ktutil keytab has a first entry")?
            .system_time();
        let mut keytab = Keytab::new();
        let principal = Principal::new("EXAMPLE.ORG", 1, ["user"]);

        for etype in [18_i32, 17_i32, 23_i32] {
            keytab
                .add_entry_from_password(
                    principal.clone(),
                    b"hello123".to_vec().into(),
                    timestamp,
                    31,
                    etype,
                )
                .context("entry is added")?;
        }

        assert_eq!(keytab.to_bytes().context("keytab serializes")?, expected);
        let mut borrowed = Keytab::new();
        for etype in [18_i32, 17_i32, 23_i32] {
            borrowed
                .add_entry_from_password_ref(principal.clone(), b"hello123", timestamp, 31, etype)
                .context("borrowed-password entry is added")?;
        }
        assert_eq!(
            borrowed.to_bytes().context("borrowed keytab serializes")?,
            expected
        );
        Ok(())
    }

    /// Pins that password-derived service entries match the ktutil keytab byte for byte.
    #[test]
    fn generates_gokrb5_service_keytab_entries_from_password() -> Result<(), TestError> {
        let expected = hex::decode(KTUTIL_SERVICE_KEYTAB)?;
        let expected_keytab = Keytab::parse(&expected).context("ktutil keytab parses")?;
        let timestamp = expected_keytab
            .entries()
            .first()
            .context("ktutil keytab has a first entry")?
            .system_time();
        let mut keytab = Keytab::new();
        let principal = Principal::new("EXAMPLE.ORG", 1, ["HTTP", "www.example.org"]);

        for etype in [18_i32, 17_i32, 23_i32] {
            keytab
                .add_entry_from_password(
                    principal.clone(),
                    b"hello456".to_vec().into(),
                    timestamp,
                    10,
                    etype,
                )
                .context("entry is added")?;
        }

        assert_eq!(keytab.to_bytes().context("keytab serializes")?, expected);
        Ok(())
    }

    /// Pins that entries added by principal name match the ktutil keytab, and that
    /// an empty name component is rejected.
    #[test]
    fn generates_gokrb5_keytab_entries_from_principal_name() -> Result<(), TestError> {
        let expected = hex::decode(KTUTIL_SERVICE_KEYTAB)?;
        let expected_keytab = Keytab::parse(&expected).context("ktutil keytab parses")?;
        let timestamp = expected_keytab
            .entries()
            .first()
            .context("ktutil keytab has a first entry")?
            .system_time();
        let mut keytab = Keytab::new();

        for etype in [18_i32, 17_i32, 23_i32] {
            keytab
                .add_entry_from_password_name(
                    "HTTP/www.example.org",
                    "EXAMPLE.ORG",
                    b"hello456".to_vec().into(),
                    timestamp,
                    10,
                    etype,
                )
                .context("entry is added")?;
        }

        assert_eq!(keytab.to_bytes().context("keytab serializes")?, expected);
        assert!(matches!(
            Principal::from_name("EXAMPLE.ORG", 1, "HTTP/")
                .err()
                .context("empty component rejected")?,
            Error::InvalidPrincipalName
        ));
        Ok(())
    }

    /// Pins that a keytab saved to a file path loads back unchanged.
    #[test]
    fn saves_and_loads_keytab_file() -> Result<(), TestError> {
        let bytes = hex::decode(KEYTAB_TESTUSER1_TEST_GOKRB5)?;
        let keytab = Keytab::parse(&bytes).context("keytab fixture parses")?;
        let path = temp_file("save-load")?;

        keytab.save(&path).context("keytab saves")?;
        let loaded = Keytab::load(&path).context("keytab loads")?;
        remove_file(&path).context("the test keytab is removed")?;

        assert_eq!(loaded, keytab);
        Ok(())
    }

    /// Keytab saves create private files without widening existing permissions.
    #[cfg(unix)]
    #[test]
    fn saves_keytab_with_private_permissions() -> Result<(), TestError> {
        use std::{
            fs::{Permissions, metadata, set_permissions, write},
            os::unix::fs::PermissionsExt as _,
        };
        // Given fresh and existing files with broad or restrictive modes.
        let keytab = Keytab::parse(&hex::decode(KTUTIL_USER_KEYTAB)?)?;
        for mode in [None, Some(0o644), Some(0o400)] {
            let path = temp_file("private-mode")?;
            if let Some(bits) = mode {
                write(&path, b"old content")?;
                set_permissions(&path, Permissions::from_mode(bits))?;
            }

            // When persisting the keytab.
            keytab.save(&path)?;

            // Then only the prior owner permissions survive.
            let actual = metadata(&path)?.permissions().mode() & 0o777;
            remove_file(&path)?;
            assert_eq!(actual, mode.unwrap_or(0o600) & 0o600);
        }
        Ok(())
    }

    /// Keytab saves reject final symlinks without replacing their referents.
    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_keytab_destination() -> Result<(), TestError> {
        use std::{
            fs::{create_dir_all, read, remove_dir_all, write},
            os::unix::fs::symlink,
        };
        // Given a symlink to a dummy file in the test tree.
        let directory = temp_file("symlink")?;
        create_dir_all(&directory)?;
        let target = directory.join("outside");
        write(&target, b"unchanged")?;
        let link = directory.join("keytab");
        symlink(&target, &link)?;
        let keytab = Keytab::parse(&hex::decode(KTUTIL_USER_KEYTAB)?)?;

        // When saving through the final symlink.
        let result = keytab.save(&link);

        // Then reject the link and preserve the original referent.
        assert!(result.is_err());
        assert_eq!(read(target)?, b"unchanged");
        remove_dir_all(directory)?;
        Ok(())
    }

    /// Pins that a keytab saved under the `KRB5_KTNAME` file name loads back unchanged.
    #[test]
    fn saves_and_loads_keytab_from_env() -> Result<(), TestError> {
        const TEST_PATH: &str = "tests::saves_and_loads_keytab_from_env";
        if !env::in_child(TEST_PATH) {
            let path = temp_file("save-load-env")?;
            let name = format!("FILE:{}", path.display());
            env::run_in_child(TEST_PATH, &[("KRB5_KTNAME", Some(name.as_ref()))]);
            return Ok(());
        }
        let bytes = hex::decode(KEYTAB_TESTUSER1_TEST_GOKRB5)?;
        let keytab = Keytab::parse(&bytes).context("keytab fixture parses")?;
        let name = var("KRB5_KTNAME").context("the parent test sets KRB5_KTNAME")?;
        let path = PathBuf::from(
            name.strip_prefix("FILE:")
                .context("KRB5_KTNAME names a FILE: path")?,
        );

        keytab.save_to_env().context("keytab saves to env name")?;
        let loaded = Keytab::load_from_env().context("keytab loads from env name")?;
        remove_file(&path).context("the test keytab is removed")?;

        assert_eq!(loaded, keytab);
        Ok(())
    }

    /// Pins that loading or saving without `KRB5_KTNAME` names the missing variable.
    #[test]
    fn rejects_missing_keytab_env_name() -> Result<(), TestError> {
        const TEST_PATH: &str = "tests::rejects_missing_keytab_env_name";
        if !env::in_child(TEST_PATH) {
            env::try_run_in_child(TEST_PATH, &[("KRB5_KTNAME", None)])?;
            return Ok(());
        }
        assert!(matches!(
            Keytab::load_from_env()
                .err()
                .context("missing KRB5_KTNAME rejected on load")?,
            Error::DefaultKeytabName(VarError::NotPresent)
        ));
        assert!(matches!(
            Keytab::new()
                .save_to_env()
                .err()
                .context("missing KRB5_KTNAME rejected on save")?,
            Error::DefaultKeytabName(VarError::NotPresent)
        ));
        Ok(())
    }

    /// Pins the file paths that bare, `FILE:`, `WRFILE:`, Windows and `%{uid}` keytab names resolve to.
    #[test]
    fn resolves_file_keytab_names() -> Result<(), TestError> {
        assert_eq!(
            Keytab::file_path_from_keytab_name("/etc/krb5.keytab").context("bare path resolves")?,
            PathBuf::from("/etc/krb5.keytab")
        );
        assert_eq!(
            Keytab::file_path_from_keytab_name("FILE:/etc/krb5.keytab")
                .context("FILE path resolves")?,
            PathBuf::from("/etc/krb5.keytab")
        );
        assert_eq!(
            Keytab::file_path_from_keytab_name("file:/etc/krb5.keytab")
                .context("lowercase FILE path resolves")?,
            PathBuf::from("/etc/krb5.keytab")
        );
        assert_eq!(
            Keytab::file_path_from_keytab_name("WRFILE:relative.keytab")
                .context("WRFILE path resolves")?,
            PathBuf::from("relative.keytab")
        );
        assert_eq!(
            Keytab::file_path_from_keytab_name("C:\\temp\\krb5.keytab")
                .context("Windows path resolves")?,
            PathBuf::from("C:\\temp\\krb5.keytab")
        );

        Ok(())
    }

    /// Linux keytab identity tokens use kernel identities, never UID text.
    #[cfg(target_os = "linux")]
    #[test]
    fn resolves_keytab_process_identity_tokens() -> Result<(), TestError> {
        const TEST_PATH: &str = "tests::resolves_keytab_process_identity_tokens";
        if !env::in_child(TEST_PATH) {
            env::try_run_in_child(TEST_PATH, &[("UID", Some("../../wrong-user".as_ref()))])?;
            return Ok(());
        }
        // Given identities reported by the running kernel.
        let status = read_to_string("/proc/self/status")?;
        let mut ids = status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .context("kernel reports identities")?
            .split_whitespace();
        let user_id = ids.next().context("real identity")?;
        let effective_id = ids.next().context("effective identity")?;

        // When resolving keytab tokens, both identity roles stay explicit.
        assert_eq!(
            Keytab::file_path_from_keytab_name("FILE:/tmp/krb5_%{uid}.keytab")
                .context("uid path token resolves")?,
            PathBuf::from(format!("/tmp/krb5_{user_id}.keytab"))
        );
        assert_eq!(
            Keytab::file_path_from_keytab_name("WRFILE:/tmp/krb5_%{euid}.keytab")
                .context("euid path token resolves")?,
            PathBuf::from(format!("/tmp/krb5_{effective_id}.keytab"))
        );
        Ok(())
    }

    /// Unsupported platforms reject identity tokens with the named error.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn keytab_identity_tokens_require_linux_procfs() {
        assert!(matches!(
            Keytab::file_path_from_keytab_name("FILE:key_%{uid}_%{euid}"),
            Err(Error::IdentityUnavailable)
        ));
    }

    /// Pins the file paths of typed `FILE:`, `WRFILE:` and Windows keytab names.
    #[test]
    fn parses_typed_file_keytab_names() -> Result<(), TestError> {
        let parsed = Name::parse("FILE:/etc/krb5.keytab").context("FILE keytab name parses")?;
        assert_eq!(parsed.file_path(), PathBuf::from("/etc/krb5.keytab"));
        assert_eq!(parsed.into_file_path(), PathBuf::from("/etc/krb5.keytab"));

        let wrfile: Name = "WRFILE:relative.keytab"
            .parse()
            .context("WRFILE keytab name parses through FromStr")?;
        assert_eq!(wrfile.file_path(), PathBuf::from("relative.keytab"));

        let windows = Name::parse("C:\\temp\\krb5.keytab").context("Windows path parses")?;
        assert_eq!(windows.file_path(), PathBuf::from("C:\\temp\\krb5.keytab"));
        Ok(())
    }

    /// Pins that empty names and `DIR:`/`MEMORY:` keytab types are rejected.
    #[test]
    fn rejects_unsupported_keytab_names() -> Result<(), TestError> {
        assert!(matches!(
            Keytab::file_path_from_keytab_name("")
                .err()
                .context("empty name rejected")?,
            Error::InvalidKeytabName
        ));
        assert!(matches!(
            Keytab::file_path_from_keytab_name("FILE:")
                .err()
                .context("empty FILE path rejected")?,
            Error::InvalidKeytabName
        ));
        assert!(matches!(
            Keytab::file_path_from_keytab_name("DIR:/tmp/krb5.keytab")
                .err()
                .context("DIR keytab rejected")?,
            Error::UnsupportedKeytabType { keytab_type } if keytab_type == "DIR"
        ));
        assert!(matches!(
            Keytab::file_path_from_keytab_name("MEMORY:test")
                .err()
                .context("MEMORY keytab rejected")?,
            Error::UnsupportedKeytabType { keytab_type } if keytab_type == "MEMORY"
        ));
        Ok(())
    }

    /// Pins that the `Debug` output of a key shows its length, not its bytes.
    #[test]
    fn encryption_key_debug_redacts_value() -> Result<(), TestError> {
        let key = EncryptionKey::new(18, vec![1, 2, 3, 4]);
        let mut debug = String::new();
        debug.write_fmt(format_args!("{key:?}"))?;

        assert_eq!(debug, "EncryptionKey { etype: 18, value_len: 4 }");
        assert_eq!(format!("{:?}", key.value), "KeyBytes { len: 4 }");
        assert!(
            !debug.contains("1, 2, 3, 4"),
            "the key bytes are not rendered"
        );
        Ok(())
    }

    /// Pins that keytab metadata and its JSON carry key lengths but no key material.
    #[cfg(feature = "serde")]
    #[test]
    fn keytab_metadata_json_redacts_key_values() -> Result<(), TestError> {
        let bytes = hex::decode(KTUTIL_USER_KEYTAB)?;
        let keytab = Keytab::parse(&bytes).context("keytab parses")?;
        let metadata = keytab.entry_metadata();

        assert_eq!(metadata.len(), 3);
        let first = metadata.first().context("metadata has a first entry")?;
        assert_eq!(first.principal, "user@EXAMPLE.ORG");
        assert_eq!(first.etype, 18_i32);
        assert_eq!(first.key_length, 32);

        let json = keytab.entries_json().context("keytab JSON renders")?;
        assert!(
            json.contains(r#""Principal": "user@EXAMPLE.ORG""#),
            "{json}"
        );
        assert!(json.contains(r#""KeyLength": 32"#), "{json}");
        assert!(
            !json.contains("6e88eb2b3931ef17c92e780a4ee421f1411ff5b104e3f75b50dd13f9ed04f9c6"),
            "raw key material is not rendered"
        );
        Ok(())
    }

    /// Pins that a keytab saved by `FILE:` name loads back unchanged.
    #[test]
    fn saves_and_loads_file_keytab_name() -> Result<(), TestError> {
        let bytes = hex::decode(KEYTAB_TESTUSER1_TEST_GOKRB5)?;
        let keytab = Keytab::parse(&bytes).context("keytab fixture parses")?;
        let path = temp_file("save-load-name")?;
        let name = format!("FILE:{}", path.display());

        keytab.save_name(&name).context("keytab saves by name")?;
        let loaded = Keytab::load_name(&name).context("keytab loads by name")?;
        remove_file(&path).context("the test keytab is removed")?;

        assert_eq!(loaded, keytab);
        Ok(())
    }

    /// Pins the key found by principal, kvno and etype, and that an unknown principal finds none.
    #[test]
    fn finds_matching_key_by_principal_kvno_and_etype() -> Result<(), TestError> {
        let bytes = hex::decode(KEYTAB_TESTUSER1_TEST_GOKRB5)?;
        let keytab = Keytab::parse(&bytes).context("keytab fixture parses")?;

        let (key, kvno) = keytab
            .find_key(&["testuser1"], "TEST.GOKRB5", 2, 18)
            .context("matching key exists")?;
        assert_eq!(kvno, 2);
        assert_eq!(key.etype, 18_i32);
        assert_eq!(
            hex::encode(&key.value),
            "bbdc430aab7e2d4622a0b6951481453b0962e9db8e2f168942ad175cda6d9de9"
        );

        assert!(
            keytab
                .find_key(&["testuser2"], "TEST.GOKRB5", 0, 18)
                .err()
                .is_some(),
            "an unknown principal has no key"
        );
        Ok(())
    }

    /// Pins the DES3 and RC4-HMAC keys found in the gokrb5 keytab fixture.
    #[test]
    fn finds_rc4_hmac_and_des3_keys_from_gokrb5_fixture() -> Result<(), TestError> {
        let bytes = hex::decode(KEYTAB_TESTUSER1_TEST_GOKRB5)?;
        let keytab = Keytab::parse(&bytes).context("keytab fixture parses")?;

        let (des3_key, des3_kvno) = keytab
            .find_key(&["testuser1"], "TEST.GOKRB5", 2, 16)
            .context("DES3 key exists")?;
        assert_eq!(des3_kvno, 2);
        assert_eq!(des3_key.etype, 16_i32);
        assert_eq!(
            hex::encode(&des3_key.value),
            "4580fb91760dabe6f808c22c26494f644cb35d61d32c79e3"
        );

        let (rc4_key, rc4_kvno) = keytab
            .find_key(&["testuser1"], "TEST.GOKRB5", 2, 23)
            .context("RC4-HMAC key exists")?;
        assert_eq!(rc4_kvno, 2);
        assert_eq!(rc4_key.etype, 23_i32);
        assert_eq!(
            hex::encode(&rc4_key.value),
            "084768c373663b3bef1f6385883cf7ff"
        );
        Ok(())
    }

    /// Pins that kvno 0 selects the newest matching entry, by timestamp.
    #[test]
    fn kvno_zero_selects_newest_matching_key() -> Result<(), TestError> {
        let mut keytab = Keytab::new();
        keytab.entries_mut().extend([
            synthetic_entry("HTTP", 1, 18, 100),
            synthetic_entry("HTTP", 2, 18, 200),
            synthetic_entry("HTTP", 3, 18, 150),
            synthetic_entry("HTTP", 4, 17, 300),
        ]);

        let (_, kvno) = keytab
            .find_key(&["HTTP"], "TEST.GOKRB5", 0, 18)
            .context("newest matching key exists")?;
        assert_eq!(kvno, 2);
        Ok(())
    }

    /// Serializer bounds match the signed fields accepted by the parser.
    #[test]
    fn serializer_rejects_unparseable_field_boundaries() -> Result<(), TestError> {
        // Given entries with one field beyond the parser's signed range.
        let fixture = Keytab::parse(&hex::decode(KTUTIL_USER_KEYTAB)?)?;
        for field in 0_u8..5 {
            let mut entry = fixture.entries().first().context("fixture entry")?.clone();
            match field {
                0 => entry.principal.realm = "r".repeat(0x8000),
                1 => entry.principal.components = vec!["c".repeat(0x8000)],
                2 => entry.principal.components = vec![String::new(); 0x8000],
                3 => entry.key.value = vec![0; 0x8000].into(),
                _ => entry.key.etype = 0x8000_i32,
            }
            let mut keytab = Keytab::new();
            keytab.entries_mut().push(entry);

            // When serializing an entry the parser cannot represent.
            let result = keytab.to_bytes();

            // Then reject rather than emit bytes that fail or change on parsing.
            assert!(
                matches!(result, Err(Error::LengthOverflow)),
                "field {field}"
            );
        }
        Ok(())
    }

    /// Signed length boundaries remain representable and round-trip exactly.
    #[test]
    fn serializer_accepts_largest_parseable_fields() -> Result<(), TestError> {
        // Given the largest accepted lengths, count and encryption type.
        let mut entry = synthetic_entry("user", 1, i32::from(i16::MAX), 100);
        entry.principal.realm = "r".repeat(0x7fff);
        entry.principal.components = vec![String::new(); 0x7fff];
        *entry
            .principal
            .components
            .first_mut()
            .context("first component")? = "c".repeat(0x7fff);
        entry.key.value = vec![7; 0x7fff].into();
        let mut keytab = Keytab::new();
        keytab.entries_mut().push(entry);

        // When serializing and parsing boundary fields.
        let parsed = Keytab::parse(&keytab.to_bytes()?)?;

        // Then all accepted values survive unchanged.
        assert_eq!(parsed, keytab);
        Ok(())
    }

    /// Version one includes the realm in its checked component count.
    #[test]
    fn serializer_checks_version_one_realm_count() -> Result<(), TestError> {
        // Given a version-one keytab with the largest admissible component count.
        let mut keytab = Keytab::parse(&[5, 1])?;
        let mut entry = synthetic_entry("user", 1, 18, 100);
        entry.principal.name_type = 0_i32;
        entry.principal.components = vec![String::new(); 0x7ffe];
        keytab.entries_mut().push(entry);
        assert_eq!(Keytab::parse(&keytab.to_bytes()?)?, keytab);
        keytab
            .entries_mut()
            .first_mut()
            .context("entry")?
            .principal
            .components
            .push(String::new());

        // When the realm-inclusive count would exceed the accepted range.
        let result = keytab.to_bytes();

        // Then serialization rejects the otherwise representable entry.
        assert!(matches!(result, Err(Error::LengthOverflow)));
        Ok(())
    }

    /// Version-one serialization must not silently erase a nonzero name type.
    #[test]
    fn version_one_rejects_unrepresentable_name_type() -> Result<(), TestError> {
        let mut keys = Keytab::parse(&[5, 1])?;
        let mut entry = synthetic_entry("alice", 1, 18, 100);
        entry.principal.name_type = 42_i32;
        keys.entries_mut().push(entry);
        assert!(matches!(
            keys.to_bytes(),
            Err(Error::UnrepresentableNameType(42_i32))
        ));
        keys.entries_mut()
            .first_mut()
            .context("entry")?
            .principal
            .name_type = 0_i32;
        assert_eq!(Keytab::parse(&keys.to_bytes()?)?, keys);
        Ok(())
    }

    /// Construction makes the extended-zero fallback explicit before lookup or save.
    #[test]
    fn zero_extended_kvno_is_canonical_at_construction() -> Result<(), TestError> {
        // Given a fixed KVNO of seven and the zero extended sentinel.
        let principal = Principal::new("EXAMPLE.COM", 1, ["user"]);
        // When constructing the entry.
        let entry = Entry::new(principal, 100, 7, EncryptionKey::new(18, vec![7; 16]), 0);
        // Then the effective lookup identity already matches the file interpretation.
        assert_eq!(entry.kvno, 7);
        let mut keytab = Keytab::new();
        keytab.entries_mut().push(entry);
        assert_eq!(Keytab::parse(&keytab.to_bytes()?)?, keytab);
        Ok(())
    }

    proptest! {
        /// Every admitted synthetic keytab survives serialization and parsing.
        #[test]
        fn serialized_keytab_roundtrips(
            realm in "[a-zA-Z.]{0,40}",
            components in collection::vec("[a-zA-Z/]{0,40}", 0..8),
            key in collection::vec(any::<u8>(), 0..128),
            etype in i32::from(i16::MIN)..=i32::from(i16::MAX),
            timestamp in any::<u32>(),
            kvno in any::<u32>(),
            kvno8 in any::<u8>(),
            name_type in any::<i32>(),
        ) {
            let mut keytab = Keytab::new();
            keytab.entries_mut().push(Entry::new(
                Principal::new(realm, name_type, components),
                timestamp, kvno8, EncryptionKey::new(etype, key), kvno,
            ));
            let parsed = Keytab::parse(&keytab.to_bytes()?)?;
            prop_assert_eq!(parsed, keytab);
        }
    }

    /// Manual key formatting explicitly accounts for every field before redaction.
    #[test]
    fn key_debug_has_exhaustive_field_audit() -> Result<(), TestError> {
        // Given the actual manual formatting implementation.
        let source = read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/keytab.rs"))?;
        // When selecting its field-audit pattern.
        let audited = source.contains("let Self { etype, value } = self;");
        // Then no rest pattern can swallow future secret fields.
        assert!(audited);
        Ok(())
    }

    /// An interrupted next-entry size is not a clean end of file.
    #[test]
    fn rejects_partial_next_entry_sizes() -> Result<(), TestError> {
        // Given empty and populated keytabs with incomplete next-record sizes.
        let mut populated = Keytab::new();
        populated
            .entries_mut()
            .push(synthetic_entry("user", 7, 18, 100));
        for prefix in [vec![5, 2], populated.to_bytes()?] {
            for fragment in [&[1_u8][..], &[0, 1][..], &[0, 0, 1][..]] {
                let mut bytes = prefix.clone();
                bytes.extend_from_slice(fragment);
                // When parsing the interrupted file.
                let result = Keytab::parse(&bytes);
                // Then truncation is reported rather than silently discarding data.
                assert!(matches!(
                    result,
                    Err(Error::Truncated {
                        offset: _,
                        needed: _,
                        remaining: _
                    })
                ));
            }
        }
        Ok(())
    }

    /// Pins that empty, misversioned and truncated keytabs are rejected.
    #[test]
    fn rejects_invalid_keytab_inputs() {
        let inputs: [&[u8]; 5] = [&[], &[5], &[4, 2], &[5, 9], &[5, 2, 0, 0, 0, 16]];
        for input in inputs {
            assert!(
                Keytab::parse(input).err().is_some(),
                "{input:?} is rejected"
            );
        }
    }

    /// Builds a `TEST.GOKRB5` entry for `component` whose key bytes repeat the low kvno byte.
    fn synthetic_entry(component: &str, kvno: u32, etype: i32, timestamp: u32) -> Entry {
        let [.., kvno8] = kvno.to_be_bytes();
        Entry::new(
            Principal::new("TEST.GOKRB5", 1, vec![component.to_owned()]),
            timestamp,
            kvno8,
            EncryptionKey::new(etype, vec![kvno8; 4]),
            kvno,
        )
    }

    /// Returns a unique path in the temporary directory for the test `name`.
    fn temp_file(name: &str) -> Result<PathBuf, TestError> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("current time is after unix epoch")?
            .as_nanos();
        Ok(temp_dir().join(format!("rskrb5-keytab-{name}-{}-{nanos}", process::id())))
    }
}
