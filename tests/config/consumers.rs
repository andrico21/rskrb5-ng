//! Profile-name expansion at existing credential consumers.

#[cfg(test)]
#[cfg(feature = "tokio")]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;
    use std::{env, ffi::OsString, fs, process};

    use rskrb5_ng::{
        Config, Principal, TokioClient,
        ccache::{CCache, Principal as CachePrincipal},
        client::transport::KdcProtocol,
        config::parameters::Failure as ExpansionFailure,
        error::{Ccache as CacheFailure, Client as ClientFailure},
        keytab::Keytab,
        service::Validator,
    };

    use crate::env as child_env;

    /// Environment replacement bytes remain literal across all default loaders.
    #[test]
    fn ambient_templates_are_expanded_once() -> Result<(), Box<dyn Error>> {
        // Given a child whose temp directory contains token-shaped data.
        const TEST: &str = "consumers::tests::ambient_templates_are_expanded_once";
        if !child_env::in_child(TEST) {
            let directory = env::temp_dir().join(format!("b2-percent-{}-%{{uid}}", process::id()));
            fs::create_dir_all(&directory)?;
            let result = child_env::try_run_in_child(
                TEST,
                &[
                    ("TMPDIR", Some(directory.as_os_str())),
                    ("TEMP", Some(directory.as_os_str())),
                    ("TMP", Some(directory.as_os_str())),
                    ("KRB5CCNAME", None),
                    ("KRB5_KTNAME", None),
                    ("KRB5_CLIENT_KTNAME", None),
                ],
            );
            fs::remove_dir_all(directory)?;
            result?;
            return Ok(());
        }
        let directory = env::temp_dir();
        CCache::new(CachePrincipal::new("EXAMPLE", 1, vec!["user".to_owned()]))
            .save(directory.join("cache"))?;
        Keytab::new().save(directory.join("keytab"))?;
        let mut config = Config::new();
        config.libdefaults.default_ccache_name = "FILE:%{TEMP}/cache".to_owned();
        config.libdefaults.default_keytab_name = "FILE:%{TEMP}/keytab".to_owned();
        config.libdefaults.default_client_keytab_name = "FILE:%{TEMP}/keytab".to_owned();
        // When each existing ambient consumer falls back to the profile.
        let cache = TokioClient::from_default_ccache(config.clone(), KdcProtocol::Tcp)?;
        cache.save_default_ccache()?;
        cache.update_default_ccache()?;
        let service = Validator::from_default_keytab(&config)?;
        let client = TokioClient::with_client_keytab_from_default(
            config,
            KdcProtocol::Tcp,
            Principal::new("EXAMPLE", 1, vec!["user".to_owned()]),
        )?;
        // Then all accesses used the literal token-shaped directory.
        assert_eq!(cache.to_ccache()?.default_principal().realm, "EXAMPLE");
        drop(service);
        drop(client);
        Ok(())
    }

    /// A value that is not Unicode, for an environment variable the resolver reads.
    ///
    /// Unix variables are arbitrary bytes (`OsStringExt::from_vec`). Windows variables are
    /// UTF-16 code units, and an unpaired surrogate is the analogue (`OsStringExt::from_wide`).
    #[cfg(unix)]
    fn non_unicode() -> OsString {
        use std::os::unix::ffi::OsStringExt as _;
        OsString::from_vec(vec![b'/', b't', 0xFF, 0xFE])
    }

    /// See the Unix variant: the Windows analogue is an unpaired surrogate.
    #[cfg(windows)]
    fn non_unicode() -> OsString {
        use std::os::windows::ffi::OsStringExt as _;
        OsString::from_wide(&[0x0061, 0xD800, 0x0062])
    }

    /// Expands `template` as `default_ccache_name` and returns the name that the
    /// unavailable-fact failure carries.
    fn unavailable_fact(template: &str) -> Result<&'static str, Box<dyn Error>> {
        let mut config = Config::new();
        config.libdefaults.default_ccache_name = template.to_owned();
        let failure = TokioClient::from_default_ccache_name(config, KdcProtocol::Tcp)
            .err()
            .ok_or("a value that is not Unicode was accepted")?;
        match failure {
            ClientFailure::CCache(CacheFailure::Expansion(ExpansionFailure::Unavailable(name))) => {
                Ok(name)
            }
            other => Err(format!("not an unavailable-fact failure: {other}").into()),
        }
    }

    /// Non-Unicode `TMPDIR` is reported under its own name, not under the token's.
    #[cfg(unix)]
    #[test]
    fn non_unicode_tmpdir_names_tmpdir() -> Result<(), Box<dyn Error>> {
        // Given a child whose TMPDIR holds bytes that are not Unicode.
        const TEST: &str = "consumers::tests::non_unicode_tmpdir_names_tmpdir";
        if !child_env::in_child(TEST) {
            child_env::try_run_in_child(TEST, &[("TMPDIR", Some(non_unicode().as_os_str()))])?;
            return Ok(());
        }
        // When `%{TEMP}` is expanded, which MIT reads from TMPDIR on non-Windows.
        let name = unavailable_fact("FILE:%{TEMP}/cache")?;
        // Then the failure names the variable that was read.
        assert_eq!(name, "TMPDIR");
        Ok(())
    }

    /// Non-Unicode `TEMP` is reported as `TEMP` (Windows reads `TEMP`).
    #[cfg(windows)]
    #[test]
    fn non_unicode_temp_names_temp() -> Result<(), Box<dyn Error>> {
        // Given a child whose TEMP holds an unpaired surrogate.
        const TEST: &str = "consumers::tests::non_unicode_temp_names_temp";
        if !child_env::in_child(TEST) {
            child_env::try_run_in_child(TEST, &[("TEMP", Some(non_unicode().as_os_str()))])?;
            return Ok(());
        }
        // When `%{TEMP}` is expanded, then the failure names TEMP.
        assert_eq!(unavailable_fact("FILE:%{TEMP}/cache")?, "TEMP");
        Ok(())
    }

    /// Non-Unicode `APPDATA` is reported as `APPDATA` for every token that reads it (Windows).
    #[cfg(windows)]
    #[test]
    fn non_unicode_appdata_names_appdata() -> Result<(), Box<dyn Error>> {
        // Given a child whose APPDATA holds an unpaired surrogate.
        const TEST: &str = "consumers::tests::non_unicode_appdata_names_appdata";
        if !child_env::in_child(TEST) {
            child_env::try_run_in_child(TEST, &[("APPDATA", Some(non_unicode().as_os_str()))])?;
            return Ok(());
        }
        // When each token that reads APPDATA is expanded, then each failure names APPDATA.
        for token in ["APPDATA", "USERCONFIG", "USERCONFIGDIR"] {
            assert_eq!(
                unavailable_fact(&format!("FILE:%{{{token}}}/cache"))?,
                "APPDATA"
            );
        }
        Ok(())
    }

    /// Configured cache load/save/update all use the same expansion boundary.
    #[test]
    fn configured_cache_templates_reach_real_files() -> Result<(), Box<dyn Error>> {
        // Given a valid empty cache at the expanded, not literal, name.
        let path = env::temp_dir().join(format!("b2-cache-{}", process::id()));
        CCache::new(CachePrincipal::new("EXAMPLE", 1, vec!["user".to_owned()])).save(&path)?;
        let mut config = Config::new();
        config.libdefaults.default_ccache_name = format!("FILE:{}%{{null}}", path.display());
        // When loading, replacing and updating through configured-name consumers.
        let result = TokioClient::from_default_ccache_name(config, KdcProtocol::Tcp);
        if let Ok(client) = &result {
            client.save_default_ccache_name()?;
            client.update_default_ccache_name()?;
        }
        fs::remove_file(&path)?;
        // Then a literal %{null} filename was never required.
        let client = result?;
        assert_eq!(client.to_ccache()?.default_principal().realm, "EXAMPLE");
        Ok(())
    }

    /// Service, HTTP and client-keytab adapters resolve their configured names.
    #[test]
    fn configured_keytab_templates_reach_real_files() -> Result<(), Box<dyn Error>> {
        // Given an empty but valid keytab at the expanded path.
        let path = env::temp_dir().join(format!("b2-keytab-{}", process::id()));
        Keytab::new().save(&path)?;
        let mut config = Config::new();
        config.libdefaults.default_keytab_name = format!("FILE:{}%{{null}}", path.display());
        config.libdefaults.default_client_keytab_name =
            config.libdefaults.default_keytab_name.clone();
        // When invoking the existing high-level consumers.
        let service = Validator::from_default_keytab_name(&config);
        #[cfg(feature = "tower")]
        let http = rskrb5_ng::http::NegotiateLayer::from_default_keytab_name(&config);
        let client = TokioClient::with_client_keytab_from_config(
            config,
            KdcProtocol::Tcp,
            Principal::new("EXAMPLE", 1, vec!["user".to_owned()]),
        );
        fs::remove_file(&path)?;
        // Then every consumer successfully opens the expanded file.
        drop(service?);
        #[cfg(feature = "tower")]
        drop(http?);
        drop(client?);
        Ok(())
    }

    /// Unknown parameters fail at the consumer before any file is opened.
    #[test]
    fn unknown_templates_return_expansion_errors() -> Result<(), Box<dyn Error>> {
        // Given unsupported tokens in all three profile names.
        let mut config = Config::new();
        config.libdefaults.default_ccache_name = "FILE:%{typo}".to_owned();
        config.libdefaults.default_keytab_name = "FILE:%{typo}".to_owned();
        config.libdefaults.default_client_keytab_name = "FILE:%{typo}".to_owned();
        // When loading a configured cache.
        let failure = TokioClient::from_default_ccache_name(config, KdcProtocol::Tcp)
            .err()
            .ok_or("unknown token accepted")?;
        // Then expansion is causal, not a misleading file-not-found failure.
        assert!(
            matches!(failure, ClientFailure::CCache(CacheFailure::Expansion(ExpansionFailure::UnknownToken(token))) if token == "typo")
        );
        Ok(())
    }
}
