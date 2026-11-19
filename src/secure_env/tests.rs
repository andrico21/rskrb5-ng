//! The secure-environment decision: auxv fixtures, the real OS decision, and
//! one injected-decision test per ambient variable.
//!
//! A test that needs an environment variable re-executes this test binary,
//! filtered to itself, with the variable set on the child process; no test
//! changes the environment of a running test process. The decision is
//! injected per thread, so every reader runs its real code on its real input.

use core::cell::Cell;

use super::Decision;

std::thread_local! {
    /// The decision injected on this thread.
    static INJECTED: Cell<Option<Decision>> = const { Cell::new(None) };
}

/// The decision injected on this thread, if any.
pub(super) fn injected() -> Option<Decision> {
    INJECTED.with(Cell::get)
}

/// The injected-decision, auxv and real-OS tests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{cell::Cell, error::Error};
    use std::{
        env,
        ffi::{OsStr, OsString},
        fs,
        path::PathBuf,
        process::{self, Command},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::INJECTED;
    use crate::secure_env::{AT_NULL, AT_SECURE, Decision, ambient, os_decision, parse_auxv};

    /// Run `read` with `decision` injected on this thread.
    fn with_decision<T>(decision: Decision, read: impl FnOnce() -> T) -> T {
        INJECTED.with(|cell| cell.set(Some(decision)));
        let result = read();
        INJECTED.with(|cell| cell.set(None));
        result
    }

    /// Marks the child process and names the one test it runs.
    const CHILD: &str = "RSKRB5_SECURE_ENV_CHILD";
    /// The variables every ambient reader reads; a child starts without them.
    const AMBIENT: [&str; 6] = [
        "KRB5_CONFIG",
        "KRB5CCNAME",
        "KRB5_KTNAME",
        "KRB5_CLIENT_KTNAME",
        "TMPDIR",
        "HOME",
    ];

    /// Whether this process is the child run of `test`.
    fn in_child(test: &str) -> bool {
        env::var_os(CHILD).is_some_and(|value| value == test)
    }

    /// Run `test` alone in a child of this test binary with `vars` set.
    fn run_child(test: &str, vars: &[(&str, &OsStr)]) -> Result<(), Box<dyn Error>> {
        let mut command = Command::new(env::current_exe()?);
        let _: &mut Command = command.args([test, "--exact", "--nocapture", "--test-threads=1"]);
        for name in AMBIENT {
            let _: &mut Command = command.env_remove(name);
        }
        for &(name, value) in vars {
            let _: &mut Command = command.env(name, value);
        }
        let output = command.env(CHILD, test).output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("test result: ok. 1 passed;"),
            "child {test} failed:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }

    /// A fresh private scratch directory.
    fn scratch(label: &str) -> Result<PathBuf, Box<dyn Error>> {
        let directory = env::temp_dir().join(format!(
            "secure-env-{label}-{}-{}",
            process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir_all(&directory)?;
        Ok(directory)
    }

    /// Auxiliary vector bytes from `(type, value)` pairs, in this target's byte order.
    fn auxv(pairs: &[(usize, usize)]) -> Vec<u8> {
        #[cfg(target_endian = "little")]
        let bytes = usize::to_le_bytes;
        #[cfg(target_endian = "big")]
        let bytes = usize::to_be_bytes;
        pairs
            .iter()
            .flat_map(|&(kind, value)| [bytes(kind), bytes(value)])
            .flatten()
            .collect()
    }

    /// `AT_SECURE` 0 is unrestricted; 1, absent, truncated and malformed vectors are restricted.
    #[test]
    fn auxv_fixtures_decide_without_the_os() {
        // Given vectors with AT_PAGESZ (6) before AT_SECURE and an AT_NULL end,
        // then only AT_SECURE 0 before AT_NULL is unrestricted.
        assert_eq!(
            parse_auxv(&auxv(&[(6, 4096), (AT_SECURE, 0), (AT_NULL, 0)])),
            Decision::Unrestricted
        );
        assert_eq!(
            parse_auxv(&auxv(&[(6, 4096), (AT_SECURE, 1), (AT_NULL, 0)])),
            Decision::Restricted
        );
        assert_eq!(
            parse_auxv(&auxv(&[(6, 4096), (AT_NULL, 0)])),
            Decision::Restricted
        );
        assert_eq!(
            parse_auxv(&auxv(&[(AT_NULL, 0), (AT_SECURE, 0)])),
            Decision::Restricted
        );
        assert_eq!(
            parse_auxv(
                auxv(&[(AT_SECURE, 0), (AT_NULL, 0)])
                    .split_last()
                    .map_or(&[][..], |(_, truncated)| truncated)
            ),
            Decision::Restricted
        );
        assert_eq!(parse_auxv(&[]), Decision::Restricted);
        assert_eq!(
            parse_auxv(&auxv(&[(AT_SECURE, 2), (AT_NULL, 0)])),
            Decision::Restricted
        );
    }

    /// The real OS decision of this test process. A normal run is unrestricted;
    /// the probe runs a set-id copy with `RSKRB5_EXPECT_DECISION=restricted`.
    #[test]
    fn os_decision_of_this_process() {
        assert_eq!(
            os_decision(),
            match env::var("RSKRB5_EXPECT_DECISION").as_deref() {
                Ok("restricted") => Decision::Restricted,
                _ => Decision::Unrestricted,
            }
        );
    }

    /// A restricted decision never runs the read; an unrestricted one does.
    #[test]
    fn restricted_decision_never_reads() -> Result<(), Box<dyn Error>> {
        let read = Cell::new(false);
        let unset = with_decision(Decision::Restricted, || {
            ambient(|| -> Result<String, env::VarError> {
                read.set(true);
                Ok("x".to_owned())
            })
        })
        .err()
        .ok_or("a restricted process read the variable")?;
        assert_eq!(unset, env::VarError::NotPresent);
        assert!(!read.get(), "a restricted process ran the read");
        let open = with_decision(Decision::Unrestricted, || {
            ambient(|| Some(OsString::from("x")))
        })
        .ok_or("an unrestricted process read nothing")?;
        assert_eq!(open, OsString::from("x"));
        Ok(())
    }

    /// `KRB5_CONFIG`: the three configuration readers ignore it when restricted.
    #[test]
    fn krb5_config_is_ignored_when_restricted() -> Result<(), Box<dyn Error>> {
        use crate::{config::Config, error::Config as ConfigError};
        let test = "secure_env::decision_tests::tests::krb5_config_is_ignored_when_restricted";
        if in_child(test) {
            let named = |config: &Config| config.libdefaults.default_realm == "ENVFILE.TEST";
            let embedded = "[libdefaults]\n default_realm = EMBEDDED.TEST\n";
            // Restricted: the variable is unset for every reader.
            with_decision(Decision::Restricted, || {
                assert!(matches!(
                    Config::load_from_env(),
                    Err(ConfigError::DefaultConfigName)
                ));
                assert!(!Config::load_default().is_ok_and(|config| named(&config)));
                assert!(
                    !Config::load_default_or_parse(embedded).is_ok_and(|config| named(&config))
                );
            });
            // Unrestricted: each reader loads the named file.
            with_decision(Decision::Unrestricted, || -> Result<(), Box<dyn Error>> {
                assert!(named(&Config::load_from_env()?));
                assert!(named(&Config::load_default()?));
                assert!(named(&Config::load_default_or_parse(embedded)?));
                Ok(())
            })?;
            return Ok(());
        }
        let directory = scratch("config")?;
        let path = directory.join("krb5.conf");
        fs::write(&path, "[libdefaults]\n default_realm = ENVFILE.TEST\n")?;
        let result = run_child(test, &[("KRB5_CONFIG", path.as_os_str())]);
        fs::remove_dir_all(directory)?;
        result
    }

    /// `HOME`: `LibDefaults::from_env` does not take `k5login_directory` from it,
    /// and there is no default `.k5identity`, when restricted.
    #[test]
    fn home_is_ignored_when_restricted() -> Result<(), Box<dyn Error>> {
        use crate::config::LibDefaults;
        let test = "secure_env::decision_tests::tests::home_is_ignored_when_restricted";
        if in_child(test) {
            let restricted = with_decision(Decision::Restricted, LibDefaults::from_env);
            assert_eq!(restricted.k5login_directory, "");
            let open = with_decision(Decision::Unrestricted, LibDefaults::from_env);
            assert_eq!(open.k5login_directory, "/hostile/home");
            #[cfg(not(windows))]
            {
                use crate::{ccache::default_k5identity, extensions::K5Identity};
                assert_eq!(
                    with_decision(Decision::Restricted, default_k5identity),
                    None
                );
                assert_eq!(
                    with_decision(Decision::Unrestricted, default_k5identity),
                    Some(K5Identity::new(
                        PathBuf::from("/hostile/home").join(".k5identity")
                    ))
                );
            }
            return Ok(());
        }
        run_child(test, &[("HOME", OsStr::new("/hostile/home"))])
    }

    /// `KRB5CCNAME`: the cache readers and the client's default name ignore it when restricted.
    #[test]
    fn krb5ccname_is_ignored_when_restricted() -> Result<(), Box<dyn Error>> {
        use crate::{
            ccache::{CCache, Principal},
            error::Ccache as CacheError,
        };
        let test = "secure_env::decision_tests::tests::krb5ccname_is_ignored_when_restricted";
        if in_child(test) {
            let cache = CCache::new(Principal::new("R", 1, vec!["env".to_owned()]));
            let unset = |result| {
                matches!(
                    result,
                    Err(CacheError::DefaultCacheName(env::VarError::NotPresent))
                )
            };
            with_decision(Decision::Restricted, || {
                assert!(unset(CCache::load_from_env().map(drop)));
                assert!(unset(cache.save_to_env()));
            });
            with_decision(Decision::Unrestricted, || -> Result<(), Box<dyn Error>> {
                assert_eq!(CCache::load_from_env()?, cache);
                cache.save_to_env()?;
                Ok(())
            })?;
            #[cfg(feature = "tokio")]
            default_ccache_name_follows_the_decision()?;
            return Ok(());
        }
        let directory = scratch("ccname")?;
        let path = directory.join("env-cache");
        CCache::new(Principal::new("R", 1, vec!["env".to_owned()])).save(&path)?;
        let name = format!("FILE:{}", path.display());
        let result = run_child(test, &[("KRB5CCNAME", OsStr::new(&name))]);
        fs::remove_dir_all(directory)?;
        result
    }

    /// The client's default cache name: the configured name when restricted, else `KRB5CCNAME`.
    #[cfg(feature = "tokio")]
    fn default_ccache_name_follows_the_decision() -> Result<(), Box<dyn Error>> {
        use crate::{
            TokioClient,
            ccache::{CCache, Principal},
            client::transport::KdcProtocol,
            config::Config,
        };
        let directory = scratch("client-ccname")?;
        let configured = directory.join("configured");
        let mut config = Config::new();
        config.libdefaults.default_ccache_name = format!("FILE:{}", configured.display());
        let principal = Principal::new("R", 1, vec!["client".to_owned()]);
        let client = TokioClient::from_ccache(config, KdcProtocol::Udp, &CCache::new(principal));
        let env_cache = || -> Result<CCache, Box<dyn Error>> {
            Ok(CCache::load_name(env::var("KRB5CCNAME")?)?)
        };
        // Restricted: the configured name receives the cache; the named one is untouched.
        with_decision(Decision::Restricted, || client.save_default_ccache())?;
        assert_eq!(CCache::load(&configured)?.client_name(), "client");
        assert_eq!(env_cache()?.client_name(), "env");
        // Unrestricted: KRB5CCNAME names the cache.
        with_decision(Decision::Unrestricted, || client.save_default_ccache())?;
        assert_eq!(env_cache()?.client_name(), "client");
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    /// `KRB5_KTNAME`: the keytab readers and the default keytab ignore it when restricted.
    #[test]
    fn krb5_ktname_is_ignored_when_restricted() -> Result<(), Box<dyn Error>> {
        use crate::{error::Keytab as KeytabError, keytab::Keytab};
        let test = "secure_env::decision_tests::tests::krb5_ktname_is_ignored_when_restricted";
        if in_child(test) {
            let keytab = Keytab::new();
            let unset = |result| {
                matches!(
                    result,
                    Err(KeytabError::DefaultKeytabName(env::VarError::NotPresent))
                )
            };
            with_decision(Decision::Restricted, || {
                assert!(unset(Keytab::load_from_env().map(drop)));
                assert!(unset(keytab.save_to_env()));
            });
            with_decision(Decision::Unrestricted, || -> Result<(), Box<dyn Error>> {
                assert_eq!(Keytab::load_from_env()?.entries().len(), 0);
                keytab.save_to_env()?;
                Ok(())
            })?;
            #[cfg(feature = "messages")]
            {
                use crate::{config::LibDefaults, keytab::default_keytab_name};
                // The configured default names a missing file: only the variable loads.
                let mut defaults = LibDefaults::new();
                defaults.default_keytab_name = "FILE:/nonexistent/rskrb5/keytab".to_owned();
                let load = || default_keytab_name(&defaults);
                drop(
                    with_decision(Decision::Restricted, load)
                        .err()
                        .ok_or("a restricted process loaded KRB5_KTNAME")?,
                );
                drop(with_decision(Decision::Unrestricted, load)?);
            }
            return Ok(());
        }
        let directory = scratch("ktname")?;
        let path = directory.join("keytab");
        Keytab::new().save(&path)?;
        let name = format!("FILE:{}", path.display());
        let result = run_child(test, &[("KRB5_KTNAME", OsStr::new(&name))]);
        fs::remove_dir_all(directory)?;
        result
    }

    /// `KRB5_CLIENT_KTNAME`: both client-keytab readers ignore it when restricted.
    #[cfg(feature = "tokio")]
    #[test]
    fn krb5_client_ktname_is_ignored_when_restricted() -> Result<(), Box<dyn Error>> {
        use crate::{
            TokioClient,
            client::{principal::Principal, transport::KdcProtocol},
            config::Config,
            error::Client as ClientError,
            keytab::Keytab,
        };
        let test =
            "secure_env::decision_tests::tests::krb5_client_ktname_is_ignored_when_restricted";
        if in_child(test) {
            let mut config = Config::new();
            config.libdefaults.default_client_keytab_name =
                "FILE:/nonexistent/rskrb5/ckt".to_owned();
            let client = || Principal::new("R", 1, ["client"]);
            let from_env = || {
                TokioClient::with_client_keytab_from_env(config.clone(), KdcProtocol::Udp, client())
            };
            let from_default = || {
                TokioClient::with_client_keytab_from_default(
                    config.clone(),
                    KdcProtocol::Udp,
                    client(),
                )
            };
            with_decision(Decision::Restricted, || -> Result<(), Box<dyn Error>> {
                assert!(matches!(
                    from_env(),
                    Err(ClientError::DefaultClientKeytabName(
                        env::VarError::NotPresent
                    ))
                ));
                drop(
                    from_default()
                        .err()
                        .ok_or("a restricted process loaded KRB5_CLIENT_KTNAME")?,
                );
                Ok(())
            })?;
            with_decision(Decision::Unrestricted, || -> Result<(), Box<dyn Error>> {
                drop(from_env()?);
                drop(from_default()?);
                Ok(())
            })?;
            return Ok(());
        }
        let directory = scratch("cktname")?;
        let path = directory.join("client.keytab");
        Keytab::new().save(&path)?;
        let name = format!("FILE:{}", path.display());
        let result = run_child(test, &[("KRB5_CLIENT_KTNAME", OsStr::new(&name))]);
        fs::remove_dir_all(directory)?;
        result
    }

    /// `TMPDIR`: `%{TEMP}` falls back to `/tmp` when restricted.
    #[cfg(all(feature = "messages", not(windows)))]
    #[test]
    fn tmpdir_is_ignored_when_restricted() -> Result<(), Box<dyn Error>> {
        use crate::config::{
            LibDefaults, credential_names::resolve_credential_template, parameters::DefaultName,
        };
        let test = "secure_env::decision_tests::tests::tmpdir_is_ignored_when_restricted";
        if in_child(test) {
            let mut defaults = LibDefaults::new();
            defaults.default_ccache_name = "FILE:%{TEMP}/cc".to_owned();
            let resolve = || resolve_credential_template(&defaults, DefaultName::Ccache);
            assert_eq!(
                with_decision(Decision::Restricted, resolve)?,
                "FILE:/tmp/cc"
            );
            assert_eq!(
                with_decision(Decision::Unrestricted, resolve)?,
                "FILE:/hostile/tmp/cc"
            );
            return Ok(());
        }
        run_child(test, &[("TMPDIR", OsStr::new("/hostile/tmp"))])
    }
}
