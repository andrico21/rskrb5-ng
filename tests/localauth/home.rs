//! `HOME` never selects the `.k5login` file (the plan-1 residual of WP-17).
//!
//! MIT reads the home directory of the target user's passwd entry
//! (`localauth_k5login.c:106`), never `HOME`. A child process runs with a
//! hostile `HOME` that holds a decoy `.k5login`, and the constructor that
//! reads the environment, `LibDefaults::from_env`, feeds the authorizer.

#[cfg(unix)]
mod unix {
    //! Unix homes and a child process.

    use std::{
        env, fs,
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
        process::Command,
    };

    use rskrb5_ng::{
        config::{Config, LibDefaults},
        localauth::{Authorization, Denial, LocalAuthorizer, Module, authorize_local, k5login::Fault},
    };

    use crate::support::{REALM, Scratch, TestError, principal, resolver};

    /// The variable that marks the child and names the resolved home.
    const RESOLVED: &str = "RSKRB5_LOCALAUTH_RESOLVED_HOME";
    /// The variable that carries the owner of the files to the child.
    const OWNER: &str = "RSKRB5_LOCALAUTH_OWNER";
    /// The test the parent re-runs as the child.
    const CHILD: &str = "home::unix::hostile_home_never_selects_the_k5login_file";

    /// Write `content` to `path` with mode 0600.
    fn write_private(path: &std::path::Path, content: &[u8]) -> Result<(), TestError> {
        fs::write(path, content)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    /// The child: the environment-reading constructor with a hostile `HOME`.
    fn child(resolved: &str, owner: &str) -> Result<(), TestError> {
        let mut config = Config::new();
        config.libdefaults = LibDefaults::from_env().with_default_realm(REALM.to_owned());
        let authorizer = LocalAuthorizer::from_config(
            &config,
            resolver("lauth", owner.parse()?, std::path::Path::new(resolved)),
        )?;
        assert_eq!(
            authorize_local(&authorizer, &principal("alice@KRBTEST.COM"), "lauth"),
            Authorization::Denied(Denial::K5login(Fault::NotListed)),
            "the decoy under HOME must not authorize alice"
        );
        assert_eq!(
            authorize_local(&authorizer, &principal("bob@KRBTEST.COM"), "lauth"),
            Authorization::Authorized(Module::K5login),
            "the resolved home authorizes bob"
        );
        Ok(())
    }

    /// With `HOME` pointing at a decoy, the `.k5login` of the resolved home
    /// decides: the decoy lists alice in `.k5login` and in a file named like
    /// the account, the resolved home lists bob only.
    #[test]
    fn hostile_home_never_selects_the_k5login_file() -> Result<(), TestError> {
        if let (Some(resolved), Some(owner)) = (env::var_os(RESOLVED), env::var_os(OWNER)) {
            return child(&resolved.to_string_lossy(), &owner.to_string_lossy());
        }
        let resolved = Scratch::new("resolved-home")?;
        let decoy = Scratch::new("decoy-home")?;
        write_private(&resolved.path().join(".k5login"), b"bob@KRBTEST.COM\n")?;
        write_private(&decoy.path().join(".k5login"), b"alice@KRBTEST.COM\n")?;
        write_private(&decoy.path().join("lauth"), b"alice@KRBTEST.COM\n")?;
        let owner = fs::metadata(resolved.path())?.uid();
        let output = Command::new(env::current_exe()?)
            .args(["--exact", CHILD, "--nocapture"])
            .env_clear()
            .env("HOME", decoy.path())
            .env(RESOLVED, resolved.path())
            .env(OWNER, owner.to_string())
            .output()?;
        assert!(
            output.status.success(),
            "the child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }
}
