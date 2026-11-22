//! The `.k5login` module: lookup of the file, ownership, modes, symlinks,
//! bounds and the exact line match (MIT `localauth_k5login.c:83-161`; the
//! modes, symlink and bound checks are stricter than MIT).

#[cfg(unix)]
mod unix {
    //! Everything that needs Unix ownership and modes.

    use std::{
        fs,
        os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink},
        path::Path,
        sync::Arc,
    };

    use rskrb5_ng::{
        ccache::Principal,
        config::Config,
        localauth::{
            Account, Authorization, Denial, LocalAuthorizer, LocalNameMapper, Module,
            accounts::StaticAccounts,
            authorize_local,
            k5login::{Fault, MAX_FILE_BYTES, MAX_LINE_BYTES, MAX_LINES},
        },
    };

    use crate::support::{Scratch, TestError, authorizer, principal, resolver};

    /// The account the scenarios authorize.
    const USER: &str = "lauth";

    /// Granted by the `.k5login` module.
    const LISTED: Authorization = Authorization::Authorized(Module::K5login);

    /// Refused by the `.k5login` module for `fault`.
    const fn refused(fault: Fault) -> Authorization {
        Authorization::Denied(Denial::K5login(fault))
    }

    /// The principal every scenario authorizes.
    fn alice() -> Principal {
        principal("alice@KRBTEST.COM")
    }

    /// A home directory with a `.k5login` of `content` and `mode`, and the
    /// user id that owns it (this process's).
    fn home_with(content: &[u8], mode: u32) -> Result<(Scratch, u32), TestError> {
        let home = Scratch::new("home")?;
        let file = home.path().join(".k5login");
        fs::write(&file, content)?;
        fs::set_permissions(&file, fs::Permissions::from_mode(mode))?;
        let owner = fs::metadata(&file)?.uid();
        Ok((home, owner))
    }

    /// The decision for `alice` as `USER` with `uid` and `home`.
    fn decide(uid: u32, home: &Path) -> Result<Authorization, TestError> {
        let authorizer = authorizer("", resolver(USER, uid, home))?;
        Ok(authorize_local(&authorizer, &alice(), USER))
    }

    /// A listed principal is authorized from `<home>/.k5login`.
    #[test]
    fn listed_principal_is_authorized() -> Result<(), TestError> {
        let (home, owner) = home_with(b"bob@KRBTEST.COM\nalice@KRBTEST.COM\n", 0o600)?;
        assert_eq!(decide(owner, home.path())?, LISTED);
        Ok(())
    }

    /// Mode 0644 and 0640 are fine; group or world write is not.
    #[test]
    fn writable_by_group_or_others_is_refused() -> Result<(), TestError> {
        for (mode, expected) in [
            (0o644, LISTED),
            (0o640, LISTED),
            (0o664, refused(Fault::WritableByOthers)),
            (0o666, refused(Fault::WritableByOthers)),
            (0o620, refused(Fault::WritableByOthers)),
            (0o602, refused(Fault::WritableByOthers)),
        ] {
            let (home, owner) = home_with(b"alice@KRBTEST.COM\n", mode)?;
            assert_eq!(decide(owner, home.path())?, expected, "mode {mode:o}");
        }
        Ok(())
    }

    /// A file that belongs to neither the account's user nor root is refused,
    /// whatever it lists.
    #[test]
    fn foreign_owner_is_refused() -> Result<(), TestError> {
        let (home, owner) = home_with(b"alice@KRBTEST.COM\n", 0o600)?;
        assert_ne!(owner, 0, "the scenario needs a non-root file owner");
        assert_eq!(
            decide(owner.wrapping_add(1), home.path())?,
            refused(Fault::WrongOwner)
        );
        Ok(())
    }

    /// A symbolic link is refused, to a file the account owns as much as to
    /// nothing.
    #[test]
    fn symlinks_are_refused() -> Result<(), TestError> {
        let (home, owner) = home_with(b"alice@KRBTEST.COM\n", 0o600)?;
        let real = home.path().join(".k5login");
        let moved = home.path().join("real-k5login");
        fs::rename(&real, &moved)?;
        symlink(&moved, &real)?;
        assert_eq!(decide(owner, home.path())?, refused(Fault::Symlink));
        fs::remove_file(&real)?;
        symlink(home.path().join("missing"), &real)?;
        assert_eq!(decide(owner, home.path())?, refused(Fault::Symlink));
        Ok(())
    }

    /// A directory is not a `.k5login` file.
    #[test]
    fn directory_is_not_a_regular_file() -> Result<(), TestError> {
        let home = Scratch::new("dir")?;
        fs::create_dir(home.path().join(".k5login"))?;
        let owner = fs::metadata(home.path())?.uid();
        assert_eq!(decide(owner, home.path())?, refused(Fault::NotRegular));
        Ok(())
    }

    /// The size, line count and line length bounds refuse and are inclusive.
    #[test]
    fn bounds_refuse_what_exceeds_them() -> Result<(), TestError> {
        let target = b"alice@KRBTEST.COM\n";
        let filler = |lines: usize| b"x\n".repeat(lines);
        let (home, owner) = home_with(&[filler(MAX_LINES - 1), target.to_vec()].concat(), 0o600)?;
        assert_eq!(decide(owner, home.path())?, LISTED, "the last allowed line");
        let (home, owner) = home_with(&[filler(MAX_LINES), target.to_vec()].concat(), 0o600)?;
        assert_eq!(decide(owner, home.path())?, refused(Fault::TooManyLines));
        let (home, owner) = home_with(&[vec![b'y'; MAX_LINE_BYTES], b"\n".to_vec(), target.to_vec()].concat(), 0o600)?;
        assert_eq!(decide(owner, home.path())?, LISTED, "the longest allowed line");
        let (home, owner) = home_with(&[vec![b'y'; MAX_LINE_BYTES + 1], b"\n".to_vec(), target.to_vec()].concat(), 0o600)?;
        assert_eq!(decide(owner, home.path())?, refused(Fault::LineTooLong));
        let (home, owner) = home_with(&vec![b'z'; MAX_FILE_BYTES + 1], 0o600)?;
        assert_eq!(decide(owner, home.path())?, refused(Fault::TooLarge));
        Ok(())
    }

    /// A line is the whole principal name: no trimming, no case folding, no
    /// carriage return, a final line without newline counts, `\` escapes as
    /// in `krb5_unparse_name`.
    #[test]
    fn line_match_is_exact() -> Result<(), TestError> {
        let listed = |content: &[u8]| -> Result<bool, TestError> {
            let (home, owner) = home_with(content, 0o600)?;
            Ok(decide(owner, home.path())? == LISTED)
        };
        assert!(listed(b"alice@KRBTEST.COM")?, "no final newline");
        assert!(!listed(b" alice@KRBTEST.COM\n")?, "leading space");
        assert!(!listed(b"alice@KRBTEST.COM \n")?, "trailing space");
        assert!(!listed(b"alice@KRBTEST.COM\r\n")?, "carriage return");
        assert!(!listed(b"Alice@KRBTEST.COM\n")?, "case");
        assert!(!listed(b"alice@krbtest.com\n")?, "realm case");
        assert!(!listed(b"alice\n")?, "no realm");
        assert!(!listed(b"alice@KRBTEST.COM/x\n")?, "suffix");
        assert!(!listed(b"# alice@KRBTEST.COM\n")?, "comment");
        let escaped = Principal::new("KRBTEST.COM", 1, vec!["a/b".to_owned(), "c@d".to_owned()]);
        let (home, owner) = home_with(b"a\\/b/c\\@d@KRBTEST.COM\n", 0o600)?;
        let authorizer = authorizer("", resolver(USER, owner, home.path()))?;
        assert_eq!(authorize_local(&authorizer, &escaped, USER), LISTED);
        Ok(())
    }

    /// No file: silence, and the `an2ln` rule decides; a refusing file is
    /// final while authoritative and silent otherwise.
    #[test]
    fn authority_decides_what_a_refusal_means() -> Result<(), TestError> {
        let (home, owner) = home_with(b"bob@KRBTEST.COM\n", 0o600)?;
        let same = principal("lauth@KRBTEST.COM");
        let strict = authorizer("", resolver(USER, owner, home.path()))?;
        assert_eq!(authorize_local(&strict, &same, USER), refused(Fault::NotListed));
        let lax = strict.with_k5login_authoritative(false);
        assert_eq!(
            authorize_local(&lax, &same, USER),
            Authorization::Authorized(Module::An2ln)
        );
        assert_eq!(
            authorize_local(&lax, &alice(), USER),
            Authorization::Denied(Denial::NoModuleAllowed)
        );
        let empty = Scratch::new("empty")?;
        let silent = authorizer("", resolver(USER, owner, empty.path()))?;
        assert_eq!(
            authorize_local(&silent, &same, USER),
            Authorization::Authorized(Module::An2ln)
        );
        assert_eq!(
            authorize_local(&silent, &alice(), USER),
            Authorization::Denied(Denial::NoModuleAllowed)
        );
        Ok(())
    }

    /// An account the resolver does not know, or a home that is not absolute,
    /// is refused while authoritative (MIT: `EPERM`).
    #[test]
    fn unknown_account_and_relative_home_are_refused() -> Result<(), TestError> {
        let (home, owner) = home_with(b"alice@KRBTEST.COM\n", 0o600)?;
        let strict = authorizer("", resolver(USER, owner, home.path()))?;
        assert_eq!(
            authorize_local(&strict, &alice(), "nobody"),
            refused(Fault::UnknownAccount)
        );
        let relative = authorizer("", resolver(USER, owner, Path::new("relative/home")))?;
        assert_eq!(
            authorize_local(&relative, &alice(), USER),
            refused(Fault::RelativeHome)
        );
        let lax = relative.with_k5login_authoritative(false);
        assert_eq!(
            authorize_local(&lax, &alice(), USER),
            Authorization::Denied(Denial::NoModuleAllowed)
        );
        Ok(())
    }

    /// An empty or NUL-holding account name is refused before any lookup.
    #[test]
    fn invalid_account_names_are_refused() -> Result<(), TestError> {
        let (home, owner) = home_with(b"alice@KRBTEST.COM\n", 0o600)?;
        let strict = authorizer("", resolver(USER, owner, home.path()))?;
        for name in ["", "la\0uth"] {
            assert_eq!(
                authorize_local(&strict, &alice(), name),
                Authorization::Denied(Denial::InvalidLocalName)
            );
        }
        Ok(())
    }

    /// `k5login_directory`: the file is `<directory>/<account>`, the home is
    /// not read, and an account name that is not a plain file name is refused.
    #[test]
    fn directory_holds_one_file_per_account() -> Result<(), TestError> {
        let (home, owner) = home_with(b"alice@KRBTEST.COM\n", 0o600)?;
        let directory = Scratch::new("directory")?;
        let file = directory.path().join(USER);
        fs::write(&file, b"bob@KRBTEST.COM\n")?;
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600))?;
        let strict = authorizer("", resolver(USER, owner, home.path()))?
            .with_k5login_directory(Some(directory.path().to_path_buf()));
        assert_eq!(authorize_local(&strict, &alice(), USER), refused(Fault::NotListed));
        assert_eq!(authorize_local(&strict, &principal("bob@KRBTEST.COM"), USER), LISTED);
        for name in [".", "..", "../x", "a/b"] {
            let table = StaticAccounts::new()
                .with_account(name, Account::new(owner, home.path().to_path_buf()));
            let hostile = LocalAuthorizer::new(
                LocalNameMapper::new(Some("KRBTEST.COM".to_owned())),
                Arc::new(table),
            )
            .with_k5login_directory(Some(directory.path().to_path_buf()));
            assert_eq!(
                authorize_local(&hostile, &alice(), name),
                refused(Fault::UnsafeLocalName),
                "{name:?}"
            );
        }
        Ok(())
    }

    /// `k5login_authoritative` and `k5login_directory` of the profile are the
    /// authorizer's policy (MIT-config-23 and MIT-config-24).
    #[test]
    fn the_profile_sets_authority_and_directory() -> Result<(), TestError> {
        let (home, owner) = home_with(b"bob@KRBTEST.COM\n", 0o600)?;
        let text = "[libdefaults]\n default_realm = KRBTEST.COM\n k5login_authoritative = false\n";
        let lax = LocalAuthorizer::from_config(
            &Config::parse(text)?,
            resolver(USER, owner, home.path()),
        )?;
        assert_eq!(
            authorize_local(&lax, &alice(), USER),
            Authorization::Denied(Denial::NoModuleAllowed)
        );
        let directory = Scratch::new("profile-dir")?;
        let file = directory.path().join(USER);
        fs::write(&file, b"alice@KRBTEST.COM\n")?;
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600))?;
        let text = format!(
            "[libdefaults]\n default_realm = KRBTEST.COM\n k5login_directory = {}\n",
            directory.path().display()
        );
        let configured = LocalAuthorizer::from_config(
            &Config::parse(&text)?,
            resolver(USER, owner, home.path()),
        )?;
        assert_eq!(authorize_local(&configured, &alice(), USER), LISTED);
        Ok(())
    }
}
/// Off Unix there is no `.k5login` module: it neither allows nor denies, and
/// only the `an2ln` rule authorizes.
#[cfg(not(unix))]
mod portable {
    //! The platform-unavailable case.

    use rskrb5_ng::localauth::{Authorization, Denial, Module, authorize_local};

    use crate::support::{Scratch, TestError, authorizer, principal, resolver};

    /// A listed principal is not authorized; the `an2ln` rule still works.
    #[test]
    fn no_k5login_module_off_unix() -> Result<(), TestError> {
        let home = Scratch::new("off-unix")?;
        std::fs::write(home.path().join(".k5login"), b"alice@KRBTEST.COM\n")?;
        let authorizer = authorizer("", resolver("lauth", 0, home.path()))?;
        assert_eq!(
            authorize_local(&authorizer, &principal("alice@KRBTEST.COM"), "lauth"),
            Authorization::Denied(Denial::NoModuleAllowed)
        );
        assert_eq!(
            authorize_local(&authorizer, &principal("lauth@KRBTEST.COM"), "lauth"),
            Authorization::Authorized(Module::An2ln)
        );
        Ok(())
    }
}
