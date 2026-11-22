//! The built-in modules as providers of the extension registry (MIT
//! `localauth` plugin interface, `localauth.c:103-141`).
//!
//! MIT registers `default`, `rule`, `names`, `auth_to_local`, `k5login` and
//! `an2ln`; the first two only answer to the `DEFAULT` and `RULE` types of
//! `auth_to_local`, so the providers are the other four, in MIT's order.

#![cfg(feature = "localauth")]

use alloc::sync::Arc;

use rskrb5_ng::{
    ccache::Principal,
    config::Config,
    extensions::{Decision, Extension, Interface, LocalAuth, ProviderError, Registry},
    localauth::{LocalAuthorizer, builtin},
};

use crate::support::{Scratch, TestError, config, principal, resolver};

use std::path::Path;

extern crate alloc;

/// A registry holding the built-in modules of an authorizer over `realm_lines`.
fn registry(realm_lines: &str, home: &Path, uid: u32) -> Result<(Registry, Config), TestError> {
    let config = config(realm_lines)?;
    let authorizer = LocalAuthorizer::from_config(&config, resolver("lauth", uid, home))?;
    let mut registry = Registry::new();
    for module in builtin::modules(&authorizer) {
        registry.register(module)?;
    }
    Ok((registry, config))
}

/// The providers are `names`, `auth_to_local`, `k5login` and `an2ln`, in MIT's order.
#[test]
fn modules_are_registered_in_mits_order() -> Result<(), TestError> {
    let home = Scratch::new("builtin-order")?;
    let (registry, _config) = registry("", home.path(), 0)?;
    assert_eq!(
        registry.ids(Interface::LocalAuth),
        ["names", "auth_to_local", "k5login", "an2ln"]
    );
    Ok(())
}

/// `krb5_aname_to_localname` through the registry: the explicit name first,
/// then the rules, `DEFAULT` when there are none.
#[test]
fn registry_translates_like_the_mapper() -> Result<(), TestError> {
    let home = Scratch::new("builtin-names")?;
    let lines = " auth_to_local_names = {\n  preauthuser = lauthnone\n }\n auth_to_local = RULE:[1:$1@$0](testuser1@KRBTEST.COM)s/.*/lauthmapped/\n auth_to_local = DEFAULT";
    let (registry, config) = registry(lines, home.path(), 0)?;
    let name = |text: &str| registry.local_name(&config, &principal(text));
    assert_eq!(name("preauthuser@KRBTEST.COM")?.as_deref(), Some("lauthnone"));
    assert_eq!(name("testuser1@KRBTEST.COM")?.as_deref(), Some("lauthmapped"));
    assert_eq!(name("someone@KRBTEST.COM")?.as_deref(), Some("someone"));
    assert_eq!(name("someone@OTHER")?, None);
    Ok(())
}

/// A module of the application: its denial wins over the built-ins, and its
/// name answer comes first when it is registered before them.
#[derive(Debug)]
struct Veto;

impl LocalAuth for Veto {
    fn id(&self) -> &'static str {
        "veto"
    }

    fn userok(&self, _principal: &Principal, local_name: &str) -> Result<Decision, ProviderError> {
        Ok(if local_name == "lauth" { Decision::Deny } else { Decision::Pass })
    }

    fn local_name(&self, principal: &Principal) -> Result<Option<String>, ProviderError> {
        Ok((principal.components.first().map(String::as_str) == Some("special")).then(|| "mapped".to_owned()))
    }
}

/// Third-party modules sit beside the built-ins: a denial anywhere denies, a
/// module registered first answers first.
#[test]
fn application_modules_combine_with_the_built_ins() -> Result<(), TestError> {
    let home = Scratch::new("builtin-veto")?;
    let config = config(" auth_to_local_names = {\n  special = fromnames\n }")?;
    let authorizer = LocalAuthorizer::from_config(&config, resolver("lauth", 0, home.path()))?;
    let mut registry = Registry::new();
    registry.register(Extension::LocalAuth(Arc::new(Veto)))?;
    for module in builtin::modules(&authorizer) {
        registry.register(module)?;
    }
    assert!(!registry.authorize_local(&config, &principal("lauth@KRBTEST.COM"), "lauth"), "the veto denies the an2ln account");
    assert_eq!(
        registry.local_name(&config, &principal("special@KRBTEST.COM"))?.as_deref(),
        Some("mapped"),
        "the first registered module answers first"
    );
    Ok(())
}

/// The tests that need a `.k5login` file with a Unix owner and mode.
#[cfg(unix)]
mod unix {
    use std::{
        fs,
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    };

    use rskrb5_ng::{config::Config, extensions::Interface};

    use crate::support::{REALM, Scratch, TestError, principal};

    use super::registry;

    /// `krb5_kuserok` through the registry: the `.k5login` module allows or
    /// denies, and `an2ln` allows the translated account.
    #[test]
    fn registry_authorizes_like_the_authorizer() -> Result<(), TestError> {
        let home = Scratch::new("builtin-userok")?;
        let file = home.path().join(".k5login");
        fs::write(&file, b"bob@KRBTEST.COM\n")?;
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600))?;
        let owner = fs::metadata(&file)?.uid();
        let (registry, config) = registry("", home.path(), owner)?;
        let ok = |text: &str, account: &str| registry.authorize_local(&config, &principal(text), account);
        assert!(ok("bob@KRBTEST.COM", "lauth"), "listed in .k5login");
        assert!(!ok("lauth@KRBTEST.COM", "lauth"), "the authoritative .k5login refuses the an2ln account");
        fs::remove_file(&file)?;
        assert!(ok("lauth@KRBTEST.COM", "lauth"), "no file: an2ln allows");
        assert!(!ok("bob@KRBTEST.COM", "lauth"), "no file: nothing allows bob");
        Ok(())
    }

    /// `[plugins] localauth = { disable = k5login }` (what MIT's own
    /// `t_localauth.py` sets) leaves `an2ln` the only authorizer.
    #[test]
    fn a_disabled_module_is_not_consulted() -> Result<(), TestError> {
        let home = Scratch::new("builtin-disable")?;
        let file = home.path().join(".k5login");
        fs::write(&file, b"bob@KRBTEST.COM\n")?;
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600))?;
        let owner = fs::metadata(&file)?.uid();
        let (registry, _) = registry("", home.path(), owner)?;
        let disabled = Config::parse(&format!(
            "[libdefaults]\n default_realm = {REALM}\n[plugins]\n localauth = {{\n disable = k5login\n }}\n"
        ))?;
        assert!(registry.authorize_local(&disabled, &principal("lauth@KRBTEST.COM"), "lauth"));
        assert!(!registry.authorize_local(&disabled, &principal("bob@KRBTEST.COM"), "lauth"));
        assert_eq!(registry.enabled(Interface::LocalAuth, &disabled), ["names", "auth_to_local", "an2ln"]);
        Ok(())
    }
}
