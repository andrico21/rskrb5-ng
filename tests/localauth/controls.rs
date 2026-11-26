//! `[plugins] localauth` controls over the public helpers (MIT-config-54).
//!
//! MIT `configure_interface` (`plugin.c:302-347`) applies `disable` and
//! `enable_only` to the built-in `default`, `rule`, `names`, `auth_to_local`,
//! `k5login` and `an2ln` modules alike (FU-EXT-P01).

#![cfg(feature = "localauth")]

use rskrb5_ng::{
    config::{Config, ParseMode},
    error::LocalAuth as Error,
    localauth::{
        Authorization, Denial, LocalAuthorizer, LocalNameMapper, Module, authorize_local,
        principal_to_local_name,
    },
};

use crate::support::{REALM, Scratch, TestError, principal, resolver};

/// A Strict profile whose default realm has `realm_lines` and whose
/// `[plugins] localauth` holds `controls`.
fn profile(realm_lines: &str, controls: &str) -> Result<Config, TestError> {
    Ok(Config::parse_with_mode(
        &format!(
            "[libdefaults]\n default_realm = {REALM}\n[realms]\n {REALM} = {{\n{realm_lines}\n }}\n\
             [plugins]\n localauth = {{\n{controls}\n }}\n"
        ),
        ParseMode::Strict,
    )?)
}

/// The account name `alice@REALM` translates to under `controls`.
fn translated(realm_lines: &str, controls: &str) -> Result<Result<String, Error>, TestError> {
    let mapper = LocalNameMapper::from_config(&profile(realm_lines, controls)?)?;
    Ok(principal_to_local_name(
        &mapper,
        &principal("alice@KRBTEST.COM"),
    ))
}

/// The helpers consult only the modules the controls leave, in their order.
#[test]
fn localauth_controls_apply_to_public_helpers() -> Result<(), TestError> {
    let names = " auth_to_local_names = {\n  alice = fromnames\n }";
    let rules = " auth_to_local = RULE:[1:$1@$0](alice@KRBTEST.COM)s/.*/fromrules/";
    let both = format!("{names}\n{rules}");
    // Given explicit names and a rule, the names module answers first.
    assert_eq!(translated(&both, "")?.ok(), Some("fromnames".to_owned()));
    // When `names` is disabled, the rule answers.
    assert_eq!(
        translated(&both, "  disable = names")?.ok(),
        Some("fromrules".to_owned())
    );
    // When `enable_only` puts `auth_to_local` first, the rule answers first.
    assert_eq!(
        translated(
            &both,
            "  enable_only = auth_to_local\n  enable_only = names\n  enable_only = rule"
        )?
        .ok(),
        Some("fromrules".to_owned())
    );
    // When the `rule` type module is removed, a configured RULE is a
    // configuration error, as MIT's missing typed module.
    assert!(matches!(
        translated(rules, "  disable = rule")?,
        Err(Error::UnsupportedRuleType { kind }) if kind == "RULE"
    ));
    // When neither mapping module is left, nothing translates.
    assert!(matches!(
        translated(&both, "  enable_only = k5login")?,
        Err(Error::NoTranslation)
    ));
    Ok(())
}

/// `krb5_kuserok` without the `an2ln` module allows no account by its
/// translation, and without the `k5login` module never reads `.k5login`.
#[test]
fn localauth_controls_apply_to_authorization() -> Result<(), TestError> {
    let home = Scratch::new("controls")?;
    let decide = |controls: &str| -> Result<Authorization, TestError> {
        let authorizer = LocalAuthorizer::from_config(
            &profile("", controls)?,
            resolver("alice", 0, home.path()),
        )?;
        Ok(authorize_local(
            &authorizer,
            &principal("alice@KRBTEST.COM"),
            "alice",
        ))
    };
    // Given no `.k5login`, the DEFAULT translation allows `alice` as `alice`.
    assert_eq!(decide("")?, Authorization::Authorized(Module::An2ln));
    // When `an2ln` is disabled, nothing allows it.
    assert_eq!(
        decide("  disable = an2ln")?,
        Authorization::Denied(Denial::NoModuleAllowed)
    );
    // When only `k5login` is enabled, the missing file allows nothing.
    assert_eq!(
        decide("  enable_only = k5login")?,
        Authorization::Denied(Denial::NoModuleAllowed)
    );
    Ok(())
}
