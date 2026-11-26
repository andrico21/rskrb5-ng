//! The four relations of WP-17 with and without the leaf.
//!
//! With the `localauth` leaf they are effective: no diagnostic in either parse
//! mode. Without it each is reported as `FeatureUnavailable`, its only
//! diagnostic, and strict mode refuses it.

use core::error::Error;

use rskrb5_ng::config::{Config, ConfigDiagnostic, ParseMode};

/// Parse `text` in both modes and check the diagnostics of `relation`.
fn check(text: &str, relation: &'static str) -> Result<(), Box<dyn Error>> {
    let config = Config::parse(text)?;
    let strict = Config::parse_with_mode(text, ParseMode::Strict);
    let unavailable = ConfigDiagnostic::FeatureUnavailable {
        relation,
        feature: "localauth",
    };
    if cfg!(feature = "localauth") {
        assert!(
            config.diagnostics().is_empty(),
            "{relation}: the leaf is compiled in: {:?}",
            config.diagnostics()
        );
        drop(strict?);
    } else {
        assert_eq!(
            config.diagnostics(),
            [unavailable],
            "{relation}: missing FeatureUnavailable"
        );
        assert!(strict.is_err(), "{relation}: strict mode admitted it");
    }
    Ok(())
}

/// `auth_to_local` rules: `DEFAULT` and `RULE:`.
#[test]
fn auth_to_local() -> Result<(), Box<dyn Error>> {
    check(
        "[realms]\n R = {\n auth_to_local = RULE:[1:$1](.*)s/a/b/\n auth_to_local = DEFAULT\n }\n",
        "auth_to_local",
    )
}

/// `k5login_authoritative`: both values.
#[test]
fn k5login_authoritative() -> Result<(), Box<dyn Error>> {
    for value in ["true", "false"] {
        check(
            &format!("[libdefaults]\n k5login_authoritative = {value}\n"),
            "k5login_authoritative",
        )?;
    }
    Ok(())
}

/// `k5login_directory`: a path.
#[test]
fn k5login_directory() -> Result<(), Box<dyn Error>> {
    check(
        "[libdefaults]\n k5login_directory = /etc/k5login\n",
        "k5login_directory",
    )
}
