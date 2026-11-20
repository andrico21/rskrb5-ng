use core::error;
use std::{
    env, fs,
    path::PathBuf,
    process,
    time::{SystemTime, UNIX_EPOCH},
};

use super::{Config, Error};

/// An existing platform default file is loaded even when an earlier
/// candidate is missing.
#[test]
fn load_default_paths_loads_existing_platform_candidate() -> Result<(), Box<dyn error::Error>> {
    let path = temp_file("load-default-paths")?;
    fs::write(
        &path,
        "
[libdefaults]
 default_realm = DEFAULT.GOKRB5
",
    )?;

    let loaded = Config::load_default_paths([PathBuf::from("/missing/krb5.conf"), path.clone()]);
    fs::remove_file(&path)?;
    let config = loaded?;

    assert_eq!(config.libdefaults.default_realm, "DEFAULT.GOKRB5");
    Ok(())
}

/// The embedded configuration is parsed when no platform default exists.
#[test]
fn load_default_or_parse_paths_uses_embedded_when_no_default_exists()
-> Result<(), Box<dyn error::Error>> {
    let config = Config::load_default_or_parse_paths(
        "
[libdefaults]
 default_realm = EMBEDDED.GOKRB5
",
        [PathBuf::from("/missing/krb5.conf")],
    )?;

    assert_eq!(config.libdefaults.default_realm, "EMBEDDED.GOKRB5");
    Ok(())
}

/// An existing but invalid platform default is an error, not a reason to
/// fall back to the embedded configuration.
#[test]
fn load_default_or_parse_paths_does_not_fallback_when_default_is_invalid()
-> Result<(), Box<dyn error::Error>> {
    let path = temp_file("load-default-invalid")?;
    fs::write(
        &path,
        "
[libdefaults]
 dns_lookup_kdc = maybe
",
    )?;

    let loaded = Config::load_default_or_parse_paths(
        "
[libdefaults]
 default_realm = EMBEDDED.GOKRB5
",
        [path.clone()],
    );
    fs::remove_file(&path)?;
    let Err(error) = loaded else {
        return Err("an invalid existing default must be returned as an error".into());
    };

    assert!(
        matches!(&error, Error::InvalidBoolean(value) if value == "maybe"),
        "the invalid boolean must be reported: {error:?}"
    );
    Ok(())
}

/// A fresh path in the temporary directory, unique to this process and
/// call.
fn temp_file(name: &str) -> Result<PathBuf, Box<dyn error::Error>> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    Ok(env::temp_dir().join(format!(
        "rskrb5-config-unit-{name}-{}-{nanos}",
        process::id()
    )))
}
