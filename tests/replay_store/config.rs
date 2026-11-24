//! `default_rcache_name`: the relation is effective and `RcacheName::default_for` consumes it.

use std::{ffi::OsStr, path::PathBuf};

use rskrb5_ng::{
    config::{Config, ParseMode},
    error::Config as ConfigError,
    replay::RcacheName,
};

use crate::{
    context::{Context as _, TestError},
    env::{in_child, run_in_child},
};

/// Parse a profile that sets `default_rcache_name` to `value`.
fn profile(value: &str, mode: ParseMode) -> Result<Config, TestError> {
    Config::parse_with_mode(
        &format!("[libdefaults]\n default_rcache_name = {value}\n"),
        mode,
    )
    .context("the profile parses")
}

/// Pins that every MIT name form is accepted in both modes and names its store.
#[test]
fn every_mit_name_is_accepted_and_selects_its_store() -> Result<(), TestError> {
    for mode in [ParseMode::Compatible, ParseMode::Strict] {
        assert_eq!(
            RcacheName::default_for(&profile("dfl:", mode)?)?,
            RcacheName::Dfl
        );
        assert_eq!(
            RcacheName::default_for(&profile("none:", mode)?)?,
            RcacheName::None
        );
        assert_eq!(
            RcacheName::default_for(&profile("file2:/var/tmp/service.rcache", mode)?)?,
            RcacheName::File2 {
                path: PathBuf::from("/var/tmp/service.rcache")
            }
        );
    }
    Ok(())
}

/// Pins that an unset relation selects MIT's `dfl:`, not a silent in-memory cache.
#[test]
fn unset_means_dfl() -> Result<(), TestError> {
    const NAME: &str = "replay_store::config::unset_means_dfl";
    if !in_child(NAME) {
        run_in_child(NAME, &[("KRB5RCACHENAME", None), ("KRB5RCACHETYPE", None)]);
        return Ok(());
    }
    assert_eq!(RcacheName::default_for(&Config::new())?, RcacheName::Dfl);
    Ok(())
}

/// Pins that a name with an unknown type or no colon is refused when the profile is read.
#[test]
fn a_malformed_name_is_refused_by_the_profile() -> Result<(), TestError> {
    for value in ["FILE:/cache", "/var/tmp/cache", "file2:"] {
        for mode in [ParseMode::Compatible, ParseMode::Strict] {
            let outcome = Config::parse_with_mode(
                &format!("[libdefaults]\n default_rcache_name = {value}\n"),
                mode,
            );
            if !matches!(outcome, Err(ConfigError::InvalidReplayCacheName(_))) {
                return Err(format!("{mode:?} accepted {value}").into());
            }
        }
    }
    Ok(())
}

/// Pins that the path tokens of a configured name are expanded: `%{euid}` is the effective user id.
#[cfg(target_os = "linux")]
#[test]
fn path_tokens_expand_in_the_configured_name() -> Result<(), TestError> {
    use std::{fs, os::unix::fs::MetadataExt as _};

    let uid = fs::metadata("/proc/self")?.uid();
    let config = profile("file2:/var/tmp/rc-%{euid}.cache", ParseMode::Compatible)?;

    assert_eq!(
        RcacheName::default_for(&config)?,
        RcacheName::File2 {
            path: PathBuf::from(format!("/var/tmp/rc-{uid}.cache"))
        }
    );
    Ok(())
}

/// Pins that `KRB5RCACHENAME` outranks `KRB5RCACHETYPE` and the profile.
#[test]
fn the_name_variable_outranks_everything() -> Result<(), TestError> {
    const NAME: &str = "replay_store::config::the_name_variable_outranks_everything";
    if !in_child(NAME) {
        run_in_child(
            NAME,
            &[
                ("KRB5RCACHENAME", Some(OsStr::new("memory:"))),
                ("KRB5RCACHETYPE", Some(OsStr::new("none"))),
            ],
        );
        return Ok(());
    }
    let config = profile("file2:/profile", ParseMode::Compatible)?;
    assert_eq!(RcacheName::default_for(&config)?, RcacheName::Memory);
    Ok(())
}

/// Pins that `KRB5RCACHETYPE` (read as `<type>:`) outranks the profile.
#[test]
fn the_type_variable_outranks_the_profile() -> Result<(), TestError> {
    const NAME: &str = "replay_store::config::the_type_variable_outranks_the_profile";
    if !in_child(NAME) {
        run_in_child(
            NAME,
            &[
                ("KRB5RCACHENAME", None),
                ("KRB5RCACHETYPE", Some(OsStr::new("none"))),
            ],
        );
        return Ok(());
    }
    let config = profile("file2:/profile", ParseMode::Compatible)?;
    assert_eq!(RcacheName::default_for(&config)?, RcacheName::None);
    Ok(())
}
