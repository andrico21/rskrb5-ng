//! The fixtures, the MIT tools and the crate's login for the KCM scenarios.

use core::{error::Error, time::Duration};
use std::{os::unix::fs::FileTypeExt as _, path::PathBuf, process::Command};

use rskrb5_ng::{
    ccache::{CCache, kcm::Store},
    client::{
        AsRepSession, Tokio,
        principal::Principal,
        transport::{KdcProtocol, Tokio as KdcTransport},
    },
    config::Config,
};
use tokio::runtime::Builder;

use crate::harness::{self, Fixture};

/// The fixture KDC the TGT comes from, reached on `INTEROP_MIT_KDC`.
pub(super) const MIT_KDC: Fixture = Fixture::new("mit-kdc", "INTEROP_MIT_KDC");

/// The fixture realm.
pub(super) const REALM: &str = "TEST.RSKRB5";

/// The MIT user whose keytab the fixture exports.
pub(super) const USER: &str = "testuser1";

/// Fail unless `actual` is the `expected` mechanism; a fallback must not pass.
pub(super) fn mechanism(what: &str, expected: &str, actual: &str) -> Result<(), Box<dyn Error>> {
    if expected == actual {
        return Ok(());
    }
    Err(format!("{what}: expected {expected:?}, got {actual:?} (a fallback must not pass)").into())
}

/// Run `script` with bash in the MIT container as the exec user; its output.
pub(super) fn mit(script: &str) -> Result<String, Box<dyn Error>> {
    let user = harness::var("INTEROP_KCM_MIT_EXEC_USER")?;
    let container = harness::var("INTEROP_KCM_MIT_CONTAINER")?;
    let output = Command::new(harness::var("INTEROP_RUNTIME")?)
        .args([
            "exec",
            "--user",
            user.as_str(),
            "-e",
            "KRB5_CONFIG=/kcm-mit/krb5.conf",
        ])
        .args([container.as_str(), "bash", "-c", script])
        .output()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if output.status.success() {
        Ok(text)
    } else {
        Err(format!("MIT `{script}` failed ({}): {text}", output.status).into())
    }
}

/// How many seconds the `kcm` fixture's daemon has been up.
///
/// The container's own clock minus the modification time of the ready file its
/// entrypoint wrote when `sssd_kcm` had created its socket. The container ends
/// when the daemon does (`scripts/interop/net-kcm/entrypoint.sh`), so a running
/// container is the daemon that wrote the file.
pub(super) fn daemon_age() -> Result<u64, Box<dyn Error>> {
    let output = Command::new(harness::var("INTEROP_RUNTIME")?)
        .args(["exec", harness::var("INTEROP_KCM_CONTAINER")?.as_str()])
        .args([
            "bash",
            "-c",
            "echo $(( $(date +%s) - $(stat -c %Y /run/interop/ready) ))",
        ])
        .output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        return Err(format!(
            "the kcm container is not running ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(text.trim().parse()?)
}

/// The daemon socket of the `kcm` fixture, which must be a socket on the host.
pub(super) fn socket() -> Result<PathBuf, Box<dyn Error>> {
    let path = PathBuf::from(harness::var("INTEROP_KCM_SOCKET")?);
    if path.metadata()?.file_type().is_socket() {
        Ok(path)
    } else {
        Err(format!(
            "required interop fixture unreachable: kcm at {} is no socket (container rskrb5-interop-kcm)",
            path.display()
        )
        .into())
    }
}

/// The store the scenarios use: the production defaults, so the socket owner
/// check runs as it does for any caller.
pub(super) fn store() -> Result<Store, Box<dyn Error>> {
    Ok(Store::new(socket()?))
}

/// The cache name `KCM:<uid>:<name>` the daemon accepts from this user.
pub(super) fn residual(name: &str) -> Result<String, Box<dyn Error>> {
    Ok(format!("{}:{name}", harness::var("INTEROP_KCM_UID")?))
}

/// A TGT of the fixture user, obtained by the crate with the exported keytab.
pub(super) fn tgt_cache() -> Result<CCache, Box<dyn Error>> {
    let kdc = harness::var("INTEROP_MIT_KDC")?;
    let keytab = harness::var("INTEROP_MIT_USER_KEYTAB")?;
    let config = Config::parse(&format!(
        "[libdefaults]\n default_realm = {REALM}\n dns_lookup_kdc = false\n[realms]\n {REALM} = {{\n  kdc = {kdc}\n }}\n"
    ))?;
    Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?
        .block_on(async {
            let mut client = Tokio::with_keytab_name(
                config,
                KdcProtocol::Tcp,
                Principal::user(REALM, USER),
                keytab,
            )?
            .with_transport(KdcTransport::new().with_timeout(Duration::from_secs(10)));
            let _: &AsRepSession = client.login().await?;
            Ok(client.to_ccache()?)
        })
}
