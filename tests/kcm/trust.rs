//! The socket trust check and the `kcm_socket` setting.

use std::{
    fs,
    os::unix::{fs::symlink, net::UnixListener},
    path::Path,
};

use rskrb5_ng::{
    ccache::{kcm::Store, stores::CredentialStore as _},
    config::Config,
    error::{Ccache as CcacheError, Kcm as Error, KcmRefusal},
};

use super::mock::{Scripted, TestError, ok, scratch, skip_request};

/// What resolving the primary cache says about the socket at `path`.
fn refusal(store: &Store) -> Option<Error> {
    match store.resolve("") {
        Err(CcacheError::Kcm(error)) => Some(error),
        Ok(_) | Err(_) => None,
    }
}

/// A symbolic link, a plain file and a missing path are refused or absent
/// before anything is sent.
#[test]
fn only_a_socket_is_connected_to() -> Result<(), TestError> {
    let directory = scratch("trust")?;
    let socket = directory.join("real.sock");
    let _listener = UnixListener::bind(&socket)?;
    symlink(&socket, directory.join("link.sock"))?;
    fs::write(directory.join("plain"), b"not a socket")?;
    assert!(matches!(
        refusal(&Store::new(directory.join("link.sock"))),
        Some(Error::Untrusted(KcmRefusal::Symlink))
    ));
    assert!(matches!(
        refusal(&Store::new(directory.join("plain"))),
        Some(Error::Untrusted(KcmRefusal::NotASocket))
    ));
    assert!(matches!(
        refusal(&Store::new(directory.join("absent"))),
        Some(Error::NoServer)
    ));
    fs::remove_dir_all(directory)?;
    Ok(())
}

/// The user running the process owns its own socket where that user can be
/// read (Linux); elsewhere only root and named users are trusted, and the
/// refusal says so.
#[test]
fn the_owning_user_is_trusted_where_it_can_be_read() -> Result<(), TestError> {
    let daemon = Scripted::start(
        "owner",
        vec![Box::new(|stream| {
            skip_request(stream)?;
            ok(stream, b"0:3\0")
        })],
    )?;
    let store = Store::new(daemon.path());
    if cfg!(target_os = "linux") {
        assert_eq!(store.collection("")?.primary()?.name(), "KCM:0:3");
        daemon.finish()?;
    } else {
        assert!(matches!(
            refusal(&store),
            Some(Error::Untrusted(KcmRefusal::IdentityUnavailable))
        ));
    }
    Ok(())
}

/// `kcm_socket` names the socket; `-` disables the transport.
#[test]
fn the_kcm_socket_setting_selects_the_socket() -> Result<(), TestError> {
    let named = Config::parse("[libdefaults]\n kcm_socket = /run/kcm.sock\n")?;
    assert_eq!(
        Store::from_libdefaults(&named.libdefaults)?
            .socket()
            .and_then(Path::to_str),
        Some("/run/kcm.sock")
    );
    let disabled = Config::parse("[libdefaults]\n kcm_socket = -\n")?;
    assert!(matches!(
        Store::from_libdefaults(&disabled.libdefaults),
        Err(Error::NoServer)
    ));
    let default = Config::parse("[libdefaults]\n")?;
    assert_eq!(
        Store::from_libdefaults(&default.libdefaults)?
            .socket()
            .and_then(Path::to_str),
        Some("/var/run/.heim_org.h5l.kcm-socket")
    );
    Ok(())
}
