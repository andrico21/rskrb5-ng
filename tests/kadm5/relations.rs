//! `[realms] <realm> admin_server` names the kadm5 client's server.
//!
//! MIT-config-44: the first value, with an optional port, else port 749 (MIT
//! `alt_prof.c` `parse_admin_server_port` and `DEFAULT_KADM5_PORT`).

use rskrb5_ng::{
    config::Config,
    error::Kadm5,
    kadm5::{self, RemoteAdminClient},
};
use std::io;

use tokio::net::TcpListener;

use super::{
    context::TestError,
    rpc::privileges,
    server::{self, Script},
    support::{self, REALM},
};

/// A profile whose realm has the `admin_server` lines `values`.
fn config(values: &[&str]) -> Result<Config, TestError> {
    let mut lines = String::new();
    for value in values {
        lines.push_str("  admin_server = ");
        lines.push_str(value);
        lines.push('\n');
    }
    Ok(Config::parse(&format!(
        "[libdefaults]\n default_realm = {REALM}\n[realms]\n {REALM} = {{\n{lines} }}\n"
    ))?)
}

/// The host and port each `admin_server` form selects.
#[test]
fn admin_server_selects_host_and_port() -> Result<(), TestError> {
    for (values, host, port) in [
        (&["kadmin.example.com"][..], "kadmin.example.com", 749),
        (&["kadmin.example.com:7749"], "kadmin.example.com", 7749),
        (&["[2001:db8::1]:750"], "2001:db8::1", 750),
        (&["[2001:db8::1]"], "2001:db8::1", 749),
        (
            &["first.example.com", "second.example.com:1"],
            "first.example.com",
            749,
        ),
    ] {
        // Given the profile, When the admin server is selected, Then it is the first value.
        let server = kadm5::admin_server(&config(values)?, REALM)?;
        assert_eq!((server.host(), server.port()), (host, port), "{values:?}");
    }
    Ok(())
}

/// No `admin_server`, or one that does not parse, is an error, never a guess.
#[test]
fn missing_or_malformed_admin_server_fails() -> Result<(), TestError> {
    let missing = kadm5::admin_server(&config(&[])?, REALM);
    assert!(
        matches!(missing, Err(Kadm5::NoAdminServer(_))),
        "{missing:?}"
    );
    for value in ["host:", "host:port", "host:70000", "[2001:db8::1", ":749"] {
        let malformed = kadm5::admin_server(&config(&[value])?, REALM);
        assert!(
            matches!(malformed, Err(Kadm5::BadAdminServer(_))),
            "{value}: {malformed:?}"
        );
    }
    Ok(())
}

/// `RemoteAdminClient::connect` reaches the server `admin_server` names.
#[tokio::test]
async fn connect_uses_admin_server() -> Result<(), TestError> {
    // Given a listener named by the profile's admin_server.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let config = config(&[&format!("127.0.0.1:{}", address.port())])?;
    let accept = tokio::spawn(async move {
        let (socket, _peer) = listener.accept().await?;
        Ok::<_, io::Error>(server::spawn_on(socket, privileges(), Script::plain()))
    });
    // When the client connects through the profile and reads its privileges.
    let credential = support::credential()?;
    let mut client =
        RemoteAdminClient::connect(&config, &credential, support::options()).await?;
    let privileges = client.get_privileges().await?;
    client.destroy().await?;
    // Then the server at that address answered.
    assert_eq!(privileges.bits(), 0x0f);
    let seen = accept.await??.await??;
    assert!(seen.destroyed);
    Ok(())
}
