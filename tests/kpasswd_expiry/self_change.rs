//! A self-service password change carries no RFC 3244 target fields (FU-IOP-P13).
//!
//! MIT `krb5_change_password` sends no target (`changepw.c:308-315`, the
//! `set_password_for` of `change_set_password` is NULL, `:200-228`); Samba takes
//! the change path only when `targname` and `targrealm` are both absent
//! (`kpasswd-service-heimdal.c:165-173`) and otherwise demands the Reset-Password
//! right. A target other than the client stays an RFC 3244 set-password.

use rasn::der;
use rskrb5_ng::{
    client::{Password, Tokio, kpasswd::RequestOptions, principal::Principal},
    kadmin::KPASSWD_SUCCESS,
    krb_priv::ipv4_host_address,
};
use tokio::net::TcpListener;

use super::{
    KdcProtocol, TestError, runtime, server,
    support::{self, REALM, epoch_plus},
};

/// Serve one kpasswd request and return the `ChangePasswdData` target it carried.
async fn serve_one(listener: TcpListener) -> Result<(Option<String>, Option<String>), TestError> {
    let (request, mut socket) = server::read_request(&listener).await?;
    let seen = server::open_request(&request)?;
    let targ_name = seen
        .change_data
        .targ_name()
        .map(|name| Ok::<_, TestError>(String::from_utf8_lossy(&der::encode(name)?).into_owned()))
        .transpose()?;
    let targ_realm = seen
        .change_data
        .targ_realm()
        .map(|realm| Ok::<_, TestError>(String::from_utf8_lossy(&der::encode(realm)?).into_owned()))
        .transpose()?;
    let reply = server::authenticated_reply(&seen, KPASSWD_SUCCESS, b"changed")?;
    server::write_response(&mut socket, &reply).await?;
    Ok((targ_name, targ_realm))
}

/// Change `target`'s password as `client` and return the target fields the server saw.
async fn change_as(
    client: &Principal,
    target: Principal,
) -> Result<(Option<String>, Option<String>), TestError> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let config = server::config(None, &listener.local_addr()?.to_string())?;
    let mut tokio_client = Tokio::from_tgt_session(config, KdcProtocol::Tcp, support::tgt(client)?);
    tokio_client.cache_service_ticket(support::changepw_ticket(client)?)?;
    let server = tokio::spawn(serve_one(listener));
    let result = tokio_client
        .change_password_for_with_options(
            target,
            Password::copy_from_str("new-password-value"),
            RequestOptions::new(
                epoch_plus(1_893_553_452)?,
                456_789,
                42,
                ipv4_host_address([127, 0, 0, 1]),
            ),
        )
        .await?;
    assert_eq!(result.code, KPASSWD_SUCCESS);
    server.await?
}

/// The client's own password is changed without target fields, whichever way it is named.
#[test]
fn a_self_change_sends_no_target_fields() -> Result<(), TestError> {
    let client = Principal::user(REALM, "testuser1");
    runtime()?.block_on(async {
        let own = change_as(&client, client.clone()).await?;
        assert_eq!(own, (None, None), "a self change must not name a target");
        // The same principal under another name type is still the client.
        let other_type = Principal::new(REALM, 2, ["testuser1"]);
        let alias = change_as(&client, other_type).await?;
        assert_eq!(alias, (None, None), "the name type does not make a target");
        Ok(())
    })
}

/// Another principal stays an RFC 3244 targeted set-password.
#[test]
fn another_principal_is_a_targeted_set_password() -> Result<(), TestError> {
    let client = Principal::user(REALM, "testuser1");
    runtime()?.block_on(async {
        let (name, realm) = change_as(&client, Principal::user(REALM, "other-user")).await?;
        assert!(name.is_some_and(|text| text.contains("other-user")));
        assert!(realm.is_some_and(|text| text.contains(REALM)));
        Ok(())
    })
}
