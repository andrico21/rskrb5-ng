//! Every remote operation of MIT 1.22.2's kadm5 client library.
//!
//! `client_principal.c`, `clnt_policy.c`, `clnt_privs.c` and `client_init.c`:
//! each argument layout from `kadm_rpc_xdr.c` built by the test's own writer,
//! each result's decoding, and the API version negotiation.

use alloc::sync::Arc;
use std::sync::Mutex;

use rskrb5_ng::{
    client::{Password, principal::Principal},
    error::Kadm5,
    kadm5::{
        ApiVersion, KeyData, KeyOptions, KeySaltTuple, PolicyRecord, PrincipalMask,
        PrincipalRecord, RemoteAdminClient, SaltType,
    },
    keytab::EncryptionKey,
};

use super::{
    context::{Context as _, TestError},
    server::{self, Handler, Script},
    support::{self, REALM},
    wire::{Reader, Writer},
};

/// `KADM5_NEW_SERVER_API_VERSION` (`kadm_err.et`, ovk base 43787520 + 39).
const NEW_SERVER_API_VERSION: u32 = 43_787_559;

/// `KADM5_AUTH_ADD` (ovk base + 2).
const AUTH_ADD: u32 = 43_787_522;

/// The kadm5 v4 API version on the wire (`admin.h:185-188`).
const V4: u32 = 0x1234_5704;

/// A principal of the test realm.
fn principal(name: &str) -> Principal {
    Principal::new(
        REALM,
        1,
        name.split('/').map(str::to_owned),
    )
}

/// The canned results of each procedure, `generic_ret` success otherwise.
fn results(procedure: u32, version: u32) -> Vec<u8> {
    let head = Writer::new().u32(version).u32(0);
    match procedure {
        5 => head
            .nullstring(Some("bob@EXAMPLE.COM"))
            .raw(&[0; 16])
            .u32(1)
            .i32(0)
            .i32(0)
            .u32(2)
            .u32(1)
            .nullstring(None)
            .raw(&[0; 20])
            .i32(0)
            .i32(0)
            .u32(1)
            .u32(0)
            .finish(),
        7 | 20 => head.u32(1).i32(17).opaque(&[0x3c; 16]).finish(),
        11 => head
            .nullstring(Some("strict"))
            .raw(&[0; 24])
            .u32(0)
            .raw(&[0; 8])
            .raw(&[0; 12])
            .nullstring(None)
            .i32(0)
            .u32(1)
            .finish(),
        12 => head.i32(0x03).finish(),
        14 | 15 => head.i32(1).u32(1).nullstring(Some("only")).finish(),
        23 => head
            .i32(1)
            .u32(1)
            .nullstring(Some("session_enctypes"))
            .nullstring(Some("aes256-cts"))
            .finish(),
        26 => head
            .u32(1)
            .u32(4)
            .i32(18)
            .opaque(&[0x5e; 32])
            .i32(0)
            .opaque(&[])
            .finish(),
        _ => head.finish(),
    }
}

/// A handler that negotiates v4 and answers with [`results`].
pub(super) fn canned() -> Handler {
    Box::new(|procedure, arguments| {
        let version = Reader::new(arguments).u32().unwrap_or_default();
        results(procedure, version)
    })
}

/// The `kadm5_principal_ent_rec` MIT's client sends for `bob`.
///
/// It has a max life of 3600 and the policy `default` (null modifier, no TL
/// or key data).
fn bob_record() -> Vec<u8> {
    Writer::new()
        .nullstring(Some("bob@EXAMPLE.COM"))
        .i32(0)
        .i32(0)
        .i32(0)
        .i32(3600)
        .u32(1)
        .i32(0)
        .i32(0)
        .u32(0)
        .u32(0)
        .nullstring(Some("default"))
        .i32(0)
        .i32(0)
        .i32(0)
        .i32(0)
        .u32(0)
        .i32(0)
        .i32(0)
        .u32(1)
        .u32(0)
        .finish()
}

/// The v4 `kadm5_policy_ent_rec` of `strict` with a minimum length of 12.
fn strict_policy() -> Vec<u8> {
    Writer::new()
        .nullstring(Some("strict"))
        .i32(0)
        .i32(0)
        .i32(12)
        .i32(0)
        .i32(0)
        .i32(0)
        .u32(0)
        .i32(0)
        .i32(0)
        .i32(0)
        .i32(0)
        .i32(0)
        .nullstring(None)
        .i32(0)
        .u32(1)
        .finish()
}

/// The argument bytes of `procedure` the scenario below must send.
fn expected() -> Vec<(u32, Vec<u8>)> {
    let begin = || Writer::new().u32(V4);
    let bob = || begin().nullstring(Some("bob@EXAMPLE.COM"));
    let aes = |writer: Writer| writer.u32(1).i32(18).i32(0);
    vec![
        (12, begin().finish()),
        (
            1,
            begin()
                .raw(&bob_record())
                .i32(0x821)
                .nullstring(Some("pw-1"))
                .finish(),
        ),
        (
            18,
            aes(begin().raw(&bob_record()).i32(0x821))
                .nullstring(Some("pw-1"))
                .finish(),
        ),
        (3, begin().raw(&bob_record()).i32(0x820).finish()),
        (5, bob().i32(0x41_ffff).finish()),
        (14, begin().nullstring(Some("b*")).finish()),
        (
            4,
            bob().nullstring(Some("carol/admin@EXAMPLE.COM")).finish(),
        ),
        (6, bob().nullstring(Some("pw-2")).finish()),
        (19, aes(bob().u32(1)).nullstring(Some("pw-3")).finish()),
        (7, bob().finish()),
        (20, aes(bob().u32(0)).finish()),
        (16, bob().u32(1).i32(17).opaque(&[0x11; 16]).finish()),
        (
            21,
            aes(bob().u32(0))
                .u32(1)
                .i32(18)
                .opaque(&[0x22; 32])
                .finish(),
        ),
        (
            25,
            bob()
                .u32(1)
                .u32(1)
                .u32(7)
                .i32(18)
                .opaque(&[0x33; 32])
                .i32(4)
                .opaque(b"salt")
                .finish(),
        ),
        (22, bob().i32(2).finish()),
        (23, bob().finish()),
        (
            24,
            bob()
                .nullstring(Some("require_auth"))
                .nullstring(Some("otp"))
                .finish(),
        ),
        (26, bob().u32(0).finish()),
        (
            27,
            begin()
                .nullstring(Some("robert@EXAMPLE.COM"))
                .nullstring(Some("bob@EXAMPLE.COM"))
                .finish(),
        ),
        (2, bob().finish()),
        (8, begin().raw(&strict_policy()).i32(0x1_0800).finish()),
        (10, begin().raw(&strict_policy()).i32(0x1_0000).finish()),
        (11, begin().nullstring(Some("strict")).finish()),
        (15, begin().nullstring(None).finish()),
        (9, begin().nullstring(Some("strict")).finish()),
    ]
}

/// Each operation sends MIT's argument layout and decodes MIT's results.
///
/// A create names the record's key field in its mask (`KADM5_PRINCIPAL`,
/// `KADM5_POLICY`) and a modify does not, as kadmind requires
/// (`svr_principal.c:313,569`, `svr_policy.c:74,269`).
#[tokio::test]
async fn every_operation_sends_mit_arguments() -> Result<(), TestError> {
    // Given a client connected to the canned server.
    let (stream, server) = server::spawn(canned(), Script::plain());
    let credential = support::credential()?;
    let mut client =
        RemoteAdminClient::over_stream(stream, &credential, support::options()).await?;
    let bob = principal("bob");
    let record = PrincipalRecord::new(bob.clone())
        .with_max_life(3600)
        .with_policy("default");
    let aes256 = KeySaltTuple::new(18, SaltType::Normal);
    let pw = |text: &str| Password::copy_from_str(text);
    // When every operation runs once.
    let privileges = client.get_privileges().await?;
    client
        .create_principal(&record, Some(&pw("pw-1")), &[])
        .await?;
    client
        .create_principal(&record, Some(&pw("pw-1")), &[aes256])
        .await?;
    client.modify_principal(&record).await?;
    let fetched = client.get_principal(&bob, PrincipalMask::NORMAL).await?;
    let names = client.list_principals(Some("b*")).await?;
    client
        .rename_principal(&bob, &principal("carol/admin"))
        .await?;
    client
        .change_password(&bob, &pw("pw-2"), &KeyOptions::new())
        .await?;
    client
        .change_password(
            &bob,
            &pw("pw-3"),
            &KeyOptions::new().keep_old(true).with_keysalts(vec![aes256]),
        )
        .await?;
    let random = client.randomize_keys(&bob, &KeyOptions::new()).await?;
    drop(
        client
            .randomize_keys(&bob, &KeyOptions::new().with_keysalts(vec![aes256]))
            .await?,
    );
    client
        .set_keys(&bob, &[EncryptionKey::new(17, vec![0x11; 16])])
        .await?;
    client
        .set_keys_for_keysalts(
            &bob,
            &KeyOptions::new().with_keysalts(vec![aes256]),
            &[EncryptionKey::new(18, vec![0x22; 32])],
        )
        .await?;
    client
        .set_key_data(
            &bob,
            true,
            &[KeyData::new(7, EncryptionKey::new(18, vec![0x33; 32]))
                .with_salt(4, b"salt".to_vec())],
        )
        .await?;
    client.purge_keys(&bob, 2).await?;
    let strings = client.get_strings(&bob).await?;
    client.set_string(&bob, "require_auth", Some("otp")).await?;
    let extracted = client.get_principal_keys(&bob, 0).await?;
    client.create_alias(&principal("robert"), &bob).await?;
    client.delete_principal(&bob).await?;
    let policy = PolicyRecord::new("strict").with_pw_min_length(12);
    client.create_policy(&policy).await?;
    client.modify_policy(&policy).await?;
    let fetched_policy = client.get_policy("strict").await?;
    let policies = client.list_policies(None).await?;
    client.delete_policy("strict").await?;
    client.destroy().await?;
    // Then the arguments are MIT's, byte for byte, in order.
    let seen = server.await??;
    let calls = seen.calls.get(1..).context("calls after INIT")?;
    for (index, (sent, wanted)) in calls.iter().zip(expected()).enumerate() {
        assert_eq!(*sent, wanted, "call {index}");
    }
    assert_eq!(calls.len(), expected().len());
    // And the results are decoded.
    assert_eq!(privileges.bits(), 3);
    assert_eq!(fetched.principal(), &bob);
    assert_eq!(fetched.kvno(), 2);
    assert_eq!(names, ["only"]);
    assert_eq!(
        random.iter().map(EncryptionKey::etype).collect::<Vec<_>>(),
        [17_i32]
    );
    assert_eq!(strings.len(), 1);
    let string = strings.first().context("a string")?;
    assert_eq!(
        (string.key(), string.value()),
        ("session_enctypes", "aes256-cts")
    );
    let key = extracted.first().context("a key")?;
    assert_eq!((key.kvno(), key.key().etype()), (4, 18_i32));
    assert_eq!(fetched_policy.name(), "strict");
    assert_eq!(policies, ["only"]);
    Ok(())
}

/// The client offers v4 and falls back to v3 (`client_init.c` `init_any`).
///
/// The server answers `KADM5_NEW_SERVER_API_VERSION` to v4; the client then
/// encodes v3 policy records.
#[tokio::test]
async fn version_negotiation_falls_back() -> Result<(), TestError> {
    // Given a server that knows v3 and older only.
    let versions = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&versions);
    let handler: Handler = Box::new(move |procedure, arguments| {
        let version = Reader::new(arguments).u32().unwrap_or_default();
        if procedure == 13 {
            if let Ok(mut seen) = log.lock() {
                seen.push(version);
            }
            let code = if version > 0x1234_5703 {
                NEW_SERVER_API_VERSION
            } else {
                0
            };
            return Writer::new().u32(version).u32(code).finish();
        }
        Writer::new().u32(version).u32(0).finish()
    });
    let (stream, server) = server::spawn(handler, Script::plain());
    // When the client connects and creates a policy.
    let credential = support::credential()?;
    let mut client =
        RemoteAdminClient::over_stream(stream, &credential, support::options()).await?;
    let version = client.api_version();
    client.create_policy(&PolicyRecord::new("p")).await?;
    drop(client);
    // Then it offered v4, then v3, and sent the v3 layout: six longs and
    // the three v3 fields after the name, then the mask.
    let seen = server.await??;
    assert_eq!(version, ApiVersion::V3);
    assert_eq!(
        *versions.lock().map_err(|_poison| "lock")?,
        [0x1234_5704, 0x1234_5703]
    );
    let (_, arguments) = seen.calls.last().context("the policy call")?;
    let wanted = Writer::new()
        .u32(0x1234_5703)
        .nullstring(Some("p"))
        .raw(&[0; 24])
        .u32(0)
        .raw(&[0; 8])
        .i32(0x800)
        .finish();
    assert_eq!(*arguments, wanted);
    Ok(())
}

/// A server that refuses every version fails the connection with its code.
#[tokio::test]
async fn unsupported_server_version_fails() -> Result<(), TestError> {
    let handler: Handler = Box::new(|_procedure, arguments| {
        let version = Reader::new(arguments).u32().unwrap_or_default();
        Writer::new()
            .u32(version)
            .u32(NEW_SERVER_API_VERSION)
            .finish()
    });
    let (stream, server) = server::spawn(handler, Script::plain());
    let credential = support::credential()?;
    let result =
        RemoteAdminClient::over_stream(stream, &credential, support::options()).await;
    assert!(
        matches!(
            result,
            Err(Kadm5::Server { code: NEW_SERVER_API_VERSION, procedure: _ })
        ),
        "{:?}",
        result.err()
    );
    assert_eq!(server.await??.calls.len(), 3);
    Ok(())
}

/// A server refusal (an ACL denial) is a definite failure that names the code.
#[tokio::test]
async fn acl_refusal_is_definite() -> Result<(), TestError> {
    let handler: Handler = Box::new(|procedure, arguments| {
        let version = Reader::new(arguments).u32().unwrap_or_default();
        let code = if procedure == 1 { AUTH_ADD } else { 0 };
        Writer::new().u32(version).u32(code).finish()
    });
    let (stream, server) = server::spawn(handler, Script::plain());
    let credential = support::credential()?;
    let mut client =
        RemoteAdminClient::over_stream(stream, &credential, support::options()).await?;
    let result = client
        .create_principal(&PrincipalRecord::new(principal("x")), None, &[])
        .await;
    assert!(
        matches!(result, Err(Kadm5::Server { code: AUTH_ADD, procedure: _ })),
        "{result:?}"
    );
    // The connection stays usable after an authenticated refusal.
    client.delete_principal(&principal("x")).await?;
    drop(client);
    drop(server.await??);
    Ok(())
}

/// Arguments MIT refuses with `EINVAL` fail before anything is sent.
#[tokio::test]
async fn invalid_arguments_fail_before_sending() -> Result<(), TestError> {
    let (stream, server) = server::spawn(canned(), Script::plain());
    let credential = support::credential()?;
    let mut client =
        RemoteAdminClient::over_stream(stream, &credential, support::options()).await?;
    let bob = principal("bob");
    // No keys to set (`setkey4` requires n_key_data > 0, client_principal.c).
    assert!(matches!(
        client.set_key_data(&bob, false, &[]).await,
        Err(Kadm5::InvalidArgument(_))
    ));
    // A string attribute key holding a NUL.
    assert!(matches!(
        client.set_string(&bob, "a\0b", None).await,
        Err(Kadm5::InvalidArgument(_))
    ));
    drop(client);
    assert_eq!(server.await??.calls.len(), 1);
    Ok(())
}
