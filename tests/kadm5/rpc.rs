//! `RPCSEC_GSS` (RFC 2203) between the client and the loopback server.
//!
//! Establishment, the integrity and privacy services, the sequence and
//! verifier checks of every reply, bounded record reassembly, and the refusal
//! of any flavor but `RPCSEC_GSS`.

use rskrb5_ng::{
    error::{Kadm5, Rpc},
    kadm5::{ApiVersion, Privileges, RemoteAdminClient},
    rpcsec_gss::Protection,
};
use tokio::{io::DuplexStream, task::JoinHandle};

use super::{
    context::{Context as _, TestError},
    server::{self, Fault, Handler, Init, RPCSEC_GSS, Script, Seen},
    support,
    wire::{Reader, Writer},
};

/// `GET_PRIVS` (MIT `kadm_rpc.h`).
const GET_PRIVS: u32 = 12;

/// `INIT` (MIT `kadm_rpc.h`).
const INIT: u32 = 13;

/// All four privileges: get, add, modify, delete (MIT `admin.h:171-174`).
const ALL_PRIVILEGES: i32 = 0x0f;

/// A handler that negotiates the version the client offers and grants every privilege.
pub(super) fn privileges() -> Handler {
    Box::new(|procedure, arguments| {
        let version = Reader::new(arguments).u32().unwrap_or_default();
        match procedure {
            INIT => Writer::new().u32(version).u32(0).finish(),
            _ => Writer::new()
                .u32(version)
                .u32(0)
                .i32(ALL_PRIVILEGES)
                .finish(),
        }
    })
}

/// A connected client and its server.
type Connected = (
    RemoteAdminClient<DuplexStream>,
    JoinHandle<Result<Seen, String>>,
);

/// Connect a client with `protection` to a server running `script`.
async fn connect(script: Script, protection: Protection) -> Result<Connected, TestError> {
    let (stream, server) = server::spawn(privileges(), script);
    let options = support::options().with_protection(protection);
    let credential = support::credential()?;
    let client = RemoteAdminClient::over_stream(stream, &credential, options).await?;
    Ok((client, server))
}

/// The privileges call under `fault`, after one correct call.
async fn second_call_under(fault: Fault) -> Result<(Result<u32, Kadm5>, Seen), TestError> {
    let (mut client, server) =
        connect(Script::faults(&[Fault::None, fault]), Protection::Privacy).await?;
    assert_eq!(client.get_privileges().await?.bits(), 0x0f);
    let result = client
        .get_privileges()
        .await
        .map(Privileges::bits);
    drop(client);
    let seen = server.await??;
    Ok((result, seen))
}

/// The privacy service (MIT's default) establishes, negotiates v4 and answers.
#[tokio::test]
async fn privacy_establishes_and_calls() -> Result<(), TestError> {
    // Given a server and a client asking for privacy.
    let (mut client, server) = connect(Script::plain(), Protection::Privacy).await?;
    // When the client reads its privileges and destroys the context.
    assert_eq!(client.api_version(), ApiVersion::V4);
    let privileges = client.get_privileges().await?;
    client.destroy().await?;
    // Then the privileges arrived, every call was RPCSEC_GSS under privacy,
    // and the context was destroyed.
    assert!(privileges.contains(
        Privileges::GET | Privileges::ADD | Privileges::MODIFY | Privileges::DELETE
    ));
    let seen = server.await??;
    assert_eq!(seen.service, 3);
    assert!(seen.flavors.iter().all(|flavor| *flavor == RPCSEC_GSS));
    assert_eq!(
        seen.calls.iter().map(|call| call.0).collect::<Vec<_>>(),
        [INIT, GET_PRIVS]
    );
    assert!(seen.destroyed);
    Ok(())
}

/// The integrity service establishes and answers.
#[tokio::test]
async fn integrity_establishes_and_calls() -> Result<(), TestError> {
    // Given a client asking for integrity.
    let (mut client, server) = connect(Script::plain(), Protection::Integrity).await?;
    // When it calls.
    let privileges = client.get_privileges().await?;
    drop(client);
    // Then the call is answered and the context is an integrity context.
    assert_eq!(privileges.bits(), 0x0f);
    assert_eq!(server.await??.service, 2);
    Ok(())
}

/// QA failure scenario: a reply with a reused sequence number is rejected.
///
/// The fresh reply's verifier and body name the previous call's
/// `RPCSEC_GSS` sequence number.
#[tokio::test]
async fn reused_sequence_number_is_rejected() -> Result<(), TestError> {
    // Given a server that answers the second call with the first call's sequence number.
    let (result, seen) = second_call_under(Fault::ReusedSequence).await?;
    // Then the client rejects the reply: its verifier does not sign this call's number.
    assert!(
        matches!(result, Err(Kadm5::Rpc(Rpc::BadVerifier(_)))),
        "{result:?}"
    );
    assert_eq!(seen.calls.len(), 3);
    Ok(())
}

/// The previous reply replayed under this call's XID is rejected.
#[tokio::test]
async fn replayed_reply_is_rejected() -> Result<(), TestError> {
    // Given a server that replays its first reply for the second call.
    let (result, _seen) = second_call_under(Fault::ReplayPrevious).await?;
    // Then the client rejects it.
    assert!(
        matches!(result, Err(Kadm5::Rpc(Rpc::BadVerifier(_)))),
        "{result:?}"
    );
    Ok(())
}

/// A correct verifier over a body naming another sequence number is rejected.
#[tokio::test]
async fn stale_body_sequence_is_rejected() -> Result<(), TestError> {
    let (result, _seen) = second_call_under(Fault::StaleBodySequence).await?;
    assert!(
        matches!(
            result,
            Err(Kadm5::Rpc(Rpc::SequenceMismatch { expected, actual })) if actual + 1 == expected
        ),
        "{result:?}"
    );
    Ok(())
}

/// A verifier MIC that does not verify is rejected.
#[tokio::test]
async fn wrong_verifier_mic_is_rejected() -> Result<(), TestError> {
    let (result, _seen) = second_call_under(Fault::WrongVerifier).await?;
    assert!(
        matches!(result, Err(Kadm5::Rpc(Rpc::BadVerifier(_)))),
        "{result:?}"
    );
    Ok(())
}

/// A body MIC (integrity) or wrap token (privacy) that does not verify is rejected.
#[tokio::test]
async fn corrupt_body_is_rejected() -> Result<(), TestError> {
    for protection in [Protection::Integrity, Protection::Privacy] {
        // Given a server that corrupts the second call's protected body.
        let (mut client, server) = connect(
            Script::faults(&[Fault::None, Fault::CorruptBody]),
            protection,
        )
        .await?;
        assert_eq!(client.get_privileges().await?.bits(), 0x0f);
        // When the client reads it, Then the GSS check refuses it.
        let result = client.get_privileges().await;
        assert!(
            matches!(result, Err(Kadm5::Rpc(Rpc::Gss(_)))),
            "{protection:?}: {result:?}"
        );
        drop(client);
        drop(server.await??);
    }
    Ok(())
}

/// A data reply with an `AUTH_NONE` verifier is rejected, never accepted unauthenticated.
#[tokio::test]
async fn unauthenticated_reply_is_rejected() -> Result<(), TestError> {
    let (result, _seen) = second_call_under(Fault::NoneVerifier).await?;
    assert!(
        matches!(result, Err(Kadm5::Rpc(Rpc::UnexpectedVerifier(0)))),
        "{result:?}"
    );
    Ok(())
}

/// A reply to another XID is rejected.
#[tokio::test]
async fn reply_to_another_call_is_rejected() -> Result<(), TestError> {
    let (result, _seen) = second_call_under(Fault::WrongXid).await?;
    assert!(
        matches!(result, Err(Kadm5::Rpc(Rpc::XidMismatch { expected: _, actual: _ }))),
        "{result:?}"
    );
    Ok(())
}

/// A reply in seven-byte fragments reassembles.
#[tokio::test]
async fn fragmented_reply_reassembles() -> Result<(), TestError> {
    let (result, _seen) = second_call_under(Fault::Fragments(7)).await?;
    assert_eq!(result?, 0x0f);
    Ok(())
}

/// A 2 GiB fragment header is refused before the body arrives, and endless
/// fragments are refused at the fragment bound.
#[tokio::test]
async fn unbounded_replies_are_refused() -> Result<(), TestError> {
    let (oversized, _seen) = second_call_under(Fault::OversizedFragment).await?;
    assert!(
        matches!(oversized, Err(Kadm5::Rpc(Rpc::RecordTooLarge { maximum: _, actual: _ }))),
        "{oversized:?}"
    );
    let (endless, _endless_seen) = second_call_under(Fault::EndlessFragments).await?;
    assert!(
        matches!(endless, Err(Kadm5::Rpc(Rpc::TooManyFragments(_)))),
        "{endless:?}"
    );
    Ok(())
}

/// A server that offers only `AUTH_SYS` is refused: the client never falls
/// back to `AUTH_SYS` or `AUTH_NONE`.
#[tokio::test]
async fn auth_sys_only_server_is_refused() -> Result<(), TestError> {
    // Given a server denying RPCSEC_GSS with AUTH_REJECTEDCRED, as one that
    // knows only AUTH_SYS does.
    let (stream, server) = server::spawn(
        privileges(),
        Script {
            init: Init::AuthSysOnly(2),
            faults: Vec::new().into(),
        },
    );
    // When the client connects.
    let credential = support::credential()?;
    let result =
        RemoteAdminClient::over_stream(stream, &credential, support::options()).await;
    // Then it fails with the denial, and every call it sent was RPCSEC_GSS.
    assert!(
        matches!(result, Err(Kadm5::Rpc(Rpc::AuthenticationRejected(2)))),
        "{:?}",
        result.err()
    );
    let seen = server.await??;
    assert_ne!(seen.flavors.len(), 0, "the client sent its context creation");
    assert!(seen.flavors.iter().all(|flavor| *flavor == RPCSEC_GSS));
    Ok(())
}

/// A context-creation reply without the window's MIC is refused, and so is
/// a zero window.
#[tokio::test]
async fn unverified_context_creation_is_refused() -> Result<(), TestError> {
    for (init, expected) in [
        (Init::NoneVerifier, "verifier"),
        (Init::Window(0), "window"),
    ] {
        let (stream, server) = server::spawn(
            privileges(),
            Script {
                init,
                faults: Vec::new().into(),
            },
        );
        let credential = support::credential()?;
        let result =
            RemoteAdminClient::over_stream(stream, &credential, support::options())
                .await;
        let refused = match &result {
            Err(Kadm5::Rpc(Rpc::UnexpectedVerifier(0))) => "verifier",
            Err(Kadm5::Rpc(Rpc::BadWindow(0))) => "window",
            _ => "accepted",
        };
        assert_eq!(refused, expected, "{:?}", result.err());
        drop(server.await?);
    }
    Ok(())
}

/// After a rejected reply the connection is closed: the next call fails
/// before anything is sent.
#[tokio::test]
async fn rejected_reply_closes_the_connection() -> Result<(), TestError> {
    // Given a client whose second call got a bad verifier.
    let (mut client, server) = connect(
        Script::faults(&[Fault::None, Fault::WrongVerifier]),
        Protection::Privacy,
    )
    .await?;
    assert_eq!(client.get_privileges().await?.bits(), 0x0f);
    drop(
        client
            .get_privileges()
            .await
            .err()
            .context("the bad verifier")?,
    );
    // When it calls again.
    let third = client.get_privileges().await;
    drop(client);
    // Then nothing more reaches the server.
    assert!(
        matches!(third, Err(Kadm5::Rpc(Rpc::ConnectionClosed))),
        "{third:?}"
    );
    assert_eq!(server.await??.calls.len(), 3);
    Ok(())
}
