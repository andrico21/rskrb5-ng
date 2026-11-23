//! A mutation whose request may have reached kadmind and that has no
//! authenticated answer has an unknown outcome: the client says so, never
//! repeats the request, and refuses the next call on that connection before
//! sending it (the kpasswd rule of plan 2 todo 23, A8).

use core::time::Duration;

use rskrb5_ng::{
    client::{Password, principal::Principal},
    error::{Kadm5, Rpc},
    kadm5::{KeyOptions, PrincipalMask, PrincipalRecord, RemoteAdminClient},
};
use tokio::{io::DuplexStream, task::JoinHandle};

use super::{
    context::TestError,
    operations::canned,
    server::{self, Fault, Script, Seen},
    support::{self, REALM},
};

/// The principal the scenarios change.
fn bob() -> Principal {
    Principal::new(REALM, 1, ["bob"])
}

/// A client whose first call meets `fault`, with a reply timeout of `timeout`.
async fn connect(
    fault: Fault,
    timeout: Duration,
) -> Result<
    (
        RemoteAdminClient<DuplexStream>,
        JoinHandle<Result<Seen, String>>,
    ),
    TestError,
> {
    let (stream, server) = server::spawn(canned(), Script::faults(&[fault]));
    let options = support::options().with_timeout(timeout);
    let client = RemoteAdminClient::over_stream(stream, &support::credential()?, options).await?;
    Ok((client, server))
}

/// Whether `result` is an unknown outcome whose cause is an RPC failure.
fn unknown<T>(result: &Result<T, Kadm5>) -> bool {
    matches!(result, Err(Kadm5::OutcomeUnknown { cause, .. }) if matches!(**cause, Kadm5::Rpc(_)))
}

/// A connection closed, a reply that does not verify and an unauthenticated
/// denial each leave a delivered mutation's outcome unknown.
#[tokio::test]
async fn unanswered_mutations_have_unknown_outcomes() -> Result<(), TestError> {
    for fault in [Fault::Close, Fault::WrongVerifier, Fault::Deny(7)] {
        // Given a server that commits `fault` on the mutation.
        let (mut client, server) = connect(fault, Duration::from_secs(30)).await?;
        // When the client creates a principal.
        let result = client
            .create_principal(&PrincipalRecord::new(bob()), None, &[])
            .await;
        // Then the outcome is unknown, and the next call is refused unsent.
        assert!(unknown(&result), "{fault:?}: {result:?}");
        let next = client.delete_principal(&bob()).await;
        assert!(
            matches!(
                next,
                Err(Kadm5::Rpc(Rpc::ConnectionClosed) | Kadm5::Interrupted(_))
            ),
            "{fault:?}: {next:?}"
        );
        drop(client);
        let seen = server.await??;
        assert!(seen.calls.iter().all(|call| call.0 != 2), "{fault:?}");
    }
    Ok(())
}

/// A read-only call that fails the same way is a plain failure: nothing on
/// the server could have changed.
#[tokio::test]
async fn failed_reads_are_plain_failures() -> Result<(), TestError> {
    let (mut client, server) = connect(Fault::WrongVerifier, Duration::from_secs(30)).await?;
    let result = client.get_principal(&bob(), PrincipalMask::NORMAL).await;
    assert!(
        matches!(result, Err(Kadm5::Rpc(Rpc::BadVerifier(_)))),
        "{result:?}"
    );
    drop(client);
    drop(server.await??);
    Ok(())
}

/// A mutation without a reply within the timeout has an unknown outcome.
#[tokio::test(start_paused = true)]
async fn timed_out_mutation_is_unknown() -> Result<(), TestError> {
    let (mut client, server) = connect(Fault::Stall, Duration::from_secs(5)).await?;
    let result = client
        .change_password(&bob(), &Password::copy_from_str("new"), &KeyOptions::new())
        .await;
    assert!(
        matches!(&result, Err(Kadm5::OutcomeUnknown { cause, .. }) if matches!(**cause, Kadm5::Rpc(Rpc::TimedOut))),
        "{result:?}"
    );
    drop(client);
    assert_eq!(server.await??.calls.len(), 2);
    Ok(())
}

/// A mutation cancelled after its request was sent leaves the client
/// refusing the next call before anything is sent.
#[tokio::test(start_paused = true)]
async fn cancelled_mutation_refuses_the_next_call() -> Result<(), TestError> {
    // Given a server that never answers the first call.
    let (mut client, server) = connect(Fault::Stall, Duration::from_secs(3600)).await?;
    // When the caller gives up on the password change after a second.
    let cancelled = tokio::time::timeout(
        Duration::from_secs(1),
        client.change_password(&bob(), &Password::copy_from_str("new"), &KeyOptions::new()),
    )
    .await;
    assert!(cancelled.is_err(), "the change must still be waiting");
    // Then the next call is refused and nothing more reaches the server.
    let next = client.get_privileges().await;
    assert!(matches!(next, Err(Kadm5::Interrupted(_))), "{next:?}");
    drop(client);
    assert_eq!(server.await??.calls.len(), 2);
    Ok(())
}
