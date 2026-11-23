//! The `NegoEx` exchange between two [`Context`]s over the test-only
//! `negoextest` mechanisms: MIT's `t_negoex.py` scenarios (krb5 1.22.2).

use std::sync::Arc;

use rskrb5_ng::{
    error::Negoex,
    extensions::{Extension, Registry},
    gss::{
        ChannelBindings,
        negoex::{Context, Conversation, Mechanism, Message, Request},
    },
};

use super::{
    context::{Context as _, TestError},
    negoextest::{KeyPolicy, Knobs, OID_FIRST, OID_SECOND, Registered, TestMechanism},
};

/// The first mechanism's GUID in MIT's trace format.
const GUID_FIRST: &str = "c0a28569-66ac-0000-0000-000000000000";
/// The second mechanism's GUID.
const GUID_SECOND: &str = "d1b08469-2ca8-0000-0000-000000000000";

/// A registry with both test mechanisms registered as GSS mechanisms.
fn registry() -> Result<Registry, TestError> {
    let mut registry = Registry::new();
    for oid in [OID_FIRST, OID_SECOND] {
        registry.register(Extension::GssMechanism(Arc::new(Registered {
            oid: oid.to_vec(),
        })))?;
    }
    Ok(registry)
}

/// A fixed random source: the nonces and the conversation id are `0x42` bytes.
fn fixed(bytes: &mut [u8]) -> Result<(), getrandom::Error> {
    bytes.fill(0x42);
    Ok(())
}

/// A context offering both mechanisms with `knobs`.
fn context(initiator: bool, knobs: &Knobs) -> Result<Context, TestError> {
    let registry = registry()?;
    let mechanisms: Vec<Arc<dyn Mechanism>> = vec![
        TestMechanism::new(&OID_FIRST, knobs.clone()),
        TestMechanism::new(&OID_SECOND, knobs.clone()),
    ];
    Ok(if initiator {
        Context::initiator(&registry, &mechanisms, Request::new())?
    } else {
        Context::acceptor(&registry, &mechanisms, Request::new())?
    }
    .with_random_source(fixed))
}

/// The tokens of one run, in order, with the side that sent each.
struct Run {
    /// `(from the initiator, token)`.
    tokens: Vec<(bool, Vec<u8>)>,
}

impl Run {
    /// MIT's trace lines for the sent messages (`sending [n]TYPE: info`).
    fn trace(&self) -> Result<Vec<String>, TestError> {
        let mut conversation = Conversation::accepting();
        let mut lines = Vec::new();
        for (_, token) in &self.tokens {
            let first = conversation.next_sequence();
            for (offset, message) in conversation.parse(token)?.iter().enumerate() {
                let sequence = usize::try_from(first)? + offset;
                let info = match message {
                    Message::Nego(nego) => nego
                        .schemes()
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(" "),
                    Message::Exchange(exchange) => exchange.scheme().to_string(),
                    Message::Verify(verify) => verify.scheme().to_string(),
                    Message::Alert(alert) => alert.scheme().to_string(),
                    _ => String::new(),
                };
                lines.push(format!(
                    "sending [{sequence}]{}: {info}",
                    message.message_type().name()
                ));
            }
        }
        Ok(lines)
    }
}

/// Drive `initiator` and `acceptor` to completion.
fn drive(initiator: &mut Context, acceptor: &mut Context) -> Result<Run, Negoex> {
    let mut run = Run { tokens: Vec::new() };
    let mut token = initiator.step(None)?.into_token();
    for _ in 0..16 {
        if let Some(bytes) = token.take() {
            run.tokens.push((true, bytes.clone()));
            let step = acceptor.step(Some(&bytes))?;
            token = step.into_token();
        } else if acceptor.is_complete() && initiator.is_complete() {
            return Ok(run);
        } else {
            return Err(Negoex::UnexpectedStep("the exchange stalled"));
        }
        if let Some(bytes) = token.take() {
            run.tokens.push((false, bytes.clone()));
            let step = initiator.step(Some(&bytes))?;
            token = step.into_token();
        }
        if initiator.is_complete() && acceptor.is_complete() && token.is_none() {
            return Ok(run);
        }
    }
    Err(Negoex::UnexpectedStep("the exchange did not finish"))
}

/// Run one scenario with the initiator's and the acceptor's knobs.
fn scenario(initiator: &Knobs, acceptor: &Knobs) -> Result<Run, TestError> {
    let mut ours = context(true, initiator)?;
    let mut theirs = context(false, acceptor)?;
    Ok(drive(&mut ours, &mut theirs)?)
}

/// Assert that the sent messages include every fragment, as MIT's `expected_trace`.
fn assert_trace(run: &Run, expected: &[&str]) -> Result<(), TestError> {
    let trace = run.trace()?;
    for fragment in expected {
        assert!(
            trace.iter().any(|line| line.starts_with(fragment)),
            "no `{fragment}` in {trace:#?}"
        );
    }
    Ok(())
}

/// Knobs for `hops` hops and the key policy.
fn knobs(hops: u8, key: KeyPolicy) -> Knobs {
    Knobs {
        hops,
        key,
        ..Knobs::default()
    }
}

/// One hop: both mechanisms offered, the optimistic `AP_REQUEST` and the `VERIFY`
/// messages in MIT's order, and both sides complete.
#[test]
fn one_hop() -> Result<(), TestError> {
    let run = scenario(&knobs(1, KeyPolicy::Established), &Knobs::default())?;
    let both = format!("{GUID_FIRST} {GUID_SECOND}");
    assert_trace(
        &run,
        &[
            &format!("sending [0]INITIATOR_NEGO: {both}"),
            &format!("sending [1]INITIATOR_META_DATA: {GUID_FIRST}"),
            &format!("sending [2]INITIATOR_META_DATA: {GUID_SECOND}"),
            &format!("sending [3]AP_REQUEST: {GUID_FIRST}"),
            &format!("sending [4]VERIFY: {GUID_FIRST}"),
            &format!("sending [5]ACCEPTOR_NEGO: {both}"),
            &format!("sending [6]ACCEPTOR_META_DATA: {GUID_FIRST}"),
            &format!("sending [7]ACCEPTOR_META_DATA: {GUID_SECOND}"),
            &format!("sending [8]VERIFY: {GUID_FIRST}"),
        ],
    )
}

/// Two to four hops continue with `CHALLENGE` and `AP_REQUEST` messages, each
/// followed by a `VERIFY` message.
#[test]
fn more_hops() -> Result<(), TestError> {
    for (hops, expected) in [
        (
            2,
            &["sending [7]CHALLENGE", "sending [8]VERIFY", "sending [9]VERIFY"][..],
        ),
        (
            3,
            &["sending [8]AP_REQUEST", "sending [9]VERIFY", "sending [10]VERIFY"][..],
        ),
        (
            4,
            &["sending [9]CHALLENGE", "sending [10]VERIFY", "sending [11]VERIFY"][..],
        ),
    ] {
        let run = scenario(&knobs(hops, KeyPolicy::Established), &Knobs::default())?;
        assert_trace(&run, expected)?;
    }
    Ok(())
}

/// Keys that exist early make the `VERIFY` messages go out early.
#[test]
fn early_keys() -> Result<(), TestError> {
    let run = scenario(&knobs(3, KeyPolicy::Always), &Knobs::default())?;
    assert_trace(
        &run,
        &["sending [4]VERIFY", "sending [9]VERIFY", "sending [10]AP_REQUEST"],
    )?;
    let run = scenario(&knobs(4, KeyPolicy::Always), &Knobs::default())?;
    assert_trace(
        &run,
        &[
            "sending [4]VERIFY",
            "sending [9]VERIFY",
            "sending [10]AP_REQUEST",
            "sending [11]CHALLENGE",
        ],
    )
}

/// No key at all fails with the verify-key error.
#[test]
fn no_keys_fail() -> Result<(), TestError> {
    let failure = scenario(&knobs(1, KeyPolicy::Never), &knobs(1, KeyPolicy::Never))
        .err()
        .context("a negotiation without keys must fail")?;
    assert!(
        failure.to_string().contains("No NegoEx verify key")
            || failure.to_string().contains("no NegoEx verify key"),
        "{failure}"
    );
    Ok(())
}

/// Without the optimistic token the acceptor leads with its `ACCEPTOR_NEGO` first
/// and the `AP_REQUEST` comes later.
#[test]
fn no_optimistic_token() -> Result<(), TestError> {
    let registry = registry()?;
    let mechanisms: Vec<Arc<dyn Mechanism>> = vec![
        TestMechanism::new(&OID_FIRST, Knobs::default()),
        TestMechanism::new(&OID_SECOND, Knobs::default()),
    ];
    let mut initiator = Context::initiator(&registry, &mechanisms, Request::new())?
        .with_random_source(fixed)
        .with_optimistic_token(false);
    let mut acceptor = context(false, &Knobs::default())?;
    let run = drive(&mut initiator, &mut acceptor)?;
    assert_trace(
        &Run { tokens: run.tokens },
        &[
            "sending [3]ACCEPTOR_NEGO",
            "sending [6]AP_REQUEST",
            "sending [7]VERIFY",
            "sending [8]VERIFY",
        ],
    )
}

/// A failing first mechanism leaves the offer: in the initiator's query, and
/// in the acceptor's query or exchange the initiator falls back to the second.
#[test]
fn first_mechanism_failures_fall_back() -> Result<(), TestError> {
    let init_query = Knobs {
        init_query_fail: Some(102),
        ..Knobs::default()
    };
    let run = scenario(&init_query, &Knobs::default())?;
    assert_trace(
        &run,
        &[
            &format!("sending [0]INITIATOR_NEGO: {GUID_SECOND}"),
            "sending [2]AP_REQUEST",
            "sending [3]VERIFY",
        ],
    )?;
    for acceptor in [
        Knobs {
            accept_query_fail: Some(102),
            ..Knobs::default()
        },
        Knobs {
            accept_exchange_fail: Some(102),
            ..Knobs::default()
        },
    ] {
        let run = scenario(&Knobs::default(), &acceptor)?;
        assert_trace(
            &run,
            &[
                &format!("sending [0]INITIATOR_NEGO: {GUID_FIRST} {GUID_SECOND}"),
                &format!("sending [3]AP_REQUEST: {GUID_FIRST}"),
                &format!("sending [5]ACCEPTOR_NEGO: {GUID_SECOND}"),
                &format!("sending [7]AP_REQUEST: {GUID_SECOND}"),
                &format!("sending [9]VERIFY: {GUID_SECOND}"),
            ],
        )?;
    }
    let init_fail = Knobs {
        init_fail: Some(102),
        ..Knobs::default()
    };
    let run = scenario(&init_fail, &Knobs::default())?;
    assert_trace(
        &run,
        &[
            &format!("sending [0]INITIATOR_NEGO: {GUID_SECOND}"),
            "sending [2]AP_REQUEST",
            "sending [3]VERIFY",
        ],
    )
}

/// When the initiator's exchange of the optimistic mechanism fails there is no
/// scheme in common, and the negotiation fails.
#[test]
fn initiator_exchange_failure_leaves_no_scheme() -> Result<(), TestError> {
    for (hops, key) in [
        (1, KeyPolicy::Established),
        (2, KeyPolicy::Always),
        (2, KeyPolicy::Established),
    ] {
        let initiator = Knobs {
            hops,
            key,
            init_exchange_fail: Some(102),
            ..Knobs::default()
        };
        let failure = scenario(&initiator, &Knobs::default())
            .err()
            .context("the negotiation must fail")?;
        assert!(
            failure
                .to_string()
                .contains("No mutually supported NegoEx authentication schemes")
                || failure
                    .to_string()
                    .contains("no mutually supported NegoEx authentication schemes"),
            "hops {hops}: {failure}"
        );
    }
    Ok(())
}

/// The acceptor's mechanism failure reaches the initiator as the mechanism's own error.
#[test]
fn accept_failure_is_reported_by_the_initiator() -> Result<(), TestError> {
    let acceptor = Knobs {
        accept_fail: Some(102),
        ..Knobs::default()
    };
    let failure = scenario(&knobs(2, KeyPolicy::Established), &acceptor)
        .err()
        .context("the negotiation must fail")?;
    assert!(failure.to_string().contains("failure from acceptor"), "{failure}");
    Ok(())
}

/// A `VERIFY_NO_KEY` alert makes the other side send its `VERIFY` message again.
#[test]
fn alerts_ask_for_the_verify_message_again() -> Result<(), TestError> {
    let run = scenario(
        &knobs(3, KeyPolicy::InitAlways),
        &knobs(3, KeyPolicy::InitAlways),
    )?;
    assert_trace(
        &run,
        &[
            "sending [3]AP_REQUEST",
            "sending [4]VERIFY",
            "sending [8]CHALLENGE",
            "sending [9]ALERT",
            "sending [10]AP_REQUEST",
            "sending [11]VERIFY",
            "sending [12]VERIFY",
        ],
    )?;
    let run = scenario(
        &knobs(4, KeyPolicy::AcceptAlways),
        &knobs(4, KeyPolicy::AcceptAlways),
    )?;
    assert!(
        run.trace()?.iter().any(|line| line.contains("]ALERT")),
        "the initiator alerts the acceptor"
    );
    Ok(())
}

/// Channel bindings of the request reach the mechanism on both sides: the test
/// mechanism refuses a step whose bindings are not the ones it expects.
#[test]
fn channel_bindings_reach_the_mechanism() -> Result<(), TestError> {
    let registry = registry()?;
    let build = |initiator: bool, expected: &[u8], given: Option<&[u8]>| -> Result<Context, TestError> {
        let knobs = Knobs {
            binding: Some(expected.to_vec()),
            ..Knobs::default()
        };
        let mechanisms: Vec<Arc<dyn Mechanism>> = vec![TestMechanism::new(&OID_FIRST, knobs)];
        let request = match given {
            Some(data) => Request::new().with_bindings(ChannelBindings::new(data.to_vec())?),
            None => Request::new(),
        };
        Ok(if initiator {
            Context::initiator(&registry, &mechanisms, request)?
        } else {
            Context::acceptor(&registry, &mechanisms, request)?
        })
    };
    let mut initiator = build(true, b"a", Some(b"a"))?;
    let mut acceptor = build(false, b"b", Some(b"b"))?;
    drive(&mut initiator, &mut acceptor)?;
    let mut unbound = build(true, b"a", None)?;
    let mut other = build(false, b"b", Some(b"b"))?;
    let failure = drive(&mut unbound, &mut other)
        .err()
        .context("a step without the expected bindings must fail")?;
    assert!(matches!(failure, Negoex::Provider(_)), "{failure}");
    Ok(())
}
