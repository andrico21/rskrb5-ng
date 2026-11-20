//! Trace events of the exchange engines and the Tokio client.
//!
//! One [`Tracer`] per exchange turns what the engine does into redacted
//! [`Event`]s. Nothing here reads a password, key, ticket or reply content:
//! only sizes, counts, the session key's enctype number and the KDC's
//! KRB-ERROR number leave the engine.

use super::{ExchangeStep, StepInput};
use crate::{
    client::{Error, Principal},
    trace::{Event, ExchangeKind, Guard, Identity},
};

/// The trace state of one exchange.
pub(crate) struct Tracer {
    /// Where the events go.
    guard: Guard,
    /// Which exchange this is.
    kind: ExchangeKind,
    /// Requests sent so far.
    rounds: u32,
}

impl Tracer {
    /// A tracer for one exchange of `kind`.
    pub(crate) const fn new(guard: Guard, kind: ExchangeKind) -> Self {
        Self {
            guard,
            kind,
            rounds: 0,
        }
    }

    /// The exchange began.
    pub(crate) fn started(&self, client: &Principal, service: &Principal) {
        let (client_name, service_name) = (full_name(client), full_name(service));
        self.guard.emit(&Event::ExchangeStarted {
            kind: self.kind,
            client: Identity::new(&client_name),
            service: Identity::new(&service_name),
        });
    }

    /// The exchange finished with a credential whose session key has `enctype`.
    pub(crate) fn completed(&self, enctype: i32) {
        self.guard.emit(&Event::Completed {
            kind: self.kind,
            enctype,
        });
    }

    /// The exchange failed with `error`; only its class and a KDC's number are traced.
    pub(crate) fn failed(&self, error: &Error) {
        let (reason, kdc_error) = classify(error);
        self.guard.emit(&Event::Failed {
            kind: self.kind,
            kdc_error,
            reason,
        });
    }

    /// What the engine was just given.
    pub(crate) fn input(&self, input: &StepInput<'_>, who: (&Principal, &Principal)) {
        match input {
            StepInput::Start => self.started(who.0, who.1),
            StepInput::Reply(reply) => self.guard.emit(&Event::ReplyReceived {
                kind: self.kind,
                bytes: reply.len(),
            }),
            StepInput::Answer(_) => {}
        }
    }

    /// What the engine just did.
    pub(crate) fn output(&mut self, result: &Result<ExchangeStep, Error>) {
        match result {
            Ok(ExchangeStep::Outbound(outbound)) => {
                self.rounds = self.rounds.saturating_add(1);
                self.guard.emit(&Event::RequestSent {
                    kind: self.kind,
                    round: self.rounds,
                    realm: Identity::new(outbound.realm()),
                    bytes: outbound.message().len(),
                });
            }
            Ok(ExchangeStep::Prompt(_)) => self.guard.emit(&Event::Prompted { kind: self.kind }),
            Ok(ExchangeStep::Complete(session)) => self.completed(session.session_key().etype()),
            Err(error) => self.failed(error),
        }
    }
}

/// A static name for the failure class and a KDC refusal's KRB-ERROR number.
fn classify(error: &Error) -> (&'static str, Option<i32>) {
    if let Error::Kdc(kdc) = error {
        return ("kdc-error", Some(kdc.error_code()));
    }
    let reason = if matches!(error, Error::ExchangeLoop { limit: _ }) {
        "exchange-loop"
    } else if matches!(error, Error::UnexpectedStepInput { expected: _ }) {
        "unexpected-input"
    } else if matches!(error, Error::Preauth(_) | Error::Armor(_)) {
        "preauth"
    } else {
        "error"
    };
    (reason, None)
}

/// A principal as `name@REALM`.
fn full_name(principal: &Principal) -> String {
    format!("{}@{}", principal.name(), principal.realm)
}
