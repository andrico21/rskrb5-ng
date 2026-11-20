//! Event names, rendering and identity escaping.

use core::fmt::{self, Write as _};

use super::{Event, ExchangeKind, Identity};
use crate::extensions::{Event as ProviderEvent, Refusal};

impl ExchangeKind {
    /// The stable name used in rendered events.
    #[inline]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Initial => "initial",
            Self::Ticket => "ticket",
            Self::Renewal => "renewal",
        }
    }
}

impl<'text> Identity<'text> {
    /// A name to deliver when the guard allows identities.
    #[inline]
    #[must_use]
    pub const fn new(text: &'text str) -> Self {
        Self { text: Some(text) }
    }

    /// A withheld name.
    #[inline]
    #[must_use]
    pub const fn withheld() -> Self {
        Self { text: None }
    }

    /// The name, or `None` when withheld.
    #[inline]
    #[must_use]
    pub const fn text(self) -> Option<&'text str> {
        self.text
    }
}

impl fmt::Debug for Identity<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.text.is_some() {
            "Identity(<redacted>)"
        } else {
            "Identity(<withheld>)"
        })
    }
}

impl fmt::Display for Identity<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.text {
            Some(text) => fmt::Display::fmt(&Escaped(text), f),
            None => f.write_str("-"),
        }
    }
}

/// Text written with every byte outside `!`..=`~`, and the backslash, as `\xNN`.
///
/// MIT `trace.c:60-72` escapes per byte; the space and the backslash are added
/// so a field never splits and an escape is never ambiguous.
struct Escaped<'text>(&'text str);

impl fmt::Display for Escaped<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0.bytes() {
            if byte.is_ascii_graphic() && byte != b'\\' {
                f.write_char(char::from(byte))?;
            } else {
                write!(f, "\\x{byte:02x}")?;
            }
        }
        Ok(())
    }
}

/// The stable name of a refusal reason.
const fn refusal_name(reason: Refusal) -> &'static str {
    match reason {
        Refusal::Failed => "failed",
        Refusal::Malformed => "malformed",
        Refusal::TooLarge => "too-large",
        Refusal::Policy => "policy",
        Refusal::Conflict => "conflict",
    }
}

impl Event<'_> {
    /// Every name [`Self::name`] returns.
    pub const NAMES: [&'static str; 12] = [
        "exchange-started",
        "request-sent",
        "reply-received",
        "prompted",
        "completed",
        "failed",
        "provider-consulted",
        "provider-chosen",
        "provider-declined",
        "provider-refused",
        "ap-req-accepted",
        "ap-req-rejected",
    ];

    /// The stable machine name that starts every rendered line.
    #[inline]
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::ExchangeStarted {
                kind: _,
                client: _,
                service: _,
            } => "exchange-started",
            Self::RequestSent {
                kind: _,
                round: _,
                realm: _,
                bytes: _,
            } => "request-sent",
            Self::ReplyReceived { kind: _, bytes: _ } => "reply-received",
            Self::Prompted { kind: _ } => "prompted",
            Self::Completed {
                kind: _,
                enctype: _,
            } => "completed",
            Self::Failed {
                kind: _,
                kdc_error: _,
                reason: _,
            } => "failed",
            Self::Provider(ProviderEvent::Consulted {
                interface: _,
                id: _,
            }) => "provider-consulted",
            Self::Provider(ProviderEvent::Chosen {
                interface: _,
                id: _,
            }) => "provider-chosen",
            Self::Provider(ProviderEvent::Declined {
                interface: _,
                id: _,
            }) => "provider-declined",
            Self::Provider(ProviderEvent::Refused {
                interface: _,
                id: _,
                reason: _,
            }) => "provider-refused",
            Self::ApReqAccepted { service: _ } => "ap-req-accepted",
            Self::ApReqRejected { reason: _ } => "ap-req-rejected",
        }
    }

    /// The same event with every identity withheld.
    #[inline]
    #[must_use]
    pub const fn withheld(self) -> Self {
        match self {
            Self::ExchangeStarted {
                kind,
                client: _,
                service: _,
            } => Self::ExchangeStarted {
                kind,
                client: Identity::withheld(),
                service: Identity::withheld(),
            },
            Self::RequestSent {
                kind,
                round,
                realm: _,
                bytes,
            } => Self::RequestSent {
                kind,
                round,
                realm: Identity::withheld(),
                bytes,
            },
            Self::ApReqAccepted { service: _ } => Self::ApReqAccepted {
                service: Identity::withheld(),
            },
            other @ (Self::ReplyReceived { kind: _, bytes: _ }
            | Self::Prompted { kind: _ }
            | Self::Completed {
                kind: _,
                enctype: _,
            }
            | Self::Failed {
                kind: _,
                kdc_error: _,
                reason: _,
            }
            | Self::Provider(_)
            | Self::ApReqRejected { reason: _ }) => other,
        }
    }
}

impl fmt::Display for Event<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())?;
        match self {
            Self::ExchangeStarted {
                kind,
                client,
                service,
            } => write!(f, " kind={} client={client} service={service}", kind.name()),
            Self::RequestSent {
                kind,
                round,
                realm,
                bytes,
            } => write!(
                f,
                " kind={} round={round} realm={realm} bytes={bytes}",
                kind.name()
            ),
            Self::ReplyReceived { kind, bytes } => {
                write!(f, " kind={} bytes={bytes}", kind.name())
            }
            Self::Prompted { kind } => write!(f, " kind={}", kind.name()),
            Self::Completed { kind, enctype } => {
                write!(f, " kind={} enctype={enctype}", kind.name())
            }
            Self::Failed {
                kind,
                kdc_error,
                reason,
            } => {
                write!(f, " kind={} reason={reason}", kind.name())?;
                kdc_error.map_or(Ok(()), |code| write!(f, " kdc_error={code}"))
            }
            Self::Provider(event) => provider(f, *event),
            Self::ApReqAccepted { service } => write!(f, " service={service}"),
            Self::ApReqRejected { reason } => write!(f, " reason={reason}"),
        }
    }
}

/// The fields of a provider event: its interface and escaped id, and a refusal's reason.
///
/// # Errors
///
/// Returns the formatter's failure.
fn provider(out: &mut fmt::Formatter<'_>, event: ProviderEvent<'_>) -> fmt::Result {
    match event {
        ProviderEvent::Consulted { interface, id }
        | ProviderEvent::Chosen { interface, id }
        | ProviderEvent::Declined { interface, id } => {
            write!(out, " interface={interface} id={}", Escaped(id))
        }
        ProviderEvent::Refused {
            interface,
            id,
            reason,
        } => write!(
            out,
            " interface={interface} id={} reason={}",
            Escaped(id),
            refusal_name(reason)
        ),
    }
}
