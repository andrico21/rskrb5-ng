//! Unit tests of the name table and the `err_fmt` expansion.

#![expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]

use super::{Event, ExchangeKind, Identity, err_fmt::ErrFmt};
use crate::extensions::{Event as ProviderEvent, Interface, Refusal};

/// One event of every variant (`Event::name` matches exhaustively, so a new variant breaks the build).
fn every_event() -> Vec<Event<'static>> {
    let kind = ExchangeKind::Initial;
    let identity = Identity::new("p");
    let event = |event| Event::Provider(event);
    let interface = Interface::CacheSelector;
    let all = vec![
        Event::ExchangeStarted {
            kind,
            client: identity,
            service: identity,
        },
        Event::RequestSent {
            kind,
            round: 1,
            realm: identity,
            bytes: 1,
        },
        Event::ReplyReceived { kind, bytes: 1 },
        Event::Prompted { kind },
        Event::Completed {
            kind,
            enctype: 18_i32,
        },
        Event::Failed {
            kind,
            kdc_error: Some(24_i32),
            reason: "kdc",
        },
        event(ProviderEvent::Consulted { interface, id: "i" }),
        event(ProviderEvent::Chosen { interface, id: "i" }),
        event(ProviderEvent::Declined { interface, id: "i" }),
        event(ProviderEvent::Refused {
            interface,
            id: "i",
            reason: Refusal::Failed,
        }),
        Event::ApReqAccepted { service: identity },
        Event::ApReqRejected { reason: "replay" },
    ];
    all
}

/// `NAMES` lists every name, once, in the order `name` produces them.
#[test]
fn the_name_table_matches_every_variant() {
    let names: Vec<&str> = every_event().iter().map(Event::name).collect();
    assert_eq!(names, Event::NAMES);
}

/// Every event renders on one line that starts with its name, and its `Debug`
/// never shows the identity text.
#[test]
fn every_event_renders_one_line_starting_with_its_name() {
    for event in every_event() {
        let text = event.to_string();
        assert!(text.starts_with(event.name()), "{text}");
        assert!(!text.contains('\n'), "{text}");
        assert!(!format!("{event:?}").contains("Identity(\"p\")"));
    }
}

/// MIT's own `err_fmt` cases (`src/tests/t_errmsg.py:8-26`, `kerrs.c:140-169`).
#[test]
fn err_fmt_matches_mit_vectors() {
    let message = "No credentials cache found (filename: testdir/xx/yy)";
    let code = -1_765_328_189;
    let cases = [
        (
            "FOO Error: %M (see http://localhost:1234/%C for more information)",
            "FOO Error: No credentials cache found (filename: testdir/xx/yy) (see http://localhost:1234/-1765328189 for more information)",
        ),
        (
            "%M - %C",
            "No credentials cache found (filename: testdir/xx/yy) - -1765328189",
        ),
        (
            "%%%M %-% %C%",
            "%No credentials cache found (filename: testdir/xx/yy) %-% -1765328189%",
        ),
    ];
    for (template, expected) in cases {
        assert_eq!(ErrFmt::new(template).format(code, message), expected);
    }
    assert_eq!(ErrFmt::unset().format(code, message), message);
    assert_eq!(ErrFmt::new("").format(code, message), message);
}
