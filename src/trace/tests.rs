//! Unit tests of the name table and the `err_fmt` expansion.

use core::{error::Error, fmt::Write as _};

use super::{Event, ExchangeKind, Identity, TransportStep, TransportWire, err_fmt::ErrFmt};
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
        Event::Transport {
            step: TransportStep::Sending,
            wire: TransportWire::Https,
            target: identity,
            size: 1,
        },
    ];
    all
}

/// `NAMES` lists every name, once, in the order `name` produces them.
#[test]
fn the_name_table_matches_every_variant() -> Result<(), Box<dyn Error>> {
    let events = every_event();
    let names: Vec<&str> = events.iter().map(Event::name).collect();
    assert_eq!(names, Event::NAMES);
    let last = events.last().ok_or("no events")?;
    assert_eq!(Some(last.name()), Event::NAMES.last().copied());
    Ok(())
}

/// Every event renders on one line that starts with its name, and its `Debug`
/// never shows the identity text.
#[test]
fn every_event_renders_one_line_starting_with_its_name() -> Result<(), Box<dyn Error>> {
    for event in every_event() {
        let mut text = String::new();
        write!(text, "{event}")?;
        assert!(text.starts_with(event.name()), "{text}");
        assert!(!text.contains('\n'), "{text}");
        assert!(!format!("{event:?}").contains("Identity(\"p\")"));
    }
    Ok(())
}

/// MIT's own `err_fmt` cases (`src/tests/t_errmsg.py:8-26`, `kerrs.c:140-169`).
#[test]
fn err_fmt_matches_mit_vectors() -> Result<(), Box<dyn Error>> {
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
    let (template, _) = cases.last().ok_or("no cases")?;
    assert_eq!(ErrFmt::new(template).template(), Some(*template));
    Ok(())
}
