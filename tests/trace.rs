//! Trace diagnostics: redacted events, bounded sinks and the `KRB5_TRACE` opt-in.

#[path = "support/env.rs"]
mod env;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    extern crate alloc;

    use alloc::sync::Arc;
    use core::error::Error;
    use std::{
        env::{temp_dir, var_os},
        ffi::OsStr,
        fs,
        path::PathBuf,
        process,
        time::{SystemTime, UNIX_EPOCH},
    };

    use rskrb5_ng::{
        ccache::Principal,
        config::{Config, ParseMode},
        error::Trace as TraceError,
        extensions::{
            CacheSelector, Event as ProviderEvent, Extension, Interface, Priority, ProviderError,
            Refusal, Registry, Selection, SelectionRequest,
        },
        trace::{
            Event, ExchangeKind, Guard, Identity, Options, Sink, TransportStep, TransportWire,
            capture::Memory, err_fmt::ErrFmt, file::Append,
        },
    };

    use super::env;

    /// A sink that fails every write and flush.
    struct Failing;

    impl Sink for Failing {
        fn write(&self, _event: &Event<'_>, _text: &str) -> Result<(), TraceError> {
            Err(TraceError::Refused)
        }
    }

    /// The event of every case: both identities are present.
    fn started<'text>(client: &'text str, service: &'text str) -> Event<'text> {
        Event::ExchangeStarted {
            kind: ExchangeKind::Initial,
            client: Identity::new(client),
            service: Identity::new(service),
        }
    }

    /// A guard over a fresh capture sink.
    fn captured(options: Options) -> (Guard, Memory) {
        let sink = Memory::new();
        (Guard::new(sink.clone(), options), sink)
    }

    /// The one line a sink captured.
    fn only_line(sink: &Memory) -> Result<String, Box<dyn Error>> {
        let lines = sink.lines();
        assert_eq!(lines.len(), 1, "{lines:?}");
        Ok(lines.into_iter().next().ok_or("no event")?)
    }

    /// A unique scratch path under the temp directory.
    fn scratch(label: &str) -> Result<PathBuf, Box<dyn Error>> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        Ok(temp_dir().join(format!("rskrb5-trace-{label}-{}-{nanos}", process::id())))
    }

    /// An event reaches the sink with a line that starts with its machine name.
    #[test]
    fn guard_delivers_the_event_with_its_name_first() -> Result<(), Box<dyn Error>> {
        let (guard, sink) = captured(Options::new().with_identities(true));
        guard.emit(&started(
            "alice@EXAMPLE.COM",
            "krbtgt/EXAMPLE.COM@EXAMPLE.COM",
        ));
        let line = only_line(&sink)?;
        assert!(line.starts_with("exchange-started "), "{line}");
        assert!(line.contains("kind=initial"), "{line}");
        assert!(line.contains("client=alice@EXAMPLE.COM"), "{line}");
        assert_eq!(guard.stats().emitted, 1);
        Ok(())
    }

    /// Principals and endpoints are sensitive: absent unless the caller opts in.
    #[test]
    fn identities_are_withheld_unless_opted_in() -> Result<(), Box<dyn Error>> {
        let (guard, sink) = captured(Options::new());
        guard.emit(&started(
            "alice@EXAMPLE.COM",
            "krbtgt/EXAMPLE.COM@EXAMPLE.COM",
        ));
        let text = only_line(&sink)?;
        assert!(
            !text.contains("alice") && !text.contains("krbtgt"),
            "{text}"
        );
        assert!(text.contains("client=-"), "{text}");
        Ok(())
    }

    /// A hostile identity cannot forge a second line or a second field.
    #[test]
    fn identity_text_is_escaped_and_stays_on_one_line() -> Result<(), Box<dyn Error>> {
        let (guard, sink) = captured(Options::new().with_identities(true));
        guard.emit(&started("a\nrequest-sent b=c\u{e9}", "x"));
        let line = only_line(&sink)?;
        assert_eq!(line.matches("client=").count(), 1, "{line}");
        assert!(line.contains("\\x0a") && line.contains("\\x20"), "{line}");
        assert!(line.is_ascii(), "{line}");
        Ok(())
    }

    /// `Debug` never prints an identity.
    #[test]
    fn debug_of_an_event_is_redacted() -> Result<(), Box<dyn Error>> {
        let text = format!("{:?}", started("alice@EXAMPLE.COM", "svc/host@EXAMPLE.COM"));
        assert!(
            !text.contains("alice") && !text.contains("svc/host"),
            "{text}"
        );
        assert!(u64::try_from(text.len())? < 200_u64, "{text}");
        Ok(())
    }

    /// One event never exceeds its byte cap, even for a long identity.
    #[test]
    fn event_text_is_capped_at_a_character_boundary() -> Result<(), Box<dyn Error>> {
        let long = "x".repeat(5_000);
        let (guard, sink) = captured(
            Options::new()
                .with_identities(true)
                .with_max_event_bytes(96),
        );
        guard.emit(&started(&long, "svc"));
        let line = only_line(&sink)?;
        assert!(line.len() <= 96, "{}", line.len());
        Ok(())
    }

    /// Past the event cap, events are dropped and counted, not delivered.
    #[test]
    fn event_count_cap_drops_and_counts() -> Result<(), Box<dyn Error>> {
        let (guard, sink) = captured(Options::new().with_max_events(3));
        for _ in 0_u8..10_u8 {
            guard.emit(&started("a", "b"));
        }
        let delivered = u64::try_from(sink.lines().len())?;
        let stats = guard.stats();
        assert_eq!(
            (delivered, stats.emitted, stats.dropped),
            (3_u64, 3_u64, 7_u64)
        );
        Ok(())
    }

    /// Past the total byte cap, nothing more is written.
    #[test]
    fn total_byte_cap_stops_the_output() -> Result<(), Box<dyn Error>> {
        let (guard, sink) = captured(
            Options::new()
                .with_identities(true)
                .with_max_total_bytes(200),
        );
        for _ in 0_u8..50_u8 {
            guard.emit(&started("alice@EXAMPLE.COM", "svc"));
        }
        let written = u64::try_from(sink.lines().iter().map(String::len).sum::<usize>())?;
        assert!(written <= 200, "{written}");
        assert!(guard.stats().dropped > 0);
        Ok(())
    }

    /// A disabled guard accepts events and does nothing.
    #[test]
    fn disabled_guard_is_inert() -> Result<(), Box<dyn Error>> {
        let guard = Guard::from_options(&Options::new())?;
        guard.emit(&started("a", "b"));
        assert!(!guard.is_enabled() && guard == Guard::disabled());
        assert_eq!(guard.stats().emitted, 0);
        Ok(())
    }

    /// A sink that fails is counted and never reaches the caller.
    #[test]
    fn failing_sink_is_counted_and_swallowed() -> Result<(), Box<dyn Error>> {
        let guard = Guard::new(Failing, Options::new());
        let attempts = [started("a", "b"), started("a", "b")];
        for event in &attempts {
            guard.emit(event);
        }
        let stats = guard.stats();
        assert_eq!(
            (stats.emitted, stats.failed),
            (0_u64, u64::try_from(attempts.len())?)
        );
        Ok(())
    }

    /// The file sink appends `[pid] seconds.micros: line` as MIT does.
    #[test]
    fn file_sink_appends_mit_framed_lines() -> Result<(), Box<dyn Error>> {
        let path = scratch("file")?;
        for _ in 0_u8..2_u8 {
            let guard = Guard::new(Append::open(&path)?, Options::new());
            guard.emit(&started("a", "b"));
        }
        let text = fs::read_to_string(&path)?;
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        let prefix = format!("[{}] ", process::id());
        assert!(lines.iter().all(|line| line.starts_with(&prefix)), "{text}");
        assert!(
            lines
                .iter()
                .all(|line| line.contains(": exchange-started ")),
            "{text}"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        }
        fs::remove_file(path)?;
        Ok(())
    }

    /// A destination that cannot be opened is a typed error, never a panic.
    #[test]
    fn unopenable_destination_is_a_typed_error() -> Result<(), Box<dyn Error>> {
        let path = scratch("missing")?.join("no").join("such").join("dir");
        let failure = Guard::from_options(&Options::new().with_file(&path)?).err();
        assert!(
            matches!(failure, Some(TraceError::Open { path: _, source: _ })),
            "{failure:?}"
        );
        Ok(())
    }

    /// An empty or oversized destination is refused before any open.
    #[test]
    fn invalid_destinations_are_refused() -> Result<(), Box<dyn Error>> {
        for bad in [String::new(), "p".repeat(5_000)] {
            let refused = Options::new().with_file(&bad).err().ok_or("accepted")?;
            assert!(
                matches!(refused, TraceError::InvalidDestination { reason: _ }),
                "{refused:?}"
            );
        }
        Ok(())
    }

    /// Options without a destination give an inert guard.
    #[test]
    fn options_without_destination_give_a_disabled_guard() -> Result<(), Box<dyn Error>> {
        assert!(!Guard::from_options(&Options::new())?.is_enabled());
        Ok(())
    }

    /// `KRB5_TRACE` is read only by `Options::from_env`, as a destination path.
    #[test]
    fn krb5_trace_names_the_destination() -> Result<(), Box<dyn Error>> {
        let test = "tests::krb5_trace_names_the_destination";
        if env::in_child(test) {
            let options = Options::from_env()?;
            assert_eq!(
                options
                    .destination()
                    .map(|path| path.as_os_str().to_owned()),
                var_os("TRACE_EXPECTED")
            );
            return Ok(());
        }
        let path = scratch("env")?;
        env::run_in_child(
            test,
            &[
                ("KRB5_TRACE", Some(path.as_os_str())),
                ("TRACE_EXPECTED", Some(path.as_os_str())),
            ],
        );
        env::run_in_child(test, &[("KRB5_TRACE", None)]);
        env::run_in_child(test, &[("KRB5_TRACE", Some(OsStr::new("")))]);
        Ok(())
    }

    /// An oversized `KRB5_TRACE` is a typed error from `from_env`.
    #[test]
    fn oversized_krb5_trace_is_refused() -> Result<(), Box<dyn Error>> {
        let test = "tests::oversized_krb5_trace_is_refused";
        if env::in_child(test) {
            let refused = Options::from_env().err().ok_or("accepted")?;
            assert!(
                matches!(refused, TraceError::InvalidDestination { reason: _ }),
                "{refused:?}"
            );
            return Ok(());
        }
        let long = "p".repeat(5_000);
        env::run_in_child(test, &[("KRB5_TRACE", Some(OsStr::new(&long)))]);
        Ok(())
    }

    /// A selector with a fixed answer, to make the registry consult a provider.
    struct Chooser;

    impl CacheSelector for Chooser {
        fn id(&self) -> &'static str {
            "chooser"
        }

        fn priority(&self) -> Priority {
            Priority::Heuristic
        }

        fn choose(&self, _request: &SelectionRequest<'_>) -> Result<Selection, ProviderError> {
            Ok(Selection::NoHandle)
        }
    }

    /// The guard registers as a `LibraryObserver` and sees the registry's events.
    #[test]
    fn guard_observes_registry_events() -> Result<(), Box<dyn Error>> {
        let (guard, sink) = captured(Options::new());
        let mut registry = Registry::new();
        registry.register(Extension::LibraryObserver(Arc::new(guard)))?;
        registry.register(Extension::CacheSelector(Arc::new(Chooser)))?;
        let server = Principal::new("EXAMPLE.ORG", 1, vec!["www".to_owned()]);
        drop(registry.select_cache(&Config::parse("")?, &server, &[])?);
        let text = sink.lines().join("\n");
        assert!(text.contains("provider-consulted"), "{text}");
        assert!(text.contains("id=chooser"), "{text}");
        Ok(())
    }

    /// A selector whose failure text carries a secret-looking marker.
    struct Leaky;

    impl CacheSelector for Leaky {
        fn id(&self) -> &'static str {
            "leaky"
        }

        fn priority(&self) -> Priority {
            Priority::Heuristic
        }

        fn choose(&self, _request: &SelectionRequest<'_>) -> Result<Selection, ProviderError> {
            Err("MARKER-OTP-123456 and the password hunter2".into())
        }
    }

    /// A provider's own error text, which may hold anything, never reaches a sink.
    #[test]
    fn provider_refusal_never_carries_the_provider_error_text() -> Result<(), Box<dyn Error>> {
        let (guard, sink) = captured(Options::new().with_identities(true));
        let mut registry = Registry::new();
        registry.register(Extension::LibraryObserver(Arc::new(guard)))?;
        registry.register(Extension::CacheSelector(Arc::new(Leaky)))?;
        let server = Principal::new("EXAMPLE.ORG", 1, vec!["www".to_owned()]);
        drop(registry.select_cache(&Config::parse("")?, &server, &[]));
        let text = sink.lines().join("\n");
        assert!(text.contains("provider-refused"), "{text}");
        assert!(
            !text.contains("MARKER") && !text.contains("hunter2"),
            "{text}"
        );
        Ok(())
    }

    /// Every event type, carrying a marker in every text field it has, shows none
    /// of it by default and never in `Debug`.
    #[test]
    fn every_event_type_withholds_and_redacts_marker_text() -> Result<(), Box<dyn Error>> {
        let marker = "MARKER-SECRET-9f3a";
        let identity = Identity::new(marker);
        let kind = ExchangeKind::Initial;
        let interface = Interface::CacheSelector;
        let events = [
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
                reason: "kdc-error",
            },
            Event::Provider(ProviderEvent::Consulted { interface, id: "p" }),
            Event::Provider(ProviderEvent::Chosen { interface, id: "p" }),
            Event::Provider(ProviderEvent::Declined { interface, id: "p" }),
            Event::Provider(ProviderEvent::Refused {
                interface,
                id: "p",
                reason: Refusal::Failed,
            }),
            Event::ApReqAccepted { service: identity },
            Event::ApReqRejected { reason: "rejected" },
            Event::Transport {
                step: TransportStep::Sending,
                wire: TransportWire::Https,
                target: identity,
                size: 1,
            },
        ];
        let names: Vec<&str> = events.iter().map(Event::name).collect();
        assert_eq!(names, Event::NAMES);
        let (guard, sink) = captured(Options::new());
        for event in &events {
            guard.emit(event);
            let debug = format!("{event:?}");
            assert!(!debug.contains(marker), "{debug}");
            assert!(u64::try_from(debug.len())? < 400_u64, "{debug}");
        }
        let text = sink.lines().join("\n");
        assert_eq!(sink.lines().len(), events.len());
        assert!(!text.contains(marker), "{text}");
        Ok(())
    }

    /// `err_fmt` raises no diagnostic, even in strict mode, and the formatter
    /// reads the configured template.
    #[test]
    fn err_fmt() -> Result<(), Box<dyn Error>> {
        let text = "[libdefaults]\n err_fmt = %C: %M\n";
        let config = Config::parse_with_mode(text, ParseMode::Strict)?;
        assert_eq!(config.diagnostics().len(), 0_usize);
        let format = ErrFmt::from_config(&config);
        assert_eq!(format.template(), Some("%C: %M"));
        assert_eq!(format.format(7, "boom"), "7: boom");
        assert_eq!(ErrFmt::from_config(&Config::parse("")?).template(), None);
        Ok(())
    }

    /// A report keeps the typed error, its source chain and its KDC code.
    #[cfg(feature = "messages")]
    #[test]
    fn report_preserves_the_typed_error_and_code() -> Result<(), Box<dyn Error>> {
        use rskrb5_ng::{
            client::{KdcError, principal::Principal as ClientPrincipal},
            error::{Any, Client},
        };
        let kdc = KdcError::new(
            SystemTime::UNIX_EPOCH,
            0,
            25,
            ClientPrincipal::tgt_service("EXAMPLE.COM"),
        );
        let failure = Client::Kdc(Box::new(kdc));
        let format = ErrFmt::new("[%C] %M");
        let report = format.report(&failure);
        assert_eq!(report.code(), -1_765_328_384 + 25);
        assert!(matches!(report.error(), Client::Kdc(_)));
        assert!(report.to_string().starts_with("[-1765328359] "), "{report}");
        let source = Error::source(&report).ok_or("no source")?;
        assert!(matches!(
            source.downcast_ref::<Client>(),
            Some(Client::Kdc(_))
        ));
        let wrapped = Any::from(Client::Kdc(Box::new(KdcError::new(
            SystemTime::UNIX_EPOCH,
            0,
            24,
            ClientPrincipal::tgt_service("EXAMPLE.COM"),
        ))));
        assert_eq!(format.report(&wrapped).code(), -1_765_328_384 + 24);
        Ok(())
    }
}
