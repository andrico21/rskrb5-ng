//! The `tracing` leaf: trace events reach the application's subscriber.

#![cfg(feature = "tracing")]

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
    use core::{error::Error, fmt, mem};
    use std::sync::Mutex;

    use rskrb5_ng::trace::{
        Event, ExchangeKind, Guard, Identity, Options, Sink as _, adapter::Forward,
    };
    use tracing::{
        Dispatch, Level, Metadata, Subscriber,
        dispatcher::get_default,
        field::{Field, Visit},
        span::{Attributes, Id, Record},
        subscriber::{NoSubscriber, with_default},
    };

    /// One event a subscriber saw.
    #[derive(Debug)]
    struct Seen {
        /// Its target.
        target: String,
        /// Its level.
        level: Level,
        /// Its `event` field.
        name: String,
        /// Its message.
        message: String,
    }

    /// Collects the fields of one event.
    #[derive(Default)]
    struct Fields {
        /// The `event` field.
        name: String,
        /// The message.
        message: String,
    }

    impl Visit for Fields {
        fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
            match field.name() {
                "message" => self.message = format!("{value:?}"),
                "event" => self.name = format!("{value:?}"),
                _ => {}
            }
        }

        fn record_str(&mut self, field: &Field, value: &str) {
            match field.name() {
                "message" => value.clone_into(&mut self.message),
                "event" => value.clone_into(&mut self.name),
                _ => {}
            }
        }
    }

    /// A subscriber that keeps every event and makes no spans.
    #[derive(Clone, Default)]
    struct Collector {
        /// What it saw.
        seen: Arc<Mutex<Vec<Seen>>>,
    }

    impl Collector {
        /// Everything seen so far, which is forgotten.
        fn take(&self) -> Vec<Seen> {
            self.seen
                .lock()
                .map_or_else(|_poisoned| Vec::new(), |mut inner| mem::take(&mut *inner))
        }
    }

    impl Subscriber for Collector {
        fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _span: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }

        fn record(&self, _span: &Id, _values: &Record<'_>) {}

        fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            let mut fields = Fields::default();
            event.record(&mut fields);
            if let Ok(mut seen) = self.seen.lock() {
                seen.push(Seen {
                    target: event.metadata().target().to_owned(),
                    level: *event.metadata().level(),
                    name: fields.name,
                    message: fields.message,
                });
            }
        }

        fn enter(&self, _span: &Id) {}

        fn exit(&self, _span: &Id) {}
    }

    /// An event of a kind, with identities that must be withheld by default.
    fn started() -> Event<'static> {
        Event::ExchangeStarted {
            kind: ExchangeKind::Initial,
            client: Identity::new("alice@EXAMPLE.COM"),
            service: Identity::new("krbtgt/EXAMPLE.COM@EXAMPLE.COM"),
        }
    }

    /// A failure event.
    const fn failed() -> Event<'static> {
        Event::Failed {
            kind: ExchangeKind::Initial,
            kdc_error: Some(24),
            reason: "kdc",
        }
    }

    /// Events reach the scoped subscriber, with the severity of their kind.
    #[test]
    fn events_reach_the_applications_subscriber() -> Result<(), Box<dyn Error>> {
        let collector = Collector::default();
        let guard = Guard::new(Forward::new(), Options::new());
        with_default(collector.clone(), || {
            guard.emit(&started());
            guard.emit(&failed());
        });
        let all = collector.take();
        assert_eq!(all.len(), 2);
        let first = all.first().ok_or("no event")?;
        assert_eq!(first.level, Level::DEBUG);
        let levels: Vec<Level> = all.iter().map(|item| item.level).collect();
        assert_eq!(levels, [Level::DEBUG, Level::WARN]);
        let names: Vec<&str> = all.iter().map(|item| item.name.as_str()).collect();
        assert_eq!(names, ["exchange-started", "failed"]);
        assert!(all.iter().all(|item| item.target == "rskrb5_ng::trace"));
        let text: String = all.iter().map(|item| item.message.clone()).collect();
        assert!(
            !text.contains("alice") && !text.contains("krbtgt"),
            "{text}"
        );
        assert!(text.contains("kdc_error=24"), "{text}");
        Ok(())
    }

    /// Without a subscriber the adapter is a no-op, and the library installs none.
    #[test]
    fn no_subscriber_is_a_no_op_and_none_is_installed() -> Result<(), Box<dyn Error>> {
        let guard = Guard::new(Forward::new(), Options::new());
        guard.emit(&started());
        assert_eq!(guard.stats().emitted, 1);
        assert!(get_default(Dispatch::is::<NoSubscriber>));
        Forward::new().write(&started(), "text")?;
        Ok(())
    }
}
