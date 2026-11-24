/// How far a mechanism's context has come.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    /// No context step ran: an optimistic context does not exist.
    Fresh,
    /// A context step ran and the context is not established.
    Started,
    /// The mechanism's context is established.
    Established,
}

/// One mechanism of a negotiation (MIT `struct negoex_auth_mech`, `gssapiP_negoex.h:122-134`).
struct Entry {
    /// The mechanism.
    mechanism: Arc<dyn Mechanism>,
    /// Its object identifier.
    oid: ObjectIdentifier,
    /// Its authentication scheme.
    scheme: AuthScheme,
    /// The negotiation's session, made when first needed.
    session: Option<Box<dyn Session>>,
    /// How far the mechanism's context has come.
    phase: Phase,
    /// The meta-data the mechanism offered.
    metadata: Vec<u8>,
    /// The keys of the `VERIFY` messages.
    keys: VerifyKeys,
    /// Whether this side sent its `VERIFY` message.
    sent_checksum: bool,
    /// Whether the peer's `VERIFY` message verified.
    verified_checksum: bool,
}

impl Entry {
    /// An entry for `mechanism`.
    fn new(mechanism: Arc<dyn Mechanism>, oid: ObjectIdentifier) -> Self {
        let scheme = mechanism.auth_scheme();
        Self {
            mechanism,
            oid,
            scheme,
            session: None,
            phase: Phase::Fresh,
            metadata: Vec::new(),
            keys: VerifyKeys::none(),
            sent_checksum: false,
            verified_checksum: false,
        }
    }

    /// Whether the mechanism's context is established.
    const fn is_complete(&self) -> bool {
        matches!(self.phase, Phase::Established)
    }

    /// Whether a context step ran.
    const fn is_started(&self) -> bool {
        !matches!(self.phase, Phase::Fresh)
    }

    /// Record the result of a context step.
    const fn record(&mut self, complete: bool) {
        self.phase = if complete || self.is_complete() {
            Phase::Established
        } else {
            Phase::Started
        };
    }

    /// The session, made on first use as `role`.
    fn session(&mut self, role: Role) -> &mut dyn Session {
        let mechanism = &self.mechanism;
        self.session
            .get_or_insert_with(|| mechanism.session(role))
            .as_mut()
    }

    /// Read the session's keys (MIT `get_session_keys`): a key the session
    /// does not have yet leaves the earlier one in place.
    fn refresh_keys(&mut self) {
        if let Some(session) = self.session.as_ref() {
            self.keys.update(session.keys());
        }
    }

    /// Forget the optimistic context (MIT `check_optimistic_result`,
    /// `negoex_ctx.c:228-232`).
    fn restart(&mut self) {
        self.session = None;
        self.phase = Phase::Fresh;
        self.keys = VerifyKeys::none();
        self.sent_checksum = false;
    }

    /// The application-facing description.
    fn describe(&self) -> MechanismMetadata {
        MechanismMetadata {
            oid: self.oid.clone(),
            scheme: self.scheme,
            metadata: self.metadata.clone(),
        }
    }
}

/// The first message of `kind` among `messages`.
fn find_exchange(messages: &[Message], kind: MessageType) -> Option<&ExchangeMessage> {
    messages.iter().find_map(|message| match message {
        Message::Exchange(exchange) if exchange.message_type() == kind => Some(exchange),
        Message::Nego(_) | Message::Exchange(_) | Message::Verify(_) | Message::Alert(_) => None,
    })
}

/// The first `NEGO_MESSAGE` of `kind` among `messages`.
fn find_nego(messages: &[Message], kind: MessageType) -> Option<&NegoMessage> {
    messages.iter().find_map(|message| match message {
        Message::Nego(nego) if nego.message_type() == kind => Some(nego),
        Message::Nego(_) | Message::Exchange(_) | Message::Verify(_) | Message::Alert(_) => None,
    })
}

/// The first `VERIFY` message among `messages`.
fn find_verify(messages: &[Message]) -> Option<&VerifyMessage> {
    messages.iter().find_map(|message| match message {
        Message::Verify(verify) => Some(verify),
        Message::Nego(_) | Message::Exchange(_) | Message::Alert(_) => None,
    })
}

/// The first `ALERT` message among `messages`.
fn find_alert(messages: &[Message]) -> Option<&AlertMessage> {
    messages.iter().find_map(|message| match message {
        Message::Alert(alert) => Some(alert),
        Message::Nego(_) | Message::Exchange(_) | Message::Verify(_) => None,
    })
}
