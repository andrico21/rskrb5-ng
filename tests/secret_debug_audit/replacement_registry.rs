//! Explicit wrapper certificates; the audit re-derives every edge from source.

pub(super) const DELEGATIONS: &[(&str, &str)] = &[
    (
        "src/client.rs::Tokio::prune_unusable_sessions",
        "delegates:src/client.rs::Tokio::prune_unusable_sessions_at",
    ),
    (
        "src/client.rs::Tokio::renew_tgt",
        "delegates:src/client.rs::Tokio::renew_tgt_session_for_realm",
    ),
    (
        "src/client.rs::Tokio::cache_tgt_session",
        "delegates:src/client.rs::Tokio::cache_tgt_session_at",
    ),
    (
        "src/client.rs::Tokio::cache_tgt_session_at",
        "delegates:src/client/cache_insert.rs::tgt_session_at",
    ),
    (
        "src/client.rs::Tokio::refresh_tgt_if_needed",
        "delegates:src/client.rs::Tokio::ensure_tgt",
    ),
    (
        "src/client.rs::Tokio::get_service_ticket",
        "delegates:src/client.rs::Tokio::get_service_ticket_with_clock",
    ),
    (
        "src/client.rs::Tokio::s4u2self",
        "delegates:src/client.rs::Tokio::s4u2self_with_options",
    ),
    (
        "src/client.rs::Tokio::s4u2self_with_options",
        "delegates:src/client.rs::Tokio::ensure_tgt",
    ),
    (
        "src/client.rs::Tokio::s4u2proxy",
        "delegates:src/client.rs::Tokio::s4u2proxy_with_options",
    ),
    (
        "src/client.rs::Tokio::s4u2proxy_with_options",
        "delegates:src/client.rs::Tokio::ensure_tgt",
    ),
    (
        "src/client.rs::Tokio::spnego_header",
        "delegates:src/client.rs::Tokio::spnego_context",
    ),
    (
        "src/client.rs::Tokio::spnego_header_with_options",
        "delegates:src/client.rs::Tokio::spnego_context_with_options",
    ),
    (
        "src/client.rs::Tokio::spnego_context",
        "delegates:src/client.rs::Tokio::spnego_context_with_options",
    ),
    (
        "src/client.rs::Tokio::spnego_context_with_options",
        "delegates:src/client.rs::Tokio::get_service_ticket",
    ),
    (
        "src/client.rs::Tokio::ensure_tgt",
        "delegates:src/client.rs::Tokio::renew_tgt",
    ),
    (
        "src/client.rs::Tokio::ensure_tgt",
        "delegates:src/client.rs::Tokio::login",
    ),
    (
        "src/client.rs::Tokio::change_password",
        "delegates:src/client.rs::Tokio::change_password_for_with_options",
    ),
    (
        "src/client.rs::Tokio::change_password_for",
        "delegates:src/client.rs::Tokio::change_password_for_with_options",
    ),
    (
        "src/client.rs::Tokio::change_password_with_options",
        "delegates:src/client.rs::Tokio::change_password_for_with_options",
    ),
    (
        "src/client/stepwise.rs::InitCreds::step",
        "delegates:src/client/stepwise/init.rs::step",
    ),
    (
        "src/client/stepwise.rs::TicketCreds::step",
        "delegates:src/client/stepwise/ticket.rs::step",
    ),
    (
        "src/client/stepwise/init.rs::step",
        "delegates:src/client/stepwise/init.rs::advance",
    ),
    (
        "src/client/stepwise/ticket.rs::step",
        "delegates:src/client/stepwise/ticket.rs::advance",
    ),
    (
        "src/client/stepwise/spake.rs::reply",
        "delegates:src/client/stepwise/spake.rs::advance",
    ),
];

/// Dependency-contract replacement proofs of the stepwise exchanges: `(method,
/// test, contract)`, each erasure resting on the named owner's Drop contract.
pub(super) const CONTRACTS: &[(&str, &str, &str)] = &[
    (
        "src/client/stepwise/init.rs::advance",
        "cancellation_drops_every_secret",
        "Each step moves the held reply and the reply key out of their slots and drops them once consumed, fills only empty slots and replaces the strengthen key through remember_cookie; erasure of the dropped values relies on the Zeroizing, Password and EncryptionKey Drop contracts, observed for the prompted password and the derived reply key when an exchange is abandoned.",
    ),
    (
        "src/client/stepwise/init.rs::accept",
        "cancellation_drops_every_secret",
        "The password slot is filled only while a password exchange still waits for its prompt, so no password is replaced; an answer in any other state is refused and dropped, its erasure relying on Password's Drop contract.",
    ),
    (
        "src/client/stepwise/init.rs::initial_reply",
        "cancellation_drops_every_secret",
        "Holds the AS-REP in the empty held-reply slot while the password is prompted for, or continues through challenge; nothing held is replaced, and the held Zeroizing reply is erased by its Drop contract when taken or abandoned.",
    ),
    (
        "src/client/stepwise/init.rs::challenge",
        "cancellation_drops_every_secret",
        "Fills the empty held-reply or reply-key slot for the next step; nothing held is replaced, and the derived reply key's erasure when the exchange is abandoned is observed.",
    ),
    (
        "src/client/stepwise/init.rs::encrypted_challenge",
        "required_fast_logs_in_with_the_encrypted_challenge",
        "Fills the empty reply-key slot for the final step and builds the request from a local clone of the request template; nothing held is replaced, and the reply key's erasure relies on EncryptionKey's Drop contract (ZeroizeOnDrop).",
    ),
    (
        "src/client/stepwise/init.rs::client_referral",
        "client_referrals_are_followed_only_when_armored_and_asked_for",
        "Moves the client to the referred realm, drops the referring realm's cookie and rebuilds the first request through start from the retained password or keytab and a clone of the request template; no credential slot is replaced: step has already moved the pending request out of the state, the reply-key and held-reply slots are empty in the initial state, and an armored error never sets a strengthen key (the FAST reply check refuses one). The dropped pending request holds no key; erasure of its encoded bytes relies on Zeroizing's Drop contract.",
    ),
    (
        "src/client/stepwise/init.rs::start",
        "password_exchange_prompts_once_and_completes",
        "Builds the first request from a clone of the request template or prompts for the password; no credential slot or template field is replaced.",
    ),
    (
        "src/client/stepwise/init.rs::registered_challenge",
        "preferred_preauth_types",
        "Appends a registered mechanism's PA-DATA to the request template in place; no credential value is replaced or dropped.",
    ),
    (
        "src/client/stepwise/pkinit.rs::start",
        "certificate_login_completes_with_the_freshness_token",
        "Builds the first request from a clone of the request template with an empty PA-AS-FRESHNESS added to the clone; no credential slot or template field is replaced.",
    ),
    (
        "src/client/stepwise/pkinit.rs::offer",
        "certificate_login_completes_with_the_freshness_token",
        "Builds the PA-PK-AS-REQ from a clone of the request template and fills the empty pkinit_pending slot with the ephemeral private value and nonce; nothing held is replaced (send moves the pending request into the next state), and the value's erasure relies on Zeroizing's Drop contract.",
    ),
    (
        "src/client/stepwise/pkinit.rs::reply",
        "anonymous_pkinit_yields_the_anonymous_principal",
        "Takes the pending ephemeral value out of its slot and consumes it in the key agreement; the derived reply key is a local dropped after the AS-REP is decrypted, its erasure relying on EncryptionKey's Drop contract (ZeroizeOnDrop) and the Zeroizing shared secret's.",
    ),
    (
        "src/client/stepwise/spake.rs::offer",
        "spake_exchange_completes_with_the_strengthened_reply_key",
        "Reads a clone of the SPAKE policy and the preferred order from the options and hands the exchange to advance; no option, credential or template field is replaced, and the reply-key slot is filled only by advance, empty before.",
    ),
    (
        "src/client/stepwise/spake.rs::advance",
        "spake_exchange_completes_with_the_strengthened_reply_key",
        "Answers one PA-SPAKE value from a clone of the request template (the template itself is not replaced) and fills the empty reply-key slot with K'[0] for the response request; nothing held is replaced, and the key's erasure when the exchange is abandoned relies on EncryptionKey's Drop contract.",
    ),
    (
        "src/client/stepwise/ticket.rs::advance",
        "referrals_are_followed_within_their_bound",
        "A referral replaces the hop's TGT with the referral TGT, which referral_tgts also keeps; the previous hop's TGT is dropped and its key erasure relies on AsRepSession's Drop contract (EncryptionKey is ZeroizeOnDrop), not an observed first-party wipe.",
    ),
    (
        "src/client/stepwise/ticket.rs::request",
        "referrals_are_followed_within_their_bound",
        "Builds the hop's request from clones of the TGT and the request template and records it as the pending request; no credential slot is replaced.",
    ),
];
