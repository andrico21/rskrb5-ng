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
