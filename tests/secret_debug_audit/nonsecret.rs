//! Explicit non-secret classifications for names that resemble credential fields.

/// Each exclusion identifies one owner and field, never an entire module.
pub(super) const FIELDS: &[(&str, &str, &str)] = &[
    (
        "src/trace/err_fmt.rs::Report",
        "error",
        "The borrowed original typed error: its own Debug is this crate's redacted error Debug, and the Debug of Report names only the code and the text size.",
    ),
    (
        "src/ccache/kcm/client.rs::Client",
        "stream",
        "The daemon socket (any `Read + Write`): it carries one request or reply at a time through the zeroizing frame buffers and retains no credential.",
    ),
    (
        "src/ccache/kcm/async_client.rs::Client",
        "stream",
        "The daemon socket (any Tokio stream): it carries one request or reply at a time through the zeroizing frame buffers and retains no credential.",
    ),
    (
        "src/http.rs::ValidatorOptions",
        "keytab_principal",
        "Principal selector components, not retained keytab credentials.",
    ),
    (
        "src/config.rs::EnctypeTerm",
        "token",
        "Configuration enctype expression spelling, not an authentication token.",
    ),
    (
        "src/error.rs::Config",
        "NoKpasswdServer.0",
        "Realm name identifying missing password-service configuration.",
    ),
    (
        "src/kadmin.rs::ChangePasswordResult",
        "text",
        "Server diagnostic result text, not a retained password or credential payload.",
    ),
    (
        "src/kadmin.rs::ChangePasswordResult",
        "text_raw",
        "Server diagnostic result bytes, not a retained password or credential payload.",
    ),
    (
        "src/error/any.rs::Any",
        "ApReq.0",
        "Codec error, not an AP-REQ message.",
    ),
    (
        "src/error/any.rs::Any",
        "ApRep.0",
        "Codec error, not an AP-REP message.",
    ),
    (
        "src/error/any.rs::Any",
        "KrbPriv.0",
        "Codec error, not a KRB-PRIV message.",
    ),
    (
        "src/error/any.rs::Any",
        "KrbCred.0",
        "Codec error, not a KRB-CRED message.",
    ),
    (
        "src/config/diagnostic.rs::Diagnostic",
        "UnsupportedSecureEnctype.token",
        "Configuration enctype expression, not an authentication token.",
    ),
    (
        "src/error.rs::Config",
        "UnknownEnctype.token",
        "Unknown configuration algorithm name.",
    ),
    (
        "src/error.rs::Config",
        "DisabledEnctype.token",
        "Disabled configuration algorithm name.",
    ),
    (
        "src/error.rs::Config",
        "RejectedEnctype.token",
        "Rejected configuration algorithm name.",
    ),
    (
        "src/error.rs::Config",
        "UnsupportedSecureEnctype.token",
        "Unsupported configuration algorithm name.",
    ),
    (
        "src/error.rs::Config",
        "InvalidInteger.key",
        "Configuration relation name.",
    ),
    (
        "src/error.rs::Keytab",
        "UnsupportedKeytabType.keytab_type",
        "Credential-store scheme name, not stored keys.",
    ),
    (
        "src/error.rs::Service",
        "Keytab.0",
        "error::Keytab is the keytab parse and lookup error: names, offsets and counts, no key bytes.",
    ),
    (
        "src/error.rs::Service",
        "ClientPrincipalMismatch.ticket",
        "Ticket client principal name, not encoded ticket bytes.",
    ),
    (
        "src/config.rs::LibDefaults",
        "default_ccache_name",
        "Credential-cache location template.",
    ),
    (
        "src/config.rs::LibDefaults",
        "default_client_keytab_name",
        "Client keytab location template.",
    ),
    (
        "src/config.rs::LibDefaults",
        "default_keytab_name",
        "Keytab location template.",
    ),
    (
        "src/config.rs::Realm",
        "kpasswd_server",
        "Password-service endpoint names.",
    ),
    (
        "src/client.rs::TokioClientDiagnostics",
        "credential_source",
        "Credential source kind label, not credential content.",
    ),
    (
        "src/client.rs::AsRepSession",
        "ticket_flags",
        "Four-byte protocol flags.",
    ),
    (
        "src/ccache.rs::Credential",
        "ticket_flags",
        "Four-byte protocol flags.",
    ),
    (
        "src/ccache.rs::CredentialMetadata",
        "ticket_flags",
        "Four-byte protocol flags.",
    ),
    (
        "src/ccache.rs::CredentialMetadata",
        "client_realm",
        "Public client realm metadata.",
    ),
    (
        "src/ccache.rs::CredentialMetadata",
        "client_components",
        "Public principal-name metadata.",
    ),
    (
        "src/routing/s4u.rs::PaS4uX509User",
        "checksum",
        "Keyed MAC over the public S4U user identity and nonce: an integrity value the KDC checks, not key material.",
    ),
    (
        "src/service/transit.rs::TrustedPair",
        "client_realm",
        "Realm-routing policy metadata.",
    ),
    (
        "src/service.rs::Validator",
        "keytab_principal",
        "Principal selector, not key bytes.",
    ),
    (
        "src/client.rs::Tokio",
        "transport",
        "Holds client::transport::Tokio (DNS server, timeout and size limits); the audit's name match confuses it with the client::Tokio owner.",
    ),
    (
        "src/spnego.rs::AcceptedContext",
        "mech_types_der",
        "Public mechanism OID offer list.",
    ),
    (
        "src/error/any.rs::Any",
        "Ticket.0",
        "Codec error, not a credential-bearing ticket value.",
    ),
];

/// Match only the explicitly reviewed field and require a nonempty rationale.
pub(super) fn contains(owner: &str, field: &str) -> bool {
    FIELDS
        .iter()
        .any(|(identity, name, reason)| *identity == owner && *name == field && !reason.is_empty())
}
