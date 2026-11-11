//! Credential diagnostics are checked against the bytes actually stored in each owner.
// allow: SIZE_OK - the audit entry point binds runtime coverage to two source inventories and their adversarial fixtures.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[path = "secret_debug_audit/inventory.rs"]
mod inventory;
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[path = "secret_debug_audit/lex.rs"]
mod lex;

#[cfg(test)]
#[path = "secret_debug_audit/nonsecret.rs"]
mod nonsecret;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[path = "secret_debug_audit/replacement.rs"]
mod replacement;

#[cfg(all(test, feature = "messages"))]
#[path = "secret_debug_audit/messages.rs"]
mod messages;

#[cfg(all(test, feature = "spnego"))]
#[path = "secret_debug_audit/tokens.rs"]
mod tokens;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    extern crate alloc;
    use alloc::collections::BTreeSet;
    use core::cell::RefCell;
    use std::{io, path::Path};

    use super::inventory::{inspect, secret_field, secret_owners};

    std::thread_local! {
        static EXERCISED: RefCell<BTreeSet<String>> = const { RefCell::new(BTreeSet::new()) };
    }

    /// New credential owners and derived diagnostics cannot silently escape review.
    #[test]
    fn public_secret_owners_are_audited() -> Result<(), io::Error> {
        EXERCISED.with_borrow_mut(BTreeSet::clear);
        file_keys_redact_credentials().map_err(io::Error::other)?;
        file_containers_redact_credentials()?;
        #[cfg(feature = "messages")]
        super::messages::tests::run_audit().map_err(|error| io::Error::other(error.to_string()))?;
        #[cfg(feature = "spnego")]
        super::tokens::tests::run_audit().map_err(|error| io::Error::other(error.to_string()))?;
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let owners = inspect(root, &root.join("src"))?;
        let nested = secret_owners(&owners);
        let mut failures = Vec::new();
        for owner in owners {
            if nested.contains(&owner.identity) && active(&owner.identity) {
                let expected = runtime_identity(&owner.identity);
                if !EXERCISED.with_borrow(|types| {
                    types
                        .iter()
                        .any(|name| name.split('<').next() == Some(expected.as_str()))
                }) {
                    failures.push(format!(
                        "{} listed without a populated Debug execution",
                        owner.identity
                    ));
                }
            }
            for (name, public, ty) in &owner.fields {
                if secret_field(name, ty) && !super::nonsecret::contains(&owner.identity, name) {
                    if owner.derived_debug {
                        failures.push(format!("{} derives Debug for {name}", owner.identity));
                    }
                    if *public && !ty.iter().any(|word| word == "&") {
                        failures.push(format!(
                            "{} exposes replaceable secret {name}",
                            owner.identity
                        ));
                    }
                    if !COVERED.contains(&owner.identity.as_str()) {
                        failures.push(format!(
                            "{} needs audit coverage ({})",
                            owner.identity, owner.name
                        ));
                    }
                }
            }
            if nested.contains(&owner.identity) {
                if owner.derived_debug {
                    failures.push(format!(
                        "{} derives Debug on a credential container",
                        owner.identity
                    ));
                }
                if !COVERED.contains(&owner.identity.as_str()) {
                    failures.push(format!("{} has no populated audit case", owner.identity));
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        Ok(())
    }

    fn active(identity: &str) -> bool {
        if identity.starts_with("src/pac") {
            return cfg!(feature = "messages");
        }
        if identity == "src/error/any.rs::Any" {
            return cfg!(feature = "messages");
        }
        if identity.starts_with("src/service") {
            return cfg!(feature = "messages");
        }
        if identity.starts_with("src/http.rs") {
            return cfg!(feature = "http")
                && (!identity.contains("TowerError") && !identity.contains("NegotiateFuture")
                    || cfg!(feature = "tower"))
                && (!identity.contains("NegotiateHttp") || cfg!(feature = "tokio"));
        }
        if identity.starts_with("src/spnego") || identity.ends_with("::Spnego") {
            return cfg!(feature = "spnego");
        }
        if identity.contains("Tokio") || identity.contains("negotiate.rs") {
            return cfg!(feature = "tokio");
        }
        if identity.starts_with("src/client")
            || identity.starts_with("src/kadmin")
            || identity.starts_with("src/messages")
            || identity.ends_with("::Client")
        {
            return cfg!(feature = "messages");
        }
        if identity.ends_with("::Http") {
            return cfg!(feature = "http");
        }
        true
    }

    fn runtime_identity(identity: &str) -> String {
        if identity == "src/error/any.rs::Any" {
            return "rskrb5_ng::error::Any".to_owned();
        }
        let (file, owner) = identity.rsplit_once("::").unwrap_or((identity, ""));
        let module = file
            .strip_prefix("src/")
            .unwrap_or(file)
            .trim_end_matches(".rs")
            .replace('/', "::");
        format!("rskrb5_ng::{module}::{owner}")
    }

    /// Every public secret replacement needs an independently observed wipe case.
    #[test]
    fn public_secret_replacements_are_audited() -> Result<(), io::Error> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let owners = inspect(root, &root.join("src"))?;
        let names = secret_owners(&owners);
        let methods = super::replacement::inspect(root, &root.join("src"))?;
        let tests = super::replacement::test_names(&root.join("src"))?;
        for (_, proof) in REPLACEMENT_PROOFS {
            assert!(
                tests.iter().any(|name| name == proof),
                "missing observed wipe test {proof}"
            );
        }
        let mut failures = Vec::new();
        for method in methods {
            let replaced = super::replacement::replaced_fields(&method);
            if names
                .iter()
                .any(|name| name.ends_with(&format!("::{}", method.owner)))
                && !replaced.is_empty()
            {
                for owner in owners.iter().filter(|owner| owner.name == method.owner) {
                    for (field, _, ty) in &owner.fields {
                        if replaced.contains(field)
                            && secret_field(field, ty)
                            && !super::nonsecret::contains(&owner.identity, field)
                            && !REPLACEMENT_EXCEPTIONS.iter().any(|(identity, reason)| {
                                *identity == method.identity && !reason.is_empty()
                            })
                            && !REPLACEMENT_PROOFS.iter().any(|(identity, proof)| {
                                *identity == method.identity && !proof.is_empty()
                            })
                        {
                            failures.push(format!("{} replaces {field}", method.identity));
                        }
                    }
                }
            }
        }
        assert!(
            failures.is_empty(),
            "uncovered replacement methods:\n{}",
            failures.join("\n")
        );
        Ok(())
    }

    /// Reviewed operations that do not destroy retained secret bytes.
    const REPLACEMENT_EXCEPTIONS: &[(&str, &str)] = &[
        (
            "src/client.rs::BuiltApReq::set_message",
            "Dependency-owned rasn OctetString residual; no mutable byte API, documented in security-policy residual copies.",
        ),
        (
            "src/client.rs::KdcError::set_method_data",
            "Dependency-owned rasn PA-DATA residual; no mutable byte API, documented in security-policy residual copies.",
        ),
        (
            "src/client/options.rs::AsReq::with_padata",
            "Dependency-owned rasn PA-DATA residual; no mutable byte API, documented in security-policy residual copies.",
        ),
        (
            "src/client/options.rs::TgsReq::with_padata",
            "Dependency-owned rasn PA-DATA residual; no mutable byte API, documented in security-policy residual copies.",
        ),
        (
            "src/client/options.rs::TgsReq::with_additional_tickets",
            "Dependency-owned rasn ticket residual; no mutable byte API, documented in security-policy residual copies.",
        ),
        (
            "src/client/options.rs::ApReq::with_checksum",
            "Dependency-owned rasn checksum residual; no mutable byte API, documented in security-policy residual copies.",
        ),
        (
            "src/kadmin/reply.rs::Reply::set_ap_rep",
            "Dependency-owned rasn AP-REP residual; no mutable byte API, documented in security-policy residual copies.",
        ),
        (
            "src/kadmin/reply.rs::Reply::set_krb_priv",
            "Dependency-owned rasn KRB-PRIV residual; no mutable byte API, documented in security-policy residual copies.",
        ),
        (
            "src/pac.rs::Pac::process_buffers",
            "Mutably borrows a retained buffer only to zero public signature bytes; no owner replacement.",
        ),
        (
            "src/spnego.rs::MicToken::set_checksum",
            "Rejects an existing checksum before assignment; initializes an absent field.",
        ),
        (
            "src/spnego.rs::WrapToken::set_checksum",
            "Rejects an existing checksum before assignment; initializes an absent field.",
        ),
    ];

    /// Methods with live pre-replacement byte observations in their owning unit tests.
    const REPLACEMENT_PROOFS: &[(&str, &str)] = &[
        (
            "src/spnego.rs::WrapToken::encrypt_payload_with_confounder",
            "sealed_wrap_replacements_erase_live_credentials",
        ),
        (
            "src/spnego.rs::WrapToken::decrypt_and_set_payload",
            "sealed_wrap_replacements_erase_live_credentials",
        ),
        (
            "src/client.rs::Tokio::clear_service_ticket_cache",
            "client_cache_clear_erases_live_key_owners",
        ),
        (
            "src/client.rs::Tokio::destroy",
            "client_cache_clear_erases_live_key_owners",
        ),
        (
            "src/spnego.rs::MicToken::clear_payload",
            "gss_replacements_erase_live_credentials",
        ),
        (
            "src/spnego.rs::MicToken::with_payload",
            "gss_replacements_erase_live_credentials",
        ),
        (
            "src/spnego.rs::MicToken::with_checksum",
            "gss_replacements_erase_live_credentials",
        ),
        (
            "src/spnego.rs::WrapToken::clear_payload",
            "gss_replacements_erase_live_credentials",
        ),
        (
            "src/spnego.rs::WrapToken::with_payload",
            "gss_replacements_erase_live_credentials",
        ),
        (
            "src/spnego.rs::WrapToken::with_checksum",
            "gss_replacements_erase_live_credentials",
        ),
        (
            "src/client/kpasswd.rs::VerifiedKpasswdApRep::set_subkey",
            "verified_password_subkey_replacement_erases_old_bytes",
        ),
        (
            "src/client/kpasswd.rs::BuiltKpasswdRequest::set_reply_key",
            "password_key_replacements_erase_old_bytes",
        ),
        (
            "src/keytab.rs::Entry::set_key",
            "nested_key_replacements_erase_old_bytes",
        ),
        (
            "src/ccache.rs::Credential::set_key",
            "nested_key_replacements_erase_old_bytes",
        ),
        (
            "src/client/options.rs::ApReq::with_subkey",
            "nested_key_replacements_erase_old_bytes",
        ),
        (
            "src/spnego.rs::InitiatorContextOptions::with_subkey",
            "nested_key_replacements_erase_old_bytes",
        ),
        (
            "src/client.rs::BuiltApReq::set_der",
            "built_request_replacements_erase_old_bytes",
        ),
        (
            "src/client.rs::BuiltApReq::set_session_key",
            "built_request_replacements_erase_old_bytes",
        ),
        (
            "src/client.rs::BuiltApReq::set_subkey",
            "built_request_replacements_erase_old_bytes",
        ),
        (
            "src/client.rs::TgsFastRequestParts::set_ap_req_der",
            "built_request_replacements_erase_old_bytes",
        ),
        (
            "src/client.rs::TgsFastRequestParts::set_authenticator_subkey",
            "built_request_replacements_erase_old_bytes",
        ),
        (
            "src/client.rs::AsRepSession::set_session_key",
            "session_and_error_replacements_erase_old_bytes",
        ),
        (
            "src/client.rs::AsRepSession::set_ticket",
            "session_and_error_replacements_erase_old_bytes",
        ),
        (
            "src/client.rs::KdcError::set_e_data",
            "session_and_error_replacements_erase_old_bytes",
        ),
        (
            "src/pac.rs::CredentialsInfo::set_encrypted_credential_data",
            "pac_payload_replacement_erases_previous_bytes",
        ),
        (
            "src/pac.rs::SecpkgSupplementalCredential::set_credentials",
            "pac_payload_replacement_erases_previous_bytes",
        ),
        (
            "src/pac.rs::NtlmSupplementalCredential::set_lm_password",
            "ntlm_replacement_erases_previous_hashes",
        ),
        (
            "src/pac.rs::NtlmSupplementalCredential::set_nt_password",
            "ntlm_replacement_erases_previous_hashes",
        ),
        (
            "src/kadmin.rs::BuiltChangePasswordRequest::set_der",
            "built_password_frame_replacement_erases_old_bytes",
        ),
        (
            "src/kadmin/payload.rs::ChangePasswdData::set_new_passwd",
            "password_setter_erases_previous_bytes",
        ),
        (
            "src/keytab.rs::EncryptionKey::set_value",
            "replacement_erases_old_key_allocation",
        ),
        (
            "src/ccache.rs::EncryptionKey::set_value",
            "replacement_erases_old_key_allocation",
        ),
        (
            "src/ccache.rs::Credential::set_ticket",
            "replacement_erases_ticket_and_authorization_payloads",
        ),
        (
            "src/ccache.rs::Credential::set_second_ticket",
            "replacement_erases_ticket_and_authorization_payloads",
        ),
        (
            "src/ccache.rs::Credential::with_second_ticket",
            "replacement_erases_ticket_and_authorization_payloads",
        ),
        (
            "src/ccache.rs::AuthorizationDataEntry::set_data",
            "replacement_erases_ticket_and_authorization_payloads",
        ),
        (
            "src/spnego.rs::Krb5MechToken::set_message",
            "negotiation_replacements_erase_live_credentials",
        ),
        (
            "src/spnego.rs::NegTokenInit::set_mech_token",
            "negotiation_replacements_erase_live_credentials",
        ),
        (
            "src/spnego.rs::NegTokenInit::set_mech_list_mic",
            "negotiation_replacements_erase_live_credentials",
        ),
        (
            "src/spnego.rs::NegTokenResp::set_response_token",
            "negotiation_replacements_erase_live_credentials",
        ),
        (
            "src/spnego.rs::NegTokenResp::set_mech_list_mic",
            "negotiation_replacements_erase_live_credentials",
        ),
        (
            "src/pac.rs::KerbValidationInfo::set_user_session_key",
            "validation_key_erased_on_success_and_failure",
        ),
        (
            "src/service.rs::ValidatedApReq::set_session_key",
            "service_key_replacements_erase_old_allocations",
        ),
        (
            "src/service.rs::ValidatedApReq::set_subkey",
            "service_key_replacements_erase_old_allocations",
        ),
        (
            "src/service.rs::ApRepOptions::set_subkey",
            "service_key_replacements_erase_old_allocations",
        ),
        (
            "src/service.rs::VerifiedApRep::set_subkey",
            "service_key_replacements_erase_old_allocations",
        ),
    ];

    /// Owners exercised with populated credential fields by this integration target.
    const COVERED: &[&str] = &[
        "src/keytab.rs::EncryptionKey",
        "src/keytab.rs::Entry",
        "src/keytab.rs::Keytab",
        "src/keytab/key_bytes.rs::Bytes",
        "src/ccache.rs::EncryptionKey",
        "src/ccache.rs::Credential",
        "src/ccache.rs::AuthorizationDataEntry",
        "src/ccache.rs::CCache",
        "src/client/options.rs::AsReq",
        "src/client/options.rs::TgsReq",
        "src/client/options.rs::ApReq",
        "src/client.rs::TgsRequestParts",
        "src/client.rs::KdcError",
        "src/client.rs::AsRepSession",
        "src/client.rs::ReferralTgsResult",
        "src/client.rs::BuiltApReq",
        "src/client.rs::BuiltAsReq",
        "src/client.rs::BuiltTgsReq",
        "src/client.rs::TgsFastRequestParts",
        "src/client.rs::Tokio",
        "src/client.rs::TokioClientCredentials",
        "src/client/password.rs::Secret",
        "src/client/kpasswd.rs::BuiltKpasswdRequest",
        "src/client/kpasswd.rs::VerifiedKpasswdApRep",
        "src/client/negotiate.rs::Client",
        "src/client/negotiate.rs::BlockingClient",
        "src/kadmin.rs::Request",
        "src/kadmin.rs::Reply",
        "src/kadmin.rs::BuiltChangePasswordRequest",
        "src/kadmin.rs::PasswordEncryption",
        "src/kadmin.rs::ChangePasswdData",
        "src/kadmin/password.rs::Bytes",
        "src/messages.rs::EncryptedData",
        "src/messages.rs::KrbErrorInfo",
        "src/messages.rs::PaReqEncPaRep",
        "src/messages.rs::PaForUser",
        "src/pac.rs::Pac",
        "src/pac.rs::KerbValidationInfo",
        "src/pac.rs::CredentialsInfo",
        "src/pac.rs::CredentialData",
        "src/pac.rs::SecpkgSupplementalCredential",
        "src/pac.rs::NtlmSupplementalCredential",
        "src/pac/session_key.rs::SessionKey",
        "src/service.rs::Validator",
        "src/service.rs::ValidatedApReq",
        "src/service.rs::ApRepOptions",
        "src/service.rs::VerifiedApRep",
        "src/spnego.rs::AcceptedContext",
        "src/http.rs::TowerError",
        "src/http.rs::NegotiateHttpError",
        "src/http.rs::ClientNegotiateResponse",
        "src/http.rs::NegotiateHttpResponse",
        "src/http.rs::NegotiateFuture",
        "src/error/any.rs::Any",
        "src/error.rs::Client",
        "src/error.rs::Http",
        "src/error.rs::Spnego",
        "src/spnego.rs::Krb5MechToken",
        "src/spnego.rs::NegTokenInit",
        "src/spnego.rs::NegTokenResp",
        "src/spnego.rs::Token",
        "src/spnego.rs::NegotiationToken",
        "src/spnego.rs::MicToken",
        "src/spnego.rs::WrapToken",
        "src/spnego.rs::InitiatorContext",
        "src/spnego.rs::InitiatorContextOptions",
    ];

    /// Literal decoys and CRLF cannot hide public credential owners or Debug derives.
    #[test]
    fn inventory_rejects_uncovered_secret_shapes() -> Result<(), io::Error> {
        use super::{inventory::declarations, lex::tokens};
        for source in [
            "#[derive(Debug)] pub struct Secret { password: Vec<u8> }",
            "#[cfg_attr(feature = \"x\", derive(Debug))] pub struct Secret { key: [u8; 16] }",
            "pub enum Secret { Credentials { token: String } }",
            "pub struct Secret(Zeroizing<Vec<u8>>);",
            "use zeroize::Zeroizing as Erased; pub struct Secret { bytes: Erased<Vec<u8>> }",
            "type Payload = Vec<u8>; pub struct Secret { password: Payload }",
            "#[derive(Debug)] pub struct Secret { r#password: Vec<u8> }",
        ] {
            for spelling in [source.to_owned(), source.replace(' ', "\r\n")] {
                let owners = declarations("src/example.rs", &tokens(&spelling)?)?;
                assert_eq!(owners.len(), 1);
                assert!(
                    owners.iter().any(|owner| owner
                        .fields
                        .iter()
                        .any(|(name, _, ty)| secret_field(name, ty))),
                    "secret shape omitted"
                );
            }
        }
        let decoys = "/* pub struct Wrong { key: Vec<u8> } */ const TEXT: &str = r###\"pub struct Wrong { secret: String }\"###;";
        assert!(
            declarations("src/example.rs", &tokens(decoys)?)?.is_empty(),
            "literal declarations are inert"
        );
        assert!(
            matches!(tokens("/* unterminated"), Err(error) if error.kind() == io::ErrorKind::Other)
        );
        assert!(
            matches!(tokens("r##\"unterminated"), Err(error) if error.kind() == io::ErrorKind::Other)
        );
        assert!(matches!(declarations(
                "src/example.rs",
                &tokens("pub struct Truncated { key: Vec<u8>")?
             ), Err(error) if error.kind() == io::ErrorKind::Other));
        Ok(())
    }

    /// Opaque macros and aliases fail closed; resolvable scalar storage stays nonsecret.
    #[test]
    fn inventory_rejects_opaque_declarations() -> Result<(), io::Error> {
        use super::{inventory::declarations, lex::tokens};
        let mut missed = Vec::new();
        for (source, cause) in [
            (
                "macro_rules! credential_owner { ($vis:vis) => { #[derive(Debug)] $vis struct Leaked { password: Vec<u8> } }; } credential_owner!(pub);",
                "unsupported macro visibility declaration",
            ),
            (
                "macro_rules! credential_owner { ($vis:vis) => { #[derive(Debug)] $vis enum Leaked { Password(Vec<u8>) } }; } credential_owner!(pub);",
                "unsupported macro visibility declaration",
            ),
            (
                "macro_rules! credential_owner { ($($vis:vis,)?) => { #[derive(Debug)] $($vis)? struct Leaked { password: Vec<u8> } }; } credential_owner!(pub,);",
                "unsupported macro visibility declaration",
            ),
            (
                "macro_rules! credential_owner { ($($vis:vis,)*) => { #[derive(Debug)] $($vis)* enum Leaked { Password(Vec<u8>) } }; } credential_owner!(pub,);",
                "unsupported macro visibility declaration",
            ),
            (
                "macro_rules! credential_owner { ($($vis:vis,)?) => { $( $($vis)? struct Leaked { password: Vec<u8> } )? }; } credential_owner!(pub,);",
                "unsupported macro visibility declaration",
            ),
            (
                "type Payload<T = u8> = Vec<T>; #[derive(Debug)] pub struct Leaked { password: Payload }",
                "unresolved generic alias Payload",
            ),
            (
                "type Payload<T> = Vec<T>; #[derive(Debug)] pub struct Leaked { password: Payload<u8> }",
                "unresolved generic alias Payload",
            ),
            (
                "type Payload<T = u8> = Vec<T>; type Storage = Payload; #[derive(Debug)] pub struct Leaked { password: Storage }",
                "unresolved generic alias Payload",
            ),
            (
                "type Scalar<T = u32> = T; #[derive(Debug)] pub struct Counter { password: Scalar }",
                "unresolved generic alias Scalar",
            ),
            (
                "type Payload<T = u8> = Vec<T>; use self::Payload as Storage; pub struct Leaked { password: Storage }",
                "unresolved generic alias Payload",
            ),
            (
                "mod unrelated { type Payload = u32; } type Payload = Vec<u8>; #[derive(Debug)] pub struct Leaked { password: Payload }",
                "ambiguous alias Payload",
            ),
            (
                "type Payload = Vec<u8>; mod unrelated { type Payload = u32; } #[derive(Debug)] pub struct Leaked { password: Payload }",
                "ambiguous alias Payload",
            ),
            (
                "type Payload = u32; mod nested { type Payload = Vec<u8>; #[derive(Debug)] pub struct Leaked { password: Payload } }",
                "ambiguous alias Payload",
            ),
            (
                "mod unrelated { use core::primitive::u32 as Payload; } type Payload = Vec<u8>; #[derive(Debug)] pub struct Leaked { password: Payload }",
                "ambiguous alias Payload",
            ),
        ] {
            for spelling in [source.to_owned(), source.replace(' ', "\r\n")] {
                if !matches!(declarations("src/example.rs", &tokens(&spelling)?), Err(error) if error.to_string().contains(cause))
                {
                    missed.push(format!("missing {cause}: {source}"));
                }
            }
        }
        for source in [
            "mod unrelated { type Payload = Vec<u8>; } #[derive(Debug)] pub struct Scalar { password: u32 }",
            "type Payload = u32; #[derive(Debug)] pub struct Scalar { password: Payload }",
            "type Payload<T = u8> = Vec<T>; #[derive(Debug)] pub struct Scalar { password: u32 }",
            "use core::result::Result as Outcome; type Result<T> = Outcome<T, u32>; pub struct Scalar { value: Outcome<u32, u32> }",
            "type Payload = u32; trait HasPayload { type Payload; } impl HasPayload for Scalar { type Payload = Vec<u8>; } #[derive(Debug)] pub struct Scalar { password: Payload }",
            "/* $vis struct Leaked { password: Vec<u8> } type Payload = Vec<u8>; */ type Payload = u32; pub struct Scalar { password: Payload }",
            "const TEXT: &str = r###\"$vis struct Leaked { password: Vec<u8> } type Payload = Vec<u8>;\"###; type Payload = u32; pub struct Scalar { password: Payload }",
        ] {
            let owners = declarations("src/example.rs", &tokens(source)?)?;
            assert_eq!(owners.len(), 1);
            assert!(
                secret_owners(&owners).is_empty(),
                "scalar owner is not secret"
            );
        }
        for source in [
            "macro_rules! plain { ($($value:expr),*) => { ($($value),*) }; } plain!(1, 2);",
            "/* macro_rules! hidden { () => { $($vis)? struct Leaked {} }; } */",
            "const TEXT: &str = r###\"macro_rules! hidden { () => { $($vis)? enum Leaked {} }; }\"###;",
        ] {
            assert!(
                declarations("src/example.rs", &tokens(source)?)?.is_empty(),
                "plain macros and literal declarations are inert"
            );
        }
        assert!(missed.is_empty(), "{}", missed.join("\n"));
        Ok(())
    }

    /// Marker encoding matches independently known base64 vectors for every tail length.
    #[test]
    fn marker_base64_matches_known_vectors() {
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"ABCDEFGHIJKLMNOP"), "QUJDREVGR0hJSktMTU5PUA==");
    }

    /// Direct assignment, builder replacement and mutable escape all require audit coverage.
    #[test]
    fn replacement_inventory_detects_mutation_forms() -> Result<(), io::Error> {
        use super::{
            lex::tokens,
            replacement::{methods, replaced_fields},
        };
        for operation in [
            "self.secret = value;",
            "self.secret.replace(value);",
            "self.secret.clear();",
            "core::mem::replace(&mut self.secret, value);",
            "&mut self.secret",
        ] {
            let source = format!(
                "impl Owner {{ pub fn with_secret(mut self, value: Vec<u8>) -> Self {{ {operation} self }} }}"
            );
            let found = methods("src/owner.rs", &tokens(&source)?)?;
            assert_eq!(found.len(), 1);
            assert_eq!(
                replaced_fields(found.first().ok_or_else(|| io::Error::other("method"))?),
                ["secret"]
            );
        }
        let found = methods(
            "src/owner.rs",
            &tokens("impl Owner { pub fn equals(&self) -> bool { self.secret == other } }")?,
        )?;
        assert!(
            replaced_fields(found.first().ok_or_else(|| io::Error::other("method"))?).is_empty(),
            "comparison is not replacement"
        );
        Ok(())
    }
    use core::{
        any::type_name,
        ascii::escape_default,
        fmt::{self, Debug, Write as _},
    };

    use rskrb5_ng::{ccache, keytab};

    /// Reject raw, escaped, decimal, hexadecimal and base64 disclosures in both
    /// formats; an empty rendering hides the disclosure check and the diagnostic.
    pub(super) fn redacted<T>(owner: &T, secrets: &[&[u8]])
    where
        T: Debug,
    {
        assert!(
            !secrets.is_empty(),
            "credential audit must populate a real field"
        );
        EXERCISED.with_borrow_mut(|owners| {
            let _: bool = owners.insert(type_name::<T>().to_owned());
        });
        for output in [format!("{owner:?}"), format!("{owner:#?}")] {
            assert!(
                !output.is_empty(),
                "{} diagnostics remain useful",
                type_name::<T>()
            );
            let compact: String = output.chars().filter(|ch| !ch.is_whitespace()).collect();
            for secret in secrets {
                assert!(
                    secret.len() >= 16,
                    "audit requires real nonempty credential bytes"
                );
                let decimal = secret
                    .iter()
                    .map(u8::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                let escaped: String = secret
                    .iter()
                    .flat_map(|byte| escape_default(*byte).map(char::from))
                    .collect();
                for marker in [
                    String::from_utf8_lossy(secret).into_owned(),
                    hex::encode(secret),
                    hex::encode_upper(secret),
                    escaped,
                    base64(secret),
                ] {
                    assert!(
                        !output.contains(&marker),
                        "credential disclosed by {}",
                        type_name::<T>()
                    );
                }
                assert!(
                    !compact.contains(&decimal),
                    "decimal credential disclosed by {}",
                    type_name::<T>()
                );
            }
        }
    }

    /// Render diagnostic output through the formatter's fallible interface.
    pub(super) fn render<T>(owner: &T) -> Result<String, fmt::Error>
    where
        T: Debug,
    {
        let mut output = String::new();
        output.write_fmt(format_args!("{owner:?}"))?;
        Ok(output)
    }

    /// Distinct nonuniform sixteen-byte credentials expose substring leaks.
    pub(super) fn pattern(field: u8) -> Vec<u8> {
        (0_u8..16)
            .map(|offset| field.wrapping_add(offset))
            .collect()
    }

    /// Encode audit markers without requiring the optional SPNEGO dependency.
    fn base64(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut output = String::new();
        for chunk in bytes.chunks(3) {
            let first = chunk.first().copied().unwrap_or_default();
            let second = chunk.get(1).copied().unwrap_or_default();
            let third = chunk.get(2).copied().unwrap_or_default();
            for value in [
                first >> 2_u32,
                ((first & 3) << 4_u32) | (second >> 4_u32),
                ((second & 15) << 2_u32) | (third >> 6_u32),
                third & 63,
            ]
            .into_iter()
            .take(chunk.len().saturating_add(1))
            {
                if let Some(character) = ALPHABET.get(usize::from(value)) {
                    output.push(char::from(*character));
                }
            }
            for _ in chunk.len()..3 {
                output.push('=');
            }
        }
        output
    }

    /// Both file-key owners redact actual key bytes.
    #[test]
    fn file_keys_redact_credentials() -> Result<(), fmt::Error> {
        let key = pattern(65);
        redacted(&keytab::key_bytes::Bytes::from(key.clone()), &[&key]);
        redacted(&keytab::EncryptionKey::new(17, key.clone()), &[&key]);
        redacted(&ccache::EncryptionKey::new(17, key.clone()), &[&key]);
        assert!(
            !render(&keytab::EncryptionKey::new(17, key))?.is_empty(),
            "key diagnostics remain useful"
        );
        Ok(())
    }

    /// Credentials and nested file containers redact independent ticket and key fields.
    #[test]
    fn file_containers_redact_credentials() -> Result<(), io::Error> {
        let key = pattern(65);
        let ticket = pattern(81);
        let second = pattern(97);
        let auth = pattern(113);
        let client = ccache::Principal::new("EXAMPLE.COM", 1, vec!["alice".to_owned()]);
        let server = ccache::Principal::new(
            "EXAMPLE.COM",
            2,
            vec!["krbtgt".to_owned(), "EXAMPLE.COM".to_owned()],
        );
        let credential = ccache::Credential::new(
            client.clone(),
            server,
            ccache::EncryptionKey::new(17, key.clone()),
            ccache::CredentialTimes::default(),
            [0; 4],
            ticket.clone().into(),
        )
        .with_second_ticket(second.clone().into())
        .with_auth_data(vec![ccache::AuthorizationDataEntry::new(
            1,
            auth.clone().into(),
        )]);
        redacted(&credential, &[&key, &ticket, &second, &auth]);
        redacted(
            credential
                .auth_data()
                .first()
                .ok_or_else(|| io::Error::other("authorization data"))?,
            &[&auth],
        );
        let mut cache = ccache::CCache::new(client);
        cache.credentials_mut().push(credential);
        redacted(&cache, &[&key, &ticket, &second, &auth]);
        let mut tab = keytab::Keytab::new();
        tab.entries_mut().push(keytab::Entry::new(
            keytab::Principal::new("EXAMPLE.COM", 1, ["alice"]),
            1,
            1,
            keytab::EncryptionKey::new(17, key.clone()),
            1,
        ));
        redacted(&tab, &[&key]);
        redacted(
            tab.entries()
                .first()
                .ok_or_else(|| io::Error::other("keytab entry"))?,
            &[&key],
        );
        Ok(())
    }
}
