//! The mechanism, name, per-OID and status inquiries.
//!
//! `gss_indicate_mechs`, `gss_inquire_names_for_mech` and
//! `gss_inquire_mechs_for_name` (MIT `gssapi_krb5.c`), the SASL security
//! strength factor of `gss_inquire_sec_context_by_oid` and the RFC 2744 major
//! status of every error.

use rskrb5_ng::{
    error::Gss,
    gss::{self, AcceptorOptions, Credential, InitiatorOptions, Name, NameType},
    spnego::oid::ObjectIdentifier,
};

use super::{
    context::TestError,
    support::{HOST, cache, cached, establish, ticket_for},
};

/// The mechanism and its name types are reported as MIT reports them.
#[test]
fn mechanisms_and_name_types_are_reported() -> Result<(), TestError> {
    // Given the mechanism list, it is krb5 and IAKERB.
    assert_eq!(
        gss::indicate_mechs(),
        vec![ObjectIdentifier::krb5(), gss::iakerb::Context::mechanism()]
    );
    // Given krb5, its name types include every MIT krb5 name type.
    let types = gss::inquire_names_for_mech(&ObjectIdentifier::krb5());
    for kind in [
        NameType::HostbasedService,
        NameType::User,
        NameType::MachineUid,
        NameType::StringUid,
        NameType::Anonymous,
        NameType::Export,
        NameType::CompositeExport,
        NameType::Principal,
        NameType::Enterprise,
        NameType::X509Cert,
    ] {
        assert!(types.contains(&kind), "{kind:?}");
    }
    // Given another mechanism, there are none.
    assert_eq!(
        gss::inquire_names_for_mech(&ObjectIdentifier::spnego()),
        Vec::new()
    );
    // A principal name is a name of every mechanism `indicate_mechs` offers, in its order.
    let name = Name::import(b"alice@EXAMPLE.COM", NameType::Principal)?;
    assert_eq!(name.inquire_mechs(), gss::indicate_mechs());
    assert_eq!(
        name.inquire_mechs(),
        vec![ObjectIdentifier::krb5(), gss::iakerb::Context::mechanism()]
    );
    Ok(())
}

/// IAKERB answers the krb5 name types.
///
/// MIT's `krb5_gss_inquire_names_for_mech` does the same (`inq_names.c:38-45`).
#[test]
fn iakerb_answers_the_name_types_of_krb5() {
    // Given krb5 and IAKERB, both give the same set of name types, and it is not empty.
    assert_eq!(
        gss::inquire_names_for_mech(&gss::iakerb::Context::mechanism()),
        gss::inquire_names_for_mech(&ObjectIdentifier::krb5())
    );
    assert!(
        !gss::inquire_names_for_mech(&gss::iakerb::Context::mechanism()).is_empty(),
        "IAKERB imports name types"
    );
    // Given a mechanism `indicate_mechs` does not offer, there are still none.
    assert_eq!(
        gss::inquire_names_for_mech(&ObjectIdentifier::spnego()),
        Vec::new()
    );
}

/// A certificate name lists no mechanism.
///
/// Only `S4U2Self` takes it; MIT's mechglue (`g_inq_names.c:107-164`) lists none for a name
/// type the mechanisms do not take.
#[test]
fn a_certificate_name_lists_no_mechanism() -> Result<(), TestError> {
    let certificate = Name::import(&[0x30, 0x03, 0x02, 0x01, 0x05], NameType::X509Cert)?;
    assert_eq!(certificate.inquire_mechs(), Vec::new());
    Ok(())
}

/// The security strength factor is the context key's strength in bits.
#[test]
fn the_security_strength_factor_is_the_key_strength() -> Result<(), TestError> {
    let credential = Credential::from_ccache(cache(vec![cached(&ticket_for(HOST, &[])?)?]))?;
    let pair = establish(
        &credential,
        InitiatorOptions::new(),
        (AcceptorOptions::new(), &[HOST], None),
    )?;
    // Given an AES256 context, both ends report 256 bits.
    assert_eq!(pair.initiator.inquire().ssf(), 256);
    assert_eq!(pair.acceptor.inquire().ssf(), 256);
    Ok(())
}

/// Errors with the RFC 2744 major status each one names.
const MAJOR_STATUSES: [(Gss, u32); 14] = [
    (Gss::BadName("x"), 2_u32 << 16_u32),
    (Gss::BadBindings, 4_u32 << 16_u32),
    (Gss::MissingBindings, 4_u32 << 16_u32),
    (Gss::NoCredential("x"), 7_u32 << 16_u32),
    (Gss::UnexpectedStep("x"), 8_u32 << 16_u32),
    (Gss::DefectiveToken("x"), 9_u32 << 16_u32),
    (Gss::DefectiveChecksum("x"), 10_u32 << 16_u32),
    (Gss::ContextExpired, 12_u32 << 16_u32),
    (Gss::LegacyTokenFormat(16_i32), 16_u32 << 16_u32),
    (Gss::DuplicateElement, 17_u32 << 16_u32),
    (Gss::DuplicateToken(1_u64), 1_u32 << 1_u32),
    (Gss::OldToken(1_u64), 1_u32 << 2_u32),
    (Gss::UnsequencedToken(1_u64), 1_u32 << 3_u32),
    (Gss::GapToken(1_u64), 1_u32 << 4_u32),
];

/// Every error names its RFC 2744 major status.
#[test]
fn errors_map_to_rfc_2744_major_statuses() {
    assert_eq!(
        MAJOR_STATUSES.map(|(error, _)| error.major_status()),
        MAJOR_STATUSES.map(|(_, status)| status),
    );
}
