//! Name import, display, export, comparison and canonicalization for every name
//! type MIT krb5 1.22.2 imports (`import_name.c:126-345`, `disp_name.c:28-78`,
//! `export_name.c:28-88`, `compare_name.c`, `canon_name.c`).
//!
//! The principal-name vectors follow MIT's `krb5_parse_name` (`parse.c:30-250`)
//! and `krb5_unparse_name` (`unparse.c:60-135`); the exported-name vector is the
//! RFC 2743 section 3.2 layout MIT writes, assembled byte by byte here.

use rskrb5_ng::{
    error::Gss,
    gss::{Name, NameType},
};

use super::context::{Context as _, TestError};

/// Import `text` as a Kerberos principal name.
fn principal(text: &str) -> Result<Name, Gss> {
    Name::import(text.as_bytes(), NameType::Principal)
}

/// Escapes, components and realms parse as MIT parses them and display back
/// in MIT's quoting.
#[test]
fn principal_names_parse_and_display_like_mit() -> Result<(), TestError> {
    for (input, components, realm, shown) in [
        (
            "alice@EXAMPLE.COM",
            &["alice"][..],
            "EXAMPLE.COM",
            "alice@EXAMPLE.COM",
        ),
        ("host/a\\/b@R", &["host", "a/b"][..], "R", "host/a\\/b@R"),
        ("a\\@b@R", &["a@b"][..], "R", "a\\@b@R"),
        ("x\\ty@R", &["x\ty"][..], "R", "x\\ty@R"),
        ("p/q/r@S.T", &["p", "q", "r"][..], "S.T", "p/q/r@S.T"),
    ] {
        // Given a principal string, when it is imported,
        let name = principal(input).context(input)?;
        // then its components and realm are MIT's, and it displays MIT's quoting.
        assert_eq!(name.principal().components, components, "{input}");
        assert_eq!(name.principal().realm, realm, "{input}");
        assert_eq!(
            name.display(),
            (shown.to_owned(), NameType::Principal),
            "{input}"
        );
    }
    Ok(())
}

/// Malformed principal strings are refused as bad names.
#[test]
fn malformed_principal_names_are_refused() {
    for input in ["abc\\", "a@b@c", "a@R/x", ""] {
        // Given a string MIT's parser refuses, when it is imported, then it is a bad name.
        assert!(
            matches!(principal(input), Err(Gss::BadName(_))),
            "{input} is refused"
        );
    }
}

/// A host-based service name keeps its service and lowercase host, and a name
/// without a host names any host of the service.
#[test]
fn hostbased_names_keep_service_and_host() -> Result<(), TestError> {
    // Given a host-based name with a mixed-case host, when it is imported,
    let name = Name::import(b"HTTP@WWW.Example.COM", NameType::HostbasedService)?;
    // then the host is lowercase and the realm is left for the client to find.
    assert_eq!(name.principal().components, ["HTTP", "www.example.com"]);
    assert_eq!(name.principal().realm, "");
    assert_eq!(name.name_type(), NameType::HostbasedService);
    // Given only the service, the host is empty (any host of the service).
    let any = Name::import(b"HTTP", NameType::HostbasedService)?;
    assert_eq!(any.principal().components, ["HTTP", ""]);
    Ok(())
}

/// An enterprise name keeps its first `@` in the one component.
#[test]
fn enterprise_names_keep_the_first_at_sign() -> Result<(), TestError> {
    // Given an enterprise name with a realm, when it is imported,
    let name = Name::import(b"alice@corp.example@EXAMPLE.COM", NameType::Enterprise)?;
    // then the UPN is one component and it displays with the first `@` quoted.
    assert_eq!(name.principal().components, ["alice@corp.example"]);
    assert_eq!(name.principal().realm, "EXAMPLE.COM");
    assert_eq!(name.principal().name_type, 10);
    assert_eq!(name.display().0, "alice\\@corp.example@EXAMPLE.COM");
    Ok(())
}

/// A name without a realm takes the default realm the caller supplies.
#[test]
fn names_without_a_realm_take_the_supplied_default() -> Result<(), TestError> {
    // Given a user name without a realm, when the default realm is supplied,
    let name = Name::import(b"alice", NameType::User)?.with_default_realm("EXAMPLE.COM");
    // then it names the user in that realm, and an explicit realm is kept.
    assert_eq!(name.display().0, "alice@EXAMPLE.COM");
    let explicit = principal("bob@OTHER.COM")?.with_default_realm("EXAMPLE.COM");
    assert_eq!(explicit.principal().realm, "OTHER.COM");
    Ok(())
}

/// The anonymous name is MIT's well-known principal and displays as anonymous.
#[test]
fn anonymous_names_are_the_well_known_principal() -> Result<(), TestError> {
    // Given the anonymous name type, when a name is imported,
    let name = Name::import(b"", NameType::Anonymous)?;
    // then it is WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS and displays as anonymous.
    assert!(name.is_anonymous());
    assert_eq!(
        name.display(),
        (
            "WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS".to_owned(),
            NameType::Anonymous
        )
    );
    Ok(())
}

/// The exported name has MIT's RFC 2743 layout and imports back equal.
#[test]
fn exported_names_have_the_rfc_2743_layout() -> Result<(), TestError> {
    // Given a principal name, when it is exported,
    let name = principal("alice@EXAMPLE.COM")?;
    let exported = name.export()?;
    // then the token is 04 01, the OID length, the krb5 OID, the name length, the name.
    let mut expected = vec![0x04, 0x01, 0x00, 0x0b, 0x06, 0x09];
    expected.extend_from_slice(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02]);
    expected.extend_from_slice(&17_u32.to_be_bytes());
    expected.extend_from_slice(b"alice@EXAMPLE.COM");
    assert_eq!(exported, expected);
    // And it imports back to an equal name.
    let back = Name::import(&exported, NameType::Export)?;
    assert!(back.compare(&name), "the exported name round-trips");
    Ok(())
}

/// Malformed, foreign and oversized exported names are refused.
#[test]
fn malformed_exported_names_are_refused() -> Result<(), TestError> {
    let good = principal("alice@EXAMPLE.COM")?.export()?;
    let mut foreign = good.clone();
    *foreign.get_mut(14).context("an OID byte")? ^= 0x01;
    let mut trailing = good.clone();
    trailing.push(0);
    let mut short = good.clone();
    short.truncate(good.len().saturating_sub(1));
    for (what, token) in [
        ("another mechanism", foreign),
        ("a trailing byte", trailing),
        ("a truncated name", short),
        ("a bad tag", vec![0x05, 0x01]),
        ("no OID", vec![0x04, 0x01, 0x00]),
    ] {
        // Given a defective exported name, when it is imported, then it is a bad name.
        assert!(
            matches!(Name::import(&token, NameType::Export), Err(Gss::BadName(_))),
            "{what}"
        );
    }
    let mut oversized = vec![0x04, 0x01, 0x00, 0x0b, 0x06, 0x09];
    oversized.extend_from_slice(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02]);
    oversized.extend_from_slice(&0x0001_0000_u32.to_be_bytes());
    oversized.resize(oversized.len().saturating_add(0x0001_0000), b'a');
    assert!(
        matches!(
            Name::import(&oversized, NameType::Export),
            Err(Gss::NameTooLong { .. })
        ),
        "a 64 KiB name is refused by its length"
    );
    Ok(())
}

/// A composite exported name (RFC 6680) imports as the same principal; its
/// attributes are kept unread.
#[test]
fn composite_exported_names_import_the_principal() -> Result<(), TestError> {
    // Given a composite token: 04 02, the krb5 OID, the name, then an attribute blob,
    let plain = principal("alice@EXAMPLE.COM")?.export()?;
    let mut composite = plain.clone();
    *composite.get_mut(1).context("the token type")? = 0x02;
    composite.extend_from_slice(&3_u32.to_be_bytes());
    composite.extend_from_slice(&[1, 2, 3]);
    // when it is imported, then it names the same principal.
    let name = Name::import(&composite, NameType::CompositeExport)?;
    assert!(name.compare(&principal("alice@EXAMPLE.COM")?));
    Ok(())
}

/// Comparison is realm and components; the imported type does not matter.
#[test]
fn comparison_is_realm_and_components() -> Result<(), TestError> {
    let user = Name::import(b"alice@EXAMPLE.COM", NameType::User)?;
    // Given the same principal imported as a user and as a principal name, they are equal.
    assert!(user.compare(&principal("alice@EXAMPLE.COM")?));
    // Another realm or component is another name.
    assert!(!user.compare(&principal("alice@OTHER.COM")?));
    assert!(!user.compare(&principal("alice/admin@EXAMPLE.COM")?));
    // Canonicalization keeps the name (MIT duplicates it).
    assert!(user.canonicalize().compare(&user));
    Ok(())
}

/// Numeric user ids resolve through the caller's resolver, never an ambient
/// password database.
#[test]
fn uid_names_resolve_through_the_caller() -> Result<(), TestError> {
    let resolver = |uid: u32| (uid == 1000).then(|| "alice@EXAMPLE.COM".to_owned());
    // Given a string uid, when the resolver knows it, then it names that account.
    let named = Name::import_uid(b"1000", NameType::StringUid, resolver)?;
    assert_eq!(named.display().0, "alice@EXAMPLE.COM");
    // Given a binary uid of the host's byte order, it resolves the same way.
    let bytes = if cfg!(target_endian = "big") {
        1000_u32.to_be_bytes()
    } else {
        1000_u32.to_le_bytes()
    };
    let machine = Name::import_uid(&bytes, NameType::MachineUid, resolver)?;
    assert!(machine.compare(&named));
    // An unknown uid, a non-numeric string and a short binary uid are refused.
    assert!(matches!(
        Name::import_uid(b"1001", NameType::StringUid, resolver),
        Err(Gss::UnresolvedUid(1001))
    ));
    assert!(matches!(
        Name::import_uid(b"x1", NameType::StringUid, resolver),
        Err(Gss::BadName(_))
    ));
    assert!(matches!(
        Name::import_uid(&[1, 2], NameType::MachineUid, resolver),
        Err(Gss::BadName(_))
    ));
    // Without a resolver, the uid types are not importable.
    assert!(matches!(
        Name::import(b"1000", NameType::StringUid),
        Err(Gss::BadNameType(_))
    ));
    Ok(())
}

/// A certificate name keeps the certificate bytes for S4U2Self by certificate.
#[test]
fn certificate_names_keep_the_certificate() -> Result<(), TestError> {
    // Given DER certificate bytes, when imported as an X.509 name, they are kept.
    let name = Name::import(&[0x30, 0x03, 0x02, 0x01, 0x05], NameType::X509Cert)?;
    assert_eq!(
        name.certificate(),
        Some(&[0x30, 0x03, 0x02, 0x01, 0x05][..])
    );
    assert_eq!(name.name_type(), NameType::X509Cert);
    Ok(())
}

/// Every name type maps to MIT's OID and back; the RFC 2743 host-based OID
/// is the same type as the GSS-API v1 one.
#[test]
fn name_types_map_to_mit_oids() -> Result<(), TestError> {
    for (kind, arcs) in [
        (NameType::User, &[1_u32, 2, 840, 113_554, 1, 2, 1, 1][..]),
        (NameType::MachineUid, &[1, 2, 840, 113_554, 1, 2, 1, 2][..]),
        (NameType::StringUid, &[1, 2, 840, 113_554, 1, 2, 1, 3][..]),
        (
            NameType::HostbasedService,
            &[1, 2, 840, 113_554, 1, 2, 1, 4][..],
        ),
        (NameType::Anonymous, &[1, 3, 6, 1, 5, 6, 3][..]),
        (NameType::Export, &[1, 3, 6, 1, 5, 6, 4][..]),
        (NameType::CompositeExport, &[1, 3, 6, 1, 5, 6, 6][..]),
        (NameType::Principal, &[1, 2, 840, 113_554, 1, 2, 2, 1][..]),
        (NameType::Enterprise, &[1, 2, 840, 113_554, 1, 2, 2, 6][..]),
        (NameType::X509Cert, &[1, 2, 840, 113_554, 1, 2, 2, 7][..]),
    ] {
        // Given a name type, its OID is MIT's and maps back to the type.
        assert_eq!(kind.oid().arcs(), arcs, "{kind:?}");
        assert_eq!(NameType::from_oid(&kind.oid()), Some(kind), "{kind:?}");
    }
    let v2 = rskrb5_ng::spnego::oid::ObjectIdentifier::from_arcs(vec![1, 3, 6, 1, 5, 6, 2])?;
    assert_eq!(NameType::from_oid(&v2), Some(NameType::HostbasedService));
    Ok(())
}
