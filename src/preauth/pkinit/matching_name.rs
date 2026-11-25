//! The text of a certificate name as MIT 1.22.2 matches it.
//!
//! MIT prints it with OpenSSL's `X509_NAME_print_ex(name, 0, XN_FLAG_SEP_COMMA_PLUS)`
//! (`pkinit_crypto_openssl.c:4769-4784`).
//!
//! The RDNs appear in encoded order, joined by `,`; the attributes of one RDN
//! are joined by `+`; each attribute is `short-name=value` (the OpenSSL short
//! name, or the dotted OID when it has none). Nothing is escaped. A value is
//! its code points: below U+0100 the single character (OpenSSL writes the raw
//! byte; here it is the Latin-1 character, so a pattern sees one character per
//! byte as in the C locale), U+0100 to U+FFFF as `\UXXXX` and above as
//! `\WXXXXXXXX`. A value that is not a string type is `#` and the hex of its
//! DER, which OpenSSL's dump flags also print.

use core::fmt::Write as _;

use der::{Encode as _, Tag, Tagged as _, asn1::Any, oid::ObjectIdentifier};
use x509_cert::{attr::AttributeTypeAndValue, name::Name};

use crate::error::Pkinit as Error;

/// OpenSSL's short names of the attribute types it knows (`objects.txt`).
const SHORT_NAMES: [(&str, &str); 30] = [
    ("2.5.4.3", "CN"),
    ("2.5.4.4", "SN"),
    ("2.5.4.5", "serialNumber"),
    ("2.5.4.6", "C"),
    ("2.5.4.7", "L"),
    ("2.5.4.8", "ST"),
    ("2.5.4.9", "street"),
    ("2.5.4.10", "O"),
    ("2.5.4.11", "OU"),
    ("2.5.4.12", "title"),
    ("2.5.4.13", "description"),
    ("2.5.4.15", "businessCategory"),
    ("2.5.4.17", "postalCode"),
    ("2.5.4.20", "telephoneNumber"),
    ("2.5.4.41", "name"),
    ("2.5.4.42", "GN"),
    ("2.5.4.43", "initials"),
    ("2.5.4.44", "generationQualifier"),
    ("2.5.4.45", "x500UniqueIdentifier"),
    ("2.5.4.46", "dnQualifier"),
    ("2.5.4.65", "pseudonym"),
    ("1.2.840.113549.1.9.1", "emailAddress"),
    ("1.2.840.113549.1.9.2", "unstructuredName"),
    ("1.2.840.113549.1.9.8", "unstructuredAddress"),
    ("0.9.2342.19200300.100.1.1", "UID"),
    ("0.9.2342.19200300.100.1.25", "DC"),
    ("1.3.6.1.4.1.311.60.2.1.1", "jurisdictionL"),
    ("1.3.6.1.4.1.311.60.2.1.2", "jurisdictionST"),
    ("1.3.6.1.4.1.311.60.2.1.3", "jurisdictionC"),
    ("2.5.4.97", "organizationIdentifier"),
];

/// The malformed-name error.
const fn unprintable() -> Error {
    Error::Malformed {
        structure: "certificate name",
        reason: "a name value OpenSSL cannot print",
    }
}

/// Append the rendering of code point `code` to `out`.
///
/// # Errors
/// Returns [`Error::Malformed`] when formatting fails.
fn push_code_point(out: &mut String, code: u32) -> Result<(), Error> {
    match (u8::try_from(code), u16::try_from(code)) {
        (Ok(byte), _) => out.push(char::from(byte)),
        (Err(_byte), Ok(unit)) => write!(out, "\\U{unit:04X}").map_err(|_detail| unprintable())?,
        (Err(_byte), Err(_unit)) => {
            write!(out, "\\W{code:08X}").map_err(|_detail| unprintable())?
        }
    }
    Ok(())
}

/// The code points of a string-typed attribute value, or `None` for another type.
///
/// # Errors
/// Returns [`Error::Malformed`] for invalid UTF-8 or an odd-length `BMPString`.
fn code_points(value: &Any) -> Result<Option<Vec<u32>>, Error> {
    let content = value.value();
    let tag = value.tag();
    if tag == Tag::Utf8String {
        let text = str::from_utf8(content).map_err(|_detail| unprintable())?;
        Ok(Some(text.chars().map(u32::from).collect()))
    } else if matches!(
        tag,
        Tag::PrintableString
            | Tag::Ia5String
            | Tag::TeletexString
            | Tag::VisibleString
            | Tag::NumericString
    ) {
        Ok(Some(content.iter().map(|byte| u32::from(*byte)).collect()))
    } else if tag == Tag::BmpString {
        let (units, rest) = content.as_chunks::<2>();
        if !rest.is_empty() {
            return Err(unprintable());
        }
        Ok(Some(
            units
                .iter()
                .map(|unit| u32::from(u16::from_be_bytes(*unit)))
                .collect(),
        ))
    } else {
        Ok(None)
    }
}

/// Append the rendering of the attribute value `value`.
///
/// # Errors
/// Returns [`Error::Malformed`] for a value OpenSSL cannot print.
fn push_value(out: &mut String, value: &Any) -> Result<(), Error> {
    if let Some(points) = code_points(value)? {
        for code in points {
            push_code_point(out, code)?;
        }
    } else {
        out.push('#');
        for byte in value.to_der().map_err(|_detail| unprintable())? {
            write!(out, "{byte:02X}").map_err(|_detail| unprintable())?;
        }
    }
    Ok(())
}

/// Append `short-name=value` for one attribute.
///
/// # Errors
/// Returns [`Error::Malformed`] for a value OpenSSL cannot print.
fn push_attribute(out: &mut String, attribute: &AttributeTypeAndValue) -> Result<(), Error> {
    let dotted = ObjectIdentifier::to_string(&attribute.oid);
    let name = SHORT_NAMES
        .iter()
        .find(|(oid, _)| *oid == dotted)
        .map_or(dotted.as_str(), |(_, short)| *short);
    out.push_str(name);
    out.push('=');
    push_value(out, &attribute.value)
}

/// The `XN_FLAG_SEP_COMMA_PLUS` rendering of `name`.
///
/// # Errors
/// Returns [`Error::Malformed`] for a value OpenSSL cannot print (invalid
/// UTF-8, an odd-length BMPString): MIT fails the whole selection then.
pub(super) fn render(name: &Name) -> Result<String, Error> {
    let mut out = String::new();
    for (index, relative) in name.iter_rdn().enumerate() {
        if index > 0 {
            out.push(',');
        }
        for (position, attribute) in relative.iter().enumerate() {
            if position > 0 {
                out.push('+');
            }
            push_attribute(&mut out, attribute)?;
        }
    }
    Ok(out)
}
