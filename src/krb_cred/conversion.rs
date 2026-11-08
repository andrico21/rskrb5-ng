//! Conversion of credential fields between ccache and ASN.1.

use alloc::str;

use super::{Error, ccache, encode_ticket, ticket_error};

/// Build the `KrbCredInfo` entry that describes one ccache credential.
///
/// # Errors
///
/// Returns [`Error::InvalidKerberosString`] for a realm or name component that
/// is not a Kerberos string, and [`Error::TimeOutOfRange`] for a time that is
/// not a valid Kerberos time.
pub(super) fn ccache_credential_to_krb_cred_info(
    credential: &ccache::Credential,
) -> Result<rasn_kerberos::KrbCredInfo, Error> {
    Ok(rasn_kerberos::KrbCredInfo {
        key: rasn_kerberos::EncryptionKey {
            r#type: credential.key.etype,
            value: credential.key.value.to_vec().into(),
        },
        prealm: Some(kerberos_string(&credential.client.realm)?),
        pname: Some(principal_name_from_ccache(&credential.client)?),
        flags: Some(rasn_kerberos::TicketFlags(
            rasn_kerberos::KerberosFlags::from_slice(&credential.ticket_flags),
        )),
        auth_time: Some(kerberos_time_from_u32(credential.times.auth_time)?),
        start_time: Some(kerberos_time_from_u32(credential.times.start_time)?),
        end_time: Some(kerberos_time_from_u32(credential.times.end_time)?),
        renew_till: Some(kerberos_time_from_u32(credential.times.renew_till)?),
        srealm: Some(kerberos_string(&credential.server.realm)?),
        sname: Some(principal_name_from_ccache(&credential.server)?),
        caddr: (!credential.addresses.is_empty()).then(|| {
            credential
                .addresses
                .iter()
                .map(host_address_from_ccache)
                .collect()
        }),
    })
}

/// Build a ccache credential from a KRB-CRED ticket and its `KrbCredInfo`.
///
/// A missing server principal falls back to the ticket's realm and name, and a
/// missing start time falls back to the authentication time.
///
/// # Errors
///
/// Returns [`Error::MissingKrbCredInfoField`] when the client principal is
/// missing or the server principal is half present, [`Error::InvalidString`]
/// for a name that is not UTF-8, [`Error::TimeOutOfRange`] for a time that does
/// not fit a ccache timestamp, and [`Error::Encode`] when the ticket cannot be
/// re-encoded.
pub(super) fn krb_cred_info_to_ccache_credential(
    ticket: &rasn_kerberos::Ticket,
    info: &rasn_kerberos::KrbCredInfo,
) -> Result<ccache::Credential, Error> {
    let client = required_principal(
        "KrbCredInfo.pname",
        info.prealm.as_ref(),
        info.pname.as_ref(),
    )?;
    let server = match optional_principal(info.srealm.as_ref(), info.sname.as_ref())? {
        Some(server) => server,
        None => principal_from_parts(&ticket.realm, &ticket.sname)?,
    };
    Ok(ccache::Credential {
        client,
        server,
        key: ccache::EncryptionKey {
            etype: info.key.r#type,
            value: info.key.value.as_ref().to_vec().into(),
        },
        times: ccache::CredentialTimes {
            auth_time: optional_kerberos_time_to_u32(info.auth_time.as_ref())?,
            start_time: optional_kerberos_time_to_u32(
                info.start_time.as_ref().or(info.auth_time.as_ref()),
            )?,
            end_time: optional_kerberos_time_to_u32(info.end_time.as_ref())?,
            renew_till: optional_kerberos_time_to_u32(info.renew_till.as_ref())?,
        },
        is_skey: false,
        ticket_flags: info
            .flags
            .as_ref()
            .map(ticket_flags_to_bytes)
            .unwrap_or_default(),
        addresses: info
            .caddr
            .as_ref()
            .map(|addresses| {
                addresses
                    .iter()
                    .map(|address| ccache::HostAddress {
                        addr_type: address.addr_type,
                        address: address.address.as_ref().to_vec(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        auth_data: Vec::new(),
        ticket: encode_ticket(ticket).map_err(ticket_error)?.into(),
        second_ticket: Vec::new().into(),
    })
}

/// Convert a ccache principal to a Kerberos principal name.
///
/// # Errors
///
/// Returns [`Error::InvalidKerberosString`] for a name component that is not a
/// Kerberos string.
fn principal_name_from_ccache(
    principal: &ccache::Principal,
) -> Result<rasn_kerberos::PrincipalName, Error> {
    Ok(rasn_kerberos::PrincipalName {
        r#type: principal.name_type,
        string: principal
            .components
            .iter()
            .map(|component| kerberos_string(component))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

/// Convert a ccache host address to a Kerberos host address.
fn host_address_from_ccache(address: &ccache::HostAddress) -> rasn_kerberos::HostAddress {
    rasn_kerberos::HostAddress {
        addr_type: address.addr_type,
        address: address.address.clone().into(),
    }
}

/// Build the principal named by a required realm and name pair.
///
/// # Errors
///
/// Returns [`Error::MissingKrbCredInfoField`] naming `field` when either half is
/// missing, and [`Error::InvalidString`] for a name that is not UTF-8.
fn required_principal(
    field: &'static str,
    realm: Option<&rasn_kerberos::Realm>,
    name: Option<&rasn_kerberos::PrincipalName>,
) -> Result<ccache::Principal, Error> {
    match (realm, name) {
        (Some(realm_value), Some(name_value)) => principal_from_parts(realm_value, name_value),
        _ => Err(Error::MissingKrbCredInfoField(field)),
    }
}

/// Build the principal named by an optional realm and name pair.
///
/// # Errors
///
/// Returns [`Error::MissingKrbCredInfoField`] when only one half is present,
/// and [`Error::InvalidString`] for a name that is not UTF-8.
fn optional_principal(
    realm: Option<&rasn_kerberos::Realm>,
    name: Option<&rasn_kerberos::PrincipalName>,
) -> Result<Option<ccache::Principal>, Error> {
    match (realm, name) {
        (Some(realm_value), Some(name_value)) => {
            principal_from_parts(realm_value, name_value).map(Some)
        }
        (None, None) => Ok(None),
        _ => Err(Error::MissingKrbCredInfoField("KrbCredInfo.srealm/sname")),
    }
}

/// Build a ccache principal from a Kerberos realm and principal name.
///
/// # Errors
///
/// Returns [`Error::InvalidString`] when the realm or a name component is not
/// UTF-8.
fn principal_from_parts(
    realm: &rasn_kerberos::Realm,
    name: &rasn_kerberos::PrincipalName,
) -> Result<ccache::Principal, Error> {
    Ok(ccache::Principal::new(
        kerberos_string_to_string(realm)?,
        name.r#type,
        name.string
            .iter()
            .map(kerberos_string_to_string)
            .collect::<Result<Vec<_>, _>>()?,
    ))
}

/// Convert a string to a Kerberos string.
///
/// # Errors
///
/// Returns [`Error::InvalidKerberosString`] when the value is not a valid
/// Kerberos string.
fn kerberos_string(value: &str) -> Result<rasn_kerberos::KerberosString, Error> {
    rasn_kerberos::KerberosString::from_bytes(value.as_bytes())
        .map_err(|source| Error::InvalidKerberosString(source.to_string()))
}

/// Convert a Kerberos string to an owned UTF-8 string.
///
/// # Errors
///
/// Returns [`Error::InvalidString`] when the bytes are not UTF-8.
fn kerberos_string_to_string(value: &rasn_kerberos::KerberosString) -> Result<String, Error> {
    Ok(str::from_utf8(value.as_bytes())?.to_owned())
}

/// Convert a ccache timestamp to a UTC Kerberos time.
///
/// # Errors
///
/// Returns [`Error::TimeOutOfRange`] when the timestamp is not a valid time.
fn kerberos_time_from_u32(seconds: u32) -> Result<rasn_kerberos::KerberosTime, Error> {
    let utc = chrono::DateTime::<chrono::Utc>::from_timestamp(seconds.into(), 0)
        .ok_or(Error::TimeOutOfRange)?;
    let offset = chrono::FixedOffset::east_opt(0).ok_or(Error::TimeOutOfRange)?;
    Ok(rasn_kerberos::KerberosTime(utc.with_timezone(&offset)))
}

/// Convert an optional Kerberos time to a ccache timestamp; absent is zero.
///
/// # Errors
///
/// Returns [`Error::TimeOutOfRange`] when the time does not fit a ccache
/// timestamp.
fn optional_kerberos_time_to_u32(time: Option<&rasn_kerberos::KerberosTime>) -> Result<u32, Error> {
    time.map(kerberos_time_to_u32)
        .transpose()
        .map(Option::unwrap_or_default)
}

/// Convert a Kerberos time to a ccache timestamp.
///
/// # Errors
///
/// Returns [`Error::TimeOutOfRange`] when the time is before the Unix epoch or
/// after 2106, or contains a fractional second.
fn kerberos_time_to_u32(time: &rasn_kerberos::KerberosTime) -> Result<u32, Error> {
    (time.0.timestamp_subsec_nanos() == 0).ok_or(Error::TimeOutOfRange)?;
    u32::try_from(time.0.timestamp())
        .ok()
        .ok_or(Error::TimeOutOfRange)
}

/// Return the first four bytes of the ticket flags, zero-padded.
fn ticket_flags_to_bytes(flags: &rasn_kerberos::TicketFlags) -> [u8; 4] {
    let raw = flags.0.as_raw_slice();
    [
        raw.first().copied().unwrap_or_default(),
        raw.get(1).copied().unwrap_or_default(),
        raw.get(2).copied().unwrap_or_default(),
        raw.get(3).copied().unwrap_or_default(),
    ]
}
