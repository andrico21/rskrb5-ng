//! KRB-CRED through an [`AuthContext`] (MIT `mk_cred.c`, `rd_cred.c`).

use rasn::{der, types::Integer};
use zeroize::Zeroizing;

use super::{
    AuthContext, CredentialTransport, Received,
    clock::{kerberos_time, system_time},
    secret_der::SecretDer,
};
use crate::{
    ccache::Credential,
    crypto::{Use, selection},
    error::{AuthMessage as Error, KrbCred},
    krb_cred::{self, KRB_CRED_ENCPART_USAGE, import},
    replay::Tag,
};

/// MIT's `ENCTYPE_NULL`: the enc-part holds plain DER (RFC 6448).
const ENCTYPE_NULL: i32 = 0;

/// Refuse a credential of another identity than the one the context is bound to.
///
/// # Errors
///
/// Returns [`Error::CredentialOwner`] naming both identities.
fn check_owner(context: &AuthContext, credentials: &[Credential]) -> Result<(), Error> {
    let Some(owner) = &context.credential_owner else {
        return Ok(());
    };
    let expected = owner.principal_string();
    for credential in credentials {
        let found = credential.client().principal_string();
        if found != expected {
            return Err(Error::CredentialOwner { expected, found });
        }
    }
    Ok(())
}

/// MIT `krb5_mk_ncred`: forward `credentials`.
///
/// The timestamp is always set (`mk_cred.c:176`), the nonce is the sequence
/// number when sequencing, and the sender and recipient addresses are those of
/// the context when it has them.
///
/// # Errors
///
/// Returns [`Error::NoKey`] for an encrypted transport without a key, and the
/// codec and policy errors.
pub(super) fn make_cred(
    context: &mut AuthContext,
    credentials: &[Credential],
    transport: CredentialTransport<'_>,
) -> Result<Vec<u8>, Error> {
    check_owner(context, credentials)?;
    let (tickets, mut part) = krb_cred::ccache_credentials_to_krb_cred_parts(credentials)?;
    let (stamp, micros) = kerberos_time(context.now())?;
    part.timestamp = Some(stamp);
    part.usec = Some(micros);
    part.nonce = context
        .policy
        .check_sequence
        .then_some(context.local_sequence);
    context.local_address.clone_into(&mut part.sender_address);
    context
        .remote_address
        .clone_into(&mut part.recipient_address);
    let plaintext = SecretDer::new(
        der::encode(&part).map_err(|source| KrbCred::Encode {
            target: "EncKrbCredPart",
            message: source.to_string(),
        })?,
        "krb-cred encode",
    );
    let enc_part = match transport {
        CredentialTransport::Protected(_channel) => rasn_kerberos::EncryptedData {
            etype: ENCTYPE_NULL,
            kvno: None,
            cipher: plaintext.to_vec().into(),
        },
        CredentialTransport::Encrypted => {
            let key = super::private_safe::sending_key(context)?;
            let etype = selection::enctype(key.etype())
                .map_err(KrbCred::from)?
                .ok_or_else(|| KrbCred::UnsupportedEtype(key.etype()))?;
            let mut confounder = Zeroizing::new(vec![0; etype.confounder_len()]);
            getrandom::fill(&mut confounder).map_err(KrbCred::from)?;
            let cipher = etype
                .encrypt_message_with_confounder(
                    key.value(),
                    &plaintext,
                    KRB_CRED_ENCPART_USAGE,
                    &confounder,
                )
                .map_err(KrbCred::from)?;
            let enc = rasn_kerberos::EncryptedData {
                etype: key.etype(),
                kvno: None,
                cipher: cipher.into(),
            };
            if context.policy.check_time {
                let tag = Tag::from_authenticator(enc.etype, enc.cipher.as_ref());
                super::private_safe::check_replay(context, Some(context.now()), tag.as_bytes())?;
            }
            enc
        }
    };
    let message = rasn_kerberos::KrbCred {
        pvno: Integer::from(5_i32),
        msg_type: Integer::from(22_i32),
        tickets,
        enc_part,
    };
    let wire = der::encode(&message).map_err(|source| KrbCred::Encode {
        target: "KRB-CRED",
        message: source.to_string(),
    })?;
    if context.policy.check_sequence {
        context.local_sequence = context.local_sequence.wrapping_add(1);
    }
    Ok(wire)
}

/// MIT `krb5_rd_cred`: read forwarded credentials.
///
/// # Errors
///
/// Returns [`Error::UnauthenticatedTransport`] for an unencrypted KRB-CRED
/// that arrives without a proven channel, [`Error::NoKey`], the codec and
/// policy errors, and the time, replay and sequence refusals.
pub(super) fn read_cred(
    context: &mut AuthContext,
    wire: &[u8],
    transport: CredentialTransport<'_>,
) -> Result<Received<Vec<Credential>>, Error> {
    let message = krb_cred::decode(wire)?;
    let unencrypted = message.enc_part.etype == ENCTYPE_NULL;
    let part = if unencrypted {
        match transport {
            CredentialTransport::Protected(_channel) => {
                krb_cred::decode_enc_krb_cred_part(message.enc_part.cipher.as_ref())?
            }
            CredentialTransport::Encrypted => return Err(Error::UnauthenticatedTransport),
        }
    } else {
        let mut failure = Error::NoKey;
        let mut decrypted = None;
        for key in super::private_safe::receiving_keys(context) {
            context
                .policy
                .crypto
                .check_use(key.etype(), Use::ImportedCredential)?;
            match krb_cred::decrypt_krb_cred_enc_part(&message, key) {
                Ok(found) => {
                    decrypted = Some(found);
                    break;
                }
                Err(error) => failure = Error::from(error),
            }
        }
        decrypted.ok_or(failure)?
    };
    let timestamp = match &part.timestamp {
        Some(stamp) => Some(system_time(stamp, part.usec.as_ref())?),
        None => None,
    };
    if !unencrypted {
        let tag = Tag::from_authenticator(message.enc_part.etype, message.enc_part.cipher.as_ref());
        super::private_safe::check_replay(context, timestamp, tag.as_bytes())?;
        super::private_safe::check_sequence(context, part.nonce)?;
    }
    let credentials = import::decrypted(&context.policy.crypto, &message, &part)?;
    check_owner(context, &credentials)?;
    Ok(Received::new(credentials, timestamp, part.nonce))
}
