//! The client half of the PA-SPAKE exchange (MIT 1.22.2 `spake_client.c`).

use rasn_kerberos::{EncryptedData, PaData};
use zeroize::Zeroizing;

use super::{
    Client, Derivation, Entropy, Group, KEY_USAGE_SPAKE, Message, PA_SPAKE, Policy, SF_NONE, Step,
    group, kdf, wire,
};
use crate::{
    crypto::KerberosEtype,
    error::{Crypto, Policy as PolicyError, Spake as Error},
    keytab::EncryptionKey,
};

/// The inputs of one response.
struct Exchange<'input> {
    /// The DER challenge exactly as received.
    challenge: &'input [u8],
    /// The KDC's element `T`.
    pubkey: &'input [u8],
    /// The DER KDC-REQ-BODY of the request being sent.
    body: &'input [u8],
    /// The initial reply key.
    key: &'input EncryptionKey,
}

impl Client {
    /// A new exchange under `policy`.
    #[inline]
    #[must_use]
    pub const fn new(policy: Policy) -> Self {
        Self {
            policy,
            support: None,
            answered: false,
        }
    }

    /// Answer the KDC's PA-SPAKE value `pa_value` for the request whose DER
    /// KDC-REQ-BODY is `request_body` (the inner body under FAST).
    ///
    /// An empty value, or a first challenge in a group the policy does not
    /// permit, is answered with a support message (MIT
    /// `spake_client.c:202-208`). A challenge in a permitted group is answered
    /// with a response; `initial_key` is called once, then, for the initial
    /// reply key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoGroups`] when no permitted group is available,
    /// [`Error::Malformed`] for a value outside the codec bounds,
    /// [`Error::Unexpected`] for a message the client does not expect now,
    /// [`Error::SecondFactorUnsupported`] for `encdata`,
    /// [`Error::GroupNotPermitted`] for a second challenge outside the policy,
    /// [`Error::NoSupportedFactor`] without `SF-NONE`, [`Error::InvalidElement`]
    /// for a bad KDC element, the key derivation and random-generator errors,
    /// and the error of `initial_key`.
    ///
    /// # Security
    ///
    /// `request_body` must be the body of the request that will carry the
    /// result: `K'[0]` and `K'[1]` are bound to it (RFC 9588 section 7).
    #[inline]
    pub fn process<F, E>(
        &mut self,
        pa_value: &[u8],
        request_body: &[u8],
        initial_key: F,
    ) -> Result<Step, E>
    where
        F: FnOnce() -> Result<EncryptionKey, E>,
        E: From<Error>,
    {
        self.process_with(pa_value, request_body, initial_key, &mut random)
    }

    /// [`Self::process`] with an explicit entropy source (tests replay vectors).
    ///
    /// # Errors
    /// As [`Self::process`].
    pub(super) fn process_with<F, E>(
        &mut self,
        pa_value: &[u8],
        request_body: &[u8],
        initial_key: F,
        entropy: &mut Entropy<'_>,
    ) -> Result<Step, E>
    where
        F: FnOnce() -> Result<EncryptionKey, E>,
        E: From<Error>,
    {
        if pa_value.is_empty() {
            return Ok(self.support()?);
        }
        let (group_id, pubkey, factors) = match wire::decode(pa_value)? {
            Message::Challenge {
                group,
                pubkey,
                factors,
            } => (group, pubkey, factors),
            Message::Encdata(_) => return Err(Error::SecondFactorUnsupported.into()),
            Message::Support { groups: _ } => return Err(unexpected("a support message").into()),
            Message::Response {
                pubkey: _,
                factor: _,
            } => return Err(unexpected("a response message").into()),
        };
        if self.answered {
            return Err(unexpected("a challenge after the response").into());
        }
        let Some(chosen) = self.policy.permitted(group_id) else {
            if self.support.is_some() {
                return Err(Error::GroupNotPermitted { group: group_id }.into());
            }
            return Ok(self.support()?);
        };
        let none = factors
            .iter()
            .find(|factor| factor.kind == SF_NONE)
            .ok_or(Error::NoSupportedFactor)?;
        if none.data.is_some() {
            return Err(wire::malformed("SF-NONE carries data").into());
        }
        if pubkey.len() != chosen.params().elem_len {
            return Err(Error::InvalidElement { group: group_id }.into());
        }
        let key = initial_key()?;
        let exchange = Exchange {
            challenge: pa_value,
            pubkey: &pubkey,
            body: request_body,
            key: &key,
        };
        let (padata, reply_key) = self.respond(chosen, &exchange, entropy)?;
        self.answered = true;
        Ok(Step::Response { padata, reply_key })
    }

    /// Build, remember and return the support message (MIT `spake_client.c:155-178`).
    ///
    /// # Errors
    /// Returns [`Error::Unexpected`] for a second support message and
    /// [`Error::NoGroups`] when no permitted group is available.
    fn support(&mut self) -> Result<Step, Error> {
        if self.support.is_some() {
            return Err(unexpected("a second request for the support message"));
        }
        if !self.policy.is_usable() {
            return Err(Error::NoGroups);
        }
        let groups = self.policy.groups.iter().map(|group| group.id()).collect();
        let der = wire::support(groups)?;
        self.support = Some(der.clone());
        Ok(Step::Support(PaData {
            r#type: PA_SPAKE,
            value: der.into(),
        }))
    }

    /// Compute the response and `K'[0]` (MIT `spake_client.c:180-298`).
    ///
    /// # Errors
    /// Returns the element, derivation, encryption and encoding errors.
    fn respond(
        &self,
        chosen: Group,
        exchange: &Exchange<'_>,
        entropy: &mut Entropy<'_>,
    ) -> Result<(PaData, EncryptionKey), Error> {
        let params = chosen.params();
        let support: &[u8] = self.support.as_deref().unwrap_or_default();
        let after_challenge = kdf::update(&params, None, &[support, exchange.challenge]);
        let wbytes = kdf::multiplier(exchange.key, params.id, params.mult_len)?;
        let shared = group::exchange(chosen, &wbytes, exchange.pubkey, entropy)?;
        let thash = kdf::update(&params, Some(&after_challenge), &[&shared.public]);
        let derivation = Derivation {
            params,
            key: exchange.key,
            wbytes: &wbytes,
            result: &shared.result,
            thash: &thash,
            body: exchange.body,
        };
        let reply_key = kdf::derive(&derivation, 0)?;
        let factor = encrypt_factor(&kdf::derive(&derivation, 1)?, entropy)?;
        let der = wire::response(shared.public, factor)?;
        Ok((
            PaData {
                r#type: PA_SPAKE,
                value: der.into(),
            },
            reply_key,
        ))
    }
}

/// `SPAKESecondFactor { SF-NONE }` encrypted in `K'[1]` with `KEY_USAGE_SPAKE`.
///
/// # Errors
/// Returns the encoding, random-generator and encryption errors.
fn encrypt_factor(key: &EncryptionKey, entropy: &mut Entropy<'_>) -> Result<EncryptedData, Error> {
    let etype = KerberosEtype::from_etype_id(key.etype()).ok_or_else(|| {
        Error::Crypto(Crypto::Policy(PolicyError::UnknownEnctype {
            etype: key.etype(),
        }))
    })?;
    let plaintext = Zeroizing::new(wire::factor_none()?);
    let mut confounder = Zeroizing::new(vec![0_u8; etype.confounder_len()]);
    entropy(&mut confounder)?;
    let cipher = etype.encrypt_message_with_confounder(
        key.value(),
        &plaintext,
        KEY_USAGE_SPAKE,
        &confounder,
    )?;
    Ok(EncryptedData {
        etype: key.etype(),
        kvno: None,
        cipher: cipher.into(),
    })
}

/// The operating system's random generator.
///
/// # Errors
/// Returns [`Error::Random`] when it fails.
fn random(buffer: &mut [u8]) -> Result<(), Error> {
    Ok(getrandom::fill(buffer)?)
}

/// An unexpected-message error.
const fn unexpected(message: &'static str) -> Error {
    Error::Unexpected { message }
}
