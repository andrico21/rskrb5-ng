//! A deterministic FAST KDC that requires OTP, as MIT's `otp` module does.
//!
//! It checks the armor AP-REQ and the request checksum, answers an armored
//! `PREAUTH_REQUIRED` with a `PA-OTP-CHALLENGE`, verifies a `PA-OTP-REQUEST` (the
//! nonce encrypted in the armor key, usage 45) and issues an armored AS-REP whose
//! reply key is the armor key (RFC 6560 section 3.6, MIT `otp/main.c:172-182`).

use core::{error::Error, time::Duration};
use std::time::{SystemTime, UNIX_EPOCH};

use rasn::{der, types::Integer};
use rasn_kerberos::{
    ApReq, AsRep, Authenticator, Checksum, EncKdcRepPart, EncTicketPart, EncryptedData, KdcRep,
    KerberosFlags, KerberosString, KerberosTime, KrbError, PaData, PrincipalName, Ticket,
    TicketFlags, TransitedEncoding,
    otp::{PaOtpChallenge, PaOtpEncRequest, PaOtpRequest},
};
use rskrb5_ng::{
    client::{AsRepSession, principal::Principal},
    crypto::{KerberosEtype, prf},
    kdc_rep,
    keytab::EncryptionKey,
    preauth::{
        fast::{PA_FX_COOKIE, PA_FX_ERROR, PA_FX_FAST},
        otp::PA_OTP_CHALLENGE,
    },
};

use super::asn1::{
    KrbFastArmoredRep, KrbFastFinished, KrbFastReq, KrbFastResponse, PaFxFastReply, PaFxFastRequest,
};

/// The test realm.
pub(crate) const REALM: &str = "OTP.TEST";
/// The client.
pub(crate) const CLIENT: &str = "otpuser";
/// A boxed test failure.
pub(crate) type TestError = Box<dyn Error>;
/// `KDC_ERR_PREAUTH_FAILED`.
pub(crate) const PREAUTH_FAILED: i32 = 24;

/// What the KDC puts in the `PA-OTP-CHALLENGE` it offers.
#[derive(Clone)]
pub(crate) enum Offer {
    /// This challenge.
    Of(PaOtpChallenge),
    /// These exact bytes as the `PA-OTP-CHALLENGE` value.
    Raw(Vec<u8>),
}

/// The fake KDC.
pub(crate) struct Kdc {
    /// The `krbtgt/REALM` key.
    tgs_key: EncryptionKey,
    /// The challenge.
    challenge: Offer,
    /// How many `PA-OTP-CHALLENGE` entries the error carries.
    copies: usize,
    /// The OTP value the KDC accepts.
    accepts: Vec<u8>,
    /// The nonce the KDC issued.
    nonce: Vec<u8>,
    /// Every request received, as sent.
    requests: Vec<Vec<u8>>,
    /// The last `PA-OTP-REQUEST`, decrypted and checked.
    seen: Option<PaOtpRequest>,
    /// The `PA-OTP-REQUEST` the KDC accepted, if any.
    accepted: bool,
}

impl Kdc {
    /// A KDC that offers `challenge` and accepts `value`.
    pub(crate) fn new(challenge: Offer, value: &[u8]) -> Self {
        let mut nonce = 1_893_553_440_u32.to_be_bytes().to_vec();
        nonce.extend_from_slice(&[0x77; 32]);
        Self {
            tgs_key: EncryptionKey::new(18, vec![0x11; 32]),
            challenge,
            copies: 1,
            accepts: value.to_vec(),
            nonce,
            requests: Vec::new(),
            seen: None,
            accepted: false,
        }
    }

    /// Offer the challenge `copies` times.
    pub(crate) const fn offering(mut self, copies: usize) -> Self {
        self.copies = copies;
        self
    }

    /// Every request received, as sent.
    pub(crate) fn requests(&self) -> &[Vec<u8>] {
        &self.requests
    }

    /// The last `PA-OTP-REQUEST` the KDC decrypted.
    pub(crate) const fn seen(&self) -> Option<&PaOtpRequest> {
        self.seen.as_ref()
    }

    /// Whether the KDC accepted an OTP request.
    pub(crate) const fn accepted(&self) -> bool {
        self.accepted
    }

    /// An armor TGT of the realm, issued to a host.
    pub(crate) fn armor_ticket(&self) -> Result<AsRepSession, TestError> {
        let session = EncryptionKey::new(18, vec![0x33; 32]);
        let ticket = self.ticket(&["host", "armor.otp.test"], &session)?;
        let now = SystemTime::now();
        Ok(AsRepSession::new(
            Principal::new(REALM, 3, ["host", "armor.otp.test"]),
            Principal::tgt_service(REALM),
            session,
            der::encode(&ticket)?.into(),
            [0x40, 0x60, 0, 0],
            now,
            now.checked_add(Duration::from_secs(3600)).ok_or("time")?,
        ))
    }

    /// Answer one request.
    pub(crate) fn handle(&mut self, request: &[u8]) -> Result<Vec<u8>, TestError> {
        self.requests.push(request.to_vec());
        let rasn_kerberos::AsReq(outer) = der::decode(request)?;
        let padata = outer.padata.clone().unwrap_or_default();
        let [fast] = padata.as_slice() else {
            return Err("the outer request must carry exactly one padata".into());
        };
        if fast.r#type != PA_FX_FAST {
            return Err("the outer padata is not PA-FX-FAST".into());
        }
        let PaFxFastRequest::ArmoredData(armored) = der::decode(&fast.value)?;
        let armor = armored.armor.ok_or("AS armor missing")?;
        let ap_req: ApReq = der::decode(&armor.armor_value)?;
        let enc_ticket: EncTicketPart =
            der::decode(&open(&self.tgs_key, 2, &ap_req.ticket.enc_part)?)?;
        let session = EncryptionKey::new(enc_ticket.key.r#type, enc_ticket.key.value.to_vec());
        let authenticator: Authenticator =
            der::decode(&open(&session, 11, &ap_req.authenticator)?)?;
        let subkey = authenticator.subkey.ok_or("armor subkey missing")?;
        let armor_key = cf2(
            (
                &EncryptionKey::new(subkey.r#type, subkey.value.to_vec()),
                b"subkeyarmor",
            ),
            (&session, b"ticketarmor"),
        )?;
        let body = der::encode(&outer.req_body)?;
        let checksum = etype(&armor_key)?.checksum(armor_key.value(), &body, 50)?;
        if armored.req_checksum.checksum.as_ref() != checksum.as_slice() {
            return Err("the request checksum does not verify".into());
        }
        let inner: KrbFastReq = der::decode(&open(&armor_key, 51, &armored.enc_fast_req)?)?;
        if inner.req_body != outer.req_body {
            return Err("the inner body differs from the outer body".into());
        }
        let context = Context {
            armor_key,
            nonce: inner.req_body.nonce,
            request: request.to_vec(),
        };
        let Some(otp) = inner.padata.iter().find(|entry| entry.r#type == 142_i32) else {
            return self.preauth_required(&context, &inner);
        };
        let sent: PaOtpRequest = der::decode(&otp.value)?;
        let plain = open(&context.armor_key, 45, &sent.enc_data)?;
        let PaOtpEncRequest { nonce, .. } = der::decode(&plain)?;
        let accepted = nonce.as_ref() == self.nonce.as_slice()
            && sent.otp_value.as_deref() == Some(self.accepts.as_slice());
        self.seen = Some(sent);
        self.accepted = accepted;
        if accepted {
            self.as_rep(&context, &inner)
        } else {
            Self::failure(&context, &inner)
        }
    }

    /// The `PA-OTP-CHALLENGE` value, with this KDC's nonce.
    fn challenge_value(&self) -> Result<Vec<u8>, TestError> {
        Ok(match &self.challenge {
            Offer::Of(offered) => {
                let mut with_nonce = offered.clone();
                with_nonce.nonce = self.nonce.clone().into();
                der::encode(&with_nonce)?
            }
            Offer::Raw(bytes) => bytes.clone(),
        })
    }

    /// The unarmored `PREAUTH_REQUIRED` that a KDC without FAST, or an attacker,
    /// sends for `request`: the challenge in the clear.
    pub(crate) fn plain_challenge(&mut self, request: &[u8]) -> Result<Vec<u8>, TestError> {
        self.requests.push(request.to_vec());
        let rasn_kerberos::AsReq(outer) = der::decode(request)?;
        let method_data = vec![pa(PA_OTP_CHALLENGE, self.challenge_value()?)];
        Ok(der::encode(&error(
            outer.req_body.cname.as_ref(),
            25,
            Some(der::encode(&method_data)?),
        )?)?)
    }

    /// The armored `PREAUTH_REQUIRED` that offers OTP.
    fn preauth_required(
        &self,
        context: &Context,
        inner: &KrbFastReq,
    ) -> Result<Vec<u8>, TestError> {
        let value = self.challenge_value()?;
        let mut padata = vec![pa(
            PA_FX_ERROR,
            der::encode(&error(inner.req_body.cname.as_ref(), 25, None)?)?,
        )];
        for _ in 0..self.copies {
            padata.push(pa(PA_OTP_CHALLENGE, value.clone()));
        }
        padata.push(pa(PA_FX_COOKIE, b"otp-cookie".to_vec()));
        armored_error(context, inner, padata, 25)
    }

    /// The armored `KDC_ERR_PREAUTH_FAILED` of a refused OTP.
    fn failure(context: &Context, inner: &KrbFastReq) -> Result<Vec<u8>, TestError> {
        let padata = vec![pa(
            PA_FX_ERROR,
            der::encode(&error(inner.req_body.cname.as_ref(), PREAUTH_FAILED, None)?)?,
        )];
        armored_error(context, inner, padata, PREAUTH_FAILED)
    }

    /// The armored AS-REP of an accepted OTP: the reply key is the armor key,
    /// strengthened by the KDC.
    fn as_rep(&self, context: &Context, inner: &KrbFastReq) -> Result<Vec<u8>, TestError> {
        let ticket = self.ticket(&[CLIENT], &EncryptionKey::new(18, vec![0x55; 32]))?;
        let strengthen = EncryptionKey::new(18, vec![0x66; 32]);
        let reply_key = cf2(
            (&strengthen, b"strengthenkey"),
            (&context.armor_key, b"replykey"),
        )?;
        let enc_part = kdc_rep::encrypt_as_rep_enc_part(
            &enc_part(context, inner, &reply_key)?,
            &reply_key,
            None,
        )?;
        let response = KrbFastResponse {
            padata: Vec::new(),
            strengthen_key: Some(rasn_kerberos::EncryptionKey {
                r#type: 18,
                value: strengthen.value().to_vec().into(),
            }),
            finished: Some(finished(context, &ticket)?),
            nonce: context.nonce,
        };
        let sealed = seal(&context.armor_key, 52, &der::encode(&response)?)?;
        Ok(der::encode(&AsRep(KdcRep {
            pvno: Integer::from(5_i32),
            msg_type: Integer::from(11_i32),
            padata: Some(vec![pa(
                PA_FX_FAST,
                der::encode(&PaFxFastReply::ArmoredData(KrbFastArmoredRep {
                    enc_fast_rep: sealed,
                }))?,
            )]),
            crealm: string(REALM)?,
            cname: name(1, &[CLIENT])?,
            ticket,
            enc_part,
        }))?)
    }

    /// A ticket of the realm for `client`, sealed in the TGS key.
    fn ticket(&self, client: &[&str], session: &EncryptionKey) -> Result<Ticket, TestError> {
        let now = whole(SystemTime::now())?;
        let part = EncTicketPart {
            flags: TicketFlags(KerberosFlags::from_slice(&[0x40, 0x60, 0, 0])),
            key: rasn_kerberos::EncryptionKey {
                r#type: session.etype(),
                value: session.value().to_vec().into(),
            },
            crealm: string(REALM)?,
            cname: name(1, client)?,
            transited: TransitedEncoding {
                r#type: 1,
                contents: Vec::new().into(),
            },
            auth_time: time(now),
            start_time: None,
            end_time: time(now.checked_add(Duration::from_secs(3600)).ok_or("time")?),
            renew_till: None,
            caddr: None,
            authorization_data: None,
        };
        Ok(Ticket {
            tkt_vno: Integer::from(5_i32),
            realm: string(REALM)?,
            sname: name(2, &["krbtgt", REALM])?,
            enc_part: seal(&self.tgs_key, 2, &der::encode(&part)?)?,
        })
    }
}

/// The armor key, the nonce and the bytes of one armored request.
struct Context {
    /// The armor key.
    armor_key: EncryptionKey,
    /// The inner request nonce.
    nonce: u32,
    /// The request as received.
    request: Vec<u8>,
}

/// An armored KRB-ERROR with `padata` in its `KrbFastResponse`.
fn armored_error(
    context: &Context,
    inner: &KrbFastReq,
    padata: Vec<PaData>,
    code: i32,
) -> Result<Vec<u8>, TestError> {
    let response = KrbFastResponse {
        padata,
        strengthen_key: None,
        finished: None,
        nonce: context.nonce,
    };
    let sealed = seal(&context.armor_key, 52, &der::encode(&response)?)?;
    let method_data = vec![pa(
        PA_FX_FAST,
        der::encode(&PaFxFastReply::ArmoredData(KrbFastArmoredRep {
            enc_fast_rep: sealed,
        }))?,
    )];
    Ok(der::encode(&error(
        inner.req_body.cname.as_ref(),
        code,
        Some(der::encode(&method_data)?),
    )?)?)
}

/// The finished message over `ticket`.
fn finished(context: &Context, ticket: &Ticket) -> Result<KrbFastFinished, TestError> {
    let cipher = etype(&context.armor_key)?;
    let value = cipher.checksum(context.armor_key.value(), &der::encode(ticket)?, 53)?;
    Ok(KrbFastFinished {
        timestamp: time(whole(SystemTime::now())?),
        usec: Integer::from(0_i32),
        crealm: string(REALM)?,
        cname: name(1, &[CLIENT])?,
        ticket_checksum: Checksum {
            r#type: cipher.checksum_type_id(),
            checksum: value.into(),
        },
    })
}

/// The encrypted part of the AS-REP, with the RFC 6806 checksum over the
/// request as received when the request asked for it.
fn enc_part(
    context: &Context,
    inner: &KrbFastReq,
    reply_key: &EncryptionKey,
) -> Result<EncKdcRepPart, TestError> {
    let negotiated = inner.padata.iter().any(|entry| entry.r#type == 149_i32);
    let encrypted_pa_data = if negotiated {
        let cipher = etype(reply_key)?;
        Some(vec![pa(
            149_i32,
            der::encode(&Checksum {
                r#type: cipher.checksum_type_id(),
                checksum: cipher
                    .checksum(reply_key.value(), &context.request, 56)?
                    .into(),
            })?,
        )])
    } else {
        None
    };
    let flags = if negotiated {
        0x0061_0000_u32
    } else {
        0x0060_0000_u32
    };
    Ok(EncKdcRepPart {
        key: rasn_kerberos::EncryptionKey {
            r#type: 18,
            value: vec![0x55; 32].into(),
        },
        last_req: Vec::new(),
        nonce: inner.req_body.nonce,
        key_expiration: None,
        flags: TicketFlags(KerberosFlags::from_slice(&flags.to_be_bytes())),
        auth_time: time(whole(SystemTime::now())?),
        start_time: None,
        end_time: inner.req_body.till.clone(),
        renew_till: None,
        srealm: string(REALM)?,
        sname: name(2, &["krbtgt", REALM])?,
        caddr: None,
        encrypted_pa_data,
    })
}

/// The KRB-ERROR `code` for `cname` with `e_data`.
fn error(
    cname: Option<&PrincipalName>,
    code: i32,
    e_data: Option<Vec<u8>>,
) -> Result<KrbError, TestError> {
    Ok(KrbError {
        pvno: Integer::from(5_i32),
        msg_type: Integer::from(30_i32),
        ctime: None,
        cusec: None,
        stime: time(whole(SystemTime::now())?),
        susec: Integer::from(0_i32),
        error_code: code,
        crealm: Some(string(REALM)?),
        cname: cname.cloned(),
        realm: string(REALM)?,
        sname: name(2, &["krbtgt", REALM])?,
        e_text: None,
        e_data: e_data.map(Into::into),
    })
}

/// One PA-DATA.
fn pa(r#type: i32, value: Vec<u8>) -> PaData {
    PaData {
        r#type,
        value: value.into(),
    }
}

/// The implemented enctype of `key`.
fn etype(key: &EncryptionKey) -> Result<KerberosEtype, TestError> {
    Ok(KerberosEtype::from_etype_id(key.etype()).ok_or("enctype")?)
}

/// `KRB-FX-CF2` of two keys.
fn cf2(
    (first, first_pepper): (&EncryptionKey, &[u8]),
    (second, second_pepper): (&EncryptionKey, &[u8]),
) -> Result<EncryptionKey, TestError> {
    let combined = prf::krb_fx_cf2(
        &prf::CfInput::new(prf::Key::new(etype(first)?, first.value()), first_pepper),
        &prf::CfInput::new(prf::Key::new(etype(second)?, second.value()), second_pepper),
    )?;
    Ok(EncryptionKey::new(first.etype(), combined.to_vec()))
}

/// Encrypt with a fixed confounder.
pub(crate) fn seal(
    key: &EncryptionKey,
    usage: u32,
    plain: &[u8],
) -> Result<EncryptedData, TestError> {
    let cipher = etype(key)?;
    let sealed = cipher.encrypt_message_with_confounder(
        key.value(),
        plain,
        usage,
        &vec![0x5a; cipher.confounder_len()],
    )?;
    Ok(EncryptedData {
        etype: key.etype(),
        kvno: None,
        cipher: sealed.into(),
    })
}

/// Decrypt.
fn open(key: &EncryptionKey, usage: u32, encrypted: &EncryptedData) -> Result<Vec<u8>, TestError> {
    Ok(etype(key)?.decrypt_message(key.value(), &encrypted.cipher, usage)?)
}

/// `value` truncated to whole seconds.
fn whole(value: SystemTime) -> Result<SystemTime, TestError> {
    let seconds = value.duration_since(UNIX_EPOCH)?.as_secs();
    Ok(UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .ok_or("time")?)
}

/// A Kerberos time.
fn time(value: SystemTime) -> KerberosTime {
    KerberosTime(chrono::DateTime::<chrono::Utc>::from(value).into())
}

/// A Kerberos string.
fn string(value: &str) -> Result<KerberosString, TestError> {
    Ok(KerberosString::try_from(value.to_owned())?)
}

/// A principal name.
fn name(r#type: i32, components: &[&str]) -> Result<PrincipalName, TestError> {
    Ok(PrincipalName {
        r#type,
        string: components
            .iter()
            .map(|component| string(component))
            .collect::<Result<_, _>>()?,
    })
}
