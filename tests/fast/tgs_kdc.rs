//! A deterministic FAST KDC for TGS requests (RFC 6113 section 5.4.2).
//!
//! It takes the request apart the way MIT's KDC does: the TGT in `PA-TGS-REQ`
//! yields the session key and the authenticator subkey, the armor key is
//! `KRB-FX-CF2(subkey, session key, "subkeyarmor", "ticketarmor")`, the
//! request checksum covers the AP-REQ, and the inner request repeats the
//! outer body and padata. It answers with an armored TGS-REP encrypted in the
//! strengthened subkey. One [`Tamper`] switch at a time breaks one rule.

use std::time::SystemTime;

use rasn::{der, types::Integer};
use rasn_kerberos::{
    ApReq, Authenticator, Checksum, EncKdcRepPart, EncTicketPart, KdcRep, KerberosFlags, KrbError,
    PaData, TgsRep, TgsReq, Ticket, TicketFlags, TransitedEncoding,
};
use rskrb5_ng::{
    kdc_rep,
    keytab::EncryptionKey,
    preauth::fast::{PA_FX_ERROR, PA_FX_FAST},
};

use super::{
    asn1::{
        KrbFastArmoredRep, KrbFastFinished, KrbFastReq, KrbFastResponse, PaFxFastReply,
        PaFxFastRequest,
    },
    kdc::{TestError, cf2, etype, flip, flip_bytes, name, open, pa, seal, string, time, whole},
};

/// The key of the `krbtgt` service every TGT of the tests is sealed in.
const TGS_KEY: [u8; 32] = [0x11; 32];
/// The `PA-TGS-REQ` padata type.
const PA_TGS_REQ: i32 = 1;

/// One RFC 6113 rule the KDC breaks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Tamper {
    /// Nothing.
    None,
    /// The TGS-REP has no `KrbFastFinished` (MIT `fast.c:534-538`).
    DropFinished,
    /// The finished ticket checksum is corrupted.
    TicketChecksum,
    /// The finished ticket checksum has a type other than the armor key's.
    TicketChecksumType,
    /// The `KrbFastResponse` nonce is not the request's.
    Nonce,
    /// The response carries no strengthen key and the reply is encrypted in the plain subkey.
    DropStrengthenKey,
    /// The strengthen key in the response is not the one that encrypted the reply.
    WrongStrengthenKey,
    /// A KDC without FAST: no `PA-FX-FAST`, the reply is encrypted in the plain subkey.
    NoFast,
    /// The armored reply loses its `PA-FX-FAST` on the way; the reply stays strengthened.
    StrippedFast,
    /// The armored response's ciphertext is corrupted.
    ReplyCiphertext,
    /// The outer client name is not the client; only the finished message is right.
    OuterClient,
    /// An armored `KDC_ERR_S_PRINCIPAL_UNKNOWN`.
    ArmoredError,
    /// An unarmored `KDC_ERR_S_PRINCIPAL_UNKNOWN`.
    UnarmoredError,
    /// An armored error whose inner error carries a strengthen key.
    ErrorStrengthenKey,
}

/// The fake TGS KDC.
pub(crate) struct TgsKdc {
    /// The rule to break.
    tamper: Tamper,
    /// Every request received, as sent.
    requests: Vec<Vec<u8>>,
    /// What the last request carried.
    seen: Option<Seen>,
}

/// What the KDC verified about the last request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Seen {
    /// The outer padata types, in order.
    pub(crate) outer_types: Vec<i32>,
    /// The inner (encrypted) padata types, in order.
    pub(crate) inner_types: Vec<i32>,
    /// Whether the armor field of the armored request was present.
    pub(crate) armor_field: bool,
    /// The type of the request checksum.
    pub(crate) checksum_type: i32,
}

impl TgsKdc {
    /// A KDC that breaks `tamper`.
    pub(crate) const fn new(tamper: Tamper) -> Self {
        Self {
            tamper,
            requests: Vec::new(),
            seen: None,
        }
    }

    /// Every request received, as sent.
    pub(crate) fn requests(&self) -> &[Vec<u8>] {
        &self.requests
    }

    /// What the KDC verified about the last request.
    pub(crate) const fn seen(&self) -> Option<&Seen> {
        self.seen.as_ref()
    }

    /// Answer one TGS-REQ.
    pub(crate) fn handle(&mut self, request: &[u8]) -> Result<Vec<u8>, TestError> {
        self.requests.push(request.to_vec());
        let TgsReq(outer) = der::decode(request)?;
        let padata = outer.padata.clone().unwrap_or_default();
        let (head, rest) = padata
            .split_at_checked(2)
            .ok_or("the outer padata must start with PA-TGS-REQ and PA-FX-FAST")?;
        let [tgs, fast] = head else {
            return Err("the outer padata must start with PA-TGS-REQ and PA-FX-FAST".into());
        };
        if tgs.r#type != PA_TGS_REQ || fast.r#type != PA_FX_FAST {
            return Err("the outer padata must be PA-TGS-REQ then PA-FX-FAST".into());
        }
        let ap_req: ApReq = der::decode(&tgs.value)?;
        let tgs_key = EncryptionKey::new(18, TGS_KEY.to_vec());
        let enc_ticket: EncTicketPart = der::decode(&open(&tgs_key, 2, &ap_req.ticket.enc_part)?)?;
        let session = EncryptionKey::new(enc_ticket.key.r#type, enc_ticket.key.value.to_vec());
        let authenticator: Authenticator = der::decode(&open(&session, 7, &ap_req.authenticator)?)?;
        let client_realm = String::from_utf8(authenticator.crealm.as_bytes().to_vec())?;
        let subkey = authenticator
            .subkey
            .ok_or("the authenticator carries no subkey")?;
        let subkey = EncryptionKey::new(subkey.r#type, subkey.value.to_vec());
        let armor_key = cf2((&subkey, b"subkeyarmor"), (&session, b"ticketarmor"))?;
        let PaFxFastRequest::ArmoredData(armored) = der::decode(&fast.value)?;
        let expected = etype(&armor_key)?.checksum(armor_key.value(), &tgs.value, 50)?;
        if armored.req_checksum.checksum.as_ref() != expected.as_slice() {
            return Err("the request checksum does not cover the AP-REQ".into());
        }
        let inner: KrbFastReq = der::decode(&open(&armor_key, 51, &armored.enc_fast_req)?)?;
        if inner.req_body != outer.req_body {
            return Err("the inner body differs from the outer body".into());
        }
        if inner.padata.as_slice() != rest {
            return Err("the inner padata must repeat the outer padata after PA-FX-FAST".into());
        }
        self.seen = Some(Seen {
            outer_types: padata.iter().map(|entry| entry.r#type).collect(),
            inner_types: inner.padata.iter().map(|entry| entry.r#type).collect(),
            armor_field: armored.armor.is_some(),
            checksum_type: armored.req_checksum.r#type,
        });
        let context = Context {
            armor_key,
            subkey,
            nonce: inner.req_body.nonce,
            request: &outer,
            client_realm,
        };
        match self.tamper {
            Tamper::ArmoredError | Tamper::ErrorStrengthenKey => context.armored_error(self.tamper),
            Tamper::UnarmoredError => context.unarmored_error(),
            Tamper::None
            | Tamper::DropFinished
            | Tamper::TicketChecksum
            | Tamper::TicketChecksumType
            | Tamper::Nonce
            | Tamper::DropStrengthenKey
            | Tamper::WrongStrengthenKey
            | Tamper::NoFast
            | Tamper::StrippedFast
            | Tamper::ReplyCiphertext
            | Tamper::OuterClient => context.reply(self.tamper),
        }
    }
}

/// The keys, nonce and request of one armored TGS request.
struct Context<'request> {
    /// The armor key.
    armor_key: EncryptionKey,
    /// The authenticator subkey.
    subkey: EncryptionKey,
    /// The inner request nonce.
    nonce: u32,
    /// The outer request.
    request: &'request rasn_kerberos::KdcReq,
    /// The realm of the client the TGT was issued to.
    client_realm: String,
}

impl Context<'_> {
    /// The client of the request: the TGT's, as the authenticator names it.
    fn client() -> Result<rasn_kerberos::PrincipalName, TestError> {
        name(3, &["host", "armor.fast.test"])
    }

    /// The realm of the request.
    fn realm(&self) -> Result<String, TestError> {
        Ok(String::from_utf8(
            self.request.req_body.realm.as_bytes().to_vec(),
        )?)
    }

    /// The armored TGS-REP, or the broken variant of it.
    fn reply(&self, tamper: Tamper) -> Result<Vec<u8>, TestError> {
        let realm = self.realm()?;
        let service = self
            .request
            .req_body
            .sname
            .clone()
            .ok_or("the request names no service")?;
        let is_tgs = service
            .string
            .first()
            .is_some_and(|component| component.as_bytes() == b"krbtgt");
        let ticket = Ticket {
            tkt_vno: Integer::from(5_i32),
            realm: string(&realm)?,
            sname: service.clone(),
            enc_part: seal(
                &EncryptionKey::new(18, if is_tgs { TGS_KEY.to_vec() } else { vec![0x88; 32] }),
                2,
                &der::encode(&EncTicketPart {
                    flags: TicketFlags(KerberosFlags::from_slice(&[0, 0x60, 0, 0])),
                    key: rasn_kerberos::EncryptionKey {
                        r#type: 18,
                        value: vec![0x77; 32].into(),
                    },
                    crealm: string(&self.client_realm)?,
                    cname: Self::client()?,
                    transited: TransitedEncoding {
                        r#type: 1,
                        contents: Vec::new().into(),
                    },
                    auth_time: time(whole(SystemTime::now())?),
                    start_time: None,
                    end_time: self.request.req_body.till.clone(),
                    renew_till: None,
                    caddr: None,
                    authorization_data: None,
                })?,
            )?,
        };
        let strengthen = EncryptionKey::new(18, vec![0x66; 32]);
        let plain = matches!(tamper, Tamper::DropStrengthenKey | Tamper::NoFast);
        let reply_key = if plain {
            self.subkey.clone()
        } else {
            cf2((&strengthen, b"strengthenkey"), (&self.subkey, b"replykey"))?
        };
        let enc_part = seal(
            &reply_key,
            9,
            &kdc_rep::encode_enc_tgs_rep_part(&EncKdcRepPart {
                key: rasn_kerberos::EncryptionKey {
                    r#type: 18,
                    value: vec![0x77; 32].into(),
                },
                last_req: Vec::new(),
                nonce: self.nonce,
                key_expiration: None,
                flags: TicketFlags(KerberosFlags::from_slice(&[0, 0x60, 0, 0])),
                auth_time: time(whole(SystemTime::now())?),
                start_time: None,
                end_time: self.request.req_body.till.clone(),
                renew_till: None,
                srealm: string(&realm)?,
                sname: service,
                caddr: None,
                encrypted_pa_data: None,
            })?,
        )?;
        let reported = match tamper {
            Tamper::DropStrengthenKey => None,
            Tamper::WrongStrengthenKey => Some(vec![0x67; 32]),
            _ => Some(strengthen.value().to_vec()),
        };
        let response = KrbFastResponse {
            padata: Vec::new(),
            strengthen_key: reported.map(|value| rasn_kerberos::EncryptionKey {
                r#type: 18,
                value: value.into(),
            }),
            finished: (tamper != Tamper::DropFinished)
                .then(|| self.finished(tamper, &ticket))
                .transpose()?,
            nonce: if tamper == Tamper::Nonce {
                self.nonce.wrapping_add(1)
            } else {
                self.nonce
            },
        };
        let mut sealed = seal(&self.armor_key, 52, &der::encode(&response)?)?;
        if tamper == Tamper::ReplyCiphertext {
            flip(&mut sealed)?;
        }
        let outer_padata = match tamper {
            Tamper::NoFast | Tamper::StrippedFast => None,
            _ => Some(vec![pa(
                PA_FX_FAST,
                der::encode(&PaFxFastReply::ArmoredData(KrbFastArmoredRep {
                    enc_fast_rep: sealed,
                }))?,
            )]),
        };
        Ok(der::encode(&TgsRep(KdcRep {
            pvno: Integer::from(5_i32),
            msg_type: Integer::from(13_i32),
            padata: outer_padata,
            crealm: string(&self.client_realm)?,
            cname: if tamper == Tamper::OuterClient {
                name(1, &["mallory"])?
            } else {
                Self::client()?
            },
            ticket,
            enc_part,
        }))?)
    }

    /// The finished message over `ticket`.
    fn finished(&self, tamper: Tamper, ticket: &Ticket) -> Result<KrbFastFinished, TestError> {
        let cipher = etype(&self.armor_key)?;
        let mut value = cipher.checksum(self.armor_key.value(), &der::encode(ticket)?, 53)?;
        if tamper == Tamper::TicketChecksum {
            flip_bytes(&mut value)?;
        }
        Ok(KrbFastFinished {
            timestamp: time(whole(SystemTime::now())?),
            usec: Integer::from(0_i32),
            crealm: string(&self.client_realm)?,
            cname: Self::client()?,
            ticket_checksum: Checksum {
                r#type: if tamper == Tamper::TicketChecksumType {
                    15_i32
                } else {
                    cipher.checksum_type_id()
                },
                checksum: value.into(),
            },
        })
    }

    /// The KRB-ERROR `KDC_ERR_S_PRINCIPAL_UNKNOWN`.
    fn error(&self, e_data: Option<Vec<u8>>) -> Result<KrbError, TestError> {
        let realm = self.realm()?;
        Ok(KrbError {
            pvno: Integer::from(5_i32),
            msg_type: Integer::from(30_i32),
            ctime: None,
            cusec: None,
            stime: time(whole(SystemTime::now())?),
            susec: Integer::from(0_i32),
            error_code: 7,
            crealm: Some(string(&self.client_realm)?),
            cname: Some(Self::client()?),
            realm: string(&realm)?,
            sname: self
                .request
                .req_body
                .sname
                .clone()
                .ok_or("the request names no service")?,
            e_text: None,
            e_data: e_data.map(Into::into),
        })
    }

    /// The error inside the armor.
    fn armored_error(&self, tamper: Tamper) -> Result<Vec<u8>, TestError> {
        let strengthen =
            (tamper == Tamper::ErrorStrengthenKey).then(|| rasn_kerberos::EncryptionKey {
                r#type: 18,
                value: vec![0x44; 32].into(),
            });
        let response = KrbFastResponse {
            padata: vec![pa(PA_FX_ERROR, der::encode(&self.error(None)?)?)],
            strengthen_key: strengthen,
            finished: None,
            nonce: self.nonce,
        };
        let method_data: Vec<PaData> = vec![pa(
            PA_FX_FAST,
            der::encode(&PaFxFastReply::ArmoredData(KrbFastArmoredRep {
                enc_fast_rep: seal(&self.armor_key, 52, &der::encode(&response)?)?,
            }))?,
        )];
        Ok(der::encode(&self.error(Some(der::encode(&method_data)?))?)?)
    }

    /// An error that is not armored.
    fn unarmored_error(&self) -> Result<Vec<u8>, TestError> {
        Ok(der::encode(&self.error(None)?)?)
    }
}
