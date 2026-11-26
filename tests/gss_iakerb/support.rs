//! Keytabs, credentials, tickets and the loop that carries the tokens.

use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use rasn::{Encoder as _, der};
use rskrb5_ng::{
    Config,
    client::{TgsRepSession, build_ap_req_with_confounder, options::ApReq, principal::Principal},
    crypto::AesSha1Etype,
    gss::{
        Acceptor, AcceptorOptions, CredStore, Credential, CredentialUsage, EstablishedContext,
        InitStep, InitiatorOptions, Name, NameType,
        iakerb::{AcceptStep, Context, KdcRelay, RelayFailure, RelayPolicy},
    },
    keytab::{self, Keytab},
    spnego::{Krb5MechToken, oid::ObjectIdentifier},
};
use zeroize::Zeroizing;

use super::{
    context::{Context as _, TestError},
    kdc::{self, Kdc, Relay},
    seal::{self, PASSWORD, REALM, USER, service_key},
};

/// The host of the service.
pub(super) const HOST: &str = "www.example.com";

/// A profile with the realm and nothing else.
pub(super) fn config() -> Result<Config, TestError> {
    Ok(Config::parse(&format!(
        "[libdefaults]\n default_realm = {REALM}\n dns_lookup_kdc = false\n dns_lookup_realm = false\n"
    ))?)
}

/// The host-based GSS name `HTTP@<host>`.
pub(super) fn target() -> Result<Name, TestError> {
    Name::import(
        format!("HTTP@{HOST}").as_bytes(),
        NameType::HostbasedService,
    )
    .context("host-based name imports")
}

/// A keytab with the `HTTP/<host>` key.
pub(super) fn keytab() -> Keytab {
    let mut keytab = Keytab::new();
    keytab.entries_mut().push(keytab::Entry::new(
        keytab::Principal::new(REALM, 3, ["HTTP", HOST]),
        0,
        1,
        service_key(HOST),
        1,
    ));
    keytab
}

/// The initiator credential of the user's password; `realm` names the client
/// in its realm, or without one (realm discovery).
pub(super) fn password_credential(realm: bool) -> Result<Credential, TestError> {
    let text = if realm {
        format!("{USER}@{REALM}")
    } else {
        USER.to_owned()
    };
    let name = Name::import(text.as_bytes(), NameType::User)?;
    let password = String::from_utf8(PASSWORD.to_vec())?;
    Ok(Credential::acquire_cred_from(
        Some(&name),
        CredentialUsage::Initiate,
        &CredStore::new().with("password", &password)?,
    )?)
}

/// The two ends of one context and the tokens that went on the wire.
#[derive(Debug)]
pub(super) struct Pair {
    /// The initiator's context.
    pub initiator: EstablishedContext,
    /// The acceptor's context.
    pub acceptor: EstablishedContext,
    /// Every token, initiator to acceptor first, in order of travel.
    pub tokens: Vec<Vec<u8>>,
    /// The requests the relay carried.
    pub relayed: Vec<(String, Vec<u8>)>,
}

/// The acceptor's policy: the realm only.
pub(super) fn policy() -> Result<RelayPolicy, TestError> {
    Ok(RelayPolicy::new(REALM)?)
}

/// Establish a context from `credential` for `HTTP@<host>`, the acceptor
/// relaying to `kdc` under `policy`; `tamper` may change each token that goes
/// to the initiator.
///
/// # Errors
///
/// Returns the first error of either end.
pub(super) fn establish_with(
    credential: &Credential,
    kdc: &Kdc,
    policy: RelayPolicy,
    tamper: impl FnMut(usize, Vec<u8>) -> Result<Vec<u8>, TestError>,
) -> Result<Pair, TestError> {
    let setup = Setup {
        config: config()?,
        options: InitiatorOptions::new(),
        policy,
    };
    run(credential, kdc, setup, tamper)
}

/// What a context is established under: the initiator's profile and options
/// and the acceptor's relay policy.
pub(super) struct Setup {
    /// The initiator's profile.
    pub config: Config,
    /// The initiator's options.
    pub options: InitiatorOptions,
    /// The acceptor's relay policy.
    pub policy: RelayPolicy,
}

/// Establish a context from `credential` under `setup`, the tokens untouched.
///
/// # Errors
///
/// Returns the first error of either end.
pub(super) fn establish_under(
    credential: &Credential,
    kdc: &Kdc,
    setup: Setup,
) -> Result<Pair, TestError> {
    run(credential, kdc, setup, |_turn, token| Ok(token))
}

/// The ends of one context: the initiator's IAKERB context, established, and
/// the acceptor's established context.
#[derive(Debug)]
pub(super) struct Ends {
    /// The initiator's IAKERB context.
    pub initiator: Context,
    /// The acceptor's context.
    pub acceptor: EstablishedContext,
}

/// Establish a context from `credential` for `HTTP@<host>` and keep the
/// initiator's IAKERB context.
///
/// # Errors
///
/// Returns the first error of either end.
pub(super) fn establish_ends(credential: &Credential, kdc: &Kdc) -> Result<Ends, TestError> {
    let setup = Setup {
        config: config()?,
        options: InitiatorOptions::new(),
        policy: policy()?,
    };
    let (ends, _wire) = exchange(credential, kdc, setup, |_turn, token| Ok(token))?;
    Ok(ends)
}

/// [`exchange`] with the initiator's context taken.
///
/// # Errors
///
/// Returns the first error of either end.
fn run(
    credential: &Credential,
    kdc: &Kdc,
    setup: Setup,
    tamper: impl FnMut(usize, Vec<u8>) -> Result<Vec<u8>, TestError>,
) -> Result<Pair, TestError> {
    let (ends, (tokens, relayed)) = exchange(credential, kdc, setup, tamper)?;
    Ok(Pair {
        initiator: ends.initiator.into_established()?,
        acceptor: ends.acceptor,
        tokens,
        relayed,
    })
}

/// What went on the wire: the tokens in order of travel, and the requests the
/// relay carried.
type Wire = (Vec<Vec<u8>>, Vec<(String, Vec<u8>)>);

/// The token loop of [`establish_with`], [`establish_under`] and
/// [`establish_ends`].
///
/// # Errors
///
/// Returns the first error of either end.
fn exchange(
    credential: &Credential,
    kdc: &Kdc,
    setup: Setup,
    mut tamper: impl FnMut(usize, Vec<u8>) -> Result<Vec<u8>, TestError>,
) -> Result<(Ends, Wire), TestError> {
    let mut initiator = Context::initiator(&setup.config, target()?, setup.options)?;
    let mut acceptor_context = Context::acceptor(setup.policy);
    let store = Credential::from_keytab(keytab());
    let mut acceptor = Acceptor::new(&store, AcceptorOptions::new())?;
    let mut relay = Relay::new(kdc);
    let mut tokens = Vec::new();
    let mut input: Option<Vec<u8>> = None;
    let mut done = false;
    let mut accepted = None;
    for turn in 0..40_usize {
        if done && accepted.is_some() {
            break;
        }
        let step = initiator.init_sec_context(credential, input.as_deref())?;
        if step == InitStep::Complete(None) {
            done = true;
            continue;
        }
        let (InitStep::Continue(token) | InitStep::Complete(Some(token))) = step else {
            return Err("an unknown initiator step".into());
        };
        tokens.push(token.clone());
        let answer = acceptor_context.accept_sec_context(&mut acceptor, &mut relay, &token)?;
        if let AcceptStep::Continue(reply) = answer {
            tokens.push(reply.clone());
            input = Some(tamper(turn, reply)?);
            continue;
        }
        let AcceptStep::Complete(established) = answer else {
            return Err("an unknown acceptor step".into());
        };
        let last = established.output_token().map(<[u8]>::to_vec);
        accepted = Some(established);
        if let Some(bytes) = last {
            tokens.push(bytes.clone());
            input = Some(bytes);
        } else {
            done = true;
        }
    }
    let finished = accepted.context("the acceptor accepted a context")?;
    let ends = Ends {
        initiator,
        acceptor: finished.into_context(),
    };
    Ok((ends, (tokens, relay.asked)))
}

/// `establish_with`, the tokens untouched.
///
/// # Errors
///
/// Returns the first error of either end.
pub(super) fn establish(credential: &Credential, kdc: &Kdc) -> Result<Pair, TestError> {
    establish_with(credential, kdc, policy()?, |_turn, token| Ok(token))
}

/// A relay that must never be called.
#[derive(Debug, Default)]
pub(super) struct NoRelay {
    /// How often it was called.
    pub calls: usize,
}

impl KdcRelay for NoRelay {
    fn relay(&mut self, _realm: &str, _request: &[u8]) -> Result<Vec<u8>, RelayFailure> {
        self.calls = self.calls.saturating_add(1);
        Err(RelayFailure::Other("no relay".to_owned()))
    }
}

/// The user's service ticket for `HTTP/<host>`, sealed in the service key.
///
/// # Errors
///
/// Returns the fixture errors.
pub(super) fn ticket() -> Result<TgsRepSession, TestError> {
    let now = SystemTime::now();
    let start = whole(now.checked_sub(Duration::from_mins(1)).context("start")?)?;
    let end = whole(now.checked_add(Duration::from_hours(1)).context("end")?)?;
    let session = keytab::EncryptionKey::new(18, vec![0x5a; 32]);
    let der = seal::service_ticket(&session, (start, end))?;
    Ok(TgsRepSession::new(
        kdc::client(),
        Principal::new(REALM, 3, ["HTTP", HOST]),
        session,
        Zeroizing::new(der),
        [0x40, 0, 0, 0],
        start,
        end,
    ))
}

/// Whole seconds of `at`.
fn whole(at: SystemTime) -> Result<SystemTime, TestError> {
    let seconds = at.duration_since(UNIX_EPOCH)?.as_secs();
    UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .context("time is representable")
}

/// The subkey the hand-built AP-REQs of [`ap_req_token`] carry.
pub(super) fn subkey() -> keytab::EncryptionKey {
    keytab::EncryptionKey::new(18, vec![0x77; 32])
}

/// An IAKERB AP-REQ token of the user for `HTTP/<host>`, built here, not by the crate.
///
/// The layout is RFC 4121's checksum and MIT's extension framing
/// (`init_sec_context.c:341-345`: a big-endian type and length): the
/// authenticator's checksum carries `extension` (an `IAKERB-FINISHED`) when given.
///
/// # Errors
///
/// Returns the fixture errors.
pub(super) fn ap_req_token(extension: Option<&[u8]>) -> Result<Vec<u8>, TestError> {
    framed(&Context::mechanism(), ap_req_der(extension)?)
}

/// `der` in the RFC 2743 frame of `mechanism` with the AP-REQ token id.
///
/// # Errors
///
/// Returns the encoding errors.
pub(super) fn framed(mechanism: &ObjectIdentifier, der: Vec<u8>) -> Result<Vec<u8>, TestError> {
    let mut token = Krb5MechToken::ap_req(der);
    token.set_oid(mechanism.clone());
    Ok(token.encode()?)
}

/// The DER AP-REQ of [`ap_req_token`], without a frame.
///
/// # Errors
///
/// Returns the fixture errors.
pub(super) fn ap_req_der(extension: Option<&[u8]>) -> Result<Vec<u8>, TestError> {
    let mut checksum = 16_u32.to_le_bytes().to_vec();
    checksum.extend_from_slice(&[0; 16]);
    checksum.extend_from_slice(&0x32_u32.to_le_bytes());
    if let Some(finished) = extension {
        checksum.extend_from_slice(&2_u32.to_be_bytes());
        checksum.extend_from_slice(&u32::try_from(finished.len())?.to_be_bytes());
        checksum.extend_from_slice(finished);
    }
    let options = ApReq::new()
        .with_ap_option_bits(0x2000_0000)
        .with_checksum(Some(rasn_kerberos::Checksum {
            r#type: 0x8003,
            checksum: checksum.into(),
        }))
        .with_subkey(Some(subkey()))
        .with_sequence_number(Some(0x1234));
    let now = whole(SystemTime::now())?;
    let built = build_ap_req_with_confounder(&ticket()?, options, now, 7, &[0x21; 16])?;
    Ok(built.der().to_vec())
}

/// The `IAKERB-FINISHED` of `transcript` under `key`, derived here, not by the crate.
///
/// The checksum type and key usage are MIT's (`iakerb.c:141`: usage 41), the
/// layout the ASN.1 module's (`asn1_k_encode.c:1102-1107`) and RFC 3961's.
///
/// # Errors
///
/// Returns the fixture errors.
pub(super) fn finished(
    key: &keytab::EncryptionKey,
    transcript: &[u8],
) -> Result<Vec<u8>, TestError> {
    /// `IAKERB-FINISHED ::= SEQUENCE { checksum [1] Checksum }`.
    #[derive(rasn::AsnType, rasn::Encode)]
    struct Finished {
        /// The checksum of the transcript.
        #[rasn(tag(explicit(1)))]
        checksum: rasn_kerberos::Checksum,
    }
    let sum = AesSha1Etype::from_etype_id(key.etype())
        .context("AES")?
        .checksum(key.value(), transcript, 41)?;
    Ok(der::encode(&Finished {
        checksum: rasn_kerberos::Checksum {
            r#type: 16,
            checksum: sum.into(),
        },
    })?)
}
