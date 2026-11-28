//! Keytabs, credentials and the loop that carries the tokens.

use rskrb5_ng::{
    Config,
    client::stepwise::Responder,
    gss::{
        Acceptor, AcceptorOptions, CredStore, Credential, CredentialUsage, EstablishedContext,
        InitStep, InitiatorOptions, Name, NameType,
        iakerb::{AcceptStep, Context, KdcRelay, RelayFailure, RelayPolicy},
    },
    keytab::{self, Keytab},
};

use super::{
    context::{Context as _, TestError},
    kdc::{Kdc, Relay},
    seal::{PASSWORD, REALM, USER, service_key},
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
        responder: None,
        relay: None,
    };
    run(credential, kdc, setup, tamper)
}

/// What a context is established under: the initiator's profile, options and
/// responder, and the acceptor's relay policy and relay.
pub(super) struct Setup<'caller> {
    /// The initiator's profile.
    pub config: Config,
    /// The initiator's options.
    pub options: InitiatorOptions,
    /// The acceptor's relay policy.
    pub policy: RelayPolicy,
    /// The initiator's responder, if any.
    pub responder: Option<&'caller mut dyn Responder>,
    /// The acceptor's relay; `None` relays to the KDC directly.
    pub relay: Option<&'caller mut dyn KdcRelay>,
}

/// Establish a context from `credential` under `setup`, the tokens untouched.
///
/// # Errors
///
/// Returns the first error of either end.
pub(super) fn establish_under(
    credential: &Credential,
    kdc: &Kdc,
    setup: Setup<'_>,
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
        responder: None,
        relay: None,
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
    setup: Setup<'_>,
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
    mut setup: Setup<'_>,
    mut tamper: impl FnMut(usize, Vec<u8>) -> Result<Vec<u8>, TestError>,
) -> Result<(Ends, Wire), TestError> {
    let mut initiator = Context::initiator(&setup.config, target()?, setup.options)?;
    let mut acceptor_context = Context::acceptor(setup.policy);
    let store = Credential::from_keytab(keytab());
    let mut acceptor = Acceptor::new(&store, AcceptorOptions::new())?;
    let mut direct = Relay::new(kdc);
    let relay: &mut dyn KdcRelay = match setup.relay.take() {
        Some(chosen) => chosen,
        None => &mut direct,
    };
    let mut tokens = Vec::new();
    let mut input: Option<Vec<u8>> = None;
    let mut done = false;
    let mut accepted = None;
    for turn in 0..40_usize {
        if done && accepted.is_some() {
            break;
        }
        let step = match setup.responder.as_deref_mut() {
            Some(responder) => initiator.init_sec_context_with_responder(
                credential,
                responder,
                input.as_deref(),
            )?,
            None => initiator.init_sec_context(credential, input.as_deref())?,
        };
        if step == InitStep::Complete(None) {
            done = true;
            continue;
        }
        let (InitStep::Continue(token) | InitStep::Complete(Some(token))) = step else {
            return Err("an unknown initiator step".into());
        };
        tokens.push(token.clone());
        let answer = acceptor_context.accept_sec_context(&mut acceptor, relay, &token)?;
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
    Ok((ends, (tokens, direct.asked)))
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
