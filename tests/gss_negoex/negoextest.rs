//! A test-only Rust implementation of MIT's `negoextest` mechanism protocol.
//!
//! The model is `src/plugins/gssapi/negoextest/main.c` of krb5 1.22.2: a
//! mechanism that passes a hop counter back and forth, offers the one-byte
//! meta-data `X`, and has all-zero AES256-SHA1 keys perturbed so that each side's
//! verify key is the other's checksum key. MIT's environment knobs are fields of
//! [`Knobs`]. It lives in the tests only; the library has no mechanism of its own.

use alloc::sync::Arc;

use rskrb5_ng::{
    extensions::GssMechanism,
    gss::negoex::{
        AuthScheme, Mechanism, MechanismStep, ProviderFailure, Request, Role, Session, VerifyKeys,
    },
    keytab::EncryptionKey,
};

/// `2.25.1414534758` as DER content octets; the final octet is 102 (0x66).
pub(super) const OID_FIRST: [u8; 6] = [0x69, 0x85, 0xa2, 0xc0, 0xac, 0x66];
/// `2.25.1175737388` as DER content octets; the final octet is 44 (0x2c).
pub(super) const OID_SECOND: [u8; 6] = [0x69, 0x84, 0xb0, 0xd1, 0xa8, 0x2c];
/// The AES256-CTS-HMAC-SHA1-96 encryption type of the mechanism's keys.
const ETYPE_AES256: i32 = 18;

/// When the mechanism's keys are available (MIT's `KEY` variable).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum KeyPolicy {
    /// Only once the context is established (the default).
    Established,
    /// Always.
    Always,
    /// Always for the initiator.
    InitAlways,
    /// Always for the acceptor.
    AcceptAlways,
    /// Never.
    Never,
}

/// MIT's environment knobs; each octet names a mechanism by its OID's last octet.
#[derive(Clone, Debug)]
pub(super) struct Knobs {
    /// `HOPS`: the hops an initiator asks for.
    pub hops: u8,
    /// `KEY`.
    pub key: KeyPolicy,
    /// `INIT_FAIL`.
    pub init_fail: Option<u8>,
    /// `ACCEPT_FAIL`.
    pub accept_fail: Option<u8>,
    /// `INIT_QUERY_FAIL`.
    pub init_query_fail: Option<u8>,
    /// `ACCEPT_QUERY_FAIL`.
    pub accept_query_fail: Option<u8>,
    /// `INIT_QUERY_NONE`: the mechanism offers no meta-data.
    pub init_query_none: Option<u8>,
    /// `ACCEPT_QUERY_NONE`.
    pub accept_query_none: Option<u8>,
    /// `INIT_EXCHANGE_FAIL`.
    pub init_exchange_fail: Option<u8>,
    /// `ACCEPT_EXCHANGE_FAIL`.
    pub accept_exchange_fail: Option<u8>,
    /// `GSS_INIT_BINDING` or `GSS_ACCEPT_BINDING`: the application data expected.
    pub binding: Option<Vec<u8>>,
    /// The encryption type of the keys (MIT's mechanism always uses AES256).
    pub etype: i32,
}

impl Default for Knobs {
    fn default() -> Self {
        Self {
            hops: 1,
            key: KeyPolicy::Established,
            init_fail: None,
            accept_fail: None,
            init_query_fail: None,
            accept_query_fail: None,
            init_query_none: None,
            accept_query_none: None,
            init_exchange_fail: None,
            accept_exchange_fail: None,
            binding: None,
            etype: ETYPE_AES256,
        }
    }
}

/// One `negoextest` mechanism.
pub(super) struct TestMechanism {
    /// Its object identifier, DER content octets.
    oid: Vec<u8>,
    /// The knobs of this end.
    knobs: Knobs,
}

impl TestMechanism {
    /// The mechanism of `oid` with `knobs`.
    pub(super) fn shared(oid: &[u8], knobs: Knobs) -> Arc<dyn Mechanism> {
        Arc::new(Self {
            oid: oid.to_vec(),
            knobs,
        })
    }
}

impl Mechanism for TestMechanism {
    fn oid(&self) -> &[u8] {
        &self.oid
    }

    /// The OID encoding right-padded with zeros (`gssspi_query_mechanism_info`).
    fn auth_scheme(&self) -> AuthScheme {
        let mut bytes = [0_u8; 16];
        for (target, source) in bytes.iter_mut().zip(&self.oid) {
            *target = *source;
        }
        AuthScheme::from_bytes(bytes)
    }

    fn session(&self, role: Role) -> Box<dyn Session> {
        Box::new(TestSession {
            role,
            oid: self.oid.clone(),
            knobs: self.knobs.clone(),
            context: None,
        })
    }
}

/// The registry entry for a mechanism of `oid`.
pub(super) struct Registered {
    /// Its unique id.
    pub id: String,
    /// Its object identifier.
    pub oid: Vec<u8>,
}

impl GssMechanism for Registered {
    fn id(&self) -> &str {
        &self.id
    }

    fn oid(&self) -> &[u8] {
        &self.oid
    }
}

/// MIT's `struct test_context`.
struct Context {
    /// Whether this is the initiator.
    initiator: bool,
    /// The hops remaining; 0 means established.
    hops: u8,
}

/// One negotiation of a `negoextest` mechanism.
struct TestSession {
    /// This end.
    role: Role,
    /// The mechanism's OID.
    oid: Vec<u8>,
    /// The knobs.
    knobs: Knobs,
    /// The mechanism context, once a step ran.
    context: Option<Context>,
}

impl TestSession {
    /// The last octet of the OID, which the knobs name mechanisms by.
    fn last(&self) -> Option<u8> {
        self.oid.last().copied()
    }

    /// Whether `knob` names this mechanism.
    fn named(&self, knob: Option<u8>) -> bool {
        knob.is_some() && knob == self.last()
    }

    /// Check the channel bindings against the knob.
    fn check_binding(&self, request: &Request) -> Result<(), ProviderFailure> {
        let Some(expected) = &self.knobs.binding else {
            return Ok(());
        };
        match request.bindings() {
            Some(bindings) if bindings.application_data() == expected.as_slice() => Ok(()),
            Some(_) | None => Err(ProviderFailure::new("channel bindings do not match")),
        }
    }

    /// `gss_encapsulate_token` of one byte (RFC 2743 3.1).
    fn encapsulate(&self, byte: u8) -> Vec<u8> {
        let inner_len = self.oid.len().saturating_add(3);
        let mut token = vec![0x60, u8::try_from(inner_len).unwrap_or(0), 0x06];
        token.push(u8::try_from(self.oid.len()).unwrap_or(0));
        token.extend_from_slice(&self.oid);
        token.push(byte);
        token
    }

    /// The step result for the hops left.
    fn outcome(&self, output: Option<Vec<u8>>) -> MechanismStep {
        if self.context.as_ref().is_some_and(|context| context.hops > 0) {
            MechanismStep::continue_needed(output)
        } else {
            MechanismStep::complete(output)
        }
    }

    /// The key `GSS_C_INQ_NEGOEX_KEY` (`verify` false) or `_VERIFY_KEY` returns.
    fn key(&self, verify: bool) -> Option<EncryptionKey> {
        let context = self.context.as_ref()?;
        if self.knobs.key == KeyPolicy::Never {
            return None;
        }
        if context.hops > 0 {
            let available = match self.knobs.key {
                KeyPolicy::Always => true,
                KeyPolicy::InitAlways => context.initiator,
                KeyPolicy::AcceptAlways => !context.initiator,
                KeyPolicy::Established | KeyPolicy::Never => false,
            };
            if !available {
                return None;
            }
        }
        let mut bytes = vec![0_u8; 32];
        *bytes.first_mut()? = u8::from(verify) ^ u8::from(context.initiator);
        Some(EncryptionKey::new(self.knobs.etype, bytes))
    }
}

impl Session for TestSession {
    fn query_meta_data(&mut self, _request: &Request) -> Result<Vec<u8>, ProviderFailure> {
        let (fail, none) = if matches!(self.role, Role::Initiator) {
            (self.knobs.init_query_fail, self.knobs.init_query_none)
        } else {
            (self.knobs.accept_query_fail, self.knobs.accept_query_none)
        };
        if self.named(fail) {
            return Err(ProviderFailure::new("query failed"));
        }
        if self.named(none) {
            return Ok(Vec::new());
        }
        Ok(b"X".to_vec())
    }

    fn exchange_meta_data(
        &mut self,
        _request: &Request,
        metadata: &[u8],
    ) -> Result<(), ProviderFailure> {
        let fail = if matches!(self.role, Role::Initiator) {
            self.knobs.init_exchange_fail
        } else {
            self.knobs.accept_exchange_fail
        };
        if self.named(fail) {
            return Err(ProviderFailure::new("exchange failed"));
        }
        if metadata == b"X" {
            Ok(())
        } else {
            Err(ProviderFailure::new("unexpected meta-data"))
        }
    }

    fn init_sec_context(
        &mut self,
        request: &Request,
        input: Option<&[u8]>,
    ) -> Result<MechanismStep, ProviderFailure> {
        self.check_binding(request)?;
        let hops = match input {
            None => self.knobs.hops,
            Some(b"fail") => return Err(ProviderFailure::new("failure from acceptor")),
            Some(token) => *token
                .first()
                .ok_or_else(|| ProviderFailure::new("empty token"))?,
        };
        if self.named(self.knobs.init_fail) {
            return Err(ProviderFailure::new("initiator failure"));
        }
        match self.context.as_mut() {
            None => {
                self.context = Some(Context {
                    initiator: true,
                    hops,
                });
            }
            Some(context) => {
                context.hops = context.hops.saturating_sub(1);
                if context.hops != hops {
                    return Err(ProviderFailure::new("unexpected hop count"));
                }
            }
        }
        let output = match self.context.as_mut() {
            Some(context) if context.hops > 0 => {
                context.hops = context.hops.saturating_sub(1);
                Some(context.hops)
            }
            Some(_) | None => None,
        };
        let token = output.map(|byte| self.encapsulate(byte));
        Ok(self.outcome(token))
    }

    fn accept_sec_context(
        &mut self,
        request: &Request,
        input: &[u8],
    ) -> Result<MechanismStep, ProviderFailure> {
        self.check_binding(request)?;
        let [.., last_octet, hops] = *input else {
            return Err(ProviderFailure::new("token too short"));
        };
        if self.named(self.knobs.accept_fail) && Some(last_octet) == self.last() {
            return Err(ProviderFailure::new("acceptor failure").with_output_token(b"fail".to_vec()));
        }
        match self.context.as_mut() {
            None => {
                self.context = Some(Context {
                    initiator: false,
                    hops,
                });
            }
            Some(context) => {
                context.hops = context.hops.saturating_sub(1);
                if context.hops != hops {
                    return Err(ProviderFailure::new("unexpected hop count"));
                }
            }
        }
        let output = match self.context.as_mut() {
            Some(context) if context.hops > 0 => {
                context.hops = context.hops.saturating_sub(1);
                Some(vec![context.hops])
            }
            Some(_) | None => None,
        };
        Ok(self.outcome(output))
    }

    fn keys(&self) -> VerifyKeys {
        let mut keys = VerifyKeys::none();
        if let Some(key) = self.key(false) {
            keys = keys.with_checksum_key(key);
        }
        if let Some(key) = self.key(true) {
            keys = keys.with_verify_key(key);
        }
        keys
    }
}
