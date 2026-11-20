//! What an armor sends passes the outgoing padata admission.
//!
//! `PA-FX-FAST` and `PA-ENCRYPTED-CHALLENGE` are decoded and their enctypes checked
//! before the request leaves the engine.

use core::error::Error as _;
use std::time::SystemTime;

use rasn::der;
use rasn_kerberos::{Checksum, EncryptedData, PaData};
use rskrb5_ng::{
    client::{
        Password,
        options::AsReq,
        principal::Principal,
        stepwise::{
            ArmorRequest, ArmoredExchange, ArmoredReply, InitCreds, InitCredsOptions, StepInput,
        },
    },
    error::{Client as ClientError, Policy},
    extensions::ProviderError,
    preauth::fast::{PA_ENCRYPTED_CHALLENGE, PA_FX_FAST},
};
use zeroize::Zeroizing;

use super::{
    asn1::{KrbFastArmoredReq, PaFxFastRequest},
    kdc::{CLIENT, REALM, TestError},
};

/// An armor that replaces the request's padata with `padata`.
struct Replacing(Vec<PaData>);

impl ArmoredExchange for Replacing {
    fn armor_request(
        &mut self,
        request: &ArmorRequest<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        let rasn_kerberos::AsReq(mut message) = der::decode(request.request)?;
        message.padata = Some(self.0.clone());
        Ok(Zeroizing::new(der::encode(&rasn_kerberos::AsReq(message))?))
    }

    fn unwrap_reply(&mut self, _reply: &[u8]) -> Result<ArmoredReply, ProviderError> {
        Err("no reply expected".into())
    }
}

/// The first step of an exchange armored by `padata`.
fn first_step(padata: Vec<PaData>) -> Result<(), ClientError> {
    let request = AsReq::new(SystemTime::now(), 7).with_etypes(vec![18_i32]);
    let mut exchange = InitCreds::with_password(
        Principal::user(REALM, CLIENT),
        Some(Password::from_vec(b"secret".to_vec())),
        InitCredsOptions::new(request),
    )
    .with_armor(Replacing(padata));
    exchange.step(StepInput::Start).map(drop)
}

/// A `PA-FX-FAST` whose inner request is encrypted in `etype`.
fn fast_padata(etype: i32) -> Result<Vec<PaData>, TestError> {
    let armored = PaFxFastRequest::ArmoredData(KrbFastArmoredReq {
        armor: None,
        req_checksum: Checksum {
            r#type: 16,
            checksum: vec![0; 12].into(),
        },
        enc_fast_req: EncryptedData {
            etype,
            kvno: None,
            cipher: vec![0x47; 48].into(),
        },
    });
    Ok(vec![PaData {
        r#type: PA_FX_FAST,
        value: der::encode(&armored)?.into(),
    }])
}

/// The policy cause of an exchange error.
fn refused_enctype(error: &ClientError) -> Option<i32> {
    let mut source = error.source();
    while let Some(current) = source {
        if let Some(Policy::EnctypeNotPermitted { etype, usage: _ }) =
            current.downcast_ref::<Policy>()
        {
            return Some(*etype);
        }
        source = current.source();
    }
    None
}

/// An armored request whose `PA-FX-FAST` is not one is refused before it is sent.
#[test]
fn malformed_armor_output_is_refused() {
    let garbage = vec![PaData {
        r#type: PA_FX_FAST,
        value: vec![0x47; 32].into(),
    }];
    assert!(
        first_step(garbage).is_err(),
        "garbage PA-FX-FAST reached the transport"
    );
    let challenge = vec![PaData {
        r#type: PA_ENCRYPTED_CHALLENGE,
        value: vec![0x47; 32].into(),
    }];
    assert!(
        first_step(challenge).is_err(),
        "garbage challenge reached the transport"
    );
}

/// The armor key's enctype and the challenge's enctype are policy-checked.
#[test]
fn armor_output_enctypes_are_policy_checked() -> Result<(), TestError> {
    first_step(fast_padata(18)?)?;
    let error = first_step(fast_padata(23)?)
        .err()
        .ok_or("RC4 armor admitted")?;
    assert_eq!(refused_enctype(&error), Some(23_i32), "{error}");
    let challenge = vec![PaData {
        r#type: PA_ENCRYPTED_CHALLENGE,
        value: der::encode(&EncryptedData {
            etype: 23,
            kvno: None,
            cipher: vec![0x47; 48].into(),
        })?
        .into(),
    }];
    let refused = first_step(challenge)
        .err()
        .ok_or("RC4 challenge admitted")?;
    assert_eq!(refused_enctype(&refused), Some(23_i32), "{refused}");
    Ok(())
}
