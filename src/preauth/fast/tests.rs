//! The MIT encoding vectors of the FAST messages and the round bound.
//!
//! Encodings: MIT krb5 1.22.2 `src/tests/asn.1/reference_encode.out:60-61`
//! (the same bytes are decoded by `krb5_decode_test.c:1024,1032`), built
//! from `ktest.c:586-594` (`ktest_make_sample_fast_response`).

use core::{error::Error, str::from_utf8};

use rasn::der;

use super::{
    ArmorSource, Exchange, MAX_ROUNDS, Policy,
    asn1::{KrbFastResponse, PaFxFastReply},
};
use crate::{
    client::stepwise::{ArmorRequest, ArmoredExchange as _},
    error::Fast,
};

/// MIT `encode_krb5_fast_response`.
const MIT_FAST_RESPONSE: &str = "30 81 9F A0 26 30 24 30 10 A1 03 02 01 0D A2 09 04 07 70 61 2D 64 61 74 61 30 10 A1 03 02 01 0D A2 09 04 07 70 61 2D 64 61 74 61 A1 13 30 11 A0 03 02 01 01 A1 0A 04 08 31 32 33 34 35 36 37 38 A2 5B 30 59 A0 11 18 0F 31 39 39 34 30 36 31 30 30 36 30 33 31 37 5A A1 05 02 03 01 E2 40 A2 10 1B 0E 41 54 48 45 4E 41 2E 4D 49 54 2E 45 44 55 A3 1A 30 18 A0 03 02 01 01 A1 11 30 0F 1B 06 68 66 74 73 61 69 1B 05 65 78 74 72 61 A4 0F 30 0D A0 03 02 01 01 A1 06 04 04 31 32 33 34 A3 03 02 01 2A";
/// MIT `encode_krb5_pa_fx_fast_reply`.
const MIT_PA_FX_FAST_REPLY: &str = "A0 29 30 27 A0 25 30 23 A0 03 02 01 00 A1 03 02 01 05 A2 17 04 15 6B 72 62 41 53 4E 2E 31 20 74 65 73 74 20 6D 65 73 73 61 67 65";

/// Bytes from spaced hex.
fn hex(text: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let digits: Vec<u8> = text.bytes().filter(u8::is_ascii_hexdigit).collect();
    digits
        .chunks(2)
        .map(|pair| Ok(u8::from_str_radix(from_utf8(pair)?, 16)?))
        .collect()
}

/// MIT's sample `KrbFastResponse` decodes to its fields and re-encodes to the same bytes.
#[test]
fn mit_fast_response_encoding_round_trips() -> Result<(), Box<dyn Error>> {
    let bytes = hex(MIT_FAST_RESPONSE)?;
    let response: KrbFastResponse = der::decode(&bytes)?;
    let types: Vec<i32> = response.padata.iter().map(|entry| entry.r#type).collect();
    assert_eq!(types, vec![13_i32, 13_i32], "two sample padata");
    let key = response.strengthen_key.as_ref().ok_or("strengthen key")?;
    assert_eq!(
        (key.r#type, key.value.as_ref()),
        (1_i32, &b"12345678"[..]),
        "the sample keyblock"
    );
    let finished = response.finished.as_ref().ok_or("finished")?;
    assert_eq!(finished.crealm.as_bytes(), b"ATHENA.MIT.EDU", "crealm");
    assert_eq!(
        finished.ticket_checksum.checksum.as_ref(),
        b"1234",
        "checksum"
    );
    assert_eq!(response.nonce, 42, "SAMPLE_NONCE");
    assert_eq!(der::encode(&response)?, bytes, "re-encoding");
    Ok(())
}

/// MIT's sample `PA-FX-FAST-REPLY` decodes to the armored-data alternative.
#[test]
fn mit_pa_fx_fast_reply_encoding_round_trips() -> Result<(), Box<dyn Error>> {
    let bytes = hex(MIT_PA_FX_FAST_REPLY)?;
    let reply: PaFxFastReply = der::decode(&bytes)?;
    let PaFxFastReply::ArmoredData(armored) = &reply;
    assert_eq!(armored.enc_fast_rep.etype, 0_i32, "sample enctype");
    assert_eq!(armored.enc_fast_rep.kvno, Some(5), "sample kvno");
    assert_eq!(
        armored.enc_fast_rep.cipher.as_ref(),
        b"krbASN.1 test message",
        "sample cipher"
    );
    assert_eq!(der::encode(&reply)?, bytes, "re-encoding");
    Ok(())
}

/// A truncated MIT encoding and an unknown CHOICE alternative are refused.
#[test]
fn malformed_fast_encodings_are_refused() -> Result<(), Box<dyn Error>> {
    let bytes = hex(MIT_FAST_RESPONSE)?;
    let shorter = bytes.get(..bytes.len().saturating_sub(1)).ok_or("short")?;
    assert!(
        der::decode::<KrbFastResponse>(shorter).is_err(),
        "truncated"
    );
    let mut unknown = hex(MIT_PA_FX_FAST_REPLY)?;
    *unknown.first_mut().ok_or("empty")? = 0xa1;
    assert!(
        der::decode::<PaFxFastReply>(&unknown).is_err(),
        "unknown alternative"
    );
    Ok(())
}

/// The armored-round bound holds whatever drives the exchange.
#[test]
fn armored_rounds_are_bounded() -> Result<(), Box<dyn Error>> {
    let mut fast = Exchange::new(Policy::Off, ArmorSource::None);
    let request = der::encode(&rasn_kerberos::AsReq(rasn_kerberos::KdcReq {
        pvno: 5_i32.into(),
        msg_type: 10_i32.into(),
        padata: None,
        req_body: rasn_kerberos::KdcReqBody {
            kdc_options: rasn_kerberos::KdcOptions(rasn_kerberos::KerberosFlags::from_slice(
                &[0; 4],
            )),
            cname: None,
            realm: rasn_kerberos::KerberosString::try_from("FAST.TEST".to_owned())?,
            sname: None,
            from: None,
            till: rasn_kerberos::KerberosTime(chrono::DateTime::<chrono::Utc>::UNIX_EPOCH.into()),
            rtime: None,
            nonce: 1,
            etype: vec![18_i32],
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        },
    }))?;
    let armor_request = ArmorRequest {
        request: &request,
        body: &[],
        cookie: None,
        canonicalize: false,
    };
    for _ in 0..MAX_ROUNDS {
        drop(
            fast.armor_request(&armor_request)
                .map_err(|error| error.to_string())?,
        );
    }
    let error = fast
        .armor_request(&armor_request)
        .err()
        .ok_or("unbounded")?;
    assert!(
        matches!(
            error.downcast_ref::<Fast>(),
            Some(Fast::TooManyRounds { limit: MAX_ROUNDS })
        ),
        "{error}"
    );
    Ok(())
}
