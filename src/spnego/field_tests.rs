//! SPNEGO sequence field cardinality and ordering regressions.

use super::{Error, NegTokenInit, NegTokenResp, der::encode_tlv};

/// Both codec boundaries enforce BIT STRING unused-bit and padding rules.
#[test]
fn req_flags_reject_malformed_bit_strings() -> Result<(), Error> {
    for (contents, valid) in [
        (vec![], false),
        (vec![8], false),
        (vec![1], false),
        (vec![1, 1], false),
        (vec![0], true),
        (vec![1, 0x80], true),
    ] {
        let fields = [
            vec![0xa0, 5, 0x30, 3, 6, 1, 0x2a],
            encode_tlv(0xa1, &encode_tlv(3, &contents)),
        ]
        .concat();
        let decoded = NegTokenInit::decode(&encode_tlv(0xa0, &encode_tlv(0x30, &fields)));
        assert_eq!(decoded.is_ok(), valid);
        if valid {
            drop(decoded?);
        }
        let mut token = NegTokenInit::krb5(vec![1]);
        token.set_req_flags(Some(contents));
        assert_eq!(token.encode().is_ok(), valid);
    }
    Ok(())
}

/// Diagnostic formatting never emits MIC or Wrap application plaintext.
#[test]
fn payload_debug_is_redacted() -> Result<(), Error> {
    use super::{MicToken, WrapToken};
    let payload = b"sensitive-payload-marker".to_vec();
    let bytes = format!("{payload:?}");
    assert!(!format!("{:?}", MicToken::new(0, 1).with_payload(payload.clone())).contains(&bytes));
    (!format!("{:?}", WrapToken::new(0, 1).with_payload(payload)).contains(&bytes))
        .ok_or(Error::InvalidGssFiller)
}

/// Verification has one success state rather than an unreachable false result.
#[test]
fn verification_returns_unit() -> Result<(), Error> {
    use super::{GSSAPI_INITIATOR_SEAL_USAGE, GSSAPI_INITIATOR_SIGN_USAGE, MicToken, WrapToken};
    use crate::keytab::EncryptionKey;
    let key = EncryptionKey::new(17, vec![0x42; 16]);
    let mic = MicToken::new_initiator(vec![1], &key)?;
    let wrap = WrapToken::new_initiator(vec![1], &key)?;
    let mic_result: Result<(), Error> = mic.verify(&key, GSSAPI_INITIATOR_SIGN_USAGE);
    mic_result?;
    wrap.verify(&key, GSSAPI_INITIATOR_SEAL_USAGE)
}

/// Failed sealing preserves every field of an existing unsealed token.
#[test]
fn failed_sealing_preserves_token() -> Result<(), Error> {
    use super::{GSSAPI_INITIATOR_SEAL_USAGE, WrapToken};
    use crate::keytab::EncryptionKey;
    for key in [
        EncryptionKey::new(999, vec![0; 16]),
        EncryptionKey::new(17, vec![0; 16]),
    ] {
        // Given an unsealed token with caller-supplied metadata and a checksum.
        let mut token = WrapToken::new(1, 42)
            .with_payload(vec![1, 2])
            .with_ec(12)
            .with_rrc(9)
            .with_checksum(Some(vec![7; 12]));
        let original = token.clone();
        let original_wire = original.encode()?;
        // When sealing fails on an unsupported enctype or invalid confounder.
        assert!(matches!(
            token.encrypt_payload_with_confounder(&key, GSSAPI_INITIATOR_SEAL_USAGE, &[]),
            Err(Error::UnsupportedEtype(999_i32) | Error::Crypto(_))
        ));
        // Then the caller can retry without a partially committed sealed state.
        assert_eq!(token, original);
        assert_eq!(token.encode()?, original_wire);
    }
    Ok(())
}

/// AP-REQ construction failures retain their typed client cause.
#[test]
fn client_error_preserves_source() -> Result<(), Error> {
    use core::error::Error as _;

    use crate::error::Client;
    // Given a client-domain failure without a SPNEGO-specific equivalent.
    let error = super::client_error_to_spnego(Client::EmptyEtypes);
    // When traversing the source chain, then the original variant is available.
    matches!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<Box<Client>>())
            .map(AsRef::as_ref),
        Some(Client::EmptyEtypes)
    )
    .ok_or(Error::MissingMechToken)
}

/// Framed extensions preserve known fields; truncated extensions still fail.
#[test]
fn sequences_accept_framed_extensions() -> Result<(), Error> {
    // Given known fields followed by an unknown extension-region field.
    let init_fields = vec![0xa0, 5, 0x30, 3, 6, 1, 0x2a];
    let resp_fields = vec![0xa0, 3, 0x0a, 1, 0];
    let extension = [0xa4, 2, 5, 0];
    let init_wire = encode_tlv(
        0xa0,
        &encode_tlv(0x30, &[init_fields.as_slice(), &extension].concat()),
    );
    let resp_wire = encode_tlv(
        0xa1,
        &encode_tlv(0x30, &[resp_fields.as_slice(), &extension].concat()),
    );
    // When parsed, then the extension does not change the known token fields.
    assert_eq!(
        NegTokenInit::decode(&init_wire)?,
        NegTokenInit::decode(&encode_tlv(0xa0, &encode_tlv(0x30, &init_fields)))?
    );
    assert_eq!(
        NegTokenResp::decode(&resp_wire)?,
        NegTokenResp::decode(&encode_tlv(0xa1, &encode_tlv(0x30, &resp_fields)))?
    );
    for (tag, fields) in [(0xa0, init_fields), (0xa1, resp_fields)] {
        let truncated = encode_tlv(
            tag,
            &encode_tlv(0x30, &[fields.as_slice(), &[0xa4, 3, 5, 0]].concat()),
        );
        let result = if tag == 0xa0 {
            NegTokenInit::decode(&truncated).map(|_| ())
        } else {
            NegTokenResp::decode(&truncated).map(|_| ())
        };
        assert!(matches!(result, Err(Error::LengthExceedsInput)));
    }
    Ok(())
}

/// Duplicate fields and adjacent reversals must fail for both negotiation choices.
#[test]
fn sequences_reject_duplicate_and_reordered_fields() -> Result<(), Error> {
    for (tag, fields) in [
        (
            0xa0,
            vec![
                vec![0xa0, 4, 0x30, 2, 6, 0],
                vec![0xa1, 3, 3, 1, 0],
                vec![0xa2, 2, 4, 0],
                vec![0xa3, 2, 4, 0],
            ],
        ),
        (
            0xa1,
            vec![
                vec![0xa0, 3, 0x0a, 1, 0],
                vec![0xa1, 3, 6, 1, 0x2a],
                vec![0xa2, 2, 4, 0],
                vec![0xa3, 2, 4, 0],
            ],
        ),
    ] {
        let mut valid = fields;
        if tag == 0xa0 {
            *valid.first_mut().ok_or(Error::TruncatedDer)? = vec![0xa0, 5, 0x30, 3, 6, 1, 0x2a];
        }
        for index in 0..4 {
            // Given a valid sequence with one known field repeated.
            let mut duplicate = valid.clone();
            duplicate.insert(index, valid.get(index).ok_or(Error::TruncatedDer)?.clone());
            // When decoded, then the duplicate cannot overwrite its predecessor.
            assert!(decode_fields(tag, &duplicate).is_err());
        }
        for index in 0_usize..3 {
            // Given a valid sequence with adjacent fields reversed.
            let mut reversed = valid.clone();
            reversed.swap(index, index.saturating_add(1));
            // When decoded, then ordering is enforced independently of payload processing.
            assert!(decode_fields(tag, &reversed).is_err());
        }
        decode_fields(tag, &valid)?;
        for field in valid.iter().skip(1) {
            let subset = if tag == 0xa0 {
                vec![
                    valid.first().ok_or(Error::TruncatedDer)?.clone(),
                    field.clone(),
                ]
            } else {
                vec![field.clone()]
            };
            decode_fields(tag, &subset)?;
        }
    }
    Ok(())
}

/// Decode independent field encodings through the public token boundary.
fn decode_fields(tag: u8, fields: &[Vec<u8>]) -> Result<(), Error> {
    let wire = encode_tlv(tag, &encode_tlv(0x30, &fields.concat()));
    if tag == 0xa0 {
        drop(NegTokenInit::decode(&wire)?);
    } else {
        drop(NegTokenResp::decode(&wire)?);
    }
    Ok(())
}
