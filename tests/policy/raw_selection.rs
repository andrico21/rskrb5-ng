#[cfg(feature = "spnego")]
extern crate alloc;

use core::error::Error;

use rskrb5_ng::{
    error::{Policy, RejectedFeature},
    keytab::EncryptionKey,
    krb_priv, krb_safe,
};

fn policy_cause<'error>(mut error: &'error (dyn Error + 'static)) -> Option<&'error Policy> {
    loop {
        if let Some(policy) = error.downcast_ref::<Policy>() {
            return Some(policy);
        }
        error = error.source()?;
    }
}

/// Raw message encryption refuses D2 algorithms before examining key material.
#[test]
fn raw_encryption_rejects_forbidden_selection() -> Result<(), Box<dyn Error>> {
    // Given empty key bytes and a prohibited profile.
    for (id, expected) in [
        (1_i32, RejectedFeature::SingleDes),
        (2_i32, RejectedFeature::SingleDes),
        (3_i32, RejectedFeature::SingleDes),
        (24_i32, RejectedFeature::Rc4Export),
        (6_i32, RejectedFeature::WeakCrypto),
    ] {
        let key = EncryptionKey::new(id, Vec::new());
        // When the raw cryptographic message API selects that profile.
        let failure = krb_priv::encrypt_krb_priv_enc_part(b"data", &key, None, &[])
            .err()
            .ok_or("D2 encrypted")?;
        // Then the policy error wins over key length or confounder errors.
        assert!(
            matches!(policy_cause(&failure), Some(Policy::RejectedFeature { feature, reason: _ }) if *feature == expected)
        );
    }
    Ok(())
}

/// A peer-selected weak checksum is rejected rather than verified as integrity.
#[test]
fn peer_checksum_selection_is_typed() -> Result<(), Box<dyn Error>> {
    // Given a decoded message carrying each historical weak checksum.
    for id in [
        1_i32, 2_i32, 3_i32, 4_i32, 5_i32, 6_i32, 7_i32, 8_i32, 9_i32, 10_i32, 14_i32,
    ] {
        let message = rasn_kerberos::KrbSafe {
            pvno: 5_i32.into(),
            msg_type: 20_i32.into(),
            body: rasn_kerberos::KrbSafeBody {
                user_data: Vec::new().into(),
                timestamp: None,
                usec: None,
                seq_number: None,
                s_address: rasn_kerberos::HostAddress {
                    addr_type: 2,
                    address: vec![127, 0, 0, 1].into(),
                },
                r_address: None,
            },
            cksum: rasn_kerberos::Checksum {
                r#type: id,
                checksum: Vec::new().into(),
            },
        };
        let key = EncryptionKey::new(17, vec![0; 16]);
        // When verification would select the peer's checksum profile.
        let failure = krb_safe::verify_krb_safe_checksum(&message, &key)
            .err()
            .ok_or("weak integrity accepted")?;
        // Then its exact wire identifier survives through the domain wrapper.
        assert!(
            matches!(policy_cause(&failure), Some(Policy::RejectedFeature { feature: RejectedFeature::UnauthenticatedChecksum { id: actual }, reason: _ }) if *actual == id)
        );
    }
    Ok(())
}

/// MIC construction adopts consumed plaintext even when rejecting a forbidden cipher.
#[cfg(feature = "spnego")]
#[test]
fn mic_rejection_follows_plaintext_adoption() -> Result<(), Box<dyn Error>> {
    use alloc::rc::Rc;
    use core::cell::Cell;

    use rskrb5_ng::spnego::MicToken;
    use zeroize::Zeroizing;
    struct Observed(Rc<Cell<bool>>);
    impl From<Observed> for Zeroizing<Vec<u8>> {
        #[inline]
        fn from(value: Observed) -> Self {
            value.0.set(true);
            Self::new(vec![0; 1024])
        }
    }
    // Given a payload conversion seam and a caller-selected export cipher.
    let converted = Rc::new(Cell::new(false));
    let key = EncryptionKey::new(24, Vec::new());
    // When constructing a MIC with that cipher.
    let failure = MicToken::new_initiator(Observed(Rc::clone(&converted)), &key)
        .err()
        .ok_or("D2 MIC accepted")?;
    // Then the payload has an erasing owner and the error remains typed.
    assert!(converted.get(), "payload must be adopted before rejection");
    assert!(matches!(
        policy_cause(&failure),
        Some(Policy::RejectedFeature {
            feature: RejectedFeature::Rc4Export,
            reason: _
        })
    ));
    Ok(())
}
