//! Independently encrypted RFC 4120 subkey replies.

use super::{
    TestError, sample_service_principal, sample_tgt_session, synthetic_tgs_rep, timestamp,
};
use rskrb5_ng::{
    client::{self, TgsRequestParts, options::TgsReq},
    crypto::KerberosEtype,
    kdc_rep,
    keytab::EncryptionKey,
};

/// Both subkey builders accept usage 9 replies; session-key requests retain usage 8.
#[test]
fn subkey_builders_complete_conforming_reply() -> Result<(), TestError> {
    let tgt = sample_tgt_session()?;
    let subkey = EncryptionKey::new(18, vec![0x42; 32]);
    for random in [false, true] {
        let options = TgsReq::new(timestamp(1_893_553_450)?, 42).with_etypes(vec![18_i32]);
        let parts = if random {
            client::build_tgs_req_for_realm_with_subkey(
                &tgt,
                "TEST.GOKRB5",
                sample_service_principal(),
                options,
            )?
        } else {
            client::build_tgs_req_for_realm_with_confounder_and_subkey(
                &tgt,
                "TEST.GOKRB5",
                sample_service_principal(),
                TgsRequestParts::new(options, &[0; 16], &subkey),
            )?
        };
        let encoded = synthetic_tgs_rep(&parts.request, 42, &tgt.session_key)?;
        let mut reply = kdc_rep::decode_tgs_rep(&encoded)?;
        let plaintext = kdc_rep::decrypt_tgs_rep_enc_part(&reply, &tgt.session_key)?;
        let cipher = KerberosEtype::from_etype_id(18)
            .ok_or("AES")?
            .encrypt_message_with_confounder(
                &parts.authenticator_subkey.value,
                &kdc_rep::encode_enc_tgs_rep_part(&plaintext)?,
                9,
                &[0; 16],
            )?;
        reply.0.enc_part.cipher = cipher.into();
        let session = client::process_tgs_rep(
            &parts.request,
            &kdc_rep::encode_tgs_rep(&reply)?,
            &parts.authenticator_subkey,
        )?;
        assert_eq!(session.service, parts.request.service);
    }
    Ok(())
}
