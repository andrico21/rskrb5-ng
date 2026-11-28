//! A verified PAC with the buffers Samba emits: the PAC attributes, the
//! requestor SID and client claims, read through the verified-PAC API and the
//! identity attributes derived from it.

use core::error::Error;

use rskrb5_ng::pac::{
    Builder, INFO_TYPE_PAC_ATTRIBUTES_INFO, INFO_TYPE_PAC_CLIENT_CLAIMS_INFO,
    INFO_TYPE_PAC_REQUESTOR, IdentityAttributes, Signing, Verification, VerificationPolicy,
    Verified,
};

use super::{client, kdc_key, pac_vectors, server_key, vector};

/// The attributes buffer: two flag bits, `PAC_WAS_REQUESTED` set.
const ATTRIBUTES: [u8; 8] = [2, 0, 0, 0, 1, 0, 0, 0];

/// gokrb5's `ClientClaimsInfoMulti`: an int64 claim and a string claim.
const CLIENT_CLAIMS_MULTI: &str = "01100800cccccccc780100000000000000000200500100000400020000000000500100000000000000000000000000005001000001100800cccccccc400100000000000000000200010000000400020000000000000000000000000001000000010000000200000008000200020000000c000200010001000100000010000200140002000300030001000000180002002a000000000000002a000000610064003a002f002f006500780074002f006d007300440053002d0053007500700070006f00720074006500640045003a0038003800640035006400650061003800660031006100660035006600310039000000010000001c00000000000000290000000000000029000000610064003a002f002f006500780074002f00730041004d004100630063006f0075006e0074004e0061006d0065003a00380038006400350064003900300038003500650061003500630030006300300000000000010000001c0002000a000000000000000a000000740065007300740075007300650072003100000000000000";

/// The requestor SID `S-1-5-21-1-2-3-1104`.
fn requestor() -> Vec<u8> {
    let mut sid = vec![1, 5, 0, 0, 0, 0, 0, 5];
    for sub in [21_u32, 1, 2, 3, 1104] {
        sid.extend_from_slice(&sub.to_le_bytes());
    }
    sid
}

/// A PAC of `pacuser` with attributes, requestor and client claims, signed
/// with the vector keys and verified under them.
fn verified() -> Result<Verified, Box<dyn Error>> {
    let (server, kdc, input) = (
        server_key()?,
        kdc_key()?,
        vector(pac_vectors::TICKET_INPUT)?,
    );
    let mut builder = Builder::new();
    builder.add_buffer(INFO_TYPE_PAC_ATTRIBUTES_INFO, &ATTRIBUTES)?;
    builder.add_buffer(INFO_TYPE_PAC_REQUESTOR, &requestor())?;
    builder.add_buffer(
        INFO_TYPE_PAC_CLIENT_CLAIMS_INFO,
        &vector(CLIENT_CLAIMS_MULTI)?,
    )?;
    let signed = builder.sign(
        &Signing::new(&server, &kdc)
            .with_client(client()?)
            .with_ticket_signature_input(&input),
    )?;
    let request = Verification::new(VerificationPolicy::kdc())
        .with_server_key(&server)
        .with_kdc_key(&kdc)
        .with_ticket_signature_input(&input)
        .with_client(client()?);
    Ok(signed.verify_ext(&request)?)
}

/// The verified PAC hands out its attributes and its requestor SID.
#[test]
fn a_verified_pac_has_its_attributes_and_requestor() -> Result<(), Box<dyn Error>> {
    // Given a verified PAC with both buffers,
    let pac = verified()?;
    // when they are read, then they are the ones that were signed.
    let attributes = pac.attributes_info().ok_or("attributes")?;
    assert_eq!(attributes.flags_length(), 2);
    assert!(attributes.was_requested() && !attributes.was_given_implicitly());
    assert_eq!(
        pac.requestor_sid().ok_or("requestor")?.sid().to_string(),
        "S-1-5-21-1-2-3-1104"
    );
    Ok(())
}

/// The identity attributes of a verified PAC hold every value of its client
/// claims, under `claim:<id>`.
#[test]
fn identity_attributes_hold_the_client_claims() -> Result<(), Box<dyn Error>> {
    // Given a verified PAC with an int64 and a string claim,
    let attributes = IdentityAttributes::from_verified(&verified()?);
    // then each claim is an attribute with its values,
    assert_eq!(
        attributes.get("claim:ad://ext/msDS-SupportedE:88d5dea8f1af5f19"),
        Some(["28".to_owned()].as_slice())
    );
    assert_eq!(
        attributes.get("claim:ad://ext/sAMAccountName:88d5d9085ea5c0c0"),
        Some(["testuser1".to_owned()].as_slice())
    );
    // next to the client name and the checks that passed.
    assert_eq!(
        attributes.get("pac:client-name"),
        Some(["pacuser".to_owned()].as_slice())
    );
    assert_eq!(attributes.get("pac:verified").map(<[String]>::len), Some(5));
    Ok(())
}
