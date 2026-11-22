//! Fuzz the PAC container and every NDR buffer parser.
//!
//! The first input byte selects the entry point and the rest is its input:
//! the whole PAC (header, buffer table and every recognized buffer, then the
//! server checksum check with a fixed synthetic key), the bare header and
//! buffer table, each info buffer parser on its own, the nested credential
//! and claims decoders, the PAC attributes, requestor SID and `PA-PAC-REQUEST`
//! decoders, the explicit-policy verification and the builder's re-signing of a
//! parsed PAC, and the bounded `AD-IF-RELEVANT` traversal that finds a PAC in
//! authorization data. None may panic.

#![no_main]

use core::time::Duration;
use std::time::UNIX_EPOCH;

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::{
    ap_req,
    keytab::EncryptionKey,
    pac::{
        self, AttributesInfo, Builder, ClaimsInfo, ClaimsSet, ClaimsSetMetadata, ClientBinding,
        ClientInfo, CredentialData, CredentialsInfo, DeviceInfo, KerbValidationInfo,
        NtlmSupplementalCredential, Pac, Request, RequestorSid, S4UDelegationInfo, SignatureData,
        Signing, UpnDnsInfo, Verification, VerificationPolicy,
    },
};

/// The AES256 key of the synthetic gokrb5 `sysHTTP` keytab, which verifies the
/// server checksum of the gokrb5 `AD_WIN2K` PAC seed.
const KEY: [u8; 32] = [
    0x43, 0x76, 0x37, 0x02, 0x86, 0x89, 0x78, 0xd1, 0xb6, 0xd9, 0x1a, 0x36, 0x70, 0x4b, 0x98, 0x7e,
    0x27, 0xe5, 0x17, 0x25, 0x00, 0x55, 0xbd, 0xfc, 0x40, 0xb8, 0xa6, 0xb3, 0x84, 0x8d, 0x9a, 0xae,
];

/// AES256-CTS-HMAC-SHA1-96.
const AES256: i32 = 18;

/// The bytes the ticket signature of the `tests/support/pac_vectors.rs` service vector covers.
const TICKET_INPUT: &[u8] = b"ticket-signature-input fixture bytes: not a real ticket";

/// Encode one DER element with a definite length.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match u8::try_from(content.len()) {
        Ok(short) if short < 0x80 => out.push(short),
        _ => {
            let length = content.len().to_be_bytes();
            let significant: Vec<u8> = length.into_iter().skip_while(|byte| *byte == 0).collect();
            out.push(0x80 | u8::try_from(significant.len()).unwrap_or(0));
            out.extend_from_slice(&significant);
        }
    }
    out.extend_from_slice(content);
    out
}

/// A DER Authenticator whose `authorization-data` field is `authorization_data`.
fn authenticator_with(authorization_data: &[u8]) -> Vec<u8> {
    let cname = tlv(
        0x30,
        &[
            tlv(0xa0, &tlv(0x02, &[1])),
            tlv(0xa1, &tlv(0x30, &tlv(0x1b, b"user"))),
        ]
        .concat(),
    );
    let fields = [
        tlv(0xa0, &tlv(0x02, &[5])),
        tlv(0xa1, &tlv(0x1b, b"TEST.GOKRB5")),
        tlv(0xa2, &cname),
        tlv(0xa4, &tlv(0x02, &[0])),
        tlv(0xa5, &tlv(0x18, b"20300101000000Z")),
        tlv(0xa8, authorization_data),
    ]
    .concat();
    tlv(0x62, &tlv(0x30, &fields))
}

/// Parse a whole PAC, then check it the way the service path does.
fn whole_pac(input: &[u8]) {
    let Ok(pac) = Pac::parse_and_process(input) else {
        return;
    };
    let key = EncryptionKey::new(AES256, KEY.to_vec());
    drop(pac.verify(&key));
    drop(pac.ad_credentials());
    if let Some(credentials) = pac.credentials_info() {
        drop(credentials.decrypt_credential_data(&key));
    }
    for claims in [pac.client_claims_info(), pac.device_claims_info()]
        .into_iter()
        .flatten()
    {
        drop(claims.metadata.claims_set());
    }
}

/// Parse the header and buffer table, then slice every buffer.
fn header_only(input: &[u8]) {
    if let Ok(pac) = Pac::parse(input) {
        for buffer in pac.buffers() {
            drop(pac.buffer_bytes(buffer));
        }
    }
}

/// Decode `input` as authorization data and search it for a PAC.
fn authorization_data(input: &[u8]) {
    if let Ok(authenticator) = ap_req::decode_authenticator(&authenticator_with(input))
        && let Some(data) = authenticator.authorization_data
    {
        drop(pac::find_pac_in_authorization_data(&data));
    }
}

/// Verify a parsed PAC under the policy that requires every signature, with the keys of
/// `tests/support/pac_vectors.rs`, then rebuild and sign it again.
fn verification(input: &[u8]) {
    let Ok(pac) = Pac::parse_and_process(input) else {
        return;
    };
    let server = EncryptionKey::new(AES256, (0x40..0x60).collect::<Vec<u8>>());
    let kdc = EncryptionKey::new(AES256, (0x60..0x80).collect::<Vec<u8>>());
    let Some(authenticated) = UNIX_EPOCH.checked_add(Duration::from_secs(1_494_083_591)) else {
        return;
    };
    let client = ClientBinding::new("pacuser", authenticated);
    let request = Verification::new(VerificationPolicy::kdc())
        .with_server_key(&server)
        .with_kdc_key(&kdc)
        .with_ticket_signature_input(TICKET_INPUT)
        .with_client(client.clone());
    drop(pac.clone().verify_ext(&request));
    if let Ok(builder) = Builder::from_pac(&pac) {
        let signing = Signing::new(&server, &kdc)
            .with_client(client)
            .with_ticket_signature_input(TICKET_INPUT);
        if let Ok(signed) = builder.sign(&signing) {
            drop(signed.verify_ext(&request));
        }
    }
}

/// Decode a `PA-PAC-REQUEST`; an accepted element encodes and decodes again to itself.
///
/// # Panics
///
/// Panics when an accepted element does not survive its own encoding: that is the defect the
/// fuzzer looks for.
fn pac_request(input: &[u8]) {
    if let Ok(request) = Request::decode_der(input)
        && let Ok(encoded) = request.encode_der()
    {
        assert_eq!(
            Request::decode_der(&encoded).ok(),
            Some(request),
            "an accepted PA-PAC-REQUEST must encode and decode to itself"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((selector, input)) = data.split_first() else {
        return;
    };
    match selector & 0x1f {
        0 => whole_pac(input),
        1 => header_only(input),
        2 => drop(KerbValidationInfo::parse(input)),
        3 => drop(SignatureData::parse(input)),
        4 => {
            if let Ok(info) = CredentialsInfo::parse(input) {
                drop(info.decrypt_credential_data(&EncryptionKey::new(AES256, KEY.to_vec())));
            }
        }
        5 => drop(CredentialData::parse(input)),
        6 => drop(NtlmSupplementalCredential::parse(input)),
        7 => drop(ClientInfo::parse(input)),
        8 => drop(UpnDnsInfo::parse(input)),
        9 => drop(S4UDelegationInfo::parse(input)),
        10 => drop(DeviceInfo::parse(input)),
        11 => {
            if let Ok(info) = ClaimsInfo::parse(input) {
                drop(info.metadata.claims_set());
            }
        }
        12 => {
            if let Ok(metadata) = ClaimsSetMetadata::parse(input) {
                drop(metadata.decoded_claims_set_bytes());
                drop(metadata.claims_set());
            }
        }
        13 => drop(ClaimsSet::parse(input)),
        16 => drop(AttributesInfo::parse(input)),
        17 => drop(RequestorSid::parse(input)),
        18 => pac_request(input),
        19 => verification(input),
        _ => authorization_data(input),
    }
});
