//! A PAC and its ticket captured from MIT krb5 1.22.2.
//!
//! Provenance: `scripts/interop/run.sh test pac` (the pinned MIT krb5 1.22.2 fixture of this
//! repository, `scripts/interop/mit/Dockerfile`), realm `TEST.RSKRB5`, a service ticket of
//! `testuser1` for `pac/svc.test.rskrb5` (a service without `+no_auth_data_required`, so the KDC
//! issued a PAC: `src/kdc/kdc_authdata.c:479-512`), obtained with the encrypted timestamp by the
//! live scenario `the_four_signatures_of_the_mit_pac_verify_with_the_krbtgt_key`, then decrypted
//! with the service key. The realm, its keys and the ticket are disposable: the keys were generated
//! by that run and protect nothing. The authentication time is KerberosTime(2026-11-22T04:56:20+00:00).

/// The service key of `pac/svc.test.rskrb5` (aes256-cts-hmac-sha384-192, 32 bytes, hex).
pub(crate) const SERVICE_KEY: &str =
    "09f1762f52999e565544cc0a1f19ab1153f0d2e2974ed9cd35199d33d6b3dad4";

/// The `krbtgt/TEST.RSKRB5` key that signed the PAC (aes256-cts-hmac-sha384-192, 32 bytes, hex).
pub(crate) const KDC_KEY: &str = "7a9ebb0e60cb86301f3ad3773ae9bd681b3795e93959448a076abdcb44decf57";

/// The DER `EncTicketPart` of the ticket, decrypted with the service key (hex); its authorization data carries the PAC.
pub(crate) const ENC_TICKET_PART: &str = concat!(
    "638201b9308201b5a00703050000090000a12b3029a003020114a1220420902e3acfc74f10a32da39611a395c9848a73",
    "a40040a8f15842e93adc1a484e17a20d1b0b544553542e52534b524235a3163014a003020101a10d300b1b0974657374",
    "7573657231a40b3009a003020101a1020400a511180f32303236313132323034353632305aa711180f32303236313132",
    "333034353632305aaa8201213082011d30820119a003020101a18201100482010c3082010830820104a00402020080a1",
    "81fb0481f805000000000000000a0000001c0000005800000000000000100000001c0000007800000000000000060000",
    "001c0000009800000000000000070000001c000000b800000000000000130000001c000000d800000000000000007276",
    "d03d7add0112007400650073007400750073006500720031000000000014000000a237c86ec897225ef848ea042807ca",
    "51cce53a0e6ac1e2f20000000014000000bbba575371762430ccbcb34263e760928c81f942735e8a1800000000140000",
    "00200f1633b4bf0384a93de54b8156390b52ee198eded3e912000000001400000058d393a16f8319923a9b5bcf8986ea",
    "b20cf64d0b1cf5258100000000",
);

/// The PAC the ticket carries (hex): client info, server, KDC, ticket and full checksums, no `KERB_VALIDATION_INFO`.
pub(crate) const PAC: &str = concat!(
    "05000000000000000a0000001c0000005800000000000000100000001c0000007800000000000000060000001c000000",
    "9800000000000000070000001c000000b800000000000000130000001c000000d800000000000000007276d03d7add01",
    "12007400650073007400750073006500720031000000000014000000a237c86ec897225ef848ea042807ca51cce53a0e",
    "6ac1e2f20000000014000000bbba575371762430ccbcb34263e760928c81f942735e8a180000000014000000200f1633",
    "b4bf0384a93de54b8156390b52ee198eded3e912000000001400000058d393a16f8319923a9b5bcf8986eab20cf64d0b",
    "1cf5258100000000",
);
