//! MIT krb5 1.22.2 encodings of the RFC 6560 messages.
//!
//! Provenance: `src/tests/asn.1/reference_encode.out` of the `krb5-1.22.2-final` tag
//! (the `encode_krb5_otp_tokeninfo`, `encode_krb5_pa_otp_challenge`,
//! `encode_krb5_pa_otp_req` and `encode_krb5_pa_otp_enc_req` lines), produced by MIT's
//! own encoder from the objects built in `src/tests/asn.1/ktest.c`
//! (`ktest_make_minimal_*` and `ktest_make_maximal_*`). The hex is copied verbatim; the
//! `(optionals NULL)` lines are the minimal objects.

/// `encode_krb5_otp_tokeninfo(optionals NULL)` (9 bytes).
pub(crate) const TOKENINFO_MINIMAL: &str = "30 07 80 05 00 00 00 00 00";

/// `encode_krb5_otp_tokeninfo` (116 bytes).
pub(crate) const TOKENINFO_MAXIMAL: &str = "30 72 80 05 00 77 00 00 00 81 0B 45 78 61 6D 70 6C 65 63 6F 72 70 82 05 68 61 72 6B 21 83 01 0A 84 01 02 85 09 79 6F 75 72 74 6F 6B 65 6E 86 28 75 72 6E 3A 69 65 74 66 3A 70 61 72 61 6D 73 3A 78 6D 6C 3A 6E 73 3A 6B 65 79 70 72 6F 76 3A 70 73 6B 63 3A 68 6F 74 70 A7 16 30 0B 06 09 60 86 48 01 65 03 04 02 01 30 07 06 05 2B 0E 03 02 1A 88 02 03 E8";

/// `encode_krb5_pa_otp_challenge(optionals NULL)` (23 bytes).
pub(crate) const CHALLENGE_MINIMAL: &str =
    "30 15 80 08 6D 69 6E 6E 6F 6E 63 65 A2 09 30 07 80 05 00 00 00 00 00";

/// `encode_krb5_pa_otp_challenge` (168 bytes).
pub(crate) const CHALLENGE_MAXIMAL: &str = "30 81 A5 80 08 6D 61 78 6E 6F 6E 63 65 81 0B 74 65 73 74 73 65 72 76 69 63 65 A2 7D 30 07 80 05 00 00 00 00 00 30 72 80 05 00 77 00 00 00 81 0B 45 78 61 6D 70 6C 65 63 6F 72 70 82 05 68 61 72 6B 21 83 01 0A 84 01 02 85 09 79 6F 75 72 74 6F 6B 65 6E 86 28 75 72 6E 3A 69 65 74 66 3A 70 61 72 61 6D 73 3A 78 6D 6C 3A 6E 73 3A 6B 65 79 70 72 6F 76 3A 70 73 6B 63 3A 68 6F 74 70 A7 16 30 0B 06 09 60 86 48 01 65 03 04 02 01 30 07 06 05 2B 0E 03 02 1A 88 02 03 E8 83 07 6B 65 79 73 61 6C 74 84 04 31 32 33 34";

/// `encode_krb5_pa_otp_req(optionals NULL)` (46 bytes).
pub(crate) const REQUEST_MINIMAL: &str = "30 2C 80 05 00 00 00 00 00 A2 23 A0 03 02 01 00 A1 03 02 01 05 A2 17 04 15 6B 72 62 41 53 4E 2E 31 20 74 65 73 74 20 6D 65 73 73 61 67 65";

/// `encode_krb5_pa_otp_req` (188 bytes).
pub(crate) const REQUEST_MAXIMAL: &str = "30 81 B9 80 05 00 60 00 00 00 81 05 6E 6F 6E 63 65 A2 23 A0 03 02 01 00 A1 03 02 01 05 A2 17 04 15 6B 72 62 41 53 4E 2E 31 20 74 65 73 74 20 6D 65 73 73 61 67 65 A3 0B 06 09 60 86 48 01 65 03 04 02 01 84 02 03 E8 85 05 66 72 6F 67 73 86 0A 6D 79 66 69 72 73 74 70 69 6E 87 05 68 61 72 6B 21 88 0F 31 39 39 34 30 36 31 30 30 36 30 33 31 37 5A 89 03 33 34 36 8A 01 02 8B 09 79 6F 75 72 74 6F 6B 65 6E 8C 28 75 72 6E 3A 69 65 74 66 3A 70 61 72 61 6D 73 3A 78 6D 6C 3A 6E 73 3A 6B 65 79 70 72 6F 76 3A 70 73 6B 63 3A 68 6F 74 70 8D 0B 45 78 61 6D 70 6C 65 63 6F 72 70";

/// `encode_krb5_pa_otp_enc_req` (12 bytes).
pub(crate) const ENC_REQUEST: &str = "30 0A 80 08 6B 72 62 35 64 61 74 61";
