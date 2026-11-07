# Kpasswd and message review dispositions

## Current follow-up

The todo 34 receipts below describe that historical checkpoint. FU-TRN-14
supersedes its password-storage residual: `ChangePasswdData::new_passwd` is now
the owning zeroizing `kadmin::password::Bytes`, and dedicated first-party DER
writers avoid a password copy into rasn `OctetString`. The proofs are
`password_storage_is_zeroizing`, `password_der_matches_rasn` and
`private_der_matches_rasn`. General decoded `EncKrbPrivPart::user_data` and other
dependency-owned ASN.1/cipher copies remain outside the erasure guarantee; see
[the current security policy](../security-policy.md#residual-copies).

## Historical todo 34 receipts

All todo 34 IDs have a disposition. Commit subjects identify
their atomic item without self-referential hashes. Full commands, red output
and exit codes are in `task-34-rskrb5-ng-own-way.log` in the execution evidence.

| ID | Status | Tests and commit | Behaviour change for CHANGELOG | Dismissal evidence |
| --- | --- | --- | --- | --- |
| RSK-A5F7D975 | fixed | `checksum_matches_whole_message_oracle`, `verifies_independent_whole_message_checksum`; commit subject suffix `(RSK-A5F7D975)` | Generate and verify usage-15 checksums over the entire DER KRB-SAFE with checksum type zero and an empty checksum value, per RFC 4120 §5.6.1, instead of body-only DER. | N/A |
| RSK-3B6BA222 | fixed | `kpasswd_bare_error_roundtrips`, `kpasswd_bare_error_cannot_assert_success`; commit subject suffix `(RSK-3B6BA222)` | Accept standalone RFC 3244 application-30 errors before frame interpretation; preserve bare encoding using version 0xff80, while version-1 legacy errors remain framed. Both forms reject unauthenticated success when consuming the result. | N/A |
| RSK-789A6FBB | fixed | `kpasswd_rejects_invalid_protected_controls`, existing password mutation tests; commit subject suffix `(RSK-789A6FBB)` | High-level result consumption validates the verified AP-REP's server sequence, requires a complete timestamp/usec pair or negotiated sequence, rejects invalid microseconds/fractions and timestamps outside 300 seconds of the explicit request time. Sender addresses must be well-formed IPv4/IPv6; an explicit request recipient pins the peer, and any response recipient must match the request sender. | N/A |
| RSK-0C0007B7 | fixed | `kpasswd_rejects_complete_frame_suffix`, `whole_message_rejects_trailing_value`, `authenticator_rejects_nonzero_authenticated_suffix`, `raw_codec_retains_prefix_contract`; commit subject suffix `(RSK-0C0007B7)` | Complete AP/KDC/ticket/KRB message codecs require an empty DER remainder, including decrypted parts after intentional zero-padding handling. Kpasswd frames require exact declared length. Generic `messages::decode_der` remains a raw prefix codec. | N/A |
| RSK-6A673A85 | fixed | `protocol_time_rejects_out_of_domain_microseconds`, `protocol_time_rejects_fractional_kerberos_time`, `protocol_time_accepts_microsecond_boundaries`, `protocol_time_kpasswd_builder_rejects_invalid_scalars`; commit suffix `(RSK-6A673A85)` | Shared checked Microseconds/whole-second conversions reject invalid KRB-ERROR diagnostics, explicit kpasswd request scalars and kpasswd AP-REP time fields. Raw ASN.1 codecs remain raw; service validation retains its earlier stricter checks. | N/A |
| RSK-471362A3 / upstream issue #1 | fixed | `password_plaintext_debug_is_redacted`, password mutation success/error probes; commit suffix `(RSK-471362A3)` | Redact password-specific Debug; attach `Zeroizing` immediately to the high-level password copy and to owned password DER, encrypted-part encoding and decrypted plaintext scratch on every return/cancellation path. | N/A |
| RSK-14E2755A / upstream issue #8 | fixed | `kpasswd_classification_preserves_pre_send_failure`, `kpasswd_classification_wraps_post_send_timeout_once`, `kpasswd_classification_marks_malformed_reply_unknown`, `kpasswd_lost_reply_has_unknown_outcome`; follow-up commit `kpasswd: classify unknown outcomes only after possible delivery (RSK-14E2755A)` | Preserve pre-send errors; return exactly one `Client::KpasswdOutcomeUnknown` after possible delivery, including malformed replies and failed reply authentication. Caller cancellation still returns nothing and must be recorded unknown externally. | N/A |
| RSK-8BBFC1EE | dismissed | Whole-tree `prose_gate.py --enforce`; cancellation sections in `client/negotiate.rs` and `http.rs`; commit suffix `(RSK-14E2755A-RSK-8BBFC1EE)` | None for wrapper annotations: earlier prose migration already documents them. Wrappers propagate the high-level unknown-outcome variant. | Source probe confirms every async wrapper already has a Cancel safety section and mutation wrappers warn that cancellation does not roll back, outcome is unknown, and verification precedes retry. No prose-string unit test added. |

## Checksum contract

The public body-based checksum function constructs a version-5, message-type-20
envelope. Verification uses the supplied envelope's version and message type,
so these fields participate in the MAC rather than being silently normalized.
The placeholder encoding is shared by generation and verification; the tests
independently construct and encode the normative peer envelope without calling
the builder. Existing round-trip, tampering and key/type mismatch tests remain.
No public signature or error variant changes. Only owned message clones are
used to replace the checksum; no caller message is mutated.

## Acceptance and outcome limits

Final acceptance results are recorded in the execution evidence, not inferred
from the per-item checks. Transport owns the possible-delivery boundary: encoding,
discovery and connection failures before sending retain their own error classes.
After possible delivery, transport/parse failures and high-level reply-validation
failures carry exactly one unknown wrapper. Confirmed server rejection remains a
normal password-change failure. No remote rollback or automatic reconciliation
is claimed; callers must not blindly retry unknown outcomes. RSK-8BBFC1EE wrappers
propagate these classes unchanged; their cancellation contract remains unchanged.

## Secret ownership boundary

The high-level password buffer is zeroizing before the first fallible await,
and moves directly into credential storage on confirmed own-password success.
Owned DER staging and encrypted-part plaintext allocations are zeroizing through
encryption errors, success and normal unwinding. Password-specific Debug prints
only a redaction marker for the password field, never its bytes.

Residuals: public `ChangePasswdData::new_passwd` and
`EncKrbPrivPart::user_data` are dependency-owned immutable `OctetString`s.
Rasn 0.29 exposes no mutable erasure API for that storage; encoding/decoding
also creates dependency-owned copies. These are not claimed erased. Closing
that residual requires a separately reviewed secret ASN.1 owner or dependency
API change; adding an allocator hook or mutating shared immutable bytes is not
a valid substitute. Caller-owned returns/inputs, compiler copies, dependency
cipher state and abort paths are outside the guarantee; abort does not run Drop.
