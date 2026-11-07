# SPNEGO and GSS review disposition

Commits are named by hash or subject suffix to avoid self-referential hashes.
Full red runs and acceptance output: `task-29-rskrb5-ng-own-way.log` in the execution evidence.

| ID | Status | Tests and commit | Behaviour change for CHANGELOG | Dismissal evidence |
| --- | --- | --- | --- | --- |
| RSK-7487E947 | fixed | `der_oid_arc_two_roundtrips_thresholds`, `der_oid_arc_two_maximum_roundtrips`, `der_oid_decodes_first_subidentifier_vectors`, `der_oid_rejects_malformed_first_subidentifier`, `der_oid_roundtrip_property`; commit `9d24f51` | Decode the full first base-128 subidentifier and split at 40/80; encode and round-trip all constructor-valid u32 arcs, including `2.40`, `2.100`, and `2.4294967295`. Reject malformed first subidentifiers with `InvalidOidEncoding`. | N/A |
| RSK-2A2C1928 | fixed | `der_state_overflow_cannot_alias_accept_completed`, `der_oid_overflow_cannot_alias_kerberos`, `der_integer_rejects_nonminimal_and_negative_values`, `der_oid_rejects_nonminimal_and_truncated_arcs`, plus unsigned boundary controls; commit `2a6a4d0` | Reject overflowing DER state values and later OID arcs instead of truncating them; reject redundant integer sign octets and nonminimal base-128 arcs. Existing typed parse errors are preserved. | N/A |
| RSK-622F4664 | fixed | `initiator_rejects_delegation_without_credentials`, `initiator_wrappers_reject_delegation`, `initiator_preserves_nondelegating_flag_masks`, `authenticator_checksum_delegation_prefix_is_mask_independent`; commit `93a2f4a` | Checked initiation rejects DELEG in split or combined masks with `DelegationRequiresCredential`; the raw checksum helper returns a consistent 24-byte prefix without fabricated delegation fields. | N/A |
| RSK-2A906A3A | fixed | `sealed_des3_wrap_roundtrips_all_payload_residues`, `sealed_des3_wrap_completes_manual_filler`, `sealed_des3_wrap_rejects_filler_overflow`; commit `e628f9e` | Sealed DES3 Wrap derives sufficient pre-header filler and EC, preserves sufficient explicit filler and application trailing zeroes, and rejects EC overflow. Generic DES3 decryption remains padding-preserving. | N/A |
| RSK-84FA90AE | fixed | `unsealed_wrap_applies_rrc_on_decode_and_encode`; commit `e405f7c` | Unsealed Wrap tokens apply RRC modulo body length on encoding and decoding. | N/A |
| RSK-C4BE57A0 | fixed | `acceptor_accepts_windows_sspi_smb_capture`, `acceptor_accepts_windows_sspi_ldap_capture`, `acceptor_accepts_optimistic_kerberos_alias`, `mech_list_mic_accepts_kerberos_after_ntlm`, `mech_list_mic_accepts_nonfirst_and_authenticates_response`, `mech_list_mic_accepts_first_choice`, `mech_list_mic_rejects_tampering_before_replay_commit`, `mech_list_mic_uses_context_subkeys`, `mech_list_mic_rejects_wrong_direction_flags_and_sequence`, `mech_list_mic_supports_bare_init_and_preserves_received_list`, `mech_list_mic_response_sequence_is_in_ap_rep`, `acceptor_rejects_nonfirst_kerberos`, `acceptor_rejects_unverified_mech_list_mic`, `acceptor_rejects_stateless_continuation`, `acceptor_preserves_selected_kerberos_oid`, `acceptor_rejects_unsupported_mechanisms`, `acceptor_accepts_raw_ms_kerberos`, `acceptor_rejection_preserves_replay_cache`; original `f84e3f8`, MIC fixes `0e62cc0`, `f3ada25`; follow-up subject `spnego: treat both Kerberos OIDs as one mechanism for first-choice selection (RSK-C4BE57A0)` | Windows token shape accepted without MIC when the first offered mechanism is either Kerberos OID. Echo first offered Kerberos OID as supportedMech and token OID as inner thisMech, per MIT/MS-SPNG. Non-Kerberos-first selection requires a MIC; supplied MICs verify before replay insertion and receive reciprocal MICs. Reject invalid MICs and stateless continuations. | N/A |
| RSK-FAF64A85 / run-2 lead `src/spnego.rs:accept_sec_context_header:mandatory-gss-authenticator-fields` | fixed | `gss_authenticator_requires_checksum`, `gss_authenticator_requires_sequence`, `gss_authenticator_rejects_wrong_checksum_type`, `gss_authenticator_rejects_short_checksum`, `gss_authenticator_rejects_invalid_binding_length`, `gss_authenticator_rejects_malformed_delegation`, `gss_authenticator_rejection_preserves_generic_validation`, `gss_authenticator_deterministic_builder_requires_sequence`; commit `f11a3db` | GSS acceptance checks RFC 4121 checksum type/framing and requires a sequence before replay insertion; deterministic initiation rejects an omitted sequence. Generic Kerberos validation is unchanged. | N/A |
| upstream issue #9 | fixed | `negotiate_header_limit_rejects_base64_before_der`, `negotiate_header_limit_precedes_base64_validation`, `negotiate_header_limit_counts_whitespace`, `negotiate_header_limit_accepts_boundary`, plus small-header error controls; commit subject suffix `(upstream-9)` | Reject header values over 65,536 bytes before scanning/base64 allocation with `NegotiateHeaderTooLong { maximum, actual }`; include scheme and whitespace in the cap. | N/A |

## GSS boundary validation

RFC 4121 section 4.1.1 requires checksum type `0x8003`, a sixteen-byte Bnd
with little-endian length, context flags and an authenticator sequence number.
Delegation framing requires option 1, the declared credential bytes and a
decodable KRB-CRED envelope. Credential import/decryption is not implemented by
this acceptor; the delegation builder is covered by its separate row above.

The service validator invokes an internal GSS check after decryption, identity
and clock checks, but before replay insertion. Ordinary AP-REQ validation does
not run that check. No second decryption or public result-field change is needed.
The API supplies no channel bindings, so it ignores Bnd content as permitted by
section 4.1.1.2; it also ignores unknown flags and trailing extensions. Positive
controls cover these cases, zero and maximum sequence numbers, and a framed
delegation envelope. Additional tests cover raw Kerberos headers and corrupted
authenticator ciphertext. No principal-forgery or channel-binding enforcement
claim is made.

## One-shot acceptor integrity and scope

Only `1.2.840.113554.1.2.2` and `1.2.840.48018.1.2.2` are accepted. The optimistic
token may use either Kerberos OID: both identify the same mechanism per RFC 4178
Appendix C. A non-Kerberos first preference requires a mechListMIC per
RFC 4178 sections 4-5. A supplied first-choice MIC must also verify. The signed
payload is the received MechTypeList TLV, excluding its explicit `[0]` wrapper.
No reconstruction, sorting or alias substitution changes the transcript.

RFC 4121 MIC decoding, direction, sequence and checksum checks run after AP-REQ
decryption and policy validation but before replay insertion. Verification uses
usage 25 and the authenticator subkey or ticket key. No acceptor subkey exists
yet. Responses carry accept-completed, the selected OID, AP-REP and (when an
initiator MIC verified) an acceptor MIC using usage 23 and the AP-REP subkey if
provided, otherwise the initiator subkey or ticket key. The acceptor MIC's
sequence number is the configured AP-REP one, otherwise the authenticator's; in
that fallback the AP-REP enc-part carries the same number, because MIT
initiators read the acceptor sequence number from the AP-REP (0 when absent).
`mech_list_mic_response_sequence_is_in_ap_rep` decrypts the AP-REP
independently and compares its seq-number with the MIC's SND_SEQ. The
first-choice no-MIC fixture remains byte-identical. Tests construct MIC headers independently and
call only the lower-level AES checksum primitive, not the MIC implementation.

RFC 4121 CFX MIC tokens use the implemented checksum families, including RC4 and
DES3 when the context's policy permits those legacy enctypes. The older RFC 4757
and RFC 1964 per-message token formats remain unsupported and fail closed as
`InvalidMechListMic`; their format is distinct from CFX using a legacy enctype.

Absent required MICs return `MissingMechListMic`; malformed, tampered, wrong-list
or context-inconsistent MICs return `InvalidMechListMic`. Unsupported mechanisms
return `UnsupportedMechanism`. All continuations still return
`NegotiationRequiresState`: this one-shot API cannot correlate a NegTokenResp
with a previous offer, established key, request-mic phase or consumed sequence.
It supports MICs already present in the initial token, not request-mic round
trips. Windows MS-first/standard-inner tokens without MIC are accepted. Following
MIT and MS-SPNG, replies echo the first offered Kerberos OID in `supportedMech`,
but preserve the optimistic token OID in inner AP-REP `thisMech`. The additive
`AcceptedContext::token_mechanism` field keeps those values separate; equal-OID
replies are unchanged. The two public Windows capture fixtures test original
AP-REQ extraction and test-key full acceptance with the same negotiation shape.

F2 M1-R follow-up commit subject: `spnego: treat both Kerberos OIDs as one mechanism
for first-choice selection (RSK-C4BE57A0)`. Regressions:
`acceptor_accepts_windows_sspi_smb_capture`, `acceptor_accepts_windows_sspi_ldap_capture`,
`acceptor_accepts_optimistic_kerberos_alias`, `mech_list_mic_accepts_kerberos_after_ntlm`.
The row's former `acceptor_rejects_optimistic_oid_mismatch` is replaced by the
alias acceptance test; `acceptor_rejects_nonfirst_kerberos` now uses NTLM first.
The alias semantics left `error::Spnego::OptimisticMechanismMismatch` unconstructed,
so it was removed before 0.3.0 release (final review n8); 0.2.2 never had it.

The mechanism-selection change addresses the acceptor only, as requested. The
original review's initiator/HTTP response-classifier observations remain outside
that change; its row does not claim those client-side paths have been repaired.

## Header resource boundary

The 64 KiB cap is a local policy, not an RFC maximum. Checking the whole borrowed
header before splitting or trimming bounds scanning as well as decoded allocation;
it also prevents whitespace from bypassing the cap. Encoders and raw token codecs
are unchanged. Existing small-header and raw Kerberos fixtures remain supported.
The regression tests require the named size error: `is_err()` alone would also
pass when an oversized input allocates and then fails DER parsing. Scratch failure
QA removes only the cap and its constant, retaining the error declaration so the
three rejection tests compile and fail while the three controls pass.
