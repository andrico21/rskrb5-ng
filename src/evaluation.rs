//! Candidate compatibility matrix and fixture probes.

/// Static candidate, contract and fixture tables behind the report.
pub mod data;

use core::fmt::{self, Display, Formatter};

use data::{ASN1_FIXTURES, ASSESSMENTS, REPORTS, V8_CONTRACT};

/// Render the current compatibility matrix as Markdown.
#[inline]
#[must_use]
pub fn render_markdown() -> String {
    MarkdownReport.to_string()
}

/// The compatibility report; its `Display` output is the Markdown document.
struct MarkdownReport;

impl Display for MarkdownReport {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("# rskrb5-ng Compatibility Report\n\n")?;
        f.write_str("This report is generated from `rskrb5_ng::evaluation` and captures the dependency decision gate and ongoing candidate matrix for a gokrb5-equivalent Rust implementation.\n\n")?;

        render_contract(f)?;
        render_decision_matrix(f)?;
        render_asn1_fixture_matrix(f)?;
        render_candidate_details(f)?;

        f.write_str("## Decision\n\n")?;
        f.write_str("Proceed with `rskrb5-ng` as the high-level pure-Rust implementation while reusing permissively licensed ASN.1/data-type crates where they pass gokrb5 vectors. Candidate crates remain useful dependencies or references, but none currently supplies a clean gokrb5-equivalent client/service/SPNEGO API. With RFC3962/RFC8009 AES, DES3-CBC-SHA1-KD, and RC4-HMAC coverage, password-derived ktutil-compatible keytab entry generation from explicit principals or SPN-style names, redacted keytab/ccache metadata JSON, X-CACHECONF ccache configuration entry read/write, EncryptedData signed-kvno preservation, PA-FOR-USER, PA-PAC-OPTIONS, PA-REQ-ENC-PA-REP, generic KRB-ERROR decode/encode/METHOD-DATA helpers and timing diagnostic decoding, generic KRB-PRIV decode/decrypt/build helpers, generic Ticket decode/decrypt/build helpers, generic KDC request decode/encode/build helpers, generic KDC reply decode/decrypt/encrypt helpers, generic AP-REQ/AP-REP decode/decrypt/build helpers, KRB-SAFE fixture decoding and keyed checksum helpers, and KRB-CRED decode/decrypt plus encrypted ccache import/export round-tripping, ChangePasswdData builders plus KRB-PRIV decode/decrypt/payload and kpasswd request-frame construction, generic AP-REQ construction, direct AS-service login helpers, complete kpasswd request assembly with generated reply keys, kpasswd AP-REP validation, a high-level Tokio password-change helper with initial kadmin/changepw ticket acquisition and credential update, gokrb5-compatible libdefaults including canonicalize KDC option handling, default_ccache_name, KRB5_CONFIG path-list loading, gokrb5-shaped config JSON, and comment/tab/no-blank-line config variants, per-enctype keytab login/service-ticket integration, keytab file-name helpers with uid/euid token expansion, direct KRB5_KTNAME load/save, and environment-preferred client keytab loading, assumed preauthentication, PA-FOR-USER, PA-PAC-OPTIONS, PA-REQ-ENC-PA-REP encrypted-padata validation, disable-fast-negotiation AS login control, runtime-neutral and Tokio S4U2Self exchange helpers, and runtime-neutral and Tokio S4U2Proxy request/exchange helpers with impersonated-user reply validation, KRB-ERROR timing surfacing, auto UDP/TCP KDC fallback with Docker AS/TGS, old-KDC password/keytab AS/TGS coverage, negative wrong-keytab and invalid-service KDC-error coverage, configured-KDC TCP failover, and gated kpasswd change/restore plus external kinit/kvno ccache coverage, configured/DNS SRV kpasswd transport and typed kpasswd request/reply/result exchanges, service replay-cache aging/shared-cache state plus file-name, configured-default, and environment-preferred keytab validators, GSSAPI MIC plus sealed/unsealed Wrap vectors, SPNEGO client AP-REQ/header generation with raw KRB5 Negotiate fallback, live Docker HTTP SPNEGO/raw-KRB5 Negotiate acceptance, and live replay-sequence rejection, config/DNS-backed Tokio KDC discovery, cross-realm TGS referral following with cached and renewable referral TGT sessions, configuration validation, structured client diagnostics, gokrb5-style refresh-window checks, primary/realm TGT renewal, cancellable Tokio auto-renewal, affirm-login reuse, Docker-backed destroy semantics, TGT/service-ticket cache removal, S4U2Self acquisition from a current service TGT, S4U2Proxy acquisition from a current service TGT and evidence ticket, unusable-session pruning, duplicate TGT/service-ticket cache selection, invalid TGT cache insertion handling, redacted debug output and zeroize-on-drop for key material, high-level Tokio client file-name and env constructors/write-back, cache JSON/lookup/removal, ccache write-back, KRB5CCNAME load/save, and FILE/WRFILE/DIR cache-name helpers with uid/euid token expansion and environment-preferred default ccache loading/write-back, HTTP/Tower borrowed, owned, file-name, env, configured-default, environment-preferred, shared-replay, and authenticated body-forwarding keytab adapters, an Axum Negotiate example, PAC credentials, UPN/DNS info, group SID derivation, gokrb5-style AD credential summaries, S4U delegation, device info, compressed/uncompressed client/device claims, and gated `TESTAD=1` AD keytab login, no-preauth login, user-domain service-ticket/PAC, and resource-trust service-ticket/PAC parity tests in place, the next implementation work is running the AD gate against a maintained lab and broadening privileged integration coverage.\n")
    }
}

/// Write the gokrb5 v8 contract table.
///
/// # Errors
///
/// Returns the formatter's error when writing fails.
fn render_contract(formatter: &mut Formatter<'_>) -> fmt::Result {
    formatter.write_str("## gokrb5 v8 Contract\n\n")?;
    formatter.write_str("| Area | gokrb5 tests | Gate | Porting note |\n")?;
    formatter.write_str("|---|---|---|---|\n")?;
    for area in V8_CONTRACT {
        writeln!(
            formatter,
            "| {} | {} | {} | {} |",
            area.area, area.gokrb5_tests, area.gate, area.porting_note
        )?;
    }
    formatter.write_str("\n")
}

/// Write the candidate-by-contract-area support matrix.
///
/// # Errors
///
/// Returns the formatter's error when writing fails.
fn render_decision_matrix(formatter: &mut Formatter<'_>) -> fmt::Result {
    formatter.write_str("## Candidate Decision Matrix\n\n")?;
    formatter.write_str("| Candidate |")?;
    for area in V8_CONTRACT {
        write!(formatter, " {} |", area.id)?;
    }
    formatter.write_str("\n")?;
    formatter.write_str("|---|")?;
    for _ in V8_CONTRACT {
        formatter.write_str("---:|")?;
    }
    formatter.write_str("\n")?;

    for assessment in ASSESSMENTS {
        write!(formatter, "| {} |", assessment.candidate.name())?;
        for area in V8_CONTRACT {
            let support = assessment.support_for(area.id);
            write!(formatter, " {support} |")?;
        }
        formatter.write_str("\n")?;
    }
    formatter.write_str("\n")
}

/// Write the ASN.1 fixture probe matrix.
///
/// # Errors
///
/// Returns the formatter's error when writing fails.
fn render_asn1_fixture_matrix(formatter: &mut Formatter<'_>) -> fmt::Result {
    formatter.write_str("## ASN.1 Fixture Probe Matrix\n\n")?;
    formatter.write_str(
        "| Fixture | Type | gokrb5 test | rasn-backed decode | rasn-backed round-trip | picky decode | picky round-trip |\n",
    )?;
    formatter.write_str("|---|---|---|---:|---:|---:|---:|\n")?;
    for fixture in ASN1_FIXTURES {
        writeln!(
            formatter,
            "| `{}` | {} | {} | {} | {} | {} | {} |",
            fixture.gokrb5_constant,
            fixture.der_type.name(),
            fixture.gokrb5_test,
            fixture.rasn_kerberos,
            fixture.rasn_kerberos_roundtrip,
            fixture.picky_krb,
            fixture.picky_krb_roundtrip
        )?;
    }
    formatter.write_str("\n")
}

/// Write one section per candidate crate with its license, recommendation and capabilities.
///
/// # Errors
///
/// Returns the formatter's error when writing fails.
fn render_candidate_details(formatter: &mut Formatter<'_>) -> fmt::Result {
    for report in REPORTS {
        formatter.write_str("## ")?;
        formatter.write_str(report.candidate.name())?;
        formatter.write_str("\n\n")?;
        formatter.write_str("- License: `")?;
        formatter.write_str(report.candidate.license())?;
        formatter.write_str("`\n")?;
        formatter.write_str("- Recommendation: ")?;
        formatter.write_str(report.recommendation)?;
        formatter.write_str("\n\n")?;
        formatter.write_str("| Area | Support | Note |\n")?;
        formatter.write_str("|---|---:|---|\n")?;
        for capability in report.capabilities {
            writeln!(
                formatter,
                "| {} | {} | {} |",
                capability.area, capability.support, capability.note
            )?;
        }
        formatter.write_str("\n")?;
    }
    Ok(())
}
