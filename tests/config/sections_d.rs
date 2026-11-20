//! Section-policy regressions for todo 15 D.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use core::error::Error;

    use rskrb5_ng::config::{Config, ParseMode};

    /// The timestamp prohibition is a typed Boolean: MIT's true spellings are admitted
    /// (the exchange engine honours them, plan 2 todo 9) and a non-Boolean fails closed.
    #[test]
    fn encrypted_timestamp_disable_is_a_typed_boolean() -> Result<(), Box<dyn Error>> {
        for mode in [ParseMode::Compatible, ParseMode::Strict] {
            for (value, admitted) in [("true", true), ("on", true), ("maybe", false)] {
                let parsed = Config::parse_with_mode(
                    &format!(
                        "[realms]\n EXAMPLE = {{\n disable_encrypted_timestamp = {value}\n }}\n"
                    ),
                    mode,
                );
                if parsed.is_ok() != admitted {
                    return Err(format!("{value} in {mode:?}: admitted {}", parsed.is_ok()).into());
                }
            }
        }
        Ok(())
    }

    /// Server sections produce strict errors even when empty.
    #[test]
    fn server_only_sections_are_not_silent() -> Result<(), Box<dyn Error>> {
        for section in ["kdcdefaults", "dbmodules", "logging"] {
            drop(
                Config::parse_with_mode(&format!("[{section}]\n"), ParseMode::Strict)
                    .err()
                    .ok_or("server section ignored")?,
            );
        }
        Ok(())
    }

    /// PKINIT enums are parsed even though authentication is unavailable.
    #[test]
    fn pkinit_invalid_enums_fail() -> Result<(), Box<dyn Error>> {
        for assignment in [
            "pkinit_eku_checking = invalid",
            "pkinit_dh_min_bits = 123",
            "pkinit_require_crl_checking = maybe",
            "pkinit_anchors = missing-prefix",
        ] {
            drop(
                Config::parse(&format!("[realms]\n EXAMPLE = {{\n {assignment}\n }}\n"))
                    .err()
                    .ok_or("malformed PKINIT accepted")?,
            );
        }
        Ok(())
    }
}
