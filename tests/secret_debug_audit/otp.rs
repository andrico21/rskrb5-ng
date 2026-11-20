//! Credential owners of OTP preauthentication (WP-08).

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
pub(super) mod tests {
    use core::error::Error;

    use rasn::der;
    use rasn_kerberos::otp::{OtpFlags, OtpTokenInfo, PaOtpChallenge};
    use rskrb5_ng::{
        client::{
            principal::Principal,
            stepwise::{Answer, NoResponder, Prompt, StepInput},
        },
        extensions::ProviderError,
        preauth::otp::{Challenge, Policy, Responder, Responders, Response},
    };

    use crate::tests::{pattern, redacted};

    pub(crate) fn run_audit() -> Result<(), Box<dyn Error>> {
        otp_answer_redacts_credentials()?;
        otp_responders_redact_what_they_wrap();
        Ok(())
    }

    /// A user that holds its secret and answers nothing.
    struct Holder {
        /// A credential a derived `Debug` would print.
        secret: Vec<u8>,
    }

    impl Responder for Holder {
        fn select(&mut self, _challenge: &Challenge) -> Result<Response, ProviderError> {
            Ok(Response::new(0, self.secret.clone()))
        }
    }

    /// The answer, its wrappers and the prompt carry the OTP value and the PIN and
    /// redact both (run by `run_audit`, which the owner audit calls).
    #[test]
    fn otp_answer_redacts_credentials() -> Result<(), Box<dyn Error>> {
        let value = pattern(177);
        let pin = pattern(33);
        let response = || {
            Response::new(0, value.clone())
                .with_pin(String::from_utf8(pin.clone()).unwrap_or_default())
        };
        redacted(&response(), &[&value, &pin]);
        redacted(&Answer::Otp(response()), &[&value, &pin]);
        redacted(&StepInput::Answer(Answer::Otp(response())), &[&value, &pin]);
        let wire = PaOtpChallenge::new(
            pattern(81).into(),
            vec![OtpTokenInfo::new(OtpFlags(rasn::types::BitString::repeat(
                false, 32,
            )))],
        );
        let challenge = Challenge::decode(&der::encode(&wire)?, &Policy::default())?;
        let prompt = Prompt::Otp {
            client: Principal::user("EXAMPLE.COM", "alice"),
            challenge,
        };
        assert!(format!("{prompt:?}").contains("alice"));
        Ok(())
    }

    /// A wrapped responder's secret never reaches the wrapper's `Debug` output.
    fn otp_responders_redact_what_they_wrap() {
        let secret = pattern(209);
        let wrapped = Responders::new(
            NoResponder::default(),
            Holder {
                secret: secret.clone(),
            },
        );
        redacted(&wrapped, &[&secret]);
    }
}
