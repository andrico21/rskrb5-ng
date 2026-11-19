//! Credential owners of the stepwise AS and TGS exchanges (WP-04).

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
pub(super) mod tests {
    use core::error::Error;
    use std::time::UNIX_EPOCH;

    use rasn::der;
    use rskrb5_ng::{
        client::{
            AsRepSession, Password,
            options::{AsReq, TgsReq},
            principal::Principal,
            stepwise::{
                Answer, ArmoredReply, ExchangeStep, InitCreds, InitCredsOptions, StepInput,
                TicketCreds, TicketOptions,
            },
        },
        kadmin::Request,
        keytab::EncryptionKey,
        ticket,
    };
    use zeroize::Zeroizing;

    use crate::tests::{pattern, redacted};

    pub(crate) fn run_audit() -> Result<(), Box<dyn Error>> {
        init_exchange_redacts_credentials()?;
        ticket_exchange_redacts_credentials()
    }

    /// PA-DATA whose encrypted part carries `cipher`.
    fn padata(cipher: &[u8]) -> Result<Vec<rasn_kerberos::PaData>, Box<dyn Error>> {
        Ok(vec![rasn_kerberos::PaData {
            r#type: 2,
            value: der::encode(&rasn_kerberos::EncryptedData {
                etype: 17,
                kvno: None,
                cipher: cipher.to_vec().into(),
            })?
            .into(),
        }])
    }

    /// Answers, step inputs, options, the exchange, its outbound request and an
    /// armored reply redact the password, PA-DATA, reply and keys they hold.
    #[test]
    fn init_exchange_redacts_credentials() -> Result<(), Box<dyn Error>> {
        let password = pattern(97);
        let preauth = pattern(65);
        let answer = || Answer::Password(Password::from_vec(password.clone()));
        redacted(&answer(), &[&password]);
        redacted(&StepInput::Answer(answer()), &[&password]);
        let options =
            InitCredsOptions::new(AsReq::new(UNIX_EPOCH, 42).with_padata(padata(&preauth)?));
        redacted(&options, &[&preauth]);
        let mut exchange = InitCreds::with_password(
            Principal::user("EXAMPLE.COM", "alice"),
            Some(Password::from_vec(password.clone())),
            options,
        );
        redacted(&exchange, &[&password, &preauth]);
        let step = exchange.step(StepInput::Start)?;
        let ExchangeStep::Outbound(outbound) = &step else {
            return Err(format!("expected an outbound request, got {step:?}").into());
        };
        assert!(
            outbound
                .message()
                .windows(preauth.len())
                .any(|window| window == preauth),
            "the request carries the PA-DATA"
        );
        redacted(outbound, &[&preauth]);
        redacted(&step, &[&preauth]);
        let reply = pattern(113);
        let strengthen = pattern(129);
        let cookie = pattern(145);
        redacted(
            &ArmoredReply::new(
                Zeroizing::new(reply.clone()),
                Some(EncryptionKey::new(17, strengthen.clone())),
                Some(cookie),
            ),
            &[&reply, &strengthen],
        );
        Ok(())
    }

    /// The ticket exchange, its options and a completed step redact the TGT's
    /// key and ticket and the request's PA-DATA.
    #[test]
    fn ticket_exchange_redacts_credentials() -> Result<(), Box<dyn Error>> {
        let frame = Request::parse(&hex::decode(
            include_str!("../fixtures/kpasswd-request.hex").trim(),
        )?)?;
        let ticket_bytes = ticket::encode(&frame.ap_req().ticket)?;
        let key = pattern(65);
        let preauth = pattern(81);
        let tgt = AsRepSession::new(
            Principal::user("TEST.GOKRB5", "testuser1"),
            Principal::tgt_service("TEST.GOKRB5"),
            EncryptionKey::new(17, key.clone()),
            ticket_bytes.clone().into(),
            [0; 4],
            UNIX_EPOCH,
            UNIX_EPOCH,
        );
        redacted(
            &ExchangeStep::Complete(Box::new(tgt.clone())),
            &[&key, &ticket_bytes],
        );
        let options =
            TicketOptions::new(TgsReq::new(UNIX_EPOCH, 43).with_padata(padata(&preauth)?))
                .with_user_to_user(&ticket_bytes)?;
        redacted(&options, &[&preauth, &ticket_bytes]);
        let exchange = TicketCreds::new(
            tgt,
            Principal::new("TEST.GOKRB5", 2, ["HTTP", "backend"]),
            options,
        )?;
        redacted(&exchange, &[&key, &ticket_bytes, &preauth]);
        Ok(())
    }
}
