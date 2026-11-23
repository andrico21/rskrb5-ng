//! IAKERB contexts, steps and errors with populated secrets.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
pub(super) mod tests {
    use core::error::Error;
    use std::time::UNIX_EPOCH;

    use rskrb5_ng::{
        Config,
        client::{KdcError, principal::Principal},
        error::{Client as ClientError, Gss, Iakerb, Spnego as SpnegoError},
        gss::{
            CredStore, Credential, CredentialUsage, InitStep, InitiatorOptions, Name, NameType,
            iakerb::{AcceptStep, IakerbContext, RelayPolicy},
        },
    };

    use crate::tests::{pattern, redacted};

    pub(crate) fn run_audit() -> Result<(), Box<dyn Error>> {
        iakerb_objects_redact_credentials()
    }

    /// The initiator context holds the password's exchange, the acceptor's step
    /// the tokens, the error the KDC's data: none shows them.
    #[test]
    fn iakerb_objects_redact_credentials() -> Result<(), Box<dyn Error>> {
        let password = pattern(97);
        let name = Name::import(b"alice@EXAMPLE.COM", NameType::User)?;
        let credential = Credential::acquire_cred_from(
            Some(&name),
            CredentialUsage::Initiate,
            &CredStore::new().with("password", &String::from_utf8_lossy(&password))?,
        )?;
        let config = Config::parse("[libdefaults]\n default_realm = EXAMPLE.COM\n")?;
        let target = Name::import(b"HTTP@www.example.com", NameType::HostbasedService)?;
        let mut context = IakerbContext::initiator(&config, target, InitiatorOptions::new())?;
        let InitStep::Continue(_first) = context.init_sec_context(&credential, None)? else {
            return Err("the first step sends a relay request".into());
        };
        redacted(&context, &[&password]);
        redacted(&IakerbContext::acceptor(RelayPolicy::new("EXAMPLE.COM")?), &[&password]);
        let token = pattern(113);
        redacted(&AcceptStep::Continue(token.clone()), &[&token]);
        let secret = pattern(129);
        let error = Iakerb::Gss(Gss::Spnego(SpnegoError::Client(Box::new(ClientError::Kdc(
            Box::new(
                KdcError::new(UNIX_EPOCH, 0, 25, Principal::tgt_service("EXAMPLE.COM"))
                    .with_e_data(Some(secret.clone().into())),
            ),
        )))));
        redacted(&error, &[&secret]);
        Ok(())
    }
}
