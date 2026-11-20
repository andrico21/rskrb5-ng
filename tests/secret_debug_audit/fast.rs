//! Credential owners of FAST and the encrypted challenge (WP-05).

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
pub(super) mod tests {
    use core::error::Error;
    use std::time::UNIX_EPOCH;

    use rskrb5_ng::{
        ccache::{
            CCache, Credential, CredentialTimes, EncryptionKey as CacheKey,
            Principal as CachePrincipal,
        },
        client::{
            AsRepSession, Password,
            options::AsReq,
            principal::Principal,
            stepwise::{ArmoredExchange as _, InitCreds, InitCredsOptions, StepInput},
        },
        crypto::{KerberosEtype, prf},
        kadmin::Request,
        keytab::EncryptionKey,
        preauth::{
            encrypted_challenge::EncryptedChallenge,
            fast::{ArmorCache, ArmorSource, Exchange, Policy},
        },
        ticket,
    };

    use crate::tests::{pattern, redacted};

    pub(crate) fn run_audit() -> Result<(), Box<dyn Error>> {
        fast_owners_redact_credentials()?;
        encrypted_challenge_redacts_its_keys()
    }

    /// A TGT session built from the kpasswd fixture's ticket.
    fn tgt(key: &[u8]) -> Result<(AsRepSession, Vec<u8>), Box<dyn Error>> {
        let frame = Request::parse(&hex::decode(
            include_str!("../fixtures/kpasswd-request.hex").trim(),
        )?)?;
        let ticket_bytes = ticket::encode(&frame.ap_req().ticket)?;
        Ok((
            AsRepSession::new(
                Principal::user("TEST.GOKRB5", "host"),
                Principal::tgt_service("TEST.GOKRB5"),
                EncryptionKey::new(17, key.to_vec()),
                ticket_bytes.clone().into(),
                [0; 4],
                UNIX_EPOCH,
                UNIX_EPOCH,
            ),
            ticket_bytes,
        ))
    }

    /// The armor source, the armor cache and an armored exchange redact the
    /// armor ticket, its session key and the armor key.
    #[test]
    fn fast_owners_redact_credentials() -> Result<(), Box<dyn Error>> {
        let key = pattern(161);
        let (session, ticket_bytes) = tgt(&key)?;
        redacted(
            &ArmorSource::Ticket(Box::new(session.clone())),
            &[&key, &ticket_bytes],
        );
        let mut cache = CCache::new(CachePrincipal::new(
            "TEST.GOKRB5",
            1,
            vec!["host".to_owned()],
        ));
        cache.credentials_mut().push(Credential::new(
            CachePrincipal::new("TEST.GOKRB5", 1, vec!["host".to_owned()]),
            CachePrincipal::new(
                "TEST.GOKRB5",
                2,
                vec!["krbtgt".to_owned(), "TEST.GOKRB5".to_owned()],
            ),
            CacheKey::new(17, key.clone()),
            CredentialTimes::default(),
            [0; 4],
            ticket_bytes.clone().into(),
        ));
        redacted(&ArmorCache::new(cache), &[&key, &ticket_bytes]);
        let mut fast = Exchange::new(Policy::Required, ArmorSource::Ticket(Box::new(session)));
        drop(
            InitCreds::with_password(
                Principal::user("TEST.GOKRB5", "alice"),
                Some(Password::from_vec(pattern(177))),
                InitCredsOptions::new(AsReq::new(UNIX_EPOCH, 44)),
            )
            .with_armor(&mut fast)
            .step(StepInput::Start)?,
        );
        let armor_key = fast.armor_key().ok_or("not armored")?.value().to_vec();
        redacted(&fast, &[&armor_key, &ticket_bytes]);
        Ok(())
    }

    /// The challenge keys never reach `Debug`.
    #[test]
    fn encrypted_challenge_redacts_its_keys() -> Result<(), Box<dyn Error>> {
        let armor = pattern(193);
        let long_term = pattern(209);
        let etype = KerberosEtype::from_etype_id(17).ok_or("aes128")?;
        let derived = |pepper: &[u8]| {
            prf::krb_fx_cf2(
                &prf::CfInput::new(prf::Key::new(etype, &armor), pepper),
                &prf::CfInput::new(prf::Key::new(etype, &long_term), b"challengelongterm"),
            )
        };
        let client = derived(b"clientchallengearmor")?;
        let kdc = derived(b"kdcchallengearmor")?;
        redacted(
            &EncryptedChallenge::new(
                &EncryptionKey::new(17, armor.clone()),
                &EncryptionKey::new(17, long_term.clone()),
            )?,
            &[&client, &kdc],
        );
        Ok(())
    }
}
