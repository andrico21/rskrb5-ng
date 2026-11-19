//! Deterministic fake-KDC exchanges, prompts and cancellation.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use alloc::sync::Arc;
    use core::{
        error::Error,
        sync::atomic::{AtomicBool, Ordering},
    };
    use std::time::{Duration, UNIX_EPOCH};

    use rasn::{der, types::Integer};

    use super::super::{
        super::{KDC_ERR_PREAUTH_REQUIRED, PA_ETYPE_INFO2, Password, options::AsReq},
        Answer, ExchangeStep, InitCreds, InitCredsOptions, Principal, StepInput, order,
    };
    use crate::keytab::key_bytes::EVENTS as KEY_EVENTS;

    /// A KDC time as a Kerberos time.
    fn kerberos_time(seconds: u64) -> Result<rasn_kerberos::KerberosTime, Box<dyn Error>> {
        let time = UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds))
            .ok_or("time")?;
        Ok(rasn_kerberos::KerberosTime(
            chrono::DateTime::<chrono::Utc>::from(time).into(),
        ))
    }

    /// A `PREAUTH_REQUIRED` error offering AES256 with the MIT default salt.
    fn preauth_required() -> Result<Vec<u8>, Box<dyn Error>> {
        let info = rasn_kerberos::EtypeInfo2::from([rasn_kerberos::EtypeInfo2Entry {
            etype: 18,
            salt: Some(rasn_kerberos::KerberosString::try_from(
                "TEST.GOKRB5testuser1".to_owned(),
            )?),
            s2kparams: None,
        }]);
        let offers = rasn_kerberos::MethodData::from([rasn_kerberos::PaData {
            r#type: PA_ETYPE_INFO2,
            value: der::encode(&info)?.into(),
        }]);
        let realm = rasn_kerberos::KerberosString::try_from("TEST.GOKRB5".to_owned())?;
        let tgs = rasn_kerberos::PrincipalName {
            r#type: 2,
            string: vec![
                rasn_kerberos::KerberosString::try_from("krbtgt".to_owned())?,
                realm.clone(),
            ],
        };
        Ok(der::encode(&rasn_kerberos::KrbError {
            pvno: Integer::from(5_i32),
            msg_type: Integer::from(30_i32),
            ctime: None,
            cusec: None,
            stime: kerberos_time(1_893_553_440)?,
            susec: Integer::from(0_i32),
            error_code: KDC_ERR_PREAUTH_REQUIRED,
            crealm: None,
            cname: None,
            realm,
            sname: tgs,
            e_text: None,
            e_data: Some(der::encode(&offers)?.into()),
        })?)
    }

    /// A password whose drop is observed.
    fn observed_password(erased: &Arc<AtomicBool>) -> Password {
        let mut password = Password::from_vec(b"passwordvalue".to_vec());
        password.observe_erasure(Arc::clone(erased));
        password
    }

    /// An exchange abandoned after the challenge erases the prompted password and
    /// the derived reply key when it is dropped.
    #[test]
    fn cancellation_drops_every_secret() -> Result<(), Box<dyn Error>> {
        let client = Principal::user("TEST.GOKRB5", "testuser1");
        let request = AsReq::new(UNIX_EPOCH, 7).with_etypes(vec![18_i32]);
        let mut exchange = InitCreds::with_password(client, None, InitCredsOptions::new(request));
        let erased = Arc::new(AtomicBool::new(false));

        assert!(matches!(
            exchange.step(StepInput::Start)?,
            ExchangeStep::Outbound(_)
        ));
        assert!(matches!(
            exchange.step(StepInput::Reply(&preauth_required()?))?,
            ExchangeStep::Prompt(_)
        ));
        let answer = Answer::Password(observed_password(&erased));
        assert!(matches!(
            exchange.step(StepInput::Answer(answer))?,
            ExchangeStep::Outbound(_)
        ));
        KEY_EVENTS.with_borrow_mut(Vec::clear);
        drop(exchange);

        assert!(
            erased.load(Ordering::SeqCst),
            "the password was still plaintext at drop"
        );
        KEY_EVENTS.with_borrow(|events| assert_eq!(events.as_slice(), [(32, true)]));
        Ok(())
    }

    /// An exchange abandoned at its prompt erases an answer it never used.
    #[test]
    fn unanswered_exchange_holds_no_secret() -> Result<(), Box<dyn Error>> {
        let client = Principal::user("TEST.GOKRB5", "testuser1");
        let erased = Arc::new(AtomicBool::new(false));
        let request = AsReq::new(UNIX_EPOCH, 7).with_etypes(vec![18_i32]);
        let exchange = InitCreds::with_password(
            client,
            Some(observed_password(&erased)),
            InitCredsOptions::new(request),
        );
        drop(exchange);
        assert!(erased.load(Ordering::SeqCst));
        Ok(())
    }

    /// MIT `sort_krb5_padata_sequence`: preferred types move to the front in
    /// preference order; the rest keep the KDC's order.
    #[test]
    fn preferred_types_move_to_the_front() {
        let offers: Vec<rasn_kerberos::PaData> = [2_i32, 136, 17, 133, 16]
            .iter()
            .map(|pa_type| rasn_kerberos::PaData {
                r#type: *pa_type,
                value: Vec::new().into(),
            })
            .collect();
        let order = |preferred: &[i32]| {
            order::sorted(&offers, preferred)
                .iter()
                .map(|offer| offer.r#type)
                .collect::<Vec<_>>()
        };
        assert_eq!(order(&[17, 16, 15, 14]), [17, 16, 2, 136, 133]);
        assert_eq!(order(&[]), [2, 136, 17, 133, 16]);
        assert_eq!(order(&[99, 133]), [133, 2, 136, 17, 16]);
    }
}
