//! Deterministic fake-KDC exchanges, prompts and cancellation.

use alloc::sync::Arc;
use core::{
    error::Error,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use std::{sync::Mutex, time::UNIX_EPOCH};

use rasn::{der, types::Integer};
use zeroize::Zeroizing;

use super::{
    super::{KDC_ERR_PREAUTH_REQUIRED, PA_ETYPE_INFO2, Password, options::AsReq},
    Answer, ArmorRequest, ArmoredExchange, ArmoredReply, ExchangeStep, InitCreds, InitCredsOptions,
    Principal, StepInput, order,
};
use crate::{
    extensions::ProviderError,
    keytab::{self, EncryptionKey, Keytab, key_bytes::EVENTS as KEY_EVENTS},
};

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
    let now = UNIX_EPOCH
        .checked_add(Duration::from_secs(1_893_553_447))
        .ok_or("time")?;
    let request = AsReq::new(now, 7).with_etypes(vec![18_i32]);
    let exchange = InitCreds::with_password(
        client,
        Some(observed_password(&erased)),
        InitCredsOptions::new(request),
    );
    drop(exchange);
    assert!(erased.load(Ordering::SeqCst));
    Ok(())
}

/// The PA types of `offers` in the order `preferred` puts them.
fn types_in_order(offers: &[rasn_kerberos::PaData], preferred: &[i32]) -> Vec<i32> {
    order::sorted(offers, preferred)
        .iter()
        .map(|offer| offer.r#type)
        .collect()
}

/// MIT `sort_krb5_padata_sequence`: preferred types move to the front in
/// preference order; the rest keep the KDC's order.
#[test]
fn preferred_types_move_to_the_front() {
    let offers = vec![
        rasn_kerberos::PaData {
            r#type: 2_i32,
            value: Vec::from([0_u8; 0]).into(),
        },
        rasn_kerberos::PaData {
            r#type: 136_i32,
            value: Vec::from([0_u8; 0]).into(),
        },
        rasn_kerberos::PaData {
            r#type: 17_i32,
            value: Vec::from([0_u8; 0]).into(),
        },
        rasn_kerberos::PaData {
            r#type: 133_i32,
            value: Vec::from([0_u8; 0]).into(),
        },
        rasn_kerberos::PaData {
            r#type: 16_i32,
            value: Vec::from([0_u8; 0]).into(),
        },
    ];
    assert_eq!(
        types_in_order(&offers, &[17_i32, 16_i32, 15_i32, 14_i32]),
        [17_i32, 16_i32, 2_i32, 136_i32, 133_i32]
    );
    assert_eq!(
        types_in_order(&offers, &[]),
        [2_i32, 136_i32, 17_i32, 133_i32, 16_i32]
    );
    assert_eq!(
        types_in_order(&offers, &[99_i32, 133_i32]),
        [133_i32, 2_i32, 136_i32, 17_i32, 16_i32]
    );
}

/// A fake armor: requests pass through unchanged, the cookie each request is
/// asked to echo is recorded, and each reply comes back with the next scripted
/// cookie and strengthen key.
struct ScriptedArmor {
    /// The cookie of each armored request, in order.
    echoed: Arc<Mutex<Vec<Option<Vec<u8>>>>>,
    /// `(cookie, strengthen key)` of the replies still to unwrap, last first.
    replies: Vec<(Vec<u8>, EncryptionKey)>,
}

impl ArmoredExchange for ScriptedArmor {
    fn armor_request(
        &mut self,
        request: &ArmorRequest<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        self.echoed
            .lock()
            .map_err(|_poisoned| "poisoned")?
            .push(request.cookie.map(<[u8]>::to_vec));
        Ok(Zeroizing::new(request.request.to_vec()))
    }

    fn unwrap_reply(&mut self, reply: &[u8]) -> Result<ArmoredReply, ProviderError> {
        let (cookie, key) = self.replies.pop().ok_or("no scripted reply")?;
        Ok(ArmoredReply::new(
            Zeroizing::new(reply.to_vec()),
            Some(key),
            Some(cookie),
        ))
    }
}

/// The FAST seam threads the KDC's newest cookie into the next armored request,
/// and a newer strengthen key erases the one it replaces.
#[test]
fn armored_replies_thread_cookies_and_erase_replaced_strengthen_keys() -> Result<(), Box<dyn Error>>
{
    let client = Principal::user("TEST.GOKRB5", "testuser1");
    let mut keytab = Keytab::new();
    keytab.entries_mut().push(keytab::Entry::new(
        keytab::Principal::new("TEST.GOKRB5", 1, ["testuser1"]),
        0,
        1,
        EncryptionKey::new(18, vec![7_u8; 32]),
        1,
    ));
    let echoed = Arc::new(Mutex::new(Vec::new()));
    let armor = ScriptedArmor {
        echoed: Arc::clone(&echoed),
        replies: vec![
            (
                b"second-cookie".to_vec(),
                EncryptionKey::new(18, vec![9_u8; 32]),
            ),
            (
                b"first-cookie".to_vec(),
                EncryptionKey::new(17, vec![8_u8; 16]),
            ),
        ],
    };
    let request = AsReq::new(UNIX_EPOCH, 7).with_etypes(vec![18_i32]);
    let mut exchange =
        InitCreds::with_keytab(client, keytab, InitCredsOptions::new(request)).with_armor(armor);

    assert!(matches!(
        exchange.step(StepInput::Start)?,
        ExchangeStep::Outbound(_)
    ));
    assert!(matches!(
        exchange.step(StepInput::Reply(&preauth_required()?))?,
        ExchangeStep::Outbound(_)
    ));
    KEY_EVENTS.with_borrow_mut(Vec::clear);
    let finished = exchange.step(StepInput::Reply(&preauth_required()?));

    assert!(
        finished.is_err(),
        "a KRB-ERROR does not finish the exchange"
    );
    assert_eq!(
        *echoed.lock().map_err(|_poisoned| "poisoned")?,
        [None, Some(b"first-cookie".to_vec())]
    );
    KEY_EVENTS.with_borrow(|events| {
        assert_eq!(
            events
                .iter()
                .filter(|event| event.0 == 16)
                .collect::<Vec<_>>(),
            [&(16, true)],
            "the replaced 16-byte strengthen key is erased once: {events:?}"
        );
        assert!(events.iter().all(|event| event.1), "{events:?}");
    });
    Ok(())
}
