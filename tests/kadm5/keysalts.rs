//! Key/salt tuples and supplied keys obey the runtime encryption policy (D2,
//! MIT-removed-7): single DES and RC4-EXP are refused by name, DES3 and RC4
//! only with `allow_des3`/`allow_rc4`, the Kerberos V4 and AFS salts never,
//! and nothing is sent for a refused request.

use rskrb5_ng::{
    client::{Password, principal::Principal},
    config::Config,
    crypto::CryptoPolicy,
    error::{Kadm5, Policy, RejectedFeature},
    kadm5::{KeyOptions, KeySaltTuple, PrincipalRecord, RemoteAdminClient, SaltType},
    keytab::EncryptionKey,
};
use tokio::{io::DuplexStream, task::JoinHandle};

use super::{
    context::TestError,
    operations::canned,
    server::{self, Script, Seen},
    support::{self, REALM},
    wire::Reader,
};

/// des-cbc-crc, single DES.
const DES_CBC_CRC: i32 = 1;

/// des3-cbc-sha1.
const DES3: i32 = 16;

/// rc4-hmac.
const RC4: i32 = 23;

/// rc4-hmac-exp.
const RC4_EXP: i32 = 24;

/// aes256-cts-hmac-sha1-96.
const AES256: i32 = 18;

/// A connected client with `options` and its server.
async fn connect(
    policy: Option<CryptoPolicy>,
) -> Result<
    (
        RemoteAdminClient<DuplexStream>,
        JoinHandle<Result<Seen, String>>,
    ),
    TestError,
> {
    let (stream, server) = server::spawn(canned(), Script::plain());
    let mut options = support::options();
    if let Some(policy) = policy {
        options = options.with_crypto_policy(policy);
    }
    let client = RemoteAdminClient::over_stream(stream, &support::credential()?, options).await?;
    Ok((client, server))
}

/// The policy of a profile that permits and allows DES3 and RC4.
fn legacy_policy() -> Result<CryptoPolicy, TestError> {
    let config = Config::parse(
        "[libdefaults]\n allow_des3 = true\n allow_rc4 = true\n \
         permitted_enctypes = aes256-cts-hmac-sha1-96 des3-cbc-sha1 arcfour-hmac\n",
    )?;
    Ok(CryptoPolicy::from_libdefaults(&config.libdefaults)?)
}

/// Whether `result` is the permanent typed rejection of `wanted`.
fn rejected(result: &Result<(), Kadm5>, wanted: RejectedFeature) -> bool {
    matches!(
        result,
        Err(Kadm5::Policy(Policy::RejectedFeature { feature, .. })) if *feature == wanted
    )
}

/// Single DES, RC4-EXP and the V4 salt are refused by name, before sending.
#[tokio::test]
async fn removed_enctypes_and_salts_are_rejected_by_name() -> Result<(), TestError> {
    // Given a client whose policy even allows DES3 and RC4.
    let (mut client, server) = connect(Some(legacy_policy()?)).await?;
    let record = PrincipalRecord::new(Principal::new(REALM, 1, ["carol"]));
    let password = Password::copy_from_str("pw");
    // When it asks for single DES, RC4-EXP and the V4 and AFS3 salts.
    let des = client
        .create_principal(
            &record,
            Some(&password),
            &[KeySaltTuple::new(DES_CBC_CRC, SaltType::Normal)],
        )
        .await;
    let rc4_exp = client
        .create_principal(
            &record,
            Some(&password),
            &[KeySaltTuple::new(RC4_EXP, SaltType::Normal)],
        )
        .await;
    let v4 = client
        .create_principal(
            &record,
            Some(&password),
            &[KeySaltTuple::new(AES256, SaltType::V4)],
        )
        .await;
    let afs3 = client
        .randomize_keys(
            record.principal(),
            &KeyOptions::new().with_keysalts(vec![KeySaltTuple::new(AES256, SaltType::Afs3)]),
        )
        .await
        .map(drop);
    let des_key = client
        .set_keys(
            record.principal(),
            &[EncryptionKey::new(DES_CBC_CRC, vec![1; 8])],
        )
        .await;
    drop(client);
    // Then each is refused with its typed rejection and nothing but INIT was sent.
    assert!(rejected(&des, RejectedFeature::SingleDes), "{des:?}");
    assert!(
        rejected(&rc4_exp, RejectedFeature::Rc4Export),
        "{rc4_exp:?}"
    );
    assert!(rejected(&v4, RejectedFeature::KerberosV4), "{v4:?}");
    assert!(rejected(&afs3, RejectedFeature::KerberosV4), "{afs3:?}");
    assert!(
        rejected(&des_key, RejectedFeature::SingleDes),
        "{des_key:?}"
    );
    assert_eq!(server.await??.calls.len(), 1);
    Ok(())
}

/// DES3 and RC4 are refused by the default policy and sent with the opt-in.
#[tokio::test]
async fn legacy_enctypes_need_the_opt_in() -> Result<(), TestError> {
    let record = PrincipalRecord::new(Principal::new(REALM, 1, ["dave"]));
    for etype in [DES3, RC4] {
        // Given the default policy, When DES3 or RC4 is asked for, Then it is not permitted.
        let (mut client, server) = connect(None).await?;
        let refused = client
            .create_principal(&record, None, &[KeySaltTuple::new(etype, SaltType::Normal)])
            .await;
        assert!(
            matches!(
                refused,
                Err(Kadm5::Policy(Policy::EnctypeNotPermitted { etype: refused_etype, .. })) if refused_etype == etype
            ),
            "{refused:?}"
        );
        drop(client);
        assert_eq!(server.await??.calls.len(), 1);
        // Given the explicit opt-in, When asked again, Then the tuple is sent.
        let (mut client, server) = connect(Some(legacy_policy()?)).await?;
        client
            .create_principal(&record, None, &[KeySaltTuple::new(etype, SaltType::Normal)])
            .await?;
        drop(client);
        let seen = server.await??;
        let (procedure, arguments) = seen.calls.last().ok_or("the create call")?;
        assert_eq!(*procedure, 18);
        let tail = arguments
            .len()
            .checked_sub(16)
            .ok_or("the tuple and password")?;
        let mut reader = Reader::new(arguments.get(tail..).ok_or("tail")?);
        assert_eq!((reader.u32()?, reader.i32()?, reader.i32()?), (1, etype, 0));
    }
    Ok(())
}

/// Without tuples the client sends none: the server's defaults apply, as
/// with MIT's client, and the client never adds a legacy default.
#[tokio::test]
async fn no_tuples_send_none() -> Result<(), TestError> {
    let (mut client, server) = connect(None).await?;
    let record = PrincipalRecord::new(Principal::new(REALM, 1, ["erin"]));
    client.create_principal(&record, None, &[]).await?;
    drop(
        client
            .randomize_keys(record.principal(), &KeyOptions::new())
            .await?,
    );
    drop(client);
    let seen = server.await??;
    assert_eq!(
        seen.calls.iter().map(|call| call.0).collect::<Vec<_>>(),
        [13, 1, 7]
    );
    Ok(())
}
