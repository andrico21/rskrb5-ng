//! The kadm5 scenarios against the fixture's kadmind (`kadmind -nofork`,
//! `kadm5.acl` granting `admin/admin@TEST.RSKRB5` `*`).
//!
//! Every name a scenario creates starts with a per-run prefix and is deleted
//! before the scenario ends; MIT's `kadmin.local` in the container checks each
//! effect, independently of the Rust client.

use core::{error::Error, time::Duration};
use std::{
    io,
    process::{self, Command},
    time::{SystemTime, UNIX_EPOCH},
};

use rskrb5_ng::{
    client::{
        Password,
        options::AsReq,
        principal::Principal,
        random_nonce,
        transport::{KdcProtocol, Tokio as TokioKdcTransport},
    },
    config::Config,
    error::Kadm5,
    gss::Credential,
    kadm5::{
        self, ApiVersion, KeyOptions, KeySaltTuple, Options, PolicyRecord, PrincipalMask,
        PrincipalRecord, Privileges, RemoteAdminClient, SaltType,
    },
    keytab::EncryptionKey,
    rpcsec_gss::Protection,
};
use tokio::{
    net::TcpStream,
    runtime::{Builder, Runtime},
};

use crate::harness::{self, Fixture, assert_negotiated_padata, kdc_tap::KdcTap};

/// The fixture KDC, reached on `INTEROP_MIT_KDC`.
const MIT_KDC: Fixture = Fixture::new("mit-kdc", "INTEROP_MIT_KDC");

/// The fixture's kadmind, on `INTEROP_MIT_KADMIN`.
const MIT_KADMIN: Fixture = Fixture::new("mit-kdc", "INTEROP_MIT_KADMIN");

/// PA type of the encrypted timestamp (RFC 4120 section 5.2.7.2).
const PA_ENC_TIMESTAMP: i32 = 2;

/// aes256-cts-hmac-sha1-96.
const AES256_SHA1: i32 = 18;

/// `KADM5_AUTH_ADD` (`kadm_err.et`: the ovk base 43787520 plus 2).
const AUTH_ADD: u32 = 43_787_522;

/// `KADM5_AUTH_EXTRACT` (the ovk base plus 60): `*` in `kadm5.acl` grants
/// every privilege but `e`.
const AUTH_EXTRACT: u32 = 43_787_580;

/// The current-thread Tokio runtime the scenarios run on.
fn runtime() -> io::Result<Runtime> {
    Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
}

/// The realm with its KDC at `kdc` and its kadmind. The realm also offers
/// SPAKE first (plan 2 todo 9): an empty group list keeps the AS exchange for
/// `kadmin/admin` on the encrypted timestamp the scenarios prove.
fn config(kdc: &str) -> Result<Config, Box<dyn Error>> {
    let realm = harness::var("INTEROP_MIT_REALM")?;
    Ok(Config::parse(&format!(
        "[libdefaults]\n default_realm = {realm}\n dns_lookup_kdc = false\n spake_preauth_groups =\n\
         [realms]\n {realm} = {{\n  kdc = {kdc}\n  admin_server = {}\n }}\n",
        harness::var("INTEROP_MIT_KADMIN")?,
    ))?)
}

/// A per-run name prefix: no other suite and no earlier run uses it.
fn prefix() -> Result<String, Box<dyn Error>> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.subsec_nanos();
    Ok(format!("kadm5it{}x{nanos}", process::id()))
}

/// Run `query` with MIT's `kadmin.local` in the KDC container; its output.
fn kadmin_local(query: &str) -> Result<String, Box<dyn Error>> {
    let output = Command::new(harness::var("INTEROP_RUNTIME")?)
        .arg("exec")
        .arg(harness::var("INTEROP_MIT_CONTAINER")?)
        .args([
            "kadmin.local",
            "-r",
            &harness::var("INTEROP_MIT_REALM")?,
            "-q",
            query,
        ])
        .output()?;
    if !output.status.success() {
        return Err(format!("kadmin.local {query:?} failed: {}", output.status).into());
    }
    Ok(format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

/// Fail unless `kadmin.local`'s answer to `query` contains `expected`.
fn mit_says(query: &str, expected: &str) -> Result<(), Box<dyn Error>> {
    let output = kadmin_local(query)?;
    if output.contains(expected) {
        Ok(())
    } else {
        Err(format!("kadmin.local {query:?} does not say {expected:?}:\n{output}").into())
    }
}

/// A principal of the fixture realm.
fn principal(name: &str) -> Result<Principal, Box<dyn Error>> {
    Ok(Principal::new(
        harness::var("INTEROP_MIT_REALM")?,
        1,
        name.split('/').map(str::to_owned),
    ))
}

/// A `kadmin/admin` credential of `client` from an AS exchange with
/// `password` through a recording relay, as MIT's `kadm5_init_with_password`
/// gets it; asserts the exchange used the encrypted timestamp.
async fn admin_credential(client: &Principal, password: &str) -> Result<Credential, Box<dyn Error>> {
    let upstream = harness::var("INTEROP_MIT_KDC")?;
    let tap = KdcTap::start(KdcProtocol::Tcp, &upstream).await?;
    let tapped = config(tap.endpoint())?;
    let nonce = random_nonce()?;
    let options = AsReq::from_libdefaults(SystemTime::now(), nonce, &tapped.libdefaults)?;
    let service = kadm5::service_principal(&client.realm);
    let session = TokioKdcTransport::new()
        .with_timeout(Duration::from_secs(10))
        .login_as_service_with_password_config(
            &tapped,
            KdcProtocol::Tcp,
            client.clone(),
            service.clone(),
            password.as_bytes(),
            options,
        )
        .await?;
    let requests = tap.as_req_padata()?;
    let last = requests.last().ok_or("no AS-REQ was sent")?;
    assert_negotiated_padata("the kadmin/admin AS exchange", PA_ENC_TIMESTAMP, last)?;
    assert_eq!(session.service(), &service);
    Ok(Credential::from_service_ticket(&session))
}

/// A client connected through the profile's `admin_server` under `protection`.
async fn connect(
    credential: &Credential,
    protection: Protection,
) -> Result<RemoteAdminClient<TcpStream>, Box<dyn Error>> {
    let config = config(&harness::var("INTEROP_MIT_KDC")?)?;
    let realm = harness::var("INTEROP_MIT_REALM")?;
    let options = Options::from_config(&config, &realm)?
        .with_protection(protection)
        .with_timeout(Duration::from_secs(30));
    Ok(RemoteAdminClient::connect(&config, credential, options).await?)
}

/// Replaces `error` by its `Display` text: libtest prints a returned error
/// through `Debug`, which for the crate errors names only the variant.
fn shown(error: Box<dyn Error>) -> Box<dyn Error> {
    let text = error.to_string();
    drop(error);
    text.into()
}

/// `who` in MIT's string form (no escapes in the scenarios' names).
fn unparsed(who: &Principal) -> String {
    format!("{}@{}", who.components.join("/"), who.realm)
}

/// Create, modify, read and list the policy `name`.
async fn policy_operations(
    client: &mut RemoteAdminClient<TcpStream>,
    stem: &str,
    name: &str,
) -> Result<(), Box<dyn Error>> {
    client
        .create_policy(&PolicyRecord::new(name).with_pw_min_length(9))
        .await?;
    mit_says(&format!("getpol {name}"), "Minimum password length: 9")?;
    client
        .modify_policy(&PolicyRecord::new(name).with_pw_min_classes(3))
        .await?;
    mit_says(
        &format!("getpol {name}"),
        "Minimum number of password character classes: 3",
    )?;
    assert_eq!(client.get_policy(name).await?.pw_min_classes(), 3_i32);
    let pattern = format!("{stem}*");
    assert!(client.list_policies(Some(&pattern)).await?.iter().any(|listed| listed == name));
    Ok(())
}

/// Create `user` under `policy`, modify, read and list it, and change its password.
async fn principal_operations(
    client: &mut RemoteAdminClient<TcpStream>,
    stem: &str,
    user: &Principal,
    policy: &str,
) -> Result<(), Box<dyn Error>> {
    let first = Password::copy_from_str(&format!("{stem}Pw1-aB"));
    client
        .create_principal(&PrincipalRecord::new(user.clone()).with_policy(policy), Some(&first), &[])
        .await?;
    mit_says(&format!("getprinc {}", unparsed(user)), &format!("Policy: {policy}"))?;
    client
        .modify_principal(&PrincipalRecord::new(user.clone()).with_max_life(7200))
        .await?;
    mit_says(
        &format!("getprinc {}", unparsed(user)),
        "Maximum ticket life: 0 days 02:00:00",
    )?;
    let record = client.get_principal(user, PrincipalMask::NORMAL).await?;
    assert_eq!((record.max_life(), record.policy()), (7_200_i32, Some(policy)));
    let pattern = format!("{stem}*");
    let listed = client.list_principals(Some(&pattern)).await?;
    assert!(listed.contains(&unparsed(user)), "{listed:?}");
    let second = Password::copy_from_str(&format!("{stem}Pw2-cD"));
    client.change_password(user, &second, &KeyOptions::new()).await?;
    mit_says(&format!("getprinc {}", unparsed(user)), "Key: vno 2,")?;
    Ok(())
}

/// Randomize, set and purge `user`'s keys; set and read a string attribute;
/// the extraction of its keys is refused by the ACL.
async fn key_operations(
    client: &mut RemoteAdminClient<TcpStream>,
    user: &Principal,
) -> Result<(), Box<dyn Error>> {
    let shown_user = unparsed(user);
    let aes = KeyOptions::new().with_keysalts(vec![KeySaltTuple::new(AES256_SHA1, SaltType::Normal)]);
    let random = client.randomize_keys(user, &aes).await?;
    assert_eq!(random.iter().map(EncryptionKey::etype).collect::<Vec<_>>(), [AES256_SHA1]);
    mit_says(&format!("getprinc {shown_user}"), "Key: vno 3, aes256-cts-hmac-sha1-96")?;
    client
        .set_keys(user, &[EncryptionKey::new(AES256_SHA1, vec![0x5c; 32])])
        .await?;
    mit_says(&format!("getprinc {shown_user}"), "Key: vno 4, aes256-cts-hmac-sha1-96")?;
    let kept = client.randomize_keys(user, &aes.clone().keep_old(true)).await?;
    assert_eq!(kept.len(), 1);
    mit_says(&format!("getprinc {shown_user}"), "Number of keys: 2")?;
    client.purge_keys(user, 5).await?;
    mit_says(&format!("getprinc {shown_user}"), "Number of keys: 1")?;
    client.set_string(user, "session_enctypes", Some("aes256-cts")).await?;
    mit_says(&format!("getstrs {shown_user}"), "session_enctypes: aes256-cts")?;
    let strings = client.get_strings(user).await?;
    assert!(strings
        .iter()
        .any(|string| string.key() == "session_enctypes" && string.value() == "aes256-cts"));
    let extracted = client.get_principal_keys(user, 0).await;
    assert!(
        matches!(extracted, Err(Kadm5::Server { code: AUTH_EXTRACT, procedure: _ })),
        "{:?}",
        extracted.map(|data| data.len())
    );
    Ok(())
}

/// Rename `user`, give the new name an alias, and delete them and the policy.
async fn rename_and_delete(
    client: &mut RemoteAdminClient<TcpStream>,
    stem: &str,
    user: &Principal,
    policy: &str,
) -> Result<(), Box<dyn Error>> {
    let renamed = principal(&format!("{stem}renamed"))?;
    let alias = principal(&format!("{stem}alias"))?;
    client.rename_principal(user, &renamed).await?;
    mit_says(&format!("getprinc {}", unparsed(user)), "Principal does not exist")?;
    mit_says(
        &format!("getprinc {}", unparsed(&renamed)),
        &format!("Principal: {}", unparsed(&renamed)),
    )?;
    client.create_alias(&alias, &renamed).await?;
    mit_says(
        &format!("getprinc {}", unparsed(&alias)),
        &format!("Principal: {}", unparsed(&renamed)),
    )?;
    client.delete_principal(&alias).await?;
    client.delete_principal(&renamed).await?;
    mit_says(&format!("getprinc {}", unparsed(&renamed)), "Principal does not exist")?;
    client.delete_policy(policy).await?;
    mit_says(&format!("getpol {policy}"), "Policy does not exist")?;
    Ok(())
}

/// The administrator creates, modifies, renames, lists and deletes a
/// principal and a policy, changes a password, randomizes and sets keys,
/// purges old keys, sets a string attribute and an alias, and reads its
/// privileges; `kadmin.local` sees each effect.
#[test]
fn administrator_operations_take_effect() -> Result<(), Box<dyn Error>> {
    if !harness::require("administrator_operations_take_effect", &[MIT_KDC, MIT_KADMIN])? {
        return Ok(());
    }
    runtime()?
        .block_on(async {
            let admin = principal(&harness::var("INTEROP_MIT_ADMIN_PRINCIPAL")?)?;
            let password = harness::var("INTEROP_MIT_ADMIN_PASSWORD")?;
            let credential = admin_credential(&admin, &password).await?;
            let mut client = connect(&credential, Protection::Privacy).await?;
            assert_eq!(client.api_version(), ApiVersion::V4);
            let privileges = client.get_privileges().await?;
            assert!(privileges.contains(
                Privileges::GET | Privileges::ADD | Privileges::MODIFY | Privileges::DELETE
            ));
            let stem = prefix()?;
            let policy = format!("{stem}pol");
            let user = principal(&format!("{stem}user"))?;
            policy_operations(&mut client, &stem, &policy).await?;
            principal_operations(&mut client, &stem, &user, &policy).await?;
            key_operations(&mut client, &user).await?;
            rename_and_delete(&mut client, &stem, &user, &policy).await?;
            client.destroy().await?;
            let mut integrity = connect(&credential, Protection::Integrity).await?;
            assert_eq!(integrity.get_privileges().await?.bits(), privileges.bits());
            integrity.destroy().await?;
            Ok::<_, Box<dyn Error>>(())
        })
        .map_err(shown)
}

/// An ordinary user has no kadmind privilege: its create is refused by the
/// ACL with `KADM5_AUTH_ADD`, and nothing is created.
#[test]
fn unprivileged_principal_is_refused_by_the_acl() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "unprivileged_principal_is_refused_by_the_acl",
        &[MIT_KDC, MIT_KADMIN],
    )? {
        return Ok(());
    }
    runtime()?
        .block_on(async {
            let user = principal(&harness::var("INTEROP_MIT_USER")?)?;
            let password = harness::var("INTEROP_MIT_USER_PASSWORD")?;
            let credential = admin_credential(&user, &password).await?;
            let mut client = connect(&credential, Protection::Privacy).await?;
            assert_eq!(client.get_privileges().await?.bits(), 0);
            let stem = prefix()?;
            let target = principal(&format!("{stem}denied"))?;
            let refused = client
                .create_principal(&PrincipalRecord::new(target.clone()), None, &[])
                .await;
            assert!(
                matches!(
                    refused,
                    Err(Kadm5::Server {
                        code: AUTH_ADD,
                        procedure: _
                    })
                ),
                "{refused:?}"
            );
            client.destroy().await?;
            mit_says(
                &format!("getprinc {}@{}", target.components.join("/"), target.realm),
                "Principal does not exist",
            )?;
            Ok::<_, Box<dyn Error>>(())
        })
        .map_err(shown)
}
