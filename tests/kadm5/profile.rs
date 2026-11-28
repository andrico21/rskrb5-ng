//! What only the live kadmind suites reached: the client options a profile
//! makes, a GSS initiator's options under them, the minimum character classes
//! of a policy record, and MIT's names of every procedure.

use rskrb5_ng::{
    client::principal::Principal,
    config::Config,
    error::{Kadm5, Policy},
    gss::{ChannelBindings, InitiatorOptions},
    kadm5::{
        KeySaltTuple, Options, PolicyMask, PolicyRecord, PrincipalRecord, Procedure,
        RemoteAdminClient, SaltType,
    },
};
use tokio::{io::DuplexStream, task::JoinHandle};

use super::{
    context::TestError,
    operations::canned,
    server::{self, Script, Seen},
    support::{self, REALM},
    wire::Writer,
};

/// rc4-hmac.
const RC4: i32 = 23;

/// The v4 API version of the scenarios.
const V4: u32 = 0x1234_5704;

/// The bindings the bound acceptor holds.
const BINDINGS: &[u8] = b"tls-server-end-point:kadmin";

/// A server with `script` and a client connected to it with `options`.
async fn connect(
    script: Script,
    options: Options,
) -> Result<
    (
        Result<RemoteAdminClient<DuplexStream>, Kadm5>,
        JoinHandle<Result<Seen, String>>,
    ),
    TestError,
> {
    let (stream, server) = server::spawn(canned(), script);
    let credential = support::credential()?;
    let client = RemoteAdminClient::over_stream(stream, &credential, options).await;
    Ok((client, server))
}

/// A server whose acceptor holds [`BINDINGS`].
fn bound() -> Result<Script, TestError> {
    Ok(Script::bound(ChannelBindings::new(BINDINGS.to_vec())?))
}

/// Ask the server to create a principal with an RC4 key/salt tuple.
async fn create_rc4(client: &mut RemoteAdminClient<DuplexStream>) -> Result<(), Kadm5> {
    let record = PrincipalRecord::new(Principal::new(REALM, 1, ["frank"]));
    client
        .create_principal(&record, None, &[KeySaltTuple::new(RC4, SaltType::Normal)])
        .await
}

/// `Options::from_config` takes the profile's encryption policy: RC4 is sent
/// only when the profile allows and permits it.
#[tokio::test]
async fn the_profile_sets_the_encryption_policy() -> Result<(), TestError> {
    let legacy = Config::parse(
        "[libdefaults]\n allow_rc4 = true\n \
         permitted_enctypes = aes256-cts-hmac-sha1-96 arcfour-hmac\n",
    )?;
    // Given a client of a profile that allows RC4, when it asks for an RC4 tuple,
    let (client, server) = connect(Script::plain(), Options::from_config(&legacy, REALM)?).await?;
    let mut client = client?;
    create_rc4(&mut client).await?;
    drop(client);
    // then the create call carries it,
    let seen = server.await??;
    assert_eq!(
        seen.calls.iter().map(|call| call.0).collect::<Vec<_>>(),
        [13, 18]
    );
    // and a client of the default profile refuses it before sending.
    let (default_client, default_server) = connect(
        Script::plain(),
        Options::from_config(&Config::parse("")?, REALM)?,
    )
    .await?;
    let mut default_client = default_client?;
    let refused = create_rc4(&mut default_client).await;
    assert!(
        matches!(&refused, Err(Kadm5::Policy(Policy::EnctypeNotPermitted { etype, .. })) if *etype == RC4),
        "{refused:?}"
    );
    drop(default_client);
    assert_eq!(default_server.await??.calls.len(), 1);
    Ok(())
}

/// `Options::from_config` takes the profile's GSS initiator relations: with
/// `client_aware_channel_bindings` the initiator asserts the channel-binding
/// option without bindings, which an acceptor holding bindings refuses.
#[tokio::test]
async fn the_profile_sets_the_initiator_relations() -> Result<(), TestError> {
    let aware = Config::parse("[libdefaults]\n client_aware_channel_bindings = true\n")?;
    // Given an acceptor holding bindings, a client of the plain profile connects,
    let (plain, plain_server) =
        connect(bound()?, Options::from_config(&Config::parse("")?, REALM)?).await?;
    drop(plain?);
    assert!(!plain_server.await??.bound, "nothing was bound");
    // and a client of the aware profile is refused at establishment.
    let (refused, refused_server) = connect(bound()?, Options::from_config(&aware, REALM)?).await?;
    assert!(
        refused.is_err(),
        "the CBT assertion without bindings is refused"
    );
    assert!(
        refused_server.await?.is_err(),
        "the acceptor failed the context"
    );
    Ok(())
}

/// `Options::with_initiator_options` gives the RPCSEC_GSS initiator its
/// options: its channel bindings bind the context, other bindings are refused.
#[tokio::test]
async fn initiator_options_reach_the_gss_context() -> Result<(), TestError> {
    // Given an acceptor holding bindings and a client sending the same ones,
    let same =
        InitiatorOptions::new().with_channel_bindings(ChannelBindings::new(BINDINGS.to_vec())?);
    let (client, server) =
        connect(bound()?, support::options().with_initiator_options(same)).await?;
    drop(client?);
    // then the acceptor's context is channel-bound,
    assert!(server.await??.bound, "the client's bindings were used");
    // and a client sending other bindings is refused.
    let other = InitiatorOptions::new()
        .with_channel_bindings(ChannelBindings::new(b"another channel".to_vec())?);
    let (refused, refused_server) =
        connect(bound()?, support::options().with_initiator_options(other)).await?;
    assert!(refused.is_err(), "mismatched bindings are refused");
    assert!(
        refused_server.await?.is_err(),
        "the acceptor failed the context"
    );
    Ok(())
}

/// The minimum number of character classes is kept, marked in the mask, and
/// sent by `create_policy` as MIT's `kadm5_policy_ent_rec` field.
#[tokio::test]
async fn the_minimum_character_classes_are_set_and_sent() -> Result<(), TestError> {
    // Given a record whose classes are set twice,
    let record = PolicyRecord::new("classes")
        .with_pw_min_classes(2)
        .with_pw_min_classes(3);
    // then the last value is kept and the mask names the field and nothing else.
    assert_eq!(record.pw_min_classes(), 3);
    assert_eq!(record.mask().bits(), PolicyMask::PW_MIN_CLASSES.bits());
    // When it is created on the server,
    let (client, server) = connect(Script::plain(), support::options()).await?;
    let mut client = client?;
    client.create_policy(&record).await?;
    drop(client);
    // then the record carries the classes and the mask the field and the name.
    let wanted = Writer::new()
        .u32(V4)
        .nullstring(Some("classes"))
        .i32(0)
        .i32(0)
        .i32(0)
        .i32(3)
        .i32(0)
        .i32(0)
        .u32(0)
        .i32(0)
        .i32(0)
        .i32(0)
        .i32(0)
        .i32(0)
        .nullstring(None)
        .i32(0)
        .u32(1)
        .i32(0x2_0800)
        .finish();
    let seen = server.await??;
    assert_eq!(seen.calls.last(), Some(&(8, wanted)));
    Ok(())
}

/// Every procedure has MIT's client-function name (`kadm_rpc.h`, `client_rpc.c`).
#[test]
fn every_procedure_has_its_mit_name() {
    let names = [
        (Procedure::CreatePrincipal, "kadm5_create_principal"),
        (Procedure::DeletePrincipal, "kadm5_delete_principal"),
        (Procedure::ModifyPrincipal, "kadm5_modify_principal"),
        (Procedure::RenamePrincipal, "kadm5_rename_principal"),
        (Procedure::GetPrincipal, "kadm5_get_principal"),
        (Procedure::ChangePassword, "kadm5_chpass_principal"),
        (Procedure::RandomizeKeys, "kadm5_randkey_principal"),
        (Procedure::CreatePolicy, "kadm5_create_policy"),
        (Procedure::DeletePolicy, "kadm5_delete_policy"),
        (Procedure::ModifyPolicy, "kadm5_modify_policy"),
        (Procedure::GetPolicy, "kadm5_get_policy"),
        (Procedure::GetPrivileges, "kadm5_get_privs"),
        (Procedure::Init, "kadm5_init"),
        (Procedure::GetPrincipals, "kadm5_get_principals"),
        (Procedure::GetPolicies, "kadm5_get_policies"),
        (Procedure::SetKeys, "kadm5_setkey_principal"),
        (Procedure::CreatePrincipal3, "kadm5_create_principal_3"),
        (Procedure::ChangePassword3, "kadm5_chpass_principal_3"),
        (Procedure::RandomizeKeys3, "kadm5_randkey_principal_3"),
        (Procedure::SetKeys3, "kadm5_setkey_principal_3"),
        (Procedure::PurgeKeys, "kadm5_purgekeys"),
        (Procedure::GetStrings, "kadm5_get_strings"),
        (Procedure::SetString, "kadm5_set_string"),
        (Procedure::SetKeys4, "kadm5_setkey_principal_4"),
        (Procedure::ExtractKeys, "kadm5_get_principal_keys"),
        (Procedure::CreateAlias, "kadm5_create_alias"),
    ];
    for (procedure, name) in names {
        assert_eq!(procedure.name(), name, "{procedure:?}");
    }
}
