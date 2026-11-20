//! Trace events of real AS and TGS exchanges carry no secret.

use core::{error::Error, time::Duration};
use std::{
    env, fs, io, process,
    time::{SystemTime, UNIX_EPOCH},
};

use rskrb5_ng::{
    client::{
        AsRepSession, Password, Tokio,
        principal::Principal,
        stepwise::{InitCreds, InitCredsOptions, NoResponder, drive_tokio},
        transport::{KdcProtocol, Tokio as KdcTransport},
    },
    config::Config,
    error::Client as ClientError,
    trace::{Guard, Options, capture::Memory},
};
use tokio::runtime::{Builder, Runtime};

use crate::{
    child_env,
    harness::{self, Fixture},
};

/// The TEST.RSKRB5 KDC (fixture `mit-kdc`).
const MIT_KDC: Fixture = Fixture::new("mit-kdc", "INTEROP_MIT_KDC");

/// The libtest path of the child-process scenario.
const FILE_SCENARIO: &str = "scenarios::krb5_trace_file_records_a_login_without_secrets";

/// The current-thread Tokio runtime the scenarios run on.
fn runtime() -> io::Result<Runtime> {
    Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
}

/// The realm and its KDC.
fn config() -> Result<Config, Box<dyn Error>> {
    let realm = harness::var("INTEROP_MIT_REALM")?;
    Ok(Config::parse(&format!(
        "[libdefaults]\n default_realm = {realm}\n dns_lookup_kdc = false\n\
         [realms]\n {realm} = {{\n  kdc = {}\n }}\n",
        harness::var("INTEROP_MIT_KDC")?,
    ))?)
}

/// A nonce unique to the current time.
fn nonce() -> Result<u32, Box<dyn Error>> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(u32::try_from(elapsed.as_nanos() & 0x7fff_ffff)?)
}

/// The run's secret inventory: every env-file value under a key that ends in
/// `_PASSWORD`, `_SECRET` or `_TOKEN` (`scripts/interop/lib.sh`).
fn secrets() -> Vec<String> {
    env::vars()
        .filter(|(key, value)| {
            key.starts_with("INTEROP_")
                && !value.is_empty()
                && ["_PASSWORD", "_SECRET", "_TOKEN"]
                    .iter()
                    .any(|suffix| key.ends_with(suffix))
        })
        .map(|(_, value)| value)
        .collect()
}

/// Asserts that no secret of the inventory, and none of `extra`, is in `text`.
fn assert_secret_free(text: &str, extra: &[String]) {
    let inventory = secrets();
    assert!(
        inventory.iter().any(|secret| secret.len() >= 8),
        "the secret inventory is empty: the check would pass for any text"
    );
    for secret in inventory.iter().chain(extra) {
        assert!(!text.contains(secret.as_str()), "a secret reached the sink");
    }
}

/// One engine login of the user named by `user` with `password`, traced to `guard`.
async fn engine_login(
    user: &str,
    password: &str,
    guard: &Guard,
) -> Result<AsRepSession, ClientError> {
    let build = || -> Result<_, Box<dyn Error>> {
        let config = config()?;
        let options = InitCredsOptions::from_config(&config, SystemTime::now(), nonce()?)?;
        let client = Principal::user(harness::var("INTEROP_MIT_REALM")?, harness::var(user)?);
        Ok((config, options, client))
    };
    let (config, options, client) =
        build().map_err(|cause| ClientError::Responder(cause.to_string().into()))?;
    let transport = KdcTransport::new().with_timeout(Duration::from_secs(10));
    let mut exchange = InitCreds::with_password(
        client,
        Some(Password::from_vec(password.as_bytes().to_vec())),
        options,
    )
    .with_trace(guard.clone());
    drive_tokio(
        &transport,
        (&config, KdcProtocol::Tcp),
        &mut exchange,
        &mut NoResponder::default(),
    )
    .await
}

/// A guard over a capture sink that also allows identities.
fn captured() -> (Guard, Memory) {
    let sink = Memory::new();
    (
        Guard::new(sink.clone(), Options::new().with_identities(true)),
        sink,
    )
}

/// An AS success and a TGS success trace their steps, and the text holds no secret.
#[test]
fn auth_success_trace_contains_no_secrets() -> Result<(), Box<dyn Error>> {
    if !harness::require("auth_success_trace_contains_no_secrets", &[MIT_KDC])? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let password = harness::var("INTEROP_MIT_PREAUTH_USER_PASSWORD")?;
        let (guard, sink) = captured();
        let session = engine_login("INTEROP_MIT_PREAUTH_USER", &password, &guard).await?;
        let mut client = Tokio::with_password(
            config()?,
            KdcProtocol::Tcp,
            Principal::user(
                harness::var("INTEROP_MIT_REALM")?,
                harness::var("INTEROP_MIT_USER")?,
            ),
            harness::var("INTEROP_MIT_USER_PASSWORD")?.into_bytes(),
        )
        .with_transport(KdcTransport::new().with_timeout(Duration::from_secs(10)))
        .with_trace(guard.clone());
        let _tgt = client.login().await?;
        let service = Principal::parse_service(format!(
            "{}@{}",
            harness::var("INTEROP_MIT_HTTP_SERVICE")?,
            harness::var("INTEROP_MIT_REALM")?
        ))?;
        let granted = client.get_service_ticket(service).await?;
        let text = sink.lines().join("\n");
        for name in [
            "exchange-started",
            "request-sent",
            "reply-received",
            "completed",
        ] {
            assert!(text.contains(name), "no {name} event in:\n{text}");
        }
        assert!(
            text.contains("kind=initial") && text.contains("kind=ticket"),
            "{text}"
        );
        assert!(!text.contains("failed "), "{text}");
        assert_secret_free(
            &text,
            &[
                hex::encode(session.session_key().value()),
                hex::encode(session.ticket()),
                hex::encode(granted.session_key().value()),
                hex::encode(granted.ticket()),
            ],
        );
        Ok(())
    })
}

/// A wrong password is refused by the KDC; the failure is traced with its code and no secret.
#[test]
fn auth_failure_trace_contains_no_secrets() -> Result<(), Box<dyn Error>> {
    if !harness::require("auth_failure_trace_contains_no_secrets", &[MIT_KDC])? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let wrong = "wrong-password-MARKER-7f3a9c";
        let (guard, sink) = captured();
        let failure = engine_login("INTEROP_MIT_PREAUTH_USER", wrong, &guard).await;
        assert!(matches!(failure, Err(ClientError::Kdc(_))), "{failure:?}");
        let text = sink.lines().join("\n");
        assert!(text.contains("failed "), "{text}");
        assert!(text.contains("kdc_error=24"), "{text}");
        assert!(!text.contains("completed "), "{text}");
        assert_secret_free(&text, &[wrong.to_owned()]);
        Ok(())
    })
}

/// `KRB5_TRACE` names a file; a success and a failure are recorded there with no secret.
#[test]
fn krb5_trace_file_records_a_login_without_secrets() -> Result<(), Box<dyn Error>> {
    if child_env::in_child(FILE_SCENARIO) {
        let guard = Guard::from_options(&Options::from_env()?)?;
        assert!(guard.is_enabled(), "KRB5_TRACE did not select a file");
        return runtime()?.block_on(async {
            let password = harness::var("INTEROP_MIT_PREAUTH_USER_PASSWORD")?;
            drop(engine_login("INTEROP_MIT_PREAUTH_USER", &password, &guard).await?);
            let failure =
                engine_login("INTEROP_MIT_PREAUTH_USER", "wrong-password-MARKER", &guard).await;
            assert!(matches!(failure, Err(ClientError::Kdc(_))));
            Ok(())
        });
    }
    if !harness::require(
        "krb5_trace_file_records_a_login_without_secrets",
        &[MIT_KDC],
    )? {
        return Ok(());
    }
    let path = env::temp_dir().join(format!("rskrb5-interop-trace-{}.log", process::id()));
    child_env::run_in_child(FILE_SCENARIO, &[("KRB5_TRACE", Some(path.as_os_str()))]);
    let text = fs::read_to_string(&path)?;
    fs::remove_file(&path)?;
    let prefix = "[";
    assert!(text.lines().all(|line| line.starts_with(prefix)), "{text}");
    assert!(
        text.contains(": completed ") && text.contains(": failed "),
        "{text}"
    );
    assert_secret_free(&text, &["wrong-password-MARKER".to_owned()]);
    Ok(())
}
