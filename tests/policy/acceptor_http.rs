use core::{
    convert::Infallible,
    error::Error,
    future::{Ready, ready},
    task::{Context, Poll},
};
use std::{env::temp_dir, fs, path::PathBuf, process};

use http_types::{Request, Response, StatusCode};
use rskrb5_ng::{
    Config,
    client::random_nonce,
    config::{
        Toggle,
        section_values::{Plugins, Value},
    },
    crypto::CryptoPolicy,
    error::Policy,
    http::{NegotiateLayer, NegotiateService},
    service::Validator,
    spnego::{self, Krb5MechToken, NegTokenInit, Token},
};
use tokio::runtime::Builder;
use tower_layer::Layer as _;
use tower_service::Service;

use super::{acceptor::fixture, client::policy_cause};

/// Isolated temporary keytab removed on every ordinary exit.
struct KeytabFile(PathBuf);
impl Drop for KeytabFile {
    fn drop(&mut self) {
        if let Err(_cleanup) = fs::remove_file(&self.0) {}
    }
}

/// Inner HTTP service makes successful authentication observable as 200.
#[derive(Clone)]
struct Accepted;
impl Service<Request<()>> for Accepted {
    type Response = Response<()>;
    type Error = Infallible;
    type Future = Ready<Result<Self::Response, Self::Error>>;
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, _req: Request<()>) -> Self::Future {
        ready(Ok(Response::new(())))
    }
}

/// Config-backed HTTP constructors refuse unsupported restrictions before keytab discovery.
#[test]
fn http_constructors_reject_restrictive_scopes() -> Result<(), Box<dyn Error>> {
    for scope in ["realm", "disable", "enable_only"] {
        let mut config = Config::parse("[realms]\nR = {\nkdc = 127.0.0.1:1\n}\n")?;
        config.libdefaults.default_keytab_name = "unsupported:policy-must-run-first".to_owned();
        if scope == "realm" {
            drop(config.realms.first_mut().ok_or("realm")?.relations.insert(
                "disable_encrypted_timestamp".to_owned(),
                Value::Boolean(Toggle::Enabled),
            ));
        } else {
            let mut plugins = Plugins::default();
            if scope == "disable" {
                plugins.disable.push("encrypted_timestamp".to_owned());
            } else {
                plugins.enable_only.push("other".to_owned());
            }
            drop(config.plugins.insert("clpreauth".to_owned(), plugins));
        }
        for result in [
            NegotiateLayer::from_default_keytab_name(&config).err(),
            NegotiateLayer::from_default_keytab(&config).err(),
            NegotiateService::from_default_keytab_name(Accepted, &config).err(),
            NegotiateService::from_default_keytab(Accepted, &config).err(),
        ] {
            let error = result.ok_or("restriction admitted")?;
            assert!(
                matches!(policy_cause(&error), Some(Policy::InvalidConfiguration)),
                "HTTP constructor bypassed whole-config admission for {scope}"
            );
        }
    }
    Ok(())
}

/// Config-based Validator and both HTTP constructors honor the exact permitted list.
#[test]
fn config_constructors_apply_policy() -> Result<(), Box<dyn Error>> {
    // Given a valid AES256 ticket and a file-backed matching keytab.
    let (keys, bytes, now) = fixture(18, 18, None)?;
    let suffix = random_nonce()?;
    let path = temp_dir().join(format!("policy-acceptor-{}-{suffix}.keytab", process::id()));
    keys.save(&path)?;
    let file = KeytabFile(path);
    let mut config = Config::parse("[libdefaults]\npermitted_enctypes = aes128-cts")?;
    config.libdefaults.default_keytab_name = file.0.to_string_lossy().into_owned();
    let token = Token::Init(NegTokenInit::krb5(
        Krb5MechToken::ap_req(bytes.clone()).encode()?,
    ));
    let header = spnego::negotiate_header(&token)?;
    // When all config-driven acceptance surfaces see the excluded ticket.
    let error = Validator::from_default_keytab_name(&config)?
        .with_now(now)
        .validate_ap_req(&bytes)
        .err()
        .ok_or("config policy ignored")?;
    assert!(policy_cause(&error).is_some());
    let mut layer = NegotiateLayer::from_default_keytab_name(&config)?
        .with_now(now)
        .layer(Accepted);
    let mut service = NegotiateService::from_default_keytab_name(Accepted, &config)?.with_now(now);
    let runtime = Builder::new_current_thread().enable_all().build()?;
    // Then both adapters refuse rather than invoking the successful inner path.
    assert_eq!(
        runtime
            .block_on(
                layer.call(
                    Request::builder()
                        .header("Authorization", &header)
                        .body(())?
                )
            )?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        runtime
            .block_on(
                service.call(
                    Request::builder()
                        .header("Authorization", &header)
                        .body(())?
                )
            )?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    Ok(())
}

/// HTTP builder permission admits RC4 only with explicit flag and membership.
#[test]
fn http_builders_propagate_legacy_permission() -> Result<(), Box<dyn Error>> {
    // Given valid RC4 GSS authentication and a default-denying HTTP service.
    let (keys, bytes, now) = fixture(23, 23, None)?;
    let header = spnego::negotiate_header(&Token::Init(NegTokenInit::krb5(
        Krb5MechToken::ap_req(bytes).encode()?,
    )))?;
    let config =
        Config::parse("[libdefaults]\nallow_rc4 = true\npermitted_enctypes = DEFAULT rc4")?;
    let policy = CryptoPolicy::from_libdefaults(&config.libdefaults)?;
    let runtime = Builder::new_current_thread().enable_all().build()?;
    let mut default = NegotiateService::new(Accepted, &keys).with_now(now);
    // When default and explicit builder policies are exercised.
    let rejected = runtime.block_on(
        default.call(
            Request::builder()
                .header("Authorization", &header)
                .body(())?,
        ),
    )?;
    let mut service = NegotiateService::new(Accepted, &keys)
        .with_now(now)
        .with_crypto_policy(policy.clone());
    let mut layered = NegotiateLayer::new(&keys)
        .with_now(now)
        .with_crypto_policy(policy)
        .layer(Accepted);
    // Then permission is identical through either builder.
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        runtime
            .block_on(
                service.call(
                    Request::builder()
                        .header("Authorization", &header)
                        .body(())?
                )
            )?
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        runtime
            .block_on(
                layered.call(
                    Request::builder()
                        .header("Authorization", &header)
                        .body(())?
                )
            )?
            .status(),
        StatusCode::OK
    );
    Ok(())
}
