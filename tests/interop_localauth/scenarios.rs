//! A verified client of the MIT KDC as a local account: this crate against MIT's own answers.

use alloc::sync::Arc;
use core::{
    error::Error,
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};
use std::{
    env, fs,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink},
    path::{Path, PathBuf},
    process::{self, Command},
    time::{SystemTime, UNIX_EPOCH},
};

use rskrb5_ng::{
    ccache::Principal as Name,
    client::{
        options::AsReq,
        principal::Principal,
        transport::{KdcProtocol, Tokio as KdcTransport},
    },
    config::Config,
    error::LocalAuth,
    localauth::{
        Account, Authorization, Denial, LocalAuthorizer, LocalNameMapper, Module, authorize_local,
        k5login::Fault, principal_to_local_name, table::StaticAccounts,
    },
};
use tokio::runtime::{Builder, Runtime};

use crate::harness::{
    self, Fixture, assert_negotiated_enctype, assert_negotiated_padata, assert_ticket_flag,
    kdc_tap::KdcTap,
};

extern crate alloc;

/// The fixture KDC, reached on `INTEROP_MIT_KDC`.
const MIT_KDC: Fixture = Fixture::new("mit-kdc", "INTEROP_MIT_KDC");

/// Enctype ID of `aes256-cts-hmac-sha384-192`, the fixture's TGT key.
const AES256_SHA2: i32 = 20;

/// PA-DATA type of PA-ENC-TIMESTAMP (RFC 4120): the password login's mechanism.
const PA_ENC_TIMESTAMP: i32 = 2;

/// RFC 4120 ticket flag bit `initial`.
const FLAG_INITIAL: u32 = 9;

/// RFC 4120 ticket flag bit `pre-authent`.
const FLAG_PRE_AUTHENT: u32 = 10;

/// The probe MIT's own functions are asked through.
const PROBE: &str = "/opt/krb5/bin/localauth-probe";

/// Makes every scratch directory of a process distinct.
static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A directory that is removed when it goes out of scope.
struct Scratch {
    /// The directory.
    path: PathBuf,
}

impl Scratch {
    /// A new empty directory.
    fn new() -> Result<Self, Box<dyn Error>> {
        let path = env::temp_dir().join(format!(
            "interop-localauth-{}-{}-{}",
            process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        drop(fs::remove_dir_all(&self.path));
    }
}

/// Run `arguments` in the MIT container; its trimmed standard output.
fn mit(arguments: &[&str]) -> Result<String, Box<dyn Error>> {
    let output = Command::new(harness::var("INTEROP_RUNTIME")?)
        .arg("exec")
        .arg(harness::var("INTEROP_MIT_CONTAINER")?)
        .args(arguments)
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if output.status.success() {
        Ok(stdout)
    } else {
        Err(format!(
            "`{}` failed in the MIT container ({}): {}",
            arguments.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into())
    }
}

/// `a/b@REALM` as a principal (no escapes).
fn name(text: &str) -> Name {
    let (components, realm) = text.rsplit_once('@').unwrap_or((text, ""));
    Name::new(realm, 1, components.split('/').map(str::to_owned).collect())
}

/// The state of an account's `.k5login`, rebuilt on the host.
#[derive(Clone, Copy, Debug)]
enum State {
    /// No file.
    Missing,
    /// Owned by the account, mode 0644, lists the verified client.
    Listed,
    /// Lists the client but the account's uid is not the owner's.
    Foreign,
    /// Owned by the account, mode 0666.
    Wide,
    /// A symbolic link to a file that lists the client.
    Link,
}

/// The accounts of `provision.d/85-localauth.sh`, with the state of each file.
const ACCOUNTS: [(&str, State); 6] = [
    ("lauthmapped", State::Missing),
    ("lauthnone", State::Missing),
    ("lauthlist", State::Listed),
    ("lauthother", State::Foreign),
    ("lauthwide", State::Wide),
    ("lauthlink", State::Link),
];

/// The accounts rebuilt under `root`, as the resolver the authorizer is given.
fn accounts(root: &Path, client: &str) -> Result<StaticAccounts, Box<dyn Error>> {
    let mut table = StaticAccounts::new();
    let line = format!("{client}\n");
    for (account, state) in ACCOUNTS {
        let home = root.join(account);
        fs::create_dir_all(&home)?;
        let file = home.join(".k5login");
        let write = |path: &Path, mode: u32| -> Result<(), Box<dyn Error>> {
            fs::write(path, &line)?;
            fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
            Ok(())
        };
        let uid = fs::metadata(&home)?.uid();
        let account_uid = match state {
            State::Missing => uid,
            State::Listed => {
                write(&file, 0o644)?;
                uid
            }
            State::Foreign => {
                write(&file, 0o644)?;
                uid.wrapping_add(1)
            }
            State::Wide => {
                write(&file, 0o666)?;
                uid
            }
            State::Link => {
                let real = home.join("k5login.real");
                write(&real, 0o644)?;
                symlink(&real, &file)?;
                uid
            }
        };
        table = table.with_account(account, Account::new(account_uid, home));
    }
    Ok(table)
}

/// The current-thread runtime of the scenario.
fn runtime() -> Result<Runtime, Box<dyn Error>> {
    Ok(Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?)
}

/// Logs `preauthuser` in against the KDC through a recording relay and returns
/// the client principal of the AS reply, after pinning what was negotiated.
fn verified_client() -> Result<Name, Box<dyn Error>> {
    let (realm, kdc) = (
        harness::var("INTEROP_MIT_REALM")?,
        harness::var("INTEROP_MIT_KDC")?,
    );
    let user = harness::var("INTEROP_MIT_PREAUTH_USER")?;
    let password = harness::var("INTEROP_MIT_PREAUTH_USER_PASSWORD")?.into_bytes();
    runtime()?.block_on(async {
        let tap = KdcTap::start(KdcProtocol::Tcp, kdc.as_str()).await?;
        let nonce =
            u32::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() & 0x00ff_ffff)?
                | 0x2500_0000;
        let options = AsReq::new(SystemTime::now(), nonce)
            .with_ticket_lifetime(Duration::from_hours(1))
            .with_etypes(vec![AES256_SHA2]);
        let session = KdcTransport::new()
            .with_timeout(Duration::from_secs(10))
            .login_tgt_with_password(
                KdcProtocol::Tcp,
                tap.endpoint(),
                Principal::user(realm.clone(), user.clone()),
                &password,
                options,
            )
            .await
            .map_err(|failure| format!("password login of {user}: {failure}"))?;
        // The login that produced the ticket answered the KDC with the encrypted timestamp.
        let sent = tap.as_req_padata()?;
        let answered = sent
            .last()
            .ok_or("the login sent no AS-REQ through the relay")?;
        assert_negotiated_padata(
            "the AS-REQ that obtained the TGT",
            PA_ENC_TIMESTAMP,
            answered,
        )?;
        assert_ticket_flag("initial", FLAG_INITIAL, session.ticket_flags())?;
        assert_ticket_flag("pre-authent", FLAG_PRE_AUTHENT, session.ticket_flags())?;
        assert_negotiated_enctype(
            "TGT session key",
            AES256_SHA2,
            session.session_key().etype(),
        )?;
        let client = session.client();
        Ok::<_, Box<dyn Error>>(Name::new(
            client.realm.clone(),
            client.name_type,
            client.components.clone(),
        ))
    })
}

/// One `krb5_kuserok` question and both answers.
struct Row {
    /// The principal: `None` is the verified client.
    principal: Option<&'static str>,
    /// The local account.
    account: &'static str,
    /// What MIT answers (pinned, so a changed fixture or MIT is noticed).
    mit: bool,
    /// What this crate answers.
    ours: Authorization,
}

/// Local authorization rows. A row whose answers differ is stricter than MIT.
fn rows() -> [Row; 9] {
    let denied = |fault| Authorization::Denied(Denial::K5login(fault));
    [
        Row {
            principal: None,
            account: "lauthlist",
            mit: true,
            ours: Authorization::Authorized(Module::K5login),
        },
        Row {
            principal: None,
            account: "lauthnone",
            mit: true,
            ours: Authorization::Authorized(Module::An2ln),
        },
        Row {
            principal: None,
            account: "lauthmapped",
            mit: false,
            ours: Authorization::Denied(Denial::NoModuleAllowed),
        },
        Row {
            principal: None,
            account: "lauthother",
            mit: false,
            ours: denied(Fault::WrongOwner),
        },
        Row {
            principal: None,
            account: "lauthwide",
            mit: true,
            ours: denied(Fault::WritableByOthers),
        },
        Row {
            principal: None,
            account: "lauthlink",
            mit: true,
            ours: denied(Fault::Symlink),
        },
        Row {
            principal: None,
            account: "lauthnosuch",
            mit: false,
            ours: denied(Fault::UnknownAccount),
        },
        Row {
            principal: Some("kpasswduser@TEST.RSKRB5"),
            account: "lauthlist",
            mit: false,
            ours: denied(Fault::NotListed),
        },
        Row {
            principal: Some("testuser1@TEST.RSKRB5"),
            account: "lauthmapped",
            mit: true,
            ours: Authorization::Authorized(Module::An2ln),
        },
    ]
}

/// Name translation rows: principal, MIT's answer, this crate's, and whether
/// this crate is stricter.
const TRANSLATIONS: [(&str, &str, &str, bool); 6] = [
    ("testuser1@TEST.RSKRB5", "lauthmapped", "lauthmapped", false),
    ("preauthuser@TEST.RSKRB5", "lauthnone", "lauthnone", false),
    ("kpasswduser@TEST.RSKRB5", "lauthlist", "lauthlist", false),
    ("someone@TEST.RSKRB5", "someone", "someone", false),
    ("admin/admin@TEST.RSKRB5", "NOTRANS", "NOTRANS", false),
    ("preauthuser@OTHER.RSKRB5", "lauthnone", "NOTRANS", true),
];

/// The verified client of an MIT ticket is authorized as the local accounts MIT
/// authorizes it for, and refused where MIT refuses or this crate is stricter.
///
/// The profile is the fixture's own `85-localauth.conf`; MIT's answers come from
/// `localauth-probe` in the container, so the comparison is live.
#[test]
fn verified_client_is_authorized_as_mit_authorizes_it() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "verified_client_is_authorized_as_mit_authorizes_it",
        &[MIT_KDC],
    )? {
        return Ok(());
    }
    let client = verified_client()?;
    let client_text = client.principal_string();
    assert_eq!(
        client_text, "preauthuser@TEST.RSKRB5",
        "the AS reply names the logged-in user"
    );
    let realm = harness::var("INTEROP_MIT_REALM")?;
    let fragment = mit(&["cat", "/etc/krb5.conf.d/85-localauth.conf"])?;
    let config = Config::parse(&format!(
        "[libdefaults]\n default_realm = {realm}\n\n{fragment}\n"
    ))?;
    let scratch = Scratch::new()?;
    let resolver = Arc::new(accounts(&scratch.path, &client_text)?);
    let authorizer = LocalAuthorizer::from_config(&config, resolver)?;
    for row in rows() {
        let principal = row.principal.map_or_else(|| client.clone(), name);
        let text = principal.principal_string();
        let mit_answer = mit(&[PROBE, "kuserok", &text, row.account])? == "yes";
        let ours = authorize_local(&authorizer, &principal, row.account);
        let granted = matches!(ours, Authorization::Authorized(_));
        assert_eq!(mit_answer, row.mit, "MIT kuserok {text} as {}", row.account);
        assert_eq!(ours, row.ours, "authorize_local {text} as {}", row.account);
        let stricter = mit_answer && !granted;
        assert!(
            mit_answer == granted || stricter,
            "{text} as {}: this crate grants what MIT refuses",
            row.account
        );
    }
    let mapper = LocalNameMapper::from_config(&config)?;
    for (text, mit_expected, ours_expected, stricter) in TRANSLATIONS {
        let mit_answer = mit(&[PROBE, "an2ln", text])?;
        let ours = match principal_to_local_name(&mapper, &name(text)) {
            Ok(local) => local,
            Err(LocalAuth::NoTranslation) => "NOTRANS".to_owned(),
            Err(other) => return Err(other.into()),
        };
        assert_eq!(mit_answer, mit_expected, "MIT an2ln {text}");
        assert_eq!(ours, ours_expected, "principal_to_local_name {text}");
        assert_eq!(
            mit_answer != ours,
            stricter,
            "{text}: the declared difference"
        );
    }
    Ok(())
}
