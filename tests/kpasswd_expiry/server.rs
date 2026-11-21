//! A fake kpasswd server over loopback TCP: framing, replies and the requests it opens.

use core::{
    future::pending,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
extern crate alloc;

use alloc::sync::Arc;
use std::{io::ErrorKind, time::SystemTime};

use rasn::der;
use rskrb5_ng::{
    ap_rep::encode_build_ap_rep_with_confounder,
    ap_req::decrypt_ap_req_authenticator,
    client::{AP_REQ_AUTHENTICATOR_USAGE, Password},
    config::Config,
    kadmin::{self, ChangePasswdData, Request, build_krb_priv_with_confounder},
    keytab::EncryptionKey,
    krb_priv::{EncKrbPrivPartOptions, ipv4_host_address},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};

use super::{
    TestError,
    realm::{Realm, kerberos_time},
    support::{REALM, changepw_key, held},
};

/// Read one length-prefixed request; `None` when the peer closed before a new one.
async fn read_frame(socket: &mut TcpStream) -> Result<Option<Vec<u8>>, TestError> {
    let mut header = [0_u8; 4];
    match timeout(Duration::from_secs(10), socket.read_exact(&mut header)).await? {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let mut request = vec![0_u8; usize::try_from(u32::from_be_bytes(header))?];
    let _: usize = timeout(Duration::from_secs(10), socket.read_exact(&mut request)).await??;
    Ok(Some(request))
}

/// Accept one TCP client within 10 s and read its length-prefixed request.
pub(super) async fn read_request(
    listener: &TcpListener,
) -> Result<(Vec<u8>, TcpStream), TestError> {
    let (mut socket, _) = timeout(Duration::from_secs(10), listener.accept()).await??;
    let request = read_frame(&mut socket)
        .await?
        .ok_or("the client sent no request")?;
    Ok((request, socket))
}

/// Write one length-prefixed response.
pub(super) async fn write_response(
    socket: &mut TcpStream,
    response: &[u8],
) -> Result<(), TestError> {
    socket
        .write_all(&u32::try_from(response.len())?.to_be_bytes())
        .await?;
    socket.write_all(response).await?;
    Ok(())
}

/// A configuration pointing `TEST.GOKRB5` at the given KDC and kpasswd servers over TCP.
pub(super) fn config(kdc: Option<&str>, kpasswd: &str) -> Result<Config, TestError> {
    let kdc_line = kdc.map_or_else(String::new, |addr| format!(" kdc = {addr}\n"));
    Ok(Config::parse(&format!(
        "[libdefaults]\n dns_lookup_kdc = false\n udp_preference_limit = 1\n\
         [realms]\n {REALM} = {{\n{kdc_line} kpasswd_server = {kpasswd}\n }}\n"
    ))?)
}

/// What a fake kpasswd server saw in one request.
pub(super) struct Seen {
    /// The authenticator of the AP-REQ, for the reply's echoed time.
    pub authenticator: rasn_kerberos::Authenticator,
    /// The decrypted request: the `ChangePasswdData` of a set-password, or the password of a
    /// change-password (no target fields).
    pub change_data: ChangePasswdData,
    /// The protocol version of the frame: 1 (change) or `0xff80` (set).
    pub version: u16,
}

/// Decrypt a kpasswd request under the changepw session key.
pub(super) fn open_request(request: &[u8]) -> Result<Seen, TestError> {
    let parsed = Request::parse(request)?;
    let authenticator =
        decrypt_ap_req_authenticator(parsed.ap_req(), &changepw_key(), AP_REQ_AUTHENTICATOR_USAGE)?;
    let subkey = authenticator.subkey.as_ref().ok_or("reply key included")?;
    let reply_key = EncryptionKey::new(subkey.r#type, subkey.value.as_ref().to_vec());
    let enc_part = kadmin::decrypt_krb_priv_enc_part(parsed.krb_priv(), &reply_key)?;
    let version = u16::from_be_bytes(
        request
            .get(2..4)
            .ok_or("frame header")?
            .try_into()
            .map_err(|_unused| "frame header")?,
    );
    let change_data = if version == 1 {
        ChangePasswdData::new(Password::from_vec(enc_part.user_data.as_ref().to_vec()))
    } else {
        ChangePasswdData::decode_der(enc_part.user_data.as_ref())?
    };
    Ok(Seen {
        authenticator,
        change_data,
        version,
    })
}

/// An authenticated kpasswd reply frame with result `code` and `text`: the AP-REP
/// is under the changepw session key and selects a server subkey for the KRB-PRIV.
pub(super) fn authenticated_reply(
    seen: &Seen,
    code: u16,
    text: &[u8],
) -> Result<Vec<u8>, TestError> {
    reply_under(seen, &changepw_key(), code, text)
}

/// A reply that looks authenticated but is sealed under a key the client does not share:
/// what a party without the session key can forge.
pub(super) fn forged_reply(seen: &Seen, code: u16, text: &[u8]) -> Result<Vec<u8>, TestError> {
    reply_under(seen, &EncryptionKey::new(18, vec![0xee; 32]), code, text)
}

/// A reply frame whose AP-REP is sealed under `ap_rep_key`.
fn reply_under(
    seen: &Seen,
    ap_rep_key: &EncryptionKey,
    code: u16,
    text: &[u8],
) -> Result<Vec<u8>, TestError> {
    let response_key = EncryptionKey::new(18, vec![0x77; 32]);
    let ap_rep = encode_build_ap_rep_with_confounder(
        &rasn_kerberos::EncApRepPart {
            ctime: seen.authenticator.ctime.clone(),
            cusec: seen.authenticator.cusec.clone(),
            subkey: Some(rasn_kerberos::EncryptionKey {
                r#type: response_key.etype(),
                value: response_key.value().to_vec().into(),
            }),
            seq_number: Some(99),
        },
        ap_rep_key,
        None,
        &[0x10; 16],
    )?;
    let mut result = code.to_be_bytes().to_vec();
    result.extend_from_slice(text);
    let krb_priv = build_krb_priv_with_confounder(
        result,
        EncKrbPrivPartOptions::new(ipv4_host_address([127, 0, 0, 1])).with_sequence_number(99),
        &response_key,
        &[0x20; 16],
    )?;
    let mut body = ap_rep.clone();
    body.extend_from_slice(&der::encode(&krb_priv)?);
    frame(u16::try_from(ap_rep.len())?, &body)
}

/// A kpasswd reply frame: message length, version 1, `ap_rep_length` and `body`.
fn frame(ap_rep_length: u16, body: &[u8]) -> Result<Vec<u8>, TestError> {
    let message_length = u16::try_from(body.len().checked_add(6).ok_or("length")?)?;
    let mut out = message_length.to_be_bytes().to_vec();
    out.extend_from_slice(&1_u16.to_be_bytes());
    out.extend_from_slice(&ap_rep_length.to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// An unauthenticated KRB-ERROR reply frame whose e-data holds result `code` and `text`: a
/// server that cannot or will not authenticate its answer, or a party in the path.
pub(super) fn unauthenticated_reply(code: u16, text: &[u8]) -> Result<Vec<u8>, TestError> {
    let mut e_data = code.to_be_bytes().to_vec();
    e_data.extend_from_slice(text);
    let error = rasn_kerberos::KrbError {
        pvno: 5_i32.into(),
        msg_type: 30_i32.into(),
        ctime: None,
        cusec: None,
        stime: kerberos_time(SystemTime::now())?,
        susec: 0_i32.into(),
        error_code: 52,
        crealm: None,
        cname: None,
        realm: rasn_kerberos::Realm::try_from(REALM.to_owned())?,
        sname: rasn_kerberos::PrincipalName {
            r#type: 2,
            string: ["kadmin", "changepw"]
                .iter()
                .map(|part| rasn_kerberos::KerberosString::try_from((*part).to_owned()))
                .collect::<Result<_, _>>()?,
        },
        e_text: None,
        e_data: Some(e_data.into()),
    };
    frame(0, &der::encode(&error)?)
}

/// How the fake kpasswd server answers one request.
pub(super) enum Behavior {
    /// Apply the new password and answer an authenticated success.
    Succeed,
    /// Answer an authenticated `KPASSWD_SOFTERROR` with this text, changing nothing.
    Soft(&'static [u8]),
    /// Answer a KRB-ERROR that claims success, changing nothing.
    UnsignedSuccess,
    /// Answer a success sealed under a key the client does not hold, changing nothing.
    ForgedSuccess,
    /// Close the connection without answering, as a lost reply; the change is applied.
    Lose,
    /// Tell the test the request arrived, then hold the connection open unanswered.
    Hold(oneshot::Sender<()>),
}

/// Serve the KDC side of `realm` on `listener`: every connection answers requests until it closes.
pub(super) fn spawn_kdc(listener: TcpListener, account: Arc<Realm>) {
    drop(tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let realm = Arc::clone(&account);
            drop(tokio::spawn(async move {
                while let Ok(Some(request)) = read_frame(&mut socket).await {
                    let Ok(reply) = realm.answer(&request) else {
                        return;
                    };
                    if write_response(&mut socket, &reply).await.is_err() {
                        return;
                    }
                }
            }));
        }
    }));
}

/// Serve the kpasswd side of `realm` following `script`, then succeeding;
/// the returned counter is the number of requests received.
pub(super) fn spawn_kpasswd(
    listener: TcpListener,
    account: Arc<Realm>,
    script: Vec<Behavior>,
) -> Arc<AtomicUsize> {
    let received = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&received);
    drop(tokio::spawn(async move {
        let mut turns = script.into_iter();
        loop {
            let Ok((request, mut socket)) = read_request(&listener).await else {
                return;
            };
            let _: usize = counter.fetch_add(1, Ordering::SeqCst);
            let Ok(seen) = open_request(&request) else {
                return;
            };
            let behavior = turns.next().unwrap_or(Behavior::Succeed);
            let apply = || {
                *held(&account.password) = seen.change_data.new_passwd().to_vec();
                *held(&account.expired) = false;
            };
            let reply = match behavior {
                Behavior::Succeed => {
                    apply();
                    authenticated_reply(&seen, 0, b"password changed")
                }
                Behavior::Soft(text) => authenticated_reply(&seen, 4, text),
                Behavior::UnsignedSuccess => unauthenticated_reply(0, b"password changed"),
                Behavior::ForgedSuccess => forged_reply(&seen, 0, b"password changed"),
                Behavior::Lose => {
                    apply();
                    drop(socket);
                    continue;
                }
                Behavior::Hold(arrived) => {
                    if arrived.send(()).is_err() {
                        return;
                    }
                    // Keep the connection open and never answer.
                    drop(tokio::spawn(async move {
                        let _open = socket;
                        pending::<()>().await;
                    }));
                    continue;
                }
            };
            let Ok(answer) = reply else {
                return;
            };
            if write_response(&mut socket, &answer).await.is_err() {
                return;
            }
        }
    }));
    received
}
