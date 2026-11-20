//! A fake kpasswd server over loopback TCP: framing, replies and the requests it opens.

use core::time::Duration;

use rasn::der;
use rskrb5_ng::{
    ap_rep::encode_build_ap_rep_with_confounder,
    ap_req::decrypt_ap_req_authenticator,
    client::AP_REQ_AUTHENTICATOR_USAGE,
    config::Config,
    kadmin::{self, ChangePasswdData, Request, build_krb_priv_with_confounder},
    keytab::EncryptionKey,
    krb_priv::{EncKrbPrivPartOptions, ipv4_host_address},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use super::{
    TestError,
    support::{REALM, changepw_key},
};

/// Accept one TCP client within 10 s and read its length-prefixed request.
pub(super) async fn read_request(
    listener: &TcpListener,
) -> Result<(Vec<u8>, TcpStream), TestError> {
    let (mut socket, _) = timeout(Duration::from_secs(10), listener.accept()).await??;
    let mut header = [0_u8; 4];
    let _: usize = timeout(Duration::from_secs(10), socket.read_exact(&mut header)).await??;
    let mut request = vec![0_u8; usize::try_from(u32::from_be_bytes(header))?];
    let _: usize = timeout(Duration::from_secs(10), socket.read_exact(&mut request)).await??;
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
    let kdc_line = kdc
        .map(|addr| format!(" kdc = {addr}\n"))
        .unwrap_or_default();
    Ok(Config::parse(&format!(
        "[libdefaults]\n dns_lookup_kdc = false\n udp_preference_limit = 1\n\
         [realms]\n {REALM} = {{\n{kdc_line} kpasswd_server = {kpasswd}\n }}\n"
    ))?)
}

/// What a fake kpasswd server saw in one request.
pub(super) struct Seen {
    /// The authenticator of the AP-REQ, for the reply's echoed time.
    pub(super) authenticator: rasn_kerberos::Authenticator,
    /// The decrypted `ChangePasswdData`.
    pub(super) change_data: ChangePasswdData,
}

/// Decrypt a kpasswd request under the changepw session key.
pub(super) fn open_request(request: &[u8]) -> Result<Seen, TestError> {
    let parsed = Request::parse(request)?;
    let authenticator =
        decrypt_ap_req_authenticator(parsed.ap_req(), &changepw_key(), AP_REQ_AUTHENTICATOR_USAGE)?;
    let subkey = authenticator.subkey.as_ref().ok_or("reply key included")?;
    let reply_key = EncryptionKey::new(subkey.r#type, subkey.value.as_ref().to_vec());
    let enc_part = kadmin::decrypt_krb_priv_enc_part(parsed.krb_priv(), &reply_key)?;
    let change_data = ChangePasswdData::decode_der(enc_part.user_data.as_ref())?;
    Ok(Seen {
        authenticator,
        change_data,
    })
}

/// An authenticated kpasswd reply frame with result `code` and `text`: the AP-REP
/// is under the changepw session key and selects a server subkey for the KRB-PRIV.
pub(super) fn authenticated_reply(
    seen: &Seen,
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
        &changepw_key(),
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
