//! Remote kadm5 and `RPCSEC_GSS` objects with populated secrets. The
//! `RPCSEC_GSS` objects exist with `spnego`, the kadm5 objects need `tokio`
//! too.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
pub(super) mod tests {
    use core::{error::Error, time::Duration};
    use std::time::{SystemTime, UNIX_EPOCH};

    use chrono::DateTime;
    use rskrb5_ng::{
        client::{KdcError, TgsRepSession, principal::Principal},
        error::{Client as ClientError, Gss, Rpc, Spnego as SpnegoError},
        gss::{Credential, InitiatorOptions, Name},
        keytab::EncryptionKey,
        rpcsec_gss::{InitStep, Program, Protection, Reply, RpcClient},
        ticket,
    };
    #[cfg(feature = "tokio")]
    use rskrb5_ng::{
        error::Kadm5,
        gss::{Acceptor, AcceptorOptions, EstablishedContext},
        kadm5::{ApiVersion, KeyData, Options, Procedure, RemoteAdminClient, Response},
        keytab::{self, Keytab},
        rpcsec_gss::encode_record,
    };
    #[cfg(feature = "tokio")]
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream, duplex},
        runtime::Builder,
    };
    use zeroize::Zeroizing;

    use crate::tests::{pattern, redacted};

    /// The realm of the audit.
    const REALM: &str = "EXAMPLE.COM";

    /// The kadmind service, `kadmin/admin` (MIT `KADM5_ADMIN_SERVICE`).
    const KADMIN: [&str; 2] = ["kadmin", "admin"];

    /// The kadm5 program, version 2 (MIT `kadm_rpc.h`).
    const KADM: Program = Program::new(2112, 2);

    /// The `kadmin/admin` principal of the realm.
    fn kadmin() -> Principal {
        Principal::new(REALM, 1, KADMIN)
    }

    /// A Kerberos string.
    fn text(value: &str) -> Result<rasn_kerberos::KerberosString, Box<dyn Error>> {
        rasn_kerberos::KerberosString::from_bytes(value.as_bytes())
            .map_err(|cause| format!("Kerberos string: {cause:?}").into())
    }

    /// A whole-second Kerberos time.
    fn time(at: SystemTime) -> Result<rasn_kerberos::KerberosTime, Box<dyn Error>> {
        let seconds = i64::try_from(at.duration_since(UNIX_EPOCH)?.as_secs())?;
        let utc = DateTime::from_timestamp(seconds, 0).ok_or("time")?;
        Ok(rasn_kerberos::KerberosTime(utc.fixed_offset()))
    }

    /// A principal name.
    fn name(components: &[&str]) -> Result<rasn_kerberos::PrincipalName, Box<dyn Error>> {
        Ok(rasn_kerberos::PrincipalName {
            r#type: 1,
            string: components
                .iter()
                .map(|component| text(component))
                .collect::<Result<_, _>>()?,
        })
    }

    /// A live ticket of `admin/admin` for `kadmin/admin`, sealed in `service_key`.
    fn ticket_for(
        service_key: &EncryptionKey,
        session: &EncryptionKey,
    ) -> Result<TgsRepSession, Box<dyn Error>> {
        let now = SystemTime::now();
        let start = UNIX_EPOCH
            .checked_add(Duration::from_secs(
                now.duration_since(UNIX_EPOCH)?.as_secs().saturating_sub(60),
            ))
            .ok_or("start")?;
        let end = start.checked_add(Duration::from_hours(1)).ok_or("end")?;
        let part = rasn_kerberos::EncTicketPart {
            flags: rasn_kerberos::TicketFlags(rasn_kerberos::KerberosFlags::repeat(false, 32)),
            key: rasn_kerberos::EncryptionKey {
                r#type: session.etype(),
                value: session.value().to_vec().into(),
            },
            crealm: text(REALM)?,
            cname: name(&["admin", "admin"])?,
            transited: rasn_kerberos::TransitedEncoding {
                r#type: 1,
                contents: Vec::new().into(),
            },
            auth_time: time(start)?,
            start_time: None,
            end_time: time(end)?,
            renew_till: None,
            caddr: None,
            authorization_data: None,
        };
        let der = ticket::encode_build_ticket_with_confounder(
            text(REALM)?,
            name(&KADMIN)?,
            &part,
            service_key,
            Some(1),
            &[0x11; 16],
        )?;
        Ok(TgsRepSession::new(
            Principal::new(REALM, 1, ["admin", "admin"]),
            kadmin(),
            session.clone(),
            Zeroizing::new(der),
            [0; 4],
            start,
            end,
        ))
    }

    /// An XDR opaque field.
    #[cfg(feature = "tokio")]
    fn opaque(out: &mut Vec<u8>, value: &[u8]) -> Result<(), Box<dyn Error>> {
        out.extend_from_slice(&u32::try_from(value.len())?.to_be_bytes());
        out.extend_from_slice(value);
        out.resize(out.len().saturating_add(value.len().wrapping_neg() & 3), 0);
        Ok(())
    }

    /// The XID, the credential's sequence number and the last opaque field of a call.
    #[cfg(feature = "tokio")]
    fn parse_call(call: &[u8]) -> Result<(u32, u32, Vec<u8>), Box<dyn Error>> {
        let word = |at: usize| -> Result<u32, Box<dyn Error>> {
            let bytes = call.get(at..at.saturating_add(4)).ok_or("a word")?;
            Ok(u32::from_be_bytes(bytes.try_into()?))
        };
        let credential_length = usize::try_from(word(28)?)?;
        let sequence = word(40)?;
        let verifier_at = 32_usize
            .saturating_add(credential_length)
            .saturating_add(credential_length.wrapping_neg() & 3);
        let verifier_length = usize::try_from(word(verifier_at.saturating_add(4))?)?;
        let body_at = verifier_at
            .saturating_add(8)
            .saturating_add(verifier_length)
            .saturating_add(verifier_length.wrapping_neg() & 3);
        let length = usize::try_from(word(body_at)?)?;
        let start = body_at.saturating_add(4);
        let body = call
            .get(start..start.saturating_add(length))
            .ok_or("the body")?;
        Ok((word(0)?, sequence, body.to_vec()))
    }

    /// A successful reply with a MIC verifier over `signed` and `results`.
    #[cfg(feature = "tokio")]
    fn reply(
        xid: u32,
        context: &mut EstablishedContext,
        signed: u32,
        results: &[u8],
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut out = [xid, 1, 0, 6]
            .iter()
            .flat_map(|word| word.to_be_bytes())
            .collect();
        opaque(&mut out, &context.get_mic(&signed.to_be_bytes())?)?;
        out.extend_from_slice(&0_u32.to_be_bytes());
        out.extend_from_slice(results);
        Ok(out)
    }

    /// Read one single-fragment record.
    #[cfg(feature = "tokio")]
    async fn read(stream: &mut DuplexStream) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let mut header = [0_u8; 4];
        let _header_length = stream.read_exact(&mut header).await?;
        let mut body = vec![0; usize::try_from(u32::from_be_bytes(header) & 0x7fff_ffff)?];
        let _body_length = stream.read_exact(&mut body).await?;
        Ok(body)
    }

    /// Answer the context creation and the version negotiation, under integrity.
    #[cfg(feature = "tokio")]
    async fn serve(mut stream: DuplexStream, service_key: EncryptionKey) -> Result<(), String> {
        let mut keys = Keytab::new();
        keys.entries_mut().push(keytab::Entry::new(
            keytab::Principal::new(REALM, 1, KADMIN),
            0,
            1,
            service_key,
            1,
        ));
        let credential = Credential::from_keytab(keys);
        let init = read(&mut stream).await.map_err(|error| error.to_string())?;
        let (mut context, first) = {
            let (xid, _, token) = parse_call(&init).map_err(|error| error.to_string())?;
            let mut acceptor = Acceptor::new(&credential, AcceptorOptions::new())
                .map_err(|error| error.to_string())?;
            let accepted = acceptor
                .accept_sec_context(&token)
                .map_err(|error| error.to_string())?;
            let answer = accepted.output_token().unwrap_or_default().to_vec();
            let mut context = accepted.into_context();
            let mut results = Vec::new();
            opaque(&mut results, b"hndl").map_err(|error| error.to_string())?;
            results.extend([0_u32, 0, 32].iter().flat_map(|word| word.to_be_bytes()));
            opaque(&mut results, &answer).map_err(|error| error.to_string())?;
            let first =
                reply(xid, &mut context, 32, &results).map_err(|error| error.to_string())?;
            (context, first)
        };
        stream
            .write_all(&encode_record(&first))
            .await
            .map_err(|error| error.to_string())?;
        let negotiation = read(&mut stream).await.map_err(|error| error.to_string())?;
        let (xid, sequence, _) = parse_call(&negotiation).map_err(|error| error.to_string())?;
        let body: Vec<u8> = [sequence, ApiVersion::V4.wire(), 0]
            .iter()
            .flat_map(|word| word.to_be_bytes())
            .collect();
        let mut results = Vec::new();
        opaque(&mut results, &body).map_err(|error| error.to_string())?;
        let checksum = context.get_mic(&body).map_err(|error| error.to_string())?;
        opaque(&mut results, &checksum).map_err(|error| error.to_string())?;
        let answer =
            reply(xid, &mut context, sequence, &results).map_err(|error| error.to_string())?;
        stream
            .write_all(&encode_record(&answer))
            .await
            .map_err(|error| error.to_string())?;
        let mut rest = Vec::new();
        let _closed = stream.read_to_end(&mut rest).await;
        Ok(())
    }

    pub(crate) fn run_audit() -> Result<(), Box<dyn Error>> {
        kadm5_objects_redact_credentials()
    }

    /// The `RPCSEC_GSS` client, its calls and replies, the kadm5 client, its
    /// key results and the errors never show keys, tickets or messages.
    #[test]
    fn kadm5_objects_redact_credentials() -> Result<(), Box<dyn Error>> {
        let service_bytes = [pattern(33), pattern(49)].concat();
        let session_bytes = [pattern(65), pattern(81)].concat();
        let service_key = EncryptionKey::new(18, service_bytes);
        let session = EncryptionKey::new(18, session_bytes.clone());
        let ticket = ticket_for(&service_key, &session)?;
        let ticket_bytes = ticket.ticket().to_vec();
        let credential = Credential::from_service_ticket(&ticket);
        let target = Name::from_principal(&kadmin());
        let initiator = RpcClient::initiator(target, InitiatorOptions::new());
        let mut rpc = RpcClient::new(KADM, Protection::Privacy, initiator)?;
        let call = rpc.start(&credential)?;
        redacted(&rpc, &[&session_bytes]);
        redacted(&call, &[&ticket_bytes]);
        let step = InitStep::Call(call);
        redacted(&step, &[&ticket_bytes]);
        let message = pattern(97);
        let mut accepted = vec![
            0, 0, 0, 7, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        accepted.extend_from_slice(&message);
        redacted(&Reply::decode(&accepted)?, &[&message]);
        let secret = pattern(145);
        let gss = || {
            Gss::Spnego(SpnegoError::Client(Box::new(ClientError::Kdc(Box::new(
                KdcError::new(UNIX_EPOCH, 0, 25, Principal::tgt_service(REALM))
                    .with_e_data(Some(secret.clone().into())),
            )))))
        };
        redacted(&Rpc::BadVerifier(gss()), &[&secret]);
        #[cfg(feature = "tokio")]
        kadm5_objects(&service_key, &credential, [&session_bytes, &ticket_bytes])?;
        Ok(())
    }

    /// The kadm5 key results, a key, an unknown outcome and a live client.
    #[cfg(feature = "tokio")]
    fn kadm5_objects(
        service_key: &EncryptionKey,
        credential: &Credential,
        live_secrets: [&[u8]; 2],
    ) -> Result<(), Box<dyn Error>> {
        let random = pattern(113);
        let mut keys = [ApiVersion::V4.wire(), 0, 1, 18, 16]
            .iter()
            .flat_map(|word| word.to_be_bytes())
            .collect::<Vec<u8>>();
        keys.extend_from_slice(&random);
        let response = Response::decode(Procedure::RandomizeKeys, ApiVersion::V4, &keys)?;
        redacted(&response, &[&random]);
        let salt = pattern(129);
        let data =
            KeyData::new(2, EncryptionKey::new(18, random.clone())).with_salt(4, salt.clone());
        redacted(&data, &[&random, &salt]);
        let secret = pattern(161);
        let gss = Gss::Spnego(SpnegoError::Client(Box::new(ClientError::Kdc(Box::new(
            KdcError::new(UNIX_EPOCH, 0, 25, Principal::tgt_service(REALM))
                .with_e_data(Some(secret.clone().into())),
        )))));
        let unknown = Kadm5::OutcomeUnknown {
            procedure: "kadm5_chpass_principal",
            cause: Box::new(Kadm5::Rpc(Rpc::Gss(gss))),
        };
        redacted(&unknown, &[&secret]);
        let runtime = Builder::new_current_thread().enable_all().build()?;
        runtime.block_on(async {
            let (client_end, server_end) = duplex(1 << 16);
            let server = tokio::spawn(serve(server_end, service_key.clone()));
            let options = Options::new(REALM).with_protection(Protection::Integrity);
            let client = RemoteAdminClient::over_stream(client_end, credential, options).await?;
            redacted(&client, &live_secrets);
            drop(client);
            server.await??;
            Ok::<_, Box<dyn Error>>(())
        })?;
        Ok(())
    }
}
