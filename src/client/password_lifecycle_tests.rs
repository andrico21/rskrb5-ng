//! Observe the original password allocation at real mutation exit boundaries.

/// Local TCP peers exercise one mutation each, without retries or live credentials.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use alloc::sync::Arc;
    use core::{
        error::Error as StdError,
        sync::atomic::{AtomicBool, Ordering},
        time::Duration,
    };
    use std::time::SystemTime;

    use rasn::types::Integer;
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::{TcpListener, TcpStream},
        time::timeout,
    };

    use super::super::Secret;
    use crate::{
        ap_rep, ap_req,
        client::{
            Error, TgsRepSession, Tokio, kpasswd::RequestOptions, principal::Principal,
            transport::KdcProtocol,
        },
        config::Config,
        error::Kadmin,
        kadmin::{self, Request},
        keytab::EncryptionKey,
        krb_priv::{EncKrbPrivPartOptions, ipv4_host_address},
        ticket,
    };

    /// Fallible local fixture operations.
    type TestError = Box<dyn StdError + Send + Sync>;

    /// Construct a tracked input with the exact original allocation preserved.
    fn observed() -> (Secret, Arc<AtomicBool>) {
        let original = String::from("original-allocation-canary");
        let address = original.as_ptr().addr();
        let erased = Arc::new(AtomicBool::new(false));
        let mut password = Secret::from_string(original);
        assert_eq!(password.as_bytes().as_ptr().addr(), address);
        password.erased = Some(Arc::clone(&erased));
        (password, erased)
    }

    /// A synthetic cached service ticket avoids any AS exchange or external authority.
    fn client(address: &str) -> Result<(Tokio, RequestOptions), TestError> {
        let fixture = Request::parse(&hex::decode(
            include_str!("../../tests/fixtures/kpasswd-request.hex").trim(),
        )?)?;
        let now = SystemTime::now();
        let seconds = now.duration_since(SystemTime::UNIX_EPOCH)?.as_secs();
        let time = SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds))
            .ok_or("time overflow")?;
        let end = time
            .checked_add(Duration::from_hours(1))
            .ok_or("end overflow")?;
        let principal = Principal::user("TEST.GOKRB5", "testuser1");
        let session = TgsRepSession::new(
            principal,
            Principal::new("TEST.GOKRB5", 2, ["kadmin", "changepw"]),
            EncryptionKey::new(18, vec![0x11; 32]),
            ticket::encode(&fixture.ap_req().ticket)?.into(),
            [0; 4],
            time,
            end,
        );
        let config = Config::parse(&format!(
            "[libdefaults]\n dns_lookup_kdc = false\n[realms]\n TEST.GOKRB5 = {{\n kpasswd_server = {address}\n }}\n"
        ))?;
        let mut client = Tokio::from_tgt_session(config, KdcProtocol::Tcp, session.clone());
        client.cache_service_ticket(session)?;
        Ok((
            client,
            RequestOptions::new(time, 123_456, 42, ipv4_host_address([127, 0, 0, 1])),
        ))
    }

    /// Read one bounded local request; cancellation affects only the synthetic peer.
    async fn receive(listener: &TcpListener) -> Result<(Vec<u8>, TcpStream), TestError> {
        let (mut socket, _address) = listener.accept().await?;
        let length = usize::try_from(socket.read_u32().await?)?;
        let _bounded = u16::try_from(length)?;
        let mut request = vec![0; length];
        let _: usize = socket.read_exact(&mut request).await?;
        Ok((request, socket))
    }

    /// Return a genuinely authenticated success or rejection, echoing request controls.
    fn reply(request: &[u8], code: u16) -> Result<Vec<u8>, TestError> {
        let parsed = Request::parse(request)?;
        let key = EncryptionKey::new(18, vec![0x11; 32]);
        let auth = ap_req::decrypt_ap_req_authenticator(
            parsed.ap_req(),
            &key,
            ap_req::authenticator_usage_for_ticket(&parsed.ap_req().ticket),
        )?;
        let subkey = auth.subkey.ok_or("request subkey")?;
        let reply_key = EncryptionKey::new(subkey.r#type, subkey.value.to_vec());
        let usec = u32::try_from(&auth.cusec).map_err(|error| error.to_string())?;
        let ap = ap_rep::build_ap_rep_with_confounder(
            &rasn_kerberos::EncApRepPart {
                ctime: auth.ctime.clone(),
                cusec: Integer::from(usec),
                subkey: None,
                seq_number: Some(42),
            },
            &key,
            None,
            &[0x55; 16],
        )?;
        let options = EncKrbPrivPartOptions::new(ipv4_host_address([127, 0, 0, 1]))
            .with_timestamp(auth.ctime, usec)
            .with_sequence_number(42);
        let private = kadmin::build_krb_priv_with_confounder(
            code.to_be_bytes(),
            options,
            &reply_key,
            &[0x77; 16],
        )?;
        let ap_bytes = ap_rep::encode(&ap)?;
        let private_bytes = kadmin::encode_krb_priv(&private)?;
        let size = 6_usize
            .checked_add(ap_bytes.len())
            .and_then(|length| length.checked_add(private_bytes.len()))
            .ok_or("reply size")?;
        let mut frame = Vec::new();
        frame.extend_from_slice(&u16::try_from(size)?.to_be_bytes());
        frame.extend_from_slice(&1_u16.to_be_bytes());
        frame.extend_from_slice(&u16::try_from(ap_bytes.len())?.to_be_bytes());
        frame.extend_from_slice(&ap_bytes);
        frame.extend_from_slice(&private_bytes);
        Ok(frame)
    }

    /// One local confirmed mutation; NOT cancel-safe, and never retried.
    async fn completed(code: u16) -> Result<(), TestError> {
        // Given a tracked original owner and an authenticated local peer.
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let (mut client, options) = client(&listener.local_addr()?.to_string())?;
        let (password, erased) = observed();
        let server = async {
            let (request, mut socket) = receive(&listener).await?;
            let response = reply(&request, code)?;
            socket.write_u32(u32::try_from(response.len())?).await?;
            socket.write_all(&response).await?;
            Ok::<(), TestError>(())
        };
        // When exactly one exchange receives the authenticated outcome.
        let (outcome, peer) = timeout(Duration::from_secs(5), async {
            tokio::join!(
                client.change_password_with_options(password, options),
                server
            )
        })
        .await?;
        peer?;
        // Then the exact expected outcome and original-owner erasure are both observed.
        if code == 0 {
            assert_eq!(outcome?.code, 0);
        } else {
            assert!(matches!(
                outcome,
                Err(Error::Kadmin(Kadmin::PasswordChangeFailed {
                    code: 4,
                    text: _,
                    text_raw: _
                }))
            ));
        }
        assert!(
            erased.load(Ordering::SeqCst),
            "original allocation was not erased"
        );
        Ok(())
    }

    /// Confirmed success drops and erases the original input owner.
    #[tokio::test]
    async fn success_erases_original() -> Result<(), TestError> {
        completed(0).await
    }

    /// Authenticated rejection drops and erases the original input owner.
    #[tokio::test]
    async fn rejection_erases_original() -> Result<(), TestError> {
        completed(4).await
    }

    /// A local request-construction failure erases the input without sending.
    #[tokio::test]
    async fn pre_send_failure_erases_original() -> Result<(), TestError> {
        // Given invalid metadata and a listening peer that must receive nothing.
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let (mut client, mut options) = client(&listener.local_addr()?.to_string())?;
        options.cusec = 1_000_000;
        let (password, erased) = observed();
        // When local construction rejects the request.
        let outcome = client.change_password_with_options(password, options).await;
        // Then the original owner is erased and no connection was made.
        assert!(matches!(
            outcome,
            Err(Error::Encode {
                target: "kpasswd request time",
                message: _
            })
        ));
        assert!(
            erased.load(Ordering::SeqCst),
            "original allocation was not erased"
        );
        assert!(
            timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err(),
            "pre-send failure contacted peer"
        );
        Ok(())
    }

    /// Cancellation after observed delivery erases the input, without retrying the mutation.
    #[tokio::test]
    async fn cancellation_erases_original() -> Result<(), TestError> {
        // Given a pending mutation and a peer that consumes its complete request.
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let (mut client, options) = client(&listener.local_addr()?.to_string())?;
        let (password, erased) = observed();
        let pending =
            tokio::spawn(
                async move { client.change_password_with_options(password, options).await },
            );
        let (_request, socket) = timeout(Duration::from_secs(5), receive(&listener)).await??;
        assert!(
            !erased.load(Ordering::SeqCst),
            "original must remain owned while pending"
        );
        // When the caller cancels after delivery (server outcome is unknown).
        pending.abort();
        let cancelled = timeout(Duration::from_secs(5), pending)
            .await?
            .err()
            .ok_or("mutation completed instead of cancelling")?;
        assert!(cancelled.is_cancelled());
        // Then the original input's legitimate destructor has erased its allocation.
        assert!(
            erased.load(Ordering::SeqCst),
            "cancelled original allocation was not erased"
        );
        drop(socket);
        Ok(())
    }

    /// An unpolled public future still owns and erases the supplied allocation.
    #[test]
    fn unpolled_future_erases_original() -> Result<(), TestError> {
        // Given a tracked original owner passed through the generated-options wrapper.
        let (mut client, _options) = client("127.0.0.1:1")?;
        let (password, erased) = observed();
        // When cancellation occurs before the first poll.
        drop(client.change_password(password, ipv4_host_address([127, 0, 0, 1])));
        // Then erasure does not depend on execution reaching the inner method.
        assert!(
            erased.load(Ordering::SeqCst),
            "unpolled original allocation was not erased"
        );
        Ok(())
    }

    /// Kadmin constructors erase consumed input on both success and target validation failure.
    #[test]
    fn kadmin_construction_erases_original() -> Result<(), TestError> {
        // Given original allocations passed to the two owning constructors.
        let (password, erased) = observed();
        // When construction succeeds, the retained payload is independently zeroizing.
        let payload = kadmin::ChangePasswdData::new(password);
        // Then the input was erased without destroying the retained payload.
        assert!(erased.load(Ordering::SeqCst));
        assert_eq!(payload.new_passwd().as_ref(), b"original-allocation-canary");
        let (invalid_password, invalid_erased) = observed();
        let error =
            kadmin::ChangePasswdData::for_target(invalid_password, 1, ["user"], "\u{1f512}")
                .err()
                .ok_or("invalid target accepted")?;
        assert!(matches!(error, Kadmin::InvalidKerberosString(_)));
        assert!(invalid_erased.load(Ordering::SeqCst));
        Ok(())
    }
}
