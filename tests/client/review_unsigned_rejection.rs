use super::*;

/// Delivered unsigned refusal must not assert rollback or replace the stored credential.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use rasn::der;
    use rskrb5_ng::{error::Kadmin, krb_error};
    use tokio::{task::JoinSet, time::timeout};

    use super::*;

    /// Exercise one delivered mutation, followed only by a read-only credential check.
    fn unsigned_rejection(framed: bool) -> Result<(), TestError> {
        runtime()?.block_on(async {
            // Given separate local authorities and distinct old/new passwords.
            let kdc = TcpListener::bind("127.0.0.1:0").await?;
            let kpasswd = TcpListener::bind("127.0.0.1:0").await?;
            let config = Config::parse(&format!(
                "[libdefaults]\n dns_lookup_kdc = false\n[realms]\n TEST.GOKRB5 = {{\n kdc = {}\n kpasswd_server = {}\n }}\n",
                kdc.local_addr()?, kpasswd.local_addr()?
            ))?;
            let principal = Principal::user("TEST.GOKRB5", "testuser1");
            let old_key = derive_password_reply_key(&principal, TESTUSER_PASSWORD, &password_key_info())?;
            let mut client = Tokio::with_password(config, KdcProtocol::Tcp, principal.clone(), TESTUSER_PASSWORD);
            let mut servers = JoinSet::new();
            drop(servers.spawn(async move {
                for service in [change_password_principal(), Principal::tgt_service("TEST.GOKRB5")] {
                    let (request, mut socket) = read_tcp_kdc_request(&kdc).await?;
                    let built = built_request_from_der(der::decode(&request)?, &request)?;
                    assert_eq!(built.client(), &principal);
                    assert_eq!(built.service(), &service);
                    let response = synthetic_as_rep_with_reply_key(&built, built.nonce(), built.service(), &old_key)?;
                    write_tcp_kdc_response(&mut socket, &response).await?;
                }
                Ok::<(), TestError>(())
            }));
            let peer = async {
                let (request, mut socket) = read_tcp_kdc_request(&kpasswd).await?;
                drop(KpasswdRequest::parse(&request)?);
                let mut refusal = krb_error::decode(&kpasswd_result_krb_error(4, "policy refused")?)?;
                refusal.e_data = Some(b"\x00\x04policy\xffrefused".to_vec().into());
                let bare = krb_error::encode(&refusal)?;
                let response = if framed { kpasswd_reply_frame(0, &bare)? } else { bare };
                write_tcp_kdc_response(&mut socket, &response).await?;
                Ok::<(), TestError>(())
            };
            // When the peer consumes the complete mutation before sending an unsigned refusal.
            let options = RequestOptions::new(timestamp(1_893_553_452)?, 456_789, 42, ipv4_host_address([127, 0, 0, 1]));
            let (outcome, served) = timeout(Duration::from_secs(5), async {
                tokio::join!(client.change_password_with_options(Password::copy_from_str("distinct-new-password"), options), peer)
            }).await?;
            served?;
            let error = outcome.err().context("unsigned refusal must not succeed")?;
            // Then exactly one unknown wrapper retains the precise unauthenticated diagnostics.
            assert!(matches!(error, Error::KpasswdOutcomeUnknown(source)
                if matches!(&*source, Error::Kadmin(Kadmin::UnauthenticatedRejection { code: 4, text_raw })
                    if text_raw == b"policy\xffrefused")));
            let logged_in = timeout(Duration::from_secs(5), client.login()).await??;
            assert_eq!(logged_in.client(), &Principal::user("TEST.GOKRB5", "testuser1"));
            while let Some(joined) = timeout(Duration::from_secs(5), servers.join_next()).await? {
                joined??;
            }
            assert!(timeout(Duration::from_millis(50), kpasswd.accept()).await.is_err(), "delivered mutation must not reconnect or retry");
            Ok(())
        })
    }

    /// Bare KRB-ERROR refusal is unknown and leaves the old credential usable.
    #[test]
    fn bare_unsigned_rejection_is_unknown_without_rotation_or_retry() -> Result<(), TestError> {
        unsigned_rejection(false)
    }

    /// Framed KRB-ERROR refusal is unknown and leaves the old credential usable.
    #[test]
    fn framed_unsigned_rejection_is_unknown_without_rotation_or_retry() -> Result<(), TestError> {
        unsigned_rejection(true)
    }
}
