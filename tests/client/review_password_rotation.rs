use super::*;

/// Confirmed password rotation follows protocol identity, not advisory name type.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use rasn::der;
    use tokio::{task::JoinSet, time::timeout};

    use super::*;

    /// One confirmed mutation is followed by a read-only login under the expected credential.
    fn assert_rotation(target: Principal, expected_password: &[u8]) -> Result<(), TestError> {
        runtime()?.block_on(async {
            // Given: explicit local authorities and independent old/new password keys.
            let kdc = TcpListener::bind("127.0.0.1:0").await?;
            let kpasswd = TcpListener::bind("127.0.0.1:0").await?;
            let config = Config::parse(&format!(
                "[libdefaults]\n dns_lookup_kdc = false\n[realms]\n TEST.GOKRB5 = {{\n kdc = {}\n kpasswd_server = {}\n }}\n",
                kdc.local_addr()?, kpasswd.local_addr()?
            ))?;
            let principal = Principal::user("TEST.GOKRB5", "testuser1");
            let old_key = derive_password_reply_key(&principal, TESTUSER_PASSWORD, &password_key_info())?;
            let expected_key = derive_password_reply_key(&principal, expected_password, &password_key_info())?;
            let mut client = Tokio::with_password(config, KdcProtocol::Tcp, principal.clone(), TESTUSER_PASSWORD);
            let mut servers = JoinSet::new();
            drop(servers.spawn(async move {
                for (key, service) in [
                    (old_key, change_password_principal()),
                    (expected_key, Principal::tgt_service("TEST.GOKRB5")),
                ] {
                    let (request, mut socket) = read_tcp_kdc_request(&kdc).await?;
                    let built = built_request_from_der(der::decode(&request)?, &request)?;
                    assert_eq!(built.client(), &principal);
                    assert_eq!(built.service(), &service);
                    let response = synthetic_as_rep_with_reply_key(&built, built.nonce(), built.service(), &key)?;
                    write_tcp_kdc_response(&mut socket, &response).await?;
                }
                Ok::<(), TestError>(())
            }));
            drop(servers.spawn(async move {
                let (request, mut socket) = read_tcp_kdc_request(&kpasswd).await?;
                let key = EncryptionKey::new(18, decode_hex(SESSION_KEY)?);
                let response = kpasswd_authenticated_success_reply(&request, &key, 0x77)?;
                write_tcp_kdc_response(&mut socket, &response).await?;
                Ok::<(), TestError>(())
            }));

            // When: the server authenticates and confirms a single explicit-target change.
            let changed = client.change_password_for_with_options(
                target,
                Password::copy_from_str("new-passwordvalue"),
                RequestOptions::new(timestamp(1_893_553_452)?, 456_789, 42, ipv4_host_address([127, 0, 0, 1])),
            ).await?;
            assert_eq!(changed.code, KPASSWD_SUCCESS);

            // Then: a fresh TGT login can decrypt only with the expected retained credential.
            let logged_in = timeout(Duration::from_secs(5), client.login()).await??;
            assert_eq!(logged_in.client(), &Principal::user("TEST.GOKRB5", "testuser1"));
            while let Some(joined) = timeout(Duration::from_secs(5), servers.join_next()).await? {
                joined??;
            }
            Ok(())
        })
    }

    /// Unknown advisory name type still identifies the client's own password.
    #[test]
    fn confirmed_own_change_rotates_name_type_zero() -> Result<(), TestError> {
        assert_rotation(
            Principal::new("TEST.GOKRB5", 0, ["testuser1"]),
            b"new-passwordvalue",
        )
    }

    /// Enterprise advisory name type still identifies the client's own password.
    #[test]
    fn confirmed_own_change_rotates_name_type_ten() -> Result<(), TestError> {
        assert_rotation(
            Principal::new("TEST.GOKRB5", 10, ["testuser1"]),
            b"new-passwordvalue",
        )
    }

    /// Another user's confirmed change leaves the client's password intact.
    #[test]
    fn confirmed_other_user_change_retains_password() -> Result<(), TestError> {
        assert_rotation(
            Principal::new("TEST.GOKRB5", 10, ["other-user"]),
            TESTUSER_PASSWORD,
        )
    }
}
