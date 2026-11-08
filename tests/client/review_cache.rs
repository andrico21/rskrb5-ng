use super::*;

/// High-level cache identity and validity regressions.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use rasn::der;

    use super::*;

    /// A fresh explicit AS login replaces an older but longer-lived TGT.
    #[tokio::test]
    async fn explicit_login_commits_new_shorter_tgt() -> Result<(), TestError> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let size = stream.read_u32().await?;
            let mut bytes = vec![0; usize::try_from(size)?];
            let _read = stream.read_exact(&mut bytes).await?;
            let built = built_request_from_der(der::decode(&bytes)?, &bytes)?;
            let reply = synthetic_as_rep_with_reply_key(
                &built,
                built.nonce,
                &built.service,
                &reply_key()?,
            )?;
            stream.write_u32(u32::try_from(reply.len())?).await?;
            stream.write_all(&reply).await?;
            Ok::<(), TestError>(())
        });
        let mut old = sample_tgt_session()?;
        old.end_time = timestamp(2_000_000_000)?;
        old.session_key.value = vec![0x11; 32].into();
        let mut client = Tokio::from_tgt_session(
            config_with_kdc_server(&address.to_string())?,
            KdcProtocol::Tcp,
            old,
        )
        .with_keytab_credential(keytab_with_reply_key(3)?);
        let session = client.login().await?;
        assert_eq!(
            session.session_key.value.as_slice(),
            decode_hex(SESSION_KEY)?
        );
        task.await??;
        Ok(())
    }
}
