//! Blocking Negotiate runtime-boundary regressions, isolated from fatal double panics.

use super::*;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use rskrb5_ng::spnego::{InitiatorContextOptions, Token, parse_negotiate_header};
    use tokio::{runtime::Builder, task::JoinSet};

    use super::*;

    /// A valid cached service credential makes a bypass observable without network I/O.
    fn cached_client() -> Result<NegotiateClient, TestError> {
        let tgt = current_tgt_session(1, 60)?;
        let mut service = sample_service_ticket_session(&tgt)?;
        service.auth_time = tgt.auth_time;
        service.start_time = tgt.start_time;
        service.end_time = tgt.end_time;
        service.renew_till = tgt.renew_till;
        let mut client = Tokio::from_tgt_session(Config::new(), KdcProtocol::Auto, tgt);
        client.cache_service_ticket(service)?;
        Ok(NegotiateClient::from_tokio_client(client))
    }

    /// String header APIs emit a decodable SPNEGO initial token from a cached ticket.
    #[test]
    fn cached_header_apis_emit_initial_tokens() -> Result<(), TestError> {
        let mut client = cached_client()?;
        let service = sample_service_principal();
        let header = runtime()?.block_on(client.authorization_header(service.clone()))?;
        assert!(matches!(parse_negotiate_header(&header)?, Token::Init(_)));
        let explicit_header = runtime()?.block_on(
            client
                .inner_mut()
                .spnego_header_with_options(service, InitiatorContextOptions::default()),
        )?;
        assert!(matches!(
            parse_negotiate_header(&explicit_header)?,
            Token::Init(_)
        ));
        Ok(())
    }

    /// Construction inside either Tokio scheduler rejects before creating an owned runtime.
    #[test]
    fn construction_rejects_when_inside_tokio_task() -> Result<(), TestError> {
        let path = "review::review_blocking::tests::construction_rejects_when_inside_tokio_task";
        if !env::in_child(path) {
            env::run_in_child(path, &[]);
            return Ok(());
        }
        for mut builder in [Builder::new_current_thread(), Builder::new_multi_thread()] {
            // Given a running Tokio task and an otherwise valid client.
            let outer = builder.worker_threads(1).enable_all().build()?;
            let client = cached_client()?;
            let rejected = outer.block_on(async move {
                let mut tasks = JoinSet::new();
                drop(tasks.spawn(async move {
                    // When a blocking client is constructed inside that task.
                    matches!(
                        BlockingNegotiateClient::new(client),
                        Err(Error::BlockingRuntimeUnavailable)
                    )
                }));
                tasks
                    .join_next()
                    .await
                    .context("construction task")?
                    .map_err(TestError::from)
            })?;
            // Then it returns the typed rejection without a destructor panic.
            assert!(rejected);
        }
        Ok(())
    }

    /// Every blocking operation rejects after a synchronously created client enters Tokio.
    #[test]
    fn operations_reject_when_inside_tokio_task() -> Result<(), TestError> {
        let path = "review::review_blocking::tests::operations_reject_when_inside_tokio_task";
        if !env::in_child(path) {
            env::run_in_child(path, &[]);
            return Ok(());
        }
        for mut builder in [Builder::new_current_thread(), Builder::new_multi_thread()] {
            // Given a live blocking client constructed outside the runtime.
            let mut client = BlockingNegotiateClient::new(cached_client()?)?;
            let outer = builder.worker_threads(1).enable_all().build()?;
            let service = Principal::host_based_service("HTTP", "host.test.gokrb5")?;
            let target = Principal::new("TEST.GOKRB5", 1, ["testuser1"]);
            let options = RequestOptions::new(
                timestamp(1_893_553_451)?,
                0,
                1,
                ipv4_host_address([127, 0, 0, 1]),
            );
            let rejected = outer.block_on(async move {
                let mut tasks = JoinSet::new();
                drop(tasks.spawn(async move {
                    // When each public blocking operation is called in a task.
                    let results = [
                        client.authorization_header(service.clone()).map(drop),
                        client
                            .authorization_header_for_host("HTTP", "host.test.gokrb5")
                            .map(drop),
                        client.authorization_context(service.clone()).map(drop),
                        client
                            .authorization_context_for_host("HTTP", "host.test.gokrb5")
                            .map(drop),
                        client
                            .authorization_context_with_options(
                                service,
                                InitiatorContextOptions::default(),
                            )
                            .map(drop),
                        client
                            .change_password(
                                Password::copy_from_str("new"),
                                ipv4_host_address([127, 0, 0, 1]),
                            )
                            .map(drop),
                        client
                            .change_password_for(
                                target.clone(),
                                Password::copy_from_str("new"),
                                ipv4_host_address([127, 0, 0, 1]),
                            )
                            .map(drop),
                        client
                            .change_password_with_options(
                                Password::copy_from_str("new"),
                                options.clone(),
                            )
                            .map(drop),
                        client
                            .change_password_for_with_options(
                                target,
                                Password::copy_from_str("new"),
                                options,
                            )
                            .map(drop),
                    ];
                    results
                        .into_iter()
                        .all(|result| matches!(result, Err(Error::BlockingRuntimeUnavailable)))
                }));
                tasks
                    .join_next()
                    .await
                    .context("operation task")?
                    .map_err(TestError::from)
            })?;
            // Then every entry point rejects without polling its exchange future.
            assert!(rejected);
        }
        Ok(())
    }

    /// Moving a used wrapper into a task for destruction must not panic.
    #[test]
    fn destruction_succeeds_when_inside_tokio_task() -> Result<(), TestError> {
        let path = "review::review_blocking::tests::destruction_succeeds_when_inside_tokio_task";
        if !env::in_child(path) {
            env::run_in_child(path, &[]);
            return Ok(());
        }
        for mut builder in [Builder::new_current_thread(), Builder::new_multi_thread()] {
            // Given a synchronously used wrapper and another runtime.
            let mut client = BlockingNegotiateClient::new(cached_client()?)?;
            drop(client.authorization_header_for_host("HTTP", "host.test.gokrb5")?);
            let outer = builder.worker_threads(1).enable_all().build()?;
            // When the wrapper is dropped inside a Tokio task.
            outer.block_on(async move {
                let mut tasks = JoinSet::new();
                drop(tasks.spawn(async move {
                    drop(client);
                }));
                // Then successful task completion proves cleanup did not panic.
                tasks.join_next().await.context("destruction task")??;
                Ok::<(), TestError>(())
            })?;
        }
        Ok(())
    }
}
