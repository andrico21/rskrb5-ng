/// An initiator step (MIT `negoex_init`, `negoex_ctx.c:633-715`).
///
/// # Errors
///
/// Returns the errors of [`Context::step`].
fn initiate(context: &mut Context, input: Option<&[u8]>) -> Result<Step, Negoex> {
    if context.step == 0 && input.is_some() {
        return Err(Negoex::UnexpectedStep("the first initiator step takes no token"));
    }
    context.step = context.step.saturating_add(1);
    let messages = match input {
        Some(token) => context.conversation.parse(token)?,
        None => Vec::new(),
    };
    process_alerts(context, &messages);
    match context.step {
        1 => {
            let mut id = [0; 16];
            (context.random)(&mut id)?;
            context.conversation = Conversation::initiating(ConversationId::from_bytes(id));
            query_meta_data(context);
        }
        2 => {
            check_optimistic_result(context, &messages);
            exchange_meta_data(context, &messages);
            let nego = find_nego(&messages, MessageType::AcceptorNego)
                .ok_or(Negoex::MissingNegoMessage)?;
            common_auth_schemes(context, nego.schemes());
        }
        _ => {}
    }
    let output = mech_init(context, &messages)?;
    if context.step == 2 {
        select_first(context);
    }
    let send_alert = verify_checksum(context, &messages, input)?;
    if let Some(token) = input {
        context.transcript.extend_from_slice(token);
    }
    let token = make_output_token(context, output, send_alert)?;
    Ok(finish(context, token))
}

/// An acceptor step (MIT `negoex_accept`, `negoex_ctx.c:717-788`).
///
/// # Errors
///
/// Returns the errors of [`Context::step`].
fn accept(context: &mut Context, input: Option<&[u8]>) -> Result<Step, Negoex> {
    let token = input.ok_or(Negoex::InvalidMessageSize)?;
    context.step = context.step.saturating_add(1);
    let messages = context.conversation.parse(token)?;
    process_alerts(context, &messages);
    if context.step == 1 {
        let nego = find_nego(&messages, MessageType::InitiatorNego)
            .ok_or(Negoex::MissingNegoMessage)?;
        restrict_auth_schemes(context, nego.schemes());
        exchange_meta_data(context, &messages);
        query_meta_data(context);
        if context.entries.is_empty() {
            return Err(Negoex::NoAvailableMechs);
        }
    }
    let outcome = mech_accept(context, &messages)?;
    let send_alert = if outcome.succeeded {
        verify_checksum(context, &messages, input)?
    } else {
        false
    };
    context.transcript.extend_from_slice(token);
    let output = make_output_token(context, outcome.output, send_alert)?;
    Ok(finish(context, output))
}

/// The step's result for the context's present state.
fn finish(context: &Context, token: Vec<u8>) -> Step {
    Step {
        token: (!token.is_empty()).then_some(token),
        complete: context.is_complete(),
    }
}

/// One initiator step of the mechanism exchange; a failing mechanism falls
/// back to the next (MIT `mech_init`, `negoex_ctx.c:238-306`).
///
/// # Errors
///
/// Returns [`Negoex::NoAvailableMechs`] with no mechanism left, and the first
/// failure as [`Negoex::Provider`] when every mechanism failed.
fn mech_init(
    context: &mut Context,
    messages: &[Message],
) -> Result<Option<Vec<u8>>, Negoex> {
    if context.step == 1 && !context.optimistic {
        return Ok(None);
    }
    let first = context.entries.first().ok_or(Negoex::NoAvailableMechs)?;
    let mut input = find_exchange(messages, MessageType::Challenge)
        .filter(|challenge| challenge.scheme() == first.scheme)
        .map(ExchangeMessage::token);
    if first.is_complete() {
        return Ok(None);
    }
    let mut first_failure: Option<ProviderFailure> = None;
    while let Some(entry) = context.entries.first_mut() {
        match entry.session(context.role).init_sec_context(&context.request, input) {
            Ok(step) => {
                entry.record(step.is_complete());
                entry.refresh_keys();
                return Ok(step.output.filter(|token| !token.is_empty()));
            }
            Err(failure) => {
                if first_failure.is_none() {
                    first_failure = Some(failure);
                }
                drop(context.entries.remove(0));
                input = None;
            }
        }
    }
    Err(first_failure.map_or(Negoex::NoAvailableMechs, Negoex::Provider))
}

/// One acceptor step of the mechanism exchange (MIT `mech_accept`, `negoex_ctx.c:308-376`).
///
/// # Errors
///
/// Returns [`Negoex::MissingApRequestMessage`], [`Negoex::NoAvailableMechs`]
/// and a mechanism failure without an error token as [`Negoex::Provider`].
fn mech_accept(
    context: &mut Context,
    messages: &[Message],
) -> Result<AcceptOutcome, Negoex> {
    let nothing = AcceptOutcome {
        output: None,
        succeeded: true,
    };
    let Some(request) = find_exchange(messages, MessageType::ApRequest) else {
        let first_complete = context.entries.first().is_some_and(Entry::is_complete);
        if context.step == 1 || first_complete {
            return Ok(nothing);
        }
        return Err(Negoex::MissingApRequestMessage);
    };
    if context.step == 1 {
        let first = context.entries.first().ok_or(Negoex::NoAvailableMechs)?;
        if request.scheme() != first.scheme {
            return Ok(nothing);
        }
    } else {
        let index = context
            .entries
            .iter()
            .position(|entry| entry.scheme == request.scheme())
            .ok_or(Negoex::NoAvailableMechs)?;
        let chosen = context.entries.remove(index);
        context.entries.clear();
        context.entries.push(chosen);
    }
    let optimistic = context.step == 1;
    let entry = context.entries.first_mut().ok_or(Negoex::NoAvailableMechs)?;
    if entry.is_complete() {
        return Ok(nothing);
    }
    match entry
        .session(context.role)
        .accept_sec_context(&context.request, request.token())
    {
        Ok(step) => {
            entry.record(step.is_complete());
            entry.refresh_keys();
            Ok(AcceptOutcome {
                output: step.output.filter(|token| !token.is_empty()),
                succeeded: true,
            })
        }
        Err(_failure) if optimistic => {
            // The optimistic token failed: pretend it never arrived.
            entry.restart();
            Ok(nothing)
        }
        Err(failure) => match failure.output_token() {
            Some(token) if !token.is_empty() => Ok(AcceptOutcome {
                output: Some(token.to_vec()),
                succeeded: false,
            }),
            Some(_) | None => Err(Negoex::Provider(failure)),
        },
    }
}
