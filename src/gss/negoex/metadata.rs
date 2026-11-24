/// Run `operation` on every entry; an entry whose call fails leaves the list
/// (MIT `query_meta_data`, `negoex_ctx.c:157-168`).
fn query_meta_data(context: &mut Context) {
    let (role, request) = (context.role, &context.request);
    context.entries.retain_mut(|entry| {
        match entry.session(role).query_meta_data(request) {
            Ok(metadata) => {
                entry.metadata = metadata;
                true
            }
            Err(_failure) => false,
        }
    });
}

/// Pass the peer's meta-data to the mechanisms; one whose call fails leaves the
/// list (MIT `exchange_meta_data`, `negoex_ctx.c:170-196`).
fn exchange_meta_data(context: &mut Context, messages: &[Message]) {
    let kind = match context.role {
        Role::Initiator => MessageType::AcceptorMetaData,
        Role::Acceptor => MessageType::InitiatorMetaData,
    };
    for message in messages {
        let Message::Exchange(exchange) = message else {
            continue;
        };
        if exchange.message_type() != kind {
            continue;
        }
        let Some(index) = context
            .entries
            .iter()
            .position(|entry| entry.scheme == exchange.scheme())
        else {
            continue;
        };
        let (role, request) = (context.role, &context.request);
        let accepted = context.entries.get_mut(index).is_some_and(|entry| {
            entry
                .session(role)
                .exchange_meta_data(request, exchange.token())
                .is_ok()
        });
        if !accepted {
            drop(context.entries.remove(index));
        }
    }
}

/// Keep only the first entry (MIT `negoex_select_auth_mech`).
fn select_first(context: &mut Context) {
    context.entries.truncate(1);
}

/// Reorder and prune the entries to the acceptor's list (MIT
/// `negoex_common_auth_schemes`, `negoex_util.c:680-700`).
fn common_auth_schemes(context: &mut Context, schemes: &[AuthScheme]) {
    let mut remaining = mem::take(&mut context.entries);
    for scheme in schemes {
        if let Some(index) = remaining.iter().position(|entry| entry.scheme == *scheme) {
            context.entries.push(remaining.remove(index));
        }
    }
}

/// Prune the entries to the initiator's list, keeping their order (MIT
/// `negoex_restrict_auth_schemes`).
fn restrict_auth_schemes(context: &mut Context, schemes: &[AuthScheme]) {
    context
        .entries
        .retain(|entry| schemes.contains(&entry.scheme));
}

/// After a `VERIFY_NO_KEY` alert the mechanism sends its `VERIFY` message again
/// once it has keys (MIT `process_alerts`, `negoex_ctx.c:443-458`).
fn process_alerts(context: &mut Context, messages: &[Message]) {
    let Some(alert) = find_alert(messages).filter(|alert| alert.is_verify_no_key()) else {
        return;
    };
    if let Some(entry) = context
        .entries
        .iter_mut()
        .find(|entry| entry.scheme == alert.scheme())
    {
        entry.sent_checksum = false;
        entry.keys = VerifyKeys::none();
    }
}

/// On the initiator's second step: commit to the optimistic mechanism when the
/// acceptor continued it, else restart it (MIT `check_optimistic_result`).
fn check_optimistic_result(context: &mut Context, messages: &[Message]) {
    let continued = find_exchange(messages, MessageType::Challenge).is_some()
        || find_verify(messages).is_some();
    let Some(first) = context.entries.first_mut().filter(|entry| entry.is_started()) else {
        return;
    };
    if continued {
        select_first(context);
    } else {
        first.restart();
    }
}
