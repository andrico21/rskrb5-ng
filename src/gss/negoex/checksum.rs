/// The key usage of the checksum this side makes or verifies (MIT
/// `verify_keyusage`, `negoex_ctx.c:333-339`).
const fn key_usage(role: Role, making: bool) -> u32 {
    let initiator = matches!(role, Role::Initiator);
    if initiator == making {
        KEYUSAGE_ACCEPTOR_CHECKSUM
    } else {
        KEYUSAGE_INITIATOR_CHECKSUM
    }
}

/// Verify the peer's `VERIFY` message over the transcript and the token bytes
/// before it; return whether to send a `VERIFY_NO_KEY` alert (MIT
/// `verify_checksum`, `negoex_ctx.c:341-390`).
///
/// # Errors
///
/// Returns [`Negoex::InvalidChecksum`] for a checksum that does not verify, of a
/// type the key does not define or that is not keyed, and the policy and
/// cryptographic errors of the key.
fn verify_checksum(
    context: &mut Context,
    messages: &[Message],
    input: Option<&[u8]>,
) -> Result<bool, Negoex> {
    let usage = key_usage(context.role, false);
    let first = context.entries.first_mut().ok_or(Negoex::NoAvailableMechs)?;
    let Some(verify) = find_verify(messages).filter(|verify| verify.scheme() == first.scheme)
    else {
        return Ok(false);
    };
    let Some(key) = first.verify_key.as_ref() else {
        return Ok(true);
    };
    let token = input.ok_or(Negoex::UnexpectedStep("a VERIFY message needs its token"))?;
    let covered = token
        .get(..verify.offset_in_token())
        .ok_or(Negoex::InvalidMessageSize)?;
    let mut data = Zeroizing::new(Vec::with_capacity(
        context.transcript.len().saturating_add(covered.len()),
    ));
    data.extend_from_slice(&context.transcript);
    data.extend_from_slice(covered);
    let etype = Etype::new(&context.policy, key.etype())?;
    if checksum_type(key) != Some(verify.checksum_type()) {
        return Err(Negoex::InvalidChecksum);
    }
    etype
        .verify_checksum(key.value(), &data, verify.checksum(), usage)
        .map_err(|failure| {
            if matches!(failure, Crypto::IntegrityCheckFailed) {
                Negoex::InvalidChecksum
            } else {
                Negoex::Crypto(failure)
            }
        })?;
    first.verified_checksum = true;
    Ok(false)
}

/// The RFC 3961 checksum type of the key's encryption type.
fn checksum_type(key: &EncryptionKey) -> Option<i32> {
    KerberosEtype::from_etype_id(key.etype()).map(KerberosEtype::checksum_type_id)
}

/// Append this side's `VERIFY` message over the transcript, when the
/// mechanism has a key (MIT `make_checksum`, `negoex_ctx.c:392-423`).
///
/// # Errors
///
/// Returns [`Negoex::NoVerifyKey`] when the mechanism is established and has no
/// key, and the policy and cryptographic errors of the key.
fn make_checksum(context: &mut Context) -> Result<(), Negoex> {
    let usage = key_usage(context.role, true);
    let first = context.entries.first_mut().ok_or(Negoex::NoAvailableMechs)?;
    let Some(key) = first.key.as_ref() else {
        return if first.is_complete() {
            Err(Negoex::NoVerifyKey)
        } else {
            Ok(())
        };
    };
    let etype = Etype::new(&context.policy, key.etype())?;
    let checksum_type = checksum_type(key).ok_or(Negoex::InvalidChecksum)?;
    let checksum = etype.checksum(key.value(), &context.transcript, usage)?;
    let verify = Message::Verify(VerifyMessage::new(first.scheme, checksum_type, checksum));
    context
        .conversation
        .encode_into(&verify, &mut context.transcript)?;
    first.sent_checksum = true;
    Ok(())
}

/// The new bytes of the transcript for the peer (MIT `make_output_token`, `negoex_ctx.c:460-536`).
///
/// They are, on the first step, the nego message and the meta-data, then the
/// mechanism token, an alert and the `VERIFY` message.
///
/// # Errors
///
/// Returns the errors of [`make_checksum`], the random source and the message encoding.
fn make_output_token(
    context: &mut Context,
    mech_output: Option<Vec<u8>>,
    send_alert: bool,
) -> Result<Vec<u8>, Negoex> {
    let first = context.entries.first().ok_or(Negoex::NoAvailableMechs)?;
    if mech_output.is_none() && first.sent_checksum {
        return Ok(Vec::new());
    }
    let old_len = context.transcript.len();
    if context.step == 1 {
        let (nego, meta) = match context.role {
            Role::Initiator => (MessageType::InitiatorNego, MessageType::InitiatorMetaData),
            Role::Acceptor => (MessageType::AcceptorNego, MessageType::AcceptorMetaData),
        };
        let mut random = [0; 32];
        (context.random)(&mut random)?;
        let schemes = context.entries.iter().map(|entry| entry.scheme).collect();
        let message = Message::Nego(NegoMessage::new(nego, random, schemes)?);
        context
            .conversation
            .encode_into(&message, &mut context.transcript)?;
        for entry in &context.entries {
            if !entry.metadata.is_empty() {
                let offered = Message::Exchange(ExchangeMessage::new(
                    meta,
                    entry.scheme,
                    entry.metadata.clone(),
                )?);
                context
                    .conversation
                    .encode_into(&offered, &mut context.transcript)?;
            }
        }
    }
    let scheme = context.entries.first().ok_or(Negoex::NoAvailableMechs)?.scheme;
    if let Some(token) = mech_output {
        let kind = match context.role {
            Role::Initiator => MessageType::ApRequest,
            Role::Acceptor => MessageType::Challenge,
        };
        let message = Message::Exchange(ExchangeMessage::new(kind, scheme, token)?);
        context
            .conversation
            .encode_into(&message, &mut context.transcript)?;
    }
    if send_alert {
        context
            .conversation
            .encode_into(&Message::Alert(AlertMessage::verify_no_key(scheme)), &mut context.transcript)?;
    }
    if !context.entries.first().is_some_and(|entry| entry.sent_checksum) {
        make_checksum(context)?;
    }
    Ok(context
        .transcript
        .get(old_len..)
        .map_or_else(Vec::new, <[u8]>::to_vec))
}
