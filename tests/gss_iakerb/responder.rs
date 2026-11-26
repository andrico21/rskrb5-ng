//! Prompts of the relayed AS exchange, answered through the client's
//! responder machinery (`client::stepwise::Responder`, MIT's responder and
//! prompter callbacks).

use rskrb5_ng::{
    ccache::{CCache, Principal},
    client::{
        Password,
        stepwise::{Answer, Prompt, Responder},
    },
    error::{Client, Gss, Iakerb},
    extensions::ProviderError,
    gss::{Credential, InitiatorOptions},
};

use super::{
    context::{Context as _, TestError},
    kdc::Kdc,
    seal::{PASSWORD, REALM, USER},
    support::{Setup, config, establish, establish_under, policy},
};

/// A responder that answers the password prompt, or declines every prompt.
#[derive(Debug, Default)]
struct Answering {
    /// Whether it answers.
    answers: bool,
    /// The prompts it saw.
    prompts: Vec<Prompt>,
}

impl Responder for Answering {
    fn respond(&mut self, prompt: &Prompt) -> Result<Answer, ProviderError> {
        self.prompts.push(prompt.clone());
        if self.answers && matches!(prompt, Prompt::Password { client: _ }) {
            Ok(Answer::Password(Password::from_vec(PASSWORD.to_vec())))
        } else {
            Err("declined".into())
        }
    }
}

/// A credential that names the client and holds neither a password, a
/// keytab nor a ticket.
fn name_only() -> Result<Credential, TestError> {
    Ok(Credential::from_ccache(CCache::new(Principal::new(
        REALM,
        1,
        vec![USER.to_owned()],
    )))?)
}

/// The password prompt of a credential without a password goes to the
/// responder, whose answer completes the relayed AS exchange; without a
/// responder, or with one that declines, the context is refused.
#[test]
fn iakerb_responder_handles_prompt() -> Result<(), TestError> {
    let kdc = Kdc::new();
    // Given a credential with no password and a responder that knows it,
    let mut responder = Answering {
        answers: true,
        ..Answering::default()
    };
    let setup = Setup {
        config: config()?,
        options: InitiatorOptions::new(),
        policy: policy()?,
        responder: Some(&mut responder),
    };
    // when the context is established,
    let mut pair = establish_under(&name_only()?, &kdc, setup)?;
    // then the responder answered one password prompt for the client,
    assert!(
        matches!(responder.prompts.as_slice(), [Prompt::Password { client }] if client.components == [USER]),
        "{:?}",
        responder.prompts
    );
    let sealed = pair.initiator.wrap(b"prompted", true)?;
    assert_eq!(pair.acceptor.unwrap(&sealed)?.message(), b"prompted");
    // and without a responder the credential has no ticket source,
    let without = establish(&name_only()?, &kdc)
        .err()
        .context("no context without a ticket source")?;
    assert!(
        matches!(
            without.downcast_ref::<Iakerb>(),
            Some(Iakerb::Gss(Gss::NoCredential(_)))
        ),
        "{without}"
    );
    // and a responder that declines ends the context with its refusal.
    let mut declining = Answering::default();
    let refusing = Setup {
        config: config()?,
        options: InitiatorOptions::new(),
        policy: policy()?,
        responder: Some(&mut declining),
    };
    let refusal = establish_under(&name_only()?, &kdc, refusing)
        .err()
        .context("no context when the responder declines")?;
    assert!(
        matches!(
            refusal.downcast_ref::<Iakerb>(),
            Some(Iakerb::Client(Client::Responder(_)))
        ),
        "{refusal}"
    );
    assert_eq!(declining.prompts.len(), 1);
    Ok(())
}
