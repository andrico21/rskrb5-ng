use core::error::Error;

use rskrb5_ng::{
    Config,
    client::{Tokio, transport::KdcProtocol},
    crypto::{CryptoPolicy, KerberosEtype},
    keytab::Keytab,
    spnego::{self, InitiatorContextOptions},
};
use tokio::runtime::Builder;

use super::client::session;

/// Both legacy families require explicit flags and membership through high-level context creation.
#[test]
fn configured_legacy_context_propagates_policy() -> Result<(), Box<dyn Error>> {
    // Given an explicitly permitted legacy cached service session.
    for (id, flag, name) in [(23_i32, "allow_rc4", "rc4"), (16_i32, "allow_des3", "des3")] {
        let config = Config::parse(&format!(
            "[libdefaults]\n{flag} = true\npermitted_enctypes = DEFAULT {name}"
        ))?;
        let mut ticket = session(id, id)?;
        let etype = KerberosEtype::from_etype_id(id).ok_or("implemented legacy")?;
        ticket.session_key.value = vec![0x45; etype.key_len()].into();
        let service = ticket.service.clone();
        let mut client = Tokio::with_keytab(
            config,
            KdcProtocol::Tcp,
            ticket.client.clone(),
            Keytab::new(),
        );
        client.cache_service_ticket(ticket)?;
        // When the high-level HTTP/SPNEGO client constructs its context.
        let context = Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(client.spnego_context(service))?;
        // Then the AP authenticator uses the authorized legacy enctype, not defaults.
        assert_eq!(context.ap_req.authenticator.etype, id);
    }
    Ok(())
}

/// Direct SPNEGO options convey explicit policy to the AP builder.
#[test]
fn explicit_spnego_policy_reaches_ap_builder() -> Result<(), Box<dyn Error>> {
    // Given RC4 permission and a correctly sized synthetic session key.
    let config =
        Config::parse("[libdefaults]\nallow_rc4 = true\npermitted_enctypes = DEFAULT rc4")?;
    let mut ticket = session(23, 23)?;
    ticket.session_key.value = vec![0x45; 16].into();
    let options = InitiatorContextOptions::new()
        .with_crypto_policy(CryptoPolicy::from_libdefaults(&config.libdefaults)?);
    // When constructing through the direct initiator API.
    let context = spnego::init_sec_context(&ticket, options)?;
    // Then explicit runtime permission is retained.
    assert_eq!(context.ap_req.authenticator.etype, 23_i32);
    Ok(())
}
