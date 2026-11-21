//! [`AnonymousArmorSource`] as the FAST anonymous-armor hook.

use std::time::SystemTime;

use super::{AnonymousArmorSource, AnonymousOptions, Exchange};
use crate::{
    client::{
        AsRepSession, KdcTransport,
        options::AsReq,
        random_nonce,
        stepwise::{self, InitCreds, InitCredsOptions, NoResponder},
    },
    extensions::ProviderError,
    preauth::fast::AnonymousArmor,
};

impl<T> AnonymousArmor for AnonymousArmorSource<T>
where
    T: KdcTransport + Send,
{
    #[inline]
    fn armor_ticket(&mut self, realm: &str) -> Result<AsRepSession, ProviderError> {
        let options = InitCredsOptions::new(AsReq::new(SystemTime::now(), random_nonce()?))
            .with_anonymous(AnonymousOptions::Full);
        let mut engine = InitCreds::with_pkinit(
            AnonymousOptions::client(realm),
            Exchange::anonymous(self.trust.clone(), self.policy.clone()),
            options,
        );
        Ok(stepwise::drive(
            &mut self.transport,
            &mut engine,
            &mut NoResponder,
        )?)
    }
}
