//! The built-in modules of MIT's `localauth` interface as extension providers.
//!
//! MIT registers six modules (`localauth.c:113-134`): `default` and `rule`
//! answer only to the `DEFAULT` and `RULE` types of `auth_to_local`, so they
//! live inside the `auth_to_local` module; `names`, `auth_to_local`, `k5login`
//! and `an2ln` are the providers [`modules`] returns, in MIT's order, for a
//! [`Registry`](crate::extensions::Registry) that also holds the application's
//! own modules and `[plugins] localauth` `disable` and `enable_only` choices.

use alloc::sync::Arc;

use crate::{
    ccache::Principal,
    error::LocalAuth as Error,
    extensions::{Decision, Extension, LocalAuth, ProviderError},
};

use super::{LocalAuthorizer, LocalNameMapper, k5login};

/// The `names` module: `auth_to_local_names`.
#[derive(Debug)]
struct Names(Arc<LocalNameMapper>);

/// The `auth_to_local` module: the rules, `DEFAULT` without any.
#[derive(Debug)]
struct Rules(Arc<LocalNameMapper>);

/// The `k5login` module.
#[derive(Debug)]
struct K5login(Arc<LocalAuthorizer>);

/// The `an2ln` module: a principal may use the account it translates to.
#[derive(Debug)]
struct An2ln(Arc<LocalNameMapper>);

/// A name answer: no translation is no answer, any other failure is one.
///
/// # Errors
///
/// The failure of the rules, boxed for the registry.
fn answer(result: Result<String, Error>) -> Result<Option<String>, ProviderError> {
    match result {
        Ok(name) => Ok(Some(name)),
        Err(Error::NoTranslation) => Ok(None),
        Err(other) => Err(other.into()),
    }
}

impl LocalAuth for Names {
    #[inline]
    fn id(&self) -> &'static str {
        "names"
    }

    #[inline]
    fn userok(&self, _principal: &Principal, _local_name: &str) -> Result<Decision, ProviderError> {
        Ok(Decision::Pass)
    }

    #[inline]
    fn local_name(&self, principal: &Principal) -> Result<Option<String>, ProviderError> {
        self.0.explicit(principal).transpose().map_err(Into::into)
    }
}

impl LocalAuth for Rules {
    #[inline]
    fn id(&self) -> &'static str {
        "auth_to_local"
    }

    #[inline]
    fn userok(&self, _principal: &Principal, _local_name: &str) -> Result<Decision, ProviderError> {
        Ok(Decision::Pass)
    }

    #[inline]
    fn local_name(&self, principal: &Principal) -> Result<Option<String>, ProviderError> {
        answer(self.0.by_rules(principal))
    }
}

impl LocalAuth for K5login {
    #[inline]
    fn id(&self) -> &'static str {
        "k5login"
    }

    #[inline]
    fn userok(&self, principal: &Principal, local_name: &str) -> Result<Decision, ProviderError> {
        Ok(match k5login::check(&self.0, principal, local_name) {
            k5login::Verdict::Listed => Decision::Allow,
            k5login::Verdict::Silent => Decision::Pass,
            k5login::Verdict::Refused(_fault) => Decision::Deny,
        })
    }

    #[inline]
    fn local_name(&self, _principal: &Principal) -> Result<Option<String>, ProviderError> {
        Ok(None)
    }
}

impl LocalAuth for An2ln {
    #[inline]
    fn id(&self) -> &'static str {
        "an2ln"
    }

    #[inline]
    fn userok(&self, principal: &Principal, local_name: &str) -> Result<Decision, ProviderError> {
        Ok(match self.0.translate(principal) {
            Ok(name) if name == local_name => Decision::Allow,
            Ok(_) | Err(_) => Decision::Pass,
        })
    }

    #[inline]
    fn local_name(&self, _principal: &Principal) -> Result<Option<String>, ProviderError> {
        Ok(None)
    }
}

/// The built-in modules of `authorizer`, in MIT's order: `names`,
/// `auth_to_local`, `k5login`, `an2ln`.
///
/// Register them after the application's own modules to keep MIT's order,
/// where a module loaded from a plugin answers before a built-in one.
#[must_use]
#[inline]
pub fn modules(authorizer: &LocalAuthorizer) -> Vec<Extension> {
    let mapper = Arc::new(authorizer.mapper.clone());
    vec![
        Extension::LocalAuth(Arc::new(Names(Arc::clone(&mapper)))),
        Extension::LocalAuth(Arc::new(Rules(Arc::clone(&mapper)))),
        Extension::LocalAuth(Arc::new(K5login(Arc::new(authorizer.clone())))),
        Extension::LocalAuth(Arc::new(An2ln(mapper))),
    ]
}
