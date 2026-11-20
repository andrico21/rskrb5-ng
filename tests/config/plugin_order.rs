//! `[plugins]` module order follows MIT 1.22.2 `plugin.c` (supervisor finding Y3-01).

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    extern crate alloc;

    use alloc::sync::Arc;
    use core::error::Error;

    use rskrb5_ng::{
        config::ParseMode,
        extensions::{Extension, HostRealm, Interface, ProviderError, RealmQuery, Registry},
    };

    /// A host-realm mapper that answers with its own id as the realm.
    struct Named(&'static str);

    impl HostRealm for Named {
        fn id(&self) -> &'static str {
            self.0
        }

        fn realms(&self, _query: &RealmQuery<'_>) -> Result<Option<Vec<String>>, ProviderError> {
            Ok(Some(vec![self.0.to_ascii_uppercase()]))
        }
    }

    /// Mappers `a` then `b`, registered in that order.
    fn registry() -> Result<Registry, Box<dyn Error>> {
        let mut registry = Registry::new();
        for id in ["a", "b"] {
            registry.register(Extension::HostRealm(Arc::new(Named(id))))?;
        }
        Ok(registry)
    }

    /// MIT `make_full_list` (`plugin.c:207-252`): configured modules come first in
    /// profile order, then registered ones, and a duplicate keeps its first place;
    /// the first enabled mapper answers.
    #[test]
    fn configured_module_precedes_registered_ones() -> Result<(), Box<dyn Error>> {
        let registry = registry()?;
        let config = registry.parse_config(
            "[plugins]\n hostrealm = {\n module = b:/ignored\n }\n",
            ParseMode::Compatible,
        )?;

        assert_eq!(registry.enabled(Interface::HostRealm, &config), ["b", "a"]);
        assert_eq!(
            registry.realms(&config, &RealmQuery::Host("host.example.org"))?,
            Some(vec!["B".to_owned()])
        );
        Ok(())
    }

    /// MIT `configure_interface` (`plugin.c:302-347`) on the configured order.
    ///
    /// Configured modules keep their profile order, a repeated module keeps its
    /// first place, `disable` removes and `enable_only` filters and reorders.
    #[test]
    fn module_order_then_disable_then_enable_only() -> Result<(), Box<dyn Error>> {
        let mut registry = registry()?;
        registry.register(Extension::HostRealm(Arc::new(Named("c"))))?;
        for (body, expected) in [
            ("module = c:/x\n module = b:/y", vec!["c", "b", "a"]),
            (
                "module = b:/x\n module = c:/y\n module = b:/z",
                vec!["b", "c", "a"],
            ),
            ("module = c:/x\n disable = c", vec!["a", "b"]),
            (
                "module = c:/x\n enable_only = a\n enable_only = c",
                vec!["a", "c"],
            ),
        ] {
            let config = registry.parse_config(
                &format!("[plugins]\n hostrealm = {{\n {body}\n }}\n"),
                ParseMode::Compatible,
            )?;
            assert_eq!(
                registry.enabled(Interface::HostRealm, &config),
                expected,
                "{body}"
            );
        }
        Ok(())
    }
}
