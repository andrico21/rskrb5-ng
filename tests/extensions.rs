//! Extension registry: order, `[plugins]` selection, `module` resolution and
//! the validation every provider output passes.

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
    use std::{env, fs, process, sync::Mutex};

    use rskrb5_ng::{
        ccache::Principal,
        config::{Config, MAX_INCLUDE_BYTES, ParseMode},
        error::{Any, Config as ConfigError, Extensions as Failure},
        extensions::{
            CacheCandidate, CacheSelector, Decision, Event, Extension, GssMechanism, HostRealm,
            HostnameSelector, Interface, K5Identity, LibraryObserver, LocalAuth, LocateRequest,
            LocateService, LocateTransport, Priority, ProfileProvider, ProviderError, RealmQuery,
            RealmSelector, Registry, Selection, SelectionRequest, ServerAddress, ServerLocator,
        },
    };

    /// A selector with a fixed id, priority and answer.
    struct Fixed {
        /// Its id.
        id: String,
        /// Its priority.
        priority: Priority,
        /// Its answer; `None` fails.
        answer: Option<Selection>,
    }

    impl CacheSelector for Fixed {
        fn id(&self) -> &str {
            &self.id
        }

        fn priority(&self) -> Priority {
            self.priority
        }

        fn choose(&self, _request: &SelectionRequest<'_>) -> Result<Selection, ProviderError> {
            self.answer.clone().ok_or_else(|| "selector failed".into())
        }
    }

    /// A heuristic selector registration.
    fn selector(id: &str, answer: Option<Selection>) -> Extension {
        Extension::CacheSelector(Arc::new(Fixed {
            id: id.to_owned(),
            priority: Priority::Heuristic,
            answer,
        }))
    }

    /// A profile provider that returns fixed text and records its residuals.
    struct Profile {
        /// The text it returns; `None` fails.
        text: Option<String>,
        /// The residuals it was given.
        seen: Mutex<Vec<String>>,
    }

    impl ProfileProvider for Profile {
        fn id(&self) -> &'static str {
            "site"
        }

        fn profile(&self, residual: &str) -> Result<String, ProviderError> {
            self.seen
                .lock()
                .map_err(|_poisoned| "poisoned")?
                .push(residual.to_owned());
            self.text
                .clone()
                .ok_or_else(|| "profile unavailable".into())
        }
    }

    /// A registry with the `site` profile provider, and a handle on it.
    fn with_profile(text: Option<&str>) -> Result<(Registry, Arc<Profile>), Box<dyn Error>> {
        let provider = Arc::new(Profile {
            text: text.map(str::to_owned),
            seen: Mutex::new(Vec::new()),
        });
        let mut registry = Registry::new();
        registry.register(Extension::ProfileProvider(Arc::<Profile>::clone(&provider)))?;
        Ok((registry, provider))
    }

    /// An observer that records every event.
    #[derive(Default)]
    struct Recorder {
        /// The events, rendered.
        events: Mutex<Vec<String>>,
    }

    impl LibraryObserver for Recorder {
        fn id(&self) -> &'static str {
            "recorder"
        }

        fn observe(&self, event: &Event<'_>) {
            if let Ok(mut events) = self.events.lock() {
                events.push(format!("{event:?}"));
            }
        }
    }

    /// The host-based server `HTTP/<host>@<realm>`.
    fn web(host: &str, realm: &str) -> Principal {
        Principal::new(realm, 3, vec!["HTTP".to_owned(), host.to_owned()])
    }

    /// A cache candidate for `name@realm`.
    fn cache(name: &str, realm: &str) -> CacheCandidate {
        CacheCandidate::new(
            format!("MEMORY:{name}"),
            Principal::new(realm, 1, vec![name.to_owned()]),
        )
    }

    /// Providers keep their registration order; the built-ins use MIT's order.
    #[test]
    fn registration_order_is_deterministic() -> Result<(), Box<dyn Error>> {
        let mut registry = Registry::new();
        for id in ["c", "a", "b"] {
            registry.register(selector(id, Some(Selection::NoHandle)))?;
        }
        let config = Config::parse("")?;
        assert_eq!(
            registry.ids(Interface::CacheSelector),
            ["c", "a", "b"],
            "ids"
        );
        assert_eq!(
            registry.enabled(Interface::CacheSelector, &config),
            ["c", "a", "b"],
            "enabled"
        );
        let builtins = Registry::with_builtins(Some(K5Identity::from_bytes(Vec::new())));
        assert_eq!(
            builtins.ids(Interface::CacheSelector),
            ["k5identity", "realm", "hostname"],
            "MIT order"
        );
        assert_eq!(
            Registry::with_builtins(None).ids(Interface::CacheSelector),
            ["realm", "hostname"],
            "no identity file"
        );
        Ok(())
    }

    /// A repeated id is refused per interface; ids are validated and bounded.
    #[test]
    fn duplicate_and_invalid_ids_are_refused() -> Result<(), Box<dyn Error>> {
        let mut registry = Registry::with_builtins(None);
        let duplicate = registry
            .register(selector("realm", Some(Selection::NoHandle)))
            .err()
            .ok_or("duplicate accepted")?;
        assert!(
            matches!(&duplicate, Failure::DuplicateId { interface: Interface::CacheSelector, id } if id == "realm"),
            "{duplicate}"
        );
        registry.register(selector("Realm", Some(Selection::NoHandle)))?;
        let long = "x".repeat(65);
        for id in ["", "a:b", "a b", "a/b", "a=b", long.as_str()] {
            let failure = registry
                .register(selector(id, Some(Selection::NoHandle)))
                .err()
                .ok_or("invalid id accepted")?;
            assert!(
                matches!(
                    failure,
                    Failure::InvalidId {
                        interface: _,
                        id: _
                    }
                ),
                "{id}: {failure}"
            );
        }
        let mut full = Registry::new();
        for index in 0_i32..32_i32 {
            full.register(selector(&format!("s{index}"), Some(Selection::NoHandle)))?;
        }
        let failure = full
            .register(selector("one-more", Some(Selection::NoHandle)))
            .err()
            .ok_or("bound ignored")?;
        assert!(
            matches!(
                failure,
                Failure::TooManyProviders {
                    interface: _,
                    limit: 32
                }
            ),
            "{failure}"
        );
        Ok(())
    }

    /// `disable` removes, `enable_only` keeps and reorders, names match exactly.
    #[test]
    fn plugins_disable_and_enable_only() -> Result<(), Box<dyn Error>> {
        let mut registry = Registry::with_builtins(Some(K5Identity::from_bytes(Vec::new())));
        registry.register(selector("mine", Some(Selection::NoHandle)))?;
        for (body, expected) in [
            ("disable = realm", vec!["k5identity", "hostname", "mine"]),
            (
                "disable = realm\n disable = mine",
                vec!["k5identity", "hostname"],
            ),
            (
                "disable = REALM",
                vec!["k5identity", "realm", "hostname", "mine"],
            ),
            (
                "enable_only = mine\n enable_only = realm",
                vec!["mine", "realm"],
            ),
            ("enable_only = absent", vec![]),
            (
                "disable = mine\n enable_only = mine\n enable_only = hostname",
                vec!["hostname"],
            ),
        ] {
            let config = Config::parse(&format!("[plugins]\n ccselect = {{\n {body}\n }}\n"))?;
            assert_eq!(
                registry.enabled(Interface::CacheSelector, &config),
                expected,
                "{body}"
            );
        }
        let unrelated = Config::parse("[plugins]\n CCSELECT = {\n disable = realm\n }\n")?;
        assert_eq!(
            registry.enabled(Interface::CacheSelector, &unrelated),
            ["k5identity", "realm", "hostname", "mine"],
            "interface names match exactly"
        );
        Ok(())
    }

    /// Authoritative selectors run first, then heuristic ones in enabled order.
    #[test]
    fn selection_order_and_priority() -> Result<(), Box<dyn Error>> {
        let caches = [cache("alice", "A.ORG"), cache("bob", "EXAMPLE.ORG")];
        let mut registry = Registry::new();
        registry.register(selector("guess", Some(Selection::Cache(0))))?;
        registry.register(Extension::CacheSelector(Arc::new(Fixed {
            id: "knows".to_owned(),
            priority: Priority::Authoritative,
            answer: Some(Selection::Cache(1)),
        })))?;
        let config = Config::parse("")?;
        let server = web("www.example.org", "EXAMPLE.ORG");
        assert_eq!(
            registry.select_cache(&config, &server, &caches)?,
            Selection::Cache(1),
            "authoritative first"
        );
        let disabled = Config::parse("[plugins]\n ccselect = {\n disable = knows\n }\n")?;
        assert_eq!(
            registry.select_cache(&disabled, &server, &caches)?,
            Selection::Cache(0),
            "disabled selector skipped"
        );
        Ok(())
    }

    /// The `realm` and `hostname` built-ins follow MIT's rules.
    #[test]
    fn realm_and_hostname_builtins() -> Result<(), Box<dyn Error>> {
        let caches = [
            cache("alice", "ORG"),
            cache("bob", "EXAMPLE.ORG"),
            cache("carol", "WWW.EXAMPLE.ORG"),
        ];
        let registry = Registry::with_builtins(None);
        let config = Config::parse("")?;
        for (server, expected) in [
            (web("www.example.org", ""), Selection::Cache(2)),
            (web("mail.example.org", ""), Selection::Cache(1)),
            (web("host.other.net", ""), Selection::NoHandle),
            (web("x", "EXAMPLE.ORG"), Selection::Cache(1)),
            (
                Principal::new("", 1, vec!["a".to_owned(), "www.example.org".to_owned()]),
                Selection::NoHandle,
            ),
        ] {
            assert_eq!(
                registry.select_cache(&config, &server, &caches)?,
                expected,
                "{}",
                server.principal_string()
            );
        }
        assert!(
            matches!(
                RealmSelector::new().choose(&request(&web("x", ""), &caches)),
                Ok(Selection::NoHandle)
            ),
            "realm needs a server realm"
        );
        assert!(
            matches!(
                HostnameSelector::new().choose(&request(&web("x.ORG", "Z"), &caches)),
                Ok(Selection::Cache(0))
            ),
            "host itself"
        );
        Ok(())
    }

    /// A request outside the driver, for calling a selector directly.
    fn request<'request>(
        server: &'request Principal,
        caches: &'request [CacheCandidate],
    ) -> SelectionRequest<'request> {
        SelectionRequest::new(server, caches, None)
    }

    /// `k5identity` names a cache or, without one, the principal it wants.
    #[test]
    fn k5identity_builtin_through_the_registry() -> Result<(), Box<dyn Error>> {
        let file = b"bob@EXAMPLE.ORG host=*.example.org\ndave realm=OTHER.ORG\n".to_vec();
        let registry = Registry::with_builtins(Some(K5Identity::from_bytes(file)));
        let config = Config::parse("[libdefaults]\n default_realm = HOME.ORG\n")?;
        let caches = [cache("alice", "EXAMPLE.ORG"), cache("bob", "EXAMPLE.ORG")];
        assert_eq!(
            registry.select_cache(&config, &web("www.example.org", "EXAMPLE.ORG"), &caches)?,
            Selection::Cache(1),
            "authoritative k5identity beats realm"
        );
        assert_eq!(
            registry.select_cache(&config, &web("www.other.org", "OTHER.ORG"), &caches)?,
            Selection::Principal(Principal::new("HOME.ORG", 1, vec!["dave".to_owned()])),
            "wanted principal without a cache"
        );
        assert_eq!(
            registry.select_cache(&config, &web("www.else.org", "EXAMPLE.ORG"), &caches)?,
            Selection::Cache(0),
            "no line: heuristic realm"
        );
        Ok(())
    }

    /// The file form reads at every selection; a missing file is no answer and
    /// an oversized one fails.
    #[test]
    fn k5identity_reads_its_file() -> Result<(), Box<dyn Error>> {
        let directory = env::temp_dir().join(format!("rskrb5-k5identity-{}", process::id()));
        fs::create_dir_all(&directory)?;
        let path = directory.join(".k5identity");
        let selector = K5Identity::new(&path);
        let caches = [cache("bob", "EXAMPLE.ORG")];
        let server = web("www.example.org", "EXAMPLE.ORG");
        let missing = selector.choose(&SelectionRequest::new(&server, &caches, None));
        fs::write(&path, "bob@EXAMPLE.ORG\n")?;
        let present = selector.choose(&SelectionRequest::new(&server, &caches, None));
        fs::write(&path, vec![b'#'; 0x0001_0001])?;
        let oversized = selector.choose(&SelectionRequest::new(&server, &caches, None));
        fs::remove_dir_all(&directory)?;
        assert!(matches!(missing, Ok(Selection::NoHandle)), "missing file");
        assert!(matches!(present, Ok(Selection::Cache(0))), "file read");
        assert!(oversized.is_err(), "oversized file refused");
        Ok(())
    }

    /// Malformed selector output and selector failures stop the selection.
    #[test]
    fn malformed_selector_output_is_refused() -> Result<(), Box<dyn Error>> {
        let caches = [cache("alice", "EXAMPLE.ORG")];
        let config = Config::parse("")?;
        let server = web("www.example.org", "EXAMPLE.ORG");
        for answer in [
            Some(Selection::Cache(1)),
            Some(Selection::Principal(Principal::new(
                "",
                1,
                vec!["x".to_owned()],
            ))),
            Some(Selection::Principal(Principal::new("R", 1, Vec::new()))),
            Some(Selection::Principal(Principal::new(
                "R",
                1,
                vec!["a\nb".to_owned()],
            ))),
        ] {
            let mut registry = Registry::new();
            registry.register(selector("bad", answer))?;
            let failure = registry
                .select_cache(&config, &server, &caches)
                .err()
                .ok_or("malformed output accepted")?;
            assert!(
                matches!(
                    failure,
                    Failure::MalformedOutput {
                        interface: _,
                        id: _,
                        reason: _
                    }
                ),
                "{failure}"
            );
        }
        let mut registry = Registry::new();
        registry.register(selector("broken", None))?;
        registry.register(selector("later", Some(Selection::Cache(0))))?;
        let failure = registry
            .select_cache(&config, &server, &caches)
            .err()
            .ok_or("failure ignored")?;
        assert!(
            matches!(
                failure,
                Failure::CallFailed {
                    interface: _,
                    id: _,
                    source: _
                }
            ),
            "{failure}"
        );
        Ok(())
    }

    /// `[plugins] module = <id>:<path>` resolves registered ids of that interface only.
    #[test]
    fn plugin_module_resolves_registered_ids() -> Result<(), Box<dyn Error>> {
        let mut registry = Registry::with_builtins(None);
        registry.register(selector("mine", Some(Selection::NoHandle)))?;
        let accepted =
            "[plugins]\n ccselect = {\n module = mine:/never/load.so\n module* = realm:\n }\n";
        for mode in [ParseMode::Compatible, ParseMode::Strict] {
            drop(registry.parse_config(accepted, mode)?);
        }
        for text in [
            "[plugins]\n ccselect = {\n module = Mine:/never/load.so\n }\n",
            "[plugins]\n ccselect = {\n module = other:/never/load.so\n }\n",
            "[plugins]\n ccselect = {\n module = mine\n }\n",
            "[plugins]\n ccselect = {\n module = \"mine:/x\"\n }\n",
            "[plugins]\n hostrealm = {\n module = mine:/never/load.so\n }\n",
            "[plugins]\n CCSELECT = {\n module = mine:/never/load.so\n }\n",
            "[plugins]\n module = mine:/never/load.so\n",
            "[libdefaults]\n module = mine:/never/load.so\n",
            "[realms]\n R = {\n module = mine:/never/load.so\n }\n",
        ] {
            let failure = registry
                .parse_config(text, ParseMode::Compatible)
                .err()
                .ok_or("unregistered module accepted")?;
            assert!(
                matches!(
                    failure,
                    Failure::Config(ConfigError::UnsupportedDynamicModule)
                ),
                "{text}: {failure}"
            );
        }
        let plain = Config::parse(accepted)
            .err()
            .ok_or("registry-free parse resolved a module")?;
        assert!(
            matches!(plain, ConfigError::UnsupportedDynamicModule),
            "{plain}"
        );
        Ok(())
    }

    /// The profile directive takes the whole profile from a registered provider.
    #[test]
    fn profile_module_directive_uses_the_provider() -> Result<(), Box<dyn Error>> {
        let (registry, provider) = with_profile(Some(
            "[libdefaults]\n default_realm = SITE.ORG\n[plugins]\n ccselect = {\n disable = realm\n }\n",
        ))?;
        let config = registry.parse_config(
            "# site profile\nmodule site:/etc/site.db?x\n",
            ParseMode::Compatible,
        )?;
        assert_eq!(
            config.libdefaults.default_realm, "SITE.ORG",
            "provider profile"
        );
        assert_eq!(
            provider
                .seen
                .lock()
                .map_err(|_poisoned| "poisoned")?
                .as_slice(),
            ["/etc/site.db?x"],
            "residual handed over"
        );
        for text in [
            "module other:/etc/site.db\n",
            "module Site:/etc/site.db\n",
            "module site:/etc/site.db\n[libdefaults]\n default_realm = X\n",
            "[libdefaults]\nmodule site:/etc/site.db\n",
            "module site\n",
        ] {
            let failure = registry
                .parse_config(text, ParseMode::Compatible)
                .err()
                .ok_or("unresolved directive accepted")?;
            assert!(
                matches!(
                    failure,
                    Failure::Config(ConfigError::UnsupportedDynamicModule)
                ),
                "{text}: {failure}"
            );
        }
        assert!(
            matches!(
                Config::parse("module site:/etc/site.db\n"),
                Err(ConfigError::UnsupportedDynamicModule)
            ),
            "registry-free parse"
        );
        Ok(())
    }

    /// A provider's profile passes the parser's policy: no D2 selector, no
    /// nested module, no unbounded text, and its failure is typed.
    #[test]
    fn profile_provider_cannot_bypass_the_parser() -> Result<(), Box<dyn Error>> {
        for (text, rejected) in [
            ("[libdefaults]\n allow_weak_crypto = true\n", "weak crypto"),
            (
                "[libdefaults]\n default_tkt_enctypes = des-cbc-crc\n",
                "single DES",
            ),
            ("module site:/again\n", "nested module"),
            (
                "[plugins]\n ccselect = {\n module = x:/y\n }\n",
                "unknown module",
            ),
        ] {
            let (registry, _) = with_profile(Some(text))?;
            let failure = registry
                .parse_config("module site:r\n", ParseMode::Compatible)
                .err()
                .ok_or("provider bypassed the parser")?;
            assert!(
                matches!(failure, Failure::Config(_)),
                "{rejected}: {failure}"
            );
        }
        let huge = "#".repeat(MAX_INCLUDE_BYTES.saturating_add(1));
        let (registry, _) = with_profile(Some(&huge))?;
        let failure = registry
            .parse_config("module site:r\n", ParseMode::Compatible)
            .err()
            .ok_or("oversized profile accepted")?;
        assert!(
            matches!(
                failure,
                Failure::OutputTooLarge {
                    interface: _,
                    id: _,
                    limit: _
                }
            ),
            "{failure}"
        );
        let (failing, _) = with_profile(None)?;
        let provider_failure = failing
            .parse_config("module site:r\n", ParseMode::Compatible)
            .err()
            .ok_or("provider failure ignored")?;
        assert!(
            matches!(
                provider_failure,
                Failure::CallFailed {
                    interface: Interface::ProfileProvider,
                    id: _,
                    source: _,
                }
            ),
            "{provider_failure}"
        );
        let any: Any = Any::Extensions(provider_failure);
        assert!(any.to_string().starts_with("extension error"), "{any}");
        Ok(())
    }

    /// Host-realm, local-authorization, locator and mechanism outputs are validated.
    #[test]
    fn provider_outputs_are_validated() -> Result<(), Box<dyn Error>> {
        let config = Config::parse("")?;
        for (answer, ok) in [
            (Some(vec!["EXAMPLE.ORG".to_owned()]), true),
            (Some(Vec::new()), false),
            (Some(vec![String::new()]), false),
            (Some(vec!["A\u{7}B".to_owned()]), false),
            (Some(vec!["R".to_owned(); 33]), false),
        ] {
            let mut registry = Registry::new();
            registry.register(Extension::HostRealm(Arc::new(Realms(answer.clone()))))?;
            let result = registry.realms(&config, &RealmQuery::Host("h.example.org"));
            assert_eq!(result.is_ok(), ok, "{answer:?}");
        }
        let mut zero_port = Registry::new();
        zero_port.register(Extension::ServerLocator(Arc::new(Locator(vec![
            ServerAddress::new("kdc.example.org", 0),
        ]))))?;
        let request = LocateRequest::new("R", LocateService::Kdc, LocateTransport::Tcp);
        assert!(zero_port.locate(&request).is_err(), "port zero refused");
        let mut locators = Registry::new();
        locators.register(Extension::ServerLocator(Arc::new(Locator(vec![
            ServerAddress::new("kdc.example.org", 88),
        ]))))?;
        assert_eq!(
            locators.locate(&request)?,
            Some(vec![ServerAddress::new("kdc.example.org", 88)]),
            "address accepted"
        );
        let mut mapper = Registry::new();
        mapper.register(Extension::LocalAuth(Arc::new(Local {
            id: "map",
            decision: Decision::Pass,
            name: Some("../root".to_owned()),
        })))?;
        let principal = Principal::new("R", 1, vec!["bob".to_owned()]);
        assert!(
            matches!(
                mapper.local_name(&config, &principal),
                Err(Failure::MalformedOutput {
                    interface: _,
                    id: _,
                    reason: _
                })
            ),
            "path in local name refused"
        );
        Ok(())
    }

    /// Any denial or failure denies; at least one authorizer must allow.
    #[test]
    fn local_authorization_denial_wins() -> Result<(), Box<dyn Error>> {
        let config = Config::parse("")?;
        let principal = Principal::new("R", 1, vec!["bob".to_owned()]);
        for (decisions, expected) in [
            (vec![Decision::Allow], true),
            (vec![Decision::Pass], false),
            (vec![], false),
            (vec![Decision::Allow, Decision::Deny], false),
            (vec![Decision::Deny, Decision::Allow], false),
            (vec![Decision::Pass, Decision::Allow], true),
        ] {
            let mut registry = Registry::new();
            for (index, decision) in decisions.iter().enumerate() {
                registry.register(Extension::LocalAuth(Arc::new(Local {
                    id: ["a", "b"].get(index).copied().unwrap_or("c"),
                    decision: *decision,
                    name: None,
                })))?;
            }
            assert_eq!(
                registry.authorize_local(&config, &principal, "bob"),
                expected,
                "{decisions:?}"
            );
        }
        let mut registry = Registry::new();
        registry.register(Extension::LocalAuth(Arc::new(Local {
            id: "allow",
            decision: Decision::Allow,
            name: None,
        })))?;
        registry.register(Extension::LocalAuth(Arc::new(Failing)))?;
        assert!(
            !registry.authorize_local(&config, &principal, "bob"),
            "failure denies"
        );
        let disabled = Config::parse("[plugins]\n localauth = {\n disable = failing\n }\n")?;
        assert!(
            registry.authorize_local(&disabled, &principal, "bob"),
            "disabled authorizer"
        );
        Ok(())
    }

    /// Mechanisms cannot take a built-in or registered object identifier.
    #[test]
    fn gss_mechanism_registration_rules() -> Result<(), Box<dyn Error>> {
        let mut registry = Registry::new();
        let own = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0x80, 0x01];
        registry.register(Extension::GssMechanism(Arc::new(Mechanism(
            "own",
            own.to_vec(),
        ))))?;
        assert!(registry.gss_mechanism(&own).is_some(), "lookup by OID");
        for (id, oid) in [
            (
                "krb5",
                vec![0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02],
            ),
            ("spnego", vec![0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]),
            ("again", own.to_vec()),
            ("empty", Vec::new()),
            ("padded", vec![0x2b, 0x80, 0x01]),
            ("open", vec![0x2b, 0x86]),
            ("long", vec![0x01; 65]),
        ] {
            let failure = registry
                .register(Extension::GssMechanism(Arc::new(Mechanism(id, oid))))
                .err()
                .ok_or("mechanism accepted")?;
            assert!(
                matches!(
                    failure,
                    Failure::InvalidRegistration {
                        interface: _,
                        id: _,
                        reason: _
                    }
                ),
                "{id}: {failure}"
            );
        }
        Ok(())
    }

    /// Observers see interface names, ids and static reasons only.
    #[test]
    fn observers_receive_redacted_events() -> Result<(), Box<dyn Error>> {
        let recorder = Arc::new(Recorder::default());
        let mut registry = Registry::with_builtins(Some(K5Identity::from_bytes(
            b"secret-user@EXAMPLE.ORG\n".to_vec(),
        )));
        registry.register(Extension::LibraryObserver(Arc::<Recorder>::clone(
            &recorder,
        )))?;
        registry.register(selector("bad", Some(Selection::Cache(9))))?;
        let config = Config::parse("[plugins]\n ccselect = {\n disable = realm\n }\n")?;
        let caches = [cache("other", "ELSEWHERE.ORG")];
        let server = web("host.example.org", "EXAMPLE.ORG");
        let selected = registry.select_cache(&config, &server, &caches)?;
        assert_eq!(
            selected,
            Selection::Principal(Principal::new(
                "EXAMPLE.ORG",
                1,
                vec!["secret-user".to_owned()]
            )),
            "k5identity answered"
        );
        let events = recorder
            .events
            .lock()
            .map_err(|_poisoned| "poisoned")?
            .clone();
        let expected = [
            Event::Consulted {
                interface: Interface::CacheSelector,
                id: "k5identity",
            },
            Event::Chosen {
                interface: Interface::CacheSelector,
                id: "k5identity",
            },
        ]
        .map(|event| format!("{event:?}"));
        assert_eq!(events, expected, "event sequence");
        assert!(
            events
                .iter()
                .all(|event| !event.contains("secret") && !event.contains("EXAMPLE")),
            "{events:?}"
        );
        Ok(())
    }

    /// A host-realm mapper with a fixed answer.
    struct Realms(Option<Vec<String>>);

    impl HostRealm for Realms {
        fn id(&self) -> &'static str {
            "fixed"
        }

        fn realms(&self, _query: &RealmQuery<'_>) -> Result<Option<Vec<String>>, ProviderError> {
            Ok(self.0.clone())
        }
    }

    /// A locator with a fixed answer.
    struct Locator(Vec<ServerAddress>);

    impl ServerLocator for Locator {
        fn id(&self) -> &'static str {
            "fixed"
        }

        fn locate(
            &self,
            _request: &LocateRequest<'_>,
        ) -> Result<Option<Vec<ServerAddress>>, ProviderError> {
            Ok(Some(self.0.clone()))
        }
    }

    /// A local authorizer with a fixed decision and name.
    struct Local {
        /// Its id.
        id: &'static str,
        /// Its decision.
        decision: Decision,
        /// Its local name.
        name: Option<String>,
    }

    impl LocalAuth for Local {
        fn id(&self) -> &str {
            self.id
        }

        fn userok(
            &self,
            _principal: &Principal,
            _local_name: &str,
        ) -> Result<Decision, ProviderError> {
            Ok(self.decision)
        }

        fn local_name(&self, _principal: &Principal) -> Result<Option<String>, ProviderError> {
            Ok(self.name.clone())
        }
    }

    /// A local authorizer that always fails.
    struct Failing;

    impl LocalAuth for Failing {
        fn id(&self) -> &'static str {
            "failing"
        }

        fn userok(
            &self,
            _principal: &Principal,
            _local_name: &str,
        ) -> Result<Decision, ProviderError> {
            Err("directory unavailable".into())
        }

        fn local_name(&self, _principal: &Principal) -> Result<Option<String>, ProviderError> {
            Err("directory unavailable".into())
        }
    }

    /// A mechanism with a fixed object identifier.
    struct Mechanism(&'static str, Vec<u8>);

    impl GssMechanism for Mechanism {
        fn id(&self) -> &str {
            self.0
        }

        fn oid(&self) -> &[u8] {
            &self.1
        }
    }

    /// Client preauthentication sessions (MIT `clpreauth`).
    #[cfg(feature = "messages")]
    mod preauth {
        use core::error::Error;

        use rasn::der;
        use rasn_kerberos::{EncryptedData, PaData};
        use rskrb5_ng::{
            config::Config,
            crypto::CryptoPolicy,
            error::{Extensions as Failure, Policy},
            extensions::{
                ClientPreauth, Event, Extension, Interface, MAX_PREAUTH_ROUNDS, PreauthInput,
                PreauthState, ProviderError, Refusal, Registry,
            },
        };

        use super::{Arc, Recorder};

        /// A mechanism whose rounds answer with `answer(round, calls)`.
        struct Mechanism {
            /// Its id.
            id: &'static str,
            /// Its PA types.
            types: Vec<i32>,
            /// The PA-DATA of each answer: type and value.
            answer: Vec<(i32, Vec<u8>)>,
        }

        /// One exchange's state: how often it was asked.
        struct Calls {
            /// The answer template.
            answer: Vec<(i32, Vec<u8>)>,
            /// Calls in this exchange.
            calls: u8,
        }

        impl PreauthState for Calls {
            fn process(&mut self, input: &PreauthInput<'_>) -> Result<Vec<PaData>, ProviderError> {
                self.calls = self.calls.saturating_add(1);
                if input.pa_type == 150_i32 {
                    return Err("mechanism failed".into());
                }
                Ok(self
                    .answer
                    .iter()
                    .map(|(pa_type, value)| {
                        let mut bytes = value.clone();
                        if bytes.is_empty() {
                            bytes.push(self.calls);
                        }
                        PaData {
                            r#type: *pa_type,
                            value: bytes.into(),
                        }
                    })
                    .collect())
            }
        }

        impl ClientPreauth for Mechanism {
            fn id(&self) -> &str {
                self.id
            }

            fn pa_types(&self) -> &[i32] {
                &self.types
            }

            fn start(&self) -> Box<dyn PreauthState> {
                Box::new(Calls {
                    answer: self.answer.clone(),
                    calls: 0,
                })
            }
        }

        /// A mechanism registration.
        fn mechanism(id: &'static str, types: &[i32], answer: Vec<(i32, Vec<u8>)>) -> Extension {
            Extension::ClientPreauth(Arc::new(Mechanism {
                id,
                types: types.to_vec(),
                answer,
            }))
        }

        /// A PA-ENC-TIMESTAMP value encrypted (nominally) with `etype`.
        fn timestamp(etype: i32) -> Result<Vec<u8>, Box<dyn Error>> {
            Ok(der::encode(&EncryptedData {
                etype,
                kvno: None,
                cipher: vec![0x22; 32].into(),
            })?)
        }

        /// The QA failure scenario: PA-DATA for a D2-rejected enctype is refused.
        #[test]
        fn rejected_enctype_padata_is_refused_by_policy() -> Result<(), Box<dyn Error>> {
            let config = Config::parse("")?;
            let policy = CryptoPolicy::from_libdefaults(&config.libdefaults)?;
            for (etype, single_des) in [
                (1_i32, true),
                (3_i32, true),
                (23_i32, false),
                (16_i32, false),
            ] {
                let mut registry = Registry::new();
                registry.register(mechanism(
                    "rogue",
                    &[2_i32],
                    vec![(2_i32, timestamp(etype)?)],
                ))?;
                let mut session = registry.preauth_session(&config, &policy);
                let failure = session
                    .respond(2, &[], b"body")
                    .err()
                    .ok_or("forbidden enctype admitted")?;
                let Failure::PolicyRefused { id, source } = &failure else {
                    return Err(format!("{etype}: {failure}").into());
                };
                assert_eq!(id, "rogue", "mechanism named");
                let rejected = matches!(
                    source,
                    Policy::RejectedFeature {
                        feature: _,
                        reason: _
                    }
                );
                let not_permitted =
                    matches!(source, Policy::EnctypeNotPermitted { etype: _, usage: _ });
                assert!(
                    if single_des { rejected } else { not_permitted },
                    "{etype}: {source}"
                );
            }
            let mut registry = Registry::new();
            registry.register(mechanism("aes", &[2_i32], vec![(2_i32, timestamp(18)?)]))?;
            let mut session = registry.preauth_session(&config, &policy);
            assert_eq!(
                session.respond(2, &[], b"body")?.map(|data| data.len()),
                Some(1),
                "permitted enctype admitted"
            );
            Ok(())
        }

        /// A mechanism cannot register a D2 PA type or answer for a type it
        /// did not register, and its output is bounded.
        #[test]
        fn mechanism_bounds_and_types() -> Result<(), Box<dyn Error>> {
            let mut registry = Registry::new();
            for types in [&[14_i32][..], &[15_i32], &[], &[133_i32, 133_i32]] {
                let failure = registry
                    .register(mechanism("draft9", types, Vec::new()))
                    .err()
                    .ok_or("bad PA types registered")?;
                assert!(
                    matches!(
                        failure,
                        Failure::InvalidRegistration {
                            interface: _,
                            id: _,
                            reason: _
                        }
                    ),
                    "{types:?}: {failure}"
                );
            }
            let config = Config::parse("")?;
            let policy = CryptoPolicy::from_libdefaults(&config.libdefaults)?;
            for (answer, too_large) in [
                (vec![(1_i32, vec![0x01])], false),
                (vec![(133_i32, vec![0; 0x0001_0001])], true),
                (vec![(133_i32, vec![0x01]); 17], true),
            ] {
                let mut bounded = Registry::new();
                bounded.register(mechanism("bounded", &[133_i32], answer))?;
                let mut session = bounded.preauth_session(&config, &policy);
                let failure = session
                    .respond(133, &[], b"body")
                    .err()
                    .ok_or("unbounded output accepted")?;
                assert_eq!(
                    matches!(
                        failure,
                        Failure::OutputTooLarge {
                            interface: _,
                            id: _,
                            limit: _
                        }
                    ),
                    too_large,
                    "{failure}"
                );
                assert_eq!(
                    matches!(
                        failure,
                        Failure::MalformedOutput {
                            interface: _,
                            id: _,
                            reason: _
                        }
                    ),
                    !too_large,
                    "{failure}"
                );
            }
            let mut unsupported = Registry::new();
            unsupported.register(mechanism("fast", &[136_i32], vec![(136_i32, vec![0x01])]))?;
            let mut session = unsupported.preauth_session(&config, &policy);
            let refusal = session
                .respond(136, &[], b"body")
                .err()
                .ok_or("unsupported PA type admitted")?;
            assert!(
                matches!(
                    refusal,
                    Failure::MalformedOutput {
                        interface: _,
                        id: _,
                        reason: _
                    }
                ),
                "{refusal}"
            );
            Ok(())
        }

        /// State lives per exchange; rounds are bounded; failures are typed.
        #[test]
        fn per_exchange_state_and_round_bound() -> Result<(), Box<dyn Error>> {
            let config = Config::parse("")?;
            let policy = CryptoPolicy::from_libdefaults(&config.libdefaults)?;
            let mut registry = Registry::new();
            registry.register(mechanism(
                "cookie",
                &[133_i32, 150_i32],
                vec![(133_i32, Vec::new())],
            ))?;
            let mut first = registry.preauth_session(&config, &policy);
            let value = |data: Option<Vec<PaData>>| {
                let items = data?;
                items.first().map(|item| item.value.to_vec())
            };
            assert_eq!(
                value(first.respond(133, &[], b"")?),
                Some(vec![1]),
                "round 1"
            );
            assert_eq!(
                value(first.respond(133, &[], b"")?),
                Some(vec![2]),
                "state kept"
            );
            let mut second = registry.preauth_session(&config, &policy);
            assert_eq!(
                value(second.respond(133, &[], b"")?),
                Some(vec![1]),
                "fresh state"
            );
            assert_eq!(second.respond(2, &[], b"")?, None, "unanswered type");
            let failure = second
                .respond(150, &[], b"")
                .err()
                .ok_or("failure ignored")?;
            assert!(
                matches!(
                    failure,
                    Failure::CallFailed {
                        interface: _,
                        id: _,
                        source: _
                    }
                ),
                "{failure}"
            );
            for _ in 2..MAX_PREAUTH_ROUNDS {
                drop(second.respond(133, &[], b"")?);
            }
            let exhausted = second
                .respond(133, &[], b"")
                .err()
                .ok_or("round bound ignored")?;
            assert!(
                matches!(exhausted, Failure::TooManyRounds { limit: 16 }),
                "{exhausted}"
            );
            Ok(())
        }

        /// Order, `[plugins] clpreauth` selection and PA-type conflicts.
        #[test]
        fn session_order_selection_and_conflicts() -> Result<(), Box<dyn Error>> {
            let recorder = Arc::new(Recorder::default());
            let mut registry = Registry::new();
            registry.register(Extension::LibraryObserver(Arc::<Recorder>::clone(
                &recorder,
            )))?;
            registry.register(mechanism("first", &[133_i32], vec![(133_i32, vec![0x01])]))?;
            registry.register(mechanism(
                "second",
                &[133_i32, 149_i32],
                vec![(149_i32, vec![0x02])],
            ))?;
            registry.register(mechanism("third", &[149_i32], vec![(149_i32, vec![0x03])]))?;
            let config = Config::parse("")?;
            let policy = CryptoPolicy::from_libdefaults(&config.libdefaults)?;
            let mut session = registry.preauth_session(&config, &policy);
            let answer = session.respond(149, &[], b"")?;
            assert_eq!(
                answer.and_then(|items| items.first().map(|item| item.value.to_vec())),
                Some(vec![0x03]),
                "conflicting mechanism skipped"
            );
            let events: Vec<String> = recorder
                .events
                .lock()
                .map_err(|_poisoned| "poisoned")?
                .clone();
            assert_eq!(
                events.first(),
                Some(&format!(
                    "{:?}",
                    Event::Refused {
                        interface: Interface::ClientPreauth,
                        id: "second",
                        reason: Refusal::Conflict,
                    }
                )),
                "conflict reported"
            );
            assert!(
                events.iter().all(|event| !event.contains("0x03")),
                "{events:?}"
            );
            let selected = Config::parse(
                "[plugins]\n clpreauth = {\n disable = first\n enable_only = encrypted_timestamp\n enable_only = second\n }\n",
            )?;
            assert_eq!(
                registry.enabled(Interface::ClientPreauth, &selected),
                ["second"],
                "selection"
            );
            let mut chosen = registry.preauth_session(&selected, &policy);
            assert_eq!(
                chosen
                    .respond(149, &[], b"")?
                    .and_then(|items| items.first().map(|item| item.value.to_vec())),
                Some(vec![0x02]),
                "selected mechanism answers"
            );
            Ok(())
        }
    }
}
