use crate::error::RejectedFeature;

/// Internal checked expression operations shared by parsing and runtime policy.
pub(crate) trait EnctypeDefaults {
    /// Resolve final profile lists or return a named expression error.
    /// # Errors
    /// Rejects invalid expressions or out-of-policy explicit requests.
    fn validate_explicit_enctypes(&mut self, enctypes: EnctypeParseState) -> Result<(), Error>;
    /// Reject blanket weakening with a typed policy error.
    /// # Errors
    /// Rejects enabled weak crypto.
    fn reject_weak_crypto(&self) -> Result<(), Error>;
    /// Resolve names or return a named expression error.
    /// # Errors
    /// Rejects invalid, disabled or forbidden selections and empty results.
    fn resolve_names(&self, names: &[String]) -> Result<ResolvedEnctypes, Error>;
    /// Validate staged request names against the effective permissions.
    /// # Errors
    /// Returns named expression or request-membership errors without narrowing.
    fn validate_request_enctypes(&self, permitted: &ResolvedEnctypes) -> Result<(), Error>;
    /// Legacy accessor returns no usable IDs for invalid public mutation.
    fn effective_enctype_ids(&self, names: &[String]) -> Vec<i32>;
}

impl EnctypeDefaults for LibDefaults {
    /// Resolve all three relations after the final family permissions are known.
    ///
    /// # Errors
    /// Rejects forbidden, disabled, unknown, empty or explicitly out-of-policy lists.
    fn validate_explicit_enctypes(&mut self, enctypes: EnctypeParseState) -> Result<(), Error> {
        self.reject_weak_crypto()?;
        for expression in &enctypes.expressions {
            drop(expression.resolve(self.allow_rc4, self.allow_des3, self.enctype_parse_mode)?);
        }
        let permitted = self.resolve_names(&self.permitted_enctypes)?;
        let ticket = if enctypes.tkt_explicit {
            self.resolve_names(&self.default_tkt_enctypes)?
        } else {
            permitted.clone()
        };
        let service = if enctypes.tgs_explicit {
            self.resolve_names(&self.default_tgs_enctypes)?
        } else {
            permitted.clone()
        };
        for (explicit, key, resolved) in [
            (enctypes.tkt_explicit, "default_tkt_enctypes", &ticket),
            (enctypes.tgs_explicit, "default_tgs_enctypes", &service),
        ] {
            if explicit && self.permitted_enctypes_explicit.is_enabled() {
                for &etype in resolved.enctypes() {
                    if !permitted.enctypes().contains(&etype) {
                        return Err(Error::EnctypeNotPermitted {
                            key,
                            enctype: enctype_names::canonical_name(etype).to_owned(),
                        });
                    }
                }
            }
        }
        self.enctype_diagnostics = permitted.diagnostics().to_vec();
        protocol::preferences(
            &mut self.preferred_preauth_types,
            &mut self.enctype_diagnostics,
        );
        if enctypes.tkt_explicit {
            self.enctype_diagnostics
                .extend_from_slice(ticket.diagnostics());
        }
        if enctypes.tgs_explicit {
            self.enctype_diagnostics
                .extend_from_slice(service.diagnostics());
        }
        self.permitted_enctypes = permitted
            .enctypes()
            .iter()
            .map(|&etype| enctype_names::canonical_name(etype).to_owned())
            .collect();
        self.default_tkt_enctypes = ticket
            .enctypes()
            .iter()
            .map(|&etype| enctype_names::canonical_name(etype).to_owned())
            .collect();
        self.default_tgs_enctypes = service
            .enctypes()
            .iter()
            .map(|&etype| enctype_names::canonical_name(etype).to_owned())
            .collect();
        Ok(())
    }

    /// Reject blanket weakening even for programmatically modified defaults.
    ///
    /// # Errors
    /// Returns the permanent weak-crypto policy rejection if enabled.
    fn reject_weak_crypto(&self) -> Result<(), Error> {
        if self.allow_weak_crypto.is_enabled() {
            return Err(Policy::RejectedFeature {
                feature: RejectedFeature::WeakCrypto,
                reason: RejectionReason::InsecureByDesign,
            }
            .into());
        }
        Ok(())
    }

    /// Resolve names without silently dropping forbidden entries.
    ///
    /// # Errors
    /// Returns expression errors under the current mode and legacy permissions.
    fn resolve_names(&self, names: &[String]) -> Result<ResolvedEnctypes, Error> {
        self.reject_weak_crypto()?;
        EnctypeExpr::parse(&names.join(" "))?.resolve(
            self.allow_rc4,
            self.allow_des3,
            self.enctype_parse_mode,
        )
    }

    /// Legacy infallible accessors fail closed as an empty list on invalid mutation.
    /// Checked callers use `CryptoPolicy::from_libdefaults` for the typed cause.
    fn effective_enctype_ids(&self, names: &[String]) -> Vec<i32> {
        self.resolve_names(names).map_or_else(
            |_| Vec::new(),
            |resolved| {
                resolved
                    .enctypes()
                    .iter()
                    .copied()
                    .map(KerberosEtype::etype_id)
                    .collect()
            },
        )
    }

    fn validate_request_enctypes(&self, permitted: &ResolvedEnctypes) -> Result<(), Error> {
        let ticket = self.resolve_names(&self.default_tkt_enctypes)?;
        let service = self.resolve_names(&self.default_tgs_enctypes)?;
        for (key, requested) in [
            ("default_tkt_enctypes", ticket),
            ("default_tgs_enctypes", service),
        ] {
            for &etype in requested.enctypes() {
                if !permitted.enctypes().contains(&etype) {
                    return Err(Error::EnctypeNotPermitted {
                        key,
                        enctype: enctype_names::canonical_name(etype).to_owned(),
                    });
                }
            }
        }
        Ok(())
    }
}
