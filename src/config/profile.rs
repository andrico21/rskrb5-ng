//! Ordered profile storage, independent of typed relation consumers.

use alloc::collections::{BTreeMap, BTreeSet};
use core::slice;

use super::{Config, EnctypeDefaults as _, EnctypeParseState, Error, Line, ParseMode, Realm};

/// A section/subsection path followed by its relation name.
type Key = Vec<String>;

/// Relations in source order and scopes closed against later contributions.
#[derive(Default)]
pub(super) struct Profile {
    /// Ordered values; scalar consumers select the first element.
    values: BTreeMap<Key, Vec<Line>>,
    /// Final relation or subsection paths.
    finals: BTreeSet<Key>,
    /// Realm names in first appearance order, including empty realms.
    realms: Vec<String>,
    /// Section headers, including empty sections.
    sections: BTreeSet<String>,
    /// All admitted subsection paths, including empty ones.
    scopes: BTreeSet<Key>,
}

impl Profile {
    /// Whether a path has already been finalized.
    pub(super) fn closed(&self, path: &[String]) -> bool {
        self.finals.iter().any(|key| path.starts_with(key))
    }

    /// Check a child without rejecting the active block's own final marker.
    pub(super) fn child_closed(&self, path: &[String]) -> bool {
        self.finals.contains(path)
    }

    /// Close a scope after its defining block is complete.
    pub(super) fn finalize(&mut self, path: Key) {
        let _: bool = self.finals.insert(path);
    }

    /// Preserve realm appearance independently of relation sorting.
    pub(super) fn scope(&mut self, path: &[String]) {
        let _: bool = self.scopes.insert(path.to_vec());
        if let [section] = path {
            let _: bool = self.sections.insert(section.clone());
        }
        if let [section, realm] = path
            && section == "realms"
            && !self.realms.contains(realm)
        {
            self.realms.push(realm.clone());
        }
    }

    /// Append a relation; scalar selection happens only at the typed boundary.
    pub(super) fn relation(&mut self, path: Key, line: Line) {
        self.values.entry(path).or_default().push(line);
    }

    /// Decode supported relations without flattening nested profile paths.
    ///
    /// # Errors
    /// Returns typed value and encryption-policy errors from the selected relations.
    pub(super) fn finish(self, mode: ParseMode) -> Result<Config, Error> {
        let mut config = Config::new();
        config.libdefaults.enctype_parse_mode = mode;
        let mut enctypes = EnctypeParseState::default();
        for (path, values) in &self.values {
            if let [section, key] = path.as_slice()
                && let Some(first) = values.first()
            {
                match section.as_str() {
                    "libdefaults" => config
                        .libdefaults
                        .parse_lines(slice::from_ref(first), &mut enctypes)?,
                    "domain_realm" => {
                        let (_, value) = super::parse_assignment(first, "domain_realm")?;
                        drop(config.domain_realm.insert(key.clone(), value.to_owned()));
                    }
                    _ => {}
                }
            }
        }
        for name in &self.realms {
            let mut lines = Vec::new();
            for (path, values) in &self.values {
                if let [section, realm, key] = path.as_slice()
                    && section == "realms"
                    && realm == name
                {
                    if matches!(
                        key.as_str(),
                        "kdc" | "admin_server" | "kpasswd_server" | "master_kdc" | "primary_kdc"
                    ) {
                        lines.extend_from_slice(values);
                    } else {
                        lines.extend(values.first().cloned());
                    }
                }
            }
            config.realms.push(Realm::parse(name, &lines)?);
        }
        config.libdefaults.validate_explicit_enctypes(enctypes)?;
        if mode == ParseMode::Strict
            && let Some(diagnostic) = config.diagnostics().first()
        {
            return Err(diagnostic.clone().into_error());
        }
        let selected = self
            .values
            .keys()
            .filter_map(|path| match path.as_slice() {
                [section, key] if section == "libdefaults" => Some(key.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        super::libdefaults::classify(&mut config.libdefaults, &selected)?;
        super::section_decode::realms(&mut config, &self.values)?;
        super::section_decode::finish(&mut config, &self.values)?;
        for section in ["kdcdefaults", "dbmodules", "logging"] {
            if self.sections.contains(section) {
                super::section_decode::server(section, &mut config)?;
            }
        }
        super::unknown::report(&mut config, &self.sections, &self.values)?;
        super::unknown::empty_scopes(&mut config, &self.scopes)?;
        super::restrictions::config(&config)?;
        Ok(config)
    }
}
