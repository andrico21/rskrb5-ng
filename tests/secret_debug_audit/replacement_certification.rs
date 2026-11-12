//! Source-derived delegation certificates never substitute for direct-write proofs.

use std::io;

use super::replacement::Method;

/// Classifies one owner field as credential storage; other writes need no proof.
pub(super) type Secret<'secret> = &'secret dyn Fn(&Method, &str) -> bool;

pub(super) fn validate(
    method: &Method,
    methods: &[Method],
    proofs: &[(&str, &str)],
    secret: Secret<'_>,
) -> Result<(), io::Error> {
    check(method, methods, proofs, secret, &mut Vec::new())
}

fn check(
    method: &Method,
    methods: &[Method],
    proofs: &[(&str, &str)],
    secret: Secret<'_>,
    active: &mut Vec<String>,
) -> Result<(), io::Error> {
    let fail = |reason: &str| {
        io::Error::other(format!(
            "{}: {}: {reason}",
            method.location, method.identity
        ))
    };
    if active.contains(&method.identity) || active.len() > 4 {
        return Err(fail("cyclic or excessive certification inheritance"));
    }
    let entries = proofs
        .iter()
        .filter(|(identity, _)| *identity == method.identity)
        .collect::<Vec<_>>();
    if entries.is_empty() {
        return Err(fail("missing replacement proof"));
    }
    if entries
        .iter()
        .any(|(_, proof)| !proof.starts_with("delegates:"))
    {
        return Ok(());
    }
    let direct = method
        .direct
        .iter()
        .filter(|field| secret(method, field))
        .cloned()
        .collect::<Vec<_>>();
    if !direct.is_empty() {
        return Err(fail(&format!(
            "direct replacement of {} requires its own proof",
            direct.join(", ")
        )));
    }
    let expected = entries
        .iter()
        .filter_map(|(_, proof)| proof.strip_prefix("delegates:"))
        .collect::<Vec<_>>();
    let actual = method
        .delegates
        .iter()
        .filter_map(|(identity, _)| {
            methods
                .iter()
                .find(|candidate| candidate.identity == *identity)
        })
        .filter(|callee| !callee.fields.is_empty())
        .collect::<Vec<_>>();
    if method
        .delegates
        .iter()
        .any(|(identity, _)| !methods.iter().any(|callee| callee.identity == *identity))
        || actual.is_empty()
        || expected.len() != actual.len()
        || actual
            .iter()
            .any(|callee| !expected.contains(&callee.identity.as_str()))
    {
        return Err(fail("delegation certificate does not match source edges"));
    }
    active.push(method.identity.clone());
    for callee in actual {
        check(callee, methods, proofs, secret, active)?;
    }
    drop(active.pop());
    Ok(())
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use std::io;

    use super::super::replacement;

    fn secret(_: &replacement::Method, field: &str) -> bool {
        field == "secret"
    }

    /// Only a resolved, unchanged wrapper can inherit a registered callee's proof.
    #[test]
    fn delegation_certification_is_source_bound() -> Result<(), io::Error> {
        let methods = replacement::methods(
            "src/probe.rs",
            "pub struct Owner { secret: Vec<u8> }\nimpl Owner { fn write(&mut self) { self.secret.clear(); } pub fn wrap(&mut self) { let this = self; this.write(); } }",
        )?;
        let wrapper = methods
            .iter()
            .find(|method| method.identity.ends_with("::wrap"))
            .ok_or_else(|| io::Error::other("wrapper"))?;
        let proofs = [
            ("src/probe.rs::Owner::write", "functional_test"),
            (
                "src/probe.rs::Owner::wrap",
                "delegates:src/probe.rs::Owner::write",
            ),
        ];
        super::validate(wrapper, &methods, &proofs, &secret)?;
        assert!(super::validate(wrapper, &methods, &proofs[1..], &secret).is_err());
        let changed = replacement::methods(
            "src/probe.rs",
            "pub struct Owner { secret: Vec<u8> }\nimpl Owner { fn write(&mut self) { self.secret.clear(); } pub fn wrap(&mut self) { self.secret = vec![]; self.write(); } }",
        )?;
        let wrapper = changed
            .iter()
            .find(|method| method.identity.ends_with("::wrap"))
            .ok_or_else(|| io::Error::other("changed wrapper"))?;
        assert!(super::validate(wrapper, &changed, &proofs, &secret).is_err());
        let changed_edge = replacement::methods(
            "src/probe.rs",
            "pub struct Owner { secret: Vec<u8> } impl Owner { fn write(&mut self) { self.secret.clear(); } fn other(&mut self) { self.secret.clear(); } pub fn wrap(&mut self) { self.other(); } }",
        )?;
        let changed_wrapper = changed_edge
            .iter()
            .find(|method| method.identity.ends_with("::wrap"))
            .ok_or_else(|| io::Error::other("changed edge wrapper"))?;
        assert!(
            super::validate(changed_wrapper, &changed_edge, &proofs, &secret)
                .err()
                .is_some()
        );
        let local = replacement::methods(
            "src/probe.rs",
            "pub struct Owner { secret: Vec<u8>, counter: u8 }\nimpl Owner { fn write(&mut self) { self.secret.clear(); } pub fn wrap(&mut self) { self.counter = 1; self.write(); } }",
        )?;
        let counted = local
            .iter()
            .find(|method| method.identity.ends_with("::wrap"))
            .ok_or_else(|| io::Error::other("counter wrapper"))?;
        super::validate(counted, &local, &proofs, &secret)?;
        Ok(())
    }
}
