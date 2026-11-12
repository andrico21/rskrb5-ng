//! Source-derived delegation certificates never substitute for direct-write proofs.

use std::io;

use super::replacement::Method;

pub(super) fn validate(
    method: &Method,
    methods: &[Method],
    proofs: &[(&str, &str)],
) -> Result<(), io::Error> {
    check(method, methods, proofs, &mut Vec::new())
}

fn check(
    method: &Method,
    methods: &[Method],
    proofs: &[(&str, &str)],
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
    if !method.direct.is_empty() {
        return Err(fail("direct replacement requires its own proof"));
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
        check(callee, methods, proofs, active)?;
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
        super::validate(wrapper, &methods, &proofs)?;
        assert!(super::validate(wrapper, &methods, &proofs[1..]).is_err());
        let changed = replacement::methods(
            "src/probe.rs",
            "pub struct Owner { secret: Vec<u8> }\nimpl Owner { fn write(&mut self) { self.secret.clear(); } pub fn wrap(&mut self) { self.secret = vec![]; self.write(); } }",
        )?;
        let wrapper = changed
            .iter()
            .find(|method| method.identity.ends_with("::wrap"))
            .ok_or_else(|| io::Error::other("changed wrapper"))?;
        assert!(super::validate(wrapper, &changed, &proofs).is_err());
        let changed_edge = replacement::methods(
            "src/probe.rs",
            "pub struct Owner { secret: Vec<u8> } impl Owner { fn write(&mut self) { self.secret.clear(); } fn other(&mut self) { self.secret.clear(); } pub fn wrap(&mut self) { self.other(); } }",
        )?;
        let changed_wrapper = changed_edge
            .iter()
            .find(|method| method.identity.ends_with("::wrap"))
            .ok_or_else(|| io::Error::other("changed edge wrapper"))?;
        assert!(
            super::validate(changed_wrapper, &changed_edge, &proofs)
                .err()
                .is_some()
        );
        Ok(())
    }
}
