//! Resolve receiver calls by complete owner identity, never by method spelling alone.

use std::io;

use super::Method;

/// Public roots and the private methods they reach share one source-derived graph.
pub(super) fn resolve(mut methods: Vec<Method>) -> Result<Vec<Method>, io::Error> {
    let mut reachable = Vec::new();
    for method in methods.iter().filter(|method| method.public) {
        drop(fields(method, &methods, &mut Vec::new(), &mut reachable)?);
    }
    let propagated = methods
        .iter()
        .map(|method| {
            if reachable.contains(&method.identity) {
                fields(method, &methods, &mut Vec::new(), &mut Vec::new())
            } else {
                Ok(Vec::new())
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    for (method, fields) in methods.iter_mut().zip(propagated) {
        method.fields = fields;
    }
    methods.retain(|method| reachable.contains(&method.identity));
    Ok(methods)
}

/// Bound recursive source analysis and reject every unresolved edge at its call site.
fn fields(
    method: &Method,
    methods: &[Method],
    active: &mut Vec<String>,
    reachable: &mut Vec<String>,
) -> Result<Vec<String>, io::Error> {
    if let Some(span) = method.opaque {
        return Err(io::Error::other(format!(
            "{}:{}: opaque replacement or receiver escape",
            method
                .location
                .rsplit_once(':')
                .map_or(method.location.as_str(), |(file, _)| file),
            span.start().line
        )));
    }
    if active.contains(&method.identity) || active.len() > 32 {
        return Err(io::Error::other(format!(
            "{}: cyclic or excessive receiver delegation",
            method.location
        )));
    }
    active.push(method.identity.clone());
    reachable.push(method.identity.clone());
    let mut result = method.direct.clone();
    for (identity, span) in &method.delegates {
        let candidates = methods
            .iter()
            .filter(|candidate| candidate.identity == *identity)
            .collect::<Vec<_>>();
        let [target] = candidates.as_slice() else {
            return Err(io::Error::other(format!(
                "{}:{}: unresolved receiver delegation {identity}",
                method
                    .location
                    .rsplit_once(':')
                    .map_or(method.location.as_str(), |(file, _)| file),
                span.start().line
            )));
        };
        result.extend(fields(target, methods, active, reachable)?);
    }
    drop(active.pop());
    result.sort();
    result.dedup();
    Ok(result)
}
