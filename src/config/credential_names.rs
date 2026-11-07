//! Ambient facts for existing default-credential consumers only.

use std::env;

use super::{
    LibDefaults,
    parameters::{DefaultName, ExpansionContext, Failure},
};
use crate::file_name;

#[cfg(test)]
#[path = "credential_names_tests.rs"]
mod tests;

/// Resolve one configured credential name exactly once.
///
/// # Ambient input
/// Reads `TMPDIR` on Unix, `TEMP` and `APPDATA` on Windows, and Linux
/// procfs identities when requested. Use `parameters::expand` with an explicit
/// context, then literal-path `load`/`save`, to avoid discovery.
///
/// # Errors
/// Returns typed missing-fact, invalid-environment and template failures.
pub(crate) fn resolve_credential_template(
    defaults: &LibDefaults,
    selection: DefaultName,
) -> Result<String, Failure> {
    let template = match selection {
        DefaultName::Ccache => &defaults.default_ccache_name,
        DefaultName::Keytab => &defaults.default_keytab_name,
        DefaultName::ClientKeytab => &defaults.default_client_keytab_name,
    };
    let mut context = ExpansionContext::default();
    if template.contains("%{uid}")
        || template.contains("%{euid}")
        || (cfg!(target_os = "linux") && template.contains("%{USERID}"))
    {
        let (real, effective) = file_name::process_identity()
            .map_err(|_source| Failure::Unavailable("process identity"))?;
        #[cfg(all(test, target_os = "linux"))]
        tests::identity::DISCOVERIES.with(|count| count.set(count.get().saturating_add(1)));
        context.uid = Some(real);
        context.euid = Some(effective);
    }
    #[cfg(not(windows))]
    let temp = if template.contains("%{TEMP}") {
        match env::var("TMPDIR") {
            Ok(value) => Some(value),
            Err(env::VarError::NotPresent) => Some("/tmp".to_owned()),
            Err(env::VarError::NotUnicode(_value)) => return Err(Failure::Unavailable("TEMP")),
        }
    } else {
        None
    };
    #[cfg(windows)]
    let temp = if template.contains("%{TEMP}") {
        Some(env::var("TEMP").map_err(|_source| Failure::Unavailable("TEMP"))?)
    } else {
        None
    };
    #[cfg(windows)]
    let appdata = if template.contains("%{APPDATA}")
        || template.contains("%{USERCONFIG}")
        || template.contains("%{USERCONFIGDIR}")
    {
        Some(env::var("APPDATA").map_err(|_source| Failure::Unavailable("APPDATA"))?)
    } else {
        None
    };
    #[cfg(not(windows))]
    let appdata: Option<String> = None;
    let userconfig = appdata
        .as_ref()
        .map(|directory| format!("{directory}\\MIT\\Kerberos5"));
    context.temp = temp.as_deref();
    context.appdata = appdata.as_deref();
    context.userconfigdir = userconfig.as_deref();
    selection.expand(defaults, &context)
}
