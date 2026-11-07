//! Ambient identity selection contracts without environment mutation.

#[cfg(test)]
#[cfg(target_os = "linux")]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
pub(super) mod identity {
    #[cfg(target_os = "linux")]
    use core::{cell::Cell, error::Error};

    #[cfg(target_os = "linux")]
    use crate::{
        config::{LibDefaults, parameters::DefaultName},
        file_name,
    };

    std::thread_local! {
        /// Completed ambient process-identity discoveries on this test thread.
        pub(in crate::configuration::credential_names) static DISCOVERIES: Cell<usize> = const { Cell::new(0) };
    }

    /// Each numeric token independently triggers process identity discovery.
    #[cfg(target_os = "linux")]
    #[test]
    fn individual_identity_tokens_resolve_process_ids() -> Result<(), Box<dyn Error>> {
        let (real, effective) =
            file_name::process_identity().map_err(|_error| "process identity unavailable")?;
        for (token, expected) in [("uid", real), ("euid", effective), ("USERID", real)] {
            let defaults =
                LibDefaults::new().with_default_ccache_name(format!("FILE:%{{{token}}}"));
            assert_eq!(
                super::super::resolve_credential_template(&defaults, DefaultName::Ccache)?,
                format!("FILE:{expected}")
            );
        }
        Ok(())
    }

    /// Literal credential names never trigger ambient identity discovery.
    #[test]
    fn literal_template_does_not_discover_identity() -> Result<(), Box<dyn Error>> {
        let defaults = LibDefaults::new().with_default_ccache_name("FILE:/explicit".to_owned());
        DISCOVERIES.set(0);
        let name = super::super::resolve_credential_template(&defaults, DefaultName::Ccache)?;
        assert_eq!(name, "FILE:/explicit");
        assert_eq!(DISCOVERIES.get(), 0);
        Ok(())
    }
}
