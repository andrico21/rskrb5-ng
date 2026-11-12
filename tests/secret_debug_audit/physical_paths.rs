//! Physical graph path regressions at the credential inventory boundary.

use std::{env, fs, io, process};

use crate::inventory;

/// Parent traversal must preserve private credential classification across physical files.
#[test]
fn repeated_super_paths_preserve_private_storage() -> Result<(), io::Error> {
    let root = env::temp_dir().join(format!("rskrb5-t66-paths-{}", process::id()));
    fs::create_dir_all(root.join("outer"))?;
    let result = (|| {
        fs::write(root.join("lib.rs"), "mod hidden; mod outer;")?;
        fs::write(root.join("outer.rs"), "mod inner;")?;
        fs::write(
            root.join("hidden.rs"),
            "#[derive(Debug)]\npub(crate) struct Hidden { password: Vec<u8> }",
        )?;
        for source in [
            "#[derive(Debug)] pub struct Outer { value: super::super::hidden::Hidden }",
            "use super::super::hidden::Hidden as Storage; #[derive(Debug)] pub struct Outer { value: Storage }",
            "type Storage = super::super::hidden::Hidden; #[derive(Debug)] pub struct Outer { value: Storage }",
            "use crate::hidden::Hidden as Storage; #[derive(Debug)] pub struct Outer { value: Storage }",
            "pub struct Outer { value: super::super::missing::Hidden }",
            "pub struct Outer { value: super::super::super::hidden::Hidden }",
        ] {
            fs::write(root.join("outer/inner.rs"), source)?;
            let observed = inventory::inspect(&root, &root);
            assert!(
                observed.is_err(),
                "local path lost private storage: {source}: {observed:?}"
            );
            let error = observed
                .err()
                .ok_or_else(|| io::Error::other("private storage admitted"))?;
            assert!(error.to_string().contains(".rs:"), "{error}");
        }
        fs::write(
            root.join("hidden.rs"),
            "#[derive(Debug)] pub(crate) struct Hidden { count: u32 }",
        )?;
        for source in [
            "#[derive(Debug)] pub struct Outer { value: super::super::hidden::Hidden }",
            "use super::super::hidden::Hidden as Storage; #[derive(Debug)] pub struct Outer { value: Storage }",
        ] {
            fs::write(root.join("outer/inner.rs"), source)?;
            let owners = inventory::inspect(&root, &root)?;
            assert_eq!(inventory::secret_owners(&owners), Vec::<String>::new());
        }
        Ok(())
    })();
    fs::remove_dir_all(&root)?;
    result
}
