//! MIT replay-cache names.

use std::path::PathBuf;

use rskrb5_ng::{
    error::Replay as Error,
    replay::{Admission, RcacheName},
};

use crate::context::TestError;
use super::{
    support::{TempDir, evidence},
};

/// Pins the accepted name forms and the refusals MIT's `k5_rc_resolve` has.
#[test]
fn names_parse_like_mit() -> Result<(), TestError> {
    assert_eq!(RcacheName::parse("dfl:")?, RcacheName::Dfl);
    assert_eq!(RcacheName::parse("dfl:ignored")?, RcacheName::Dfl);
    assert_eq!(RcacheName::parse("none:")?, RcacheName::None);
    assert_eq!(RcacheName::parse("memory:")?, RcacheName::Memory);
    assert_eq!(
        RcacheName::parse("file2:/var/tmp/x.rcache")?,
        RcacheName::File2 {
            path: PathBuf::from("/var/tmp/x.rcache")
        }
    );
    assert_eq!(
        RcacheName::parse("file2:C:\\cache")?,
        RcacheName::File2 {
            path: PathBuf::from("C:\\cache")
        }
    );
    assert!(matches!(RcacheName::parse("/var/tmp/x"), Err(Error::InvalidName)));
    assert!(matches!(RcacheName::parse("file2:"), Err(Error::EmptyPath)));
    assert!(matches!(
        RcacheName::parse("DFL:"),
        Err(Error::UnsupportedType { name_type }) if name_type == "DFL"
    ));
    assert!(matches!(
        RcacheName::parse("file:/x"),
        Err(Error::UnsupportedType { name_type }) if name_type == "file"
    ));
    Ok(())
}

/// Pins that `none:` admits everything, `memory:` and `file2:` stop a replay, and each name opens its store.
#[test]
fn a_name_opens_the_store_it_names() -> Result<(), TestError> {
    let directory = TempDir::new("names")?;
    let path = directory.path().join("named.rcache2");
    let file_name = format!("file2:{}", path.display());
    let candidate = evidence(5, 1_000_000)?;

    let none = RcacheName::parse("none:")?.open()?;
    assert_eq!(none.admit(&candidate)?, Admission::Fresh);
    assert_eq!(none.admit(&candidate)?, Admission::Fresh);
    let memory = RcacheName::parse("memory:")?.open()?;
    assert_eq!(memory.admit(&candidate)?, Admission::Fresh);
    assert_eq!(memory.admit(&candidate)?, Admission::Replayed);
    let file = RcacheName::parse(&file_name)?.open()?;
    assert_eq!(file.admit(&candidate)?, Admission::Fresh);
    assert_eq!(RcacheName::parse(&file_name)?.open()?.admit(&candidate)?, Admission::Replayed);
    Ok(())
}
