//! The `.k5login` file contents: bounds and the exact line match.
//!
//! MIT compares each line with the unparsed principal
//! (`localauth_k5login.c:138-149`); the size, line-count and line-length bounds
//! are this crate's.

#![cfg(feature = "localauth")]

use rskrb5_ng::{
    ccache::Principal,
    localauth::{
        Authorization, authorize_local,
        k5login::{Fault, MAX_FILE_BYTES, MAX_LINE_BYTES, MAX_LINES},
    },
};

use crate::support::{
    TestError, authorizer,
    homes::{LISTED, USER, decide, home_with, refused},
    resolver,
};

/// The decision for `alice` over a `.k5login` of `content`, mode 0600.
fn decide_content(content: &[u8]) -> Result<Authorization, TestError> {
    let (home, owner) = home_with(content, 0o600)?;
    decide(owner, home.path())
}

/// The size, line count and line length bounds refuse and are inclusive.
#[test]
fn bounds_refuse_what_exceeds_them() -> Result<(), TestError> {
    let target = b"alice@KRBTEST.COM\n";
    let lines = |count: usize| [b"x\n".repeat(count), target.to_vec()].concat();
    let long = |width: usize| [vec![b'y'; width], b"\n".to_vec(), target.to_vec()].concat();
    assert_eq!(
        decide_content(&lines(MAX_LINES - 1))?,
        LISTED,
        "the last allowed line"
    );
    assert_eq!(
        decide_content(&lines(MAX_LINES))?,
        refused(Fault::TooManyLines)
    );
    assert_eq!(
        decide_content(&long(MAX_LINE_BYTES))?,
        LISTED,
        "the longest allowed line"
    );
    assert_eq!(
        decide_content(&long(MAX_LINE_BYTES + 1))?,
        refused(Fault::LineTooLong)
    );
    assert_eq!(
        decide_content(&vec![b'z'; MAX_FILE_BYTES + 1])?,
        refused(Fault::TooLarge)
    );
    Ok(())
}

/// A line is the whole principal name: no trimming, no case folding, no
/// carriage return, a final line without newline counts, `\` escapes as
/// in `krb5_unparse_name`.
#[test]
fn line_match_is_exact() -> Result<(), TestError> {
    let listed =
        |content: &[u8]| -> Result<bool, TestError> { Ok(decide_content(content)? == LISTED) };
    assert!(listed(b"alice@KRBTEST.COM")?, "no final newline");
    assert!(!listed(b" alice@KRBTEST.COM\n")?, "leading space");
    assert!(!listed(b"alice@KRBTEST.COM \n")?, "trailing space");
    assert!(!listed(b"alice@KRBTEST.COM\r\n")?, "carriage return");
    assert!(!listed(b"Alice@KRBTEST.COM\n")?, "case");
    assert!(!listed(b"alice@krbtest.com\n")?, "realm case");
    assert!(!listed(b"alice\n")?, "no realm");
    assert!(!listed(b"alice@KRBTEST.COM/x\n")?, "suffix");
    assert!(!listed(b"# alice@KRBTEST.COM\n")?, "comment");
    let escaped = Principal::new("KRBTEST.COM", 1, vec!["a/b".to_owned(), "c@d".to_owned()]);
    let (home, owner) = home_with(b"a\\/b/c\\@d@KRBTEST.COM\n", 0o600)?;
    let authorizer = authorizer("", resolver(USER, owner, home.path()))?;
    assert_eq!(authorize_local(&authorizer, &escaped, USER), LISTED);
    Ok(())
}
