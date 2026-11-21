//! Realm paths.
//!
//! MIT 1.22.2 `src/lib/krb5/krb/walktree-tests` (sha256
//! d629bd41d595251ffe87531a97acb98e0acccd006291d89891ffa072ec36864c) with the
//! `[capaths]` of `src/lib/krb5/krb/t_krb5.conf:30-45`, the client path of
//! `walk_rtree.c:93-142` and the bounds of this crate.

use core::fmt::Write as _;

use rskrb5_ng::{config::Config, error::Routing, routing::RealmPath};

use crate::TestError;

/// The `[capaths]` of MIT's `t_krb5.conf:37-45` (the domain-style entries).
const MIT_CAPATHS: &str = "[capaths]
 ATHENA.MIT.EDU = {
  KERBEROS.COM = .
 }
 LCS.MIT.EDU = {
  KERBEROS.COM = ATHENA.MIT.EDU
  ATHENA.MIT.EDU = .
  KABLOOEY.KERBEROS.COM = ATHENA.MIT.EDU
  KABLOOEY.KERBEROS.COM = KERBEROS.COM
 }
";

/// `walktree-tests:14-70` and `:74-78`: client, server and the expected realm
/// path (the realms of the TGS principals `t_walk_rtree` prints, in order).
const WALKS: [(&str, &str, &[&str]); 20] = [
    (
        "ATHENA.MIT.EDU",
        "HACK.EXAMPLE.COM",
        &[
            "ATHENA.MIT.EDU",
            "MIT.EDU",
            "EDU",
            "COM",
            "EXAMPLE.COM",
            "HACK.EXAMPLE.COM",
        ],
    ),
    (
        "ATHENA.MIT.EDU",
        "CSAIL.MIT.EDU",
        &["ATHENA.MIT.EDU", "MIT.EDU", "CSAIL.MIT.EDU"],
    ),
    (
        "FOO.EXAMPLE.COM",
        "BAR.EXAMPLE.COM",
        &["FOO.EXAMPLE.COM", "EXAMPLE.COM", "BAR.EXAMPLE.COM"],
    ),
    (
        "FOZ.EXAMPLE.COM",
        "BAZ.EXAMPLE.COM",
        &["FOZ.EXAMPLE.COM", "EXAMPLE.COM", "BAZ.EXAMPLE.COM"],
    ),
    (
        "FOZ.EXAMPLE.COM",
        "BOZ.EXAMPLE.COM",
        &["FOZ.EXAMPLE.COM", "EXAMPLE.COM", "BOZ.EXAMPLE.COM"],
    ),
    (
        "FOZ.EXAMPLE.COM",
        "OZ.EXAMPLE.COM",
        &["FOZ.EXAMPLE.COM", "EXAMPLE.COM", "OZ.EXAMPLE.COM"],
    ),
    (
        "OZ.EXAMPLE.COM",
        "FOZ.EXAMPLE.COM",
        &["OZ.EXAMPLE.COM", "EXAMPLE.COM", "FOZ.EXAMPLE.COM"],
    ),
    (
        "A.FOZ.EXAMPLE.COM",
        "A.OZ.EXAMPLE.COM",
        &[
            "A.FOZ.EXAMPLE.COM",
            "FOZ.EXAMPLE.COM",
            "EXAMPLE.COM",
            "OZ.EXAMPLE.COM",
            "A.OZ.EXAMPLE.COM",
        ],
    ),
    (
        "A.OZ.EXAMPLE.COM",
        "A.FOZ.EXAMPLE.COM",
        &[
            "A.OZ.EXAMPLE.COM",
            "OZ.EXAMPLE.COM",
            "EXAMPLE.COM",
            "FOZ.EXAMPLE.COM",
            "A.FOZ.EXAMPLE.COM",
        ],
    ),
    (
        "A.FOZ.EXAMPLE.COM",
        "A.BOZ.EXAMPLE.COM",
        &[
            "A.FOZ.EXAMPLE.COM",
            "FOZ.EXAMPLE.COM",
            "EXAMPLE.COM",
            "BOZ.EXAMPLE.COM",
            "A.BOZ.EXAMPLE.COM",
        ],
    ),
    (
        "A.BOZ.EXAMPLE.COM",
        "A.FOZ.EXAMPLE.COM",
        &[
            "A.BOZ.EXAMPLE.COM",
            "BOZ.EXAMPLE.COM",
            "EXAMPLE.COM",
            "FOZ.EXAMPLE.COM",
            "A.FOZ.EXAMPLE.COM",
        ],
    ),
    (
        "A.FOZ.EXAMPLE.COM",
        "OZ.EXAMPLE.COM",
        &[
            "A.FOZ.EXAMPLE.COM",
            "FOZ.EXAMPLE.COM",
            "EXAMPLE.COM",
            "OZ.EXAMPLE.COM",
        ],
    ),
    (
        "OZ.EXAMPLE.COM",
        "A.FOZ.EXAMPLE.COM",
        &[
            "OZ.EXAMPLE.COM",
            "EXAMPLE.COM",
            "FOZ.EXAMPLE.COM",
            "A.FOZ.EXAMPLE.COM",
        ],
    ),
    ("A.B", "B.B", &["A.B", "B", "B.B"]),
    ("AB.B", "B.B", &["AB.B", "B", "B.B"]),
    ("A.B", "BA.B", &["A.B", "B", "BA.B"]),
    (
        "EXAMPLE.COM",
        "A.EXAMPLE.COM",
        &["EXAMPLE.COM", "A.EXAMPLE.COM"],
    ),
    (
        "A.EXAMPLE.COM",
        "EXAMPLE.COM",
        &["A.EXAMPLE.COM", "EXAMPLE.COM"],
    ),
    (
        "ATHENA.MIT.EDU",
        "KERBEROS.COM",
        &["ATHENA.MIT.EDU", "KERBEROS.COM"],
    ),
    (
        "LCS.MIT.EDU",
        "KABLOOEY.KERBEROS.COM",
        &[
            "LCS.MIT.EDU",
            "ATHENA.MIT.EDU",
            "KERBEROS.COM",
            "KABLOOEY.KERBEROS.COM",
        ],
    ),
];

/// Every `walktree-tests` vector gives MIT's path.
///
/// The `[capaths]` entry of the pair when one exists, the hierarchical walk
/// otherwise (`walk_rtree.c:65-91`).
#[test]
fn walks_match_the_mit_vectors() -> Result<(), TestError> {
    // Given MIT's test profile.
    let config = Config::parse(MIT_CAPATHS)?;
    for (client, server, expected) in WALKS {
        // When the path between the two realms is walked.
        let path = RealmPath::walk(&config, client, server)?;
        // Then it lists MIT's realms in MIT's order.
        assert_eq!(path.realms(), expected, "{client} -> {server}");
    }
    Ok(())
}

/// A realm has no cross-realm path to itself, and an empty realm has none.
///
/// `walktree-tests:54` (MIT `KRB5_NO_TKT_IN_RLM`, `walk_rtree.c:78-79`).
#[test]
fn same_or_empty_realm_has_no_path() -> Result<(), TestError> {
    // Given a profile without `[capaths]`.
    let config = Config::parse("")?;
    // When a path to the same realm or from an empty realm is walked.
    let same = RealmPath::walk(&config, "EXAMPLE.COM", "EXAMPLE.COM");
    let empty = RealmPath::walk(&config, "", "EXAMPLE.COM");
    // Then both are refused by name.
    assert!(matches!(same, Err(Routing::SameRealm)), "{same:?}");
    assert!(matches!(empty, Err(Routing::EmptyRealm)), "{empty:?}");
    Ok(())
}

/// The client path is the `[capaths]` entry, else the direct path.
///
/// It never falls back to the hierarchy (`k5_client_realm_path`,
/// `walk_rtree.c:93-142`).
#[test]
fn client_path_is_capaths_or_direct() -> Result<(), TestError> {
    // Given MIT's test profile.
    let config = Config::parse(MIT_CAPATHS)?;
    // When client paths are built for a configured and an unconfigured pair.
    let configured = RealmPath::client(&config, "LCS.MIT.EDU", "KABLOOEY.KERBEROS.COM")?;
    let direct = RealmPath::client(&config, "ATHENA.MIT.EDU", "HACK.EXAMPLE.COM")?;
    let explicit_direct = RealmPath::client(&config, "LCS.MIT.EDU", "ATHENA.MIT.EDU")?;
    // Then the configured one has its intermediates and the others have none.
    assert_eq!(
        configured.realms(),
        [
            "LCS.MIT.EDU",
            "ATHENA.MIT.EDU",
            "KERBEROS.COM",
            "KABLOOEY.KERBEROS.COM"
        ]
    );
    assert_eq!(direct.realms(), ["ATHENA.MIT.EDU", "HACK.EXAMPLE.COM"]);
    assert_eq!(explicit_direct.realms(), ["LCS.MIT.EDU", "ATHENA.MIT.EDU"]);
    Ok(())
}

/// A configured path that loops is refused.
///
/// A path that repeats a realm or names an endpoint as an intermediate (stricter
/// than MIT, which builds it).
#[test]
fn looping_capaths_are_refused() -> Result<(), TestError> {
    for (route, looped) in [
        ("B.TEST = M.TEST\n  B.TEST = M.TEST", "M.TEST"),
        ("B.TEST = A.TEST", "A.TEST"),
        ("B.TEST = B.TEST", "B.TEST"),
    ] {
        // Given a `[capaths]` entry whose route loops.
        let config = Config::parse(&format!("[capaths]\n A.TEST = {{\n  {route}\n }}\n"))?;
        // When the path is walked for the client and for the acceptor.
        for result in [
            RealmPath::walk(&config, "A.TEST", "B.TEST"),
            RealmPath::client(&config, "A.TEST", "B.TEST"),
        ] {
            // Then the loop is named.
            assert!(
                matches!(&result, Err(Routing::PathLoop { realm }) if realm == looped),
                "{route}: {result:?}"
            );
        }
    }
    Ok(())
}

/// A configured path longer than the bound is refused before it is used.
#[test]
fn overlong_capaths_are_refused() -> Result<(), TestError> {
    // Given a route through more intermediates than the bound allows.
    let mut hops = String::new();
    for index in 0..RealmPath::MAX_REALMS {
        writeln!(hops, "  B.TEST = HOP{index}.TEST")?;
    }
    let config = Config::parse(&format!("[capaths]\n A.TEST = {{\n{hops} }}\n"))?;
    // When the path is walked.
    let result = RealmPath::walk(&config, "A.TEST", "B.TEST");
    // Then the bound is named.
    assert!(
        matches!(result, Err(Routing::PathTooLong { max }) if max == RealmPath::MAX_REALMS),
        "{result:?}"
    );
    Ok(())
}

/// A transited realm off the path fails the acceptor check.
///
/// `chk_trans.c:293-306,353`: every transited realm must be a realm of the path
/// other than the server realm.
#[test]
fn transited_realms_must_lie_on_the_path() -> Result<(), TestError> {
    // Given the configured path LCS -> ATHENA -> KERBEROS -> KABLOOEY.
    let config = Config::parse(MIT_CAPATHS)?;
    let path = RealmPath::walk(&config, "LCS.MIT.EDU", "KABLOOEY.KERBEROS.COM")?;
    let owned = |names: &[&str]| {
        names
            .iter()
            .map(|&name| name.to_owned())
            .collect::<Vec<_>>()
    };
    // When transited lists on and off the path are checked.
    // Then the on-path lists pass, and a realm off the path or the server realm fails.
    assert!(path.admits_transited(&[]), "a direct ticket");
    assert!(
        path.admits_transited(&owned(&["ATHENA.MIT.EDU", "KERBEROS.COM"])),
        "the configured intermediates"
    );
    assert!(
        !path.admits_transited(&owned(&["ATHENA.MIT.EDU", "EVIL.EXAMPLE"])),
        "a realm not in [capaths]"
    );
    assert!(
        !path.admits_transited(&owned(&["KABLOOEY.KERBEROS.COM"])),
        "the server realm is not an intermediate"
    );
    Ok(())
}
