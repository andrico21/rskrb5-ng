//! `.k5identity` grammar and pattern tests (MIT 1.22.2 `ccselect_k5identity.c`).

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;

    use crate::{
        ccache::Principal,
        extensions::k5identity::{choose, fnmatch},
    };

    /// A host-based server principal `service/host@REALM`.
    fn server(service: &str, host: &str, realm: &str) -> Principal {
        Principal::new(realm, 3, vec![service.to_owned(), host.to_owned()])
    }

    /// The principal `name@realm` as `krb5_parse_name` builds it.
    fn user(name: &str, realm: &str) -> Principal {
        Principal::new(realm, 1, vec![name.to_owned()])
    }

    /// The principal the first matching line of `file` names.
    fn chosen(
        file: &[u8],
        target: &Principal,
        default_realm: Option<&str>,
    ) -> Result<Principal, Box<dyn Error>> {
        Ok(choose(file, target, default_realm).ok_or("no line matched")?)
    }

    /// Globs follow `fnmatch(pattern, text, 0)`.
    #[test]
    fn fnmatch_follows_posix_flags_zero() {
        for case in [
            ("*.example.com", "www.example.com", true),
            ("*.example.com", "example.com", false),
            ("*", "", true),
            ("", "", true),
            ("", "a", false),
            ("a?c", "abc", true),
            ("a?c", "ac", false),
            ("*a*b", "xaxxb", true),
            ("*a*b", "xaxxbc", false),
            ("[a-c]x", "bx", true),
            ("[a-c]x", "dx", false),
            ("[!a]", "b", true),
            ("[!a]", "a", false),
            ("[^a]", "a", false),
            ("[]a]", "]", true),
            ("[a-]", "-", true),
            ("[[:digit:]]*", "7up", true),
            ("[[:upper:]]", "a", false),
            ("\\*", "*", true),
            ("\\*", "a", false),
            ("a\\", "a\\", false),
            ("[ab", "[ab", true),
            ("*", "a/b", true),
            ("*", ".hidden", true),
        ] {
            assert_eq!(
                fnmatch(case.0.as_bytes(), case.1.as_bytes()),
                case.2,
                "{} against {}",
                case.0,
                case.1
            );
        }
    }

    /// The first line whose constraints the server satisfies wins.
    #[test]
    fn first_matching_line_wins() -> Result<(), Box<dyn Error>> {
        let file = b"# comment\n\
            alice@OTHER.ORG realm=OTHER.ORG\n\
            bob@EXAMPLE.ORG service=HTTP host=*.example.org\n\
            carol@EXAMPLE.ORG realm=EXAMPLE.ORG\n";
        let web = server("HTTP", "www.example.org", "EXAMPLE.ORG");
        assert_eq!(
            chosen(file, &web, None)?,
            user("bob", "EXAMPLE.ORG"),
            "service and host constraints"
        );
        let mail = server("imap", "mail.example.org", "EXAMPLE.ORG");
        assert_eq!(
            chosen(file, &mail, None)?,
            user("carol", "EXAMPLE.ORG"),
            "realm constraint"
        );
        let other = server("HTTP", "www.other.org", "OTHER.ORG");
        assert_eq!(
            chosen(file, &other, None)?,
            user("alice", "OTHER.ORG"),
            "first line"
        );
        Ok(())
    }

    /// The host is folded to lower case before matching; the pattern is not.
    #[test]
    fn host_is_folded_but_not_the_pattern() -> Result<(), Box<dyn Error>> {
        let upper = server("HTTP", "WWW.EXAMPLE.ORG", "EXAMPLE.ORG");
        assert_eq!(
            chosen(b"bob@R host=www.example.org\n", &upper, None)?,
            user("bob", "R"),
            "folded host"
        );
        assert_eq!(
            choose(b"bob@R host=WWW.EXAMPLE.ORG\n", &upper, None),
            None,
            "pattern compared as written"
        );
        assert_eq!(
            choose(b"bob@R realm=example.org\n", &upper, None),
            None,
            "realm is not folded"
        );
        Ok(())
    }

    /// Unknown, malformed and host constraints on a non-host server never match.
    #[test]
    fn unknown_or_malformed_constraints_never_match() -> Result<(), Box<dyn Error>> {
        let web = server("HTTP", "www.example.org", "EXAMPLE.ORG");
        for line in [
            "bob@R color=blue\n",
            "bob@R realm\n",
            "bob@R Realm=EXAMPLE.ORG\n",
            "#bob@R\n",
            "\n",
            "   \t\n",
        ] {
            assert_eq!(choose(line.as_bytes(), &web, None), None, "{line}");
        }
        let plain = user("svc", "EXAMPLE.ORG");
        assert_eq!(
            choose(b"bob@R service=svc\n", &plain, None),
            None,
            "service needs a host-based server"
        );
        assert_eq!(
            chosen(b"bob@R realm=EXAMPLE.ORG\n", &plain, None)?,
            user("bob", "R"),
            "realm applies to any server"
        );
        Ok(())
    }

    /// `krb5_parse_name` rules: escapes, components, default realm.
    #[test]
    fn principal_field_parses_like_krb5_parse_name() -> Result<(), Box<dyn Error>> {
        let web = server("HTTP", "www.example.org", "EXAMPLE.ORG");
        assert_eq!(
            chosen(b"bob\n", &web, Some("DEFAULT.ORG"))?,
            user("bob", "DEFAULT.ORG"),
            "default realm"
        );
        assert_eq!(choose(b"bob\n", &web, None), None, "no realm, no default");
        assert_eq!(
            chosen(b"host/a.example.org@R\n", &web, None)?,
            Principal::new("R", 1, vec!["host".to_owned(), "a.example.org".to_owned()]),
            "components"
        );
        assert_eq!(
            chosen(b"a\\/b\\@c@R\n", &web, None)?,
            user("a/b@c", "R"),
            "escaped separators"
        );
        for line in ["bob@R@S\n", "bob@R/x\n", "bob@\n", "bob\\\n", "bob\\n@R\n"] {
            assert_eq!(choose(line.as_bytes(), &web, Some("D")), None, "{line}");
        }
        Ok(())
    }

    /// A line MIT's 256-byte `fgets` buffer would split never matches here.
    #[test]
    fn overlong_lines_never_match() -> Result<(), Box<dyn Error>> {
        let web = server("HTTP", "www.example.org", "EXAMPLE.ORG");
        let fits = format!("bob@R realm={}\n", "*".repeat(242));
        assert_eq!(fits.trim_end().len(), 254, "boundary line");
        assert_eq!(
            chosen(fits.as_bytes(), &web, None)?,
            user("bob", "R"),
            "fits"
        );
        let long = format!("bob@R realm={}\n", "*".repeat(243));
        assert_eq!(choose(long.as_bytes(), &web, None), None, "too long");
        Ok(())
    }
}
