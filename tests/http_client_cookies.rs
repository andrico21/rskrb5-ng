//! Cookie jar tests (the `http-client` leaf): storage, matching and the
//! refusals the jar adds on top of RFC 6265.
#![cfg(feature = "http-client")]

/// Turns `Option` and `Result` failures into test errors.
#[path = "support/context.rs"]
mod context;

/// The jar scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use http_types::{HeaderMap, HeaderValue, Uri, header::SET_COOKIE};
    use pretty_assertions::assert_eq;
    use rskrb5_ng::{
        error::HttpCookie as CookieError,
        http::{agent::CookieJar as _, cookies::CookieStore},
    };

    use super::context::{Context as _, TestError};

    /// A public-suffix list with a TLD and a two-label suffix.
    const SUFFIXES: &str =
        "// ===BEGIN ICANN DOMAINS===\ncom\nuk\nco.uk\n// ===END ICANN DOMAINS===\n";

    /// Parse a test URI.
    fn uri(text: &str) -> Result<Uri, TestError> {
        text.parse().context("test URI parses")
    }

    /// The `Cookie` header the jar sends to `target`.
    fn sent(jar: &CookieStore, target: &str) -> Result<Option<String>, TestError> {
        jar.cookie_header(&uri(target)?)
            .map(|value| value.to_str().map(str::to_owned))
            .transpose()
            .context("the Cookie header is visible ASCII")
    }

    /// A host-only cookie goes back to its host, on every path, and to no other host.
    #[test]
    fn a_host_only_cookie_goes_back_to_its_host_only() -> Result<(), TestError> {
        let mut jar = CookieStore::new();
        jar.store_set_cookie(&uri("https://www.example.com/login")?, "sid=abc123; Path=/")?;
        assert_eq!(
            sent(&jar, "https://www.example.com/other/page")?.as_deref(),
            Some("sid=abc123")
        );
        assert_eq!(sent(&jar, "https://sub.www.example.com/")?, None);
        assert_eq!(sent(&jar, "https://example.com/")?, None);
        assert_eq!(sent(&jar, "https://www.example.org/")?, None);
        assert_eq!(jar.len(), 1);
        Ok(())
    }

    /// A path-scoped cookie matches its directory and below, not a sibling prefix.
    #[test]
    fn a_path_scoped_cookie_matches_its_directory() -> Result<(), TestError> {
        let mut jar = CookieStore::new();
        jar.store_set_cookie(&uri("https://www.example.com/app/")?, "p=1; Path=/app")?;
        assert_eq!(
            sent(&jar, "https://www.example.com/app")?.as_deref(),
            Some("p=1")
        );
        assert_eq!(
            sent(&jar, "https://www.example.com/app/deep/er")?.as_deref(),
            Some("p=1")
        );
        assert_eq!(sent(&jar, "https://www.example.com/apple")?, None);
        assert_eq!(sent(&jar, "https://www.example.com/")?, None);
        Ok(())
    }

    /// A `Secure` cookie is sent over `https` only, and is refused from a cleartext response.
    #[test]
    fn a_secure_cookie_stays_off_cleartext() -> Result<(), TestError> {
        let mut jar = CookieStore::new();
        jar.store_set_cookie(&uri("https://www.example.com/")?, "s=1; Secure; Path=/")?;
        assert_eq!(
            sent(&jar, "https://www.example.com/")?.as_deref(),
            Some("s=1")
        );
        assert_eq!(sent(&jar, "http://www.example.com/")?, None);
        let refused = jar.store_set_cookie(&uri("http://www.example.com/")?, "t=1; Secure; Path=/");
        assert!(
            matches!(refused, Err(CookieError::SecureOverCleartext)),
            "{refused:?}"
        );
        assert_eq!(jar.len(), 1);
        Ok(())
    }

    /// `Max-Age=0` and a past `Expires` remove a cookie.
    #[test]
    fn an_expired_cookie_is_removed() -> Result<(), TestError> {
        let mut jar = CookieStore::new();
        let target = uri("https://www.example.com/")?;
        jar.store_set_cookie(&target, "a=1; Path=/")?;
        jar.store_set_cookie(&target, "b=2; Path=/")?;
        assert_eq!(
            sent(&jar, "https://www.example.com/")?.as_deref(),
            Some("a=1; b=2")
        );
        jar.store_set_cookie(&target, "a=; Max-Age=0; Path=/")?;
        let _gone =
            jar.store_set_cookie(&target, "b=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/");
        assert_eq!(sent(&jar, "https://www.example.com/")?, None);
        Ok(())
    }

    /// A `Domain` attribute is refused without a public-suffix list, and accepted
    /// with one unless the domain is itself a public suffix.
    #[test]
    fn a_domain_attribute_needs_the_suffix_list() -> Result<(), TestError> {
        let target = uri("https://www.example.co.uk/")?;
        let mut bare = CookieStore::new();
        let refused = bare.store_set_cookie(&target, "d=1; Domain=example.co.uk; Path=/");
        assert!(
            matches!(refused, Err(CookieError::DomainNeedsSuffixList)),
            "{refused:?}"
        );
        assert!(bare.is_empty(), "a refused cookie was stored");

        let mut jar = CookieStore::new().with_public_suffix_list(SUFFIXES)?;
        jar.store_set_cookie(&target, "d=1; Domain=example.co.uk; Path=/")?;
        assert_eq!(
            sent(&jar, "https://shop.example.co.uk/")?.as_deref(),
            Some("d=1")
        );
        assert_eq!(sent(&jar, "https://other.co.uk/")?, None);
        let suffix = jar.store_set_cookie(&target, "e=1; Domain=co.uk; Path=/");
        assert!(
            matches!(suffix, Err(CookieError::Rejected { reason: _ })),
            "{suffix:?}"
        );
        let foreign = jar.store_set_cookie(&target, "f=1; Domain=example.com; Path=/");
        assert!(
            matches!(foreign, Err(CookieError::Rejected { reason: _ })),
            "{foreign:?}"
        );
        assert_eq!(jar.len(), 1);
        Ok(())
    }

    /// A list text that is not a public-suffix list is a typed error.
    #[test]
    fn a_bad_suffix_list_is_refused() -> Result<(), TestError> {
        let _valid = CookieStore::new().with_public_suffix_list(SUFFIXES)?;
        let refused = CookieStore::new().with_public_suffix_list("*.*.bad\n!x\n*.*");
        assert!(
            matches!(refused, Err(CookieError::SuffixList)),
            "refused list was accepted"
        );
        Ok(())
    }

    /// An oversized `Set-Cookie`, a malformed one and a full jar are refused.
    #[test]
    fn oversized_malformed_and_surplus_cookies_are_refused() -> Result<(), TestError> {
        let target = uri("https://www.example.com/")?;
        let mut jar = CookieStore::new().with_max_cookies(2);
        let huge = format!("big={}", "x".repeat(CookieStore::MAX_SET_COOKIE_BYTES));
        let refused = jar.store_set_cookie(&target, &huge);
        assert!(
            matches!(
                refused,
                Err(CookieError::TooLarge {
                    limit: 4096,
                    actual: _
                })
            ),
            "{refused:?}"
        );
        let unparsed = jar.store_set_cookie(&target, "no-equals-sign");
        assert!(
            matches!(unparsed, Err(CookieError::Malformed)),
            "{unparsed:?}"
        );
        jar.store_set_cookie(&target, "a=1")?;
        jar.store_set_cookie(&target, "b=2")?;
        let surplus = jar.store_set_cookie(&target, "c=3");
        assert!(
            matches!(surplus, Err(CookieError::JarFull { limit: 2 })),
            "{surplus:?}"
        );
        jar.store_set_cookie(&target, "a=updated")?;
        assert_eq!(jar.len(), 2);
        let other = jar.store_set_cookie(&uri("ftp://www.example.com/")?, "x=1");
        assert!(matches!(other, Err(CookieError::InvalidUrl)), "{other:?}");
        Ok(())
    }

    /// The jar takes every `Set-Cookie` header of a response and counts the ones it refuses.
    #[test]
    fn the_jar_trait_stores_what_it_accepts_and_counts_the_rest() -> Result<(), TestError> {
        let mut jar = CookieStore::new();
        let mut headers = HeaderMap::new();
        for value in [
            "a=1; Path=/",
            "broken",
            "b=2; Domain=example.com; Path=/",
            "c=3",
        ] {
            let _added =
                headers.append(SET_COOKIE, HeaderValue::from_str(value).context("header")?);
        }
        jar.store(&uri("https://www.example.com/")?, &headers);
        assert_eq!(
            sent(&jar, "https://www.example.com/")?.as_deref(),
            Some("a=1; c=3")
        );
        assert_eq!(jar.rejected(), 2);
        Ok(())
    }

    /// `Debug` shows the count of cookies and never a name or value.
    #[test]
    fn debug_output_hides_cookie_values() -> Result<(), TestError> {
        let mut jar = CookieStore::new();
        jar.store_set_cookie(&uri("https://www.example.com/")?, "token=hunter2")?;
        let shown = format!("{jar:?}");
        assert!(
            !shown.contains("hunter2") && !shown.contains("token"),
            "{shown}"
        );
        Ok(())
    }
}
