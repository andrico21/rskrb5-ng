//! A bad value among repeated `[plugins]` and `[capaths]` relations reports its own line.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use core::error::Error;

    use rskrb5_ng::{config::Config, error::Config as Failure};

    /// Repeated relations paired with the line number and trimmed text of the offending value.
    const CASES: [(&str, usize, &str); 7] = [
        (
            "[plugins]\nclpreauth = {\n  disable = a\n  disable = \"x y\"\n}\n",
            4,
            "disable = x y",
        ),
        (
            "[plugins]\nclpreauth = {\n  disable = a,b\n  disable = \"x y\"\n}\n",
            4,
            "disable = x y",
        ),
        (
            "[plugins]\npa = {\n  enable_only = a\n  enable_only = \"x y\"\n  enable_only = c\n}\n",
            4,
            "enable_only = x y",
        ),
        (
            "[plugins]\npa = {\n  disable = a\n  disable = b\n  disable = \"\"\n}\n",
            5,
            "disable =",
        ),
        (
            "[capaths]\nA = {\n  B = C\n  B = \"x y\"\n}\n",
            4,
            "B = x y",
        ),
        ("[capaths]\nA = {\n  B = C\n  B = .\n}\n", 4, "B = ."),
        ("[capaths]\nA = {\n  B = .\n  B = C\n}\n", 4, "B = C"),
    ];

    fn assert_offending(failure: &Failure, line: usize, text: &str, source: &str) {
        assert!(
            matches!(
                failure,
                Failure::InvalidLine { section: "profile", line: found, text: found_text }
                    if *found == line && found_text.trim() == text
            ),
            "{source:?}: {failure:?}"
        );
    }

    /// Given a repeated relation with one bad value, then the error names that value's line.
    #[test]
    fn parse_reports_the_offending_value_line() -> Result<(), Box<dyn Error>> {
        for (source, line, text) in CASES {
            // When parsing the profile text.
            let failure = Config::parse(source).err().ok_or("accepted")?;
            // Then the reported line is the offending one, not the first of the relation.
            assert_offending(&failure, line, text, source);
        }
        Ok(())
    }

    /// The reader path reports the same line as `parse`.
    #[test]
    fn reader_reports_the_offending_value_line() -> Result<(), Box<dyn Error>> {
        for (source, line, text) in CASES {
            let failure = Config::from_reader(source.as_bytes())
                .err()
                .ok_or("accepted")?;
            assert_offending(&failure, line, text, source);
        }
        Ok(())
    }

    /// A relation with a single bad value still reports its only line.
    #[test]
    fn single_bad_value_reports_its_line() -> Result<(), Box<dyn Error>> {
        let source = "[plugins]\nclpreauth = {\n  enable_only = x y\n}\n";
        let failure = Config::parse(source).err().ok_or("accepted")?;
        assert_offending(&failure, 3, "enable_only = x y", source);
        Ok(())
    }
}
