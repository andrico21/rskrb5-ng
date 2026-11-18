//! Shared harness of the live interop suites.
//!
//! Each suite is a `tests/interop_<topic>.rs`. `scripts/interop/run.sh test <suite>` sources the env file that `run.sh up`
//! wrote and runs one suite; this module reads that environment. Each scenario
//! starts with [`require`]: with `INTEROP=1` and every fixture reachable it
//! prints `interop: ran <scenario>` and returns `true`; otherwise it prints a
//! visible `interop: SKIP` and returns `false`, or, with `INTEROP_REQUIRED=1`
//! (or plan 1's `INTEGRATION_REQUIRED=1`), fails with a [`FixtureUnavailable`]
//! naming the fixture, its endpoint and its container. The
//! `assert_negotiated_*` helpers make every scenario state which mechanism,
//! enctype, pre-authentication type or ticket flag was negotiated, so a
//! fallback cannot pass. The layout contract is in `scripts/interop/lib.sh`.

use core::{error::Error, fmt, time::Duration};
use std::{
    env,
    io::{self, Write as _},
    net::{TcpStream, ToSocketAddrs as _},
};

/// A container fixture a scenario needs.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Fixture {
    /// Fixture name; its container is `rskrb5-interop-<name>`.
    name: &'static str,
    /// Env-file key holding the fixture's TCP endpoint (`host:port`).
    endpoint_key: &'static str,
}

impl Fixture {
    /// A fixture reached through the TCP endpoint in `endpoint_key`.
    pub(crate) const fn new(name: &'static str, endpoint_key: &'static str) -> Self {
        Self { name, endpoint_key }
    }
}

/// A required fixture that a scenario cannot reach.
///
/// `Debug` prints the `Display` text: a test that returns this error is
/// reported by libtest through `Debug`, and the report must name the fixture.
pub(crate) struct FixtureUnavailable {
    /// Fixture name.
    fixture: &'static str,
    /// Endpoint tried, or the unset env-file key.
    endpoint: String,
    /// Why the fixture is unavailable.
    reason: String,
}

impl fmt::Display for FixtureUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "required interop fixture unreachable: {} at {} (container rskrb5-interop-{}): {}",
            self.fixture, self.endpoint, self.fixture, self.reason
        )
    }
}

impl fmt::Debug for FixtureUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Error for FixtureUnavailable {}

/// A negotiated value that differs from the one the scenario requires.
///
/// `Debug` prints the `Display` text, which libtest shows for a failed scenario.
pub(crate) struct NotNegotiated {
    /// What was negotiated (enctype, mechanism, pre-authentication, flag).
    what: String,
    /// The required value.
    expected: String,
    /// The value the peer negotiated.
    actual: String,
}

impl fmt::Display for NotNegotiated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "negotiated {}: expected {}, got {} (a fallback must not pass)",
            self.what, self.expected, self.actual
        )
    }
}

impl fmt::Debug for NotNegotiated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Error for NotNegotiated {}

/// Whether the interop suites are requested (`INTEROP=1`).
fn enabled() -> bool {
    env::var("INTEROP").as_deref() == Ok("1")
}

/// Whether an unavailable fixture must fail the scenario: `INTEROP_REQUIRED=1`,
/// or plan 1's `INTEGRATION_REQUIRED=1`.
fn required() -> bool {
    env::var("INTEROP_REQUIRED").as_deref() == Ok("1")
        || env::var("INTEGRATION_REQUIRED").as_deref() == Ok("1")
}

/// Whether some address of `endpoint` accepts a TCP connection within 2 s.
fn tcp_reachable(endpoint: &str) -> bool {
    endpoint.to_socket_addrs().is_ok_and(|mut addrs| {
        addrs.any(|addr| TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok())
    })
}

/// Returns whether `scenario` runs: `INTEROP=1` and every fixture reachable.
///
/// Prints `interop: ran <scenario>` when it runs and `interop: SKIP
/// <scenario>: <reason>` when it does not; `run.sh test` counts both.
///
/// # Errors
///
/// In required mode, returns [`FixtureUnavailable`] for the first fixture whose
/// env-file key is unset or whose endpoint accepts no TCP connection; also
/// returns the error of a failed write to stderr.
pub(crate) fn require(scenario: &str, fixtures: &[Fixture]) -> Result<bool, Box<dyn Error>> {
    if !enabled() {
        writeln!(
            io::stderr(),
            "interop: SKIP {scenario}: set INTEROP=1 to enable"
        )?;
        return Ok(false);
    }
    for fixture in fixtures {
        let unavailable = match env::var(fixture.endpoint_key) {
            Ok(endpoint) if tcp_reachable(&endpoint) => continue,
            Ok(endpoint) => FixtureUnavailable {
                fixture: fixture.name,
                endpoint,
                reason: "no TCP connection".to_owned(),
            },
            Err(_) => FixtureUnavailable {
                fixture: fixture.name,
                endpoint: format!("<{} unset>", fixture.endpoint_key),
                reason: format!(
                    "env-file key {} is not set; run scripts/interop/run.sh up",
                    fixture.endpoint_key
                ),
            },
        };
        if required() {
            return Err(unavailable.into());
        }
        writeln!(io::stderr(), "interop: SKIP {scenario}: {unavailable}")?;
        return Ok(false);
    }
    writeln!(io::stderr(), "interop: ran {scenario}")?;
    Ok(true)
}

/// Reads the env-file key `key` that `run.sh test` exported.
///
/// # Errors
///
/// Returns an error naming `key` when it is unset or not Unicode.
pub(crate) fn var(key: &str) -> Result<String, Box<dyn Error>> {
    env::var(key).map_err(|cause| {
        format!("env-file key {key}: {cause}; run scripts/interop/run.sh up and test").into()
    })
}

/// Checks that `what` was negotiated as `expected`.
///
/// # Errors
///
/// Returns [`NotNegotiated`] naming both values when `actual` differs.
fn negotiated<T>(what: &str, expected: &T, actual: &T) -> Result<(), NotNegotiated>
where
    T: PartialEq + fmt::Display,
{
    if expected == actual {
        return Ok(());
    }
    Err(NotNegotiated {
        what: what.to_owned(),
        expected: expected.to_string(),
        actual: actual.to_string(),
    })
}

/// Asserts that `what` (a ticket or a session key) uses the enctype `expected`.
///
/// # Errors
///
/// Returns [`NotNegotiated`] when `actual` differs.
pub(crate) fn assert_negotiated_enctype(
    what: &str,
    expected: i32,
    actual: i32,
) -> Result<(), NotNegotiated> {
    negotiated(&format!("enctype of {what}"), &expected, &actual)
}

/// Asserts that the GSS mechanism with the arcs `actual` is `expected`.
///
/// # Errors
///
/// Returns [`NotNegotiated`] when the arcs differ.
pub(crate) fn assert_negotiated_mechanism(
    expected: &[u32],
    actual: &[u32],
) -> Result<(), NotNegotiated> {
    let dotted = |arcs: &[u32]| {
        arcs.iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(".")
    };
    negotiated("GSS mechanism", &dotted(expected), &dotted(actual))
}

/// Asserts that the PA-DATA types of `what` include `expected`.
///
/// # Errors
///
/// Returns [`NotNegotiated`] when `expected` is not among `offered`.
pub(crate) fn assert_negotiated_padata(
    what: &str,
    expected: i32,
    offered: &[i32],
) -> Result<(), NotNegotiated> {
    if offered.contains(&expected) {
        return Ok(());
    }
    Err(NotNegotiated {
        what: format!("PA-DATA of {what}"),
        expected: format!("type {expected} among them"),
        actual: offered
            .iter()
            .map(i32::to_string)
            .collect::<Vec<_>>()
            .join(", "),
    })
}

/// Asserts that RFC 4120 ticket flag `bit` (bit 0 is the most significant bit
/// of the first byte) named `name` is set in `flags`.
///
/// # Errors
///
/// Returns [`NotNegotiated`] when the flag is clear or `bit` is beyond 31.
pub(crate) fn assert_ticket_flag(
    name: &str,
    bit: u32,
    flags: [u8; 4],
) -> Result<(), NotNegotiated> {
    let mask = 0x8000_0000_u32.checked_shr(bit).unwrap_or(0);
    if mask != 0 && u32::from_be_bytes(flags) & mask == mask {
        return Ok(());
    }
    Err(NotNegotiated {
        what: format!("ticket flag {name} (RFC 4120 bit {bit})"),
        expected: "set".to_owned(),
        actual: format!("flags {}", u32::from_be_bytes(flags)),
    })
}

/// Harness regressions; the environment-dependent ones run in child processes.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "harness_tests.rs"]
mod tests;
