//! Required-mode failures are observed in isolated test processes.

use core::error::Error;
use std::{env, net::TcpListener, process::Command};

use super::{integration_enabled, required_command_available};

/// Execute the gate in a child while the parent asserts the process outcome.
fn required_fixture(required: bool) -> Result<(), Box<dyn Error>> {
    let name = if required {
        "preflight::tests::required_closed_fixture_fails"
    } else {
        "preflight::tests::optional_closed_fixture_skips"
    };
    if env::var_os("RSKRB5_T4_PREFLIGHT_CHILD").is_some() {
        let _enabled = integration_enabled()?;
        return Ok(());
    }
    // Given a closed loopback endpoint and an isolated requested integration run.
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    drop(listener);
    let output = Command::new(env::current_exe()?)
        .args([name, "--exact", "--nocapture"])
        .env("RSKRB5_T4_PREFLIGHT_CHILD", "1")
        .env("INTEGRATION", "1")
        .env("INTEGRATION_REQUIRED", if required { "1" } else { "0" })
        .env("TEST_KDC_ADDR", address.to_string())
        .output()?;
    // When the fixture preflight runs, then required mode cannot pass a skip.
    assert_eq!(
        output.status.success(),
        !required,
        "child output: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("running 1 test"),
        "child must run exactly one test"
    );
    Ok(())
}

/// Requested but unavailable fixtures fail required integration runs.
#[test]
fn required_closed_fixture_fails() -> Result<(), Box<dyn Error>> {
    required_fixture(true)
}

/// Optional integration runs retain their explicit skip behavior.
#[test]
fn optional_closed_fixture_skips() -> Result<(), Box<dyn Error>> {
    required_fixture(false)
}

/// A missing requested executable cannot turn required mode into a passing skip.
#[test]
fn required_missing_executable_fails() -> Result<(), Box<dyn Error>> {
    // Given an isolated required run with a nonexistent executable.
    if env::var_os("RSKRB5_T4_COMMAND_CHILD").is_some() {
        let _available = required_command_available("rskrb5-nonexistent-fixture-command")?;
        return Ok(());
    }
    // When the preflight result becomes the child test's result.
    let output = Command::new(env::current_exe()?)
        .args([
            "preflight::tests::required_missing_executable_fails",
            "--exact",
            "--nocapture",
        ])
        .env("RSKRB5_T4_COMMAND_CHILD", "1")
        .env("INTEGRATION_REQUIRED", "1")
        .env("PATH", "")
        .output()?;
    // Then the child fails rather than passing without exercising the fixture.
    assert!(
        !output.status.success(),
        "missing required executable passed"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("running 1 test"),
        "child must run one test"
    );
    Ok(())
}

/// Primary-only runs do not require unrelated KDC or HTTP fixtures.
#[test]
fn primary_fixture_does_not_require_unrelated_services() -> Result<(), Box<dyn Error>> {
    // Given an open primary KDC and closed unrelated fixture endpoints.
    if env::var_os("RSKRB5_T4_SCOPE_CHILD").is_some() {
        assert!(integration_enabled()?, "primary fixture must be sufficient");
        return Ok(());
    }
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let output = Command::new(env::current_exe()?)
        .args([
            "preflight::tests::primary_fixture_does_not_require_unrelated_services",
            "--exact",
            "--nocapture",
        ])
        .env("RSKRB5_T4_SCOPE_CHILD", "1")
        .env("INTEGRATION", "1")
        .env("INTEGRATION_REQUIRED", "1")
        .env("TEST_KDC_ADDR", listener.local_addr()?.to_string())
        .env("TEST_OLD_KDC_ADDR", "127.0.0.1:9")
        .env("TEST_LATEST_KDC_ADDR", "127.0.0.1:9")
        .env("TEST_RESDOM_KDC_ADDR", "127.0.0.1:9")
        .env("TEST_SHORT_KDC_ADDR", "127.0.0.1:9")
        .env("TEST_HTTP_ADDR", "127.0.0.1:9")
        .output()?;
    // When primary-only preflight runs, then unrelated outages do not suppress it.
    assert!(
        output.status.success(),
        "scoped child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "child must execute"
    );
    Ok(())
}
