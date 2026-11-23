//! Container commands of the replay scenarios: run a command, copy cache files in and out.

use core::error::Error;
use std::{
    fs,
    io::Write as _,
    path::Path,
    process::{Command, Stdio},
};

use crate::harness;

/// The container runtime of the run.
pub(super) fn runtime() -> Result<String, Box<dyn Error>> {
    harness::var("INTEROP_RUNTIME")
}

/// Run `command` in the `replay` or `mit-peer` container; its stdout.
pub(super) fn exec(
    container_key: &str,
    command: &[&str],
    stdin: Option<&Path>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut command_line = Command::new(runtime()?);
    let mut options = vec!["exec"];
    if stdin.is_some() {
        options.push("-i");
    }
    let mut process = command_line
        .args(options)
        .arg(harness::var(container_key)?)
        .args(command)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let (Some(path), Some(mut pipe)) = (stdin, process.stdin.take()) {
        pipe.write_all(&fs::read(path)?)?;
    }
    let output = process.wait_with_output()?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(format!(
            "`{}` failed in the container ({}): {}",
            command.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into())
    }
}

/// Copy a replay-cache file into the `replay` container.
pub(super) fn put_cache(source: &Path) -> Result<(), Box<dyn Error>> {
    let target = harness::var("INTEROP_REPLAY_RCACHE")?;
    drop(exec(
        "INTEROP_REPLAY_CONTAINER",
        &["sh", "-c", "umask 077 && cat > \"$1\"", "sh", &target],
        Some(source),
    )?);
    Ok(())
}

/// Copy a file out of a container into `destination`.
pub(super) fn get_file(
    container_key: &str,
    path_command: &[&str],
    destination: &Path,
) -> Result<(), Box<dyn Error>> {
    fs::write(destination, exec(container_key, path_command, None)?)?;
    Ok(())
}
