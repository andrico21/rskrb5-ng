//! Deadlines for in-process transport peer activity.

use core::time::Duration;
use std::io;

use tokio::{task::JoinHandle, time::timeout};

/// Await peer activity without delaying a ready operation.
///
/// # Errors
/// Returns a named timeout diagnostic if the peer never performs the activity.
///
/// # Cancel safety
/// Cancel safety is inherited from the supplied future; timeout drops it.
pub(super) async fn bounded<F>(
    duration: Duration,
    activity: &str,
    future: F,
) -> io::Result<F::Output>
where
    F: Future,
{
    timeout(duration, future).await.map_err(|_elapsed| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("transport fixture deadline: {activity}"),
        )
    })
}

/// Abort a DNS fixture and observe its termination with a deadline.
///
/// # Errors
/// Returns a deadline, task panic, or fixture error.
///
/// # Cancel safety
/// cancel-safe: the task is aborted before awaiting its completion.
pub(super) async fn stop(
    task: JoinHandle<Result<(), super::TestError>>,
) -> Result<(), super::TestError> {
    task.abort();
    match bounded(Duration::from_secs(10), "aborted DNS fixture", task).await? {
        Ok(result) => result?,
        Err(error) if error.is_cancelled() => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}
