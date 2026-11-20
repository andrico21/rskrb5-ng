//! Namespace isolation: the process and thread keyrings are private to their
//! process and thread; the session and user keyrings are shared with a child.
//!
//! A child is this test binary started again, filtered to [`child`], with
//! `RSKRB5_KEYRING_CHILD` naming what it checks; it fails by panicking.

use std::{
    env,
    process::{Command, Stdio},
    thread,
};

use rskrb5_ng::error::Ccache as Error;

use crate::support::{TestError, available, open, principal};

/// The environment variable that makes [`child`] do something.
const CHILD: &str = "RSKRB5_KEYRING_CHILD";

/// Run this test binary again as a child that does `role`; whether it passed.
fn run_child(role: &str) -> Result<bool, TestError> {
    Ok(Command::new(env::current_exe()?)
        .args([
            "--exact",
            "namespaces::child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, role)
        .stdout(Stdio::null())
        .status()?
        .success())
}

/// What the child checks: it is the same test binary and runs only when
/// `RSKRB5_KEYRING_CHILD` is set.
#[test]
fn child() -> Result<(), TestError> {
    let Ok(role) = env::var(CHILD) else {
        return Ok(());
    };
    assert!(
        available("child")?,
        "the parent saw the keyring, so the child must"
    );
    match role.as_str() {
        "private" => {
            let parent = open("process:rskrb5ng-ns-parent")?;
            assert!(
                matches!(parent.load(), Err(Error::CacheNotFound { name: _ })),
                "the child sees the process cache of its parent"
            );
            let own = open("process:rskrb5ng-ns-child")?;
            own.initialize(&principal("child"))?;
        }
        "shared" => {
            for name in ["session:rskrb5ng-ns-session", "user:rskrb5ng-ns-user"] {
                assert_eq!(
                    open(name)?.load()?.default_principal(),
                    &principal("alice"),
                    "{name} is shared with a child"
                );
            }
        }
        other => return Err(format!("unknown role {other}").into()),
    }
    Ok(())
}

/// Two processes never see each other's process keyring: not the cache of the
/// parent, nor the cache the child writes.
#[test]
fn process_keyring_is_private_to_the_process() -> Result<(), TestError> {
    if !available("process_keyring_is_private_to_the_process")? {
        return Ok(());
    }
    let parent = open("process:rskrb5ng-ns-parent")?;
    parent.initialize(&principal("alice"))?;
    assert!(
        run_child("private")?,
        "the child saw the parent's process keyring or failed"
    );
    let child = open("process:rskrb5ng-ns-child")?;
    assert!(
        matches!(child.load(), Err(Error::CacheNotFound { name: _ })),
        "the parent sees the process cache of its child"
    );
    parent.destroy()?;
    Ok(())
}

/// Two threads never see each other's thread keyring.
#[test]
fn thread_keyring_is_private_to_the_thread() -> Result<(), TestError> {
    if !available("thread_keyring_is_private_to_the_thread")? {
        return Ok(());
    }
    let own = open("thread:rskrb5ng-ns-thread")?;
    own.initialize(&principal("alice"))?;
    let other_sees_it = thread::scope(|scope| {
        scope
            .spawn(|| open("thread:rskrb5ng-ns-thread").map(|cache| cache.load().is_ok()))
            .join()
    })
    .map_err(|_panic| "the other thread panicked")??;
    assert!(!other_sees_it, "another thread sees the thread cache");
    assert_eq!(
        own.load()?.default_principal(),
        &principal("alice"),
        "still there"
    );
    own.destroy()?;
    Ok(())
}

/// A child sees the caches of the session and user keyrings.
#[test]
fn session_and_user_keyrings_are_shared() -> Result<(), TestError> {
    if !available("session_and_user_keyrings_are_shared")? {
        return Ok(());
    }
    let caches = [
        open("session:rskrb5ng-ns-session")?,
        open("user:rskrb5ng-ns-user")?,
    ];
    for cache in &caches {
        cache.initialize(&principal("alice"))?;
    }
    let shared = run_child("shared")?;
    for cache in &caches {
        cache.destroy()?;
    }
    assert!(shared, "the child did not see the session or user cache");
    Ok(())
}
