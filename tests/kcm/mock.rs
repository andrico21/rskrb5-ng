//! A scripted KCM daemon on a temporary Unix socket, and helpers to speak
//! the protocol by hand.

use core::{
    error,
    sync::atomic::{AtomicU32, Ordering},
};
use std::{
    env, fs, io,
    io::{Read as _, Write as _},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    process,
    thread::{self, JoinHandle},
};

/// Error type of the `Result`-returning tests.
pub(super) type TestError = Box<dyn error::Error>;

/// What a scripted daemon does with one accepted connection.
pub(super) type Script = Box<dyn FnOnce(&mut UnixStream) -> io::Result<()> + Send>;

/// A daemon that runs one script per accepted connection, in order.
pub(super) struct Scripted {
    /// The socket path.
    path: PathBuf,
    /// The private directory holding it.
    directory: PathBuf,
    /// The accept loop.
    thread: Option<JoinHandle<io::Result<()>>>,
}

/// A fresh private directory.
pub(super) fn scratch(label: &str) -> Result<PathBuf, TestError> {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let directory = env::temp_dir().join(format!(
        "rskrb5-kcm-{label}-{}-{}",
        process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&directory)?;
    Ok(directory)
}

impl Scripted {
    /// Listen and run `scripts` against the next connections.
    pub(super) fn start(label: &str, scripts: Vec<Script>) -> Result<Self, TestError> {
        let directory = scratch(label)?;
        let path = directory.join("kcm.sock");
        let listener = UnixListener::bind(&path)?;
        let thread = thread::spawn(move || -> io::Result<()> {
            for script in scripts {
                let (mut stream, _peer) = listener.accept()?;
                script(&mut stream)?;
            }
            Ok(())
        });
        Ok(Self {
            path,
            directory,
            thread: Some(thread),
        })
    }

    /// The socket path.
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// Wait for every script to finish, and fail if one failed.
    pub(super) fn finish(mut self) -> Result<(), TestError> {
        if let Some(thread) = self.thread.take() {
            thread.join().map_err(|_panic| "script panicked")??;
        }
        Ok(())
    }
}

impl Drop for Scripted {
    fn drop(&mut self) {
        drop(fs::remove_dir_all(&self.directory));
    }
}

/// Read one request frame and ignore it.
pub(super) fn skip_request(stream: &mut UnixStream) -> io::Result<()> {
    read_request(stream).map(|_request| ())
}

/// Read one request frame: its opcode and parameters.
pub(super) fn read_request(stream: &mut UnixStream) -> io::Result<(u16, Vec<u8>)> {
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length)?;
    let mut request =
        vec![0_u8; usize::try_from(u32::from_be_bytes(length)).map_err(io::Error::other)?];
    stream.read_exact(&mut request)?;
    let [major, minor, high, low, parameters @ ..] = request.as_slice() else {
        return Err(io::Error::other("request shorter than its header"));
    };
    if (*major, *minor) != (2, 0) {
        return Err(io::Error::other("wrong protocol version"));
    }
    Ok((u16::from_be_bytes([*high, *low]), parameters.to_vec()))
}

/// Send a reply frame: transport code, then a body that starts with the
/// daemon's status.
pub(super) fn reply(
    stream: &mut UnixStream,
    transport: i32,
    status: i32,
    payload: &[u8],
) -> io::Result<()> {
    let mut body = status.to_be_bytes().to_vec();
    body.extend_from_slice(payload);
    let mut frame = u32::try_from(body.len())
        .map_err(io::Error::other)?
        .to_be_bytes()
        .to_vec();
    frame.extend_from_slice(&transport.to_be_bytes());
    frame.extend_from_slice(&body);
    stream.write_all(&frame)
}

/// A successful reply with `payload`.
pub(super) fn ok(stream: &mut UnixStream, payload: &[u8]) -> io::Result<()> {
    reply(stream, 0, 0, payload)
}

/// A reply that is only a transport error code, with an empty body (an
/// unsupported opcode on SSSD).
pub(super) fn transport_error(stream: &mut UnixStream, code: i32) -> io::Result<()> {
    let mut frame = 0_u32.to_be_bytes().to_vec();
    frame.extend_from_slice(&code.to_be_bytes());
    stream.write_all(&frame)
}
