/// Replay-store error ([`crate::replay`]): every variant fails closed.
///
/// A store that cannot prove an authenticator is fresh reports one of these
/// errors; it never admits the authenticator.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Replay {
    /// A replay-cache name has no `type:` prefix (MIT `KRB5_RC_PARSE`).
    #[error("replay cache name has no `type:` prefix")]
    InvalidName,
    /// The replay-cache type is not one of `dfl`, `file2`, `none` or `memory`
    /// (MIT `KRB5_RC_TYPE_NOTFOUND`).
    #[error("unsupported replay cache type {name_type:?}")]
    UnsupportedType {
        /// The type prefix as written.
        name_type: String,
    },
    /// A `file2:` name has an empty path.
    #[error("the file2 replay cache name has an empty path")]
    EmptyPath,
    /// A path token of the name cannot be expanded.
    #[error("replay cache path tokens cannot be expanded")]
    IdentityUnavailable,
    /// A file operation failed, so freshness could not be proved.
    #[error("replay cache {operation} failed for {path}: {source}")]
    Io {
        /// The failed operation.
        operation: &'static str,
        /// The cache file.
        path: PathBuf,
        /// The operating-system error.
        #[source]
        source: io::Error,
    },
    /// The cache file is damaged or truncated.
    #[error("replay cache file {path} is corrupt: {reason}")]
    Corrupt {
        /// The cache file.
        path: PathBuf,
        /// What is wrong.
        reason: &'static str,
    },
    /// The cache file is not a private regular file owned by this user.
    #[error("replay cache file {path} is not safe to use: {reason}")]
    UnsafeFile {
        /// The cache file.
        path: PathBuf,
        /// Why it was refused.
        reason: &'static str,
    },
    /// Every slot holds live evidence and the file may not grow further.
    #[error("replay cache file is full: {maximum_bytes} bytes hold only live evidence")]
    FileFull {
        /// The file-size bound.
        maximum_bytes: u64,
    },
    /// Every slot holds live evidence (memory store).
    #[error("replay cache capacity {capacity} exhausted")]
    Capacity {
        /// The bound on live records.
        capacity: usize,
    },
    /// A validator's clock skew exceeds the store's retention ceiling.
    #[error("validator skew {requested:?} exceeds replay cache maximum {maximum:?}")]
    SkewExceeded {
        /// The store's maximum skew.
        maximum: Duration,
        /// The validator's skew.
        requested: Duration,
    },
    /// The validation time moved behind the store's high-water mark.
    #[error("replay cache clock moved backwards")]
    ClockRollback,
    /// A shared lock was poisoned by a panic.
    #[error("replay cache lock is poisoned")]
    Poisoned,
    /// The presentation time cannot be stored as a 32-bit Unix timestamp.
    #[error("presentation time is outside the 32-bit replay timestamp range")]
    TimeOutOfRange,
}
