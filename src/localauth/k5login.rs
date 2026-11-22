//! The `.k5login` module (`localauth_k5login.c`).

use std::io;

/// The largest `.k5login` file read, in bytes.
pub const MAX_FILE_BYTES: usize = 1_048_576;
/// The most lines in a `.k5login` file.
pub const MAX_LINES: usize = 16_384;
/// The longest line of a `.k5login` file, newline excluded: MIT reads with a
/// `BUFSIZ` (8192) buffer and cannot match a longer line.
pub const MAX_LINE_BYTES: usize = 8191;

/// Why the `.k5login` module refused.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Fault {
    /// The resolver does not know the account.
    UnknownAccount,
    /// The account name cannot be a file name under `k5login_directory`.
    UnsafeLocalName,
    /// The account's home directory is not absolute.
    RelativeHome,
    /// The file or its metadata could not be read.
    Unreadable(io::ErrorKind),
    /// The path is a symbolic link.
    Symlink,
    /// The path is not a regular file.
    NotRegular,
    /// The file is not the one that was inspected (it was replaced).
    Changed,
    /// The file belongs to neither the account's user nor root.
    WrongOwner,
    /// The file is writable by its group or by others.
    WritableByOthers,
    /// The file is larger than [`MAX_FILE_BYTES`].
    TooLarge,
    /// The file has more than [`MAX_LINES`] lines.
    TooManyLines,
    /// A line is longer than [`MAX_LINE_BYTES`].
    LineTooLong,
    /// The file does not list the principal.
    NotListed,
}
