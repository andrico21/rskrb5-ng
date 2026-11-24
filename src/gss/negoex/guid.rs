/// A 16-byte GUID in its wire order (`Data1`, `Data2` and `Data3` little endian).
///
/// Formats as MIT's trace does (`negoex_util.c:134-143`): `c0a28569-66ac-0000-0000-000000000000`.
///
/// # Errors
///
/// Returns the formatter's error.
fn format_guid(guid: &[u8; 16], out: &mut fmt::Formatter<'_>) -> fmt::Result {
    let [a0, a1, a2, a3, b0, b1, c0, c1, d0, d1, e0, e1, e2, e3, e4, e5] = *guid;
    let data1 = u32::from_le_bytes([a0, a1, a2, a3]);
    let data2 = u16::from_le_bytes([b0, b1]);
    let data3 = u16::from_le_bytes([c0, c1]);
    write!(
        out,
        "{data1:08x}-{data2:04x}-{data3:04x}-{d0:02x}{d1:02x}-{e0:02x}{e1:02x}{e2:02x}{e3:02x}{e4:02x}{e5:02x}"
    )
}

/// The authentication scheme GUID of a `NegoEx` mechanism (MS-NEGOEX 2.2.2.1).
///
/// MIT asks the mechanism (`gssspi_query_mechanism_info`); for its test
/// mechanisms the GUID is the mechanism's object identifier right-padded with zeros.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct AuthScheme([u8; 16]);

impl AuthScheme {
    /// A scheme from its wire bytes.
    #[inline]
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The wire bytes.
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for AuthScheme {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        format_guid(&self.0, f)
    }
}

impl fmt::Debug for AuthScheme {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AuthScheme({self})")
    }
}

/// The id every message of one `NegoEx` conversation carries (MS-NEGOEX 2.2.6.2).
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ConversationId([u8; 16]);

impl ConversationId {
    /// A conversation id from its wire bytes.
    #[inline]
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The wire bytes.
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for ConversationId {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        format_guid(&self.0, f)
    }
}

impl fmt::Debug for ConversationId {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConversationId({self})")
    }
}
