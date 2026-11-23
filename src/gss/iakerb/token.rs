/// One IAKERB proxy token: the realm a KDC request is for, the proxy's cookie
/// and the KDC message (MIT `iakerb.c:203-330`).
///
/// On the wire it is an RFC 2743 initial context token of the IAKERB mechanism
/// with token id `05 01`, an `IAKERB-HEADER` DER sequence and the raw KDC
/// message. A realm-discovery request has an empty realm and an empty message;
/// the acceptor's answer carries its realm and an empty message.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct Token {
    /// The target realm; empty in a realm-discovery request.
    realm: String,
    /// The proxy's cookie, echoed by the initiator.
    cookie: Option<Vec<u8>>,
    /// The KDC request, reply or `KRB-ERROR`; empty in a discovery token.
    message: Vec<u8>,
}

impl fmt::Debug for Token {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Token")
            .field("realm", &self.realm)
            .field("cookie_len", &self.cookie.as_ref().map(Vec::len))
            .field("message_len", &self.message.len())
            .finish()
    }
}

impl Token {
    /// A token for `realm` carrying `message`.
    #[inline]
    #[must_use]
    pub fn new(realm: &str, cookie: Option<Vec<u8>>, message: Vec<u8>) -> Self {
        Self {
            realm: realm.to_owned(),
            cookie,
            message,
        }
    }

    /// The target realm.
    #[inline]
    #[must_use]
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// The proxy's cookie.
    #[inline]
    #[must_use]
    pub fn cookie(&self) -> Option<&[u8]> {
        self.cookie.as_deref()
    }

    /// The KDC message.
    #[inline]
    #[must_use]
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// Whether `bytes` frame an IAKERB proxy token (MIT `iakerb_is_iakerb_token`,
    /// `iakerb.c:827-835`): the IAKERB mechanism and token id `05 01`.
    #[inline]
    #[must_use]
    pub fn is_iakerb(bytes: &[u8]) -> bool {
        let _unread = bytes;
        false
    }

    /// Parse a token.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TokenTooLarge`] above 256 KiB, [`Error::NotIakerb`] for
    /// another mechanism or token id, and [`Error::BadToken`] for a malformed
    /// frame or header.
    #[inline]
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let _unread = bytes;
        Err(Error::BadToken("not implemented"))
    }

    /// Encode the token.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TokenTooLarge`] above 256 KiB and [`Error::BadToken`]
    /// for a realm above 255 bytes.
    #[inline]
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        Err(Error::BadToken("not implemented"))
    }
}
