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
        unframe(bytes).is_ok_and(|(id, _body)| id == PROXY_TOKEN_ID)
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
        let (id, body) = unframe(bytes)?;
        if id != PROXY_TOKEN_ID {
            return Err(Error::NotIakerb("not token id 05 01"));
        }
        let (header, message): (Header, &[u8]) = der::decode_with_remainder(body)
            .map_err(|_malformed| Error::BadToken("the IAKERB-HEADER does not decode"))?;
        if header.target_realm.len() > MAX_REALM_BYTES {
            return Err(Error::BadToken("the target realm is too long"));
        }
        Ok(Self {
            realm: header.target_realm,
            cookie: header.cookie.map(|cookie| cookie.to_vec()),
            message: message.to_vec(),
        })
    }

    /// Encode the token.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TokenTooLarge`] above 256 KiB and [`Error::BadToken`]
    /// for a realm above 255 bytes.
    #[inline]
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.realm.len() > MAX_REALM_BYTES {
            return Err(Error::BadToken("the target realm is too long"));
        }
        let header = Header {
            target_realm: self.realm.clone(),
            cookie: self.cookie.clone().map(OctetString::from),
        };
        let mut body = der::encode(&header)
            .map_err(|_encode| Error::BadToken("the IAKERB-HEADER does not encode"))?;
        body.extend_from_slice(&self.message);
        frame(PROXY_TOKEN_ID, &body)
    }
}

/// `IAKERB-HEADER ::= SEQUENCE { target-realm [1] UTF8String, cookie [2] OCTET
/// STRING OPTIONAL }` (MIT `asn1_k_encode.c:1094-1100`).
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
struct Header {
    /// The realm the message is for.
    #[rasn(tag(explicit(1)))]
    target_realm: String,
    /// The proxy's state.
    #[rasn(tag(explicit(2)))]
    cookie: Option<OctetString>,
}

/// The longest token, in bytes (the bound of [`super::Acceptor`]).
const MAX_TOKEN_BYTES: usize = 0x4_0000;
/// The longest target realm, in bytes.
const MAX_REALM_BYTES: usize = 255;
/// The IAKERB mechanism `1.3.6.1.5.2.5` as a DER OBJECT IDENTIFIER
/// (MIT `gssapiP_krb5.h:90-91`).
const MECHANISM_DER: [u8; 8] = [0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x02, 0x05];
/// The token id of a proxy token (`IAKERB_TOK_PROXY`, `gssapiP_krb5.h:108`).
const PROXY_TOKEN_ID: [u8; 2] = [0x05, 0x01];
/// The token id of an AP-REQ (`KG_TOK_CTX_AP_REQ`).
const AP_REQ_TOKEN_ID: [u8; 2] = [0x01, 0x00];
/// The token id of an AP-REP (`KG_TOK_CTX_AP_REP`).
const AP_REP_TOKEN_ID: [u8; 2] = [0x02, 0x00];

/// The RFC 2743 initial context token of the IAKERB mechanism: tag `60`, a DER
/// length, the mechanism, `id` and `body`.
///
/// # Errors
///
/// Returns [`Error::TokenTooLarge`] above the token bound.
fn frame(id: [u8; 2], body: &[u8]) -> Result<Vec<u8>, Error> {
    let content = MECHANISM_DER.len() + id.len() + body.len();
    let length = content.to_be_bytes();
    let significant = length
        .iter()
        .position(|byte| *byte != 0)
        .map_or(&[0][..], |first| length.get(first..).unwrap_or_default());
    let mut token = vec![0x60];
    if let [only] = significant
        && *only < 0x80
    {
        token.push(*only);
    } else {
        let count = u8::try_from(significant.len()).unwrap_or(u8::MAX);
        token.push(0x80 | count);
        token.extend_from_slice(significant);
    }
    token.extend_from_slice(&MECHANISM_DER);
    token.extend_from_slice(&id);
    token.extend_from_slice(body);
    if token.len() > MAX_TOKEN_BYTES {
        return Err(Error::TokenTooLarge {
            maximum: MAX_TOKEN_BYTES,
            actual: token.len(),
        });
    }
    Ok(token)
}

/// Split an IAKERB-mechanism token into its token id and body (MIT
/// `g_verify_token_header`).
///
/// # Errors
///
/// Returns [`Error::TokenTooLarge`] above the token bound, [`Error::BadToken`]
/// for a frame that is not a definite-length application 0 element holding
/// exactly the token, and [`Error::NotIakerb`] for another mechanism.
fn unframe(bytes: &[u8]) -> Result<([u8; 2], &[u8]), Error> {
    if bytes.len() > MAX_TOKEN_BYTES {
        return Err(Error::TokenTooLarge {
            maximum: MAX_TOKEN_BYTES,
            actual: bytes.len(),
        });
    }
    let malformed = Error::BadToken("not a GSS-API initial context token");
    let (&tag, rest) = bytes.split_first().ok_or(malformed)?;
    let (&first, rest) = rest
        .split_first()
        .ok_or(Error::BadToken("not a GSS-API initial context token"))?;
    let (length, content) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 3 {
            return Err(Error::BadToken("an unsupported DER length"));
        }
        let (digits, content) = rest
            .split_at_checked(count)
            .ok_or(Error::BadToken("a truncated DER length"))?;
        (
            digits
                .iter()
                .fold(0_usize, |length, digit| (length << 8_u32) | usize::from(*digit)),
            content,
        )
    };
    if tag != 0x60 || content.len() != length {
        return Err(Error::BadToken("not a GSS-API initial context token"));
    }
    let after_oid = content
        .strip_prefix(&MECHANISM_DER)
        .ok_or(if content.first() == Some(&0x06) {
            Error::NotIakerb("another mechanism")
        } else {
            Error::BadToken("no mechanism identifier")
        })?;
    let (id, body) = after_oid
        .split_first_chunk::<2>()
        .ok_or(Error::BadToken("no token id"))?;
    Ok((*id, body))
}
