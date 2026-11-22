// Assembling and signing a PAC, included into `pac`.
//
// MIT 1.22.2 `krb5_pac_init`, `krb5_pac_add_buffer` (`src/lib/krb5/krb/pac.c:40-110`) and
// `sign_pac` (`pac_sign.c:187-283`) are the model: a buffer type occurs once, at most 4096 buffers,
// every buffer is padded to eight bytes, and the signatures are written last: the full checksum
// over the PAC with all three signatures zero, the server checksum over the PAC with the server and
// KDC signatures zero, the KDC checksum over the server signature. KDC issuance policy (which
// groups a PAC lists, which tickets get one) stays outside this library (D1).

/// Signature buffer types a builder recreates at signing time.
const SIGNATURE_TYPES: [u32; 4] = [
    INFO_TYPE_PAC_SERVER_SIGNATURE_DATA,
    INFO_TYPE_PAC_KDC_SIGNATURE_DATA,
    INFO_TYPE_PAC_TICKET_SIGNATURE_DATA,
    INFO_TYPE_PAC_FULL_SIGNATURE_DATA,
];

/// The keys, client and ticket data a PAC is signed with.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Signing<'keys> {
    /// The service key: server signature.
    server_key: &'keys EncryptionKey,
    /// The KDC key: KDC signature, ticket signature and full checksum.
    kdc_key: &'keys EncryptionKey,
    /// The client whose info the PAC carries (added, or validated when present).
    client: Option<ClientBinding>,
    /// The ticket re-encoded with its PAC replaced by one zero byte.
    ticket_signature_input: Option<&'keys [u8]>,
    /// The kind of ticket that will carry the PAC.
    ticket_kind: TicketKind,
}

impl<'keys> Signing<'keys> {
    /// Sign with the service key and the KDC key.
    #[inline]
    #[must_use]
    pub const fn new(server_key: &'keys EncryptionKey, kdc_key: &'keys EncryptionKey) -> Self {
        Self {
            server_key,
            kdc_key,
            client: None,
            ticket_signature_input: None,
            ticket_kind: TicketKind::Service,
        }
    }

    /// Add the client info for this client, or check it when the PAC has one.
    #[inline]
    #[must_use]
    pub fn with_client(mut self, client: ClientBinding) -> Self {
        self.client = Some(client);
        self
    }

    /// Supply the bytes the ticket signature covers, from [`ticket_signature_input`].
    #[inline]
    #[must_use]
    pub const fn with_ticket_signature_input(mut self, input: &'keys [u8]) -> Self {
        self.ticket_signature_input = Some(input);
        self
    }

    /// Set the kind of the ticket (default [`TicketKind::Service`]).
    #[inline]
    #[must_use]
    pub const fn with_ticket_kind(mut self, kind: TicketKind) -> Self {
        self.ticket_kind = kind;
        self
    }
}

/// A PAC under construction: typed buffers, each at most once.
#[derive(Clone, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct Builder {
    /// The buffers in table order.
    buffers: Vec<(u32, Zeroizing<Vec<u8>>)>,
}

impl fmt::Debug for Builder {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let types: Vec<u32> = self.buffers.iter().map(|(ul_type, _)| *ul_type).collect();
        f.debug_struct("Builder")
            .field("buffer_types", &types)
            .finish()
    }
}

impl Builder {
    /// An empty PAC (MIT `krb5_pac_init`).
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buffers: Vec::new(),
        }
    }

    /// Start from the buffers of `pac`, except its signatures, which signing recreates.
    ///
    /// # Errors
    ///
    /// Returns the buffer-range errors of [`Pac::buffer_bytes`].
    #[inline]
    pub fn from_pac(pac: &Pac) -> Result<Self, Error> {
        let mut builder = Self::new();
        for buffer in pac.buffers() {
            if !SIGNATURE_TYPES.contains(&buffer.ul_type) {
                builder.add_buffer(buffer.ul_type, pac.buffer_bytes(buffer)?)?;
            }
        }
        Ok(builder)
    }

    /// Add a buffer (MIT `krb5_pac_add_buffer`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::DuplicateBuffer`] when the type is present, [`Error::BufferCountLimit`] at
    /// 4096 buffers and [`Error::LengthOverflow`] for a buffer longer than `u32::MAX`.
    #[inline]
    pub fn add_buffer(&mut self, ul_type: u32, data: &[u8]) -> Result<(), Error> {
        if self.buffer(ul_type).is_some() {
            return Err(Error::DuplicateBuffer(ul_type));
        }
        let count =
            u32::try_from(self.buffers.len()).map_err(|_out_of_range| Error::LengthOverflow)?;
        if count >= MAX_PAC_BUFFERS {
            return Err(Error::BufferCountLimit(count.saturating_add(1)));
        }
        if u32::try_from(data.len()).is_err() {
            return Err(Error::LengthOverflow);
        }
        self.buffers.push((ul_type, Zeroizing::new(data.to_vec())));
        Ok(())
    }

    /// Remove the buffer of a type; `true` when there was one.
    #[inline]
    pub fn remove_buffer(&mut self, ul_type: u32) -> bool {
        let before = self.buffers.len();
        self.buffers.retain(|(kind, _)| *kind != ul_type);
        self.buffers.len() != before
    }

    /// The types of the buffers, in table order (MIT `krb5_pac_get_types`).
    #[inline]
    #[must_use]
    pub fn buffer_types(&self) -> Vec<u32> {
        self.buffers.iter().map(|(ul_type, _)| *ul_type).collect()
    }

    /// The data of the buffer of a type.
    #[inline]
    #[must_use]
    pub fn buffer(&self, ul_type: u32) -> Option<&[u8]> {
        self.buffers
            .iter()
            .find(|(kind, _)| *kind == ul_type)
            .map(|(_, data)| data.as_slice())
    }

    /// Add, or check, the client info, then the signatures, and return the signed PAC
    /// (MIT `krb5_pac_sign_ext`, and for a [`TicketKind::Service`] ticket
    /// `krb5_kdc_sign_ticket`'s ticket signature and full checksum).
    ///
    /// # Errors
    ///
    /// Returns [`Error::ClientInfoMismatch`] when the PAC already has client info for another
    /// client, [`Error::MissingVerificationKey`] when a service ticket's signature input is
    /// missing, [`Error::UnsupportedEncryptionType`] or a policy rejection for a key that cannot
    /// sign, and the layout and parse errors of the result.
    #[inline]
    pub fn sign(mut self, request: &Signing<'_>) -> Result<Pac, Error> {
        if let Some(client) = &request.client {
            self.ensure_client_info(client)?;
        }
        self.buffers
            .retain(|(kind, _)| !SIGNATURE_TYPES.contains(kind));
        let server = signing_etype(request.server_key)?;
        let kdc = signing_etype(request.kdc_key)?;
        let service = request.ticket_kind.expects_ticket_signature();
        if service {
            let input = request
                .ticket_signature_input
                .ok_or(Error::MissingVerificationKey("ticket signature input"))?;
            let signature = signature_buffer(kdc, &sign_bytes(kdc, request.kdc_key, input)?)?;
            self.add_buffer(INFO_TYPE_PAC_TICKET_SIGNATURE_DATA, &signature)?;
        }
        self.add_buffer(
            INFO_TYPE_PAC_SERVER_SIGNATURE_DATA,
            &signature_buffer(server, &vec![0; server.hmac_len()])?,
        )?;
        self.add_buffer(
            INFO_TYPE_PAC_KDC_SIGNATURE_DATA,
            &signature_buffer(kdc, &vec![0; kdc.hmac_len()])?,
        )?;
        if service {
            self.add_buffer(
                INFO_TYPE_PAC_FULL_SIGNATURE_DATA,
                &signature_buffer(kdc, &vec![0; kdc.hmac_len()])?,
            )?;
        }
        let mut bytes = self.encode()?;
        if service {
            let full = sign_bytes(kdc, request.kdc_key, &bytes)?;
            write_signature(&mut bytes, INFO_TYPE_PAC_FULL_SIGNATURE_DATA, &full)?;
        }
        let server_signature = sign_bytes(server, request.server_key, &bytes)?;
        write_signature(
            &mut bytes,
            INFO_TYPE_PAC_SERVER_SIGNATURE_DATA,
            &server_signature,
        )?;
        let kdc_signature = sign_bytes(kdc, request.kdc_key, &server_signature)?;
        write_signature(&mut bytes, INFO_TYPE_PAC_KDC_SIGNATURE_DATA, &kdc_signature)?;
        Pac::parse_and_process(&bytes)
    }

    /// Sign the PAC for `ticket` and put it into the ticket's authorization data, as the first
    /// element (MIT `krb5_kdc_sign_ticket`, `pac_sign.c:315-395`).
    ///
    /// For a [`TicketKind::Service`] ticket the ticket signature covers the ticket with a dummy PAC
    /// in the place the signed PAC takes, so `request` needs no signature input. The ticket is
    /// changed only when signing succeeds.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Builder::sign`], [`ticket_signature_input`] and
    /// [`Error::DerEncode`].
    #[cfg(feature = "messages")]
    #[inline]
    pub fn sign_ticket(
        self,
        ticket: &mut rasn_kerberos::EncTicketPart,
        request: &Signing<'_>,
    ) -> Result<(), Error> {
        let rest = ticket.authorization_data.clone().unwrap_or_default();
        let mut staged = ticket.clone();
        staged.authorization_data = Some(pac_first(&rest, &[TICKET_SIGNATURE_PLACEHOLDER])?);
        let covered = ticket_signature_input(&staged)?;
        let pac = self.sign(&request.clone().with_ticket_signature_input(&covered))?;
        ticket.authorization_data = Some(pac_first(&rest, pac.data())?);
        Ok(())
    }

    /// Add the client info of `client`, or check the existing one against it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ClientInfoMismatch`] for another client or time (or a time no `FILETIME`
    /// holds) and the client-info parse errors.
    fn ensure_client_info(&mut self, client: &ClientBinding) -> Result<(), Error> {
        let ticks = client.auth_ticks.ok_or(Error::ClientInfoMismatch)?;
        if let Some(existing) = self.buffer(INFO_TYPE_PAC_CLIENT_INFO) {
            let info = ClientInfo::parse(existing)?;
            return (info.name == client.name && info.client_id.ticks() == ticks)
                .then_some(())
                .ok_or(Error::ClientInfoMismatch);
        }
        let name: Vec<u8> = client
            .name
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let name_len = u16::try_from(name.len()).map_err(|_out_of_range| Error::LengthOverflow)?;
        let mut data = ticks.to_le_bytes().to_vec();
        data.extend_from_slice(&name_len.to_le_bytes());
        data.extend_from_slice(&name);
        self.add_buffer(INFO_TYPE_PAC_CLIENT_INFO, &data)
    }

    /// The PAC wire bytes: header, table and the buffers, each padded to eight bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] when a length or offset does not fit its field.
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let count =
            u32::try_from(self.buffers.len()).map_err(|_out_of_range| Error::LengthOverflow)?;
        let header_len = PAC_HEADER_LEN
            .checked_add(
                self.buffers
                    .len()
                    .checked_mul(PAC_INFO_BUFFER_LEN)
                    .ok_or(Error::LengthOverflow)?,
            )
            .ok_or(Error::LengthOverflow)?;
        let mut out = Zeroizing::new(Vec::new());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&0_u32.to_le_bytes());
        let mut offset = header_len;
        for (ul_type, data) in &self.buffers {
            out.extend_from_slice(&ul_type.to_le_bytes());
            out.extend_from_slice(
                &u32::try_from(data.len())
                    .map_err(|_out_of_range| Error::LengthOverflow)?
                    .to_le_bytes(),
            );
            out.extend_from_slice(
                &u64::try_from(offset)
                    .map_err(|_out_of_range| Error::LengthOverflow)?
                    .to_le_bytes(),
            );
            offset = offset
                .checked_add(data.len().next_multiple_of(8))
                .ok_or(Error::LengthOverflow)?;
        }
        for (_, data) in &self.buffers {
            out.extend_from_slice(data);
            let padded = out.len().next_multiple_of(8);
            out.resize(padded, 0);
        }
        Ok(out)
    }
}

/// Write `signature` into the signature buffer of `ul_type` of the encoded `bytes`.
///
/// # Errors
///
/// Returns [`Error::MissingRequiredBuffer`] or the buffer-range errors.
fn write_signature(bytes: &mut [u8], ul_type: u32, signature: &[u8]) -> Result<(), Error> {
    let (offset, len) = Pac::parse(bytes)?
        .buffer(ul_type)
        .ok_or(Error::MissingRequiredBuffer("signature"))?
        .offset_and_len()?;
    let start = offset
        .checked_add(PAC_SIGNATURE_TYPE_LEN)
        .ok_or(Error::LengthOverflow)?;
    let end = start
        .checked_add(signature.len())
        .ok_or(Error::LengthOverflow)?;
    let limit = offset.checked_add(len).ok_or(Error::LengthOverflow)?;
    let target =
        bytes
            .get_mut(start..end)
            .filter(|_| end <= limit)
            .ok_or(Error::BufferOutOfBounds {
                ul_type,
                offset: u64::try_from(offset).map_err(|_out_of_range| Error::LengthOverflow)?,
                len: u32::try_from(len).map_err(|_out_of_range| Error::LengthOverflow)?,
                total_len: end,
            })?;
    target.copy_from_slice(signature);
    Ok(())
}

/// The checksum profile of a signing key.
///
/// # Errors
///
/// Returns a policy rejection for a rejected enctype and [`Error::UnsupportedEncryptionType`].
fn signing_etype(key: &EncryptionKey) -> Result<KerberosEtype, Error> {
    selection::enctype(key.etype())?.ok_or_else(|| Error::UnsupportedEncryptionType(key.etype()))
}

/// The keyed checksum of `data` under `key` (key usage 17).
///
/// # Errors
///
/// Returns the crypto error of the checksum.
fn sign_bytes(etype: KerberosEtype, key: &EncryptionKey, data: &[u8]) -> Result<Vec<u8>, Error> {
    Ok(etype.checksum(key.value(), data, PAC_SERVER_CHECKSUM_KEY_USAGE)?)
}

/// A signature buffer: the PAC checksum type of `etype` and `signature`.
///
/// # Errors
///
/// Returns [`Error::UnsupportedChecksumType`] when the checksum type has no PAC number.
fn signature_buffer(etype: KerberosEtype, signature: &[u8]) -> Result<Vec<u8>, Error> {
    let id = etype.checksum_type_id();
    let number = if id == -138_i32 {
        CHECKSUM_HMAC_MD5_UNSIGNED
    } else {
        u32::try_from(id).map_err(|_out_of_range| Error::UnsupportedChecksumType(0))?
    };
    let mut out = number.to_le_bytes().to_vec();
    out.extend_from_slice(signature);
    Ok(out)
}

/// `rest` with an `AD-IF-RELEVANT` element holding a PAC element of `pac` bytes put first.
///
/// # Errors
///
/// Returns [`Error::DerEncode`] when the wrapper cannot be encoded.
#[cfg(feature = "messages")]
fn pac_first(
    rest: &rasn_kerberos::AuthorizationData,
    pac: &[u8],
) -> Result<rasn_kerberos::AuthorizationData, Error> {
    let nested =
        rasn_kerberos::AuthorizationData::from(vec![rasn_kerberos::AuthorizationDataValue {
            r#type: AD_WIN2K_PAC,
            data: pac.to_vec().into(),
        }]);
    let wrapper = rasn_kerberos::AuthorizationDataValue {
        r#type: AD_IF_RELEVANT,
        data: der_encode(&nested)
            .map_err(|source| Error::DerEncode(source.to_string()))?
            .into(),
    };
    let mut out = vec![wrapper];
    out.extend(rest.iter().cloned());
    Ok(rasn_kerberos::AuthorizationData::from(out))
}
