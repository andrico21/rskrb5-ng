//! Names and credential requests of the adapter client.

use zeroize::Zeroizing;

/// A GSS name with the type byte the adapter understands.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Name {
    /// `h` host-based service, `p` Kerberos principal, `e` enterprise, `u` user.
    kind: u8,
    /// The name text; empty means "no name" (the default credential name).
    text: String,
}

impl Name {
    /// A host-based service name, `service@host`.
    pub(crate) fn hostbased(text: &str) -> Self {
        Self {
            kind: b'h',
            text: text.to_owned(),
        }
    }

    /// A Kerberos principal name, `primary/instance@REALM`.
    pub(crate) fn principal(text: &str) -> Self {
        Self {
            kind: b'p',
            text: text.to_owned(),
        }
    }

    /// An enterprise name (IAKERB realm discovery uses one without realm).
    pub(crate) fn enterprise(text: &str) -> Self {
        Self {
            kind: b'e',
            text: text.to_owned(),
        }
    }

    /// No name: the credential's default.
    pub(crate) const fn default_name() -> Self {
        Self {
            kind: b'p',
            text: String::new(),
        }
    }

    /// The two request fields of the name: type byte and text.
    pub(crate) fn fields(&self) -> ([u8; 1], &[u8]) {
        ([self.kind], self.text.as_bytes())
    }
}

/// What a credential is acquired for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Usage {
    /// `GSS_C_INITIATE`.
    Initiate,
    /// `GSS_C_ACCEPT`.
    Accept,
}

impl Usage {
    /// The wire byte.
    pub(crate) const fn byte(self) -> u8 {
        match self {
            Self::Initiate => b'i',
            Self::Accept => b'a',
        }
    }
}

/// Where the credential's secret comes from.
#[derive(Debug)]
pub(crate) enum Source {
    /// The adapter's default credential cache or keytab.
    Default,
    /// A keytab delivered to the container, by id (`peeruser`, `acceptor`).
    Keytab(String),
    /// A password sent in the frame (`gss_acquire_cred_with_password`).
    Password(Zeroizing<Vec<u8>>),
}

/// A request to acquire a credential.
#[derive(Debug)]
pub(crate) struct CredRequest {
    /// Initiate or accept.
    usage: Usage,
    /// The credential's name.
    name: Name,
    /// Dotted OIDs of the mechanisms; empty means the default set.
    mechs: Vec<String>,
    /// The secret's source.
    source: Source,
}

impl CredRequest {
    /// A default-name, default-mechanism, default-source credential.
    pub(crate) const fn new(usage: Usage) -> Self {
        Self {
            usage,
            name: Name::default_name(),
            mechs: Vec::new(),
            source: Source::Default,
        }
    }

    /// Names the credential.
    #[must_use]
    pub(crate) fn named(mut self, name: Name) -> Self {
        self.name = name;
        self
    }

    /// Restricts the credential to the dotted OIDs `mechs`.
    #[must_use]
    pub(crate) fn with_mechs(mut self, mechs: &[&str]) -> Self {
        self.mechs = mechs.iter().map(|oid| (*oid).to_owned()).collect();
        self
    }

    /// Takes the secret from the container keytab `id`.
    #[must_use]
    pub(crate) fn with_keytab(mut self, id: &str) -> Self {
        self.source = Source::Keytab(id.to_owned());
        self
    }

    /// Takes the secret from `password`.
    #[must_use]
    pub(crate) fn with_password(mut self, password: &[u8]) -> Self {
        self.source = Source::Password(Zeroizing::new(password.to_vec()));
        self
    }

    /// The six request fields.
    pub(crate) fn fields(&self) -> Vec<Vec<u8>> {
        let (kind, text) = self.name.fields();
        let (source, argument) = match &self.source {
            Source::Default => ("default", Vec::new()),
            Source::Keytab(id) => ("keytab", id.as_bytes().to_vec()),
            Source::Password(password) => ("password", password.to_vec()),
        };
        vec![
            vec![self.usage.byte()],
            kind.to_vec(),
            text.to_vec(),
            self.mechs.join(",").into_bytes(),
            source.as_bytes().to_vec(),
            argument,
        ]
    }
}
