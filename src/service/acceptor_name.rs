/// Which ticket server principals a named GSS acceptor takes.
///
/// It applies before the keytab lookup (MIT 1.22.2 `kg_acceptor_princ`,
/// `naming_exts.c:136-168`, and `krb5_sname_match`, `sname_match.c:30-58`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AcceptorName {
    /// The realm; empty matches any.
    realm: String,
    /// The components; a host-based name's empty host matches any.
    components: Vec<String>,
    /// Whether the name is host-based (`service`, `host`).
    hostbased: bool,
    /// `ignore_acceptor_hostname`: a host-based name's host matches any.
    ignore_hostname: bool,
}

impl AcceptorName {
    /// The rule of an acceptor name.
    pub(crate) const fn new(
        realm: String,
        components: Vec<String>,
        hostbased: bool,
        ignore_hostname: bool,
    ) -> Self {
        Self {
            realm,
            components,
            hostbased,
            ignore_hostname,
        }
    }

    /// Whether a ticket for `realm` and `components` is for this acceptor.
    pub(crate) fn matches(&self, realm: &str, components: &[String]) -> bool {
        let (true, [service, host]) = (self.hostbased, self.components.as_slice()) else {
            return self.realm == realm && self.components == components;
        };
        let [ticket_service, ticket_host] = components else {
            return false;
        };
        (self.realm.is_empty() || self.realm == realm)
            && service == ticket_service
            && (host.is_empty() || self.ignore_hostname || host == ticket_host)
    }

    /// The rule as `components@realm`.
    pub(crate) fn display(&self) -> String {
        format!("{}@{}", self.components.join("/"), self.realm)
    }
}
