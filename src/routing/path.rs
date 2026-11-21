/// An ordered cross-realm path: the client realm, the intermediate realms in
/// the order a client crosses them, and the server realm.
///
/// [`Self::walk`] is MIT's `krb5_walk_realm_tree` (the acceptor's view, used to
/// check a transited list), [`Self::client`] MIT's `k5_client_realm_path` (the
/// order a client asks for cross-realm TGTs in), and [`Self::hierarchical`] the
/// walk through the common DNS-style suffix of the two realm names.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmPath {
    /// The realms from the client realm to the server realm, both included.
    realms: Vec<String>,
}

impl RealmPath {
    /// Most realms a path holds, the two endpoints included.
    pub const MAX_REALMS: usize = 32;

    /// The path MIT 1.22.2 checks a transited list against
    /// (`walk_rtree.c:65-91`): the `[capaths]` entry for the pair when the
    /// profile has one, otherwise the hierarchical path.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyRealm`] or [`Error::SameRealm`] for endpoints with
    /// no cross-realm path, [`Error::PathTooLong`] for a path past
    /// [`Self::MAX_REALMS`], and [`Error::PathLoop`] for a configured path that
    /// names a realm twice.
    #[inline]
    pub fn walk(capaths: &Capaths, client: &str, server: &str) -> Result<Self, Error> {
        Self::configured(capaths, client, server)?
            .map_or_else(|| Self::hierarchical(client, server), Ok)
    }

    /// The path a client crosses to reach `server` (`walk_rtree.c:93-142`): the
    /// `[capaths]` entry for the pair, otherwise the direct path. A client never
    /// guesses the hierarchy; a KDC refers it off a direct path instead.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::walk`].
    #[inline]
    pub fn client(capaths: &Capaths, client: &str, server: &str) -> Result<Self, Error> {
        Self::configured(capaths, client, server)?
            .map_or_else(|| Self::checked(vec![client.to_owned(), server.to_owned()]), Ok)
    }

    /// The `[capaths]` path for the pair, or `None` when the profile names none
    /// (`walk_rtree.c:229-291`; `.` is the direct path).
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::walk`].
    #[inline]
    pub fn configured(capaths: &Capaths, client: &str, server: &str) -> Result<Option<Self>, Error> {
        endpoints(client, server)?;
        let Some(route) = capaths.get(client).and_then(|servers| servers.get(server)) else {
            return Ok(None);
        };
        let mut realms = vec![client.to_owned()];
        match route {
            Route::Direct => {}
            Route::Via(hops) => {
                if hops.len() > Self::MAX_REALMS {
                    return Err(Error::PathTooLong {
                        max: Self::MAX_REALMS,
                    });
                }
                realms.extend(hops.iter().cloned());
            }
        }
        realms.push(server.to_owned());
        Self::checked(realms).map(Some)
    }

    /// The hierarchical path through the common suffix of the two realm names
    /// (`walk_rtree.c:344-613`): up the client's name to the common suffix, then
    /// down the server's name.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::walk`].
    #[inline]
    pub fn hierarchical(client: &str, server: &str) -> Result<Self, Error> {
        endpoints(client, server)?;
        let (client_tail, server_tail) = common_tail(client.as_bytes(), server.as_bytes());
        let mut realms = tweens(client, client_tail, true);
        let mut down = tweens(server, server_tail, false);
        down.reverse();
        realms.append(&mut down);
        Self::checked(realms)
    }

    /// The realms from the client realm to the server realm, both included.
    #[inline]
    #[must_use]
    pub fn realms(&self) -> &[String] {
        &self.realms
    }

    /// Whether every realm of a decoded transited list lies on this path before
    /// the server realm: MIT's acceptor check (`chk_trans.c:293-306,353`).
    #[inline]
    #[must_use]
    pub fn admits_transited(&self, transited: &[String]) -> bool {
        let issuers = self.realms.split_last().map_or(&[][..], |(_, rest)| rest);
        transited.iter().all(|realm| issuers.contains(realm))
    }

    /// Bound a path and refuse a loop.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PathTooLong`] or [`Error::PathLoop`].
    fn checked(realms: Vec<String>) -> Result<Self, Error> {
        if realms.len() > Self::MAX_REALMS {
            return Err(Error::PathTooLong {
                max: Self::MAX_REALMS,
            });
        }
        for (index, realm) in realms.iter().enumerate() {
            if realms.get(..index).is_some_and(|seen| seen.contains(realm)) {
                return Err(Error::PathLoop {
                    realm: realm.clone(),
                });
            }
        }
        Ok(Self { realms })
    }
}

/// Refuse endpoints with no cross-realm path between them.
///
/// # Errors
///
/// Returns [`Error::EmptyRealm`] or [`Error::SameRealm`].
fn endpoints(client: &str, server: &str) -> Result<(), Error> {
    if client.is_empty() || server.is_empty() {
        return Err(Error::EmptyRealm);
    }
    if client == server {
        return Err(Error::SameRealm);
    }
    Ok(())
}

/// The start of the common suffix in each name, moved to a component boundary
/// (MIT `comtail` and `adjtail`, `walk_rtree.c:515-613`), or `None` when the
/// names share no whole component.
fn common_tail(client: &[u8], server: &[u8]) -> (Option<usize>, Option<usize>) {
    let mut client_at = client.len();
    let mut server_at = server.len();
    let mut dots = None;
    while let (Some(left), Some(right)) = (client_at.checked_sub(1), server_at.checked_sub(1)) {
        if client.get(left) != server.get(right) {
            break;
        }
        client_at = left;
        server_at = right;
        if client.get(left) == Some(&b'.') {
            dots = Some((left, right));
        }
    }
    if client_at == client.len() {
        return (None, None);
    }
    let whole = |name: &[u8], at: usize| {
        at.checked_sub(1)
            .is_none_or(|before| name.get(before) == Some(&b'.'))
    };
    if whole(client, client_at) && whole(server, server_at) {
        return (Some(client_at), Some(server_at));
    }
    match dots {
        Some((client_dot, server_dot))
            if client_dot.saturating_add(1) < client.len()
                && server_dot.saturating_add(1) < server.len() =>
        {
            (
                Some(client_dot.saturating_add(1)),
                Some(server_dot.saturating_add(1)),
            )
        }
        _ => (None, None),
    }
}

/// The names from `realm` towards its common suffix.
///
/// MIT `rtree_hier_tweens` (`walk_rtree.c:466-513`): every suffix that starts a
/// component, the realm itself first; the suffix at `tail` is included only
/// when `with_tail` is set.
fn tweens(realm: &str, tail: Option<usize>, with_tail: bool) -> Vec<String> {
    let bytes = realm.as_bytes();
    let mut names = Vec::new();
    let mut start = 0_usize;
    for (index, &byte) in bytes.iter().enumerate() {
        if byte != b'.' && index.saturating_add(1) != bytes.len() {
            continue;
        }
        let at_tail = tail == Some(start);
        if at_tail && !with_tail {
            break;
        }
        if let Some(name) = realm.get(start..) {
            names.push(name.to_owned());
        }
        if at_tail {
            break;
        }
        start = index.saturating_add(1);
    }
    names
}
