//! Resolved storage with reviewed read-only method contracts.

/// These operations are read-only only on classified storage, never arbitrary receivers.
pub(super) const METHODS: &[&str] = &[
    "as_ref", "as_deref", "as_slice", "as_str", "clone", "to_vec", "len", "get", "iter", "values",
    "etype", "is_some", "is_none", "is_empty",
];

/// Unknown storage never inherits a read-only exemption from a method's spelling.
pub(super) fn classified(parts: &[String]) -> bool {
    parts.iter().all(|part| {
        matches!(
            part.as_str(),
            "std"
                | "core"
                | "alloc"
                | "vec"
                | "option"
                | "string"
                | "collections"
                | "Vec"
                | "Option"
                | "String"
                | "u8"
                | "Zeroizing"
                | "zeroize"
                | "HashMap"
                | "BTreeMap"
                | "TgsRepSession"
                | "AsRepSession"
                | "TokioClientCredentials"
                | "Principal"
                | "principal"
                | "EncryptionKey"
                | "Bytes"
                | "key_bytes"
                | "keytab"
                | "SessionKey"
                | "Secret"
                | "OctetString"
                | "rasn"
                | "types"
                | "crate"
                | "crypto"
                | "client"
                | "rasn_kerberos"
                | "ApRep"
                | "KrbPriv"
                | "Checksum"
        )
    })
}
