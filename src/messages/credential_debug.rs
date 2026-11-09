//! Redact credential payloads while retaining message metadata.

use core::fmt;

use super::{EncryptedData, KrbErrorInfo, PaForUser, PaReqEncPaRep};

impl fmt::Debug for KrbErrorInfo {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            ctime,
            cusec,
            stime,
            susec,
            error_code,
            client,
            service,
            e_text,
            e_data,
        } = self;
        f.debug_struct("KrbErrorInfo")
            .field("ctime", ctime)
            .field("cusec", cusec)
            .field("stime", stime)
            .field("susec", susec)
            .field("error_code", error_code)
            .field("client", client)
            .field("service", service)
            .field("e_text_len", &e_text.as_ref().map(String::len))
            .field("e_data_len", &e_data.as_ref().map(|bytes| bytes.len()))
            .finish()
    }
}

impl fmt::Debug for EncryptedData {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            etype,
            kvno,
            cipher,
        } = self;
        f.debug_struct("EncryptedData")
            .field("etype", etype)
            .field("kvno", kvno)
            .field("cipher_len", &cipher.len())
            .finish()
    }
}

impl fmt::Debug for PaForUser {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            user_name,
            user_realm,
            cksum,
            auth_package,
        } = self;
        f.debug_struct("PaForUser")
            .field("user_name", user_name)
            .field("user_realm", user_realm)
            .field("checksum_type", &cksum.r#type)
            .field("auth_package", auth_package)
            .finish()
    }
}

impl fmt::Debug for PaReqEncPaRep {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            checksum_type,
            checksum,
        } = self;
        f.debug_struct("PaReqEncPaRep")
            .field("checksum_type", checksum_type)
            .field("checksum_len", &checksum.len())
            .finish()
    }
}
