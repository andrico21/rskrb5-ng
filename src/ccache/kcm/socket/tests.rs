//! The ownership rule of the daemon socket.

use std::io;

use super::{Trust, judge};
use crate::{
    error::{Kcm as Error, KcmRefusal},
    file_name,
};

/// A user that is neither root nor the user running the test is refused with
/// its id, or with the identity refusal where this process's user cannot be
/// read; root and a named user pass.
#[test]
fn a_stranger_is_refused_unless_named() -> Result<(), io::Error> {
    let own = file_name::process_identity().map(|(_real, effective)| effective);
    let stranger = match own {
        Ok(12_345) => 12_346_u32,
        Ok(_) | Err(_) => 12_345_u32,
    };
    let refusal = KcmRefusal::UntrustedOwner { uid: stranger };
    match (judge(&Trust::new(), stranger, refusal), own.is_ok()) {
        (Err(Error::Untrusted(KcmRefusal::UntrustedOwner { uid })), true) => {
            assert_eq!(uid, stranger, "the refusal names the owner");
        }
        (Err(Error::Untrusted(KcmRefusal::IdentityUnavailable)), false) => {}
        (other, _known) => return Err(io::Error::other(format!("{other:?}"))),
    }
    judge(&Trust::new().with_uid(stranger), stranger, refusal).map_err(io::Error::other)?;
    judge(&Trust::new(), 0, refusal).map_err(io::Error::other)?;
    Ok(())
}
