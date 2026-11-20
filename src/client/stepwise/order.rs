//! MIT's `preferred_preauth_types` ordering.
//!
//! As `sort_krb5_padata_sequence` (`get_in_tkt.c:400-470`): each preferred type,
//! in preference order, moves its first offer to the front; the other offers
//! keep the KDC's order.

use rasn_kerberos::PaData;

/// The KDC's offers in MIT preference order.
pub(super) fn sorted<'offers>(
    offers: &'offers [PaData],
    preferred: &[i32],
) -> Vec<&'offers PaData> {
    let mut ordered: Vec<&PaData> = offers.iter().collect();
    let mut base = 0_usize;
    for pa_type in preferred {
        let found = ordered
            .get(base..)
            .and_then(|rest| rest.iter().position(|offer| offer.r#type == *pa_type));
        if let Some(position) = found {
            let index = base.saturating_add(position);
            let offer = ordered.remove(index);
            ordered.insert(base, offer);
            base = base.saturating_add(1);
        }
    }
    ordered
}
