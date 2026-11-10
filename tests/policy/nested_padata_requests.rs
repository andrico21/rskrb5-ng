use core::error::Error;
use std::time::SystemTime;

use rasn::der;
use rasn_kerberos::PaData;
use rskrb5_ng::{
    client::{self, BuiltAsReq, BuiltTgsReq, options::AsReq, principal::Principal},
    crypto::CryptoPolicy,
    kdc_req,
};

/// Bind exactly matching DER, then narrow the built request's policy.
pub(super) fn requests(data: Vec<PaData>) -> Result<(BuiltAsReq, BuiltTgsReq), Box<dyn Error>> {
    let mut as_request = client::build_tgt_as_req(
        Principal::user("EXAMPLE.COM", "alice"),
        AsReq::new(SystemTime::UNIX_EPOCH, 42)
            .with_etypes(vec![17_i32])
            .with_padata(data),
    )?;
    let message = kdc_req::build_tgs_req(
        as_request.message().0.req_body.clone(),
        as_request.message().0.padata.clone(),
    );
    let encoded = der::encode(&message)?;
    let mut tgs_request = BuiltTgsReq::new(
        message,
        encoded.into(),
        as_request.client().clone(),
        as_request.service().clone(),
        "EXAMPLE.COM".to_owned(),
        as_request.nonce(),
    );
    let policy = CryptoPolicy::from_libdefaults(&super::config()?.libdefaults)?;
    as_request.set_crypto_policy(policy.clone());
    tgs_request.set_crypto_policy(policy);
    Ok((as_request, tgs_request))
}
