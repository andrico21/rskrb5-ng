//! Client referral and `[capaths]` routing on the sans-I/O TGS engine.
//!
//! FU-IOP-P12: a KDC referral answering a request for the service is followed
//! to the realm it names, for the service (MIT 1.22.2 `get_creds.c:561-634`);
//! the client path of `[capaths]` is crossed farthest first and backed off
//! hop by hop on a KDC error (`get_creds.c:889-977`); a referral loop stops.

use std::time::SystemTime;

use rskrb5_ng::{
    client::{
        options::TgsReq,
        principal::Principal,
        stepwise::{ExchangeStep, StepInput, TicketCreds, TicketOptions},
    },
    config::Config,
    error::Client as ClientError,
    routing::RealmPath,
};

use crate::{
    TestError,
    kdc::{answer, key_for, refuse, request_of, tgs, tgt},
};

/// KDC error code of an unknown server principal.
const KDC_ERR_S_PRINCIPAL_UNKNOWN: i32 = 7;

/// The request template of every exchange.
fn options() -> TicketOptions {
    TicketOptions::new(TgsReq::new(SystemTime::now(), 0x0102_0304).with_etypes(vec![18_i32]))
}

/// FU-IOP-P12: a service referral is followed to the realm it names.
///
/// A request for the service that a KDC answers with a referral TGT continues
/// with a request for the same service at the referred realm, not with a
/// cross-realm TGT request back to the service's original realm.
#[test]
fn service_referral_is_followed_to_the_referred_realm() -> Result<(), TestError> {
    // Given a USER.TEST TGT and a service named in USER.TEST that lives in RES.TEST.
    let service = Principal::new("USER.TEST", 2, ["HTTP", "host.res.test"]);
    let mut exchange = TicketCreds::new(tgt("USER.TEST")?, service, options())?;
    let first = exchange.step(StepInput::Start)?;
    let (first_realm, first_requested, _) = request_of(&first)?;
    assert_eq!(first_realm, "USER.TEST");
    assert_eq!(first_requested.components, ["HTTP", "host.res.test"]);
    // When the USER.TEST KDC refers the request to RES.TEST.
    let second = answer(
        &mut exchange,
        &first,
        &key_for("USER.TEST"),
        &tgs("USER.TEST", "RES.TEST"),
    )?;
    // Then the next request asks the RES.TEST KDC for the service itself.
    let (realm, requested, _) = request_of(&second)?;
    assert_eq!(realm, "RES.TEST");
    assert_eq!(
        requested,
        Principal::new("RES.TEST", 2, ["HTTP", "host.res.test"])
    );
    // And the service ticket the RES.TEST KDC issues completes the exchange.
    let issued = Principal::new("RES.TEST", 2, ["HTTP", "host.res.test"]);
    let ExchangeStep::Complete(ticket) =
        answer(&mut exchange, &second, &key_for("RES.TEST"), &issued)?
    else {
        return Err("expected the service ticket".into());
    };
    assert_eq!(ticket.service(), &issued);
    assert_eq!(exchange.referral_tgts().len(), 1);
    Ok(())
}

/// A service referral back to a realm the exchange already visited is a loop
/// and stops the exchange (`get_creds.c:612-614`).
#[test]
fn service_referral_loop_is_refused() -> Result<(), TestError> {
    // Given a service request referred from USER.TEST to RES.TEST.
    let service = Principal::new("USER.TEST", 2, ["HTTP", "host.res.test"]);
    let mut exchange =
        TicketCreds::new(tgt("USER.TEST")?, service, options().with_max_referrals(5))?;
    let first = exchange.step(StepInput::Start)?;
    let second = answer(
        &mut exchange,
        &first,
        &key_for("USER.TEST"),
        &tgs("USER.TEST", "RES.TEST"),
    )?;
    // When RES.TEST refers it back to USER.TEST.
    let looped = answer(
        &mut exchange,
        &second,
        &key_for("RES.TEST"),
        &tgs("RES.TEST", "USER.TEST"),
    );
    // Then the loop is named.
    assert!(
        matches!(&looped, Err(error) if error.to_string().contains("referral loop")),
        "{looped:?}"
    );
    Ok(())
}

/// The client path of `[capaths]` (TEST -> OTHER -> FAR) is crossed farthest
/// first: a KDC that cannot issue the far TGT is asked for the next hop, and
/// the exchange continues from the hop it reached.
#[test]
fn capaths_path_backs_off_to_the_configured_hop() -> Result<(), TestError> {
    // Given a client path from the profile and a TEST.RSKRB5 TGT.
    let config = Config::parse("[capaths]\n TEST.RSKRB5 = {\n  FAR.EXAMPLE = OTHER.RSKRB5\n }\n")?;
    let path = RealmPath::client(&config.capaths, "TEST.RSKRB5", "FAR.EXAMPLE")?;
    let service = Principal::new("FAR.EXAMPLE", 2, ["HTTP", "http.far.example"]);
    let mut exchange = TicketCreds::new(
        tgt("TEST.RSKRB5")?,
        service.clone(),
        options().with_realm_path(path),
    )?;
    // When the TEST KDC refuses the far TGT.
    let first = exchange.step(StepInput::Start)?;
    assert_eq!(request_of(&first)?.1, tgs("TEST.RSKRB5", "FAR.EXAMPLE"));
    let second = refuse(&mut exchange, &first, KDC_ERR_S_PRINCIPAL_UNKNOWN)??;
    // Then it asks for the next hop, then from there for the far realm, then for the service.
    assert_eq!(request_of(&second)?.1, tgs("TEST.RSKRB5", "OTHER.RSKRB5"));
    let third = answer(
        &mut exchange,
        &second,
        &key_for("TEST.RSKRB5"),
        &tgs("TEST.RSKRB5", "OTHER.RSKRB5"),
    )?;
    let (realm, requested, _) = request_of(&third)?;
    assert_eq!(
        (realm.as_str(), requested),
        ("OTHER.RSKRB5", tgs("OTHER.RSKRB5", "FAR.EXAMPLE"))
    );
    let fourth = answer(
        &mut exchange,
        &third,
        &key_for("OTHER.RSKRB5"),
        &tgs("OTHER.RSKRB5", "FAR.EXAMPLE"),
    )?;
    let (fourth_realm, fourth_requested, _) = request_of(&fourth)?;
    assert_eq!(fourth_realm, "FAR.EXAMPLE");
    assert_eq!(fourth_requested, service);
    let ExchangeStep::Complete(ticket) =
        answer(&mut exchange, &fourth, &key_for("FAR.EXAMPLE"), &service)?
    else {
        return Err("expected the service ticket".into());
    };
    assert_eq!(ticket.service(), &service);
    assert_eq!(exchange.referral_tgts().len(), 2);
    Ok(())
}

/// Without a configured path the client asks for the service realm's TGT
/// directly, and a KDC error ends the exchange (`walk_rtree.c:106-110`).
#[test]
fn direct_path_stops_on_a_kdc_error() -> Result<(), TestError> {
    // Given a TEST.RSKRB5 TGT and a FAR.EXAMPLE service without a configured path.
    let service = Principal::new("FAR.EXAMPLE", 2, ["HTTP", "http.far.example"]);
    let mut exchange = TicketCreds::new(tgt("TEST.RSKRB5")?, service, options())?;
    let first = exchange.step(StepInput::Start)?;
    // When the TEST KDC refuses the far TGT.
    let refused = refuse(&mut exchange, &first, KDC_ERR_S_PRINCIPAL_UNKNOWN)?;
    // Then the KDC error is returned.
    assert!(
        matches!(&refused, Err(ClientError::Kdc(error)) if error.error_code() == KDC_ERR_S_PRINCIPAL_UNKNOWN),
        "{refused:?}"
    );
    Ok(())
}

/// The `[capaths]` back-off ends at the hop next to the client's realm
/// (`get_creds.c:923-932`): when the KDC refuses that TGT too, no closer realm
/// is left and its error is returned.
#[test]
fn capaths_back_off_stops_at_the_nearest_hop() -> Result<(), TestError> {
    // Given the client path TEST -> OTHER -> FAR and a TEST.RSKRB5 TGT.
    let config = Config::parse("[capaths]\n TEST.RSKRB5 = {\n  FAR.EXAMPLE = OTHER.RSKRB5\n }\n")?;
    let path = RealmPath::client(&config.capaths, "TEST.RSKRB5", "FAR.EXAMPLE")?;
    let service = Principal::new("FAR.EXAMPLE", 2, ["HTTP", "http.far.example"]);
    let mut exchange =
        TicketCreds::new(tgt("TEST.RSKRB5")?, service, options().with_realm_path(path))?;
    let first = exchange.step(StepInput::Start)?;
    let second = refuse(&mut exchange, &first, KDC_ERR_S_PRINCIPAL_UNKNOWN)??;
    assert_eq!(request_of(&second)?.1, tgs("TEST.RSKRB5", "OTHER.RSKRB5"));
    // When the TEST KDC refuses the TGT of the nearest hop as well.
    let refused = refuse(&mut exchange, &second, KDC_ERR_S_PRINCIPAL_UNKNOWN)?;
    // Then its error ends the exchange.
    assert!(
        matches!(&refused, Err(ClientError::Kdc(error)) if error.error_code() == KDC_ERR_S_PRINCIPAL_UNKNOWN),
        "{refused:?}"
    );
    Ok(())
}
