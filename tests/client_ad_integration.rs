//! Live Active Directory integration tests.
//!
//! The tests log in to the gokrb5 AD fixture domains (USER.GOKRB5 and the
//! trusting RES.GOKRB5) with keytabs, and validate the service tickets and PACs
//! they obtain. They run only with `TESTAD=1`; `TESTAD_REQUIRED=1` turns a
//! skip into a failure. The keytab fixtures and the environment overrides of
//! the gate are tested without a domain.
#![cfg(feature = "tokio")]

use core::{error::Error, time::Duration};
use std::{
    env,
    ffi::OsStr,
    fs, io,
    net::{TcpListener, TcpStream, ToSocketAddrs as _},
    path::PathBuf,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use rskrb5_ng::{
    client::{
        AsRepSession, TgsRepSession, Tokio, build_ap_req_with_confounder, options::ApReq,
        principal::Principal, transport::KdcProtocol,
    },
    config::Config,
    crypto::{CryptoPolicy, KerberosEtype},
    keytab::Keytab,
    service::Validator,
};

/// Realm of the AD user domain.
const USER_REALM: &str = "USER.GOKRB5";

/// Realm of the AD resource domain that trusts the user domain.
const RESOURCE_REALM: &str = "RES.GOKRB5";

/// AD fixture user that logs in and requests the service tickets.
const TESTUSER1: &str = "testuser1";

/// User whose keytab also keys the user-realm HTTP service.
const TESTUSER2: &str = "testuser2";

/// User that does not require preauthentication.
const TESTUSER3: &str = "testuser3";

/// Account that keys the resource-realm HTTP service.
const SYSHTTP: &str = "sysHTTP";

/// Host of the HTTP service in the user realm.
const USER_SERVICE_HOST: &str = "user2.user.gokrb5";

/// Host of the HTTP service in the resource realm.
const RESOURCE_SERVICE_HOST: &str = "host.res.gokrb5";

/// Enctype id of aes128-cts-hmac-sha1-96.
const AES128_ETYPE: i32 = 17;

/// Enctype id of aes256-cts-hmac-sha1-96.
const AES256_ETYPE: i32 = 18;

/// Enctype id of rc4-hmac.
const RC4_HMAC_ETYPE: i32 = 23;

/// Enctypes every embedded AD keytab must hold.
const AD_FIXTURE_ETYPES: [i32; 3] = [AES128_ETYPE, AES256_ETYPE, RC4_HMAC_ETYPE];

/// Embedded keytab of testuser1@USER.GOKRB5.
const KEYTAB_TESTUSER1_USER_GOKRB5: &str = "05020000003b0001000b555345522e474f4b5242350009746573747573657231000000015e80c2750100170010084768c373663b3bef1f6385883cf7ff000000010000003b0001000b555345522e474f4b5242350009746573747573657231000000015e80c2750100110010528b8ba0ae5131fbf71f6ddc5870cdce000000010000004b0001000b555345522e474f4b5242350009746573747573657231000000015e80c275010012002016475f89eba70e62af20a20e7bf3ca4ccad5ae22485c93ffb133650bc6f12585000000010000003b0001000b555345522e474f4b5242350009746573747573657231000000015e80c2750100130010a3ddea306fa06c068bc3e1fcf4b280ca000000010000004b0001000b555345522e474f4b5242350009746573747573657231000000015e80c27501001400205d2a66a8af5142db59bcaabac8310777bf60a85e8881469e2063bba4dff0c00a000000010000003b0001000b555345522e474f4b5242350009746573747573657231000000015e80c2750200170010084768c373663b3bef1f6385883cf7ff000000020000003b0001000b555345522e474f4b5242350009746573747573657231000000015e80c2750200110010528b8ba0ae5131fbf71f6ddc5870cdce000000020000004b0001000b555345522e474f4b5242350009746573747573657231000000015e80c275020012002016475f89eba70e62af20a20e7bf3ca4ccad5ae22485c93ffb133650bc6f12585000000020000003b0001000b555345522e474f4b5242350009746573747573657231000000015e80c2750200130010a3ddea306fa06c068bc3e1fcf4b280ca000000020000004b0001000b555345522e474f4b5242350009746573747573657231000000015e80c27502001400205d2a66a8af5142db59bcaabac8310777bf60a85e8881469e2063bba4dff0c00a00000002";

/// Embedded keytab of testuser2@USER.GOKRB5.
const KEYTAB_TESTUSER2_USER_GOKRB5: &str = "05020000003b0001000b555345522e474f4b5242350009746573747573657232000000015e80b9f30100170010084768c373663b3bef1f6385883cf7ff000000010000003b0001000b555345522e474f4b5242350009746573747573657232000000015e80b9f30100110010a771a31fae504621fffc644a521e0cee000000010000004b0001000b555345522e474f4b5242350009746573747573657232000000015e80b9f301001200203262b201af7ec73c77bbee75a4ff10950cf2bda56529ead30ced4f0f0b9a591d000000010000003b0001000b555345522e474f4b5242350009746573747573657232000000015e80b9f301001300104be17a4cf1761f0494475617f671fa6a000000010000004b0001000b555345522e474f4b5242350009746573747573657232000000015e80b9f301001400208b1c60589b6c0d78d5e8fe265e92c2babf920a6a2828c37fc343e43497ad9fab000000010000003b0001000b555345522e474f4b5242350009746573747573657232000000015e80c30a0200170010084768c373663b3bef1f6385883cf7ff000000020000003b0001000b555345522e474f4b5242350009746573747573657232000000015e80c30a0200110010a771a31fae504621fffc644a521e0cee000000020000004b0001000b555345522e474f4b5242350009746573747573657232000000015e80c30a02001200203262b201af7ec73c77bbee75a4ff10950cf2bda56529ead30ced4f0f0b9a591d000000020000003b0001000b555345522e474f4b5242350009746573747573657232000000015e80c30a02001300104be17a4cf1761f0494475617f671fa6a000000020000004b0001000b555345522e474f4b5242350009746573747573657232000000015e80c30a02001400208b1c60589b6c0d78d5e8fe265e92c2babf920a6a2828c37fc343e43497ad9fab00000002";

/// Embedded keytab of testuser3@USER.GOKRB5.
const KEYTAB_TESTUSER3_USER_GOKRB5: &str = "05020000003b0001000b555345522e474f4b5242350009746573747573657233000000015e80ba950100170010084768c373663b3bef1f6385883cf7ff000000010000003b0001000b555345522e474f4b5242350009746573747573657233000000015e80ba95010011001025b79e18723ecd0fdf76c3a5bb21d5dd000000010000004b0001000b555345522e474f4b5242350009746573747573657233000000015e80ba950100120020c98c6dcc3ee520d5712aba339b2aa1930414b24fb52b9f70bf46259a57c1740b000000010000003b0001000b555345522e474f4b5242350009746573747573657233000000015e80ba95010013001007f06e524ee5d738b5bb464c876a5087000000010000004b0001000b555345522e474f4b5242350009746573747573657233000000015e80ba95010014002024cb938c683c9fcbe548f2febc93f8090fbaf44541751fc2b781e453dba36a11000000010000003b0001000b555345522e474f4b5242350009746573747573657233000000015e80c37d0200170010084768c373663b3bef1f6385883cf7ff000000020000003b0001000b555345522e474f4b5242350009746573747573657233000000015e80c37d020011001025b79e18723ecd0fdf76c3a5bb21d5dd000000020000004b0001000b555345522e474f4b5242350009746573747573657233000000015e80c37d0200120020c98c6dcc3ee520d5712aba339b2aa1930414b24fb52b9f70bf46259a57c1740b000000020000003b0001000b555345522e474f4b5242350009746573747573657233000000015e80c37d020013001007f06e524ee5d738b5bb464c876a5087000000020000004b0001000b555345522e474f4b5242350009746573747573657233000000015e80c37d020014002024cb938c683c9fcbe548f2febc93f8090fbaf44541751fc2b781e453dba36a1100000002";

/// Embedded keytab of sysHTTP@RES.GOKRB5.
const KEYTAB_SYSHTTP_RES_GOKRB5: &str = "0502000000380001000a5245532e474f4b524235000773797348545450000000015e7a7e2f0200170010084768c373663b3bef1f6385883cf7ff00000002000000380001000a5245532e474f4b524235000773797348545450000000015e7a7e2f0200110010c622e44a32022f4cb81775263151140d00000002000000480001000a5245532e474f4b524235000773797348545450000000015e7a7e2f02001200209da0dc4802bf5d375dfe2a77ddfc5065b3bf789126c2dc89ff4c2aa90dfa43ce00000002000000380001000a5245532e474f4b524235000773797348545450000000015e7a7e2f0200130010541beb216c1cdf22ef7c2225066a385e00000002000000480001000a5245532e474f4b524235000773797348545450000000015e7a7e2f02001400205f0983acd70fcaee0acb7ac4a14f8ad89f3a35915914e696200370637d8fef2300000002";

/// Serialises the AD tests, which share the live domain and the environment.
static AD_LOCK: Mutex<()> = Mutex::new(());

/// An embedded AD keytab fixture and the environment variables that override it.
#[derive(Clone, Copy)]
struct AdKeytabFixture {
    /// Principal the keytab belongs to, for messages.
    label: &'static str,
    /// Hex dump of the embedded keytab.
    default_hex: &'static str,
    /// Variable naming a keytab file that replaces the fixture.
    path_env: &'static str,
    /// Variable holding a hex keytab that replaces the fixture.
    hex_env: &'static str,
    /// Variable holding a base64 keytab that replaces the fixture.
    base64_env: &'static str,
}

/// The testuser1 keytab fixture and its overrides.
const TESTUSER1_KEYTAB: AdKeytabFixture = AdKeytabFixture {
    label: "testuser1@USER.GOKRB5",
    default_hex: KEYTAB_TESTUSER1_USER_GOKRB5,
    path_env: "TEST_AD_TESTUSER1_KEYTAB_PATH",
    hex_env: "TEST_AD_TESTUSER1_KEYTAB_HEX",
    base64_env: "TEST_AD_TESTUSER1_KEYTAB_BASE64",
};

/// The testuser2 keytab fixture and its overrides.
const TESTUSER2_KEYTAB: AdKeytabFixture = AdKeytabFixture {
    label: "testuser2@USER.GOKRB5",
    default_hex: KEYTAB_TESTUSER2_USER_GOKRB5,
    path_env: "TEST_AD_TESTUSER2_KEYTAB_PATH",
    hex_env: "TEST_AD_TESTUSER2_KEYTAB_HEX",
    base64_env: "TEST_AD_TESTUSER2_KEYTAB_BASE64",
};

/// The testuser3 keytab fixture and its overrides.
const TESTUSER3_KEYTAB: AdKeytabFixture = AdKeytabFixture {
    label: "testuser3@USER.GOKRB5",
    default_hex: KEYTAB_TESTUSER3_USER_GOKRB5,
    path_env: "TEST_AD_TESTUSER3_KEYTAB_PATH",
    hex_env: "TEST_AD_TESTUSER3_KEYTAB_HEX",
    base64_env: "TEST_AD_TESTUSER3_KEYTAB_BASE64",
};

/// The sysHTTP keytab fixture and its overrides.
const SYSHTTP_KEYTAB: AdKeytabFixture = AdKeytabFixture {
    label: "sysHTTP@RES.GOKRB5",
    default_hex: KEYTAB_SYSHTTP_RES_GOKRB5,
    path_env: "TEST_AD_SYSHTTP_KEYTAB_PATH",
    hex_env: "TEST_AD_SYSHTTP_KEYTAB_HEX",
    base64_env: "TEST_AD_SYSHTTP_KEYTAB_BASE64",
};

/// Wraps an AD gate or fixture failure `message` as an error.
fn ad_gate_error(message: String) -> Box<dyn Error> {
    io::Error::other(message).into()
}

/// Parses the keytab `bytes` loaded for fixture `label` from `source`.
///
/// # Errors
///
/// Returns an error naming `label` and `source` if the bytes are not a keytab.
fn parse_keytab_bytes(label: &str, source: &str, bytes: &[u8]) -> Result<Keytab, Box<dyn Error>> {
    Keytab::parse(bytes).map_err(|error| {
        ad_gate_error(format!(
            "failed to parse AD keytab {label} from {source}: {error}"
        ))
    })
}

/// Child-process runner for the tests that change the environment.
#[path = "support/env.rs"]
mod child_env;

/// Live Active Directory integration tests (gated on `TESTAD=1`), embedded
/// keytab fixtures and the environment overrides of the AD gate.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::str;
    use std::{io::Write as _, process};

    use rskrb5_ng::service::ValidatedApReq;
    use tokio::runtime::{Builder, Runtime};

    use super::*;

    /// Pins that testuser1 logs in to the AD user realm with its keytab and gets an AES256 TGT.
    #[test]
    fn active_directory_keytab_login() -> Result<(), Box<dyn Error>> {
        let _guard = AD_LOCK
            .lock()
            .map_err(|cause| format!("AD integration test lock: {cause}"))?;
        if !ad_enabled()? {
            return Ok(());
        }

        runtime()?.block_on(async {
            let mut client = ad_client(TESTUSER1, testuser1_keytab()?, false)?;
            let tgt = client.login().await?;

            assert_eq!(tgt.client, Principal::user(USER_REALM, TESTUSER1));
            assert_eq!(tgt.service, Principal::tgt_service(USER_REALM));
            assert_eq!(tgt.session_key.etype, AES256_ETYPE);

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that testuser3, which does not require preauthentication, logs in with its keytab.
    #[test]
    fn active_directory_keytab_login_without_preauth() -> Result<(), Box<dyn Error>> {
        let _guard = AD_LOCK
            .lock()
            .map_err(|cause| format!("AD integration test lock: {cause}"))?;
        if !ad_enabled()? {
            return Ok(());
        }

        runtime()?.block_on(async {
            let mut client = ad_client(TESTUSER3, testuser3_keytab()?, false)?;
            let tgt = client.login().await?;

            assert_eq!(tgt.client, Principal::user(USER_REALM, TESTUSER3));
            assert_eq!(tgt.service, Principal::tgt_service(USER_REALM));
            assert_eq!(tgt.session_key.etype, AES256_ETYPE);

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that a user-realm service ticket validates and carries a PAC from the USER domain.
    #[test]
    fn active_directory_service_ticket_validates_user_domain_pac() -> Result<(), Box<dyn Error>> {
        let _guard = AD_LOCK
            .lock()
            .map_err(|cause| format!("AD integration test lock: {cause}"))?;
        if !ad_enabled()? {
            return Ok(());
        }

        runtime()?.block_on(async {
            let mut client = ad_client(TESTUSER1, testuser1_keytab()?, false)?;
            let _: &AsRepSession = client.login().await?;

            let ticket = client
                .get_service_ticket(http_service(USER_REALM, USER_SERVICE_HOST))
                .await?;
            assert_eq!(ticket.service.name(), format!("HTTP/{USER_SERVICE_HOST}"));
            assert_eq!(ticket.session_key.etype, AES256_ETYPE);

            let service_keytab = testuser2_keytab()?;
            let validated = validate_service_ticket(&ticket, &service_keytab, [TESTUSER2], false)?;
            let pac = validated
                .pac
                .as_ref()
                .ok_or("AD service ticket has a PAC")?;
            let credentials = pac.ad_credentials().ok_or("PAC has validation info")?;
            assert_eq!(credentials.logon_domain_name, "USER");

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that a cross-trust resource-realm ticket (RC4) validates and names testuser1 in its PAC.
    #[test]
    fn active_directory_trust_resource_domain_service_ticket_validates_pac()
    -> Result<(), Box<dyn Error>> {
        let _guard = AD_LOCK
            .lock()
            .map_err(|cause| format!("AD integration test lock: {cause}"))?;
        if !ad_enabled()? {
            return Ok(());
        }

        runtime()?.block_on(async {
            let mut client = ad_client(TESTUSER1, testuser1_keytab()?, true)?;
            let _: &AsRepSession = client.login().await?;

            let ticket = client
                .get_service_ticket(http_service(RESOURCE_REALM, RESOURCE_SERVICE_HOST))
                .await?;
            assert_eq!(
                ticket.service.name(),
                format!("HTTP/{RESOURCE_SERVICE_HOST}")
            );
            assert_eq!(ticket.session_key.etype, RC4_HMAC_ETYPE);

            let service_keytab = syshttp_keytab()?;
            let validated = validate_service_ticket(&ticket, &service_keytab, [SYSHTTP], true)?;
            let pac = validated
                .pac
                .as_ref()
                .ok_or("AD service ticket has a PAC")?;
            let credentials = pac.ad_credentials().ok_or("PAC has validation info")?;
            assert_eq!(credentials.effective_name, TESTUSER1);

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that a user-realm ticket obtained under the trust configuration validates its PAC.
    #[test]
    fn active_directory_trust_user_domain_service_ticket_validates_pac()
    -> Result<(), Box<dyn Error>> {
        let _guard = AD_LOCK
            .lock()
            .map_err(|cause| format!("AD integration test lock: {cause}"))?;
        if !ad_enabled()? {
            return Ok(());
        }

        runtime()?.block_on(async {
            let mut client = ad_client(TESTUSER1, testuser1_keytab()?, true)?;
            let _: &AsRepSession = client.login().await?;

            let ticket = client
                .get_service_ticket(http_service(USER_REALM, USER_SERVICE_HOST))
                .await?;
            assert_eq!(ticket.service.name(), format!("HTTP/{USER_SERVICE_HOST}"));

            let service_keytab = testuser2_keytab()?;
            let validated = validate_service_ticket(&ticket, &service_keytab, [TESTUSER2], false)?;
            let pac = validated
                .pac
                .as_ref()
                .ok_or("AD service ticket has a PAC")?;
            let credentials = pac.ad_credentials().ok_or("PAC has validation info")?;
            assert_eq!(credentials.effective_name, TESTUSER1);

            Ok::<_, Box<dyn Error>>(())
        })
    }

    /// Pins that every embedded AD keytab holds its principal in each fixture enctype.
    #[test]
    fn embedded_ad_keytabs_cover_required_principals_and_enctypes() -> Result<(), Box<dyn Error>> {
        assert_ad_keytab_fixture(TESTUSER1_KEYTAB, USER_REALM, TESTUSER1)?;
        assert_ad_keytab_fixture(TESTUSER2_KEYTAB, USER_REALM, TESTUSER2)?;
        assert_ad_keytab_fixture(TESTUSER3_KEYTAB, USER_REALM, TESTUSER3)?;
        assert_ad_keytab_fixture(SYSHTTP_KEYTAB, RESOURCE_REALM, SYSHTTP)?;
        Ok(())
    }

    /// Pins that `TESTAD_REQUIRED=1` turns a missing `TESTAD` into an error.
    #[test]
    fn strict_ad_gate_rejects_missing_testad() -> Result<(), Box<dyn Error>> {
        const TEST_PATH: &str = "tests::strict_ad_gate_rejects_missing_testad";
        if !child_env::in_child(TEST_PATH) {
            child_env::run_in_child(
                TEST_PATH,
                &[
                    ("TESTAD", None),
                    ("TESTAD_REQUIRED", Some(OsStr::new("1"))),
                    ("TEST_AD_USER_KDC_ADDR", None),
                    ("TEST_AD_RESOURCE_KDC_ADDR", None),
                    ("TEST_AD_USER_ADMIN_ADDR", None),
                    ("TEST_AD_RESOURCE_ADMIN_ADDR", None),
                    ("TEST_AD_KDC_ADDR", None),
                    ("TEST_AD_RES_KDC_ADDR", None),
                    ("TEST_AD_ADMIN_ADDR", None),
                    ("TEST_AD_RES_ADMIN_ADDR", None),
                ],
            );
            return Ok(());
        }
        let _guard = AD_LOCK
            .lock()
            .map_err(|cause| format!("AD integration test lock: {cause}"))?;

        let error = ad_enabled()
            .err()
            .ok_or("strict AD gate rejects a TESTAD soft skip")?;
        assert!(
            error
                .to_string()
                .contains("TESTAD_REQUIRED=1 forbids soft skips"),
            "{error}"
        );
        Ok(())
    }

    /// Pins that the strict AD gate rejects a malformed user KDC endpoint.
    #[test]
    fn strict_ad_gate_rejects_malformed_user_kdc_endpoint() -> Result<(), Box<dyn Error>> {
        const TEST_PATH: &str = "tests::strict_ad_gate_rejects_malformed_user_kdc_endpoint";
        if !child_env::in_child(TEST_PATH) {
            child_env::run_in_child(
                TEST_PATH,
                &[
                    ("TESTAD", Some(OsStr::new("1"))),
                    ("TESTAD_REQUIRED", Some(OsStr::new("1"))),
                    (
                        "TEST_AD_USER_KDC_ADDR",
                        Some(OsStr::new("127.0.0.1:not-a-port")),
                    ),
                    ("TEST_AD_RESOURCE_KDC_ADDR", None),
                    ("TEST_AD_USER_ADMIN_ADDR", None),
                    ("TEST_AD_RESOURCE_ADMIN_ADDR", None),
                    ("TEST_AD_KDC_ADDR", None),
                    ("TEST_AD_RES_KDC_ADDR", None),
                    ("TEST_AD_ADMIN_ADDR", None),
                    ("TEST_AD_RES_ADMIN_ADDR", None),
                ],
            );
            return Ok(());
        }
        let _guard = AD_LOCK
            .lock()
            .map_err(|cause| format!("AD integration test lock: {cause}"))?;

        let error = ad_enabled()
            .err()
            .ok_or("strict AD gate rejects malformed endpoints")?;
        assert!(
            error.to_string().contains("cannot reach user KDC"),
            "{error}"
        );
        Ok(())
    }

    /// Pins that the strict AD gate rejects an unreachable user KDC endpoint.
    #[test]
    fn strict_ad_gate_rejects_unreachable_user_kdc_endpoint() -> Result<(), Box<dyn Error>> {
        const TEST_PATH: &str = "tests::strict_ad_gate_rejects_unreachable_user_kdc_endpoint";
        if !child_env::in_child(TEST_PATH) {
            let listener = TcpListener::bind(("127.0.0.1", 0))?;
            let endpoint = listener.local_addr()?.to_string();
            drop(listener);

            child_env::run_in_child(
                TEST_PATH,
                &[
                    ("TESTAD", Some(OsStr::new("1"))),
                    ("TESTAD_REQUIRED", Some(OsStr::new("1"))),
                    ("TEST_AD_USER_KDC_ADDR", Some(OsStr::new(&endpoint))),
                    ("TEST_AD_RESOURCE_KDC_ADDR", None),
                    ("TEST_AD_USER_ADMIN_ADDR", None),
                    ("TEST_AD_RESOURCE_ADMIN_ADDR", None),
                    ("TEST_AD_KDC_ADDR", None),
                    ("TEST_AD_RES_KDC_ADDR", None),
                    ("TEST_AD_ADMIN_ADDR", None),
                    ("TEST_AD_RES_ADMIN_ADDR", None),
                ],
            );
            return Ok(());
        }
        let _guard = AD_LOCK
            .lock()
            .map_err(|cause| format!("AD integration test lock: {cause}"))?;

        let error = ad_enabled()
            .err()
            .ok_or("strict AD gate rejects unreachable endpoints")?;
        assert!(
            error.to_string().contains("cannot reach user KDC at"),
            "{error}"
        );

        Ok(())
    }

    /// Pins that the AD config uses the endpoint overrides and the RC4 trust options.
    #[test]
    fn ad_config_uses_endpoint_overrides_and_rc4_trust_options() -> Result<(), Box<dyn Error>> {
        const TEST_PATH: &str = "tests::ad_config_uses_endpoint_overrides_and_rc4_trust_options";
        if !child_env::in_child(TEST_PATH) {
            child_env::run_in_child(
                TEST_PATH,
                &[
                    ("TESTAD", None),
                    ("TESTAD_REQUIRED", None),
                    (
                        "TEST_AD_USER_KDC_ADDR",
                        Some(OsStr::new("192.0.2.10:10088")),
                    ),
                    (
                        "TEST_AD_RESOURCE_KDC_ADDR",
                        Some(OsStr::new("192.0.2.11:10088")),
                    ),
                    (
                        "TEST_AD_USER_ADMIN_ADDR",
                        Some(OsStr::new("192.0.2.10:10464")),
                    ),
                    (
                        "TEST_AD_RESOURCE_ADMIN_ADDR",
                        Some(OsStr::new("192.0.2.11:10464")),
                    ),
                    ("TEST_AD_KDC_ADDR", None),
                    ("TEST_AD_RES_KDC_ADDR", None),
                    ("TEST_AD_ADMIN_ADDR", None),
                    ("TEST_AD_RES_ADMIN_ADDR", None),
                ],
            );
            return Ok(());
        }
        let _guard = AD_LOCK
            .lock()
            .map_err(|cause| format!("AD integration test lock: {cause}"))?;

        let config = ad_config(false)?;
        assert_eq!(
            config.configured_kdcs(USER_REALM)?,
            &["192.0.2.10:10088".to_owned()]
        );
        assert_eq!(
            config.configured_kdcs(RESOURCE_REALM)?,
            &["192.0.2.11:10088".to_owned()]
        );
        assert_eq!(
            config
                .realm(USER_REALM)
                .ok_or("USER realm exists")?
                .admin_server,
            ["192.0.2.10:10464".to_owned()]
        );
        assert_eq!(
            config
                .realm(RESOURCE_REALM)
                .ok_or("RESOURCE realm exists")?
                .admin_server,
            ["192.0.2.11:10464".to_owned()]
        );
        assert!(!config.libdefaults.allow_weak_crypto.is_enabled());
        assert!(!config.libdefaults.canonicalize.is_enabled());
        assert_eq!(config.libdefaults.default_tkt_enctype_ids(), [AES256_ETYPE]);
        assert_eq!(config.libdefaults.default_tgs_enctype_ids(), [AES256_ETYPE]);

        let rc4_config = ad_config(true)?;
        assert!(!rc4_config.libdefaults.allow_weak_crypto.is_enabled());
        assert!(rc4_config.libdefaults.allow_rc4.is_enabled());
        assert!(rc4_config.libdefaults.canonicalize.is_enabled());
        assert_eq!(
            rc4_config.libdefaults.default_tkt_enctype_ids(),
            [RC4_HMAC_ETYPE]
        );
        assert_eq!(
            rc4_config.libdefaults.default_tgs_enctype_ids(),
            [RC4_HMAC_ETYPE]
        );
        assert_eq!(
            rc4_config.libdefaults.permitted_enctype_ids(),
            [RC4_HMAC_ETYPE]
        );

        Ok(())
    }

    /// Pins that the AD keytab loader reads the path override.
    #[test]
    fn ad_keytab_uses_path_override() -> Result<(), Box<dyn Error>> {
        const TEST_PATH: &str = "tests::ad_keytab_uses_path_override";
        if !child_env::in_child(TEST_PATH) {
            let path = temp_keytab_path("testuser1")?;
            child_env::run_in_child(
                TEST_PATH,
                &[
                    (TESTUSER1_KEYTAB.path_env, Some(path.as_os_str())),
                    (TESTUSER1_KEYTAB.hex_env, None),
                    (TESTUSER1_KEYTAB.base64_env, None),
                ],
            );
            return Ok(());
        }
        let _guard = AD_LOCK
            .lock()
            .map_err(|cause| format!("AD integration test lock: {cause}"))?;
        let bytes = decode_hex_value(KEYTAB_TESTUSER1_USER_GOKRB5)?;
        let path = PathBuf::from(
            env::var_os(TESTUSER1_KEYTAB.path_env).ok_or("the parent test sets the keytab path")?,
        );
        fs::write(&path, &bytes)?;

        assert_eq!(testuser1_keytab()?, keytab(KEYTAB_TESTUSER1_USER_GOKRB5)?);

        // Best-effort cleanup of the temporary keytab; a leftover file is harmless.
        let _: Option<()> = fs::remove_file(path).ok();
        Ok(())
    }

    /// Pins that the AD keytab loader decodes the whitespace-split hex override.
    #[test]
    fn ad_keytab_uses_hex_override() -> Result<(), Box<dyn Error>> {
        const TEST_PATH: &str = "tests::ad_keytab_uses_hex_override";
        if !child_env::in_child(TEST_PATH) {
            let spaced_hex = KEYTAB_TESTUSER2_USER_GOKRB5
                .as_bytes()
                .chunks(64)
                .map(str::from_utf8)
                .collect::<Result<Vec<_>, _>>()?
                .join("\n");
            child_env::run_in_child(
                TEST_PATH,
                &[
                    (TESTUSER2_KEYTAB.path_env, None),
                    (TESTUSER2_KEYTAB.hex_env, Some(OsStr::new(&spaced_hex))),
                    (TESTUSER2_KEYTAB.base64_env, None),
                ],
            );
            return Ok(());
        }
        let _guard = AD_LOCK
            .lock()
            .map_err(|cause| format!("AD integration test lock: {cause}"))?;

        assert_eq!(testuser2_keytab()?, keytab(KEYTAB_TESTUSER2_USER_GOKRB5)?);

        Ok(())
    }

    /// Pins that the AD keytab loader decodes the base64 override.
    #[cfg(feature = "spnego")]
    #[test]
    fn ad_keytab_uses_base64_override() -> Result<(), Box<dyn Error>> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        const TEST_PATH: &str = "tests::ad_keytab_uses_base64_override";
        if !child_env::in_child(TEST_PATH) {
            let bytes = decode_hex_value(KEYTAB_SYSHTTP_RES_GOKRB5)?;
            let base64 = STANDARD.encode(bytes);
            child_env::run_in_child(
                TEST_PATH,
                &[
                    (SYSHTTP_KEYTAB.path_env, None),
                    (SYSHTTP_KEYTAB.hex_env, None),
                    (SYSHTTP_KEYTAB.base64_env, Some(OsStr::new(&base64))),
                ],
            );
            return Ok(());
        }
        let _guard = AD_LOCK
            .lock()
            .map_err(|cause| format!("AD integration test lock: {cause}"))?;

        assert_eq!(syshttp_keytab()?, keytab(KEYTAB_SYSHTTP_RES_GOKRB5)?);

        Ok(())
    }

    /// Pins that the keytab path override wins over the encoded overrides.
    #[test]
    fn ad_keytab_path_override_takes_precedence_over_encoded_values() -> Result<(), Box<dyn Error>>
    {
        const TEST_PATH: &str =
            "tests::ad_keytab_path_override_takes_precedence_over_encoded_values";
        if !child_env::in_child(TEST_PATH) {
            let path = temp_keytab_path("testuser3")?;
            child_env::run_in_child(
                TEST_PATH,
                &[
                    (TESTUSER3_KEYTAB.path_env, Some(path.as_os_str())),
                    (TESTUSER3_KEYTAB.hex_env, Some(OsStr::new("00"))),
                    (TESTUSER3_KEYTAB.base64_env, None),
                ],
            );
            return Ok(());
        }
        let _guard = AD_LOCK
            .lock()
            .map_err(|cause| format!("AD integration test lock: {cause}"))?;
        let path = PathBuf::from(
            env::var_os(TESTUSER3_KEYTAB.path_env).ok_or("the parent test sets the keytab path")?,
        );
        fs::write(&path, decode_hex_value(KEYTAB_TESTUSER3_USER_GOKRB5)?)?;

        assert_eq!(testuser3_keytab()?, keytab(KEYTAB_TESTUSER3_USER_GOKRB5)?);

        // Best-effort cleanup of the temporary keytab; a leftover file is harmless.
        let _: Option<()> = fs::remove_file(path).ok();
        Ok(())
    }

    /// Asserts that an embedded AD keytab is v2 and holds `principal@realm` in every fixture enctype.
    fn assert_ad_keytab_fixture(
        fixture: AdKeytabFixture,
        realm: &str,
        principal: &str,
    ) -> Result<(), Box<dyn Error>> {
        let keytab = keytab(fixture.default_hex)?;
        assert_eq!(keytab.version(), 2, "{} uses keytab v2", fixture.label);

        for etype in AD_FIXTURE_ETYPES {
            let (key, kvno) = keytab
                .find_key(&[principal], realm, 0, etype)
                .map_err(|error| {
                    ad_gate_error(format!(
                        "embedded AD keytab {} is missing {principal}@{realm} etype {etype}: {error}",
                        fixture.label
                    ))
                })?;
            assert_eq!(
                key.value.len(),
                expected_key_len(etype)?,
                "{} has the expected etype {etype} key length",
                fixture.label
            );
            assert!(
                kvno > 0,
                "{} etype {etype} resolves to a nonzero kvno",
                fixture.label
            );
        }

        Ok(())
    }

    /// Returns the key length of a fixture enctype.
    fn expected_key_len(etype: i32) -> Result<usize, Box<dyn Error>> {
        match etype {
            AES128_ETYPE | RC4_HMAC_ETYPE => Ok(16),
            AES256_ETYPE => Ok(32),
            _ => Err(format!("AD fixture etype list is fixed, got {etype}").into()),
        }
    }

    /// Returns whether the AD tests run: `TESTAD=1` and both KDCs reachable.
    ///
    /// Reports a soft skip on stderr; under `TESTAD_REQUIRED=1` a skip is an error.
    fn ad_enabled() -> Result<bool, Box<dyn Error>> {
        let required = ad_required();
        if !ad_prefetch_gate() {
            let message = "skipping AD integration test; set TESTAD=1 to enable";
            if required {
                return Err(ad_gate_error(format!(
                    "{message}; TESTAD_REQUIRED=1 forbids soft skips"
                )));
            }
            writeln!(io::stderr(), "{message}")?;
            return Ok(false);
        }

        let user_kdc = ad_user_kdc_addr();
        let resource_kdc = ad_resource_kdc_addr();

        if !tcp_reachable(&user_kdc, "USER realm KDC")? {
            let message =
                format!("skipping AD integration test; cannot reach user KDC at {user_kdc}");
            if required {
                return Err(ad_gate_error(format!(
                    "{message}; TESTAD_REQUIRED=1 forbids soft skips"
                )));
            }
            writeln!(io::stderr(), "{message}")?;
            return Ok(false);
        }

        if !tcp_reachable(&resource_kdc, "RESOURCE realm KDC")? {
            let message = format!(
                "skipping AD integration test; cannot reach resource KDC at {resource_kdc}"
            );
            if required {
                return Err(ad_gate_error(format!(
                    "{message}; TESTAD_REQUIRED=1 forbids soft skips"
                )));
            }
            writeln!(io::stderr(), "{message}")?;
            return Ok(false);
        }

        Ok(true)
    }

    /// Returns whether `TESTAD=1` enables the AD tests.
    fn ad_prefetch_gate() -> bool {
        env::var("TESTAD").as_deref() == Ok("1")
    }

    /// Returns whether `TESTAD_REQUIRED=1` turns a soft skip into an error.
    fn ad_required() -> bool {
        env::var("TESTAD_REQUIRED").as_deref() == Ok("1")
    }

    /// Returns the user realm KDC endpoint, overridable from the environment.
    fn ad_user_kdc_addr() -> String {
        env_value(
            &["TEST_AD_USER_KDC_ADDR", "TEST_AD_KDC_ADDR"],
            "192.168.88.100:88",
        )
    }

    /// Returns the resource realm KDC endpoint, overridable from the environment.
    fn ad_resource_kdc_addr() -> String {
        env_value(
            &["TEST_AD_RESOURCE_KDC_ADDR", "TEST_AD_RES_KDC_ADDR"],
            "192.168.88.101:88",
        )
    }

    /// Returns the user realm admin server endpoint, overridable from the environment.
    fn ad_user_admin_addr() -> String {
        env_value(
            &["TEST_AD_USER_ADMIN_ADDR", "TEST_AD_ADMIN_ADDR"],
            "192.168.88.100:464",
        )
    }

    /// Returns the resource realm admin server endpoint, overridable from the environment.
    fn ad_resource_admin_addr() -> String {
        env_value(
            &["TEST_AD_RESOURCE_ADMIN_ADDR", "TEST_AD_RES_ADMIN_ADDR"],
            "192.168.88.101:464",
        )
    }

    /// Returns whether any resolved address of `endpoint` accepts a TCP connection within a second.
    ///
    /// A resolution failure is reported on stderr and counts as unreachable.
    fn tcp_reachable(endpoint: &str, label: &str) -> Result<bool, Box<dyn Error>> {
        let mut addrs = match endpoint.to_socket_addrs() {
            Ok(addrs) => addrs,
            Err(error) => {
                writeln!(
                    io::stderr(),
                    "failed to resolve {label} {endpoint}: {error}"
                )?;
                return Ok(false);
            }
        };
        let timeout = Duration::from_secs(1);

        Ok(addrs.any(|addr| TcpStream::connect_timeout(&addr, timeout).is_ok()))
    }

    /// Builds a keytab client for `user` in the user realm, with or without the RC4 trust options.
    fn ad_client(user: &str, keytab: Keytab, rc4: bool) -> Result<Tokio, Box<dyn Error>> {
        Ok(Tokio::with_keytab(
            ad_config(rc4)?,
            KdcProtocol::Auto,
            Principal::user(USER_REALM, user),
            keytab,
        ))
    }

    /// Builds the two-realm AD configuration, optionally restricted to RC4 for the trust path.
    fn ad_config(rc4: bool) -> Result<Config, Box<dyn Error>> {
        let user_kdc = ad_user_kdc_addr();
        let user_admin = ad_user_admin_addr();
        let resource_kdc = ad_resource_kdc_addr();
        let resource_admin = ad_resource_admin_addr();
        let rc4_options = if rc4 {
            "
  allow_weak_crypto = false
  canonicalize = true
  default_tkt_enctypes = rc4-hmac
  allow_rc4 = true
  default_tgs_enctypes = rc4-hmac
  permitted_enctypes = rc4-hmac
"
        } else {
            ""
        };

        Ok(Config::parse(&format!(
            "[libdefaults]
  default_realm = {USER_REALM}
  dns_lookup_realm = false
  dns_lookup_kdc = false
  ticket_lifetime = 24h
  forwardable = yes
{rc4_options}
  default_tkt_enctypes = aes256-cts-hmac-sha1-96
  default_tgs_enctypes = aes256-cts-hmac-sha1-96
  noaddresses = true

[realms]
 {USER_REALM} = {{
  kdc = {user_kdc}
  admin_server = {user_admin}
  default_domain = user.gokrb5
 }}
 {RESOURCE_REALM} = {{
  kdc = {resource_kdc}
  admin_server = {resource_admin}
  default_domain = res.gokrb5
 }}

[domain_realm]
 .user.gokrb5 = {USER_REALM}
 user.gokrb5 = {USER_REALM}
 .res.gokrb5 = {RESOURCE_REALM}
 res.gokrb5 = {RESOURCE_REALM}
",
        ))?)
    }

    /// Returns the first non-empty environment variable of `names`, else `default`.
    fn env_value(names: &[&str], default: &str) -> String {
        names
            .iter()
            .find_map(|name| env::var(name).ok().filter(|value| !value.is_empty()))
            .unwrap_or_else(|| default.to_owned())
    }

    /// Builds the `HTTP/<host>` service principal in `realm`.
    fn http_service(realm: &str, host: &str) -> Principal {
        Principal::new(realm, 2, ["HTTP", host])
    }

    /// Validates `ticket` as an AP-REQ against `keytab` with a fixed confounder.
    fn validate_service_ticket<const N: usize>(
        ticket: &TgsRepSession,
        keytab: &Keytab,
        keytab_principal: [&str; N],
        rc4: bool,
    ) -> Result<ValidatedApReq, Box<dyn Error>> {
        validate_service_ticket_at(ticket, keytab, keytab_principal, rc4, SystemTime::now())
    }

    /// Validate a service fixture at an explicit wall-clock sample.
    fn validate_service_ticket_at<const N: usize>(
        ticket: &TgsRepSession,
        keytab: &Keytab,
        keytab_principal: [&str; N],
        rc4: bool,
        timestamp: SystemTime,
    ) -> Result<ValidatedApReq, Box<dyn Error>> {
        let etype = KerberosEtype::from_etype_id(ticket.session_key.etype)
            .ok_or("ticket etype is supported")?;
        let confounder = vec![0x42_u8; etype.confounder_len()];
        let (seconds, cusec) = service_authenticator_time(timestamp)?;
        let policy = CryptoPolicy::from_libdefaults(&ad_config(rc4)?.libdefaults)?;
        let mut options = ApReq::new();
        options.crypto_policy = Some(policy.clone());
        let ap_req = build_ap_req_with_confounder(ticket, options, seconds, cusec, &confounder)?;
        let mut validator = Validator::new(keytab)
            .with_crypto_policy(policy)
            .with_now(timestamp)
            .with_keytab_principal(keytab_principal);
        Ok(validator.validate_ap_req(&ap_req.der)?)
    }

    /// Split a clock sample into the AP builder's whole seconds and microseconds.
    fn service_authenticator_time(time: SystemTime) -> Result<(SystemTime, u32), Box<dyn Error>> {
        let elapsed = time.duration_since(SystemTime::UNIX_EPOCH)?;
        Ok((
            SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(elapsed.as_secs()))
                .ok_or("time overflow")?,
            elapsed.subsec_micros(),
        ))
    }

    /// Synthetic AES and opted-in RC4 tickets traverse the live helper at a fractional clock.
    #[test]
    fn ad_service_helper_accepts_aes_and_opted_in_rc4() -> Result<(), Box<dyn Error>> {
        use rskrb5_ng::{
            ap_req,
            keytab::{EncryptionKey, Entry, Principal as KeyPrincipal},
            ticket,
        };
        let original = ap_req::decode(include_bytes!("../fuzz/fixtures/valid_ap_req.der"))?;
        let original_key = EncryptionKey::new(
            18,
            hex::decode("9cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51")?,
        );
        let original_part = ticket::decrypt_ticket_enc_part(&original.ticket, &original_key)?;
        let now = UNIX_EPOCH
            .checked_add(Duration::from_millis(1_893_553_447_500))
            .ok_or("clock")?;
        for id in [18_i32, 23_i32] {
            let etype = KerberosEtype::from_etype_id(id).ok_or("enctype")?;
            let service_key = EncryptionKey::new(id, vec![0x31; etype.key_len()]);
            let session_key = EncryptionKey::new(id, vec![0x32; etype.key_len()]);
            let mut part = original_part.clone();
            part.key = rasn_kerberos::EncryptionKey {
                r#type: id,
                value: session_key.value.to_vec().into(),
            };
            let encrypted = ticket::build_ticket_with_confounder(
                original.ticket.realm.clone(),
                original.ticket.sname.clone(),
                &part,
                &service_key,
                Some(1),
                &vec![0x33; etype.confounder_len()],
            )?;
            let session = TgsRepSession::new(
                Principal::user("TEST.GOKRB5", "testuser1"),
                Principal::new("TEST.GOKRB5", 2, ["HTTP", "host.test.gokrb5"]),
                session_key,
                ticket::encode(&encrypted)?.into(),
                [0; 4],
                now,
                now,
            );
            let mut keys = Keytab::new();
            keys.entries_mut().push(Entry::new(
                KeyPrincipal::new(
                    "TEST.GOKRB5",
                    2,
                    vec!["HTTP".to_owned(), "host.test.gokrb5".to_owned()],
                ),
                0,
                1,
                service_key,
                1,
            ));
            let accepted = validate_service_ticket_at(
                &session,
                &keys,
                ["HTTP", "host.test.gokrb5"],
                id == 23_i32,
                now,
            )?;
            assert_eq!(accepted.session_key.etype, id);
            if id == 23_i32 {
                let failure = validate_service_ticket_at(
                    &session,
                    &keys,
                    ["HTTP", "host.test.gokrb5"],
                    false,
                    now,
                )
                .err()
                .ok_or("default RC4 accepted")?;
                assert!(failure.to_string().contains("not permitted"));
            }
        }
        Ok(())
    }

    /// Fractional wall clocks remain valid input to the live service-ticket helper.
    #[test]
    fn ad_service_time_is_whole_seconds() -> Result<(), Box<dyn Error>> {
        let sample = SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_millis(1500))
            .ok_or("time")?;
        let (seconds, micros) = service_authenticator_time(sample)?;
        assert_eq!(
            seconds
                .duration_since(SystemTime::UNIX_EPOCH)?
                .subsec_nanos(),
            0
        );
        assert_eq!(micros, 500_000);
        Ok(())
    }

    /// Loads the testuser1 keytab, honouring its overrides.
    fn testuser1_keytab() -> Result<Keytab, Box<dyn Error>> {
        ad_keytab(TESTUSER1_KEYTAB)
    }

    /// Loads the testuser2 keytab, honouring its overrides.
    fn testuser2_keytab() -> Result<Keytab, Box<dyn Error>> {
        ad_keytab(TESTUSER2_KEYTAB)
    }

    /// Loads the testuser3 keytab, honouring its overrides.
    fn testuser3_keytab() -> Result<Keytab, Box<dyn Error>> {
        ad_keytab(TESTUSER3_KEYTAB)
    }

    /// Loads the sysHTTP keytab, honouring its overrides.
    fn syshttp_keytab() -> Result<Keytab, Box<dyn Error>> {
        ad_keytab(SYSHTTP_KEYTAB)
    }

    /// Loads an AD keytab from its path, hex or base64 override, else the embedded fixture.
    fn ad_keytab(fixture: AdKeytabFixture) -> Result<Keytab, Box<dyn Error>> {
        if let Some(path) = env_path_optional(fixture.path_env) {
            let bytes = fs::read(&path).map_err(|error| {
                ad_gate_error(format!(
                    "failed to read AD keytab {} from {}={}: {error}",
                    fixture.label,
                    fixture.path_env,
                    path.display()
                ))
            })?;
            return parse_keytab_bytes(
                fixture.label,
                &format!("{}={}", fixture.path_env, path.display()),
                &bytes,
            );
        }

        if let Some(hex) = env_string_optional(fixture.hex_env) {
            let bytes = decode_hex_value(&hex).map_err(|error| {
                ad_gate_error(format!(
                    "failed to decode AD keytab {} from {}: {error}",
                    fixture.label, fixture.hex_env
                ))
            })?;
            return parse_keytab_bytes(fixture.label, fixture.hex_env, &bytes);
        }

        if let Some(base64) = env_string_optional(fixture.base64_env) {
            let bytes = decode_base64_value(&base64).map_err(|error| {
                ad_gate_error(format!(
                    "failed to decode AD keytab {} from {}: {error}",
                    fixture.label, fixture.base64_env
                ))
            })?;
            return parse_keytab_bytes(fixture.label, fixture.base64_env, &bytes);
        }

        keytab(fixture.default_hex)
    }

    /// Parses a keytab from its hex dump.
    fn keytab(hex: &str) -> Result<Keytab, Box<dyn Error>> {
        let bytes = decode_hex_value(hex)?;
        Ok(Keytab::parse(&bytes)?)
    }

    /// Returns the non-empty path in environment variable `name`.
    fn env_path_optional(name: &str) -> Option<PathBuf> {
        env::var_os(name)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    }

    /// Returns the non-empty value of environment variable `name`.
    fn env_string_optional(name: &str) -> Option<String> {
        env::var(name).ok().filter(|value| !value.is_empty())
    }

    /// Decodes hex, ignoring ASCII whitespace anywhere in the input.
    fn decode_hex_value(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let compact: Vec<u8> = input
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect();
        if !compact.len().is_multiple_of(2) {
            return Err(ad_gate_error(format!(
                "hex input has odd length after whitespace removal: {}",
                compact.len()
            )));
        }

        let pairs = compact.as_chunks::<2>().0;
        let mut out = Vec::with_capacity(pairs.len());
        for &[high, low] in pairs {
            let byte = hex_nibble(high)?
                .saturating_mul(16)
                .saturating_add(hex_nibble(low)?);
            out.push(u8::try_from(byte)?);
        }
        Ok(out)
    }

    /// Returns the value of one hex digit.
    fn hex_nibble(byte: u8) -> Result<u32, Box<dyn Error>> {
        char::from(byte).to_digit(16).ok_or_else(|| {
            ad_gate_error(format!("invalid hex byte 0x{byte:02x} in keytab override"))
        })
    }

    /// Decodes standard base64, ignoring whitespace anywhere in the input.
    #[cfg(feature = "spnego")]
    fn decode_base64_value(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        let compact: String = input.chars().filter(|ch| !ch.is_whitespace()).collect();
        STANDARD
            .decode(compact)
            .map_err(|error| ad_gate_error(format!("base64 decode error: {error}")))
    }

    /// Rejects a base64 override: decoding needs the `spnego` feature.
    #[cfg(not(feature = "spnego"))]
    fn decode_base64_value(_input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        Err(ad_gate_error(
            "base64 keytab overrides require the spnego/default feature".to_owned(),
        ))
    }

    /// Builds the current-thread Tokio runtime the tests run on.
    fn runtime() -> io::Result<Runtime> {
        Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
    }

    /// Returns a unique temporary keytab path for `label`.
    fn temp_keytab_path(label: &str) -> Result<PathBuf, Box<dyn Error>> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        Ok(env::temp_dir().join(format!(
            "rskrb5-ad-{label}-{}-{nanos}.keytab",
            process::id()
        )))
    }
}
