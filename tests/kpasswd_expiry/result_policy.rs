//! Password-policy mapping of a kpasswd result: the code, MIT's description of it and
//! the message `krb5_chpw_message` builds (MIT `chpw.c:245-275,372-510`), against the
//! vectors of MIT's own `tests/misc/test_chpw_message.c` (1.22.2).

use rskrb5_ng::kadmin::{
    ChangePasswordResult,
    policy::{AdPasswordPolicy, ResultCode},
};

use super::TestError;

/// The result of a reply with `code` and `text`.
fn result(code: u16, text: &[u8]) -> Result<ChangePasswordResult, TestError> {
    let mut bytes = code.to_be_bytes().to_vec();
    bytes.extend_from_slice(text);
    Ok(ChangePasswordResult::parse(&bytes)?)
}

/// MIT's AD policy structure: two zero bytes, then the five big-endian fields.
fn ad_policy(min_length: u32, history: u32, properties: u32, min_age: u64) -> Vec<u8> {
    let mut bytes = vec![0_u8; 2];
    bytes.extend_from_slice(&min_length.to_be_bytes());
    bytes.extend_from_slice(&history.to_be_bytes());
    bytes.extend_from_slice(&properties.to_be_bytes());
    bytes.extend_from_slice(&0_u64.to_be_bytes());
    bytes.extend_from_slice(&min_age.to_be_bytes());
    bytes
}

/// The message of a rejection whose text is `text`.
fn message(text: &[u8]) -> Result<String, TestError> {
    Ok(result(4, text)?.message())
}

/// Every RFC 3244 code has its kind and MIT's description.
#[test]
fn result_codes_map_to_kinds_with_mits_descriptions() -> Result<(), TestError> {
    let table = [
        (0_u16, ResultCode::Success, "Success"),
        (1, ResultCode::Malformed, "Malformed request error"),
        (2, ResultCode::HardError, "Server error"),
        (3, ResultCode::AuthError, "Authentication error"),
        (4, ResultCode::SoftError, "Password change rejected"),
        (5, ResultCode::AccessDenied, "Access denied"),
        (6, ResultCode::BadVersion, "Wrong protocol version"),
        (
            7,
            ResultCode::InitialFlagNeeded,
            "Initial password required",
        ),
        (8, ResultCode::Other(8), "Password change failed"),
        (0xffff, ResultCode::Other(0xffff), "Password change failed"),
    ];
    for (code, kind, description) in table {
        let parsed = result(code, b"")?;
        assert_eq!(parsed.kind(), kind, "code {code}");
        assert_eq!(kind.description(), description, "code {code}");
        assert_eq!(ResultCode::from(code), kind);
    }
    Ok(())
}

/// Valid UTF-8 text is returned as is; anything else gets MIT's generic advice.
#[test]
fn a_plain_message_is_returned_and_garbage_gets_generic_advice() -> Result<(), TestError> {
    assert_eq!(
        message(b"This is a valid string.")?,
        "This is a valid string."
    );
    assert!(message(b"\0This is not valid.")?.contains("contact your administrator"));
    assert!(message(&[0xff, 0xfe, 0xfd])?.contains("contact your administrator"));
    assert!(message(b"")?.contains("contact your administrator"));
    Ok(())
}

/// An Active Directory policy structure becomes MIT's sentences (`test_chpw_message.c`).
#[test]
fn an_ad_policy_becomes_mits_sentences() -> Result<(), TestError> {
    let complex = message(&ad_policy(0, 0, 1, 0))?;
    assert!(complex.contains("The password must include numbers or symbols."));
    assert!(complex.contains("Don't include any part of your name in the password."));
    assert!(
        message(&ad_policy(13, 0, 0, 0))?
            .contains("The password must contain at least 13 characters.")
    );
    assert!(
        message(&ad_policy(0, 9, 0, 0))?
            .contains("The password must be different from the previous 9 passwords.")
    );
    assert!(
        message(&ad_policy(0, 0, 0, 0x0192_54d3_8000))?
            .contains("The password can only be changed every 2 days.")
    );
    let all = message(&ad_policy(5, 13, 1, 0x00c9_2a69_c000))?;
    for expected in [
        "The password can only be changed once a day.",
        "The password must be different from the previous 13 passwords.",
        "The password must contain at least 5 characters.",
        "The password must include numbers or symbols.",
        "Don't include any part of your name in the password.",
    ] {
        assert!(all.contains(expected), "{expected}");
    }
    // The singular forms.
    assert!(message(&ad_policy(1, 1, 0, 0))?.contains("at least 1 character."));
    assert!(message(&ad_policy(1, 1, 0, 0))?.contains("different from the previous password."));
    Ok(())
}

/// The structure's fields are readable, and only a well-formed structure is one.
#[test]
fn the_ad_policy_fields_are_typed_and_malformed_ones_are_not_policies() -> Result<(), TestError> {
    let parsed = result(4, &ad_policy(5, 13, 1, 0x00c9_2a69_c000))?
        .ad_policy()
        .ok_or("a policy")?;
    assert_eq!(parsed, AdPasswordPolicy::new(5, 13, 1, 0, 864_000_000_000));
    assert!(parsed.requires_complexity());
    // Wrong length, or the two leading bytes not zero: ordinary text.
    assert!(
        result(4, &ad_policy(5, 13, 1, 0)[..29])?
            .ad_policy()
            .is_none()
    );
    let mut shifted = ad_policy(5, 13, 1, 0);
    shifted[1] = 1;
    assert!(result(4, &shifted)?.ad_policy().is_none());
    assert!(result(4, b"This is a valid string.")?.ad_policy().is_none());
    Ok(())
}
