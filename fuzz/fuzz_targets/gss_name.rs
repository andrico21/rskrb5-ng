//! Fuzz GSS-API name import and the names it yields.
//!
//! The first input byte selects the name type (the user-id types resolve
//! through a fixed account); the rest is the name buffer: a host-based name, a
//! principal or enterprise string with escapes, an RFC 2743 exported or RFC
//! 6680 composite exported token, a user id, or a certificate. An imported
//! name is displayed, exported, imported back, compared and canonicalized.
//! None may panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::gss::{Name, NameType};

/// The name types in selector order.
const TYPES: [NameType; 10] = [
    NameType::HostbasedService,
    NameType::User,
    NameType::MachineUid,
    NameType::StringUid,
    NameType::Anonymous,
    NameType::Export,
    NameType::CompositeExport,
    NameType::Principal,
    NameType::Enterprise,
    NameType::X509Cert,
];

fuzz_target!(|data: &[u8]| {
    let Some((selector, input)) = data.split_first() else {
        return;
    };
    let Some(kind) = TYPES.get(usize::from(*selector).checked_rem(TYPES.len()).unwrap_or(0)) else {
        return;
    };
    let imported = if matches!(kind, NameType::MachineUid | NameType::StringUid) {
        Name::import_uid(input, *kind, |uid| Some(format!("user{uid}@EXAMPLE.COM")))
    } else {
        Name::import(input, *kind)
    };
    let Ok(name) = imported else {
        return;
    };
    let (shown, _) = name.display();
    drop(Name::import(shown.as_bytes(), NameType::Principal));
    if let Ok(exported) = name.export()
        && let Ok(back) = Name::import(&exported, NameType::Export)
    {
        assert!(back.compare(&name), "an exported name imports back equal");
    }
    drop(name.canonicalize().with_default_realm("EXAMPLE.COM"));
    let _attributes: Option<&[u8]> = name.composite_attributes();
    assert_eq!(NameType::from_oid(&kind.oid()), Some(*kind), "the type maps back");
});
