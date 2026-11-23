//! Fuzz the remote kadm5 client's decoders of untrusted bytes.
//!
//! The first input byte selects the entry point and the rest is its input:
//! the ONC RPC record-marking reassembler (`rpcsec_gss::decode_record`), the
//! RPC reply decoder (`rpcsec_gss::Reply::decode`), and the kadm5 result
//! decoder (`kadm5::Response::decode`) for every procedure under each API
//! version, the second byte choosing the procedure and the version. None may
//! panic, allocate past its bounds or accept trailing bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::{
    kadm5::{ApiVersion, Procedure, Response},
    rpcsec_gss::{self, Reply},
};

/// Every kadm5 procedure, in `kadm_rpc.h` order.
const PROCEDURES: [Procedure; 26] = [
    Procedure::CreatePrincipal,
    Procedure::DeletePrincipal,
    Procedure::ModifyPrincipal,
    Procedure::RenamePrincipal,
    Procedure::GetPrincipal,
    Procedure::ChangePassword,
    Procedure::RandomizeKeys,
    Procedure::CreatePolicy,
    Procedure::DeletePolicy,
    Procedure::ModifyPolicy,
    Procedure::GetPolicy,
    Procedure::GetPrivileges,
    Procedure::Init,
    Procedure::GetPrincipals,
    Procedure::GetPolicies,
    Procedure::SetKeys,
    Procedure::CreatePrincipal3,
    Procedure::ChangePassword3,
    Procedure::RandomizeKeys3,
    Procedure::SetKeys3,
    Procedure::PurgeKeys,
    Procedure::GetStrings,
    Procedure::SetString,
    Procedure::SetKeys4,
    Procedure::ExtractKeys,
    Procedure::CreateAlias,
];

/// The API versions a connection may speak.
const VERSIONS: [ApiVersion; 3] = [ApiVersion::V2, ApiVersion::V3, ApiVersion::V4];

fuzz_target!(|data: &[u8]| {
    let Some((selector, input)) = data.split_first() else {
        return;
    };
    match selector & 0x03 {
        0 => {
            if let Ok(Some((message, consumed))) = rpcsec_gss::decode_record(input) {
                assert!(
                    consumed <= input.len(),
                    "a record never takes more than its input"
                );
                drop(Reply::decode(&message));
            }
        }
        1 => drop(Reply::decode(input)),
        _ => {
            let Some((choice, payload)) = input.split_first() else {
                return;
            };
            let Some(procedure) = PROCEDURES.get(usize::from(*choice & 0x1f)) else {
                return;
            };
            let Some(version) = VERSIONS.get(usize::from(*choice >> 5) & 0x03) else {
                return;
            };
            drop(Response::decode(*procedure, *version, payload));
        }
    }
});
