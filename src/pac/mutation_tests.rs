//! PAC processing and diagnostic contracts.

use core::{cell::Cell, fmt};

use super::{
    ClaimValues, ClaimsInfo, ClaimsSet, ClaimsSetMetadata, ClientInfo, CredentialsInfo, DeviceInfo,
    EncryptionKey, Error, FileTime, InfoBuffer, NtlmSupplementalCredential, Pac, RpcUnicodeString,
    S4UDelegationInfo, SecpkgSupplementalCredential, Sid, SignatureData, UpnDnsInfo,
};

/// Existing gokrb5 `AD_WIN2K` wire vector, used to obtain real validation information.
const PAC_FIXTURE: &str = concat!(
    "0500000000000000010000002802000058000000000000000a0000001c00000080020000000000000c00000058000000",
    "a0020000000000000600000010000000f8020000000000000700000014000000080300000000000001100800cccccccc",
    "180200000000000000000200058e4fdd80c6d201ffffffffffffff7fffffffffffffff7fcc27969c39c6d201cce7ffc6",
    "02c7d201ffffffffffffff7f12001200040002001600160008000200000000000c000200000000001000020000000000",
    "140002000000000018000200d80000005104000001020000050000001c00020020000000000000000000000000000000",
    "0000000008000a002000020008000a002400020028000200000000000000000010020000000000000000000000000000",
    "00000000000000000000000000000000020000002c000200000000000000000000000000090000000000000009000000",
    "74006500730074007500730065007200310000000b000000000000000b00000054006500730074003100200055007300",
    "650072003100000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000050000000102000007000000540400000700000055040000070000005b040000070000005c040000",
    "070000000500000000000000040000004100440044004300050000000000000004000000540045005300540004000000",
    "0104000000000005150000004c86cebca07160e63fdce887020000003000020007000020340002000700002005000000",
    "0105000000000005150000004c86cebca07160e63fdce8875a040000050000000105000000000005150000004c86cebc",
    "a07160e63fdce8875704000000000000808dd1dc80c6d201120074006500730074007500730065007200310000000000",
    "2a001000160040000000000000000000740065007300740075007300650072003100400074006500730074002e006700",
    "6f006b0072006200350000000000000054004500530054002e0047004f004b005200420035000000100000001e251d98",
    "d552be7df384f55076ffffff340be28b48765d0519ee9346cf53d82200000000",
);

std::thread_local! {
    /// Observes live optional hash fields after actual destructor erasure.
    pub(super) static ERASED_HASHES: Cell<bool> = const { Cell::new(false) };
}

/// Claims report both empty and multi-value lengths for every typed variant.
#[test]
fn claim_values_report_cardinality() -> Result<(), Error> {
    for values in [
        ClaimValues::Int64(vec![]),
        ClaimValues::UInt64(vec![]),
        ClaimValues::String(vec![]),
        ClaimValues::Boolean(vec![]),
    ] {
        assert_eq!(values.len(), 0);
        assert!(values.is_empty(), "empty claim reported nonempty");
    }
    for values in [
        ClaimValues::Int64(vec![1, 2]),
        ClaimValues::UInt64(vec![1, 2]),
        ClaimValues::String(vec!["a".to_owned(), "b".to_owned()]),
        ClaimValues::Boolean(vec![true, false]),
    ] {
        (values.len() == 2).ok_or(Error::LengthOverflow)?;
        assert!(!values.is_empty(), "populated claim reported empty");
    }
    Ok(())
}

/// SID authorities use decimal through `u32::MAX` and hexadecimal above it.
#[test]
fn sid_formats_authority_boundaries() -> Result<(), fmt::Error> {
    for (authority, expected) in [
        ([0, 0, 0, 0, 0, 5], "S-1-5"),
        ([0, 0, 255, 255, 255, 255], "S-1-4294967295"),
        ([0, 1, 0, 0, 0, 0], "S-1-0x000100000000"),
    ] {
        let sid = Sid {
            revision: 1,
            identifier_authority: authority,
            sub_authorities: vec![],
        };
        let mut output = String::new();
        fmt::write(&mut output, format_args!("{sid}"))?;
        assert_eq!(output, expected);
    }
    Ok(())
}

/// An empty PAC has a complete eight-byte table; truncated entries are reported precisely.
#[test]
fn pac_table_boundary_and_truncation() -> Result<(), Error> {
    assert_eq!(Pac::parse(&[0; 8])?.c_buffers, 0);
    let mut bytes = 1_u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[0; 19]);
    assert!(
        matches!(
            Pac::parse(&bytes),
            Err(Error::TooShort {
                target: "PAC info buffer table",
                minimum: 24,
                actual: 23
            })
        ),
        "truncated table misclassified"
    );
    Ok(())
}

/// Buffer table validation rejects offsets that are not eight-byte aligned.
#[test]
fn pac_rejects_unaligned_buffer() -> Result<(), Error> {
    let bytes = [
        1_u32.to_le_bytes().as_slice(),
        &[0; 4],
        &[0; 8],
        &25_u64.to_le_bytes(),
        &[0; 8],
    ]
    .concat();
    let error = Pac::parse(&bytes).err().ok_or(Error::LengthOverflow)?;
    assert!(
        matches!(
            error,
            Error::BufferOffsetNotAligned {
                ul_type: 0,
                offset: 25
            }
        ),
        "unaligned buffer accepted"
    );
    Ok(())
}

/// Required-buffer validation names missing logon information before checksum validation.
#[test]
fn pac_verification_requires_logon_info() -> Result<(), Error> {
    let pac = Pac::parse(&[0; 8])?;
    assert!(
        matches!(
            pac.verify(&EncryptionKey::new(17, vec![0x42; 16])),
            Err(Error::MissingRequiredBuffer("KerbValidationInfo"))
        ),
        "missing logon info misclassified"
    );
    Ok(())
}

/// SHA384 PAC signature records have exactly 24 signature octets.
#[test]
fn signature_parser_accepts_sha384() -> Result<(), Error> {
    let bytes = [20_u32.to_le_bytes().as_slice(), &[0x42; 24]].concat();
    assert_eq!(SignatureData::parse(&bytes)?.signature, vec![0x42; 24]);
    Ok(())
}

/// Credential diagnostics preserve package metadata without exposing credential bytes.
#[test]
fn supplemental_debug_retains_metadata() -> Result<(), fmt::Error> {
    let credential = SecpkgSupplementalCredential {
        package_name: RpcUnicodeString {
            length: 8,
            maximum_length: 8,
            value: "NTLM".to_owned(),
        },
        credential_size: 3,
        credentials: vec![241, 242, 243].into(),
    };
    let mut output = String::new();
    fmt::write(&mut output, format_args!("{credential:?}"))?;
    assert!(output.contains("NTLM"), "package metadata missing");
    assert!(
        output.contains("credential_size: 3"),
        "size metadata missing"
    );
    assert!(!output.contains("241"), "secret byte printed");
    Ok(())
}

/// Calling the real destructor erases both optional NTLM hashes in live storage.
#[test]
fn ntlm_destructor_erases_hashes() -> Result<(), Error> {
    let credential = NtlmSupplementalCredential::parse(
        &[
            0_u32.to_le_bytes().as_slice(),
            &3_u32.to_le_bytes(),
            &[0x42; 16],
            &[0x24; 16],
        ]
        .concat(),
    )?;
    ERASED_HASHES.set(false);
    drop(credential);
    assert!(ERASED_HASHES.get(), "owned hashes were not erased");
    Ok(())
}

/// Processing keeps the first decoded buffer for every recognized type.
#[test]
fn processing_preserves_first_decoded_buffers() -> Result<(), Error> {
    let mut pac = Pac::parse(&[0; 8])?;
    let fixture_bytes = hex::decode(PAC_FIXTURE).map_err(|error| Error::InvalidUtf16 {
        target: "fixture",
        message: error.to_string(),
    })?;
    pac.kerb_validation_info = Pac::parse_and_process(&fixture_bytes)?.kerb_validation_info;
    let empty_string = RpcUnicodeString {
        length: 0,
        maximum_length: 0,
        value: String::new(),
    };
    let claims = ClaimsInfo {
        metadata: ClaimsSetMetadata {
            claims_set_size: 0,
            claims_set_bytes: vec![],
            compression_format: 0,
            uncompressed_claims_set_size: 0,
            reserved_type: 0,
            reserved_field_size: 0,
            reserved_field: vec![],
        },
        claims_set: ClaimsSet {
            claims_array_count: 0,
            claims_arrays: vec![],
            reserved_type: 0,
            reserved_field_size: 0,
            reserved_field: vec![],
        },
    };
    pac.server_checksum = Some(SignatureData {
        signature_type: 15,
        signature: vec![0; 12],
        rodc_identifier: None,
        zeroed_data: vec![],
    });
    pac.kdc_checksum = pac.server_checksum.clone();
    pac.credentials_info = Some(CredentialsInfo {
        version: 0,
        encryption_type: 17,
        encrypted_credential_data: vec![].into(),
    });
    pac.client_info = Some(ClientInfo {
        client_id: FileTime::from_ticks(0),
        name_length: 0,
        name: String::new(),
    });
    pac.upn_dns_info = Some(UpnDnsInfo::parse(&[0; 12])?);
    pac.s4u_delegation_info = Some(S4UDelegationInfo {
        s4u2proxy_target: empty_string,
        transited_list_size: 0,
        s4u_transited_services: vec![],
    });
    pac.device_info = Some(DeviceInfo {
        user_id: 1,
        primary_group_id: 2,
        account_domain_id: None,
        account_group_count: 0,
        account_group_ids: vec![],
        sid_count: 0,
        extra_sids: vec![],
        domain_group_count: 0,
        domain_group: vec![],
    });
    pac.client_claims_info = Some(claims.clone());
    pac.device_claims_info = Some(claims);
    for ul_type in [1, 2, 6, 7, 10, 11, 12, 13, 14, 15] {
        pac.buffers = vec![InfoBuffer {
            ul_type,
            cb_buffer_size: 0,
            offset: 8,
        }];
        pac.process_buffers()?;
    }
    Ok(())
}
