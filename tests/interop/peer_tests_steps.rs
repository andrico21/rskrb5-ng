//! Credential, step and inquire commands against a scripted stream.

use core::error::Error;

use super::{peer, reply, written};
use crate::peer::{
    cred::{CredRequest, Name, Usage},
    frame::encode_request,
    types::{AcceptRequest, ContextHandle, CredHandle, InitRequest},
};

/// Credential commands carry their documented fields.
#[test]
fn credential_commands_carry_their_fields() -> Result<(), Box<dyn Error>> {
    let cred_request = CredRequest::new(Usage::Accept)
        .named(Name::principal("peer/x@R"))
        .with_mechs(&["1.2.3", "1.3.6.1.5.5.2"])
        .with_keytab("acceptor");
    let mut client = peer(&[
        reply(0, &[&[0, 0, 0, 3], b"peer/x@R"]),
        reply(0, &[]),
        reply(0, &[]),
        reply(0, &[]),
    ]);
    let (handle, shown) = client.acquire(&cred_request)?;
    assert_eq!(
        (handle, shown.as_str()),
        (CredHandle::new(3), "peer/x@R"),
        "the credential handle and name"
    );
    client.set_neg_mechs(handle, &["2.25.1", "2.25.2"])?;
    client.release_cred(handle)?;
    client.release_context(ContextHandle::new(2))?;
    assert_eq!(
        written(&client),
        [
            encode_request(
                b'A',
                &[
                    b"a",
                    b"p",
                    b"peer/x@R",
                    b"1.2.3,1.3.6.1.5.5.2",
                    b"keytab",
                    b"acceptor"
                ]
            )?,
            encode_request(b'S', &[&[0, 0, 0, 3], b"2.25.1,2.25.2"])?,
            encode_request(b'R', &[b"c", &[0, 0, 0, 3]])?,
            encode_request(b'R', &[b"x", &[0, 0, 0, 2]])?,
        ]
        .concat(),
        "the four commands"
    );
    Ok(())
}

/// Init and accept steps carry their documented fields and decode their replies.
#[test]
fn step_commands_carry_their_fields() -> Result<(), Box<dyn Error>> {
    let init_request = InitRequest::new(Name::hostbased("peer@host"))
        .with_cred(CredHandle::new(3))
        .with_mech("1.3.6.1.5.2.5")
        .with_flags(0x1002)
        .with_bindings(b"cb")
        .continuing(ContextHandle::new(2), b"tok");
    let accept_request = AcceptRequest::new(b"in")
        .with_cred(CredHandle::new(3))
        .with_bindings(b"cb")
        .continuing(ContextHandle::new(2));
    let mut client = peer(&[
        reply(
            1,
            &[&[0, 0, 0, 2], b"out", &[0, 0, 0x10, 2], b"1.3.6.1.5.2.5"],
        ),
        reply(
            0,
            &[
                &[0, 0, 0, 2],
                b"",
                &[0, 0, 0, 2],
                b"1.2.840.113554.1.2.2",
                b"user@R",
                &[0, 0, 0, 0],
            ],
        ),
    ]);
    let init_step = client.init_step(&init_request)?;
    assert!(
        init_step.continue_needed() && init_step.source().is_empty(),
        "an init step wants more and has no source"
    );
    assert_eq!(
        (
            init_step.context(),
            init_step.token(),
            init_step.flags(),
            init_step.mech()
        ),
        (ContextHandle::new(2), &b"out"[..], 0x1002, "1.3.6.1.5.2.5"),
        "the init reply"
    );
    let accept_step = client.accept_step(&accept_request)?;
    assert_eq!(
        (
            accept_step.continue_needed(),
            accept_step.source(),
            accept_step.mech()
        ),
        (false, "user@R", "1.2.840.113554.1.2.2"),
        "the accept reply"
    );
    assert_eq!(
        written(&client),
        [
            encode_request(
                b'I',
                &[
                    &[0, 0, 0, 2],
                    &[0, 0, 0, 3],
                    b"h",
                    b"peer@host",
                    b"1.3.6.1.5.2.5",
                    &[0, 0, 0x10, 2],
                    &[1],
                    b"cb",
                    b"tok"
                ]
            )?,
            encode_request(b'C', &[&[0, 0, 0, 2], &[0, 0, 0, 3], &[1], b"cb", b"in"])?,
        ]
        .concat(),
        "the two step commands"
    );
    Ok(())
}

/// `inquire` reads every field of the context.
#[test]
fn inquire_reads_every_context_field() -> Result<(), Box<dyn Error>> {
    let mut client = peer(&[reply(
        0,
        &[
            b"user@R",
            b"peer/h@R",
            &[0, 0, 0x54, 0x60],
            b"1.2.840.113554.1.2.2",
            &[0, 0, 0, 0x2a],
            &[1],
            &[1],
        ],
    )]);
    let info = client.inquire(ContextHandle::new(1))?;
    assert_eq!(
        (
            info.source(),
            info.target(),
            info.lifetime(),
            info.mech(),
            info.flags()
        ),
        ("user@R", "peer/h@R", 0x5460, "1.2.840.113554.1.2.2", 0x2a),
        "the context fields"
    );
    assert!(info.initiated() && info.open(), "initiated and open");
    Ok(())
}
