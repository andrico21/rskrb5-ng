//! Fuzz the KCM reply reader on an arbitrary daemon byte stream.
//!
//! Every input is served as the whole reply stream to a fresh blocking
//! client, once for each shape of reply: a cache name, a UUID list, a default
//! principal, one credential, a credential list, a KDC offset and an empty
//! reply. The reader checks the announced length against the limit before it
//! allocates (the limit here is 64 KiB, below the production cap, to keep the
//! target fast), then decodes strictly. None may panic or allocate from an
//! unbounded field.

#![no_main]

use std::io::{self, Cursor, Read, Write};

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::ccache::kcm::{
    client::Client,
    wire::{Residual, Uuid, calls},
};

/// The reply limit of the fuzz client.
const LIMIT: usize = 64 * 1024;

/// A daemon that sends the fuzz input and swallows requests.
struct Daemon<'input>(Cursor<&'input [u8]>);

impl Read for Daemon<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for Daemon<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A client over the fuzz input.
const fn client(data: &[u8]) -> Client<Daemon<'_>> {
    Client::new(Daemon(Cursor::new(data))).with_reply_limit(LIMIT)
}

fuzz_target!(|data: &[u8]| {
    let Some(name) = Residual::new("0:1") else {
        return;
    };
    let uuid = Uuid::new([7; 16]);
    drop(client(data).call(&calls::get_default_cache()));
    drop(client(data).call(&calls::get_cache_uuid_list()));
    drop(client(data).call(&calls::get_principal(&name)));
    drop(client(data).call(&calls::get_cred_by_uuid(&name, uuid)));
    drop(client(data).call(&calls::get_cred_list(&name)));
    drop(client(data).call(&calls::get_kdc_offset(&name)));
    drop(client(data).call(&calls::destroy(&name)));
});
