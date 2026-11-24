# MIT forwarding fixture

`krb-cred.hex` is a KRB-CRED that MIT krb5 1.22.2's own library produced
(`krb5_fwd_tgt_creds` -> `krb5_mk_1cred`, the `F` command of the interop peer adapter,
`scripts/interop/peer-mit/peer/peer_krb.c`), forwarding the forwardable ticket-granting ticket of
the interop realm user `peeruser@TEST.RSKRB5` (obtained with `krb5_get_init_creds_keytab`, forwardable
requested) to the service `peer/mit-peer.test.rskrb5`. It is encrypted under the AES256-CTS-HMAC-SHA1-96
key in `key.hex`, a throwaway key the adapter drew with `krb5_c_make_random_key` for that one message.
The tickets and keys inside belong to the throwaway interop realm of that run (`scripts/interop/mit/`),
which no longer exists; nothing here is a real credential.

Provenance: captured on 2026-11-24 from the live run of the suite `replay`
(`scripts/interop/run.sh test replay`, `tests/interop_replay`, scenario
`mit_forwarded_credentials_cross_the_credential_transport`, run with `RSKRB5_CAPTURE=1`), MIT krb5 1.22.2
(`krb5-1.22.2-final`) built from source in `scripts/interop/peer-mit/Dockerfile`.
Independent of this crate: no byte was produced by it.
