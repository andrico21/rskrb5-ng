# Mutation campaign register

This register records every mutant that survived the whole-crate
`cargo mutants` campaign (FU-FUZ-01): one row per `missed` or `timeout`
outcome, keyed by the campaign SHA and the full cargo-mutants name with its
location. `scripts/lint-gates/mutants_report.py --register` reads the table at
the end of this file; [`../lint-policy.md`](../lint-policy.md) describes the
schema and the final statuses (`killed` with the test that kills it,
`equivalent` with the reason no caller can observe the change, `hang` for a
timeout that still hangs in a 600 s local re-run). Every row starts `open`;
the triage replaces the status and the proof, and the verification campaign
moves the rows to its own SHA.

## Campaign

- Commit: `91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0` (`main`).
- CI run: [`41348118329`](https://github.com/andrico21/rskrb5-ng/actions/runs/41348118329)
  (`workflow_dispatch`), jobs `mutants (0)` to `mutants (31)`.
- Command per shard: `timeout -k 5m 170m cargo mutants --all-features
  --no-shuffle --cap-lints=true --shard k/32 -j 2` with cargo-mutants 27.1.0,
  `CARGO_BUILD_WARNINGS=allow`, no debug info, and the run confined to a
  cgroup with 12 GiB of memory and no swap. The per-mutant timeout is the one
  cargo-mutants derives from each shard's baseline test time (120 s to 210 s
  in this run).
- Completeness: `mutants_report.py --artifacts <the 32 shard artifacts>
  --expect-shards 32 --campaign 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 --enforce` prints `mutants:
  caught=2779 missed=418 timeout=110 unviable=818 success=0` and `0 problem(s)`.

## Totals

| Outcome | Mutants |
| --- | ---: |
| caught | 2779 |
| missed | 418 |
| timeout | 110 |
| unviable | 818 |
| total | 4125 |

These are the outcomes CI recorded. Four of the unviable mutants are caught
when tested alone (see "Memory kills"), which makes 2783 caught and 814
unviable. The register has 528 rows (418 missed, 110 timeout).

### Earlier campaigns

- `7953988` (8 shards, run `40623509423`): caught 1813, missed 288, timeout 76,
  unviable 641 over the 2818 mutants it reached. Shard 7 uploaded nothing and
  shards 2 and 5 stopped at 359 and 394 of 413 mutants, so the campaign was
  incomplete. The crate has changed a great deal since, so the counts are not
  comparable one to one.
- `38970af` (16 shards, run `41325372774`): incomplete. Shards 9, 11 and 14
  were cut off at the 170-minute wall, and the runners of shards 0, 3, 4, 5
  and 15 were lost mid-run. The losses came from mutants that allocate without
  bound and starve the runner before their timeout fires (see "Memory kills"),
  so the mutation job now runs 32 shards without debug info, inside a memory
  cgroup (`.github/workflows/ci.yml`, commits `5fef86f` and `fd58097`).

### Memory kills

The cgroup's OOM killer ended 14 processes in this campaign (shards 1, 7, 9,
10 and 30, all inside the mutant ranges of the shards whose runners were lost
in run `41325372774`). Each matches one mutant whose log shows the SIGKILL:
10 were recorded as caught (a test binary was killed) and 4 as unviable,
because the killed process was a `rustc` building that mutant while the
other job slot (`-j 2`) held the memory. Each of the 14 was then re-tested
alone (`cargo mutants --all-features --no-shuffle --cap-lints=true -j 1
--baseline=skip --timeout 300 -f <file> --re '^<name>$'`, 8 GiB cgroup, no
swap): all 14 are caught, 11 of them by the OOM kill of their own test run.
None of them is missed or timed out, so the register below is complete; with
the 4 reclassified, the totals are caught 2783 and unviable 814.

| Mutant | CI outcome | Alone |
| --- | --- | --- |
| `src/ccache.rs:1465:5: replace read_array -> Result<[u8; N], Error> with Ok([0; N])` | caught | caught (OOM kill) |
| `src/crypto.rs:1044:9: replace Des3CbcSha1KdEtype::encrypt_data -> Result<(Vec<u8>, Vec<u8>), Error> with Ok((vec![1], vec![]))` | caught | caught (OOM kill) |
| `src/crypto.rs:1841:5: replace aes_cts_encrypt -> Result<(Vec<u8>, Vec<u8>), Error> with Ok((vec![0], vec![]))` | unviable | caught (OOM kill) |
| `src/crypto.rs:1841:5: replace aes_cts_encrypt -> Result<(Vec<u8>, Vec<u8>), Error> with Ok((vec![1], vec![]))` | caught | caught (OOM kill) |
| `src/crypto.rs:1841:5: replace aes_cts_encrypt -> Result<(Vec<u8>, Vec<u8>), Error> with Ok((vec![], vec![]))` | caught | caught (OOM kill) |
| `src/crypto.rs:2002:5: replace des3_cbc_encrypt -> Result<(Vec<u8>, Vec<u8>), Error> with Ok((vec![1], vec![]))` | caught | caught (OOM kill) |
| `src/crypto.rs:2031:5: replace des3_cbc_decrypt -> Result<Vec<u8>, Error> with Ok(vec![1])` | unviable | caught (test failure) |
| `src/crypto.rs:312:9: replace AesSha1Etype::encrypt_data -> Result<(Vec<u8>, Vec<u8>), Error> with Ok((vec![0], vec![]))` | caught | caught (OOM kill) |
| `src/crypto.rs:312:9: replace AesSha1Etype::encrypt_data -> Result<(Vec<u8>, Vec<u8>), Error> with Ok((vec![1], vec![]))` | caught | caught (OOM kill) |
| `src/crypto.rs:312:9: replace AesSha1Etype::encrypt_data -> Result<(Vec<u8>, Vec<u8>), Error> with Ok((vec![], vec![1]))` | unviable | caught (test failure) |
| `src/crypto.rs:312:9: replace AesSha1Etype::encrypt_data -> Result<(Vec<u8>, Vec<u8>), Error> with Ok((vec![], vec![]))` | caught | caught (OOM kill) |
| `src/spnego/der.rs:234:21: replace == with != in decode_base128` | unviable | caught (test failure) |
| `src/spnego/der.rs:234:5: replace decode_base128 -> Result<u64, Error> with Ok(0)` | caught | caught (OOM kill) |
| `src/spnego/der.rs:234:5: replace decode_base128 -> Result<u64, Error> with Ok(1)` | caught | caught (OOM kill) |

## Shards

Wall time is the cargo-mutants run (`start_time` to `end_time` of the shard's
`outcomes.json`); the job time adds checkout, the cargo-mutants install and the
upload. Every shard finished well inside the 170-minute wall.

| Shard | Job | Mutants | Caught | Missed | Timeout | Unviable | OOM kills | Wall time (min) | Job time (min) |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 124972224071 | 129 | 84 | 13 | 0 | 32 | 0 | 48.7 | 50 |
| 1 | 124972224192 | 129 | 105 | 6 | 0 | 18 | 1 | 47.4 | 49 |
| 2 | 124972224336 | 129 | 74 | 7 | 0 | 48 | 0 | 29.4 | 31 |
| 3 | 124972224199 | 129 | 47 | 16 | 0 | 66 | 0 | 21.6 | 22 |
| 4 | 124972224390 | 129 | 89 | 3 | 1 | 36 | 0 | 28.4 | 29 |
| 5 | 124972224155 | 129 | 97 | 9 | 9 | 14 | 0 | 65.6 | 67 |
| 6 | 124972224176 | 129 | 83 | 18 | 1 | 27 | 0 | 55.7 | 57 |
| 7 | 124972224135 | 129 | 113 | 4 | 5 | 7 | 4 | 42.7 | 44 |
| 8 | 124972224404 | 129 | 123 | 3 | 0 | 3 | 0 | 49.5 | 51 |
| 9 | 124972224343 | 129 | 109 | 13 | 3 | 4 | 1 | 69.1 | 70 |
| 10 | 124972224099 | 129 | 115 | 8 | 2 | 4 | 5 | 68.3 | 70 |
| 11 | 124972224124 | 129 | 100 | 23 | 0 | 6 | 0 | 44.0 | 45 |
| 12 | 124972224209 | 129 | 48 | 6 | 3 | 72 | 0 | 37.4 | 38 |
| 13 | 124972224158 | 129 | 77 | 12 | 0 | 40 | 0 | 51.4 | 53 |
| 14 | 124972224132 | 129 | 92 | 4 | 0 | 33 | 0 | 36.1 | 37 |
| 15 | 124972224156 | 129 | 82 | 17 | 0 | 30 | 0 | 58.4 | 60 |
| 16 | 124972224222 | 129 | 85 | 18 | 0 | 26 | 0 | 71.1 | 72 |
| 17 | 124972224178 | 129 | 85 | 9 | 0 | 35 | 0 | 43.8 | 45 |
| 18 | 124972224254 | 129 | 89 | 16 | 0 | 24 | 0 | 46.8 | 48 |
| 19 | 124972224286 | 129 | 89 | 19 | 0 | 21 | 0 | 39.7 | 41 |
| 20 | 124972224247 | 129 | 100 | 13 | 0 | 16 | 0 | 55.1 | 56 |
| 21 | 124972224305 | 129 | 62 | 13 | 4 | 50 | 0 | 48.2 | 50 |
| 22 | 124972224328 | 129 | 38 | 6 | 34 | 51 | 0 | 90.1 | 92 |
| 23 | 124972225341 | 129 | 71 | 21 | 23 | 14 | 0 | 74.7 | 76 |
| 24 | 124972224171 | 129 | 94 | 15 | 12 | 8 | 0 | 70.0 | 71 |
| 25 | 124972224263 | 129 | 87 | 36 | 0 | 6 | 0 | 69.2 | 70 |
| 26 | 124972224259 | 129 | 85 | 19 | 1 | 24 | 0 | 39.7 | 41 |
| 27 | 124972224235 | 129 | 81 | 14 | 0 | 34 | 0 | 57.5 | 59 |
| 28 | 124972224214 | 129 | 97 | 22 | 0 | 10 | 0 | 80.5 | 82 |
| 29 | 124972224331 | 129 | 97 | 16 | 0 | 16 | 0 | 50.2 | 51 |
| 30 | 124972224323 | 129 | 96 | 9 | 0 | 24 | 3 | 52.6 | 54 |
| 31 | 124972224251 | 126 | 85 | 10 | 12 | 19 | 0 | 54.4 | 56 |

## Open rows per file

Todo 19 triages the acceptor, HTTP, client, transport and kadmin files
(`src/spnego*`, `src/der.rs`, `src/http.rs`, `src/service*`, `src/client.rs`,
`src/client/**`, `src/kadmin*`); todo 20 triages the rest.

| File | Missed | Timeout | Rows | Triage |
| --- | ---: | ---: | ---: | --- |
| `src/ap_rep.rs` | 6 | 0 | 6 | todo 20 |
| `src/ap_req.rs` | 4 | 0 | 4 | todo 20 |
| `src/bin/rskrb5-compat-report.rs` | 1 | 0 | 1 | todo 20 |
| `src/ccache.rs` | 6 | 0 | 6 | todo 20 |
| `src/client.rs` | 35 | 5 | 40 | todo 19 |
| `src/client/crypto_policy.rs` | 1 | 0 | 1 | todo 19 |
| `src/client/kpasswd.rs` | 4 | 0 | 4 | todo 19 |
| `src/client/kpasswd/request.rs` | 1 | 0 | 1 | todo 19 |
| `src/client/negotiate.rs` | 2 | 0 | 2 | todo 19 |
| `src/client/password.rs` | 1 | 0 | 1 | todo 19 |
| `src/client/principal.rs` | 3 | 0 | 3 | todo 19 |
| `src/client/renewal_eligibility.rs` | 1 | 0 | 1 | todo 19 |
| `src/client/reply_constraints.rs` | 11 | 0 | 11 | todo 19 |
| `src/client/time.rs` | 1 | 0 | 1 | todo 19 |
| `src/client/transport.rs` | 11 | 52 | 63 | todo 19 |
| `src/client/transport/password_delivery.rs` | 2 | 4 | 6 | todo 19 |
| `src/client/transport/password_dns.rs` | 1 | 0 | 1 | todo 19 |
| `src/client/transport/realm_auto.rs` | 4 | 6 | 10 | todo 19 |
| `src/client/transport/srv_targets.rs` | 1 | 0 | 1 | todo 19 |
| `src/client/transport/udp.rs` | 1 | 2 | 3 | todo 19 |
| `src/config.rs` | 21 | 10 | 31 | todo 20 |
| `src/config/credential_names.rs` | 5 | 0 | 5 | todo 20 |
| `src/config/expansion.rs` | 8 | 0 | 8 | todo 20 |
| `src/config/hostname.rs` | 1 | 0 | 1 | todo 20 |
| `src/config/libdefaults.rs` | 1 | 0 | 1 | todo 20 |
| `src/config/libdefaults/duration.rs` | 1 | 0 | 1 | todo 20 |
| `src/config/profile.rs` | 1 | 9 | 10 | todo 20 |
| `src/config/profile_syntax.rs` | 5 | 12 | 17 | todo 20 |
| `src/config/protocol.rs` | 6 | 0 | 6 | todo 20 |
| `src/config/realm_values.rs` | 3 | 0 | 3 | todo 20 |
| `src/config/section_decode.rs` | 7 | 0 | 7 | todo 20 |
| `src/config/unknown.rs` | 26 | 0 | 26 | todo 20 |
| `src/crypto.rs` | 27 | 6 | 33 | todo 20 |
| `src/crypto/checked.rs` | 4 | 0 | 4 | todo 20 |
| `src/crypto/policy.rs` | 4 | 0 | 4 | todo 20 |
| `src/crypto/scratch.rs` | 0 | 1 | 1 | todo 20 |
| `src/crypto/selection.rs` | 15 | 0 | 15 | todo 20 |
| `src/crypto/verification.rs` | 1 | 0 | 1 | todo 20 |
| `src/der.rs` | 14 | 0 | 14 | todo 19 |
| `src/evaluation.rs` | 2 | 0 | 2 | todo 20 |
| `src/evaluation/data.rs` | 8 | 0 | 8 | todo 20 |
| `src/file_name.rs` | 7 | 0 | 7 | todo 20 |
| `src/http.rs` | 6 | 3 | 9 | todo 19 |
| `src/kadmin/password.rs` | 2 | 0 | 2 | todo 19 |
| `src/kadmin/reply.rs` | 1 | 0 | 1 | todo 19 |
| `src/kadmin/secret_der.rs` | 4 | 0 | 4 | todo 19 |
| `src/kdc_rep.rs` | 4 | 0 | 4 | todo 20 |
| `src/kdc_req.rs` | 5 | 0 | 5 | todo 20 |
| `src/keytab.rs` | 4 | 0 | 4 | todo 20 |
| `src/krb_cred.rs` | 3 | 0 | 3 | todo 20 |
| `src/krb_cred/conversion.rs` | 2 | 0 | 2 | todo 20 |
| `src/krb_cred/import.rs` | 1 | 0 | 1 | todo 20 |
| `src/krb_priv.rs` | 2 | 0 | 2 | todo 20 |
| `src/krb_safe.rs` | 1 | 0 | 1 | todo 20 |
| `src/pac.rs` | 25 | 0 | 25 | todo 20 |
| `src/pac/credential_secrets.rs` | 2 | 0 | 2 | todo 20 |
| `src/pac/ndr.rs` | 27 | 0 | 27 | todo 20 |
| `src/pac/reader.rs` | 1 | 0 | 1 | todo 20 |
| `src/service.rs` | 13 | 0 | 13 | todo 19 |
| `src/service/replay.rs` | 5 | 0 | 5 | todo 19 |
| `src/service/replay_quota.rs` | 4 | 0 | 4 | todo 19 |
| `src/service/validation.rs` | 1 | 0 | 1 | todo 19 |
| `src/spnego.rs` | 25 | 0 | 25 | todo 19 |
| `src/spnego/der.rs` | 8 | 0 | 8 | todo 19 |
| `src/spnego/negotiation.rs` | 2 | 0 | 2 | todo 19 |
| `src/spnego/oid.rs` | 3 | 0 | 3 | todo 19 |
| `src/ticket.rs` | 3 | 0 | 3 | todo 20 |
| total | 418 | 110 | 528 | todo 19: 240, todo 20: 288 |

## Register

| campaign | mutant (full name) | file | function | operator | outcome | status | proof or reason |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/ap_rep.rs:167:5: replace build_encoded -> Result<Vec<u8>, Error> with Ok(vec![0])` | src/ap_rep.rs | build_encoded | replace body with Ok(vec![0]) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/ap_rep.rs:167:5: replace build_encoded -> Result<Vec<u8>, Error> with Ok(vec![1])` | src/ap_rep.rs | build_encoded | replace body with Ok(vec![1]) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/ap_rep.rs:167:5: replace build_encoded -> Result<Vec<u8>, Error> with Ok(vec![])` | src/ap_rep.rs | build_encoded | replace body with Ok(vec![]) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/ap_rep.rs:225:5: replace validate_integer -> Result<(), Error> with Ok(())` | src/ap_rep.rs | validate_integer | replace body with Ok(()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/ap_rep.rs:42:5: replace validate -> Result<(), Error> with Ok(())` | src/ap_rep.rs | validate | replace body with Ok(()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/ap_rep.rs:95:87: replace < with <= in decrypt_ap_rep_enc_part` | src/ap_rep.rs | decrypt_ap_rep_enc_part | replace < with <= | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/ap_req.rs:232:5: replace build_encoded -> Result<Vec<u8>, Error> with Ok(vec![0])` | src/ap_req.rs | build_encoded | replace body with Ok(vec![0]) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/ap_req.rs:232:5: replace build_encoded -> Result<Vec<u8>, Error> with Ok(vec![1])` | src/ap_req.rs | build_encoded | replace body with Ok(vec![1]) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/ap_req.rs:232:5: replace build_encoded -> Result<Vec<u8>, Error> with Ok(vec![])` | src/ap_req.rs | build_encoded | replace body with Ok(vec![]) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/ap_req.rs:45:5: replace validate -> Result<(), Error> with Ok(())` | src/ap_req.rs | validate | replace body with Ok(()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/bin/rskrb5-compat-report.rs:13:5: replace main -> io::Result<()> with Ok(())` | src/bin/rskrb5-compat-report.rs | main | replace body with Ok(()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/ccache.rs:1409:26: replace \|\| with && in Endian::for_version` | src/ccache.rs | Endian::for_version | replace \|\| with && | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/ccache.rs:543:9: replace CCache::contains_server -> bool with true` | src/ccache.rs | CCache::contains_server | replace body with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/ccache.rs:675:23: replace match guard error.kind() == io::ErrorKind::NotFound with true in dir_collection_primary_path` | src/ccache.rs | dir_collection_primary_path | replace match guard error.kind() == io::ErrorKind::NotFound with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/ccache.rs:677:16: delete ! in dir_collection_primary_path` | src/ccache.rs | dir_collection_primary_path | delete ! | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/ccache.rs:703:75: replace \|\| with && in parse_dir_primary_name` | src/ccache.rs | parse_dir_primary_name | replace \|\| with && | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/ccache.rs:723:40: replace \|\| with && in parse_config_entry` | src/ccache.rs | parse_config_entry | replace \|\| with && | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:1189:46: replace match guard error.kind() == io::ErrorKind::NotFound with false in Tokio::update_ccache_file` | src/client.rs | Tokio::update_ccache_file | replace match guard error.kind() == io::ErrorKind::NotFound with false | missed | killed | `file_update_distinguishes_missing_from_unreadable` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:1189:46: replace match guard error.kind() == io::ErrorKind::NotFound with true in Tokio::update_ccache_file` | src/client.rs | Tokio::update_ccache_file | replace match guard error.kind() == io::ErrorKind::NotFound with true | missed | killed | `file_update_distinguishes_missing_from_unreadable` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:1189:59: replace == with != in Tokio::update_ccache_file` | src/client.rs | Tokio::update_ccache_file | replace == with != | missed | killed | `file_update_distinguishes_missing_from_unreadable` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:1461:9: replace Tokio::assume_preauthentication -> bool with true` | src/client.rs | Tokio::assume_preauthentication | replace body with true | missed | killed | `login_setting_queries_preserve_both_values` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:1467:9: replace Tokio::fast_negotiation -> bool with false` | src/client.rs | Tokio::fast_negotiation | replace body with false | missed | killed | `login_setting_queries_preserve_both_values` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:1669:31: replace >= with < in Tokio::affirm_login` | src/client.rs | Tokio::affirm_login | replace >= with < | missed | equivalent | Valid sessions return at 1665; session_renewable_at requires validity at the same captured now. The later renewal branch is unreachable, so expired has no observable consumer here. |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:1673:51: delete ! in Tokio::affirm_login` | src/client.rs | Tokio::affirm_login | delete ! | missed | equivalent | Renewal eligibility requires validity, but valid sessions already returned using the same now; both renewal predicates are therefore false. |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:1673:61: replace && with \|\| in Tokio::affirm_login` | src/client.rs | Tokio::affirm_login | replace && with \|\| | missed | equivalent | Outer renewal eligibility is false after the earlier same-now valid-session return; the mutated inner expression cannot affect control flow. |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:1678:35: delete ! in Tokio::affirm_login` | src/client.rs | Tokio::affirm_login | delete ! | missed | equivalent | Renewal error arm is unreachable: renewal eligibility requires validity that already caused an early return using the same now. |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:1678:35: replace match guard !has_credentials with false in Tokio::affirm_login` | src/client.rs | Tokio::affirm_login | replace match guard !has_credentials with false | missed | equivalent | Renewal error arm is unreachable after the valid-session return because renewal requires validity at the same captured now. |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:1678:35: replace match guard !has_credentials with true in Tokio::affirm_login` | src/client.rs | Tokio::affirm_login | replace match guard !has_credentials with true | missed | equivalent | Renewal error arm is unreachable after the valid-session return because renewal requires validity at the same captured now. |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:1865:21: replace match guard service.realm != self.client.realm with false in Tokio::get_service_ticket` | src/client.rs | Tokio::get_service_ticket | replace match guard service.realm != self.client.realm with false | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:1865:21: replace match guard service.realm != self.client.realm with true in Tokio::get_service_ticket` | src/client.rs | Tokio::get_service_ticket | replace match guard service.realm != self.client.realm with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:1865:35: replace != with == in Tokio::get_service_ticket` | src/client.rs | Tokio::get_service_ticket | replace != with == | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:2017:9: replace Tokio::spnego_header_with_options -> Result<String, Error> with Ok("xyzzy".into())` | src/client.rs | Tokio::spnego_header_with_options | replace body with Ok("xyzzy".into()) | missed | killed | `cached_header_apis_emit_initial_tokens` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:2017:9: replace Tokio::spnego_header_with_options -> Result<String, Error> with Ok(String::new())` | src/client.rs | Tokio::spnego_header_with_options | replace body with Ok(String::new()) | missed | killed | `cached_header_apis_emit_initial_tokens` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:2093:39: replace match guard !has_credentials with false in Tokio::ensure_tgt` | src/client.rs | Tokio::ensure_tgt | replace match guard !has_credentials with false | missed | killed | `due_tgt_renewal_error_is_preserved` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:2174:9: replace Tokio::cached_tgt_session_for_realm -> Option<AsRepSession> with None` | src/client.rs | Tokio::cached_tgt_session_for_realm | replace body with None | missed | killed | `realm_cache_lookup_returns_live_ticket` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:2192:9: replace Tokio::renew_cached_tgt_session_for_realm -> Result<Option<AsRepSession>, Error> with Ok(None)` | src/client.rs | Tokio::renew_cached_tgt_session_for_realm | replace body with Ok(None) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:2209:26: replace == with != in Tokio::renew_cached_tgt_session_for_realm` | src/client.rs | Tokio::renew_cached_tgt_session_for_realm | replace == with != | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:2879:50: replace != with == in build_s4u2self_req_with_confounder` | src/client.rs | build_s4u2self_req_with_confounder | replace != with == | missed | killed | `s4u_replaces_only_impersonation_padata` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:3841:5: replace ticket_flags_contain_bits -> bool with true` | src/client.rs | ticket_flags_contain_bits | replace body with true | missed | killed | `ticket_flag_membership_requires_all_bits` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:4357:38: replace == with != in password_initial_as_rep_session` | src/client.rs | password_initial_as_rep_session | replace == with != | missed | killed | `initial_as_reply_uses_legacy_password_salt` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:4555:5: replace ensure_permitted_enctype -> Result<(), Error> with Ok(())` | src/client.rs | ensure_permitted_enctype | replace body with Ok(()) | missed | killed | `permitted_enctype_requires_membership` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:4712:5: replace principal_matches -> bool with true` | src/client.rs | principal_matches | replace body with true | timeout | killed | `principal_matching_preserves_identity` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:4798:10: replace \| with ^ in renewal_kdc_option_bits` | src/client.rs | renewal_kdc_option_bits | replace \| with ^ | missed | killed | `renewal_options_are_idempotent` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:4798:33: replace \| with ^ in renewal_kdc_option_bits` | src/client.rs | renewal_kdc_option_bits | replace \| with ^ | missed | equivalent | XOR binds tighter than OR: bits OR (RENEWABLE XOR RENEW). These two constants have disjoint bits, so their XOR equals their OR for every caller-supplied bits value. |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:4803:5: replace ticket_flags_to_bytes -> [u8; 4] with [1; 4]` | src/client.rs | ticket_flags_to_bytes | replace body with [1; 4] | timeout | killed | `ticket_flag_membership_requires_all_bits` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:4882:31: replace && with \|\| in same_ccache_client_identity` | src/client.rs | same_ccache_client_identity | replace && with \|\| | missed | killed | `ccache_identity_requires_both_coordinates` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:4882:5: replace same_ccache_client_identity -> bool with true` | src/client.rs | same_ccache_client_identity | replace body with true | missed | killed | `ccache_identity_requires_both_coordinates` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:4959:9: delete match arm (false, true) in prefer_current_session_at` | src/client.rs | prefer_current_session_at | delete match arm (false, true) | missed | killed | `valid_candidate_beats_longer_invalid_session` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:4973:5: replace session_valid_at -> bool with true` | src/client.rs | session_valid_at | replace body with true | timeout | killed | `session_validity_boundaries` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:4974:9: replace && with \|\| in session_valid_at` | src/client.rs | session_valid_at | replace && with \|\| | timeout | killed | `session_validity_boundaries` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:4975:16: replace < with <= in session_valid_at` | src/client.rs | session_valid_at | replace < with <= | missed | killed | `session_validity_boundaries` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:4975:9: replace && with \|\| in session_valid_at` | src/client.rs | session_valid_at | replace && with \|\| | timeout | killed | `session_validity_boundaries` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:4981:36: replace \|\| with && in session_usable_at` | src/client.rs | session_usable_at | replace \|\| with && | missed | killed | `session_validity_boundaries` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:5069:16: replace < with <= in system_time_to_u32_seconds` | src/client.rs | system_time_to_u32_seconds | replace < with <= | missed | killed | `cache_timestamp_epoch_boundaries` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:5069:16: replace < with == in system_time_to_u32_seconds` | src/client.rs | system_time_to_u32_seconds | replace < with == | missed | killed | `cache_timestamp_epoch_boundaries` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:624:9: replace <impl fmt::Debug for TokioClientCredentials>::fmt -> fmt::Result with Ok(Default::default())` | src/client.rs | <impl fmt::Debug for TokioClientCredentials>::fmt | replace body with Ok(Default::default()) | missed | killed | `audited_debug_redacts_secret_fields` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client.rs:723:53: replace && with \|\| in PrunedSessions::is_empty` | src/client.rs | PrunedSessions::is_empty | replace && with \|\| | missed | killed | `prune_reports_each_nonempty_field` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/crypto_policy.rs:20:5: replace padata -> Result<(), Error> with Ok(())` | src/client/crypto_policy.rs | padata | replace body with Ok(()) | missed | killed | `padata_policy_rejects_draft9` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/kpasswd.rs:303:23: replace > with == in validated_result` | src/client/kpasswd.rs | validated_result | replace > with == | missed | killed | `checked_reply_fixtures_are_valid` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/kpasswd.rs:303:23: replace > with >= in validated_result` | src/client/kpasswd.rs | validated_result | replace > with >= | missed | killed | `checked_reply_fixtures_are_valid` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/kpasswd.rs:303:33: replace \|\| with && in validated_result` | src/client/kpasswd.rs | validated_result | replace \|\| with && | missed | killed | `checked_helpers_reject_invalid_contexts` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/kpasswd.rs:316:21: replace > with >= in validated_result` | src/client/kpasswd.rs | validated_result | replace > with >= | missed | killed | `checked_reply_fixtures_are_valid` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/kpasswd/request.rs:38:49: replace != with == in build_kpasswd_ap_req_with_confounder` | src/client/kpasswd/request.rs | build_kpasswd_ap_req_with_confounder | replace != with == | missed | killed | `whole_pre_epoch_request_builds` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/negotiate.rs:181:9: replace Client::authorization_header -> Result<String, Error> with Ok("xyzzy".into())` | src/client/negotiate.rs | Client::authorization_header | replace body with Ok("xyzzy".into()) | missed | killed | `cached_header_apis_emit_initial_tokens` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/negotiate.rs:181:9: replace Client::authorization_header -> Result<String, Error> with Ok(String::new())` | src/client/negotiate.rs | Client::authorization_header | replace body with Ok(String::new()) | missed | killed | `cached_header_apis_emit_initial_tokens` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/password.rs:71:9: replace <impl fmt::Debug for Secret>::fmt -> fmt::Result with Ok(Default::default())` | src/client/password.rs | <impl fmt::Debug for Secret>::fmt | replace body with Ok(Default::default()) | missed | killed | `borrowed_input_and_debug_are_explicit` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/principal.rs:218:28: replace < with <= in parse_name_and_realm` | src/client/principal.rs | parse_name_and_realm | replace < with <= | missed | equivalent | This else branch requires parts.len() != 2, so the only boundary where the comparisons differ is unreachable. |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/principal.rs:218:28: replace < with == in parse_name_and_realm` | src/client/principal.rs | parse_name_and_realm | replace < with == | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/principal.rs:218:28: replace < with > in parse_name_and_realm` | src/client/principal.rs | parse_name_and_realm | replace < with > | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/renewal_eligibility.rs:14:43: replace < with <= in session_renewable_at` | src/client/renewal_eligibility.rs | session_renewable_at | replace < with <= | missed | equivalent | Validity requires now < end_time; the same predicate requires end_time <= renew_till, hence now < renew_till already follows. Equality cannot pass the other conjuncts. |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/reply_constraints.rs:38:20: replace & with ^ in validate` | src/client/reply_constraints.rs | validate | replace & with ^ | missed | killed | `requested_from_binds_only_postdated_replies` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/reply_constraints.rs:38:20: replace & with \| in validate` | src/client/reply_constraints.rs | validate | replace & with \| | missed | killed | `requested_from_binds_only_postdated_replies` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/reply_constraints.rs:38:32: replace != with == in validate` | src/client/reply_constraints.rs | validate | replace != with == | missed | killed | `requested_from_binds_only_postdated_replies` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/reply_constraints.rs:40:16: replace == with != in validate` | src/client/reply_constraints.rs | validate | replace == with != | missed | killed | `requested_from_binds_only_postdated_replies` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/reply_constraints.rs:42:29: replace \| with & in validate` | src/client/reply_constraints.rs | validate | replace \| with & | missed | killed | `requested_from_binds_only_postdated_replies` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/reply_constraints.rs:42:29: replace \| with ^ in validate` | src/client/reply_constraints.rs | validate | replace \| with ^ | missed | equivalent | POSTDATED (0x02000000) and VALIDATE (0x00000001) have disjoint set bits, so OR equals XOR for every options value. |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/reply_constraints.rs:51:20: replace & with \| in validate` | src/client/reply_constraints.rs | validate | replace & with \| | missed | killed | `unrequested_renewal_metadata_ignores_optional_bounds` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/reply_constraints.rs:56:59: replace & with \| in validate` | src/client/reply_constraints.rs | validate | replace & with \| | missed | killed | `unrequested_renewal_metadata_ignores_optional_bounds` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/reply_constraints.rs:63:36: replace \| with ^ in validate` | src/client/reply_constraints.rs | validate | replace \| with ^ | missed | equivalent | RENEW (0x00000002) and VALIDATE (0x00000001) have disjoint set bits; the mask is identical under OR and XOR. |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/reply_constraints.rs:65:29: replace \| with ^ in validate` | src/client/reply_constraints.rs | validate | replace \| with ^ | missed | equivalent | POSTDATED (0x02000000) and INVALID (0x01000000) have disjoint set bits; OR and XOR produce the same flag mask. |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/reply_constraints.rs:67:79: replace \| with ^ in validate` | src/client/reply_constraints.rs | validate | replace \| with ^ | missed | equivalent | RENEWABLE (0x00800000) and RENEWABLE_OK (0x00000010) have disjoint set bits; OR and XOR produce the same request mask. |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/time.rs:15:16: replace < with <= in from_kerberos` | src/client/time.rs | from_kerberos | replace < with <= | missed | equivalent | Only seconds=0 changes branch; checked addition and subtraction of Duration::ZERO both return UNIX_EPOCH. |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:2053:60: replace && with \|\| in Tokio::discover_srv_endpoints` | src/client/transport.rs | Tokio::discover_srv_endpoints | replace && with \|\| | missed | equivalent | Wire-decoded DNS names are fully qualified; the earlier is_root check rejects zero-label names. Remaining names contain a nonempty label (literal label dots are escaped by Hickory), so trimming terminal dots leaves neither empty nor dot. Both predicates are true for every reachable target. |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:2086:9: replace Tokio::send_to_endpoints -> Result<Vec<u8>, Error> with Ok(vec![0])` | src/client/transport.rs | Tokio::send_to_endpoints | replace body with Ok(vec![0]) | timeout | killed | `configured_auto_logins_reuse_connection` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:2086:9: replace Tokio::send_to_endpoints -> Result<Vec<u8>, Error> with Ok(vec![1])` | src/client/transport.rs | Tokio::send_to_endpoints | replace body with Ok(vec![1]) | timeout | killed | `configured_auto_logins_reuse_connection` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:2086:9: replace Tokio::send_to_endpoints -> Result<Vec<u8>, Error> with Ok(vec![])` | src/client/transport.rs | Tokio::send_to_endpoints | replace body with Ok(vec![]) | timeout | killed | `configured_auto_logins_reuse_connection` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:2113:9: replace Tokio::send_to_endpoints_pinned -> Result<(Vec<u8>, Option<TcpStream>), Error> with Ok((vec![0], None))` | src/client/transport.rs | Tokio::send_to_endpoints_pinned | replace body with Ok((vec![0], None)) | timeout | killed | `configured_auto_logins_reuse_connection` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:2113:9: replace Tokio::send_to_endpoints_pinned -> Result<(Vec<u8>, Option<TcpStream>), Error> with Ok((vec![1], None))` | src/client/transport.rs | Tokio::send_to_endpoints_pinned | replace body with Ok((vec![1], None)) | timeout | killed | `configured_auto_logins_reuse_connection` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:2113:9: replace Tokio::send_to_endpoints_pinned -> Result<(Vec<u8>, Option<TcpStream>), Error> with Ok((vec![], None))` | src/client/transport.rs | Tokio::send_to_endpoints_pinned | replace body with Ok((vec![], None)) | timeout | killed | `tokio_transport_auto_honors_tcp_first_udp_preference_limit` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:2162:9: replace Tokio::send_to_realm_auto -> Result<(Vec<u8>, Option<TcpStream>), Error> with Ok((vec![0], None))` | src/client/transport.rs | Tokio::send_to_realm_auto | replace body with Ok((vec![0], None)) | timeout | killed | `tokio_transport_auto_honors_tcp_first_udp_preference_limit` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:2162:9: replace Tokio::send_to_realm_auto -> Result<(Vec<u8>, Option<TcpStream>), Error> with Ok((vec![1], None))` | src/client/transport.rs | Tokio::send_to_realm_auto | replace body with Ok((vec![1], None)) | timeout | killed | `tokio_transport_auto_honors_tcp_first_udp_preference_limit` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:2162:9: replace Tokio::send_to_realm_auto -> Result<(Vec<u8>, Option<TcpStream>), Error> with Ok((vec![], None))` | src/client/transport.rs | Tokio::send_to_realm_auto | replace body with Ok((vec![], None)) | timeout | killed | `tokio_transport_auto_honors_tcp_first_udp_preference_limit` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:2185:9: replace Tokio::send_to_kpasswd_realm_auto -> Result<Vec<u8>, Error> with Ok(vec![0])` | src/client/transport.rs | Tokio::send_to_kpasswd_realm_auto | replace body with Ok(vec![0]) | timeout | killed | `kpasswd_udp_timeout_does_not_retry_tcp` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:2185:9: replace Tokio::send_to_kpasswd_realm_auto -> Result<Vec<u8>, Error> with Ok(vec![1])` | src/client/transport.rs | Tokio::send_to_kpasswd_realm_auto | replace body with Ok(vec![1]) | timeout | killed | `kpasswd_udp_timeout_does_not_retry_tcp` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:2185:9: replace Tokio::send_to_kpasswd_realm_auto -> Result<Vec<u8>, Error> with Ok(vec![])` | src/client/transport.rs | Tokio::send_to_kpasswd_realm_auto | replace body with Ok(vec![]) | timeout | killed | `kpasswd_udp_timeout_does_not_retry_tcp` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:2283:5: replace srv_draw -> Result<u64, Error> with Ok(0)` | src/client/transport.rs | srv_draw | replace body with Ok(0) | missed | killed | `srv_draw_rejects_overflowing_range` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:2292:18: replace >= with < in srv_draw` | src/client/transport.rs | srv_draw | replace >= with < | timeout | killed | `srv_draw_singleton_terminates` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:2322:5: replace parse_kdc_endpoint -> Result<(String, u16), Error> with Ok(("xyzzy".into(), 0))` | src/client/transport.rs | parse_kdc_endpoint | replace body with Ok(("xyzzy".into(), 0)) | timeout | killed | `endpoint_port_boundaries` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:2322:5: replace parse_kdc_endpoint -> Result<(String, u16), Error> with Ok(("xyzzy".into(), 1))` | src/client/transport.rs | parse_kdc_endpoint | replace body with Ok(("xyzzy".into(), 1)) | timeout | killed | `endpoint_port_boundaries` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:2322:5: replace parse_kdc_endpoint -> Result<(String, u16), Error> with Ok((String::new(), 0))` | src/client/transport.rs | parse_kdc_endpoint | replace body with Ok((String::new(), 0)) | timeout | killed | `endpoint_port_boundaries` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:2322:5: replace parse_kdc_endpoint -> Result<(String, u16), Error> with Ok((String::new(), 1))` | src/client/transport.rs | parse_kdc_endpoint | replace body with Ok((String::new(), 1)) | timeout | killed | `endpoint_port_boundaries` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:2349:12: delete ! in parse_kdc_endpoint` | src/client/transport.rs | parse_kdc_endpoint | delete ! | timeout | killed | `endpoint_port_boundaries` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:2350:12: delete ! in parse_kdc_endpoint` | src/client/transport.rs | parse_kdc_endpoint | delete ! | timeout | killed | `endpoint_port_boundaries` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:2352:12: delete ! in parse_kdc_endpoint` | src/client/transport.rs | parse_kdc_endpoint | delete ! | timeout | killed | `endpoint_port_boundaries` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:2372:5: replace parse_kdc_port -> Result<u16, Error> with Ok(0)` | src/client/transport.rs | parse_kdc_port | replace body with Ok(0) | timeout | killed | `endpoint_port_boundaries` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:2372:5: replace parse_kdc_port -> Result<u16, Error> with Ok(1)` | src/client/transport.rs | parse_kdc_port | replace body with Ok(1) | timeout | killed | `endpoint_port_boundaries` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:2481:5: replace kdc_error_code -> Option<i32> with None` | src/client/transport.rs | kdc_error_code | replace body with None | timeout | killed | `direct_auto_classifies_udp_reply` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:2481:5: replace kdc_error_code -> Option<i32> with Some(-1)` | src/client/transport.rs | kdc_error_code | replace body with Some(-1) | timeout | killed | `configured_auto_classifies_protocol_and_reply` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:2481:5: replace kdc_error_code -> Option<i32> with Some(0)` | src/client/transport.rs | kdc_error_code | replace body with Some(0) | timeout | killed | `configured_auto_classifies_protocol_and_reply` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:2481:5: replace kdc_error_code -> Option<i32> with Some(1)` | src/client/transport.rs | kdc_error_code | replace body with Some(1) | timeout | killed | `configured_auto_classifies_protocol_and_reply` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:2489:36: replace < with <= in auto_uses_udp_first` | src/client/transport.rs | auto_uses_udp_first | replace < with <= | missed | killed | `profile_udp_preference_boundaries` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:293:26: replace > with < in Tokio::send_udp` | src/client/transport.rs | Tokio::send_udp | replace > with < | timeout | killed | `tokio_transport_sends_udp_datagram` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:293:26: replace > with == in Tokio::send_udp` | src/client/transport.rs | Tokio::send_udp | replace > with == | missed | killed | `udp_request_size_boundaries` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:293:26: replace > with >= in Tokio::send_udp` | src/client/transport.rs | Tokio::send_udp | replace > with >= | missed | killed | `udp_request_size_boundaries` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:293:9: replace Tokio::send_udp -> Result<Vec<u8>, Error> with Ok(vec![0])` | src/client/transport.rs | Tokio::send_udp | replace body with Ok(vec![0]) | timeout | killed | `tokio_transport_sends_udp_datagram` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:293:9: replace Tokio::send_udp -> Result<Vec<u8>, Error> with Ok(vec![1])` | src/client/transport.rs | Tokio::send_udp | replace body with Ok(vec![1]) | timeout | killed | `tokio_transport_sends_udp_datagram` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:293:9: replace Tokio::send_udp -> Result<Vec<u8>, Error> with Ok(vec![])` | src/client/transport.rs | Tokio::send_udp | replace body with Ok(vec![]) | timeout | killed | `tokio_transport_sends_udp_datagram` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:415:9: replace Tokio::exchange_tcp -> Result<Vec<u8>, Error> with Ok(vec![0])` | src/client/transport.rs | Tokio::exchange_tcp | replace body with Ok(vec![0]) | timeout | killed | `tokio_transport_auto_honors_tcp_first_udp_preference_limit` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:415:9: replace Tokio::exchange_tcp -> Result<Vec<u8>, Error> with Ok(vec![1])` | src/client/transport.rs | Tokio::exchange_tcp | replace body with Ok(vec![1]) | timeout | killed | `tokio_transport_auto_honors_tcp_first_udp_preference_limit` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:415:9: replace Tokio::exchange_tcp -> Result<Vec<u8>, Error> with Ok(vec![])` | src/client/transport.rs | Tokio::exchange_tcp | replace body with Ok(vec![]) | timeout | killed | `tokio_transport_auto_honors_tcp_first_udp_preference_limit` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:432:9: replace Tokio::exchange_tcp_framed -> Result<Vec<u8>, Error> with Ok(vec![0])` | src/client/transport.rs | Tokio::exchange_tcp_framed | replace body with Ok(vec![0]) | timeout | killed | `tokio_transport_auto_honors_tcp_first_udp_preference_limit` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:432:9: replace Tokio::exchange_tcp_framed -> Result<Vec<u8>, Error> with Ok(vec![1])` | src/client/transport.rs | Tokio::exchange_tcp_framed | replace body with Ok(vec![1]) | timeout | killed | `configured_auto_logins_reuse_connection` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:432:9: replace Tokio::exchange_tcp_framed -> Result<Vec<u8>, Error> with Ok(vec![])` | src/client/transport.rs | Tokio::exchange_tcp_framed | replace body with Ok(vec![]) | timeout | killed | `tokio_transport_auto_honors_tcp_first_udp_preference_limit` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:475:9: replace Tokio::send_pinned -> Result<(Vec<u8>, Option<TcpStream>), Error> with Ok((vec![0], None))` | src/client/transport.rs | Tokio::send_pinned | replace body with Ok((vec![0], None)) | timeout | killed | `configured_auto_logins_reuse_connection` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:475:9: replace Tokio::send_pinned -> Result<(Vec<u8>, Option<TcpStream>), Error> with Ok((vec![1], None))` | src/client/transport.rs | Tokio::send_pinned | replace body with Ok((vec![1], None)) | timeout | killed | `configured_auto_classifies_protocol_and_reply` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:475:9: replace Tokio::send_pinned -> Result<(Vec<u8>, Option<TcpStream>), Error> with Ok((vec![], None))` | src/client/transport.rs | Tokio::send_pinned | replace body with Ok((vec![], None)) | timeout | killed | `tokio_transport_auto_honors_tcp_first_udp_preference_limit` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:485:33: replace match guard kdc_error_code(&response) == Some(KRB_ERR_RESPONSE_TOO_BIG) with false in Tokio::send_pinned` | src/client/transport.rs | Tokio::send_pinned | replace match guard kdc_error_code(&response) == Some(KRB_ERR_RESPONSE_TOO_BIG) with false | missed | killed | `pinned_auto_retries_response_too_big` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:485:33: replace match guard kdc_error_code(&response) == Some(KRB_ERR_RESPONSE_TOO_BIG) with true in Tokio::send_pinned` | src/client/transport.rs | Tokio::send_pinned | replace match guard kdc_error_code(&response) == Some(KRB_ERR_RESPONSE_TOO_BIG) with true | missed | killed | `pinned_auto_preserves_ordinary_udp_reply` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:485:59: replace == with != in Tokio::send_pinned` | src/client/transport.rs | Tokio::send_pinned | replace == with != | missed | killed | `pinned_auto_preserves_ordinary_udp_reply` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:566:37: replace match guard kdc_error_code(&response) == Some(KRB_ERR_RESPONSE_TOO_BIG) with false in Tokio::send` | src/client/transport.rs | Tokio::send | replace match guard kdc_error_code(&response) == Some(KRB_ERR_RESPONSE_TOO_BIG) with false | timeout | killed | `direct_auto_classifies_udp_reply` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:566:37: replace match guard kdc_error_code(&response) == Some(KRB_ERR_RESPONSE_TOO_BIG) with true in Tokio::send` | src/client/transport.rs | Tokio::send | replace match guard kdc_error_code(&response) == Some(KRB_ERR_RESPONSE_TOO_BIG) with true | missed | killed | `direct_auto_classifies_udp_reply` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:566:63: replace == with != in Tokio::send` | src/client/transport.rs | Tokio::send | replace == with != | timeout | killed | `direct_auto_classifies_udp_reply` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:601:9: replace Tokio::discover_kdcs -> Result<Vec<KdcEndpoint>, Error> with Ok(vec![])` | src/client/transport.rs | Tokio::discover_kdcs | replace body with Ok(vec![]) | timeout | killed | `tokio_transport_auto_honors_tcp_first_udp_preference_limit` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:602:16: delete ! in Tokio::discover_kdcs` | src/client/transport.rs | Tokio::discover_kdcs | delete ! | timeout | killed | `tokio_transport_auto_honors_tcp_first_udp_preference_limit` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:704:9: replace Tokio::send_to_realm_pinned -> Result<(Vec<u8>, Option<TcpStream>), Error> with Ok((vec![0], None))` | src/client/transport.rs | Tokio::send_to_realm_pinned | replace body with Ok((vec![0], None)) | timeout | killed | `configured_auto_logins_reuse_connection` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:704:9: replace Tokio::send_to_realm_pinned -> Result<(Vec<u8>, Option<TcpStream>), Error> with Ok((vec![1], None))` | src/client/transport.rs | Tokio::send_to_realm_pinned | replace body with Ok((vec![1], None)) | timeout | killed | `configured_auto_logins_reuse_connection` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:704:9: replace Tokio::send_to_realm_pinned -> Result<(Vec<u8>, Option<TcpStream>), Error> with Ok((vec![], None))` | src/client/transport.rs | Tokio::send_to_realm_pinned | replace body with Ok((vec![], None)) | timeout | killed | `configured_auto_classifies_protocol_and_reply` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:747:9: replace Tokio::send_password_once -> Result<Vec<u8>, Error> with Ok(vec![0])` | src/client/transport.rs | Tokio::send_password_once | replace body with Ok(vec![0]) | timeout | killed | `password_udp_request_size_boundaries` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:747:9: replace Tokio::send_password_once -> Result<Vec<u8>, Error> with Ok(vec![1])` | src/client/transport.rs | Tokio::send_password_once | replace body with Ok(vec![1]) | timeout | killed | `password_udp_request_size_boundaries` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:747:9: replace Tokio::send_password_once -> Result<Vec<u8>, Error> with Ok(vec![])` | src/client/transport.rs | Tokio::send_password_once | replace body with Ok(vec![]) | timeout | killed | `password_udp_request_size_boundaries` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:764:9: replace Tokio::send_to_realm_explicit -> Result<Vec<u8>, Error> with Ok(vec![0])` | src/client/transport.rs | Tokio::send_to_realm_explicit | replace body with Ok(vec![0]) | timeout | killed | `configured_auto_classifies_protocol_and_reply` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:764:9: replace Tokio::send_to_realm_explicit -> Result<Vec<u8>, Error> with Ok(vec![1])` | src/client/transport.rs | Tokio::send_to_realm_explicit | replace body with Ok(vec![1]) | timeout | killed | `configured_auto_classifies_protocol_and_reply` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:764:9: replace Tokio::send_to_realm_explicit -> Result<Vec<u8>, Error> with Ok(vec![])` | src/client/transport.rs | Tokio::send_to_realm_explicit | replace body with Ok(vec![]) | timeout | killed | `configured_auto_classifies_protocol_and_reply` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:82:46: replace * with +` | src/client/transport.rs | - | replace * with + | missed | killed | `default_tcp_response_limit_is_sixteen_mib` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport.rs:82:53: replace * with +` | src/client/transport.rs | - | replace * with + | missed | killed | `default_tcp_response_limit_is_sixteen_mib` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport/password_delivery.rs:65:5: replace send -> Result<Vec<u8>, Error> with Ok(vec![0])` | src/client/transport/password_delivery.rs | send | replace body with Ok(vec![0]) | timeout | killed | `password_udp_request_size_boundaries` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport/password_delivery.rs:65:5: replace send -> Result<Vec<u8>, Error> with Ok(vec![1])` | src/client/transport/password_delivery.rs | send | replace body with Ok(vec![1]) | timeout | killed | `password_udp_request_size_boundaries` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport/password_delivery.rs:65:5: replace send -> Result<Vec<u8>, Error> with Ok(vec![])` | src/client/transport/password_delivery.rs | send | replace body with Ok(vec![]) | timeout | killed | `password_udp_request_size_boundaries` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport/password_delivery.rs:81:30: replace > with < in send` | src/client/transport/password_delivery.rs | send | replace > with < | timeout | killed | `password_udp_request_size_boundaries` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport/password_delivery.rs:81:30: replace > with == in send` | src/client/transport/password_delivery.rs | send | replace > with == | missed | killed | `password_udp_request_size_boundaries` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport/password_delivery.rs:81:30: replace > with >= in send` | src/client/transport/password_delivery.rs | send | replace > with >= | missed | killed | `password_udp_request_size_boundaries` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport/password_dns.rs:21:26: replace match guard !endpoints.is_empty() with true in discover` | src/client/transport/password_dns.rs | discover | replace match guard !endpoints.is_empty() with true | missed | killed | `udp_password_discovers_admin_tcp_service` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport/realm_auto.rs:23:5: replace send -> Result<(Vec<u8>, Option<TcpStream>), Error> with Ok((vec![0], None))` | src/client/transport/realm_auto.rs | send | replace body with Ok((vec![0], None)) | timeout | killed | `configured_auto_classifies_protocol_and_reply` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport/realm_auto.rs:23:5: replace send -> Result<(Vec<u8>, Option<TcpStream>), Error> with Ok((vec![1], None))` | src/client/transport/realm_auto.rs | send | replace body with Ok((vec![1], None)) | timeout | killed | `configured_auto_classifies_protocol_and_reply` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport/realm_auto.rs:23:5: replace send -> Result<(Vec<u8>, Option<TcpStream>), Error> with Ok((vec![], None))` | src/client/transport/realm_auto.rs | send | replace body with Ok((vec![], None)) | timeout | killed | `configured_auto_classifies_protocol_and_reply` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport/realm_auto.rs:31:16: replace match guard first == KdcProtocol::Udp && kdc_error_code(&response) == Some(KRB_ERR_RESPONSE_TOO_BIG) with false in send` | src/client/transport/realm_auto.rs | send | replace match guard first == KdcProtocol::Udp && kdc_error_code(&response) == Some(KRB_ERR_RESPONSE_TOO_BIG) with false | missed | killed | `configured_auto_classifies_protocol_and_reply` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport/realm_auto.rs:31:22: replace == with != in send` | src/client/transport/realm_auto.rs | send | replace == with != | missed | killed | `configured_auto_classifies_protocol_and_reply` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport/realm_auto.rs:32:17: replace && with \|\| in send` | src/client/transport/realm_auto.rs | send | replace && with \|\| | missed | killed | `configured_auto_classifies_protocol_and_reply` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport/realm_auto.rs:32:46: replace == with != in send` | src/client/transport/realm_auto.rs | send | replace == with != | missed | killed | `configured_auto_classifies_protocol_and_reply` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport/realm_auto.rs:53:5: replace send_explicit -> Result<(Vec<u8>, Option<TcpStream>), Error> with Ok((vec![0], None))` | src/client/transport/realm_auto.rs | send_explicit | replace body with Ok((vec![0], None)) | timeout | killed | `configured_auto_classifies_protocol_and_reply` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport/realm_auto.rs:53:5: replace send_explicit -> Result<(Vec<u8>, Option<TcpStream>), Error> with Ok((vec![1], None))` | src/client/transport/realm_auto.rs | send_explicit | replace body with Ok((vec![1], None)) | timeout | killed | `configured_auto_logins_reuse_connection` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport/realm_auto.rs:53:5: replace send_explicit -> Result<(Vec<u8>, Option<TcpStream>), Error> with Ok((vec![], None))` | src/client/transport/realm_auto.rs | send_explicit | replace body with Ok((vec![], None)) | timeout | killed | `configured_auto_classifies_protocol_and_reply` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport/srv_targets.rs:42:32: delete ! in resolve` | src/client/transport/srv_targets.rs | resolve | delete ! | missed | killed | `empty_srv_answers_preserve_empty_success` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport/udp.rs:53:5: replace receive -> Result<Vec<u8>, Error> with Ok(vec![0])` | src/client/transport/udp.rs | receive | replace body with Ok(vec![0]) | timeout | killed | `receive_preserves_datagram_bytes` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport/udp.rs:53:5: replace receive -> Result<Vec<u8>, Error> with Ok(vec![1])` | src/client/transport/udp.rs | receive | replace body with Ok(vec![1]) | timeout | killed | `receive_preserves_datagram_bytes` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/client/transport/udp.rs:68:16: replace && with \|\| in receive_error` | src/client/transport/udp.rs | receive_error | replace && with \|\| | missed | killed | `unrelated_receive_errors_preserve_io_kind` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config.rs:1102:32: delete - in LibDefaults::with_home` | src/config.rs | LibDefaults::with_home | delete - | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config.rs:1318:17: delete match arm "kdc" in Realm::parse` | src/config.rs | Realm::parse | delete match arm "kdc" | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config.rs:1733:5: replace optional_ip_addresses -> Option<Vec<String>> with None` | src/config.rs | optional_ip_addresses | replace body with None | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config.rs:1733:5: replace optional_ip_addresses -> Option<Vec<String>> with Some(vec!["xyzzy".into()])` | src/config.rs | optional_ip_addresses | replace body with Some(vec!["xyzzy".into()]) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config.rs:1733:5: replace optional_ip_addresses -> Option<Vec<String>> with Some(vec![String::new()])` | src/config.rs | optional_ip_addresses | replace body with Some(vec![String::new()]) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config.rs:1733:5: replace optional_ip_addresses -> Option<Vec<String>> with Some(vec![])` | src/config.rs | optional_ip_addresses | replace body with Some(vec![]) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config.rs:1759:50: replace \| with ^ in base64_standard` | src/config.rs | base64_standard | replace \| with ^ | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config.rs:1759:71: replace << with >> in base64_standard` | src/config.rs | base64_standard | replace << with >> | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config.rs:1759:81: replace \| with & in base64_standard` | src/config.rs | base64_standard | replace \| with & | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config.rs:1759:81: replace \| with ^ in base64_standard` | src/config.rs | base64_standard | replace \| with ^ | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config.rs:1762:39: replace >> with << in base64_standard` | src/config.rs | base64_standard | replace >> with << | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config.rs:1764:43: replace >> with << in base64_standard` | src/config.rs | base64_standard | replace >> with << | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config.rs:1768:24: replace > with >= in base64_standard` | src/config.rs | base64_standard | replace > with >= | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config.rs:1929:5: replace add_default_port -> String with "xyzzy".into()` | src/config.rs | add_default_port | replace body with "xyzzy".into() | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config.rs:1929:5: replace add_default_port -> String with String::new()` | src/config.rs | add_default_port | replace body with String::new() | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config.rs:1948:5: replace append_until_final with ()` | src/config.rs | append_until_final | replace body with () | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config.rs:1997:5: replace starts_with_whitespace -> bool with true` | src/config.rs | starts_with_whitespace | replace body with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config.rs:2053:9: replace IncludeExpansion::with_roots -> Self with Default::default()` | src/config.rs | IncludeExpansion::with_roots | replace body with Default::default() | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config.rs:2069:9: replace IncludeExpansion::expand -> Result<(), Error> with Ok(())` | src/config.rs | IncludeExpansion::expand | replace body with Ok(()) | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config.rs:394:9: replace Config::parse -> Result<Self, Error> with Ok(Default::default())` | src/config.rs | Config::parse | replace body with Ok(Default::default()) | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config.rs:463:9: replace Config::parse_with_roots -> Result<Self, Error> with Ok(Default::default())` | src/config.rs | Config::parse_with_roots | replace body with Ok(Default::default()) | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config.rs:474:9: replace Config::parse_with_roots_mode -> Result<Self, Error> with Ok(Default::default())` | src/config.rs | Config::parse_with_roots_mode | replace body with Ok(Default::default()) | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config.rs:501:52: replace == with != in Config::realm` | src/config.rs | Config::realm | replace == with != | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config.rs:501:9: replace Config::realm -> Option<&Realm> with None` | src/config.rs | Config::realm | replace body with None | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config.rs:825:9: replace LibDefaults::with_default_ccache_name -> Self with Default::default()` | src/config.rs | LibDefaults::with_default_ccache_name | replace body with Default::default() | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config.rs:832:9: replace LibDefaults::with_default_client_keytab_name -> Self with Default::default()` | src/config.rs | LibDefaults::with_default_client_keytab_name | replace body with Default::default() | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config.rs:839:9: replace LibDefaults::with_default_keytab_name -> Self with Default::default()` | src/config.rs | LibDefaults::with_default_keytab_name | replace body with Default::default() | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config.rs:879:9: replace LibDefaults::with_dns_canonicalize_hostname -> Self with Default::default()` | src/config.rs | LibDefaults::with_dns_canonicalize_hostname | replace body with Default::default() | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config.rs:900:9: replace LibDefaults::with_extra_addresses -> Self with Default::default()` | src/config.rs | LibDefaults::with_extra_addresses | replace body with Default::default() | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config.rs:928:9: replace LibDefaults::with_k5login_directory -> Self with Default::default()` | src/config.rs | LibDefaults::with_k5login_directory | replace body with Default::default() | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config.rs:976:9: replace LibDefaults::with_preferred_preauth_types -> Self with Default::default()` | src/config.rs | LibDefaults::with_preferred_preauth_types | replace body with Default::default() | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/credential_names.rs:31:9: replace \|\| with && in resolve_credential_template` | src/config/credential_names.rs | resolve_credential_template | replace \|\| with && | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/credential_names.rs:32:39: replace && with \|\| in resolve_credential_template` | src/config/credential_names.rs | resolve_credential_template | replace && with \|\| | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/credential_names.rs:32:9: replace \|\| with && in resolve_credential_template` | src/config/credential_names.rs | resolve_credential_template | replace \|\| with && | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/credential_names.rs:57:9: replace \|\| with && in resolve_credential_template` | src/config/credential_names.rs | resolve_credential_template | replace \|\| with && | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/credential_names.rs:58:9: replace \|\| with && in resolve_credential_template` | src/config/credential_names.rs | resolve_credential_template | replace \|\| with && | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/expansion.rs:120:22: replace match guard cfg!(target_os = "linux") with true in expand` | src/config/expansion.rs | expand | replace match guard cfg!(target_os = "linux") with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/expansion.rs:124:23: replace match guard cfg!(target_os = "linux") with true in expand` | src/config/expansion.rs | expand | replace match guard cfg!(target_os = "linux") with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/expansion.rs:128:25: replace match guard cfg!(target_os = "linux") with true in expand` | src/config/expansion.rs | expand | replace match guard cfg!(target_os = "linux") with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/expansion.rs:132:25: replace match guard cfg!(windows) with false in expand` | src/config/expansion.rs | expand | replace match guard cfg!(windows) with false | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/expansion.rs:132:25: replace match guard cfg!(windows) with true in expand` | src/config/expansion.rs | expand | replace match guard cfg!(windows) with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/expansion.rs:135:13: delete match arm "uid" in expand` | src/config/expansion.rs | expand | delete match arm "uid" | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/expansion.rs:136:13: delete match arm "euid" in expand` | src/config/expansion.rs | expand | delete match arm "euid" | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/expansion.rs:137:13: delete match arm "USERID" in expand` | src/config/expansion.rs | expand | delete match arm "USERID" | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/hostname.rs:37:9: replace Canonicalization::is_enabled -> bool with true` | src/config/hostname.rs | Canonicalization::is_enabled | replace body with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/libdefaults.rs:23:45: replace == with != in classify` | src/config/libdefaults.rs | classify | replace == with != | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/libdefaults/duration.rs:65:9: delete match arm (2, 1) in clock_seconds` | src/config/libdefaults/duration.rs | clock_seconds | delete match arm (2, 1) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/profile.rs:114:35: replace match guard section == "libdefaults" with true in Profile::finish` | src/config/profile.rs | Profile::finish | replace match guard section == "libdefaults" with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/profile.rs:29:9: replace Profile::closed -> bool with true` | src/config/profile.rs | Profile::closed | replace body with true | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/profile.rs:34:9: replace Profile::child_closed -> bool with true` | src/config/profile.rs | Profile::child_closed | replace body with true | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/profile.rs:44:9: replace Profile::scope with ()` | src/config/profile.rs | Profile::scope | replace body with () | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/profile.rs:49:24: replace == with != in Profile::scope` | src/config/profile.rs | Profile::scope | replace == with != | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/profile.rs:50:16: delete ! in Profile::scope` | src/config/profile.rs | Profile::scope | delete ! | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/profile.rs:58:9: replace Profile::relation with ()` | src/config/profile.rs | Profile::relation | replace body with () | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/profile.rs:66:9: replace Profile::finish -> Result<Config, Error> with Ok(Default::default())` | src/config/profile.rs | Profile::finish | replace body with Ok(Default::default()) | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/profile.rs:89:32: replace == with != in Profile::finish` | src/config/profile.rs | Profile::finish | replace == with != | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/profile.rs:90:30: replace == with != in Profile::finish` | src/config/profile.rs | Profile::finish | replace == with != | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/profile_syntax.rs:117:12: delete ! in State::line` | src/config/profile_syntax.rs | State::line | delete ! | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/profile_syntax.rs:137:9: replace State::finish -> Result<(), Error> with Ok(())` | src/config/profile_syntax.rs | State::finish | replace body with Ok(()) | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/profile_syntax.rs:160:5: replace marker -> (&str, bool) with ("xyzzy", false)` | src/config/profile_syntax.rs | marker | replace body with ("xyzzy", false) | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/profile_syntax.rs:160:5: replace marker -> (&str, bool) with ("xyzzy", true)` | src/config/profile_syntax.rs | marker | replace body with ("xyzzy", true) | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/profile_syntax.rs:211:5: replace comments -> &str with ""` | src/config/profile_syntax.rs | comments | replace body with "" | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/profile_syntax.rs:221:27: replace && with \|\| in comments` | src/config/profile_syntax.rs | comments | replace && with \|\| | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/profile_syntax.rs:221:41: replace && with \|\| in comments` | src/config/profile_syntax.rs | comments | replace && with \|\| | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/profile_syntax.rs:31:9: replace State::line -> Result<(), Error> with Ok(())` | src/config/profile_syntax.rs | State::line | replace body with Ok(()) | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/profile_syntax.rs:35:43: replace \|\| with && in State::line` | src/config/profile_syntax.rs | State::line | replace \|\| with && | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/profile_syntax.rs:61:35: replace \|\| with && in State::line` | src/config/profile_syntax.rs | State::line | replace \|\| with && | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/profile_syntax.rs:72:41: replace == with != in State::line` | src/config/profile_syntax.rs | State::line | replace == with != | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/profile_syntax.rs:72:46: replace && with \|\| in State::line` | src/config/profile_syntax.rs | State::line | replace && with \|\| | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/profile_syntax.rs:72:57: replace == with != in State::line` | src/config/profile_syntax.rs | State::line | replace == with != | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/profile_syntax.rs:73:13: replace \|\| with && in State::line` | src/config/profile_syntax.rs | State::line | replace \|\| with && | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/profile_syntax.rs:92:34: replace > with == in State::line` | src/config/profile_syntax.rs | State::line | replace > with == | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/profile_syntax.rs:92:34: replace > with >= in State::line` | src/config/profile_syntax.rs | State::line | replace > with >= | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/profile_syntax.rs:98:16: delete ! in State::line` | src/config/profile_syntax.rs | State::line | delete ! | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/protocol.rs:10:5: replace recognized -> bool with false` | src/config/protocol.rs | recognized | replace body with false | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/protocol.rs:11:9: replace \|\| with && in recognized` | src/config/protocol.rs | recognized | replace \|\| with && | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/protocol.rs:12:9: replace \|\| with && in recognized` | src/config/protocol.rs | recognized | replace \|\| with && | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/protocol.rs:51:16: replace match guard matches!( value.to_ascii_lowercase().as_str(), "rsa" \| "rsa-only" \| "key-transport" \| "dh-less" ) with false in relation` | src/config/protocol.rs | relation | replace match guard matches!( value.to_ascii_lowercase().as_str(), "rsa" \| "rsa-only" \| "key-transport" \| "dh-less" ) with false | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/protocol.rs:51:16: replace match guard matches!( value.to_ascii_lowercase().as_str(), "rsa" \| "rsa-only" \| "key-transport" \| "dh-less" ) with true in relation` | src/config/protocol.rs | relation | replace match guard matches!( value.to_ascii_lowercase().as_str(), "rsa" \| "rsa-only" \| "key-transport" \| "dh-less" ) with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/protocol.rs:69:14: replace match guard key.starts_with("v4_") with false in relation` | src/config/protocol.rs | relation | replace match guard key.starts_with("v4_") with false | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/realm_values.rs:115:38: replace != with == in location` | src/config/realm_values.rs | location | replace != with == | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/realm_values.rs:122:21: replace match guard identity with true in location` | src/config/realm_values.rs | location | replace match guard identity with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/realm_values.rs:123:21: replace match guard identity with true in location` | src/config/realm_values.rs | location | replace match guard identity with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/section_decode.rs:108:20: replace match guard section == "realms" && subsection == "auth_to_local_names" with true in finish` | src/config/section_decode.rs | finish | replace match guard section == "realms" && subsection == "auth_to_local_names" with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/section_decode.rs:108:40: replace && with \|\| in finish` | src/config/section_decode.rs | finish | replace && with \|\| | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/section_decode.rs:127:20: replace match guard section == "plugins" && matches!(key.as_str(), "disable" \| "enable_only") with true in finish` | src/config/section_decode.rs | finish | replace match guard section == "plugins" && matches!(key.as_str(), "disable" \| "enable_only") with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/section_decode.rs:127:41: replace && with \|\| in finish` | src/config/section_decode.rs | finish | replace && with \|\| | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/section_decode.rs:132:49: replace \|\| with && in finish` | src/config/section_decode.rs | finish | replace \|\| with && | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/section_decode.rs:231:35: replace == with != in realms` | src/config/section_decode.rs | realms | replace == with != | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/section_decode.rs:86:49: replace \|\| with && in finish` | src/config/section_decode.rs | finish | replace \|\| with && | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/unknown.rs:62:27: replace match guard section == "libdefaults" with true in known` | src/config/unknown.rs | known | replace match guard section == "libdefaults" with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/unknown.rs:65:17: replace \|\| with && in known` | src/config/unknown.rs | known | replace \|\| with && | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/unknown.rs:67:30: replace match guard section == "realms" with false in known` | src/config/unknown.rs | known | replace match guard section == "realms" with false | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/unknown.rs:67:30: replace match guard section == "realms" with true in known` | src/config/unknown.rs | known | replace match guard section == "realms" with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/unknown.rs:67:38: replace == with != in known` | src/config/unknown.rs | known | replace == with != | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/unknown.rs:68:60: replace \|\| with && in known` | src/config/unknown.rs | known | replace \|\| with && | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/unknown.rs:70:33: replace match guard section == "realms" && map == "auth_to_local_names" with false in known` | src/config/unknown.rs | known | replace match guard section == "realms" && map == "auth_to_local_names" with false | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/unknown.rs:70:33: replace match guard section == "realms" && map == "auth_to_local_names" with true in known` | src/config/unknown.rs | known | replace match guard section == "realms" && map == "auth_to_local_names" with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/unknown.rs:70:41: replace == with != in known` | src/config/unknown.rs | known | replace == with != | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/unknown.rs:70:53: replace && with \|\| in known` | src/config/unknown.rs | known | replace && with \|\| | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/unknown.rs:70:60: replace == with != in known` | src/config/unknown.rs | known | replace == with != | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/unknown.rs:71:25: replace match guard section == "domain_realm" with false in known` | src/config/unknown.rs | known | replace match guard section == "domain_realm" with false | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/unknown.rs:71:25: replace match guard section == "domain_realm" with true in known` | src/config/unknown.rs | known | replace match guard section == "domain_realm" with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/unknown.rs:71:33: replace == with != in known` | src/config/unknown.rs | known | replace == with != | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/unknown.rs:72:28: replace match guard section == "capaths" with false in known` | src/config/unknown.rs | known | replace match guard section == "capaths" with false | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/unknown.rs:73:33: replace match guard section == "appdefaults" with false in known` | src/config/unknown.rs | known | replace match guard section == "appdefaults" with false | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/unknown.rs:74:30: replace match guard section == "plugins" with false in known` | src/config/unknown.rs | known | replace match guard section == "plugins" with false | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/unknown.rs:74:30: replace match guard section == "plugins" with true in known` | src/config/unknown.rs | known | replace match guard section == "plugins" with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/unknown.rs:74:38: replace == with != in known` | src/config/unknown.rs | known | replace == with != | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/unknown.rs:90:74: replace == with != in empty_scopes` | src/config/unknown.rs | empty_scopes | replace == with != | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/unknown.rs:95:13: delete match arm [section, _, key] in empty_scopes` | src/config/unknown.rs | empty_scopes | delete match arm [section, _, key] | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/unknown.rs:96:25: replace == with != in empty_scopes` | src/config/unknown.rs | empty_scopes | replace == with != | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/unknown.rs:96:42: replace \|\| with && in empty_scopes` | src/config/unknown.rs | empty_scopes | replace \|\| with && | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/unknown.rs:96:54: replace == with != in empty_scopes` | src/config/unknown.rs | empty_scopes | replace == with != | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/unknown.rs:96:66: replace && with \|\| in empty_scopes` | src/config/unknown.rs | empty_scopes | replace && with \|\| | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/config/unknown.rs:96:73: replace == with != in empty_scopes` | src/config/unknown.rs | empty_scopes | replace == with != | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:1044:9: replace Des3CbcSha1KdEtype::encrypt_data -> Result<(Vec<u8>, Vec<u8>), Error> with Ok((vec![0], vec![]))` | src/crypto.rs | Des3CbcSha1KdEtype::encrypt_data | replace body with Ok((vec![0], vec![])) | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:1044:9: replace Des3CbcSha1KdEtype::encrypt_data -> Result<(Vec<u8>, Vec<u8>), Error> with Ok((vec![], vec![]))` | src/crypto.rs | Des3CbcSha1KdEtype::encrypt_data | replace body with Ok((vec![], vec![])) | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:1153:9: replace Des3CbcSha1KdEtype::validate_key -> Result<(), Error> with Ok(())` | src/crypto.rs | Des3CbcSha1KdEtype::validate_key | replace body with Ok(()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:1242:9: replace Rc4HmacEtype::default_s2kparams -> &'static str with ""` | src/crypto.rs | Rc4HmacEtype::default_s2kparams | replace body with "" | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:1272:9: replace Rc4HmacEtype::random_to_key -> Vec<u8> with vec![0]` | src/crypto.rs | Rc4HmacEtype::random_to_key | replace body with vec![0] | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:1272:9: replace Rc4HmacEtype::random_to_key -> Vec<u8> with vec![1]` | src/crypto.rs | Rc4HmacEtype::random_to_key | replace body with vec![1] | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:1272:9: replace Rc4HmacEtype::random_to_key -> Vec<u8> with vec![]` | src/crypto.rs | Rc4HmacEtype::random_to_key | replace body with vec![] | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:1286:9: replace Rc4HmacEtype::derive_key -> Result<Vec<u8>, Error> with Ok(vec![0])` | src/crypto.rs | Rc4HmacEtype::derive_key | replace body with Ok(vec![0]) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:1286:9: replace Rc4HmacEtype::derive_key -> Result<Vec<u8>, Error> with Ok(vec![1])` | src/crypto.rs | Rc4HmacEtype::derive_key | replace body with Ok(vec![1]) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:1286:9: replace Rc4HmacEtype::derive_key -> Result<Vec<u8>, Error> with Ok(vec![])` | src/crypto.rs | Rc4HmacEtype::derive_key | replace body with Ok(vec![]) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:1335:9: replace Rc4HmacEtype::decrypt_data -> Result<Vec<u8>, Error> with Ok(vec![0])` | src/crypto.rs | Rc4HmacEtype::decrypt_data | replace body with Ok(vec![0]) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:1335:9: replace Rc4HmacEtype::decrypt_data -> Result<Vec<u8>, Error> with Ok(vec![1])` | src/crypto.rs | Rc4HmacEtype::decrypt_data | replace body with Ok(vec![1]) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:1335:9: replace Rc4HmacEtype::decrypt_data -> Result<Vec<u8>, Error> with Ok(vec![])` | src/crypto.rs | Rc4HmacEtype::decrypt_data | replace body with Ok(vec![]) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:1472:13: delete match arm 20 in KerberosEtype::from_checksum_type_id` | src/crypto.rs | KerberosEtype::from_checksum_type_id | delete match arm 20 | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:1741:25: replace \|\| with && in nfold` | src/crypto.rs | nfold | replace \|\| with && | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:1854:24: replace > with >= in aes_cts_encrypt` | src/crypto.rs | aes_cts_encrypt | replace > with >= | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:2002:5: replace des3_cbc_encrypt -> Result<(Vec<u8>, Vec<u8>), Error> with Ok((vec![0], vec![]))` | src/crypto.rs | des3_cbc_encrypt | replace body with Ok((vec![0], vec![])) | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:2002:5: replace des3_cbc_encrypt -> Result<(Vec<u8>, Vec<u8>), Error> with Ok((vec![], vec![]))` | src/crypto.rs | des3_cbc_encrypt | replace body with Ok((vec![], vec![])) | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:2115:5: replace des3_fix_weak_key with ()` | src/crypto.rs | des3_fix_weak_key | replace body with () | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:2116:36: replace ^= with &= in des3_fix_weak_key` | src/crypto.rs | des3_fix_weak_key | replace ^= with &= | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:2116:36: replace ^= with \|= in des3_fix_weak_key` | src/crypto.rs | des3_fix_weak_key | replace ^= with \|= | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:2122:5: replace des3_is_weak_key -> bool with false` | src/crypto.rs | des3_is_weak_key | replace body with false | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:2176:9: delete match arm 3 \| 9 in rc4_hmac_usage_to_ms_msg_type` | src/crypto.rs | rc4_hmac_usage_to_ms_msg_type | delete match arm 3 \| 9 | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:2211:18: replace > with == in hmac_any_key` | src/crypto.rs | hmac_any_key | replace > with == | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:2211:18: replace > with >= in hmac_any_key` | src/crypto.rs | hmac_any_key | replace > with >= | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:2340:32: replace \| with ^ in hex_pair` | src/crypto.rs | hex_pair | replace \| with ^ | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:259:25: replace < with <= in AesSha1Etype::derive_random` | src/crypto.rs | AesSha1Etype::derive_random | replace < with <= | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:262:26: replace < with <= in AesSha1Etype::derive_random` | src/crypto.rs | AesSha1Etype::derive_random | replace < with <= | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:822:9: replace AesSha2Etype::validate_protocol_key -> Result<(), Error> with Ok(())` | src/crypto.rs | AesSha2Etype::validate_protocol_key | replace body with Ok(()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:839:9: replace AesSha2Etype::validate_encrypt_key -> Result<(), Error> with Ok(())` | src/crypto.rs | AesSha2Etype::validate_encrypt_key | replace body with Ok(()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:922:9: replace Des3CbcSha1KdEtype::default_s2kparams -> &'static str with ""` | src/crypto.rs | Des3CbcSha1KdEtype::default_s2kparams | replace body with "" | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:994:25: replace < with <= in Des3CbcSha1KdEtype::derive_random` | src/crypto.rs | Des3CbcSha1KdEtype::derive_random | replace < with <= | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto.rs:997:26: replace < with <= in Des3CbcSha1KdEtype::derive_random` | src/crypto.rs | Des3CbcSha1KdEtype::derive_random | replace < with <= | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto/checked.rs:40:9: replace Etype::string_to_key -> Result<Vec<u8>, error::Crypto> with Ok(vec![0])` | src/crypto/checked.rs | Etype::string_to_key | replace body with Ok(vec![0]) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto/checked.rs:40:9: replace Etype::string_to_key -> Result<Vec<u8>, error::Crypto> with Ok(vec![1])` | src/crypto/checked.rs | Etype::string_to_key | replace body with Ok(vec![1]) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto/checked.rs:40:9: replace Etype::string_to_key -> Result<Vec<u8>, error::Crypto> with Ok(vec![])` | src/crypto/checked.rs | Etype::string_to_key | replace body with Ok(vec![]) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto/checked.rs:64:9: replace Etype::verify_checksum -> Result<(), error::Crypto> with Ok(())` | src/crypto/checked.rs | Etype::verify_checksum | replace body with Ok(()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto/policy.rs:135:13: delete match arm 16_i32 in Policy::check_use` | src/crypto/policy.rs | Policy::check_use | delete match arm 16_i32 | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto/policy.rs:136:13: delete match arm 23_i32 in Policy::check_use` | src/crypto/policy.rs | Policy::check_use | delete match arm 23_i32 | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto/policy.rs:195:9: replace <impl TryFrom<&LibDefaults> for Policy>::try_from -> Result<Self, Self::Error> with Ok(Default::default())` | src/crypto/policy.rs | <impl TryFrom<&LibDefaults> for Policy>::try_from | replace body with Ok(Default::default()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto/policy.rs:38:9: replace <impl fmt::Display for Use>::fmt -> fmt::Result with Ok(Default::default())` | src/crypto/policy.rs | <impl fmt::Display for Use>::fmt | replace body with Ok(Default::default()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto/scratch.rs:63:9: replace <impl DerefMut for SecretScratch>::deref_mut -> &mut Self::Target with Box::leak(Box::new(Default::default()))` | src/crypto/scratch.rs | <impl DerefMut for SecretScratch>::deref_mut | replace body with Box::leak(Box::new(Default::default())) | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto/selection.rs:63:9: delete match arm "rsa-md4-des" in checksum_name` | src/crypto/selection.rs | checksum_name | delete match arm "rsa-md4-des" | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto/selection.rs:64:9: delete match arm "des-mac" in checksum_name` | src/crypto/selection.rs | checksum_name | delete match arm "des-mac" | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto/selection.rs:65:9: delete match arm "des-mac-k" in checksum_name` | src/crypto/selection.rs | checksum_name | delete match arm "des-mac-k" | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto/selection.rs:66:9: delete match arm "rsa-md4-des-k" in checksum_name` | src/crypto/selection.rs | checksum_name | delete match arm "rsa-md4-des-k" | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto/selection.rs:71:9: delete match arm "hmac-sha1-des3" \| "hmac-sha1-des3-kd" in checksum_name` | src/crypto/selection.rs | checksum_name | delete match arm "hmac-sha1-des3" \| "hmac-sha1-des3-kd" | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto/selection.rs:72:71: delete - in checksum_name` | src/crypto/selection.rs | checksum_name | delete - | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto/selection.rs:72:9: delete match arm "hmac-md5-rc4" \| "hmac-md5-enc" \| "hmac-md5-earcfour" in checksum_name` | src/crypto/selection.rs | checksum_name | delete match arm "hmac-md5-rc4" \| "hmac-md5-enc" \| "hmac-md5-earcfour" | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto/selection.rs:73:9: delete match arm "hmac-sha1-96-aes128" in checksum_name` | src/crypto/selection.rs | checksum_name | delete match arm "hmac-sha1-96-aes128" | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto/selection.rs:74:9: delete match arm "hmac-sha1-96-aes256" in checksum_name` | src/crypto/selection.rs | checksum_name | delete match arm "hmac-sha1-96-aes256" | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto/selection.rs:75:9: delete match arm "hmac-sha256-128-aes128" in checksum_name` | src/crypto/selection.rs | checksum_name | delete match arm "hmac-sha256-128-aes128" | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto/selection.rs:76:9: delete match arm "hmac-sha384-192-aes256" in checksum_name` | src/crypto/selection.rs | checksum_name | delete match arm "hmac-sha384-192-aes256" | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto/selection.rs:77:9: delete match arm "cmac-camellia128" in checksum_name` | src/crypto/selection.rs | checksum_name | delete match arm "cmac-camellia128" | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto/selection.rs:78:9: delete match arm "cmac-camellia256" in checksum_name` | src/crypto/selection.rs | checksum_name | delete match arm "cmac-camellia256" | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto/selection.rs:79:32: delete - in checksum_name` | src/crypto/selection.rs | checksum_name | delete - | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto/selection.rs:79:9: delete match arm "md5-hmac-rc4" in checksum_name` | src/crypto/selection.rs | checksum_name | delete match arm "md5-hmac-rc4" | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/crypto/verification.rs:22:46: replace \|\| with && in verify_checksum` | src/crypto/verification.rs | verify_checksum | replace \|\| with && | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/der.rs:30:19: replace & with ^ in top_level_der_end` | src/der.rs | top_level_der_end | replace & with ^ | missed | killed | `trims_padding_after_high_tag_identifiers` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/der.rs:30:19: replace & with \| in top_level_der_end` | src/der.rs | top_level_der_end | replace & with \| | missed | killed | `trims_padding_after_high_tag_identifiers` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/der.rs:34:21: replace & with ^ in top_level_der_end` | src/der.rs | top_level_der_end | replace & with ^ | missed | killed | `trims_padding_after_high_tag_identifiers` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/der.rs:34:21: replace & with \| in top_level_der_end` | src/der.rs | top_level_der_end | replace & with \| | missed | killed | `trims_padding_after_high_tag_identifiers` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/der.rs:34:28: replace == with != in top_level_der_end` | src/der.rs | top_level_der_end | replace == with != | missed | killed | `trims_padding_after_high_tag_identifiers` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/der.rs:45:43: replace & with ^ in top_level_der_end` | src/der.rs | top_level_der_end | replace & with ^ | missed | killed | `trims_padding_after_long_form_lengths` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/der.rs:45:43: replace & with \| in top_level_der_end` | src/der.rs | top_level_der_end | replace & with \| | missed | killed | `trims_padding_after_long_form_lengths` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/der.rs:46:18: replace == with != in top_level_der_end` | src/der.rs | top_level_der_end | replace == with != | missed | killed | `preserves_indefinite_and_overwide_lengths` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/der.rs:46:23: replace \|\| with && in top_level_der_end` | src/der.rs | top_level_der_end | replace \|\| with && | missed | killed | `preserves_indefinite_and_overwide_lengths` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/der.rs:46:32: replace > with < in top_level_der_end` | src/der.rs | top_level_der_end | replace > with < | missed | killed | `preserves_indefinite_and_overwide_lengths` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/der.rs:46:32: replace > with == in top_level_der_end` | src/der.rs | top_level_der_end | replace > with == | missed | killed | `preserves_indefinite_and_overwide_lengths` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/der.rs:46:32: replace > with >= in top_level_der_end` | src/der.rs | top_level_der_end | replace > with >= | missed | killed | `trims_padding_after_native_width_length` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/der.rs:54:34: replace \| with & in top_level_der_end` | src/der.rs | top_level_der_end | replace \| with & | missed | killed | `trims_padding_after_long_form_lengths` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/der.rs:54:34: replace \| with ^ in top_level_der_end` | src/der.rs | top_level_der_end | replace \| with ^ | missed | equivalent | Shifting len left by eight clears its low eight bits; each u8 operand occupies only those bits. OR and XOR therefore produce identical usize lengths on every iteration, including wrapping shifts. All callers receive the identical trimmed slice. |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/evaluation.rs:116:5: replace render_candidate_details -> fmt::Result with Ok(Default::default())` | src/evaluation.rs | render_candidate_details | replace body with Ok(Default::default()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/evaluation.rs:60:5: replace render_decision_matrix -> fmt::Result with Ok(Default::default())` | src/evaluation.rs | render_decision_matrix | replace body with Ok(Default::default()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/evaluation/data.rs:173:9: replace DerType::name -> &'static str with ""` | src/evaluation/data.rs | DerType::name | replace body with "" | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/evaluation/data.rs:173:9: replace DerType::name -> &'static str with "xyzzy"` | src/evaluation/data.rs | DerType::name | replace body with "xyzzy" | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/evaluation/data.rs:280:41: replace == with != in CandidateAssessment::support_for` | src/evaluation/data.rs | CandidateAssessment::support_for | replace == with != | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/evaluation/data.rs:32:9: replace Candidate::name -> &'static str with ""` | src/evaluation/data.rs | Candidate::name | replace body with "" | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/evaluation/data.rs:32:9: replace Candidate::name -> &'static str with "xyzzy"` | src/evaluation/data.rs | Candidate::name | replace body with "xyzzy" | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/evaluation/data.rs:49:9: replace Candidate::license -> &'static str with ""` | src/evaluation/data.rs | Candidate::license | replace body with "" | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/evaluation/data.rs:49:9: replace Candidate::license -> &'static str with "xyzzy"` | src/evaluation/data.rs | Candidate::license | replace body with "xyzzy" | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/evaluation/data.rs:79:9: replace <impl fmt::Display for Support>::fmt -> fmt::Result with Ok(Default::default())` | src/evaluation/data.rs | <impl fmt::Display for Support>::fmt | replace body with Ok(Default::default()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/file_name.rs:386:5: replace process_identity -> Result<(u32, u32), Error> with Ok((0, 0))` | src/file_name.rs | process_identity | replace body with Ok((0, 0)) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/file_name.rs:386:5: replace process_identity -> Result<(u32, u32), Error> with Ok((0, 1))` | src/file_name.rs | process_identity | replace body with Ok((0, 1)) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/file_name.rs:386:5: replace process_identity -> Result<(u32, u32), Error> with Ok((1, 0))` | src/file_name.rs | process_identity | replace body with Ok((1, 0)) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/file_name.rs:386:5: replace process_identity -> Result<(u32, u32), Error> with Ok((1, 1))` | src/file_name.rs | process_identity | replace body with Ok((1, 1)) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/file_name.rs:404:26: delete ! in write_private` | src/file_name.rs | write_private | delete ! | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/file_name.rs:458:23: replace match guard error.kind() == io::ErrorKind::NotFound with true in reject_symlink` | src/file_name.rs | reject_symlink | replace match guard error.kind() == io::ErrorKind::NotFound with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/file_name.rs:499:27: replace match guard error.kind() == io::ErrorKind::AlreadyExists with true in create_primary_with` | src/file_name.rs | create_primary_with | replace match guard error.kind() == io::ErrorKind::AlreadyExists with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/http.rs:231:5: replace authorize_request -> Result<()> with Ok(())` | src/http.rs | authorize_request | replace body with Ok(()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/http.rs:873:9: replace <impl Iterator for WwwAuthenticateSegments<'value>>::next -> Option<Self::Item> with Some(Default::default())` | src/http.rs | <impl Iterator for WwwAuthenticateSegments<'value>>::next | replace body with Some(Default::default()) | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/http.rs:883:28: replace == with != in <impl Iterator for WwwAuthenticateSegments<'value>>::next` | src/http.rs | <impl Iterator for WwwAuthenticateSegments<'value>>::next | replace == with != | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/http.rs:883:37: replace && with \|\| in <impl Iterator for WwwAuthenticateSegments<'value>>::next` | src/http.rs | <impl Iterator for WwwAuthenticateSegments<'value>>::next | replace && with \|\| | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/http.rs:885:28: replace == with != in <impl Iterator for WwwAuthenticateSegments<'value>>::next` | src/http.rs | <impl Iterator for WwwAuthenticateSegments<'value>>::next | replace == with != | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/http.rs:886:26: delete ! in <impl Iterator for WwwAuthenticateSegments<'value>>::next` | src/http.rs | <impl Iterator for WwwAuthenticateSegments<'value>>::next | delete ! | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/http.rs:887:28: replace == with != in <impl Iterator for WwwAuthenticateSegments<'value>>::next` | src/http.rs | <impl Iterator for WwwAuthenticateSegments<'value>>::next | replace == with != | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/http.rs:887:36: replace && with \|\| in <impl Iterator for WwwAuthenticateSegments<'value>>::next` | src/http.rs | <impl Iterator for WwwAuthenticateSegments<'value>>::next | replace && with \|\| | timeout | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/http.rs:887:39: delete ! in <impl Iterator for WwwAuthenticateSegments<'value>>::next` | src/http.rs | <impl Iterator for WwwAuthenticateSegments<'value>>::next | delete ! | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/kadmin/password.rs:32:9: replace <impl fmt::Debug for Bytes>::fmt -> fmt::Result with Ok(Default::default())` | src/kadmin/password.rs | <impl fmt::Debug for Bytes>::fmt | replace body with Ok(Default::default()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/kadmin/password.rs:60:9: replace <impl PartialEq<Vec<u8>> for Bytes>::eq -> bool with true` | src/kadmin/password.rs | <impl PartialEq<Vec<u8>> for Bytes>::eq | replace body with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/kadmin/reply.rs:159:38: replace \|\| with && in Reply::encode` | src/kadmin/reply.rs | Reply::encode | replace \|\| with && | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/kadmin/secret_der.rs:19:37: replace < with <= in wrap` | src/kadmin/secret_der.rs | wrap | replace < with <= | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/kadmin/secret_der.rs:19:37: replace < with == in wrap` | src/kadmin/secret_der.rs | wrap | replace < with == | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/kadmin/secret_der.rs:19:37: replace < with > in wrap` | src/kadmin/secret_der.rs | wrap | replace < with > | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/kadmin/secret_der.rs:41:18: replace \| with ^ in wrap` | src/kadmin/secret_der.rs | wrap | replace \| with ^ | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/kdc_rep.rs:276:5: replace validate_kdc_rep -> Result<(), Error> with Ok(())` | src/kdc_rep.rs | validate_kdc_rep | replace body with Ok(()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/kdc_rep.rs:367:5: replace validate_integer -> Result<(), Error> with Ok(())` | src/kdc_rep.rs | validate_integer | replace body with Ok(()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/kdc_rep.rs:56:5: replace validate_as_rep -> Result<(), Error> with Ok(())` | src/kdc_rep.rs | validate_as_rep | replace body with Ok(()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/kdc_rep.rs:91:5: replace validate_tgs_rep -> Result<(), Error> with Ok(())` | src/kdc_rep.rs | validate_tgs_rep | replace body with Ok(()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/kdc_req.rs:145:5: replace validate_tgs_req -> Result<(), Error> with Ok(())` | src/kdc_req.rs | validate_tgs_req | replace body with Ok(()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/kdc_req.rs:195:5: replace validate_kdc_req -> Result<(), Error> with Ok(())` | src/kdc_req.rs | validate_kdc_req | replace body with Ok(()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/kdc_req.rs:237:5: replace validate_integer -> Result<(), Error> with Ok(())` | src/kdc_req.rs | validate_integer | replace body with Ok(()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/kdc_req.rs:40:5: replace validate_kdc_req_body -> Result<(), Error> with Ok(())` | src/kdc_req.rs | validate_kdc_req_body | replace body with Ok(()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/kdc_req.rs:80:5: replace validate_as_req -> Result<(), Error> with Ok(())` | src/kdc_req.rs | validate_as_req | replace body with Ok(()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/keytab.rs:190:26: replace < with <= in Keytab::parse` | src/keytab.rs | Keytab::parse | replace < with <= | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/keytab.rs:190:26: replace < with == in Keytab::parse` | src/keytab.rs | Keytab::parse | replace < with == | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/keytab.rs:323:47: replace != with == in Keytab::to_bytes` | src/keytab.rs | Keytab::to_bytes | replace != with == | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/keytab.rs:896:5: replace checked_advance -> Result<(), Error> with Ok(())` | src/keytab.rs | checked_advance | replace body with Ok(()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/krb_cred.rs:103:38: replace && with \|\| in decrypt_part` | src/krb_cred.rs | decrypt_part | replace && with \|\| | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/krb_cred.rs:103:87: replace < with <= in decrypt_part` | src/krb_cred.rs | decrypt_part | replace < with <= | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/krb_cred.rs:376:5: replace validate_integer -> Result<(), Error> with Ok(())` | src/krb_cred.rs | validate_integer | replace body with Ok(()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/krb_cred/conversion.rs:162:5: replace optional_principal -> Result<Option<ccache::Principal>, Error> with Ok(None)` | src/krb_cred/conversion.rs | optional_principal | replace body with Ok(None) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/krb_cred/conversion.rs:166:9: delete match arm (None, None) in optional_principal` | src/krb_cred/conversion.rs | optional_principal | delete match arm (None, None) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/krb_cred/import.rs:60:5: replace decode_decrypt -> Result<Vec<Credential>, Error> with Ok(vec![])` | src/krb_cred/import.rs | decode_decrypt | replace body with Ok(vec![]) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/krb_priv.rs:142:5: replace validate -> Result<(), Error> with Ok(())` | src/krb_priv.rs | validate | replace body with Ok(()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/krb_priv.rs:343:5: replace validate_integer -> Result<(), Error> with Ok(())` | src/krb_priv.rs | validate_integer | replace body with Ok(()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/krb_safe.rs:179:5: replace validate_integer -> Result<(), Error> with Ok(())` | src/krb_safe.rs | validate_integer | replace body with Ok(()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac.rs:1288:9: replace ClaimValues::len -> usize with 0` | src/pac.rs | ClaimValues::len | replace body with 0 | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac.rs:1288:9: replace ClaimValues::len -> usize with 1` | src/pac.rs | ClaimValues::len | replace body with 1 | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac.rs:1300:20: replace == with != in ClaimValues::is_empty` | src/pac.rs | ClaimValues::is_empty | replace == with != | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac.rs:1300:9: replace ClaimValues::is_empty -> bool with false` | src/pac.rs | ClaimValues::is_empty | replace body with false | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac.rs:1300:9: replace ClaimValues::is_empty -> bool with true` | src/pac.rs | ClaimValues::is_empty | replace body with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac.rs:1396:36: replace << with >> in <impl fmt::Display for Sid>::fmt` | src/pac.rs | <impl fmt::Display for Sid>::fmt | replace << with >> | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac.rs:1396:46: replace \| with ^ in <impl fmt::Display for Sid>::fmt` | src/pac.rs | <impl fmt::Display for Sid>::fmt | replace \| with ^ | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac.rs:1398:22: replace > with == in <impl fmt::Display for Sid>::fmt` | src/pac.rs | <impl fmt::Display for Sid>::fmt | replace > with == | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac.rs:1398:22: replace > with >= in <impl fmt::Display for Sid>::fmt` | src/pac.rs | <impl fmt::Display for Sid>::fmt | replace > with >= | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac.rs:1770:9: delete match arm CHECKSUM_HMAC_SHA384_192_AES256 in checksum_signature_len` | src/pac.rs | checksum_signature_len | delete match arm CHECKSUM_HMAC_SHA384_192_AES256 | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac.rs:182:24: replace < with <= in Pac::parse` | src/pac.rs | Pac::parse | replace < with <= | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac.rs:182:24: replace < with == in Pac::parse` | src/pac.rs | Pac::parse | replace < with == | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac.rs:248:51: replace match guard self.kerb_validation_info.is_none() with true in Pac::process_buffers` | src/pac.rs | Pac::process_buffers | replace match guard self.kerb_validation_info.is_none() with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac.rs:251:56: replace match guard self.server_checksum.is_none() with true in Pac::process_buffers` | src/pac.rs | Pac::process_buffers | replace match guard self.server_checksum.is_none() with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac.rs:256:53: replace match guard self.kdc_checksum.is_none() with true in Pac::process_buffers` | src/pac.rs | Pac::process_buffers | replace match guard self.kdc_checksum.is_none() with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac.rs:261:42: replace match guard self.credentials_info.is_none() with true in Pac::process_buffers` | src/pac.rs | Pac::process_buffers | replace match guard self.credentials_info.is_none() with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac.rs:264:46: replace match guard self.client_info.is_none() with true in Pac::process_buffers` | src/pac.rs | Pac::process_buffers | replace match guard self.client_info.is_none() with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac.rs:267:43: replace match guard self.upn_dns_info.is_none() with true in Pac::process_buffers` | src/pac.rs | Pac::process_buffers | replace match guard self.upn_dns_info.is_none() with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac.rs:270:50: replace match guard self.s4u_delegation_info.is_none() with true in Pac::process_buffers` | src/pac.rs | Pac::process_buffers | replace match guard self.s4u_delegation_info.is_none() with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac.rs:273:46: replace match guard self.device_info.is_none() with true in Pac::process_buffers` | src/pac.rs | Pac::process_buffers | replace match guard self.device_info.is_none() with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac.rs:276:53: replace match guard self.client_claims_info.is_none() with true in Pac::process_buffers` | src/pac.rs | Pac::process_buffers | replace match guard self.client_claims_info.is_none() with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac.rs:279:53: replace match guard self.device_claims_info.is_none() with true in Pac::process_buffers` | src/pac.rs | Pac::process_buffers | replace match guard self.device_claims_info.is_none() with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac.rs:366:9: replace Pac::require_service_buffers -> Result<(), Error> with Ok(())` | src/pac.rs | Pac::require_service_buffers | replace body with Ok(()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac.rs:450:9: replace InfoBuffer::validate -> Result<(), Error> with Ok(())` | src/pac.rs | InfoBuffer::validate | replace body with Ok(()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac.rs:814:48: replace \| with ^ in NtlmSupplementalCredential::parse` | src/pac.rs | NtlmSupplementalCredential::parse | replace \| with ^ | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac/credential_secrets.rs:12:9: replace <impl fmt::Debug for SecpkgSupplementalCredential>::fmt -> fmt::Result with Ok(Default::default())` | src/pac/credential_secrets.rs | <impl fmt::Debug for SecpkgSupplementalCredential>::fmt | replace body with Ok(Default::default()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac/credential_secrets.rs:49:9: replace <impl Drop for NtlmSupplementalCredential>::drop with ()` | src/pac/credential_secrets.rs | <impl Drop for NtlmSupplementalCredential>::drop | replace body with () | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac/ndr.rs:104:21: replace \|\| with && in read_ndr_wrapper` | src/pac/ndr.rs | read_ndr_wrapper | replace \|\| with && | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac/ndr.rs:104:43: replace \|\| with && in read_ndr_wrapper` | src/pac/ndr.rs | read_ndr_wrapper | replace \|\| with && | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac/ndr.rs:167:14: replace > with == in read_ndr_reasonable_count` | src/pac/ndr.rs | read_ndr_reasonable_count | replace > with == | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac/ndr.rs:167:14: replace > with >= in read_ndr_reasonable_count` | src/pac/ndr.rs | read_ndr_reasonable_count | replace > with >= | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac/ndr.rs:283:18: replace == with != in read_deferred_rpc_unicode_strings` | src/pac/ndr.rs | read_deferred_rpc_unicode_strings | replace == with != | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac/ndr.rs:326:18: replace == with != in read_deferred_claims_arrays` | src/pac/ndr.rs | read_deferred_claims_arrays | replace == with != | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac/ndr.rs:384:18: replace == with != in read_deferred_claim_entries` | src/pac/ndr.rs | read_deferred_claim_entries | replace == with != | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac/ndr.rs:482:18: replace == with != in read_deferred_i64_array` | src/pac/ndr.rs | read_deferred_i64_array | replace == with != | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac/ndr.rs:519:18: replace == with != in read_deferred_u64_array` | src/pac/ndr.rs | read_deferred_u64_array | replace == with != | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac/ndr.rs:556:18: replace == with != in read_deferred_bool_array` | src/pac/ndr.rs | read_deferred_bool_array | replace == with != | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac/ndr.rs:600:18: replace == with != in read_deferred_lpwstr_array` | src/pac/ndr.rs | read_deferred_lpwstr_array | replace == with != | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac/ndr.rs:648:15: replace > with == in read_deferred_claim_string` | src/pac/ndr.rs | read_deferred_claim_string | replace > with == | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac/ndr.rs:648:15: replace > with >= in read_deferred_claim_string` | src/pac/ndr.rs | read_deferred_claim_string | replace > with >= | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac/ndr.rs:648:27: replace \|\| with && in read_deferred_claim_string` | src/pac/ndr.rs | read_deferred_claim_string | replace \|\| with && | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac/ndr.rs:648:43: replace > with < in read_deferred_claim_string` | src/pac/ndr.rs | read_deferred_claim_string | replace > with < | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac/ndr.rs:683:5: replace ensure_zero_trailing -> Result<(), Error> with Ok(())` | src/pac/ndr.rs | ensure_zero_trailing | replace body with Ok(()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac/ndr.rs:732:27: replace \|\| with && in read_deferred_unicode_string` | src/pac/ndr.rs | read_deferred_unicode_string | replace \|\| with && | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac/ndr.rs:831:39: replace > with < in read_deferred_sid` | src/pac/ndr.rs | read_deferred_sid | replace > with < | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac/ndr.rs:831:65: replace \|\| with && in read_deferred_sid` | src/pac/ndr.rs | read_deferred_sid | replace \|\| with && | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac/ndr.rs:831:88: replace > with == in read_deferred_sid` | src/pac/ndr.rs | read_deferred_sid | replace > with == | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac/ndr.rs:831:88: replace > with >= in read_deferred_sid` | src/pac/ndr.rs | read_deferred_sid | replace > with >= | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac/ndr.rs:868:18: replace == with != in read_deferred_sid_and_attributes` | src/pac/ndr.rs | read_deferred_sid_and_attributes | replace == with != | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac/ndr.rs:913:18: replace == with != in read_deferred_domain_group_memberships` | src/pac/ndr.rs | read_deferred_domain_group_memberships | replace == with != | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac/ndr.rs:93:21: replace < with <= in read_ndr_wrapper` | src/pac/ndr.rs | read_ndr_wrapper | replace < with <= | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac/ndr.rs:93:21: replace < with == in read_ndr_wrapper` | src/pac/ndr.rs | read_ndr_wrapper | replace < with == | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac/ndr.rs:957:14: replace > with == in read_reasonable_count` | src/pac/ndr.rs | read_reasonable_count | replace > with == | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac/ndr.rs:957:14: replace > with >= in read_reasonable_count` | src/pac/ndr.rs | read_reasonable_count | replace > with >= | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/pac/reader.rs:133:27: replace \|\| with && in Reader<'buffer>::align` | src/pac/reader.rs | Reader<'buffer>::align | replace \|\| with && | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/service.rs:1049:34: replace match guard scope.ticket with true in validate_authorization_elements` | src/service.rs | validate_authorization_elements | replace match guard scope.ticket with true | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/service.rs:1272:40: replace == with != in unix_timestamp_parts` | src/service.rs | unix_timestamp_parts | replace == with != | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/service.rs:1316:34: replace > with >= in starts_after_skew` | src/service.rs | starts_after_skew | replace > with >= | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/service.rs:1322:34: replace > with >= in expired_after_skew` | src/service.rs | expired_after_skew | replace > with >= | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/service.rs:323:9: replace SharedReplayCache::prune_expired -> Result<usize, Error> with Ok(0)` | src/service.rs | SharedReplayCache::prune_expired | replace body with Ok(0) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/service.rs:333:9: replace SharedReplayCache::prune_expired_at -> Result<usize, Error> with Ok(0)` | src/service.rs | SharedReplayCache::prune_expired_at | replace body with Ok(0) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/service.rs:333:9: replace SharedReplayCache::prune_expired_at -> Result<usize, Error> with Ok(1)` | src/service.rs | SharedReplayCache::prune_expired_at | replace body with Ok(1) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/service.rs:363:9: replace SharedReplayCache::clear -> Result<(), Error> with Ok(())` | src/service.rs | SharedReplayCache::clear | replace body with Ok(()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/service.rs:383:9: replace SharedReplayCache::is_empty -> Result<bool, Error> with Ok(true)` | src/service.rs | SharedReplayCache::is_empty | replace body with Ok(true) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/service.rs:400:9: replace SharedReplayCache::force_clear_older_than -> Result<usize, Error> with Ok(0)` | src/service.rs | SharedReplayCache::force_clear_older_than | replace body with Ok(0) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/service.rs:400:9: replace SharedReplayCache::force_clear_older_than -> Result<usize, Error> with Ok(1)` | src/service.rs | SharedReplayCache::force_clear_older_than | replace body with Ok(1) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/service.rs:614:9: replace Validator<'keytab>::attach_replay_cache with ()` | src/service.rs | Validator<'keytab>::attach_replay_cache | replace body with () | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/service.rs:742:9: replace Validator<'keytab>::shared_replay_cache -> Option<&SharedReplayCache> with None` | src/service.rs | Validator<'keytab>::shared_replay_cache | replace body with None | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/service/replay.rs:137:9: replace ReplayCache::force_clear_older_than -> usize with 0` | src/service/replay.rs | ReplayCache::force_clear_older_than | replace body with 0 | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/service/replay.rs:137:9: replace ReplayCache::force_clear_older_than -> usize with 1` | src/service/replay.rs | ReplayCache::force_clear_older_than | replace body with 1 | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/service/replay.rs:179:9: replace ReplayCache::prune_expired -> usize with 0` | src/service/replay.rs | ReplayCache::prune_expired | replace body with 0 | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/service/replay.rs:187:9: replace ReplayCache::prune_expired_at -> usize with 0` | src/service/replay.rs | ReplayCache::prune_expired_at | replace body with 0 | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/service/replay.rs:65:9: replace ReplayCache::with_principal_capacity -> Self with Default::default()` | src/service/replay.rs | ReplayCache::with_principal_capacity | replace body with Default::default() | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/service/replay_quota.rs:62:32: replace > with < in PrincipalQuota::set_limit` | src/service/replay_quota.rs | PrincipalQuota::set_limit | replace > with < | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/service/replay_quota.rs:62:32: replace > with == in PrincipalQuota::set_limit` | src/service/replay_quota.rs | PrincipalQuota::set_limit | replace > with == | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/service/replay_quota.rs:62:32: replace > with >= in PrincipalQuota::set_limit` | src/service/replay_quota.rs | PrincipalQuota::set_limit | replace > with >= | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/service/replay_quota.rs:62:9: replace PrincipalQuota::set_limit with ()` | src/service/replay_quota.rs | PrincipalQuota::set_limit | replace body with () | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/service/validation.rs:135:55: replace > with >= in Validator<'_>::validate_ap_req_with_check` | src/service/validation.rs | Validator<'_>::validate_ap_req_with_check | replace > with >= | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego.rs:1050:24: replace == with != in Krb5MechToken::ap_req_bytes` | src/spnego.rs | Krb5MechToken::ap_req_bytes | replace == with != | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego.rs:1050:9: replace Krb5MechToken::ap_req_bytes -> Option<&[u8]> with None` | src/spnego.rs | Krb5MechToken::ap_req_bytes | replace body with None | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego.rs:1050:9: replace Krb5MechToken::ap_req_bytes -> Option<&[u8]> with Some(Vec::leak(Vec::new()))` | src/spnego.rs | Krb5MechToken::ap_req_bytes | replace body with Some(Vec::leak(Vec::new())) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego.rs:1050:9: replace Krb5MechToken::ap_req_bytes -> Option<&[u8]> with Some(Vec::leak(vec![0]))` | src/spnego.rs | Krb5MechToken::ap_req_bytes | replace body with Some(Vec::leak(vec![0])) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego.rs:1050:9: replace Krb5MechToken::ap_req_bytes -> Option<&[u8]> with Some(Vec::leak(vec![1]))` | src/spnego.rs | Krb5MechToken::ap_req_bytes | replace body with Some(Vec::leak(vec![1])) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego.rs:1057:24: replace == with != in Krb5MechToken::ap_rep_bytes` | src/spnego.rs | Krb5MechToken::ap_rep_bytes | replace == with != | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego.rs:1057:9: replace Krb5MechToken::ap_rep_bytes -> Option<&[u8]> with None` | src/spnego.rs | Krb5MechToken::ap_rep_bytes | replace body with None | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego.rs:1057:9: replace Krb5MechToken::ap_rep_bytes -> Option<&[u8]> with Some(Vec::leak(Vec::new()))` | src/spnego.rs | Krb5MechToken::ap_rep_bytes | replace body with Some(Vec::leak(Vec::new())) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego.rs:1057:9: replace Krb5MechToken::ap_rep_bytes -> Option<&[u8]> with Some(Vec::leak(vec![0]))` | src/spnego.rs | Krb5MechToken::ap_rep_bytes | replace body with Some(Vec::leak(vec![0])) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego.rs:1057:9: replace Krb5MechToken::ap_rep_bytes -> Option<&[u8]> with Some(Vec::leak(vec![1]))` | src/spnego.rs | Krb5MechToken::ap_rep_bytes | replace body with Some(Vec::leak(vec![1])) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego.rs:1461:24: delete ! in Token::krb5_ap_req` | src/spnego.rs | Token::krb5_ap_req | delete ! | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego.rs:1594:9: replace <impl fmt::Debug for InitiatorContext>::fmt -> fmt::Result with Ok(Default::default())` | src/spnego.rs | <impl fmt::Debug for InitiatorContext>::fmt | replace body with Ok(Default::default()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego.rs:1662:17: replace \|\| with && in InitiatorContext::validate_completion` | src/spnego.rs | InitiatorContext::validate_completion | replace \|\| with && | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego.rs:1736:46: replace \|\| with && in InitiatorContext::verify_ap_rep` | src/spnego.rs | InitiatorContext::verify_ap_rep | replace \|\| with && | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego.rs:2030:53: replace \|\| with && in decode_negotiate_header` | src/spnego.rs | decode_negotiate_header | replace \|\| with && | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego.rs:2134:72: replace \| with ^ in authenticator_checksum` | src/spnego.rs | authenticator_checksum | replace \| with ^ | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego.rs:2148:5: replace validate_gss_token_id -> Result<(), Error> with Ok(())` | src/spnego.rs | validate_gss_token_id | replace body with Ok(()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego.rs:2324:5: replace random_sequence_number -> Result<u32, Error> with Ok(0)` | src/spnego.rs | random_sequence_number | replace body with Ok(0) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego.rs:2324:5: replace random_sequence_number -> Result<u32, Error> with Ok(1)` | src/spnego.rs | random_sequence_number | replace body with Ok(1) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego.rs:2326:34: replace & with ^ in random_sequence_number` | src/spnego.rs | random_sequence_number | replace & with ^ | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego.rs:2326:34: replace & with \| in random_sequence_number` | src/spnego.rs | random_sequence_number | replace & with \| | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego.rs:349:9: replace <impl fmt::Debug for MicToken>::fmt -> fmt::Result with Ok(Default::default())` | src/spnego.rs | <impl fmt::Debug for MicToken>::fmt | replace body with Ok(Default::default()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego.rs:614:20: replace == with != in WrapToken::set_checksum` | src/spnego.rs | WrapToken::set_checksum | replace == with != | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego.rs:696:9: replace WrapToken::new_initiator_sealed -> Result<Self, Error> with Ok(Default::default())` | src/spnego.rs | WrapToken::new_initiator_sealed | replace body with Ok(Default::default()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego.rs:890:9: replace <impl fmt::Debug for WrapToken>::fmt -> fmt::Result with Ok(Default::default())` | src/spnego.rs | <impl fmt::Debug for WrapToken>::fmt | replace body with Ok(Default::default()) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego/der.rs:115:9: replace DerReader<'buffer>::finish -> Result<(), Error> with Ok(())` | src/spnego/der.rs | DerReader<'buffer>::finish | replace body with Ok(()) | missed | killed | `der_token_rejects_trailing_elements` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego/der.rs:141:18: replace > with == in DerReader<'buffer>::read_len` | src/spnego/der.rs | DerReader<'buffer>::read_len | replace > with == | missed | killed | `der_lengths_reject_overwide_values` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego/der.rs:141:18: replace > with >= in DerReader<'buffer>::read_len` | src/spnego/der.rs | DerReader<'buffer>::read_len | replace > with >= | missed | killed | `der_lengths_reject_nonminimal_forms` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego/der.rs:155:40: replace \| with ^ in DerReader<'buffer>::read_len` | src/spnego/der.rs | DerReader<'buffer>::read_len | replace \| with ^ | missed | equivalent | length shifted left by eight has zero low eight bits, while the u8 operand occupies only those bits. OR and XOR yield the identical length on every iteration; every TLV caller receives identical values, remaining bytes and errors. |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego/der.rs:282:28: replace \| with ^ in encode_base128` | src/spnego/der.rs | encode_base128 | replace \| with ^ | missed | equivalent | group is masked with 0x7f, so bit 0x80 is always clear. OR and XOR with 0x80 both set only the continuation bit and emit identical OID bytes for every caller. |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego/der.rs:352:12: replace < with <= in encode_len` | src/spnego/der.rs | encode_len | replace < with <= | missed | killed | `der_encoder_uses_long_form_at_128` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego/der.rs:364:19: replace \| with ^ in encode_len` | src/spnego/der.rs | encode_len | replace \| with ^ | missed | equivalent | count is the number of significant octets of a usize length (at most size_of::<usize>(), 8 on supported 64-bit targets and 4 on 32-bit). Bit 0x80 is clear, so OR and XOR emit the identical long-form length prefix for every encoded TLV. |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego/der.rs:78:16: replace & with ^ in DerReader<'buffer>::read_tlv` | src/spnego/der.rs | DerReader<'buffer>::read_tlv | replace & with ^ | missed | killed | `der_reader_rejects_high_tag_identifiers` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego/negotiation.rs:117:9: replace \| with ^ in response_mic` | src/spnego/negotiation.rs | response_mic | replace \| with ^ | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego/negotiation.rs:74:52: replace \| with ^ in verify_mic` | src/spnego/negotiation.rs | verify_mic | replace \| with ^ | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego/oid.rs:65:5: replace validate_arcs -> Result<(), Error> with Ok(())` | src/spnego/oid.rs | validate_arcs | replace body with Ok(()) | missed | killed | `der_oid_constructor_rejects_invalid_arc_prefixes` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego/oid.rs:68:18: replace \|\| with && in validate_arcs` | src/spnego/oid.rs | validate_arcs | replace \|\| with && | missed | killed | `der_oid_constructor_rejects_invalid_arc_prefixes` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/spnego/oid.rs:68:28: replace < with > in validate_arcs` | src/spnego/oid.rs | validate_arcs | replace < with > | missed | killed | `der_oid_constructor_rejects_invalid_arc_prefixes` |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/ticket.rs:165:5: replace build_encoded -> Result<Vec<u8>, Error> with Ok(vec![0])` | src/ticket.rs | build_encoded | replace body with Ok(vec![0]) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/ticket.rs:165:5: replace build_encoded -> Result<Vec<u8>, Error> with Ok(vec![1])` | src/ticket.rs | build_encoded | replace body with Ok(vec![1]) | missed | open | - |
| 91b09c279ffadbf55c71a3e2f11eb8bcbcb8dbb0 | `src/ticket.rs:165:5: replace build_encoded -> Result<Vec<u8>, Error> with Ok(vec![])` | src/ticket.rs | build_encoded | replace body with Ok(vec![]) | missed | open | - |
