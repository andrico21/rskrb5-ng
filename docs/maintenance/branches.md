# Branch ledger

Every ref of the repository as of the merge of `release/0.3.0` into `main`
(todo 1 of the rskrb5-ng plan), with the disposition each one received. Each
row carries the tip SHA, the containment proof (method, exact command, and its
output when it was re-run) and the disposition. `origin/*` refs were
remote-tracking refs of `https://github.com/andrico21/rskrb5.git`, which is now
`https://github.com/andrico21/rskrb5-ng.git`; `release/0.3.0` merge target:
see `git log --first-parent main`. The final state and the upstream pull
request states are at the end.

Proof methods:

- `is-ancestor`: `git merge-base --is-ancestor <ref> <base>`, exit 0 = contained.
- `merge-tree no-op`: `git merge-tree --write-tree <base> <ref>` prints `<base>^{tree}` as its first line, so merging `<ref>` into `<base>` changes nothing.
- `patch-id` / `range-diff`: the change is present under another SHA.

| Ref | Tip | Proof method | Proof command | Proof output | Disposition |
|---|---|---|---|---|---|
| `refs/heads/chore/deps-refresh` | `4142dcec0c92` | same tip as remote | `test "$(git rev-parse refs/heads/chore/deps-refresh)" = "$(git rev-parse refs/remotes/origin/chore/deps-refresh)"` | exit 0 | local ref deleted: done (archive tag archive/chore/deps-refresh, 7e8aee4136287223d571e2f98de8e5544c127eb1) |
| `refs/heads/fix/ccache-count-bounds` | `fdf641aaea94` | same tip as remote | `test "$(git rev-parse refs/heads/fix/ccache-count-bounds)" = "$(git rev-parse refs/remotes/origin/fix/ccache-count-bounds)"` | exit 0 | kept: local copy of the PR-head branch (same tip as origin) |
| `refs/heads/fix/client-renewal-series` | `fbf4320f2a83` | same tip as remote | `test "$(git rev-parse refs/heads/fix/client-renewal-series)" = "$(git rev-parse refs/remotes/origin/fix/client-renewal-series)"` | exit 0 | kept: local copy of the PR-head branch (same tip as origin) |
| `refs/heads/fix/config-clockskew-handoff` | `3e4c6c545484` | same tip as remote | `test "$(git rev-parse refs/heads/fix/config-clockskew-handoff)" = "$(git rev-parse refs/remotes/origin/fix/config-clockskew-handoff)"` | exit 0 | kept: local copy of the PR-head branch (same tip as origin) |
| `refs/heads/fix/domain-realm-normalization` | `20e48ab9a944` | same tip as remote | `test "$(git rev-parse refs/heads/fix/domain-realm-normalization)" = "$(git rev-parse refs/remotes/origin/fix/domain-realm-normalization)"` | exit 0 | kept: local copy of the PR-head branch (same tip as origin) |
| `refs/heads/fix/enctype-policy` | `7c2c29763da9` | is-ancestor | `git merge-base --is-ancestor refs/heads/fix/enctype-policy origin/fix/enctype-policy` | exit 0 | fast-forwarded: done |
| `refs/heads/fix/host-case-spn` | `5dd96f294af3` | same tip as remote | `test "$(git rev-parse refs/heads/fix/host-case-spn)" = "$(git rev-parse refs/remotes/origin/fix/host-case-spn)"` | exit 0 | kept: local copy of the PR-head branch (same tip as origin) |
| `refs/heads/fix/kadmin-unsigned-success` | `a089831e548e` | same tip as remote | `test "$(git rev-parse refs/heads/fix/kadmin-unsigned-success)" = "$(git rev-parse refs/remotes/origin/fix/kadmin-unsigned-success)"` | exit 0 | kept: local copy of the PR-head branch (same tip as origin) |
| `refs/heads/fix/mutual-auth-classification` | `71cc63b220fe` | same tip as remote | `test "$(git rev-parse refs/heads/fix/mutual-auth-classification)" = "$(git rev-parse refs/remotes/origin/fix/mutual-auth-classification)"` | exit 0 | kept: local copy of the PR-head branch (same tip as origin) |
| `refs/heads/fix/service-authenticator-realm` | `920f9b0d2faf` | same tip as remote | `test "$(git rev-parse refs/heads/fix/service-authenticator-realm)" = "$(git rev-parse refs/remotes/origin/fix/service-authenticator-realm)"` | exit 0 | kept: local copy of the PR-head branch (same tip as origin) |
| `refs/heads/fix/service-replay-name-type` | `b7fb459c9d33` | same tip as remote | `test "$(git rev-parse refs/heads/fix/service-replay-name-type)" = "$(git rev-parse refs/remotes/origin/fix/service-replay-name-type)"` | exit 0 | kept: local copy of the PR-head branch (same tip as origin) |
| `refs/heads/fix/tcp-preauth-pinning` | `b1153c7b826b` | same tip as remote | `test "$(git rev-parse refs/heads/fix/tcp-preauth-pinning)" = "$(git rev-parse refs/remotes/origin/fix/tcp-preauth-pinning)"` | exit 0 | kept: local copy of the PR-head branch (same tip as origin) |
| `refs/heads/main` | `49f2f296258e` | is-ancestor | `git merge-base --is-ancestor 49f2f29 origin/main` | exit 0 | fast-forwarded to origin/main and merged in todo 1 (integration branch in worktree rskrb5-ng-wt/main); tip listed is the pre-todo-1 value |
| `refs/heads/release/0.2.1` | `f441b11a8ae3` | same tip as remote | `test "$(git rev-parse refs/heads/release/0.2.1)" = "$(git rev-parse refs/remotes/origin/release/0.2.1)"` | exit 0 | local ref deleted: done (archive tag archive/release/0.2.1, 158ba8f0dafc1d16dc3c3596a8aa9fc926192cde) |
| `refs/heads/release/0.2.2` | `ca1ee8988d03` | same tip as remote | `test "$(git rev-parse refs/heads/release/0.2.2)" = "$(git rev-parse refs/remotes/origin/release/0.2.2)"` | exit 0 | local ref deleted: done (archive tag archive/release/0.2.2, 366dec196fe4d6eefa007edad6867e7575aaa6e8) |
| `refs/heads/release/0.3.0` | `7f7bf1a91b3e` | same tip as remote | `test "$(git rev-parse refs/heads/release/0.3.0)" = "$(git rev-parse refs/remotes/origin/release/0.3.0)"` | exit 0 | local ref deleted: done (archive tag archive/release/0.3.0, a67a5a23e1beeb834299b0319fdd2f67f8f62dd6) |
| `refs/remotes/bundle/i0` | `3f4010e186ca` | merge-tree no-op | `git merge-tree --write-tree origin/release/0.2.2 refs/remotes/bundle/i0` | exit 0; first line 2133092aa5ec == origin/release/0.2.2^{tree} (2133092aa5ec) | local ref deleted: done (no remote is configured) |
| `refs/remotes/bundle/i10` | `9d7c08a07cf7` | range-diff | `git range-diff --creation-factor=95 --no-patch 1450607^! refs/remotes/bundle/i10^!` | 1:  1450607 ! 1:  9d7c08a Add environment-free Config and LibDefaults constructors | local ref deleted: done (no remote is configured) |
| `refs/remotes/bundle/i11` | `4545255a5c93` | range-diff | `git range-diff --creation-factor=95 --no-patch 7a61eb2^! refs/remotes/bundle/i11^!` | 1:  7a61eb2 ! 1:  4545255 Detect include cycles through roots and directories | local ref deleted: done (no remote is configured) |
| `refs/remotes/bundle/i12` | `926c33d220ff` | merge-tree no-op | `git merge-tree --write-tree origin/release/0.2.2 refs/remotes/bundle/i12` | exit 0; first line 2133092aa5ec == origin/release/0.2.2^{tree} (2133092aa5ec) | local ref deleted: done (no remote is configured) |
| `refs/remotes/bundle/i13` | `57591ec46553` | merge-tree no-op | `git merge-tree --write-tree origin/release/0.2.2 refs/remotes/bundle/i13` | exit 0; first line 2133092aa5ec == origin/release/0.2.2^{tree} (2133092aa5ec) | local ref deleted: done (no remote is configured) |
| `refs/remotes/bundle/i14` | `a39abf4040c9` | merge-tree no-op | `git merge-tree --write-tree origin/release/0.2.2 refs/remotes/bundle/i14` | exit 0; first line 2133092aa5ec == origin/release/0.2.2^{tree} (2133092aa5ec) | local ref deleted: done (no remote is configured) |
| `refs/remotes/bundle/i2` | `9ab741254432` | merge-tree no-op | `git merge-tree --write-tree origin/release/0.2.2 refs/remotes/bundle/i2` | exit 0; first line 2133092aa5ec == origin/release/0.2.2^{tree} (2133092aa5ec) | local ref deleted: done (no remote is configured) |
| `refs/remotes/bundle/pristine` | `6f4abc9c1c51` | tip | `git rev-parse refs/remotes/bundle/pristine` | 6f4abc9c1c51ffa5a93ebe8bb4a63cc0d4fc801f | local ref deleted: done (no remote is configured) |
| `refs/remotes/origin/HEAD` | `79a28d34f46a` | symbolic-ref | `git symbolic-ref refs/remotes/origin/HEAD` | refs/remotes/origin/main | symbolic ref to origin/main; not a branch |
| `refs/remotes/origin/chore/deps-refresh` | `4142dcec0c92` | is-ancestor | `git merge-base --is-ancestor refs/remotes/origin/chore/deps-refresh origin/release/0.3.0` | exit 0 | archive tag archive/chore/deps-refresh (7e8aee4136287223d571e2f98de8e5544c127eb1), branch deleted from origin: done |
| `refs/remotes/origin/export-padata-constants` | `017f23f9c59f` | merge-tree no-op | `git merge-tree --write-tree origin/release/0.2.2 refs/remotes/origin/export-padata-constants` | exit 0; first line 2133092aa5ec == origin/release/0.2.2^{tree} (2133092aa5ec) | kept: frozen head of clelange/rskrb5#17 (open on 2026-10-27, see below) |
| `refs/remotes/origin/fix/ccache-count-bounds` | `fdf641aaea94` | is-ancestor | `git merge-base --is-ancestor refs/remotes/origin/fix/ccache-count-bounds origin/release/0.3.0` | exit 0 | kept: frozen head of clelange/rskrb5#22 (open on 2026-10-27, see below) |
| `refs/remotes/origin/fix/client-renewal-series` | `fbf4320f2a83` | is-ancestor | `git merge-base --is-ancestor refs/remotes/origin/fix/client-renewal-series origin/release/0.3.0` | exit 0 | kept: frozen head of clelange/rskrb5#28 (open on 2026-10-27, see below) |
| `refs/remotes/origin/fix/config-clockskew-handoff` | `3e4c6c545484` | is-ancestor | `git merge-base --is-ancestor refs/remotes/origin/fix/config-clockskew-handoff origin/release/0.3.0` | exit 0 | kept: frozen head of clelange/rskrb5#24 (open on 2026-10-27, see below) |
| `refs/remotes/origin/fix/domain-realm-normalization` | `20e48ab9a944` | is-ancestor | `git merge-base --is-ancestor refs/remotes/origin/fix/domain-realm-normalization origin/release/0.3.0` | exit 0 | kept: frozen head of clelange/rskrb5#26 (open on 2026-10-27, see below) |
| `refs/remotes/origin/fix/enctype-policy` | `752832b08379` | is-ancestor | `git merge-base --is-ancestor refs/remotes/origin/fix/enctype-policy origin/release/0.3.0` | exit 0 | kept: frozen head of clelange/rskrb5#27 (open on 2026-10-27, see below) |
| `refs/remotes/origin/fix/host-case-spn` | `5dd96f294af3` | is-ancestor | `git merge-base --is-ancestor refs/remotes/origin/fix/host-case-spn origin/release/0.3.0` | exit 0 | kept: frozen head of clelange/rskrb5#25 (open on 2026-10-27, see below) |
| `refs/remotes/origin/fix/kadmin-unsigned-success` | `a089831e548e` | is-ancestor | `git merge-base --is-ancestor refs/remotes/origin/fix/kadmin-unsigned-success origin/release/0.3.0` | exit 0 | kept: frozen head of clelange/rskrb5#23 (open on 2026-10-27, see below) |
| `refs/remotes/origin/fix/mutual-auth-classification` | `71cc63b220fe` | is-ancestor | `git merge-base --is-ancestor refs/remotes/origin/fix/mutual-auth-classification origin/release/0.3.0` | exit 0 | kept: frozen head of clelange/rskrb5#29 (open on 2026-10-27, see below) |
| `refs/remotes/origin/fix/service-authenticator-realm` | `920f9b0d2faf` | merge-tree no-op | `git merge-tree --write-tree origin/release/0.2.2 refs/remotes/origin/fix/service-authenticator-realm` | exit 0; first line 2133092aa5ec == origin/release/0.2.2^{tree} (2133092aa5ec) | kept: frozen head of clelange/rskrb5#21 (open on 2026-10-27, see below) |
| `refs/remotes/origin/fix/service-replay-name-type` | `b7fb459c9d33` | patch-id | `for c in 5148851 1f85793; do git show $c \| git patch-id --stable; done; echo cherry-pick:; git log -1 --format='%H %s' a1ace38` | b9095e85e938bcfea5b22f041cc5afbf9ebbe58d 51488518286ccb9e2a5a89cc65faac48e78d6634 / b9095e85e938bcfea5b22f041cc5afbf9ebbe58d 1f85793894772022479dbe302092f7bbbc74f67e / cherry-pick: / a1ace388dd3308e52454f7deb21b1387e4b2704c service: reject an authenticator re-presented under a rewritten ticket sname | kept: frozen head of clelange/rskrb5#20 (open on 2026-10-27, see below) |
| `refs/remotes/origin/fix/tcp-preauth-pinning` | `b1153c7b826b` | merge-tree no-op | `git merge-tree --write-tree origin/release/0.2.2 refs/remotes/origin/fix/tcp-preauth-pinning` | exit 0; first line 2133092aa5ec == origin/release/0.2.2^{tree} (2133092aa5ec) | kept: frozen head of Gittingc0dez/rskrb5#1 (open on 2026-10-27, see below) |
| `refs/remotes/origin/hex-dev-dependency` | `0f9a113a2603` | merge-tree no-op | `git merge-tree --write-tree origin/release/0.2.2 refs/remotes/origin/hex-dev-dependency` | exit 0; first line 2133092aa5ec == origin/release/0.2.2^{tree} (2133092aa5ec) | kept: frozen head of clelange/rskrb5#16 (open on 2026-10-27, see below) |
| `refs/remotes/origin/kpasswd-verbatim-result-bytes` | `d65a038a2b2e` | merge-tree no-op | `git merge-tree --write-tree origin/release/0.2.2 refs/remotes/origin/kpasswd-verbatim-result-bytes` | exit 0; first line 2133092aa5ec == origin/release/0.2.2^{tree} (2133092aa5ec) | kept: frozen head of clelange/rskrb5#18 (open on 2026-10-27, see below) |
| `refs/remotes/origin/main` | `79a28d34f46a` | tip | `git rev-parse origin/main` | 79a28d34f46a33f915bf94f3fdde829b0b3e321e | main (development branch; holds the merge of release/0.3.0) |
| `refs/remotes/origin/release/0.2.1` | `f441b11a8ae3` | is-ancestor | `git merge-base --is-ancestor refs/remotes/origin/release/0.2.1 origin/release/0.3.0` | exit 0 | archive tag archive/release/0.2.1 (158ba8f0dafc1d16dc3c3596a8aa9fc926192cde), branch deleted from origin: done |
| `refs/remotes/origin/release/0.2.2` | `ca1ee8988d03` | is-ancestor | `git merge-base --is-ancestor refs/remotes/origin/release/0.2.2 origin/release/0.3.0` | exit 0 | archive tag archive/release/0.2.2 (366dec196fe4d6eefa007edad6867e7575aaa6e8), branch deleted from origin: done |
| `refs/remotes/origin/release/0.3.0` | `7f7bf1a91b3e` | is-ancestor | `git merge-base --is-ancestor refs/remotes/origin/release/0.3.0 origin/release/0.3.0` | exit 0 | archive tag archive/release/0.3.0 (a67a5a23e1beeb834299b0319fdd2f67f8f62dd6), branch deleted from origin: done (merged into main in todo 1) |
| `refs/remotes/origin/rust-1-98-clippy-drift` | `40c506d5f243` | merge-tree no-op | `git merge-tree --write-tree origin/release/0.2.2 refs/remotes/origin/rust-1-98-clippy-drift` | exit 0; first line 2133092aa5ec == origin/release/0.2.2^{tree} (2133092aa5ec) | kept: frozen head of clelange/rskrb5#15 (open on 2026-10-27, see below) |
| `refs/tags/v0.1.0` | `203f78af396f` | is-ancestor | `git merge-base --is-ancestor refs/tags/v0.1.0 origin/release/0.3.0` | exit 0 | kept: release tag |
| `refs/tags/v0.2.0` | `62eaa01060e2` | is-ancestor | `git merge-base --is-ancestor refs/tags/v0.2.0 origin/release/0.3.0` | exit 0 | kept: release tag |
| `refs/tags/v0.2.1` | `16411806e0dd` | is-ancestor | `git merge-base --is-ancestor refs/tags/v0.2.1 origin/release/0.3.0` | exit 0 | kept: release tag |
| `refs/tags/v0.2.2` | `58b27bbb6867` | is-ancestor | `git merge-base --is-ancestor refs/tags/v0.2.2 origin/release/0.3.0` | exit 0 | kept: release tag |

## Branch model

- Trunk development happens on `main`.
- Work branches are local `work/*` branches only and are never pushed.
- Current rskrb5-ng release tags `N.N.N` (without `v`) are placed on `main`
  commits. The v-prefixed tags above are historical rskrb5/rskrb5-patched releases.
- PR-head branches (the `fix/*` branches and the four other kept branches above) are frozen: they are not deleted, rebased or force-pushed.
- `archive/*` tags hold the tips of deleted branches (`chore/deps-refresh`, `release/0.2.1`, `release/0.2.2`, `release/0.3.0`).

## Final state

Checked on 2026-10-27 with `git ls-remote --heads origin`,
`git ls-remote --tags origin` and `gh pr view` (read-only):

- Remote branches: `main` and the 15 frozen pull-request head branches below,
  16 in all.
- Remote tags: the upstream release tags `v0.1.0` (`203f78a`) and `v0.2.0`
  (`a17d210`), the `rskrb5-patched` release tags `v0.2.1` (`f441b11`) and
  `v0.2.2` (`58b27bb`), and the four archive tags
  `archive/chore/deps-refresh`, `archive/release/0.2.1`,
  `archive/release/0.2.2` and `archive/release/0.3.0`. No `rskrb5-ng` release
  tag exists yet.
- Local refs: `main`, local copies of the eleven `fix/*` PR-head branches, and a
  `work/*` branch only while a change is in progress.
- The repository is standalone: `gh api repos/andrico21/rskrb5-ng --jq .fork`
  prints `false` (since 2026-10-25).

## Upstream pull request state

Each frozen head branch is the head of one pull request. The state was first
recorded right after the repository left the fork network
(2026-10-25T16:51:06Z, todo 3 of the plan) and checked again on 2026-10-27.
The state of the fourteen `clelange/rskrb5` pull requests was the same both
times;
`Gittingc0dez/rskrb5#1` was not recorded on 2026-10-25 and was first recorded
on 2026-10-27. On 2026-10-27 every pull request's head commit equalled the
branch tip. These pull requests are a historical record: the
project doesn't maintain them, and nothing here comments on or edits them.

| Head branch | Pull request | Head commit | State 2026-10-25 | State 2026-10-27 |
|---|---|---|---|---|
| `rust-1-98-clippy-drift` | [clelange/rskrb5#15](https://github.com/clelange/rskrb5/pull/15) | `40c506d5f243` | open | open |
| `hex-dev-dependency` | [clelange/rskrb5#16](https://github.com/clelange/rskrb5/pull/16) | `0f9a113a2603` | open | open |
| `export-padata-constants` | [clelange/rskrb5#17](https://github.com/clelange/rskrb5/pull/17) | `017f23f9c59f` | open | open |
| `kpasswd-verbatim-result-bytes` | [clelange/rskrb5#18](https://github.com/clelange/rskrb5/pull/18) | `d65a038a2b2e` | open | open |
| `fix/service-replay-name-type` | [clelange/rskrb5#20](https://github.com/clelange/rskrb5/pull/20) | `b7fb459c9d33` | open | open |
| `fix/service-authenticator-realm` | [clelange/rskrb5#21](https://github.com/clelange/rskrb5/pull/21) | `920f9b0d2faf` | open | open |
| `fix/ccache-count-bounds` | [clelange/rskrb5#22](https://github.com/clelange/rskrb5/pull/22) | `fdf641aaea94` | open | open |
| `fix/kadmin-unsigned-success` | [clelange/rskrb5#23](https://github.com/clelange/rskrb5/pull/23) | `a089831e548e` | open | open |
| `fix/config-clockskew-handoff` | [clelange/rskrb5#24](https://github.com/clelange/rskrb5/pull/24) | `3e4c6c545484` | open | open |
| `fix/host-case-spn` | [clelange/rskrb5#25](https://github.com/clelange/rskrb5/pull/25) | `5dd96f294af3` | open | open |
| `fix/domain-realm-normalization` | [clelange/rskrb5#26](https://github.com/clelange/rskrb5/pull/26) | `20e48ab9a944` | open | open |
| `fix/enctype-policy` | [clelange/rskrb5#27](https://github.com/clelange/rskrb5/pull/27) | `752832b08379` | open | open |
| `fix/client-renewal-series` | [clelange/rskrb5#28](https://github.com/clelange/rskrb5/pull/28) | `fbf4320f2a83` | open | open |
| `fix/mutual-auth-classification` | [clelange/rskrb5#29](https://github.com/clelange/rskrb5/pull/29) | `71cc63b220fe` | open | open |
| `fix/tcp-preauth-pinning` | [Gittingc0dez/rskrb5#1](https://github.com/Gittingc0dez/rskrb5/pull/1) | `b1153c7b826b` | not recorded | open |

`Gittingc0dez/rskrb5#1` is stacked on the third-party upstream pull request
[clelange/rskrb5#19](https://github.com/clelange/rskrb5/pull/19), whose head
lives in the `Gittingc0dez/rskrb5` repository, not here.
