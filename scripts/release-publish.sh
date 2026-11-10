#!/usr/bin/env bash
# The checks and release steps of .github/workflows/publish.yml (and the tag
# lookup of release.yml), kept in one script so `self-test` can run them on
# stubbed cargo, curl and gh with no network, token or registry.
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
CRATE=rskrb5-ng
USER_AGENT="rskrb5-ng-release (https://github.com/andrico21/rskrb5-ng)"
CRATES_IO_API="${CRATES_IO_API:-https://crates.io/api/v1}"
CRATES_IO_STATIC="${CRATES_IO_STATIC:-https://static.crates.io}"
RELEASE_TAG='^[0-9]+\.[0-9]+\.[0-9]+$'

usage() {
  cat <<'EOF'
Usage: scripts/release-publish.sh <command> [args...]

  find-tag SHA HEAD_BRANCH    release.yml: print "No N.N.N tag points at SHA" and
                              output an empty tag, or output the one N.N.N tag and
                              whether this CI run (on HEAD_BRANCH) dispatches it.
  check-ref REF SHA           REF is refs/tags/N.N.N, Cargo.toml names rskrb5-ng at
                              version N.N.N, the tag points at SHA, and SHA is an
                              ancestor of origin/main.
  check-ci-run REPO SHA       a CI run of REPO for SHA concluded success, from REPO
                              itself, triggered by push or workflow_dispatch.
  package OUT_DIR [--no-verify]
                              cargo package --locked; copy the .crate and its
                              .sha256 to OUT_DIR.
  publish VERSION SHA256      re-package without building, require SHA256, then
                              upload, or verify that crates.io already holds
                              exactly these bytes.
  release TAG VERSION         create the GitHub release for TAG unless it exists.
  self-test                   run the commands above on stubs.
EOF
}

die() {
  echo "::error::$*" >&2
  exit 1
}

output() {
  printf '%s=%s\n' "$1" "$2" >>"${GITHUB_OUTPUT:-/dev/null}"
}

manifest_identity() {
  python3 -c 'import sys, tomllib; p = tomllib.load(open(sys.argv[1], "rb")).get("package", {}); print(p.get("name", ""), p.get("version", ""))' \
    "$ROOT_DIR/Cargo.toml"
}

find_tag() {
  local sha="$1" head_branch="$2" tags count all_tags status
  git -C "$ROOT_DIR" rev-parse --verify "$sha^{commit}" >/dev/null || die "invalid release commit $sha"
  all_tags="$(git -C "$ROOT_DIR" tag --points-at "$sha")" || die "release tag lookup failed"
  tags="$(grep -E "$RELEASE_TAG" <<<"$all_tags")" || {
    status=$?
    [[ "$status" == 1 ]] || die "release tag filtering failed (exit $status)"
  }
  if [[ -z "$tags" ]]; then
    echo "::notice::No N.N.N tag points at $sha - this run is not a release invocation; nothing is dispatched."
    output tag ""
    output dispatch false
    return 0
  fi
  count="$(printf '%s\n' "$tags" | wc -l)"
  [[ "$count" -eq 1 ]] || die "more than one N.N.N tag points at $sha: $(tr '\n' ' ' <<<"$tags"); a release commit carries exactly one."
  output tag "$tags"
  # The tag push runs CI on the tag ref (`head_branch` is the tag name); only
  # that run dispatches, so a commit pushed to main together with its tag is
  # dispatched once. A run without a head branch dispatches too: a missed
  # dispatch would block the release, a second one only asks for a second
  # approval of an idempotent publish.
  if [[ "$head_branch" == "$tags" || -z "$head_branch" ]]; then
    output dispatch true
    echo "Found tag $tags at $sha; dispatching publish.yml at refs/tags/$tags."
  else
    output dispatch false
    echo "::notice::Tag $tags points at $sha; the CI run on the tag ref dispatches publish.yml, not this run on $head_branch."
  fi
}

check_ref() {
  local ref="$1" sha="$2" tag name version tagged
  [[ "$ref" =~ ^refs/tags/([0-9]+\.[0-9]+\.[0-9]+)$ ]] ||
    die "$ref is not a release tag ref (refs/tags/N.N.N); publish.yml runs only at a release tag"
  tag="${BASH_REMATCH[1]}"
  read -r name version < <(manifest_identity)
  [[ "$name" == "$CRATE" ]] || die "Cargo.toml names package '$name', not $CRATE"
  [[ "$version" == "$tag" ]] || die "tag $tag does not match the Cargo.toml version $version"
  git -C "$ROOT_DIR" fetch --quiet --no-tags --force origin "refs/tags/$tag:refs/tags/$tag"
  tagged="$(git -C "$ROOT_DIR" rev-parse "refs/tags/$tag^{commit}")"
  [[ "$tagged" == "$sha" ]] || die "tag $tag points at $tagged, not at $sha"
  git -C "$ROOT_DIR" fetch --quiet --no-tags --force origin "+refs/heads/main:refs/remotes/origin/main"
  git -C "$ROOT_DIR" merge-base --is-ancestor "$sha" origin/main ||
    die "$sha (tag $tag) is not an ancestor of origin/main; release commits land on main first"
  output tag "$tag"
  output version "$version"
  echo "$tag -> $sha: $CRATE $version, on origin/main."
}

check_ci_run() {
  local repo="$1" sha="$2" passed
  passed="$(gh api "repos/$repo/actions/workflows/ci.yml/runs?head_sha=$sha&per_page=100" |
    jq --arg repo "$repo" '[.workflow_runs[]
      | select(.conclusion == "success" and .head_repository.full_name == $repo
        and (.event == "push" or .event == "workflow_dispatch"))] | length')"
  [[ "$passed" -ge 1 ]] ||
    die "no successful push or workflow_dispatch CI run of $repo for $sha"
  echo "CI passed for $sha ($passed successful run(s))."
}

crate_file() {
  printf '%s/package/%s-%s.crate\n' "${CARGO_TARGET_DIR:-$ROOT_DIR/target}" "$CRATE" "$1"
}

package() {
  local out="$1" verify="${2:-}" version
  read -r _ version < <(manifest_identity)
  (cd "$ROOT_DIR" && cargo package --locked ${verify:+"$verify"})
  mkdir -p "$out"
  cp "$(crate_file "$version")" "$out/"
  (cd "$out" && sha256sum "$CRATE-$version.crate" >"$CRATE-$version.crate.sha256")
  output sha256 "$(cut -d' ' -f1 "$out/$CRATE-$version.crate.sha256")"
}

sha256_of() {
  sha256sum "$1" | cut -d' ' -f1
}

published_status() {
  curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
    --user-agent "$USER_AGENT" "$CRATES_IO_API/crates/$CRATE/$1"
}

# Downloads the published .crate and requires it to be exactly the bytes this
# tag packages: an out-of-band or different upload is never certified.
verify_published() {
  local version="$1" expected="$2" download
  download="$(mktemp)"
  local published status=0
  curl --fail --silent --show-error --location --user-agent "$USER_AGENT" \
    --output "$download" "$CRATES_IO_STATIC/crates/$CRATE/$CRATE-$version.crate" || status=$?
  published="$(sha256_of "$download")"
  rm -f "$download"
  [[ "$status" -eq 0 ]] || die "downloading the published $CRATE $version failed (curl exit $status)"
  [[ "$published" == "$expected" ]] ||
    die "crates.io holds $CRATE $version with sha256 $published, not this tag's $expected; no release is created"
  echo "crates.io holds exactly this tag's $CRATE $version (sha256 $expected)."
}

publish() {
  local version="$1" expected="$2" local_sha status upload rc
  (cd "$ROOT_DIR" && cargo package --locked --no-verify)
  local_sha="$(sha256_of "$(crate_file "$version")")"
  [[ "$local_sha" == "$expected" ]] ||
    die "re-packaged sha256 $local_sha differs from the verified artifact $expected"
  status="$(published_status "$version")"
  case "$status" in
    200)
      echo "$CRATE $version is already on crates.io; verifying the published bytes."
      verify_published "$version" "$expected"
      ;;
    404)
      upload="$(cd "$ROOT_DIR" && cargo publish --locked --no-verify 2>&1)" && rc=0 || rc=$?
      printf '%s\n' "$upload"
      if [[ "$rc" -eq 0 ]]; then
        echo "::notice::Published $CRATE $version to crates.io."
      elif grep -qiF "already exists" <<<"$upload"; then
        verify_published "$version" "$expected"
      else
        die "cargo publish failed for $CRATE $version (exit $rc)"
      fi
      ;;
    *) die "crates.io answered $status for $CRATE $version" ;;
  esac
}

release() {
  local tag="$1" version="$2" notes
  if gh release view "$tag" >/dev/null 2>&1; then
    echo "The GitHub release $tag exists; nothing to create."
    return 0
  fi
  notes="$(mktemp)"
  if [[ -f "$ROOT_DIR/CHANGELOG.md" ]]; then
    awk -v ver="$version" '
      $0 ~ "^## \\[" ver "\\]" { found=1; next }
      found && /^## \[/        { exit }
      found                    { print }
    ' "$ROOT_DIR/CHANGELOG.md" >"$notes"
  fi
  [[ -s "$notes" ]] || printf '%s %s; see CHANGELOG.md\n' "$CRATE" "$version" >"$notes"
  local status=0
  gh release create "$tag" --title "$CRATE $tag" --notes-file "$notes" --verify-tag || status=$?
  rm -f "$notes"
  return "$status"
}

self_test() {
  local scratch failures=0
  scratch="$(mktemp -d "${TMPDIR:-/tmp}/rskrb5-release-selftest.XXXXXX")"
  st_fail() {
    echo "self-test FAIL: $*" >&2
    failures=$((failures + 1))
  }
  # A repository with a main branch, its origin, and a tag of the release commit.
  local origin="$scratch/origin.git" work="$scratch/work"
  git init --quiet --bare "$origin"
  git init --quiet -b main "$work"
  printf '[package]\nname = "%s"\nversion = "0.3.0"\n' "$CRATE" >"$work/Cargo.toml"
  printf '# Changelog\n\n## [0.3.0] - 2026-11-01\n\n- Notes.\n' >"$work/CHANGELOG.md"
  git -C "$work" -c user.name=t -c user.email=t@t add -A
  git -C "$work" -c user.name=t -c user.email=t@t commit --quiet -m release
  git -C "$work" tag 0.3.0
  git -C "$work" tag v0.3.0
  git -C "$work" remote add origin "$origin"
  git -C "$work" push --quiet origin main 0.3.0
  local sha
  sha="$(git -C "$work" rev-parse HEAD)"

  local -a run=(env "ROOT_DIR_OVERRIDE=$work" bash "${BASH_SOURCE[0]}")
  "${run[@]}" check-ref "refs/tags/0.3.0" "$sha" >/dev/null 2>&1 || st_fail "check-ref rejected a valid release tag"
  for bad in refs/heads/main refs/tags/v0.3.0 refs/tags/0.3.0-rc.1; do
    if "${run[@]}" check-ref "$bad" "$sha" >/dev/null 2>&1; then st_fail "check-ref accepted $bad"; fi
  done
  if "${run[@]}" check-ref refs/tags/0.3.0 0000000000000000000000000000000000000000 >/dev/null 2>&1; then
    st_fail "check-ref accepted a tag that points elsewhere"
  fi
  git -C "$work" tag 0.3.1
  git -C "$work" push --quiet origin 0.3.1
  if "${run[@]}" check-ref refs/tags/0.3.1 "$sha" >/dev/null 2>&1; then
    st_fail "check-ref accepted tag 0.3.1 on a 0.3.0 manifest"
  fi
  git -C "$work" tag -d 0.3.1 >/dev/null
  git -C "$work" checkout --quiet -b side
  git -C "$work" -c user.name=t -c user.email=t@t commit --quiet --allow-empty -m side
  git -C "$work" tag 0.3.2
  printf '[package]\nname = "%s"\nversion = "0.3.2"\n' "$CRATE" >"$work/Cargo.toml"
  git -C "$work" push --quiet origin 0.3.2
  if "${run[@]}" check-ref refs/tags/0.3.2 "$(git -C "$work" rev-parse HEAD)" >/dev/null 2>&1; then
    st_fail "check-ref accepted a commit that is not on main"
  fi
  git -C "$work" checkout --quiet -- Cargo.toml
  git -C "$work" -c user.name=t -c user.email=t@t commit --quiet --allow-empty -m untagged
  local untagged
  untagged="$(git -C "$work" rev-parse HEAD)"
  git -C "$work" checkout --quiet main

  local out
  if "${run[@]}" find-tag 0000000000000000000000000000000000000000 main >/dev/null 2>&1; then
    st_fail "find-tag accepted a nonexistent commit"
  fi
  if (git() { return 73; }; find_tag "$sha" main) >/dev/null 2>&1; then
    st_fail "find-tag swallowed a Git failure"
  fi
  out="$("${run[@]}" find-tag "$untagged" main 2>&1)"
  [[ "$out" == *"No N.N.N tag points at"* ]] || st_fail "find-tag on an untagged commit: $out"
  GITHUB_OUTPUT="$scratch/find-out" "${run[@]}" find-tag "$sha" 0.3.0 >/dev/null
  grep -qx 'tag=0.3.0' "$scratch/find-out" && grep -qx 'dispatch=true' "$scratch/find-out" ||
    st_fail "find-tag on the tag ref did not dispatch 0.3.0: $(cat "$scratch/find-out")"
  GITHUB_OUTPUT="$scratch/find-main" "${run[@]}" find-tag "$sha" main >/dev/null
  grep -qx 'dispatch=false' "$scratch/find-main" || st_fail "the main-branch CI run would dispatch too"
  GITHUB_OUTPUT="$scratch/find-none" "${run[@]}" find-tag "$sha" "" >/dev/null
  grep -qx 'dispatch=true' "$scratch/find-none" || st_fail "a tagged run without a head branch did not dispatch"

  # Stubs: cargo packages the bytes in STUB_CRATE and uploads per STUB_UPLOAD;
  # curl answers STUB_STATUS and serves STUB_REMOTE; gh fails `release create`
  # while $state/gh-fail exists and records every release it creates.
  local stubs="$scratch/stubs" state="$scratch/state"
  mkdir -p "$stubs" "$state"
  cat >"$stubs/cargo" <<'EOF'
#!/usr/bin/env bash
echo "cargo $*" >>"$STATE/log"
case "$1" in
  package) mkdir -p "$CARGO_TARGET_DIR/package"; printf '%s' "$STUB_CRATE" >"$CARGO_TARGET_DIR/package/rskrb5-ng-0.3.0.crate" ;;
  publish)
    case "$STUB_UPLOAD" in
      ok) printf '%s' "$STUB_CRATE" >"$STATE/registry"; echo "Uploaded" ;;
      exists) echo "error: crate version \`0.3.0\` is already exists on crates.io index" >&2; exit 101 ;;
      *) echo "error: network" >&2; exit 101 ;;
    esac ;;
esac
EOF
  cat >"$stubs/curl" <<'EOF'
#!/usr/bin/env bash
echo "curl ${*: -1}" >>"$STATE/log"
if [[ "$*" == *"--write-out"* ]]; then
  [[ -f "$STATE/registry" ]] && printf 200 || printf 404
  exit 0
fi
while [[ $# -gt 0 ]]; do [[ "$1" == --output ]] && { cat "$STATE/registry" >"$2"; exit 0; }; shift; done
EOF
  cat >"$stubs/gh" <<'EOF'
#!/usr/bin/env bash
echo "gh $*" >>"$STATE/log"
case "$1 $2" in
  "api "*)
    [[ "${STUB_CI_API_FAILURE:-0}" == 0 ]] || { cat "$STATE/ci-runs.json"; echo "HTTP 502" >&2; exit 1; }
    cat "$STATE/ci-runs.json" ;;
  "release view") [[ -f "$STATE/release" ]] ;;
  "release create")
    if [[ -f "$STATE/gh-fail" ]]; then rm -f "$STATE/gh-fail"; echo "HTTP 502" >&2; exit 1; fi
    [[ -f "$STATE/release" ]] && { echo "release exists" >&2; exit 1; }
    echo created >>"$STATE/release-creations"; touch "$STATE/release" ;;
esac
EOF
  chmod +x "$stubs/cargo" "$stubs/curl" "$stubs/gh"
  local good bad
  good="$(printf '%s' crate-bytes | sha256sum | cut -d' ' -f1)"
  bad="$(printf '%s' other-bytes | sha256sum | cut -d' ' -f1)"
  local -a stubbed=(env "PATH=$stubs:$PATH" "STATE=$state" "CARGO_TARGET_DIR=$scratch/target"
    "STUB_CRATE=crate-bytes" "ROOT_DIR_OVERRIDE=$work" bash "${BASH_SOURCE[0]}")
  local ci_case conclusion event repository expected
  for ci_case in \
    'success|push|andrico21/rskrb5-ng|accept' \
    'success|workflow_dispatch|andrico21/rskrb5-ng|accept' \
    'failure|push|andrico21/rskrb5-ng|reject' \
    'pending|push|andrico21/rskrb5-ng|reject' \
    'success|pull_request|andrico21/rskrb5-ng|reject' \
    'success|push|foreign/rskrb5-ng|reject'; do
    IFS='|' read -r conclusion event repository expected <<<"$ci_case"
    jq -n --arg conclusion "$conclusion" --arg event "$event" --arg repo "$repository" \
      '{workflow_runs: [{conclusion: (if $conclusion == "pending" then null else $conclusion end),
        event: $event, head_repository: {full_name: $repo}}]}' >"$state/ci-runs.json"
    if "${stubbed[@]}" check-ci-run andrico21/rskrb5-ng "$sha" >"$state/ci-result" 2>&1; then
      [[ "$expected" == accept ]] || st_fail "check-ci-run accepted $ci_case"
    else
      [[ "$expected" == reject ]] || st_fail "check-ci-run rejected $ci_case: $(cat "$state/ci-result")"
    fi
  done
  printf '{"workflow_runs": []}\n' >"$state/ci-runs.json"
  if "${stubbed[@]}" check-ci-run andrico21/rskrb5-ng "$sha" >"$state/ci-result" 2>&1; then
    st_fail "check-ci-run accepted an empty run list"
  fi
  printf '{"workflow_runs": [{"conclusion": "success", "event": "push", "head_repository": {"full_name": "andrico21/rskrb5-ng"}}]}\n' >"$state/ci-runs.json"
  if STUB_CI_API_FAILURE=1 "${stubbed[@]}" check-ci-run andrico21/rskrb5-ng "$sha" >"$state/ci-result" 2>&1; then
    st_fail "check-ci-run accepted an API failure"
  fi
  publish_and_release() {
    "${stubbed[@]}" publish 0.3.0 "$1" >/dev/null 2>&1 && "${stubbed[@]}" release 0.3.0 0.3.0 >/dev/null 2>&1
  }

  # 1. The upload succeeds and the GitHub release creation fails once.
  touch "$state/gh-fail"
  if STUB_UPLOAD=ok publish_and_release "$good"; then st_fail "the run with a failing gh succeeded"; fi
  [[ -f "$state/registry" && ! -f "$state/release" ]] || st_fail "the first run did not upload, or created a release"
  # 2. The re-dispatch finds the version published, verifies its bytes and
  #    creates the missing release; 3. a further re-dispatch creates nothing.
  STUB_UPLOAD=fail publish_and_release "$good" || st_fail "recovery after an upload and a failed release did not succeed"
  STUB_UPLOAD=fail publish_and_release "$good" || st_fail "a re-dispatch after recovery failed"
  [[ "$(wc -l <"$state/release-creations")" -eq 1 ]] || st_fail "the release was not created exactly once"
  grep -q 'curl .*static.*rskrb5-ng-0.3.0.crate' "$state/log" || st_fail "recovery did not download the published crate"
  [[ "$(grep -c '^cargo publish' "$state/log")" -eq 1 ]] || st_fail "an already-published version was uploaded again"
  # 4. Other bytes under the version: no release, an error.
  rm -f "$state/release" "$state/release-creations"
  printf other-bytes >"$state/registry"
  if publish_and_release "$good"; then st_fail "different published bytes were certified"; fi
  [[ ! -f "$state/release" ]] || st_fail "a release was created for different published bytes"
  # 5. The upload races another run: "already exists" is verified, not trusted.
  rm -f "$state/registry"
  STUB_UPLOAD=exists "${stubbed[@]}" publish 0.3.0 "$good" >/dev/null 2>&1 &&
    st_fail "an 'already exists' answer without published bytes was accepted"
  # 6. A re-package that differs from the verified artifact uploads nothing.
  : >"$state/log"
  if STUB_UPLOAD=ok "${stubbed[@]}" publish 0.3.0 "$bad" >/dev/null 2>&1; then
    st_fail "a re-package that differs from the artifact was published"
  fi
  if grep -q '^cargo publish' "$state/log"; then st_fail "cargo publish ran after a sha256 mismatch"; fi

  rm -rf "$scratch"
  [[ "$failures" -eq 0 ]] || return 1
  echo "self-test: ok"
}

main() {
  if [[ -n "${ROOT_DIR_OVERRIDE:-}" ]]; then
    ROOT_DIR="$ROOT_DIR_OVERRIDE"
  fi
  local command="${1:-}"
  shift || true
  case "$command" in
    find-tag) find_tag "$@" ;;
    check-ref) check_ref "$@" ;;
    check-ci-run) check_ci_run "$@" ;;
    package) package "$@" ;;
    publish) publish "$@" ;;
    release) release "$@" ;;
    self-test) self_test ;;
    -h | --help | "") usage ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
}

main "$@"
