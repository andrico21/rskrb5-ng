# shellcheck shell=bash
# Sourced by run.sh: the INTEROP_* globals it sets are read by lib.sh/run.sh
# functions (SC2034, SC2153), and the stubs are invoked indirectly (SC2317).
# shellcheck disable=SC2034,SC2153,SC2317
# `scripts/interop/run.sh self-test`: checks the env-file serialization, the
# redaction and the required-mode handling of `test` with the container
# runtime and cargo stubbed out. No container, network or image is touched.
# Sourced by run.sh after lib.sh; uses its cmd_test.

interop_self_test() {
  local scratch failures=0 printed loaded out
  scratch="$(mktemp -d "${TMPDIR:-/tmp}/rskrb5-interop-selftest.XXXXXX")"
  st_fail() {
    echo "self-test FAIL: $*" >&2
    failures=$((failures + 1))
  }
  mode_of() {
    stat -c %A "$1"
  }

  # 1. Env file: private modes, secrets redacted, hostile values stay data.
  INTEROP_STATE_DIR="$scratch/state"
  INTEROP_ENV_FILE="$INTEROP_STATE_DIR/interop.env"
  umask 022
  mkdir -p "$INTEROP_STATE_DIR"
  chmod 755 "$INTEROP_STATE_DIR"
  printf 'stale\n' >"$INTEROP_ENV_FILE"
  chmod 644 "$INTEROP_ENV_FILE"
  local secret marker="$scratch/EXECUTED"
  secret="$(interop_new_secret)"
  local hostile_path="/tmp/lab keytabs/user's \"one\".keytab"
  local hostile_addr="kdc.example:88; touch $marker"
  local hostile_url="http://example.test/\$(touch $marker)/\`touch $marker\`"
  local multiline=$'first-line-secret\nsecond-line-secret'
  INTEROP_ENV_NAMES=()
  interop_env INTEROP 1
  interop_env INTEROP_SELFTEST_KDC "$hostile_addr"
  interop_env INTEROP_SELFTEST_KEYTAB "$hostile_path"
  interop_env INTEROP_SELFTEST_URL "$hostile_url"
  interop_env INTEROP_SELFTEST_USER_PASSWORD "$secret"
  interop_env INTEROP_SELFTEST_TOKEN "$multiline"
  interop_write_env "$INTEROP_ENV_FILE" || st_fail "interop_write_env failed"
  [[ "$(mode_of "$INTEROP_ENV_FILE")" == "-rw-------" ]] || st_fail "env file mode is $(mode_of "$INTEROP_ENV_FILE")"
  [[ "$(mode_of "$INTEROP_STATE_DIR")" == "drwx------" ]] || st_fail "state dir mode is $(mode_of "$INTEROP_STATE_DIR")"
  ! grep -q '^stale$' "$INTEROP_ENV_FILE" || st_fail "the stale env file was not replaced"
  loaded="$(
    # shellcheck disable=SC1090
    source "$INTEROP_ENV_FILE" &&
      printf '%s\0' "$INTEROP_SELFTEST_KDC" "$INTEROP_SELFTEST_KEYTAB" "$INTEROP_SELFTEST_URL" \
        "$INTEROP_SELFTEST_USER_PASSWORD" "$INTEROP_SELFTEST_TOKEN" | od -An -c
  )" || st_fail "the env file does not source"
  [[ "$loaded" == "$(printf '%s\0' "$hostile_addr" "$hostile_path" "$hostile_url" "$secret" "$multiline" | od -An -c)" ]] ||
    st_fail "values did not round-trip through the env file"
  [[ ! -e "$marker" ]] || st_fail "an env-file value ran as a shell command"
  printed="$(interop_print_env "$INTEROP_ENV_FILE")"
  [[ "$printed" != *"$secret"* && "$printed" != *first-line-secret* && "$printed" != *second-line-secret* ]] ||
    st_fail "env printed a secret"
  [[ "$printed" == *"export INTEROP_SELFTEST_USER_PASSWORD=<redacted>"* &&
    "$printed" == *"export INTEROP_SELFTEST_TOKEN=<redacted>"* ]] || st_fail "env did not mark the secrets redacted"
  [[ "$printed" == *"export INTEROP=1"* ]] || st_fail "env dropped a non-secret value"
  if interop_env FOO bar 2>/dev/null || interop_env INTEROP_lower x 2>/dev/null; then
    st_fail "an invalid env-file key was accepted"
  fi
  mkdir "$scratch/elsewhere"
  ln -s "$scratch/elsewhere" "$scratch/linked"
  if interop_write_env "$scratch/linked/interop.env" 2>/dev/null; then
    st_fail "interop_write_env wrote through a symlinked directory"
  fi
  [[ -z "$(ls -A "$scratch/elsewhere")" ]] || st_fail "a file reached the symlink target"

  # 2. Runtime selection is explicit or detected, never guessed.
  if (INTEROP_RUNTIME=containerd interop_detect_runtime 2>/dev/null); then
    st_fail "an unsupported INTEROP_RUNTIME was accepted"
  fi
  if (PATH="$scratch/empty" INTEROP_RUNTIME=podman interop_detect_runtime 2>/dev/null); then
    st_fail "INTEROP_RUNTIME=podman without podman on PATH was accepted"
  fi

  # 3. Required mode: an unreachable fixture fails the suite and names it.
  INTEROP_SUITE_NAMES=(selftest)
  INTEROP_SUITE_TARGETS=(interop_selftest)
  INTEROP_SUITE_FIXTURES=(mit-kdc)
  # `run.sh test` starts without a selected runtime: the fixture report must
  # select one itself (probe run 44267620042 printed `missing`).
  INTEROP_RT=""
  interop_detect_runtime() { INTEROP_RT=stub; }
  interop_rt() {
    [[ "$INTEROP_RT" == stub ]] || return 1
    case "$1" in
      inspect) printf 'exited' ;;
      *) return 0 ;;
    esac
  }
  # The stub test binary prints what SELFTEST_CARGO_MODE selects; the listing
  # has two scenarios.
  cargo() {
    if [[ " $* " == *" --list "* ]]; then
      printf 'scenarios::first: test\nscenarios::second: test\nharness::tests::unit: test\n'
      return 0
    fi
    [[ "${INTEROP_REQUIRED:-}" != 1 || "${INTEGRATION_REQUIRED:-}" == 1 ]] || {
      echo "INTEGRATION_REQUIRED was not implied"
      return 101
    }
    case "$SELFTEST_CARGO_MODE" in
      unreachable)
        printf 'test scenarios::first ... interop: ran scenarios::first\nok\n'
        printf 'Error: required interop fixture unreachable: mit-kdc at 127.0.0.1:18088 (container rskrb5-interop-mit-kdc)\n'
        printf 'test result: FAILED. 1 passed; 1 failed\n'
        return 101
        ;;
      skipped)
        printf 'test scenarios::first ... interop: ran scenarios::first\nok\n'
        printf 'test scenarios::second ... interop: SKIP scenarios::second: INTEROP_MIT_KDC unset\nok\n'
        printf 'test result: ok. 2 passed; 0 failed\n'
        ;;
      complete)
        printf 'test scenarios::first ... interop: ran scenarios::first\nok\n'
        printf 'test scenarios::second ... interop: ran scenarios::second\nok\n'
        printf 'test result: ok. 2 passed; 0 failed\n'
        ;;
    esac
  }
  out="$( (SELFTEST_CARGO_MODE=unreachable INTEROP_REQUIRED=1 cmd_test selftest) 2>&1)" &&
    st_fail "required mode passed with an unreachable fixture"
  [[ "$out" == *"fixture mit-kdc (container rskrb5-interop-mit-kdc): exited"* &&
    "$out" == *"required interop fixture unreachable: mit-kdc"* ]] ||
    st_fail "the required-mode failure did not name the fixture: $out"
  out="$( (SELFTEST_CARGO_MODE=skipped INTEROP_REQUIRED=1 cmd_test selftest) 2>&1)" &&
    st_fail "required mode passed with a skipped scenario"
  out="$( (SELFTEST_CARGO_MODE=skipped INTEROP_REQUIRED='' cmd_test selftest) 2>&1)" ||
    st_fail "optional mode failed on a visible skip: $out"
  [[ "$out" == *"ran 1, skipped 1"* ]] || st_fail "the skip count was not reported: $out"
  out="$( (SELFTEST_CARGO_MODE=complete INTEROP_REQUIRED=1 cmd_test selftest) 2>&1)" ||
    st_fail "required mode failed with every scenario run: $out"
  [[ "$out" == *"scenarios listed 2, ran 2, skipped 0"* ]] || st_fail "the scenario counts were not reported: $out"
  unset -f cargo interop_rt interop_detect_runtime

  # 4. Redaction of fixture logs.
  "$INTEROP_ROOT/scripts/interop/redact.sh" --self-test >/dev/null || st_fail "redact.sh --self-test failed"

  # 5. Lane 1D-a (FAST, SPAKE, OTP+RADIUS, PKINIT, anonymous fixtures): per-run
  #    secrets, env keys, the self-check runners (container runtime stubbed),
  #    the container-side assertion helpers, number ranges and image pins.
  out="$(interop_preauth_self_test "$scratch")" || true
  [[ "$out" == *interop-preauth-checks-complete ]] || st_fail "lane 1D-a checks aborted before the end: $out"
  out="${out%interop-preauth-checks-complete}"
  [[ -z "$out" ]] || st_fail "lane 1D-a checks:"$'\n'"$out"

  # 5. Lane 1F: the mit-peer fixture's registration, order and policy.
  interop_peer_self_test st_fail

  # 5. Lane 1D-b network fixtures (scripts/interop/net-*/).
  interop_self_test_net "$scratch" || failures=$((failures + 1))

  rm -rf "$scratch"
  if ((failures != 0)); then
    return 1
  fi
  echo "self-test: ok"
}

# Lane 1D-a cases of `run.sh self-test`; prints one line per failed check.
# Runs in a subshell so the fixtures it sources and the stubs it defines leave
# no state behind.
interop_preauth_self_test() {
  (
    local dir="$INTEROP_ROOT/scripts/interop" work="$1/preauth" name file prefix calls
    mkdir -p "$work"
    INTEROP_ENV_NAMES=()
    # shellcheck source=scripts/interop/mit/fixture.sh
    source "$dir/mit/fixture.sh" || {
      printf 'cannot source mit/fixture.sh\n'
      exit 0
    }
    # shellcheck source=scripts/interop/radius/fixture.sh
    source "$dir/radius/fixture.sh" || {
      printf 'cannot source radius/fixture.sh\n'
      exit 0
    }
    bad() { printf '%s\n' "$*"; }
    interop_log() { :; }

    # Secrets: fresh [A-Za-z0-9]{24} values, all redacted as secrets, distinct.
    interop_mit_preauth_secrets || bad "interop_mit_preauth_secrets failed"
    local -A seen=()
    for name in "${INTEROP_MIT_PREAUTH_SECRET_NAMES[@]}"; do
      [[ "${!name:-}" =~ ^[A-Za-z0-9]{24}$ ]] || bad "$name is not a fresh 24-character secret"
      interop_is_secret_name "$name" || bad "$name would not be redacted (names must end in _PASSWORD, _SECRET or _TOKEN)"
      [[ -z "${seen[${!name:-}]:-}" ]] || bad "$name repeats another secret"
      seen["${!name:-}"]=1
    done

    # Env keys: valid names, the files under OUT/pki, no secret-looking key.
    local before=${#INTEROP_ENV_NAMES[@]}
    interop_mit_preauth_env /state/mit || bad "interop_mit_preauth_env failed"
    local -a added=("${INTEROP_ENV_NAMES[@]:before}")
    for name in INTEROP_MIT_FAST_USER INTEROP_MIT_FAST_REQUIRED_SERVICE INTEROP_MIT_SPAKE_USER \
      INTEROP_MIT_SPAKE_REQUIRED_SERVICE INTEROP_MIT_OTP_USER INTEROP_MIT_PKINIT_USER INTEROP_MIT_PKINIT_CERT \
      INTEROP_MIT_PKINIT_KEY INTEROP_MIT_PKINIT_RSA_CERT INTEROP_MIT_PKINIT_ANCHORS INTEROP_MIT_ANONYMOUS_PRINCIPAL; do
      [[ " ${added[*]} " == *" $name "* ]] || bad "interop_mit_preauth_env did not record $name"
    done
    [[ "${INTEROP_MIT_PKINIT_CERT:-}" == /state/mit/pki/pkinit-ec.pem ]] || bad "PKINIT cert path is ${INTEROP_MIT_PKINIT_CERT:-unset}"
    for name in "${added[@]}"; do
      ! interop_is_secret_name "$name" || bad "$name is recorded as a secret by the preauth env (secrets are made by interop_mit_preauth_secrets)"
    done

    # The mit-kdc self-check runner stops at the first failing check and names
    # the fixture, the container and the check.
    calls="$work/calls"
    : >"$calls"
    interop_rt() {
      printf '%s\n' "$*" >>"$calls"
      [[ "$*" != *"${FAILING_CHECK:-none}.sh"* ]]
    }
    interop_mit_run_selfcheck c1 20-fast 30-spake 2>/dev/null || bad "interop_mit_run_selfcheck failed with passing checks"
    [[ "$(cat "$calls")" == $'exec c1 bash /opt/interop/mit/preauth/selfcheck/20-fast.sh\nexec c1 bash /opt/interop/mit/preauth/selfcheck/30-spake.sh' ]] ||
      bad "the self-checks did not run in order: $(tr '\n' '|' <"$calls")"
    : >"$calls"
    local message
    message="$(FAILING_CHECK=30-spake interop_mit_run_selfcheck c1 30-spake 45-pkinit 2>&1)" &&
      bad "interop_mit_run_selfcheck passed with a failing check"
    [[ "$message" == *"fixture mit-kdc (container c1): self-check 30-spake failed"* ]] ||
      bad "the failure did not name fixture, container and check: $message"
    ! grep -q 45-pkinit "$calls" || bad "a check ran after the failing one"

    # The radius self-check: accepted AND rejected logins of otpuser must be
    # logged after the radclient step (the radclient requests do not count).
    interop_rt() {
      case "$1 ${2:-}" in
        "logs "*)
          printf 'Info: Ready to process requests\n'
          printf 'Auth: (3) Login OK: [otpuser] (from client interop port 0)\n'
          printf 'Auth: (4) Login incorrect (pap: mismatch): [otpuser] (from client interop port 0)\n'
          if [[ -e "$work/kdc-ran" ]]; then
            case "${RADIUS_LOG_MODE:-both}" in
              both)
                printf 'Auth: (5) Login OK: [otpuser] (from client interop port 0)\n'
                printf 'Auth: (6) Login incorrect (pap: mismatch): [otpuser] (from client interop port 0)\n'
                ;;
              no-rejection) printf 'Auth: (5) Login OK: [otpuser] (from client interop port 0)\n' ;;
            esac
          fi
          ;;
        "exec rskrb5-interop-mit-kdc") : >"$work/kdc-ran" ;;
        *) : ;;
      esac
    }
    rm -f "$work/kdc-ran"
    interop_radius_selfcheck 2>/dev/null || bad "interop_radius_selfcheck failed although radiusd logged the KDC's accepted and rejected logins"
    for RADIUS_LOG_MODE in none no-rejection; do
      rm -f "$work/kdc-ran"
      message="$(RADIUS_LOG_MODE=$RADIUS_LOG_MODE interop_radius_selfcheck 2>&1)" &&
        bad "interop_radius_selfcheck passed with RADIUS log mode $RADIUS_LOG_MODE"
      [[ "$message" == *"fixture radius (container rskrb5-interop-radius)"* ]] ||
        bad "the radius failure (mode $RADIUS_LOG_MODE) did not name the fixture and container: $message"
    done

    # Container-side helpers: a trace line must match, the KDC log is read only
    # after the mark.
    SC_NAME=selftest SC_DIR="$work/sc" SC_KDC_LOG="$work/kdc.log"
    # shellcheck source=scripts/interop/mit/preauth/selfcheck/lib.sh
    source "$dir/mit/preauth/selfcheck/lib.sh"
    sc_prepare
    printf 'Preauth module spake (151) (real) returned: 0/Success\n' >"$SC_DIR/run.trace"
    sc_expect_trace run 'Preauth module spake \(151\) \(real\) returned: 0/Success' "present" >/dev/null || bad "sc_expect_trace missed a present line"
    ! sc_expect_trace run 'Encrypted timestamp' "absent" >/dev/null 2>&1 || bad "sc_expect_trace accepted a missing line"
    sc_expect_no_trace run 'Encrypted timestamp' "absent" >/dev/null || bad "sc_expect_no_trace rejected a missing line"
    ! sc_expect_no_trace run 'spake' "present" >/dev/null 2>&1 || bad "sc_expect_no_trace accepted a present line"
    printf 'old ISSUE line\n' >"$SC_KDC_LOG"
    sc_log_mark
    printf 'new HIGHER_AUTHENTICATION_REQUIRED line\n' >>"$SC_KDC_LOG"
    sc_expect_kdc_log 'HIGHER_AUTHENTICATION_REQUIRED' "new line" >/dev/null || bad "sc_expect_kdc_log missed a line after the mark"
    ! sc_expect_kdc_log 'old ISSUE' "old line" >/dev/null 2>&1 || bad "sc_expect_kdc_log matched a line before the mark"
    sc_run echoed echo hello
    if [[ "$SC_RC" -ne 0 ]] || ! sc_expect_out echoed '^hello$' "stdout" >/dev/null; then
      bad "sc_run did not capture the command output"
    fi
    sc_run failed false
    if [[ "$SC_RC" -eq 0 ]] || sc_expect_rc failed zero "exit" >/dev/null 2>&1; then
      bad "sc_expect_rc zero accepted a failing command"
    fi

    # Number ranges (plan lanes share one image): the 1D-a drop-ins use 20-49
    # and no directory holds two drop-ins with one prefix; host ports stay in
    # 19000-19099.
    for file in provision.d/20-fast.sh provision.d/30-spake.sh provision.d/40-otp.sh provision.d/45-pkinit.sh \
      provision.d/48-anonymous.sh kdc.conf.d/20-fast.conf kdc.conf.d/30-spake.conf kdc.conf.d/40-otp.conf \
      kdc.conf.d/45-pkinit.conf krb5.conf.d/30-spake.conf; do
      [[ -f "$dir/mit/$file" ]] || { bad "missing lane 1D-a file mit/$file"; continue; }
      prefix="${file##*/}"
      prefix="${prefix%%-*}"
      ((10#$prefix >= 20 && 10#$prefix <= 49)) || bad "mit/$file is outside the lane 1D-a prefix range 20-49"
    done
    for file in provision.d started.d kdc.conf.d krb5.conf.d; do
      [[ -z "$(find "$dir/mit/$file" -maxdepth 1 -type f -name '[0-9][0-9]-*' -printf '%f\n' | cut -c1-2 | sort | uniq -d)" ]] ||
        bad "mit/$file holds two drop-ins with the same prefix"
    done
    prefix="$(grep -o 'INTEROP_RADIUS_PORT:-[0-9]*' "$dir/radius/fixture.sh" | head -1)"
    prefix="${prefix##*-}"
    ((prefix >= 19000 && prefix <= 19099)) || bad "the radius host port ${prefix:-unset} is outside 19000-19099"

    # Every image of the fixture is pinned by digest.
    while IFS= read -r file; do
      [[ "$file" =~ @sha256:[0-9a-f]{64}($|[[:space:]]) ]] || bad "radius/Dockerfile FROM line is not pinned by digest: $file"
    done < <(grep -E '^FROM ' "$dir/radius/Dockerfile")
    printf 'interop-preauth-checks-complete'
  )
}

# Lane 1F: checks of the mit-peer fixture (scripts/interop/peer-mit/) that need
# no container: it registers itself and its suite, it is sourced after mit-kdc,
# its security policy holds, and the constants that two languages share agree.
# $1 is the failure reporter of interop_self_test.
interop_peer_self_test() {
  local report="$1" peer_dir="$INTEROP_ROOT/scripts/interop" registered files first_peer first_mit index
  if [[ ! -f "$peer_dir/peer-mit/fixture.sh" ]]; then
    "$report" "scripts/interop/peer-mit/fixture.sh is missing"
    return 0
  fi
  registered="$(
    INTEROP_FIXTURES=()
    INTEROP_SUITE_NAMES=()
    INTEROP_SUITE_TARGETS=()
    INTEROP_SUITE_FIXTURES=()
    # shellcheck disable=SC1091
    source "$peer_dir/peer-mit/fixture.sh"
    printf '%s|%s|%s|%s' "${INTEROP_FIXTURES[*]}" "${INTEROP_SUITE_NAMES[*]}" "${INTEROP_SUITE_TARGETS[*]}" "${INTEROP_SUITE_FIXTURES[*]}"
    declare -F fixture_mit_peer_up >/dev/null || printf '|no-up'
  )"
  [[ "$registered" == "mit-peer|peer|interop_peer|mit-kdc mit-peer mit-peer-iso" ]] ||
    "$report" "peer-mit/fixture.sh registered '$registered'"
  # run.sh sources the fixtures in glob order: the KDC fixture must come first,
  # in the C collation and in the caller's.
  for index in C ""; do
    files="$(
      if [[ -n "$index" ]]; then export LC_ALL="$index"; fi
      cd "$INTEROP_ROOT/scripts/interop" && printf '%s\n' */fixture.sh
    )"
    first_mit="$(grep -n '^mit/fixture.sh$' <<<"$files" | cut -d: -f1)"
    first_peer="$(grep -n '^peer-mit/fixture.sh$' <<<"$files" | cut -d: -f1)"
    [[ -n "$first_mit" && -n "$first_peer" && "$first_mit" -lt "$first_peer" ]] ||
      "$report" "peer-mit/fixture.sh does not sort after mit/fixture.sh (collation '${index:-default}')"
  done
  ! grep -v '^[[:space:]]*#' "$peer_dir/peer-mit/fixture.sh" | grep -q -- '--privileged' ||
    "$report" "peer-mit/fixture.sh starts a privileged container"
  grep -q -- '--cap-drop ALL' "$peer_dir/peer-mit/fixture.sh" || "$report" "peer-mit/fixture.sh does not drop every capability"
  ! grep -E -- ' -p "?[^1"]' "$peer_dir/peer-mit/fixture.sh" | grep -q -v '127\.0\.0\.1' ||
    "$report" "peer-mit/fixture.sh publishes a port beyond 127.0.0.1"
  # The per-run password of peeruser is derived the same way on both sides.
  # shellcheck disable=SC2016  # the needle is literal text of the two scripts
  local derivation='"rskrb5-interop peer-user v1${INTEROP_MIT_ADMIN_PASSWORD}"'
  if ! grep -F -q -- "$derivation" "$peer_dir/peer-mit/fixture.sh" ||
    ! grep -F -q -- "$derivation" "$peer_dir/mit/provision.d/70-peer.sh"; then
    "$report" "the peeruser password derivation differs between fixture.sh and 70-peer.sh"
  fi
  # The frame limit is shared by the adapter and the Rust client: 1 MiB.
  grep -q 'PEER_MAX_FRAME = 1048576' "$peer_dir/peer-mit/peer/peer.h" || "$report" "the adapter's frame limit is not 1 MiB"
  grep -q 'MAX_FRAME: usize = 0x10_0000' "$INTEROP_ROOT/tests/interop/peer_frame.rs" ||
    "$report" "the Rust client's frame limit is not 1 MiB"
}

# Lane 1D-b: the network fixtures register after mit-kdc with the dns zone
# last, the derived TEST-side secrets agree between host and provision.d,
# the zone carries every record type MIT discovery reads, and the self-check
# helpers fail naming the fixture. No container is started.
interop_self_test_net() {
  local scratch="$1" failures=0 order out zone a b
  net_fail() {
    echo "self-test FAIL (net): $*" >&2
    failures=$((failures + 1))
  }
  order="$(
    INTEROP_FIXTURES=()
    INTEROP_SUITE_NAMES=()
    INTEROP_SUITE_TARGETS=()
    INTEROP_SUITE_FIXTURES=()
    load_fixtures
    printf '%s\n' "${INTEROP_FIXTURES[*]}"
    printf '%s\n' "$(cmd_suites)"
  )" || net_fail "the fixture files do not load"
  [[ "$order" =~ ^mit-kdc\ .*mit-other\ .*dns$'\n' ]] ||
    net_fail "mit-kdc must start first and dns last: $order"
  local fixture
  for fixture in httpd kcm kdcproxy mit-other; do
    [[ " ${order%%$'\n'*} " == *" $fixture "* ]] || net_fail "fixture $fixture is not registered: $order"
  done
  [[ "$order" == *$'\n'"net interop_net mit-kdc mit-other dns httpd"* ]] ||
    net_fail "suite net is not registered with its fixtures: $order"

  # shellcheck source=scripts/interop/net-common/net.sh
  source "$INTEROP_ROOT/scripts/interop/net-common/net.sh"
  a="$(net_derive_secret cross-realm Abc123)" || net_fail "net_derive_secret refused a valid password"
  b="$(net_derive_secret kpasswd-old Abc123)"
  [[ "$a" =~ ^[0-9a-f]{32}$ && "$a" != "$b" ]] || net_fail "derived secrets must be 32 hex characters and differ per label"
  for label in cross-realm kpasswd-old; do
    [[ "$(net_derive_secret "$label" Abc123)" == "$(printf 'rskrb5-interop %s v1:%s' "$label" Abc123 | sha256sum | cut -c1-32)" ]] ||
      net_fail "net_derive_secret $label does not match the provision.d derivation"
  done
  if ! grep -qF "printf 'rskrb5-interop %s v1:%s' cross-realm" "$INTEROP_ROOT/scripts/interop/mit/provision.d/50-other-realm.sh" ||
    ! grep -qF "printf 'rskrb5-interop %s v1:%s' kpasswd-old" "$INTEROP_ROOT/scripts/interop/mit/provision.d/51-net-services.sh"; then
    net_fail "a provision.d script no longer derives its secret like net_derive_secret"
  fi
  if (net_derive_secret cross-realm 'bad value' 2>/dev/null); then
    net_fail "net_derive_secret accepted a non-alphanumeric password"
  fi

  zone="$(
    source "$INTEROP_ROOT/scripts/interop/net-zone/fixture.sh" 2>/dev/null
    net_zone_file test.rskrb5 TEST.RSKRB5 10.0.0.2 "88 464 749"
  )" || net_fail "net_zone_file failed"
  local record
  for record in '_kerberos                IN TXT  "TEST.RSKRB5"' \
    '_kerberos._udp           IN SRV  0 0 88 kdc.test.rskrb5.' \
    '_kerberos._tcp           IN SRV  0 0 88 kdc.test.rskrb5.' \
    '_kpasswd._udp            IN SRV  0 0 464 kdc.test.rskrb5.' \
    '_kpasswd._tcp            IN SRV  0 0 464 kdc.test.rskrb5.' \
    '_kerberos-adm._tcp       IN SRV  0 0 749 kdc.test.rskrb5.' \
    '_kerberos                IN URI  10 1 "krb5srv:m:udp:kdc.test.rskrb5:88"' \
    '_kerberos                IN URI  20 1 "krb5srv::tcp:kdc.test.rskrb5:88"' \
    '_kerberos._udp.lab1._sites IN SRV  0 0 88 kdc-lab1.test.rskrb5.' \
    '_kerberos.lab1._sites      IN URI  10 1 "krb5srv:m:udp:kdc-lab1.test.rskrb5:88"' \
    'kdc                      IN A    10.0.0.2'; do
    [[ "$zone" == *"$record"* ]] || net_fail "the zone lacks: $record"
  done
  if (source "$INTEROP_ROOT/scripts/interop/net-zone/fixture.sh" 2>/dev/null &&
    net_zone_file test.rskrb5 OTHER.RSKRB5 10.0.0.2 "88 464 749" >/dev/null 2>&1); then
    net_fail "net_zone_file accepted a zone that does not match its realm"
  fi

  # Docker prints "invalid IP" for a network without IPv6 (probe run 44305937659).
  for a in "invalid IP" "<no value>" "" "fd00:89::5"; do
    b="$(
      interop_rt() { printf '%s' "$a"; }
      net_container_ipv6 rskrb5-interop-mit-kdc
    )"
    if [[ "$a" == fd00:89::5 ]]; then
      [[ "$b" == "$a" ]] || net_fail "net_container_ipv6 dropped the address $a"
    else
      [[ -z "$b" ]] || net_fail "net_container_ipv6 turned '$a' into an address: $b"
    fi
  done

  local INTEROP_STATE_DIR="$scratch/net-state"
  mkdir -p "$INTEROP_STATE_DIR/fx"
  printf 'Storing x in KCM:0\nkey aes256-cts/1A2B used\n' >"$scratch/net.log"
  out="$(net_expect fx good "$scratch/net.log" "Storing x in KCM:" 2>&1)" || net_fail "net_expect failed on a present line: $out"
  out="$(net_expect fx bad "$scratch/net.log" "Received creds" 2>&1)" && net_fail "net_expect passed on a missing line"
  [[ "$out" == *"fixture fx self-check bad failed"* ]] || net_fail "net_expect did not name the fixture: $out"
  out="$(net_refuse fx refused "$scratch/net.log" "Storing x" 2>&1)" && net_fail "net_refuse passed on a present line"
  [[ "$out" == *"fixture fx self-check refused failed"* ]] || net_fail "net_refuse did not name the fixture: $out"
  [[ "$(net_mask_trace <"$scratch/net.log")" != *1A2B* ]] || net_fail "net_mask_trace left a key hash"
  [[ "$(cat "$INTEROP_STATE_DIR/fx/selfcheck.txt")" == "good: Storing x in KCM:0" ]] ||
    net_fail "the self-check summary does not hold exactly the matched line"
  unset -f net_fail
  ((failures == 0))
}
