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

  # 5. Lane 1D-b network fixtures (scripts/interop/net-*/).
  interop_self_test_net "$scratch" || failures=$((failures + 1))

  rm -rf "$scratch"
  if ((failures != 0)); then
    return 1
  fi
  echo "self-test: ok"
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
