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

  rm -rf "$scratch"
  if ((failures != 0)); then
    return 1
  fi
  echo "self-test: ok"
}
