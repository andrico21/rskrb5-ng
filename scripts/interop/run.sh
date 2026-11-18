#!/usr/bin/env bash
# Live interoperability fixtures and suites (plan 2 todo 1). See usage below
# and the layout contract at the top of scripts/interop/lib.sh.
set -euo pipefail

INTEROP_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
INTEROP_STATE_DIR="${INTEROP_STATE_DIR:-"$INTEROP_ROOT/target/interop"}"
INTEROP_ENV_FILE="$INTEROP_STATE_DIR/interop.env"
# shellcheck source=scripts/interop/lib.sh
source "$INTEROP_ROOT/scripts/interop/lib.sh"

usage() {
  cat <<'EOF'
Usage: scripts/interop/run.sh <command>

Commands:
  up            Build (once per context hash) and start every fixture, then
                write the private env file $INTEROP_STATE_DIR/interop.env.
  down          Collect redacted logs (when INTEROP_LOG_DIR is set), remove
                every labelled container, network and volume, delete the state
                directory and print a cleanup receipt.
  test <suite>  Source the env file and run the suite's Rust tests:
                cargo test --all-features --locked --test <target>
                  -- --nocapture --test-threads=1
  all           INTEROP=1 INTEROP_REQUIRED=1: up, every suite, down (down also
                runs on failure). Exit 0 only when every suite passed.
  env           Print the env file with secrets replaced by <redacted>.
  suites        Print `<suite> <test target> <fixtures>` per registered suite.
  self-test     Check the env file, redaction and required-mode handling
                without containers.

Environment:
  INTEROP=1             Enables the interop tests (set by `test` and `all`).
  INTEROP_REQUIRED=1    An unreachable fixture fails the test, naming the
                        fixture (implies INTEGRATION_REQUIRED=1); unset, tests
                        skip with a visible `interop: SKIP` reason.
  INTEROP_RUNTIME       docker | podman (default: docker if its daemon answers,
                        else podman). Plain run/exec, user-defined network, no
                        compose, no privileged containers.
  INTEROP_STATE_DIR     Private per-run directory (default target/interop):
                        env file, keytabs and caches, mode 0700/0600.
  INTEROP_LOG_DIR       Where `down` puts redacted fixture logs.
  INTEROP_READY_TIMEOUT Readiness bound per fixture in seconds (default 180).
  INTEROP_MIT_KDC_PORT, INTEROP_MIT_KPASSWD_PORT, INTEROP_MIT_KADMIN_PORT
                        Host ports of the MIT fixture (18088, 18464, 18749).

Contract for later lanes (full text: scripts/interop/lib.sh):
  fixture   scripts/interop/<dir>/{Dockerfile,fixture.sh}; fixture.sh calls
            `interop_fixture <name>` and defines fixture_<id>_up (and
            optionally fixture_<id>_logs); container rskrb5-interop-<name> on
            network rskrb5-interop, label rskrb5-interop=1.
  readiness the container writes /run/interop/ready; fixture_<id>_up calls
            interop_wait_ready <name> (bounded, names the fixture on failure).
  env keys  interop_env INTEROP_<FIXTURE>_<WHAT> <value>; *_PASSWORD,
            *_SECRET and *_TOKEN keys are secrets (redacted everywhere).
  suite     `interop_suite <suite> interop_<topic> <fixture>...` and
            tests/interop_<topic>.rs using tests/interop/harness.rs.
  scenarios scripts/interop/scenarios/<todo>/ holds a todo's data files.
  required  `interop: ERROR`/test failure text names the fixture, its endpoint
            and its container; `test` then prints every suite fixture's state.
EOF
}

load_fixtures() {
  local file
  for file in "$INTEROP_ROOT"/scripts/interop/*/fixture.sh; do
    [[ -e "$file" ]] || continue
    # shellcheck disable=SC1090
    source "$file"
  done
}

cmd_up() {
  interop_detect_runtime
  interop_remove_all >/dev/null 2>&1 || true
  rm -rf "$INTEROP_STATE_DIR"
  interop_prepare_private_dir "$INTEROP_STATE_DIR"
  INTEROP_ENV_NAMES=()
  interop_env INTEROP 1
  interop_env INTEROP_RUNTIME "$INTEROP_RT"
  interop_env INTEROP_STATE_DIR "$INTEROP_STATE_DIR"
  interop_create_network
  local fixture id
  for fixture in "${INTEROP_FIXTURES[@]}"; do
    id="$(interop_fixture_id "$fixture")"
    interop_log "starting fixture $fixture"
    "fixture_${id}_up" || interop_die "fixture $fixture failed to start" || return 1
  done
  interop_write_env "$INTEROP_ENV_FILE"
  interop_log "env file written to $INTEROP_ENV_FILE"
  interop_print_env "$INTEROP_ENV_FILE" >&2
}

collect_logs() {
  local dest="$1" container fixture id raw
  raw="$INTEROP_STATE_DIR/raw-logs"
  interop_prepare_private_dir "$raw" || return 1
  for container in $(interop_rt ps -a --filter "label=$INTEROP_LABEL" --format '{{.Names}}' 2>/dev/null); do
    interop_rt logs "$container" >"$raw/$container.log" 2>&1 || true
  done
  for fixture in "${INTEROP_FIXTURES[@]}"; do
    id="$(interop_fixture_id "$fixture")"
    if declare -F "fixture_${id}_logs" >/dev/null; then
      "fixture_${id}_logs" "$raw" || true
    fi
  done
  mkdir -p "$dest"
  local file
  for file in "$raw"/*; do
    [[ -f "$file" ]] || continue
    "$INTEROP_ROOT/scripts/interop/redact.sh" "$INTEROP_ENV_FILE" "$file"
    cp "$file" "$dest/"
  done
  interop_log "redacted fixture logs in $dest"
}

cmd_down() {
  interop_detect_runtime
  if [[ -n "${INTEROP_LOG_DIR:-}" ]]; then
    collect_logs "$INTEROP_LOG_DIR" || interop_log "log collection failed"
  fi
  local status=0
  interop_remove_all || status=1
  rm -rf "$INTEROP_STATE_DIR"
  interop_log "cleanup receipt: state directory $INTEROP_STATE_DIR removed"
  return "$status"
}

# Counts the occurrences of a fixed string in a log, 0 when absent. libtest
# prints a scenario's stderr on the line of its `test <name> ...` header, so
# the markers are counted anywhere in a line.
count_marks() {
  { grep -oF -- "$1" "$2" || true; } | wc -l
}

cmd_test() {
  local suite="${1:-}" index target fixtures log listed ran skipped status=0
  [[ -n "$suite" ]] || interop_die "usage: run.sh test <suite>" || return 2
  index="$(interop_suite_index "$suite")" || return 2
  target="${INTEROP_SUITE_TARGETS[index]}"
  fixtures="${INTEROP_SUITE_FIXTURES[index]}"
  [[ -f "$INTEROP_ENV_FILE" ]] || interop_die "missing $INTEROP_ENV_FILE; run 'scripts/interop/run.sh up' first" || return 1
  # shellcheck disable=SC1090
  source "$INTEROP_ENV_FILE"
  export INTEROP=1
  if [[ "${INTEROP_REQUIRED:-}" == 1 ]]; then
    export INTEROP_REQUIRED=1 INTEGRATION_REQUIRED=1
  fi
  log="$INTEROP_STATE_DIR/test-$suite.log"
  interop_log "suite $suite: cargo test --all-features --locked --test $target"
  cargo test --all-features --locked --test "$target" -- --nocapture --test-threads=1 2>&1 | tee "$log" || status=1
  listed="$(cargo test --all-features --locked --test "$target" -- --list 2>/dev/null | grep -c '^scenarios::.*: test$' || true)"
  ran="$(count_marks 'interop: ran ' "$log")"
  skipped="$(count_marks 'interop: SKIP ' "$log")"
  interop_log "suite $suite: scenarios listed $listed, ran $ran, skipped $skipped"
  if [[ "${INTEROP_REQUIRED:-}" == 1 ]] && ((skipped != 0 || ran != listed || listed == 0)); then
    interop_log "suite $suite: required mode needs every listed scenario to run and none to skip"
    status=1
  fi
  if ((status != 0)); then
    # shellcheck disable=SC2086
    interop_fixture_report $fixtures
    interop_die "suite $suite failed" || return 1
  fi
  interop_log "suite $suite: ok"
}

cmd_all() {
  export INTEROP=1 INTEROP_REQUIRED=1 INTEGRATION_REQUIRED=1
  local status=0 suite
  trap 'cmd_down || status=1' EXIT
  cmd_up || {
    interop_die "up failed"
    exit 1
  }
  for suite in "${INTEROP_SUITE_NAMES[@]}"; do
    (cmd_test "$suite") || status=1
  done
  trap - EXIT
  cmd_down || status=1
  if ((status != 0)); then
    interop_die "interop run failed" || exit 1
  fi
  interop_log "all suites passed"
}

cmd_suites() {
  local index=0
  while ((index < ${#INTEROP_SUITE_NAMES[@]})); do
    printf '%s %s %s\n' "${INTEROP_SUITE_NAMES[index]}" "${INTEROP_SUITE_TARGETS[index]}" "${INTEROP_SUITE_FIXTURES[index]}"
    index=$((index + 1))
  done
}

main() {
  local command="${1:-}"
  case "$command" in
    "" | -h | --help | help) usage ;;
    self-test)
      # shellcheck source=scripts/interop/selftest.sh
      source "$INTEROP_ROOT/scripts/interop/selftest.sh"
      interop_self_test
      ;;
    *)
      load_fixtures
      shift
      case "$command" in
        up) cmd_up ;;
        down) cmd_down ;;
        test) cmd_test "$@" ;;
        all) cmd_all ;;
        env) interop_print_env "$INTEROP_ENV_FILE" ;;
        suites) cmd_suites ;;
        *)
          usage >&2
          exit 2
          ;;
      esac
      ;;
  esac
}

main "$@"
