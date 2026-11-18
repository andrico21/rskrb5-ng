# shellcheck shell=bash
# Container-side helpers of the lane 1D-a fixture self-checks (FAST, SPAKE,
# OTP, PKINIT, anonymous). Sourced by preauth/selfcheck/NN-*.sh, which
# fixture.sh runs with `<runtime> exec`. A self-check proves a mechanism with
# the MIT reference tools: it runs kinit/kvno with KRB5_TRACE, and asserts on
# the mechanism lines of the trace and of the KDC log, not on an exit code
# alone. Every PASS line names the assertion and quotes the evidence line;
# no secret is ever printed (trace lines carry key checksums at most).
#
#   SC_NAME  check name for the messages (default: selfcheck)
#   SC_DIR   scratch directory on tmpfs (default /run/interop/selfcheck)
#   SC_KDC_LOG the KDC log (default /var/log/krb5/krb5kdc.log)

SC_NAME="${SC_NAME:-selfcheck}"
SC_DIR="${SC_DIR:-/run/interop/selfcheck}"
SC_KDC_LOG="${SC_KDC_LOG:-/var/log/krb5/krb5kdc.log}"
SC_RC=0
SC_LOG_MARK=0

sc_say() {
  printf 'selfcheck[%s]: %s\n' "$SC_NAME" "$*"
}

sc_fail() {
  printf 'selfcheck[%s]: FAIL %s\n' "$SC_NAME" "$*" >&2
  return 1
}

sc_prepare() {
  (umask 077 && mkdir -p "$SC_DIR")
}

# sc_load_secrets: exports the validated NAME=value lines of the secrets file
# delivered by run.sh (never evaluated).
sc_load_secrets() {
  local name value
  while IFS='=' read -r name value; do
    [[ "$name" =~ ^INTEROP_[A-Z0-9_]+$ && "$value" =~ ^[A-Za-z0-9]+$ ]] ||
      sc_fail "malformed secrets file line" || return 1
    printf -v "$name" '%s' "$value"
    export "${name?}"
  done <"${SC_SECRETS:-/run/interop/secrets}"
}

# sc_run LABEL COMMAND...: runs COMMAND with KRB5_TRACE, stdout and stderr in
# $SC_DIR/LABEL.{trace,out}, stdin inherited; the exit status goes to SC_RC.
sc_run() {
  local label="$1"
  shift
  : >"$SC_DIR/$label.trace"
  : >"$SC_DIR/$label.out"
  if KRB5_TRACE="$SC_DIR/$label.trace" "$@" >"$SC_DIR/$label.out" 2>&1; then
    SC_RC=0
  else
    SC_RC=$?
  fi
}

# sc_expect_rc LABEL zero|nonzero DESCRIPTION
sc_expect_rc() {
  local label="$1" want="$2" what="$3"
  case "$want" in
    zero) [[ "$SC_RC" -eq 0 ]] || sc_fail "$what: $label exited $SC_RC, expected 0: $(head -c 300 "$SC_DIR/$label.out")" || return 1 ;;
    nonzero) [[ "$SC_RC" -ne 0 ]] || sc_fail "$what: $label exited 0, expected a failure" || return 1 ;;
    *) sc_fail "sc_expect_rc: unknown expectation '$want'" || return 1 ;;
  esac
  sc_say "PASS $what: $label exit $SC_RC"
}

# sc_expect_file LABEL SUFFIX REGEX DESCRIPTION: an ERE must match a line of
# $SC_DIR/LABEL.SUFFIX (trace or out); the first match is quoted.
sc_expect_file() {
  local label="$1" suffix="$2" regex="$3" what="$4" line
  line="$(grep -E -m1 -- "$regex" "$SC_DIR/$label.$suffix" || true)"
  [[ -n "$line" ]] || sc_fail "$what: no line matching /$regex/ in $label.$suffix" || return 1
  sc_say "PASS $what: ${line:0:180}"
}

sc_expect_trace() { sc_expect_file "$1" trace "$2" "$3"; }
sc_expect_out() { sc_expect_file "$1" out "$2" "$3"; }

# sc_expect_no_trace LABEL REGEX DESCRIPTION: the trace must NOT match.
sc_expect_no_trace() {
  local label="$1" regex="$2" what="$3" line
  line="$(grep -E -m1 -- "$regex" "$SC_DIR/$label.trace" || true)"
  [[ -z "$line" ]] || sc_fail "$what: unexpected trace line: ${line:0:180}" || return 1
  sc_say "PASS $what: no /$regex/ line in the trace of $label"
}

# sc_log_mark / sc_expect_kdc_log REGEX DESCRIPTION: assertions on the KDC
# log lines written after the mark.
sc_log_mark() {
  SC_LOG_MARK="$(wc -l <"$SC_KDC_LOG")"
}

sc_expect_kdc_log() {
  local regex="$1" what="$2" line
  line="$(tail -n "+$((SC_LOG_MARK + 1))" "$SC_KDC_LOG" | grep -E -m1 -- "$regex" || true)"
  [[ -n "$line" ]] || sc_fail "$what: no new KDC log line matching /$regex/" || return 1
  line="${line#*krb5kdc}"
  sc_say "PASS $what: ${line:0:240}"
}

# sc_armor_tgt LABEL: a normal TGT of testuser1 (from its exported keytab) in
# $SC_DIR/LABEL.cc, the FAST armor ccache of the checks.
sc_armor_tgt() {
  sc_run "$1" kinit -k -t /run/interop/out/testuser1.keytab -c "FILE:$SC_DIR/$1.cc" testuser1
  sc_expect_rc "$1" zero "armor TGT of testuser1 (normal password-less keytab login)"
}

# sc_conf NAME: writes the profile fragment read from stdin to
# $SC_DIR/NAME.conf. A check adds it to the container profile with
# KRB5_CONFIG=/etc/krb5.conf:$SC_DIR/NAME.conf (new sections and plugin
# switches) or KRB5_CONFIG=$SC_DIR/NAME.conf:/etc/krb5.conf (a relation that
# must override: the first file wins).
sc_conf() {
  cat >"$SC_DIR/$1.conf"
}
