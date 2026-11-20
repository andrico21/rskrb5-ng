# shellcheck shell=bash
# Shared definitions of the Samba AD DC fixture scripts (entrypoint.sh,
# setup-*.sh, trust.sh, selfcheck.sh), sourced inside the container. The
# constants are read by the scripts that source this file (SC2034).
# shellcheck disable=SC2034

readonly RUN_DIR="${INTEROP_RUN_DIR:-/run/interop}"
readonly SECRETS="$RUN_DIR/secrets"
readonly READY="$RUN_DIR/ready"
readonly OUT="$RUN_DIR/out"
readonly ACCOUNT_TOOL=/opt/interop/samba/account.py

case "${SAMBA_ROLE:-}" in
  user)
    readonly REALM=USER.RSKRB5 NETBIOS=USER DC_NAME=dcuser ROLE_UPPER=USER FUNCTION_LEVEL=2016
    ;;
  res)
    readonly REALM=RES.RSKRB5 NETBIOS=RES DC_NAME=dcres ROLE_UPPER=RES FUNCTION_LEVEL=2016
    ;;
  *)
    printf 'interop[samba]: FAILED: SAMBA_ROLE must be user or res, not "%s"\n' "${SAMBA_ROLE:-}" >&2
    exit 1
    ;;
esac
readonly DNS_DOMAIN="${REALM,,}"
readonly FIXTURE="samba-$SAMBA_ROLE"

log() {
  printf 'interop[%s]: %s\n' "$FIXTURE" "$*" >&2
}

fail() {
  log "FAILED: $*"
  exit 1
}

LOADED_SECRETS=()

# Exports each NAME=value line; names and values are validated, never evaluated.
# The names are kept so that scrub can hide the values (Y1-01).
load_secrets() {
  local name value
  [[ -f "$SECRETS" ]] || fail "no secrets in $SECRETS"
  while IFS='=' read -r name value; do
    [[ "$name" =~ ^INTEROP_[A-Z0-9_]+$ ]] || fail "malformed secret name in $SECRETS"
    [[ "$value" =~ ^[A-Za-z0-9]+$ ]] || fail "secret $name has characters outside [A-Za-z0-9]"
    printf -v "$name" '%s' "$value"
    export "${name?}"
    LOADED_SECRETS+=("$name")
  done <"$SECRETS"
}

# scrub: copies stdin to stdout with every loaded secret replaced by <redacted>.
scrub() {
  local line name
  while IFS= read -r line || [[ -n "$line" ]]; do
    for name in ${LOADED_SECRETS[@]+"${LOADED_SECRETS[@]}"}; do
      line="${line//"${!name}"/<redacted>}"
    done
    printf '%s\n' "$line"
  done
}

# tail_scrubbed LINES FILE: the last LINES of FILE on stderr, scrubbed.
tail_scrubbed() {
  tail -n "$1" "$2" | scrub >&2
}

tcp_open() {
  (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

# Runs a command whose output may echo a secret: the output stays in a tmpfs
# file and only its scrubbed tail is shown when the command fails.
quiet() {
  local log="$RUN_DIR/step.log"
  if ! "$@" >"$log" 2>&1; then
    tail_scrubbed 15 "$log"
    fail "step failed: $1 $2"
  fi
}

# create_user NAME PASSWORD_VARIABLE [ATTRIBUTE=VALUE...]: a user whose
# password is read from the environment by account.py (never from argv).
create_user() {
  quiet python3 "$ACCOUNT_TOOL" create "$@"
}

# add_spn ACCOUNT SPN...
add_spn() {
  local account="$1" spn
  shift
  for spn in "$@"; do
    quiet samba-tool spn add "$spn" "$account"
  done
}

# export_keytab FILE PRINCIPAL: every key of PRINCIPAL into $OUT/FILE.
export_keytab() {
  rm -f "$OUT/$1"
  quiet samba-tool domain exportkeytab "$OUT/$1" --principal="$2"
  chmod 600 "$OUT/$1"
}
