#!/usr/bin/env bash
# Redacts the run's secrets from fixture logs before they are printed or
# uploaded as an artifact. The secrets are the non-empty values of the
# env-file keys ending in _PASSWORD, _SECRET or _TOKEN (scripts/interop/lib.sh).
#
#   redact.sh ENV_FILE FILE...   rewrite each FILE in place
#   redact.sh --stdin ENV_FILE   filter stdin to stdout
#   redact.sh --self-test        check the redaction on a marker secret
# ENV_FILE is the env file or the secret inventory (scripts/interop/lib.sh); a
# missing or unusable one is an error (exit 1, nothing written or printed).
set -euo pipefail

INTEROP_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/interop/lib.sh
source "$INTEROP_ROOT/scripts/interop/lib.sh"

# load_secrets ENV_FILE: reads the secret values; fails (so nothing is
# redacted or printed) when the file is missing or unusable (Y1-01).
load_secrets() {
  local value values
  SECRETS=()
  values="$(interop_secret_values "$1")" || return 1
  while IFS= read -r value; do
    [[ -n "$value" ]] && SECRETS+=("$value")
  done <<<"$values"
}

redact_files() {
  local env_file="$1" file staged
  shift
  load_secrets "$env_file" || return 1
  for file in "$@"; do
    staged="$(mktemp "$file.redact.XXXXXX")"
    interop_redact_stream "${SECRETS[@]}" <"$file" >"$staged"
    mv -f "$staged" "$file"
  done
}

self_test() {
  local scratch failures=0 marker other filtered
  scratch="$(mktemp -d "${TMPDIR:-/tmp}/rskrb5-interop-redact.XXXXXX")"
  marker="MarkerSecret$(interop_new_secret)"
  other="MarkerToken$(interop_new_secret)"
  INTEROP_ENV_NAMES=()
  interop_env INTEROP_SELFTEST_PASSWORD "$marker"
  interop_env INTEROP_SELFTEST_TOKEN "$other"
  interop_env INTEROP_SELFTEST_KDC "127.0.0.1:18088"
  interop_write_env "$scratch/state/interop.env"
  printf 'kadmin: password %s accepted\n%s\nkdc 127.0.0.1:18088 token=%s%s\nlast line %s' \
    "$marker" "$marker" "$other" "$marker" "$marker" >"$scratch/fixture.log"
  "$0" "$scratch/state/interop.env" "$scratch/fixture.log"
  if grep -qF -e "$marker" -e "$other" "$scratch/fixture.log"; then
    echo "redact self-test FAIL: a marker secret survived in place" >&2
    failures=$((failures + 1))
  fi
  [[ "$(grep -c '<redacted>' "$scratch/fixture.log")" -eq 4 ]] || {
    echo "redact self-test FAIL: expected 4 redacted lines" >&2
    failures=$((failures + 1))
  }
  grep -qF '127.0.0.1:18088' "$scratch/fixture.log" || {
    echo "redact self-test FAIL: a non-secret value was removed" >&2
    failures=$((failures + 1))
  }
  filtered="$(printf 'x%sy\n' "$marker" | "$0" --stdin "$scratch/state/interop.env")"
  [[ "$filtered" == "x<redacted>y" ]] || {
    echo "redact self-test FAIL: --stdin did not redact" >&2
    failures=$((failures + 1))
  }
  rm -rf "$scratch"
  ((failures == 0)) || return 1
  echo "redact self-test: ok"
}

main() {
  case "${1:-}" in
    --self-test) self_test ;;
    --stdin)
      [[ $# -eq 2 ]] || { echo "usage: redact.sh --stdin ENV_FILE" >&2; exit 2; }
      load_secrets "$2" || exit 1
      interop_redact_stream "${SECRETS[@]}"
      ;;
    "" | -h | --help)
      sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
      ;;
    *)
      [[ $# -ge 2 ]] || { echo "usage: redact.sh ENV_FILE FILE..." >&2; exit 2; }
      redact_files "$@"
      ;;
  esac
}

main "$@"
