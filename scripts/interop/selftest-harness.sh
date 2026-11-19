# shellcheck shell=bash
# Sourced by selftest.sh: the INTEROP_* globals the stubs set are read by the
# lib.sh/run.sh functions they replace (SC2034), the stubs are invoked
# indirectly (SC2317), INTEROP_ROOT comes from run.sh (SC2153) and the `bash -c`
# scripts are single-quoted on purpose (SC2016).
# shellcheck disable=SC2016,SC2034,SC2153,SC2317
# Cases of `run.sh self-test` for the harness itself (plan 2 todo 34):
# the redaction that fails closed (Y1-01); the liveness check of every fixture at the end of `all` (Y1-05); run namespaces and host-port offsets (FU-IOP-P01); the corporate-CA build hook (FU-IOP-P02).
# No container, network or image is touched. Each group runs in a subshell and prints one line per failed check.

# Y1-01: a missing or unusable secret inventory refuses the log upload.
interop_self_test_redaction() {
  local scratch="$1/redaction" marker out state dest
  mkdir -p "$scratch"
  bad() { printf 'redaction: %s\n' "$*"; }
  marker="Y1Marker$(interop_new_secret)"
  export ST_MARKER="$marker"
  local redact="$INTEROP_ROOT/scripts/interop/redact.sh"

  # The supervisor's probe: no inventory file at all.
  if out="$(printf 'INTEROP_SAMBA_USER_ADMIN_PASSWORD=%s\n' "$marker" | "$redact" --stdin "$scratch/missing.env" 2>/dev/null)"; then
    bad "redact.sh --stdin exited 0 without an inventory"
  fi
  [[ "$out" != *"$marker"* ]] || bad "redact.sh --stdin printed the marker without an inventory"
  printf 'kadmin: password %s\n' "$marker" >"$scratch/file.log"
  if "$redact" "$scratch/missing.env" "$scratch/file.log" 2>/dev/null; then
    bad "redact.sh FILE exited 0 without an inventory"
  fi

  # A log collection with stubbed container logs that all carry the marker.
  collect() {
    (
      INTEROP_STATE_DIR="$1"
      INTEROP_RT=stub
      INTEROP_FIXTURES=()
      interop_rt() {
        case "$1" in
          ps) printf 'c1\n' ;;
          logs) printf 'provisioning failed: password %s rejected\n' "$ST_MARKER" ;;
        esac
      }
      collect_logs "$2"
    ) >/dev/null 2>&1
  }

  # Provisioning failed after a secret was recorded and before the env file
  # was written: the inventory alone redacts, and the secret is in it.
  state="$scratch/after-secret" dest="$scratch/after-secret-dest"
  (
    INTEROP_STATE_DIR="$state"
    interop_prepare_private_dir "$state"
    INTEROP_ENV_NAMES=()
    interop_inventory_init "$state/secrets.inventory"
    interop_env INTEROP_ADMIN_PASSWORD "$marker"
    generated="$(interop_new_secret)"
    [[ "$(interop_secret_values "$state/secrets.inventory")" == *"$generated"* ]] ||
      bad "a secret drawn by interop_new_secret is not in the inventory"
  ) || bad "recording the inventory failed"
  [[ "$(interop_secret_values "$state/secrets.inventory" 2>/dev/null)" == *"$marker"* ]] ||
    bad "interop_env did not put a secret into the inventory"
  [[ ! -e "$state/interop.env" ]] || bad "the case wrote an env file"
  collect "$state" "$dest" || bad "collect_logs refused although the inventory exists"
  ! grep -rqF -- "$marker" "$dest" 2>/dev/null || bad "the marker reached the upload directory unredacted"
  grep -rqF '<redacted>' "$dest" 2>/dev/null || bad "the upload directory holds no redacted log"

  # No inventory: nothing may be uploaded but the refusal note.
  state="$scratch/no-inventory" dest="$scratch/no-inventory-dest"
  interop_prepare_private_dir "$state"
  if collect "$state" "$dest"; then
    bad "collect_logs succeeded without an inventory"
  fi
  ! grep -rqF -- "$marker" "$dest" 2>/dev/null || bad "the marker reached the upload directory without an inventory"
  [[ -f "$dest/LOG-UPLOAD-REFUSED.txt" ]] || bad "no refusal note in the upload directory"
  [[ "$(find "$dest" -type f | wc -l)" -eq 1 ]] || bad "the upload directory holds more than the refusal note"

  # An inventory that cannot be read as a secret list: redaction fails, so does the upload.
  state="$scratch/broken-inventory" dest="$scratch/broken-inventory-dest"
  interop_prepare_private_dir "$state"
  printf "export INTEROP_INVENTORY_1_SECRET='unterminated\n" >"$state/secrets.inventory"
  chmod 600 "$state/secrets.inventory"
  if collect "$state" "$dest"; then
    bad "collect_logs succeeded with a broken inventory"
  fi
  ! grep -rqF -- "$marker" "$dest" 2>/dev/null || bad "the marker reached the upload directory with a broken inventory"

  # The Samba container scripts scrub what they print on a failed step.
  mkdir -p "$scratch/run"
  out="$(
    export SAMBA_ROLE=user INTEROP_RUN_DIR="$scratch/run"
    # shellcheck disable=SC1091
    source "$INTEROP_ROOT/scripts/interop/samba/lib-dc.sh"
    printf 'INTEROP_SAMBA_USER_ADMIN_PASSWORD=%s\n' "$marker" >"$SECRETS"
    load_secrets
    quiet sh -c 'echo "samba-tool said: bad password $INTEROP_SAMBA_USER_ADMIN_PASSWORD"; exit 1' 2>&1
  )" || true
  [[ "$out" != *"$marker"* ]] || bad "lib-dc.sh printed a secret on a failed step"
  [[ "$out" == *"samba-tool said: bad password <redacted>"* ]] || bad "lib-dc.sh did not show the scrubbed tail"
}

# FU-IOP-P01: a namespace scopes every name; host ports move by an offset.
interop_self_test_namespace() {
  local scratch="$1/namespace" out calls
  mkdir -p "$scratch"
  calls="$scratch/calls"
  bad() { printf 'namespace: %s\n' "$*"; }
  probe() {
    # probe NAMESPACE: prints the derived names (or fails to source lib.sh).
    env -u INTEROP_PORT_OFFSET INTEROP_NAMESPACE="$1" bash -c \
      'source "$1/scripts/interop/lib.sh" && printf "%s|%s|%s" "$INTEROP_NETWORK" "$INTEROP_LABEL" "$(interop_container_name mit-kdc)"' \
      _ "$INTEROP_ROOT" 2>/dev/null
  }
  [[ "$(probe "")" == "rskrb5-interop|rskrb5-interop|rskrb5-interop-mit-kdc" ]] ||
    bad "the default names changed: $(probe "")"
  out="$(probe abc2)"
  [[ "$out" == "rskrb5-interop--abc2|rskrb5-interop--abc2|rskrb5-interop--abc2-mit-kdc" ]] ||
    bad "namespace abc2 gave '$out'"
  for out in Bad a-b 1x abcdefghijklmnopq 'a b'; do
    if probe "$out" >/dev/null; then
      bad "the namespace '$out' was accepted"
    fi
  done

  # up and down of a namespace only look at, create and remove its own labelled resources.
  : >"$calls"
  env INTEROP_NAMESPACE=abc2 CALLS="$calls" bash -c '
    source "$1/scripts/interop/lib.sh"
    INTEROP_RT=stub
    interop_rt() { printf "%s\n" "$*" >>"$CALLS"; }
    interop_remove_all >/dev/null 2>&1
    interop_create_network
    interop_run_container mit-kdc image:tag
  ' _ "$INTEROP_ROOT" || bad "the namespaced stub run failed"
  grep -q -- '--filter label=rskrb5-interop--abc2$' "$calls" || bad "remove_all did not filter on the namespace label"
  ! grep -- '--filter' "$calls" | grep -qv -- '--filter label=rskrb5-interop--abc2$' ||
    bad "remove_all filtered on another label: $(grep -- '--filter' "$calls" | tr '\n' '|')"
  grep -q -- 'network create --label rskrb5-interop--abc2=1 rskrb5-interop--abc2' "$calls" ||
    bad "the network and its label are not namespaced"
  grep -q -- 'run -d --name rskrb5-interop--abc2-mit-kdc --label rskrb5-interop--abc2=1 --network rskrb5-interop--abc2 ' "$calls" ||
    bad "the container name, label and network are not namespaced: $(grep -- 'run -d' "$calls")"

  # Ports: explicit variable, default, offset, and refusals.
  port() {
    # port OFFSET VARIABLE-VALUE: INTEROP_T_PORT=<value> interop_port INTEROP_T_PORT 18088
    env INTEROP_PORT_OFFSET="$1" INTEROP_T_PORT="$2" bash -c \
      'source "$1/scripts/interop/lib.sh" && interop_port INTEROP_T_PORT 18088' _ "$INTEROP_ROOT" 2>/dev/null
  }
  [[ "$(port 0 "")" == 18088 ]] || bad "the default port moved without an offset: $(port 0 "")"
  [[ "$(port 100 "")" == 18188 ]] || bad "the offset was not added: $(port 100 "")"
  [[ "$(port 100 20000)" == 20000 ]] || bad "an explicit port lost against the offset"
  if port 60000 "" >/dev/null; then bad "a port above 65535 was accepted"; fi
  if port abc "" >/dev/null; then bad "a non-numeric offset was accepted"; fi
  if port 0 "x1" >/dev/null; then bad "a non-numeric explicit port was accepted"; fi
  # A fixture that publishes a default port through a literal skips the offset.
  out="$(grep -n '_PORT:-[0-9]' "$INTEROP_ROOT"/scripts/interop/*/fixture.sh || true)"
  [[ -z "$out" ]] || bad "fixtures with a literal default port (use interop_port): $out"
}

# FU-IOP-P02: the corporate-CA build hook is off by default and podman only.
interop_self_test_build_hook() {
  local scratch="$1/buildhook" calls cas
  mkdir -p "$scratch/ctx" "$scratch/cas"
  printf 'FROM scratch\n' >"$scratch/ctx/Dockerfile"
  calls="$scratch/calls"
  cas="$scratch/cas"
  bad() { printf 'build hook: %s\n' "$*"; }
  build() {
    # build RUNTIME [VARIABLE=VALUE...]: runs interop_build_image against a stubbed runtime.
    local runtime="$1"
    shift
    : >"$calls"
    env "$@" RUNTIME="$runtime" CALLS="$calls" CTX="$scratch/ctx" bash -c '
      source "$1/scripts/interop/lib.sh"
      INTEROP_RT="$RUNTIME"
      interop_rt() {
        printf "%s\n" "$*" >>"$CALLS"
        if [[ "$1 $2" == "image inspect" ]]; then
          [[ "$3" == -f ]] && { printf 42; return 0; }
          return 1
        fi
      }
      interop_build_image hook "$CTX"
    ' _ "$INTEROP_ROOT" >/dev/null 2>&1
  }
  build podman || bad "the default build failed"
  grep -qE '^build -t rskrb5-interop/hook:[0-9a-f]{12} ' "$calls" || bad "the default build line changed: $(grep '^build' "$calls")"
  ! grep -q -- '--volume' "$calls" || bad "the hook is not off by default"
  build podman "INTEROP_BUILD_CA_DIR=$cas" || bad "the podman build with a CA directory failed"
  grep -qE "^build --volume $cas:/usr/local/share/ca-certificates:ro -t rskrb5-interop/hook:[0-9a-f]{12} " "$calls" ||
    bad "the CA directory is not mounted read-only for the build: $(grep '^build' "$calls")"
  if build docker "INTEROP_BUILD_CA_DIR=$cas"; then bad "docker accepted INTEROP_BUILD_CA_DIR"; fi
  ! grep -q '^build' "$calls" || bad "docker ran a build with INTEROP_BUILD_CA_DIR"
  if build podman "INTEROP_BUILD_CA_DIR=$scratch/absent"; then bad "a missing CA directory was accepted"; fi
  ! grep -q '^build' "$calls" || bad "a build ran with a missing CA directory"
}

# Y1-05: every registered fixture, and every labelled container, must still run
# when `all` is about to report success.
interop_self_test_liveness() {
  local out state
  bad() { printf 'liveness: %s\n' "$*"; }
  INTEROP_RT=stub
  INTEROP_FIXTURES=(alpha beta)
  INTEROP_SUITE_NAMES=(one)
  declare -A states=()
  interop_rt() {
    case "$1" in
      ps) printf '%s\n' "${!states[@]}" ;;
      inspect)
        [[ -n "${states[${*: -1}]:-}" ]] || return 1
        printf '%s' "${states[${*: -1}]}"
        ;;
    esac
  }
  cmd_up() { :; }
  cmd_test() { :; }
  cmd_down() { :; }
  states=([rskrb5-interop-alpha]=running [rskrb5-interop-beta]=running [rskrb5-interop-beta-iso]=running)
  out="$( (cmd_all) 2>&1)" || bad "all failed with every container running: $out"
  [[ "$out" == *"all suites passed"* ]] || bad "all did not report success with every container running"
  for state in exited missing; do
    case "$state" in
      exited) states=([rskrb5-interop-alpha]=running [rskrb5-interop-beta]=exited [rskrb5-interop-beta-iso]=running) ;;
      missing) states=([rskrb5-interop-alpha]=running [rskrb5-interop-beta-iso]=running) ;;
    esac
    out="$( (cmd_all) 2>&1)" && bad "all passed with the beta fixture $state"
    [[ "$out" != *"all suites passed"* ]] || bad "all reported success with the beta fixture $state"
    [[ "$out" == *"fixture beta"* ]] || bad "the failure with beta $state did not name the fixture: $out"
  done
  states=([rskrb5-interop-alpha]=running [rskrb5-interop-beta]=running [rskrb5-interop-beta-iso]=exited)
  out="$( (cmd_all) 2>&1)" && bad "all passed with a stopped labelled container"
  [[ "$out" == *"rskrb5-interop-beta-iso"* ]] || bad "the failure did not name the stopped container: $out"
}

# Runs the groups above; $1 is the failure reporter of interop_self_test, $2 its scratch directory.
interop_self_test_harness_groups() {
  local report="$1" group out
  for group in redaction liveness namespace build_hook; do
    out="$("interop_self_test_$group" "$2" 2>&1)" || true
    [[ -z "$out" ]] || "$report" "harness $group:"$'\n'"$out"
  done
}
