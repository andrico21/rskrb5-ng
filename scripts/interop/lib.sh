# shellcheck shell=bash
# Shared library of scripts/interop/run.sh. Sourced, never executed.
#
# ============================== LAYOUT CONTRACT ==============================
# Lane 1C (plan 2 todo 1) owns this harness; later lanes (1D advanced MIT
# fixtures, 1E Samba, 1F GSS peer adapter, and every work-package todo that
# adds an interop test) EXTEND it without rewriting it:
#
# Fixtures. A fixture is one container. Its directory scripts/interop/<dir>/
# holds the image build context (Dockerfile) and a host-side `fixture.sh` that
# run.sh sources (every scripts/interop/*/fixture.sh, in path order). A
# fixture.sh registers itself and its suites, and defines functions named
# after the fixture id (fixture name with '-' replaced by '_'):
#     interop_fixture <name>                      e.g. interop_fixture mit-kdc
#     fixture_<id>_up        build/start the container, deliver secrets, wait
#                            until ready, copy keytabs out, record env keys
#     fixture_<id>_logs DIR  optional: copy daemon log files into DIR
#     interop_suite <suite> <cargo test target> <fixture>...
#                                                 e.g. interop_suite mit interop_mit mit-kdc
#   Names: container `rskrb5-interop-<name>` (interop_container_name), on the
#   user-defined network `rskrb5-interop`, labelled `rskrb5-interop=1` (down
#   removes every labelled container, network and volume). All three derive
#   from INTEROP_PREFIX, which INTEROP_NAMESPACE=<ns> turns into
#   `rskrb5-interop--<ns>` (FU-IOP-P01): build every name from INTEROP_PREFIX,
#   INTEROP_NETWORK, INTEROP_LABEL and interop_container_name, never a literal.
#   Host ports: `interop_port VARIABLE DEFAULT` (the variable wins, else the
#   default plus INTEROP_PORT_OFFSET); a literal `${VARIABLE:-1234}` fails the
#   self-test. Images are tagged
#   `rskrb5-interop/<name>:<12 hex of the build context sha256>` (fixture.sh
#   excluded, also through .dockerignore), never latest;
#   base images are pinned by digest in the Dockerfile. Ports are published on
#   127.0.0.1 only. No --privileged; a needed capability is added with
#   --cap-add and documented in the Dockerfile and the fixture.sh.
#   An MIT fixture may instead extend the mit-kdc image: provision.d/NN-*.sh
#   (before the daemons start), started.d/NN-*.sh (after they listen) and
#   profile fragments in /etc/krb5.conf.d/ and /etc/krb5kdc/kdc.conf.d/.
# Secrets. Generated per run on the host (interop_new_secret), delivered into
#   the container's tmpfs /run/interop/secrets (interop_deliver_secrets, NAME=
#   value lines, values [A-Za-z0-9]), never passed as `-e`, never COPY'd. Every
#   secret is appended to the run's secret inventory (interop_inventory_init in
#   `up`, before any secret-bearing step) the moment it is drawn or recorded
#   with `interop_env KEY` under a secret key; log redaction reads the inventory
#   and refuses (no log is copied, LOG-UPLOAD-REFUSED.txt says why) when it is
#   missing or unusable (Y1-01). Container scripts that print tool output
#   scrub it with the secrets they loaded (samba/lib-dc.sh scrub).
# Readiness. The container writes /run/interop/ready when it serves;
#   interop_wait_ready waits for it with a bound (INTEROP_READY_TIMEOUT,
#   default 180 s) and fails naming the fixture and its container, with the
#   redacted container log tail. interop_wait_tcp checks a published port.
# Env file. Every value a test needs is recorded with `interop_env KEY VALUE`.
#   Keys: INTEROP_<FIXTURE ID UPPERCASE>_<WHAT>, e.g. INTEROP_MIT_KDC
#   (host:port), INTEROP_MIT_HTTP_KEYTAB (path). Keys ending in _PASSWORD,
#   _SECRET or _TOKEN are secrets: redacted by `run.sh env`, in logs and in
#   artifacts. The file ($INTEROP_STATE_DIR/interop.env) is written with the
#   FU-GATE-12/13 serialization of scripts/run-gated-integration.sh: private
#   mode-0700 directory (symlinks and foreign owners refused), staged mode-0600
#   file renamed into place, one `export KEY=<printf %q>` line per key, no
#   eval; `run.sh test` sources it. Keytabs and caches copied out of a
#   container are mode-0600 files in $INTEROP_STATE_DIR/<fixture>/.
# Scenarios. Data files for a todo go to scripts/interop/scenarios/<todo>/
#   (e.g. scenarios/todo-07/); a test reads them through its env key or a
#   path relative to the crate root.
# Tests. tests/interop_<topic>.rs, gated by INTEROP=1, includes the shared
#   harness `#[path = "interop/harness.rs"] mod harness;` and starts each
#   scenario with `harness::require(<scenario>, &[harness::Fixture::new(..)])`.
#   It prints `interop: ran <scenario>` or `interop: SKIP <scenario>: <reason>`.
#   With INTEROP_REQUIRED=1 (or INTEGRATION_REQUIRED=1) an unreachable fixture
#   is a test failure whose message names the fixture, its endpoint and its
#   container. Every scenario asserts the negotiated mechanism or protocol
#   (harness::assert_negotiated_* helpers) so a fallback cannot pass.
# Liveness. After the last suite `run.sh all` calls interop_check_alive: every
#   registered fixture's container and every other labelled container must
#   still run, or the run fails naming it (Y1-05).
# Suites. `run.sh test <suite>` runs `cargo test --all-features --locked
#   --test <target> -- --nocapture --test-threads=1` and, in required mode,
#   fails unless every listed `scenarios::` test printed `interop: ran` and
#   none printed SKIP; on failure it prints the state of the suite's fixtures.
# =============================================================================

# Run namespace (FU-IOP-P01). INTEROP_NAMESPACE (default empty) scopes every
# name this run creates: the label key, the network (and the isolated peer
# network), the containers and the check containers all start with
# INTEROP_PREFIX, so `up` and `down` of one namespace never touch the
# resources of another run on the same container runtime. With no namespace
# the prefix is `rskrb5-interop` (today's names). A namespace is [a-z][a-z0-9]*
# of at most 16 characters and joins as `rskrb5-interop--<namespace>`: the
# double hyphen cannot occur right after the prefix of an un-namespaced
# container (`rskrb5-interop-<fixture>`, fixture names start with a letter),
# so two namespaces, or one namespace and the default, cannot collide.
# INTEROP_PORT_OFFSET (default 0) moves every default host port by a number
# (interop_port); the state directory is target/interop[-<namespace>].
if [[ -n "${INTEROP_NAMESPACE:-}" && ! "${INTEROP_NAMESPACE}" =~ ^[a-z][a-z0-9]{0,15}$ ]]; then
  printf 'interop: ERROR: INTEROP_NAMESPACE must match [a-z][a-z0-9]* (at most 16 characters), not "%s"\n' \
    "$INTEROP_NAMESPACE" >&2
  return 1
fi
if [[ -n "${INTEROP_PORT_OFFSET:-}" && ! "${INTEROP_PORT_OFFSET}" =~ ^[0-9]{1,5}$ ]]; then
  printf 'interop: ERROR: INTEROP_PORT_OFFSET must be a number of at most five digits, not "%s"\n' \
    "$INTEROP_PORT_OFFSET" >&2
  return 1
fi
readonly INTEROP_PREFIX="rskrb5-interop${INTEROP_NAMESPACE:+--$INTEROP_NAMESPACE}"
readonly INTEROP_NETWORK="$INTEROP_PREFIX"
readonly INTEROP_LABEL="$INTEROP_PREFIX"
INTEROP_FIXTURES=()
INTEROP_SUITE_NAMES=()
INTEROP_SUITE_TARGETS=()
INTEROP_SUITE_FIXTURES=()
INTEROP_ENV_NAMES=()
INTEROP_RT=""

interop_log() {
  printf 'interop: %s\n' "$*" >&2
}

interop_die() {
  printf 'interop: ERROR: %s\n' "$*" >&2
  return 1
}

# ------------------------------------------------------------------ runtime --

# Selects the container runtime: INTEROP_RUNTIME=docker|podman, else docker
# when its daemon answers, else podman.
interop_detect_runtime() {
  case "${INTEROP_RUNTIME:-}" in
    docker | podman)
      command -v "$INTEROP_RUNTIME" >/dev/null 2>&1 ||
        interop_die "INTEROP_RUNTIME=$INTEROP_RUNTIME but $INTEROP_RUNTIME is not on PATH" || return 1
      INTEROP_RT="$INTEROP_RUNTIME"
      ;;
    "")
      if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        INTEROP_RT=docker
      elif command -v podman >/dev/null 2>&1; then
        INTEROP_RT=podman
      else
        interop_die "no container runtime: install docker or podman, or set INTEROP_RUNTIME" || return 1
      fi
      ;;
    *)
      interop_die "INTEROP_RUNTIME must be docker or podman, not '$INTEROP_RUNTIME'" || return 1
      ;;
  esac
}

interop_rt() {
  "$INTEROP_RT" "$@"
}

# ----------------------------------------------------------------- registry --

interop_fixture_id() {
  printf '%s' "${1//-/_}"
}

interop_container_name() {
  printf '%s-%s' "$INTEROP_PREFIX" "$1"
}

# interop_port VARIABLE DEFAULT: prints the host port a fixture publishes: the
# value of VARIABLE when set, else DEFAULT plus INTEROP_PORT_OFFSET.
interop_port() {
  local port="${!1:-}"
  if [[ -z "$port" ]]; then
    port=$(($2 + 10#${INTEROP_PORT_OFFSET:-0}))
  fi
  [[ "$port" =~ ^[0-9]+$ ]] && ((port >= 1 && port <= 65535)) ||
    interop_die "host port for $1 is '$port', not a port number" || return 1
  printf '%s' "$port"
}

interop_fixture() {
  [[ "$1" =~ ^[a-z][a-z0-9-]*$ ]] || interop_die "invalid fixture name '$1'" || return 1
  INTEROP_FIXTURES+=("$1")
}

interop_suite() {
  local suite="$1" target="$2"
  shift 2
  [[ "$suite" =~ ^[a-z][a-z0-9-]*$ && "$target" =~ ^interop_[a-z0-9_]+$ ]] ||
    interop_die "invalid suite '$suite' or test target '$target'" || return 1
  INTEROP_SUITE_NAMES+=("$suite")
  INTEROP_SUITE_TARGETS+=("$target")
  INTEROP_SUITE_FIXTURES+=("$*")
}

# Prints the index of a registered suite.
interop_suite_index() {
  local index=0
  while ((index < ${#INTEROP_SUITE_NAMES[@]})); do
    if [[ "${INTEROP_SUITE_NAMES[index]}" == "$1" ]]; then
      printf '%s' "$index"
      return 0
    fi
    index=$((index + 1))
  done
  interop_die "unknown suite '$1' (registered: ${INTEROP_SUITE_NAMES[*]:-none})"
}

# ---------------------------------------------------------------- env file --

interop_is_secret_name() {
  [[ "$1" =~ _(PASSWORD|SECRET|TOKEN)$ ]]
}

# interop_env KEY VALUE: records one env-file entry (later values win).
interop_env() {
  local name="$1" known
  [[ "$name" =~ ^(INTEROP|INTEGRATION)_[A-Z0-9_]+$ || "$name" == INTEROP ]] ||
    interop_die "invalid env-file key '$name'" || return 1
  if interop_is_secret_name "$name"; then
    interop_inventory_add "$2" || return 1
  fi
  printf -v "$name" '%s' "$2"
  for known in "${INTEROP_ENV_NAMES[@]}"; do
    [[ "$known" == "$name" ]] && return 0
  done
  INTEROP_ENV_NAMES+=("$name")
}

# Creates the private state directory at mode 0700, or brings an existing one
# owned by the invoking user to 0700; refuses a symlink or a foreign owner.
interop_prepare_private_dir() {
  local dir="$1"
  if [[ -L "$dir" ]]; then
    interop_die "$dir is a symlink; refusing to write secrets through it"
    return 1
  fi
  (umask 077 && mkdir -p "$dir") || return 1
  if [[ ! -O "$dir" ]]; then
    interop_die "$dir is not owned by the current user; refusing to write secrets into it"
    return 1
  fi
  chmod 700 "$dir"
}

# Writes every recorded key to FILE: staged under a fresh mode-0600 name in the
# private directory, then renamed, so secrets never land in a file with
# umask-default or inherited permissions.
interop_write_env() {
  local file="$1" dir staged name
  dir="$(dirname -- "$file")"
  interop_prepare_private_dir "$dir" || return 1
  staged="$(mktemp "$dir/.interop.env.XXXXXX")" || return 1
  chmod 600 "$staged" || {
    rm -f "$staged"
    return 1
  }
  if ! for name in "${INTEROP_ENV_NAMES[@]}"; do
    printf 'export %s=%q\n' "$name" "${!name:-}"
  done >"$staged"; then
    rm -f "$staged"
    return 1
  fi
  mv -f "$staged" "$file" || {
    rm -f "$staged"
    return 1
  }
}

# Prints the keys of FILE (from its `export KEY=` lines), one per line.
interop_env_keys() {
  local line
  while IFS= read -r line; do
    if [[ "$line" =~ ^export\ ([A-Z][A-Z0-9_]*)= ]]; then
      printf '%s\n' "${BASH_REMATCH[1]}"
    fi
  done <"$1"
}

# Prints FILE re-serialized by key with every non-empty secret as <redacted>;
# the values are read back by sourcing, so a multiline secret never leaks.
interop_print_env() {
  local file="$1"
  [[ -f "$file" ]] || interop_die "missing $file; run 'scripts/interop/run.sh up' first" || return 1
  (
    local name
    local -a names=()
    while IFS= read -r name; do names+=("$name"); done < <(interop_env_keys "$file")
    # shellcheck disable=SC1090
    source "$file"
    for name in "${names[@]}"; do
      if interop_is_secret_name "$name" && [[ -n "${!name:-}" ]]; then
        printf 'export %s=<redacted>\n' "$name"
      else
        printf 'export %s=%q\n' "$name" "${!name:-}"
      fi
    done
  )
}

# Prints the non-empty secret values of FILE, one per line (for redaction).
# Fails when FILE is missing or cannot be sourced: a redaction without its
# secrets must not look like a redaction (Y1-01).
interop_secret_values() {
  local file="$1"
  [[ -f "$file" ]] || interop_die "no secret inventory at $file" || return 1
  (
    local name
    local -a names=()
    while IFS= read -r name; do names+=("$name"); done < <(interop_env_keys "$file")
    # shellcheck disable=SC1090
    source "$file"
    for name in "${names[@]}"; do
      if interop_is_secret_name "$name" && [[ -n "${!name:-}" ]]; then
        printf '%s\n' "${!name}"
      fi
    done
  )
}

# ------------------------------------------------------------------ secrets --

# Prints a fresh 24-character [A-Za-z0-9] secret.
interop_new_secret() {
  local value
  value="$(head -c 96 /dev/urandom | base64 -w0 | tr -dc 'A-Za-z0-9')"
  ((${#value} >= 24)) || interop_die "could not generate a secret" || return 1
  interop_inventory_add "${value:0:24}" || return 1
  printf '%s' "${value:0:24}"
}

# Secret inventory (Y1-01). `up` creates a private append-only file before any
# secret-bearing step (interop_inventory_init); every secret value is appended
# to it the moment it is drawn (interop_new_secret) or recorded under a secret
# key (interop_env), one `export INTEROP_INVENTORY_<n>_SECRET=<%q value>` line
# each, so the redaction of fixture logs knows every secret even when `up`
# fails before it writes the env file. The inventory is optional only while
# INTEROP_SECRET_INVENTORY is unset (self-tests, redact.sh); once it is set, a
# vanished file is an error.
interop_inventory_init() {
  local file="$1"
  interop_prepare_private_dir "$(dirname -- "$file")" || return 1
  (umask 077 && : >"$file") || interop_die "could not create the secret inventory $file" || return 1
  chmod 600 "$file" || return 1
  INTEROP_SECRET_INVENTORY="$file"
}

# interop_inventory_add VALUE: appends a secret value; a no-op for an empty
# value or while no inventory is active.
interop_inventory_add() {
  [[ -n "$1" && -n "${INTEROP_SECRET_INVENTORY:-}" ]] || return 0
  [[ -f "$INTEROP_SECRET_INVENTORY" ]] ||
    interop_die "the secret inventory $INTEROP_SECRET_INVENTORY is missing" || return 1
  printf 'export INTEROP_INVENTORY_%d_SECRET=%q\n' "$(($(wc -l <"$INTEROP_SECRET_INVENTORY") + 1))" "$1" \
    >>"$INTEROP_SECRET_INVENTORY"
}

# interop_deliver_secrets CONTAINER KEY...: streams `KEY=value` lines into the
# container's tmpfs /run/interop/secrets through `exec -i` (never argv/env).
interop_deliver_secrets() {
  local container="$1" name
  shift
  for name in "$@"; do
    [[ "${!name:-}" =~ ^[A-Za-z0-9]+$ ]] || interop_die "secret $name is empty or not [A-Za-z0-9]" || return 1
    printf '%s=%s\n' "$name" "${!name}"
  done | interop_rt exec -i "$container" sh -c \
    'umask 077 && cat >/run/interop/secrets.tmp && mv /run/interop/secrets.tmp /run/interop/secrets'
}

# --------------------------------------------------------------- containers --

interop_image_tag() {
  local name="$1" context="$2" digest
  digest="$(cd -- "$context" && find . -type f ! -name fixture.sh -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum)"
  printf 'rskrb5-interop/%s:%s' "$name" "${digest:0:12}"
}

# interop_build_image NAME CONTEXT: builds once per context hash; prints the tag.
interop_build_image() {
  local name="$1" context="$2" tag size
  local -a options=()
  # FU-IOP-P02: INTEROP_BUILD_CA_DIR names a directory of extra root
  # certificates (*.crt, PEM) for a host behind a TLS-inspecting proxy. It is
  # mounted read-only at /usr/local/share/ca-certificates during the build, the
  # directory Debian's ca-certificates package reads; the Dockerfiles' sha256
  # and PGP checks of the downloads still bind. Off by default (CI never sets
  # it); `docker build` cannot mount a directory, so it needs podman.
  if [[ -n "${INTEROP_BUILD_CA_DIR:-}" ]]; then
    [[ "$INTEROP_RT" == podman ]] ||
      interop_die "INTEROP_BUILD_CA_DIR needs INTEROP_RUNTIME=podman: docker build cannot mount a directory" || return 1
    [[ -d "$INTEROP_BUILD_CA_DIR" ]] ||
      interop_die "INTEROP_BUILD_CA_DIR=$INTEROP_BUILD_CA_DIR is not a directory" || return 1
    options+=(--volume "$INTEROP_BUILD_CA_DIR:/usr/local/share/ca-certificates:ro")
  fi
  tag="$(interop_image_tag "$name" "$context")" || return 1
  if ! interop_rt image inspect "$tag" >/dev/null 2>&1; then
    interop_log "building image $tag from ${context#"$INTEROP_ROOT"/}"
    interop_rt build ${options[@]+"${options[@]}"} -t "$tag" "$context" >&2 ||
      interop_die "image build failed for fixture $name" || return 1
  fi
  size="$(interop_rt image inspect -f '{{.Size}}' "$tag")"
  interop_log "image $tag size $size bytes"
  printf '%s' "$tag"
}

interop_container_state() {
  if [[ -z "$INTEROP_RT" ]] && ! interop_detect_runtime 2>/dev/null; then
    printf 'unknown (no container runtime)'
    return 0
  fi
  interop_rt inspect -f '{{.State.Status}}' "$1" 2>/dev/null || printf 'missing'
}

# Prints `fixture <name> (container <c>): <state>` for every given fixture.
interop_fixture_report() {
  local name
  for name in "$@"; do
    printf 'interop: fixture %s (container %s): %s\n' "$name" "$(interop_container_name "$name")" \
      "$(interop_container_state "$(interop_container_name "$name")")" >&2
  done
}

# interop_redact_stream SECRET...: copies stdin to stdout, each secret replaced.
interop_redact_stream() {
  local line secret
  while IFS= read -r line || [[ -n "$line" ]]; do
    for secret in "$@"; do
      [[ -n "$secret" ]] && line="${line//"$secret"/<redacted>}"
    done
    printf '%s\n' "$line"
  done
}

# Prints the last lines of a container log with the secrets recorded so far
# in this run (interop_env) redacted.
interop_log_tail() {
  local name value inventory
  local -a secrets=()
  for name in "${INTEROP_ENV_NAMES[@]}"; do
    interop_is_secret_name "$name" && secrets+=("${!name:-}")
  done
  if [[ -n "${INTEROP_SECRET_INVENTORY:-}" ]]; then
    if ! inventory="$(interop_secret_values "$INTEROP_SECRET_INVENTORY")"; then
      interop_log "log tail of $1 withheld: the secret inventory is unusable"
      return 0
    fi
    while IFS= read -r value; do
      [[ -n "$value" ]] && secrets+=("$value")
    done <<<"$inventory"
  fi
  interop_rt logs --tail 40 "$1" 2>&1 | interop_redact_stream "${secrets[@]}" >&2 || true
}

# interop_wait_ready FIXTURE: bounded wait for /run/interop/ready in its container.
interop_wait_ready() {
  local fixture="$1" container limit waited=0 state
  container="$(interop_container_name "$fixture")"
  limit="${INTEROP_READY_TIMEOUT:-180}"
  while ! interop_rt exec "$container" test -f /run/interop/ready >/dev/null 2>&1; do
    state="$(interop_container_state "$container")"
    if [[ "$state" != running ]] || ((waited >= limit)); then
      interop_log_tail "$container"
      interop_die "fixture $fixture (container $container) not ready after ${waited}s (state: $state)"
      return 1
    fi
    sleep 1
    waited=$((waited + 1))
  done
  interop_log "fixture $fixture ready after ${waited}s"
}

# interop_wait_tcp FIXTURE HOST PORT: bounded wait for a published TCP port.
interop_wait_tcp() {
  local fixture="$1" host="$2" port="$3" limit waited=0
  limit="${INTEROP_READY_TIMEOUT:-180}"
  until (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; do
    if ((waited >= limit)); then
      interop_die "fixture $fixture: $host:$port does not accept TCP connections after ${waited}s"
      return 1
    fi
    sleep 1
    waited=$((waited + 1))
  done
}

# interop_copy_out CONTAINER PATH DEST: copies a file out of the container
# (tmpfs paths included) into a mode-0600 file.
interop_copy_out() {
  (umask 077 && interop_rt exec "$1" cat "$2" >"$3") ||
    interop_die "could not copy $2 out of $1" || return 1
  chmod 600 "$3"
}

# Removes every labelled container, network and volume; prints a receipt.
interop_remove_all() {
  local kind ids remaining
  ids="$(interop_rt ps -aq --filter "label=$INTEROP_LABEL" 2>/dev/null || true)"
  if [[ -n "$ids" ]]; then
    # shellcheck disable=SC2086
    interop_rt rm -f $ids >/dev/null 2>&1 || true
  fi
  ids="$(interop_rt network ls -q --filter "label=$INTEROP_LABEL" 2>/dev/null || true)"
  if [[ -n "$ids" ]]; then
    # shellcheck disable=SC2086
    interop_rt network rm $ids >/dev/null 2>&1 || true
  fi
  ids="$(interop_rt volume ls -q --filter "label=$INTEROP_LABEL" 2>/dev/null || true)"
  if [[ -n "$ids" ]]; then
    # shellcheck disable=SC2086
    interop_rt volume rm -f $ids >/dev/null 2>&1 || true
  fi
  for kind in containers networks volumes; do
    case "$kind" in
      containers) remaining="$(interop_rt ps -aq --filter "label=$INTEROP_LABEL" | wc -l)" ;;
      networks) remaining="$(interop_rt network ls -q --filter "label=$INTEROP_LABEL" | wc -l)" ;;
      volumes) remaining="$(interop_rt volume ls -q --filter "label=$INTEROP_LABEL" | wc -l)" ;;
    esac
    printf 'interop: cleanup receipt: %s labelled %s remaining: %s\n' "$INTEROP_RT" "$kind" "$remaining" >&2
    [[ "$remaining" -eq 0 ]] || return 1
  done
}

interop_create_network() {
  interop_rt network create --label "$INTEROP_LABEL=1" "$INTEROP_NETWORK" >/dev/null
}

# interop_run_container FIXTURE IMAGE [run options...]: starts the fixture's
# container detached on the interop network with the label and a private
# tmpfs /run/interop.
interop_run_container() {
  local fixture="$1" image="$2"
  shift 2
  interop_rt run -d --name "$(interop_container_name "$fixture")" \
    --label "$INTEROP_LABEL=1" --network "$INTEROP_NETWORK" \
    --tmpfs /run/interop:rw,mode=0700 "$@" "$image" >/dev/null
}

# interop_check_alive: fails, naming each one, unless every registered
# fixture's container and every other container this run labelled is still
# running (Y1-05). `all` calls it after the last suite and before it reports
# success, so a fixture that died after its own startup check cannot pass.
interop_check_alive() {
  local fixture name state status=0
  for fixture in "${INTEROP_FIXTURES[@]}"; do
    state="$(interop_container_state "$(interop_container_name "$fixture")")"
    if [[ "$state" != running ]]; then
      interop_log "fixture $fixture (container $(interop_container_name "$fixture")) is not running at the end of the run (state: $state)"
      status=1
    fi
  done
  for name in $(interop_rt ps -a --filter "label=$INTEROP_LABEL" --format '{{.Names}}' 2>/dev/null); do
    state="$(interop_container_state "$name")"
    if [[ "$state" != running ]]; then
      interop_log "container $name is not running at the end of the run (state: $state)"
      status=1
    fi
  done
  return "$status"
}

# ------------------------------------------------ protocol-level liveness --
# FU-IOP-P21 (plan 2 todo 10). interop_check_alive proves a container still
# runs; a daemon that stays up and stops answering passes it. After it, `all`
# calls interop_check_protocols: every registered fixture that serves a protocol
# and has an `interop_probe_<id>` function (id = the fixture name with '-'
# replaced by '_') must give one real protocol answer, or the run fails naming
# the fixture. Probes: radius (an Access-Request accepted and one rejected, the
# fixture's own selfcheck), mit-kdc (an AS-REQ answered by a KRB-ERROR), kcm (a
# KCM GET_DEFAULT_CACHE request over the socket) and kdcproxy (an MS-KKDCP
# AS-REQ relayed over HTTPS, scripts/interop/probe.py). A fixture without a probe
# function is checked by interop_check_alive only.

# interop_probe_radius: radiusd answers an Access-Request in its container.
interop_probe_radius() {
  local container out
  container="$(interop_container_name radius)"
  out="$(interop_rt exec "$container" /opt/interop/radius/selfcheck.sh 2>&1)" ||
    interop_die "fixture radius (container $container) is running but radiusd answers no Access-Request: $(tail -n 2 <<<"$out" | tr '\n' ' ')" || return 1
}

# interop_probe_mit_kdc: the KDC answers an AS-REQ over TCP with a Kerberos reply.
interop_probe_mit_kdc() {
  local out
  out="$(python3 "$INTEROP_ROOT/scripts/interop/probe.py" kdc "${INTEROP_MIT_KDC:?}" "${INTEROP_MIT_REALM:?}" 2>&1)" ||
    interop_die "fixture mit-kdc (container $(interop_container_name mit-kdc)) is running but gives no Kerberos answer: $out" || return 1
}

# interop_probe_kcm: sssd_kcm answers a protocol request on its socket.
interop_probe_kcm() {
  local out
  out="$(net_kcm_host_probe "${INTEROP_KCM_SOCKET:?}" 2>&1)" && [[ "$out" == *"GET_DEFAULT_CACHE status 0 "* ]] ||
    interop_die "fixture kcm (container $(interop_container_name kcm)) is running but the daemon gives no KCM answer: $out" || return 1
}

# interop_probe_kdcproxy: the proxy relays an AS-REQ to the KDC over HTTPS.
interop_probe_kdcproxy() {
  local out
  out="$(python3 "$INTEROP_ROOT/scripts/interop/probe.py" kdcproxy "${INTEROP_KDCPROXY_URL:?}" "${INTEROP_KDCPROXY_CA:?}" "${INTEROP_KDCPROXY_REALM:?}" 2>&1)" ||
    interop_die "fixture kdcproxy (container $(interop_container_name kdcproxy)) is running but relays no KDC answer: $out" || return 1
}

# interop_check_protocols: runs the probe of every registered fixture that has
# one and fails, naming each fixture, unless every probe answered.
interop_check_protocols() {
  local fixture probe status=0
  for fixture in "${INTEROP_FIXTURES[@]}"; do
    probe="interop_probe_${fixture//-/_}"
    declare -F "$probe" >/dev/null || continue
    "$probe" || status=1
  done
  return "$status"
}
