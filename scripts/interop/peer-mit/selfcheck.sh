#!/bin/bash
# In-container checks of the `mit-peer` fixture (lane 1F). fixture.sh runs them
# through `exec` and fails the fixture naming itself when one exits non-zero.
#   frames   the adapter answers a ping frame and rejects an oversize frame, an
#            empty frame, a truncated frame (stream ends inside the frame),
#            an idle partial frame and an unknown command
#   negoex   MIT's t_context drives SPNEGO with the negoextest mechanisms loaded
#            from /etc/gss/mech.negoextest: the trace must show the NegoEx
#            messages of a two-hop exchange
#   serve M  gss-server (mode M: krb5 | spnego | iakerb | krb5-blocked) accepts
#            ONE connection with -export and -verbose; its output goes to
#            /run/peer/gss-server-M.log
#   client M HOST  gss-client (mode M) against HOST with the client keytab of
#            peeruser; prints its output
set -euo pipefail

readonly RUN_DIR=/run/peer
readonly PORT=4401
readonly KEYTABS="$RUN_DIR/keytabs"

fail() {
  printf 'selfcheck: FAILED: %s\n' "$*" >&2
  exit 1
}

pass() {
  printf 'selfcheck: PASS: %s\n' "$*"
}

hex() {
  od -An -tx1 -v | tr -d ' \n'
}

text_hex() {
  printf '%s' "$1" | hex
}

# open_conn PORT: connects file descriptor 3 to 127.0.0.1:PORT.
open_conn() {
  exec 3<>"/dev/tcp/127.0.0.1/$1" || fail "cannot connect to 127.0.0.1:$1"
}

# send_hex HEX: writes the bytes of HEX to descriptor 3.
send_hex() {
  local hex="$1" offset
  for ((offset = 0; offset < ${#hex}; offset += 2)); do
    printf '%b' "\\x${hex:offset:2}"
  done >&3
}

# read_reply: reads one reply frame from descriptor 3, prints its payload hex.
read_reply() {
  local header body length
  header="$(timeout 8 head -c 4 <&3 | hex)"
  [[ ${#header} -eq 8 ]] || fail "no reply header (got '$header')"
  length=$((16#$header))
  body="$(timeout 8 head -c "$length" <&3 | hex)"
  [[ ${#body} -eq $((length * 2)) ]] || fail "short reply body"
  printf '%s' "$body"
}

# expect_status BODYHEX STATUSHEX TEXT WHAT: status byte and a text fragment.
expect_status() {
  local body="$1" status="$2" text="$3" what="$4"
  [[ "${body:0:2}" == "$status" ]] || fail "$what: status ${body:0:2}, expected $status"
  [[ "$body" == *"$(text_hex "$text")"* ]] || fail "$what: reply lacks '$text'"
  pass "$what: status $status, '$text'"
}

# wait_log FILE PATTERN: bounded poll for a log line.
wait_log() {
  local tries=0
  until grep -q -- "$2" "$1" 2>/dev/null; do
    tries=$((tries + 1))
    ((tries <= 50)) || fail "no '$2' in $1 within 10 s"
    sleep 0.2
  done
}

check_frames() {
  local body
  open_conn "$PORT"
  send_hex "0000000150"
  body="$(read_reply)"
  expect_status "$body" 00 "rskrb5-peer/1" "ping"
  [[ "$body" == *"00100000"* ]] || fail "ping does not advertise the 1 MiB frame limit"
  send_hex "000000015a"
  expect_status "$(read_reply)" 03 "unknown command" "unknown command"
  exec 3>&-

  open_conn "$PORT"
  send_hex "00100001"
  expect_status "$(read_reply)" 03 "frame too large" "oversize frame (1 MiB + 1)"
  [[ -z "$(timeout 5 head -c 1 <&3 | hex)" ]] || fail "the adapter kept an oversize connection open"
  exec 3>&-
  open_conn "$PORT"
  send_hex "ffffffff"
  expect_status "$(read_reply)" 03 "frame too large" "oversize frame (4 GiB - 1)"
  exec 3>&-
  open_conn "$PORT"
  send_hex "00000000"
  expect_status "$(read_reply)" 03 "empty frame" "empty frame"
  exec 3>&-

  # A truncated frame: the stream ends after 4 of the 16 announced bytes.
  open_conn "$PORT"
  send_hex "0000001050505050"
  exec 3>&-
  wait_log "$RUN_DIR/adapter.log" "framing error: truncated frame"
  pass "truncated frame (stream ended inside the frame): logged and dropped"

  # An idle partial frame on a second adapter with a 2 s idle bound.
  PEER_IDLE_SECONDS=2 peer-adapter 127.0.0.1 4403 2>"$RUN_DIR/idle-adapter.log" &
  local idle=$! tries=0
  until (exec 4<>/dev/tcp/127.0.0.1/4403) 2>/dev/null; do
    tries=$((tries + 1))
    ((tries <= 50)) || fail "the idle-test adapter did not start"
    sleep 0.2
  done
  open_conn 4403
  send_hex "0000001050505050"
  expect_status "$(read_reply)" 03 "idle timeout" "partial frame then silence"
  exec 3>&-
  kill "$idle"
  wait "$idle" 2>/dev/null || true

  open_conn "$PORT"
  send_hex "0000000150"
  expect_status "$(read_reply)" 00 "rskrb5-peer/1" "ping after the malformed frames"
  exec 3>&-
}

check_negoex() {
  local trace="$RUN_DIR/negoex.trace" line
  grep -q '^negoextest 2.25.1414534758 ' /etc/gss/mech.negoextest || fail "mech config lacks the first negoextest OID"
  grep -q '^negoextest 2.25.1175737388 ' /etc/gss/mech.negoextest || fail "mech config lacks the second negoextest OID"
  rm -f "$trace"
  GSS_MECH_CONFIG=/etc/gss/mech.negoextest KRB5_TRACE="$trace" HOPS=2 \
    KRB5CCNAME=MEMORY:negoex KRB5_KTNAME=FILE:/nonexistent \
    t_context h:host || fail "t_context (SPNEGO with negoextest) exited non-zero"
  for line in \
    'NegoEx sending \[0\]INITIATOR_NEGO: c0a28569-66ac-0000-0000-000000000000 d1b08469-2ca8-0000-0000-000000000000' \
    'NegoEx sending \[3\]AP_REQUEST: c0a28569-66ac' \
    'NegoEx sending \[7\]CHALLENGE: c0a28569-66ac' \
    'NegoEx sending \[8\]VERIFY: c0a28569-66ac' \
    'NegoEx received \[8\]VERIFY: c0a28569-66ac' \
    'NegoEx sending \[9\]VERIFY: c0a28569-66ac'; do
    grep -q "$line" "$trace" || fail "the NegoEx trace lacks: $line"
  done
  pass "negoextest negotiated under SPNEGO/NegoEx: both mechanisms offered, two-hop CHALLENGE/VERIFY exchange traced"
}

# mode_of MODE: prints "mechanism port" of a gss-server/gss-client mode. The
# modes have their own ports so a server that is still shutting down never
# receives the next mode's client; krb5-blocked is the negative control of the
# isolated container (a krb5 exchange that must fail there).
mode_of() {
  case "$1" in
    krb5) printf 'krb5 4402' ;;
    spnego) printf 'spnego 4412' ;;
    iakerb) printf 'iakerb 4422' ;;
    krb5-blocked) printf 'krb5 4432' ;;
    *) fail "unknown mode $1" ;;
  esac
}

serve() {
  local mode="$1" mech port flag=()
  read -r mech port <<<"$(mode_of "$mode")"
  [[ "$mech" == iakerb ]] && flag=(-iakerb)
  rm -f "$RUN_DIR/gss-server-$mode.log"
  exec timeout 120 gss-server -port "$port" -once -export -verbose "${flag[@]}" \
    -keytab "$KEYTABS/acceptor.keytab" peer >"$RUN_DIR/gss-server-$mode.log" 2>&1
}

client() {
  local mode="$1" host="$2" mech port flag
  read -r mech port <<<"$(mode_of "$mode")"
  case "$mech" in
    krb5) flag=-krb5 ;;
    spnego) flag=-spnego ;;
    iakerb) flag=-iakerb ;;
    *) fail "unknown mechanism $mech" ;;
  esac
  rm -f "$RUN_DIR/cc-client-$mode"
  KRB5_CLIENT_KTNAME="FILE:$KEYTABS/peeruser.keytab" KRB5CCNAME="FILE:$RUN_DIR/cc-client-$mode" \
    timeout 60 gss-client -port "$port" "$flag" "$host" "peer@$host" testmsg
}

case "${1:-}" in
  frames) check_frames ;;
  negoex) check_negoex ;;
  serve) serve "${2:?mechanism}" ;;
  client) client "${2:?mechanism}" "${3:?host}" ;;
  *) fail "usage: selfcheck.sh frames|negoex|serve M|client M HOST" ;;
esac
