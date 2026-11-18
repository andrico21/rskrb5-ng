#!/bin/sh
# RADIUS-side self-check of the `radius` fixture (lane 1D-a), run by fixture.sh
# with `<runtime> exec`: an Access-Request for otpuser with the per-run token
# must be accepted and one with a wrong token rejected, answered by the
# radiusd of this container. Prints one PASS line per assertion.
set -eu

secrets=/run/interop/secrets
shared="$(sed -n 's/^INTEROP_RADIUS_SHARED_SECRET=//p' "$secrets")"
token="$(sed -n 's/^INTEROP_MIT_OTP_TOKEN=//p' "$secrets")"
if [ -z "$shared" ] || [ -z "$token" ]; then
  echo "selfcheck[radius]: FAIL the secrets file lacks the shared secret or the token" >&2
  exit 1
fi

# attempt LABEL PASSWORD EXPECTED: sends an Access-Request, expects EXPECTED
# ("Access-Accept" or "Access-Reject") in the answer.
attempt() {
  answer="$(printf 'User-Name = otpuser\nUser-Password = %s\n' "$2" |
    /opt/bin/radclient -t 2 -r 1 127.0.0.1:1812 auth "$shared" 2>&1 || true)"
  case "$answer" in
    *"Received $3"*) echo "selfcheck[radius]: PASS $1: radclient received $3 from radiusd" ;;
    *)
      echo "selfcheck[radius]: FAIL $1: expected $3, radclient said: $(printf '%s' "$answer" | head -c 200)" >&2
      exit 1
      ;;
  esac
}

attempt "otpuser with the OTP token is accepted" "$token" Access-Accept
attempt "otpuser with a wrong token is rejected" "${token}x" Access-Reject
echo "selfcheck[radius]: PASS radius: all assertions"
