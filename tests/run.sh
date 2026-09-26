#!/usr/bin/env bash
#
# The library's tests: an Ur/Web application (tests/app) sends messages to a
# fake SMTP server (tests/smtpd.py), and what the server saw, what the
# application answered and what it logged are compared with a golden file.
#
#   tests/run.sh [-u] [CASE...]      all cases under tests/cases unless given;
#                                    -u rewrites what the cases expect
#
# A case is a directory tests/cases/NAME with
#
#   args        shell lines: mode=... (smtpd.py's mode), tls=... (none,
#               starttls, starttls-ca, starttls-noverify: what the client is
#               told), form=(...) (the fields of the request, curl -d style),
#               sends=N (the request is made N times; the server then
#               serves up to N sessions)
#   expected    the transcript: the HTTP status and body, the server's
#               transcript, then the application's log
#
# The compiler is the one URWEB names, run with the flags in URWEB_FLAGS if
# set, or else `urweb` on the PATH.  Needs python3, openssl and curl.  The
# library must have been built (tests/config.urp names it).  Exit status: 0
# every case passed, 1 some failed, 2 could not run.

set -u

here=$(cd "$(dirname "$0")" && pwd)
top=$(cd "$here/.." && pwd)
out=$here/out
urweb=${URWEB:-urweb}
urweb_flags=${URWEB_FLAGS:-}

update=0
if [ "${1:-}" = "-u" ]; then update=1; shift; fi

die() { echo "run.sh: $*" >&2; exit 2; }

for tool in python3 openssl curl; do
  command -v "$tool" >/dev/null || die "$tool is needed"
done
command -v "$urweb" >/dev/null || die "no urweb: set URWEB or put it on the PATH"
[ -f "$here/config.urp" ] || die "tests/config.urp is missing: run configure and make first"

if [ $# -gt 0 ]; then
  cases=("$@")
else
  cases=()
  for d in "$here"/cases/*/; do cases+=("$(basename "$d")"); done
fi

rm -rf "$out"
mkdir -p "$out"

# A certificate for the fake server's STARTTLS, self-signed, so that it
# doubles as the CA the client is given.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=localhost \
  -addext subjectAltName=IP:127.0.0.1 \
  -keyout "$out/key.pem" -out "$out/cert.pem" >/dev/null 2>&1 || die "openssl failed"

# The application, built once.
( cd "$here/app" && rm -f test.exe && "$urweb" $urweb_flags -protocol http test ) \
  > "$out/build.log" 2>&1 || { cat "$out/build.log" >&2; die "the test application failed to build"; }

# Replace what varies from run to run.
normalize() {
  local boundary
  boundary=$(sed -n 's/.*boundary="\([^"]*\)".*/\1/p' "$1" | head -1)
  sed -e 's/^| EHLO .*/| EHLO <host>/; s/^C: EHLO .*/C: EHLO <host>/' \
      -e 's/^| Date: .*/| Date: <date>/' \
      -e 's/^| Message-ID: <[0-9a-f]\{24\}@/| Message-ID: <generated@/' \
      -e "${boundary:+s/$boundary/<boundary>/g}" \
      "$1"
}

failed=0
for case in "${cases[@]}"; do
  dir=$here/cases/$case
  [ -f "$dir/args" ] || { echo "$case: no args file" >&2; failed=1; continue; }
  mode=accept; tls=none; form=(); sends=1
  # shellcheck disable=SC1090
  . "$dir/args"
  work=$out/$case
  mkdir -p "$work"

  # The server, with STARTTLS on offer unless the case says otherwise; or,
  # with mode=none, no server: a port nothing listens on.
  if [ "$mode" = none ]; then
    srv_pid=
    smtp_port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
    echo "(no server)" > "$work/transcript"
  else
    srv_args=(--transcript "$work/transcript" --mode "$mode" --port-file "$work/port" --sessions "$sends")
    [ "$mode" != no-starttls ] && srv_args+=(--cert "$out/cert.pem" --key "$out/key.pem")
    python3 "$here/smtpd.py" "${srv_args[@]}" 2> "$work/smtpd.err" &
    srv_pid=$!
    for _ in $(seq 100); do [ -s "$work/port" ] && break; sleep 0.05; done
    [ -s "$work/port" ] || { echo "$case: the fake server did not start" >&2; cat "$work/smtpd.err" >&2; failed=1; continue; }
    smtp_port=$(cat "$work/port")
  fi

  # The application, fresh for every case so that its log is the case's.
  # -d3 prints pid=, port= and status= on fd 3 once it listens.
  eval "$( URMAIL_TIMEOUT=2 "$here/app/test.exe" -a 127.0.0.1 -p 8000 -P 9000 -d3 3>&1 1>/dev/null 2> "$work/app.log" )"
  if [ "${status:-}" != OK ]; then
    echo "$case: the test application did not start" >&2; failed=1; [ -n "$srv_pid" ] && kill "$srv_pid" 2>/dev/null; continue
  fi
  app_pid=$pid; app_port=$port

  case $tls in
    none|starttls|starttls-noverify) ca= ;;
    starttls-ca) ca=$out/cert.pem ;;
    *) die "$case: unknown tls setting $tls" ;;
  esac
  curl_args=(-s -o "$work/body" -w '%{http_code}' --max-time 120
             --data-urlencode "Server=smtp://127.0.0.1:$smtp_port"
             --data-urlencode "Tls=$tls" --data-urlencode "Ca=$ca")
  for f in From To Cc Bcc Subject Body Html User Password MessageId UserAgent; do
    v=
    for kv in "${form[@]}"; do
      case $kv in "$f="*) v=${kv#*=} ;; esac
    done
    curl_args+=(--data-urlencode "$f=$v")
  done
  http=
  for _ in $(seq "$sends"); do
    http="$http$(curl "${curl_args[@]}" "http://127.0.0.1:$app_port/Test/sendMail") "
  done

  # The application first: it keeps the connection open for the next message,
  # and the server's session ends when it goes.
  kill "$app_pid" 2>/dev/null; wait "$app_pid" 2>/dev/null
  [ -n "$srv_pid" ] && wait "$srv_pid"

  {
    echo "HTTP ${http% }"
    cat "$work/body"; echo
    echo "--- server"
    cat "$work/transcript"
    echo "--- application log"
    cat "$work/app.log"
  } > "$work/actual.raw"
  normalize "$work/actual.raw" > "$work/actual"

  if [ $update = 1 ]; then
    cp "$work/actual" "$dir/expected"
    echo "$case: updated"
  elif [ ! -f "$dir/expected" ]; then
    echo "$case: no expected file (run with -u to create it)" >&2; failed=1
  elif diff -u "$dir/expected" "$work/actual" > "$work/diff"; then
    echo "$case: ok"
  else
    echo "$case: FAILED" >&2; cat "$work/diff" >&2; failed=1
  fi
done

exit $failed
