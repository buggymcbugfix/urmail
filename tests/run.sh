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
#               told), form=(...) (the fields of the request, curl -d style;
#               Attach1..3 spell attachments and images, and Srcs lists the
#               img srcs of the HTML version, see tests/app/test.ur),
#               sends=N (the request is made N times; the server then
#               serves up to N sessions), pause=SECONDS (slept between the
#               requests), url=smtp|bare|smtps|http (how the
#               server is named: smtp://host:port, host:port alone,
#               smtps://host:port, or an http:// URL, which must be refused),
#               app_env=(NAME=VALUE ...) (added to the application's
#               environment), logfilter=REGEX (only the lines of the
#               application's log that match, grep -E, are transcribed),
#               api=io|check (the message is
#               queued and sent by the application's io task, the default,
#               or only checked by Urmail.message; the transcript's first
#               part is the statuses the task recorded, or what
#               Urmail.message said)
#   expected    the transcript: the statuses or Urmail.message's verdict,
#               the server's transcript (not with api=check, which starts no
#               server), then the application's log
#
# The compiler is the one URWEB names, run with the flags in URWEB_FLAGS if
# set, or else `urweb` on the PATH.  Needs python3, openssl, curl and sqlite3
# (the application keeps its queue in a database, fresh for every case).  The
# library must have been built: BUILDDIR is the build tree (the source tree
# unless set, as `make check` sets it), and its tests/config.urp names the
# library.  Everything the run makes lands under the build tree's tests/out:
# copies of the application and the examples, whose lib.urp names the
# sources and the library by absolute path, so that a build tree apart from
# the source tree works and nothing is written into the source tree.
#
# Every case starts from nothing: its own directory under tests/out, its own
# server and application, which are stopped when it ends, however it ends.
# Every wait has a limit (below).  A case passes when its transcript is the
# golden one; it fails when the transcript differs, when the application
# exits during the case, or when a request is not answered with 200; it
# could not run when its server or application did not start.  Exit
# status: 0 every case passed, 1 some failed, 2 some could not run (or the
# run itself could not: a tool missing, the application not building).

set -u

here=$(cd "$(dirname "$0")" && pwd)
top=$(cd "$here/.." && pwd)
build=${BUILDDIR:-$top}
out=$build/tests/out
urweb=${URWEB:-urweb}
urweb_flags=${URWEB_FLAGS:-}

# The limits on the waits, in seconds: for the server and the application
# to start; for a request to be answered; for the statuses to be recorded
# after the last request (what has been recorded by then is what the case
# shows); for a process told to stop to exit, before it is killed.
start_limit=30
request_limit=60
status_limit=60
stop_limit=10

update=0
if [ "${1:-}" = "-u" ]; then update=1; shift; fi

die() { echo "run.sh: $*" >&2; exit 2; }

for tool in python3 openssl curl sqlite3 timeout; do
  command -v "$tool" >/dev/null || die "$tool is needed"
done
command -v "$urweb" >/dev/null || die "no urweb: set URWEB or put it on the PATH"
[ -f "$build/tests/config.urp" ] || die "tests/config.urp is missing: run configure and make first"

if [ $# -gt 0 ]; then
  cases=("$@")
else
  cases=()
  for d in "$here"/cases/*/; do cases+=("$(basename "$d")"); done
fi

# Whether process $1 is still running.  The application is a daemon whose
# parent has exited, and a container's init need not reap it once it exits:
# kill -0 then still succeeds, so a zombie counts as gone where /proc
# shows it.
running() {
  kill -0 "$1" 2>/dev/null || return 1
  [ -r "/proc/$1/stat" ] || return 0
  case $(sed 's/.*) //' "/proc/$1/stat" 2>/dev/null) in
    Z*) return 1 ;;
  esac
  return 0
}

# Stop process $1: SIGTERM, and SIGKILL if it is still running after
# stop_limit seconds.
stop() {
  local i
  kill -TERM "$1" 2>/dev/null || return 0
  for ((i = 0; i < stop_limit * 10; ++i)); do
    running "$1" || return 0
    sleep 0.1
  done
  echo "run.sh: process $1 is still running after SIGTERM; killing it" >&2
  kill -KILL "$1" 2>/dev/null
}

# The current case's server and application, stopped when the case ends,
# and by the trap when the run is interrupted.
srv_pid=
app_pid=
stop_case() {
  if [ -n "$app_pid" ]; then stop "$app_pid"; app_pid=; fi
  if [ -n "$srv_pid" ]; then stop "$srv_pid"; wait "$srv_pid" 2>/dev/null; srv_pid=; fi
}
trap stop_case EXIT
trap 'exit 2' HUP INT TERM

rm -rf "$out"
mkdir -p "$out"

# The application and the examples, copied, over a lib.urp made from
# tests/lib.urp with the sources named by absolute path and config.urp the
# build tree's.
cp -r "$here/app" "$out/app"
cp -r "$top/examples" "$out/examples"
cp "$build/tests/config.urp" "$out/config.urp"
sed -e "s#^ffi \.\./#ffi $top/#; s#^\.\./#$top/#" "$here/lib.urp" > "$out/lib.urp"

# A certificate for the fake server's STARTTLS, self-signed, so that it
# doubles as the CA the client is given.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=localhost \
  -addext subjectAltName=IP:127.0.0.1 \
  -keyout "$out/key.pem" -out "$out/cert.pem" >/dev/null 2>&1 || die "openssl failed"

# The examples must at least typecheck against the signature.
for ex in "$out"/examples/*.urp; do
  ( cd "$(dirname "$ex")" && "$urweb" $urweb_flags -tc "$(basename "$ex" .urp)" ) \
    > "$out/examples.log" 2>&1 || { cat "$out/examples.log" >&2; die "example $(basename "$ex") does not typecheck"; }
done

# The application, built once; its database is created afresh for each case.
( cd "$out/app" && "$urweb" $urweb_flags -protocol http -dbms sqlite \
    -db "$out/app.db" -sql "$out/app.sql" test ) \
  > "$out/build.log" 2>&1 || { cat "$out/build.log" >&2; die "the test application failed to build"; }

# Replace what varies from run to run.
normalize() {
  sed -e 's/^| EHLO .*/| EHLO <host>/; s/^C: EHLO .*/C: EHLO <host>/' \
      -e 's/^| Date: .*/| Date: <date>/' \
      -e 's/^| Message-ID: <[0-9a-f]\{24\}@/| Message-ID: <generated@/' \
      -e 's/127\.0\.0\.1:[0-9]\{1,5\}/127.0.0.1:<port>/g' \
      "$1"
}

# Pages as text: one line per <br />, without the markup and escaping.
text() { sed -e 's#<br />#\n#g' -e 's#<[^>]*>##g' -e 's#&lt;#<#g' -e 's#&gt;#>#g' -e 's#&amp;#\&#g' "$1" | grep -v '^$'; }

failed=0
broken=0
# The verdicts other than ok.  Each case reports at most one.
case_failed() { echo "$case: FAILED: $*" >&2; failed=1; }
cannot_run() { echo "$case: could not run: $*" >&2; broken=1; }

# What became of a request, by curl's %{http_code}.
answered() {
  if [ "$1" = 000 ]; then echo "got no answer"; else echo "was answered with HTTP $1"; fi
}

# Wait for process $2 to write file $1, at most start_limit seconds.
wait_for_file() {
  local i
  for ((i = 0; i < start_limit * 20; ++i)); do
    [ -s "$1" ] && return 0
    running "$2" || break
    sleep 0.05
  done
  [ -s "$1" ]
}

run_case() {
  local case=$1
  local dir=$here/cases/$1 work=$out/$1
  local mode=accept tls=none sends=1 pause=0 api=io url=smtp logfilter=
  local -a form=() app_env=()
  local ca server handler smtp_port app_port f v kv code i n deadline
  local -a srv_args curl_args

  [ -f "$dir/args" ] || { cannot_run "no args file"; return; }
  # shellcheck disable=SC1090
  . "$dir/args"

  case $tls in
    none|starttls|starttls-noverify) ca= ;;
    starttls-ca) ca=$out/cert.pem ;;
    *) cannot_run "unknown tls setting $tls"; return ;;
  esac
  case $url in
    smtp|smtps|bare|http) ;;
    *) cannot_run "unknown url form $url"; return ;;
  esac
  case $api in
    io) handler=queue ;;
    check) handler=check ;;
    *) cannot_run "unknown api $api"; return ;;
  esac

  # A directory of its own, emptied: nothing of an earlier run, or of an
  # earlier case of the same name, can make it pass.
  rm -rf "$work"
  mkdir -p "$work"

  # The server, with STARTTLS on offer unless the case says otherwise; or,
  # with mode=none, no server: a port nothing listens on.  A check sends
  # nothing, so it has no server either.
  if [ "$mode" = none ] || [ "$api" = check ]; then
    smtp_port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
    echo "(no server)" > "$work/transcript"
  else
    srv_args=(--transcript "$work/transcript" --mode "$mode" --port-file "$work/port" --sessions "$sends")
    [ "$mode" != no-starttls ] && srv_args+=(--cert "$out/cert.pem" --key "$out/key.pem")
    python3 "$here/smtpd.py" "${srv_args[@]}" 2> "$work/smtpd.err" &
    srv_pid=$!
    if ! wait_for_file "$work/port" "$srv_pid"; then
      cannot_run "the fake server did not start"; cat "$work/smtpd.err" >&2; stop_case; return
    fi
    smtp_port=$(cat "$work/port")
  fi

  # The application, fresh for every case so that its log and its queue are
  # the case's.  -d3 writes pid=, port= and status= on fd 3 once it listens,
  # and the process that was started exits, leaving the server running.
  sqlite3 "$work/app.db" < "$out/app.sql" >/dev/null   # a PRAGMA in there prints its value
  timeout "$start_limit" env URMAIL_TIMEOUT=2 URWEB_SQLITE_DB_PATH="$work/app.db" "${app_env[@]}" \
    "$out/app/test.exe" -a 127.0.0.1 -p 8000 -P 9000 -d3 3> "$work/handshake" > /dev/null 2> "$work/app.log"
  code=$?
  app_pid=$(sed -n 's/^pid=\([0-9][0-9]*\)$/\1/p' "$work/handshake")
  app_port=$(sed -n 's/^port=\([0-9][0-9]*\)$/\1/p' "$work/handshake")
  if [ "$code" != 0 ] || ! grep -qx "status='OK'" "$work/handshake" || [ -z "$app_pid" ] || [ -z "$app_port" ]; then
    if [ "$code" = 124 ]; then
      cannot_run "the test application did not start within $start_limit s"
    else
      cannot_run "the test application did not start"
    fi
    cat "$work/app.log" >&2; stop_case; return
  fi

  case $url in
    smtp) server="smtp://127.0.0.1:$smtp_port" ;;
    smtps) server="smtps://127.0.0.1:$smtp_port" ;;
    bare) server="127.0.0.1:$smtp_port" ;;
    http) server="http://127.0.0.1:$smtp_port" ;;
  esac
  curl_args=(-s -o "$work/body" -w '%{http_code}' --max-time "$request_limit"
             --data-urlencode "Server=$server"
             --data-urlencode "Tls=$tls" --data-urlencode "Ca=$ca")
  for f in From To Cc Bcc Subject Body Html Srcs User Password MessageId UserAgent Attach1 Attach2 Attach3; do
    v=
    for kv in "${form[@]}"; do
      case $kv in "$f="*) v=${kv#*=} ;; esac
    done
    curl_args+=(--data-urlencode "$f=$v")
  done
  for ((i = 1; i <= sends; ++i)); do
    [ "$i" -gt 1 ] && [ "$pause" != 0 ] && sleep "$pause"
    code=$(curl "${curl_args[@]}" "http://127.0.0.1:$app_port/Test/$handler")
    if [ "$code" != 200 ]; then
      case_failed "request $i $(answered "$code")"; cat "$work/app.log" >&2; stop_case; return
    fi
  done
  if [ "$api" = io ]; then
    # The task sends within a second of the request; wait for as many
    # statuses as there were requests (a hung server takes the timeout).
    deadline=$((SECONDS + status_limit))
    while running "$app_pid"; do
      code=$(curl -s -o "$work/status" -w '%{http_code}' --max-time "$request_limit" \
                  "http://127.0.0.1:$app_port/Test/status")
      if [ "$code" != 200 ]; then
        case_failed "the status request $(answered "$code")"; cat "$work/app.log" >&2; stop_case; return
      fi
      n=$(grep -o '<br />' "$work/status" | wc -l)
      [ "$n" -ge "$sends" ] || [ "$SECONDS" -ge "$deadline" ] && break
      sleep 0.1
    done
  fi
  if ! running "$app_pid"; then
    app_pid=
    case_failed "the application exited during the case"; cat "$work/app.log" >&2; stop_case; return
  fi

  # The application first: it keeps the connection open for the next message,
  # and the server's session ends when it goes.  Then the server, which no
  # client can come to any more: it ends as if its wait had timed out, and
  # writes its transcript.
  stop "$app_pid"
  app_pid=
  if [ -n "$srv_pid" ]; then
    stop "$srv_pid"
    wait "$srv_pid"
    code=$?
    srv_pid=
    if [ "$code" != 0 ]; then
      cannot_run "the fake server failed (exit status $code)"; cat "$work/smtpd.err" >&2; return
    fi
  fi

  {
    if [ "$api" = io ]; then
      echo "--- status"
      text "$work/status"
    else
      echo "--- check"
      text "$work/body"
    fi
    if [ "$api" != check ]; then
      echo "--- server"
      cat "$work/transcript"
    fi
    echo "--- application log"
    # libcurl ends the lines of its trace with CRLF.
    if [ -n "$logfilter" ]; then grep -E "$logfilter" "$work/app.log" | tr -d '\r'; else tr -d '\r' < "$work/app.log"; fi
  } > "$work/actual.raw"
  normalize "$work/actual.raw" > "$work/actual"

  if [ $update = 1 ]; then
    cp "$work/actual" "$dir/expected"
    echo "$case: updated"
  elif [ ! -f "$dir/expected" ]; then
    case_failed "no expected file (run with -u to create it)"
  elif diff -u "$dir/expected" "$work/actual" > "$work/diff"; then
    echo "$case: ok"
  else
    case_failed "the transcript differs"; cat "$work/diff" >&2
  fi
}

for c in "${cases[@]}"; do
  run_case "$c"
done

[ $broken = 1 ] && exit 2
exit $failed
