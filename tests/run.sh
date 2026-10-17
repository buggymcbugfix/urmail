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
#               told; starttls-badca names a CA file that does not exist),
#               form=(...) (the fields of the request, curl -d style;
#               Attach1..3 spell attachments and images, Srcs lists the
#               img srcs of the HTML version, and Markup picks more markup
#               for it, see tests/app/test.ur),
#               sends=N (the request is made N times; the server then
#               serves up to N sessions, one after the other, or all at
#               once with concurrent=1), vary=FIELD (the field's value has
#               the request's number appended, 1 to N), pause=SECONDS
#               (slept between the requests), url=smtp|bare|smtps|http|smtp-path|smtp-userinfo|empty|unresolvable
#               (how the server is named: smtp://host:port, host:port alone,
#               smtps://host:port, an http:// URL, which must be refused,
#               smtp://host:port/mail.example.com, whose path libcurl sends
#               as the EHLO name, smtp://mallory:stolen@host:port, with
#               credentials in it, an empty string, or
#               smtp://nonexistent.invalid:25, a host name that does not
#               resolve),
#               app_env=(NAME=VALUE ...) (added to the application's
#               environment), logfilter=REGEX (only the lines of the
#               application's log that match, grep -E, are transcribed),
#               api=io|check|ffi|parallel (the message is
#               queued and sent by the application's io task, the default,
#               or only checked by Urmail.message, or made by the task with
#               UrmailFfi's builders and sent with UrmailFfi.send, or sent
#               by whichever of two io tasks takes it first, which run at
#               the same time; the transcript's first part is the statuses
#               the tasks recorded, or what Urmail.message said; a task
#               that dies records none, and the log says why).  The file runs in a shell of its own,
#               under set -u; a setting with a value not listed here, or a
#               variable that is not a setting and whose name does not
#               start with '_', means the case cannot run.
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
# the source tree works and nothing is written into the source tree.  Runs
# in one build tree take turns.
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
unset CDPATH  # with it, cd prints the directory, into the paths below

die() { echo "run.sh: $*" >&2; exit 2; }

# Every path absolute, since the compiler and the application run in other
# directories.
here=$(cd "$(dirname "$0")" && pwd)
top=$(cd "$here/.." && pwd)
build=$(cd "${BUILDDIR:-$top}" 2>/dev/null && pwd) || die "BUILDDIR=${BUILDDIR:-} is not a directory"
out=$build/tests/out
urweb=${URWEB:-urweb}
case $urweb in
  */*) d=$(cd "$(dirname "$urweb")" 2>/dev/null && pwd) || die "URWEB=$urweb: no such directory"
       urweb=$d/$(basename "$urweb") ;;
  *) found=$(command -v "$urweb") || die "no $urweb on the PATH: set URWEB or put it there"
     urweb=$found ;;
esac
[ -f "$urweb" ] && [ -x "$urweb" ] || die "URWEB=$urweb is not an executable"
urweb_flags=${URWEB_FLAGS:-}

# URMAIL_TIMEOUT for the application, in seconds: a send gives up after
# this long without progress, and a connection idle for longer is closed at
# the next send.  The cases' comments and pauses are written against it.
urmail_timeout=2

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

for tool in python3 openssl curl sqlite3 timeout; do
  command -v "$tool" >/dev/null || die "$tool is needed"
done
modes=$(python3 "$here/smtpd.py" --list-modes) || die "smtpd.py does not run"
modes=$(echo "$modes" | tr '\n' ' ')
fields="From To Cc Bcc Subject Body Html Srcs User Password MessageId UserAgent Attach1 Attach2 Attach3 Markup"
is_field() {
  local x
  for x in $fields; do [ "$x" = "$1" ] && return 0; done
  return 1
}
[ -f "$build/tests/config.urp" ] || die "tests/config.urp is missing: run configure and make first"

if [ $# -gt 0 ]; then
  cases=("$@")
  # A name is a directory under tests/cases, nothing that could be a path.
  for c in "${cases[@]}"; do
    [[ $c =~ ^[A-Za-z0-9_-]+$ ]] || die "$c is not a case name: letters, digits, '-' and '_' only"
  done
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

# One run at a time in a build tree, since a run starts by deleting
# tests/out.  The lock is a directory, made atomically, holding the pid of
# the run that made it; a lock whose run is gone is taken over.  The run is
# gone when its pid is, or belongs to another program now (/proc says, where
# there is one), or when the lock has had no pid file for a while: the pid
# is written right after mkdir, so a lock without one is a run that died
# between the two, or a stray directory.
lock=$build/tests/out.lock
locked=0
lock_grace=10
lock_is_stale() {
  local owner
  owner=$(cat "$lock/pid" 2>/dev/null)
  if [ -n "$owner" ]; then
    running "$owner" || return 0
    [ -r "/proc/$owner/cmdline" ] && ! grep -qa "run\.sh" "/proc/$owner/cmdline" && return 0
    return 1
  fi
  [ $(( $(date +%s) - $(stat -c %Y "$lock" 2>/dev/null || date +%s) )) -gt $lock_grace ]
}
take_lock() {
  local said=0
  until mkdir "$lock" 2>/dev/null; do
    if lock_is_stale; then
      rm -rf "$lock"
      continue
    fi
    [ $said = 1 ] || echo "run.sh: waiting for the run in $build$(sed -n 's/^/ (pid /; s/$/)/p' "$lock/pid" 2>/dev/null) to end" >&2
    said=1
    sleep 1
  done
  echo $$ > "$lock/pid"
  locked=1
}

trap 'stop_case; [ $locked = 0 ] || rm -rf "$lock"' EXIT
trap 'exit 2' HUP INT TERM
take_lock

rm -rf "$out"
mkdir -p "$out"

# The application and the examples, copied, and made writable, since the
# source tree may not be (make distcheck makes it read-only), and the
# compiler writes next to the .urp.  Over them, lib.urp: the library's own,
# with the sources named by absolute path, so that its config.urp is the
# build tree's, copied next to it.
cp -r "$here/app" "$out/app"
cp -r "$top/examples" "$out/examples"
chmod -R u+w "$out/app" "$out/examples"
cp "$build/tests/config.urp" "$out/config.urp"
while IFS= read -r line; do
  case $line in
    "ffi "*) printf 'ffi %s/%s\n' "$top" "${line#ffi }" ;;
    ""|"#"*|"$/"*|*" "*) printf '%s\n' "$line" ;;
    *) printf '%s/%s\n' "$top" "$line" ;;
  esac
done < "$top/lib.urp" > "$out/lib.urp"

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

# Replace what varies from run to run, each where it occurs and nowhere
# else, so that the same text in a message's body stays as it is: the
# client's host name in the EHLO command; the date and a generated
# Message-ID (24 hex digits) in a message's headers, which run from
# MESSAGE: to the first empty line; the declared size with its MAIL FROM;
# the fake server's port after smtp:// or smtps://, in the library's log
# and in statuses, and in libcurl's trace lines; the milliseconds libcurl
# gives for a timeout; the port and the milliseconds in libcurl's text for
# a connection that failed.
normalize() {
  awk '
    /^C: EHLO / { $0 = "C: EHLO <host>" }
    /^MESSAGE:$/ { headers = 1 }
    headers && /^\|$/ { headers = 0 }
    headers && /^\| Date: / { $0 = "| Date: <date>" }
    headers && match($0, /^\| Message-ID: <[0-9a-f]+@/) && RLENGTH == 40 { $0 = "| Message-ID: <generated@" substr($0, RLENGTH + 1) }
    index($0, "MAIL FROM:<") && match($0, /> SIZE=[0-9]+/) { $0 = substr($0, 1, RSTART) " SIZE=<size>" substr($0, RSTART + RLENGTH) }
    { gsub(/smtp:\/\/127\.0\.0\.1:[0-9]+/, "smtp://127.0.0.1:<port>"); gsub(/smtps:\/\/127\.0\.0\.1:[0-9]+/, "smtps://127.0.0.1:<port>") }
    /^\* / { gsub(/127\.0\.0\.1:[0-9]+/, "127.0.0.1:<port>"); gsub(/ port [0-9]+/, " port <port>") }
    /^\* Operation timed out after [0-9]+ milliseconds/ { sub(/after [0-9]+ milliseconds/, "after <ms> milliseconds") }
    /Failed to connect to 127\.0\.0\.1:[0-9]+ / { sub(/127\.0\.0\.1:[0-9]+/, "127.0.0.1:<port>"); sub(/ after [0-9]+ ms/, " after <ms> ms") }
    { print }
  ' "$1"
}

# Pages as text: one line per <br /> or line break, without the markup and
# the empty lines, and with the entities decoded, the numeric ones too
# (the runtime writes a character that is not ASCII as one).
text() {
  python3 -c '
import html, re, sys
sys.stdout.reconfigure(encoding="utf-8", errors="surrogateescape")
page = open(sys.argv[1], encoding="utf-8", errors="surrogateescape").read()
for line in re.split(r"<br />|\n", page):
    line = html.unescape(re.sub(r"<[^>]*>", "", line))
    if line:
        print(line)
' "$1"
}

failed=0
broken=0
# The verdicts other than ok.  Each case reports at most one.
case_failed() { echo "$case: FAILED: $*" >&2; failed=1; }
cannot_run() { echo "$case: could not run: $*" >&2; broken=1; }
# A failure during the case: the application's log says what happened.
failed_with_log() { case_failed "$@"; cat "$work/app.log" >&2; stop_case; }

# What became of a request, by curl's %{http_code}.
answered() {
  if [ "$1" = 000 ]; then echo "got no answer"; else echo "was answered with HTTP $1"; fi
}

# A case's settings, read from its args file (the header above).  The file
# runs in a subshell, so that a syntax error, an unset variable or an exit
# in it ends only that; the settings come back as declare lines.
read_args() {
  (
    set -u
    mode=accept
    tls=none
    form=()
    sends=1
    concurrent=0
    vary=
    pause=0
    api=io
    url=smtp
    app_env=()
    logfilter=
    _before=$(compgen -v | sort)
    # shellcheck disable=SC1090
    . "$1" || exit
    _unknown=$(comm -13 <(echo "$_before") <(compgen -v | sort) | grep -v -e '^_' -e '^BASH_')
    if [ -n "$_unknown" ]; then
      echo "not a setting:" $_unknown >&2
      exit 1
    fi
    declare -p mode tls form sends concurrent vary pause api url app_env logfilter
  )
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
  local settings ca server handler smtp_port app_port f kv code i n deadline
  local -a srv_args curl_args
  local -A value=()

  # A directory of its own, emptied: nothing of an earlier run, or of an
  # earlier case of the same name, can make it pass.
  rm -rf "$work"
  mkdir -p "$work"

  [ -f "$dir/args" ] || { cannot_run "no args file"; return; }
  if ! settings=$(read_args "$dir/args" 2> "$work/args.err") || [ -z "$settings" ]; then
    [ -s "$work/args.err" ] || echo "it ended before its last line" > "$work/args.err"
    cannot_run "its args file failed: $(tr '\n' ' ' < "$work/args.err")"; return
  fi
  # The settings, as variables of this function.
  eval "$settings"

  case " none $modes" in
    *" $mode "*) ;;
    *) cannot_run "unknown mode $mode"; return ;;
  esac
  case $tls in
    none|starttls|starttls-noverify) ca= ;;
    starttls-ca) ca=$out/cert.pem ;;
    starttls-badca) ca=$out/no-such-ca.pem; tls=starttls-ca ;;
    *) cannot_run "unknown tls setting $tls"; return ;;
  esac
  case $url in
    smtp|smtps|bare|http|smtp-path|smtp-userinfo|empty|unresolvable) ;;
    *) cannot_run "unknown url form $url"; return ;;
  esac
  case $api in
    io) handler=queue ;;
    check) handler=check ;;
    ffi) handler=queueFfi ;;
    parallel) handler=queueParallel ;;
    *) cannot_run "unknown api $api"; return ;;
  esac
  [[ $sends =~ ^[1-9][0-9]*$ ]] || { cannot_run "sends=$sends is not a number of requests"; return; }
  [[ $concurrent =~ ^[01]$ ]] || { cannot_run "concurrent=$concurrent is not 0 or 1"; return; }
  if [ -n "$vary" ]; then
    is_field "$vary" || { cannot_run "vary=$vary is not a field"; return; }
  fi
  # No leading zero: bash would read the number as octal.
  [[ $pause =~ ^(0|[1-9][0-9]*)$ ]] || { cannot_run "pause=$pause is not a whole number of seconds"; return; }
  for kv in "${form[@]}"; do
    f=${kv%%=*}
    is_field "$f" || { cannot_run "form has ${f:0:40}, which is not a field"; return; }
    [[ $kv == *=* ]] || { cannot_run "form has $f, which is not NAME=VALUE"; return; }
    [ -z "${value[$f]+set}" ] || { cannot_run "form gives $f twice"; return; }
    value[$f]=${kv#*=}
  done
  for kv in "${app_env[@]}"; do
    [[ $kv =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || { cannot_run "app_env has ${kv:0:40}, which is not NAME=VALUE"; return; }
  done
  if [ -n "$logfilter" ]; then
    grep -E -e "$logfilter" < /dev/null 2> "$work/args.err"
    [ $? -le 1 ] || { cannot_run "logfilter: $(tr '\n' ' ' < "$work/args.err")"; return; }
  fi

  # The server, with STARTTLS on offer unless the case says otherwise; or,
  # with mode=none, no server: a port nothing listens on.  A check sends
  # nothing, so it has no server either.
  if [ "$mode" = none ] || [ "$api" = check ]; then
    smtp_port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
    echo "(no server)" > "$work/transcript"
  else
    # The server waits for a client, and for each command, longer than the
    # case can take: through its pauses, and then as long as the runner
    # waits for the statuses.
    srv_args=(--transcript "$work/transcript" --mode "$mode" --port-file "$work/port" --sessions "$sends"
              --timeout $((pause * sends + status_limit)))
    [ "$concurrent" = 1 ] && srv_args+=(--concurrent)
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
  timeout "$start_limit" env URMAIL_TIMEOUT=$urmail_timeout URWEB_SQLITE_DB_PATH="$work/app.db" "${app_env[@]}" \
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
    smtp-path) server="smtp://127.0.0.1:$smtp_port/mail.example.com" ;;
    smtp-userinfo) server="smtp://mallory:stolen@127.0.0.1:$smtp_port" ;;
    empty) server= ;;
    unresolvable) server="smtp://nonexistent.invalid:25" ;;
  esac
  curl_args=(-s -o "$work/body" -w '%{http_code}' --max-time "$request_limit"
             --data-urlencode "Server=$server"
             --data-urlencode "Tls=$tls" --data-urlencode "Ca=$ca")
  # The values from files, since one on the command line is limited to 128
  # KiB.  An empty file gives no field at all, so an empty value is given
  # as such.
  mkdir "$work/fields"
  for f in $fields; do
    [ "$f" = "$vary" ] && continue
    if [ -n "${value[$f]-}" ]; then
      printf '%s' "${value[$f]}" > "$work/fields/$f"
      curl_args+=(--data-urlencode "$f@$work/fields/$f")
    else
      curl_args+=(--data-urlencode "$f=")
    fi
  done
  for ((i = 1; i <= sends; ++i)); do
    [ "$i" -gt 1 ] && [ "$pause" != 0 ] && sleep "$pause"
    if [ -n "$vary" ]; then
      printf '%s%d' "${value[$vary]-}" "$i" > "$work/fields/$vary"
      code=$(curl "${curl_args[@]}" --data-urlencode "$vary@$work/fields/$vary" \
                  "http://127.0.0.1:$app_port/Test/$handler")
    else
      code=$(curl "${curl_args[@]}" "http://127.0.0.1:$app_port/Test/$handler")
    fi
    if [ "$code" != 200 ]; then
      failed_with_log "request $i $(answered "$code")"; return
    fi
  done
  if [ "$api" != check ]; then
    # The task sends within a second of the request; wait for as many
    # statuses as there were requests (a hung server takes the timeout), or
    # for the task to die, which the runtime logs: a send that refuses its
    # message ends the task's run before any status is recorded.
    deadline=$((SECONDS + status_limit))
    while running "$app_pid"; do
      code=$(curl -s -o "$work/status" -w '%{http_code}' --max-time "$request_limit" \
                  "http://127.0.0.1:$app_port/Test/status")
      if [ "$code" != 200 ]; then
        failed_with_log "the status request $(answered "$code")"; return
      fi
      n=$(grep -o '<br />' "$work/status" | wc -l)
      [ "$n" -ge "$sends" ] || grep -q '^Fatal error in io task' "$work/app.log" || [ "$SECONDS" -ge "$deadline" ] && break
      sleep 0.1
    done
  fi
  if ! running "$app_pid"; then
    app_pid=
    failed_with_log "the application exited during the case"; return
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
    if [ "$api" != check ]; then
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
    if [ -n "$logfilter" ]; then grep -E -e "$logfilter" "$work/app.log" | tr -d '\r'; else tr -d '\r' < "$work/app.log"; fi
  } > "$work/actual.raw"
  normalize "$work/actual.raw" > "$work/actual"

  if [ $update = 1 ]; then
    cp "$work/actual" "$dir/expected" || { cannot_run "its expected file cannot be written"; return; }
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
