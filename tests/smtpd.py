#!/usr/bin/env python3
"""A fake SMTP server for the tests: one session, scripted, transcribed.

    smtpd.py --transcript FILE [--mode MODE] [--cert PEM --key PEM] [--port-file FILE]

It listens on 127.0.0.1 at a free port, writes the port to --port-file (or
stdout) once listening, serves one session (--sessions N: up to N, one after
the other, each headed in the transcript), writes the transcript and exits.
It waits for a client for --timeout seconds, or until SIGTERM, which says
that none is coming.  The transcript has one line per command and reply,
`C: ...` and `S: ...`, and the message as delivered under `MESSAGE:`, one
line per CRLF line, with the leading dot of a line removed, as a server
undoes dot-stuffing (RFC 5321, section 4.5.2).  What the client sent is
shown as UTF-8, with a backslash doubled, a CR, LF or other control
character but a tab as \\r, \\n or \\xNN, and a byte that is not part of
UTF-8 as \\xNN, so that every line of the transcript is one line of what
was sent.  The credentials of an AUTH PLAIN are decoded so that they can be
read: its three fields, each in quotes.

The modes:

    accept            everything succeeds (the default)
    close-after-one   the connection is closed after the first message is
                      accepted, as a server that limits a session would
    reject-rcpt       every RCPT TO is refused with 550
    defer-rcpt        every RCPT TO is declined with 450, as for greylisting
    reject-data       the message is read in full and then refused with 554
    drop-after-data   the message is read in full and the connection is
                      closed without a reply: the client cannot know
                      whether it was delivered
    drop-before-data  the connection is closed on DATA, before any of the
                      message was sent
    hang              no reply at all after the greeting
    no-starttls       STARTTLS is not offered (and refused)
    reject-auth       every AUTH PLAIN is refused with 535
    reject-bad-rcpt   a RCPT TO whose address contains "bad" is refused with
                      550; the others are accepted
    defer-data        the message is read in full and then declined with 452
    drop-on-reuse     the first message is accepted; when a second MAIL FROM
                      arrives on the same connection, the connection is closed
                      without a reply, as a server does that dropped an idle
                      session; a new connection is served normally
    implicit-tls      the connection is TLS from the first byte (smtps://),
                      and STARTTLS is not offered
    reject-greeting   the greeting is a 554, as a server gives that will not
                      serve this client, and the session goes on from there
    defer-auth        every AUTH PLAIN is declined with 454, a temporary
                      failure
    auth-xoauth2      the only AUTH mechanism offered is XOAUTH2, which
                      libcurl cannot use with a password
    auth-required     MAIL FROM is refused with 530, as a submission server
                      refuses a client that has not logged in
    starttls-drop     STARTTLS is accepted with 220, and the connection is
                      closed instead of the TLS handshake
    reject-mail       MAIL FROM is refused with 550 5.7.1, as a server
                      refuses a sender that the account may not use
    reject-mail-size  MAIL FROM is refused with 552 5.3.4: the message is
                      too big
    rcpt-needs-login  every RCPT TO is refused with 550 5.7.0, as a server
                      refuses to relay for a client that has not logged in
    reject-rcpt-long  every RCPT TO is refused with a reply of three lines
                      and an enhanced status code, as large providers send
    drop-during-data  the connection is closed after the first 64 KiB of the
                      message, while the client is still sending it
    size-limit        SIZE 1000 is offered (RFC 1870): a MAIL FROM that
                      declares more, and a message longer, are refused with
                      552 5.3.4

STARTTLS is offered when --cert and --key are given.  AUTH PLAIN is
offered unless the mode says otherwise; anything else is refused.
--list-modes prints the modes, one per line."""

import argparse
import base64
import os
import re
import signal
import socket
import ssl
import sys
import time

CRLF = b"\r\n"

MODES = ("accept", "close-after-one", "reject-rcpt", "defer-rcpt", "reject-data",
         "drop-after-data", "drop-before-data", "hang", "no-starttls", "reject-auth",
         "reject-bad-rcpt", "defer-data", "drop-on-reuse", "implicit-tls",
         "reject-greeting", "defer-auth", "auth-xoauth2", "auth-required",
         "starttls-drop", "reject-mail", "reject-mail-size", "rcpt-needs-login",
         "reject-rcpt-long", "drop-during-data", "size-limit")

# The SIZE that size-limit offers.
SIZE_LIMIT = 1000
TOO_BIG = "552 5.3.4 message size exceeds fixed maximum message size"

# How much of the message drop-during-data reads before it closes the
# connection.
DROP_AFTER = 64 * 1024


def escape(data):
    """What the client sent, as the transcript shows it (see above)."""
    out = []
    for ch in data.decode("utf-8", "surrogateescape"):
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\n":
            out.append("\\n")
        elif 0xDC80 <= o <= 0xDCFF:  # a byte that is not part of UTF-8
            out.append("\\x%02X" % (o - 0xDC00))
        elif (o < 0x20 and ch != "\t") or o == 0x7F:
            out.append("\\x%02X" % o)
        else:
            out.append(ch)
    return "".join(out)


def quoted(data):
    return '"' + escape(data).replace('"', '\\"') + '"'


class Session:
    def __init__(self, conn, mode, sslctx, transcript):
        self.conn = conn
        self.mode = mode
        self.sslctx = sslctx
        self.transcript = transcript
        self.buf = b""
        self.messages = 0  # accepted on this connection

    def log(self, line):
        self.transcript.append(line)

    def reply(self, text):
        for line in text.split("\n"):
            self.log("S: " + line.rstrip())
        self.conn.sendall(text.replace("\n", "\r\n").encode() + CRLF)

    def readline(self):
        while CRLF not in self.buf:
            chunk = self.conn.recv(4096)
            if not chunk:
                return None
            self.buf += chunk
        line, self.buf = self.buf.split(CRLF, 1)
        return line

    def read_message(self):
        end = CRLF + b"." + CRLF
        data = self.buf
        self.buf = b""
        # The message may legitimately be empty, so the terminator can
        # follow DATA's reply directly: prepend a CRLF for the search.
        haystack = CRLF + data
        while end not in haystack:
            chunk = self.conn.recv(65536)
            if not chunk:
                return None
            data += chunk
            haystack = CRLF + data
        body, rest = haystack.split(end, 1)
        self.buf = rest
        return body[len(CRLF):]

    def log_message(self, body):
        self.log("MESSAGE:")
        for line in body.split(CRLF):
            if line.startswith(b"."):
                line = line[1:]
            text = escape(line)
            self.log("| " + text if text else "|")
        self.log("END")

    def ehlo_reply(self):
        exts = ["250-fake.test"]
        if self.sslctx is not None and not isinstance(self.conn, ssl.SSLSocket) \
                and self.mode != "no-starttls":
            exts.append("250-STARTTLS")
        exts.append("250-8BITMIME")
        if self.mode == "size-limit":
            exts.append("250-SIZE %d" % SIZE_LIMIT)
        exts.append("250 AUTH XOAUTH2" if self.mode == "auth-xoauth2" else "250 AUTH PLAIN")
        return "\n".join(exts)

    def handshake(self):
        """TLS, server side, and whether it was set up.  A client that gives
        up during the handshake may do it by an alert or by closing the
        connection, which may arrive as either, so the two read the same."""
        try:
            self.conn = self.sslctx.wrap_socket(self.conn, server_side=True)
        except (ssl.SSLError, ConnectionError):
            self.log("(TLS handshake failed)")
            return False
        self.log("(TLS established)")
        return True

    def run(self):
        self.reply("554 5.3.2 no service here" if self.mode == "reject-greeting" else "220 fake.test ESMTP")
        if self.mode == "hang":
            # Read until the client gives up, replying to nothing.
            while self.conn.recv(4096):
                pass
            self.log("(client closed the connection)")
            return
        while True:
            line = self.readline()
            if line is None:
                self.log("(client closed the connection)")
                return
            cmd = escape(line)
            verb = cmd.split(" ", 1)[0].upper()
            if verb == "AUTH" and cmd.upper().startswith("AUTH PLAIN"):
                # Either `AUTH PLAIN <blob>` or `AUTH PLAIN`, 334, then the blob.
                words = line.split(b" ", 2)
                if len(words) == 3:
                    blob = words[2]
                else:
                    self.log("C: AUTH PLAIN")
                    self.reply("334 ")
                    blob = self.readline()
                    if blob is None:
                        self.log("(client closed the connection)")
                        return
                try:
                    fields = base64.b64decode(blob, validate=True).split(b"\0")
                except ValueError:
                    fields = []
                if len(fields) == 3:
                    # The authorization identity, the user and the password.
                    self.log("C: [AUTH PLAIN credentials: " + " ".join(quoted(f) for f in fields) + "]")
                else:
                    self.log("C: " + escape(blob))
                self.reply("535 5.7.8 authentication failed" if self.mode == "reject-auth"
                           else "454 4.7.0 temporary authentication failure" if self.mode == "defer-auth"
                           else "235 ok")
                continue
            self.log("C: " + cmd)
            if verb == "EHLO":
                self.reply(self.ehlo_reply())
            elif verb == "HELO":
                self.reply("250 fake.test")
            elif verb == "STARTTLS":
                if self.sslctx is None or self.mode == "no-starttls":
                    self.reply("454 TLS not available")
                    continue
                self.reply("220 go ahead")
                if self.mode == "starttls-drop":
                    self.log("(server closed the connection)")
                    return
                if not self.handshake():
                    return
                self.buf = b""
            elif verb == "AUTH":
                self.reply("504 mechanism not supported")
            elif verb == "MAIL":
                if self.mode == "drop-on-reuse" and self.messages >= 1:
                    self.log("(server closed the connection)")
                    return
                declared = re.search(r" SIZE=([0-9]+)", cmd, re.I)
                self.reply("530 5.7.0 authentication required" if self.mode == "auth-required"
                           else "550 5.7.1 sender address not owned by user" if self.mode == "reject-mail"
                           else TOO_BIG if self.mode == "reject-mail-size"
                           else TOO_BIG if self.mode == "size-limit" and declared
                                           and int(declared.group(1)) > SIZE_LIMIT
                           else "250 ok")
            elif verb == "RCPT":
                if self.mode == "reject-rcpt":
                    self.reply("550 no such user")
                elif self.mode == "defer-rcpt":
                    self.reply("450 try again later")
                elif self.mode == "reject-bad-rcpt" and "bad" in cmd:
                    self.reply("550 no such user")
                elif self.mode == "rcpt-needs-login":
                    self.reply("550 5.7.0 authentication required to relay")
                elif self.mode == "reject-rcpt-long":
                    self.reply("550-5.1.1 The account that you tried to reach does not exist.\n"
                               "550-5.1.1 Please check the address for typos\n"
                               "550 5.1.1 or unnecessary spaces.")
                else:
                    self.reply("250 ok")
            elif verb == "DATA":
                if self.mode == "drop-before-data":
                    self.log("(server closed the connection)")
                    return
                self.reply("354 go ahead")
                if self.mode == "drop-during-data":
                    got = len(self.buf)
                    while got < DROP_AFTER:
                        chunk = self.conn.recv(65536)
                        if not chunk:
                            break
                        got += len(chunk)
                    self.log("(server closed the connection during the message)")
                    return
                body = self.read_message()
                if body is None:
                    self.log("(client closed the connection)")
                    return
                self.log_message(body)
                if self.mode == "drop-after-data":
                    self.log("(server closed the connection)")
                    return
                if self.mode == "reject-data":
                    self.reply("554 rejected")
                elif self.mode == "size-limit" and len(body) > SIZE_LIMIT:
                    self.reply(TOO_BIG)
                elif self.mode == "defer-data":
                    self.reply("452 try again later")
                else:
                    self.reply("250 queued")
                    self.messages += 1
                if self.mode == "close-after-one":
                    self.log("(server closed the connection)")
                    return
            elif verb == "RSET":
                self.reply("250 ok")
            elif verb == "NOOP":
                self.reply("250 ok")
            elif verb == "QUIT":
                self.reply("221 bye")
                return
            else:
                self.reply("500 unknown command")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--transcript")
    ap.add_argument("--mode", default="accept", choices=MODES)
    ap.add_argument("--list-modes", action="store_true")
    ap.add_argument("--cert")
    ap.add_argument("--key")
    ap.add_argument("--port-file")
    def more_than_zero(kind):
        def check(text):
            value = kind(text)
            if not value > 0:
                raise argparse.ArgumentTypeError("must be more than 0")
            return value
        return check

    ap.add_argument("--timeout", type=more_than_zero(float), default=20.0,
                    help="give up waiting for the client after this many seconds")
    ap.add_argument("--sessions", type=more_than_zero(int), default=1,
                    help="serve up to this many sessions, one after the other")
    args = ap.parse_args()
    if args.list_modes:
        print("\n".join(MODES))
        return
    if not args.transcript:
        ap.error("--transcript is required")

    sslctx = None
    if args.cert:
        sslctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sslctx.load_cert_chain(args.cert, args.key)

    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    port = lsock.getsockname()[1]

    # SIGTERM, which the runner sends once the application is gone: no client
    # is coming any more.  While waiting for one, that ends the server as the
    # timeout would; during a session, it ends the server once the session
    # is over, which it is as soon as the client's end is closed.  The
    # handler only notes the signal, and the wait for a client looks at the
    # note every POLL seconds: an exception raised from the handler could
    # arrive anywhere, and a signal that arrives just before accept() blocks
    # does not interrupt it.  The handler is in place before the port is
    # announced, since the runner may send SIGTERM as soon as it knows the
    # port.
    stopping = []
    signal.signal(signal.SIGTERM, lambda signum, frame: stopping.append(signum))

    POLL = 0.1
    lsock.settimeout(POLL)

    def accept():
        """A client, or None once SIGTERM or the timeout says none is coming."""
        deadline = time.monotonic() + args.timeout
        while not stopping and time.monotonic() < deadline:
            try:
                return lsock.accept()[0]
            except socket.timeout:
                pass
        return None

    if args.port_file:
        with open(args.port_file, "w") as f:
            f.write("%d\n" % port)
    else:
        print(port, flush=True)

    transcript = []
    for n in range(args.sessions):
        if args.sessions > 1:
            transcript.append("--- session %d" % (n + 1))
        conn = accept()
        if conn is None:
            transcript.append("(no client connected)")
            break
        conn.settimeout(args.timeout)
        session = Session(conn, args.mode, sslctx, transcript)
        try:
            if args.mode != "implicit-tls" or session.handshake():
                session.run()
        except (ssl.SSLError, ConnectionError):
            # An alert, a reset or an orderly close: the client went away.
            transcript.append("(client closed the connection)")
        except socket.timeout:
            transcript.append("(timed out waiting for the client)")
        finally:
            try:
                session.conn.close()
            except Exception:
                pass
    with open(args.transcript, "w") as f:
        f.write("\n".join(transcript) + "\n")
    # Exit now, not through Python's exit, which restores the default action
    # of SIGTERM before it is done: a SIGTERM from the runner in that window
    # would end the process with a status that says it was killed.
    sys.stdout.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
