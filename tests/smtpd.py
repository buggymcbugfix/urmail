#!/usr/bin/env python3
"""A fake SMTP server for the tests: one session, scripted, transcribed.

    smtpd.py --transcript FILE [--mode MODE] [--cert PEM --key PEM] [--port-file FILE]

It listens on 127.0.0.1 at a free port, writes the port to --port-file (or
stdout) once listening, serves one session (--sessions N: up to N, one after
the other, each headed in the transcript), writes the transcript and exits.  The transcript has one line per command and reply, `C: ...` and
`S: ...`, and the message as delivered under `MESSAGE:`, one line per CRLF
line; a CR or LF that is not part of a CRLF shows up as \\r or \\n.  The
credentials of an AUTH PLAIN are decoded so that they can be read.

The modes:

    accept            everything succeeds (the default)
    close-after-one   the connection is closed after the first message is
                      accepted, as a server that limits a session would
    reject-rcpt       every RCPT TO is refused with 550
    reject-data       the message is read in full and then refused with 554
    drop-after-data   the message is read in full and the connection is
                      closed without a reply: the client cannot know
                      whether it was delivered
    drop-before-data  the connection is closed on DATA, before any of the
                      message was sent
    hang              no reply at all after the greeting
    no-starttls       STARTTLS is not offered (and refused)

STARTTLS is offered when --cert and --key are given.  AUTH PLAIN is always
offered; anything else is refused."""

import argparse
import base64
import socket
import ssl
import sys

CRLF = b"\r\n"


class Session:
    def __init__(self, conn, mode, sslctx, transcript):
        self.conn = conn
        self.mode = mode
        self.sslctx = sslctx
        self.transcript = transcript
        self.buf = b""

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
            text = line.decode("utf-8", "backslashreplace")
            text = text.replace("\r", "\\r").replace("\n", "\\n")
            # Dot-stuffing undone, as a real server would.
            if text.startswith(".."):
                text = text[1:]
            self.log("| " + text if text else "|")
        self.log("END")

    def ehlo_reply(self):
        exts = ["250-fake.test"]
        if self.sslctx is not None and not isinstance(self.conn, ssl.SSLSocket) \
                and self.mode != "no-starttls":
            exts.append("250-STARTTLS")
        exts.append("250-8BITMIME")
        exts.append("250 AUTH PLAIN")
        return "\n".join(exts)

    def run(self):
        self.reply("220 fake.test ESMTP")
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
            cmd = line.decode("utf-8", "backslashreplace")
            verb = cmd.split(" ", 1)[0].upper()
            if verb == "AUTH" and cmd.upper().startswith("AUTH PLAIN"):
                # Either `AUTH PLAIN <blob>` or `AUTH PLAIN`, 334, then the blob.
                words = cmd.split(" ", 2)
                if len(words) == 3:
                    blob = words[2]
                else:
                    self.log("C: AUTH PLAIN")
                    self.reply("334 ")
                    line = self.readline()
                    if line is None:
                        self.log("(client closed the connection)")
                        return
                    blob = line.decode("ascii", "replace")
                try:
                    parts = base64.b64decode(blob).split(b"\0")
                    creds = " ".join(p.decode("utf-8", "backslashreplace") for p in parts[1:])
                    self.log("C: [AUTH PLAIN credentials: " + creds + "]")
                except Exception:
                    self.log("C: " + blob)
                self.reply("235 ok")
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
                self.conn = self.sslctx.wrap_socket(self.conn, server_side=True)
                self.buf = b""
                self.log("(TLS established)")
            elif verb == "AUTH":
                self.reply("504 mechanism not supported")
            elif verb == "MAIL":
                self.reply("250 ok")
            elif verb == "RCPT":
                if self.mode == "reject-rcpt":
                    self.reply("550 no such user")
                else:
                    self.reply("250 ok")
            elif verb == "DATA":
                if self.mode == "drop-before-data":
                    self.log("(server closed the connection)")
                    return
                self.reply("354 go ahead")
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
                else:
                    self.reply("250 queued")
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
    ap.add_argument("--transcript", required=True)
    ap.add_argument("--mode", default="accept")
    ap.add_argument("--cert")
    ap.add_argument("--key")
    ap.add_argument("--port-file")
    ap.add_argument("--timeout", type=float, default=20.0,
                    help="give up waiting for the client after this many seconds")
    ap.add_argument("--sessions", type=int, default=1,
                    help="serve up to this many sessions, one after the other")
    args = ap.parse_args()

    sslctx = None
    if args.cert:
        sslctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sslctx.load_cert_chain(args.cert, args.key)

    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    lsock.settimeout(args.timeout)
    port = lsock.getsockname()[1]
    if args.port_file:
        with open(args.port_file, "w") as f:
            f.write("%d\n" % port)
    else:
        print(port, flush=True)

    transcript = []
    for n in range(args.sessions):
        if args.sessions > 1:
            transcript.append("--- session %d" % (n + 1))
        try:
            conn, _ = lsock.accept()
        except socket.timeout:
            transcript.append("(no client connected)")
            break
        conn.settimeout(args.timeout)
        session = Session(conn, args.mode, sslctx, transcript)
        try:
            session.run()
        except ssl.SSLError:
            transcript.append("(TLS error)")
        except ConnectionError:
            # A reset reads like an orderly close: the client went away.
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


if __name__ == "__main__":
    main()
