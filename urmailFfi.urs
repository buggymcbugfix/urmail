(* The C side of urmail, for Urmail (urmail.ur) to wrap.  Applications use
   Urmail. *)

(* An address, parsed into its display name and its addr-spec.
   [parseAddress] never fails: what is wrong with what it was given is what
   [addressProblem] says, and [addressString] gives the text back as it was
   given, without the blanks around it. *)
type emailAddress
val parseAddress : string -> emailAddress
val addressProblem : emailAddress -> option string
val addressString : emailAddress -> string

(* A message, built up one field at a time by Urmail.message.  The builders
   never fail: what is wrong is kept, one line for each problem, naming the
   field and the value given, and [problems] gives the lines, in the order
   they were found, joined by newlines.  [lookUpImages] looks up the
   page's img srcs, after [html] and the entries of Images.  [finish] comes
   last: it adds a problem for each part that was not given (From, a
   recipient, Subject, the text, the look-up), and a message that a builder
   changed after it is not finished.  [send] takes only a finished message
   without problems. *)
type message
val start : message
val from : string -> message -> message
val to : string -> message -> message
val cc : string -> message -> message
val bcc : string -> message -> message
val subject : string -> message -> message
val userAgent : string -> message -> message
val messageId : string -> message -> message
val text : string -> message -> message
val html : page -> message -> message
(* An entry of Images: the url, then the Blob's name, MIME type and bytes,
   or the ServedFile's name, if given, and path. *)
val imageBlob : url -> string -> string -> blob -> message -> message
val imageServedFile : url -> option string -> string -> message -> message
(* An attachment, the same way. *)
val attachBlob : string -> string -> blob -> message -> message
val attachServedFile : option string -> string -> message -> message
val lookUpImages : message -> message
val finish : message -> message
val problems : message -> option string

(* How to talk to the server. *)
datatype tls =
    Plain                 (* No TLS. *)
  | Tls of option string  (* TLS, by STARTTLS or an smtps:// URL, with the
                             server's certificate verified: against the CA
                             file given, or the system's CAs if None. *)
  | TlsNoVerify           (* TLS without verifying the certificate. For a
                             development server with a self-signed
                             certificate; never for production, since anyone
                             on the path can then read the credentials. *)

(* What became of a message.  Where the server answered, the string is its
   reply and the command it answered; otherwise what libcurl said. *)
datatype sendStatus =
    Sent
  | Refused of string    (* The server refused the message for good: a 5xx
                            reply to MAIL FROM, RCPT TO or after DATA (no
                            such recipient, message rejected).  Sending it
                            again will not help. *)
  | NotSent of string    (* Not delivered, for now: the server declined with
                            a 4xx reply (mailbox busy, storage short,
                            greylisting, a temporary failure of the login),
                            or the connection failed before any of the
                            message was uploaded.  Worth another try
                            later. *)
  | MaybeSent of string  (* The connection was lost after the upload began
                            and the server's verdict never arrived: the
                            server may or may not have accepted the message.
                            Sending again may deliver it twice. *)
  | Failed of string     (* Nothing was tried against the message: the
                            server URL is not an smtp:// or smtps:// one,
                            TLS could not be set up or the certificate did
                            not verify, or the server refused the session
                            with a 5xx before MAIL FROM (to the greeting,
                            EHLO, STARTTLS or the login).  The same call
                            fails the same way until the configuration is
                            changed; the message itself is fine. *)

(* Send now.  The message must be finished and without problems, as one
   that Urmail.message returned is; any other is a fatal error. *)
val send : string           (* Server, as a libcurl URL *)
           -> tls
           -> string        (* Username (for SMTP authentication; "" for no login) *)
           -> string        (* Password (for SMTP authentication) *)
           -> message
           -> io sendStatus
