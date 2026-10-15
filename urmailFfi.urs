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

(* The text of a header (Subject, User-Agent) and a Message-ID, parsed the
   same way. *)
type headerText
val parseHeaderText : string -> headerText
val headerTextProblem : headerText -> option string
val headerTextString : headerText -> string

type messageId
val parseMessageId : string -> messageId
val messageIdProblem : messageId -> option string
val messageIdString : messageId -> string

(* The headers of a message, built up one part at a time.  The builders
   never fail: a part with a problem is remembered, and [problem] reports
   it. *)
type headers

val empty : headers
val from : emailAddress -> headers -> headers
val subject : headerText -> headers -> headers
val user_agent : headerText -> headers -> headers
val message_id : messageId -> headers -> headers
val to : emailAddress -> headers -> headers
val cc : emailAddress -> headers -> headers
val bcc : emailAddress -> headers -> headers

(* What is wrong with the headers, if anything: a part with a problem, no
   From, no recipient. *)
val problem : headers -> option string

(* An attachment, checked as the headers are: [attach] never fails, and
   [attachmentProblem] says what is wrong with what it was given.  The
   arguments: the ASCII name, the UTF-8 name if any, the MIME type, the
   bytes. *)
type attachment
val attach : string -> option string -> string -> blob -> attachment
val attachmentProblem : attachment -> option string

(* A fatal error, for an attachment the caller was sure of and the checks
   refused: the location the caller gave, and what is wrong.  Never
   returns. *)
val refuse : string -> string -> attachment

(* The same part marked inline, to be referred to from the HTML part by
   the cid: URL [cid] gives for it.  The Content-ID is a function of the
   part. *)
val inline : attachment -> attachment
val cid : attachment -> url

(* The attachments of a message, for [send]. *)
type attachments
val noAttachments : attachments
val addAttachment : attachment -> attachments -> attachments

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
                            such recipient, message rejected); or the
                            library would not send it (an inline part with
                            no HTML part to refer to it).  Sending it again
                            will not help. *)
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

(* Send now.  The headers must have passed [problem] and every attachment
   [attachmentProblem]; Urmail.send sees to it. *)
val send : string           (* Server, as a libcurl URL *)
           -> tls
           -> string        (* Username (for SMTP authentication; "" for no login) *)
           -> string        (* Password (for SMTP authentication) *)
           -> headers
           -> string        (* Plain text message body *)
           -> option page   (* Optional HTML version of the message *)
           -> attachments
           -> io sendStatus
