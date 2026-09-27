(* The C side of urmail, for Urmail (urmail.ur) to wrap.  Applications use
   Urmail. *)

(* Header values, built up one at a time.  The builders never fail: a value
   they cannot accept is remembered, and [problem] reports it. *)
type headers

val empty : headers
val from : string -> headers -> headers
val subject : string -> headers -> headers
val user_agent : string -> headers -> headers
val messageId : string -> headers -> headers
val to : string -> headers -> headers
val cc : string -> headers -> headers
val bcc : string -> headers -> headers

(* What is wrong with the headers, if anything: a value a builder refused, no
   From, no recipient. *)
val problem : headers -> option string

(* An attachment, checked as the headers are: [attach] never fails, and
   [attachmentProblem] says what is wrong with what it was given.  The
   arguments: the ASCII name, the UTF-8 name if any, the MIME type, the
   bytes. *)
type attachment
val attach : string -> option string -> string -> blob -> attachment
val attachmentProblem : attachment -> option string

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

(* What became of a message. *)
datatype sendStatus =
    Sent
  | NotSent of string    (* Certainly not delivered: the server refused it (a
                            recipient, or the message), or the connection
                            failed before any of the message was uploaded.
                            The string says what happened. *)
  | MaybeSent of string  (* The connection was lost after the upload began
                            and the server's verdict never arrived: the
                            server may or may not have accepted the message.
                            Sending again may deliver it twice. *)

(* Send now.  The headers must have passed [problem] and every attachment
   [attachmentProblem]; Urmail.send sees to it. *)
val send : string           (* Server, as a libcurl URL *)
           -> tls
           -> string        (* Username (for SMTP authentication) *)
           -> string        (* Password (for SMTP authentication) *)
           -> headers
           -> string        (* Plain text message body *)
           -> option page   (* Optional HTML version of the message *)
           -> attachments
           -> io sendStatus
