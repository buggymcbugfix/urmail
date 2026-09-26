(** Ur/Web e-mail sending library *)

(* To assemble a message, produce a value in this type standing for header values. *)
type headers

val empty : headers

(* Each of the following may be used at most once in constructing a [headers]. *)
val from : string -> headers -> headers
val subject : string -> headers -> headers
val user_agent : string -> headers -> headers
val messageId : string -> headers -> headers
(* The Message-ID header, "<unique@domain>".  One is generated when none is
   given.  Give one that is a function of the message when the message may be
   sent more than once (a retry after a failure whose outcome was unknown, say):
   receivers recognise a duplicate by it. *)

(* The following must be called with single valid e-mail address arguments, and
 * all such addresses passed are combined into single header values. *)
val to : string -> headers -> headers
val cc : string -> headers -> headers
val bcc : string -> headers -> headers

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

(* Send out a message through the given SMTP server, once the transaction has
   committed.  The connection is kept open for the next message to the same
   server and account.

   A failure is an error of the transaction, after its commit, with a message
   starting in "urmail: not sent:" when the message certainly did not go out
   (the server refused it, or the connection failed before any of it was
   uploaded), or "urmail: outcome unknown:" when the connection was lost after
   the upload began and the server's verdict never arrived.  A retry in the
   second case may deliver the message twice; see [messageId].

   A send is given up after URMAIL_TIMEOUT seconds (60 unless set) without
   progress.  URMAIL_DEBUG=1 traces the sends on stderr. *)
val send : string           (* Server, in CURL URL form *)
           -> tls
           -> string        (* Username (for SMTP authentication) *)
           -> string        (* Password (for SMTP authentication) *)
           -> headers
           -> string        (* Plain text message body *)
           -> option page   (* Optional HTML version of the message *)
           -> transaction unit
