(** Ur/Web e-mail sending library *)

(* To assemble a message, produce a value in this type standing for header values. *)
type headers

val empty : headers

(* Each of the following may be used at most once in constructing a [headers]. *)
val from : string -> headers -> headers
val subject : string -> headers -> headers

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

(* Send out a message by connecting to the given SMTP server. *)
val send : string           (* Server, in CURL URL form *)
           -> tls
           -> string        (* Username (for SMTP authentication) *)
           -> string        (* Password (for SMTP authentication) *)
           -> headers
           -> string        (* Plain text message body *)
           -> option page   (* Optional HTML version of the message *)
           -> transaction unit
