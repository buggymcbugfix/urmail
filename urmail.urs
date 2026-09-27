(** Ur/Web e-mail sending library *)

(* The headers of a message, as [mkHeaders] checked them. *)
type headers

(* An attachment, as [Attachment.fromBlob] checked it. *)
type attachment

datatype tls = datatype UrmailFfi.tls
datatype sendStatus = datatype UrmailFfi.sendStatus

(* The headers of a message, or what is wrong with them: an address is
   "addr@domain" or "Name <addr@domain>", no value may contain a line break,
   there has to be a recipient among To, Cc and Bcc, and a MessageId given has
   the form "<unique@domain>".  One is generated when none is given; give one
   that is a function of the message when the message may be sent more than
   once (a retry after a MaybeSent, say), since receivers recognise a
   duplicate by it. *)
val mkHeaders :
	{
		From : string,
		Subject : string,
		UserAgent : option string,
		MessageId : option string,
		To : list string,
		Cc : list string,
		Bcc : list string
	} ->
	result headers

structure Attachment : sig
	(* An attachment, or what is wrong with it.  AsciiName is the name every
	   client reads (the filename= parameter): printable ASCII, not empty, no
	   '/' or '\', at most 255 bytes.  Utf8Name, if given, is sent beside it
	   for the clients that read RFC 2231 (filename*=), under the same limits
	   but for the ASCII one.  MimeType is type/subtype, and the project file
	   must allow it (`allow mime`), as it must for Basis.checkMime. *)
	val fromBlob :
		{
			AsciiName : string,
			Utf8Name : option string,
			MimeType : string,
			Data : blob
		} ->
		result attachment
end

(* Send a message through an SMTP server, now, and say what became of it.
   In io, since a send cannot be undone: an io task claims what is to be sent
   in one transaction, sends, and records the status in another.  The
   connection is kept open for the next message to the same server and
   account.

   A send is given up after URMAIL_TIMEOUT seconds (60 unless set) without
   progress.  URMAIL_DEBUG=1 traces the sends on stderr. *)
val send :
	{
		ServerUrl : string,   (* smtp://host:port or smtps://host:port *)
		Tls : tls,
		User : string,        (* for SMTP authentication *)
		Password : string,
		Headers : headers,
		Text : string,        (* the plain text body *)
		Html : option page,   (* the HTML version, if any *)
		Attachments : list attachment  (* after the body, in this order *)
	} ->
	io sendStatus
