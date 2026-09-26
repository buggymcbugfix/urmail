(** Ur/Web e-mail sending library *)

(* The headers of a message, as [mkHeaders] checked them. *)
type headers

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
		Html : option page    (* the HTML version, if any *)
	} ->
	io sendStatus
