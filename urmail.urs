(** Ur/Web e-mail sending library *)

(* An e-mail address, as [emailAddress] parsed it from "local@domain" or
   "Name <local@domain>" (blanks around are dropped).  local is of letters,
   digits, !#$%&'*+-/=?^_`{|}~ and single dots between them; domain is
   labels of letters, digits and inner hyphens, joined by dots; both ASCII,
   the whole at most 254 bytes.  Refused: quoted local parts ("a b"@x),
   address literals ([127.0.0.1]), non-ASCII, and anything after the '>'.
   The name may be anything but a line break; a name given in quotes keeps
   its meaning.  [show] gives the text back as it was given. *)
type emailAddress
val emailAddress : string -> result emailAddress
val show_emailAddress : show emailAddress

(* The text of a header, as [headerText] checked it: anything but a line
   break, at most 2000 bytes; encoded and folded when it is long or not
   ASCII.  For Subject and User-Agent.  [show] gives the text back. *)
type headerText
val headerText : string -> result headerText
val show_headerText : show headerText

(* A Message-ID, as [messageId] checked it: "<unique@domain>", without
   blanks or stray brackets.  [show] gives the text back. *)
type messageId
val messageId : string -> result messageId
val show_messageId : show messageId

(* An attachment, as [Attachment.fromBlob] or [Attachment.fromServedFile]
   checked it; or an inline part of the HTML, after [Attachment.inline]. *)
type attachment

datatype tls = datatype UrmailFfi.tls
datatype sendStatus = datatype UrmailFfi.sendStatus

structure Attachment : sig
	(* The name the recipient sees.  AsciiName is the one every client reads
	   (the filename= parameter): printable ASCII, not empty, no '/' or '\',
	   at most 255 bytes.  Utf8Name, if given, is sent beside it for the
	   clients that read RFC 2231 (filename*=), under the same limits but for
	   the ASCII one. *)
	type name =
		{
			AsciiName : string,
			Utf8Name : option string
		}

	val asciiName : string -> name

	(* An attachment, or what is wrong with it.  MimeType is type/subtype,
	   and the project file must allow it (`allow mime`), as it must for
	   Basis.checkMime. *)
	val fromBlob :
		name ->
		{MimeType : string, Data : blob} ->
		result attachment

	(* The same for an attachment the caller is sure of: what [fromBlob]
	   would refuse is a fatal error, prefixed with the first argument,
	   meant to be _LOC_, so that the error names the call. *)
	val blessBlob :
		string (* _LOC_ *) ->
		name ->
		{MimeType : string, Data : blob} ->
		attachment

	(* An attachment holding a file the application serves by a `file`
	   directive of its project file, by the path it is served at: the
	   bytes and the MIME type are the directive's, the type allowed by
	   being declared there.  Fails when nothing is served at the path or
	   no MIME type is known for it. *)
	val fromServedFile :
		name ->
		string (* servedPath *) ->
		result attachment

	(* [fromServedFile] for a caller sure of the path, as [blessBlob]. *)
	val blessServedFile :
		string (* _LOC_ *) ->
		name ->
		string (* servedPath *) ->
		attachment

	(* The same part, marked inline, and the cid: url the HTML part refers
	   to it by, for <img src={u}/> and the like.  The Content-ID is a
	   function of the part, so the two agree.  A message with an inline
	   part and no HTML part is Refused by [send] itself: nothing would
	   refer to the part. *)
	val inline : attachment -> attachment * url
end

(* Send a message through an SMTP server, now, and say what became of it.
   In io, since a send cannot be undone: an io task claims what is to be sent
   in one transaction, sends, and records the status in another.  The
   connection is kept open for the next message to the same server and
   account, until it has been idle for URMAIL_TIMEOUT seconds or more
   than 8 connections are open; and sends to one server and account go
   one at a time, each waiting for the one before it.

   The parts of the headers are what [emailAddress], [headerText] and
   [messageId] checked, so nothing in them can be refused here; a message
   with no recipient among To, Cc and Bcc is Refused, nothing being sent.
   A Message-ID is generated when none is given; give one that is a
   function of the message when the message may be sent more than once (a
   retry after a MaybeSent, say), since receivers recognise a duplicate by
   it.

   A send is given up after URMAIL_TIMEOUT seconds (60 unless set) without
   progress.  URMAIL_DEBUG=1 traces the sends on stderr. *)
val send :
	{
		ServerUrl : string,   (* smtp://host:port, smtps://host:port, or
		                         host:port, which is smtp:// *)
		Tls : tls,
		User : string,        (* for SMTP authentication; "" for no login,
		                         and Password is then not used *)
		Password : string,
		From : emailAddress,
		To : list emailAddress,
		Cc : list emailAddress,
		Bcc : list emailAddress,
		Subject : headerText,
		UserAgent : option headerText,
		MessageId : option messageId,
		Text : string,        (* the plain text body *)
		Html : option page,   (* the HTML version, if any *)
		Attachments : list attachment  (* the attached ones after the body,
		                                  in this order; the inline ones
		                                  with the HTML *)
	} ->
	io sendStatus
