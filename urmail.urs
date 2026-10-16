(** Ur/Web e-mail sending library *)

(* An e-mail address: "local@domain" or "Name <local@domain>", blanks
   around dropped.  local is of letters, digits, !#$%&'*+-/=?^_`{|}~ and
   single dots between them; domain is labels of letters, digits and inner
   hyphens, joined by dots; both ASCII, the whole at most 254 bytes.
   Quoted local parts ("a b"@x), address literals ([127.0.0.1]) and
   anything after the '>' are refused.  The name may be anything but a
   line break; a name given in quotes keeps its meaning.  [message] parses
   its addresses this way; this is for checking one on its own, a form
   field say.  [show] gives the text back. *)
type emailAddress
val emailAddress : string -> result emailAddress
val show_emailAddress : show emailAddress

(* An attachment, or an image of the HTML version, as given; [message]
   checks it.  Name is what the recipient sees: not empty, at most 255
   bytes, no control character, '/' or '\'.  A name that is not ASCII is
   sent as an RFC 2231 filename*, beside an ASCII copy with '_' for each
   other character, for clients that do not read filename*.  A Blob's
   MimeType is type/subtype and must be allowed by the project file
   (`allow mime`).  A ServedFile is the file a `file` directive serves at
   exactly ServedPath, with the directive's bytes and MIME type; its name
   is the path's last segment unless Name gives one.  A text/* attachment
   whose bytes are UTF-8, and not all ASCII, is labelled charset=utf-8;
   one in another encoding goes out without a charset, which means
   US-ASCII. *)
datatype attachment =
	| Blob of {Name : string, MimeType : string, Data : blob}
	| ServedFile of {Name : option string, ServedPath : string}

(* A message, as [message] checked it. *)
type message

(* A message, or everything that is wrong with it, one line per problem,
   each naming the field and the value given (cut after 60 characters,
   line breaks escaped):

   - From, To, Cc and Bcc, as [emailAddress] parses them, and a recipient
     among To, Cc and Bcc;
   - Subject and UserAgent: no line break, at most 2000 bytes;
   - MessageId: RFC 5322's "<left@right>": printable ASCII, left of
     atext and single dots (as an address's local part), right the same
     or a domain literal in brackets, the whole at most 986 bytes, which
     fills the header's one line (a Message-ID cannot be folded);
   - each attachment, and each image of HtmlBody;
   - Images: each url at most once, and each used by an img src of the
     page;
   - each img src of the page that no entry of Images names, has no
     scheme and does not start with "//": a file directive serving
     exactly that path, which then gives the image, as a ServedFile.

   In the message as sent, each src that an entry of Images names, or that
   a file directive serves, points at its image, which goes with the HTML
   version; other srcs are left as they are.  The page itself is not
   changed, so it can be served to a browser as it is.  Images that are the
   same (name, type and bytes) are sent once.  The attachments go after the
   body, in the order of the list.  The texts are sent as given, labelled
   UTF-8.  In the headers, a word that is not ASCII, or looks like an RFC
   2047 encoded word, goes out as encoded words in Q encoding, which
   leaves its ASCII readable, and a long value is folded at its blanks
   into lines of at most 78 characters, where its words allow.  A
   Message-ID is generated when none is given; give one that is a
   function of the message when it may be sent more than once (a retry
   after a MaybeSent, say), since receivers recognise a duplicate by it. *)
val message :
	{
		From : string,
		To : list string,
		Cc : list string,
		Bcc : list string,
		Subject : string,
		UserAgent : option string,
		MessageId : option string,
		PlainTextBody : string,
		HtmlBody : option {Page : page, Images : list (url * attachment)},
		Attachments : list attachment
	} ->
	result message

datatype tls = datatype UrmailFfi.tls
datatype sendStatus = datatype UrmailFfi.sendStatus

(* Send a message through an SMTP server, now, and say what became of it.
   In io, since a send cannot be undone: an io task builds and claims the
   message in one transaction, sends it, and records the status in
   another.  The connection is kept open for the next message to the same
   server and account, until it has been idle for URMAIL_TIMEOUT seconds or
   more than 8 connections are open; sends to one server and account go
   one at a time.  A send is given up after URMAIL_TIMEOUT seconds (100
   unless set) without progress.  URMAIL_DEBUG=1 traces the sends on
   stderr. *)
val send :
	{
		ServerUrl : string,   (* smtp://host:port, smtps://host:port, or
		                         host:port, which is smtp:// *)
		Tls : tls,
		User : string,        (* "" for no login; Password is then not used *)
		Password : string,
		Message : message
	} ->
	io sendStatus
