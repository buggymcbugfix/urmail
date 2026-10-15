type emailAddress = UrmailFfi.emailAddress
type headerText = UrmailFfi.headerText
type messageId = UrmailFfi.messageId
type attachment = UrmailFfi.attachment

datatype tls = datatype UrmailFfi.tls
datatype sendStatus = datatype UrmailFfi.sendStatus

(* A part, parsed, or what is wrong with it. *)
fun parsed [t] (parse : string -> t) (problem : t -> option string) (s : string) : result t =
	let
		val v = parse s
	in
		case problem v of
		| None => Success v
		| Some e => Failure <xml>{[e]}</xml>
	end

val emailAddress = parsed UrmailFfi.parseAddress UrmailFfi.addressProblem
val show_emailAddress = mkShow UrmailFfi.addressString

val headerText = parsed UrmailFfi.parseHeaderText UrmailFfi.headerTextProblem
val show_headerText = mkShow UrmailFfi.headerTextString

val messageId = parsed UrmailFfi.parseMessageId UrmailFfi.messageIdProblem
val show_messageId = mkShow UrmailFfi.messageIdString

structure Attachment = struct
	type name = {AsciiName : string, Utf8Name : option string}

	fun asciiName s = {AsciiName = s, Utf8Name = None}

	(* An attachment, or what is wrong with it, as text: a Failure for the
	   from* functions, a fatal error for the bless* ones. *)
	datatype checked = Ok of attachment | Bad of string

	fun named (n : name) what = "Attachment \"" ^ n.AsciiName ^ "\": " ^ what

	fun built (n : name) a =
		case UrmailFfi.attachmentProblem a of
		| None => Ok a
		| Some e => Bad (named n e)

	fun blob (n : name) r =
		case checkMime r.MimeType of
		| None => Bad (named n ("MIME type " ^ r.MimeType ^ " is not allowed by the project file"))
		| Some _ => built n (UrmailFfi.attach n.AsciiName n.Utf8Name r.MimeType r.Data)

	fun served (n : name) path =
		case checkServedFile path of
		| None => Bad (named n ("no file directive serves " ^ path))
		| Some f =>
			if fileMimeType f = "" then
				Bad (named n ("no MIME type is known for " ^ path ^ "; give one in its file directive"))
			else
				built n (UrmailFfi.attach n.AsciiName n.Utf8Name (fileMimeType f) (fileData f))

	fun result c =
		case c of
		| Ok a => Success a
		| Bad e => Failure <xml>{[e]}</xml>

	(* A refusal of what the caller was sure of is the caller's mistake. *)
	fun bless loc c =
		case c of
		| Ok a => a
		| Bad e => UrmailFfi.refuse loc e

	fun fromBlob n r = result (blob n r)
	fun blessBlob loc n r = bless loc (blob n r)
	fun fromServedFile n path = result (served n path)
	fun blessServedFile loc n path = bless loc (served n path)

	fun inline a =
		let
			val a = UrmailFfi.inline a
		in
			(a, UrmailFfi.cid a)
		end
end

fun send r =
	let
		fun opt [t ::: Type] (f : t -> UrmailFfi.headers -> UrmailFfi.headers) (v : option t) h =
			case v of
			| None => h
			| Some s => f s h

		fun all f xs h = List.foldl f h xs

		val h =
			UrmailFfi.empty
				|> UrmailFfi.from r.From
				|> UrmailFfi.subject r.Subject
				|> opt UrmailFfi.user_agent r.UserAgent
				|> opt UrmailFfi.message_id r.MessageId
				|> all UrmailFfi.to r.To
				|> all UrmailFfi.cc r.Cc
				|> all UrmailFfi.bcc r.Bcc
	in
		case UrmailFfi.problem h of
		| Some e => return (Refused e)
		| None =>
			UrmailFfi.send r.ServerUrl r.Tls r.User r.Password h r.Text r.Html
				(List.foldl UrmailFfi.addAttachment UrmailFfi.noAttachments r.Attachments)
	end
