type headers = UrmailFfi.headers
type attachment = UrmailFfi.attachment

datatype tls = datatype UrmailFfi.tls
datatype sendStatus = datatype UrmailFfi.sendStatus

fun mkHeaders r =
	let
		fun opt f v h =
			case v of
			| None => h
			| Some s => f s h

		fun all f xs h = List.foldl f h xs

		val h =
			UrmailFfi.empty
				|> UrmailFfi.from r.From
				|> UrmailFfi.subject r.Subject
				|> opt UrmailFfi.user_agent r.UserAgent
				|> opt UrmailFfi.messageId r.MessageId
				|> all UrmailFfi.to r.To
				|> all UrmailFfi.cc r.Cc
				|> all UrmailFfi.bcc r.Bcc
	in
		case UrmailFfi.problem h of
		| None => Success h
		| Some e => Failure <xml>{[e]}</xml>
	end

structure Attachment = struct
	fun checked name a =
		case UrmailFfi.attachmentProblem a of
		| None => Success a
		| Some e => Failure <xml>Attachment "{[name]}": {[e]}</xml>

	fun fromBlob r =
		case checkMime r.MimeType of
		| None =>
			Failure <xml>Attachment "{[r.AsciiName]}": MIME type {[r.MimeType]} is not allowed by the project file</xml>
		| Some _ =>
			checked r.AsciiName (UrmailFfi.attach r.AsciiName r.Utf8Name r.MimeType r.Data)

	fun fromFile r =
		case checkServedFile r.ServedPath of
		| None => Failure <xml>Attachment "{[r.AsciiName]}": no file directive serves {[r.ServedPath]}</xml>
		| Some f =>
			if fileMimeType f = "" then
				Failure <xml>Attachment "{[r.AsciiName]}": no MIME type is known for {[r.ServedPath]}; give one in its file directive</xml>
			else
				checked r.AsciiName (UrmailFfi.attach r.AsciiName r.Utf8Name (fileMimeType f) (fileData f))

	fun inline a =
		let
			val a = UrmailFfi.inline a
		in
			(a, UrmailFfi.cid a)
		end
end

fun send r =
	UrmailFfi.send r.ServerUrl r.Tls r.User r.Password r.Headers r.Text r.Html
		(List.foldl UrmailFfi.addAttachment UrmailFfi.noAttachments r.Attachments)
