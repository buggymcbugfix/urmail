type emailAddress = UrmailFfi.emailAddress
type message = UrmailFfi.message

datatype tls = datatype UrmailFfi.tls
datatype sendStatus = datatype UrmailFfi.sendStatus

datatype attachment =
	  Blob of {Name : string, MimeType : string, Data : blob}
	| ServedFile of {Name : option string, ServedPath : string}

fun emailAddress s =
	let
		val a = UrmailFfi.parseAddress s
	in
		case UrmailFfi.addressProblem a of
		| None => Success a
		| Some e => Failure <xml>{[e]}</xml>
	end

val show_emailAddress = mkShow UrmailFfi.addressString

(* The problems, one line each: the lines are joined by newlines, which the
   values in them have escaped. *)
fun lines (s : string) : xbody =
	case String.split s #"\n" of
	| None => <xml>{[s]}</xml>
	| Some (l, rest) => <xml>{[l]}<br/>{lines rest}</xml>

fun message r =
	let
		fun opt [t ::: Type] (f : t -> UrmailFfi.message -> UrmailFfi.message) (v : option t) m =
			case v of
			| None => m
			| Some x => f x m

		fun all [t ::: Type] (f : t -> UrmailFfi.message -> UrmailFfi.message) (xs : list t) m =
			List.foldl f m xs

		fun attachment (a : attachment) m =
			case a of
			| Blob b => UrmailFfi.attachBlob b.Name b.MimeType b.Data m
			| ServedFile f => UrmailFfi.attachServedFile f.Name f.ServedPath m

		fun image ((u, a) : url * attachment) m =
			case a of
			| Blob b => UrmailFfi.imageBlob u b.Name b.MimeType b.Data m
			| ServedFile f => UrmailFfi.imageServedFile u f.Name f.ServedPath m

		fun html (h : {Page : page, Images : list (url * attachment)}) m =
			m |> UrmailFfi.html h.Page |> all image h.Images |> UrmailFfi.lookUpImages

		val m =
			UrmailFfi.start
				|> UrmailFfi.from r.From
				|> all UrmailFfi.to r.To
				|> all UrmailFfi.cc r.Cc
				|> all UrmailFfi.bcc r.Bcc
				|> UrmailFfi.subject r.Subject
				|> opt UrmailFfi.userAgent r.UserAgent
				|> opt UrmailFfi.messageId r.MessageId
				|> UrmailFfi.text r.PlainTextBody
				|> opt html r.HtmlBody
				|> all attachment r.Attachments
				|> UrmailFfi.finish
	in
		case UrmailFfi.problems m of
		| None => Success m
		| Some e => Failure (lines e)
	end

fun send r =
	UrmailFfi.send r.ServerUrl r.Tls r.User r.Password r.Message
