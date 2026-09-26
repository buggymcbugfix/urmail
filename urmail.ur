type headers = UrmailFfi.headers

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

fun send r =
	UrmailFfi.send r.ServerUrl r.Tls r.User r.Password r.Headers r.Text r.Html
