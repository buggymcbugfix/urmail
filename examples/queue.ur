(* The shape of an application that sends e-mail: a request handler queues
   the message in a table, and a periodic task in io claims it in one
   transaction, sends it, and records what became of it in another.  Nothing
   is sent while a transaction is open, and a message whose status is
   MaybeSent (the connection died after the upload, before the server's
   verdict) is the application's decision to send again or not; here it is
   sent again, and the Message-ID, a function of the row, lets receivers
   drop a duplicate.  The HTML version carries the application's logo, a
   file it serves, as an inline part. *)

val serverUrl = "smtp://you.com:587"
val user = "you"
val password = "pass"

sequence ids
table queue : { Id : int, From : string, To : string, Subject : string, Text : string,
                Claimed : bool, Status : option string }
  PRIMARY KEY Id

fun enqueue r =
    id <- nextval ids;
    dml (INSERT INTO queue (Id, From, To, Subject, Text, Claimed, Status)
         VALUES ({[id]}, {[r.From]}, {[r.To]}, {[r.Subject]}, {[r.Text]}, FALSE, NULL));
    return <xml><body>Queued as #{[id]}</body></xml>

(* The logo: the `file` directive in queue.urp makes the bytes and the MIME
   type the compiler's, and blessing it says that a refusal (nothing served
   at the path) is a mistake here, to be reported as a fatal error naming
   this line, not a status of the message. *)
val logo =
    Urmail.Attachment.blessServedFile _LOC_ (Urmail.Attachment.asciiName "logo.png") "/logo.png"

(* The headers of a queued message, parsed from the text the row holds, or
   what is wrong with the first part that is not right.  The Message-ID is
   a function of the row, so that a message sent twice is one message to
   the receiver. *)
fun headers r =
    from <- Urmail.emailAddress r.From;
    to <- Urmail.emailAddress r.To;
    subject <- Urmail.headerText r.Subject;
    messageId <- Urmail.messageId ("<queue-" ^ show r.Id ^ "@you.com>");
    return {From = from, To = to :: [], Cc = [], Bcc = [], Subject = subject,
            UserAgent = None, MessageId = Some messageId}

(* Step 1, a transaction: the next message, claimed, with its headers
   checked. *)
val claim =
    r <- oneOrNoRows1 (SELECT * FROM queue WHERE NOT queue.Claimed ORDER BY queue.Id LIMIT 1);
    case r of
        None => return None
      | Some r =>
        dml (UPDATE queue SET Claimed = TRUE WHERE Id = {[r.Id]});
        case headers r of
            Failure e =>
            dml (UPDATE queue SET Status = {[Some ("not sent: " ^ show e)]} WHERE Id = {[r.Id]});
            return None
          | Success h =>
            let
                val (l, logoUrl) = Urmail.Attachment.inline logo
            in
                return (Some (r, h, l, logoUrl))
            end

(* Step 3, another transaction: what became of it. *)
fun record id status =
    case status of
        Urmail.Sent =>
        dml (UPDATE queue SET Status = {[Some "sent"]} WHERE Id = {[id]})
      | Urmail.Refused why =>
        dml (UPDATE queue SET Status = {[Some ("refused: " ^ why)]} WHERE Id = {[id]})
      | Urmail.NotSent why =>
        (* Declined for now, or no connection: back into the queue. *)
        dml (UPDATE queue SET Claimed = FALSE WHERE Id = {[id]})
      | Urmail.MaybeSent _ =>
        (* Back into the queue: sent again, with the same Message-ID. *)
        dml (UPDATE queue SET Claimed = FALSE WHERE Id = {[id]})

(* Step 2, around the other two, once a second. *)
task periodic 1 = fn () =>
    claimed <- runTransaction claim;
    case claimed of
        None => return ()
      | Some (r, h, logo, logoUrl) =>
        status <- Urmail.send (h ++ {ServerUrl = serverUrl, Tls = Urmail.Tls None, User = user, Password = password,
                                     Text = r.Text,
                                     Html = Some <xml><body><img src={logoUrl}/><p>{[r.Text]}</p></body></xml>,
                                     Attachments = logo :: []});
        runTransaction (record r.Id status)

fun main () = return <xml><body>
  <form>
    From: <textbox{#From}/><br/>
    To: <textbox{#To}/><br/>
    Subject: <textbox{#Subject}/><br/>
    Text: <textarea{#Text}/><br/>
    <submit action={enqueue}/>
  </form>
</body></xml>
