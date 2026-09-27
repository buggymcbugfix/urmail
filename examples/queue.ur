(* The shape of an application that sends e-mail: a request handler queues
   the message in a table, and a periodic task in io claims it in one
   transaction, sends it, and records what became of it in another.  Nothing
   is sent while a transaction is open, and a message whose status is
   MaybeSent (the connection died after the upload, before the server's
   verdict) is the application's decision to send again or not; here it is
   sent again, and the Message-ID, a function of the row, lets receivers
   drop a duplicate. *)

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

(* Step 1, a transaction: the next message, claimed, with its headers checked. *)
val claim =
    r <- oneOrNoRows1 (SELECT * FROM queue WHERE NOT queue.Claimed ORDER BY queue.Id LIMIT 1);
    case r of
        None => return None
      | Some r =>
        dml (UPDATE queue SET Claimed = TRUE WHERE Id = {[r.Id]});
        case Urmail.mkHeaders {From = r.From, Subject = r.Subject, UserAgent = None,
                               MessageId = Some ("<queue-" ^ show r.Id ^ "@you.com>"),
                               To = r.To :: [], Cc = [], Bcc = []} of
            Failure e =>
            dml (UPDATE queue SET Status = {[Some ("not sent: " ^ show e)]} WHERE Id = {[r.Id]});
            return None
          | Success h => return (Some (r, h))

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
      | Some (r, h) =>
        status <- Urmail.send {ServerUrl = serverUrl, Tls = Urmail.Tls None, User = user, Password = password,
                               Headers = h, Text = r.Text, Html = None, Attachments = []};
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
