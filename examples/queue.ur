(* The shape of an application that sends e-mail: a request handler queues
   the message in a table, and a periodic task in io claims it in one
   transaction, sends it, and records what became of it in another.  Nothing
   is sent while a transaction is open, and a message whose status is
   MaybeSent (the connection died after the upload, before the server's
   verdict) is the application's decision to send again or not; here it is
   sent again, and the Message-ID, a function of the row, lets receivers
   drop a duplicate.  The HTML version shows the application's logo by the
   path it is served at, as a page in a browser would; Urmail.message
   attaches the file for the mail, so the same page can be shown in a
   browser too. *)

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

fun page (text : string) : page =
    <xml><body><img src="/logo.png"/><p>{[text]}</p></body></xml>

(* The message of a queued row, or what is wrong with it.  The Message-ID is
   a function of the row, so that a message sent twice is one message to
   the receiver. *)
fun message r =
    Urmail.message {From = r.From, To = r.To :: [], Cc = [], Bcc = [], Subject = r.Subject,
                    UserAgent = None, MessageId = Some ("<queue-" ^ show r.Id ^ "@you.com>"),
                    PlainTextBody = r.Text, HtmlBody = Some {Page = page r.Text, Images = []},
                    Attachments = []}

(* A claim outlives the process that made it: a message the application
   was sending when it died stays claimed, and may or may not have gone out.
   Nothing else runs at startup, so every claim is given back then; a
   message that did go out is sent again with its Message-ID, and dropped
   by the receiver as a duplicate, as after a MaybeSent. *)
task initialize = fn () =>
    dml (UPDATE queue SET Claimed = FALSE WHERE Claimed AND Status IS NULL)

(* Step 1, a transaction: the next message, claimed and checked. *)
val claim =
    r <- oneOrNoRows1 (SELECT * FROM queue WHERE NOT queue.Claimed ORDER BY queue.Id LIMIT 1);
    case r of
        None => return None
      | Some r =>
        dml (UPDATE queue SET Claimed = TRUE WHERE Id = {[r.Id]});
        case message r of
            Failure e =>
            dml (UPDATE queue SET Status = {[Some ("not sent: " ^ show e)]} WHERE Id = {[r.Id]});
            return None
          | Success m => return (Some (r.Id, m))

(* Step 3, another transaction: what became of it. *)
fun record id status =
    case status of
        Urmail.Sent =>
        dml (UPDATE queue SET Status = {[Some "sent"]} WHERE Id = {[id]})
      | Urmail.Refused _ =>
        dml (UPDATE queue SET Status = {[Some (show status)]} WHERE Id = {[id]})
      | Urmail.Deferred _ =>
        (* Declined for now, or no connection: back into the queue, where
           the next tick takes it again.  A real queue would wait longer
           after each try, with a column for when to try next, rather than
           knock every second, and give up after a while. *)
        dml (UPDATE queue SET Claimed = FALSE WHERE Id = {[id]})
      | Urmail.MaybeSent _ =>
        (* Back into the queue: sent again, with the same Message-ID. *)
        dml (UPDATE queue SET Claimed = FALSE WHERE Id = {[id]})
      | Urmail.Misconfigured _ =>
        (* The server URL, the TLS setting, the login or what the account
           may send is wrong, which no message is to blame for: back into
           the queue, and the log says what to fix.  Until it is fixed
           every tick fails the same way; a real queue would stop and raise
           an alarm instead, and not count the tries against the
           message. *)
        debug ("urmail: message " ^ show id ^ " cannot be sent: " ^ show status);
        dml (UPDATE queue SET Claimed = FALSE WHERE Id = {[id]})

(* Step 2, around the other two, once a second. *)
task periodic 1 = fn () =>
    claimed <- runTransaction claim;
    case claimed of
        None => return ()
      | Some (id, m) =>
        status <- Urmail.send {ServerUrl = serverUrl, Tls = Urmail.Tls None, User = user, Password = password,
                               Message = m};
        runTransaction (record id status)

fun main () = return <xml><body>
  <form>
    From: <textbox{#From}/><br/>
    To: <textbox{#To}/><br/>
    Subject: <textbox{#Subject}/><br/>
    Text: <textarea{#Text}/><br/>
    <submit action={enqueue}/>
  </form>
</body></xml>
