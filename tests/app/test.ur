(* The test application.  The runner posts a message's fields to `queue`,
   which stores them for the io task below; the task builds the headers with
   Urmail.mkHeaders, sends the message with Urmail.send and records the status,
   to be read back from `status`.  `check` shows what Urmail.mkHeaders makes
   of the fields, for the cases about the header checks.  The fake SMTP server
   records what arrives. *)

type fields = { Server : string, Tls : string, Ca : string, User : string, Password : string,
                From : string, To : string, Cc : string, Bcc : string, Subject : string,
                Body : string, Html : string, MessageId : string, UserAgent : string }

sequence jobIds
table job : { Id : int, Server : string, Tls : string, Ca : string, User : string, Password : string,
              From : string, To : string, Cc : string, Bcc : string, Subject : string,
              Body : string, Html : string, MessageId : string, UserAgent : string,
              Status : option string }
  PRIMARY KEY Id

(* A comma-separated list of addresses; an empty field means none. *)
fun addrs (s : string) : list string =
    if s = "" then []
    else case String.split s #"," of
             None => s :: []
           | Some (a, rest) => a :: addrs rest

fun opt (s : string) : option string = if s = "" then None else Some s

fun headers [rest ::: {Type}] [rest ~ [From, To, Cc, Bcc, Subject, MessageId, UserAgent]]
            (r : $([From = string, To = string, Cc = string, Bcc = string, Subject = string,
                    MessageId = string, UserAgent = string] ++ rest)) : result Urmail.headers =
    Urmail.mkHeaders {From = r.From, Subject = r.Subject, UserAgent = opt r.UserAgent,
                      MessageId = opt r.MessageId, To = addrs r.To, Cc = addrs r.Cc, Bcc = addrs r.Bcc}

fun html [rest ::: {Type}] [rest ~ [Html]] (r : $([Html = string] ++ rest)) : option page =
    if r.Html = "" then None
    else Some <xml><body><p>Hello <b>{[r.Html]}</b> &amp; goodbye</p></body></xml>

fun tls [rest ::: {Type}] [rest ~ [Tls, Ca]] (r : $([Tls = string, Ca = string] ++ rest)) : Urmail.tls =
    case r.Tls of
        "none" => Urmail.Plain
      | "starttls" => Urmail.Tls None
      | "starttls-ca" => Urmail.Tls (Some r.Ca)
      | "starttls-noverify" => Urmail.TlsNoVerify
      | _ => error <xml>bad Tls field</xml>

fun showStatus s =
    case s of
        Urmail.Sent => "Sent"
      | Urmail.NotSent m => "NotSent: " ^ m
      | Urmail.MaybeSent m => "MaybeSent: " ^ m

fun queue (r : fields) =
    id <- nextval jobIds;
    dml (INSERT INTO job (Id, Server, Tls, Ca, User, Password, From, To, Cc, Bcc, Subject, Body,
                          Html, MessageId, UserAgent, Status)
         VALUES ({[id]}, {[r.Server]}, {[r.Tls]}, {[r.Ca]}, {[r.User]}, {[r.Password]}, {[r.From]},
                 {[r.To]}, {[r.Cc]}, {[r.Bcc]}, {[r.Subject]}, {[r.Body]}, {[r.Html]},
                 {[r.MessageId]}, {[r.UserAgent]}, NULL));
    return <xml><body>queued</body></xml>

(* An application checks the headers in the transaction that claims the job
   (see examples/queue.ur); here a refusal is just recorded, and the cases
   about the checks post to `check` instead. *)
task periodic 1 = fn () =>
    jobs <- runTransaction (queryL1 (SELECT * FROM job WHERE job.Status IS NULL ORDER BY job.Id));
    _ <- List.mapM (fn j =>
                       s <- (case headers j of
                                 Failure e => return ("Refused: " ^ show e)
                               | Success h =>
                                 s <- Urmail.send {ServerUrl = j.Server, Tls = tls j, User = j.User,
                                                   Password = j.Password, Headers = h, Text = j.Body,
                                                   Html = html j};
                                 return (showStatus s));
                       runTransaction (dml (UPDATE job SET Status = {[Some s]} WHERE Id = {[j.Id]})))
                   jobs;
    return ()

fun status () =
    rows <- queryX1 (SELECT job.Status FROM job WHERE job.Status IS NOT NULL ORDER BY job.Id)
                    (fn r => <xml>{[Option.get "" r.Status]}<br/></xml>);
    return <xml><body>{rows}</body></xml>

(* What Urmail.mkHeaders makes of the fields. *)
fun check (r : fields) =
    return <xml><body>{case headers r of
                           Success _ => <xml>ok</xml>
                         | Failure e => <xml>refused: {e}</xml>}</body></xml>

(* The forms give the handlers their input names; the runner posts to them
   directly. *)
fun main () : transaction page = return <xml><body>
  <form>
    <textbox{#Server}/> <textbox{#Tls}/> <textbox{#Ca}/> <textbox{#User}/> <textbox{#Password}/>
    <textbox{#From}/> <textbox{#To}/> <textbox{#Cc}/> <textbox{#Bcc}/> <textbox{#Subject}/>
    <textarea{#Body}/> <textbox{#Html}/> <textbox{#MessageId}/> <textbox{#UserAgent}/>
    <submit action={queue}/>
  </form>
  <form>
    <textbox{#Server}/> <textbox{#Tls}/> <textbox{#Ca}/> <textbox{#User}/> <textbox{#Password}/>
    <textbox{#From}/> <textbox{#To}/> <textbox{#Cc}/> <textbox{#Bcc}/> <textbox{#Subject}/>
    <textarea{#Body}/> <textbox{#Html}/> <textbox{#MessageId}/> <textbox{#UserAgent}/>
    <submit action={check}/>
  </form>
</body></xml>
