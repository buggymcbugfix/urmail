(* The test application.  The runner posts a message's fields to `queue`,
   which stores them for the io task below; the task makes the message with
   Urmail.message, sends it with Urmail.send and records the status, to be
   read back from `status`.  `check` shows what Urmail.message makes of the
   fields, for the cases about the checks.  The fake SMTP server records
   what arrives. *)

type fields = { Server : string, Tls : string, Ca : string, User : string, Password : string,
                From : string, To : string, Cc : string, Bcc : string, Subject : string,
                Body : string, Html : string, Srcs : string, MessageId : string, UserAgent : string,
                Attach1 : string, Attach2 : string, Attach3 : string }

sequence jobIds
table job : { Id : int, Server : string, Tls : string, Ca : string, User : string, Password : string,
              From : string, To : string, Cc : string, Bcc : string, Subject : string,
              Body : string, Html : string, Srcs : string, MessageId : string, UserAgent : string,
              Attach1 : string, Attach2 : string, Attach3 : string,
              Status : option string }
  PRIMARY KEY Id

(* A comma-separated list; an empty field means none. *)
fun addrs (s : string) : list string =
    if s = "" then []
    else case String.split s #"," of
             None => s :: []
           | Some (a, rest) => a :: addrs rest

fun opt (s : string) : option string = if s = "" then None else Some s

(* An attachment or an entry of Images as the runner spells it, the fields
   separated by '|':

     blob|NAME|TYPE|DATA                an attachment, a Blob of DATA's text
     file|NAME|PATH                     an attachment, a ServedFile; an empty
                                        NAME is none
     image-blob|URL|NAME|TYPE|DATA      an entry of Images, for URL
     image-file|URL|NAME|PATH           the same, a ServedFile *)
fun fields (s : string) : list string =
    case String.split s #"|" of
        None => s :: []
      | Some (a, rest) => a :: fields rest

datatype spec = Attachment of Urmail.attachment | Image of url * Urmail.attachment

fun spec (s : string) : spec =
    case fields s of
        "blob" :: name :: typ :: data :: [] =>
        Attachment (Urmail.Blob {Name = name, MimeType = typ, Data = textBlob data})
      | "file" :: name :: path :: [] =>
        Attachment (Urmail.ServedFile {Name = opt name, ServedPath = path})
      | "image-blob" :: u :: name :: typ :: data :: [] =>
        Image (bless u, Urmail.Blob {Name = name, MimeType = typ, Data = textBlob data})
      | "image-file" :: u :: name :: path :: [] =>
        Image (bless u, Urmail.ServedFile {Name = opt name, ServedPath = path})
      | _ => error <xml>Bad attachment spec: {[s]}</xml>

(* The message of the fields: the HTML version, when Html is given, has
   an img for each of the comma-separated Srcs, after the text. *)
fun message [rest ::: {Type}]
            [rest ~ [From, To, Cc, Bcc, Subject, MessageId, UserAgent, Body, Html, Srcs,
                     Attach1, Attach2, Attach3]]
            (r : $([From = string, To = string, Cc = string, Bcc = string, Subject = string,
                    MessageId = string, UserAgent = string, Body = string, Html = string, Srcs = string,
                    Attach1 = string, Attach2 = string, Attach3 = string] ++ rest))
    : result Urmail.message =
    let
        val specs = List.mp spec (List.filter (fn s => s <> "") (r.Attach1 :: r.Attach2 :: r.Attach3 :: []))
        val images = List.mapPartial (fn s => case s of Image i => Some i | _ => None) specs
        val attachments = List.mapPartial (fn s => case s of Attachment a => Some a | _ => None) specs
        val page = <xml><body><p>Hello <b>{[r.Html]}</b> &amp; goodbye</p>{List.mapX (fn s => <xml><img src={bless s}/></xml>) (addrs r.Srcs)}</body></xml>
    in
        Urmail.message {From = r.From, To = addrs r.To, Cc = addrs r.Cc, Bcc = addrs r.Bcc,
                        Subject = r.Subject, UserAgent = opt r.UserAgent, MessageId = opt r.MessageId,
                        PlainTextBody = r.Body,
                        HtmlBody = if r.Html = "" then None else Some {Page = page, Images = images},
                        Attachments = attachments}
    end

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
      | Urmail.Refused m => "Refused: " ^ m
      | Urmail.NotSent m => "NotSent: " ^ m
      | Urmail.MaybeSent m => "MaybeSent: " ^ m
      | Urmail.Failed m => "Failed: " ^ m

fun queue (r : fields) =
    id <- nextval jobIds;
    dml (INSERT INTO job (Id, Server, Tls, Ca, User, Password, From, To, Cc, Bcc, Subject, Body,
                          Html, Srcs, MessageId, UserAgent, Attach1, Attach2, Attach3, Status)
         VALUES ({[id]}, {[r.Server]}, {[r.Tls]}, {[r.Ca]}, {[r.User]}, {[r.Password]}, {[r.From]},
                 {[r.To]}, {[r.Cc]}, {[r.Bcc]}, {[r.Subject]}, {[r.Body]}, {[r.Html]}, {[r.Srcs]},
                 {[r.MessageId]}, {[r.UserAgent]}, {[r.Attach1]}, {[r.Attach2]}, {[r.Attach3]}, NULL));
    return <xml><body>queued</body></xml>

(* An application makes the message in the transaction that claims the job
   (see examples/queue.ur); here what is wrong with it is just recorded, and
   the cases about the checks post to `check` instead. *)
task periodic 1 = fn () =>
    jobs <- runTransaction (queryL1 (SELECT * FROM job WHERE job.Status IS NULL ORDER BY job.Id));
    _ <- List.mapM (fn j =>
                       s <- (case message j of
                                 Failure e => return ("Invalid: " ^ show e)
                               | Success m =>
                                 s <- Urmail.send {ServerUrl = j.Server, Tls = tls j, User = j.User,
                                                   Password = j.Password, Message = m};
                                 return (showStatus s));
                       runTransaction (dml (UPDATE job SET Status = {[Some s]} WHERE Id = {[j.Id]})))
                   jobs;
    return ()

fun status () =
    rows <- queryX1 (SELECT job.Status FROM job WHERE job.Status IS NOT NULL ORDER BY job.Id)
                    (fn r => <xml>{[Option.get "" r.Status]}<br/></xml>);
    return <xml><body>{rows}</body></xml>

(* What Urmail.message makes of the fields. *)
fun check (r : fields) =
    return <xml><body>{case message r of
                           Failure e => <xml>refused: {e}</xml>
                         | Success _ => <xml>ok</xml>}</body></xml>

(* The forms give the handlers their input names; the runner posts to them
   directly. *)
fun main () : transaction page = return <xml><body>
  <form>
    <textbox{#Server}/> <textbox{#Tls}/> <textbox{#Ca}/> <textbox{#User}/> <textbox{#Password}/>
    <textbox{#From}/> <textbox{#To}/> <textbox{#Cc}/> <textbox{#Bcc}/> <textbox{#Subject}/>
    <textarea{#Body}/> <textbox{#Html}/> <textbox{#Srcs}/> <textbox{#MessageId}/> <textbox{#UserAgent}/>
    <textbox{#Attach1}/> <textbox{#Attach2}/> <textbox{#Attach3}/>
    <submit action={queue}/>
  </form>
  <form>
    <textbox{#Server}/> <textbox{#Tls}/> <textbox{#Ca}/> <textbox{#User}/> <textbox{#Password}/>
    <textbox{#From}/> <textbox{#To}/> <textbox{#Cc}/> <textbox{#Bcc}/> <textbox{#Subject}/>
    <textarea{#Body}/> <textbox{#Html}/> <textbox{#Srcs}/> <textbox{#MessageId}/> <textbox{#UserAgent}/>
    <textbox{#Attach1}/> <textbox{#Attach2}/> <textbox{#Attach3}/>
    <submit action={check}/>
  </form>
</body></xml>
