(* The test application.  The runner posts a message's fields to `queue`,
   which stores them for the io task below; the task builds the headers with
   Urmail.mkHeaders and the attachments with Urmail.Attachment, sends the
   message with Urmail.send and records the status, to be read back from
   `status`.  `check` shows what Urmail.mkHeaders and Urmail.Attachment make
   of the fields, for the cases about the checks.  The fake SMTP server
   records what arrives. *)

type fields = { Server : string, Tls : string, Ca : string, User : string, Password : string,
                From : string, To : string, Cc : string, Bcc : string, Subject : string,
                Body : string, Html : string, MessageId : string, UserAgent : string,
                Attach1 : string, Attach2 : string, Attach3 : string }

sequence jobIds
table job : { Id : int, Server : string, Tls : string, Ca : string, User : string, Password : string,
              From : string, To : string, Cc : string, Bcc : string, Subject : string,
              Body : string, Html : string, MessageId : string, UserAgent : string,
              Attach1 : string, Attach2 : string, Attach3 : string,
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

(* An attachment as the runner spells it, KIND|ASCII|UTF8|TYPE|DATA, an
   empty UTF8 meaning none.  KIND blob: DATA is the text of the file.  KIND
   file: the file is one of this project's `file` directives, DATA its
   served path, and TYPE is not used.  inline and inline-file: the same, and
   the part is inline, its url given to the HTML part. *)
fun fields (s : string) : list string =
    case String.split s #"|" of
        None => s :: []
      | Some (a, rest) => a :: fields rest

fun attachment (spec : string) : result (Urmail.attachment * option url) =
    let
        fun make kind ascii utf8 typ data =
            case kind of
                "blob" => Urmail.Attachment.fromBlob {AsciiName = ascii, Utf8Name = opt utf8, MimeType = typ,
                                                      Data = textBlob data}
              | "file" => Urmail.Attachment.fromFile {AsciiName = ascii, Utf8Name = opt utf8, ServedPath = data}
              | _ => error <xml>Bad attachment kind: {[kind]}</xml>
    in
        case fields spec of
            kind :: ascii :: utf8 :: typ :: data :: [] =>
            (case kind of
                 "inline" =>
                 a <- make "blob" ascii utf8 typ data;
                 return (Urmail.Attachment.inline a |> (fn (a, u) => (a, Some u)))
               | "inline-file" =>
                 a <- make "file" ascii utf8 typ data;
                 return (Urmail.Attachment.inline a |> (fn (a, u) => (a, Some u)))
               | _ =>
                 a <- make kind ascii utf8 typ data;
                 return (a, None))
          | _ => error <xml>Bad attachment spec: {[spec]}</xml>
    end

(* The attachments of the fields, in order, with the urls of the inline
   ones; an empty field is none. *)
fun attachments [rest ::: {Type}] [rest ~ [Attach1, Attach2, Attach3]]
                (r : $([Attach1 = string, Attach2 = string, Attach3 = string] ++ rest))
    : result (list Urmail.attachment * list url) =
    aus <- List.mapM attachment (List.filter (fn s => s <> "") (r.Attach1 :: r.Attach2 :: r.Attach3 :: []));
    return (List.mp (fn (a, _) => a) aus,
            List.mapPartial (fn (_, u) => u) aus)

fun html [rest ::: {Type}] [rest ~ [Html]] (r : $([Html = string] ++ rest)) (inlines : list url) : option page =
    if r.Html = "" then None
    else Some <xml><body><p>Hello <b>{[r.Html]}</b> &amp; goodbye</p>{List.mapX (fn u => <xml><img src={u}/></xml>) inlines}</body></xml>

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
                          Html, MessageId, UserAgent, Attach1, Attach2, Attach3, Status)
         VALUES ({[id]}, {[r.Server]}, {[r.Tls]}, {[r.Ca]}, {[r.User]}, {[r.Password]}, {[r.From]},
                 {[r.To]}, {[r.Cc]}, {[r.Bcc]}, {[r.Subject]}, {[r.Body]}, {[r.Html]},
                 {[r.MessageId]}, {[r.UserAgent]}, {[r.Attach1]}, {[r.Attach2]}, {[r.Attach3]}, NULL));
    return <xml><body>queued</body></xml>

(* An application checks the headers and the attachments in the transaction
   that claims the job (see examples/queue.ur); here a refusal is just
   recorded, and the cases about the checks post to `check` instead. *)
task periodic 1 = fn () =>
    jobs <- runTransaction (queryL1 (SELECT * FROM job WHERE job.Status IS NULL ORDER BY job.Id));
    _ <- List.mapM (fn j =>
                       s <- (case headers j of
                                 Failure e => return ("Refused: " ^ show e)
                               | Success h =>
                                 case attachments j of
                                     Failure e => return ("Refused: " ^ show e)
                                   | Success (as, inlines) =>
                                     s <- Urmail.send {ServerUrl = j.Server, Tls = tls j, User = j.User,
                                                       Password = j.Password, Headers = h, Text = j.Body,
                                                       Html = html j inlines, Attachments = as};
                                     return (showStatus s));
                       runTransaction (dml (UPDATE job SET Status = {[Some s]} WHERE Id = {[j.Id]})))
                   jobs;
    return ()

fun status () =
    rows <- queryX1 (SELECT job.Status FROM job WHERE job.Status IS NOT NULL ORDER BY job.Id)
                    (fn r => <xml>{[Option.get "" r.Status]}<br/></xml>);
    return <xml><body>{rows}</body></xml>

(* What Urmail.mkHeaders and Urmail.Attachment make of the fields. *)
fun check (r : fields) =
    return <xml><body>{case headers r of
                           Failure e => <xml>refused: {e}</xml>
                         | Success _ =>
                           case attachments r of
                               Failure e => <xml>refused: {e}</xml>
                             | Success _ => <xml>ok</xml>}</body></xml>

(* The forms give the handlers their input names; the runner posts to them
   directly. *)
fun main () : transaction page = return <xml><body>
  <form>
    <textbox{#Server}/> <textbox{#Tls}/> <textbox{#Ca}/> <textbox{#User}/> <textbox{#Password}/>
    <textbox{#From}/> <textbox{#To}/> <textbox{#Cc}/> <textbox{#Bcc}/> <textbox{#Subject}/>
    <textarea{#Body}/> <textbox{#Html}/> <textbox{#MessageId}/> <textbox{#UserAgent}/>
    <textbox{#Attach1}/> <textbox{#Attach2}/> <textbox{#Attach3}/>
    <submit action={queue}/>
  </form>
  <form>
    <textbox{#Server}/> <textbox{#Tls}/> <textbox{#Ca}/> <textbox{#User}/> <textbox{#Password}/>
    <textbox{#From}/> <textbox{#To}/> <textbox{#Cc}/> <textbox{#Bcc}/> <textbox{#Subject}/>
    <textarea{#Body}/> <textbox{#Html}/> <textbox{#MessageId}/> <textbox{#UserAgent}/>
    <textbox{#Attach1}/> <textbox{#Attach2}/> <textbox{#Attach3}/>
    <submit action={check}/>
  </form>
</body></xml>
