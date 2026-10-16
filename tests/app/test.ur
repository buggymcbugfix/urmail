(* The test application.  The runner posts a message's fields to `queue`,
   which stores them for the io task below; the task makes the message with
   Urmail.message, sends it with Urmail.send and records the status, to be
   read back from `status`.  `check` shows what Urmail.message makes of the
   fields, for the cases about the checks.  `queueFfi` is `queue` for a
   message that the task makes with UrmailFfi directly, bypassing
   Urmail.message, as an application could.  `queueParallel` is `queue` for
   messages that go to two io tasks in turn, which send at the same time.
   The fake SMTP server records what arrives. *)

type fields = { Server : string, Tls : string, Ca : string, User : string, Password : string,
                From : string, To : string, Cc : string, Bcc : string, Subject : string,
                Body : string, Html : string, Srcs : string, MessageId : string, UserAgent : string,
                Attach1 : string, Attach2 : string, Attach3 : string }

sequence jobIds
table job : { Id : int, Server : string, Tls : string, Ca : string, User : string, Password : string,
              From : string, To : string, Cc : string, Bcc : string, Subject : string,
              Body : string, Html : string, Srcs : string, MessageId : string, UserAgent : string,
              Attach1 : string, Attach2 : string, Attach3 : string,
              Ffi : bool, Lane : int, Status : option string }
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
     image-file|URL|NAME|PATH           the same, a ServedFile
     big|NAME|TYPE|SIZE                 an attachment, a Blob of SIZE bytes
                                        of filler, for the cases about big
                                        messages *)
fun fields (s : string) : list string =
    case String.split s #"|" of
        None => s :: []
      | Some (a, rest) => a :: fields rest

datatype spec = Attachment of Urmail.attachment | Image of url * Urmail.attachment

(* n bytes of filler, by halves, so that it takes a logarithmic number of
   concatenations. *)
val filler64 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/"

fun filler (n : int) : string =
    if n <= 64 then
        String.substring filler64 {Start = 0, Len = if n < 0 then 0 else n}
    else
        let
            val half = filler (n / 2)
        in
            half ^ half ^ (if n % 2 = 1 then "=" else "")
        end

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
      | "big" :: name :: typ :: size :: [] =>
        Attachment (Urmail.Blob {Name = name, MimeType = typ, Data = textBlob (filler (readError size))})
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

(* A message made with UrmailFfi's builders: only from the fields that are
   not empty, and with none of Urmail.message's other steps but finish.  A
   UserAgent, if given, is set after finish, which leaves the message
   unfinished. *)
fun ffiMessage [rest ::: {Type}] [rest ~ [From, To, Cc, Bcc, Subject, Body, UserAgent]]
               (r : $([From = string, To = string, Cc = string, Bcc = string, Subject = string,
                       Body = string, UserAgent = string] ++ rest)) : UrmailFfi.message =
    let
        fun given f s m = if s = "" then m else f s m
        fun all f l m = List.foldl f m l
    in
        UrmailFfi.start
            |> given UrmailFfi.from r.From
            |> all UrmailFfi.to (addrs r.To)
            |> all UrmailFfi.cc (addrs r.Cc)
            |> all UrmailFfi.bcc (addrs r.Bcc)
            |> given UrmailFfi.subject r.Subject
            |> given UrmailFfi.text r.Body
            |> UrmailFfi.finish
            |> given UrmailFfi.userAgent r.UserAgent
    end


(* A job goes to the first io task, unless it may go in parallel: then the
   jobs alternate between the two. *)
fun enqueue (viaFfi : bool) (parallel : bool) (r : fields) =
    id <- nextval jobIds;
    dml (INSERT INTO job (Id, Server, Tls, Ca, User, Password, From, To, Cc, Bcc, Subject, Body,
                          Html, Srcs, MessageId, UserAgent, Attach1, Attach2, Attach3, Ffi, Lane,
                          Status)
         VALUES ({[id]}, {[r.Server]}, {[r.Tls]}, {[r.Ca]}, {[r.User]}, {[r.Password]}, {[r.From]},
                 {[r.To]}, {[r.Cc]}, {[r.Bcc]}, {[r.Subject]}, {[r.Body]}, {[r.Html]}, {[r.Srcs]},
                 {[r.MessageId]}, {[r.UserAgent]}, {[r.Attach1]}, {[r.Attach2]}, {[r.Attach3]},
                 {[viaFfi]}, {[if parallel then id % 2 else 1]}, NULL));
    return <xml><body>queued</body></xml>

fun queue r = enqueue False False r
fun queueFfi r = enqueue True False r
fun queueParallel r = enqueue False True r

fun record id s = dml (UPDATE job SET Status = {[Some s]} WHERE Id = {[id]})

(* An application makes the message in the transaction that claims the job
   (see examples/queue.ur); here what is wrong with it is just recorded, and
   the cases about the checks post to `check` instead.  A send that fails
   ends the task's run, so for a message made with UrmailFfi, which send is
   expected to refuse that way, a status is recorded first. *)
fun sendJob j =
    if j.Ffi then
        runTransaction (record j.Id "sending a message made with UrmailFfi");
        s <- UrmailFfi.send j.Server (tls j) j.User j.Password (ffiMessage j);
        runTransaction (record j.Id ("UrmailFfi.send gave " ^ (case s of
                                                                  UrmailFfi.Sent => "Sent"
                                                                | _ => "something else")))
    else
        s <- (case message j of
                  Failure e => return ("Invalid: " ^ show e)
                | Success m =>
                  s <- Urmail.send {ServerUrl = j.Server, Tls = tls j, User = j.User,
                                    Password = j.Password, Message = m};
                  return (show s));
        runTransaction (record j.Id s)

(* The jobs of a task's lane, one after the other.  Each transaction only
   reads or starts by writing, so that two tasks at once do not run into
   SQLite's refusal to let a transaction that has read begin to write once
   another has written. *)
fun work (lane : int) =
    jobs <- runTransaction (queryL1 (SELECT * FROM job WHERE job.Status IS NULL AND job.Lane = {[lane]}
                                     ORDER BY job.Id));
    List.app sendJob jobs

task periodic 1 = fn () => work 1
task periodic 1 = fn () => work 0

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
  <form>
    <textbox{#Server}/> <textbox{#Tls}/> <textbox{#Ca}/> <textbox{#User}/> <textbox{#Password}/>
    <textbox{#From}/> <textbox{#To}/> <textbox{#Cc}/> <textbox{#Bcc}/> <textbox{#Subject}/>
    <textarea{#Body}/> <textbox{#Html}/> <textbox{#Srcs}/> <textbox{#MessageId}/> <textbox{#UserAgent}/>
    <textbox{#Attach1}/> <textbox{#Attach2}/> <textbox{#Attach3}/>
    <submit action={queueFfi}/>
  </form>
  <form>
    <textbox{#Server}/> <textbox{#Tls}/> <textbox{#Ca}/> <textbox{#User}/> <textbox{#Password}/>
    <textbox{#From}/> <textbox{#To}/> <textbox{#Cc}/> <textbox{#Bcc}/> <textbox{#Subject}/>
    <textarea{#Body}/> <textbox{#Html}/> <textbox{#Srcs}/> <textbox{#MessageId}/> <textbox{#UserAgent}/>
    <textbox{#Attach1}/> <textbox{#Attach2}/> <textbox{#Attach3}/>
    <submit action={queueParallel}/>
  </form>
</body></xml>
