(* The test application: one POST handler that builds a message from the
   form's fields and sends it.  The runner drives it with curl; the fake SMTP
   server records what arrives. *)

(* A comma-separated list of addresses; an empty field means none. *)
fun addrs (f : string -> Urmail.headers -> Urmail.headers) (s : string) (h : Urmail.headers) =
    if s = "" then h
    else case String.split s #"," of
             None => f s h
           | Some (a, rest) => addrs f rest (f a h)

fun sendMail r =
    let
        val h = Urmail.empty
                    |> Urmail.from r.From
                    |> addrs Urmail.to r.To
                    |> addrs Urmail.cc r.Cc
                    |> addrs Urmail.bcc r.Bcc
                    |> (fn h => if r.Subject = "" then h else Urmail.subject r.Subject h)
        val html = if r.Html = "" then None
                   else Some <xml><body><p>Hello <b>{[r.Html]}</b> &amp; goodbye</p></body></xml>
    in
        Urmail.send r.Server
                    (case r.Tls of
                         "none" => Urmail.Plain
                       | "starttls" => Urmail.Tls None
                       | "starttls-ca" => Urmail.Tls (Some r.Ca)
                       | "starttls-noverify" => Urmail.TlsNoVerify
                       | _ => error <xml>bad Tls field</xml>)
                    r.User r.Password h r.Body html;
        return <xml><body>sent</body></xml>
    end

(* The form gives the handler its input names; the runner posts to it
   directly. *)
fun main () : transaction page = return <xml><body>
  <form>
    <textbox{#Server}/> <textbox{#Tls}/> <textbox{#Ca}/> <textbox{#User}/> <textbox{#Password}/>
    <textbox{#From}/> <textbox{#To}/> <textbox{#Cc}/> <textbox{#Bcc}/> <textbox{#Subject}/>
    <textarea{#Body}/> <textbox{#Html}/>
    <submit action={sendMail}/>
  </form>
</body></xml>
