val server = "smtp://you.com:465"
val user = "you"
val password = "pass"
val send = Urmail.send server (Urmail.Tls None) user password
               
fun sendPlain r =
    send (Urmail.from r.From (Urmail.to r.To (Urmail.subject r.Subject Urmail.empty)))
         r.Body None;
    return <xml>Sent</xml>

fun sendHtml r =
    send (Urmail.from r.From (Urmail.to r.To (Urmail.subject r.Subject Urmail.empty)))
         r.Body (Some <xml><body><a href={url (main ())}>Spread the love!</a></body></xml>);
    return <xml>Sent</xml>

and main () = return <xml><body>
  <h2>Plain</h2>

  <form>
    From: <textbox{#From}/><br/>
    To: <textbox{#To}/><br/>
    Subject: <textbox{#Subject}/><br/>
    Body: <textarea{#Body}/><br/>
    <submit action={sendPlain}/>
  </form>

  <h2>HTML</h2>

  <form>
    From: <textbox{#From}/><br/>
    To: <textbox{#To}/><br/>
    Subject: <textbox{#Subject}/><br/>
    Body: <textarea{#Body}/><br/>
    <submit action={sendHtml}/>
  </form>
</body></xml>
