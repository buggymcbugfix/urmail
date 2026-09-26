#include "config.h"
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>

#include <urweb/urweb.h>
#include "urmail.h"

struct headers {
  uw_Basis_string from, to, cc, bcc, subject, user_agent;
};

typedef struct headers *uw_Urmail_headers;

static uw_Basis_string copy_string(uw_Basis_string s) {
  if (s == NULL)
    return NULL;
  else
    return strdup(s);
}

static void free_string(uw_Basis_string s) {
  if (s == NULL)
    return;
  else
    free(s);
}

static uw_Urmail_headers copy_headers(uw_Urmail_headers h) {
  uw_Urmail_headers h2 = malloc(sizeof(struct headers));
  h2->from = copy_string(h->from);
  h2->to = copy_string(h->to);
  h2->cc = copy_string(h->cc);
  h2->bcc = copy_string(h->bcc);
  h2->subject = copy_string(h->subject);
  h2->user_agent = copy_string(h->user_agent);
  return h2;
}

static void free_headers(uw_Urmail_headers h) {
  free_string(h->from);
  free_string(h->to);
  free_string(h->cc);
  free_string(h->bcc);
  free_string(h->subject);
  free_string(h->user_agent);
  free(h);
}

uw_Urmail_headers uw_Urmail_empty = NULL;

static void header(uw_context ctx, uw_Basis_string s) {
  if (strlen(s) > 100)
    uw_error(ctx, FATAL, "Header value too long");

  for (; *s; ++s)
    if (*s == '\r' || *s == '\n')
      uw_error(ctx, FATAL, "Header value contains newline");
}

// An address is either an addr-spec or "Display Name <addr-spec>".  The
// addr-spec is what goes into the envelope, so it must be there.
static void address(uw_context ctx, uw_Basis_string s) {
  const char *p;

  header(ctx, s);

  if (strchr(s, ','))
    uw_error(ctx, FATAL, "E-mail address contains comma");

  for (p = s; *p == ' ' || *p == '\t'; ++p);
  if (!*p)
    uw_error(ctx, FATAL, "Empty e-mail address");
  if (strchr(p, '<') && !strchr(p, '>'))
    uw_error(ctx, FATAL, "E-mail address has '<' but no '>'");
}

uw_Urmail_headers uw_Urmail_from(uw_context ctx, uw_Basis_string s, uw_Urmail_headers h) {
  uw_Urmail_headers h2 = uw_malloc(ctx, sizeof(struct headers));

  if (h)
    *h2 = *h;
  else
    memset(h2, 0, sizeof(*h2));

  if (h2->from)
    uw_error(ctx, FATAL, "Duplicate From header");

  address(ctx, s);
  h2->from = uw_strdup(ctx, s);

  return h2;
}

uw_Urmail_headers uw_Urmail_to(uw_context ctx, uw_Basis_string s, uw_Urmail_headers h) {
  uw_Urmail_headers h2 = uw_malloc(ctx, sizeof(struct headers));
  if (h)
    *h2 = *h;
  else
    memset(h2, 0, sizeof(*h2));

  address(ctx, s);
  if (h2->to) {
    uw_Basis_string all = uw_malloc(ctx, strlen(h2->to) + 2 + strlen(s));
    sprintf(all, "%s,%s", h2->to, s);
    h2->to = all;
  } else
    h2->to = uw_strdup(ctx, s);

  return h2;
}

uw_Urmail_headers uw_Urmail_cc(uw_context ctx, uw_Basis_string s, uw_Urmail_headers h) {
  uw_Urmail_headers h2 = uw_malloc(ctx, sizeof(struct headers));
  if (h)
    *h2 = *h;
  else
    memset(h2, 0, sizeof(*h2));

  address(ctx, s);
  if (h2->cc) {
    uw_Basis_string all = uw_malloc(ctx, strlen(h2->cc) + 2 + strlen(s));
    sprintf(all, "%s,%s", h2->cc, s);
    h2->cc = all;
  } else
    h2->cc = uw_strdup(ctx, s);

  return h2;
}

uw_Urmail_headers uw_Urmail_bcc(uw_context ctx, uw_Basis_string s, uw_Urmail_headers h) {
  uw_Urmail_headers h2 = uw_malloc(ctx, sizeof(struct headers));
  if (h)
    *h2 = *h;
  else
    memset(h2, 0, sizeof(*h2));

  address(ctx, s);
  if (h2->bcc) {
    uw_Basis_string all = uw_malloc(ctx, strlen(h2->bcc) + 2 + strlen(s));
    sprintf(all, "%s,%s", h2->bcc, s);
    h2->bcc = all;
  } else
    h2->bcc = uw_strdup(ctx, s);

  return h2;
}

uw_Urmail_headers uw_Urmail_subject(uw_context ctx, uw_Basis_string s, uw_Urmail_headers h) {
  uw_Urmail_headers h2 = uw_malloc(ctx, sizeof(struct headers));

  if (h)
    *h2 = *h;
  else
    memset(h2, 0, sizeof(*h2));

  if (h2->subject)
    uw_error(ctx, FATAL, "Duplicate Subject header");

  header(ctx, s);
  h2->subject = uw_strdup(ctx, s);

  return h2;
}

uw_Urmail_headers uw_Urmail_user_agent(uw_context ctx, uw_Basis_string s, uw_Urmail_headers h) {
  uw_Urmail_headers h2 = uw_malloc(ctx, sizeof(struct headers));

  if (h)
    *h2 = *h;
  else
    memset(h2, 0, sizeof(*h2));

  if (h2->user_agent)
    uw_error(ctx, FATAL, "Duplicate User-Agent header");

  header(ctx, s);
  h2->user_agent = uw_strdup(ctx, s);

  return h2;
}

typedef struct {
  uw_context ctx;
  uw_Urmail_headers h;
  uw_Basis_string server, ca, user, password;
  enum uw_Urmail_tls_tag tls;
  char *message;   // the message as it goes over the wire, assembled at the call
  size_t length;
} job;

typedef struct {
  const char *content;
  size_t length;
} upload_status;

static size_t do_upload(void *ptr, size_t size, size_t nmemb, void *userp)
{
  upload_status *upload_ctx = (upload_status *)userp;
  size *= nmemb;
  if (size > upload_ctx->length)
    size = upload_ctx->length;

  memcpy(ptr, upload_ctx->content, size);
  upload_ctx->content += size;
  upload_ctx->length -= size;
  return size;
}

// Extract e-mail address from a string that is either *just* an e-mail address or looks like "Recipient <address>".
// Note: it's destructive!
// Luckily, we only apply it to strings we are done using for other purposes (copied into buffer with e-mail contents).
static char *addrOf(char *s) {
  char *p = strchr(s, '<');
  if (p) {
    char *p2 = strchr(p+1, '>');
    if (p2) {
      *p2 = 0;
      return p+1;
    } else
      return s;
  } else
    return s;
}

/* ---- A growable byte buffer for assembling the message.  malloc-based, so
   that the message can live in the job until the transaction commits. ---- */

typedef struct {
  char *s;
  size_t len, cap;
} buf;

static void buf_reserve(uw_context ctx, buf *b, size_t extra) {
  if (b->len + extra + 1 > b->cap) {
    size_t cap = b->cap ? b->cap : 1024;
    while (b->len + extra + 1 > cap)
      cap *= 2;
    char *s = realloc(b->s, cap);
    if (!s) {
      free(b->s);
      uw_error(ctx, FATAL, "urmail: out of memory assembling the message");
    }
    b->s = s;
    b->cap = cap;
  }
}

static void buf_append(uw_context ctx, buf *b, const char *s, size_t n) {
  buf_reserve(ctx, b, n);
  memcpy(b->s + b->len, s, n);
  b->len += n;
  b->s[b->len] = 0;
}

static void buf_str(uw_context ctx, buf *b, const char *s) {
  buf_append(ctx, b, s, strlen(s));
}

// The lines of a message end in CRLF; a bare LF in a body is turned into one.
static void buf_text(uw_context ctx, buf *b, const char *s) {
  int last_was_cr = 0;
  for (; *s; ++s) {
    if (*s == '\n' && !last_was_cr)
      buf_append(ctx, b, "\r\n", 2);
    else
      buf_append(ctx, b, s, 1);
    last_was_cr = (*s == '\r');
  }
}

// A MIME boundary that occurs in neither part.
static void boundary(const char *body, const char *xbody, char out[11]) {
  out[10] = 0;
  do {
    int i;
    for (i = 0; i < 10; ++i)
      out[i] = 'A' + (rand() % 26);
  } while (strstr(body, out) || (xbody && strstr(xbody, out)));
}

// Assemble the message: headers, then the text body, or a multipart/alternative
// of the text body and the HTML document.  `xbody` is the string of a `page`
// value, which is the document's contents without the html element (the
// runtime adds that when it serves a page), hence the wrapper.
static void assemble(uw_context ctx, buf *b, uw_Urmail_headers h,
                     uw_Basis_string body, uw_Basis_string xbody) {
  if (h->from) {
    buf_str(ctx, b, "From: "); buf_str(ctx, b, h->from); buf_str(ctx, b, "\r\n");
  }
  if (h->subject) {
    buf_str(ctx, b, "Subject: "); buf_str(ctx, b, h->subject); buf_str(ctx, b, "\r\n");
  }
  if (h->to) {
    buf_str(ctx, b, "To: "); buf_str(ctx, b, h->to); buf_str(ctx, b, "\r\n");
  }
  if (h->cc) {
    buf_str(ctx, b, "Cc: "); buf_str(ctx, b, h->cc); buf_str(ctx, b, "\r\n");
  }
  if (h->user_agent) {
    buf_str(ctx, b, "User-Agent: "); buf_str(ctx, b, h->user_agent); buf_str(ctx, b, "\r\n");
  }

  if (xbody) {
    char sep[11];
    boundary(body, xbody, sep);

    buf_str(ctx, b, "MIME-Version: 1.0\r\n"
                    "Content-Type: multipart/alternative; boundary=\"");
    buf_str(ctx, b, sep);
    buf_str(ctx, b, "\"\r\n\r\n--");
    buf_str(ctx, b, sep);
    buf_str(ctx, b, "\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n");
    buf_text(ctx, b, body);
    buf_str(ctx, b, "\r\n--");
    buf_str(ctx, b, sep);
    buf_str(ctx, b, "\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
                    "<!DOCTYPE html><html>");
    buf_text(ctx, b, xbody);
    buf_str(ctx, b, "</html>\r\n--");
    buf_str(ctx, b, sep);
    buf_str(ctx, b, "--");
  } else {
    buf_str(ctx, b, "Content-Type: text/plain; charset=utf-8\r\n\r\n");
    buf_text(ctx, b, body);
  }
}

static void commit(void *data) {
  job *j = data;
  CURL *curl;
  CURLcode res;
  upload_status upload_ctx;
  struct curl_slist *recipients = NULL;

  upload_ctx.content = j->message;
  upload_ctx.length = j->length;

  if (j->h->to) {
    char *saveptr, *addr = strtok_r(j->h->to, ",", &saveptr);
    if (addr)
      do {
        recipients = curl_slist_append(recipients, addrOf(addr));
      } while ((addr = strtok_r(NULL, ",", &saveptr)));
  }

  if (j->h->cc) {
    char *saveptr, *addr = strtok_r(j->h->cc, ",", &saveptr);
    if (addr)
      do {
        recipients = curl_slist_append(recipients, addrOf(addr));
      } while ((addr = strtok_r(NULL, ",", &saveptr)));
  }

  if (j->h->bcc) {
    char *saveptr, *addr = strtok_r(j->h->bcc, ",", &saveptr);
    if (addr)
      do {
        recipients = curl_slist_append(recipients, addrOf(addr));
      } while ((addr = strtok_r(NULL, ",", &saveptr)));
  }

  curl = curl_easy_init();
  if (!curl) {
    uw_set_error_message(j->ctx, "Can't create curl object");
    return;
  }

  curl_easy_setopt(curl, CURLOPT_USERNAME, j->user);
  curl_easy_setopt(curl, CURLOPT_PASSWORD, j->password);
  curl_easy_setopt(curl, CURLOPT_URL, j->server);

  switch (j->tls) {
  case uw_Urmail_Plain:
    curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_NONE);
    break;
  case uw_Urmail_Tls:
    curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
    if (j->ca)
      curl_easy_setopt(curl, CURLOPT_CAINFO, j->ca);
    // else libcurl's default: the system's CA bundle, verified.
    break;
  case uw_Urmail_TlsNoVerify:
    curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    break;
  }

  curl_easy_setopt(curl, CURLOPT_MAIL_FROM, addrOf(j->h->from));
  curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
  curl_easy_setopt(curl, CURLOPT_READFUNCTION, do_upload);
  curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
  curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
  //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  res = curl_easy_perform(curl);

  if (res != CURLE_OK)
    uw_set_error_message(j->ctx, "Curl error sending e-mail: %s", curl_easy_strerror(res));

  curl_slist_free_all(recipients);
  curl_easy_cleanup(curl);
}

static void free_job(void *p, int will_retry) {
  job *j = p;

  free_headers(j->h);
  free_string(j->server);
  free_string(j->ca);
  free_string(j->user);
  free_string(j->password);
  free(j->message);
  free(j);
}

uw_unit uw_Urmail_send(uw_context ctx, uw_Basis_string server, uw_Urmail_tls tls,
                     uw_Basis_string user, uw_Basis_string password,
                     uw_Urmail_headers h, uw_Basis_string body, uw_Basis_string xbody) {
  job *j;
  buf b = {NULL, 0, 0};

  if (!h || !h->from)
    uw_error(ctx, FATAL, "No From address set for e-mail message");

  if (!h->to && !h->cc && !h->bcc)
    uw_error(ctx, FATAL, "No recipients specified for e-mail message");

  // Everything that can fail happens here, in the transaction, where an error
  // is an error of the request; the commit callback only talks to the server.
  assemble(ctx, &b, h, body, xbody);

  j = malloc(sizeof(job));

  j->ctx = ctx;
  j->h = copy_headers(h);
  j->server = copy_string(server);
  j->tls = tls->tag;
  j->ca = tls->tag == uw_Urmail_Tls ? copy_string(tls->data.uw_Tls) : NULL;
  j->user = copy_string(user);
  j->password = copy_string(password);
  j->message = b.s;
  j->length = b.len;

  if (uw_register_transactional(ctx, j, commit, NULL, free_job)) {
    free_job(j, 0);
    uw_error(ctx, FATAL, "urmail: too many transactionals registered");
  }

  return uw_unit_v;
}
