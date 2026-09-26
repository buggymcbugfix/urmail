#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <curl/curl.h>

#include <urweb/urweb.h>
#include "urmail.h"

struct headers {
  uw_Basis_string from, to, cc, bcc, subject, user_agent, message_id;
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
  h2->message_id = copy_string(h->message_id);
  return h2;
}

static void free_headers(uw_Urmail_headers h) {
  free_string(h->from);
  free_string(h->to);
  free_string(h->cc);
  free_string(h->bcc);
  free_string(h->subject);
  free_string(h->user_agent);
  free_string(h->message_id);
  free(h);
}

uw_Urmail_headers uw_Urmail_empty = NULL;

// A header value may be anything but a line break; long or non-ASCII values
// are encoded and folded when the message is assembled (RFC 2047 and 5322).
// The limit is generous but there has to be one: it bounds the buffers.
static void header(uw_context ctx, uw_Basis_string s) {
  if (strlen(s) > 2000)
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

uw_Urmail_headers uw_Urmail_messageId(uw_context ctx, uw_Basis_string s, uw_Urmail_headers h) {
  uw_Urmail_headers h2 = uw_malloc(ctx, sizeof(struct headers));
  size_t n = strlen(s);
  const char *p;

  if (h)
    *h2 = *h;
  else
    memset(h2, 0, sizeof(*h2));

  if (h2->message_id)
    uw_error(ctx, FATAL, "Duplicate Message-ID header");

  header(ctx, s);
  if (n < 3 || s[0] != '<' || s[n-1] != '>' || !strchr(s, '@'))
    uw_error(ctx, FATAL, "Message-ID is not of the form <left@right>");
  for (p = s; *p; ++p)
    if (*p == ' ' || *p == '\t' || (*p == '<' && p != s) || (*p == '>' && p != s + n - 1))
      uw_error(ctx, FATAL, "Message-ID contains a space or a stray bracket");
  h2->message_id = uw_strdup(ctx, s);

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

/* ---- Header encoding: RFC 2047 encoded-words for what is not ASCII, and
   folding for what is long. ---- */

static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void buf_base64(uw_context ctx, buf *b, const unsigned char *s, size_t n) {
  size_t i;
  for (i = 0; i + 2 < n; i += 3) {
    char q[4] = {b64[s[i] >> 2], b64[((s[i] & 3) << 4) | (s[i+1] >> 4)],
                 b64[((s[i+1] & 15) << 2) | (s[i+2] >> 6)], b64[s[i+2] & 63]};
    buf_append(ctx, b, q, 4);
  }
  if (i + 1 == n) {
    char q[4] = {b64[s[i] >> 2], b64[(s[i] & 3) << 4], '=', '='};
    buf_append(ctx, b, q, 4);
  } else if (i + 2 == n) {
    char q[4] = {b64[s[i] >> 2], b64[((s[i] & 3) << 4) | (s[i+1] >> 4)],
                 b64[(s[i+1] & 15) << 2], '='};
    buf_append(ctx, b, q, 4);
  }
}

static int is_ascii_text(const char *s) {
  for (; *s; ++s)
    if ((unsigned char)*s >= 0x80 || ((unsigned char)*s < 0x20 && *s != '\t'))
      return 0;
  return 1;
}

// `s` as a sequence of encoded-words, each of at most 75 characters and
// holding whole UTF-8 characters, folded onto continuation lines.
static void buf_encoded_words(uw_context ctx, buf *b, const char *s) {
  size_t n = strlen(s), i = 0;
  int first = 1;
  while (i < n) {
    // Up to 45 bytes (60 base64 characters, 72 with the wrapping), cut at a
    // character boundary: a continuation byte is 10xxxxxx.
    size_t len = n - i < 45 ? n - i : 45;
    while (len > 1 && i + len < n && ((unsigned char)s[i+len] & 0xC0) == 0x80)
      --len;
    if (!first)
      buf_str(ctx, b, "\r\n ");
    buf_str(ctx, b, "=?UTF-8?B?");
    buf_base64(ctx, b, (const unsigned char *)s + i, len);
    buf_str(ctx, b, "?=");
    first = 0;
    i += len;
  }
}

// A header value that is plain text (Subject, User-Agent): as it is when
// ASCII and short, encoded otherwise.
static void buf_text_header(uw_context ctx, buf *b, const char *s) {
  if (is_ascii_text(s) && strlen(s) <= 76)
    buf_str(ctx, b, s);
  else
    buf_encoded_words(ctx, b, s);
}

// One address for a header, with its display name encoded if it is not
// ASCII, or quoted if it has characters an unquoted phrase may not.
static void buf_address(uw_context ctx, buf *b, const char *s) {
  const char *lt = strchr(s, '<');
  const char *name_end;
  size_t name_len;
  while (*s == ' ' || *s == '\t')
    ++s;
  if (!lt || lt == s) {
    buf_str(ctx, b, s);
    return;
  }
  name_end = lt;
  while (name_end > s && (name_end[-1] == ' ' || name_end[-1] == '\t'))
    --name_end;
  name_len = name_end - s;
  if (name_len == 0) {
    buf_str(ctx, b, lt);
    return;
  }
  {
    char *name = malloc(name_len + 1);
    int plain = 1;
    const char *p;
    memcpy(name, s, name_len);
    name[name_len] = 0;
    for (p = name; *p; ++p)
      if (strchr("()<>[]:;@\\.\"", *p))
        plain = 0;
    if (!is_ascii_text(name))
      buf_encoded_words(ctx, b, name);
    else if (plain)
      buf_str(ctx, b, name);
    else {
      buf_str(ctx, b, "\"");
      for (p = name; *p; ++p) {
        if (*p == '"' || *p == '\\')
          buf_str(ctx, b, "\\");
        buf_append(ctx, b, p, 1);
      }
      buf_str(ctx, b, "\"");
    }
    free(name);
  }
  buf_str(ctx, b, " ");
  buf_str(ctx, b, lt);
}

// A list of addresses as the setters built it (comma-separated), one per
// line after the first when there are several.
static void buf_address_list(uw_context ctx, buf *b, const char *s) {
  int first = 1;
  while (*s) {
    const char *comma = strchr(s, ',');
    size_t len = comma ? (size_t)(comma - s) : strlen(s);
    char *one = malloc(len + 1);
    memcpy(one, s, len);
    one[len] = 0;
    if (!first)
      buf_str(ctx, b, ",\r\n ");
    buf_address(ctx, b, one);
    free(one);
    first = 0;
    s += len + (comma ? 1 : 0);
  }
}

// The current time as an RFC 5322 date, in UTC.  Not strftime, whose names
// follow the locale.
static void date_header(char out[64]) {
  static const char *days[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
  static const char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  time_t now = time(NULL);
  struct tm tm;
  gmtime_r(&now, &tm);
  snprintf(out, 64, "%s, %d %s %d %02d:%02d:%02d +0000",
           days[tm.tm_wday], tm.tm_mday, months[tm.tm_mon], tm.tm_year + 1900,
           tm.tm_hour, tm.tm_min, tm.tm_sec);
}

// The domain of an address ("Name <user@domain>" or "user@domain"), for a
// generated Message-ID; "localhost" when there is none.
static void domain_of(const char *addr, char *out, size_t n) {
  const char *lt = strchr(addr, '<'), *at, *end;
  at = strchr(lt ? lt : addr, '@');
  if (!at) {
    snprintf(out, n, "localhost");
    return;
  }
  ++at;
  end = at + strcspn(at, "> \t");
  if (end == at) {
    snprintf(out, n, "localhost");
    return;
  }
  snprintf(out, n, "%.*s", (int)(end - at), at);
}

// A Message-ID unique enough: random bytes, or if the system will not give
// any, the time, the process and a counter.
static void generate_message_id(const char *from, char *out, size_t n) {
  unsigned char r[12];
  char hex[25];
  char domain[256];
  FILE *f = fopen("/dev/urandom", "rb");
  int ok = f && fread(r, 1, sizeof r, f) == sizeof r;
  if (f)
    fclose(f);
  if (ok) {
    int i;
    for (i = 0; i < 12; ++i)
      snprintf(hex + 2*i, 3, "%02x", r[i]);
  } else {
    static unsigned counter = 0;
    snprintf(hex, sizeof hex, "%lx.%x.%x", (long)time(NULL), (unsigned)getpid(), ++counter);
  }
  domain_of(from, domain, sizeof domain);
  snprintf(out, n, "<%s@%s>", hex, domain);
}

// Assemble the message: headers, then the text body, or a multipart/alternative
// of the text body and the HTML document.  `xbody` is the string of a `page`
// value, which is the document's contents without the html element (the
// runtime adds that when it serves a page), hence the wrapper.
static void assemble(uw_context ctx, buf *b, uw_Urmail_headers h,
                     uw_Basis_string body, uw_Basis_string xbody) {
  char date[64], message_id[512];

  date_header(date);
  buf_str(ctx, b, "Date: "); buf_str(ctx, b, date); buf_str(ctx, b, "\r\n");
  if (h->message_id)
    buf_str(ctx, b, "Message-ID: "), buf_str(ctx, b, h->message_id), buf_str(ctx, b, "\r\n");
  else {
    generate_message_id(h->from, message_id, sizeof message_id);
    buf_str(ctx, b, "Message-ID: "); buf_str(ctx, b, message_id); buf_str(ctx, b, "\r\n");
  }
  if (h->from) {
    buf_str(ctx, b, "From: "); buf_address(ctx, b, h->from); buf_str(ctx, b, "\r\n");
  }
  if (h->subject) {
    buf_str(ctx, b, "Subject: "); buf_text_header(ctx, b, h->subject); buf_str(ctx, b, "\r\n");
  }
  if (h->to) {
    buf_str(ctx, b, "To: "); buf_address_list(ctx, b, h->to); buf_str(ctx, b, "\r\n");
  }
  if (h->cc) {
    buf_str(ctx, b, "Cc: "); buf_address_list(ctx, b, h->cc); buf_str(ctx, b, "\r\n");
  }
  if (h->user_agent) {
    buf_str(ctx, b, "User-Agent: "); buf_text_header(ctx, b, h->user_agent); buf_str(ctx, b, "\r\n");
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
