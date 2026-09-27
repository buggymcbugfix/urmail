#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <curl/curl.h>

#include <urweb/urweb.h>
#include "urmail.h"

struct headers {
  uw_Basis_string from, to, cc, bcc, subject, user_agent, message_id;
  // What is wrong with the message, if anything: the first problem a builder
  // below found.  Urmail.mkHeaders asks for it (problem, below) and reports
  // it, so that no builder has to fail.
  const char *error;
};

typedef struct headers *uw_UrmailFfi_headers;

uw_UrmailFfi_headers uw_UrmailFfi_empty = NULL;

// A header value may be anything but a line break; long or non-ASCII values
// are encoded and folded when the message is assembled (RFC 2047 and 5322).
// The limit is generous but there has to be one: it bounds the buffers.
// The checks return what is wrong, or NULL.
static const char *header(uw_Basis_string s) {
  if (strlen(s) > 2000)
    return "Header value too long";

  for (; *s; ++s)
    if (*s == '\r' || *s == '\n')
      return "Header value contains newline";

  return NULL;
}

// An address is either an addr-spec or "Display Name <addr-spec>".  The
// addr-spec is what goes into the envelope, so it must be there.
static const char *address(uw_Basis_string s) {
  const char *p, *e;

  if ((e = header(s)))
    return e;

  if (strchr(s, ','))
    return "E-mail address contains comma";

  for (p = s; *p == ' ' || *p == '\t'; ++p);
  if (!*p)
    return "Empty e-mail address";
  if (strchr(p, '<') && !strchr(p, '>'))
    return "E-mail address has '<' but no '>'";

  return NULL;
}

// A copy of the headers to add to, with the first problem kept.
static uw_UrmailFfi_headers extend(uw_context ctx, uw_UrmailFfi_headers h, const char *error) {
  uw_UrmailFfi_headers h2 = uw_malloc(ctx, sizeof(struct headers));

  if (h)
    *h2 = *h;
  else
    memset(h2, 0, sizeof(*h2));

  if (error && !h2->error)
    h2->error = error;

  return h2;
}

// A comma-separated list of addresses, as the envelope wants them.
static uw_Basis_string append_address(uw_context ctx, uw_Basis_string list, uw_Basis_string s) {
  if (list) {
    uw_Basis_string all = uw_malloc(ctx, strlen(list) + 2 + strlen(s));
    sprintf(all, "%s,%s", list, s);
    return all;
  } else
    return uw_strdup(ctx, s);
}

uw_UrmailFfi_headers uw_UrmailFfi_from(uw_context ctx, uw_Basis_string s, uw_UrmailFfi_headers h) {
  uw_UrmailFfi_headers h2 = extend(ctx, h, h && h->from ? "Duplicate From header" : address(s));
  h2->from = uw_strdup(ctx, s);
  return h2;
}

uw_UrmailFfi_headers uw_UrmailFfi_to(uw_context ctx, uw_Basis_string s, uw_UrmailFfi_headers h) {
  uw_UrmailFfi_headers h2 = extend(ctx, h, address(s));
  h2->to = append_address(ctx, h2->to, s);
  return h2;
}

uw_UrmailFfi_headers uw_UrmailFfi_cc(uw_context ctx, uw_Basis_string s, uw_UrmailFfi_headers h) {
  uw_UrmailFfi_headers h2 = extend(ctx, h, address(s));
  h2->cc = append_address(ctx, h2->cc, s);
  return h2;
}

uw_UrmailFfi_headers uw_UrmailFfi_bcc(uw_context ctx, uw_Basis_string s, uw_UrmailFfi_headers h) {
  uw_UrmailFfi_headers h2 = extend(ctx, h, address(s));
  h2->bcc = append_address(ctx, h2->bcc, s);
  return h2;
}

uw_UrmailFfi_headers uw_UrmailFfi_subject(uw_context ctx, uw_Basis_string s, uw_UrmailFfi_headers h) {
  uw_UrmailFfi_headers h2 = extend(ctx, h, h && h->subject ? "Duplicate Subject header" : header(s));
  h2->subject = uw_strdup(ctx, s);
  return h2;
}

uw_UrmailFfi_headers uw_UrmailFfi_user_agent(uw_context ctx, uw_Basis_string s, uw_UrmailFfi_headers h) {
  uw_UrmailFfi_headers h2 = extend(ctx, h, h && h->user_agent ? "Duplicate User-Agent header" : header(s));
  h2->user_agent = uw_strdup(ctx, s);
  return h2;
}

static const char *message_id(uw_Basis_string s) {
  size_t n = strlen(s);
  const char *p, *e;

  if ((e = header(s)))
    return e;
  if (n < 3 || s[0] != '<' || s[n-1] != '>' || !strchr(s, '@'))
    return "Message-ID is not of the form <left@right>";
  for (p = s; *p; ++p)
    if (*p == ' ' || *p == '\t' || (*p == '<' && p != s) || (*p == '>' && p != s + n - 1))
      return "Message-ID contains a space or a stray bracket";
  return NULL;
}

uw_UrmailFfi_headers uw_UrmailFfi_messageId(uw_context ctx, uw_Basis_string s, uw_UrmailFfi_headers h) {
  uw_UrmailFfi_headers h2 = extend(ctx, h, h && h->message_id ? "Duplicate Message-ID header" : message_id(s));
  h2->message_id = uw_strdup(ctx, s);
  return h2;
}

/* ---- Attachments: built one at a time and checked, like the headers; a
   list of them goes to send. ---- */

struct attachment {
  uw_Basis_string ascii_name;  // the filename= every client reads
  uw_Basis_string utf8_name;   // the filename*= beside it, or NULL
  uw_Basis_string type;        // type/subtype
  uw_Basis_blob data;
  int is_inline;               // referred to from the HTML part by its Content-ID
  char content_id[24];         // for an inline part: hex@urmail, without the brackets
  const char *error;           // the first problem a check found, or NULL
};

// The name limits keep a Content-Disposition line under the 998 bytes SMTP
// allows without RFC 2231 continuations: 255 bytes percent-encoded is 765.
#define NAME_MAX_BYTES 255

// What is wrong with a name as a filename= parameter, or NULL.
static const char *ascii_name(uw_Basis_string s) {
  const char *p;

  if (!*s)
    return "name is empty";
  if (strlen(s) > NAME_MAX_BYTES)
    return "name is longer than 255 bytes";
  for (p = s; *p; ++p) {
    if ((unsigned char)*p < 0x20 || (unsigned char)*p > 0x7E)
      return "name is not printable ASCII";
    if (*p == '/' || *p == '\\')
      return "name contains '/' or '\\'";
  }
  return NULL;
}

// The same for the UTF-8 name, which any byte but a control character may be in.
static const char *utf8_name(uw_Basis_string s) {
  const char *p;

  if (!*s)
    return "UTF-8 name is empty";
  if (strlen(s) > NAME_MAX_BYTES)
    return "UTF-8 name is longer than 255 bytes";
  for (p = s; *p; ++p) {
    if ((unsigned char)*p < 0x20 || *p == 0x7F)
      return "UTF-8 name contains a control character";
    if (*p == '/' || *p == '\\')
      return "UTF-8 name contains '/' or '\\'";
  }
  return NULL;
}

// A MIME type as it goes into Content-Type: type/subtype of the characters
// Basis.checkMime allows, so no parameters, and exactly one slash.
static const char *mime_type(uw_Basis_string s) {
  const char *p, *slash = NULL;

  for (p = s; *p; ++p) {
    if (*p == '/') {
      if (slash)
        return "MIME type has more than one slash";
      slash = p;
    } else if (!isalnum((unsigned char)*p) && *p != '-' && *p != '.' && *p != '+')
      return "MIME type has a character outside type/subtype";
  }
  if (!slash || slash == s || !slash[1])
    return "MIME type is not of the form type/subtype";
  return NULL;
}

uw_UrmailFfi_attachment uw_UrmailFfi_attach(uw_context ctx, uw_Basis_string ascii, uw_Basis_string utf8,
                                            uw_Basis_string type, uw_Basis_blob data) {
  uw_UrmailFfi_attachment a = uw_malloc(ctx, sizeof(struct attachment));
  const char *error;

  a->ascii_name = uw_strdup(ctx, ascii);
  a->utf8_name = utf8 ? uw_strdup(ctx, utf8) : NULL;
  a->type = uw_strdup(ctx, type);
  a->data = data;
  a->is_inline = 0;
  a->content_id[0] = 0;
  if (!(error = ascii_name(ascii)) && !(utf8 && (error = utf8_name(utf8))))
    error = mime_type(type);
  a->error = error;
  return a;
}

uw_Basis_string uw_UrmailFfi_attachmentProblem(uw_context ctx, uw_UrmailFfi_attachment a) {
  return a->error ? uw_strdup(ctx, (char *)a->error) : NULL;
}

// An inline part's Content-ID: a function of the part (FNV-1a over its name,
// type and bytes), so that `inline` is pure and the cid: URL it hands out is
// the one assemble() writes.
static void content_id(uw_UrmailFfi_attachment a) {
  unsigned long long h = 14695981039346656037ULL;
  const unsigned char *p;
  size_t i;

  for (p = (const unsigned char *)a->ascii_name; ; ++p) {
    h = (h ^ *p) * 1099511628211ULL;
    if (!*p) break;
  }
  for (p = (const unsigned char *)a->type; ; ++p) {
    h = (h ^ *p) * 1099511628211ULL;
    if (!*p) break;
  }
  for (i = 0, p = (const unsigned char *)a->data.data; i < a->data.size; ++i, ++p)
    h = (h ^ *p) * 1099511628211ULL;
  snprintf(a->content_id, sizeof a->content_id, "%016llx@urmail", h);
}

uw_UrmailFfi_attachment uw_UrmailFfi_inline(uw_context ctx, uw_UrmailFfi_attachment a) {
  uw_UrmailFfi_attachment a2 = uw_malloc(ctx, sizeof(struct attachment));

  *a2 = *a;
  a2->is_inline = 1;
  content_id(a2);
  return a2;
}

uw_Basis_string uw_UrmailFfi_cid(uw_context ctx, uw_UrmailFfi_attachment a) {
  uw_Basis_string url;

  if (!a->is_inline)
    uw_error(ctx, FATAL, "urmail: cid of an attachment that is not inline");
  url = uw_malloc(ctx, 4 + strlen(a->content_id) + 1);
  sprintf(url, "cid:%s", a->content_id);
  return url;
}

// The list, newest first; send reads it backwards.
struct attachments {
  uw_UrmailFfi_attachment a;
  struct attachments *next;
};

uw_UrmailFfi_attachments uw_UrmailFfi_noAttachments = NULL;

uw_UrmailFfi_attachments uw_UrmailFfi_addAttachment(uw_context ctx, uw_UrmailFfi_attachment a,
                                                    uw_UrmailFfi_attachments l) {
  uw_UrmailFfi_attachments l2 = uw_malloc(ctx, sizeof(struct attachments));

  l2->a = a;
  l2->next = l;
  return l2;
}

// What deliver() needs: the arguments of send, the TLS choice unpacked, and
// the message as it goes over the wire.  Nothing here outlives the call.
typedef struct {
  uw_UrmailFfi_headers h;
  const char *server, *ca, *user, *password;
  enum uw_UrmailFfi_tls_tag tls;
  const char *message;
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

/* ---- A growable byte buffer for assembling the message.  malloc-based,
   since it grows by realloc; freed once the message is delivered. ---- */

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

// A body as quoted-printable (RFC 2045): lines of at most 76 characters,
// CRLF line ends whatever the input had, everything outside printable ASCII
// as =XX.  Long lines and 8-bit text then pass any SMTP server, and a bare
// '.' at the start of a line is encoded too, so nothing depends on
// dot-stuffing.
static void buf_qp(uw_context ctx, buf *b, const char *s) {
  static const char hex[] = "0123456789ABCDEF";
  size_t col = 0;
  int at_line_start = 1;
  for (; *s; ++s) {
    unsigned char c = *s;
    char enc[3];
    size_t n;
    if (c == '\r' && s[1] == '\n')
      continue;  // the \n below writes the CRLF
    if (c == '\n') {
      buf_append(ctx, b, "\r\n", 2);
      col = 0;
      at_line_start = 1;
      continue;
    }
    if ((c >= 33 && c <= 126 && c != '=' && !(at_line_start && c == '.'))
        || ((c == ' ' || c == '\t') && s[1] && s[1] != '\n' && !(s[1] == '\r' && s[2] == '\n'))) {
      enc[0] = c;
      n = 1;
    } else {
      enc[0] = '=';
      enc[1] = hex[c >> 4];
      enc[2] = hex[c & 15];
      n = 3;
    }
    if (col + n > 75) {  // room for the soft break's '=' within 76
      buf_append(ctx, b, "=\r\n", 3);
      col = 0;
    }
    buf_append(ctx, b, enc, n);
    col += n;
    at_line_start = 0;
  }
}

// The boundaries of the multiparts.  Fixed, and safe: every part is
// quoted-printable or base64, and neither encoding can produce "=_" (in
// quoted-printable an '=' is followed by two hex digits or a line break, and
// base64 has no '_'), so no boundary starting with it can occur in a part.
#define ALTERNATIVE_BOUNDARY "=_urmail_alternative"
#define RELATED_BOUNDARY "=_urmail_related"
#define MIXED_BOUNDARY "=_urmail_mixed"

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

// The bytes as base64 in lines of 76 characters (RFC 2045), CRLF between
// them and none after the last.
static void buf_base64_lines(uw_context ctx, buf *b, const unsigned char *s, size_t n) {
  size_t i;
  for (i = 0; i < n; i += 57) {
    if (i)
      buf_append(ctx, b, "\r\n", 2);
    buf_base64(ctx, b, s + i, n - i < 57 ? n - i : 57);
  }
}

// A name as the value of filename=: quoted, with '"' and '\' escaped.
static void buf_quoted(uw_context ctx, buf *b, const char *s) {
  buf_str(ctx, b, "\"");
  for (; *s; ++s) {
    if (*s == '"' || *s == '\\')
      buf_str(ctx, b, "\\");
    buf_append(ctx, b, s, 1);
  }
  buf_str(ctx, b, "\"");
}

// A name as the value of filename*= (RFC 2231): UTF-8, percent-encoded but
// for letters, digits and "-._".
static void buf_extended(uw_context ctx, buf *b, const char *s) {
  static const char hex[] = "0123456789ABCDEF";
  buf_str(ctx, b, "UTF-8''");
  for (; *s; ++s) {
    unsigned char c = *s;
    if (isalnum(c) || c == '-' || c == '.' || c == '_')
      buf_append(ctx, b, s, 1);
    else {
      char enc[3] = {'%', hex[c >> 4], hex[c & 15]};
      buf_append(ctx, b, enc, 3);
    }
  }
}

// One attachment as a MIME part: its headers, then the bytes in base64.  The
// ASCII name is the filename= every client reads; the UTF-8 name, when
// there is one, is a filename*= (RFC 2231) beside it, first, since a parser
// that takes the first of the two is then right, and on a line of its own.
// An inline part has the Content-ID the HTML refers to.
static void buf_attachment(uw_context ctx, buf *b, uw_UrmailFfi_attachment a) {
  buf_str(ctx, b, "Content-Type: "); buf_str(ctx, b, a->type); buf_str(ctx, b, "\r\n");
  if (a->is_inline) {
    buf_str(ctx, b, "Content-ID: <"); buf_str(ctx, b, a->content_id); buf_str(ctx, b, ">\r\n");
  }
  buf_str(ctx, b, a->is_inline ? "Content-Disposition: inline;" : "Content-Disposition: attachment;");
  if (a->utf8_name) {
    buf_str(ctx, b, " filename*=");
    buf_extended(ctx, b, a->utf8_name);
    buf_str(ctx, b, ";\r\n");
  }
  buf_str(ctx, b, " filename=");
  buf_quoted(ctx, b, a->ascii_name);
  buf_str(ctx, b, "\r\nContent-Transfer-Encoding: base64\r\n\r\n");
  buf_base64_lines(ctx, b, (const unsigned char *)a->data.data, a->data.size);
}

// The text body, or the multipart/alternative of it and the HTML document,
// with its Content-Type: the whole message's, or a part's.  `xbody` is the
// string of a `page` value, which is the document's contents without the
// html element (the runtime adds that when it serves a page), hence the
// wrapper.
static void buf_body(uw_context ctx, buf *b, uw_Basis_string body, uw_Basis_string xbody) {
  if (xbody) {
    buf_str(ctx, b, "Content-Type: multipart/alternative; boundary=\"" ALTERNATIVE_BOUNDARY "\"\r\n\r\n"
                    "--" ALTERNATIVE_BOUNDARY "\r\n"
                    "Content-Type: text/plain; charset=utf-8\r\n"
                    "Content-Transfer-Encoding: quoted-printable\r\n\r\n");
    buf_qp(ctx, b, body);
    buf_str(ctx, b, "\r\n--" ALTERNATIVE_BOUNDARY "\r\n"
                    "Content-Type: text/html; charset=utf-8\r\n"
                    "Content-Transfer-Encoding: quoted-printable\r\n\r\n");
    {
      // The wrapper is part of the encoded document.
      buf doc = {NULL, 0, 0};
      buf_str(ctx, &doc, "<!DOCTYPE html><html>");
      buf_str(ctx, &doc, xbody);
      buf_str(ctx, &doc, "</html>");
      buf_qp(ctx, b, doc.s);
      free(doc.s);
    }
    buf_str(ctx, b, "\r\n--" ALTERNATIVE_BOUNDARY "--");
  } else {
    buf_str(ctx, b, "Content-Type: text/plain; charset=utf-8\r\n"
                    "Content-Transfer-Encoding: quoted-printable\r\n\r\n");
    buf_qp(ctx, b, body);
  }
}

// The inline or the attached parts of the list, in the order they were
// given: the list is newest first.
static size_t in_order(uw_UrmailFfi_attachments l, int is_inline, uw_UrmailFfi_attachment **out) {
  size_t n = 0, i;
  uw_UrmailFfi_attachments p;

  for (p = l; p; p = p->next)
    if (p->a->is_inline == is_inline)
      ++n;
  *out = n ? malloc(n * sizeof **out) : NULL;
  for (p = l, i = n; p; p = p->next)
    if (p->a->is_inline == is_inline)
      (*out)[--i] = p->a;
  return n;
}

// Whether any part of the list is inline.
static int has_inline(uw_UrmailFfi_attachments l) {
  for (; l; l = l->next)
    if (l->a->is_inline)
      return 1;
  return 0;
}

// Assemble the message: headers, then the body; with inline parts, a
// multipart/related of the body and those; with attached parts, a
// multipart/mixed of all that and those.
static void assemble(uw_context ctx, buf *b, uw_UrmailFfi_headers h,
                     uw_Basis_string body, uw_Basis_string xbody, uw_UrmailFfi_attachments attachments) {
  char date[64], message_id[512];
  uw_UrmailFfi_attachment *inlines, *attached;
  size_t n_inline, n_attached, i;

  date_header(date);
  buf_str(ctx, b, "MIME-Version: 1.0\r\n");
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

  n_inline = in_order(attachments, 1, &inlines);
  n_attached = in_order(attachments, 0, &attached);
  if (n_attached)
    buf_str(ctx, b, "Content-Type: multipart/mixed; boundary=\"" MIXED_BOUNDARY "\"\r\n\r\n"
                    "--" MIXED_BOUNDARY "\r\n");
  if (n_inline)  // RFC 2387 wants the root's type named; with an inline part there is an HTML part
    buf_str(ctx, b, "Content-Type: multipart/related; type=\"multipart/alternative\";\r\n"
                    " boundary=\"" RELATED_BOUNDARY "\"\r\n\r\n"
                    "--" RELATED_BOUNDARY "\r\n");
  buf_body(ctx, b, body, xbody);
  for (i = 0; i < n_inline; ++i) {
    buf_str(ctx, b, "\r\n--" RELATED_BOUNDARY "\r\n");
    buf_attachment(ctx, b, inlines[i]);
  }
  if (n_inline)
    buf_str(ctx, b, "\r\n--" RELATED_BOUNDARY "--");
  for (i = 0; i < n_attached; ++i) {
    buf_str(ctx, b, "\r\n--" MIXED_BOUNDARY "\r\n");
    buf_attachment(ctx, b, attached[i]);
  }
  if (n_attached)
    buf_str(ctx, b, "\r\n--" MIXED_BOUNDARY "--");
  free(inlines);
  free(attached);
}

/* ---- Delivery: a persistent connection per server and account, one send at
   a time on each, and an outcome that says what is known. ---- */

typedef enum { SENT, REFUSED, NOT_SENT, MAYBE_SENT } outcome_kind;

typedef struct {
  outcome_kind kind;
  char message[512];  // unless SENT: what libcurl said, and the server's
                      // last reply code if there was one
} outcome;

// Debug tracing, on stderr, when URMAIL_DEBUG is set to anything but "" or "0".
static int debugging(void) {
  static int state = -1;
  if (state < 0) {
    const char *v = getenv("URMAIL_DEBUG");
    state = v && *v && strcmp(v, "0") != 0;
  }
  return state;
}

#define DBG(...) do { if (debugging()) { fprintf(stderr, "urmail: " __VA_ARGS__); fputc('\n', stderr); } } while (0)

// Seconds without progress (connecting, or waiting for the server) after
// which a send is given up.  URMAIL_TIMEOUT overrides the default, for tests.
static long timeout_seconds(void) {
  static long t = -1;
  if (t < 0) {
    const char *v = getenv("URMAIL_TIMEOUT");
    t = v && *v ? atol(v) : 60;
    if (t <= 0)
      t = 60;
  }
  return t;
}

typedef struct smtp_conn {
  char *server, *user, *password, *ca;
  enum uw_UrmailFfi_tls_tag tls;
  CURL *curl;
  pthread_mutex_t lock;  // held for the duration of a send on this connection
  struct smtp_conn *next;
} smtp_conn;

static smtp_conn *conns = NULL;
static pthread_mutex_t conns_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t curl_once = PTHREAD_ONCE_INIT;

static void curl_init(void) {
  curl_global_init(CURL_GLOBAL_DEFAULT);
}

static int str_eq(const char *a, const char *b) {
  return (a == NULL && b == NULL) || (a && b && !strcmp(a, b));
}

// The connection for this server and account, created on first use.  The
// libcurl handle keeps the TCP (and TLS) connection open between sends, so a
// batch of messages does not pay for a handshake and a login each.
static smtp_conn *get_connection(job *j) {
  smtp_conn *c;
  pthread_once(&curl_once, curl_init);
  pthread_mutex_lock(&conns_lock);
  for (c = conns; c; c = c->next)
    if (!strcmp(c->server, j->server) && !strcmp(c->user, j->user)
        && !strcmp(c->password, j->password) && str_eq(c->ca, j->ca) && c->tls == j->tls)
      break;
  if (!c) {
    c = malloc(sizeof(smtp_conn));
    c->server = strdup(j->server);
    c->user = strdup(j->user);
    c->password = strdup(j->password);
    c->ca = j->ca ? strdup(j->ca) : NULL;
    c->tls = j->tls;
    c->curl = NULL;
    pthread_mutex_init(&c->lock, NULL);
    c->next = conns;
    conns = c;
    DBG("new connection record for %s as %s", c->server, c->user);
  }
  pthread_mutex_unlock(&conns_lock);
  return c;
}

static struct curl_slist *add_recipients(struct curl_slist *l, const char *list) {
  if (list) {
    char *copy = strdup(list), *saveptr, *addr = strtok_r(copy, ",", &saveptr);
    if (addr)
      do {
        l = curl_slist_append(l, addrOf(addr));
      } while ((addr = strtok_r(NULL, ",", &saveptr)));
    free(copy);
  }
  return l;
}

// One attempt; `fresh` forces a new TCP connection.
static CURLcode attempt(smtp_conn *c, job *j, struct curl_slist *recipients,
                        upload_status *up, int fresh) {
  CURL *curl = c->curl;
  char *from = strdup(j->h->from);
  CURLcode res;
  long t = timeout_seconds();

  curl_easy_reset(curl);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);  // threads: no SIGALRM for timeouts
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, t);
  curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1L);
  curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, t);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10 * t);  // the hard cap, for a stalling server
  if (fresh)
    curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 1L);

  curl_easy_setopt(curl, CURLOPT_USERNAME, j->user);
  curl_easy_setopt(curl, CURLOPT_PASSWORD, j->password);
  curl_easy_setopt(curl, CURLOPT_URL, j->server);
  // A URL without a scheme is SMTP (libcurl would otherwise guess from the
  // host name, HTTP unless it starts with "smtp."), and nothing else is.
  curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "smtp");
#if LIBCURL_VERSION_NUM >= 0x075500
  curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "smtp,smtps");
#else
  curl_easy_setopt(curl, CURLOPT_PROTOCOLS, (long)(CURLPROTO_SMTP | CURLPROTO_SMTPS));
#endif

  switch (j->tls) {
  case uw_UrmailFfi_Plain:
    curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_NONE);
    break;
  case uw_UrmailFfi_Tls:
    curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
    if (j->ca)
      curl_easy_setopt(curl, CURLOPT_CAINFO, j->ca);
    // else libcurl's default: the system's CA bundle, verified.
    break;
  case uw_UrmailFfi_TlsNoVerify:
    curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    break;
  }

  curl_easy_setopt(curl, CURLOPT_MAIL_FROM, addrOf(from));
  curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
  curl_easy_setopt(curl, CURLOPT_READFUNCTION, do_upload);
  curl_easy_setopt(curl, CURLOPT_READDATA, up);
  curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
  if (debugging())
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  res = curl_easy_perform(curl);
  free(from);
  return res;
}

// Send the job's message.  What can be told afterwards:
//
//   - CURLE_OK: sent.
//   - The server answered with a code of 500 or more: it refused something
//     (a recipient, the message) for good; sending again will not help.
//   - The server answered with a code of 400 to 499: it declined for now (a
//     mailbox busy, storage short, greylisting); not sent, try again later.
//   - The connection broke before any of the message was uploaded: not sent.
//     When the connection was a reused one, the server may simply have
//     dropped it while idle, and one more attempt is made, on a fresh one.
//   - The connection broke after the message was uploaded, in full or in part,
//     and the server's verdict never arrived: maybe sent.  No retry here; that
//     is the caller's decision, since it may mean a duplicate.
static void deliver(job *j, outcome *o) {
  smtp_conn *c = get_connection(j);
  struct curl_slist *recipients = NULL;
  upload_status up;
  CURLcode res;
  int fresh = 0, tries = 0;

  recipients = add_recipients(recipients, j->h->to);
  recipients = add_recipients(recipients, j->h->cc);
  recipients = add_recipients(recipients, j->h->bcc);

  pthread_mutex_lock(&c->lock);
  if (!c->curl)
    c->curl = curl_easy_init();
  if (!c->curl) {
    pthread_mutex_unlock(&c->lock);
    curl_slist_free_all(recipients);
    o->kind = NOT_SENT;
    snprintf(o->message, sizeof o->message, "cannot create a libcurl handle");
    return;
  }

  for (;;) {
    long code = 0, connects = 0;
    curl_off_t uploaded = 0;

    up.content = j->message;
    up.length = j->length;
    ++tries;
    DBG("attempt %d (%s connection) for %s", tries, fresh ? "fresh" : "reused if possible", j->server);
    res = attempt(c, j, recipients, &up, fresh);

    if (res == CURLE_OK) {
      DBG("sent");
      o->kind = SENT;
      o->message[0] = 0;
      break;
    }

    curl_easy_getinfo(c->curl, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_getinfo(c->curl, CURLINFO_SIZE_UPLOAD_T, &uploaded);
    curl_easy_getinfo(c->curl, CURLINFO_NUM_CONNECTS, &connects);
    DBG("failed: %s (SMTP %ld, uploaded %lld bytes, %ld new connections)",
        curl_easy_strerror(res), code, (long long)uploaded, connects);

    if (code >= 500) {
      o->kind = REFUSED;
      snprintf(o->message, sizeof o->message, "server refused: %s (SMTP %ld)",
               curl_easy_strerror(res), code);
      break;
    }

    if (code >= 400) {
      o->kind = NOT_SENT;
      snprintf(o->message, sizeof o->message, "server declined for now: %s (SMTP %ld)",
               curl_easy_strerror(res), code);
      break;
    }

    if (uploaded > 0) {
      o->kind = MAYBE_SENT;
      snprintf(o->message, sizeof o->message, "connection lost after the message was sent: %s",
               curl_easy_strerror(res));
      break;
    }

    if (tries == 1 && connects == 0
        && (res == CURLE_SEND_ERROR || res == CURLE_RECV_ERROR || res == CURLE_GOT_NOTHING)) {
      // A reused connection that the server had closed: try once more, fresh.
      fresh = 1;
      continue;
    }

    o->kind = NOT_SENT;
    snprintf(o->message, sizeof o->message, "%s", curl_easy_strerror(res));
    break;
  }

  if (res != CURLE_OK) {
    // Whatever state the connection is in, do not reuse it.
    curl_easy_cleanup(c->curl);
    c->curl = NULL;
  }
  pthread_mutex_unlock(&c->lock);
  curl_slist_free_all(recipients);
}

// What is wrong with the message, or NULL: the problems the builders found,
// and what only the whole message shows.
static const char *check(uw_UrmailFfi_headers h) {
  if (!h || !h->from)
    return "No From address set for e-mail message";
  if (h->error)
    return h->error;
  if (!h->to && !h->cc && !h->bcc)
    return "No recipients specified for e-mail message";
  return NULL;
}

// UrmailFfi.problem: what check() says, for Urmail.mkHeaders to report.  An
// `option string` is the string itself, or NULL for None.
uw_Basis_string uw_UrmailFfi_problem(uw_context ctx, uw_UrmailFfi_headers h) {
  const char *wrong = check(h);

  return wrong ? uw_strdup(ctx, wrong) : NULL;
}

// Headers that Urmail.mkHeaders did not pass, or an attachment that
// Urmail.Attachment did not: not something the Ur side can produce, so an
// error of the caller.
static void refuse(uw_context ctx, uw_UrmailFfi_headers h, uw_UrmailFfi_attachments attachments) {
  const char *wrong = check(h);
  uw_UrmailFfi_attachments p;

  if (wrong)
    uw_error(ctx, FATAL, "urmail: headers not from mkHeaders: %s", wrong);
  for (p = attachments; p; p = p->next)
    if (p->a->error)
      uw_error(ctx, FATAL, "urmail: attachment not from Urmail.Attachment: %s", p->a->error);
}

// UrmailFfi.send, in io: assemble the message, send it now, and say what
// became of it.
uw_UrmailFfi_sendStatus uw_UrmailFfi_send(uw_context ctx, uw_Basis_string server, uw_UrmailFfi_tls tls,
                                          uw_Basis_string user, uw_Basis_string password,
                                          uw_UrmailFfi_headers h, uw_Basis_string body, uw_Basis_string xbody,
                                          uw_UrmailFfi_attachments attachments) {
  buf b = {NULL, 0, 0};
  job j;
  outcome o;
  uw_UrmailFfi_sendStatus r = uw_malloc(ctx, sizeof(struct uw_UrmailFfi_sendStatus));

  refuse(ctx, h, attachments);
  if (!xbody && has_inline(attachments)) {
    // Nothing would refer to the part: a mistake of the caller, reported
    // as the status rather than as an error, which would leave the message
    // claimed and unsent; Refused, since sending it again will not help.
    r->tag = uw_UrmailFfi_Refused;
    r->data.uw_Refused = uw_strdup(ctx, "inline attachment without an HTML part");
    return r;
  }
  assemble(ctx, &b, h, body, xbody, attachments);

  j.h = h;
  j.server = server;
  j.tls = tls->tag;
  j.ca = tls->tag == uw_UrmailFfi_Tls ? tls->data.uw_Tls : NULL;
  j.user = user;
  j.password = password;
  j.message = b.s;
  j.length = b.len;

  deliver(&j, &o);
  free(b.s);

  switch (o.kind) {
  case SENT:
    r->tag = uw_UrmailFfi_Sent;
    break;
  case REFUSED:
    r->tag = uw_UrmailFfi_Refused;
    r->data.uw_Refused = uw_strdup(ctx, o.message);
    break;
  case NOT_SENT:
    r->tag = uw_UrmailFfi_NotSent;
    r->data.uw_NotSent = uw_strdup(ctx, o.message);
    break;
  case MAYBE_SENT:
    r->tag = uw_UrmailFfi_MaybeSent;
    r->data.uw_MaybeSent = uw_strdup(ctx, o.message);
    break;
  }
  return r;
}
