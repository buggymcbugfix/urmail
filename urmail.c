#include "config.h"
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <curl/curl.h>

#include <urweb/urweb.h>
#include "urmail.h"

/* ---- Addresses: parsed once, by UrmailFfi.parseAddress, into the display
   name and the addr-spec, so that the envelope gets exactly the addr-spec
   and the header gets the two parts, each written as its syntax wants.
   Nothing that was not parsed reaches the server. ---- */

struct address {
  uw_Basis_string text;   // as given, blanks around dropped: what show gives
  uw_Basis_string name;   // the display name as given, or NULL
  uw_Basis_string addr;   // local@domain: what the envelope gets
  const char *error;      // what is wrong with it, or NULL
};

typedef struct address *uw_UrmailFfi_emailAddress;

// The longest line a message may have, without its CRLF (RFC 5322,
// section 2.1.1).
#define MAX_LINE 998

// A number in a message.
#define DIGITS(x) #x
#define NUMBER(x) DIGITS(x)

// Whether s starts with prefix.
static int starts_with(const char *s, const char *prefix) {
  return !strncmp(s, prefix, strlen(prefix));
}

static int starts_with_nocase(const char *s, const char *prefix) {
  return !strncasecmp(s, prefix, strlen(prefix));
}

// Whether c is printable ASCII, RFC 5234's VCHAR: no blank, no control.
static int is_vchar(unsigned char c) {
  return c > ' ' && c < 0x7F;
}

// Whether s[0..n) is all ASCII.
static int is_ascii(const unsigned char *s, size_t n) {
  size_t i;

  for (i = 0; i < n; ++i)
    if (s[i] >= 0x80)
      return 0;
  return 1;
}

// Whether s[0..n) is UTF-8 as RFC 3629 has it: no overlong forms, no
// surrogates, nothing above U+10FFFF.
static int is_utf8(const unsigned char *s, size_t n) {
  size_t i = 0, len, k;
  unsigned long c, min;

  while (i < n) {
    if (s[i] < 0x80) {
      ++i;
      continue;
    }
    if ((s[i] & 0xE0) == 0xC0)
      len = 2, c = s[i] & 0x1F, min = 0x80;
    else if ((s[i] & 0xF0) == 0xE0)
      len = 3, c = s[i] & 0x0F, min = 0x800;
    else if ((s[i] & 0xF8) == 0xF0)
      len = 4, c = s[i] & 0x07, min = 0x10000;
    else
      return 0;
    if (n - i < len)
      return 0;
    for (k = 1; k < len; ++k) {
      if ((s[i+k] & 0xC0) != 0x80)
        return 0;
      c = c << 6 | (s[i+k] & 0x3F);
    }
    if (c < min || c > 0x10FFFF || (c >= 0xD800 && c <= 0xDFFF))
      return 0;
    i += len;
  }
  return 1;
}

// The characters of RFC 5322's atext, which a local part is made of (with
// dots between runs of them) and which a display name may hold unquoted.
static int is_atext(unsigned char c) {
  return c && (isalnum(c) || strchr("!#$%&'*+-/=?^_`{|}~", c));
}

// What is wrong with s[0..n) as RFC 5322's dot-atom-text, runs of atext
// with single dots between them, or DOT_ATOM_OK.
enum { DOT_ATOM_OK, DOT_ATOM_EMPTY, DOT_ATOM_MISPLACED_DOT, DOT_ATOM_CHARACTER };

static int dot_atom(const char *s, size_t n) {
  size_t i;

  if (!n)
    return DOT_ATOM_EMPTY;
  for (i = 0; i < n; ++i) {
    if (s[i] == '.') {
      if (i == 0 || i + 1 == n || s[i+1] == '.')
        return DOT_ATOM_MISPLACED_DOT;
    } else if (!is_atext((unsigned char)s[i]))
      return DOT_ATOM_CHARACTER;
  }
  return DOT_ATOM_OK;
}

// The longest addr-spec: the 256 bytes of a path, less its brackets (RFC
// 5321, section 4.5.3.1.3), and the longest label of a domain (section
// 4.5.3.1.2).
#define MAX_ADDR_SPEC 254
#define MAX_LABEL 63

// What is wrong with s[0..n) as a dot-atom-text on `side` ("before" or
// "after") of the '@' of `what`, an e-mail address or a Message-ID, or
// NULL.
static const char *dot_atom_problem(uw_context ctx, const char *what, const char *side, const char *s, size_t n) {
  switch (dot_atom(s, n)) {
  case DOT_ATOM_EMPTY:
    return uw_Basis_mstrcat(ctx, what, " has nothing ", side, " the '@'", NULL);
  case DOT_ATOM_MISPLACED_DOT:
    return uw_Basis_mstrcat(ctx, what, " has a misplaced dot", NULL);
  case DOT_ATOM_CHARACTER:
    return uw_Basis_mstrcat(ctx, what, " has a character not allowed ", side, " the '@'", NULL);
  }
  return NULL;
}

// What is wrong with an addr-spec, or NULL.  RFC 5321's Mailbox without the
// quoted local parts and the address literals, which no one types: a local
// part of atext with single dots between runs, an '@', a domain of labels of
// letters, digits and inner hyphens joined by dots, all ASCII, the whole at
// most MAX_ADDR_SPEC bytes.
static const char *addr_spec(uw_context ctx, const char *s) {
  const char *at, *p, *e;

  if (!*s)
    return "Empty e-mail address";
  for (p = s; *p; ++p)
    if ((unsigned char)*p >= 0x80)
      return "E-mail address is not ASCII";
  if (strlen(s) > MAX_ADDR_SPEC)
    return "E-mail address is longer than " NUMBER(MAX_ADDR_SPEC) " bytes";
  if (!(at = strchr(s, '@')))
    return "E-mail address has no '@'";
  if ((e = dot_atom_problem(ctx, "E-mail address", "before", s, at - s)))
    return e;
  if (!at[1])
    return "E-mail address has nothing after the '@'";
  for (p = at + 1; ; ) {
    const char *label = p;
    while (isalnum((unsigned char)*p) || *p == '-')
      ++p;
    if (p == label)
      return *p == '.' ? "E-mail address has a misplaced dot"
                       : "E-mail address has a character not allowed after the '@'";
    if (*label == '-' || p[-1] == '-')
      return "E-mail address has a '-' at the start or the end of a domain label";
    if (p - label > MAX_LABEL)
      return "E-mail address has a domain label longer than " NUMBER(MAX_LABEL) " characters";
    if (!*p)
      return NULL;
    if (*p != '.')
      return "E-mail address has a character not allowed after the '@'";
    if (!*++p)
      return "E-mail address has a misplaced dot";
  }
}

static const char *text_problem(uw_context ctx, const char *s, const char *what);

// Parse "local@domain" or "Name <local@domain>".  The addr-spec is what
// stands between the last '<' and a final '>', or the whole when there are
// no brackets; the name is what stands before that '<', and may be anything
// but a line break, since it is quoted or encoded when the header is
// written.  Text after the '>' is refused: it would otherwise end up in the
// envelope, where a server reads it as parameters of the command.
static void parse_address(uw_context ctx, const char *s, struct address *a) {
  const char *p, *lt;
  size_t n;

  a->name = a->addr = NULL;
  a->error = NULL;
  while (*s == ' ' || *s == '\t')
    ++s;
  n = strlen(s);
  while (n && (s[n-1] == ' ' || s[n-1] == '\t'))
    --n;
  a->text = uw_malloc(ctx, n + 1);
  memcpy(a->text, s, n);
  a->text[n] = 0;
  s = a->text;

  for (p = s; *p; ++p)
    if (*p == '\r' || *p == '\n') {
      a->error = "E-mail address contains a line break";
      return;
    }
  if (!n) {
    a->error = "Empty e-mail address";
    return;
  }

  if (s[n-1] == '>') {
    if (!(lt = strrchr(s, '<'))) {
      a->error = "E-mail address has a '>' but no '<'";
      return;
    }
    a->addr = uw_malloc(ctx, s + n - lt);
    memcpy(a->addr, lt + 1, s + n - 1 - (lt + 1));
    a->addr[s + n - 1 - (lt + 1)] = 0;
    for (p = lt; p > s && (p[-1] == ' ' || p[-1] == '\t'); --p);
    if (p > s) {
      a->name = uw_malloc(ctx, p - s + 1);
      memcpy(a->name, s, p - s);
      a->name[p - s] = 0;
    }
  } else if (strchr(s, '>')) {
    a->error = "E-mail address has text after the '>'";
    return;
  } else if (strchr(s, '<')) {
    a->error = "E-mail address has a '<' but no '>'";
    return;
  } else
    a->addr = a->text;

  a->error = addr_spec(ctx, a->addr);
  if (!a->error && a->name)
    a->error = text_problem(ctx, a->name, "Display name");
}

uw_UrmailFfi_emailAddress uw_UrmailFfi_parseAddress(uw_context ctx, uw_Basis_string s) {
  uw_UrmailFfi_emailAddress a = uw_malloc(ctx, sizeof(struct address));

  parse_address(ctx, s, a);
  return a;
}

uw_Basis_string uw_UrmailFfi_addressProblem(uw_context ctx, uw_UrmailFfi_emailAddress a) {
  return a->error ? uw_strdup(ctx, (char *)a->error) : NULL;
}

uw_Basis_string uw_UrmailFfi_addressString(uw_context ctx, uw_UrmailFfi_emailAddress a) {
  (void)ctx;
  return a->text;
}

// A list, newest first: consing keeps the messages that the builders
// return immutable, since the messages made from one another share their
// lists.  The items are of the type the list's comment names; in_order
// gives them in the order they were added.
struct list {
  void *item;
  struct list *next;
};

static struct list *cons(uw_context ctx, void *item, struct list *l) {
  struct list *cell = uw_malloc(ctx, sizeof *cell);

  cell->item = item;
  cell->next = l;
  return cell;
}

// The items of a list in the order they were added, and how many, in an
// array of the request's memory.
static size_t in_order(uw_context ctx, const struct list *l, void ***out) {
  size_t n = 0, i;
  const struct list *p;
  void **a;

  for (p = l; p; p = p->next)
    ++n;
  a = uw_malloc(ctx, n * sizeof *a);
  for (p = l, i = n; p; p = p->next)
    a[--i] = p->item;
  *out = a;
  return n;
}

/* ---- The checks of the parts of a message.  Each returns what is wrong,
   or NULL. ---- */

// A text that goes into a header, a subject or a display name, say: UTF-8,
// with no line break, at most 998 bytes, a line's worth.  It is folded
// and encoded when the message is assembled (RFC 5322 and 2047), so it
// may be longer than a line, but a limit bounds the work, and one line's
// worth is plenty for a header.
#define MAX_HEADER_TEXT MAX_LINE

static const char *text_problem(uw_context ctx, const char *s, const char *what) {
  size_t n = strlen(s);

  if (strpbrk(s, "\r\n"))
    return uw_Basis_mstrcat(ctx, what, " contains a line break", NULL);
  if (n > MAX_HEADER_TEXT)
    return uw_Basis_mstrcat(ctx, what, " is longer than " NUMBER(MAX_HEADER_TEXT) " bytes", NULL);
  if (!is_utf8((const unsigned char *)s, n))
    return uw_Basis_mstrcat(ctx, what, " is not UTF-8", NULL);
  return NULL;
}

static const char *header(uw_context ctx, uw_Basis_string s) {
  return text_problem(ctx, s, "Header value");
}

#define MESSAGE_ID_HEADER "Message-ID: "

// The longest Message-ID: it cannot be folded, so it must fit on the line
// of its header.
#define MAX_MESSAGE_ID (MAX_LINE - (sizeof MESSAGE_ID_HEADER - 1))

// What is wrong with a Message-ID, or NULL.  RFC 5322's msg-id without the
// obsolete forms and the blanks around: '<', a dot-atom-text, '@', a
// dot-atom-text or a domain literal in brackets, '>'.  All of it is
// printable ASCII.
static const char *message_id(uw_context ctx, uw_Basis_string s) {
  size_t n = strlen(s), i, right_n;
  const char *at, *right, *e;

  for (i = 0; i < n; ++i)
    if (!is_vchar(s[i]))
      return "Message-ID has a character that is not printable ASCII";
  if (n > MAX_MESSAGE_ID)
    return uw_Basis_mstrcat(ctx, "Message-ID is longer than ", uw_Basis_intToString(ctx, MAX_MESSAGE_ID),
                            " bytes, too long for one header line", NULL);
  if (n < 2 || s[0] != '<' || s[n-1] != '>' || !(at = memchr(s, '@', n)))
    return "Message-ID is not of the form <left@right>";
  if ((e = dot_atom_problem(ctx, "Message-ID", "before", s + 1, at - (s + 1))))
    return e;
  right = at + 1;
  right_n = s + n - 1 - right;
  if (right_n && right[0] == '[') {
    // dtext: printable ASCII but '[', ']' and '\'.
    if (right_n < 2 || right[right_n-1] != ']')
      return "Message-ID has a character not allowed after the '@'";
    for (i = 1; i + 1 < right_n; ++i)
      if (strchr("[]\\", right[i]))
        return "Message-ID has a character not allowed after the '@'";
    return NULL;
  }
  return dot_atom_problem(ctx, "Message-ID", "after", right, right_n);
}

// The name limit keeps a Content-Disposition line under the 998 bytes SMTP
// allows without RFC 2231 continuations: 255 bytes percent-encoded is 765.
#define NAME_MAX_BYTES 255

// The name of an attachment or an image, which a client saves the file as:
// any byte but a control character, and no '/' or '\', which would name a
// directory.  A name that is not ASCII is sent as an RFC 2231 filename*.
static const char *part_name(uw_Basis_string s) {
  const char *p;

  if (!*s)
    return "name is empty";
  if (strlen(s) > NAME_MAX_BYTES)
    return "name is longer than " NUMBER(NAME_MAX_BYTES) " bytes";
  for (p = s; *p; ++p) {
    if ((unsigned char)*p < 0x20 || *p == 0x7F)
      return "name contains a control character";
    if (*p == '/' || *p == '\\')
      return "name contains '/' or '\\'";
  }
  if (!is_utf8((const unsigned char *)s, strlen(s)))
    return "name is not UTF-8";
  return NULL;
}

// The longest type or subtype of a MIME type (RFC 6838, section 4.2).
#define MAX_MIME_NAME 127

// A MIME type as it goes into Content-Type: type/subtype of the characters
// Basis.checkMime allows, so no parameters, and exactly one slash; each
// name starting with a letter or digit and at most 127 characters long, as
// RFC 6838 has them.
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
  if (slash - s > MAX_MIME_NAME || strlen(slash + 1) > MAX_MIME_NAME)
    return "MIME type has a type or subtype longer than " NUMBER(MAX_MIME_NAME) " characters";
  if (!isalnum((unsigned char)s[0]) || !isalnum((unsigned char)slash[1]))
    return "MIME type has a type or subtype that does not start with a letter or digit";
  return NULL;
}

/* ---- A message, built up one field at a time by Urmail.message.  The
   builders never fail: what is wrong is kept, one line for each problem,
   naming the field and the value given, and Urmail.message reports all of
   them.  Each builder returns a new message and leaves the one it was given
   as it was, as a pure function must; the lists are shared. ---- */

// The Content-ID of an image, what the HTML refers to it by: a hash of the
// image, at a domain of the library's own (see add_image).
#define CONTENT_ID_DOMAIN "urmail"
#define CONTENT_ID_FORMAT "%016llx@" CONTENT_ID_DOMAIN
#define CONTENT_ID_FORMAT_NTH "%016llx.%u@" CONTENT_ID_DOMAIN

// An attachment or an image, checked.
struct part {
  uw_Basis_string name;  // what the recipient sees, as given
  uw_Basis_string type;  // type/subtype
  uw_Basis_blob data;
  // An image of the message only: its hash and Content-ID.
  unsigned long long hash;
  char content_id[sizeof "0123456789abcdef.4294967295@" CONTENT_ID_DOMAIN];
};

// An entry of Images: the url of the img src it stands for, and the image,
// or NULL when the entry has a problem (which is kept).
struct image_entry {
  uw_Basis_string url;
  struct part *part;
};

// The fields of recipients, each a list of addresses.
enum { TO_FIELD, CC_FIELD, BCC_FIELD, RECIPIENT_FIELDS };
static const char *const recipient_field[RECIPIENT_FIELDS] = {"To", "Cc", "Bcc"};

struct message {
  uw_UrmailFfi_emailAddress from;
  struct list *recipients[RECIPIENT_FIELDS];  // of uw_UrmailFfi_emailAddress
  uw_Basis_string subject, user_agent, message_id, text;
  uw_Basis_string page;      // the HTML version as given, or NULL
  struct list *entries;      // Images, of struct image_entry *
  struct list *attachments;  // of struct part *
  struct list *problems;     // of const char *, one line each
  // What lookUpImages (below) made of the page: the HTML as sent, its img
  // srcs pointing at the images, and the images, each once.
  uw_Basis_string html;
  struct list *images;       // of struct part *
  int finished;  // by finish, and nothing changed since
};

typedef struct message *uw_UrmailFfi_message;

uw_UrmailFfi_message uw_UrmailFfi_start = NULL;

// The message to change, a copy: every builder starts with one, so the copy
// is not finished, whatever m was.
static uw_UrmailFfi_message copy(uw_context ctx, uw_UrmailFfi_message m) {
  uw_UrmailFfi_message m2 = uw_malloc(ctx, sizeof *m2);

  if (m)
    *m2 = *m;
  else
    memset(m2, 0, sizeof *m2);
  m2->finished = 0;
  return m2;
}

// A value as a problem shows it: in quotes, with quotes, backslashes and
// control characters escaped, so that the line stays one line and shows
// where the value ends; cut after 60 characters of UTF-8, with "..." after
// it then.  A character takes at most 4 bytes, escaped or not, but nothing
// says the value is UTF-8, and a run of continuation bytes starts no
// character, so the bytes are bounded too.
#define SHOWN_CHARACTERS 60
#define SHOWN_BYTES (4 * SHOWN_CHARACTERS)

static char *quoted_value(uw_context ctx, const char *s) {
  char *out = uw_malloc(ctx, 1 + SHOWN_BYTES + sizeof "\"..."), *o = out;
  int characters = 0;

  *o++ = '"';
  for (; *s; ++s) {
    unsigned char c = *s;
    if (((c & 0xC0) != 0x80 && ++characters > SHOWN_CHARACTERS) || o + 4 > out + 1 + SHOWN_BYTES) {
      strcpy(o, "\"...");
      return out;
    }
    if (c >= 0x80) {
      // A character of UTF-8 as it is, a byte that is not part of one as
      // \xNN, so that the line is UTF-8 whatever the value.
      size_t len = (c & 0xE0) == 0xC0 ? 2 : (c & 0xF0) == 0xE0 ? 3 : (c & 0xF8) == 0xF0 ? 4 : 0;
      // is_utf8 stops at the first byte that is not a continuation byte,
      // so it does not read past the NUL.
      if (len && is_utf8((const unsigned char *)s, len)) {
        if (o + len > out + 1 + SHOWN_BYTES) {
          strcpy(o, "\"...");
          return out;
        }
        memcpy(o, s, len);
        o += len;
        s += len - 1;
      } else {
        sprintf(o, "\\x%02X", c);
        o += 4;
      }
    } else if (c == '"' || c == '\\') {
      *o++ = '\\';
      *o++ = c;
    } else if (c == '\n') {
      *o++ = '\\';
      *o++ = 'n';
    } else if (c == '\r') {
      *o++ = '\\';
      *o++ = 'r';
    } else if (c == '\t') {
      *o++ = '\\';
      *o++ = 't';
    } else if (c < 0x20 || c == 0x7F) {
      sprintf(o, "\\x%02X", c);
      o += 4;
    } else
      *o++ = c;
  }
  *o++ = '"';
  *o = 0;
  return out;
}

// `format` with its one %s replaced by `value`, quoted.
static const char *with_value(uw_context ctx, const char *format, const char *value) {
  const char *v = quoted_value(ctx, value);
  char *s = uw_malloc(ctx, strlen(format) + strlen(v) + 1);

  sprintf(s, format, v);
  return s;
}

// Keep a problem: FIELD VALUE: WHAT, or FIELD: WHAT when there is no value.
static void add_problem(uw_context ctx, uw_UrmailFfi_message m, const char *field,
                        const char *value, const char *what) {
  const char *v = value ? quoted_value(ctx, value) : "";
  char *line = uw_malloc(ctx, strlen(field) + 1 + strlen(v) + 2 + strlen(what) + 1);

  sprintf(line, "%s%s%s: %s", field, value ? " " : "", v, what);
  m->problems = cons(ctx, line, m->problems);
}

static uw_UrmailFfi_emailAddress address_of(uw_context ctx, uw_UrmailFfi_message m, const char *field,
                                            uw_Basis_string s) {
  uw_UrmailFfi_emailAddress a = uw_UrmailFfi_parseAddress(ctx, s);

  if (a->error)
    add_problem(ctx, m, field, s, a->error);
  return a;
}

uw_UrmailFfi_message uw_UrmailFfi_from(uw_context ctx, uw_Basis_string s, uw_UrmailFfi_message m) {
  uw_UrmailFfi_message m2 = copy(ctx, m);

  m2->from = address_of(ctx, m2, "From", s);
  return m2;
}

static uw_UrmailFfi_message add_recipient(uw_context ctx, int field, uw_Basis_string s, uw_UrmailFfi_message m) {
  uw_UrmailFfi_message m2 = copy(ctx, m);

  m2->recipients[field] = cons(ctx, address_of(ctx, m2, recipient_field[field], s), m2->recipients[field]);
  return m2;
}

uw_UrmailFfi_message uw_UrmailFfi_to(uw_context ctx, uw_Basis_string s, uw_UrmailFfi_message m) {
  return add_recipient(ctx, TO_FIELD, s, m);
}

uw_UrmailFfi_message uw_UrmailFfi_cc(uw_context ctx, uw_Basis_string s, uw_UrmailFfi_message m) {
  return add_recipient(ctx, CC_FIELD, s, m);
}

uw_UrmailFfi_message uw_UrmailFfi_bcc(uw_context ctx, uw_Basis_string s, uw_UrmailFfi_message m) {
  return add_recipient(ctx, BCC_FIELD, s, m);
}

// A copy of m, with a problem if s is not a header text, for `field`.
static uw_UrmailFfi_message with_header_text(uw_context ctx, const char *field, uw_Basis_string s,
                                             uw_UrmailFfi_message m) {
  uw_UrmailFfi_message m2 = copy(ctx, m);
  const char *e = header(ctx, s);

  if (e)
    add_problem(ctx, m2, field, s, e);
  return m2;
}

uw_UrmailFfi_message uw_UrmailFfi_subject(uw_context ctx, uw_Basis_string s, uw_UrmailFfi_message m) {
  uw_UrmailFfi_message m2 = with_header_text(ctx, "Subject", s, m);

  m2->subject = s;
  return m2;
}

uw_UrmailFfi_message uw_UrmailFfi_userAgent(uw_context ctx, uw_Basis_string s, uw_UrmailFfi_message m) {
  uw_UrmailFfi_message m2 = with_header_text(ctx, "UserAgent", s, m);

  m2->user_agent = s;
  return m2;
}

uw_UrmailFfi_message uw_UrmailFfi_messageId(uw_context ctx, uw_Basis_string s, uw_UrmailFfi_message m) {
  uw_UrmailFfi_message m2 = copy(ctx, m);
  const char *e = message_id(ctx, s);

  if (e)
    add_problem(ctx, m2, "MessageId", s, e);
  m2->message_id = s;
  return m2;
}

uw_UrmailFfi_message uw_UrmailFfi_text(uw_context ctx, uw_Basis_string s, uw_UrmailFfi_message m) {
  uw_UrmailFfi_message m2 = copy(ctx, m);

  if (!is_utf8((const unsigned char *)s, strlen(s)))
    add_problem(ctx, m2, "PlainTextBody", NULL, "not UTF-8");
  m2->text = s;
  return m2;
}

// The HTML as sent and its images, made by lookUpImages from the page and
// the entries of Images, and so out of date when either changes.
static void forget_lookup(uw_UrmailFfi_message m) {
  m->html = NULL;
  m->images = NULL;
}

uw_UrmailFfi_message uw_UrmailFfi_html(uw_context ctx, uw_Basis_string page, uw_UrmailFfi_message m) {
  uw_UrmailFfi_message m2 = copy(ctx, m);

  if (!is_utf8((const unsigned char *)page, strlen(page)))
    add_problem(ctx, m2, "HtmlBody", NULL, "the page is not UTF-8");
  m2->page = page;
  forget_lookup(m2);
  return m2;
}

static struct part *new_part(uw_context ctx, uw_Basis_string name, uw_Basis_string type, uw_Basis_blob data) {
  struct part *p = uw_malloc(ctx, sizeof *p);

  p->name = name;
  p->type = type;
  p->data = data;
  p->hash = 0;
  p->content_id[0] = 0;
  return p;
}

// A Blob, checked, or NULL with its problems kept under FIELD VALUE.
static struct part *blob_part(uw_context ctx, uw_UrmailFfi_message m, const char *field, const char *value,
                              uw_Basis_string name, uw_Basis_string type, uw_Basis_blob data) {
  const char *e;
  int ok = 1;

  if ((e = part_name(name))) {
    add_problem(ctx, m, field, value, e);
    ok = 0;
  }
  if ((e = mime_type(type))) {
    add_problem(ctx, m, field, value, e);
    ok = 0;
  } else if (!uw_Basis_checkMime(ctx, type)) {
    add_problem(ctx, m, field, value, with_value(ctx, "MIME type %s is not allowed by the project file", type));
    ok = 0;
  }
  return ok ? new_part(ctx, name, type, data) : NULL;
}

// A ServedFile, checked, the same way.  Its bytes and its MIME type are
// those of the file directive serving `path`; `name`, when NULL, is the
// path's last segment, as Basis names a served file.  For an img src (the
// path is the src), the problems say what is to be done about it there.
static struct part *served_part(uw_context ctx, uw_UrmailFfi_message m, const char *field, const char *value,
                                uw_Basis_string name, uw_Basis_string path, int for_src) {
  uw_Basis_file *f = uw_Basis_checkServedFile(ctx, path);
  const char *e;
  int ok = 1;

  if (name && (e = part_name(name))) {
    add_problem(ctx, m, field, value, e);
    ok = 0;
  }
  if (!f) {
    add_problem(ctx, m, field, value,
                for_src ? "no entry of Images names it, and no file directive serves it"
                        : with_value(ctx, "no file directive serves %s", path));
    return NULL;
  }
  if (!*f->type) {
    add_problem(ctx, m, field, value,
                for_src ? "no MIME type is known for it; give one in its file directive"
                        : with_value(ctx, "no MIME type is known for %s; give one in its file directive", path));
    ok = 0;
  }
  if (!name) {
    name = f->name;
    if (!name) {
      add_problem(ctx, m, field, value,
                  for_src ? "it has no last segment to name the image by"
                          : with_value(ctx, "%s has no last segment to name the file by; give a Name", path));
      ok = 0;
    } else if ((e = part_name(name))) {
      add_problem(ctx, m, field, value, e);
      ok = 0;
    }
  }
  return ok ? new_part(ctx, name, f->type, f->data) : NULL;
}

uw_UrmailFfi_message uw_UrmailFfi_attachBlob(uw_context ctx, uw_Basis_string name, uw_Basis_string type,
                                             uw_Basis_blob data, uw_UrmailFfi_message m) {
  uw_UrmailFfi_message m2 = copy(ctx, m);
  struct part *p = blob_part(ctx, m2, "Attachment", name, name, type, data);

  if (p)
    m2->attachments = cons(ctx, p, m2->attachments);
  return m2;
}

uw_UrmailFfi_message uw_UrmailFfi_attachServedFile(uw_context ctx, uw_Basis_string name, uw_Basis_string path,
                                                   uw_UrmailFfi_message m) {
  uw_UrmailFfi_message m2 = copy(ctx, m);
  struct part *p = served_part(ctx, m2, "Attachment", name ? name : path, name, path, 0);

  if (p)
    m2->attachments = cons(ctx, p, m2->attachments);
  return m2;
}

// An entry of Images, kept unless there is one for the url already, which
// is a problem: the first one stands.
static void add_entry(uw_context ctx, uw_UrmailFfi_message m, uw_Basis_string url, struct part *p) {
  struct list *l;
  struct image_entry *e;

  for (l = m->entries; l; l = l->next)
    if (!strcmp(((struct image_entry *)l->item)->url, url)) {
      add_problem(ctx, m, "Image", url, "given twice in Images");
      return;
    }
  e = uw_malloc(ctx, sizeof *e);
  e->url = url;
  e->part = p;
  m->entries = cons(ctx, e, m->entries);
}

uw_UrmailFfi_message uw_UrmailFfi_imageBlob(uw_context ctx, uw_Basis_string url, uw_Basis_string name,
                                            uw_Basis_string type, uw_Basis_blob data, uw_UrmailFfi_message m) {
  uw_UrmailFfi_message m2 = copy(ctx, m);

  add_entry(ctx, m2, url, blob_part(ctx, m2, "Image", url, name, type, data));
  forget_lookup(m2);
  return m2;
}

uw_UrmailFfi_message uw_UrmailFfi_imageServedFile(uw_context ctx, uw_Basis_string url, uw_Basis_string name,
                                                  uw_Basis_string path, uw_UrmailFfi_message m) {
  uw_UrmailFfi_message m2 = copy(ctx, m);

  add_entry(ctx, m2, url, served_part(ctx, m2, "Image", url, name, path, 0));
  forget_lookup(m2);
  return m2;
}

static void rewrite_page(uw_context ctx, uw_UrmailFfi_message m);

// The page's img srcs looked up, after the entries of Images (rewrite_page,
// below).
uw_UrmailFfi_message uw_UrmailFfi_lookUpImages(uw_context ctx, uw_UrmailFfi_message m) {
  uw_UrmailFfi_message m2 = copy(ctx, m);

  if (m2->page)
    rewrite_page(ctx, m2);
  return m2;
}

// The most recipients a message may have: RFC 5321 says a server must take
// 100 (section 4.5.3.1.8), and may refuse more for now, again and again.
#define MAX_RECIPIENTS 100

// The most bytes of text, HTML, attachments and images a message may have,
// 18 MiB: it goes out base64-encoded as at most 25 MiB, a common limit of
// servers.  A server with a lower one says so (SIZE, RFC 1870), and send
// declares the size, so that the server refuses before the upload.
#define MAX_CONTENT (18 * 1024 * 1024)

// Whether two addr-specs name one mailbox: the local part as it is, the
// domain in any case (RFC 5321, section 2.4).
static int same_mailbox(const char *a, const char *b) {
  const char *at_a = strchr(a, '@'), *at_b = strchr(b, '@');

  return at_a - a == at_b - b && !strncmp(a, b, at_a - a) && !strcasecmp(at_a, at_b);
}

// The addr-specs of To, Cc and Bcc, in the order given, each mailbox once:
// what the envelope gets, the RCPT TO commands.  At most `limit` of them;
// addresses with a problem are left out.
static size_t envelope(uw_context ctx, uw_UrmailFfi_message m, const char ***out, size_t limit) {
  size_t total = 0, count = 0, n, i, j;
  int k;
  const char **r;
  void **as;

  for (k = 0; k < RECIPIENT_FIELDS; ++k)
    total += in_order(ctx, m->recipients[k], &as);
  r = uw_malloc(ctx, total * sizeof *r);
  for (k = 0; k < RECIPIENT_FIELDS; ++k) {
    n = in_order(ctx, m->recipients[k], &as);
    for (i = 0; i < n && count < limit; ++i) {
      uw_UrmailFfi_emailAddress a = as[i];
      if (a->error)
        continue;
      for (j = 0; j < count && !same_mailbox(r[j], a->addr); ++j);
      if (j == count)
        r[count++] = a->addr;
    }
  }
  *out = r;
  return count;
}

// The message complete, with a problem for each part it lacks, so that
// send can rely on them.  Urmail.message gives every part, and the
// recipients may be missing only there; the rest can only be missing from
// a message built with UrmailFfi directly.
uw_UrmailFfi_message uw_UrmailFfi_finish(uw_context ctx, uw_UrmailFfi_message m) {
  uw_UrmailFfi_message m2 = copy(ctx, m);

  if (!m2->from)
    add_problem(ctx, m2, "From", NULL, "not given");
  if (!m2->recipients[TO_FIELD] && !m2->recipients[CC_FIELD] && !m2->recipients[BCC_FIELD])
    add_problem(ctx, m2, "To, Cc and Bcc", NULL, "no recipient");
  if (!m2->subject)
    add_problem(ctx, m2, "Subject", NULL, "not given");
  if (!m2->text)
    add_problem(ctx, m2, "PlainTextBody", NULL, "not given");
  if (m2->page && !m2->html)
    add_problem(ctx, m2, "HtmlBody", NULL, "its img srcs were not looked up after it and its Images were given");
  {
    const char **rcpt;
    if (envelope(ctx, m2, &rcpt, MAX_RECIPIENTS + 1) > MAX_RECIPIENTS)
      add_problem(ctx, m2, "To, Cc and Bcc", NULL, "more than " NUMBER(MAX_RECIPIENTS) " recipients");
  }
  {
    struct list *l;
    uw_Basis_int size = (m2->text ? strlen(m2->text) : 0) + (m2->page ? strlen(m2->page) : 0);
    for (l = m2->attachments; l; l = l->next)
      size += ((struct part *)l->item)->data.size;
    for (l = m2->images; l; l = l->next)
      size += ((struct part *)l->item)->data.size;
    if (size > MAX_CONTENT)
      add_problem(ctx, m2, "The message", NULL,
                  uw_Basis_mstrcat(ctx, "its text, HTML, attachments and images come to ", uw_Basis_intToString(ctx, size),
                                   " bytes, more than the ", uw_Basis_intToString(ctx, MAX_CONTENT), " allowed",
                                   NULL));
  }
  m2->finished = 1;
  return m2;
}

// The problems in the order they were found, with `sep` between them, or
// NULL when there are none.
static char *problems_joined(uw_context ctx, uw_UrmailFfi_message m, const char *sep) {
  size_t n, len = 1, i;
  void **lines;
  char *s, *o;

  if (!m || !m->problems)
    return NULL;
  n = in_order(ctx, m->problems, &lines);
  for (i = 0; i < n; ++i)
    len += strlen(lines[i]) + strlen(sep);
  s = o = uw_malloc(ctx, len);
  for (i = 0; i < n; ++i) {
    if (i) {
      strcpy(o, sep);
      o += strlen(sep);
    }
    strcpy(o, lines[i]);
    o += strlen(lines[i]);
  }
  *o = 0;
  return s;
}

// The problems, one line each, in the order they were found, or NULL.
uw_Basis_string uw_UrmailFfi_problems(uw_context ctx, uw_UrmailFfi_message m) {
  return problems_joined(ctx, m, "\n");
}

// What deliver() needs: the arguments of send, the TLS choice unpacked, and
// the message as it goes over the wire.  Nothing here outlives the call.
typedef struct {
  uw_UrmailFfi_message m;
  const char *server, *ca, *user, *password;
  enum uw_UrmailFfi_tls_tag tls;
  const char *message;
  size_t length;
  const char **recipients;  // the envelope's
  size_t n_recipients;
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

/* ---- A growable byte buffer for assembling the message.  malloc-based,
   since it grows by realloc; freed once the message is delivered. ---- */

typedef struct {
  char *s;
  size_t len, cap;
} buf;

// The room a buffer starts with; it doubles as needed.
#define BUF_START 1024

static void buf_reserve(uw_context ctx, buf *b, size_t extra) {
  if (b->len + extra + 1 > b->cap) {
    size_t cap = b->cap ? b->cap : BUF_START;
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

// s as RFC 5322's quoted-string: quotes around, '"' and '\\' escaped.  With
// ascii_only, a character that is not ASCII becomes '_' (each byte that
// does not continue a UTF-8 sequence does), for the copy of a name that a
// client that does not read RFC 2231's filename* shows.
static void buf_quoted(uw_context ctx, buf *b, const char *s, int ascii_only) {
  buf_str(ctx, b, "\"");
  for (; *s; ++s) {
    unsigned char c = *s;
    if (ascii_only && c >= 0x80) {
      if ((c & 0xC0) != 0x80)
        buf_str(ctx, b, "_");
      continue;
    }
    if (c == '"' || c == '\\')
      buf_str(ctx, b, "\\");
    buf_append(ctx, b, s, 1);
  }
  buf_str(ctx, b, "\"");
}

static const char hex_digits[] = "0123456789ABCDEF";

// The longest line of quoted-printable or base64 (RFC 2045, sections 6.7
// and 6.8), and the bytes base64 makes such a line of.
#define ENCODED_LINE 76
#define BASE64_LINE_BYTES (ENCODED_LINE / 4 * 3)

// A body as quoted-printable (RFC 2045, section 6.7): lines of at most 76
// characters, CRLF line ends whatever the input had, and as =XX everything
// outside printable ASCII, '=', a space or tab before a line end, and the
// 'F' of a "From " that starts a line.  Long lines and 8-bit text then
// pass any SMTP server.  Delivery into an mbox file turns "From " at the
// start of a line into ">From ", since such a line starts a new message
// there, and RFC 2049 (section 3, item 8) advises encoding the 'F' against
// that.  A line of a single '.', the other danger that item names, is
// taken care of by SMTP itself: libcurl doubles a '.' at the start of a
// line, and the server removes it again (dot-stuffing, RFC 5321, section
// 4.5.2).
static void buf_qp(uw_context ctx, buf *b, const char *s) {
  size_t col = 0;
  for (; *s; ++s) {
    unsigned char c = *s;
    char enc[3];
    size_t n;
    if (c == '\r' && s[1] == '\n')
      continue;  // the \n below writes the CRLF
    if (c == '\n') {
      buf_append(ctx, b, "\r\n", 2);
      col = 0;
      continue;
    }
    n = (is_vchar(c) && c != '=')
        || ((c == ' ' || c == '\t') && s[1] && s[1] != '\n' && !(s[1] == '\r' && s[2] == '\n'))
        ? 1 : 3;
    if (col + n > ENCODED_LINE - 1) {  // room for the soft break's "="
      buf_append(ctx, b, "=\r\n", 3);
      col = 0;
    }
    // After the soft break, if any, which may have moved it to the start.
    if (col == 0 && starts_with(s, "From "))
      n = 3;
    if (n == 1)
      enc[0] = c;
    else {
      enc[0] = '=';
      enc[1] = hex_digits[c >> 4];
      enc[2] = hex_digits[c & 15];
    }
    buf_append(ctx, b, enc, n);
    col += n;
  }
}

// The boundaries of the multiparts.  Fixed, and safe: every part is
// quoted-printable or base64, and neither encoding can produce "=_" (in
// quoted-printable an '=' is followed by two hex digits or a line break, and
// base64 has no '_'), so no boundary starting with it can occur in a part.
#define ALTERNATIVE_BOUNDARY "=_urmail_alternative"
#define RELATED_BOUNDARY "=_urmail_related"
#define MIXED_BOUNDARY "=_urmail_mixed"

/* ---- Encodings. ---- */

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

/* ---- Header values: folded at blanks, so that a line keeps to 78
   characters where the text allows and to 998 always (RFC 5322, sections
   2.1.1 and 3.2.2), with RFC 2047 encoded words for the words that need
   them only, in Q encoding, which leaves ASCII readable.

   A reader gives back the blanks of a value if they are written by these
   rules, which are the only place that says how a run of blanks is
   written, by what is on each side of it:

     plain  | plain    as they are; a line break may come before them, since
                       a reader removes the break alone (section 3.2.2)
     encoded| encoded  inside the encoded words, as '_': a reader drops the
                       blanks between two encoded words (RFC 2047, 6.2)
     plain  | encoded  as they are, a reader keeps them
     plain  | end      as they are if they fit on the line; if not, the first
                       as it is and the rest as encoded words
     encoded| end      as they are if they fit; if not, all inside encoded
                       words, since a blank kept between two encoded words
                       is lost
     start  | any      the first is the one after the colon, and is not the
                       value's; after a line break before the first token it
                       is still the first, unless the line would be too long

   A blank cannot be written at the end of a line that is full, and a line
   that is only blanks is not allowed, so the word before blanks that end a
   value is encoded too if it leaves no room for one.  header_place says
   where a token lands, for header_put and for that question alike. ---- */

// The longest line a message should have, without its CRLF.
#define GOOD_LINE 78

// An encoded word, of at most 75 characters (RFC 2047, section 2).
#define ENCODED_WORD_START "=?UTF-8?Q?"
#define ENCODED_WORD_END "?="
#define ENCODED_WORD_MAX 75
#define ENCODED_WORD_OVERHEAD (sizeof ENCODED_WORD_START - 1 + sizeof ENCODED_WORD_END - 1)

// A header being written: its line so far, for the folding.
typedef struct {
  uw_context ctx;
  buf *b;
  size_t col;     // the length of the current line
  int has_token;  // whether the current line has a token, after which it may be folded
  int fold_next;  // the next token goes on a new line
  int last_encoded;  // whether the last token written is an encoded word
} header_out;

static void header_begin(header_out *h, uw_context ctx, buf *b, const char *name) {
  h->ctx = ctx;
  h->b = b;
  buf_str(ctx, b, name);
  buf_str(ctx, b, ":");
  h->col = strlen(name) + 1;
  h->has_token = 0;
  h->fold_next = 0;
  h->last_encoded = 0;
}

static void header_end(header_out *h) {
  buf_str(h->ctx, h->b, "\r\n");
}

// Text that goes right after the last token, without blanks: a comma.
static void header_append(header_out *h, const char *s) {
  buf_str(h->ctx, h->b, s);
  h->col += strlen(s);
}

// Where a token of n bytes lands after ws_n blanks, which must not be
// empty: on the current line if it fits within 78 characters, or within 998
// while the line has no token yet; else on a new line, which starts with
// the blanks. That is folding (RFC 5322, section 3.2.2), which a reader
// undoes by removing the line break alone, so the blanks stay as they
// were. Before the first token, the first blank is the one after the
// colon, which is not the value's, and a reader that takes the first blank
// after the colon as that one needs it after a fold too. It is left out
// only if the new line would be longer than 998 then, which a value of 998
// bytes makes it.
typedef struct {
  int new_line;    // whether it goes on a new line
  size_t skipped;  // how many of the blanks are left out there
  size_t end;      // the length of its line when it is on it
} placement;

static placement header_place(const header_out *h, size_t ws_n, size_t n) {
  placement p = {0, 0, h->col + ws_n + n};
  size_t limit = h->has_token ? GOOD_LINE : MAX_LINE;

  if (h->fold_next || p.end > limit) {
    p.new_line = 1;
    p.skipped = !h->has_token && ws_n > 1 && ws_n + n > MAX_LINE;
    p.end = ws_n - p.skipped + n;
  }
  return p;
}

// tok[0..n) after the blanks ws[0..ws_n), where header_place says.
static void header_put(header_out *h, const char *ws, size_t ws_n, const char *tok, size_t n) {
  placement p = header_place(h, ws_n, n);

  if (p.new_line) {
    buf_str(h->ctx, h->b, "\r\n");
    h->fold_next = 0;
    ws += p.skipped;
    ws_n -= p.skipped;
  }
  buf_append(h->ctx, h->b, ws, ws_n);
  buf_append(h->ctx, h->b, tok, n);
  h->col = p.end;
  h->has_token = 1;
  h->last_encoded = 0;
}

static int is_blank(char c) {
  return c == ' ' || c == '\t';
}

// One byte in Q encoding (RFC 2047, section 4.2), into out, and how many
// characters that is: '_' for a space, the byte itself where it can stand
// for itself, =XX otherwise.  In a display name fewer can stand for
// themselves (section 5, rule 3).
static size_t q_byte(unsigned char c, int in_name, char *out) {
  int itself = in_name
    ? (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
      || c == '!' || c == '*' || c == '+' || c == '-' || c == '/'
    : is_vchar(c) && c != '=' && c != '?' && c != '_';

  if (c == ' ') {
    out[0] = '_';
    return 1;
  }
  if (itself) {
    out[0] = c;
    return 1;
  }
  out[0] = '=';
  out[1] = hex_digits[c >> 4];
  out[2] = hex_digits[c & 15];
  return 3;
}

// The longest Q encoding of a character: four bytes of UTF-8, each =XX.
#define Q_CHAR_MAX 12

// The character at s[i] (of n bytes) in Q encoding, into out, and its
// length in s, through *len: a UTF-8 lead byte and the continuation bytes
// after it, so that no character is split between two encoded words
// (section 5).
static size_t q_char(const unsigned char *s, size_t i, size_t n, int in_name, char *out, size_t *len) {
  size_t k = 1, e = q_byte(s[i], in_name, out);

  while (k < 4 && i + k < n && (s[i+k] & 0xC0) == 0x80)
    e += q_byte(s[i+k], in_name, out + e), ++k;
  *len = k;
  return e;
}

// s[0..n) as encoded words, the first after the blanks ws[0..ws_n): each
// fills the line it is on and holds whole characters, and blanks go
// between them, which a reader drops (section 6.2).
static void header_encoded(header_out *h, const char *ws, size_t ws_n, const unsigned char *s, size_t n,
                           int in_name) {
  char word[ENCODED_WORD_MAX + Q_CHAR_MAX], enc[Q_CHAR_MAX];
  size_t i = 0;

  while (i < n) {
    size_t len, e = q_char(s, i, n, in_name, enc, &len), t, room;

    // The room for the text on this line, or on a new one, if not even
    // the first character fits here; at least that character, and at most
    // what an encoded word can hold.
    if (h->col + ws_n + ENCODED_WORD_OVERHEAD + e <= GOOD_LINE)
      room = GOOD_LINE - h->col - ws_n - ENCODED_WORD_OVERHEAD;
    else {
      h->fold_next = h->has_token;
      room = GOOD_LINE > ws_n + ENCODED_WORD_OVERHEAD ? GOOD_LINE - ws_n - ENCODED_WORD_OVERHEAD : 0;
    }
    if (room > ENCODED_WORD_MAX - ENCODED_WORD_OVERHEAD)
      room = ENCODED_WORD_MAX - ENCODED_WORD_OVERHEAD;
    if (room < e)
      room = e;

    strcpy(word, ENCODED_WORD_START);
    t = sizeof ENCODED_WORD_START - 1;
    while (t - (sizeof ENCODED_WORD_START - 1) + e <= room) {
      memcpy(word + t, enc, e);
      t += e;
      i += len;
      if (i == n)
        break;
      e = q_char(s, i, n, in_name, enc, &len);
    }
    memcpy(word + t, ENCODED_WORD_END, sizeof ENCODED_WORD_END - 1);
    t += sizeof ENCODED_WORD_END - 1;
    // It fits where the room was worked out, so header_put folds only if
    // told to.
    header_put(h, ws, ws_n, word, t);
    h->last_encoded = 1;
    ws = " ";
    ws_n = 1;
  }
}

// Whether a word of a header value has to be encoded: it has a byte
// outside printable ASCII, or "=?", which a reader could take for the
// start of an encoded word, or it is too long for a line of its own.
static int must_encode(const char *w, size_t n) {
  size_t i;

  if (n > MAX_LINE - 1)
    return 1;
  for (i = 0; i < n; ++i) {
    unsigned char c = w[i];
    if (!is_vchar(c) || (c == '=' && i + 1 < n && w[i+1] == '?'))
      return 1;
  }
  return 0;
}

static int is_atom(const char *w, size_t n) {
  size_t i;

  for (i = 0; i < n; ++i)
    if (!is_atext((unsigned char)w[i]))
      return 0;
  return 1;
}

// Which words header_words encodes.
enum { ENCODE_MUST, ENCODE_MUST_OR_NOT_ATOM };

static int encoded(const char *w, size_t n, int which) {
  return must_encode(w, n) || (which == ENCODE_MUST_OR_NOT_ATOM && !is_atom(w, n));
}

// Blanks that end a value, ws[0..ws_n), by the rules at the head of this
// section. A fold will not do here: a line break among the blanks that end
// a value is the obsolete syntax (RFC 5322, section 4.1). One blank may
// stand past the 78th column, as long as it is on the line.
static void header_trailing_blanks(header_out *h, const char *ws, size_t ws_n, int in_name) {
  if (h->col + ws_n <= (ws_n <= 1 ? MAX_LINE : GOOD_LINE)) {
    buf_append(h->ctx, h->b, ws, ws_n);
    h->col += ws_n;
  } else if (h->last_encoded)
    header_encoded(h, " ", 1, (const unsigned char *)ws, ws_n, in_name);
  else  // more than one: header_leaves_no_room made sure that one fits
    header_encoded(h, ws, 1, (const unsigned char *)ws + 1, ws_n - 1, in_name);
}

// Whether the last word of a value, of n bytes after ws_n blanks, leaves no
// room for a blank after it. If blanks follow it, the word has to be
// encoded then.  The first word of a header is placed after what is
// written; any other that does not fit its line is on a line of its own, so
// the sizes are enough.
static int header_leaves_no_room(const header_out *h, int first, size_t ws_n, size_t n) {
  if (first && !h->has_token)
    return header_place(h, ws_n, n).end + 1 > MAX_LINE;
  return ws_n + n + 1 > MAX_LINE;
}

// The words of s with the blanks between them as they are, the first after
// a blank, then s's own: each word that `which` says is encoded, together
// with the encoded words next to it and the blanks between them, since the
// blanks between two encoded words are dropped (RFC 2047, section 6.2).
// The rest go as they are.
static void header_words(header_out *h, const char *s, int which, int in_name) {
  size_t n = strlen(s), i = 0, ws_n, tail, last, forced = (size_t)-1;
  const char *ws;
  char *first;

  while (i < n && is_blank(s[i]))
    ++i;
  first = uw_malloc(h->ctx, i + 1);
  first[0] = ' ';
  memcpy(first + 1, s, i);
  ws = first;
  ws_n = i + 1;
  if (i == n) {  // no word: the blanks alone
    header_append(h, " ");
    header_trailing_blanks(h, s, n, in_name);
    return;
  }
  // The last word, if blanks follow it: encoded too if it leaves no room
  // for one (header_leaves_no_room).
  for (tail = n; is_blank(s[tail-1]); --tail);
  if (tail < n) {
    size_t blanks;

    for (last = tail; last > i && !is_blank(s[last-1]); --last);
    for (blanks = last; blanks > i && is_blank(s[blanks-1]); --blanks);
    if (!encoded(s + last, tail - last, which)
        && header_leaves_no_room(h, last == i, last == i ? ws_n : last - blanks, tail - last))
      forced = last;
  }
  while (i < n) {
    size_t w = i, end;

    while (i < n && !is_blank(s[i]))
      ++i;
    end = i;
    if (encoded(s + w, end - w, which) || w == forced) {
      // The words that follow and are encoded too.
      for (;;) {
        size_t next = end, next_end;
        while (next < n && is_blank(s[next]))
          ++next;
        if (next == n)
          break;
        for (next_end = next; next_end < n && !is_blank(s[next_end]); ++next_end);
        if (!encoded(s + next, next_end - next, which) && next != forced)
          break;
        end = next_end;
      }
      header_encoded(h, ws, ws_n, (const unsigned char *)s + w, end - w, in_name);
      i = end;
    } else
      header_put(h, ws, ws_n, s + w, end - w);
    // The blanks after: between this word and the next, or at the end.
    ws = s + i;
    while (i < n && is_blank(s[i]))
      ++i;
    ws_n = s + i - ws;
    if (i == n && ws_n)
      header_trailing_blanks(h, ws, ws_n, in_name);
  }
}

// An unstructured header value (Subject, User-Agent).
static void header_text(header_out *h, const char *s) {
  header_words(h, s, ENCODE_MUST, 0);
}

// Whether `s` (of n bytes) is a quoted-string as RFC 5322 has it: quotes
// around, inside them any character but an unescaped quote, a backslash
// escaping the next character.
static int is_quoted_string(const char *s, size_t n) {
  size_t i;

  if (n < 2 || s[0] != '"' || s[n-1] != '"')
    return 0;
  for (i = 1; i < n - 1; ++i) {
    if (s[i] == '\\')
      ++i;
    else if (s[i] == '"')
      return 0;
  }
  return i == n - 1;
}

// A display name as RFC 5322's phrase. One given as a quoted-string is
// unquoted first, so that its quotes do not become part of the name. Then,
// when no word must be encoded: the words as they are if they are atoms,
// else the whole in one quoted-string, folded at its blanks, which RFC
// 5322 allows (section 3.2.4).  When some word must be encoded: the words
// that are not atoms too, and the atoms as they are.
static void header_name(header_out *h, const char *name) {
  size_t n = strlen(name), i, len = 0;
  char *text = uw_malloc(h->ctx, n + 1);
  int must = 0, atoms = 1;
  buf quoted = {NULL, 0, 0};

  if (is_quoted_string(name, n)) {
    for (i = 1; i < n - 1; ++i) {
      if (name[i] == '\\')
        ++i;
      text[len++] = name[i];
    }
  } else {
    memcpy(text, name, n);
    len = n;
  }
  text[len] = 0;

  for (i = 0; i < len; ) {
    size_t w;
    while (i < len && is_blank(text[i]))
      ++i;
    for (w = i; i < len && !is_blank(text[i]); ++i);
    if (i > w) {
      must = must || must_encode(text + w, i - w);
      atoms = atoms && is_atom(text + w, i - w);
    }
  }
  if (must || atoms) {
    header_words(h, text, ENCODE_MUST_OR_NOT_ATOM, 1);
    return;
  }
  // A quoted-string; its blanks are where it folds.
  buf_quoted(h->ctx, &quoted, text, 0);
  header_words(h, uw_strdup(h->ctx, quoted.s), ENCODE_MUST, 0);
  free(quoted.s);
}

// One address: the addr-spec alone, or the name as a phrase and the
// addr-spec in brackets.
static void header_address(header_out *h, uw_UrmailFfi_emailAddress a) {
  if (a->name) {
    char *bracketed = uw_Basis_mstrcat(h->ctx, "<", a->addr, ">", NULL);
    header_name(h, a->name);
    header_put(h, " ", 1, bracketed, strlen(bracketed));
  } else
    header_put(h, " ", 1, a->addr, strlen(a->addr));
}

// A list of addresses in the order given, one per line after the first.
static void header_address_list(header_out *h, struct list *l) {
  void **as;
  size_t n = in_order(h->ctx, l, &as), i;

  for (i = 0; i < n; ++i) {
    if (i) {
      header_append(h, ",");
      h->fold_next = 1;
    }
    header_address(h, as[i]);
  }
}

// The current time as an RFC 5322 date, in UTC.  Not strftime, whose names
// follow the locale.
static void date_header(char *out, size_t n) {
  static const char *days[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
  static const char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  time_t now = time(NULL);
  struct tm tm;
  gmtime_r(&now, &tm);
  snprintf(out, n, "%s, %d %s %d %02d:%02d:%02d +0000",
           days[tm.tm_wday], tm.tm_mday, months[tm.tm_mon], tm.tm_year + 1900,
           tm.tm_hour, tm.tm_min, tm.tm_sec);
}

// The random bytes of a generated Message-ID, 96 bits, and the room for
// what goes before its '@': the bytes in hex, or else the time, the
// process and a counter, each up to 16 hex digits, between dots.
#define MESSAGE_ID_RANDOM 12
#define MESSAGE_ID_UNIQUE (2 * MESSAGE_ID_RANDOM > 3 * 16 + 2 ? 2 * MESSAGE_ID_RANDOM : 3 * 16 + 2)

// A Message-ID unique enough: random bytes, or if the system will not give
// any, the time, the process and a counter; at the domain of the From
// address, which parse_address made sure is there.
static void generate_message_id(uw_UrmailFfi_emailAddress from, char *out, size_t n) {
  unsigned char r[MESSAGE_ID_RANDOM];
  char unique[MESSAGE_ID_UNIQUE + 1];
  FILE *f = fopen("/dev/urandom", "rb");
  int ok = f && fread(r, 1, sizeof r, f) == sizeof r;
  if (f)
    fclose(f);
  if (ok) {
    size_t i;
    for (i = 0; i < sizeof r; ++i)
      snprintf(unique + 2*i, 3, "%02x", r[i]);
  } else {
    static unsigned counter = 0;
    snprintf(unique, sizeof unique, "%lx.%x.%x", (unsigned long)time(NULL), (unsigned)getpid(),
             __atomic_add_fetch(&counter, 1, __ATOMIC_RELAXED));
  }
  snprintf(out, n, "<%s@%s>", unique, strchr(from->addr, '@') + 1);
}

// The bytes as base64 in lines of 76 characters (RFC 2045), CRLF between
// them and none after the last.
static void buf_base64_lines(uw_context ctx, buf *b, const unsigned char *s, size_t n) {
  size_t i;
  for (i = 0; i < n; i += BASE64_LINE_BYTES) {
    if (i)
      buf_append(ctx, b, "\r\n", 2);
    buf_base64(ctx, b, s + i, n - i < BASE64_LINE_BYTES ? n - i : BASE64_LINE_BYTES);
  }
}

// A name as the value of filename*= (RFC 2231): UTF-8, percent-encoded but
// for letters, digits and "-._".
static void buf_extended(uw_context ctx, buf *b, const char *s) {
  buf_str(ctx, b, "UTF-8''");
  for (; *s; ++s) {
    unsigned char c = *s;
    if (isalnum(c) || c == '-' || c == '.' || c == '_')
      buf_append(ctx, b, s, 1);
    else {
      char enc[3] = {'%', hex_digits[c >> 4], hex_digits[c & 15]};
      buf_append(ctx, b, enc, 3);
    }
  }
}

// Whether a name can go into filename= as it is: ASCII.  The name has no
// control character (part_name), so this is whether it has no byte >= 0x80.
static int is_ascii_name(const char *s) {
  for (; *s; ++s)
    if ((unsigned char)*s >= 0x80)
      return 0;
  return 1;
}

// One part as MIME has it: its headers, then the bytes in base64.  An image
// has the Content-ID the HTML refers to.  A name that is not ASCII goes into
// a filename*= (RFC 2231), first, since a parser that takes the first of the
// two is then right, and on a line of its own; filename= is then an ASCII
// copy, for the clients that read only that.
static void buf_part(uw_context ctx, buf *b, struct part *p, int is_image) {
  const unsigned char *data = (const unsigned char *)p->data.data;

  buf_str(ctx, b, "Content-Type: "); buf_str(ctx, b, p->type);
  // A text type without a charset is US-ASCII (RFC 2046, section 4.1.2).
  // Text in UTF-8 is labelled so; text in another encoding cannot be told
  // from bytes alone, and is left as it is.
  if (starts_with_nocase(p->type, "text/") && !is_ascii(data, p->data.size) && is_utf8(data, p->data.size))
    buf_str(ctx, b, "; charset=utf-8");
  buf_str(ctx, b, "\r\n");
  if (is_image) {
    buf_str(ctx, b, "Content-ID: <"); buf_str(ctx, b, p->content_id); buf_str(ctx, b, ">\r\n");
  }
  buf_str(ctx, b, is_image ? "Content-Disposition: inline;" : "Content-Disposition: attachment;");
  if (is_ascii_name(p->name)) {
    buf_str(ctx, b, " filename=");
    buf_quoted(ctx, b, p->name, 0);
  } else {
    buf_str(ctx, b, " filename*=");
    buf_extended(ctx, b, p->name);
    buf_str(ctx, b, ";\r\n filename=");
    buf_quoted(ctx, b, p->name, 1);
  }
  buf_str(ctx, b, "\r\nContent-Transfer-Encoding: base64\r\n\r\n");
  buf_base64_lines(ctx, b, (const unsigned char *)p->data.data, p->data.size);
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

// Assemble the message: headers, then the body; with images, a
// multipart/related of the body and those; with attachments, a
// multipart/mixed of all that and those.
static void assemble(uw_context ctx, buf *b, uw_UrmailFfi_message m) {
  char date[sizeof "Thu, 01 Jan 1970 00:00:00 +0000" + 8];  // room for a long year
  char message_id[sizeof "<@>" + MESSAGE_ID_UNIQUE + MAX_ADDR_SPEC];
  void **images, **attached;
  size_t n_images, n_attached, i;
  header_out h;

  date_header(date, sizeof date);
  buf_str(ctx, b, "MIME-Version: 1.0\r\n");
  buf_str(ctx, b, "Date: "); buf_str(ctx, b, date); buf_str(ctx, b, "\r\n");
  if (!m->message_id)
    generate_message_id(m->from, message_id, sizeof message_id);
  buf_str(ctx, b, MESSAGE_ID_HEADER);
  buf_str(ctx, b, m->message_id ? m->message_id : message_id);
  buf_str(ctx, b, "\r\n");
  header_begin(&h, ctx, b, "From");
  header_address(&h, m->from);
  header_end(&h);
  header_begin(&h, ctx, b, "Subject");
  header_text(&h, m->subject);
  header_end(&h);
  for (i = TO_FIELD; i <= CC_FIELD; ++i)  // Bcc is the envelope's only
    if (m->recipients[i]) {
      header_begin(&h, ctx, b, recipient_field[i]);
      header_address_list(&h, m->recipients[i]);
      header_end(&h);
    }
  if (m->user_agent) {
    header_begin(&h, ctx, b, "User-Agent");
    header_text(&h, m->user_agent);
    header_end(&h);
  }

  n_images = in_order(ctx, m->images, &images);
  n_attached = in_order(ctx, m->attachments, &attached);
  if (n_attached)
    buf_str(ctx, b, "Content-Type: multipart/mixed; boundary=\"" MIXED_BOUNDARY "\"\r\n\r\n"
                    "--" MIXED_BOUNDARY "\r\n");
  if (n_images)  // RFC 2387 wants the root's type named; with an image there is an HTML part
    buf_str(ctx, b, "Content-Type: multipart/related; type=\"multipart/alternative\";\r\n"
                    " boundary=\"" RELATED_BOUNDARY "\"\r\n\r\n"
                    "--" RELATED_BOUNDARY "\r\n");
  buf_body(ctx, b, m->text, m->page ? m->html : NULL);
  for (i = 0; i < n_images; ++i) {
    buf_str(ctx, b, "\r\n--" RELATED_BOUNDARY "\r\n");
    buf_part(ctx, b, images[i], 1);
  }
  if (n_images)
    buf_str(ctx, b, "\r\n--" RELATED_BOUNDARY "--");
  for (i = 0; i < n_attached; ++i) {
    buf_str(ctx, b, "\r\n--" MIXED_BOUNDARY "\r\n");
    buf_part(ctx, b, attached[i], 0);
  }
  if (n_attached)
    buf_str(ctx, b, "\r\n--" MIXED_BOUNDARY "--");
}

/* ---- The page's img srcs.  A page is the string Ur/Web renders, which is
   regular: text has '<' and '&' escaped, so every '<' in text starts a tag;
   attribute values are in double quotes, with '"' and '&' escaped, but may
   hold '<' and '>'; and a script's text is not markup.  So the tags are
   read with their quotes, and script elements are skipped. ---- */

// Whether s begins with a URI scheme (RFC 3986): a letter, then letters,
// digits, '+', '-' or '.', then ':'.
static int has_scheme(const char *s) {
  if (!isalpha((unsigned char)*s))
    return 0;
  for (++s; isalnum((unsigned char)*s) || *s == '+' || *s == '-' || *s == '.'; ++s);
  return *s == ':';
}

// Whether s[0..n) is `lit`, ignoring case.
static int name_is(const char *s, size_t n, const char *lit) {
  return strlen(lit) == n && !strncasecmp(s, lit, n);
}

// An attribute value s[0..n) as the runtime writes it, unescaped.
static char *unattrify(uw_context ctx, const char *s, size_t n) {
  char *out = uw_malloc(ctx, n + 1), *o = out;
  size_t i = 0;

  while (i < n) {
    if (n - i >= sizeof "&amp;" - 1 && starts_with(s + i, "&amp;")) {
      *o++ = '&';
      i += sizeof "&amp;" - 1;
    } else if (n - i >= sizeof "&quot;" - 1 && starts_with(s + i, "&quot;")) {
      *o++ = '"';
      i += sizeof "&quot;" - 1;
    } else
      *o++ = s[i++];
  }
  *o = 0;
  return out;
}

// The image an img src stands for, or NULL when there is none or it has a
// problem (which is kept): the entry of Images for exactly that url;
// failing that, for a src with no scheme that does not start with "//", the
// file a file directive serves at exactly that path, named by its last
// segment.  Other srcs are left as they are.  `used` marks the entries used,
// `entries` being them in the order given.
static struct part *image_for(uw_context ctx, uw_UrmailFfi_message m, const char *src,
                              void **entries, size_t n_entries, char *used) {
  size_t i;

  for (i = 0; i < n_entries; ++i) {
    struct image_entry *e = entries[i];
    if (!strcmp(e->url, src)) {
      used[i] = 1;
      return e->part;
    }
  }
  if (has_scheme(src) || (src[0] == '/' && src[1] == '/'))
    return NULL;
  return served_part(ctx, m, "img src", src, NULL, (uw_Basis_string)src, 1);
}

// FNV-1a, 64 bits, over s[0..n), continuing from h.
#define FNV_OFFSET_BASIS 14695981039346656037ULL
#define FNV_PRIME 1099511628211ULL

static unsigned long long fnv1a(unsigned long long h, const void *s, size_t n) {
  const unsigned char *c = s;
  size_t i;

  for (i = 0; i < n; ++i)
    h = (h ^ c[i]) * FNV_PRIME;
  return h;
}

// An image's hash: of its name, type and bytes, each name and type with its
// NUL, so that no two of those can run together.
static unsigned long long part_hash(const struct part *p) {
  unsigned long long h = fnv1a(FNV_OFFSET_BASIS, p->name, strlen(p->name) + 1);

  h = fnv1a(h, p->type, strlen(p->type) + 1);
  return fnv1a(h, p->data.data, p->data.size);
}

static int same_part(const struct part *a, const struct part *b) {
  return !strcmp(a->name, b->name) && !strcmp(a->type, b->type) && a->data.size == b->data.size
         && !memcmp(a->data.data, b->data.data, a->data.size);
}

// An image of the message, once: the one already there when it is the same
// (name, type and bytes), else a copy of this one with its Content-ID.  The
// hash finds the image that may be the same, and the bytes decide, since
// FNV-1a can give two images the same hash.  The Content-ID is the hash, so
// that it is unique beyond the message without anything random, and
// Urmail.message stays a function; another image with the same hash gets a
// count after it.
static struct part *add_image(uw_context ctx, uw_UrmailFfi_message m, struct part *p) {
  struct list *l;
  struct part *image;
  unsigned long long h = part_hash(p);
  unsigned same_hash = 0;

  for (l = m->images; l; l = l->next) {
    struct part *q = l->item;
    if (q->hash == h) {
      if (same_part(q, p))
        return q;
      ++same_hash;
    }
  }
  image = uw_malloc(ctx, sizeof *image);
  *image = *p;
  image->hash = h;
  if (same_hash)
    snprintf(image->content_id, sizeof image->content_id, CONTENT_ID_FORMAT_NTH, h, same_hash + 1);
  else
    snprintf(image->content_id, sizeof image->content_id, CONTENT_ID_FORMAT, h);
  m->images = cons(ctx, image, m->images);
  return image;
}

// The first "</script", ignoring case, or NULL.
static const char *script_end(const char *s) {
  for (; (s = strchr(s, '<')); ++s)
    if (starts_with_nocase(s, "</script"))
      return s;
  return NULL;
}

// The HTML as sent: the page, with each img src that stands for an image
// pointing at it by its cid: url.  Then the entries of Images that no img
// src used, each a problem.
static void rewrite_page(uw_context ctx, uw_UrmailFfi_message m) {
  const char *s = m->page, *last = s, *p = s;
  void **entries;
  size_t n_entries = in_order(ctx, m->entries, &entries), i;
  char *used = uw_malloc(ctx, n_entries);
  buf out = {NULL, 0, 0};

  memset(used, 0, n_entries);

  while ((p = strchr(p, '<'))) {
    const char *name;
    size_t name_len;
    int closing, is_img;

    ++p;
    closing = *p == '/';
    if (closing)
      ++p;
    for (name = p; isalnum((unsigned char)*p); ++p);
    name_len = p - name;
    is_img = !closing && name_is(name, name_len, "img");

    // The attributes, up to the '>' that is not in a value.
    while (*p && *p != '>') {
      const char *an, *vs, *ve;
      size_t an_len;

      if (isspace((unsigned char)*p) || *p == '/') {
        ++p;
        continue;
      }
      for (an = p; *p && !isspace((unsigned char)*p) && *p != '=' && *p != '>' && *p != '/'; ++p);
      an_len = p - an;
      while (isspace((unsigned char)*p))
        ++p;
      if (*p != '=') {
        if (!an_len)
          ++p;  // a stray character: on
        continue;
      }
      ++p;
      while (isspace((unsigned char)*p))
        ++p;
      if (*p == '"' || *p == '\'') {
        char quote = *p++;
        vs = p;
        ve = strchr(p, quote);
        if (!ve)
          ve = p + strlen(p);
        p = *ve ? ve + 1 : ve;
      } else {
        for (vs = p; *p && !isspace((unsigned char)*p) && *p != '>'; ++p);
        ve = p;
      }
      if (is_img && name_is(an, an_len, "src")) {
        struct part *image = image_for(ctx, m, unattrify(ctx, vs, ve - vs), entries, n_entries, used);
        if (image) {
          image = add_image(ctx, m, image);
          buf_append(ctx, &out, last, vs - last);
          buf_str(ctx, &out, "cid:");
          buf_str(ctx, &out, image->content_id);
          last = ve;
        }
      }
    }
    if (*p == '>')
      ++p;
    if (!closing && name_is(name, name_len, "script")) {
      const char *end = script_end(p);
      p = end ? end : p + strlen(p);
    }
  }
  buf_str(ctx, &out, last);
  m->html = uw_strdup(ctx, out.s);
  free(out.s);

  for (i = 0; i < n_entries; ++i)
    if (!used[i])
      add_problem(ctx, m, "Image", ((struct image_entry *)entries[i])->url, "no img src of the page uses it");
}

/* ---- Delivery: a persistent connection per server and account, one send at
   a time on each, closed when idle for long or when too many are open, and
   an outcome that says what is known. ---- */

// The longest line of SMTP, a command or a reply, with its CRLF (RFC 5321,
// sections 4.5.3.1.4 and 4.5.3.1.5).
#define SMTP_LINE 512

// What the trace shows for credentials.
#define CREDENTIALS "[credentials]"

// Replies that matter here (RFC 5321, section 4.2.3; RFC 4954; RFC 1870):
// the server wants more of the AUTH exchange; it takes the message's data;
// it wants a login; the message is too big.  A reply in the 400s is for
// now, in the 500s for good.
#define REPLY_AUTH_MORE 334
#define REPLY_DATA_GO 354
#define REPLY_LOGIN_NEEDED 530
#define REPLY_TOO_BIG 552
#define FOR_NOW 400
#define FOR_GOOD 500

// What became of a send, as UrmailFfi.sendStatus has it.  (urweb.h has
// FAILED, so that is not a name for one.)
typedef enum { SENT, REFUSED, DEFERRED, MAYBE_SENT, MISCONFIGURED } outcome_kind;

// A reply of the server's (RFC 5321, section 4.2): its code, its enhanced
// status code (RFC 3463), its text, and the command it answered.
typedef struct {
  int code;           // 0: no reply
  char enhanced[16];  // "" when there is none
  char text[1024];    // after the codes, the lines joined by blanks, cut to fit
  char command[SMTP_LINE];  // as sent, credentials left out, or "greeting" or "end of DATA"
} reply;

typedef struct {
  outcome_kind kind;
  reply reply;        // the reply that decided the kind, if one did
  char detail[1024];  // what else is known, or what libcurl said
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

// What the exchange with the server came to, kept by trace_callback for the
// status: the last command sent, the last reply, and the reply being read.
typedef struct {
  char command[SMTP_LINE];  // without the line end; "" before the first
  reply last;         // the last complete reply
  reply partial;      // the reply being read, until its last line
  int in_auth;        // the AUTH exchange is on: what goes out is credentials
} trace;

// One line of libcurl's, without its line end, truncated to what fits.
static void trace_line(char *out, size_t n, const char *data, size_t size) {
  while (size && (data[size-1] == '\n' || data[size-1] == '\r'))
    --size;
  if (size >= n)
    size = n - 1;
  memcpy(out, data, size);
  out[size] = 0;
}

static int digits(const char *s, int n) {
  int i;

  for (i = 0; i < n; ++i)
    if (!isdigit((unsigned char)s[i]))
      return 0;
  return 1;
}

// The enhanced status code at the start of a reply's text, if it has one,
// copied to out (n bytes), and the text after it.  RFC 3463 has it as
// class.subject.detail: the class is the first digit of the reply's code,
// the others are of 1 to 3 digits each.
static const char *enhanced_code(const char *s, char class, char *out, size_t n) {
  const char *p = s;
  size_t k;
  int part;

  if (p[0] != class || p[1] != '.')
    return s;
  p += 2;
  for (part = 0; part < 2; ++part) {  // the subject, then the detail
    for (k = 0; isdigit((unsigned char)p[k]); ++k);
    if (k < 1 || k > 3)
      return s;
    p += k;
    if (part == 0) {
      if (*p != '.')
        return s;
      ++p;
    }
  }
  if ((*p && *p != ' ') || (size_t)(p - s) >= n)
    return s;
  memcpy(out, s, p - s);
  out[p - s] = 0;
  return *p ? p + 1 : p;
}

// One line of a reply: "ddd-text" for each but the last, "ddd text" or
// "ddd" for the last (RFC 5321, section 4.2.1).  The texts are joined,
// each without the codes.
static void reply_line(trace *t, const char *line) {
  reply *r = &t->partial;
  const char *text;
  size_t len, room;

  if (!digits(line, 3) || (line[3] && line[3] != ' ' && line[3] != '-'))
    return;
  if (!r->code) {
    r->code = atoi(line);
    r->enhanced[0] = 0;
    r->text[0] = 0;
    snprintf(r->command, sizeof r->command, "%s", t->command[0] ? t->command : "greeting");
  }
  text = enhanced_code(line[3] ? line + 4 : line + 3, line[0], r->enhanced, sizeof r->enhanced);
  len = strlen(r->text);
  room = sizeof r->text - 1 - len;
  if (len && room && *text)
    r->text[len++] = ' ', --room;
  snprintf(r->text + len, room + 1, "%s", text);
  if (line[3] != '-') {
    t->last = *r;
    r->code = 0;
  }
}

// libcurl's debug callback, always installed: it records the exchange for
// the status, and prints it as libcurl's own trace would when URMAIL_DEBUG
// is set, except that the credentials are not printed.  The AUTH exchange
// is the AUTH command, possibly with the credentials after the mechanism,
// and then one line of credentials for each 334 the server answers.  The
// message itself is never printed.
static int trace_callback(CURL *curl, curl_infotype type, char *data, size_t size, void *userp) {
  trace *t = userp;
  char line[SMTP_LINE];
  (void)curl;

  switch (type) {
  case CURLINFO_TEXT:
    if (debugging())
      fprintf(stderr, "* %.*s", (int)size, data);
    break;
  case CURLINFO_HEADER_OUT:
    if (t->in_auth) {
      if (debugging())
        fputs("> " CREDENTIALS "\n", stderr);
      break;
    }
    trace_line(t->command, sizeof t->command, data, size);
    if (starts_with(t->command, "AUTH ")) {
      // The credentials after the mechanism, if any, are left out.
      char *ir = strchr(t->command + sizeof "AUTH " - 1, ' ');
      if (ir && (size_t)(ir - t->command) + sizeof " " CREDENTIALS <= sizeof t->command)
        strcpy(ir, " " CREDENTIALS);
      t->in_auth = 1;
    }
    if (debugging())
      fprintf(stderr, "> %s\n", t->command);
    break;
  case CURLINFO_HEADER_IN:
    trace_line(line, sizeof line, data, size);
    reply_line(t, line);
    if (!t->partial.code) {  // a reply is complete
      if (t->in_auth && t->last.code != REPLY_AUTH_MORE)
        t->in_auth = 0;
      if (t->last.code == REPLY_DATA_GO && !strcmp(t->command, "DATA"))
        strcpy(t->command, "end of DATA");  // what the next reply answers
    }
    if (debugging())
      fprintf(stderr, "< %s\n", line);
    break;
  default:
    break;
  }
  return 0;
}

// The part of the session a reply answered.
typedef enum { SESSION, MAIL, RECIPIENT, DATA } stage;

static stage stage_of(const reply *r) {
  if (starts_with(r->command, "MAIL FROM"))
    return MAIL;
  if (starts_with(r->command, "RCPT TO"))
    return RECIPIENT;
  if (!strcmp(r->command, "DATA") || !strcmp(r->command, "end of DATA"))
    return DATA;
  return SESSION;  // the greeting, EHLO, HELO, STARTTLS, AUTH
}

static void decided(outcome *o, outcome_kind kind, const char *detail, const char *libcurl) {
  o->kind = kind;
  if (libcurl)
    snprintf(o->detail, sizeof o->detail, "%s (%s)", detail, libcurl);
  else
    snprintf(o->detail, sizeof o->detail, "%s", detail);
}

// What a reply of 400 or more means for the message.  A 4xx is for now.  A
// 5xx before MAIL FROM is about the session, and a 5xx to MAIL FROM about
// the sender, which belongs to the account, unless it is 552, a message
// too big (RFC 1870); both are the configuration's to fix.  So is a 530, or
// a 5.7.0 to MAIL FROM or RCPT TO: a login is needed (RFC 4954, section 6).
// A 5xx to RCPT TO, to DATA or after the message is about the message.
static void judge_reply(const reply *r, outcome *o) {
  stage s = stage_of(r);

  o->reply = *r;
  if (r->code == REPLY_LOGIN_NEEDED
      || (r->code >= FOR_GOOD && (s == MAIL || s == RECIPIENT) && !strcmp(r->enhanced, "5.7.0")))
    decided(o, MISCONFIGURED, "the server wants a login", NULL);
  else if (r->code >= FOR_GOOD && s == SESSION)
    decided(o, MISCONFIGURED, starts_with(r->command, "AUTH") ? "the server refused the login"
                              : !strcmp(r->command, "STARTTLS") ? "the server refused TLS"
                              : "the server refused the session", NULL);
  else if (r->code >= FOR_GOOD && s == MAIL && r->code != REPLY_TOO_BIG)
    decided(o, MISCONFIGURED, "the server refused the sender", NULL);
  else if (r->code >= FOR_GOOD)
    decided(o, REFUSED, "", NULL);
  else
    decided(o, DEFERRED, "the server declined for now", NULL);
}

// Seconds without progress after which a send is given up: for the
// connection, for each reply of the server's, and for an upload slower
// than MIN_UPLOAD_RATE (attempt, below); and for how long an idle
// connection is kept.  URMAIL_TIMEOUT, a whole number of seconds from 1 to
// TIMEOUT_MAX, or TIMEOUT_DEFAULT.  Anything else gets one line on stderr
// and the default.  An hour is the most: a send blocks the io task that
// makes it for as long as it goes on, and nothing is gained by waiting
// longer for a server that does not answer.
#define TIMEOUT_DEFAULT 100
#define TIMEOUT_MAX 3600

// The least an upload may make, in bytes per second, before it counts as
// making no progress: with it, an upload of n bytes is over within
// n / MIN_UPLOAD_RATE seconds, plus the timeout, so no cap on the whole
// send is needed.  Any link that can carry mail does far better.
#define MIN_UPLOAD_RATE 1024

static long timeout_seconds(void) {
  static long t = -1;
  if (t < 0) {
    const char *v = getenv("URMAIL_TIMEOUT");
    long n = TIMEOUT_DEFAULT;
    if (v && *v) {
      char *end;
      errno = 0;
      n = strtol(v, &end, 10);
      if (errno || *end || n < 1 || n > TIMEOUT_MAX) {
        fprintf(stderr, "urmail: URMAIL_TIMEOUT=%s is not a number of seconds from 1 to " NUMBER(TIMEOUT_MAX)
                        "; using " NUMBER(TIMEOUT_DEFAULT) "\n", v);
        n = TIMEOUT_DEFAULT;
      }
    }
    t = n;
  }
  return t;
}

// What a failure without a reply to decide it means: libcurl's result, and
// whether the whole message had gone to libcurl.  Only after that may the
// server have the end of the data, and so the message.
static void judge_error(CURLcode res, int all_sent, outcome *o) {
  const char *why = curl_easy_strerror(res);
  // Room for the seconds as any long prints: three digits per byte and a
  // sign.
  char no_reply[sizeof "the server did not answer the message within " + sizeof(long) * 3 + 1 + sizeof " s"];

  o->reply.code = 0;
  switch (res) {
  case CURLE_OPERATION_TIMEDOUT:
    if (all_sent) {
      // The reply to the end of the message did not come in time: it may
      // have been taken, as after a connection lost at that point.
      snprintf(no_reply, sizeof no_reply, "the server did not answer the message within %ld s", timeout_seconds());
      decided(o, MAYBE_SENT, no_reply, why);
    } else
      decided(o, DEFERRED, why, NULL);
    break;
  case CURLE_URL_MALFORMAT:
  case CURLE_UNSUPPORTED_PROTOCOL:
    decided(o, MISCONFIGURED, "the server URL is not an smtp:// or smtps:// one", why);
    break;
  case CURLE_PEER_FAILED_VERIFICATION:
    decided(o, MISCONFIGURED, "the server's certificate did not verify", why);
    break;
  case CURLE_SSL_CACERT_BADFILE:
    decided(o, MISCONFIGURED, "the CA file cannot be used", why);
    break;
  case CURLE_USE_SSL_FAILED:
    decided(o, MISCONFIGURED, "the server does not offer STARTTLS", why);
    break;
  case CURLE_LOGIN_DENIED:
    decided(o, MISCONFIGURED, "the server offers no login that libcurl can make with a password", why);
    break;
  default:
    if (all_sent)
      decided(o, MAYBE_SENT, "the connection was lost after the whole message was sent", why);
    else
      decided(o, DEFERRED, why, NULL);
    break;
  }
}

// A connection per server and account.  Its lock is held for the duration
// of a send on it; conns_lock guards the list of them and what is marked
// so below.  A thread that needs both takes the connection's first: one
// that holds conns_lock only ever tries a connection's lock, never waits
// for it.
typedef struct smtp_conn {
  char *server, *user, *password, *ca;
  enum uw_UrmailFfi_tls_tag tls;
  CURL *curl;            // the open connection, or NULL; under lock
  int open;              // whether curl is set: written under both locks,
                         // read under either
  long long last_used;   // when the last send on it ended, in milliseconds
                         // of the monotonic clock; under lock
  int users;             // the threads between get_connection and
                         // release_connection; under conns_lock
  pthread_mutex_t lock;
  struct smtp_conn *next;
} smtp_conn;

// How many connections may be open at once.
#define MAX_OPEN 8

static smtp_conn *conns = NULL;
static pthread_mutex_t conns_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t curl_once = PTHREAD_ONCE_INIT;

static void curl_init(void) {
  curl_global_init(CURL_GLOBAL_DEFAULT);
}

static int str_eq(const char *a, const char *b) {
  return (a == NULL && b == NULL) || (a && b && !strcmp(a, b));
}

// Milliseconds of a clock that only moves forward, whatever is done to the
// time of day.
static long long now_ms(void) {
  struct timespec ts;

  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// Overwrite a secret before its memory is given back.  Through a volatile
// pointer, so that the compiler does not drop the stores as dead.
static void wipe(char *s) {
  volatile char *p = s;

  while (*p)
    *p++ = 0;
}

// Mark whether c has a connection.  Called with c's lock held.
static void set_open(smtp_conn *c, int open) {
  pthread_mutex_lock(&conns_lock);
  c->open = open;
  pthread_mutex_unlock(&conns_lock);
}

// Free a record, its strings and its lock if it has one, the password
// wiped first.
static void free_record(smtp_conn *c, int has_lock) {
  if (c->password)
    wipe(c->password);
  free(c->server);
  free(c->user);
  free(c->password);
  free(c->ca);
  if (has_lock)
    pthread_mutex_destroy(&c->lock);
  free(c);
}

// Free the records that no thread uses and that have no connection.  Called
// with conns_lock held; a record without users has no thread holding or
// waiting for its lock.
static void free_unused(void) {
  smtp_conn **p = &conns, *c;

  while ((c = *p)) {
    if (c->users || c->open) {
      p = &c->next;
      continue;
    }
    *p = c->next;
    DBG("forgetting the connection record for %s as %s", c->server, c->user);
    free_record(c, 1);
  }
}

// Take the connections to close off their records: those idle for longer
// than the timeout and, while more than MAX_OPEN would be open once `next`
// has one, the least recently used of the others, so that a process that
// sends on many accounts does not hold a socket per account for its life.
// Called with conns_lock held.  A connection in use, its lock held, is left
// alone.  The handles go into `closing` (room for every record), for the
// caller to clean up once conns_lock is released, since that sends QUIT and
// waits for the reply; their number is returned.
static size_t close_idle(smtp_conn *next, CURL **closing) {
  long long now = now_ms(), limit = timeout_seconds() * 1000LL;
  smtp_conn *c, **idle;
  size_t n = 0, n_idle = 0, n_closing = 0, i, oldest;
  int open = next->open ? 0 : 1;

  for (c = conns; c; c = c->next)
    ++n;
  idle = malloc(n * sizeof *idle);
  for (c = conns; c; c = c->next) {
    if (!c->open)
      continue;
    ++open;
    if (pthread_mutex_trylock(&c->lock))
      continue;  // a send is on
    if (now - c->last_used > limit) {
      DBG("closing the connection to %s as %s, idle for longer than %ld s", c->server, c->user,
          timeout_seconds());
      closing[n_closing++] = c->curl;
      c->curl = NULL;
      c->open = 0;
      --open;
      pthread_mutex_unlock(&c->lock);
    } else if (c == next || !idle)
      pthread_mutex_unlock(&c->lock);  // about to be used, or no room to keep it locked
    else
      idle[n_idle++] = c;
  }
  while (open > MAX_OPEN && n_idle) {
    for (oldest = 0, i = 1; i < n_idle; ++i)
      if (idle[i]->last_used < idle[oldest]->last_used)
        oldest = i;
    c = idle[oldest];
    DBG("closing the connection to %s as %s: %d are open", c->server, c->user, open);
    closing[n_closing++] = c->curl;
    c->curl = NULL;
    c->open = 0;
    --open;
    pthread_mutex_unlock(&c->lock);
    idle[oldest] = idle[--n_idle];
  }
  for (i = 0; i < n_idle; ++i)
    pthread_mutex_unlock(&idle[i]->lock);
  free(idle);
  return n_closing;
}

static smtp_conn *new_record(job *j) {
  smtp_conn *c = calloc(1, sizeof *c);

  if (!c)
    return NULL;
  c->server = strdup(j->server);
  c->user = strdup(j->user);
  c->password = strdup(j->password);
  c->ca = j->ca ? strdup(j->ca) : NULL;
  if (!c->server || !c->user || !c->password || (j->ca && !c->ca)) {
    free_record(c, 0);
    return NULL;
  }
  c->tls = j->tls;
  pthread_mutex_init(&c->lock, NULL);
  return c;
}

// The connection for this server and account, created on first use, or
// NULL when there is no memory for it; release_connection lets it go.  The
// libcurl handle keeps the TCP (and TLS) connection open between sends, so
// a batch of messages does not pay for a handshake and a login each.
static smtp_conn *get_connection(job *j) {
  smtp_conn *c;
  CURL **closing = NULL;
  size_t n = 0, n_closing = 0, i;

  pthread_once(&curl_once, curl_init);
  pthread_mutex_lock(&conns_lock);
  for (c = conns; c; c = c->next)
    if (!strcmp(c->server, j->server) && !strcmp(c->user, j->user)
        && !strcmp(c->password, j->password) && str_eq(c->ca, j->ca) && c->tls == j->tls)
      break;
  if (!c && (c = new_record(j))) {
    c->next = conns;
    conns = c;
    DBG("new connection record for %s as %s", c->server, c->user);
  }
  if (c) {
    smtp_conn *d;
    ++c->users;
    for (d = conns; d; d = d->next)  // room in closing for every record
      ++n;
    closing = malloc(n * sizeof *closing);
    if (closing)
      n_closing = close_idle(c, closing);
    free_unused();
  }
  pthread_mutex_unlock(&conns_lock);
  for (i = 0; i < n_closing; ++i)
    curl_easy_cleanup(closing[i]);
  free(closing);
  return c;
}

static void release_connection(smtp_conn *c) {
  pthread_mutex_lock(&conns_lock);
  --c->users;
  free_unused();
  pthread_mutex_unlock(&conns_lock);
}

// One attempt; `fresh` forces a new TCP connection.  `t` records the
// exchange.
static CURLcode attempt(smtp_conn *c, job *j, struct curl_slist *recipients,
                        upload_status *up, int fresh, trace *t) {
  CURL *curl = c->curl;
  CURLcode res;
  long timeout = timeout_seconds();

  memset(t, 0, sizeof *t);
  curl_easy_reset(curl);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);  // threads: no SIGALRM for timeouts
  // The trace is always on, since the status is made from it; it prints
  // only when debugging.
  curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, trace_callback);
  curl_easy_setopt(curl, CURLOPT_DEBUGDATA, t);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, timeout);
  // Each reply within the timeout, the one to the end of the message
  // included: libcurl waits for that one after the transfer, where the
  // speed check below does not run, and would otherwise wait with a
  // timeout of its own.
  curl_easy_setopt(curl, CURLOPT_SERVER_RESPONSE_TIMEOUT, timeout);
  // The upload at MIN_UPLOAD_RATE or better, else given up after the
  // timeout without.
  curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, (long)MIN_UPLOAD_RATE);
  curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, timeout);
  if (fresh)
    curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 1L);

  if (*j->user) {
    curl_easy_setopt(curl, CURLOPT_USERNAME, j->user);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, j->password);
  }
  // else no login: libcurl sends AUTH only when a user name is set.  With
  // an empty one set it would log in with empty credentials.
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

  curl_easy_setopt(curl, CURLOPT_MAIL_FROM, j->m->from->addr);
  curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
  curl_easy_setopt(curl, CURLOPT_READFUNCTION, do_upload);
  curl_easy_setopt(curl, CURLOPT_READDATA, up);
  curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
  // The size, for MAIL FROM's SIZE= when the server offers SIZE (RFC 1870),
  // so that one with a lower limit refuses before the upload.
  curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)j->length);

  res = curl_easy_perform(curl);
  return res;
}

// Whether a server URL has credentials in it, user@ or user:password@
// before the host.  libcurl would log in with them where no User is given,
// and the trace would show them.
static int has_credentials(const char *url) {
  const char *p = strstr(url, "://");

  p = p ? p + 3 : url;
  for (; *p && *p != '/' && *p != '?' && *p != '#'; ++p)
    if (*p == '@')
      return 1;
  return 0;
}

// Send the job's message, and say what became of it: SENT, or what
// judge_reply makes of the server's reply when one decided it, or
// judge_error of libcurl's result.  A reused connection that breaks before
// any of the message went out may have been closed by the server while
// idle, so one more attempt is made then, on a fresh connection.
static void deliver(job *j, outcome *o) {
  smtp_conn *c;
  CURL *dead = NULL;
  struct curl_slist *recipients = NULL;
  upload_status up;
  trace t;
  CURLcode res;
  int fresh = 0, tries = 0;
  size_t i;

  o->reply.code = 0;
  if (has_credentials(j->server)) {
    decided(o, MISCONFIGURED, "the server URL has credentials in it; give them as User and Password", NULL);
    return;
  }
  if (!(c = get_connection(j))) {
    decided(o, DEFERRED, "out of memory for a connection record", NULL);
    return;
  }
  for (i = 0; i < j->n_recipients; ++i)
    recipients = curl_slist_append(recipients, j->recipients[i]);

  pthread_mutex_lock(&c->lock);
  if (!c->curl && (c->curl = curl_easy_init()))
    set_open(c, 1);
  if (!c->curl) {
    pthread_mutex_unlock(&c->lock);
    release_connection(c);
    curl_slist_free_all(recipients);
    decided(o, DEFERRED, "cannot create a libcurl handle", NULL);
    return;
  }

  for (;;) {
    long connects = 0;

    up.content = j->message;
    up.length = j->length;
    ++tries;
    DBG("attempt %d (%s connection) for %s", tries, fresh ? "fresh" : "reused if possible", j->server);
    res = attempt(c, j, recipients, &up, fresh, &t);

    if (res == CURLE_OK) {
      DBG("sent");
      o->kind = SENT;
      o->reply.code = 0;
      o->detail[0] = 0;
      break;
    }

    curl_easy_getinfo(c->curl, CURLINFO_NUM_CONNECTS, &connects);
    DBG("failed: %s (last reply %d, %zu of %zu bytes not sent, %ld new connections)",
        curl_easy_strerror(res), t.last.code, up.length, j->length, connects);

    if (t.last.code >= FOR_NOW) {
      judge_reply(&t.last, o);
      break;
    }
    if (tries == 1 && connects == 0 && up.length == j->length
        && (res == CURLE_SEND_ERROR || res == CURLE_RECV_ERROR || res == CURLE_GOT_NOTHING)) {
      fresh = 1;
      continue;
    }
    judge_error(res, up.length == 0, o);
    break;
  }

  if (res != CURLE_OK) {
    // Whatever state the connection is in, do not reuse it.  It is cleaned
    // up once the lock is released, since that may send QUIT and wait.
    dead = c->curl;
    c->curl = NULL;
    set_open(c, 0);
  }
  c->last_used = now_ms();
  pthread_mutex_unlock(&c->lock);
  if (dead)
    curl_easy_cleanup(dead);
  release_connection(c);
  curl_slist_free_all(recipients);
}

// UrmailFfi.reply and UrmailFfi.problem, which Urmail makes records of.
struct send_reply {
  uw_Basis_int code;
  uw_Basis_string enhanced, text, command;
};

struct send_problem {
  uw_UrmailFfi_reply reply;  // or NULL
  uw_Basis_string detail;
};

static uw_UrmailFfi_reply ffi_reply(uw_context ctx, const reply *r) {
  uw_UrmailFfi_reply x = uw_malloc(ctx, sizeof *x);

  x->code = r->code;
  x->enhanced = r->enhanced[0] ? uw_strdup(ctx, r->enhanced) : NULL;
  x->text = uw_strdup(ctx, r->text);
  x->command = uw_strdup(ctx, r->command);
  return x;
}

static uw_UrmailFfi_problem ffi_problem(uw_context ctx, const outcome *o) {
  uw_UrmailFfi_problem p = uw_malloc(ctx, sizeof *p);

  p->reply = o->reply.code ? ffi_reply(ctx, &o->reply) : NULL;
  p->detail = uw_strdup(ctx, o->detail);
  return p;
}

uw_Basis_int uw_UrmailFfi_replyCode(uw_context ctx, uw_UrmailFfi_reply r) {
  (void)ctx;
  return r->code;
}

uw_Basis_string uw_UrmailFfi_replyEnhanced(uw_context ctx, uw_UrmailFfi_reply r) {
  (void)ctx;
  return r->enhanced;
}

uw_Basis_string uw_UrmailFfi_replyText(uw_context ctx, uw_UrmailFfi_reply r) {
  (void)ctx;
  return r->text;
}

uw_Basis_string uw_UrmailFfi_replyCommand(uw_context ctx, uw_UrmailFfi_reply r) {
  (void)ctx;
  return r->command;
}

uw_Basis_bool uw_UrmailFfi_problemHasReply(uw_context ctx, uw_UrmailFfi_problem p) {
  (void)ctx;
  return p->reply ? uw_Basis_True : uw_Basis_False;
}

uw_UrmailFfi_reply uw_UrmailFfi_problemReply(uw_context ctx, uw_UrmailFfi_problem p) {
  if (!p->reply)
    uw_error(ctx, FATAL, "urmail: problemReply of a problem without a reply");
  return p->reply;
}

uw_Basis_string uw_UrmailFfi_problemDetail(uw_context ctx, uw_UrmailFfi_problem p) {
  (void)ctx;
  return p->detail;
}

// UrmailFfi.send, in io: assemble the message, send it now, and say what
// became of it.  Urmail.message gives send only finished messages without
// problems, so another one comes from code that used UrmailFfi directly:
// an error of that code, reported with what is wrong.
uw_UrmailFfi_sendStatus uw_UrmailFfi_send(uw_context ctx, uw_Basis_string server, uw_UrmailFfi_tls tls,
                                          uw_Basis_string user, uw_Basis_string password,
                                          uw_UrmailFfi_message m) {
  buf b = {NULL, 0, 0};
  job j;
  outcome o;
  uw_UrmailFfi_sendStatus r = uw_malloc(ctx, sizeof(struct uw_UrmailFfi_sendStatus));

  if (!m || !m->finished)
    uw_error(ctx, FATAL, "urmail: send was given a message that UrmailFfi.finish did not end"
                         " (Urmail.message makes complete ones)");
  if (m->problems)
    uw_error(ctx, FATAL, "urmail: send was given a message with problems (Urmail.message refuses those): %s",
             problems_joined(ctx, m, "; "));
  j.n_recipients = envelope(ctx, m, &j.recipients, (size_t)-1);
  assemble(ctx, &b, m);

  j.m = m;
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
    r->data.uw_Refused = ffi_reply(ctx, &o.reply);
    break;
  case DEFERRED:
    r->tag = uw_UrmailFfi_Deferred;
    r->data.uw_Deferred = ffi_problem(ctx, &o);
    break;
  case MAYBE_SENT:
    r->tag = uw_UrmailFfi_MaybeSent;
    r->data.uw_MaybeSent = ffi_problem(ctx, &o);
    break;
  case MISCONFIGURED:
    r->tag = uw_UrmailFfi_Misconfigured;
    r->data.uw_Misconfigured = ffi_problem(ctx, &o);
    break;
  }
  return r;
}
