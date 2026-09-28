#include <urweb.h>

typedef struct headers *uw_UrmailFfi_headers;
typedef struct attachment *uw_UrmailFfi_attachment;
typedef struct attachments *uw_UrmailFfi_attachments;  // NULL for none

// UrmailFfi.tls, laid out as the compiler expects a datatype declared in an FFI
// signature: the struct's tag is uw_Module_type, the constructors are the tag
// enum's constants uw_Module_Con, and a constructor's argument is the union
// member uw_Con.
enum uw_UrmailFfi_tls_tag { uw_UrmailFfi_Plain, uw_UrmailFfi_Tls, uw_UrmailFfi_TlsNoVerify };
struct uw_UrmailFfi_tls {
  enum uw_UrmailFfi_tls_tag tag;
  union { uw_Basis_string uw_Tls; } data;  // the CA file, or NULL for the system's
};
typedef struct uw_UrmailFfi_tls *uw_UrmailFfi_tls;

extern uw_UrmailFfi_headers uw_UrmailFfi_empty;

uw_UrmailFfi_headers uw_UrmailFfi_from(uw_context, uw_Basis_string, uw_UrmailFfi_headers);
uw_UrmailFfi_headers uw_UrmailFfi_to(uw_context, uw_Basis_string, uw_UrmailFfi_headers);
uw_UrmailFfi_headers uw_UrmailFfi_cc(uw_context, uw_Basis_string, uw_UrmailFfi_headers);
uw_UrmailFfi_headers uw_UrmailFfi_bcc(uw_context, uw_Basis_string, uw_UrmailFfi_headers);
uw_UrmailFfi_headers uw_UrmailFfi_subject(uw_context, uw_Basis_string, uw_UrmailFfi_headers);
uw_UrmailFfi_headers uw_UrmailFfi_user_agent(uw_context, uw_Basis_string, uw_UrmailFfi_headers);
uw_UrmailFfi_headers uw_UrmailFfi_messageId(uw_context, uw_Basis_string, uw_UrmailFfi_headers);

// An attachment: the filename= every client reads, the filename*= beside it
// (an `option string`: NULL for None), type/subtype, and the bytes.
uw_UrmailFfi_attachment uw_UrmailFfi_attach(uw_context, uw_Basis_string ascii_name, uw_Basis_string utf8_name,
                                            uw_Basis_string type, uw_Basis_blob data);
uw_Basis_string uw_UrmailFfi_attachmentProblem(uw_context, uw_UrmailFfi_attachment);
// A fatal error naming the location given and what is wrong; never returns.
uw_UrmailFfi_attachment uw_UrmailFfi_refuse(uw_context, uw_Basis_string loc, uw_Basis_string what);
// The same part marked inline, and the cid: URL of such a part (a `url`,
// which is a string in C).
uw_UrmailFfi_attachment uw_UrmailFfi_inline(uw_context, uw_UrmailFfi_attachment);
uw_Basis_string uw_UrmailFfi_cid(uw_context, uw_UrmailFfi_attachment);

extern uw_UrmailFfi_attachments uw_UrmailFfi_noAttachments;
uw_UrmailFfi_attachments uw_UrmailFfi_addAttachment(uw_context, uw_UrmailFfi_attachment, uw_UrmailFfi_attachments);

// UrmailFfi.sendStatus, laid out as uw_UrmailFfi_tls is.
enum uw_UrmailFfi_sendStatus_tag { uw_UrmailFfi_Sent, uw_UrmailFfi_Refused, uw_UrmailFfi_NotSent, uw_UrmailFfi_MaybeSent };
struct uw_UrmailFfi_sendStatus {
  enum uw_UrmailFfi_sendStatus_tag tag;
  union { uw_Basis_string uw_Refused; uw_Basis_string uw_NotSent; uw_Basis_string uw_MaybeSent; } data;
};
typedef struct uw_UrmailFfi_sendStatus *uw_UrmailFfi_sendStatus;

// What is wrong with the headers, if anything: an `option string`, which for
// a string is the string or NULL.
uw_Basis_string uw_UrmailFfi_problem(uw_context, uw_UrmailFfi_headers);

uw_UrmailFfi_sendStatus uw_UrmailFfi_send(uw_context, uw_Basis_string server, uw_UrmailFfi_tls tls,
                                          uw_Basis_string user, uw_Basis_string password,
                                          uw_UrmailFfi_headers, uw_Basis_string body, uw_Basis_string xbody,
                                          uw_UrmailFfi_attachments);
