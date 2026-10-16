#include <urweb.h>

typedef struct address *uw_UrmailFfi_emailAddress;
typedef struct message *uw_UrmailFfi_message;

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

// An address, parsed: never fails; what is wrong with it is an `option
// string` (the string or NULL), and its text is what it was given, trimmed.
uw_UrmailFfi_emailAddress uw_UrmailFfi_parseAddress(uw_context, uw_Basis_string);
uw_Basis_string uw_UrmailFfi_addressProblem(uw_context, uw_UrmailFfi_emailAddress);
uw_Basis_string uw_UrmailFfi_addressString(uw_context, uw_UrmailFfi_emailAddress);

// A message, built up one field at a time.  The builders never fail; what is
// wrong is kept, and problems gives it.  An `option string` is the string or
// NULL, a `url` and a `page` are strings.
extern uw_UrmailFfi_message uw_UrmailFfi_start;

uw_UrmailFfi_message uw_UrmailFfi_from(uw_context, uw_Basis_string, uw_UrmailFfi_message);
uw_UrmailFfi_message uw_UrmailFfi_to(uw_context, uw_Basis_string, uw_UrmailFfi_message);
uw_UrmailFfi_message uw_UrmailFfi_cc(uw_context, uw_Basis_string, uw_UrmailFfi_message);
uw_UrmailFfi_message uw_UrmailFfi_bcc(uw_context, uw_Basis_string, uw_UrmailFfi_message);
uw_UrmailFfi_message uw_UrmailFfi_subject(uw_context, uw_Basis_string, uw_UrmailFfi_message);
uw_UrmailFfi_message uw_UrmailFfi_userAgent(uw_context, uw_Basis_string, uw_UrmailFfi_message);
uw_UrmailFfi_message uw_UrmailFfi_messageId(uw_context, uw_Basis_string, uw_UrmailFfi_message);
uw_UrmailFfi_message uw_UrmailFfi_text(uw_context, uw_Basis_string, uw_UrmailFfi_message);
uw_UrmailFfi_message uw_UrmailFfi_html(uw_context, uw_Basis_string page, uw_UrmailFfi_message);
uw_UrmailFfi_message uw_UrmailFfi_imageBlob(uw_context, uw_Basis_string url, uw_Basis_string name,
                                            uw_Basis_string type, uw_Basis_blob data, uw_UrmailFfi_message);
uw_UrmailFfi_message uw_UrmailFfi_imageServedFile(uw_context, uw_Basis_string url, uw_Basis_string name,
                                                  uw_Basis_string path, uw_UrmailFfi_message);
uw_UrmailFfi_message uw_UrmailFfi_attachBlob(uw_context, uw_Basis_string name, uw_Basis_string type,
                                             uw_Basis_blob data, uw_UrmailFfi_message);
uw_UrmailFfi_message uw_UrmailFfi_attachServedFile(uw_context, uw_Basis_string name, uw_Basis_string path,
                                                   uw_UrmailFfi_message);
uw_UrmailFfi_message uw_UrmailFfi_lookUpImages(uw_context, uw_UrmailFfi_message);
uw_UrmailFfi_message uw_UrmailFfi_finish(uw_context, uw_UrmailFfi_message);
uw_Basis_string uw_UrmailFfi_problems(uw_context, uw_UrmailFfi_message);

// What became of a send: UrmailFfi.reply and UrmailFfi.problem, read with
// the functions below, and UrmailFfi.sendStatus, laid out as
// uw_UrmailFfi_tls is.
typedef struct send_reply *uw_UrmailFfi_reply;
typedef struct send_problem *uw_UrmailFfi_problem;

uw_Basis_int uw_UrmailFfi_replyCode(uw_context, uw_UrmailFfi_reply);
uw_Basis_string uw_UrmailFfi_replyEnhanced(uw_context, uw_UrmailFfi_reply);
uw_Basis_string uw_UrmailFfi_replyText(uw_context, uw_UrmailFfi_reply);
uw_Basis_string uw_UrmailFfi_replyCommand(uw_context, uw_UrmailFfi_reply);
uw_Basis_bool uw_UrmailFfi_problemHasReply(uw_context, uw_UrmailFfi_problem);
uw_UrmailFfi_reply uw_UrmailFfi_problemReply(uw_context, uw_UrmailFfi_problem);
uw_Basis_string uw_UrmailFfi_problemDetail(uw_context, uw_UrmailFfi_problem);

enum uw_UrmailFfi_sendStatus_tag { uw_UrmailFfi_Sent, uw_UrmailFfi_Refused, uw_UrmailFfi_Deferred,
                                   uw_UrmailFfi_MaybeSent, uw_UrmailFfi_Misconfigured };
struct uw_UrmailFfi_sendStatus {
  enum uw_UrmailFfi_sendStatus_tag tag;
  union {
    uw_UrmailFfi_reply uw_Refused;
    uw_UrmailFfi_problem uw_Deferred;
    uw_UrmailFfi_problem uw_MaybeSent;
    uw_UrmailFfi_problem uw_Misconfigured;
  } data;
};
typedef struct uw_UrmailFfi_sendStatus *uw_UrmailFfi_sendStatus;

uw_UrmailFfi_sendStatus uw_UrmailFfi_send(uw_context, uw_Basis_string server, uw_UrmailFfi_tls tls,
                                          uw_Basis_string user, uw_Basis_string password,
                                          uw_UrmailFfi_message);
