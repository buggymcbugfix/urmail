#include <urweb.h>

typedef struct headers *uw_Urmail_headers;

// Urmail.tls, laid out as the compiler expects a datatype declared in an FFI
// signature: the struct's tag is uw_Module_type, the constructors are the tag
// enum's constants uw_Module_Con, and a constructor's argument is the union
// member uw_Con.
enum uw_Urmail_tls_tag { uw_Urmail_Plain, uw_Urmail_Tls, uw_Urmail_TlsNoVerify };
struct uw_Urmail_tls {
  enum uw_Urmail_tls_tag tag;
  union { uw_Basis_string uw_Tls; } data;  // the CA file, or NULL for the system's
};
typedef struct uw_Urmail_tls *uw_Urmail_tls;

extern uw_Urmail_headers uw_Urmail_empty;

uw_Urmail_headers uw_Urmail_from(uw_context, uw_Basis_string, uw_Urmail_headers);
uw_Urmail_headers uw_Urmail_to(uw_context, uw_Basis_string, uw_Urmail_headers);
uw_Urmail_headers uw_Urmail_cc(uw_context, uw_Basis_string, uw_Urmail_headers);
uw_Urmail_headers uw_Urmail_bcc(uw_context, uw_Basis_string, uw_Urmail_headers);
uw_Urmail_headers uw_Urmail_subject(uw_context, uw_Basis_string, uw_Urmail_headers);
uw_Urmail_headers uw_Urmail_user_agent(uw_context, uw_Basis_string, uw_Urmail_headers);
uw_Urmail_headers uw_Urmail_messageId(uw_context, uw_Basis_string, uw_Urmail_headers);

uw_unit uw_Urmail_send(uw_context, uw_Basis_string server, uw_Urmail_tls tls,
                     uw_Basis_string user, uw_Basis_string password,
                     uw_Urmail_headers, uw_Basis_string body, uw_Basis_string xbody);
