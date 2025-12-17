#include <urweb.h>

typedef struct headers *uw_Urmail_headers;

extern uw_Urmail_headers uw_Urmail_empty;

uw_Urmail_headers uw_Urmail_from(uw_context, uw_Basis_string, uw_Urmail_headers);
uw_Urmail_headers uw_Urmail_to(uw_context, uw_Basis_string, uw_Urmail_headers);
uw_Urmail_headers uw_Urmail_cc(uw_context, uw_Basis_string, uw_Urmail_headers);
uw_Urmail_headers uw_Urmail_bcc(uw_context, uw_Basis_string, uw_Urmail_headers);
uw_Urmail_headers uw_Urmail_subject(uw_context, uw_Basis_string, uw_Urmail_headers);

uw_unit uw_Urmail_send(uw_context, uw_Basis_string server,
                     uw_Basis_bool ssl, uw_Basis_string ca,
                     uw_Basis_string user, uw_Basis_string password,
                     uw_Urmail_headers, uw_Basis_string body,
					 uw_Basis_string xbody, uw_Basis_int email_id);
