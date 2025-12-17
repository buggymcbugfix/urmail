#include <errno.h>
#include <sqlite3.h>
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>

#include <urweb/urweb.h>

#define STR(x) #x
#define TOSTR(x) STR(x)
#define _LOC_ __FILE__ ":" TOSTR(__LINE__)

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

// Some values are expected to be long enough that they might exceed SMTP's limit on line length.
// Let's at least make sure that the line breaks are clear to SMTP,
// by changing bare '\n' into "\r\n".
static uw_Basis_string copy_long_string(uw_context ctx, uw_Basis_string s) {
	uw_Basis_string copy, in, out;
	int last_was_cr = 0;

	if (s == NULL)
		return NULL;

	copy = uw_malloc(ctx, 2 * strlen(s) + 1);
	out = copy;
	for (in = s; *in; ++in) {
		if (*in == '\n' && !last_was_cr) {
			*out++ = '\r';
			*out++ = '\n';
		} else
			*out++ = *in;
		last_was_cr = (*in == '\r');
	}
	*out = 0;

	return strdup(copy);
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
		uw_error(ctx, FATAL, "urmail: Header value too long");

	for (; *s; ++s)
		if (*s == '\r' || *s == '\n')
			uw_error(ctx, FATAL, "urmail: Header value contains newline");
}

static void address(uw_context ctx, uw_Basis_string s) {
	header(ctx, s);

	if (strchr(s, ','))
		uw_error(ctx, FATAL, "urmail: E-mail address contains comma");
}

uw_Urmail_headers uw_Urmail_from(uw_context ctx, uw_Basis_string s, uw_Urmail_headers h) {
	uw_Urmail_headers h2 = uw_malloc(ctx, sizeof(struct headers));

	if (h)
		*h2 = *h;
	else
		memset(h2, 0, sizeof(*h2));

	if (h2->from)
		uw_error(ctx, FATAL, "urmail: Duplicate From header");

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
		uw_error(ctx, FATAL, "urmail: Duplicate Subject header");

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
		uw_error(ctx, FATAL, "urmail: Duplicate User-Agent header");

	header(ctx, s);
	h2->user_agent = uw_strdup(ctx, s);

	return h2;
}

typedef struct {
	uw_context ctx;
	uw_Urmail_headers h;
	uw_Basis_string server, ca, user, password, body, xbody;
	uw_Basis_bool ssl;
	uw_Basis_int email_id;
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

static void update_tbEmail_err(sqlite3 *sqlite, uw_context ctx, uw_Basis_int email_id, const char *msg) {

	const char *max_retry_count_env = getenv("WW_EMAIL_MAX_RETRY_COUNT");

	if (max_retry_count_env == NULL) {
		fprintf(stderr, "WW_EMAIL_MAX_RETRY_COUNT not set\n");
		return;
	}

	char *endptr;
	errno = 0;
	uw_Basis_int max_retry_count = strtoll(max_retry_count_env, &endptr, 10);

	if (errno != 0 || *endptr != '\0' || endptr == max_retry_count_env) {
		fprintf(stderr, "WW_EMAIL_MAX_RETRY_COUNT set to invalid number: %s\n", max_retry_count_env);
		return;
	}

	if (max_retry_count < 0 || max_retry_count > 15) {
		fprintf(stderr, "WW_EMAIL_MAX_RETRY_COUNT outside sensible range [0-15]: %lld\n", max_retry_count);
		return;
	}

	sqlite3_stmt *stmt = NULL;

	const char *sql = "SELECT RetryCount FROM tbEmail WHERE Id = ?";
	if (sqlite3_prepare_v2(sqlite, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, "SQLite error: %s at " _LOC_ "\n", sqlite3_errmsg(sqlite));
		return;
	}
	if(sqlite3_bind_int64(stmt, 1, email_id) != SQLITE_OK) {
		fprintf(stderr, "SQLite bind error: %s at " _LOC_ "\n", sqlite3_errmsg(sqlite));
		goto cleanup;
	}

	if (sqlite3_step(stmt) != SQLITE_ROW) {
		fprintf(stderr, "Error getting row at " _LOC_ "\n");
		goto cleanup;
	}

	uw_Basis_int retry_count = sqlite3_column_int64(stmt, 0);

	sqlite3_finalize(stmt);
	stmt = NULL;

	const char *insert_sql =
		"INSERT INTO tbEmailErr (\"EmailId\", \"Timestamp\", \"Message\") VALUES (?, CURRENT_TIMESTAMP, ?)";
	if (sqlite3_prepare_v2(sqlite, insert_sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, "SQLite error: %s at " _LOC_ "\n", sqlite3_errmsg(sqlite));
		return;
	}
	if(sqlite3_bind_int64(stmt, 1, email_id) != SQLITE_OK) {
		fprintf(stderr, "SQLite bind error: %s at " _LOC_ "\n", sqlite3_errmsg(sqlite));
		goto cleanup;
	}
	if(sqlite3_bind_text(stmt, 2, msg, -1, SQLITE_STATIC) != SQLITE_OK) {
		fprintf(stderr, "SQLite bind error: %s at " _LOC_ "\n", sqlite3_errmsg(sqlite));
		goto cleanup;
	}

	if (sqlite3_step(stmt) != SQLITE_DONE) {
		fprintf(stderr, "SQLite error executing INSERT: %s at " _LOC_ "\n", sqlite3_errmsg(sqlite));
		goto cleanup;
	}

	sqlite3_finalize(stmt);
	stmt = NULL;

	if (retry_count < max_retry_count) {
		if (retry_count < 0) {
			fprintf(stderr, "Negative retry_count: %lld at " _LOC_ "\n", retry_count);
			return;
		}
		uw_Basis_int new_scheduled = 1LL << retry_count;
		const char *update_sql =
			"UPDATE tbEmail"
			" SET"
				" RetryCount = RetryCount + 1,"
				" RetryAt = datetime(CURRENT_TIMESTAMP, '+' || ? || ' minutes')"
				" WHERE Id = ?";
		if (sqlite3_prepare_v2(sqlite, update_sql, -1, &stmt, NULL) != SQLITE_OK) {
			fprintf(stderr, "SQLite error: %s at " _LOC_ "\n", sqlite3_errmsg(sqlite));
			return;
		}
		if(sqlite3_bind_int64(stmt, 1, new_scheduled) != SQLITE_OK) {
			fprintf(stderr, "SQLite bind error: %s at " _LOC_ "\n", sqlite3_errmsg(sqlite));
			goto cleanup;
		}
		if(sqlite3_bind_int64(stmt, 2, email_id) != SQLITE_OK) {
			fprintf(stderr, "SQLite bind error: %s at " _LOC_ "\n", sqlite3_errmsg(sqlite));
			goto cleanup;
		}
		if (sqlite3_step(stmt) != SQLITE_DONE) {
			fprintf(stderr, "SQLite error executing UPDATE: %s at " _LOC_ "\n", sqlite3_errmsg(sqlite));
		}

	} else {
		const char *update_sql =
			"UPDATE tbEmail"
			" SET"
				" Status = 'PermanentlyFailed'"
				" WHERE Id = ?";
		if (sqlite3_prepare_v2(sqlite, update_sql, -1, &stmt, NULL) != SQLITE_OK) {
			fprintf(stderr, "SQLite error: %s at " _LOC_ "\n", sqlite3_errmsg(sqlite));
			return;
		}
		if(sqlite3_bind_int64(stmt, 1, email_id) != SQLITE_OK) {
			fprintf(stderr, "SQLite bind error: %s at " _LOC_ "\n", sqlite3_errmsg(sqlite));
			goto cleanup;
		}
		if (sqlite3_step(stmt) != SQLITE_DONE) {
			fprintf(stderr, "SQLite error executing UPDATE: %s at " _LOC_ "\n", sqlite3_errmsg(sqlite));
		}
		sqlite3_finalize(stmt);
		stmt = NULL;

		// Enqueue alert email to notify about permanently failed email
		const char *shop_email_outgoing_address = getenv("WW_SHOP_EMAIL_OUTGOING_ADDRESS");
		if (shop_email_outgoing_address == NULL) {
			fprintf(stderr, "WW_SHOP_EMAIL_OUTGOING_ADDRESS not set\n");
			return;
		}
		const char *debug_email_recipient_address = getenv("WW_DEBUG_EMAIL_RECIPIENT_ADDRESS");
		if (debug_email_recipient_address == NULL) {
			fprintf(stderr, "WW_DEBUG_EMAIL_RECIPIENT_ADDRESS not set\n");
			return;
		}
		char email_template[64];
		snprintf(email_template, sizeof email_template, "ERR_email_permanently_failed_1/%lld", email_id);

		const char *update_sql2 =
			"INSERT INTO tbEmail"
			" (Status  , FromSender, ToRecipient, Priority, Language, Template, ScheduledFor     ) VALUES"
			" ('Outbox', ?         , ?          , 12345   , 'En'    , ?       , CURRENT_TIMESTAMP)";
		if (sqlite3_prepare_v2(sqlite, update_sql2, -1, &stmt, NULL) != SQLITE_OK) {
			fprintf(stderr, "SQLite error: %s at " _LOC_ "\n", sqlite3_errmsg(sqlite));
			return;
		}
		if(sqlite3_bind_text(stmt, 1, shop_email_outgoing_address, -1, SQLITE_STATIC) != SQLITE_OK) {
			fprintf(stderr, "SQLite bind error: %s at " _LOC_ "\n", sqlite3_errmsg(sqlite));
			goto cleanup;
		}
		if(sqlite3_bind_text(stmt, 2, debug_email_recipient_address, -1, SQLITE_STATIC) != SQLITE_OK) {
			fprintf(stderr, "SQLite bind error: %s at " _LOC_ "\n", sqlite3_errmsg(sqlite));
			goto cleanup;
		}
		if(sqlite3_bind_text(stmt, 3, email_template, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
			fprintf(stderr, "SQLite bind error: %s at " _LOC_ "\n", sqlite3_errmsg(sqlite));
			goto cleanup;
		}
		if (sqlite3_step(stmt) != SQLITE_DONE) {
			fprintf(stderr, "SQLite error executing INSERT: %s at " _LOC_ "\n", sqlite3_errmsg(sqlite));
		}
	}
	cleanup:
	sqlite3_finalize(stmt);
}

static void urmail_err(sqlite3 *sqlite, job* j, const char* msg) {
	uw_set_error_message(j->ctx, msg);
	update_tbEmail_err(sqlite, j->ctx, j->email_id, msg);
}

static void commit(void *data) {
	job *j = data;

	const char *ww_db = getenv("WW_DB");

	if (ww_db == NULL) {
		fprintf(stderr, "WW_DB not set\n");
		return;
	}

	sqlite3 *sqlite;
	if (sqlite3_open(ww_db, &sqlite) != SQLITE_OK) {
		fprintf(stderr, "Can't open SQLite database %s", ww_db);
		return;
	}
	sqlite3_busy_timeout(sqlite, 1000);
	sqlite3_stmt *stmt;

	const char *sql = "SELECT 1 FROM tbEmail WHERE Id = ? AND Status = 'Outbox'";
	if (sqlite3_prepare_v2(sqlite, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, "SQLite error: %s at " _LOC_ "\n", sqlite3_errmsg(sqlite));
		goto close;
	}
	if(sqlite3_bind_int64(stmt, 1, j->email_id) != SQLITE_OK) {
		fprintf(stderr, "SQLite bind error: %s at " _LOC_ "\n", sqlite3_errmsg(sqlite));
		goto cleanup;
	}

	if (sqlite3_step(stmt) != SQLITE_ROW) {
		fprintf(stderr, "Email Id %lld does not have status Outbox " _LOC_ "\n", j->email_id);
		goto cleanup;
	}

	sqlite3_finalize(stmt);
	stmt = NULL;

	char *buf, *cur;
	size_t buflen = 50;
	CURL *curl;
	CURLcode res;
	upload_status upload_ctx;
	struct curl_slist *recipients = NULL;

	buflen += 8 + strlen(j->h->from);
	if (j->h->to)
		buflen += 6 + strlen(j->h->to);
	if (j->h->cc)
		buflen += 6 + strlen(j->h->cc);
	if (j->h->bcc)
		buflen += 7 + strlen(j->h->bcc);
	if (j->h->subject)
		buflen += 11 + strlen(j->h->subject);
	if (j->h->user_agent)
		buflen += 14 + strlen(j->h->user_agent);
	buflen += strlen(j->body);
	if (j->xbody)
		buflen += 219 + strlen(j->xbody);

	cur = buf = malloc(buflen);
	if (!buf) {
		urmail_err(sqlite, j, "urmail: Can't allocate buffer for message contents");
		return;
	}

	if (j->h->from) {
		int written = sprintf(cur, "From: %s\r\n", j->h->from);
		if (written < 0) {
			urmail_err(sqlite, j, "urmail: Error writing From address");
			free(buf);
			return;
		} else
			cur += written;
	}

	if (j->h->subject) {
		int written = sprintf(cur, "Subject: %s\r\n", j->h->subject);
		if (written < 0) {
			urmail_err(sqlite, j, "urmail: Error writing Subject");
			free(buf);
			return;
		} else
			cur += written;
	}

	if (j->h->to) {
		int written = sprintf(cur, "To: %s\r\n", j->h->to);
		if (written < 0) {
			urmail_err(sqlite, j, "urmail: Error writing To addresses");
			free(buf);
			return;
		} else
			cur += written;
	}

	if (j->h->cc) {
		int written = sprintf(cur, "Cc: %s\r\n", j->h->cc);
		if (written < 0) {
			urmail_err(sqlite, j, "urmail: Error writing Cc addresses");
			free(buf);
			return;
		} else
			cur += written;
	}

	if (j->h->user_agent) {
		int written = sprintf(cur, "User-Agent: %s\r\n", j->h->user_agent);
		if (written < 0) {
			urmail_err(sqlite, j, "urmail: Error writing User-Agent");
			free(buf);
			return;
		} else
			cur += written;
	}

	if (j->xbody) {
		int written;
		char separator[11];
		separator[sizeof(separator)-1] = 0;

		do {
			int i;

			for (i = 0; i < sizeof(separator)-1; ++i)
				separator[i] = 'A' + (rand() % 26);
		} while (strstr(j->body, separator) || strstr(j->xbody, separator));

		written = sprintf(cur, "MIME-Version: 1.0\r\n"
											"Content-Type: multipart/alternative; boundary=\"%s\"\r\n"
											"\r\n"
											"--%s\r\n"
											"Content-Type: text/plain; charset=utf-8\r\n"
											"\r\n"
											"%s\r\n"
											"--%s\r\n"
											"Content-Type: text/html; charset=utf-8\r\n"
											"\r\n"
											"%s\r\n"
											"--%s--",
											separator, separator, j->body, separator, j->xbody, separator);

		if (written < 0) {
			urmail_err(sqlite, j, "urmail: Error writing bodies, including HTML");
			free(buf);
			return;
		}
	} else {
		int written = sprintf(cur, "Content-Type: text/plain; charset=utf-8\r\n"
													"\r\n"
													"%s",
													j->body);

		if (written < 0) {
			urmail_err(sqlite, j, "urmail: Error writing body");
			free(buf);
			return;
		}
	}

	upload_ctx.content = buf;
	upload_ctx.length = strlen(buf);

	if (j->h->to) {
		char *saveptr, *addr = strtok_r(j->h->to, ",", &saveptr);
		do {
			recipients = curl_slist_append(recipients, addrOf(addr));
		} while ((addr = strtok_r(NULL, ",", &saveptr)));
	}

	if (j->h->cc) {
		char *saveptr, *addr = strtok_r(j->h->cc, ",", &saveptr);
		do {
			recipients = curl_slist_append(recipients, addrOf(addr));
		} while ((addr = strtok_r(NULL, ",", &saveptr)));
	}

	if (j->h->bcc) {
		char *saveptr, *addr = strtok_r(j->h->bcc, ",", &saveptr);
		do {
			recipients = curl_slist_append(recipients, addrOf(addr));
		} while ((addr = strtok_r(NULL, ",", &saveptr)));
	}

	curl = curl_easy_init();
	if (!curl) {
		curl_slist_free_all(recipients);
		free(buf);
		urmail_err(sqlite, j, "urmail: Can't create curl object");
		return;
	}

	curl_easy_setopt(curl, CURLOPT_USERNAME, j->user);
	curl_easy_setopt(curl, CURLOPT_PASSWORD, j->password);
	curl_easy_setopt(curl, CURLOPT_URL, j->server);

	if (j->ssl) {
		curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
		if (j->ca) {
			curl_easy_setopt(curl, CURLOPT_CAINFO, j->ca);
		} else {
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		}
	}

	curl_easy_setopt(curl, CURLOPT_MAIL_FROM, addrOf(j->h->from));
	curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, do_upload);
	curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
	curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
	//curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

	res = curl_easy_perform(curl);

	curl_slist_free_all(recipients);
	curl_easy_cleanup(curl);
	free(buf);

	if (res != CURLE_OK) {
		char msg[256];
		snprintf(msg, sizeof(msg), "urmail: Curl error sending e-mail: %s", curl_easy_strerror(res));
		urmail_err(sqlite, j, msg);
		return;
	}

	const char *update_sql =
		"UPDATE tbEmail "
		" SET"
			" Status = 'Sent',"
			" SentAt = CURRENT_TIMESTAMP"
		" WHERE Id = ?";
	if (sqlite3_prepare_v2(sqlite, update_sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, "SQLite error: %s at " _LOC_ "\n", sqlite3_errmsg(sqlite));
		return;
	}
	if(sqlite3_bind_int64(stmt, 1, j->email_id) != SQLITE_OK) {
		fprintf(stderr, "SQLite bind error: %s at " _LOC_ "\n", sqlite3_errmsg(sqlite));
		goto cleanup;
	}

	if (sqlite3_step(stmt) != SQLITE_DONE) {
		fprintf(stderr, "SQLite error executing UPDATE: %s at " _LOC_ "\n", sqlite3_errmsg(sqlite));
	}
	cleanup:
	sqlite3_finalize(stmt);
	close:
	if (sqlite3_close(sqlite) != SQLITE_OK) {
		fprintf(stderr, "SQLite couldn't close db.");
	}
}

static void free_job(void *p, int will_retry) {
	job *j = p;

	free_headers(j->h);
	free_string(j->server);
	free_string(j->ca);
	free_string(j->user);
	free_string(j->password);
	free_string(j->body);
	free_string(j->xbody);
	free(j);
}

uw_unit uw_Urmail_send(uw_context ctx, uw_Basis_string server,
										 uw_Basis_bool ssl, uw_Basis_string ca,
										 uw_Basis_string user, uw_Basis_string password,
										 uw_Urmail_headers h, uw_Basis_string body,
					 uw_Basis_string xbody, uw_Basis_int email_id) {
	job *j;

	if (!h || !h->from)
		uw_error(ctx, FATAL, "urmail: No From address set for e-mail message");

	if (!h->to && !h->cc && !h->bcc)
		uw_error(ctx, FATAL, "urmail: No recipients specified for e-mail message");

	j = malloc(sizeof(job));

	j->ctx = ctx;
	j->h = copy_headers(h);
	j->server = copy_string(server);
	j->ssl = ssl;
	j->ca = copy_string(ca);
	j->user = copy_string(user);
	j->password = copy_string(password);
	j->body = copy_long_string(ctx, body);
	j->xbody = copy_long_string(ctx, xbody);
	j->email_id = email_id;

	uw_register_transactional(ctx, j, commit, NULL, free_job);

	return uw_unit_v;
}
