// KRB-CRED commands of the adapter (plan 2 todo 27, WP-20): MIT's own
// krb5_fwd_tgt_creds / krb5_mk_1cred and krb5_rd_cred, so the Rust
// messages::AuthContext reads a credential MIT forwarded and MIT reads one the
// Rust side made. Both use a key the caller names, never a GSS context.
#include "peer.h"

#include <krb5/krb5.h>
#include <stdio.h>
#include <string.h>

#ifndef PEER_KEYTAB_DIR
#define PEER_KEYTAB_DIR "/run/peer/keytabs"
#endif

static int krb_fail(struct out *o, const char *what, krb5_context ctx, krb5_error_code code)
{
    char text[PEER_MAX_TEXT];
    const char *msg = ctx != NULL ? krb5_get_error_message(ctx, code) : "no context";

    snprintf(text, sizeof(text), "%s: %s", what, msg);
    if (ctx != NULL)
        krb5_free_error_message(ctx, msg);
    out_init(o);
    out_u32(o, (uint32_t)code);
    out_u32(o, 0);
    out_text(o, text);
    return PEER_GSS_ERROR;
}

static int keytab_id_path(const struct field *id, char *path, size_t cap)
{
    size_t i;

    if (id->n == 0 || id->n > 32)
        return -1;
    for (i = 0; i < id->n; i++)
        if (!((id->p[i] >= 'a' && id->p[i] <= 'z') || (id->p[i] >= '0' && id->p[i] <= '9') || id->p[i] == '-'))
            return -1;
    return snprintf(path, cap, "FILE:%s/%.*s.keytab", PEER_KEYTAB_DIR, (int)id->n, (const char *)id->p) < (int)cap ? 0 : -1;
}

// Copies a field into a terminated string; -1 when it does not fit or holds a NUL.
static int field_str(const struct field *f, char *dst, size_t cap)
{
    if (f->n == 0 || f->n >= cap || memchr(f->p, 0, f->n) != NULL)
        return -1;
    memcpy(dst, f->p, f->n);
    dst[f->n] = '\0';
    return 0;
}

static void out_principal(struct out *o, krb5_context ctx, krb5_const_principal p)
{
    char *name = NULL;

    if (krb5_unparse_name(ctx, p, &name) == 0) {
        out_text(o, name);
        krb5_free_unparsed_name(ctx, name);
    } else {
        out_text(o, "");
    }
}

// Fields: user keytab id, user principal, forwarded-to service principal, host name.
// Reply: key etype u32, key bytes, KRB-CRED, the forwarded ticket's server principal.
// The TGT of the user is obtained forwardable from the KDC, then forwarded with
// krb5_fwd_tgt_creds; the KRB-CRED is encrypted under a fresh AES256 key that is
// returned (a throwaway of the test realm).
int cmd_krb_forward(const struct field *f, size_t nf, struct out *o)
{
    krb5_context ctx = NULL;
    krb5_error_code ret;
    krb5_keytab kt = NULL;
    krb5_ccache cc = NULL;
    krb5_principal client = NULL, server = NULL;
    krb5_get_init_creds_opt *opt = NULL;
    krb5_creds creds;
    krb5_auth_context ac = NULL;
    krb5_keyblock key;
    krb5_data cred_msg = {0, 0, NULL};
    char path[128], user[128], service[192], host[128], ccname[64];
    int rc = PEER_OK, have_creds = 0, have_key = 0;

    NEED(4);
    if (keytab_id_path(&f[0], path, sizeof(path)) != 0 || field_str(&f[1], user, sizeof(user)) != 0 ||
        field_str(&f[2], service, sizeof(service)) != 0 || field_str(&f[3], host, sizeof(host)) != 0)
        return proto_fail(o, "a keytab id, a user, a service principal and a host are required");
    memset(&creds, 0, sizeof(creds));
    memset(&key, 0, sizeof(key));
    if ((ret = krb5_init_context(&ctx)) != 0)
        return krb_fail(o, "krb5_init_context", NULL, ret);
    if ((ret = krb5_kt_resolve(ctx, path, &kt)) != 0 || (ret = krb5_parse_name(ctx, user, &client)) != 0 ||
        (ret = krb5_parse_name(ctx, service, &server)) != 0) {
        rc = krb_fail(o, "resolve", ctx, ret);
        goto done;
    }
    if ((ret = krb5_get_init_creds_opt_alloc(ctx, &opt)) != 0) {
        rc = krb_fail(o, "krb5_get_init_creds_opt_alloc", ctx, ret);
        goto done;
    }
    krb5_get_init_creds_opt_set_forwardable(opt, 1);
    if ((ret = krb5_get_init_creds_keytab(ctx, &creds, client, kt, 0, NULL, opt)) != 0) {
        rc = krb_fail(o, "krb5_get_init_creds_keytab", ctx, ret);
        goto done;
    }
    have_creds = 1;
    snprintf(ccname, sizeof(ccname), "MEMORY:peer-fwd-%p", (void *)ctx);
    if ((ret = krb5_cc_resolve(ctx, ccname, &cc)) != 0 || (ret = krb5_cc_initialize(ctx, cc, client)) != 0 ||
        (ret = krb5_cc_store_cred(ctx, cc, &creds)) != 0) {
        rc = krb_fail(o, "credential cache", ctx, ret);
        goto done;
    }
    if ((ret = krb5_c_make_random_key(ctx, ENCTYPE_AES256_CTS_HMAC_SHA1_96, &key)) != 0) {
        rc = krb_fail(o, "krb5_c_make_random_key", ctx, ret);
        goto done;
    }
    have_key = 1;
    if ((ret = krb5_auth_con_init(ctx, &ac)) != 0 || (ret = krb5_auth_con_setuseruserkey(ctx, ac, &key)) != 0) {
        rc = krb_fail(o, "auth context", ctx, ret);
        goto done;
    }
    if ((ret = krb5_fwd_tgt_creds(ctx, ac, host, client, server, cc, 1, &cred_msg)) != 0) {
        rc = krb_fail(o, "krb5_fwd_tgt_creds", ctx, ret);
        goto done;
    }
    out_init(o);
    out_u32(o, (uint32_t)key.enctype);
    out_bytes(o, key.contents, key.length);
    out_bytes(o, cred_msg.data, cred_msg.length);
    out_principal(o, ctx, creds.server);
done:
    if (cred_msg.data != NULL)
        krb5_free_data_contents(ctx, &cred_msg);
    if (have_key)
        krb5_free_keyblock_contents(ctx, &key);
    if (ac != NULL)
        krb5_auth_con_free(ctx, ac);
    if (cc != NULL)
        krb5_cc_destroy(ctx, cc);
    if (have_creds)
        krb5_free_cred_contents(ctx, &creds);
    if (opt != NULL)
        krb5_get_init_creds_opt_free(ctx, opt);
    if (client != NULL)
        krb5_free_principal(ctx, client);
    if (server != NULL)
        krb5_free_principal(ctx, server);
    if (kt != NULL)
        krb5_kt_close(ctx, kt);
    krb5_free_context(ctx);
    return rc;
}

// Fields: key etype u32, key bytes, KRB-CRED. Reply: count u32, then for each
// credential the client principal, the server principal and the ticket flags u32.
int cmd_krb_read_cred(const struct field *f, size_t nf, struct out *o)
{
    krb5_context ctx = NULL;
    krb5_error_code ret;
    krb5_auth_context ac = NULL;
    krb5_keyblock key;
    krb5_creds **list = NULL;
    krb5_data msg;
    uint32_t etype;
    size_t i;
    int rc = PEER_OK;

    NEED(3);
    if (field_u32(&f[0], &etype) != 0 || f[1].n == 0 || f[1].n > 64 || f[2].n == 0)
        return proto_fail(o, "an etype, a key and a KRB-CRED are required");
    if ((ret = krb5_init_context(&ctx)) != 0)
        return krb_fail(o, "krb5_init_context", NULL, ret);
    memset(&key, 0, sizeof(key));
    key.magic = KV5M_KEYBLOCK;
    key.enctype = (krb5_enctype)etype;
    key.length = (unsigned int)f[1].n;
    key.contents = f[1].p;
    if ((ret = krb5_auth_con_init(ctx, &ac)) != 0 || (ret = krb5_auth_con_setuseruserkey(ctx, ac, &key)) != 0) {
        rc = krb_fail(o, "auth context", ctx, ret);
        goto done;
    }
    msg.magic = KV5M_DATA;
    msg.length = (unsigned int)f[2].n;
    msg.data = (char *)f[2].p;
    if ((ret = krb5_rd_cred(ctx, ac, &msg, &list, NULL)) != 0) {
        rc = krb_fail(o, "krb5_rd_cred", ctx, ret);
        goto done;
    }
    out_init(o);
    i = 0;
    while (list != NULL && list[i] != NULL)
        i++;
    out_u32(o, (uint32_t)i);
    for (i = 0; list != NULL && list[i] != NULL; i++) {
        out_principal(o, ctx, list[i]->client);
        out_principal(o, ctx, list[i]->server);
        out_u32(o, (uint32_t)list[i]->ticket_flags);
    }
done:
    if (list != NULL)
        krb5_free_tgt_creds(ctx, list);
    if (ac != NULL)
        krb5_auth_con_free(ctx, ac);
    krb5_free_context(ctx);
    return rc;
}
