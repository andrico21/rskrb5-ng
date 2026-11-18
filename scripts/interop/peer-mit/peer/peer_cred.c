// Handle tables and credential commands of the adapter.
#include "peer.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <gssapi/gssapi_ext.h>

#ifndef PEER_KEYTAB_DIR
#define PEER_KEYTAB_DIR "/run/peer/keytabs"
#endif

gss_ctx_id_t g_ctx[PEER_MAX_SLOTS];
unsigned g_steps[PEER_MAX_SLOTS];
gss_cred_id_t g_cred[PEER_MAX_SLOTS];

// Resolves a u32 handle (1-based) to a slot index.
int slot_of(const struct field *h, uint32_t *index)
{
    if (field_u32(h, index) != 0 || *index == 0 || *index > PEER_MAX_SLOTS)
        return -1;
    *index -= 1;
    return 0;
}

int ctx_lookup(const struct field *h, struct out *o, gss_ctx_id_t *ctx)
{
    uint32_t i;

    if (slot_of(h, &i) != 0 || g_ctx[i] == GSS_C_NO_CONTEXT)
        return proto_fail(o, "unknown context handle");
    *ctx = g_ctx[i];
    return PEER_OK;
}

int free_ctx_slot(void)
{
    int i;

    for (i = 0; i < PEER_MAX_SLOTS; i++)
        if (g_ctx[i] == GSS_C_NO_CONTEXT)
            return i;
    return -1;
}

static int free_cred_slot(void)
{
    int i;

    for (i = 0; i < PEER_MAX_SLOTS; i++)
        if (g_cred[i] == GSS_C_NO_CREDENTIAL)
            return i;
    return -1;
}

int cred_lookup(const struct field *h, struct out *o, gss_cred_id_t *cred)
{
    uint32_t i;

    if (field_u32(h, &i) == 0 && i == 0) {
        *cred = GSS_C_NO_CREDENTIAL;
        return PEER_OK;
    }
    if (slot_of(h, &i) != 0 || g_cred[i] == GSS_C_NO_CREDENTIAL)
        return proto_fail(o, "unknown credential handle");
    *cred = g_cred[i];
    return PEER_OK;
}

int cmd_mechs(const struct field *f, size_t nf, struct out *o)
{
    OM_uint32 major, minor;
    gss_OID_set set;
    size_t i;

    (void)f;
    NEED(0);
    major = gss_indicate_mechs(&minor, &set);
    if (GSS_ERROR(major))
        return gss_fail(o, "gss_indicate_mechs", major, minor);
    out_init(o);
    for (i = 0; i < set->count; i++)
        out_oid(o, &set->elements[i]);
    gss_release_oid_set(&minor, &set);
    return PEER_OK;
}

static int keytab_path(const struct field *id, char *path, size_t cap)
{
    size_t i;

    if (id->n == 0 || id->n > 32)
        return -1;
    for (i = 0; i < id->n; i++)
        if (!((id->p[i] >= 'a' && id->p[i] <= 'z') || (id->p[i] >= '0' && id->p[i] <= '9') || id->p[i] == '-'))
            return -1;
    return snprintf(path, cap, "%s/%.*s.keytab", PEER_KEYTAB_DIR, (int)id->n, (const char *)id->p) < (int)cap ? 0 : -1;
}

// Fields: usage (i|a|b), name type, name, mechs, source (default|keytab|password), argument.
int cmd_acquire(const struct field *f, size_t nf, struct out *o)
{
    OM_uint32 major, minor;
    gss_name_t name, shown = GSS_C_NO_NAME;
    gss_OID_desc elems[PEER_MAX_MECHS];
    uint8_t store[PEER_MAX_MECHS * 5 * PEER_MAX_OID_ARCS];
    gss_OID_set_desc set;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_cred_usage_t usage;
    char path[128], ccache[48];
    int slot, rc;

    NEED(6);
    if (f[0].n != 1 || (f[0].p[0] != 'i' && f[0].p[0] != 'a' && f[0].p[0] != 'b'))
        return proto_fail(o, "usage is i, a or b");
    usage = f[0].p[0] == 'i' ? GSS_C_INITIATE : f[0].p[0] == 'a' ? GSS_C_ACCEPT : GSS_C_BOTH;
    if (mechset_parse(&f[3], &set, elems, store) != 0)
        return proto_fail(o, "malformed mechanism list");
    if ((slot = free_cred_slot()) < 0)
        return proto_fail(o, "no free credential slot");
    if ((rc = name_import(&f[1], &f[2], &name, o)) != PEER_OK)
        return rc;
    if (f[4].n == 7 && memcmp(f[4].p, "default", 7) == 0) {
        major = gss_acquire_cred(&minor, name, GSS_C_INDEFINITE, set.count ? &set : GSS_C_NO_OID_SET,
                                 usage, &cred, NULL, NULL);
    } else if (f[4].n == 8 && memcmp(f[4].p, "password", 8) == 0) {
        gss_buffer_desc pw;
        buf_of(&f[5], &pw);
        major = gss_acquire_cred_with_password(&minor, name, &pw, GSS_C_INDEFINITE,
                                               set.count ? &set : GSS_C_NO_OID_SET, usage, &cred, NULL, NULL);
    } else if (f[4].n == 6 && memcmp(f[4].p, "keytab", 6) == 0 && keytab_path(&f[5], path, sizeof(path)) == 0) {
        gss_key_value_element_desc elem[2];
        gss_key_value_set_desc store_set = {0, elem};
        elem[0].key = usage == GSS_C_ACCEPT ? "keytab" : "client_keytab";
        elem[0].value = path;
        store_set.count = 1;
        if (usage != GSS_C_ACCEPT) {
            snprintf(ccache, sizeof(ccache), "MEMORY:peer-%ld-%d", (long)getpid(), slot);
            elem[1].key = "ccache";
            elem[1].value = ccache;
            store_set.count = 2;
        }
        major = gss_acquire_cred_from(&minor, name, GSS_C_INDEFINITE, set.count ? &set : GSS_C_NO_OID_SET,
                                      usage, &store_set, &cred, NULL, NULL);
    } else {
        if (name != GSS_C_NO_NAME)
            gss_release_name(&minor, &name);
        return proto_fail(o, "source is default, keytab <id> or password <secret>");
    }
    if (name != GSS_C_NO_NAME)
        gss_release_name(&minor, &name);
    if (GSS_ERROR(major))
        return gss_fail(o, "gss_acquire_cred", major, minor);
    g_cred[slot] = cred;
    out_init(o);
    out_u32(o, (uint32_t)slot + 1);
    if (!GSS_ERROR(gss_inquire_cred(&minor, cred, &shown, NULL, NULL, NULL))) {
        out_name(o, shown);
        gss_release_name(&minor, &shown);
    } else {
        out_text(o, "");
    }
    return PEER_OK;
}

// Fields: credential handle, mechanisms. Restricts the SPNEGO mechanisms offered.
int cmd_negmechs(const struct field *f, size_t nf, struct out *o)
{
    OM_uint32 major, minor;
    gss_OID_desc elems[PEER_MAX_MECHS];
    uint8_t store[PEER_MAX_MECHS * 5 * PEER_MAX_OID_ARCS];
    gss_OID_set_desc set;
    gss_cred_id_t cred;
    int rc;

    NEED(2);
    if ((rc = cred_lookup(&f[0], o, &cred)) != PEER_OK)
        return rc;
    if (cred == GSS_C_NO_CREDENTIAL || mechset_parse(&f[1], &set, elems, store) != 0 || set.count == 0)
        return proto_fail(o, "a credential handle and a mechanism list are required");
    major = gss_set_neg_mechs(&minor, cred, &set);
    if (GSS_ERROR(major))
        return gss_fail(o, "gss_set_neg_mechs", major, minor);
    out_init(o);
    return PEER_OK;
}

// Fields: kind (c credential, x context), handle.
int cmd_release(const struct field *f, size_t nf, struct out *o)
{
    OM_uint32 minor;
    uint32_t i;

    NEED(2);
    if (f[0].n != 1 || slot_of(&f[1], &i) != 0)
        return proto_fail(o, "kind c or x and a handle are required");
    if (f[0].p[0] == 'c' && g_cred[i] != GSS_C_NO_CREDENTIAL) {
        gss_release_cred(&minor, &g_cred[i]);
    } else if (f[0].p[0] == 'x' && g_ctx[i] != GSS_C_NO_CONTEXT) {
        gss_delete_sec_context(&minor, &g_ctx[i], GSS_C_NO_BUFFER);
        g_steps[i] = 0;
    } else {
        return proto_fail(o, "unknown handle");
    }
    out_init(o);
    return PEER_OK;
}
