// Security-context commands of the adapter: steps, inquiry, export and import.
#include "peer.h"

#include <string.h>

// Stores `ctx` in a fresh slot or in the slot of an existing handle `h`.
static int step_slot(const struct field *h, struct out *o, uint32_t *index)
{
    uint32_t value;
    int slot;

    if (field_u32(h, &value) != 0)
        return proto_fail(o, "a handle is four bytes");
    if (value == 0) {
        if ((slot = free_ctx_slot()) < 0)
            return proto_fail(o, "no free context slot");
        g_steps[slot] = 0;
        *index = (uint32_t)slot;
        return PEER_OK;
    }
    if (slot_of(h, index) != 0 || g_ctx[*index] == GSS_C_NO_CONTEXT)
        return proto_fail(o, "unknown context handle");
    return PEER_OK;
}

static int finish_step(struct out *o, OM_uint32 major, OM_uint32 minor, const char *what,
                       uint32_t i, gss_ctx_id_t ctx, gss_buffer_t token)
{
    OM_uint32 ignored;

    if (GSS_ERROR(major)) {
        if (ctx != GSS_C_NO_CONTEXT)
            gss_delete_sec_context(&ignored, &ctx, GSS_C_NO_BUFFER);
        g_ctx[i] = GSS_C_NO_CONTEXT;
        gss_release_buffer(&ignored, token);
        return gss_fail(o, what, major, minor);
    }
    g_ctx[i] = ctx;
    out_init(o);
    out_u32(o, i + 1);
    out_release(o, token);
    return (major & GSS_S_CONTINUE_NEEDED) ? PEER_CONTINUE : PEER_OK;
}

static int channel_bindings(const struct field *flag, const struct field *data,
                            gss_channel_bindings_t *cb, struct gss_channel_bindings_struct *store)
{
    int present;

    if (field_bool(flag, &present) != 0)
        return -1;
    memset(store, 0, sizeof(*store));
    store->initiator_addrtype = GSS_C_AF_NULLADDR;
    store->acceptor_addrtype = GSS_C_AF_NULLADDR;
    store->application_data.length = data->n;
    store->application_data.value = data->p;
    *cb = present ? store : GSS_C_NO_CHANNEL_BINDINGS;
    return 0;
}

// Fields: context handle (0 starts one), credential handle (0 default), target
// name type, target name, mechanism (empty: default), request flags u32,
// channel bindings present (0|1), channel bindings application data, input token.
int cmd_init(const struct field *f, size_t nf, struct out *o)
{
    OM_uint32 major, minor, flags, ret_flags = 0;
    gss_cred_id_t cred;
    gss_name_t target;
    gss_OID_desc elems[1];
    uint8_t store[5 * PEER_MAX_OID_ARCS];
    gss_OID_set_desc set;
    gss_OID mech = GSS_C_NO_OID, actual = GSS_C_NO_OID;
    gss_channel_bindings_t cb;
    struct gss_channel_bindings_struct cbs;
    gss_buffer_desc in, out = GSS_C_EMPTY_BUFFER;
    gss_ctx_id_t ctx;
    uint32_t i;
    int rc;

    NEED(9);
    if ((rc = step_slot(&f[0], o, &i)) != PEER_OK || (rc = cred_lookup(&f[1], o, &cred)) != PEER_OK)
        return rc;
    if (field_u32(&f[5], &flags) != 0 || channel_bindings(&f[6], &f[7], &cb, &cbs) != 0 ||
        mechset_parse(&f[4], &set, elems, store) != 0 || set.count > 1)
        return proto_fail(o, "malformed flags, channel bindings or mechanism");
    if (f[3].n == 0)
        return proto_fail(o, "a target name is required");
    if (++g_steps[i] > PEER_MAX_STEPS)
        return proto_fail(o, "step limit reached");
    if ((rc = name_import(&f[2], &f[3], &target, o)) != PEER_OK)
        return rc;
    mech = set.count ? &elems[0] : GSS_C_NO_OID;
    ctx = g_ctx[i];
    buf_of(&f[8], &in);
    major = gss_init_sec_context(&minor, cred, &ctx, target, mech, flags, GSS_C_INDEFINITE, cb,
                                 in.length ? &in : GSS_C_NO_BUFFER, &actual, &out, &ret_flags, NULL);
    gss_release_name(&minor, &target);
    rc = finish_step(o, major, minor, "gss_init_sec_context", i, ctx, &out);
    if (rc == PEER_OK || rc == PEER_CONTINUE) {
        out_u32(o, ret_flags);
        out_oid(o, actual);
    }
    return rc;
}

// Fields: context handle (0 starts one), credential handle (0 default),
// channel bindings present, channel bindings application data, input token.
int cmd_accept(const struct field *f, size_t nf, struct out *o)
{
    OM_uint32 major, minor, ret_flags = 0;
    gss_cred_id_t cred, delegated = GSS_C_NO_CREDENTIAL;
    gss_name_t source = GSS_C_NO_NAME;
    gss_OID mech = GSS_C_NO_OID;
    gss_channel_bindings_t cb;
    struct gss_channel_bindings_struct cbs;
    gss_buffer_desc in, out = GSS_C_EMPTY_BUFFER;
    gss_ctx_id_t ctx;
    uint32_t i;
    int rc;

    NEED(5);
    if ((rc = step_slot(&f[0], o, &i)) != PEER_OK || (rc = cred_lookup(&f[1], o, &cred)) != PEER_OK)
        return rc;
    if (channel_bindings(&f[2], &f[3], &cb, &cbs) != 0)
        return proto_fail(o, "malformed channel bindings");
    if (++g_steps[i] > PEER_MAX_STEPS)
        return proto_fail(o, "step limit reached");
    ctx = g_ctx[i];
    buf_of(&f[4], &in);
    major = gss_accept_sec_context(&minor, &ctx, cred, &in, cb, &source, &mech, &out, &ret_flags,
                                   NULL, &delegated);
    rc = finish_step(o, major, minor, "gss_accept_sec_context", i, ctx, &out);
    if (rc == PEER_OK || rc == PEER_CONTINUE) {
        out_u32(o, ret_flags);
        out_oid(o, mech);
        out_name(o, source);
        out_u32(o, 0);
    }
    if (source != GSS_C_NO_NAME)
        gss_release_name(&minor, &source);
    if (delegated != GSS_C_NO_CREDENTIAL)
        gss_release_cred(&minor, &delegated);
    return rc;
}

// Fields: context handle. Reply: source name, target name, lifetime u32,
// mechanism, flags u32, locally initiated (0|1), open (0|1).
int cmd_inquire(const struct field *f, size_t nf, struct out *o)
{
    OM_uint32 major, minor, lifetime, flags;
    gss_name_t src = GSS_C_NO_NAME, tgt = GSS_C_NO_NAME;
    gss_OID mech;
    gss_ctx_id_t ctx;
    int local, open, rc;

    NEED(1);
    if ((rc = ctx_lookup(&f[0], o, &ctx)) != PEER_OK)
        return rc;
    major = gss_inquire_context(&minor, ctx, &src, &tgt, &lifetime, &mech, &flags, &local, &open);
    if (GSS_ERROR(major))
        return gss_fail(o, "gss_inquire_context", major, minor);
    out_init(o);
    out_name(o, src);
    out_name(o, tgt);
    out_u32(o, lifetime);
    out_oid(o, mech);
    out_u32(o, flags);
    out_bytes(o, local ? "\1" : "\0", 1);
    out_bytes(o, open ? "\1" : "\0", 1);
    if (src != GSS_C_NO_NAME)
        gss_release_name(&minor, &src);
    if (tgt != GSS_C_NO_NAME)
        gss_release_name(&minor, &tgt);
    return PEER_OK;
}

// Fields: context handle. The context is consumed; the reply is the token.
int cmd_export(const struct field *f, size_t nf, struct out *o)
{
    OM_uint32 major, minor;
    gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
    uint32_t i;

    NEED(1);
    if (slot_of(&f[0], &i) != 0 || g_ctx[i] == GSS_C_NO_CONTEXT)
        return proto_fail(o, "unknown context handle");
    major = gss_export_sec_context(&minor, &g_ctx[i], &token);
    if (GSS_ERROR(major))
        return gss_fail(o, "gss_export_sec_context", major, minor);
    g_ctx[i] = GSS_C_NO_CONTEXT;
    out_init(o);
    out_release(o, &token);
    return PEER_OK;
}

// Fields: exported token. Reply: the new context handle.
int cmd_import(const struct field *f, size_t nf, struct out *o)
{
    OM_uint32 major, minor;
    gss_buffer_desc token;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    int slot;

    NEED(1);
    if ((slot = free_ctx_slot()) < 0)
        return proto_fail(o, "no free context slot");
    buf_of(&f[0], &token);
    major = gss_import_sec_context(&minor, &token, &ctx);
    if (GSS_ERROR(major))
        return gss_fail(o, "gss_import_sec_context", major, minor);
    g_ctx[slot] = ctx;
    g_steps[slot] = 0;
    out_init(o);
    out_u32(o, (uint32_t)slot + 1);
    return PEER_OK;
}
