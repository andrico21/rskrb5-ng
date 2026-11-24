// Delegation command of the adapter (plan 2 todo 19, register row FU-GSS-P04):
// an accept step that keeps the credential the initiator delegated, so a test
// can initiate with it (cmd_accept releases it and reports 0).
#include "peer.h"

// The first free credential slot, or -1.
static int deleg_cred_slot(void)
{
    int i;

    for (i = 0; i < PEER_MAX_SLOTS; i++)
        if (g_cred[i] == GSS_C_NO_CREDENTIAL)
            return i;
    return -1;
}

// Fields: credential handle (0 default), input token (a one-leg krb5 AP-REQ,
// no channel bindings). Reply: context handle, output token, ret flags u32,
// mech, source name, delegated credential handle u32 (0: none delegated).
int cmd_accept_deleg(const struct field *f, size_t nf, struct out *o)
{
    OM_uint32 major, minor, ignored, ret_flags = 0;
    gss_cred_id_t cred, delegated = GSS_C_NO_CREDENTIAL;
    gss_name_t source = GSS_C_NO_NAME;
    gss_OID mech = GSS_C_NO_OID;
    gss_buffer_desc in, out = GSS_C_EMPTY_BUFFER;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    int slot, cred_slot = -1, rc;

    NEED(2);
    if ((rc = cred_lookup(&f[0], o, &cred)) != PEER_OK)
        return rc;
    if ((slot = free_ctx_slot()) < 0)
        return proto_fail(o, "no free context slot");
    buf_of(&f[1], &in);
    major = gss_accept_sec_context(&minor, &ctx, cred, &in, GSS_C_NO_CHANNEL_BINDINGS, &source,
                                   &mech, &out, &ret_flags, NULL, &delegated);
    if (major == GSS_S_COMPLETE && delegated != GSS_C_NO_CREDENTIAL &&
        (cred_slot = deleg_cred_slot()) < 0)
        rc = proto_fail(o, "no free credential slot");
    else if (GSS_ERROR(major))
        rc = gss_fail(o, "gss_accept_sec_context", major, minor);
    else if (major != GSS_S_COMPLETE)
        rc = proto_fail(o, "the delegation accept takes one step");
    if (rc != PEER_OK || major != GSS_S_COMPLETE) {
        if (ctx != GSS_C_NO_CONTEXT)
            gss_delete_sec_context(&ignored, &ctx, GSS_C_NO_BUFFER);
        if (delegated != GSS_C_NO_CREDENTIAL)
            gss_release_cred(&ignored, &delegated);
        if (source != GSS_C_NO_NAME)
            gss_release_name(&ignored, &source);
        gss_release_buffer(&ignored, &out);
        return rc;
    }
    if (cred_slot >= 0)
        g_cred[cred_slot] = delegated;
    g_ctx[slot] = ctx;
    g_steps[slot] = 1;
    out_init(o);
    out_u32(o, (uint32_t)slot + 1);
    out_release(o, &out);
    out_u32(o, ret_flags);
    out_oid(o, mech);
    out_name(o, source);
    out_u32(o, cred_slot < 0 ? 0 : (uint32_t)cred_slot + 1);
    if (source != GSS_C_NO_NAME)
        gss_release_name(&ignored, &source);
    return PEER_OK;
}
