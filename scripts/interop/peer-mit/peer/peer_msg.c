// Per-message commands of the adapter: MIC, wrap, IOV, AEAD, pseudo-random.
#include "peer.h"

#include <gssapi/gssapi_ext.h>

// Fields: context handle, qop u32, message. Reply: token.
int cmd_get_mic(const struct field *f, size_t nf, struct out *o)
{
    OM_uint32 major, minor, qop;
    gss_buffer_desc msg, token = GSS_C_EMPTY_BUFFER;
    gss_ctx_id_t ctx;
    int rc;

    NEED(3);
    if ((rc = ctx_lookup(&f[0], o, &ctx)) != PEER_OK)
        return rc;
    if (field_u32(&f[1], &qop) != 0)
        return proto_fail(o, "qop is four bytes");
    buf_of(&f[2], &msg);
    major = gss_get_mic(&minor, ctx, qop, &msg, &token);
    if (GSS_ERROR(major))
        return gss_fail(o, "gss_get_mic", major, minor);
    out_init(o);
    out_release(o, &token);
    return PEER_OK;
}

// Fields: context handle, message, token. Reply: qop u32. A supplementary status
// (duplicate, old, unsequenced or gap token) is reported as an error: the
// verification functions below treat anything but GSS_S_COMPLETE as a failure.
int cmd_verify_mic(const struct field *f, size_t nf, struct out *o)
{
    OM_uint32 major, minor;
    gss_qop_t qop = 0;
    gss_buffer_desc msg, token;
    gss_ctx_id_t ctx;
    int rc;

    NEED(3);
    if ((rc = ctx_lookup(&f[0], o, &ctx)) != PEER_OK)
        return rc;
    buf_of(&f[1], &msg);
    buf_of(&f[2], &token);
    major = gss_verify_mic(&minor, ctx, &msg, &token, &qop);
    if (major != GSS_S_COMPLETE)
        return gss_fail(o, "gss_verify_mic", major, minor);
    out_init(o);
    out_u32(o, qop);
    return PEER_OK;
}

// Fields: context handle, confidentiality (0|1), qop u32, message.
// Reply: confidentiality state (0|1), token.
int cmd_wrap(const struct field *f, size_t nf, struct out *o)
{
    OM_uint32 major, minor, qop;
    gss_buffer_desc msg, token = GSS_C_EMPTY_BUFFER;
    gss_ctx_id_t ctx;
    int conf_req, conf = 0, rc;

    NEED(4);
    if ((rc = ctx_lookup(&f[0], o, &ctx)) != PEER_OK)
        return rc;
    if (field_bool(&f[1], &conf_req) != 0 || field_u32(&f[2], &qop) != 0)
        return proto_fail(o, "malformed confidentiality or qop");
    buf_of(&f[3], &msg);
    major = gss_wrap(&minor, ctx, conf_req, qop, &msg, &conf, &token);
    if (GSS_ERROR(major))
        return gss_fail(o, "gss_wrap", major, minor);
    out_init(o);
    out_bytes(o, conf ? "\1" : "\0", 1);
    out_release(o, &token);
    return PEER_OK;
}

// Fields: context handle, token. Reply: confidentiality state, qop u32, message.
int cmd_unwrap(const struct field *f, size_t nf, struct out *o)
{
    OM_uint32 major, minor;
    gss_qop_t qop = 0;
    gss_buffer_desc token, msg = GSS_C_EMPTY_BUFFER;
    gss_ctx_id_t ctx;
    int conf = 0, rc;

    NEED(2);
    if ((rc = ctx_lookup(&f[0], o, &ctx)) != PEER_OK)
        return rc;
    buf_of(&f[1], &token);
    major = gss_unwrap(&minor, ctx, &token, &msg, &conf, &qop);
    if (major != GSS_S_COMPLETE)
        return gss_fail(o, "gss_unwrap", major, minor);
    out_init(o);
    out_bytes(o, conf ? "\1" : "\0", 1);
    out_u32(o, qop);
    out_release(o, &msg);
    return PEER_OK;
}

// The IOV layout is HEADER, SIGN_ONLY (only when non-empty), DATA, PADDING, TRAILER.
// Fields: context handle, confidentiality (0|1), qop u32, data, sign-only data.
// Reply: confidentiality state, header, data (encrypted), padding, trailer.
int cmd_wrap_iov(const struct field *f, size_t nf, struct out *o)
{
    OM_uint32 major, minor, qop;
    gss_iov_buffer_desc iov[5];
    gss_ctx_id_t ctx;
    int conf_req, conf = 0, count = 0, header, data, padding, trailer, rc;

    NEED(5);
    if ((rc = ctx_lookup(&f[0], o, &ctx)) != PEER_OK)
        return rc;
    if (field_bool(&f[1], &conf_req) != 0 || field_u32(&f[2], &qop) != 0)
        return proto_fail(o, "malformed confidentiality or qop");
    header = count++;
    iov[header].type = GSS_IOV_BUFFER_TYPE_HEADER | GSS_IOV_BUFFER_FLAG_ALLOCATE;
    iov[header].buffer.length = 0;
    iov[header].buffer.value = NULL;
    if (f[4].n != 0) {
        iov[count].type = GSS_IOV_BUFFER_TYPE_SIGN_ONLY;
        buf_of(&f[4], &iov[count].buffer);
        count++;
    }
    data = count++;
    iov[data].type = GSS_IOV_BUFFER_TYPE_DATA;
    buf_of(&f[3], &iov[data].buffer);
    padding = count++;
    iov[padding].type = GSS_IOV_BUFFER_TYPE_PADDING | GSS_IOV_BUFFER_FLAG_ALLOCATE;
    iov[padding].buffer.length = 0;
    iov[padding].buffer.value = NULL;
    trailer = count++;
    iov[trailer].type = GSS_IOV_BUFFER_TYPE_TRAILER | GSS_IOV_BUFFER_FLAG_ALLOCATE;
    iov[trailer].buffer.length = 0;
    iov[trailer].buffer.value = NULL;
    major = gss_wrap_iov(&minor, ctx, conf_req, qop, &conf, iov, count);
    if (GSS_ERROR(major)) {
        gss_release_iov_buffer(&minor, iov, count);
        return gss_fail(o, "gss_wrap_iov", major, minor);
    }
    out_init(o);
    out_bytes(o, conf ? "\1" : "\0", 1);
    out_bytes(o, iov[header].buffer.value, iov[header].buffer.length);
    out_bytes(o, iov[data].buffer.value, iov[data].buffer.length);
    out_bytes(o, iov[padding].buffer.value, iov[padding].buffer.length);
    out_bytes(o, iov[trailer].buffer.value, iov[trailer].buffer.length);
    gss_release_iov_buffer(&minor, iov, count);
    return PEER_OK;
}

// Fields: context handle, header, sign-only data, data, padding, trailer.
// Reply: confidentiality state, qop u32, data (decrypted).
int cmd_unwrap_iov(const struct field *f, size_t nf, struct out *o)
{
    OM_uint32 major, minor;
    gss_qop_t qop = 0;
    gss_iov_buffer_desc iov[5];
    gss_ctx_id_t ctx;
    int conf = 0, count = 0, data, rc;

    NEED(6);
    if ((rc = ctx_lookup(&f[0], o, &ctx)) != PEER_OK)
        return rc;
    iov[count].type = GSS_IOV_BUFFER_TYPE_HEADER;
    buf_of(&f[1], &iov[count++].buffer);
    if (f[2].n != 0) {
        iov[count].type = GSS_IOV_BUFFER_TYPE_SIGN_ONLY;
        buf_of(&f[2], &iov[count++].buffer);
    }
    data = count++;
    iov[data].type = GSS_IOV_BUFFER_TYPE_DATA;
    buf_of(&f[3], &iov[data].buffer);
    iov[count].type = GSS_IOV_BUFFER_TYPE_PADDING;
    buf_of(&f[4], &iov[count++].buffer);
    iov[count].type = GSS_IOV_BUFFER_TYPE_TRAILER;
    buf_of(&f[5], &iov[count++].buffer);
    major = gss_unwrap_iov(&minor, ctx, &conf, &qop, iov, count);
    if (major != GSS_S_COMPLETE)
        return gss_fail(o, "gss_unwrap_iov", major, minor);
    out_init(o);
    out_bytes(o, conf ? "\1" : "\0", 1);
    out_u32(o, qop);
    out_bytes(o, iov[data].buffer.value, iov[data].buffer.length);
    return PEER_OK;
}

// Fields: context handle, confidentiality (0|1), qop u32, associated data, message.
// Reply: confidentiality state, token.
int cmd_wrap_aead(const struct field *f, size_t nf, struct out *o)
{
    OM_uint32 major, minor, qop;
    gss_buffer_desc assoc, msg, token = GSS_C_EMPTY_BUFFER;
    gss_ctx_id_t ctx;
    int conf_req, conf = 0, rc;

    NEED(5);
    if ((rc = ctx_lookup(&f[0], o, &ctx)) != PEER_OK)
        return rc;
    if (field_bool(&f[1], &conf_req) != 0 || field_u32(&f[2], &qop) != 0)
        return proto_fail(o, "malformed confidentiality or qop");
    buf_of(&f[3], &assoc);
    buf_of(&f[4], &msg);
    major = gss_wrap_aead(&minor, ctx, conf_req, qop, &assoc, &msg, &conf, &token);
    if (GSS_ERROR(major))
        return gss_fail(o, "gss_wrap_aead", major, minor);
    out_init(o);
    out_bytes(o, conf ? "\1" : "\0", 1);
    out_release(o, &token);
    return PEER_OK;
}

// Fields: context handle, associated data, token.
// Reply: confidentiality state, qop u32, message.
int cmd_unwrap_aead(const struct field *f, size_t nf, struct out *o)
{
    OM_uint32 major, minor;
    gss_qop_t qop = 0;
    gss_buffer_desc assoc, token, msg = GSS_C_EMPTY_BUFFER;
    gss_ctx_id_t ctx;
    int conf = 0, rc;

    NEED(3);
    if ((rc = ctx_lookup(&f[0], o, &ctx)) != PEER_OK)
        return rc;
    buf_of(&f[1], &assoc);
    buf_of(&f[2], &token);
    major = gss_unwrap_aead(&minor, ctx, &token, &assoc, &msg, &conf, &qop);
    if (major != GSS_S_COMPLETE)
        return gss_fail(o, "gss_unwrap_aead", major, minor);
    out_init(o);
    out_bytes(o, conf ? "\1" : "\0", 1);
    out_u32(o, qop);
    out_release(o, &msg);
    return PEER_OK;
}

// Fields: context handle, key kind u32 (0 full, 1 partial), input, output length u32.
// Reply: the pseudo-random output.
int cmd_prf(const struct field *f, size_t nf, struct out *o)
{
    OM_uint32 major, minor, kind, length;
    gss_buffer_desc in, result = GSS_C_EMPTY_BUFFER;
    gss_ctx_id_t ctx;
    int rc;

    NEED(4);
    if ((rc = ctx_lookup(&f[0], o, &ctx)) != PEER_OK)
        return rc;
    if (field_u32(&f[1], &kind) != 0 || kind > 1 || field_u32(&f[3], &length) != 0 ||
        length == 0 || length > PEER_MAX_PRF)
        return proto_fail(o, "malformed key kind or output length");
    buf_of(&f[2], &in);
    major = gss_pseudo_random(&minor, ctx, (int)kind, &in, (ssize_t)length, &result);
    if (GSS_ERROR(major))
        return gss_fail(o, "gss_pseudo_random", major, minor);
    out_init(o);
    out_release(o, &result);
    return PEER_OK;
}
