// Error replies, OIDs, names and GSS buffers of the adapter.
#include "peer.h"

#include <stdio.h>
#include <string.h>

#include <gssapi/gssapi_krb5.h>

int proto_fail(struct out *o, const char *text)
{
    out_init(o);
    out_text(o, text);
    return PEER_PROTOCOL;
}

// Appends the GSS status texts of `code` of `type` to `text`, bounded.
static void append_status(char *text, size_t cap, OM_uint32 code, int type)
{
    OM_uint32 minor, context = 0;
    gss_buffer_desc msg;

    do {
        size_t used = strlen(text);
        if (gss_display_status(&minor, code, type, (gss_OID)gss_mech_krb5,
                               &context, &msg) != GSS_S_COMPLETE)
            return;
        if (used + 3 < cap)
            snprintf(text + used, cap - used, "%s%.*s", used ? "; " : "",
                     (int)(msg.length < cap - used - 3 ? msg.length : cap - used - 3),
                     (const char *)msg.value);
        gss_release_buffer(&minor, &msg);
    } while (context != 0);
}

int gss_fail(struct out *o, const char *what, OM_uint32 major, OM_uint32 minor)
{
    char text[PEER_MAX_TEXT];

    snprintf(text, sizeof(text), "%s: ", what);
    append_status(text, sizeof(text), major, GSS_C_GSS_CODE);
    if (minor != 0)
        append_status(text, sizeof(text), minor, GSS_C_MECH_CODE);
    out_init(o);
    out_u32(o, major);
    out_u32(o, minor);
    out_text(o, text);
    return PEER_GSS_ERROR;
}

static size_t put_base128(uint8_t *dst, unsigned long long v)
{
    uint8_t tmp[8];
    size_t n = 0, i;

    do {
        tmp[n++] = (uint8_t)(v & 0x7f);
        v >>= 7;
    } while (v != 0);
    for (i = 0; i < n; i++)
        dst[i] = (uint8_t)(tmp[n - 1 - i] | (i + 1 < n ? 0x80 : 0));
    return n;
}

// Encodes the dotted OID in `s` (`n` bytes, no terminator) as DER content into
// `store` (at least 5 * PEER_MAX_OID_ARCS bytes). Returns 0, or -1 if it is
// malformed, has too many arcs or an arc above 2^32 - 1.
int oid_parse(const uint8_t *s, size_t n, uint8_t *store, gss_OID_desc *oid)
{
    unsigned long long arcs[PEER_MAX_OID_ARCS];
    size_t count = 0, i = 0, len = 0, k;

    while (i < n) {
        unsigned long long v = 0;
        if (count == PEER_MAX_OID_ARCS || s[i] < '0' || s[i] > '9')
            return -1;
        while (i < n && s[i] >= '0' && s[i] <= '9') {
            v = v * 10 + (unsigned long long)(s[i] - '0');
            if (v > 0xffffffffULL)
                return -1;
            i++;
        }
        arcs[count++] = v;
        if (i < n && (s[i] != '.' || ++i == n))
            return -1;
    }
    if (count < 2 || arcs[0] > 2 || (arcs[0] < 2 && arcs[1] > 39))
        return -1;
    len += put_base128(store, arcs[0] * 40 + arcs[1]);
    for (k = 2; k < count; k++)
        len += put_base128(store + len, arcs[k]);
    oid->length = (OM_uint32)len;
    oid->elements = store;
    return 0;
}

void oid_format(const gss_OID_desc *oid, char *buf, size_t cap)
{
    const uint8_t *p = oid->elements;
    size_t i, used = 0;
    unsigned long long v = 0;
    int first = 1;

    buf[0] = '\0';
    for (i = 0; i < oid->length; i++) {
        v = (v << 7) | (p[i] & 0x7f);
        if (p[i] & 0x80)
            continue;
        if (first) {
            unsigned long long a = v < 80 ? v / 40 : 2;
            used += (size_t)snprintf(buf + used, cap - used, "%llu.%llu", a, v - a * 40);
            first = 0;
        } else {
            used += (size_t)snprintf(buf + used, cap - used, ".%llu", v);
        }
        v = 0;
        if (used >= cap)
            return;
    }
}

void out_oid(struct out *o, const gss_OID_desc *oid)
{
    char text[PEER_MAX_OID_ARCS * 11 + 4];

    if (oid == GSS_C_NO_OID) {
        out_text(o, "");
        return;
    }
    oid_format(oid, text, sizeof(text));
    out_text(o, text);
}

// Parses a comma-separated list of dotted OIDs (empty field: empty set).
// `elems` holds PEER_MAX_MECHS entries; `store` 5 * PEER_MAX_OID_ARCS bytes per entry.
int mechset_parse(const struct field *f, gss_OID_set_desc *set,
                  gss_OID_desc *elems, uint8_t *store)
{
    size_t start = 0, i;

    set->count = 0;
    set->elements = elems;
    if (f->n == 0)
        return 0;
    for (i = 0; i <= f->n; i++) {
        if (i != f->n && f->p[i] != ',')
            continue;
        if (set->count == PEER_MAX_MECHS ||
            oid_parse(f->p + start, i - start,
                      store + set->count * 5 * PEER_MAX_OID_ARCS,
                      &elems[set->count]) != 0)
            return -1;
        set->count++;
        start = i + 1;
    }
    return 0;
}

// Imports a name; `type` is one byte: h host-based service, p Kerberos
// principal, e enterprise name, u user name. An empty value is GSS_C_NO_NAME.
int name_import(const struct field *type, const struct field *value,
                gss_name_t *name, struct out *o)
{
    gss_OID nt;
    gss_buffer_desc buf;
    OM_uint32 major, minor;

    *name = GSS_C_NO_NAME;
    if (value->n == 0)
        return PEER_OK;
    if (type->n != 1)
        return proto_fail(o, "a name type is one byte");
    switch (type->p[0]) {
    case 'h': nt = GSS_C_NT_HOSTBASED_SERVICE; break;
    case 'p': nt = GSS_KRB5_NT_PRINCIPAL_NAME; break;
    case 'e': nt = GSS_KRB5_NT_ENTERPRISE_NAME; break;
    case 'u': nt = GSS_C_NT_USER_NAME; break;
    default: return proto_fail(o, "unknown name type");
    }
    buf_of(value, &buf);
    major = gss_import_name(&minor, &buf, nt, name);
    return GSS_ERROR(major) ? gss_fail(o, "gss_import_name", major, minor) : PEER_OK;
}

void out_name(struct out *o, gss_name_t name)
{
    OM_uint32 minor;
    gss_buffer_desc buf = GSS_C_EMPTY_BUFFER;

    if (name != GSS_C_NO_NAME &&
        !GSS_ERROR(gss_display_name(&minor, name, &buf, NULL))) {
        out_bytes(o, buf.value, buf.length);
        gss_release_buffer(&minor, &buf);
    } else {
        out_text(o, "");
    }
}

// Appends a GSS-allocated buffer to the reply and releases it.
void out_release(struct out *o, gss_buffer_t buf)
{
    OM_uint32 minor;

    out_bytes(o, buf->value, buf->length);
    gss_release_buffer(&minor, buf);
}

void buf_of(const struct field *f, gss_buffer_desc *b)
{
    b->length = f->n;
    b->value = f->p;
}
