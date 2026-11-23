// Shared declarations of the rskrb5-ng external-peer adapter. The frame
// protocol is documented at the top of peer.c.
#ifndef PEER_H
#define PEER_H

#include <stddef.h>
#include <stdint.h>

#include <gssapi/gssapi.h>

enum {
    PEER_MAX_FRAME = 1048576,  // payload bytes of one frame, either direction
    PEER_MAX_FIELDS = 16,      // fields in one request
    PEER_MAX_SLOTS = 16,       // credential and context handles per connection
    PEER_MAX_STEPS = 64,       // init/accept steps per context
    PEER_MAX_COMMANDS = 4096,  // requests per connection
    PEER_MAX_CHILDREN = 8,     // concurrent connections
    PEER_MAX_MECHS = 8,        // mechanisms in one list
    PEER_MAX_OID_ARCS = 32,
    PEER_MAX_PRF = 65536,      // pseudo_random output bytes
    PEER_MAX_TEXT = 1024       // error text bytes
};

enum peer_status {
    PEER_OK = 0,
    PEER_CONTINUE = 1,   // GSS_S_CONTINUE_NEEDED
    PEER_GSS_ERROR = 2,  // major u32, minor u32, text
    PEER_PROTOCOL = 3    // text
};

enum peer_read {
    RD_OK = 0, RD_EOF, RD_TIMEOUT, RD_ERROR, RD_OVERSIZE, RD_EMPTY, RD_TRUNCATED
};

struct field {
    uint8_t *p;
    size_t n;
};

// The reply under construction; `buf` is the payload after the status byte.
struct out {
    uint8_t *buf;
    size_t n;
    int overflow;
};

extern uint8_t g_reply[PEER_MAX_FRAME + 4];

// peer_wire.c: frames, fields and the reply builder.
int wire_read_frame(int fd, uint8_t *buf, uint32_t *len);
int wire_send(int fd, uint8_t status, const struct out *o);
int wire_parse(uint8_t *payload, size_t n, struct field *f, size_t *nf);
void out_init(struct out *o);
void out_bytes(struct out *o, const void *p, size_t n);
void out_u32(struct out *o, uint32_t v);
void out_text(struct out *o, const char *s);
int field_u32(const struct field *f, uint32_t *v);
int field_bool(const struct field *f, int *v);

// peer_util.c: errors, OIDs, names, buffers.
int proto_fail(struct out *o, const char *text);
int gss_fail(struct out *o, const char *what, OM_uint32 major, OM_uint32 minor);
int oid_parse(const uint8_t *s, size_t n, uint8_t *store, gss_OID_desc *oid);
void oid_format(const gss_OID_desc *oid, char *buf, size_t cap);
void out_oid(struct out *o, const gss_OID_desc *oid);
int mechset_parse(const struct field *f, gss_OID_set_desc *set,
                  gss_OID_desc *elems, uint8_t *store);
int name_import(const struct field *type, const struct field *value,
                gss_name_t *name, struct out *o);
void out_name(struct out *o, gss_name_t name);
void out_release(struct out *o, gss_buffer_t buf);
void buf_of(const struct field *f, gss_buffer_desc *b);

// peer_cred.c: handle tables and credentials.
extern gss_ctx_id_t g_ctx[PEER_MAX_SLOTS];
extern unsigned g_steps[PEER_MAX_SLOTS];
extern gss_cred_id_t g_cred[PEER_MAX_SLOTS];
int slot_of(const struct field *h, uint32_t *index);
int free_ctx_slot(void);
int cred_lookup(const struct field *h, struct out *o, gss_cred_id_t *cred);
int ctx_lookup(const struct field *h, struct out *o, gss_ctx_id_t *ctx);
int cmd_mechs(const struct field *f, size_t nf, struct out *o);
int cmd_acquire(const struct field *f, size_t nf, struct out *o);
int cmd_negmechs(const struct field *f, size_t nf, struct out *o);
int cmd_release(const struct field *f, size_t nf, struct out *o);

// peer_ctx.c: security contexts.
int cmd_init(const struct field *f, size_t nf, struct out *o);
int cmd_accept(const struct field *f, size_t nf, struct out *o);
int cmd_inquire(const struct field *f, size_t nf, struct out *o);
int cmd_export(const struct field *f, size_t nf, struct out *o);
int cmd_import(const struct field *f, size_t nf, struct out *o);

// peer_msg.c: per-message operations.
int cmd_get_mic(const struct field *f, size_t nf, struct out *o);
int cmd_verify_mic(const struct field *f, size_t nf, struct out *o);
int cmd_wrap(const struct field *f, size_t nf, struct out *o);
int cmd_unwrap(const struct field *f, size_t nf, struct out *o);
int cmd_wrap_iov(const struct field *f, size_t nf, struct out *o);
int cmd_unwrap_iov(const struct field *f, size_t nf, struct out *o);
int cmd_wrap_aead(const struct field *f, size_t nf, struct out *o);
int cmd_unwrap_aead(const struct field *f, size_t nf, struct out *o);
int cmd_prf(const struct field *f, size_t nf, struct out *o);

// peer_krb.c: MIT KRB-CRED forwarding and reading (todo 27).
int cmd_krb_forward(const struct field *f, size_t nf, struct out *o);
int cmd_krb_read_cred(const struct field *f, size_t nf, struct out *o);

#define NEED(count) \
    do { if (nf != (count)) return proto_fail(o, "wrong number of fields"); } while (0)

#endif
