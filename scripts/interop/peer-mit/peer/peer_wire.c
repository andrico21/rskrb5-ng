// Frame transport, field parsing and the reply builder of the adapter.
#include "peer.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

uint8_t g_reply[PEER_MAX_FRAME + 4];

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static int read_exact(int fd, uint8_t *buf, size_t n, size_t *got)
{
    *got = 0;
    while (*got < n) {
        ssize_t r = recv(fd, buf + *got, n - *got, 0);
        if (r > 0) {
            *got += (size_t)r;
        } else if (r == 0) {
            return RD_EOF;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return RD_TIMEOUT;
        } else if (errno != EINTR) {
            return RD_ERROR;
        }
    }
    return RD_OK;
}

// Reads one request frame. The length is checked BEFORE any body byte is read.
int wire_read_frame(int fd, uint8_t *buf, uint32_t *len)
{
    uint8_t header[4];
    size_t got;
    int rc = read_exact(fd, header, sizeof(header), &got);

    if (rc == RD_EOF)
        return got == 0 ? RD_EOF : RD_TRUNCATED;
    if (rc != RD_OK)
        return rc;
    *len = be32(header);
    if (*len == 0)
        return RD_EMPTY;
    if (*len > PEER_MAX_FRAME)
        return RD_OVERSIZE;
    rc = read_exact(fd, buf, *len, &got);
    return rc == RD_EOF ? RD_TRUNCATED : rc;
}

int wire_send(int fd, uint8_t status, const struct out *o)
{
    size_t total = 4 + 1 + o->n, sent = 0;

    put_be32(g_reply, (uint32_t)(1 + o->n));
    g_reply[4] = status;
    while (sent < total) {
        ssize_t w = send(fd, g_reply + sent, total - sent, MSG_NOSIGNAL);
        if (w > 0)
            sent += (size_t)w;
        else if (w < 0 && errno != EINTR)
            return -1;
    }
    return 0;
}

// Splits `n` payload bytes after the command byte into length-prefixed fields.
int wire_parse(uint8_t *payload, size_t n, struct field *f, size_t *nf)
{
    size_t off = 0, count = 0;

    while (off < n) {
        uint32_t len;
        if (count == PEER_MAX_FIELDS || n - off < 4)
            return -1;
        len = be32(payload + off);
        off += 4;
        if (len > n - off)
            return -1;
        f[count].p = payload + off;
        f[count].n = len;
        count++;
        off += len;
    }
    *nf = count;
    return 0;
}

void out_init(struct out *o)
{
    o->buf = g_reply + 5;
    o->n = 0;
    o->overflow = 0;
}

void out_bytes(struct out *o, const void *p, size_t n)
{
    if (o->overflow || n > (size_t)PEER_MAX_FRAME - 1 - 4 - o->n) {
        o->overflow = 1;
        return;
    }
    put_be32(o->buf + o->n, (uint32_t)n);
    if (n != 0)
        memcpy(o->buf + o->n + 4, p, n);
    o->n += 4 + n;
}

void out_u32(struct out *o, uint32_t v)
{
    uint8_t b[4];

    put_be32(b, v);
    out_bytes(o, b, sizeof(b));
}

void out_text(struct out *o, const char *s)
{
    out_bytes(o, s, strlen(s));
}

int field_u32(const struct field *f, uint32_t *v)
{
    if (f->n != 4)
        return -1;
    *v = be32(f->p);
    return 0;
}

int field_bool(const struct field *f, int *v)
{
    if (f->n != 1 || f->p[0] > 1)
        return -1;
    *v = f->p[0];
    return 0;
}
