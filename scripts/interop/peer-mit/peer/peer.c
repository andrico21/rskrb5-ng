// peer-adapter: the external-peer adapter of the rskrb5-ng interop fixture
// `mit-peer` (plan 2 todo 1, lane 1F). A small test program linked against the
// pinned MIT krb5 1.22.2 build INSIDE the fixture image only. The Rust test
// client tests/interop/peer.rs mirrors this protocol; there is no other
// document. Usage: peer-adapter <IPv4 address> <port>.
//
// FRAMES. Every request and every reply is one frame on a TCP stream:
//     length  u32, big endian, 1 ..= 1048576 (1 MiB), the payload size
//     payload `length` bytes
// A length of 0 or above 1 MiB is a protocol error: the adapter answers with
// status 3 and closes; it never reads or allocates the announced body. A
// stream that ends inside a frame ("truncated frame") gets status 3 and a
// close; one that sends nothing for PEER_IDLE_SECONDS (default 60) gets status
// 3 "idle timeout" and a close. Each connection runs in its own forked
// process (at most 8 at once) with its own handles, environment and trace.
//
// REQUEST payload: one command byte, then fields. A field is a u32 big-endian
// length and that many bytes; at most 16 fields; no trailing bytes. A u32 field
// is four bytes big endian, a flag field is one byte 0 or 1, a handle is a u32
// (1..=16; 0 means "none/new" where stated).
// REPLY payload: one status byte, then fields.
//     0 OK            fields as listed per command
//     1 CONTINUE      GSS_S_CONTINUE_NEEDED; the fields of a step reply
//     2 GSS ERROR     major u32, minor u32, text (MIT status text); verify_mic,
//                     unwrap, unwrap_iov and unwrap_aead report ANY status but
//                     GSS_S_COMPLETE (a gap, duplicate, old or unsequenced token
//                     included) as an error
//     3 PROTOCOL      text (bad frame, unknown command, bad field, limit)
//
// COMMANDS (byte: fields -> reply fields):
//   P ping                  -> "rskrb5-peer/1", max frame u32, max fields u32, max handles u32
//   M mechs                 -> one dotted OID per mechanism of gss_indicate_mechs
//   E setenv: name, value   -> (none). Only HOPS KEY NEGOEX_NO_OPTIMISTIC_TOKEN
//        INIT_QUERY_FAIL ACCEPT_QUERY_FAIL ACCEPT_EXCHANGE_FAIL INIT_EXCHANGE_FAIL
//        INIT_FAIL ACCEPT_FAIL GSS_INIT_BINDING GSS_ACCEPT_BINDING (the
//        negoextest knobs) and GSS_MECH_CONFIG=negoextest (loads the mechanisms
//        of /etc/gss/mech.negoextest); refused once any GSS command ran.
//   T trace                 -> the last 64 KiB of this connection's KRB5_TRACE file
//   A acquire cred: usage (i|a|b), name type, name, mechs (comma list of dotted
//        OIDs, empty: default), source (default|keytab|password), argument
//        (keytab id [a-z0-9-]{1,32} under /run/peer/keytabs, or the password)
//                           -> cred handle u32, display name
//   S set_neg_mechs: cred handle, mechs   -> (none); restricts what SPNEGO offers
//   R release: kind (c cred|x context), handle -> (none)
//   I init_sec_context: context handle (0 new), cred handle (0 default), target
//        name type, target name, mech (one dotted OID or empty), request flags
//        u32, channel bindings present flag, channel bindings application data,
//        input token (empty on the first step)
//                           -> status 0|1, context handle, output token, ret flags u32, mech
//   C accept_sec_context: context handle (0 new), cred handle (0 default),
//        channel bindings present flag, application data, input token
//                           -> status 0|1, context handle, output token, ret flags u32,
//                              mech, source name, delegated cred (always 0)
//   D accept keeping the delegated credential: cred handle (0 default), input
//        token (one-leg krb5, no channel bindings)
//                           -> context handle, output token, ret flags u32, mech,
//                              source name, delegated cred handle u32 (0: none)
//   Q inquire_context: context handle
//                           -> source, target, lifetime u32, mech, flags u32,
//                              locally initiated flag, open flag
//   m get_mic: context, qop u32, message              -> token
//   v verify_mic: context, message, token             -> qop u32
//   w wrap: context, conf flag, qop u32, message      -> conf flag, token
//   u unwrap: context, token                          -> conf flag, qop u32, message
//   W wrap_iov: context, conf flag, qop u32, data, sign-only data
//                           -> conf flag, header, data, padding, trailer
//        (layout HEADER, SIGN_ONLY when non-empty, DATA, PADDING, TRAILER)
//   U unwrap_iov: context, header, sign-only data, data, padding, trailer
//                           -> conf flag, qop u32, data
//   a wrap_aead: context, conf flag, qop u32, associated data, message -> conf flag, token
//   b unwrap_aead: context, associated data, token    -> conf flag, qop u32, message
//   p pseudo_random: context, key kind u32 (0 full|1 partial), input, length u32
//        (1..=65536)        -> output bytes
//   x export_sec_context: context  -> token (the context is consumed)
//   y import_sec_context: token    -> context handle
//   F krb_forward (todo 27): keytab id, user principal, service principal, host
//        -> key etype u32, key bytes, KRB-CRED, forwarded server principal
//        (MIT krb5_fwd_tgt_creds of a forwardable TGT, encrypted under a fresh AES256 key)
//   G krb_read_cred (todo 27): key etype u32, key bytes, KRB-CRED
//        -> count u32, then per credential client, server, ticket flags u32 (MIT krb5_rd_cred)
// Limits: 16 context and 16 credential handles, 64 init/accept steps per
// context, 4096 requests per connection. No secret is logged: the log line of a
// request holds its command byte and the reply status only.
#define _GNU_SOURCE
#include "peer.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PEER_RUN_DIR
#define PEER_RUN_DIR "/run/peer"
#endif
#define PEER_MECH_CONFIG "/etc/gss/mech.negoextest"

static uint8_t g_request[PEER_MAX_FRAME];
static char g_trace_path[96];
static int g_gss_used;
static volatile sig_atomic_t g_children;

static const char *const g_env_names[] = {
    "HOPS", "KEY", "NEGOEX_NO_OPTIMISTIC_TOKEN", "INIT_QUERY_FAIL", "ACCEPT_QUERY_FAIL",
    "ACCEPT_EXCHANGE_FAIL", "INIT_EXCHANGE_FAIL", "INIT_FAIL", "ACCEPT_FAIL",
    "GSS_INIT_BINDING", "GSS_ACCEPT_BINDING", "GSS_MECH_CONFIG"};

static int cmd_ping(const struct field *f, size_t nf, struct out *o)
{
    (void)f;
    NEED(0);
    out_init(o);
    out_text(o, "rskrb5-peer/1");
    out_u32(o, PEER_MAX_FRAME);
    out_u32(o, PEER_MAX_FIELDS);
    out_u32(o, PEER_MAX_SLOTS);
    return PEER_OK;
}

static int cmd_setenv(const struct field *f, size_t nf, struct out *o)
{
    char name[40], value[72];
    size_t i;

    NEED(2);
    if (g_gss_used)
        return proto_fail(o, "the environment is frozen once a GSS command ran");
    if (f[0].n >= sizeof(name) || f[1].n >= sizeof(value))
        return proto_fail(o, "environment name or value too long");
    memcpy(name, f[0].p, f[0].n);
    name[f[0].n] = '\0';
    memcpy(value, f[1].p, f[1].n);
    value[f[1].n] = '\0';
    for (i = 0; i < f[1].n; i++)
        if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'z') ||
              (value[i] >= 'A' && value[i] <= 'Z') || value[i] == '-' || value[i] == '_'))
            return proto_fail(o, "environment value outside [A-Za-z0-9_-]");
    for (i = 0; i < sizeof(g_env_names) / sizeof(g_env_names[0]); i++) {
        if (strcmp(name, g_env_names[i]) != 0)
            continue;
        if (strcmp(name, "GSS_MECH_CONFIG") == 0) {
            if (strcmp(value, "negoextest") != 0)
                return proto_fail(o, "GSS_MECH_CONFIG accepts only the value negoextest");
            snprintf(value, sizeof(value), "%s", PEER_MECH_CONFIG);
        }
        setenv(name, value, 1);
        out_init(o);
        return PEER_OK;
    }
    return proto_fail(o, "environment name not allowed");
}

static int cmd_trace(const struct field *f, size_t nf, struct out *o)
{
    FILE *fp;
    long size;
    size_t got;
    uint8_t tail[65536];

    (void)f;
    NEED(0);
    out_init(o);
    fp = fopen(g_trace_path, "rb");
    if (fp == NULL || fseek(fp, 0, SEEK_END) != 0 || (size = ftell(fp)) < 0) {
        if (fp != NULL)
            fclose(fp);
        out_text(o, "");
        return PEER_OK;
    }
    if ((size_t)size > sizeof(tail))
        fseek(fp, size - (long)sizeof(tail), SEEK_SET);
    else
        rewind(fp);
    got = fread(tail, 1, sizeof(tail), fp);
    fclose(fp);
    out_bytes(o, tail, got);
    return PEER_OK;
}

static int dispatch(uint8_t command, struct field *f, size_t nf, struct out *o)
{
    out_init(o);
    switch (command) {
    case 'P': return cmd_ping(f, nf, o);
    case 'E': return cmd_setenv(f, nf, o);
    case 'T': return cmd_trace(f, nf, o);
    default: break;
    }
    g_gss_used = 1;
    switch (command) {
    case 'M': return cmd_mechs(f, nf, o);
    case 'A': return cmd_acquire(f, nf, o);
    case 'S': return cmd_negmechs(f, nf, o);
    case 'R': return cmd_release(f, nf, o);
    case 'I': return cmd_init(f, nf, o);
    case 'C': return cmd_accept(f, nf, o);
    case 'D': return cmd_accept_deleg(f, nf, o);
    case 'Q': return cmd_inquire(f, nf, o);
    case 'm': return cmd_get_mic(f, nf, o);
    case 'v': return cmd_verify_mic(f, nf, o);
    case 'w': return cmd_wrap(f, nf, o);
    case 'u': return cmd_unwrap(f, nf, o);
    case 'W': return cmd_wrap_iov(f, nf, o);
    case 'U': return cmd_unwrap_iov(f, nf, o);
    case 'a': return cmd_wrap_aead(f, nf, o);
    case 'b': return cmd_unwrap_aead(f, nf, o);
    case 'p': return cmd_prf(f, nf, o);
    case 'x': return cmd_export(f, nf, o);
    case 'y': return cmd_import(f, nf, o);
    case 'F': return cmd_krb_forward(f, nf, o);
    case 'G': return cmd_krb_read_cred(f, nf, o);
    default: return proto_fail(o, "unknown command");
    }
}

// Sends a protocol-error reply for a framing failure, then half-closes.
static void reject(int fd, const char *text)
{
    struct out o;

    out_init(&o);
    out_text(&o, text);
    wire_send(fd, PEER_PROTOCOL, &o);
    shutdown(fd, SHUT_WR);
}

static const char *framing_error(int rc)
{
    switch (rc) {
    case RD_OVERSIZE: return "frame too large (limit 1048576 bytes)";
    case RD_EMPTY: return "empty frame";
    case RD_TRUNCATED: return "truncated frame";
    case RD_TIMEOUT: return "idle timeout";
    default: return NULL;
    }
}

static void serve(int fd)
{
    const char *idle_text = getenv("PEER_IDLE_SECONDS");
    long idle = idle_text != NULL ? atol(idle_text) : 60;
    struct timeval tv;
    int commands;

    tv.tv_sec = idle >= 1 && idle <= 3600 ? idle : 60;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    snprintf(g_trace_path, sizeof(g_trace_path), "%s/trace.%ld", PEER_RUN_DIR, (long)getpid());
    setenv("KRB5_TRACE", g_trace_path, 1);
    for (commands = 0; commands < PEER_MAX_COMMANDS; commands++) {
        struct field fields[PEER_MAX_FIELDS];
        struct out o;
        uint32_t len = 0;
        size_t nf = 0;
        int rc = wire_read_frame(fd, g_request, &len), status;

        if (rc != RD_OK) {
            if (framing_error(rc) != NULL) {
                fprintf(stderr, "peer-adapter[%ld]: framing error: %s\n", (long)getpid(), framing_error(rc));
                reject(fd, framing_error(rc));
            }
            break;
        }
        if (wire_parse(g_request + 1, len - 1, fields, &nf) != 0) {
            out_init(&o);
            out_text(&o, "malformed fields");
            status = PEER_PROTOCOL;
        } else {
            status = dispatch(g_request[0], fields, nf, &o);
        }
        if (o.overflow) {
            out_init(&o);
            out_text(&o, "reply too large");
            status = PEER_PROTOCOL;
        }
        fprintf(stderr, "peer-adapter[%ld]: command %c status %d\n", (long)getpid(), g_request[0], status);
        explicit_bzero(g_request, len);
        if (wire_send(fd, (uint8_t)status, &o) != 0)
            break;
    }
    if (commands == PEER_MAX_COMMANDS)
        reject(fd, "command limit reached");
    unlink(g_trace_path);
}

static void on_child(int sig)
{
    int saved = errno;

    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0)
        g_children--;
    errno = saved;
}

static int listen_on(const char *address, int port)
{
    struct sockaddr_in sa;
    int one = 1, fd = socket(AF_INET, SOCK_STREAM, 0);

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (fd < 0 || inet_pton(AF_INET, address, &sa.sin_addr) != 1 ||
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0 ||
        bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(fd, 16) != 0)
        return -1;
    return fd;
}

static void accept_loop(int listener)
{
    sigset_t chld, previous;

    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    for (;;) {
        int conn = accept(listener, NULL, NULL);
        pid_t pid;

        if (conn < 0) {
            if (errno == EINTR || errno == ECONNABORTED)
                continue;
            perror("peer-adapter: accept");
            return;
        }
        sigprocmask(SIG_BLOCK, &chld, &previous);
        if (g_children >= PEER_MAX_CHILDREN) {
            reject(conn, "too many connections");
            pid = -1;
        } else if ((pid = fork()) == 0) {
            sigprocmask(SIG_SETMASK, &previous, NULL);
            signal(SIGCHLD, SIG_DFL);
            close(listener);
            serve(conn);
            close(conn);
            _exit(0);
        } else if (pid > 0) {
            g_children++;
        }
        sigprocmask(SIG_SETMASK, &previous, NULL);
        close(conn);
    }
}

int main(int argc, char **argv)
{
    int port, listener;

    if (argc != 3 || (port = atoi(argv[2])) < 1 || port > 65535) {
        fprintf(stderr, "usage: peer-adapter <IPv4 address> <port>\n");
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, on_child);
    if ((listener = listen_on(argv[1], port)) < 0) {
        perror("peer-adapter: listen");
        return 1;
    }
    fprintf(stderr, "peer-adapter: listening on %s:%d\n", argv[1], port);
    accept_loop(listener);
    return 1;
}
