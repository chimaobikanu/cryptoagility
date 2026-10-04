/*
 * ca_shim.c — CryptoAgility runtime observation layer (unprivileged).
 *
 * LD_PRELOAD interposer for libssl. Observes what cryptography a process is
 * ACTUALLY using at runtime: the cipher suites it configures and the ciphers and
 * protocol versions it negotiates on live connections. Writes JSON Lines to the
 * path in $CA_LOG (default /tmp/ca-runtime.jsonl).
 *
 * This is the second discovery layer. Static analysis finds cryptography in code;
 * this finds it in flight — including libraries and vendored binaries whose source
 * you never see.
 *
 * Build:  gcc -shared -fPIC -O2 -o ca_shim.so ca_shim.c -ldl
 * Use:    CA_LOG=/tmp/ca.jsonl LD_PRELOAD=./ca_shim.so <program>
 *
 * No root, no kernel module, no CAP_BPF required.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dlfcn.h>

/* Opaque types — declared here so the shim builds without libssl headers. */
typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_cipher_st SSL_CIPHER;

/* ---- real symbols -------------------------------------------------------- */
static int   (*real_SSL_write)(SSL *, const void *, int);
static const char *(*real_SSL_get_version)(const SSL *);
static const SSL_CIPHER *(*real_SSL_get_current_cipher)(const SSL *);
static const char *(*real_SSL_CIPHER_get_name)(const SSL_CIPHER *);
static int   (*real_SSL_CIPHER_get_bits)(const SSL_CIPHER *, int *);
static int   (*real_SSL_CTX_set_cipher_list)(SSL_CTX *, const char *);
static int   (*real_SSL_set_cipher_list)(SSL *, const char *);
static int   (*real_SSL_CTX_set_ciphersuites)(SSL_CTX *, const char *);
static int   (*real_SSL_CTX_set_min_proto_version)(SSL_CTX *, int);
static int   (*real_SSL_CTX_set_max_proto_version)(SSL_CTX *, int);

static void *sym(const char *name) {
    void *p = dlsym(RTLD_NEXT, name);
    if (!p) {
        /* resolve from libssl directly if RTLD_NEXT ordering is unusual */
        void *h = dlopen("libssl.so.3", RTLD_LAZY | RTLD_NOLOAD);
        if (!h) h = dlopen("libssl.so", RTLD_LAZY | RTLD_NOLOAD);
        if (h) p = dlsym(h, name);
    }
    return p;
}

#define RESOLVE(v, n) do { if (!(v)) (v) = sym(n); } while (0)

static void json_escape(const char *in, char *out, size_t n) {
    size_t j = 0;
    if (!in) { out[0] = '\0'; return; }
    for (size_t i = 0; in[i] && j + 2 < n; i++) {
        char c = in[i];
        if (c == '"' || c == '\\') { out[j++] = '\\'; out[j++] = c; }
        else if (c == '\n' || c == '\r' || c == '\t') { out[j++] = ' '; }
        else out[j++] = c;
    }
    out[j] = '\0';
}

static void emit(const char *event, const char *detail, const char *version,
                 const char *cipher, int bits) {
    const char *path = getenv("CA_LOG");
    if (!path) path = "/tmp/ca-runtime.jsonl";
    FILE *f = fopen(path, "a");
    if (!f) return;

    char ed[512], ec[256];
    json_escape(detail, ed, sizeof ed);
    json_escape(cipher, ec, sizeof ec);

    char ts[40];
    time_t t = time(NULL);
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%SZ", &tm);

    fprintf(f,
            "{\"ts\":\"%s\",\"event\":\"%s\",\"pid\":%d,\"version\":\"%s\","
            "\"cipher\":\"%s\",\"bits\":%d,\"detail\":\"%s\"}\n",
            ts, event, (int)getpid(), version ? version : "", ec, bits, ed);
    fclose(f);
}

/* ---- interposers --------------------------------------------------------- */

int SSL_write(SSL *ssl, const void *buf, int num) {
    RESOLVE(real_SSL_write, "SSL_write");
    RESOLVE(real_SSL_get_version, "SSL_get_version");
    RESOLVE(real_SSL_get_current_cipher, "SSL_get_current_cipher");
    RESOLVE(real_SSL_CIPHER_get_name, "SSL_CIPHER_get_name");
    RESOLVE(real_SSL_CIPHER_get_bits, "SSL_CIPHER_get_bits");

    if (real_SSL_get_current_cipher && real_SSL_CIPHER_get_name) {
        const SSL_CIPHER *c = real_SSL_get_current_cipher(ssl);
        if (c) {
            int bits = 0;
            const char *nm = real_SSL_CIPHER_get_name(c);
            if (real_SSL_CIPHER_get_bits) bits = real_SSL_CIPHER_get_bits(c, NULL);
            const char *v = real_SSL_get_version ? real_SSL_get_version(ssl) : "";
            emit("negotiated", "observed on encrypted write", v, nm, bits);
        }
    }
    if (!real_SSL_write) return -1;
    return real_SSL_write(ssl, buf, num);
}

/* Many tools (including the openssl CLI) ask the connection what cipher it chose. */
const SSL_CIPHER *SSL_get_current_cipher(const SSL *ssl) {
    RESOLVE(real_SSL_get_current_cipher, "SSL_get_current_cipher");
    RESOLVE(real_SSL_get_version, "SSL_get_version");
    RESOLVE(real_SSL_CIPHER_get_name, "SSL_CIPHER_get_name");
    RESOLVE(real_SSL_CIPHER_get_bits, "SSL_CIPHER_get_bits");
    if (!real_SSL_get_current_cipher) return NULL;
    const SSL_CIPHER *c = real_SSL_get_current_cipher(ssl);
    if (c && real_SSL_CIPHER_get_name) {
        int bits = 0;
        if (real_SSL_CIPHER_get_bits) bits = real_SSL_CIPHER_get_bits(c, NULL);
        const char *v = real_SSL_get_version ? real_SSL_get_version(ssl) : "";
        emit("negotiated", "queried active cipher", v, real_SSL_CIPHER_get_name(c), bits);
    }
    return c;
}

int SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str) {
    RESOLVE(real_SSL_CTX_set_cipher_list, "SSL_CTX_set_cipher_list");
    emit("configured", "SSL_CTX_set_cipher_list", "", "", 0);
    /* detail carries the configured list, escaped */
    {
        const char *path = getenv("CA_LOG");
        if (path) {
            FILE *f = fopen(path, "a");
            if (f) { fprintf(f, "{\"config\":\"cipher_list\",\"value\":\"%s\"}\n", str ? str : ""); fclose(f); }
        }
    }
    return real_SSL_CTX_set_cipher_list ? real_SSL_CTX_set_cipher_list(ctx, str) : 0;
}

int SSL_set_cipher_list(SSL *ssl, const char *str) {
    RESOLVE(real_SSL_set_cipher_list, "SSL_set_cipher_list");
    const char *path = getenv("CA_LOG");
    if (path) {
        FILE *f = fopen(path, "a");
        if (f) { fprintf(f, "{\"config\":\"cipher_list_per_ssl\",\"value\":\"%s\"}\n", str ? str : ""); fclose(f); }
    }
    return real_SSL_set_cipher_list ? real_SSL_set_cipher_list(ssl, str) : 0;
}

int SSL_CTX_set_ciphersuites(SSL_CTX *ctx, const char *str) {
    RESOLVE(real_SSL_CTX_set_ciphersuites, "SSL_CTX_set_ciphersuites");
    const char *path = getenv("CA_LOG");
    if (path) {
        FILE *f = fopen(path, "a");
        if (f) { fprintf(f, "{\"config\":\"tls13_ciphersuites\",\"value\":\"%s\"}\n", str ? str : ""); fclose(f); }
    }
    return real_SSL_CTX_set_ciphersuites ? real_SSL_CTX_set_ciphersuites(ctx, str) : 0;
}

int SSL_CTX_set_min_proto_version(SSL_CTX *ctx, int version) {
    RESOLVE(real_SSL_CTX_set_min_proto_version, "SSL_CTX_set_min_proto_version");
    emit("configured", "SSL_CTX_set_min_proto_version", "", "", version);
    return real_SSL_CTX_set_min_proto_version ? real_SSL_CTX_set_min_proto_version(ctx, version) : 0;
}

int SSL_CTX_set_max_proto_version(SSL_CTX *ctx, int version) {
    RESOLVE(real_SSL_CTX_set_max_proto_version, "SSL_CTX_set_max_proto_version");
    emit("configured", "SSL_CTX_set_max_proto_version", "", "", version);
    return real_SSL_CTX_set_max_proto_version ? real_SSL_CTX_set_max_proto_version(ctx, version) : 0;
}
