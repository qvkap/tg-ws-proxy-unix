#include "ws_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

static SSL_CTX *g_ssl_ctx = NULL;

static void base64_encode(const unsigned char *input, int length, char *output) {
    EVP_EncodeBlock((unsigned char *)output, input, length);
}

int ws_init(void) {
    if (g_ssl_ctx) return 0;
    
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    const SSL_METHOD *method = TLS_client_method();
    g_ssl_ctx = SSL_CTX_new(method);
    if (!g_ssl_ctx) {
        return -1;
    }

    /* Configure reasonable defaults: TLS 1.2 minimum, modern cipher list */
    SSL_CTX_set_min_proto_version(g_ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(g_ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);

    return 0;
}

void ws_cleanup(void) {
    if (g_ssl_ctx) {
        SSL_CTX_free(g_ssl_ctx);
        g_ssl_ctx = NULL;
    }
}

static int connect_with_timeout(const char *host, int port, int timeout_sec) {
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        return -1;
    }

    int sock = -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) continue;

        /* Set socket options */
        int nodelay = 1;
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof(nodelay));
        int keepalive = 1;
        setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (const char *)&keepalive, sizeof(keepalive));

        /* Set non-blocking to enforce connect timeout */
        int flags = fcntl(sock, F_GETFL, 0);
        if (flags >= 0) {
            fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        }

        int ret = connect(sock, rp->ai_addr, rp->ai_addrlen);
        if (ret == 0) {
            /* Connected immediately */
            if (flags >= 0) fcntl(sock, F_SETFL, flags);
            break;
        }

        if (errno == EINPROGRESS) {
            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(sock, &wfds);
            struct timeval tv = { .tv_sec = timeout_sec, .tv_usec = 0 };

            int sel = select(sock + 1, NULL, &wfds, NULL, &tv);
            if (sel > 0) {
                int err = 0;
                socklen_t len = sizeof(err);
                if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0) {
                    /* Connected successfully */
                    if (flags >= 0) fcntl(sock, F_SETFL, flags);
                    break;
                }
            }
        }

        close(sock);
        sock = -1;
    }

    freeaddrinfo(res);
    return sock;
}

static int read_exact(SSL *ssl, unsigned char *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        int r = SSL_read(ssl, buf + total, (int)(len - total));
        if (r <= 0) return -1;
        total += (size_t)r;
    }
    return (int)total;
}

SSL *ws_connect(const char *host, int port, const char *sni, const char *host_header, const char *path, int timeout_sec) {
    if (ws_init() < 0) return NULL;

    int sock = connect_with_timeout(host, port, timeout_sec > 0 ? timeout_sec : 5);
    if (sock < 0) {
        return NULL;
    }

    /* Set socket read/write timeouts */
    struct timeval tv = { .tv_sec = timeout_sec > 0 ? timeout_sec : 5, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));

    SSL *ssl = SSL_new(g_ssl_ctx);
    if (!ssl) {
        close(sock);
        return NULL;
    }

    SSL_set_fd(ssl, sock);
    if (sni && sni[0] != '\0') {
        SSL_set_tlsext_host_name(ssl, sni);
    }

    if (SSL_connect(ssl) <= 0) {
        SSL_free(ssl);
        close(sock);
        return NULL;
    }

    /* Generate Sec-WebSocket-Key */
    unsigned char random_key[16];
    char b64_key[32];
    RAND_bytes(random_key, sizeof(random_key));
    base64_encode(random_key, sizeof(random_key), b64_key);

    /* Formulate WebSocket HTTP Upgrade request */
    char request[1024];
    int req_len = snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             "Sec-WebSocket-Key: %s\r\n"
             "Sec-WebSocket-Version: 13\r\n"
             "Sec-WebSocket-Protocol: binary\r\n"
             "\r\n", path ? path : "/apiws", host_header, b64_key);

    if (SSL_write(ssl, request, req_len) <= 0) {
        SSL_free(ssl);
        close(sock);
        return NULL;
    }

    /* Read HTTP Upgrade response until \r\n\r\n */
    char response[2048];
    int total_bytes = 0;
    int header_done = 0;

    while (total_bytes < (int)sizeof(response) - 1) {
        int bytes = SSL_read(ssl, response + total_bytes, 1);
        if (bytes <= 0) break;
        total_bytes += bytes;
        response[total_bytes] = '\0';

        if (total_bytes >= 4 &&
            response[total_bytes - 4] == '\r' &&
            response[total_bytes - 3] == '\n' &&
            response[total_bytes - 2] == '\r' &&
            response[total_bytes - 1] == '\n') {
            header_done = 1;
            break;
        }
    }

    if (!header_done || strstr(response, "101") == NULL) {
        SSL_free(ssl);
        close(sock);
        return NULL;
    }

    /* Reset socket timeouts to zero for continuous data transfer */
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));

    return ssl;
}

static int ws_send_pong(SSL *ssl, const unsigned char *payload, size_t len) {
    if (len > 125) len = 125;
    unsigned char frame[132];
    frame[0] = 0x8A; /* FIN + opcode 10 (pong) */
    frame[1] = (unsigned char)len | 0x80; /* Mask bit set */

    unsigned char mask[4];
    RAND_bytes(mask, 4);
    memcpy(frame + 2, mask, 4);

    for (size_t i = 0; i < len; i++) {
        frame[6 + i] = payload[i] ^ mask[i % 4];
    }
    return SSL_write(ssl, frame, 6 + (int)len);
}

int ws_send_frame(SSL *ssl, const unsigned char *data, size_t len) {
    if (!ssl) return -1;

    size_t header_len = 0;
    unsigned char header[14];

    header[0] = 0x82; /* FIN + Opcode 2 (Binary) */

    if (len < 126) {
        header[1] = (unsigned char)len | 0x80;
        header_len = 2;
    } else if (len <= 65535) {
        header[1] = 126 | 0x80;
        header[2] = (unsigned char)((len >> 8) & 0xFF);
        header[3] = (unsigned char)(len & 0xFF);
        header_len = 4;
    } else {
        header[1] = 127 | 0x80;
        header[2] = 0;
        header[3] = 0;
        header[4] = 0;
        header[5] = 0;
        header[6] = (unsigned char)((len >> 24) & 0xFF);
        header[7] = (unsigned char)((len >> 16) & 0xFF);
        header[8] = (unsigned char)((len >> 8) & 0xFF);
        header[9] = (unsigned char)(len & 0xFF);
        header_len = 10;
    }

    unsigned char mask[4];
    RAND_bytes(mask, 4);
    memcpy(header + header_len, mask, 4);
    header_len += 4;

    /* For small packets, combine header and masked payload into stack buffer */
    if (len <= 8192) {
        unsigned char buf[8192 + 14];
        memcpy(buf, header, header_len);
        for (size_t i = 0; i < len; i++) {
            buf[header_len + i] = data[i] ^ mask[i % 4];
        }
        return SSL_write(ssl, buf, (int)(header_len + len));
    }

    /* For larger packets, send header then masked payload */
    if (SSL_write(ssl, header, (int)header_len) <= 0) {
        return -1;
    }

    unsigned char *masked = malloc(len);
    if (!masked) return -1;

    for (size_t i = 0; i < len; i++) {
        masked[i] = data[i] ^ mask[i % 4];
    }
    int w = SSL_write(ssl, masked, (int)len);
    free(masked);
    return w;
}

int ws_recv_frame(SSL *ssl, unsigned char *out_buf, size_t max_len) {
    if (!ssl || !out_buf || max_len == 0) return -1;

    while (1) {
        unsigned char header[2];
        if (read_exact(ssl, header, 2) <= 0) return -1;

        int opcode = header[0] & 0x0F;
        size_t payload_len = header[1] & 0x7F;
        int is_masked = (header[1] & 0x80) != 0;

        if (payload_len == 126) {
            unsigned char ext_len[2];
            if (read_exact(ssl, ext_len, 2) <= 0) return -1;
            payload_len = ((size_t)ext_len[0] << 8) | (size_t)ext_len[1];
        } else if (payload_len == 127) {
            unsigned char ext_len[8];
            if (read_exact(ssl, ext_len, 8) <= 0) return -1;
            payload_len = ((size_t)ext_len[4] << 24) |
                          ((size_t)ext_len[5] << 16) |
                          ((size_t)ext_len[6] << 8) |
                          (size_t)ext_len[7];
        }

        unsigned char mask[4] = {0};
        if (is_masked) {
            if (read_exact(ssl, mask, 4) <= 0) return -1;
        }

        /* Handle Control Frames */
        if (opcode == 0x8) {
            /* CLOSE frame */
            return 0;
        }

        if (opcode == 0x9) {
            /* PING frame: read payload (<= 125) and reply with PONG */
            unsigned char ping_payload[128];
            size_t plen = payload_len < sizeof(ping_payload) ? payload_len : sizeof(ping_payload);
            if (plen > 0) {
                if (read_exact(ssl, ping_payload, plen) <= 0) return -1;
                if (is_masked) {
                    for (size_t i = 0; i < plen; i++) ping_payload[i] ^= mask[i % 4];
                }
            }
            ws_send_pong(ssl, ping_payload, plen);
            continue;
        }

        if (opcode == 0xA) {
            /* PONG frame: discard payload and wait for next frame */
            unsigned char discard[128];
            size_t remaining = payload_len;
            while (remaining > 0) {
                size_t chunk = remaining < sizeof(discard) ? remaining : sizeof(discard);
                if (read_exact(ssl, discard, chunk) <= 0) return -1;
                remaining -= chunk;
            }
            continue;
        }

        /* Data Frame (Opcode 0x1 TEXT, 0x2 BINARY, or 0x0 CONT) */
        if (payload_len > max_len) {
            return -1;
        }

        if (payload_len > 0) {
            if (read_exact(ssl, out_buf, payload_len) <= 0) return -1;
            if (is_masked) {
                for (size_t i = 0; i < payload_len; i++) {
                    out_buf[i] ^= mask[i % 4];
                }
            }
        }

        return (int)payload_len;
    }
}

int ws_get_fd(SSL *ssl) {
    return ssl ? SSL_get_fd(ssl) : -1;
}

int ws_has_pending(SSL *ssl) {
    return (ssl != NULL && SSL_pending(ssl) > 0);
}

void ws_close(SSL *ssl) {
    if (ssl) {
        int sock = SSL_get_fd(ssl);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        if (sock >= 0) close(sock);
    }
}
