#ifndef WS_CLIENT_H
#define WS_CLIENT_H

#include <stddef.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/**
 * Initialize OpenSSL and shared SSL_CTX.
 * Returns 0 on success, -1 on error.
 */
int ws_init(void);

/**
 * Free shared OpenSSL resources.
 */
void ws_cleanup(void);

/**
 * Establish a TLS + WebSocket connection to the target host.
 *
 * @param host        Destination hostname or IP (e.g. "kws2.pclead.co.uk")
 * @param port        Port (e.g. 443)
 * @param sni         TLS SNI server hostname
 * @param host_header HTTP Host header
 * @param path        HTTP request path (e.g. "/apiws")
 * @param timeout_sec Connect and handshake timeout in seconds
 * @return SSL pointer on successful 101 WebSocket Upgrade, or NULL on error
 */
SSL *ws_connect(const char *host, int port, const char *sni, const char *host_header, const char *path, int timeout_sec);

/**
 * Send a WebSocket binary frame (masked, RFC 6455).
 * Returns bytes written, or -1 on error.
 */
int ws_send_frame(SSL *ssl, const unsigned char *data, size_t len);

/**
 * Receive a WebSocket frame payload.
 * Automatically replies to PING (opcode 9) with PONG (opcode 10).
 * Handles PONG and CLOSE frames.
 *
 * @param ssl     SSL pointer
 * @param out_buf Output buffer for frame payload
 * @param max_len Size of out_buf
 * @return Number of payload bytes read, 0 on clean close, or -1 on error
 */
int ws_recv_frame(SSL *ssl, unsigned char *out_buf, size_t max_len);

/**
 * Get underlying file descriptor from SSL object.
 */
int ws_get_fd(SSL *ssl);

/**
 * Check if SSL object has pending decrypted bytes buffered.
 */
int ws_has_pending(SSL *ssl);

/**
 * Close and free the WebSocket TLS connection.
 */
void ws_close(SSL *ssl);

#endif /* WS_CLIENT_H */
