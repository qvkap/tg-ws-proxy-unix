#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <pthread.h>
#include <sys/select.h>
#include <errno.h>
#include <openssl/rand.h>
#include <sys/stat.h>
#include <syslog.h>
#include <stdarg.h>
#include <time.h>
#include <signal.h>
#ifdef __FreeBSD__
#include <sys/sysctl.h>
#endif
#include "ws_client.h"

#define DEFAULT_PORT 8080
#define BUFFER_SIZE (64 * 1024)
#define TARGET_PATH "/apiws"
#define CONFIG_FILE "config.json"
#define MAX_CUSTOM_WORKERS 8
#define MAX_CUSTOM_DOMAINS 8

static int run_as_daemon = 0;
static int g_enable_tcp_fragment = 1;
static int g_enable_direct_fallback = 1;

static char g_custom_workers[MAX_CUSTOM_WORKERS][256];
static int g_custom_workers_count = 0;

static char g_custom_domains[MAX_CUSTOM_DOMAINS][256];
static int g_custom_domains_count = 0;

/* Embedded encrypted Cloudflare reverse proxy domains */
static const char* CFPROXY_ENC[] = {
    "virkgj.com", "vmmzovy.com", "mkuosckvso.com", "zaewayzmplad.com",
    "twdmbzcm.com", "awzwsldi.com", "clngqrflngqin.com", "tjacxbqtj.com",
    "bxaxtxmrw.com", "dmohrsgmohcrwb.com", "vwbmtmoi.com", "khgrre.com",
    "ulihssf.com", "tmhqsdqmfpmk.com", "xwuwoqbm.com", "orgcnunpj.com",
    "zhkuldz.com", "zypoljnslxa.com", "efabnxaowuzs.com", "zaftuzsftqdq.com"
};
#define CFPROXY_COUNT (int)(sizeof(CFPROXY_ENC)/sizeof(CFPROXY_ENC[0]))

/* Telegram default DC IP addresses */
static const char *TG_DC_IPS[] = {
    "",                 /* DC0 unused */
    "149.154.175.50",   /* DC1 */
    "149.154.167.51",   /* DC2 */
    "149.154.175.100",  /* DC3 */
    "149.154.167.91",   /* DC4 */
    "149.154.171.5"     /* DC5 */
};

/* Additional fallback IPs for DC2 */
static const char *TG_DC2_FALLBACK_IPS[] = {
    "149.154.167.50", "149.154.167.51", "91.108.12.114", "91.108.12.115"
};
#define TG_DC2_FALLBACK_COUNT (int)(sizeof(TG_DC2_FALLBACK_IPS)/sizeof(TG_DC2_FALLBACK_IPS[0]))

void proxy_log(int level, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if (run_as_daemon) {
        vsyslog(level == 0 ? LOG_INFO : LOG_ERR, fmt, args);
    } else {
        vprintf(fmt, args);
        fflush(stdout);
    }
    va_end(args);
}

void censor_domain(const char *domain, char *out, size_t out_len) {
    if (!domain || !out || out_len == 0) return;
    char temp[256];
    strncpy(temp, domain, sizeof(temp) - 1);
    temp[sizeof(temp) - 1] = '\0';

    int len = strlen(temp);
    if (len >= 12 && strcmp(temp + len - 12, "telegram.org") == 0) {
        strncpy(out, domain, out_len - 1);
        out[out_len - 1] = '\0';
        return;
    }

    out[0] = '\0';
    char *saveptr = NULL;
    char *token = strtok_r(temp, ".", &saveptr);
    char *parts[32];
    int part_count = 0;
    while (token && part_count < 32) {
        parts[part_count++] = token;
        token = strtok_r(NULL, ".", &saveptr);
    }

    if (part_count < 2) {
        strncpy(out, domain, out_len - 1);
        out[out_len - 1] = '\0';
        return;
    }

    for (int i = 0; i < part_count; i++) {
        if (i > 0) strncat(out, ".", out_len - strlen(out) - 1);

        if (i == part_count - 1) {
            strncat(out, parts[i], out_len - strlen(out) - 1);
        } else {
            int p_len = strlen(parts[i]);
            int half = p_len / 2;
            int cur_len = strlen(out);
            for (int j = 0; j < p_len && (size_t)(cur_len + j) < out_len - 1; j++) {
                if (j < half) {
                    out[cur_len + j] = parts[i][j];
                } else {
                    out[cur_len + j] = '*';
                }
            }
            int new_len = cur_len + p_len;
            if ((size_t)new_len >= out_len) new_len = out_len - 1;
            out[new_len] = '\0';
        }
    }
}

void decode_domain(const char *s, char *out, size_t out_len) {
    int len = strlen(s);
    if (len < 4 || strcmp(s + len - 4, ".com") != 0) {
        strncpy(out, s, out_len - 1);
        out[out_len - 1] = '\0';
        return;
    }

    int p_len = len - 4;
    int n = 0;
    for (int i = 0; i < p_len; i++) {
        if ((s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z')) n++;
    }

    for (int i = 0; i < p_len && (size_t)i < out_len - 1; i++) {
        char c = s[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
            char base = (c >= 'a') ? 'a' : 'A';
            int diff = (c - base - n);
            out[i] = ((diff % 26) + 26) % 26 + base;
        } else {
            out[i] = c;
        }
    }
    out[p_len] = '\0';
    strncat(out, ".co.uk", out_len - strlen(out) - 1);
}

/* Detect Telegram DC from IP address or hostname */
int detect_telegram_dc(const char *ip_str, uint32_t ip, const char *hostname) {
    if (hostname && hostname[0] != '\0') {
        if (strstr(hostname, "kws1") || strstr(hostname, "dc1")) return 1;
        if (strstr(hostname, "kws2") || strstr(hostname, "dc2")) return 2;
        if (strstr(hostname, "kws3") || strstr(hostname, "dc3")) return 3;
        if (strstr(hostname, "kws4") || strstr(hostname, "dc4")) return 4;
        if (strstr(hostname, "kws5") || strstr(hostname, "dc5")) return 5;
    }

    if (ip_str && ip_str[0] != '\0') {
        if (strncmp(ip_str, "149.154.175.", 12) == 0) return 1;
        if (strncmp(ip_str, "149.154.167.", 12) == 0) return 2;
        if (strncmp(ip_str, "149.154.171.", 12) == 0) return 5;
        if (strncmp(ip_str, "91.108.4.", 9) == 0 || strncmp(ip_str, "91.108.56.", 10) == 0) return 4;
        if (strncmp(ip_str, "91.108.12.", 10) == 0 || strncmp(ip_str, "91.108.16.", 10) == 0) return 5;
        if (strncmp(ip_str, "91.105.192.", 11) == 0) return 2; /* DC203 */
    }

    /* Check subnet 149.154.160.0/20 or 91.108.0.0/16 */
    uint32_t ip_h = ntohl(ip);
    if ((ip_h & 0xFFFFF000) == 0x959AA000) { /* 149.154.160.0/20 */
        return 2;
    }
    if ((ip_h & 0xFFFF0000) == 0x5B6C0000) { /* 91.108.0.0/16 */
        return 2;
    }

    return -1;
}

/* Send data with TCP fragmentation / trickle for DPI bypass */
static ssize_t send_with_fragmentation(int fd, const unsigned char *buf, size_t len) {
    if (!g_enable_tcp_fragment || len <= 2) {
        return send(fd, buf, len, 0);
    }

    /* Send first 2 bytes separately to break signature matching on naive DPI */
    ssize_t s1 = send(fd, buf, 2, 0);
    if (s1 <= 0) return s1;

    usleep(1500); /* 1.5ms pause to guarantee separate TCP packet transmission */

    ssize_t s2 = send(fd, buf + 2, len - 2, 0);
    if (s2 <= 0) return s2;

    return s1 + s2;
}

/* Establish WSS tunnel to Cloudflare with automatic domain rotation and fallback */
static SSL *establish_cf_wss_tunnel(int dc, char *out_censored_host, size_t censored_len) {
    if (dc <= 0 || dc > 5) dc = 2;

    /* 1. Try Custom Cloudflare Worker if configured */
    if (g_custom_workers_count > 0) {
        for (int i = 0; i < g_custom_workers_count; i++) {
            const char *worker = g_custom_workers[i];
            char path[512];
            snprintf(path, sizeof(path), "/apiws?dst=%s&dc=%d", TG_DC_IPS[dc], dc);

            char censored[512];
            censor_domain(worker, censored, sizeof(censored));
            if (out_censored_host && censored_len > 0) {
                strncpy(out_censored_host, censored, censored_len - 1);
                out_censored_host[censored_len - 1] = '\0';
            }

            proxy_log(0, "[WSS] Trying custom Cloudflare Worker: %s\n", censored);
            SSL *ssl = ws_connect(worker, 443, worker, worker, path, 5);
            if (ssl) {
                proxy_log(0, "[WSS] Connected successfully via Worker: %s\n", censored);
                return ssl;
            }
        }
    }

    /* 2. Try Custom Reverse Proxy Domains if configured */
    if (g_custom_domains_count > 0) {
        for (int i = 0; i < g_custom_domains_count; i++) {
            char target_host[1024];
            snprintf(target_host, sizeof(target_host), "kws%d.%.240s", dc, g_custom_domains[i]);

            char censored[512];
            censor_domain(target_host, censored, sizeof(censored));

            if (out_censored_host && censored_len > 0) {
                strncpy(out_censored_host, censored, censored_len - 1);
                out_censored_host[censored_len - 1] = '\0';
            }

            proxy_log(0, "[WSS] Trying custom proxy domain: %s\n", censored);
            SSL *ssl = ws_connect(target_host, 443, target_host, target_host, TARGET_PATH, 5);
            if (ssl) {
                proxy_log(0, "[WSS] Connected successfully via custom domain: %s\n", censored);
                return ssl;
            }
        }
    }

    /* 3. Try Rotating Cloudflare Reverse Proxy Pool */
    int start_idx = rand() % CFPROXY_COUNT;
    for (int attempt = 0; attempt < CFPROXY_COUNT; attempt++) {
        int idx = (start_idx + attempt) % CFPROXY_COUNT;
        char base_domain[256];
        decode_domain(CFPROXY_ENC[idx], base_domain, sizeof(base_domain));

        char target_host[1024];
        snprintf(target_host, sizeof(target_host), "kws%d.%.240s", dc, base_domain);

        char censored[512];
        censor_domain(target_host, censored, sizeof(censored));

        if (out_censored_host && censored_len > 0) {
            strncpy(out_censored_host, censored, censored_len - 1);
            out_censored_host[censored_len - 1] = '\0';
        }

        proxy_log(0, "[WSS] Routing to Cloudflare proxy: %s\n", censored);
        SSL *ssl = ws_connect(target_host, 443, target_host, target_host, TARGET_PATH, 5);
        if (ssl) {
            proxy_log(0, "[WSS] Established WSS tunnel to %s\n", censored);
            return ssl;
        }
        proxy_log(1, "[WSS] %s failed, rotating to next domain...\n", censored);
    }

    return NULL;
}

/* Fallback to direct TCP connection with TCP fragmentation DPI bypass */
static int establish_direct_tcp_fallback(int dc) {
    if (!g_enable_direct_fallback) return -1;
    if (dc <= 0 || dc > 5) dc = 2;

    proxy_log(1, "[FALLBACK] Attempting direct TCP connection with DPI fragmentation to Telegram DC%d...\n", dc);

    const char *ips[8];
    int count = 0;

    if (dc == 2) {
        for (int i = 0; i < TG_DC2_FALLBACK_COUNT; i++) ips[count++] = TG_DC2_FALLBACK_IPS[i];
    } else {
        ips[count++] = TG_DC_IPS[dc];
    }

    for (int i = 0; i < count; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;

        int nodelay = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof(nodelay));

        struct sockaddr_in serv_addr;
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(443);
        serv_addr.sin_addr.s_addr = inet_addr(ips[i]);

        struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));

        if (connect(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) {
            tv.tv_sec = 0;
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
            proxy_log(0, "[FALLBACK] Connected directly to Telegram IP: %s\n", ips[i]);
            return fd;
        }
        close(fd);
    }

    proxy_log(1, "[ERROR] All direct TCP fallbacks failed\n");
    return -1;
}

/* SOCKS5 proxy protocol handler with intelligent Telegram DC interception */
void handle_socks5(int client_fd) {
    unsigned char buf[BUFFER_SIZE];
    proxy_log(0, "[INFO] SOCKS5 Protocol Selected.\n");

    /* 1. SOCKS5 Auth Handshake */
    if (recv(client_fd, buf, 2, 0) <= 0) { close(client_fd); return; }
    int nmethods = buf[1];
    if (nmethods > 0) {
        if (recv(client_fd, buf, nmethods, 0) <= 0) { close(client_fd); return; }
    }
    unsigned char auth_reply[2] = {0x05, 0x00}; /* No authentication */
    send(client_fd, auth_reply, 2, 0);

    /* 2. SOCKS5 Request */
    if (recv(client_fd, buf, 4, 0) <= 0 || buf[1] != 0x01) { close(client_fd); return; }

    char target_host[256] = {0};
    int target_port = 0;
    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;

    if (buf[3] == 0x01) { /* IPv4 address */
        if (recv(client_fd, buf + 4, 6, 0) <= 0) { close(client_fd); return; }
        memcpy(&target_addr.sin_addr.s_addr, buf + 4, 4);
        target_port = (buf[8] << 8) | buf[9];
        inet_ntop(AF_INET, &target_addr.sin_addr, target_host, sizeof(target_host));
    } else if (buf[3] == 0x03) { /* Domain name */
        unsigned char len;
        if (recv(client_fd, &len, 1, 0) <= 0) { close(client_fd); return; }
        if (recv(client_fd, target_host, len, 0) <= 0) { close(client_fd); return; }
        target_host[len] = '\0';
        unsigned char port_buf[2];
        if (recv(client_fd, port_buf, 2, 0) <= 0) { close(client_fd); return; }
        target_port = (port_buf[0] << 8) | port_buf[1];
    } else {
        close(client_fd);
        return;
    }
    target_addr.sin_port = htons(target_port);

    int dc = detect_telegram_dc(target_host, target_addr.sin_addr.s_addr, target_host);
    if (dc < 0 && target_port == 443) dc = 2; /* Default to DC2 for typical Telegram SSL connections */

    SSL *wss = NULL;
    int target_fd = -1;

    if (dc > 0) {
        char censored[256];
        proxy_log(0, "[SOCKS5] Intercepted Telegram DC%d request (%s:%d) -> Routing via WSS tunnel\n",
                  dc, target_host, target_port);
        wss = establish_cf_wss_tunnel(dc, censored, sizeof(censored));
    }

    if (!wss) {
        /* Fall back to direct TCP with fragmentation */
        if (dc > 0) {
            target_fd = establish_direct_tcp_fallback(dc);
        } else {
            target_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (target_fd >= 0) {
                int nodelay = 1;
                setsockopt(target_fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof(nodelay));
                if (connect(target_fd, (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
                    close(target_fd);
                    target_fd = -1;
                }
            }
        }
    }

    if (!wss && target_fd < 0) {
        /* Connection failed: send SOCKS5 general failure */
        unsigned char fail_reply[10] = {0x05, 0x01, 0x00, 0x01, 0,0,0,0, 0,0};
        send(client_fd, fail_reply, 10, 0);
        close(client_fd);
        return;
    }

    /* Send SOCKS5 Connection Success */
    unsigned char success_reply[10] = {0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0};
    send(client_fd, success_reply, 10, 0);

    /* Full-duplex proxy relay loop */
    int upstream_fd = wss ? ws_get_fd(wss) : target_fd;
    int max_fd = (client_fd > upstream_fd) ? client_fd : upstream_fd;
    fd_set readfds;
    ssize_t bytes_read;
    int first_client_pkt = 1;

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(client_fd, &readfds);
        FD_SET(upstream_fd, &readfds);

        struct timeval tv = { .tv_sec = 0, .tv_usec = 250000 }; /* 250ms timeout for SSL_pending */

        int sel = select(max_fd + 1, &readfds, NULL, NULL, &tv);
        if (sel < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* Client -> Upstream */
        if (FD_ISSET(client_fd, &readfds)) {
            bytes_read = recv(client_fd, buf, sizeof(buf), 0);
            if (bytes_read <= 0) break;

            if (wss) {
                if (ws_send_frame(wss, buf, bytes_read) <= 0) break;
            } else {
                if (first_client_pkt) {
                    if (send_with_fragmentation(target_fd, buf, bytes_read) <= 0) break;
                    first_client_pkt = 0;
                } else {
                    if (send(target_fd, buf, bytes_read, 0) <= 0) break;
                }
            }
        }

        /* Upstream -> Client */
        int has_data = FD_ISSET(upstream_fd, &readfds);
        if (wss && ws_has_pending(wss)) has_data = 1;

        if (has_data) {
            if (wss) {
                bytes_read = ws_recv_frame(wss, buf, sizeof(buf));
                if (bytes_read <= 0) break;
            } else {
                bytes_read = recv(target_fd, buf, sizeof(buf), 0);
                if (bytes_read <= 0) break;
            }
            if (send(client_fd, buf, bytes_read, 0) <= 0) break;
        }
    }

    if (wss) ws_close(wss);
    if (target_fd >= 0) close(target_fd);
    close(client_fd);
}

/* MTProto handler with WSS tunneling and multi-DC resolution */
void handle_mtproto_wss(int client_fd) {
    unsigned char buf[BUFFER_SIZE];
    int dc = 2; /* Default DC2 */

    /* Peek at initial bytes to detect protocol tag and DC */
    ssize_t peek_len = recv(client_fd, buf, 64, MSG_PEEK);
    if (peek_len >= 64) {
        /* Check if intermediate or abridged tag is present in plain or obfuscated init */
        unsigned char proto_tag[4];
        memcpy(proto_tag, buf + 56, 4);
        if (proto_tag[0] == 0xee || proto_tag[0] == 0xef || proto_tag[0] == 0xdd) {
            int16_t dc_idx = (int16_t)(buf[60] | (buf[61] << 8));
            int parsed_dc = abs(dc_idx);
            if (parsed_dc >= 1 && parsed_dc <= 5) dc = parsed_dc;
        }
    }

    char censored[256];
    SSL *wss = establish_cf_wss_tunnel(dc, censored, sizeof(censored));
    int target_fd = -1;

    if (!wss) {
        proxy_log(1, "[ERROR] All WSS tunnels failed, falling back to direct TCP...\n");
        target_fd = establish_direct_tcp_fallback(dc);
        if (target_fd < 0) {
            close(client_fd);
            return;
        }
    }

    int upstream_fd = wss ? ws_get_fd(wss) : target_fd;
    int max_fd = (client_fd > upstream_fd) ? client_fd : upstream_fd;
    fd_set readfds;
    ssize_t bytes_read;
    int first_client_pkt = 1;

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(client_fd, &readfds);
        FD_SET(upstream_fd, &readfds);

        struct timeval tv = { .tv_sec = 0, .tv_usec = 250000 };

        int sel = select(max_fd + 1, &readfds, NULL, NULL, &tv);
        if (sel < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (FD_ISSET(client_fd, &readfds)) {
            bytes_read = recv(client_fd, buf, sizeof(buf), 0);
            if (bytes_read <= 0) break;

            if (wss) {
                if (ws_send_frame(wss, buf, bytes_read) <= 0) break;
            } else {
                if (first_client_pkt) {
                    if (send_with_fragmentation(target_fd, buf, bytes_read) <= 0) break;
                    first_client_pkt = 0;
                } else {
                    if (send(target_fd, buf, bytes_read, 0) <= 0) break;
                }
            }
        }

        int has_data = FD_ISSET(upstream_fd, &readfds);
        if (wss && ws_has_pending(wss)) has_data = 1;

        if (has_data) {
            if (wss) {
                bytes_read = ws_recv_frame(wss, buf, sizeof(buf));
                if (bytes_read <= 0) break;
            } else {
                bytes_read = recv(target_fd, buf, sizeof(buf), 0);
                if (bytes_read <= 0) break;
            }
            if (send(client_fd, buf, bytes_read, 0) <= 0) break;
        }
    }

    if (wss) ws_close(wss);
    if (target_fd >= 0) close(target_fd);
    close(client_fd);
}

void *handle_client(void *client_socket_ptr) {
    int client_fd = *((int *)client_socket_ptr);
    free(client_socket_ptr);

    int nodelay = 1;
    setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof(nodelay));

    unsigned char first_byte;
    if (recv(client_fd, &first_byte, 1, MSG_PEEK) <= 0) {
        close(client_fd);
        return NULL;
    }

    if (first_byte == 0x05) {
        handle_socks5(client_fd);
    } else {
        handle_mtproto_wss(client_fd);
    }

    return NULL;
}

void load_or_generate_secret(char *secret_out) {
    FILE *f = fopen(CONFIG_FILE, "r");
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            char *pos = strstr(line, "\"secret\": \"");
            if (pos) {
                pos += 11;
                char *end = strchr(pos, '"');
                if (end) {
                    *end = '\0';
                    strncpy(secret_out, pos, 63);
                    secret_out[63] = '\0';
                    fclose(f);
                    return;
                }
            }
        }
        fclose(f);
    }

    /* Generate clean 16-byte cryptographically secure random secret */
    unsigned char rand_bytes[16];
    RAND_bytes(rand_bytes, 16);
    for (int i = 0; i < 16; i++) {
        sprintf(secret_out + i * 2, "%02x", rand_bytes[i]);
    }
    secret_out[32] = '\0';

    f = fopen(CONFIG_FILE, "w");
    if (f) {
        fprintf(f, "{\n  \"secret\": \"%s\",\n  \"tcp_fragment\": true,\n  \"direct_fallback\": true\n}\n", secret_out);
        fclose(f);
    }
}

void install_autostart(int argc, char *argv[]) {
    if (geteuid() != 0) {
        printf("[INFO] To configure autostart, the program needs root privileges.\n");
        printf("[INFO] Asking for password via 'doas' or 'sudo'...\n");
        char cmd[1024] = {0};
        if (system("command -v doas > /dev/null 2>&1") == 0) strcat(cmd, "doas ");
        else strcat(cmd, "sudo ");

        char exe_path[512];
        ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path)-1);
        if (len != -1) { exe_path[len] = '\0'; strcat(cmd, exe_path); }
        else strcat(cmd, argv[0]);

        for (int i = 1; i < argc; i++) { strcat(cmd, " "); strcat(cmd, argv[i]); }
        int ret = system(cmd);
        exit(ret == 0 ? 0 : 1);
    }

    char exe_path[512];
#ifdef __FreeBSD__
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1};
    size_t cb = sizeof(exe_path);
    if (sysctl(mib, 4, exe_path, &cb, NULL, 0) != 0) {
        strcpy(exe_path, "/usr/local/bin/tg-ws-proxy");
    }
#else
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path)-1);
    if (len == -1) strcpy(exe_path, "/usr/local/bin/tg-ws-proxy"); else exe_path[len] = '\0';
#endif

    char *user = getenv("SUDO_USER");
    if (!user) user = getenv("DOAS_USER");
    if (!user) user = "root";

    if (access("/run/systemd/system", F_OK) == 0) {
        FILE *f = fopen("/etc/systemd/system/tg-ws-proxy.service", "w");
        if (f) {
            fprintf(f, "[Unit]\nDescription=Telegram WebSocket Proxy\nAfter=network.target\n\n");
            fprintf(f, "[Service]\nType=forking\nUser=%s\n", user);
            fprintf(f, "ExecStart=%s 8080 --daemon\nRestart=always\nRestartSec=3\n\n", exe_path);
            fprintf(f, "[Install]\nWantedBy=multi-user.target\n");
            fclose(f);
            if (system("systemctl daemon-reload && systemctl enable tg-ws-proxy && systemctl start tg-ws-proxy") != 0) {
                proxy_log(1, "[WARN] Failed to fully start systemd service\n");
            }
        }
#ifdef __FreeBSD__
    } else if (access("/etc/rc.d", F_OK) == 0) {
        FILE *f = fopen("/etc/rc.d/tg_ws_proxy", "w");
        if (f) {
            fprintf(f, "#!/bin/sh\n# PROVIDE: tg_ws_proxy\n# REQUIRE: NETWORKING\n\n. /etc/rc.subr\n\nname=\"tg_ws_proxy\"\nrcvar=\"tg_ws_proxy_enable\"\n\ncommand=\"%s\"\ncommand_args=\"8080 --daemon\"\npidfile=\"/var/run/${name}.pid\"\n\nload_rc_config $name\nrun_rc_command \"$1\"\n", exe_path);
            fclose(f);
            chmod("/etc/rc.d/tg_ws_proxy", 0755);
            if (system("sysrc tg_ws_proxy_enable=YES && service tg_ws_proxy start") != 0) {
                proxy_log(1, "[WARN] Failed to start FreeBSD rc service\n");
            }
        }
#endif
    } else if (access("/run/openrc", F_OK) == 0) {
        FILE *f = fopen("/etc/init.d/tg-ws-proxy", "w");
        if (f) {
            fprintf(f, "#!/sbin/openrc-run\n\nname=\"tg-ws-proxy\"\n");
            fprintf(f, "command=\"%s\"\ncommand_args=\"8080 --daemon\"\n", exe_path);
            fprintf(f, "pidfile=\"/run/${RC_SVCNAME}.pid\"\n");
            fprintf(f, "command_user=\"%s\"\n\ndepend() {\n    need net\n}\n", user);
            fclose(f);
            chmod("/etc/init.d/tg-ws-proxy", 0755);
            if (system("rc-update add tg-ws-proxy default && rc-service tg-ws-proxy start") != 0) {
                proxy_log(1, "[WARN] Failed to start OpenRC service\n");
            }
        }
    } else if (access("/etc/sv", F_OK) == 0 || access("/var/service", F_OK) == 0) {
        if (system("mkdir -p /etc/sv/tg-ws-proxy") == 0) {
            FILE *f = fopen("/etc/sv/tg-ws-proxy/run", "w");
            if (f) {
                fprintf(f, "#!/bin/sh\nexec chpst -u %s %s 8080\n", user, exe_path);
                fclose(f);
                chmod("/etc/sv/tg-ws-proxy/run", 0755);
                if (system("ln -s /etc/sv/tg-ws-proxy /var/service/ 2>/dev/null || ln -s /etc/sv/tg-ws-proxy /etc/service/ 2>/dev/null && sv start tg-ws-proxy") != 0) {
                    proxy_log(1, "[WARN] Failed to activate runit service\n");
                }
            }
        }
    } else {
        if (system("mkdir -p /etc/dinit.d") == 0) {
            FILE *f = fopen("/etc/dinit.d/tg-ws-proxy", "w");
            if (f) {
                fprintf(f, "type = bgprocess\ncommand = %s 8080 --daemon\n", exe_path);
                fprintf(f, "run-as = %s\nrestart = true\nsmooth-recovery = true\n", user);
                fclose(f);
                if (system("dinitctl enable tg-ws-proxy && dinitctl start tg-ws-proxy") != 0) {
                    proxy_log(1, "[WARN] Failed to activate dinit service\n");
                }
            }
        }
    }
    printf("[SUCCESS] Service installed!\n");
    exit(0);
}

static void run_self_test(void) {
    printf("[TEST] Testing Cloudflare WSS connectivity across rotating proxy pool...\n");
    int success = 0;
    for (int i = 0; i < 3 && i < CFPROXY_COUNT; i++) {
        char base_domain[256];
        decode_domain(CFPROXY_ENC[i], base_domain, sizeof(base_domain));
        char host[1024];
        snprintf(host, sizeof(host), "kws2.%.240s", base_domain);
        char censored[512];
        censor_domain(host, censored, sizeof(censored));

        printf("[TEST] Testing %s:443 ... ", censored);
        fflush(stdout);

        SSL *ssl = ws_connect(host, 443, host, host, TARGET_PATH, 5);
        if (ssl) {
            printf("PASSED (HTTP 101 WebSocket Upgrade)\n");
            ws_close(ssl);
            success++;
        } else {
            printf("FAILED\n");
        }
    }
    printf("[TEST] Self-test complete: %d/3 nodes verified.\n", success);
    exit(success > 0 ? 0 : 1);
}

int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN);
    srand(time(NULL));

    int port = DEFAULT_PORT;
    char secret[64] = {0};

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--autostart") == 0) install_autostart(argc, argv);
        if (strcmp(argv[i], "--daemon") == 0) run_as_daemon = 1;
        if (strcmp(argv[i], "--test") == 0) run_self_test();
        if (strcmp(argv[i], "--no-fragment") == 0) g_enable_tcp_fragment = 0;
        if (strcmp(argv[i], "--no-fallback") == 0) g_enable_direct_fallback = 0;
        if (strcmp(argv[i], "--cf-worker") == 0 && i + 1 < argc) {
            if (g_custom_workers_count < MAX_CUSTOM_WORKERS) {
                strncpy(g_custom_workers[g_custom_workers_count++], argv[++i], 255);
            }
        }
        if (strcmp(argv[i], "--cf-domain") == 0 && i + 1 < argc) {
            if (g_custom_domains_count < MAX_CUSTOM_DOMAINS) {
                strncpy(g_custom_domains[g_custom_domains_count++], argv[++i], 255);
            }
        }
        if (strcmp(argv[i], "--secret") == 0 && i + 1 < argc) {
            strncpy(secret, argv[++i], sizeof(secret) - 1);
        }
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Telegram WebSocket Proxy (C Edition - Unix)\n");
            printf("Usage: %s [port] [options]\n", argv[0]);
            printf("Options:\n");
            printf("  [port]               Port to listen on (default: 8080)\n");
            printf("  --daemon             Run in background with syslog logging\n");
            printf("  --cf-worker <domain> Add custom Cloudflare worker domain\n");
            printf("  --cf-domain <domain> Add custom Cloudflare proxy domain\n");
            printf("  --secret <hex>       Set proxy secret (32 hex characters)\n");
            printf("  --no-fragment        Disable TCP fragmentation DPI bypass\n");
            printf("  --no-fallback        Disable direct TCP fallback\n");
            printf("  --autostart          Install system service (Systemd/OpenRC/rc.d)\n");
            printf("  --test               Run self-test on Cloudflare WSS pool\n");
            return 0;
        }
        if (argv[i][0] != '-' && i == 1) {
            port = atoi(argv[i]);
            if (port <= 0 || port > 65535) port = DEFAULT_PORT;
        }
    }

    if (secret[0] == '\0') {
        load_or_generate_secret(secret);
    }

    if (run_as_daemon) {
        if (daemon(1, 0) < 0) exit(EXIT_FAILURE);
        openlog("tg-ws-proxy", LOG_PID | LOG_CONS, LOG_DAEMON);
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) exit(EXIT_FAILURE);

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        proxy_log(1, "[ERROR] Bind failed on port %d: %s\n", port, strerror(errno));
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 128) < 0) {
        proxy_log(1, "[ERROR] Listen failed: %s\n", strerror(errno));
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    proxy_log(0, "====================================================\n");
    proxy_log(0, "Telegram Multiplexed Proxy (C Edition - Unix)\n");
    proxy_log(0, "Port: %d | TCP Fragmentation: %s | Pool: 20 CF Nodes\n",
              port, g_enable_tcp_fragment ? "ENABLED" : "DISABLED");
    proxy_log(0, "1. MTProto Proxy Link:\n   tg://proxy?server=127.0.0.1&port=%d&secret=%s\n", port, secret);
    proxy_log(0, "2. SOCKS5 Proxy Link:\n   tg://socks?server=127.0.0.1&port=%d\n", port);
    proxy_log(0, "====================================================\n");

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addrlen = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addrlen);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            continue;
        }

        int *pfd = malloc(sizeof(int));
        if (!pfd) {
            close(client_fd);
            continue;
        }
        *pfd = client_fd;

        pthread_t tid;
        if (pthread_create(&tid, NULL, handle_client, pfd) != 0) {
            free(pfd);
            close(client_fd);
        } else {
            pthread_detach(tid);
        }
    }

    if (run_as_daemon) closelog();
    close(server_fd);
    ws_cleanup();
    return 0;
}
