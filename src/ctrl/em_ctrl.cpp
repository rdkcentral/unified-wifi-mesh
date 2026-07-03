/**
 * Copyright 2023 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/filter.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
#include <cjson/cJSON.h>
#include "em.h"
#include "em_msg.h"
#include "em_ctrl.h"
#include "em_cmd_ctrl.h"
#include "dm_easy_mesh.h"
#include "em_orch_ctrl.h"
#include "util.h"
#include "wifi_util.h"

#ifdef AL_SAP
#include "al_service_access_point.h"
#endif

#define EM_WEBSOCKET_PUSH 1

#ifdef EM_WEBSOCKET_PUSH
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <netdb.h>
#include <time.h>
#include <signal.h>
#include <stdint.h>

/* ================================================================
 * EasyMesh topology streaming over VB-SB WebSocket (wss://)
 * ================================================================ */

/* Message format toggle:
 * EM_TOPO_MSG_FORMAT_PYTHON  — matches xb_topology_client.py envelope
 * Comment out to use the legacy start_id/ordering_id/end_id format */
#define EM_TOPO_MSG_FORMAT_PYTHON 1

#define EM_TOPO_STREAM_URL_SIZE    4096
#define EM_TOPO_STREAM_TOKEN_KEY   "token="
#define EM_TOPO_STREAM_SAT_URL     "https://devprimary.vbautobot.comcast.com:6002/get_sat"
#define EM_TOPO_STREAM_TOKEN_SIZE  4096
#define EM_TOPO_GATEWAY_MAC_SIZE   18

/* Default base URL — SAT token is appended as ?token=<JWT> after fetch */
static char g_em_topo_stream_url[EM_TOPO_STREAM_URL_SIZE] =
    "wss://vb-streamer-api.vb.comcast.com:6100/ws/topology/xb";

static int                g_em_topo_socket_fd     = -1;
static SSL_CTX           *g_em_topo_ssl_ctx       = NULL;
static SSL               *g_em_topo_ssl           = NULL;
static unsigned long long g_em_topo_order_id      = 0;
static char              g_em_topo_gateway_mac[EM_TOPO_GATEWAY_MAC_SIZE] = {0};

typedef struct {
    bool     use_tls;
    char     host[128];
    uint16_t port;
    char     path_query[1024];
} em_topo_url_info_t;

/* --- URL parsing (same logic as parse_csi_stream_url in websocket.c) --- */
static bool em_topo_parse_url(em_topo_url_info_t *info)
{
    const char *url       = g_em_topo_stream_url;
    const char *scheme    = strstr(url, "://");
    const char *host_start, *host_end, *path_start;
    long parsed_port = 6100;

    if (!info) return false;
    memset(info, 0, sizeof(*info));

    if (scheme) {
        info->use_tls = ((size_t)(scheme - url) == 3 && strncmp(url, "wss", 3) == 0);
        host_start = scheme + 3;
    } else {
        info->use_tls  = true;
        host_start = url;
    }

    host_end = host_start;
    while (*host_end && *host_end != ':' && *host_end != '/' && *host_end != '?')
        host_end++;

    {
        size_t hlen = (size_t)(host_end - host_start);
        if (hlen > 0 && hlen < sizeof(info->host)) {
            memcpy(info->host, host_start, hlen);
            info->host[hlen] = '\0';
        }
    }

    if (*host_end == ':') {
        char *ep = NULL;
        long p = strtol(host_end + 1, &ep, 10);
        if (ep != host_end + 1 && p > 0 && p <= 65535) parsed_port = p;
    }
    info->port = (uint16_t)parsed_port;

    path_start = host_end;
    if (*path_start == ':')
        while (*path_start && *path_start != '/' && *path_start != '?')
            path_start++;
    snprintf(info->path_query, sizeof(info->path_query), "%s",
        *path_start ? path_start : "/");
    return (info->host[0] != '\0');
}

static int em_topo_build_url_with_token(const char *token)
{
    char updated[EM_TOPO_STREAM_URL_SIZE] = {0};
    const char *cur = g_em_topo_stream_url;
    const char *tp  = strstr(cur, EM_TOPO_STREAM_TOKEN_KEY);
    int written;

    if (!token || !token[0]) return -1;
    if (tp) {
        size_t prefix_len = (size_t)(tp - cur) + strlen(EM_TOPO_STREAM_TOKEN_KEY);
        const char *suffix = strchr(tp, '&');
        written = snprintf(updated, sizeof(updated), "%.*s%s%s",
            (int)prefix_len, cur, token, suffix ? suffix : "");
    } else {
        const char *sep = strchr(cur, '?') ? "&" : "?";
        written = snprintf(updated, sizeof(updated), "%s%s%s%s",
            cur, sep, EM_TOPO_STREAM_TOKEN_KEY, token);
    }
    if (written <= 0 || (size_t)written >= sizeof(updated)) return -1;
    snprintf(g_em_topo_stream_url, sizeof(g_em_topo_stream_url), "%s", updated);
    return 0;
}

/* --- SAT token fetch via MTLS (same pattern as fetch_latest_csi_stream_token) --- */
static int em_topo_fetch_sat_token(char *token_out, size_t token_out_len)
{
    static char password[256] = {0};
    char curl_cmd[1024] = {0};
    char curl_output[EM_TOPO_STREAM_TOKEN_SIZE] = {0};
    int  curl_exit_code = -1;
    FILE *fp = NULL;
    char line_buf[256] = {0};
    size_t used = 0;

    if (token_out == NULL || token_out_len == 0) {
        em_printfout("[TOPO-WS] em_topo_fetch_sat_token: invalid args (token_out=%p len=%zu)", token_out, token_out_len);
        return -1;
    }

    if (!password[0]) {
        em_printfout("[TOPO-WS] No cached password, running GetConfigFile /tmp/.cfgDynamicSExpki");
        if (system("GetConfigFile /tmp/.cfgDynamicSExpki") != 0) {
            em_printfout("[TOPO-WS] GetConfigFile failed");
            return -1;
        }
        em_printfout("[TOPO-WS] GetConfigFile OK, reading password");
        fp = popen("cat /tmp/.cfgDynamicSExpki", "r");
        if (fp == NULL) {
            em_printfout("[TOPO-WS] popen(cat /tmp/.cfgDynamicSExpki) failed");
            return -1;
        }
        if (!fgets(password, sizeof(password), fp)) {
            em_printfout("[TOPO-WS] fgets password failed");
            pclose(fp);
            return -1;
        }
        pclose(fp); fp = NULL;
        password[strcspn(password, "\r\n")] = '\0';
        em_printfout("[TOPO-WS] Password read OK (len=%zu)", strlen(password));
    } else {
        em_printfout("[TOPO-WS] Using cached password (len=%zu)", strlen(password));
    }

    for (int attempt = 0; attempt < 2; attempt++) {
        int status;
        const char *cert = "/nvram/certs/devicecert_2.pk12";
        snprintf(curl_cmd, sizeof(curl_cmd),
            "curl -s --cert-type P12 --cert %s:%s %s",
            cert, password, EM_TOPO_STREAM_SAT_URL);

        em_printfout("[TOPO-WS] SAT attempt %d: running curl for %s", attempt + 1, EM_TOPO_STREAM_SAT_URL);
        fp = popen(curl_cmd, "r");
        if (fp == NULL) {
            em_printfout("[TOPO-WS] popen(curl) failed: %s", strerror(errno));
            return -1;
        }
        used = 0;
        while (fgets(line_buf, sizeof(line_buf), fp)) {
            size_t ll = strlen(line_buf);
            if (used + ll >= sizeof(curl_output) - 1) break;
            memcpy(curl_output + used, line_buf, ll); used += ll;
        }
        curl_output[used] = '\0';
        status = pclose(fp); fp = NULL;
        curl_exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        em_printfout("[TOPO-WS] curl exit_code=%d output_len=%zu", curl_exit_code, used);

        if (curl_exit_code == 0 && used > 0) {
            while (used > 0 && (curl_output[used-1] == '\n' ||
                                curl_output[used-1] == '\r' ||
                                curl_output[used-1] == ' '))
                curl_output[--used] = '\0';
            if (used > 0 && curl_output[0] == '<') {
                em_printfout("[TOPO-WS] SAT endpoint returned HTML error page (gateway error), treating as failure");
                break;
            }
            /* Strip surrounding double quotes if the server wrapped the token */
            if (used >= 2 && curl_output[0] == '"' && curl_output[used-1] == '"') {
                memmove(curl_output, curl_output + 1, used - 2);
                used -= 2;
                curl_output[used] = '\0';
                em_printfout("[TOPO-WS] Stripped surrounding quotes from token (new len=%zu)", used);
            }
            if (used > 0 && used < token_out_len) {
                memcpy(token_out, curl_output, used + 1);
                em_printfout("[TOPO-WS] SAT token fetched OK (len=%zu)", used);
                return 0;
            }
            em_printfout("[TOPO-WS] curl output empty or too large (used=%zu max=%zu)", used, token_out_len);
        } else {
            em_printfout("[TOPO-WS] curl failed or empty response (exit_code=%d used=%zu)", curl_exit_code, used);
        }

        if (curl_exit_code == 58 && attempt == 0) {
            em_printfout("[TOPO-WS] PKCS12 password stale (curl error 58), refreshing and retrying");
            memset(password, 0, sizeof(password));
            if (system("GetConfigFile /tmp/.cfgDynamicSExpki") != 0) {
                em_printfout("[TOPO-WS] GetConfigFile retry failed");
                return -1;
            }
            fp = popen("cat /tmp/.cfgDynamicSExpki", "r");
            if (fp == NULL || !fgets(password, sizeof(password), fp)) {
                em_printfout("[TOPO-WS] Password retry read failed");
                if (fp) pclose(fp);
                return -1;
            }
            pclose(fp); fp = NULL;
            password[strcspn(password, "\r\n")] = '\0';
            em_printfout("[TOPO-WS] Password refreshed OK, retrying curl");
            continue;
        }
        break;
    }
    em_printfout("[TOPO-WS] SAT token fetch failed after all attempts");
    return -1;
}

/* --- RFC 6455 WebSocket text frame encoding (client-to-server, masked) --- */
static int ws_send_frame(const char *payload, size_t payload_len)
{
    unsigned char header[14];
    size_t header_len = 0;
    unsigned char mask[4];
    uint32_t mask_val;
    unsigned char *masked = NULL;
    int ret;

    if (!payload || payload_len == 0) return -1;

    /* Random 4-byte masking key (required for client frames per RFC 6455 §5.3) */
    mask_val = ((uint32_t)rand() << 16) ^ (uint32_t)rand();
    mask[0] = (mask_val >> 24) & 0xFF;
    mask[1] = (mask_val >> 16) & 0xFF;
    mask[2] = (mask_val >>  8) & 0xFF;
    mask[3] =  mask_val        & 0xFF;

    /* FIN=1, RSV=0, opcode=0x1 (text frame) */
    header[0] = 0x81;
    if (payload_len <= 125) {
        header[1] = 0x80 | (unsigned char)payload_len;
        header_len = 2;
    } else if (payload_len <= 65535) {
        header[1] = 0x80 | 126;
        header[2] = (unsigned char)((payload_len >> 8) & 0xFF);
        header[3] = (unsigned char)( payload_len       & 0xFF);
        header_len = 4;
    } else {
        header[1] = 0x80 | 127;
        header[2] = 0; header[3] = 0; header[4] = 0; header[5] = 0;
        header[6] = (unsigned char)((payload_len >> 24) & 0xFF);
        header[7] = (unsigned char)((payload_len >> 16) & 0xFF);
        header[8] = (unsigned char)((payload_len >>  8) & 0xFF);
        header[9] = (unsigned char)( payload_len        & 0xFF);
        header_len = 10;
    }
    /* Append masking key to header */
    header[header_len++] = mask[0];
    header[header_len++] = mask[1];
    header[header_len++] = mask[2];
    header[header_len++] = mask[3];

    /* Mask the payload */
    masked = (unsigned char *)malloc(payload_len);
    if (!masked) {
        em_printfout("[TOPO-WS] ws_send_frame: malloc failed (%zu bytes)", payload_len);
        return -1;
    }
    for (size_t i = 0; i < payload_len; i++)
        masked[i] = ((unsigned char)payload[i]) ^ mask[i & 3];

    /* Send header then masked payload */
    ret = g_em_topo_ssl ? SSL_write(g_em_topo_ssl, header, (int)header_len)
                        : (int)send(g_em_topo_socket_fd, header, header_len, MSG_NOSIGNAL);
    if (ret <= 0) {
        em_printfout("[TOPO-WS] ws_send_frame: header write failed (ret=%d)", ret);
        free(masked);
        return -1;
    }
    ret = g_em_topo_ssl ? SSL_write(g_em_topo_ssl, masked, (int)payload_len)
                        : (int)send(g_em_topo_socket_fd, masked, payload_len, MSG_NOSIGNAL);
    free(masked);
    if (ret <= 0) {
        em_printfout("[TOPO-WS] ws_send_frame: payload write failed (ret=%d)", ret);
        return -1;
    }
    return 0;
}

static void em_topo_close(void)
{
    em_printfout("[TOPO-WS] Closing connection (fd=%d ssl=%p)", g_em_topo_socket_fd, (void *)g_em_topo_ssl);
    if (g_em_topo_ssl) {
        em_printfout("[TOPO-WS] SSL_shutdown + SSL_free");
        SSL_shutdown(g_em_topo_ssl);
        SSL_free(g_em_topo_ssl);
        g_em_topo_ssl = NULL;
    }
    if (g_em_topo_ssl_ctx) {
        em_printfout("[TOPO-WS] SSL_CTX_free");
        SSL_CTX_free(g_em_topo_ssl_ctx);
        g_em_topo_ssl_ctx = NULL;
    }
    if (g_em_topo_socket_fd >= 0) {
        em_printfout("[TOPO-WS] closing socket fd=%d", g_em_topo_socket_fd);
        close(g_em_topo_socket_fd);
        g_em_topo_socket_fd = -1;
    }
    em_printfout("[TOPO-WS] Connection closed");
}

/* --- Entry point: called from publish_network_topology() --- */
static void em_topo_stream_send_topology(const char *topology_json)
{
    char          *envelope_str = NULL;
    char           ts_buf[64]   = {0};
    struct timeval tv_now       = {0};

    if (topology_json == NULL) {
        em_printfout("[TOPO-WS] topology_json is NULL, skipping");
        return;
    }

    g_em_topo_order_id++;
    gettimeofday(&tv_now, NULL);

    cJSON *envelope = cJSON_CreateObject();
    if (envelope == NULL) {
        em_printfout("[TOPO-WS] cJSON_CreateObject failed");
        return;
    }

#ifdef EM_TOPO_MSG_FORMAT_PYTHON
    /* Python-compatible format: {"type","gatewayMac","timestamp"(ISO8601),"payload"(object)} */
    {
        struct tm tm_utc;
        gmtime_r(&tv_now.tv_sec, &tm_utc);
        strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%dT%H:%M:%S+00:00", &tm_utc);
    }
    cJSON *payload_obj = cJSON_Parse(topology_json);
    if (payload_obj == NULL) {
        em_printfout("[TOPO-WS] topology_json parse failed, sending as string");
        cJSON_AddStringToObject(envelope, "type",       "topology");
        cJSON_AddStringToObject(envelope, "gatewayMac", g_em_topo_gateway_mac);
        cJSON_AddStringToObject(envelope, "timestamp",  ts_buf);
        cJSON_AddStringToObject(envelope, "payload",    topology_json);
    } else {
        cJSON_AddStringToObject(envelope, "type",       "topology");
        cJSON_AddStringToObject(envelope, "gatewayMac", g_em_topo_gateway_mac);
        cJSON_AddStringToObject(envelope, "timestamp",  ts_buf);
        cJSON_AddItemToObject(envelope,   "payload",    payload_obj);
    }
#else
    /* Legacy format: {"start_id","ordering_id","app_type","timestamp"(mmddyyHHMMSS),"payload"(string),"end_id"} */
    {
        struct tm tm_now;
        char id_buf[32] = {0};
        localtime_r(&tv_now.tv_sec, &tm_now);
        strftime(ts_buf, sizeof(ts_buf), "%m%d%y%H%M%S", &tm_now);
        snprintf(id_buf, sizeof(id_buf), "%llu", g_em_topo_order_id);
        cJSON_AddStringToObject(envelope, "start_id",    id_buf);
        cJSON_AddStringToObject(envelope, "ordering_id", id_buf);
        cJSON_AddStringToObject(envelope, "app_type",    "easyMesh");
        cJSON_AddStringToObject(envelope, "timestamp",   ts_buf);
        cJSON_AddStringToObject(envelope, "payload",     topology_json);
        cJSON_AddStringToObject(envelope, "end_id",      id_buf);
    }
#endif

    envelope_str = cJSON_PrintUnformatted(envelope);
    cJSON_Delete(envelope);
    if (envelope_str == NULL) {
        em_printfout("[TOPO-WS] cJSON_PrintUnformatted failed");
        return;
    }

    em_printfout("[TOPO-WS] Sending topology #%llu ts=%s mac=%s", g_em_topo_order_id, ts_buf, g_em_topo_gateway_mac);

    /* ---- Connect (only if not already up) ---- */
    if (g_em_topo_socket_fd < 0) {
        em_printfout("[TOPO-WS] No active connection, starting connect sequence");
        em_printfout("[TOPO-WS] Target URL: %s", g_em_topo_stream_url);

        char token[EM_TOPO_STREAM_TOKEN_SIZE] = {0};
        em_printfout("[TOPO-WS] Fetching SAT token from %s", EM_TOPO_STREAM_SAT_URL);
        if (em_topo_fetch_sat_token(token, sizeof(token)) == 0) {
            em_printfout("[TOPO-WS] SAT token fetched OK (len=%zu)", strlen(token));
            em_topo_build_url_with_token(token);
            em_printfout("[TOPO-WS] URL updated with token: %s", g_em_topo_stream_url);
        } else {
            em_printfout("[TOPO-WS] SAT token fetch failed, proceeding without token");
        }

        em_topo_url_info_t info;
        char port_str[8] = {0};
        struct addrinfo hints = {}, *result = NULL;

        em_printfout("[TOPO-WS] Parsing URL: %s", g_em_topo_stream_url);
        if (!em_topo_parse_url(&info)) {
            em_printfout("[TOPO-WS] URL parse failed");
            goto cleanup;
        }
        snprintf(port_str, sizeof(port_str), "%u", (unsigned int)info.port);
        em_printfout("[TOPO-WS] Parsed — host=%s port=%s path=%s tls=%d",
            info.host, port_str, info.path_query, info.use_tls);

        em_printfout("[TOPO-WS] Resolving DNS for %s", info.host);
        hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(info.host, port_str, &hints, &result) != 0 || !result) {
            em_printfout("[TOPO-WS] DNS lookup failed for %s", info.host);
            goto cleanup;
        }
        em_printfout("[TOPO-WS] DNS resolved OK, attempting TCP connect to %s:%s", info.host, port_str);

        for (struct addrinfo *rp = result; rp; rp = rp->ai_next) {
            int fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (fd < 0) {
                em_printfout("[TOPO-WS] socket() failed: %s", strerror(errno));
                continue;
            }
            if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
                g_em_topo_socket_fd = fd;
                break;
            }
            em_printfout("[TOPO-WS] connect() failed: %s", strerror(errno));
            close(fd);
        }
        freeaddrinfo(result);

        if (g_em_topo_socket_fd < 0) {
            em_printfout("[TOPO-WS] TCP connect to %s:%s failed", info.host, port_str);
            goto cleanup;
        }
        em_printfout("[TOPO-WS] TCP connected to %s:%s (fd=%d)", info.host, port_str, g_em_topo_socket_fd);

        if (info.use_tls) {
            em_printfout("[TOPO-WS] Starting TLS setup");
            SSL_library_init();
            g_em_topo_ssl_ctx = SSL_CTX_new(TLS_client_method());
            if (g_em_topo_ssl_ctx == NULL) {
                em_printfout("[TOPO-WS] SSL_CTX_new failed");
                em_topo_close(); goto cleanup;
            }
            em_printfout("[TOPO-WS] SSL_CTX created OK");

            g_em_topo_ssl = SSL_new(g_em_topo_ssl_ctx);
            if (g_em_topo_ssl == NULL) {
                em_printfout("[TOPO-WS] SSL_new failed");
                em_topo_close(); goto cleanup;
            }
            em_printfout("[TOPO-WS] SSL object created OK");

            SSL_set_tlsext_host_name(g_em_topo_ssl, info.host);
            SSL_set_fd(g_em_topo_ssl, g_em_topo_socket_fd);
            em_printfout("[TOPO-WS] Calling SSL_connect to %s", info.host);
            if (SSL_connect(g_em_topo_ssl) != 1) {
                em_printfout("[TOPO-WS] SSL_connect failed (SSL error=%d)", SSL_get_error(g_em_topo_ssl, -1));
                em_topo_close(); goto cleanup;
            }
            em_printfout("[TOPO-WS] TLS handshake OK — cipher=%s", SSL_get_cipher(g_em_topo_ssl));
        }

        char req[2048] = {0}, resp[1024] = {0};
        unsigned char ws_key_bytes[16];
        char ws_key_b64[25] = {0};
        RAND_bytes(ws_key_bytes, sizeof(ws_key_bytes));
        EVP_EncodeBlock((unsigned char *)ws_key_b64, ws_key_bytes, sizeof(ws_key_bytes));
        snprintf(req, sizeof(req),
            "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n",
            info.path_query, info.host, ws_key_b64);
        em_printfout("[TOPO-WS] Sending WS upgrade request (%zu bytes):\n%s", strlen(req), req);

        int w = g_em_topo_ssl ? SSL_write(g_em_topo_ssl, req, (int)strlen(req))
                               : (int)send(g_em_topo_socket_fd, req, strlen(req), 0);
        em_printfout("[TOPO-WS] WS upgrade write returned %d (expected %zu)", w, strlen(req));
        if (w <= 0) {
            em_printfout("[TOPO-WS] WS upgrade write failed");
            em_topo_close(); goto cleanup;
        }

        int r = g_em_topo_ssl ? SSL_read(g_em_topo_ssl, resp, (int)sizeof(resp) - 1)
                               : (int)recv(g_em_topo_socket_fd, resp, sizeof(resp) - 1, 0);
        em_printfout("[TOPO-WS] WS upgrade read returned %d bytes", r);
        if (r <= 0) {
            em_printfout("[TOPO-WS] WS upgrade read failed");
            em_topo_close(); goto cleanup;
        }
        resp[r] = '\0';
        em_printfout("[TOPO-WS] WS upgrade response: %.120s", resp);

        if (!strstr(resp, "101")) {
            em_printfout("[TOPO-WS] WS upgrade rejected — no 101 in response");
            em_topo_close(); goto cleanup;
        }
        em_printfout("[TOPO-WS] WS upgrade OK — connected to %s:%s%s", info.host, port_str, info.path_query);
    } else {
        em_printfout("[TOPO-WS] Reusing existing connection (fd=%d)", g_em_topo_socket_fd);
    }

    /* ---- Send ---- */
    {
        size_t jlen = strlen(envelope_str);
        em_printfout("[TOPO-WS] Sending DataFrame #%llu len=%zu", g_em_topo_order_id, jlen);
        em_printfout("[TOPO-WS] DataFrame content: %s", envelope_str);
        int n = ws_send_frame(envelope_str, jlen);
        if (n == 0) {
            em_printfout("[TOPO-WS] DataFrame sent successfully #%llu len=%zu", g_em_topo_order_id, jlen);
        } else {
            em_printfout("[TOPO-WS] Send failed #%llu — closing connection", g_em_topo_order_id);
            em_topo_close();
        }
    }

cleanup:
    free(envelope_str);
}

#endif /* EM_WEBSOCKET_PUSH */

em_ctrl_t *em_ctrl_t::s_em_ctrl = NULL;
em_network_topo_t *g_network_topology = NULL;

#ifdef AL_SAP
AlServiceAccessPoint* g_sap;
MacAddress g_al_mac_sap;
#endif

void em_ctrl_t::handle_dm_commit(em_bus_event_t *evt)
{
    em_commit_info_t *info;
    mac_addr_str_t  mac_str;
    dm_easy_mesh_t *dm, new_dm;
    dm_easy_mesh_t *ref_dm;
    dm_network_t *net, *pnet;
    dm_network_ssid_t *net_ssid, *pnet_ssid;

    info = &evt->u.commit;

    dm_easy_mesh_t::macbytes_to_string(info->mac, mac_str);
    dm = m_data_model.get_data_model(info->net_id, info->mac);
    if (dm == NULL) {
        new_dm.init();
        em_printfout("data model mac: %s and info->net_id : %s\n",mac_str, info->net_id);
        memcpy(new_dm.m_device.m_device_info.id.dev_mac, info->mac, sizeof(mac_addr_t));
        memcpy(new_dm.m_device.m_device_info.intf.mac, info->mac, sizeof(mac_addr_t));
        strncpy(new_dm.m_device.m_device_info.id.net_id, info->net_id, strlen(info->net_id) + 1);
        em_printfout("data model dev mac: %s and int.mac: %s\n", util::mac_to_string(new_dm.m_device.m_device_info.id.dev_mac).c_str(),
            util::mac_to_string(new_dm.m_device.m_device_info.intf.mac).c_str());

        if ((net = m_data_model.get_network(info->net_id)) != NULL) {
            em_printfout("net id: %s", net->m_net_info.id);
            pnet = new_dm.get_network();
            *pnet = *net;

            ref_dm = get_data_model(net->m_net_info.id, net->m_net_info.ctrl_id.mac);
            assert(ref_dm != NULL);
            new_dm.set_num_network_ssid(ref_dm->get_num_network_ssid());
            for (unsigned int i = 0; i < ref_dm->get_num_network_ssid(); i++) {
                pnet_ssid = new_dm.get_network_ssid(i);
                net_ssid = ref_dm->get_network_ssid(i);
                *pnet_ssid = *net_ssid;
            }
        }
        em_printfout("data model dev mac: %s and int.mac: %s\n", util::mac_to_string(new_dm.m_device.m_device_info.id.dev_mac).c_str(),
            util::mac_to_string(new_dm.m_device.m_device_info.intf.mac).c_str());
        new_dm.set_db_cfg_param(db_cfg_type_device_list_update, "");
        m_data_model.set_config(&new_dm);
    }
}

void em_ctrl_t::handle_client_steer(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_command_steer(evt, pcmd)) == 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, static_cast<unsigned int> (num)) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    }
}

void em_ctrl_t::handle_client_disassoc(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_command_disassoc(evt, pcmd)) == 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, static_cast<unsigned int> (num)) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    }
}

void em_ctrl_t::handle_client_btm(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_command_btm(evt, pcmd)) == 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, static_cast<unsigned int> (num)) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    }
}

void em_ctrl_t::handle_start_dpp(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_dpp_start(evt, pcmd)) == 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, static_cast<unsigned int> (num)) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    } 

}

void em_ctrl_t::handle_set_channel_list(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_set_channel(evt, pcmd)) == 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, static_cast<unsigned int> (num)) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    } 

}

void em_ctrl_t::handle_scan_channel_list(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_scan_channel(evt, pcmd)) == 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, static_cast<unsigned int> (num)) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    } 

}

void em_ctrl_t::handle_set_policy(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_set_policy(evt, pcmd)) == 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, static_cast<unsigned int> (num)) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    }
}

void em_ctrl_t::handle_config_renew(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;
    
    if ((num = m_data_model.analyze_config_renew(evt, pcmd)) > 0) {
        m_orch->submit_commands(pcmd, static_cast<unsigned int> (num));
    }
}

void em_ctrl_t::handle_m2_tx(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;
    
    if ((num = m_data_model.analyze_m2_tx(evt, pcmd)) > 0) {
        m_orch->submit_commands(pcmd, static_cast<unsigned int> (num));
    }
}

void em_ctrl_t::handle_sta_assoc_event(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;
    
    if ((num = m_data_model.analyze_sta_assoc_event(evt, pcmd)) > 0) {
        m_orch->submit_commands(pcmd, static_cast<unsigned int> (num));
    }
}

void em_ctrl_t::handle_set_radio(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_set_radio(evt, pcmd)) == 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, static_cast<unsigned int> (num)) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    } 
}

void em_ctrl_t::handle_set_ssid_list(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num, ret;

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((ret = m_data_model.analyze_set_ssid(evt, pcmd)) <= 0) {
        if (ret == EM_PARSE_ERR_NO_CHANGE) {
        	m_ctrl_cmd->send_result(em_cmd_out_status_no_change);
		} else {
        	m_ctrl_cmd->send_result(em_cmd_out_status_invalid_input);
		}
    } else if (m_orch->submit_commands(pcmd, static_cast<unsigned int> (num = ret)) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    } 

}

void em_ctrl_t::handle_remove_device(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_remove_device(evt, pcmd)) == 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, static_cast<unsigned int> (num)) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    } 

}

void em_ctrl_t::handle_get_dev_test(em_bus_event_t *evt)
{
    em_cmd_params_t params = evt->params;
    char *temp = NULL;
    bool teststatus = false;

    if (params.u.args.num_args < 1) {
        m_ctrl_cmd->send_result(em_cmd_out_status_invalid_input);
        return;
    }

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
    }

    if ((temp = strstr(evt->u.subdoc.name, "update")) != NULL) {
	dev_test.encode(&evt->u.subdoc, m_em_map, true, false);
    } else {
	   
           teststatus = m_orch->get_dev_test_status();
	   dev_test.encode(&evt->u.subdoc, m_em_map, false, teststatus);
    }
    evt->data_len = static_cast<unsigned int> (strlen(evt->u.subdoc.buff)) + 1;
    m_ctrl_cmd->copy_bus_event(evt);
    m_ctrl_cmd->send_result(em_cmd_out_status_success);
}

void em_ctrl_t::handle_set_dev_test(em_bus_event_t *evt)
{

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else {
	dev_test.analyze_set_dev_test(evt, m_em_map);
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    }

}

void em_ctrl_t::handle_get_dm_data(em_bus_event_t *evt)
{           
    em_cmd_params_t params = evt->params;
        
    //em_cmd_t::dump_bus_event(evt);
    if (params.u.args.num_args < 1) {
        m_ctrl_cmd->send_result(em_cmd_out_status_invalid_input);
        return;
    }

    m_data_model.get_config(params.u.args.args[1], &evt->u.subdoc);
	evt->data_len = static_cast<unsigned int> (strlen(evt->u.subdoc.buff)) + 1;
    m_ctrl_cmd->copy_bus_event(evt);
    m_ctrl_cmd->send_result(em_cmd_out_status_success);
}        

void em_ctrl_t::handle_reset(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num = 0;
	
    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_reset(evt, pcmd)) == 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, static_cast<unsigned int> (num)) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    }

}

void em_ctrl_t::handle_mld_reconfig(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_mld_reconfig(pcmd)) == 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, static_cast<unsigned int> (num)) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    }
}

void em_ctrl_t::handle_radio_metrics_req()
{

}

void em_ctrl_t::handle_ap_metrics_req()
{

}

void em_ctrl_t::handle_unassoc_sta_metrics_query(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;

    if (m_orch->is_cmd_type_in_progress(evt) == true) {
        m_ctrl_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_unassoc_sta_metrics_query(evt, pcmd)) == 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, static_cast<unsigned int> (num)) > 0) {
        m_ctrl_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_ctrl_cmd->send_result(em_cmd_out_status_not_ready);
    }
}

void em_ctrl_t::handle_client_metrics_req()
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;

    if ((num = m_data_model.analyze_sta_link_metrics(pcmd)) > 0) {
        m_orch->submit_commands(pcmd, static_cast<unsigned int> (num));
    }
}

void em_ctrl_t::handle_bsta_cap_req(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    int num;

    if ((num = m_data_model.analyze_bsta_cap_req(evt, pcmd)) > 0) {
        m_orch->submit_commands(pcmd, static_cast<unsigned int> (num));
    }
}

void em_ctrl_t::handle_link_stats_alarm_report(em_bus_event_t *evt)
{
    em_subdoc_info_t *info = &evt->u.subdoc;
    wifi_bus_desc_t *desc = NULL;
    char *str = NULL;
    raw_data_t raw;

    snprintf(info->name, sizeof(info->name), "alarm_report");

    cJSON *parent = cJSON_CreateObject();
    em_printfout("Getting STAList for alarm report\n");
    m_data_model.get_sta_config(parent, const_cast<char*>(GLOBAL_NET_ID), em_get_sta_list_reason_alarm_report, info->buff);

    //publish to orch
    if((desc = get_bus_descriptor()) == NULL) {
        em_printfout("descriptor is null");
        cJSON_Delete(parent);
        return;
    }

    if (parent == NULL) {
        em_printfout("Failed to create or populate JSON object");
        return;
    }

    str = cJSON_Print(parent);
    em_printfout("Publishing Link Report Json:\n%s",str);

	raw.data_type    = bus_data_type_string;
    raw.raw_data.bytes = reinterpret_cast<unsigned char *> (str);
    raw.raw_data_len = static_cast<unsigned int> (strlen(str));

    if (desc->bus_event_publish_fn(m_data_model.get_bus_hdl(), DEVICE_WIFI_DATAELEMENTS_NETWORK_NODE_LINKSTATS_ALARM, &raw)== 0) {
        em_printfout("Link Stats Alarm published successfull");
    } else {
        em_printfout("Link Stats Alarm publish fail");
    }

    cJSON_Delete(parent);
}

void em_ctrl_t::handle_dirty_dm()
{
	m_data_model.handle_dirty_dm();
}

void em_ctrl_t::handle_5s_tick()
{
	//handle_client_metrics_req();
}

void em_ctrl_t::handle_2s_tick()
{

}

void em_ctrl_t::handle_1s_tick()
{

}

void em_ctrl_t::handle_250ms_tick()
{
    handle_dirty_dm();
    m_orch->handle_timeout();
}

void em_ctrl_t::input_listener()
{
    em_long_string_t str;

    // the listener must block on inputs (rbus or pipe or other ipc messages)
    io(str, false);
}

void em_ctrl_t::handle_nb_event(em_nb_event_t *evt)
{
    bus_resp_get_t *resp = static_cast<bus_resp_get_t *> (calloc(1, sizeof(*resp)));
    assert(resp != NULL);
    resp->id = evt->id;

    switch (evt->type) {
        case NB_REQTYPE_GET: {
            char *name = evt->u.get.name;
            raw_data_t *property = static_cast<raw_data_t *> (evt->u.get.property);
            bus_get_handler_t cb = reinterpret_cast<bus_get_handler_t>(evt->cb);
            /* TODO: sending property only for now */
            resp->rc = cb(name, property, NULL);
        } break;
#if 0
        case NB_REQTYPE_METHOD: {
            const char *method = evt->u.method.method;
            rbusObject_t in = static_cast<rbusObject_t> (evt->u.method.in);
            rbusObject_t out = static_cast<rbusObject_t> (evt->u.method.out);
            rbusMethodAsyncHandle_t async = static_cast<rbusMethodAsyncHandle_t> (evt->u.method.async);
            rbusMethodHandler_t cb = (rbusMethodHandler_t) evt->cb;
            resp->rc = cb(NULL, method, in, out, async);
        } break;
#endif
        default:
            break;
    }

    uintptr_t buf = reinterpret_cast<uintptr_t>(resp);
    ssize_t len = write(m_data_model.m_nb_pipe_wr, &buf, sizeof(buf));
    assert(len == sizeof(buf));
}

void em_ctrl_t::handle_bus_event(em_bus_event_t *evt)
{
    switch (evt->type) {
        case em_bus_event_type_reset:
            handle_reset(evt);
            break;

        case em_bus_event_type_dev_test:
	    handle_get_dev_test(evt);
	    break;

	case em_bus_event_type_set_dev_test:
	    handle_set_dev_test(evt);
	    break;

        case em_bus_event_type_get_network:
        case em_bus_event_type_get_ssid:
        case em_bus_event_type_get_channel:
        case em_bus_event_type_get_device:
        case em_bus_event_type_get_radio:
        case em_bus_event_type_get_bss:
        case em_bus_event_type_get_sta:
        case em_bus_event_type_get_policy:
        case em_bus_event_type_scan_result:
        case em_bus_event_type_get_mld_config:
        case em_bus_event_type_get_reset:
            handle_get_dm_data(evt);
            break;

        case em_bus_event_type_set_radio:
            handle_set_radio(evt);  
            break;

        case em_bus_event_type_set_ssid:
            handle_set_ssid_list(evt);  
            break;

        case em_bus_event_type_remove_device:
            handle_remove_device(evt);
            break;
        
        case em_bus_event_type_set_channel:
            handle_set_channel_list(evt);
            break;

        case em_bus_event_type_scan_channel:
            handle_scan_channel_list(evt);
            break;

        case em_bus_event_type_set_policy:
            handle_set_policy(evt);
            break;

        case em_bus_event_type_start_dpp:
            handle_start_dpp(evt);  
            break;

        case em_bus_event_type_steer_sta:
            handle_client_steer(evt);   
            break;

        case em_bus_event_type_disassoc_sta:
            handle_client_disassoc(evt);
            break;

        case em_bus_event_type_btm_sta:
            handle_client_btm(evt);
            break;

        case em_bus_event_type_dm_commit:
            handle_dm_commit(evt);
            break;

        case em_bus_event_type_m2_tx:
            handle_m2_tx(evt);
            break;

        case em_bus_event_type_cfg_renew:
			handle_config_renew(evt);
			break;

		case em_bus_event_type_sta_assoc:
			handle_sta_assoc_event(evt);
			break;

        case em_bus_event_type_mld_reconfig:
			handle_mld_reconfig(evt);
			break;

        case em_bus_event_type_bsta_cap_req:
            handle_bsta_cap_req(evt);
            break;

        case em_bus_event_type_link_quality_report:
           handle_link_stats_alarm_report(evt);
           break;

	case em_bus_event_type_unassoc_sta_query:
           handle_unassoc_sta_metrics_query(evt);
           break;

        default:
            break;
    }
}

void em_ctrl_t::handle_event(em_event_t *evt)
{
    switch(evt->type) {
        case em_event_type_bus:
            handle_bus_event(&evt->u.bevt);
            break;

        case em_event_type_nb:
            handle_nb_event(&evt->u.nevt);
            break;

        default:
            break;
    }

}

void em_ctrl_t::publish_network_topology()
{
    assert(g_network_topology != NULL);

	wifi_bus_desc_t *desc = NULL;
    cJSON *parent = NULL;
    char *str = NULL;
    raw_data_t raw;
    dm_easy_mesh_ctrl_t *dm_ctrl = NULL;

    if((desc = get_bus_descriptor()) == NULL) {
        printf("%s:%d descriptor is null\n", __func__, __LINE__);
    }

    parent = cJSON_CreateObject();
    dm_ctrl = reinterpret_cast<dm_easy_mesh_ctrl_t *>(get_data_model(GLOBAL_NET_ID));
    dm_ctrl->get_network_config(parent, const_cast<char*>(GLOBAL_NET_ID));

    str = cJSON_Print(parent);
    em_printfout("    ===============Publish Network Topology Json:\n%s\n===============\n",str);

	raw.data_type    = bus_data_type_string;
    raw.raw_data.bytes = reinterpret_cast<unsigned char *> (str);
    raw.raw_data_len = static_cast<unsigned int> (strlen(str));

    if (desc->bus_event_publish_fn(m_data_model.get_bus_hdl(), const_cast<char*>(DEVICE_WIFI_DATAELEMENTS_NETWORK_TOPOLOGY), &raw)== 0) {
        em_printfout("Topology published successfull");
    } else {
        em_printfout("Topology publish fail");
    }

#ifdef EM_WEBSOCKET_PUSH
    em_topo_stream_send_topology(str);
#endif

#if 0
    //Test code here
    // if (desc->bus_event_subs_fn(&m_bus_hdl, DEVICE_WIFI_DATAELEMENTS_NETWORK_NODE_CFG_POLICY, (void *)&em_agent_t::onewifi_cb, NULL, 0) != 0) {
    //     printf("%s:%d bus get failed\n", __func__, __LINE__);
    //     return;
    // }
    em_printfout("\n%s:%d TEST_POLICY_CFG start\n", __func__, __LINE__);

    /* Read policy JSON from /nik/orch/policy.json and publish it */
    const char *policy_path = "/nik/orch/policy.json";
    FILE *fp = fopen(policy_path, "rb");
    if (!fp) {
        printf("%s:%d Failed to open %s: %s\n", __func__, __LINE__, policy_path, strerror(errno));
    } else {
        if (fseek(fp, 0, SEEK_END) != 0) {
            printf("%s:%d fseek failed\n", __func__, __LINE__);
            fclose(fp);
        } else {
            long fsize = ftell(fp);
            rewind(fp);
            if (fsize <= 0) {
                printf("%s:%d Empty or invalid file size: %ld\n", __func__, __LINE__, fsize);
                fclose(fp);
            } else {
                char *buf = (char*)malloc((size_t)fsize + 1);
                if (!buf) {
                    printf("%s:%d malloc failed\n", __func__, __LINE__);
                    fclose(fp);
                } else {
                    size_t read = fread(buf, 1, (size_t)fsize, fp);
                    buf[read] = '\0';
                    fclose(fp);

                    printf("%s:%d Read %zu bytes from %s:\n%s\n", __func__, __LINE__, read, policy_path, buf);

                    raw_data_t raw;
                    memset(&raw, 0, sizeof(raw));
                    raw.data_type = bus_data_type_string;
                    raw.raw_data.bytes = reinterpret_cast<unsigned char*>(buf);
                    raw.raw_data_len = static_cast<unsigned int>(read);

                    if (desc->bus_event_publish_fn(m_data_model.get_bus_hdl(), DEVICE_WIFI_DATAELEMENTS_NETWORK_NODE_CFG_POLICY, &raw) == 0) {
                    //if (desc->bus_set_fn(m_data_model.get_bus_hdl(), DEVICE_WIFI_DATAELEMENTS_NETWORK_NODE_CFG_POLICY, &raw) == 0) {
                        printf("%s:%d Policy published successfully\n", __func__, __LINE__);
                    } else {
                        printf("%s:%d Policy publish failed\n", __func__, __LINE__);
                    }

                    free(buf);
                }
            }
        }
    }
#endif
}

int em_ctrl_t::data_model_init(const char *data_model_path)
{
    em_t *em = NULL;
    em_interface_t *intf;
    dm_easy_mesh_t *dm;
    mac_addr_str_t  mac_str;

    m_ctrl_cmd = new em_cmd_ctrl_t();
    if (m_ctrl_cmd->init() != 0) {
        printf("%s:%d: ctrl command init failed\n", __func__, __LINE__);
        return 0;
    }
    
    if (m_data_model.init(data_model_path, this) != 0) {
        printf("%s:%d: data model init failed\n", __func__, __LINE__);
        return 0;
    }

    intf = m_data_model.get_ctrl_al_interface(const_cast<char*>(GLOBAL_NET_ID));
	if (intf == NULL) {
		printf("%s:%d: data model init failed could not find netid\n", __func__, __LINE__);
		return 0;
	}
    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (intf->mac), mac_str);

    if ((dm = get_data_model(GLOBAL_NET_ID, intf->mac)) == NULL) {
        printf("%s:%s:%d: Could not find data model for mac:%s\n", __FILE__, __func__, __LINE__, mac_str);
    } else {
        //printf("%s:%s:%d: Data model found, creating node for mac:%s\n", __FILE__, __func__, __LINE__, mac_str);
            //dm->print_config();

        if ((em = create_node(intf, em_freq_band_unknown, dm, true, em_profile_type_3, em_service_type_ctrl)) == NULL) {
            printf("%s:%d: Could not create and start abstraction layer interface\n", __func__, __LINE__);
        }
    }

    return 0;
}

int em_ctrl_t::orch_init()
{
    m_orch = new em_orch_ctrl_t(this);
    return 0;
}

em_t *em_ctrl_t::find_em_for_msg_type(unsigned char *data, unsigned int len, em_t *al_em)
{
    em_raw_hdr_t *hdr;
    em_cmdu_t *cmdu;
    em_interface_t intf;
    em_freq_band_t band;
    dm_easy_mesh_t *dm;
    em_t *em = NULL;
    mac_address_t ruid;
    bssid_t	bssid;
    dm_bss_t *bss;
    em_profile_type_t profile;
    unsigned int i;
    mac_addr_str_t mac_str1 = {0}, mac_str2 = {0};
    em_commit_info_t dm_commit;
    mac_address_t fallback_ruid = {0};

    assert(len > ((sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))));
    if (len < ((sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)))) {
        em_printfout("[%s %d]\n", __func__,__LINE__); 
	    return NULL;
    }

    hdr = reinterpret_cast<em_raw_hdr_t *> (data);
    
    if (hdr->type != htons(ETH_P_1905)) {
        em_printfout("[%s %d]\n", __func__,__LINE__); 
        return NULL;
    }
    
    cmdu = reinterpret_cast<em_cmdu_t *> (data + sizeof(em_raw_hdr_t));

    switch (htons(cmdu->type)) {
        case em_msg_type_autoconf_search:
            if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)), len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_freq_band(&band) == false) {
        em_printfout("[%s %d]\n", __func__,__LINE__); 
                return NULL;
            }

            if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)), len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_al_mac_address(intf.mac) == false) {
        em_printfout("[%s %d]\n", __func__,__LINE__); 
                return NULL;
            }

            dm_easy_mesh_t::macbytes_to_string(intf.mac, mac_str1);
            em_printfout("[%s] Received autoconfig search from agent al mac: %s\n", __func__, mac_str1);
            if ((dm = get_data_model(GLOBAL_NET_ID, const_cast<const unsigned char *> (intf.mac))) == NULL) {
                if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)), len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_profile(&profile) == false) {
                    profile = em_profile_type_1;
                }
                //dm = create_data_model(GLOBAL_NET_ID, const_cast<const em_interface_t *> (&intf), profile);
                memcpy(dm_commit.mac, intf.mac, sizeof(mac_addr_t));
                strncpy(dm_commit.net_id, GLOBAL_NET_ID, sizeof(dm_commit.net_id));
                io_process(em_bus_event_type_dm_commit, reinterpret_cast<unsigned char *> (&dm_commit), sizeof(em_commit_info_t));
                em_printfout("[%s] Creating data model for mac: %s net: %s\n", __func__, mac_str1, GLOBAL_NET_ID);
            } else {
                dm_easy_mesh_t::macbytes_to_string(dm->get_agent_al_interface_mac(), mac_str1);
                em_printfout("[%s] Found existing data model for mac: %s net: %s\n", __func__, mac_str1, GLOBAL_NET_ID);
            }
            em = al_em;
            break;

        case em_msg_type_autoconf_wsc:
            if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                	len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_radio_id(&ruid) == false) {
        em_printfout("[%s %d]\n", __func__,__LINE__); 
                return NULL;
            }

            dm_easy_mesh_t::macbytes_to_string(ruid, mac_str1);
        
            if ((em = static_cast<em_t *> (hash_map_get(m_em_map, mac_str1))) != NULL) {
                printf("%s:%d: Found existing radio:%s\n", __func__, __LINE__, mac_str1);
                if(em->get_state() != em_state_ctrl_wsc_m2_sent)
                    em->set_state(em_state_ctrl_wsc_m1_pending);
                else
                    printf("%s:%d: Autoconf wsc msg sent already. Incorrect state = (%d)\n", __func__, __LINE__, em->get_state());
            } else {
                if ((dm = get_data_model(GLOBAL_NET_ID, const_cast<const unsigned char *> (hdr->src))) == NULL) {
                    printf("%s:%d: Can not find data model\n", __func__, __LINE__);
                    break;
                }

                dm_easy_mesh_t::macbytes_to_string(hdr->src, mac_str1);
                dm_easy_mesh_t::macbytes_to_string(ruid, mac_str2);

                printf("%s:%d: Found data model for mac: %s, creating node for ruid: %s\n", __func__, __LINE__, mac_str1, mac_str2);

                memcpy(intf.mac, ruid, sizeof(mac_address_t));
                if ((em = create_node(&intf, em_freq_band_unknown, dm, false,  dm->get_device()->m_device_info.profile,
                        em_service_type_ctrl)) != NULL) {
                    em->set_state(em_state_ctrl_wsc_m1_pending);
                }
            }

            break;

        case em_msg_type_topo_resp:
        case em_msg_type_channel_pref_rprt:
        case em_msg_type_channel_sel_rsp:
        case em_msg_type_op_channel_rprt:
        case em_msg_type_ap_cap_rprt:
            if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                    len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_radio_id(&ruid) == false) {
                em_printfout("Could not find radio id in msg:0x%04x", htons(cmdu->type));
                return NULL;
            }

            dm_easy_mesh_t::macbytes_to_string(ruid, mac_str1);
            if ((em = static_cast<em_t *> (hash_map_get(m_em_map, mac_str1))) == NULL) {
                em_printfout("Could not find radio:%s", mac_str1);
                return NULL;
            }
            break;

        case em_msg_type_topo_notif:
        case em_msg_type_client_cap_rprt:
        case em_msg_type_ap_metrics_rsp:
        case em_msg_type_failed_conn:
           if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                    len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_bss_id(&bssid) == false) {
                printf("%s:%d: Could not find bss id in msg:0x%04x\n", __func__, __LINE__, htons(cmdu->type));
                return NULL;
            }

            if ((dm = get_data_model(GLOBAL_NET_ID, const_cast<const unsigned char *> (hdr->src))) == NULL) {
                printf("%s:%d: Can not find data model\n", __func__, __LINE__);
                return NULL;
            }

            if (dm->is_ap_mld_mac(bssid) == false) {
                bss = NULL;
                for (i = 0; i < dm->get_num_radios(); i++) {
                    bss = dm->get_bss(dm->get_radio_info(i)->id.ruid, bssid);
                    if (bss != NULL) {
                        break;
                    }
                }

                if (bss == NULL) {
                    em_printfout("Could not find bss=%s from data model",
                        util::mac_to_string(bssid).c_str());
                    return NULL;
                }

                dm_easy_mesh_t::macbytes_to_string(bss->m_bss_info.ruid.mac, mac_str1);
                if ((em = static_cast<em_t *>(hash_map_get(m_em_map, mac_str1))) == NULL) {
                    em_printfout("Could not find radio:%s", mac_str1);
                    return NULL;
                }
            } else {
                if ((htons(cmdu->type) == em_msg_type_topo_notif) ||
                    (htons(cmdu->type) == em_msg_type_client_cap_rprt)) {
                    if (dm->resolve_ap_mld_to_fallback_ruid(bssid, fallback_ruid)) {
                        dm_easy_mesh_t::macbytes_to_string(fallback_ruid, mac_str1);
                        em = static_cast<em_t *>(hash_map_get(m_em_map, mac_str1));
                        if (em != NULL) {
                            em_printfout("Resolved AP-MLD bssid=%s to radio=%s for msg=0x%04x",
                                util::mac_to_string(bssid).c_str(),
                                util::mac_to_string(fallback_ruid).c_str(),
                                htons(cmdu->type));
                        }
                    }
                    if (em == NULL) {
                        em_printfout("fallback em not found for msg 0x%04x", htons(cmdu->type));
                        return NULL;
                    }
                } else {
                    em_printfout("Could not find bss=%s from data model",
                        util::mac_to_string(bssid).c_str());
                    return NULL;
                }
            }

            break;

        case em_msg_type_autoconf_resp:
        case em_msg_type_topo_query:
        case em_msg_type_autoconf_renew:
        case em_msg_type_channel_pref_query:
        case em_msg_type_channel_sel_req:
        case em_msg_type_client_cap_query:
        case em_msg_type_assoc_sta_link_metrics_query:
        case em_msg_type_unassoc_sta_link_metrics_query:	    
        case em_msg_type_beacon_metrics_query:
        case em_msg_type_client_steering_req:
        case em_msg_type_client_assoc_ctrl_req:
        case em_msg_type_map_policy_config_req:
        case em_msg_type_channel_scan_req:
        case em_msg_type_ap_mld_config_req:
			break;

		case em_msg_type_channel_scan_rprt:
            if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                	len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_radio_id(&ruid) == false) {
        em_printfout("[%s %d]\n", __func__,__LINE__); 
                return NULL;
            }

            dm_easy_mesh_t::macbytes_to_string(ruid, mac_str1);

            if ((em = static_cast<em_t *> (hash_map_get(m_em_map, mac_str1))) != NULL) {        
        em_printfout("[%s %d]\n", __func__,__LINE__); 
                //printf("%s:%d: Found existing radio:%s\n", __func__, __LINE__, mac_str1);
			}
            break;

        case em_msg_type_assoc_sta_link_metrics_rsp:
            em = static_cast<em_t *> (hash_map_get_first(m_em_map));
            while(em != NULL) {
                if ((em->is_al_interface_em() == false) && (em->has_at_least_one_associated_sta() == true)) {
        em_printfout("[%s %d]\n", __func__,__LINE__); 
                    break;
                }
                em = static_cast<em_t *> (hash_map_get_next(m_em_map, em));
            }

            break;

        case em_msg_type_client_steering_btm_rprt:
            em = static_cast<em_t *> (hash_map_get_first(m_em_map));
            while(em != NULL) {
                if ((em->is_al_interface_em() == false) && (em->has_at_least_one_associated_sta() == true)) {
                    break;
                }
                em = static_cast<em_t *> (hash_map_get_next(m_em_map, em));
            }
            break;

        case em_msg_type_ap_mld_config_resp:
        case em_msg_type_1905_ack:
            em = static_cast<em_t *> (hash_map_get_first(m_em_map));
            while(em != NULL) {
                if ((em->is_al_interface_em() == false)) {
                    break;
                }
                em = static_cast<em_t *> (hash_map_get_next(m_em_map, em));
            }
            break;

        case em_msg_type_beacon_metrics_rsp:
            em = static_cast<em_t *> (hash_map_get_first(m_em_map));
            while(em != NULL) {
                if ((em->is_al_interface_em() == false) && (em->has_at_least_one_associated_sta() == true)) {
                    break;
                }
                em = static_cast<em_t *> (hash_map_get_next(m_em_map, em));
            }
            break;

        case em_msg_type_chirp_notif:
        case em_msg_type_proxied_encap_dpp:
        case em_msg_type_direct_encap_dpp:
        case em_msg_type_dpp_cce_ind:
        case em_msg_type_1905_rekey_req:
        case em_msg_type_1905_encap_eapol:
        case em_msg_type_bss_config_req:
        case em_msg_type_bss_config_res:
	        em = al_em;
	        break;
        case em_msg_type_topo_disc:
            em = NULL;
            break;

        case em_msg_type_bh_sta_cap_query:
        break;

        case em_msg_type_bh_sta_cap_rprt:
            if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                len - static_cast<unsigned int> (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_radio_id(&ruid) == false) {
        	em_printfout("[%s %d]\n", __func__,__LINE__); 
                return NULL;
            }

            dm_easy_mesh_t::macbytes_to_string(ruid, mac_str1);
            if ((em = static_cast<em_t *> (hash_map_get(m_em_map, mac_str1))) != NULL) {
                em_printfout("Received bsta report, found em:%s", mac_str1);
            }
            break;

        case em_msg_type_topo_vendor:
            em = static_cast<em_t *> (hash_map_get_first(m_em_map));
            while(em != NULL) {
                if (em->is_al_interface_em() == false) {
                    break;
                }
                em = static_cast<em_t *> (hash_map_get_next(m_em_map, em));
            }
            break;

	case em_msg_type_unassoc_sta_link_metrics_rsp:
            em = static_cast<em_t *>(hash_map_get_first(m_em_map));
            while (em != NULL) {
                if ((em->is_al_interface_em() == false) && 
	          (memcmp(em->get_data_model()->get_agent_al_interface_mac(), hdr->src, sizeof(mac_address_t)) == 0)) {
                    break;
                }
                em = static_cast<em_t *>(hash_map_get_next(m_em_map, em));
            }
            break;

        default:
            printf("%s:%d: Frame: 0x%04x not handled in controller\n", __func__, __LINE__, htons(cmdu->type));
            em = NULL;
            break;
    }

    return em;
}

void em_ctrl_t::io(void *data, bool input)
{
    char *str = static_cast<char *> (data);
    m_ctrl_cmd->execute(str);

    m_ctrl_cmd->deinit();
    delete m_ctrl_cmd;
}

void em_ctrl_t::start_complete()
{
	dm_easy_mesh_t *dm;
	wifi_bus_desc_t *desc;
	raw_data_t raw;
	em_interface_t	*intf;
	mac_addr_str_t  al_mac_str;
	em_bus_event_type_cfg_renew_params_t ac_config_raw;
	mac_address_t null_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	int i = 0;
    bus_error_t bus_error_val;
    unsigned int num_elements = 0;

    //Todo: Revisit placement of data elements registration done for orch
    bus_data_element_t dataElements[] = {
        { const_cast<char*>(DEVICE_WIFI_DATAELEMENTS_NETWORK_TOPOLOGY), bus_element_type_method,
            { tr_181_t::get_network_topology, NULL , NULL, NULL, NULL, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_string, false, 0, 0, 0, NULL } },
        { const_cast<char*>(DEVICE_WIFI_DATAELEMENTS_NETWORK_NODE_SYNC), bus_element_type_method,
            { tr_181_t::get_node_sync,  tr_181_t::set_node_sync , NULL, NULL, NULL, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_string, false, 0, 0, 0, NULL } },
        { const_cast<char*>(DEVICE_WIFI_DATAELEMENTS_NETWORK_NODE_CFG_POLICY), bus_element_type_method,
            { NULL, tr_181_t::policy_config , NULL, NULL, NULL, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_string, false, 0, 0, 0, NULL } },
         { const_cast<char*>(DEVICE_WIFI_DATAELEMENTS_NETWORK_NODE_LINKSTATS_ALARM), bus_element_type_method,
            { NULL, NULL , NULL, NULL, NULL, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_string, false, 0, 0, 0, NULL } },
        { const_cast<char*>(DEVICE_WIFI_DATAELEMENTS_NETWORK_SETSSID_CMD), bus_element_type_method,
            { NULL, NULL , NULL, NULL, NULL, tr_181_t::setssid_handler}, slow_speed, ZERO_TABLE,
            { bus_data_type_property, false, 0, 0, 0, NULL } },
        { const_cast<char*>(DE_MAPDEVBH_STEERWIFIBH), bus_element_type_method,
            { NULL, NULL , NULL, NULL, NULL, tr_181_t::steerwifibh_handler}, slow_speed, ZERO_TABLE,
            { bus_data_type_property, false, 0, 0, 0, NULL } },
        { const_cast<char*>(DE_RADIO_CHSCANREQ), bus_element_type_method,
            { NULL, NULL , NULL, NULL, NULL, tr_181_t::channelscan_handler}, slow_speed, ZERO_TABLE,
            { bus_data_type_property, false, 0, 0, 0, NULL } },
        { const_cast<char*>(DE_STA_CLIENTSTEER), bus_element_type_method,
            { NULL, NULL , NULL, NULL, NULL, tr_181_t::clientsteer_handler}, slow_speed, ZERO_TABLE,
            { bus_data_type_property, false, 0, 0, 0, NULL } },
        { const_cast<char*>(DE_STAMAP_DISASSOC), bus_element_type_method,
            { NULL, NULL , NULL, NULL, NULL, tr_181_t::disassociate_handler}, slow_speed, ZERO_TABLE,
            { bus_data_type_property, false, 0, 0, 0, NULL } }
        };

	if (m_data_model.is_initialized() == false) {
		printf("%s:%d: Database not initialized ... needs reset\n", __func__, __LINE__);
		return;
	}

	// build initial network topology
	init_network_topology();

    dm = m_data_model.get_first_dm();
    while (dm != NULL) {
		dm->set_db_cfg_param(db_cfg_type_scan_result_list_delete, "");
		dm->set_db_cfg_param(db_cfg_type_sta_list_delete, "");
		dm->set_db_cfg_param(db_cfg_type_op_class_list_delete, "");
		dm->set_db_cfg_param(db_cfg_type_bss_list_delete, "");
        dm = m_data_model.get_next_dm(dm);
    }
	memcpy(&ac_config_raw.radio, &null_mac, sizeof(mac_address_t));
	io_process(em_bus_event_type_cfg_renew, reinterpret_cast<unsigned char *> (&ac_config_raw), sizeof(em_bus_event_type_cfg_renew_params_t));
	//Initialze cli devtest
	for (i = 0; i < em_dev_test_type_max; i++) {
		dev_test.dev_test_info.num_iteration[i] = 50;
		dev_test.dev_test_info.test_type[i] = static_cast<em_dev_test_type>(i);;
		dev_test.dev_test_info.enabled[i] = 0;
		dev_test.dev_test_info.num_of_iteration_completed[i] = 0;
		dev_test.dev_test_info.test_inprogress[i] = 0;
		dev_test.dev_test_info.test_status[i] = em_dev_test_status_idle;
		dev_test.dev_test_info.haul_type = em_haul_type_iot;
		dev_test.dev_test_info.freq_band = em_freq_band_24;
	}

    if((desc = get_bus_descriptor()) == NULL) {
        printf("%s:%d descriptor is null\n", __func__, __LINE__);
        return;
    }

    num_elements = (sizeof(dataElements) / sizeof(bus_data_element_t));
    bus_error_val = desc->bus_reg_data_element_fn(m_data_model.get_bus_hdl(), dataElements, num_elements);
    if (bus_error_val != bus_error_success) {
        printf("%s:%d bus: bus_regDataElements failed\n", __func__, __LINE__);
        return;
    }

    dm = m_data_model.get_first_dm();
    while (dm != NULL && dm->is_controller() == false) {
        dm = m_data_model.get_next_dm(dm);
    }

    if (dm) {
        intf = dm->get_ctrl_al_interface();
        assert(intf != NULL);

        dm_easy_mesh_t::macbytes_to_string(intf->mac, al_mac_str);
        raw.data_type    = bus_data_type_string;
        raw.raw_data.bytes   = al_mac_str;
        raw.raw_data_len = static_cast<unsigned int> (strlen(al_mac_str));

        if (desc->bus_set_fn(m_data_model.get_bus_hdl(), "Device.WiFi.DataElements.Network.ControllerID", &raw) == 0) {
            em_printfout("Controller ID: %s publish successful.", al_mac_str);
        }
        else {
            em_printfout("Controller ID: %s publish failed.", al_mac_str);
        }
    } else {
            em_printfout("Could not find data model with controller role");
    }

    if (desc->bus_event_subs_fn(m_data_model.get_bus_hdl(), DEVICE_WIFI_DATAELEMENTS_NETWORK_NODE_CFG_POLICY, reinterpret_cast<void *> (&tr_181_t::subs_policy_config), NULL, 0) != 0) {
        em_printfout("bus subscribe failed");
        return;
    }
}

em_ctrl_t *em_ctrl_t::get_em_ctrl_instance()
{
    if (s_em_ctrl == nullptr) {
        s_em_ctrl = new em_ctrl_t();
    }
    return s_em_ctrl;
}

em_ctrl_t::em_ctrl_t()
{
}

em_ctrl_t::~em_ctrl_t()
{
}

#ifdef AL_SAP
AlServiceAccessPoint* em_ctrl_t::al_sap_register(const std::string& data_socket_path, const std::string& control_socket_path)
{
    AlServiceAccessPoint* sap = new AlServiceAccessPoint(data_socket_path.c_str(), control_socket_path.c_str());

    AlServiceRegistrationRequest registrationRequest(SAPActivation::SAP_ENABLE, ServiceType::EmController);
    sap->serviceAccessPointRegistrationRequest(registrationRequest);

    AlServiceRegistrationResponse registrationResponse = sap->serviceAccessPointRegistrationResponse();

    RegistrationResult result = registrationResponse.getResult();
    if (result == RegistrationResult::SUCCESS) {
        g_al_mac_sap = registrationResponse.getAlMacAddressLocal();
        uint8_t* al_mac_bytes = g_al_mac_sap.data();
        em_printfout("AL SAP registration successful, AL MAC: %s", util::mac_to_string(al_mac_bytes).c_str());

        m_data_model.set_dev_interface_mac(al_mac_bytes);
    } else {
        std::cout << "Registration failed with error: " << static_cast<int>(result) << std::endl;
    }

    return sap;
}
#endif


#ifndef TESTING
int main(int argc, const char *argv[])
{
    em_ctrl_t  *em_ctrl = em_ctrl_t::get_em_ctrl_instance();
    const char *data_model_path = NULL;
    bool passive = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--passive") == 0) {
            passive = true;
        } else if (strncmp(argv[i], "--cmmac=", 8) == 0) {
#ifdef EM_WEBSOCKET_PUSH
            snprintf(g_em_topo_gateway_mac, sizeof(g_em_topo_gateway_mac), "%s", argv[i] + 8);
            em_printfout("Gateway MAC set from CLI: %s", g_em_topo_gateway_mac);
#endif
        } else {
            data_model_path = argv[i];
        }
    }

    if (passive == true) {
#ifdef EM_WEBSOCKET_PUSH
        if (g_em_topo_gateway_mac[0] == '\0') {
            em_printfout("Usage: %s --passive --cmmac=<MAC> [data_model_path]", argv[0]);
            em_printfout("  --passive           Run controller in passive mode");
            em_printfout("  --cmmac=<MAC>       Gateway CM MAC address (required with --passive)");
            em_printfout("Example: %s --passive --cmmac=D4:E2:CB:9D:4E:D4", argv[0]);
            return 1;
        }
#endif
        em_ctrl->set_passive(true);
        em_printfout("Controller started in passive mode");
    }

#ifdef AL_SAP
    g_sap = em_ctrl->al_sap_register("/tmp/al_em_ctrl_data_socket", "/tmp/al_em_ctrl_control_socket");
#endif

    if (em_ctrl->init(data_model_path) == 0) {
        em_ctrl->start();
    }

    return 0;
}

#endif // TESTING

extern "C" void wifi_util_print(wifi_log_level_t level, wifi_dbg_type_t module, const char *format, ...)
{

}
