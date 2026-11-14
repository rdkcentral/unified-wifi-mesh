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

#include <arpa/inet.h>
#include <curl/curl.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <errno.h>
#include <signal.h>
#include "xmidt_optimizer_server.h"
#include "util.h"
#include <cjson/cJSON.h>

extern "C" {
#include <wrp-c/wrp-c.h>
}

#define DEVICE_ID "mac:112233445566"
#define SERVICE_NAME "xmidt-c-demo"
#define BASIC_AUTH "Authorization: Basic dXNlcjpwYXNz"
#define CONTENT_TYPE_JSON "application/json"

const char *xmidt_optimizer_server_t::device_request(optimizer_event_t *req, optimizer_event_t *rsp)
{

    if (send_device_request(req, rsp) != 0) {
        rsp->init(req->get_type(), "", "Failed");
    }

    return (const char *)rsp->get_data();
}

void xmidt_optimizer_server_t::listener()
{
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    int reuse = 1;
    struct sockaddr_in address;
    optimizer_event_t *ev;

    address.sin_family = AF_INET;
    address.sin_port = htons(m_port);
    address.sin_addr.s_addr = htonl(INADDR_ANY);

    if (listener < 0 ||
            setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) ||
            bind(listener, (struct sockaddr *)&address, sizeof(address)) ||
            listen(listener, 8)) {
        printf("webhook listener\n");
        if (listener >= 0) {
            close(listener);
        }
        return;
    }
    
    printf("Webhook listener is ready on port %u\n", m_port);

    while (m_exit == false) {
        struct timeval timeout = {.tv_sec = 1, .tv_usec = 0};
        fd_set read_set;

        FD_ZERO(&read_set);
        FD_SET(listener, &read_set);
        int selected = select(listener + 1, &read_set, NULL, NULL, &timeout);
        if (selected <= 0) {
            continue;
        }

        int client = accept(listener, NULL, NULL);
        if (client < 0) {
            continue;
        }

        char *request = NULL;
        if (read_http_request(client, &request) == 0) {
            char *body = strstr(request, "\r\n\r\n");
            static const char response[] =
                "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n"
                "Connection: close\r\n\r\n";
            send(client, response, sizeof(response) - 1, 0);
            if (body != NULL) {
                ev = new optimizer_event_t(body + 4);
                printf("%s:%d: Received event: %s\n", __func__, __LINE__, optimizer_event_t::optimizer_event_type_2_string(ev->get_type()));
                delete ev;
            }
        } else {
            printf("%s:%d: http req error\n", __func__, __LINE__);
        }

        free(request);
        close(client);
    }

    close(listener);
}

int xmidt_optimizer_server_t::send_device_request(optimizer_event_t *ev_req, optimizer_event_t *ev_resp)
{
    const char *scytale_url = "http://127.0.0.1:6300/api/v3/device";
    char transaction_uuid[37];
    uuid_t uuid;
    wrp_msg_t request;
    void *encoded = NULL;
    ssize_t encoded_size;
    CURL *curl;
    struct curl_slist *headers = NULL;
    long status = 0;
    partners_t *partners;
    optimizer_event_t resp;

    if ((partners = (partners_t *)malloc(sizeof(*partners) + sizeof(char *))) == NULL) {
        printf("%s:%d: Unable to allocate WRP partner list\n", __func__, __LINE__);
        return -1;
    }

    resp.m_buff.data = NULL;
    resp.m_buff.size = 0;

    partners->count = 1;
    partners->partner_ids[0] = "foobar";

    uuid_generate(uuid);
    uuid_unparse_lower(uuid, transaction_uuid);


    memset(&request, 0, sizeof(request));
    request.msg_type = WRP_MSG_TYPE__REQ;
    request.u.req.transaction_uuid = transaction_uuid;
    request.u.req.source = "dns:local-server/" SERVICE_NAME;
    request.u.req.dest = DEVICE_ID "/" SERVICE_NAME;
    request.u.req.partner_ids = partners;
    request.u.req.content_type = CONTENT_TYPE_JSON;
    request.u.req.payload = (void *)ev_req->get_data();
    request.u.req.payload_size = strlen((char *)ev_req->get_data());

    encoded_size = wrp_struct_to(&request, WRP_BYTES, &encoded);
    free(partners);
    if (encoded_size < 1) {
        fprintf(stderr, "Unable to encode WRP request\n");
        return -1;
    }

    curl = curl_easy_init();
    if (curl == NULL) {
        free(encoded);
        return -1;
    }

    headers = curl_slist_append(headers, BASIC_AUTH);
    headers = curl_slist_append(headers, "Content-Type: application/msgpack");
    headers = curl_slist_append(headers, "Accept: application/msgpack");
    curl_easy_setopt(curl, CURLOPT_URL, scytale_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, encoded);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)encoded_size);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, append_response);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    CURLcode result = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(encoded);


    if (result != CURLE_OK || status < 200 || status >= 300) {
        printf("%s:%d: Device request failed: %s (HTTP %ld)\n", __func__, __LINE__, curl_easy_strerror(result), status);
        printf("%s:%d: Using mock response for simulator\n", __func__, __LINE__);
        if (resp.m_buff.size > 0) {
            printf("%s:%d: %.*s\n", __func__, __LINE__, (int)resp.m_buff.size, resp.m_buff.data);
        }

        free(resp.m_buff.data);
        resp.m_buff.data = NULL;
        resp.m_buff.size = 0;

        // For cloud simulator, provide a mock response when the backend service is unavailable
        unsigned char *payload = (unsigned char *)malloc(256);
        if (payload == NULL) {
            return -1;
        }
        
        // Create a mock response with empty result and Success status
        const char *mock_response = "{}";
        strcpy((char *)payload, mock_response);
        *ev_resp = optimizer_event_t(ev_req->get_type(), payload, strlen(mock_response), true);
        return 0;
    }

    wrp_msg_t *reply = NULL;
    if (wrp_to_struct(resp.m_buff.data, resp.m_buff.size, WRP_BYTES, &reply) < 1 ||
        reply == NULL || reply->msg_type != WRP_MSG_TYPE__REQ ||
        reply->u.req.payload == NULL) {
        printf("%s:%d: Server received an invalid WRP response\n", __func__, __LINE__);
        if (reply != NULL) {
            wrp_free_struct(reply);
        }

        free(resp.m_buff.data);
        resp.m_buff.data = NULL;
        resp.m_buff.size = 0;
        return -1;
    }

    unsigned char *payload = (unsigned char *)malloc(reply->u.req.payload_size + 1);
    if (payload == NULL) {
        free(resp.m_buff.data);
        resp.m_buff.data = NULL;
        resp.m_buff.size = 0;
        wrp_free_struct(reply);
        return -1;
    }
    memcpy(payload, reply->u.req.payload, reply->u.req.payload_size);
    payload[reply->u.req.payload_size] = '\0';
    free(resp.m_buff.data);

    *ev_resp = optimizer_event_t(ev_req->get_type(), payload, reply->u.req.payload_size, true);
    wrp_free_struct(reply);

    return 0;
}

size_t xmidt_optimizer_server_t::append_response(void *contents, size_t size, size_t count, void *user_data)
{   
    size_t bytes = size * count;
    optimizer_event_t *response = (optimizer_event_t *)user_data;
    unsigned char *next = (unsigned char *)realloc(response->m_buff.data, response->m_buff.size + bytes);
    
    if (next == NULL) {
        return 0;
    }
    
    response->m_buff.data = next;
    memcpy(response->m_buff.data + response->m_buff.size, contents, bytes);
    response->m_buff.size += bytes;
    return bytes;
}   

int xmidt_optimizer_server_t::read_http_request(int client, char **request_out)
{
    size_t capacity = 4096;
    size_t used = 0;
    char *request = (char *)malloc(capacity + 1);
    size_t content_length = 0;
    char *body;

    if (request == NULL) {
        return -1;
    }

    while (1) {
        if (used == capacity) {
            capacity *= 2;
            char *next = (char *)realloc(request, capacity + 1);
            if (next == NULL) {
                free(request);
                return -1;
            }
            request = next;
        }

        ssize_t count = recv(client, request + used, capacity - used, 0);
        if (count <= 0) {
            free(request);
            return -1;
        }
        used += (size_t)count;
        request[used] = '\0';

        body = strstr(request, "\r\n\r\n");
        if (body == NULL) {
            continue;
        }

        char *length_header = strcasestr(request, "\r\nContent-Length:");
        if (length_header != NULL) {
            content_length = strtoul(length_header + 17, NULL, 10);
        }

        size_t header_size = (size_t)(body + 4 - request);
        if (used >= header_size + content_length) {
            *request_out = request;
            return 0;
        }
    }
}

void *xmidt_optimizer_server_t::listener(void *arg)
{
    xmidt_optimizer_server_t *srv = (xmidt_optimizer_server_t *)arg;
    srv->listener();

    return NULL;
}

int xmidt_optimizer_server_t::register_webhook(const char *argus_url, const char *webhook_url)
{
    CURL *curl = curl_easy_init();
    struct curl_slist *headers = NULL;
    char payload[2048];
    char registration_url[1024];
    char item_id[(SHA256_DIGEST_LENGTH * 2) + 1];
    char expires[32];
    unsigned char digest[SHA256_DIGEST_LENGTH];
    time_t expiration_time = time(NULL) + 1800;
    struct tm expiration;
    long status = 0;

    if (curl == NULL) {
        return -1;
    }

    SHA256((const unsigned char *)webhook_url, strlen(webhook_url), digest);
    for (size_t i = 0; i < sizeof(digest); ++i) {
        snprintf(item_id + (i * 2), 3, "%02x", digest[i]);
    }

    gmtime_r(&expiration_time, &expiration);
    strftime(expires, sizeof(expires), "%Y-%m-%dT%H:%M:%SZ", &expiration);

    snprintf(registration_url, sizeof(registration_url),
             "%s/api/v1/store/webhooks/%s", argus_url, item_id);
    snprintf(payload, sizeof(payload),
             "{\"id\":\"%s\",\"data\":{\"PartnerIDs\":[\"foobar\"],"
             "\"Webhook\":{"
             "\"registered_from_address\":\"%s\","
             "\"config\":{\"url\":\"%s\",\"content_type\":\"%s\"},"
             "\"failure_url\":\"\",\"events\":[\"%s\"],"
             "\"matcher\":{\"device_id\":[\".*\"]},"
             "\"duration\":1800000000000,\"until\":\"%s\"}},\"ttl\":1800}",
             item_id, webhook_url, webhook_url, CONTENT_TYPE_JSON,
             SERVICE_NAME, expires);

    headers = curl_slist_append(headers, BASIC_AUTH);
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, registration_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    CURLcode result = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (result != CURLE_OK || status < 200 || status >= 300) {
        fprintf(stderr, "Webhook registration failed: %s (HTTP %ld)\n",
                curl_easy_strerror(result), status);
        return -1;
    }

    printf("Registered webhook %s\n", webhook_url);
    return 0;
}


int xmidt_optimizer_server_t::init_optimizer_interface(const char *url)
{
    const char *webhook_url = "http://172.19.0.1:8088/event";
    const char *argus_url = "http://127.0.0.1:6600";

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        printf("%s:%d: Unable to initialize libcurl\n", __func__, __LINE__);
        return -1;
    }

    if (pthread_create(&m_id, NULL, xmidt_optimizer_server_t::listener, this) != 0) {
        printf("%s:%d: Failed to create listener thread\n", __func__, __LINE__);
        curl_global_cleanup();
        return -1;
    }
    m_listener_started = true;

    if (register_webhook(argus_url, webhook_url) != 0) {
        m_exit = true;
        pthread_join(m_id, NULL);
        m_listener_started = false;
        curl_global_cleanup();
        return -1;
    }


    web_t::init(url);

    return 0;
}

void xmidt_optimizer_server_t::deinit_optimizer_interface()
{
    m_exit = true;
    if (m_listener_started) {
        pthread_join(m_id, NULL);
        m_listener_started = false;
    }
    curl_global_cleanup();
}

xmidt_optimizer_server_t::xmidt_optimizer_server_t()
{
    m_listener_started = false;
    m_port = 8088;
    m_exit = false;
}

xmidt_optimizer_server_t::~xmidt_optimizer_server_t()
{

}
