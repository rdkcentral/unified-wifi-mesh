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
#include <signal.h>
#include "bus.h"
#include "bus_common.h"
#include "optimizer.h"
#include "xmidt_optimizer_client.h"
#include "util.h"

int xmidt_optimizer_client_t::send_event(optimizer_event_type_t type)
{
    wrp_msg_t message;
    optimizer_event_t ev(type);

    memset(&message, 0, sizeof(message));
    message.msg_type = WRP_MSG_TYPE__EVENT;
    message.u.event.source = DEVICE_ID "/" SERVICE_NAME;
    message.u.event.dest = "event:" SERVICE_NAME "/" DEVICE_ID;
    message.u.event.content_type = CONTENT_TYPE_JSON;
    message.u.event.payload = (void *)ev.get_data();
    message.u.event.payload_size = strlen((char *)message.u.event.payload);

    if (libparodus_send(m_instance, &message) != 0) {
        printf("%s:%d: Unable to send event\n", __func__, __LINE__);
        return -1;
    }

    return 0;
}

int xmidt_optimizer_client_t::reply_to_request(const wrp_msg_t *request)
{
    wrp_msg_t response;
    cJSON *rsp_obj, *req_obj, *in_params;
    optimizer_event_type_t type;
    const char *status = "Failed";

    if ((request == NULL) || (request->u.req.payload == NULL)) {
        return -1;
    }

    optimizer_event_t ev_req((const char *)request->u.req.payload);

    switch (type = ev_req.get_type()) {
        case optimizer_event_type_get_de:
            rsp_obj = get_de();
            status = "Complete";
            break;

        case optimizer_event_type_get_topology:
            rsp_obj = get_topology();
            status = "Complete";
            break;

        case optimizer_event_type_nbr_wifi_diag:
            rsp_obj = nbr_diagnostics();
            printf("%s\n", cJSON_Print(rsp_obj));
            status = "Complete";
            break;

        case optimizer_event_type_set_ssid:
            if ((req_obj = cJSON_Parse((char *)ev_req.get_data())) == NULL) {
                rsp_obj = cJSON_CreateString("Failed");
                status = "Failed";
            } else if ((in_params = cJSON_GetObjectItem(req_obj, "Data")) == NULL) {
                rsp_obj = cJSON_CreateString("Failed");
                status = "Failed";
            } else {
                rsp_obj = set_ssid(in_params);
                status = "Complete";
            }
            break;

        case optimizer_event_type_full_scan:
            if ((req_obj = cJSON_Parse((char *)ev_req.get_data())) == NULL) {
                rsp_obj = cJSON_CreateString("Failed");
                status = "Failed";
            } else if ((in_params = cJSON_GetObjectItem(req_obj, "Data")) == NULL) {
                rsp_obj = cJSON_CreateString("Failed");
                status = "Failed";
            } else {
                rsp_obj = full_scan(in_params);
                status = "Complete";
            }
            break;

        case optimizer_event_type_channel_scan:
            if ((req_obj = cJSON_Parse((char *)ev_req.get_data())) == NULL) {
                rsp_obj = cJSON_CreateString("Failed");
                status = "Failed";
            } else if ((in_params = cJSON_GetObjectItem(req_obj, "Data")) == NULL) {
                rsp_obj = cJSON_CreateString("Failed");
                status = "Failed";
            } else {
                rsp_obj = channel_scan(in_params);
                status = "Complete";
            }
            break;

        default:
            rsp_obj = cJSON_CreateString("");
            status = "Failed";
            break;
    }

    optimizer_event_t ev_rsp(type, rsp_obj, status);
    cJSON_Delete(rsp_obj);
    if (ev_rsp.get_data() == NULL) {
        printf("%s:%d: Unable to serialize response\n", __func__, __LINE__);
        return -1;
    }

    memset(&response, 0, sizeof(response));
    response.msg_type = WRP_MSG_TYPE__REQ;
    response.u.req.transaction_uuid = request->u.req.transaction_uuid;
    response.u.req.source = request->u.req.dest;
    response.u.req.dest = request->u.req.source;
    response.u.req.partner_ids = request->u.req.partner_ids;
    response.u.req.headers = request->u.req.headers;
    response.u.req.content_type = CONTENT_TYPE_JSON;
    response.u.req.payload = (void *)ev_rsp.get_data();
    response.u.req.payload_size = strlen((char *)ev_rsp.get_data());

    int result = libparodus_send(m_instance, &response);
    if (result != 0) {
        printf("%s:%d: Unable to send response: %s (%d)\n", __func__, __LINE__, libparodus_strerror((libpd_error_t)result), result);
        return -1;
    }

    return 0;
}

void xmidt_optimizer_client_t::listener()
{
    wrp_msg_t *message = NULL;
    int result;
    
    while (m_exit == false) {
        result = libparodus_receive(m_instance, &message, 1000);
        if (result == 1) {
            continue;
        }
        if (result == 2) {
            break;
        }
        if (result != 0) {
            printf("%s:%d: libparodus_receive failed: %d\n", __func__, __LINE__, result);
            break;
        }

        if (message != NULL && message->msg_type == WRP_MSG_TYPE__REQ &&
            strcmp(message->u.req.source,
                   "dns:local-server/" SERVICE_NAME) == 0) {
            printf("Received request: %.*s\n",
                   (int)message->u.req.payload_size,
                   (const char *)message->u.req.payload);
            reply_to_request(message);
        } else if (message != NULL && message->msg_type == WRP_MSG_TYPE__REQ) {
            printf("Ignoring request from %s\n", message->u.req.source);
        } else if (message != NULL) {
            printf("Ignoring WRP message type %d\n", message->msg_type);
        }

        wrp_free_struct(message);
    }

}

void *xmidt_optimizer_client_t::listener(void *arg)
{
    xmidt_optimizer_client_t *opt = (xmidt_optimizer_client_t *)arg;

    opt->listener();
    return NULL;
}

int xmidt_optimizer_client_t::init_optimizer_interface(const char *url)
{
    const char *parodus_url = "tcp://127.0.0.1:6666";
    const char *client_url = "tcp://172.19.0.1:6667";
    int result;

    (void)url;

    libpd_cfg_t config = {
        .service_name = SERVICE_NAME,
        .receive = true,
        .keepalive_timeout_secs = 64,
        .parodus_url = parodus_url,
        .client_url = client_url,
        .test_flags = 0
    }; 

    result = libparodus_init(&m_instance, &config);
    if (result != 0) {
        printf("%s:%d: libparodus_init failed for %s: %s (%d)\n",
               __func__, __LINE__, parodus_url,
               libparodus_strerror(static_cast<libpd_error_t>(result)), result);
        return -1;
    } 

    printf("%s:%d: parodus init successful\n", __func__, __LINE__);
    if (send_event(optimizer_event_type_hello) != 0) {
        libparodus_close_receiver(m_instance);
        libparodus_shutdown(&m_instance);
        return -1;
    }

    if (pthread_create(&m_tid, NULL, xmidt_optimizer_client_t::listener, this) != 0) {
        printf("%s:%d: Failed to start em mgr thread\n", __func__, __LINE__);
        libparodus_close_receiver(m_instance);
        libparodus_shutdown(&m_instance);
        return -1;
    }
   
    return 0;
}

void xmidt_optimizer_client_t::deinit_optimizer_interface()
{
    printf("%s:%d: Enter\n", __func__, __LINE__);
    m_exit = true;
    libparodus_close_receiver(m_instance);
    libparodus_shutdown(&m_instance);
}

xmidt_optimizer_client_t::xmidt_optimizer_client_t()
{
    set_optimizer_access_type(optimizer_access_type_xmidt);
    m_exit = false;
}

xmidt_optimizer_client_t::~xmidt_optimizer_client_t()
{

}
