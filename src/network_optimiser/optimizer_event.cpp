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
#include "em_base.h"
#include "util.h"
#include "optimizer_event.h"

optimizer_events_map_t e2smap[] = {
    {optimizer_event_type_get_de, "DataElements"},
    {optimizer_event_type_subscribed, "Subscribed"},
    {optimizer_event_type_get_topology, "Topology"},
    {optimizer_event_type_set_ssid, "SetSSID"},
    {optimizer_event_type_nbr_wifi_diag, "NeighboringWiFiDiagnostic"},
    {optimizer_event_type_full_scan, "FullScan"},
    {optimizer_event_type_channel_scan, "ChannelScan"},
    {optimizer_event_type_hello, "Hello"},
    {optimizer_event_type_unknown, "Unknown"},
    {optimizer_event_type_max, "None"}
};

const char *optimizer_event_t::optimizer_event_type_2_string(optimizer_event_type_t type)
{
    for (unsigned int i = 0; i < sizeof(e2smap)/sizeof(optimizer_events_map_t); i++) {
        if (type == e2smap[i].type) {
            return e2smap[i].string;
        }
    }

    return "None";
}

optimizer_event_type_t optimizer_event_t::optimizer_string_2_event_type(const char *string, size_t length)
{
    if (string == NULL) {
        return optimizer_event_type_max;
    }

    for (unsigned int i = 0; i < sizeof(e2smap)/sizeof(optimizer_events_map_t); i++) {
        size_t event_length = strlen(e2smap[i].string);
        if ((length == event_length) && (memcmp(string, e2smap[i].string, length) == 0)) {
            return e2smap[i].type;
        }
    }

    return optimizer_event_type_max;
}

void optimizer_event_t::init(optimizer_event_type_t type, const char *data, const char *status)
{
    cJSON *obj;

    m_type = type;
    m_copy = true;

    obj = cJSON_CreateObject();
    m_buff.size = (data == NULL) ? sizeof(em_long_string_t):strlen(data) + sizeof(em_long_string_t);
    m_buff.data = (unsigned char *)malloc(m_buff.size);

    if (data == NULL) {
        // Event or Get
        cJSON_AddStringToObject(obj, is_notification_event(type) ? "Event":"Request", optimizer_event_type_2_string(type));

    } else {
        if (status == NULL) {
            // Post
            cJSON_AddStringToObject(obj, "Request", optimizer_event_type_2_string(type));

        } else {
            // Response
            cJSON_AddStringToObject(obj, "Response", optimizer_event_type_2_string(type));
            cJSON_AddStringToObject(obj, "Status", status);

        }
        cJSON_AddStringToObject(obj, "Data", data);
    }

    cJSON_PrintPreallocated(obj, (char *)m_buff.data, m_buff.size, true);
    cJSON_Delete(obj);

}

optimizer_event_t::optimizer_event_t(optimizer_event_type_t type, const cJSON *data, const char *status)
{
    cJSON *obj;
    char *serialized;

    m_type = type;
    m_copy = true;
    m_buff.data = NULL;
    m_buff.size = 0;

    obj = cJSON_CreateObject();
    if (obj == NULL) {
        return;
    }

    if (data == NULL) {
        // Event or Get
        cJSON_AddStringToObject(obj, is_notification_event(type) ? "Event":"Request", optimizer_event_type_2_string(type));

    } else {
        if (status == NULL) {
            // Post
            cJSON_AddStringToObject(obj, "Request", optimizer_event_type_2_string(type));

        } else {
            // Response
            cJSON_AddStringToObject(obj, "Response", optimizer_event_type_2_string(type));
            cJSON_AddStringToObject(obj, "Status", status);

        }
        cJSON_AddItemToObject(obj, "Data", cJSON_Duplicate(data, true));
    }

    serialized = cJSON_Print(obj);
    if (serialized != NULL) {
        m_buff.size = strlen(serialized) + 1;
        m_buff.data = (unsigned char *)malloc(m_buff.size);
        if (m_buff.data != NULL) {
            memcpy(m_buff.data, serialized, m_buff.size);
        } else {
            m_buff.size = 0;
        }
        cJSON_free(serialized);
    }
    cJSON_Delete(obj);
}

optimizer_event_t::optimizer_event_t(optimizer_event_type_t type, const char *data, const char *status)
{
    cJSON *obj;
    char *serialized;

    m_type = type;
    m_copy = true;
    m_buff.data = NULL;
    m_buff.size = 0;

    obj = cJSON_CreateObject();
    if (obj == NULL) {
        return;
    }

    if (data == NULL) {
        // Event or Get
        cJSON_AddStringToObject(obj, is_notification_event(type) ? "Event":"Request", optimizer_event_type_2_string(type));

    } else {
        if (status == NULL) {
            // Post
            cJSON_AddStringToObject(obj, "Request", optimizer_event_type_2_string(type));

        } else {
            // Response
            cJSON_AddStringToObject(obj, "Response", optimizer_event_type_2_string(type));
            cJSON_AddStringToObject(obj, "Status", status);

        }
        cJSON *tmp;
        if ((tmp = cJSON_Parse(data)) == NULL) {
            printf("%s:%d: Can not parse data\n", __func__, __LINE__);
        } else {
            cJSON_AddItemToObject(obj, "Data", tmp);
        }
    }

    serialized = cJSON_Print(obj);
    if (serialized != NULL) {
        m_buff.size = strlen(serialized) + 1;
        m_buff.data = (unsigned char *)malloc(m_buff.size);
        if (m_buff.data != NULL) {
            memcpy(m_buff.data, serialized, m_buff.size);
        } else {
            m_buff.size = 0;
        }
        cJSON_free(serialized);
    }

    cJSON_Delete(obj);
}

optimizer_event_t::optimizer_event_t(optimizer_event_type_t type, void *data, unsigned int len, bool zero_cp)
{
    m_type = type;
    m_copy = !zero_cp;
    if (zero_cp == false) {
        m_buff.data = (unsigned char *)malloc(len);
        memcpy(m_buff.data, data, len);
    } else {
        m_buff.data = (unsigned char *)data;
    }

    m_buff.size = len; 
}

optimizer_event_t::optimizer_event_t(const char *data)
{
    cJSON *obj;
    const char *ptr = NULL;
    
    m_copy = true;

    if ((obj = cJSON_Parse(data)) == NULL) {
        m_type = optimizer_event_type_unknown;
    } else if ((ptr = cJSON_GetStringValue(cJSON_GetObjectItem(obj, "Event"))) != NULL) {
        m_type = optimizer_string_2_event_type(ptr, strlen(ptr));
    } else if ((ptr = cJSON_GetStringValue(cJSON_GetObjectItem(obj, "Request"))) != NULL) {
        m_type = optimizer_string_2_event_type(ptr, strlen(ptr));
    } else if ((ptr = cJSON_GetStringValue(cJSON_GetObjectItem(obj, "Response"))) != NULL) {
        m_type = optimizer_string_2_event_type(ptr, strlen(ptr));
    } else {
        m_type = optimizer_event_type_unknown;
    }

    m_buff.size = strlen(data) + 1;
    m_buff.data = (unsigned char *)malloc(m_buff.size);
    strncpy((char *)m_buff.data, data, m_buff.size);
            
}

optimizer_event_t::optimizer_event_t()
{
    m_copy = true;
    m_buff.data = NULL;
    m_buff.size = 0;
}

optimizer_event_t::~optimizer_event_t()
{
    if ((m_copy == true) && (m_buff.data != NULL)) {
        free(m_buff.data);
    }
}
