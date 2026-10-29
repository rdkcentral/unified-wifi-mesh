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
#include "comcast_optimizer_web.h"
#include "util.h"
#include <cjson/cJSON.h>

const char *comcast_optimizer_web_t::handle_get(optimizer_event_type_t type, char *buff, unsigned int len)
{
    switch (type) {
        case optimizer_event_type_get_topology:
            get_topology(buff, len);
            break;

        case optimizer_event_type_get_de:
            get_de(buff, len);
            break;

        default:
            break;
    }

    return buff;
}

const char *comcast_optimizer_web_t::handle_post_request(const char *action, const char *body,
    char *buff, unsigned int len)
{
    cJSON *root = NULL;
    cJSON *records;
    cJSON *record;
    unsigned int applied = 0;
    rbusError_t rc;

    if ((action == NULL) || (strcmp(action, "/NetworkParameters.json") != 0)) {
        snprintf(buff, len, "{\"error\":\"Unsupported POST endpoint\"}");
        return buff;
    }

    root = cJSON_Parse(body);
    records = root == NULL ? NULL : cJSON_GetObjectItemCaseSensitive(root, "NetworkSSIDList");
    if (!cJSON_IsObject(root) || !cJSON_IsArray(records)) {
        snprintf(buff, len, "{\"error\":\"NetworkSSIDList must be an array\"}");
        cJSON_Delete(root);
        return buff;
    }

    cJSON_ArrayForEach(record, records) {
        cJSON *index = cJSON_GetObjectItemCaseSensitive(record, "Index");
        cJSON *operation = cJSON_GetObjectItemCaseSensitive(record, "Operation");
        cJSON *ssid = cJSON_GetObjectItemCaseSensitive(record, "SSID");
        cJSON *enabled = cJSON_GetObjectItemCaseSensitive(record, "Enable");
        cJSON *advertisement = cJSON_GetObjectItemCaseSensitive(record, "AdvertisementEnabled");
        cJSON *mfp = cJSON_GetObjectItemCaseSensitive(record, "MFPConfig");
        cJSON *mobility = cJSON_GetObjectItemCaseSensitive(record, "MobilityDomain");

        if (!cJSON_IsObject(record) || !cJSON_IsNumber(index) ||
            (index->valuedouble < 1) || (index->valuedouble != index->valueint) ||
            !cJSON_IsString(operation) ||
            ((strcmp(operation->valuestring, "Add") != 0) &&
             (strcmp(operation->valuestring, "Change") != 0) &&
             (strcmp(operation->valuestring, "Remove") != 0)) ||
            !cJSON_IsString(ssid) || !cJSON_IsBool(enabled) ||
            !cJSON_IsBool(advertisement) || !cJSON_IsString(mfp) || !cJSON_IsString(mobility) ||
            (strlen(operation->valuestring) >= sizeof(em_string_t)) ||
            (strlen(ssid->valuestring) >= sizeof(em_string_t)) ||
            (strlen(mfp->valuestring) >= sizeof(em_string_t)) ||
            (strlen(mobility->valuestring) >= sizeof(em_string_t))) {
            snprintf(buff, len, "{\"error\":\"Invalid NetworkSSIDList record\"}");
            cJSON_Delete(root);
            return buff;
        }
    }

    cJSON_ArrayForEach(record, records) {
        de_net_ssid_t net_ssid;
        cJSON *index = cJSON_GetObjectItemCaseSensitive(record, "Index");
        cJSON *operation = cJSON_GetObjectItemCaseSensitive(record, "Operation");
        cJSON *ssid = cJSON_GetObjectItemCaseSensitive(record, "SSID");
        cJSON *enabled = cJSON_GetObjectItemCaseSensitive(record, "Enable");
        cJSON *advertisement = cJSON_GetObjectItemCaseSensitive(record, "AdvertisementEnabled");
        cJSON *mfp = cJSON_GetObjectItemCaseSensitive(record, "MFPConfig");
        cJSON *mobility = cJSON_GetObjectItemCaseSensitive(record, "MobilityDomain");
        em_string_t key = {0};
        de_net_ssid_t *existing;

        snprintf(key, sizeof(key), "%s.%d", NET_SSIDS, index->valueint);
        existing = (de_net_ssid_t *)hash_map_get(m_de_network->m_de_net_ssids->m_net_ssid_map, key);
        snprintf(net_ssid.m_op, sizeof(net_ssid.m_op), "%s", operation->valuestring);
        snprintf(net_ssid.m_ssid, sizeof(net_ssid.m_ssid), "%s", ssid->valuestring);
        net_ssid.m_enabled = cJSON_IsTrue(enabled);
        net_ssid.m_advertisement = cJSON_IsTrue(advertisement);
        snprintf(net_ssid.m_mfp_config, sizeof(net_ssid.m_mfp_config), "%s", mfp->valuestring);
        snprintf(net_ssid.m_mob_domain, sizeof(net_ssid.m_mob_domain), "%s", mobility->valuestring);

        if (strcmp(net_ssid.m_op, "Add") == 0) {
            if (existing != NULL) {
                snprintf(buff, len, "{\"error\":\"NetworkSSID index %d already exists\"}", index->valueint);
                cJSON_Delete(root);
                return buff;
            }
            rc = m_de_network->m_de_net_ssids->update(net_ssid, index->valueint);
        } else if (strcmp(net_ssid.m_op, "Change") == 0) {
            if (existing == NULL) {
                snprintf(buff, len, "{\"error\":\"NetworkSSID index %d does not exist\"}", index->valueint);
                cJSON_Delete(root);
                return buff;
            }
            rc = m_de_network->m_de_net_ssids->update(net_ssid, index->valueint);
        } else {
            if (existing == NULL) {
                snprintf(buff, len, "{\"error\":\"NetworkSSID index %d does not exist\"}", index->valueint);
                cJSON_Delete(root);
                return buff;
            }
            snprintf(existing->m_op, sizeof(existing->m_op), "%s", net_ssid.m_op);
            rc = m_de_network->m_de_net_ssids->remove(index->valueint);
        }

        if (rc != RBUS_ERROR_SUCCESS) {
            snprintf(buff, len, "{\"error\":\"RBUS %s failed\",\"code\":%d}",
                net_ssid.m_op, rc);
            cJSON_Delete(root);
            return buff;
        }
        applied++;
    }

    snprintf(buff, len, "{\"success\":true,\"applied\":%u}", applied);
    cJSON_Delete(root);
    return buff;
}

int comcast_optimizer_web_t::init_optimizer_interface(const char *url)
{
    web_t::init(url);
    start();

    return 0;
}

void comcast_optimizer_web_t::deinit_optimizer_interface()
{
    stop();
}

comcast_optimizer_web_t::comcast_optimizer_web_t()
{
    set_optimizer_type(optimizer_type_comcast);

}

comcast_optimizer_web_t::~comcast_optimizer_web_t()
{

}
