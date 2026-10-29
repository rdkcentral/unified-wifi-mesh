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
#include "util.h"
#include "de_net_ssids.h"
#include "optimizer.h"

rbusError_t de_net_ssids_t::update(de_net_ssid_t& net_ssid, unsigned int pos)
{
    rbusValue_t value;
    rbusError_t rc;
    em_long_string_t name = {0};
    unsigned int inst;
    de_net_ssid_t *pnet_ssid;
    em_string_t alias = {0};

    snprintf(alias, sizeof(em_string_t), "%s.%d", NET_SSIDS, pos);

    if ((pnet_ssid = (de_net_ssid_t *)hash_map_get(m_net_ssid_map, alias)) == NULL) {
        snprintf(name, sizeof(em_long_string_t), "%s", DE_NET_SSIDS);
        if ((rc = rbusTable_addRow(m_bus_handle, name, alias, &inst)) != RBUS_ERROR_SUCCESS) {
            return rc;
        }
    }

    snprintf(name, sizeof(em_long_string_t), "%s%d.SSID", DE_NET_SSIDS, pos);
    rbusValue_Init(&value);
    rbusValue_SetString(value, net_ssid.m_ssid);
    rc = rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
    if (rc != RBUS_ERROR_SUCCESS) return rc;

    snprintf(name, sizeof(em_long_string_t), "%s%d.Enable", DE_NET_SSIDS, pos);
    rbusValue_Init(&value);
    rbusValue_SetBoolean(value, net_ssid.m_enabled);
    rc = rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
    if (rc != RBUS_ERROR_SUCCESS) return rc;

    snprintf(name, sizeof(em_long_string_t), "%s%d.AdvertisementEnabled", DE_NET_SSIDS, pos);
    rbusValue_Init(&value);
    rbusValue_SetBoolean(value, net_ssid.m_advertisement);
    rc = rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
    if (rc != RBUS_ERROR_SUCCESS) return rc;
    
    snprintf(name, sizeof(em_long_string_t), "%s%d.MFPConfig", DE_NET_SSIDS, pos);
    rbusValue_Init(&value);
    rbusValue_SetString(value, net_ssid.m_mfp_config);
    rc = rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
    if (rc != RBUS_ERROR_SUCCESS) return rc;
    
    snprintf(name, sizeof(em_long_string_t), "%s%d.MobilityDomain", DE_NET_SSIDS, pos);
    rbusValue_Init(&value);
    rbusValue_SetString(value, net_ssid.m_mob_domain);
    rc = rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
    if (rc != RBUS_ERROR_SUCCESS) return rc;

    if (pnet_ssid == NULL) {
        pnet_ssid = new de_net_ssid_t();
        pnet_ssid->init(alias);
        hash_map_put(m_net_ssid_map, strdup(alias), pnet_ssid);
    }
    pnet_ssid->update(net_ssid);

    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_net_ssids_t::remove(unsigned int pos)
{
    em_long_string_t row_name = {0};
    em_string_t key = {0};
    rbusError_t rc;

    snprintf(row_name, sizeof(row_name), "%s%u", DE_NET_SSIDS, pos);
    rc = rbusTable_removeRow(m_bus_handle, row_name);
    if (rc != RBUS_ERROR_SUCCESS) {
        return rc;
    }

    snprintf(key, sizeof(key), "%s.%u", NET_SSIDS, pos);
    delete static_cast<de_net_ssid_t *>(hash_map_remove(m_net_ssid_map, key));
    return RBUS_ERROR_SUCCESS;
}


rbusError_t de_net_ssids_t::add(rbusHandle_t handle, char const* table_name, char const* alias_name, uint32_t* inst_num)
{
    unsigned int row;
    de_net_ssid_t *net_ssid;

    sscanf(alias_name, NET_SSIDS ".%d", &row);

    net_ssid = new de_net_ssid_t();
    net_ssid->init(alias_name);

    hash_map_put(m_net_ssid_map, strdup(alias_name), net_ssid);

    *inst_num = row;

    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_net_ssids_t::remove(rbusHandle_t handle, char const* row_name)
{
    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_net_ssids_t::get(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* options)
{
    em_string_t str = {0}, key = {0};
    unsigned int inst;
    int len;
    de_net_ssid_t *net_ssid;
    const char *name, *ptr;

    name  = rbusProperty_GetName(property);
    printf("%s:%d: Property Name: %s\n", __func__, __LINE__, name);

    snprintf(key, sizeof(key), "%s", DE_NET_SSIDS);

    if ((ptr = strstr(name, key)) == NULL) {
        printf("%s:%d: Could not find data for key: %s\n", __func__, __LINE__, key);
        return RBUS_ERROR_INVALID_OPERATION;
    }

    ptr += strlen(DE_NET_SSIDS);

    if (sscanf(ptr, "%u.%31s", &inst, str) != 2) {
        return RBUS_ERROR_INVALID_INPUT;
    }
    snprintf(key, sizeof(key), "%s.%u", NET_SSIDS, inst);

    if ((net_ssid = (de_net_ssid_t *)hash_map_get(m_net_ssid_map, key)) == NULL) {
        printf("%s:%d: Could not find object\n", __func__, __LINE__);
        return RBUS_ERROR_INVALID_HANDLE;
    }

    if (strncmp(str, "SSID", strlen("SSID")) == 0) {
        rbusProperty_SetString(property, net_ssid->m_ssid);
    } else if (strncmp(str, "Enable", strlen("Enable")) == 0) {
        rbusProperty_SetBoolean(property, net_ssid->m_enabled);
    } else if (strncmp(str, "AdvertisementEnabled", strlen("AdvertisementEnabled")) == 0) {
        rbusProperty_SetBoolean(property, net_ssid->m_advertisement);
    } else if (strncmp(str, "MFPConfig", strlen("MFPConfig")) == 0) {
        rbusProperty_SetString(property, net_ssid->m_mfp_config);
    } else if (strncmp(str, "MobilityDomain", strlen("MobilityDomain")) == 0) {
        rbusProperty_SetString(property, net_ssid->m_mob_domain);
    }


    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_net_ssids_t::set(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* options)
{
    em_string_t str, key;
    unsigned int inst;
    int len;
    de_net_ssid_t *net_ssid;
    const char *name, *ptr;

    name  = rbusProperty_GetName(property);
    snprintf(key, sizeof(key), "%s", DE_NET_SSIDS);

    if ((ptr = strstr(name, key)) == NULL) {
        return RBUS_ERROR_INVALID_OPERATION;
    }

    ptr += strlen(DE_NET_SSIDS);

    if (sscanf(ptr, "%u.%31s", &inst, str) != 2) {
        return RBUS_ERROR_INVALID_INPUT;
    }
    snprintf(key, sizeof(key), "%s.%u", NET_SSIDS, inst);

    if ((net_ssid = (de_net_ssid_t *)hash_map_get(m_net_ssid_map, key)) == NULL) {
        printf("%s:%d: Could not find object\n", __func__, __LINE__);
        return RBUS_ERROR_INVALID_HANDLE;
    }

    if (strncmp(str, "SSID", strlen("SSID")) == 0) {
        ptr = rbusProperty_GetString(property, &len);
        strncpy(net_ssid->m_ssid, ptr, len + 1);
    } else if (strncmp(str, "Enable", strlen("Enable")) == 0) {
        net_ssid->m_enabled = rbusProperty_GetBoolean(property);
    } else if (strncmp(str, "AdvertisementEnabled", strlen("AdvertisementEnabled")) == 0) {
        net_ssid->m_advertisement = rbusProperty_GetBoolean(property);
    } else if (strncmp(str, "MFPConfig", strlen("MFPConfig")) == 0) {
        ptr = rbusProperty_GetString(property, &len);
        strncpy(net_ssid->m_mfp_config, ptr, len + 1);
    } else if (strncmp(str, "MobilityDomain", strlen("MobilityDomain")) == 0) {
        ptr = rbusProperty_GetString(property, &len);
        strncpy(net_ssid->m_mob_domain, ptr, len + 1);
    }

    return RBUS_ERROR_SUCCESS;
}

void de_net_ssids_t::publish(const char *name)
{
    int rc, inst;
    de_net_ssid_t *net_ssid;
    rbusEvent_t event = {0};
    rbusValue_t value;
    rbusObject_t data, row;

    if (strncmp(name, NET_SSIDS, strlen(NET_SSIDS)) != 0) {
        printf("%s:%d: Name mismatch, name: %s\n", __func__, __LINE__, name);
        return;
    }

    rbusObject_Init(&data, NULL);

    net_ssid = (de_net_ssid_t *)hash_map_get_first(m_net_ssid_map);
    while (net_ssid != NULL) {
        rbusObject_Init(&row, net_ssid->m_key);

        rbusValue_Init(&value);
        rbusValue_SetString(value, net_ssid->m_ssid);
        rbusObject_SetValue(row, "SSID", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetBoolean(value, net_ssid->m_enabled);
        rbusObject_SetValue(row, "Enable", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetBoolean(value, net_ssid->m_advertisement);
        rbusObject_SetValue(row, "AdvertisementEnabled", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetString(value, net_ssid->m_mfp_config);
        rbusObject_SetValue(row, "MFPConfig", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetString(value, net_ssid->m_mob_domain);
        rbusObject_SetValue(row, "MobilityDomain", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetObject(value, row);
        rbusObject_Release(row);

        rbusObject_SetValue(data, net_ssid->m_key, value);
        rbusValue_Release(value);

        net_ssid = (de_net_ssid_t *)hash_map_get_next(m_net_ssid_map, net_ssid);
    }

    event.name = name;;
    event.data = data;
    event.type = RBUS_EVENT_GENERAL;

    if ((rc = rbusEvent_Publish(m_bus_handle, &event)) != RBUS_ERROR_SUCCESS) {
        printf("%s:%d: Failed to publish data for event: %s, err: %d\n", __func__, __LINE__,
            event.name, rc);
    } else {
        printf("%s:%d: Successfully published data for event: %s\n", __func__, __LINE__, event.name);
    }

    rbusObject_Release(data);

}


void de_net_ssids_t::handler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{
    rbusValue_t value;
    rbusObject_t row;
    rbusProperty_t prop;

    const char *ptr;
    de_net_ssid_t *net_ssid;

    if (strncmp(subscription->eventName, NET_SSIDS, strlen(NET_SSIDS)) != 0) {
        printf("%s:%d: Unknown event: %s\n", __func__, __LINE__, event->name);
        return;
    }

    prop = rbusObject_GetProperties(event->data);
    while (prop != NULL) {
        ptr = rbusProperty_GetName(prop);

        if ((net_ssid = (de_net_ssid_t *)hash_map_get(m_net_ssid_map, ptr)) == NULL) {
            net_ssid = new de_net_ssid_t();
            net_ssid->init(ptr);
            hash_map_put(m_net_ssid_map, strdup(ptr), net_ssid);
        }

        row = rbusProperty_GetObject(prop);

        if ((value = rbusObject_GetValue(row, "SSID")) == NULL) {
            printf("%s:%d: Could not find SSID value\n", __func__, __LINE__);
        } else {
            ptr = rbusValue_GetString(value, NULL);
            strncpy(net_ssid->m_ssid, ptr, strlen(ptr) + 1);
        }

        if ((value = rbusObject_GetValue(row, "Enable")) == NULL) {
            printf("%s:%d: Could not find Enable value\n", __func__, __LINE__);
        } else {
            net_ssid->m_enabled = rbusValue_GetBoolean(value);
        }

        if ((value = rbusObject_GetValue(row, "AdvertisementEnabled")) == NULL) {
            printf("%s:%d: Could not find AdvertisementEnabled value\n", __func__, __LINE__);
        } else {
            net_ssid->m_advertisement = rbusValue_GetBoolean(value);
        }

        if ((value = rbusObject_GetValue(row, "MFPConfig")) == NULL) {
            printf("%s:%d: Could not find MFPConfig value\n", __func__, __LINE__);
        } else {
            ptr = rbusValue_GetString(value, NULL);
            strncpy(net_ssid->m_mfp_config, ptr, strlen(ptr) + 1);
        }

        if ((value = rbusObject_GetValue(row, "MobilityDomain")) == NULL) {
            printf("%s:%d: Could not find MobilityDomain value\n", __func__, __LINE__);
        } else {
            ptr = rbusValue_GetString(value, NULL);
            strncpy(net_ssid->m_mob_domain, ptr, strlen(ptr) + 1);
        }

        prop = rbusProperty_GetNext(prop);

    }

}

int de_net_ssids_t::init(rbusHandle_t handle)
{
    m_net_ssid_map = hash_map_create();

    m_elems[m_num_elems].name = NET_SSIDS;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;
    
    m_elems[m_num_elems].name = DE_NET_SSIDS_TABLE;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_TABLE;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_NET_SSIDS_SSID;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_NET_SSIDS_ENABLED;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_NET_SSIDS_ADV_ENABLED;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_NET_SSIDS_MFP;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_NET_SSIDS_MOB_DOM;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_subs[m_num_subs].eventName = NET_SSIDS;
    m_num_subs++;



    return de_t::init(handle); 
}

void de_net_ssids_t::deinit(bool bus_close)
{
    if (m_net_ssid_map != NULL) {
        hash_map_destroy(m_net_ssid_map);
    }
    de_t::deinit(bus_close);
}

de_net_ssids_t::de_net_ssids_t(const char *name, bool provider, notifier_t func)
{
    m_provider = provider;
    strncpy(m_name, name, strlen(name));
    m_func = func;
    m_net_ssid_map = NULL;
}
