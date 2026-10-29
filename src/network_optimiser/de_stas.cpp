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
#include "de_bsss.h"
#include "de_stas.h"
#include "optimizer.h"

void de_stas_t::update(de_sta_t& sta, unsigned int dpos, unsigned int rpos, unsigned int bpos, unsigned int spos)
{
    rbusValue_t value;
    em_long_string_t name = {0};
    unsigned int inst;
    de_sta_t *psta = NULL;
    em_long_string_t alias = {0};

    snprintf(alias, sizeof(em_long_string_t), "%s.%u.%s.%u.%s.%u.%s.%u",
        DEVICES, dpos, RADIOS, rpos, BSSS, bpos, STAS, spos);
    if ((psta = (de_sta_t *)hash_map_get(m_sta_map, alias)) == NULL) { 
        snprintf(name, sizeof(em_long_string_t), "%s%u.%s.%u.%s.%u.%s.",
            DE_DEVICES, dpos, RADIOS, rpos, BSSS, bpos, STAS);
        printf("%s:%d: adding row, name: %s, alias: %s\n", __func__, __LINE__, name, alias);
        if (rbusTable_addRow(m_bus_handle, name, alias, &inst) != RBUS_ERROR_SUCCESS) {
            printf("%s:%d: Failed to add STA row, name: %s, alias: %s\n",
                __func__, __LINE__, name, alias);
            return;
        }
        psta = (de_sta_t *)hash_map_get(m_sta_map, alias);
    }

    if (psta != NULL) {
        psta->update(sta);
    }
       
    snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.%s.%d.%s.%d.MACAddress", DE_DEVICES, dpos, RADIOS, rpos, BSSS, bpos, STAS, spos);
    rbusValue_Init(&value);
    rbusValue_SetString(value, sta.m_mac);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);

    snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.%s.%d.%s.%d.SignalStrength", DE_DEVICES, dpos, RADIOS, rpos, BSSS, bpos, STAS, spos);
    rbusValue_Init(&value);
    rbusValue_SetInt32(value, sta.m_rssi);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);

    snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.%s.%d.%s.%d.LastDataUplinkRate", DE_DEVICES, dpos, RADIOS, rpos, BSSS, bpos, STAS, spos);
    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, sta.m_ul_rate);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
 
    snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.%s.%d.%s.%d.LastDataDownlinkRate", DE_DEVICES, dpos, RADIOS, rpos, BSSS, bpos, STAS, spos);
    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, sta.m_dl_rate);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
 
    snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.%s.%d.%s.%d.RetransCount", DE_DEVICES, dpos, RADIOS, rpos, BSSS, bpos, STAS, spos);
    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, sta.m_retrans);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
 
    snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.%s.%d.%s.%d.PacketsReceived", DE_DEVICES, dpos, RADIOS, rpos, BSSS, bpos, STAS, spos);
    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, sta.m_pkts_rx);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
 
    snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.%s.%d.%s.%d.PacketsSent", DE_DEVICES, dpos, RADIOS, rpos, BSSS, bpos, STAS, spos);
    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, sta.m_pkts_tx);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
 
    snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.%s.%d.%s.%d.BytesReceived", DE_DEVICES, dpos, RADIOS, rpos, BSSS, bpos, STAS, spos);
    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, sta.m_bytes_rx);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
 
    snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.%s.%d.%s.%d.BytesSent", DE_DEVICES, dpos, RADIOS, rpos, BSSS, bpos, STAS, spos);
    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, sta.m_bytes_tx);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
 
    snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.%s.%d.%s.%d.ClientCapabilities", DE_DEVICES, dpos, RADIOS, rpos, BSSS, bpos, STAS, spos);
    rbusValue_Init(&value);
    rbusValue_SetString(value, sta.m_cap);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
    
    //snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.%s.%d.%s.%d.WiFi6Capabilities", DE_DEVICES, dpos, RADIOS, rpos, BSSS, bpos, STAS, spos);
    //rbusValue_Init(&value);
    //rbusValue_SetString(value, sta.m_wifi6_cap);
    //rbus_set(m_bus_handle, name, value, NULL);
    //rbusValue_Release(value);
    
    snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.%s.%d.%s.%d.HTCapabilities", DE_DEVICES, dpos, RADIOS, rpos, BSSS, bpos, STAS, spos);
    rbusValue_Init(&value);
    rbusValue_SetString(value, sta.m_ht_cap);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
    
    snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.%s.%d.%s.%d.VHTCapabilities", DE_DEVICES, dpos, RADIOS, rpos, BSSS, bpos, STAS, spos);
    rbusValue_Init(&value);
    rbusValue_SetString(value, sta.m_vht_cap);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
    
    snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.%s.%d.%s.%d.HECapabilities", DE_DEVICES, dpos, RADIOS, rpos, BSSS, bpos, STAS, spos);
    rbusValue_Init(&value);
    rbusValue_SetString(value, sta.m_he_cap);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
    
    snprintf(name, sizeof(em_long_string_t), "%s%d.%s.%d.%s.%d.%s.%d.SecurityAssociation", DE_DEVICES, dpos, RADIOS, rpos, BSSS, bpos, STAS, spos);
    rbusValue_Init(&value);
    rbusValue_SetString(value, sta.m_sec_assoc);
    rbus_set(m_bus_handle, name, value, NULL);
    rbusValue_Release(value);
    
}


rbusError_t de_stas_t::add(rbusHandle_t handle, char const* table_name, char const* alias_name, uint32_t* inst_num)
{
    unsigned int dpos, rpos, bpos, spos;
    de_sta_t *sta;
    
    sscanf(alias_name, "DeviceList.%d.RadioList.%d.BSSList.%d.STAList.%d", &dpos, &rpos, &bpos, &spos);
    printf("%s:%d: Name: %s\n", __func__, __LINE__, alias_name);

    if ((sta = (de_sta_t *)hash_map_get(m_sta_map, alias_name)) == NULL) {
        sta = new de_sta_t();
        sta->init(alias_name);

        hash_map_put(m_sta_map, strdup(alias_name), sta);
    }

    *inst_num = spos;

    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_stas_t::remove(rbusHandle_t handle, char const* row_name)
{
    printf("%s:%d: name: %s, row: %s\n", __func__, __LINE__, row_name);

    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_stas_t::get(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* options)
{
    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_stas_t::set(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* options)
{
    em_string_t str; 
    em_long_string_t key;
    unsigned int dpos, rpos, bpos, spos;
    int len;
    de_sta_t *sta;
    const char *name, *ptr;

    name  = rbusProperty_GetName(property);
    printf("%s:%d: Property Name: %s\n", __func__, __LINE__, name);

    snprintf(key, sizeof(em_long_string_t), "%s", DE_DEVICES);

    if ((ptr = strstr(name, key)) == NULL) {
        printf("%s:%d: Substring(%s) not found in %s\n", __func__, __LINE__, key, name);
        return RBUS_ERROR_INVALID_OPERATION;
    }

    ptr += strlen(DE_DEVICES);

    sscanf(ptr, "%d.RadioList.%d.BSSList.%d.STAList.%d.%s", &dpos, &rpos, &bpos, &spos, str);
    snprintf(key, sizeof(em_long_string_t), "DeviceList.%d.RadioList.%d.BSSList.%d.STAList.%d", dpos, rpos, bpos, spos);

    if ((sta = (de_sta_t *)hash_map_get(m_sta_map, key)) == NULL) {
        printf("%s:%d: Could not find sta at key: %s\n", __func__, __LINE__, key);
        return RBUS_ERROR_INVALID_HANDLE;
    }

    if (strncmp(str, "MACAddress", strlen("MACAddress")) == 0) {
        ptr = rbusProperty_GetString(property, &len);
        strncpy(sta->m_mac, ptr, len + 1);
    } else if (strncmp(str, "SignalStrength", strlen("SignalStrength")) == 0) {
        sta->m_rssi = rbusProperty_GetInt32(property);
    } else if (strncmp(str, "LastDataUplinkRate", strlen("LastDataUplinkRate")) == 0) {
        sta->m_ul_rate = rbusProperty_GetUInt32(property);
    } else if (strncmp(str, "LastDataDownlinkRate", strlen("LastDataDownlinkRate")) == 0) {
        sta->m_dl_rate = rbusProperty_GetUInt32(property);
    } else if (strncmp(str, "RetransCount", strlen("RetransCount")) == 0) {
        sta->m_retrans = rbusProperty_GetUInt32(property);
    } else if (strncmp(str, "PacketsReceived", strlen("PacketsReceived")) == 0) {
        sta->m_pkts_rx = rbusProperty_GetUInt32(property);
    } else if (strncmp(str, "PacketsSent", strlen("PacketsSent")) == 0) {
        sta->m_pkts_tx = rbusProperty_GetUInt32(property);
    } else if (strncmp(str, "BytesReceived", strlen("BytesReceived")) == 0) {
        sta->m_bytes_rx = rbusProperty_GetUInt32(property);
    } else if (strncmp(str, "BytesSent", strlen("BytesSent")) == 0) {
        sta->m_bytes_tx = rbusProperty_GetUInt32(property);
    } else if (strncmp(str, "ClientCapabilities", strlen("ClientCapabilities")) == 0) {
        ptr = rbusProperty_GetString(property, &len);
        strncpy(sta->m_cap, ptr, len + 1);
    //} else if (strncmp(str, "WiFi6Capabilities", strlen("WiFi6Capabilities")) == 0) {
        //ptr = rbusProperty_GetString(property, &len);
        //strncpy(sta->m_wifi6_cap, ptr, len + 1);
    } else if (strncmp(str, "HTCapabilities", strlen("HTCapabilities")) == 0) {
        ptr = rbusProperty_GetString(property, &len);
        strncpy(sta->m_ht_cap, ptr, len + 1);
    } else if (strncmp(str, "VHTCapabilities", strlen("VHTCapabilities")) == 0) {
        ptr = rbusProperty_GetString(property, &len);
        strncpy(sta->m_vht_cap, ptr, len + 1);
    } else if (strncmp(str, "HECapabilities", strlen("HECapabilities")) == 0) {
        ptr = rbusProperty_GetString(property, &len);
        strncpy(sta->m_he_cap, ptr, len + 1);
    } else if (strncmp(str, "SecurityAssociation", strlen("SecurityAssociation")) == 0) {
        ptr = rbusProperty_GetString(property, &len);
        strncpy(sta->m_sec_assoc, ptr, len + 1);
    }

    return RBUS_ERROR_SUCCESS;
}

void de_stas_t::publish(const char *name)
{
    int rc, inst;
    de_sta_t *sta;
    rbusEvent_t event = {0};
    rbusValue_t value;
    rbusObject_t data, row;

    if (strncmp(name, STAS, strlen(STAS)) != 0) {
        return;
    }

    rbusObject_Init(&data, NULL);

    sta = (de_sta_t *)hash_map_get_first(m_sta_map);
    while (sta != NULL) {
        rbusObject_Init(&row, sta->m_key);

        rbusValue_Init(&value);
        rbusValue_SetString(value, sta->m_mac);
        rbusObject_SetValue(row, "MACAddress", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetInt32(value, sta->m_rssi);
        rbusObject_SetValue(row, "SignalStrength", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetUInt32(value, sta->m_ul_rate);
        rbusObject_SetValue(row, "LastDataUplinkRate", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetUInt32(value, sta->m_dl_rate);
        rbusObject_SetValue(row, "LastDataDownlinkRate", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetUInt32(value, sta->m_retrans);
        rbusObject_SetValue(row, "RetransCount", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetUInt32(value, sta->m_pkts_rx);
        rbusObject_SetValue(row, "PacketsReceived", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetUInt32(value, sta->m_pkts_tx);
        rbusObject_SetValue(row, "PacketsSent", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetUInt32(value, sta->m_bytes_rx);
        rbusObject_SetValue(row, "BytesReceived", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetUInt32(value, sta->m_bytes_tx);
        rbusObject_SetValue(row, "BytesSent", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_Init(&value);
        rbusValue_SetString(value, sta->m_cap);
        rbusObject_SetValue(row, "ClientCapabilities", value);
        rbusValue_Release(value);

        //rbusValue_Init(&value);
        //rbusValue_SetString(value, sta->m_wifi6_cap);
        //rbusObject_SetValue(row, "WiFi6Capabilities", value);
        //rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetString(value, sta->m_ht_cap);
        rbusObject_SetValue(row, "HTCapabilities", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetString(value, sta->m_vht_cap);
        rbusObject_SetValue(row, "VHTCapabilities", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetString(value, sta->m_he_cap);
        rbusObject_SetValue(row, "HECapabilities", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetString(value, sta->m_sec_assoc);
        rbusObject_SetValue(row, "SecurityAssociation", value);
        rbusValue_Release(value);

        rbusValue_Init(&value);
        rbusValue_SetObject(value, row);
        rbusObject_Release(row);

        rbusObject_SetValue(data, sta->m_key, value);
        rbusValue_Release(value);

        sta = (de_sta_t *)hash_map_get_next(m_sta_map, sta);
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

void de_stas_t::handler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{
    rbusValue_t value;
    rbusObject_t row;
    rbusProperty_t prop;

    const char *ptr;
    de_sta_t *sta;

    if (strncmp(subscription->eventName, STAS, strlen(STAS)) != 0) {
        printf("%s:%d: Unknown event: %s\n", __func__, __LINE__, event->name);
        return;
    }


    prop = rbusObject_GetProperties(event->data);
    while (prop != NULL) {
        ptr = rbusProperty_GetName(prop);
        printf("%s:%d: Name: %s\n", __func__, __LINE__, ptr);

        if ((sta = (de_sta_t *)hash_map_get(m_sta_map, ptr)) == NULL) {
            sta = new de_sta_t();
            sta->init(ptr);
            hash_map_put(m_sta_map, strdup(ptr), sta);
        }

        row = rbusProperty_GetObject(prop);

        if ((value = rbusObject_GetValue(row, "MACAddress")) == NULL) {
            printf("%s:%d: Could not find mac address value\n", __func__, __LINE__);
        } else {
            ptr = rbusValue_GetString(value, NULL);
            strncpy(sta->m_mac, ptr, strlen(ptr) + 1);
        }

        if ((value = rbusObject_GetValue(row, "SignalStrength")) == NULL) {
            printf("%s:%d: Could not find Signal Strength value\n", __func__, __LINE__);
        } else {
            sta->m_rssi = rbusValue_GetInt32(value);
        }

        if ((value = rbusObject_GetValue(row, "LastDataUplinkRate")) == NULL) {
            printf("%s:%d: Could not find Last Uplink Rate value\n", __func__, __LINE__);
        } else {
            sta->m_ul_rate = rbusValue_GetUInt32(value);
        }

        if ((value = rbusObject_GetValue(row, "LastDataDownlinkRate")) == NULL) {
            printf("%s:%d: Could not find Last Downlink Rate value\n", __func__, __LINE__);
        } else {
            sta->m_dl_rate = rbusValue_GetUInt32(value);
        }

        if ((value = rbusObject_GetValue(row, "RetransCount")) == NULL) {
            printf("%s:%d: Could not find RetransCount value\n", __func__, __LINE__);
        } else {
            sta->m_retrans = rbusValue_GetUInt32(value);
        }

        if ((value = rbusObject_GetValue(row, "PacketsReceived")) == NULL) {
            printf("%s:%d: Could not find PacketsReceived value\n", __func__, __LINE__);
        } else {
            sta->m_pkts_rx = rbusValue_GetUInt32(value);
        }

        if ((value = rbusObject_GetValue(row, "PacketsSent")) == NULL) {
            printf("%s:%d: Could not find PacketsSent value\n", __func__, __LINE__);
        } else {
            sta->m_pkts_tx = rbusValue_GetUInt32(value);
        }

        if ((value = rbusObject_GetValue(row, "BytesReceived")) == NULL) {
            printf("%s:%d: Could not find BytesReceived value\n", __func__, __LINE__);
        } else {
            sta->m_bytes_rx = rbusValue_GetUInt32(value);
        }

        if ((value = rbusObject_GetValue(row, "BytesSent")) == NULL) {
            printf("%s:%d: Could not find BytesSent value\n", __func__, __LINE__);
        } else {
            sta->m_bytes_tx = rbusValue_GetUInt32(value);
        }

        if ((value = rbusObject_GetValue(row, "ClientCapabilities")) == NULL) {
            printf("%s:%d: Could not find Capabilities value\n", __func__, __LINE__);
        } else {
            ptr = rbusValue_GetString(value, NULL);
            strncpy(sta->m_cap, ptr, strlen(ptr) + 1);
        }

        //if ((value = rbusObject_GetValue(row, "WiFi6Capabilities")) == NULL) {
        //    printf("%s:%d: Could not find WiFi6 Capabilities value\n", __func__, __LINE__);
        //} else {
        //    ptr = rbusValue_GetString(value, NULL);
        //    strncpy(sta->m_wifi6_cap, ptr, strlen(ptr) + 1);
        //}

        if ((value = rbusObject_GetValue(row, "HTCapabilities")) == NULL) {
            printf("%s:%d: Could not find HT Capabilities value\n", __func__, __LINE__);
        } else {
            ptr = rbusValue_GetString(value, NULL);
            strncpy(sta->m_ht_cap, ptr, strlen(ptr) + 1);
        }

        if ((value = rbusObject_GetValue(row, "VHTCapabilities")) == NULL) {
            printf("%s:%d: Could not find VHT Capabilities value\n", __func__, __LINE__);
        } else {
            ptr = rbusValue_GetString(value, NULL);
            strncpy(sta->m_vht_cap, ptr, strlen(ptr) + 1);
        }

        if ((value = rbusObject_GetValue(row, "HECapabilities")) == NULL) {
            printf("%s:%d: Could not find HE Capabilities value\n", __func__, __LINE__);
        } else {
            ptr = rbusValue_GetString(value, NULL);
            strncpy(sta->m_he_cap, ptr, strlen(ptr) + 1);
        }

        if ((value = rbusObject_GetValue(row, "SecurityAssociation")) == NULL) {
            printf("%s:%d: Could not find Security Association value\n", __func__, __LINE__);
        } else {
            ptr = rbusValue_GetString(value, NULL);
            strncpy(sta->m_sec_assoc, ptr, strlen(ptr) + 1);
        }

        prop = rbusProperty_GetNext(prop);
    }

}

int de_stas_t::init(rbusHandle_t handle)
{
    m_sta_map = hash_map_create();

    m_elems[m_num_elems].name = STAS;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;
    
    m_elems[m_num_elems].name = DE_STAS_TABLE;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_TABLE;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_STAS_MAC;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_STAS_RSSI;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_STAS_UL_RATE;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_STAS_DL_RATE;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_STAS_RETRANS;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_STAS_PKTS_RX;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_STAS_PKTS_TX;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_STAS_BYTES_RX;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_STAS_BYTES_TX;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_STAS_CAP;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    //m_elems[m_num_elems].name = DE_STAS_WIFI6_CAP;
    //m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    //m_num_elems++;

    m_elems[m_num_elems].name = DE_STAS_HT_CAP;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_STAS_VHT_CAP;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_STAS_HE_CAP;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_elems[m_num_elems].name = DE_STAS_SEC_ASSOC;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_PROPERTY;
    m_num_elems++;

    m_subs[m_num_subs].eventName = STAS;
    m_num_subs++;

    return de_t::init(handle);
}

void de_stas_t::deinit(bool bus_close)
{
    if (m_sta_map != NULL) {
        hash_map_destroy(m_sta_map);
    }
    de_t::deinit(false);
}

de_stas_t::de_stas_t(const char *name, bool provider, notifier_t func)
{
    m_provider = provider;
    strncpy(m_name, name, strlen(name));
    m_func = func;
    m_sta_map = NULL;
}
