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
#include "comcast_optimizer.h"
#include "util.h"

void comcast_optimizer_t::add_stas(cJSON *parent, unsigned int dpos, unsigned int rpos, unsigned int bpos)
{
    de_sta_t *sta;
    cJSON *obj;
    unsigned int posd, posr, posb, poss;

    if ((parent == NULL) || (m_de_devices == NULL) || (m_de_devices->m_de_radios == NULL) ||
        (m_de_devices->m_de_radios->m_de_bsss == NULL) || (m_de_devices->m_de_radios->m_de_bsss->m_de_stas == NULL) ||
        (m_de_devices->m_de_radios->m_de_bsss->m_de_stas->m_sta_map == NULL)) {
        return;
    }
            
    sta = (de_sta_t *)hash_map_get_first(m_de_devices->m_de_radios->m_de_bsss->m_de_stas->m_sta_map);
    while (sta != NULL) {
        if (sscanf(sta->m_key, DEVICES ".%u." RADIOS ".%u." BSSS ".%u." STAS ".%u", &posd, &posr, &posb, &poss) != 4) {
            printf("%s:%d: Stations position parse failure, Key: %s\n", __func__, __LINE__, sta->m_key);
            sta = (de_sta_t *)hash_map_get_next(m_de_devices->m_de_radios->m_de_bsss->m_de_stas->m_sta_map, sta);
            continue;
        }
            
        if (dpos != posd) {
            sta = (de_sta_t *)hash_map_get_next(m_de_devices->m_de_radios->m_de_bsss->m_de_stas->m_sta_map, sta);
            continue;
        }

        if (rpos != posr) {
            sta = (de_sta_t *)hash_map_get_next(m_de_devices->m_de_radios->m_de_bsss->m_de_stas->m_sta_map, sta);
            continue;
        }

        if (bpos != posb) {
            sta = (de_sta_t *)hash_map_get_next(m_de_devices->m_de_radios->m_de_bsss->m_de_stas->m_sta_map, sta);
            continue;
        }

        obj = cJSON_CreateObject();
        if (obj == NULL) {
            sta = (de_sta_t *)hash_map_get_next(m_de_devices->m_de_radios->m_de_bsss->m_de_stas->m_sta_map, sta);
            continue;
        }
        cJSON_AddItemToArray(parent, obj);

        cJSON_AddStringToObject(obj, "MACAddress", sta->m_mac);
        cJSON_AddNumberToObject(obj, "SignalStrength", sta->m_rssi);
        cJSON_AddNumberToObject(obj, "LastDataUplinkRate", sta->m_ul_rate);
        cJSON_AddNumberToObject(obj, "LastDataDownlinkRate", sta->m_dl_rate);
        cJSON_AddNumberToObject(obj, "RetransCount", sta->m_retrans);
        cJSON_AddNumberToObject(obj, "PacketsReceived", sta->m_pkts_rx);
        cJSON_AddNumberToObject(obj, "PacketsSent", sta->m_pkts_tx);
        cJSON_AddNumberToObject(obj, "BytesReceived", sta->m_bytes_rx);
        cJSON_AddNumberToObject(obj, "BytesSent", sta->m_bytes_tx);
        cJSON_AddStringToObject(obj, "ClientCapabilities", sta->m_cap);
        //cJSON_AddStringToObject(obj, "WiFi6Capabilities", sta->m_wifi6_cap);
        cJSON_AddStringToObject(obj, "HTCapabilities", sta->m_ht_cap);
        cJSON_AddStringToObject(obj, "VHTCapabilities", sta->m_vht_cap);
        cJSON_AddStringToObject(obj, "HECapabilities", sta->m_he_cap);
        cJSON_AddStringToObject(obj, "SecurityAssociation", sta->m_sec_assoc);

        sta = (de_sta_t *)hash_map_get_next(m_de_devices->m_de_radios->m_de_bsss->m_de_stas->m_sta_map, sta);
    }

}

void comcast_optimizer_t::add_bsss(cJSON *parent, unsigned int dpos, unsigned int rpos)
{
    de_bss_t *bss;
    cJSON *obj;
    unsigned int posd, posr, posb;

    if ((parent == NULL) || (m_de_devices == NULL) || (m_de_devices->m_de_radios == NULL) ||
        (m_de_devices->m_de_radios->m_de_bsss == NULL) || 
        (m_de_devices->m_de_radios->m_de_bsss->m_bss_map == NULL)) {
        return;
    }

    bss = (de_bss_t *)hash_map_get_first(m_de_devices->m_de_radios->m_de_bsss->m_bss_map);
    while (bss != NULL) {
        if (sscanf(bss->m_key, DEVICES ".%u." RADIOS ".%u." BSSS ".%u", &posd, &posr, &posb) != 3) {
            bss = (de_bss_t *)hash_map_get_next(m_de_devices->m_de_radios->m_de_bsss->m_bss_map, bss);
            continue;
        }

        if (dpos != posd) {
            bss = (de_bss_t *)hash_map_get_next(m_de_devices->m_de_radios->m_de_bsss->m_bss_map, bss);
            continue;
        }

        if (rpos != posr) {
            bss = (de_bss_t *)hash_map_get_next(m_de_devices->m_de_radios->m_de_bsss->m_bss_map, bss);
            continue;
        }

        obj = cJSON_CreateObject();
        if (obj == NULL) {
            bss = (de_bss_t *)hash_map_get_next(m_de_devices->m_de_radios->m_de_bsss->m_bss_map, bss);
            continue;
        }
        cJSON_AddItemToArray(parent, obj);

        cJSON_AddStringToObject(obj, "BSSID", bss->m_bssid);
        cJSON_AddStringToObject(obj, "SSID", bss->m_ssid);
        cJSON_AddBoolToObject(obj, "Enabled", bss->m_enabled);
        cJSON_AddBoolToObject(obj, "TransmittedBSSID", bss->m_broadcast);
        cJSON_AddBoolToObject(obj, "FronthaulUse", bss->m_fronthaul);
        cJSON_AddBoolToObject(obj, "BackhaulUse", bss->m_backhaul);

        if (m_de_devices->m_de_radios->m_de_bsss->m_de_stas == NULL) {
            cJSON_AddStringToObject(obj, "Error", "STA data is not initialized");
        } else {
            add_stas(cJSON_AddArrayToObject(obj, "STAList"), posd, posr, posb);
        }

        bss = (de_bss_t *)hash_map_get_next(m_de_devices->m_de_radios->m_de_bsss->m_bss_map, bss);
    }

}

void comcast_optimizer_t::add_radios(cJSON *parent, unsigned int dpos)
{
    de_radio_t *rd;
    cJSON *obj;
    unsigned int posd, posr;

    if ((parent == NULL) || (m_de_devices == NULL) || (m_de_devices->m_de_radios == NULL) ||
        (m_de_devices->m_de_radios->m_radio_map == NULL)) {
        return;
    }

    rd = (de_radio_t *)hash_map_get_first(m_de_devices->m_de_radios->m_radio_map);
    while (rd != NULL) {
        if (sscanf(rd->m_key, DEVICES ".%u." RADIOS ".%u", &posd, &posr) != 2) {
            rd = (de_radio_t *)hash_map_get_next(m_de_devices->m_de_radios->m_radio_map, rd);
            continue;
        }

        if (dpos != posd) {
            rd = (de_radio_t *)hash_map_get_next(m_de_devices->m_de_radios->m_radio_map, rd);
            continue;
        }

        obj = cJSON_CreateObject();
        if (obj == NULL) {
            rd = (de_radio_t *)hash_map_get_next(m_de_devices->m_de_radios->m_radio_map, rd);
            continue;
        }
        cJSON_AddItemToArray(parent, obj);

        cJSON_AddStringToObject(obj, "ID", rd->m_id);
        cJSON_AddBoolToObject(obj, "Enabled", rd->m_enabled);
        cJSON_AddNumberToObject(obj, "Utilization", static_cast<double>(rd->m_util));
        cJSON_AddNumberToObject(obj, "Noise", static_cast<double>(rd->m_noise));

        if (m_de_devices->m_de_radios->m_de_bsss == NULL) {
            cJSON_AddStringToObject(obj, "Error", "BSS data is not initialized");
        } else {
            add_bsss(cJSON_AddArrayToObject(obj, "BSSList"), posd, posr);
        }


        rd = (de_radio_t *)hash_map_get_next(m_de_devices->m_de_radios->m_radio_map, rd);
    }

}

void comcast_optimizer_t::add_network(cJSON *parent)
{
    if ((parent == NULL) || (m_de_network == NULL)) {
        return;
    }

    cJSON_AddStringToObject(parent, "ID", m_de_network->m_id);
    cJSON_AddStringToObject(parent, "ControllerID", m_de_network->m_controller_id);
}


void comcast_optimizer_t::add_devices(cJSON *parent)
{
    cJSON *arr, *obj;
    de_device_t *dev;
    unsigned int dpos;

    if ((parent == NULL) || (m_de_devices == NULL) || (m_de_devices->m_device_map == NULL)) {
        return;
    }

    arr = cJSON_AddArrayToObject(parent, "DeviceList");
    if (arr == NULL) {
        return;
    }

    dev = (de_device_t *)hash_map_get_first(m_de_devices->m_device_map);
    while (dev != NULL) {
        obj = cJSON_CreateObject();
        if (obj == NULL) {
            return;
        }

        cJSON_AddStringToObject(obj, "ID", dev->m_id);
        cJSON_AddStringToObject(obj, "Manufacturer", dev->m_manufacturer);
        cJSON_AddStringToObject(obj, "ManufacturerModel", dev->m_model);
        cJSON_AddStringToObject(obj, "SerialNumber", dev->m_serial);
        cJSON_AddStringToObject(obj, "SoftwareVersion", dev->m_version);

        if (sscanf(dev->m_key, DEVICES ".%u", &dpos) != 1) {
            cJSON_Delete(obj);
            dev = (de_device_t *)hash_map_get_next(m_de_devices->m_device_map, dev);
            continue;
        }
        if (m_de_devices->m_de_radios == NULL) {
            cJSON_AddStringToObject(obj, "Error", "Radio data is not initialized");
        } else {
            add_radios(cJSON_AddArrayToObject(obj, "RadioList"), dpos);
        }

        if (!cJSON_AddItemToArray(arr, obj)) {
            cJSON_Delete(obj);
            return;
        }

        dev = (de_device_t *)hash_map_get_next(m_de_devices->m_device_map, dev);
    }
}

void comcast_optimizer_t::add_services(cJSON *parent)
{
    cJSON *arr, *obj;
    de_service_t *svc;

    if ((parent == NULL) || (m_de_services == NULL) || (m_de_services->m_service_map == NULL)) {
        return;
    }

    arr = cJSON_AddArrayToObject(parent, "X_RDK_Services");
    if (arr == NULL) {
        return;
    }

    svc = (de_service_t *)hash_map_get_first(m_de_services->m_service_map);
    while (svc != NULL) {
        obj = cJSON_CreateObject();
        if (obj == NULL) {
            return;
        }

        cJSON_AddNumberToObject(obj, "Type", (double)svc->m_type);
        cJSON_AddStringToObject(obj, "Operator", svc->m_operator_name);
        cJSON_AddStringToObject(obj, "URL", svc->m_url);

        if (!cJSON_AddItemToArray(arr, obj)) {
            cJSON_Delete(obj);
            return;
        }

        svc = (de_service_t *)hash_map_get_next(m_de_services->m_service_map, svc);
    }
}

const char *comcast_optimizer_t::get_de(char *buff, unsigned int len)
{
    cJSON *parent, *obj;

    if ((buff == NULL) || (len == 0)) {
        return "";
    }

    buff[0] = '\0';
    parent = cJSON_CreateObject();
    if (parent == NULL) {
        snprintf(buff, len, "{\"error\":\"Unable to create data elements response\"}");
        return (const char *)buff;
    }

    obj = cJSON_AddObjectToObject(parent, "wfa-dataelements:Network");
    if (obj == NULL) {
        cJSON_Delete(parent);
        snprintf(buff, len, "{\"error\":\"Unable to create network response\"}");
        return (const char *)buff;
    }

    if (m_de_network == NULL) {
        cJSON_AddStringToObject(obj, "Error", "Network data is not initialized");
    } else {
        add_network(obj);
    }
    if ((m_de_services == NULL) || (m_de_services->m_service_map == NULL)) {
        cJSON_AddStringToObject(obj, "ServicesError", "Service data is not initialized");
    } else {
        add_services(obj);
    }

    if ((m_de_devices == NULL) || (m_de_devices->m_device_map == NULL)) {
        cJSON_AddStringToObject(obj, "DevicesError", "Device data is not initialized");
    } else {
        add_devices(obj);
    }

    if (!cJSON_PrintPreallocated(parent, buff, len, true)) {
        snprintf(buff, len, "{\"error\":\"Data elements response is too large\"}");
    }
    cJSON_Delete(parent);

    return (const char *)buff;
}

const char *comcast_optimizer_t::get_topology(char *buff, unsigned int len)
{
    cJSON *obj, *parent, *arr;

    if ((buff == NULL) || (len == 0)) {
        return "";
    }

    buff[0] = '\0';
    parent = cJSON_CreateObject();
    if (parent == NULL) {
        snprintf(buff, len, "{\"error\":\"Unable to create topology response\"}");
        return buff;
    }

    obj = cJSON_AddObjectToObject(parent, "wfa-dataelements:Network");
    if (obj == NULL) {
        cJSON_Delete(parent);
        snprintf(buff, len, "{\"error\":\"Unable to create network response\"}");
        return buff;
    }

    cJSON_AddStringToObject(obj, "ID", "NetworkID");
    cJSON_AddStringToObject(obj, "ControllerID", "ControllerID");

    arr = cJSON_AddArrayToObject(obj, "Services");
    if (arr == NULL) {
        cJSON_Delete(parent);
        snprintf(buff, len, "{\"error\":\"Unable to create services response\"}");
        return buff;
    }

    obj = cJSON_CreateObject();
    if (obj == NULL) {
        cJSON_Delete(parent);
        snprintf(buff, len, "{\"error\":\"Unable to create service response\"}");
        return buff;
    }
    if (!cJSON_AddItemToArray(arr, obj)) {
        cJSON_Delete(obj);
        cJSON_Delete(parent);
        snprintf(buff, len, "{\"error\":\"Unable to add service response\"}");
        return buff;
    }

    cJSON_AddNumberToObject(obj, "Type", service_type_optimizer);
    cJSON_AddStringToObject(obj, "Operator", "comcast");
    cJSON_AddStringToObject(obj, "URL", "data");
    obj = cJSON_AddObjectToObject(obj, "Vendor");
    if (obj == NULL) {
        cJSON_Delete(parent);
        snprintf(buff, len, "{\"error\":\"Unable to create vendor response\"}");
        return buff;
    }
    cJSON_AddStringToObject(obj, "Mode", "RDKMesh");
    cJSON_AddStringToObject(obj, "Type", "Topology");

    if (!cJSON_PrintPreallocated(parent, buff, len, true)) {
        snprintf(buff, len, "{\"error\":\"Topology response is too large\"}");
    }
    cJSON_Delete(parent);

    return buff;
}

void comcast_optimizer_t::process_event(optimizer_event_t *ev)
{

}

void comcast_optimizer_t::process_timeout(char *time_str)
{

}

comcast_optimizer_t::comcast_optimizer_t()
{

}

comcast_optimizer_t::~comcast_optimizer_t()
{

}
