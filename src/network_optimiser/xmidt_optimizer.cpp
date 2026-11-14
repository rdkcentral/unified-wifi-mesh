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
#include "xmidt_optimizer.h"
#include "util.h"

void xmidt_optimizer_t::add_stas(cJSON *parent, unsigned int dpos, unsigned int rpos, unsigned int bpos)
{
    de_sta_t *sta;
    cJSON *obj;
    unsigned int posd, posr, posb, poss;

    if ((parent == NULL) || (m_de_network->m_de_devices == NULL) || (m_de_network->m_de_devices->m_de_radios == NULL) ||
        (m_de_network->m_de_devices->m_de_radios->m_de_bsss == NULL) || (m_de_network->m_de_devices->m_de_radios->m_de_bsss->m_de_stas == NULL) ||
        (m_de_network->m_de_devices->m_de_radios->m_de_bsss->m_de_stas->m_sta_map == NULL)) {
        return;
    }
            
    sta = (de_sta_t *)hash_map_get_first(m_de_network->m_de_devices->m_de_radios->m_de_bsss->m_de_stas->m_sta_map);
    while (sta != NULL) {
        if (sscanf(sta->m_key, DEVICES ".%u." RADIOS ".%u." BSSS ".%u." STAS ".%u", &posd, &posr, &posb, &poss) != 4) {
            printf("%s:%d: Stations position parse failure, Key: %s\n", __func__, __LINE__, sta->m_key);
            sta = (de_sta_t *)hash_map_get_next(m_de_network->m_de_devices->m_de_radios->m_de_bsss->m_de_stas->m_sta_map, sta);
            continue;
        }
            
        if (dpos != posd) {
            sta = (de_sta_t *)hash_map_get_next(m_de_network->m_de_devices->m_de_radios->m_de_bsss->m_de_stas->m_sta_map, sta);
            continue;
        }

        if (rpos != posr) {
            sta = (de_sta_t *)hash_map_get_next(m_de_network->m_de_devices->m_de_radios->m_de_bsss->m_de_stas->m_sta_map, sta);
            continue;
        }

        if (bpos != posb) {
            sta = (de_sta_t *)hash_map_get_next(m_de_network->m_de_devices->m_de_radios->m_de_bsss->m_de_stas->m_sta_map, sta);
            continue;
        }

        obj = cJSON_CreateObject();
        if (obj == NULL) {
            sta = (de_sta_t *)hash_map_get_next(m_de_network->m_de_devices->m_de_radios->m_de_bsss->m_de_stas->m_sta_map, sta);
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

        sta = (de_sta_t *)hash_map_get_next(m_de_network->m_de_devices->m_de_radios->m_de_bsss->m_de_stas->m_sta_map, sta);
    }

}

void xmidt_optimizer_t::add_bsss(cJSON *parent, unsigned int dpos, unsigned int rpos)
{
    de_bss_t *bss;
    cJSON *obj;
    unsigned int posd, posr, posb;

    if ((parent == NULL) || (m_de_network->m_de_devices == NULL) || (m_de_network->m_de_devices->m_de_radios == NULL) ||
        (m_de_network->m_de_devices->m_de_radios->m_de_bsss == NULL) || 
        (m_de_network->m_de_devices->m_de_radios->m_de_bsss->m_bss_map == NULL)) {
        return;
    }

    bss = (de_bss_t *)hash_map_get_first(m_de_network->m_de_devices->m_de_radios->m_de_bsss->m_bss_map);
    while (bss != NULL) {
        if (sscanf(bss->m_key, DEVICES ".%u." RADIOS ".%u." BSSS ".%u", &posd, &posr, &posb) != 3) {
            bss = (de_bss_t *)hash_map_get_next(m_de_network->m_de_devices->m_de_radios->m_de_bsss->m_bss_map, bss);
            continue;
        }

        if (dpos != posd) {
            bss = (de_bss_t *)hash_map_get_next(m_de_network->m_de_devices->m_de_radios->m_de_bsss->m_bss_map, bss);
            continue;
        }

        if (rpos != posr) {
            bss = (de_bss_t *)hash_map_get_next(m_de_network->m_de_devices->m_de_radios->m_de_bsss->m_bss_map, bss);
            continue;
        }

        obj = cJSON_CreateObject();
        if (obj == NULL) {
            bss = (de_bss_t *)hash_map_get_next(m_de_network->m_de_devices->m_de_radios->m_de_bsss->m_bss_map, bss);
            continue;
        }
        cJSON_AddItemToArray(parent, obj);

        cJSON_AddStringToObject(obj, "BSSID", bss->m_bssid);
        cJSON_AddStringToObject(obj, "SSID", bss->m_ssid);
        cJSON_AddBoolToObject(obj, "Enabled", bss->m_enabled);
        cJSON_AddBoolToObject(obj, "TransmittedBSSID", bss->m_broadcast);
        cJSON_AddBoolToObject(obj, "FronthaulUse", bss->m_fronthaul);
        cJSON_AddBoolToObject(obj, "BackhaulUse", bss->m_backhaul);

        if (m_de_network->m_de_devices->m_de_radios->m_de_bsss->m_de_stas == NULL) {
            cJSON_AddStringToObject(obj, "Error", "STA data is not initialized");
        } else {
            add_stas(cJSON_AddArrayToObject(obj, "STAList"), posd, posr, posb);
        }

        bss = (de_bss_t *)hash_map_get_next(m_de_network->m_de_devices->m_de_radios->m_de_bsss->m_bss_map, bss);
    }

}

void xmidt_optimizer_t::add_curr_op_classes(cJSON *parent, unsigned int dpos, unsigned int rpos)
{
    de_curr_op_class_t *op_class;
    cJSON *obj;
    unsigned int posd, posr, poso;

    if ((parent == NULL) || (m_de_network->m_de_devices == NULL) || (m_de_network->m_de_devices->m_de_radios == NULL) ||
        (m_de_network->m_de_devices->m_de_radios->m_de_curr_op_classes == NULL) ||
        (m_de_network->m_de_devices->m_de_radios->m_de_curr_op_classes->m_op_class_map == NULL)) {
        return;
    }

    op_class = (de_curr_op_class_t *)hash_map_get_first(m_de_network->m_de_devices->m_de_radios->m_de_curr_op_classes->m_op_class_map);
    while (op_class != NULL) {
        if (sscanf(op_class->m_key, DEVICES ".%u." RADIOS ".%u." CURR_OP_CLASSES ".%u", &posd, &posr, &poso) != 3) {
            op_class = (de_curr_op_class_t *)hash_map_get_next(m_de_network->m_de_devices->m_de_radios->m_de_curr_op_classes->m_op_class_map, op_class);
            continue;
        }

        if (dpos != posd) {
            op_class = (de_curr_op_class_t *)hash_map_get_next(m_de_network->m_de_devices->m_de_radios->m_de_curr_op_classes->m_op_class_map, op_class);
            continue;
        }

        if (rpos != posr) {
            op_class = (de_curr_op_class_t *)hash_map_get_next(m_de_network->m_de_devices->m_de_radios->m_de_curr_op_classes->m_op_class_map, op_class);
            continue;
        }

        obj = cJSON_CreateObject();
        if (obj == NULL) {
            op_class = (de_curr_op_class_t *)hash_map_get_next(m_de_network->m_de_devices->m_de_radios->m_de_curr_op_classes->m_op_class_map, op_class);
            continue;
        }
        cJSON_AddItemToArray(parent, obj);

        cJSON_AddNumberToObject(obj, "Class", static_cast<double>(op_class->m_class));
        cJSON_AddNumberToObject(obj, "TxPower", static_cast<double>(op_class->m_tx_power));
        cJSON_AddNumberToObject(obj, "Channel", static_cast<double>(op_class->m_channel));

        op_class = (de_curr_op_class_t *)hash_map_get_next(m_de_network->m_de_devices->m_de_radios->m_de_curr_op_classes->m_op_class_map, op_class);
    }

}

void xmidt_optimizer_t::add_op_classes(cJSON *parent, unsigned int dpos, unsigned int rpos)
{
    de_op_class_t *op_class;
    cJSON *obj;
    unsigned int posd, posr, poso;

    if ((parent == NULL) || (m_de_network->m_de_devices == NULL) || (m_de_network->m_de_devices->m_de_radios == NULL) ||
        (m_de_network->m_de_devices->m_de_radios->m_de_caps == NULL) ||
        (m_de_network->m_de_devices->m_de_radios->m_de_caps->m_de_op_classes == NULL) ||
        (m_de_network->m_de_devices->m_de_radios->m_de_caps->m_de_op_classes->m_op_class_map == NULL)) {
        return;
    }

    op_class = (de_op_class_t *)hash_map_get_first(m_de_network->m_de_devices->m_de_radios->m_de_caps->m_de_op_classes->m_op_class_map);
    while (op_class != NULL) {
        if (sscanf(op_class->m_key, DEVICES ".%u." RADIOS ".%u." CAPS "." OP_CLASSES ".%u", &posd, &posr, &poso) != 3) {
            op_class = (de_op_class_t *)hash_map_get_next(m_de_network->m_de_devices->m_de_radios->m_de_caps->m_de_op_classes->m_op_class_map, op_class);
            continue;
        }

        if ((dpos != posd) || (rpos != posr)) {
            op_class = (de_op_class_t *)hash_map_get_next(m_de_network->m_de_devices->m_de_radios->m_de_caps->m_de_op_classes->m_op_class_map, op_class);
            continue;
        }

        obj = cJSON_CreateObject();
        if (obj == NULL) {
            op_class = (de_op_class_t *)hash_map_get_next(m_de_network->m_de_devices->m_de_radios->m_de_caps->m_de_op_classes->m_op_class_map, op_class);
            continue;
        }
        cJSON_AddItemToArray(parent, obj);

        cJSON_AddNumberToObject(obj, "Class", static_cast<double>(op_class->m_class));
        cJSON_AddNumberToObject(obj, "MaxTxPower", static_cast<double>(op_class->m_max_tx_power));
        cJSON_AddNumberToObject(obj, "NumberOfNonOperChan", static_cast<double>(op_class->m_num_non_oper_chan));

        op_class = (de_op_class_t *)hash_map_get_next(m_de_network->m_de_devices->m_de_radios->m_de_caps->m_de_op_classes->m_op_class_map, op_class);
    }

}

void xmidt_optimizer_t::add_capabilities(cJSON *parent, unsigned int dpos, unsigned int rpos)
{
    de_cap_t *cap;
    unsigned int posd, posr;

    if ((parent == NULL) || (m_de_network->m_de_devices == NULL) || (m_de_network->m_de_devices->m_de_radios == NULL) ||
        (m_de_network->m_de_devices->m_de_radios->m_de_caps == NULL) ||
        (m_de_network->m_de_devices->m_de_radios->m_de_caps->m_cap_map == NULL)) {
        return;
    }

    cap = (de_cap_t *)hash_map_get_first(m_de_network->m_de_devices->m_de_radios->m_de_caps->m_cap_map);
    while (cap != NULL) {
        if ((sscanf(cap->m_key, DEVICES ".%u." RADIOS ".%u." CAPS, &posd, &posr) == 2) && (dpos == posd) && (rpos == posr)) {
            cJSON_AddNumberToObject(parent, "NumberOfOpClass", static_cast<double>(cap->m_num_op_class));
            cJSON_AddStringToObject(parent, "HTCapabilities", cap->m_ht_cap);
            break;
        }
        cap = (de_cap_t *)hash_map_get_next(m_de_network->m_de_devices->m_de_radios->m_de_caps->m_cap_map, cap);
    }

    add_op_classes(cJSON_AddArrayToObject(parent, "OperatingClasses"), dpos, rpos);
}

void xmidt_optimizer_t::add_radios(cJSON *parent, unsigned int dpos)
{
    de_radio_t *rd;
    cJSON *obj;
    unsigned int posd, posr;

    if ((parent == NULL) || (m_de_network->m_de_devices == NULL) || (m_de_network->m_de_devices->m_de_radios == NULL) ||
        (m_de_network->m_de_devices->m_de_radios->m_radio_map == NULL)) {
        return;
    }

    rd = (de_radio_t *)hash_map_get_first(m_de_network->m_de_devices->m_de_radios->m_radio_map);
    while (rd != NULL) {
        if (sscanf(rd->m_key, DEVICES ".%u." RADIOS ".%u", &posd, &posr) != 2) {
            rd = (de_radio_t *)hash_map_get_next(m_de_network->m_de_devices->m_de_radios->m_radio_map, rd);
            continue;
        }

        if (dpos != posd) {
            rd = (de_radio_t *)hash_map_get_next(m_de_network->m_de_devices->m_de_radios->m_radio_map, rd);
            continue;
        }

        obj = cJSON_CreateObject();
        if (obj == NULL) {
            rd = (de_radio_t *)hash_map_get_next(m_de_network->m_de_devices->m_de_radios->m_radio_map, rd);
            continue;
        }
        cJSON_AddItemToArray(parent, obj);

        cJSON_AddStringToObject(obj, "ID", rd->m_id);
        cJSON_AddBoolToObject(obj, "Enabled", rd->m_enabled);
        cJSON_AddNumberToObject(obj, "Utilization", static_cast<double>(rd->m_util));
        cJSON_AddNumberToObject(obj, "Noise", static_cast<double>(rd->m_noise));

        if (m_de_network->m_de_devices->m_de_radios->m_de_curr_op_classes == NULL) {
            cJSON_AddStringToObject(obj, "CurrentOperatingClassesError", "Current operating class data is not initialized");
        } else {
            add_curr_op_classes(cJSON_AddArrayToObject(obj, "CurrentOperatingClasses"), posd, posr);
        }

        if (m_de_network->m_de_devices->m_de_radios->m_de_caps == NULL) {
            cJSON_AddStringToObject(obj, "CapabilitiesError", "Capabilities data is not initialized");
        } else {
            add_capabilities(cJSON_AddObjectToObject(obj, "Capabilities"), posd, posr);
        }

        if (m_de_network->m_de_devices->m_de_radios->m_de_bsss == NULL) {
            cJSON_AddStringToObject(obj, "Error", "BSS data is not initialized");
        } else {
            add_bsss(cJSON_AddArrayToObject(obj, "BSSList"), posd, posr);
        }


        rd = (de_radio_t *)hash_map_get_next(m_de_network->m_de_devices->m_de_radios->m_radio_map, rd);
    }

}

void xmidt_optimizer_t::add_network(cJSON *parent)
{
    if ((parent == NULL) || (m_de_network == NULL)) {
        return;
    }

    cJSON_AddStringToObject(parent, "ID", m_de_network->m_id);
    cJSON_AddStringToObject(parent, "ControllerID", m_de_network->m_controller_id);
}


void xmidt_optimizer_t::add_devices(cJSON *parent)
{
    cJSON *arr, *obj;
    de_device_t *dev;
    unsigned int dpos;

    if ((parent == NULL) || (m_de_network->m_de_devices == NULL) || (m_de_network->m_de_devices->m_device_map == NULL)) {
        return;
    }

    arr = cJSON_AddArrayToObject(parent, "DeviceList");
    if (arr == NULL) {
        return;
    }

    dev = (de_device_t *)hash_map_get_first(m_de_network->m_de_devices->m_device_map);
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
            dev = (de_device_t *)hash_map_get_next(m_de_network->m_de_devices->m_device_map, dev);
            continue;
        }
        if (m_de_network->m_de_devices->m_de_radios == NULL) {
            cJSON_AddStringToObject(obj, "Error", "Radio data is not initialized");
        } else {
            add_radios(cJSON_AddArrayToObject(obj, "RadioList"), dpos);
        }

        if (!cJSON_AddItemToArray(arr, obj)) {
            cJSON_Delete(obj);
            return;
        }

        dev = (de_device_t *)hash_map_get_next(m_de_network->m_de_devices->m_device_map, dev);
    }
}

void xmidt_optimizer_t::add_services(cJSON *parent)
{
    cJSON *arr, *obj;
    de_service_t *svc;

    if ((parent == NULL) || (m_de_network->m_de_services == NULL) || (m_de_network->m_de_services->m_service_map == NULL)) {
        return;
    }

    arr = cJSON_AddArrayToObject(parent, "X_RDK_Services");
    if (arr == NULL) {
        return;
    }

    svc = (de_service_t *)hash_map_get_first(m_de_network->m_de_services->m_service_map);
    while (svc != NULL) {
        obj = cJSON_CreateObject();
        if (obj == NULL) {
            return;
        }

        cJSON_AddStringToObject(obj, "Type", svc->m_type);
        cJSON_AddStringToObject(obj, "Operator", svc->m_access);
        cJSON_AddStringToObject(obj, "URL", svc->m_url);

        if (!cJSON_AddItemToArray(arr, obj)) {
            cJSON_Delete(obj);
            return;
        }

        svc = (de_service_t *)hash_map_get_next(m_de_network->m_de_services->m_service_map, svc);
    }
}


void xmidt_optimizer_t::add_net_ssids(cJSON *parent)
{
    cJSON *arr, *obj;
    de_net_ssid_t *net_ssid;

    if (parent == NULL) {
        return;
    }

    arr = cJSON_AddArrayToObject(parent, "NetworkSSIDList");
    if (arr == NULL) {
        return;
    }

    net_ssid = (de_net_ssid_t *)hash_map_get_first(m_de_network->m_de_net_ssids->m_net_ssid_map);
    while (net_ssid != NULL) {
        unsigned int index;

        obj = cJSON_CreateObject();
        if (obj == NULL) {
            return;
        }

        if (sscanf(net_ssid->m_key, NET_SSIDS ".%u", &index) == 1) {
            cJSON_AddNumberToObject(obj, "Index", index);
        }
        cJSON_AddStringToObject(obj, "SSID", net_ssid->m_ssid);
        cJSON_AddBoolToObject(obj, "Enable", net_ssid->m_enabled);
        cJSON_AddBoolToObject(obj, "AdvertisementEnabled", net_ssid->m_advertisement);
        cJSON_AddStringToObject(obj, "MFPConfig", net_ssid->m_mfp_config);
        cJSON_AddStringToObject(obj, "MobilityDomain", net_ssid->m_mob_domain);
        cJSON_AddStringToObject(obj, "Band", net_ssid->m_band);
        cJSON_AddStringToObject(obj, "AKMsAllowed", net_ssid->m_akms_allowed);
        cJSON_AddStringToObject(obj, "SuiteSelector", net_ssid->m_suite_selector);
        cJSON_AddStringToObject(obj, "HaulType", net_ssid->m_haul_type);
        cJSON_AddStringToObject(obj, "Type", net_ssid->m_type);

        if (!cJSON_AddItemToArray(arr, obj)) {
            cJSON_Delete(obj);
            return;
        }

        net_ssid = (de_net_ssid_t *)hash_map_get_next(m_de_network->m_de_net_ssids->m_net_ssid_map, net_ssid);
    }

    printf("%s:%d: Number of elements added: %d\n", __func__, __LINE__, cJSON_GetArraySize(arr));
}

cJSON *xmidt_optimizer_t::get_de()
{
    cJSON *parent, *obj;

    if ((parent = cJSON_CreateObject()) == NULL) {
        return NULL;
    }

    obj = cJSON_AddObjectToObject(parent, "Device");
    obj = cJSON_AddObjectToObject(obj, "WiFI");
    obj = cJSON_AddObjectToObject(obj, "DataElements");
    obj = cJSON_AddObjectToObject(obj, "Network");

    if (m_de_network == NULL) {
        cJSON_AddStringToObject(obj, "Error", "Network data is not initialized");
    } else {
        add_network(obj);

        if ((m_de_network->m_de_services == NULL) || (m_de_network->m_de_services->m_service_map == NULL)) {
            cJSON_AddStringToObject(obj, "ServicesError", "Service data is not initialized");
        } else {
            add_services(obj);
        }

        if ((m_de_network->m_de_devices == NULL) || (m_de_network->m_de_devices->m_device_map == NULL)) {
            cJSON_AddStringToObject(obj, "DevicesError", "Device data is not initialized");
        } else {
            add_devices(obj);
        }

        if ((m_de_network->m_de_net_ssids == NULL) || (m_de_network->m_de_net_ssids->m_net_ssid_map == NULL)) {
            cJSON_AddStringToObject(obj, "NetworkSSIDError", "Device data is not initialized");
        } else {
            add_net_ssids(obj);
        }
    }

    return parent;
}

cJSON *xmidt_optimizer_t::full_scan(cJSON *in)
{
    cJSON *parent, *elem;
    de_scan_t scan;
    const char *str;
    em_string_t status; 
    em_long_string_t method_name;
    de_device_t *dev;
    de_radio_t *radio;
    bool found = false;

    if ((parent = cJSON_CreateObject()) == NULL) {
        return NULL;
    }

    if (in == NULL) {
        cJSON_AddStringToObject(parent, "Status", "Error_Other");
        return parent;
    }

    elem = cJSON_GetObjectItem(in, "Device");
    str = cJSON_GetStringValue(elem);
    strncpy(scan.m_device, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(in, "Radio");
    str = cJSON_GetStringValue(elem);
    strncpy(scan.m_radio, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(in, "Band");
    str = cJSON_GetStringValue(elem);
    strncpy(scan.m_band, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(in, "DwellTime");
    scan.m_dwell_time = cJSON_GetNumberValue(elem);
    
    elem = cJSON_GetObjectItem(in, "DFSDwellTime");
    scan.m_dwell_time = cJSON_GetNumberValue(elem);
    
    elem = cJSON_GetObjectItem(in, "HomeTime");
    scan.m_dwell_time = cJSON_GetNumberValue(elem);

    elem = cJSON_GetObjectItem(in, "SSID");
    str = cJSON_GetStringValue(elem);
    strncpy(scan.m_ssid, str, strlen(str) + 1);

    dev = (de_device_t *)hash_map_get_first(m_de_network->m_de_devices->m_device_map); 
    while (dev != NULL) {
        if (strncmp(dev->m_id, scan.m_device, strlen(scan.m_device)) == 0) {
            found = true;
            break;
        }
        dev = (de_device_t *)hash_map_get_next(m_de_network->m_de_devices->m_device_map, dev);
    }

    if (found == false) {
        cJSON_AddStringToObject(parent, "Status", "Error_Other");
        return parent;
    }

    found = false;

    radio = (de_radio_t *)hash_map_get_first(m_de_network->m_de_devices->m_de_radios->m_radio_map);
    while (radio != NULL) {
        if (strncmp(radio->m_id, scan.m_radio, strlen(scan.m_radio)) == 0) {
            found = true;
            break;
        }
        
        radio = (de_radio_t *)hash_map_get_next(m_de_network->m_de_devices->m_de_radios->m_radio_map, radio);
    }

    if (found == false) {
        cJSON_AddStringToObject(parent, "Status", "Error_Other");
        return parent;
    }

    snprintf(method_name, sizeof(method_name), "%s%s.%s", DE_NETWORK, radio->m_key, FULL_SCAN);

    if (m_de_network->m_de_devices->m_de_radios->invoke_method(method_name, &scan, status) != 0) {
        cJSON_AddStringToObject(parent, "Status", "Error_Other");
        return parent;
    }

    cJSON_AddStringToObject(parent, "Status", status);

    return parent;
}

cJSON *xmidt_optimizer_t::channel_scan(cJSON *in)
{

}

cJSON *xmidt_optimizer_t::set_ssid(cJSON *in)
{
    cJSON *parent, *elem;
    de_net_ssid_t net_ssid;
    const char *str;
    em_string_t status;

    if ((parent = cJSON_CreateObject()) == NULL) {
        return NULL;
    }

    if (in == NULL) {
        cJSON_AddStringToObject(parent, "Status", "Error_Other");
        return parent;
    }

    elem = cJSON_GetObjectItem(in, "SSID");
    str = cJSON_GetStringValue(elem);
    strncpy(net_ssid.m_ssid, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(in, "Enable");
    net_ssid.m_enabled = cJSON_IsTrue(elem);

    elem = cJSON_GetObjectItem(in, "AddRemoveChange");
    str = cJSON_GetStringValue(elem);
    strncpy(net_ssid.m_op, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(in, "PassPhrase");
    str = cJSON_GetStringValue(elem);
    strncpy(net_ssid.m_passphrase, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(in, "Band");
    str = cJSON_GetStringValue(elem);
    strncpy(net_ssid.m_band, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(in, "AKMsAllowed");
    str = cJSON_GetStringValue(elem);
    strncpy(net_ssid.m_akms_allowed, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(in, "SuiteSelector");
    str = cJSON_GetStringValue(elem);
    strncpy(net_ssid.m_akms_allowed, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(in, "AdvertisementEnabled");
    net_ssid.m_advertisement = cJSON_IsTrue(elem);

    elem = cJSON_GetObjectItem(in, "MFPConfig");
    str = cJSON_GetStringValue(elem);
    strncpy(net_ssid.m_mfp_config, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(in, "MobilityDomain");
    str = cJSON_GetStringValue(elem);
    strncpy(net_ssid.m_mob_domain, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(in, "HaulType");
    str = cJSON_GetStringValue(elem);
    strncpy(net_ssid.m_haul_type, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(in, "Type");
    str = cJSON_GetStringValue(elem);
    strncpy(net_ssid.m_type, str, strlen(str) + 1);

    if (m_de_network->m_de_net_ssids->invoke_method(DE_NET_SSID_SET, &net_ssid, status) != 0) {
        cJSON_AddStringToObject(parent, "Status", "Error_Other");
        return parent;
    }
        
    cJSON_AddStringToObject(parent, "Status", status);

    return parent;
}

cJSON *xmidt_optimizer_t::get_topology()
{
    cJSON *obj, *parent, *arr;

    if ((parent = cJSON_CreateObject()) == NULL) {
        return NULL;
    }

    obj = cJSON_AddObjectToObject(parent, "wfa-dataelements:Network");

    cJSON_AddStringToObject(obj, "ID", "NetworkID");
    cJSON_AddStringToObject(obj, "ControllerID", "ControllerID");

    return parent;
}

cJSON *xmidt_optimizer_t::nbr_diagnostics()
{
    de_nbr_node_t *node;
    cJSON *parent, *item, *arr;
    em_string_t key;

    if ((parent = cJSON_CreateObject()) == NULL) {
        return NULL;
    }

    cJSON_AddStringToObject(parent, "Status", "Complete");
    arr = cJSON_AddArrayToObject(parent, "Results");
    
    if (m_de_nbr_nodes->invoke_method(NBR_WIFI_DIAG, NULL, NULL) != 0) {
        cJSON_AddStringToObject(parent, "Status", "Error_Other");
        return parent;
    }
       
    node = (de_nbr_node_t *)hash_map_get_first(m_de_nbr_nodes->m_nbr_node_map);
    while (node != NULL) {
        item = cJSON_CreateObject();
        cJSON_AddItemToArray(arr, item);

        cJSON_AddStringToObject(item, "Radio", node->m_radio);
        cJSON_AddStringToObject(item, "SSID", node->m_ssid);
        cJSON_AddStringToObject(item, "BSSID", node->m_bssid);
        cJSON_AddStringToObject(item, "Mode", node->m_mode);
        cJSON_AddNumberToObject(item, "Channel", node->m_channel);
        cJSON_AddNumberToObject(item, "SignalStrength", node->m_signal_strength);
        cJSON_AddStringToObject(item, "SecurityModeEnabled", node->m_security_mode_enabled);
        cJSON_AddStringToObject(item, "EncryptionMode", node->m_encryption_mode);
        cJSON_AddStringToObject(item, "OperatingFrequencyBand", node->m_op_frequency_band);
        cJSON_AddStringToObject(item, "SupportedStandards", node->m_supported_standards);
        cJSON_AddStringToObject(item, "OperatingStandards", node->m_op_standards);
        cJSON_AddStringToObject(item, "OperatingChannelBandwidth", node->m_op_channel_bw);
        cJSON_AddNumberToObject(item, "BeaconPeriod", node->m_beacon_period);
        cJSON_AddNumberToObject(item, "Noise", node->m_noise);
        cJSON_AddStringToObject(item, "BasicDataTransferRates", node->m_basic_data_tx_rated);
        cJSON_AddStringToObject(item, "SupportedDataTransferRates", node->m_supported_data_tx_rates);
        cJSON_AddNumberToObject(item, "DTIMPeriod", node->m_dtim_period);

        node = (de_nbr_node_t *)hash_map_get_next(m_de_nbr_nodes->m_nbr_node_map, node); 
    } 

    return parent;
}

void xmidt_optimizer_t::process_event(optimizer_event_t *ev)
{

}

void xmidt_optimizer_t::process_timeout(char *time_str)
{

}

xmidt_optimizer_t::xmidt_optimizer_t()
{

}

xmidt_optimizer_t::~xmidt_optimizer_t()
{

}
