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
#include <assert.h>
#include <unistd.h>
#if 0
#include <libubox/utils.h>
#endif

#include "em_ctrl.h"
#include "tr_181.h"

#define DATAELEMS_NETWORK       "Device.WiFi.DataElements.Network."

#define MAX_INSTANCE_LEN        32
#define MAX_CAPS_STR_LEN        32
#define ARRAY_SIZE(a)           (sizeof(a) / sizeof(a[0]))

extern em_ctrl_t g_ctrl;

bus_error_t radio_tget_params(dm_easy_mesh_t *dm, const char *root, bus_data_prop_t **property);
bus_error_t curops_tget_params(dm_easy_mesh_t *dm, const char *root, em_radio_info_t *ri, bus_data_prop_t **property);
bus_error_t bss_tget_params(dm_easy_mesh_t *dm, const char *root, em_radio_info_t *ri, bus_data_prop_t **property);
bus_error_t sta_tget_params(dm_easy_mesh_t *dm, const char *root, em_bss_info_t *bi, bus_data_prop_t **property);

mac_addr_str_t g_temp_node_mac = {0};

bus_error_t em_ctrl_t::get_node_sync(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    p_data->data_type       = bus_data_type_string;
    p_data->raw_data.bytes  = malloc(sizeof(mac_addr_str_t));
    if (p_data->raw_data.bytes == NULL) {
        em_printfout("Memory allocation is failed\r");
        return bus_error_out_of_resources;
    }
    em_printfout(" get_node_sync: node mac len: %d", sizeof(mac_addr_str_t));

    strncpy((char *)p_data->raw_data.bytes, (const char *)g_temp_node_mac, sizeof(g_temp_node_mac));
    p_data->raw_data_len    = sizeof(mac_addr_str_t);

    em_printfout(" get_node_sync: node mac: %s", p_data->raw_data.bytes);

    return bus_error_success;
}

bus_error_t em_ctrl_t::set_node_sync(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    wifi_bus_desc_t *desc = NULL;
    raw_data_t raw;

    em_printfout(" Event rcvd: %s for node mac: %s", event_name, p_data->raw_data.bytes);

    snprintf(g_temp_node_mac, sizeof(mac_addr_str_t), "%s", (char *)p_data->raw_data.bytes);

    if((desc = get_bus_descriptor()) == NULL) {
        em_printfout("%s:%d descriptor is null\n", __func__, __LINE__);
    }

    //TODO: Temp code to publish node sync once received
    raw.data_type    = bus_data_type_string;
    raw.raw_data.bytes = reinterpret_cast<unsigned char *> (g_temp_node_mac);
    raw.raw_data_len = static_cast<unsigned int> (strlen(g_temp_node_mac));

    if (desc->bus_event_publish_fn(&g_ctrl.m_bus_hdl, DEVICE_WIFI_DATAELEMENTS_NETWORK_NODE_SYNC, &raw)== 0) {
        em_printfout("Node sync published successfull\n",__func__, __LINE__);
    } else {
        em_printfout("Node sync publish fail\n",__func__, __LINE__);
    }

    return bus_error_success;
}

bus_error_t em_ctrl_t::policy_config(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_printfout(" Event rcvd: %s\n Policy cfg is: \n%s\n", event_name, p_data->raw_data.bytes);

    return bus_error_success;
}

bus_error_t em_ctrl_t::get_device_wifi_dataelements_network_colocated_agentid (char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_interface_t  *intf;
    mac_addr_str_t  al_mac_str;
    int len = 0;
    
    intf = g_ctrl.m_data_model.get_ctrl_al_interface(const_cast<char *> (GLOBAL_NET_ID));
    
    dm_easy_mesh_t::macbytes_to_string(intf->mac, al_mac_str);
    p_data->data_type    = bus_data_type_string;
    len = strlen(al_mac_str) + 1;
    p_data->raw_data.bytes = malloc(len);
    if (p_data->raw_data.bytes == NULL) {
        em_printfout("Memory allocation is failed:%d\r", len);
        return bus_error_out_of_resources;
    }
    snprintf((char*)p_data->raw_data.bytes, len, "%s", al_mac_str);
    p_data->raw_data_len = len;

    return bus_error_success;
}

bus_error_t em_ctrl_t::get_device_wifi_dataelements_network_controllerid (char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_interface_t  *intf;
    int len = 0;
    mac_addr_str_t  ctrl_mac;

    dm_easy_mesh_t::macbytes_to_string(g_ctrl.m_data_model.get_network(GLOBAL_NET_ID)->get_network_info()->ctrl_id.mac, ctrl_mac);
    em_printfout("Ctrlr mac: %s", ctrl_mac);
    len = strlen(ctrl_mac) + 1;
    p_data->data_type = bus_data_type_string;
    p_data->raw_data.bytes = malloc(len);
    if (p_data->raw_data.bytes == NULL) {
        em_printfout("Memory allocation is failed:%d\r", len);
        return bus_error_out_of_resources;
    }
    snprintf((char*)p_data->raw_data.bytes, len, "%s", ctrl_mac);
    p_data->raw_data_len = len;
    em_printfout("Descriptor value=%s, len=%d\n", (char *)p_data->raw_data.bytes, p_data->raw_data_len);

    return bus_error_success;
}

const char *get_table_instance(const char *src, char *instance, size_t max_len, bool *is_num)
{
	char *dst = instance;
	size_t len = 0;

    src = strstr(src, ".");
    ++src;

	if (*src == '[') {
		*is_num = false;
		++src;
		while (*src && *src != ']' && ++len < max_len) {
			*dst++ = *src++;
		}
		*dst++ = 0;
		src += 2;
	} else {
		*is_num = true;
		while (*src && *src != '.' && ++len < max_len) {
			*dst++ = *src++;
		}
		*dst++ = 0;
		src++;
	}

	return src;
}

dm_easy_mesh_t *get_dm_easy_mesh(char *instance, bool is_num)
{
    dm_easy_mesh_t *dm = g_ctrl.get_first_dm();

    if (is_num) {
        int i = 0;
        do {
            if (i == atoi(instance) - 1) {
                return dm;
            }
            ++i;
            dm = g_ctrl.get_next_dm(dm);
        } while (dm != NULL);

        return NULL;
    }

    do {
        char mac_str[18];
        dm_device_t *dev = dm->get_device();
        if (dev == NULL) {
            dm = g_ctrl.get_next_dm(dm);
            continue;
        }
        em_device_info_t *di = dev->get_device_info();
        dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (di->id.dev_mac), mac_str);
        if (strcmp(instance, mac_str) == 0) {
            return dm;
        }
        dm = g_ctrl.get_next_dm(dm);
    } while (dm != NULL);

    return NULL;
}

dm_device_t *get_dm_dev(mac_address_t dev_mac, mac_address_t bmac)
{
    dm_easy_mesh_t *dm = g_ctrl.get_first_dm();
    do {
        dm_device_t *dev = dm->get_device();
        if (dev == NULL) {
            dm = g_ctrl.get_next_dm(dm);
            continue;
        }
        em_device_info_t *sdi = dev->get_device_info();
        if (memcmp(dev_mac, sdi->id.dev_mac, sizeof(sdi->id.dev_mac)) == 0) {
            dm = g_ctrl.get_next_dm(dm);
            continue;
        }

        for (unsigned int i = 0; i < dm->get_num_bss(); i++) {
            dm_bss_t *bss = dm->get_bss(i);
            if (bss == NULL) {
                continue;
            }
            em_bss_info_t *bi = bss->get_bss_info();
            if (memcmp(bmac, bi->bssid.mac, sizeof(bi->bssid.mac)) == 0) {
                return dev;
            }
        }
        dm = g_ctrl.get_next_dm(dm);
    } while (dm != NULL);

    return NULL;
}

dm_radio_t *get_dm_radio(dm_easy_mesh_t *dm, char *instance, bool is_num)
{
    dm_radio_t *radio = NULL;

    if (is_num) {
        unsigned int idx = static_cast<unsigned int>(atoi(instance) - 1);
        radio = dm->get_radio(idx);
        return radio;
    }

    for (unsigned int i = 0; i < dm->get_num_radios(); i++) {
        char mac_str[18];
        radio = dm->get_radio(i);
        if (radio == NULL) {
            continue;
        }
        em_radio_info_t *ri = radio->get_radio_info();
        dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (ri->id.ruid), mac_str);
        /* Probably wrong, we need base64 */
        if (strcmp(instance, mac_str) == 0) {
            return radio;
        }
    }

    return radio;
}

dm_sta_t *get_dm_bh_sta(dm_easy_mesh_t *dm, dm_radio_t *radio)
{
    dm_device_t *dev = dm->get_device();
    if (dev == NULL) {
        return NULL;
    }
    em_device_info_t *di = dev->get_device_info();
    if (memcmp(di->backhaul_mac.mac, ZERO_MAC_ADDR, sizeof(ZERO_MAC_ADDR)) == 0) {
        return NULL;
    }

    dm_easy_mesh_t *sdm = g_ctrl.get_first_dm();
    do {
        dm_device_t *sdev = sdm->get_device();
        if (sdev == NULL) {
            sdm = g_ctrl.get_next_dm(sdm);
            continue;
        }
        em_device_info_t *sdi = sdev->get_device_info();
        if (memcmp(di->id.dev_mac, sdi->id.dev_mac, sizeof(di->id.dev_mac)) == 0) {
            sdm = g_ctrl.get_next_dm(sdm);
            continue;
        }

        dm_sta_t *sta = static_cast<dm_sta_t *> (hash_map_get_first(sdm->m_sta_map));
        while (sta != NULL) {
            em_sta_info_t *si = sta->get_sta_info();
            if (si->associated == 0) {
                sta = static_cast<dm_sta_t *> (hash_map_get_next(sdm->m_sta_map, sta));
                continue;
            }
            //si->radiomac; radio->m_radio_info.
            if (memcmp(di->backhaul_mac.mac, si->bssid, sizeof(si->bssid)) == 0) {
                return sta;
            }
            sta = static_cast<dm_sta_t *> (hash_map_get_next(sdm->m_sta_map, sta));
        }

        sdm = g_ctrl.get_next_dm(sdm);
    } while (sdm != NULL);

    return NULL;
}

dm_op_class_t *get_dm_curop(dm_easy_mesh_t *dm, dm_radio_t *radio, char *instance, bool is_num)
{
    unsigned int ocnt = 0;
    unsigned int idx = 0;
    em_radio_info_t *ri = radio->get_radio_info();

    if (!is_num) {
        return NULL;
    }
    idx = static_cast<unsigned int>(atoi(instance));

    for (unsigned int i = 0; i < dm->get_num_op_class(); i++) {
        dm_op_class_t *op_class = dm->get_op_class(i);
        if (op_class == NULL) {
            continue;
        }
        em_op_class_info_t *oci = op_class->get_op_class_info();
        if (oci->id.type != em_op_class_type_current) {
            continue;
        }
        if (memcmp(ri->id.ruid, oci->id.ruid, sizeof(oci->id.ruid)) != 0) {
            continue;
        }
        ++ocnt;
        if (ocnt == idx) {
            return op_class;
        }
    }

    return NULL;
}

dm_bss_t *get_dm_bss(dm_easy_mesh_t *dm, dm_radio_t *radio, char *instance, bool is_num)
{
    unsigned int bcnt = 0;
    unsigned int idx = 0;
    mac_address_t mac = { 0 };
    em_radio_info_t *ri = radio->get_radio_info();

    if (is_num) {
        idx = static_cast<unsigned int>(atoi(instance));
    } else {
        dm_easy_mesh_t::string_to_macbytes(instance, mac);
    }

    for (unsigned int i = 0; i < dm->get_num_bss(); i++) {
        dm_bss_t *bss = dm->get_bss(i);
        if (bss == NULL) {
            continue;
        }
        em_bss_info_t *bi = bss->get_bss_info();
        if (memcmp(bi->bssid.mac, ZERO_MAC_ADDR, sizeof(ZERO_MAC_ADDR)) == 0 ||
            memcmp(ri->id.ruid, bi->ruid.mac, sizeof(bi->ruid.mac)) != 0) {
            continue;
        }
        ++bcnt;
        if (bcnt == 4) { /* A very nasy hack, to prevent bss index 4 */
            continue;
        }
        if (is_num) {
            if (bcnt == idx) {
                return bss;
            }
        } else {
            if (memcmp(mac, bi->bssid.mac, sizeof(bi->bssid.mac)) == 0) {
                return bss;
            }
        }
    }

    return NULL;
}

dm_sta_t *get_dm_sta(dm_easy_mesh_t *dm, dm_bss_t *bss, char *instance, bool is_num)
{
    unsigned int scnt = 0;
    unsigned int idx = 0;
    mac_address_t mac = { 0 };
    em_bss_info_t *bi = bss->get_bss_info();

    if (is_num) {
        idx = static_cast<unsigned int>(atoi(instance));
    } else {
        dm_easy_mesh_t::string_to_macbytes(instance, mac);
    }

    dm_sta_t *sta = static_cast<dm_sta_t *> (hash_map_get_first(dm->m_sta_map));
    while (sta != NULL) {
        em_sta_info_t *si = sta->get_sta_info();
        if (si->associated == 0 ||
            memcmp(bi->bssid.mac, si->bssid, sizeof(si->bssid)) != 0) {
            sta = static_cast<dm_sta_t *> (hash_map_get_next(dm->m_sta_map, sta));
            continue;
        }
        ++scnt;
        if (is_num) {
            if (scnt == idx) {
                return sta;
            }
        } else {
            if (memcmp(mac, si->id, sizeof(si->id)) == 0) {
                return sta;
            }
        }
        sta = static_cast<dm_sta_t *> (hash_map_get_next(dm->m_sta_map, sta));
    }

    return NULL;
}

void fill_comma_sep(em_short_string_t str[], size_t max, char *buf)
{
    unsigned int cnt = 0;
    const char *delim = NULL;

    if (max > 15) {
        max = 15;
    }

    while (cnt < max) {
        if (strlen(str[cnt]) > 0) {
            if (delim) {
                strcat(buf, delim);
            } else {
                delim = ",";
            }
            strcat(buf, str[cnt]);
        } else {
            break;
        }
        cnt++;
    }
}

void fill_haul_type(em_haul_type_t hauls[], size_t max, char *buf)
{
    unsigned int cnt = 0;
    const char *delim = NULL;
    const char *str;

    if (max > 8) {
        max = 8;
    }

    while (cnt < max) {
        switch (hauls [cnt]) {
            case em_haul_type_fronthaul: str = "Fronthaul"; break;
            case em_haul_type_backhaul: str = "Backhaul"; break;
            case em_haul_type_iot: str = "IoT"; break;
            case em_haul_type_configurator: str = "Configurator"; break;
            case em_haul_type_hotspot: str = "Hotspot"; break;
            default: str = NULL; break;
        }
        if (str == NULL) {
            break;
        }
        if (delim) {
            strcat(buf, delim);
        } else {
            delim = ",";
        }
        strcat(buf, str);
        ++cnt;
    }
}

bus_error_t raw_data_set(raw_data_t *p_data, bool b)
{
    p_data->data_type = bus_data_type_boolean;
    p_data->raw_data.b = b;
    return bus_error_success;
}

bus_error_t raw_data_set(raw_data_t *p_data, int32_t i)
{
    p_data->data_type = bus_data_type_int32;
    p_data->raw_data.i32 = i;
    return bus_error_success;
}

bus_error_t raw_data_set(raw_data_t *p_data, uint8_t u)
{
    p_data->data_type = bus_data_type_uint8;
    p_data->raw_data.u8 = u;
    return bus_error_success;
}

bus_error_t raw_data_set(raw_data_t *p_data, uint16_t u)
{
    p_data->data_type = bus_data_type_uint16;
    p_data->raw_data.u16 = u;
    return bus_error_success;
}

bus_error_t raw_data_set(raw_data_t *p_data, uint32_t u)
{
    p_data->data_type = bus_data_type_uint32;
    p_data->raw_data.u32 = u;
    return bus_error_success;
}

bus_error_t raw_data_set(raw_data_t *p_data, const char *str)
{
    uint32_t str_size;

    str_size = strlen(str) + 1;
    p_data->data_type = bus_data_type_string;
    p_data->raw_data.bytes = malloc(str_size);
    if (p_data->raw_data.bytes == NULL) {
        return bus_error_out_of_resources;
    }
    memcpy(p_data->raw_data.bytes, str, str_size);
    p_data->raw_data_len = str_size;

    return bus_error_success;
}

bus_error_t raw_data_set(raw_data_t *p_data, mac_address_t mac)
{
    mac_addr_str_t mac_str;

    p_data->data_type = bus_data_type_string;
    p_data->raw_data.bytes = malloc(sizeof(mac_addr_str_t));
    if (p_data->raw_data.bytes == NULL) {
        return bus_error_out_of_resources;
    }
    dm_easy_mesh_t::macbytes_to_string(mac, mac_str);
    memcpy(p_data->raw_data.bytes, mac_str, sizeof(mac_addr_str_t));
    p_data->raw_data_len = sizeof(mac_addr_str_t);

    return bus_error_success;
}

bus_error_t raw_data_set(raw_data_t *p_data, wifi_ieee80211Variant_t var)
{
    const char *var_str;

    switch (var) {
        case WIFI_80211_VARIANT_A:
            var_str = "IEEE 802.11a";
            break;
        case WIFI_80211_VARIANT_B:
            var_str = "IEEE 802.11b";
            break;
        case WIFI_80211_VARIANT_G:
            var_str = "IEEE 802.11g";
            break;
        case WIFI_80211_VARIANT_N:
            var_str = "IEEE 802.11n 2.4";
            break;
        case WIFI_80211_VARIANT_H:
            var_str = "IEEE 802.11n 5.0";
            break;
        case WIFI_80211_VARIANT_AC:
            var_str = "IEEE 802.11ac";
            break;
        case WIFI_80211_VARIANT_AD:
            var_str = "IEEE 802.11ad";
            break;
        case WIFI_80211_VARIANT_AX:
            var_str = "IEEE 802.11ax";
            break;
        case WIFI_80211_VARIANT_BE:
            var_str = "IEEE 802.11be";
            break;
        default:
            var_str = "Generic PHY";
            break;
    }

    return raw_data_set(p_data, var_str);
}

bus_error_t raw_data_set(raw_data_t *p_data, bus_data_prop_t *property)
{
    p_data->data_type = bus_data_type_property;
    p_data->raw_data.bytes = malloc(sizeof(bus_data_prop_t));
    if (p_data->raw_data.bytes == NULL) {
        return bus_error_out_of_resources;
    }
    memcpy(p_data->raw_data.bytes, property, sizeof(bus_data_prop_t));
    p_data->raw_data_len = sizeof(bus_data_prop_t);

    return bus_error_success;
}

template <typename T> bus_data_prop_t *property_init_value(const char *root, unsigned int idx, const char *param, T value)
{
    bus_data_prop_t *property = (bus_data_prop_t *)calloc(1, sizeof(bus_data_prop_t));

    if (property == NULL) {
        return NULL;
    }

    snprintf(property->name, sizeof(bus_name_string_t), "%s%d.%s", root, idx, param);
    raw_data_set(&property->value, value);
    property->name_len = static_cast<uint32_t>(strlen(property->name));
    property->is_data_set = true;

    return property;
}

template <typename T> void property_append_tail(bus_data_prop_t **property, const char *root, unsigned int idx, const char *param, T value)
{
    bus_data_prop_t *tail;
    bus_data_prop_t *last;

    if (*property == NULL) {
        *property = property_init_value(root, idx, param, value);
    } else {
        tail = (bus_data_prop_t *)calloc(1, sizeof(bus_data_prop_t));
        snprintf(tail->name, sizeof(bus_name_string_t), "%s%d.%s", root, idx, param);
        raw_data_set(&tail->value, value);
        tail->name_len = static_cast<uint32_t>(strlen(tail->name));
        tail->is_data_set = true;

        last = *property;
        while (last->next_data) {
            last = last->next_data;
        }
        last->next_data = tail;
    }
}

bus_error_t network_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    (void) user_data;
    const char *name = event_name;
    const char *param;
    bus_error_t rc = bus_error_success;

    if (!name || !p_data) {
        return bus_error_invalid_input;
    }

    param = strrchr(name, '.');
    if (param == NULL) {
        return bus_error_invalid_input;
    }
    ++param;

    em_string_t str_val = { 0 };
    if (strcmp(param, "ID") == 0) {
        strncpy(str_val, GLOBAL_NET_ID, sizeof(str_val) - 1);
        rc = raw_data_set(p_data, str_val);
    } else if (strcmp(param, "ControllerID") == 0) {
        dm_easy_mesh_t *dm = g_ctrl.get_first_dm();
        dm_easy_mesh_t::macbytes_to_string(dm->get_controller_interface_mac(), str_val);
        //dm_easy_mesh_t::macbytes_to_string(dm->get_network_info()->ctrl_id.mac, str_val);
        rc = raw_data_set(p_data, str_val);
    } else if (strcmp(param, "ColocatedAgentID") == 0) {
        dm_easy_mesh_t *dm = g_ctrl.get_first_dm();
        dm_easy_mesh_t::macbytes_to_string(dm->get_ctrl_al_interface_mac(), str_val);
        //dm_easy_mesh_t::macbytes_to_string(dm->get_network_info()->ctrl_id.mac, str_val);
        rc = raw_data_set(p_data, str_val);
    } else if (strcmp(param, "DeviceNumberOfEntries") == 0) {
        unsigned int dev_cnt = 0;
        dm_easy_mesh_t *dm = g_ctrl.get_first_dm();
        while (dm != NULL) {
            dm_device_t *dev = dm->get_device();
            if (dev != NULL) {
                em_device_info_t *di = dev->get_device_info();
                if (memcmp(di->id.dev_mac, ZERO_MAC_ADDR, sizeof(di->id.dev_mac)) != 0) {
                    ++dev_cnt;
                }
            }
            dm = g_ctrl.get_next_dm(dm);
        }
        rc = raw_data_set(p_data, dev_cnt);
    } else {
        rc = bus_error_invalid_input;
    }

    return rc;
}

bus_error_t device_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    (void) user_data;
    const char *name = event_name;
    const char *param;
    char instance[MAX_INSTANCE_LEN] = { 0 };
    bool is_num;
    bus_error_t rc;

    if (!name || !p_data) {
        return bus_error_invalid_input;
    }

    param = strrchr(name, '.');
    if (param == NULL) {
        return bus_error_invalid_input;
    }
    ++param;

    name += sizeof(DATAELEMS_NETWORK);
    name = get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    dm_easy_mesh_t *dm = get_dm_easy_mesh(instance, is_num);
    if (dm == NULL) {
        printf("data model is NULL\n");
        return bus_error_invalid_input;
    }
    dm_device_t *dev = dm->get_device();
    if (dev == NULL) {
        printf("device is NULL\n");
        return bus_error_invalid_input;
    }
    em_device_info_t *di = dev->get_device_info();
    if (memcmp(di->id.dev_mac, ZERO_MAC_ADDR, sizeof(di->id.dev_mac)) == 0) {
        return bus_error_invalid_input;
    }

    if (strcmp(param, "ID") == 0) {
        rc = raw_data_set(p_data, di->id.dev_mac);
    } else if (strcmp(param, "Manufacturer") == 0) {
        rc = raw_data_set(p_data, di->manufacturer);
    } else if (strcmp(param, "SerialNumber") == 0) {
        rc = raw_data_set(p_data, di->serial_number);
    } else if (strcmp(param, "ManufacturerModel") == 0) {
        rc = raw_data_set(p_data, di->manufacturer_model);
    } else if (strcmp(param, "SoftwareVersion") == 0) {
        rc = raw_data_set(p_data, di->software_ver);
    } else if (strcmp(param, "ExecutionEnv") == 0) {
        rc = raw_data_set(p_data, di->exec_env);
    } else if (strcmp(param, "CountryCode") == 0) {
        rc = raw_data_set(p_data, di->country_code);
    } else if (strcmp(param, "BackhaulMACAddress") == 0) {
        if (memcmp(di->backhaul_mac.mac, ZERO_MAC_ADDR, sizeof(ZERO_MAC_ADDR)) == 0) {
            rc = raw_data_set(p_data, "");
        } else {
            rc = raw_data_set(p_data, di->backhaul_mac.mac);
        }
    } else if (strcmp(param, "BackhaulALID") == 0) {
        if (memcmp(di->backhaul_mac.mac, ZERO_MAC_ADDR, sizeof(ZERO_MAC_ADDR)) == 0) {
            rc = raw_data_set(p_data, "");
        } else {
            dm_device_t *bhdev = get_dm_dev(di->id.dev_mac, di->backhaul_mac.mac);
            if (bhdev == NULL) {
                rc = raw_data_set(p_data, "");
            } else {
                em_device_info_t *bhdi = bhdev->get_device_info();
                rc = raw_data_set(p_data, bhdi->id.dev_mac);
            }
        }
    } else if (strcmp(param, "BackhaulMediaType") == 0) {
        if (memcmp(di->backhaul_mac.mac, ZERO_MAC_ADDR, sizeof(ZERO_MAC_ADDR)) == 0) {
            rc = raw_data_set(p_data, di->backhaul_media_type);
        } else {
            rc = raw_data_set(p_data, WIFI_80211_VARIANT_AC);
        }
    } else if (strcmp(param, "RadioNumberOfEntries") == 0) {
        rc = raw_data_set(p_data, dm->get_num_radios());
    } else if (strcmp(param, "CACStatusNumberOfEntries") == 0) {
        rc = raw_data_set(p_data, 0U);
    } else if (strcmp(param, "BackhaulDownNumberOfEntries") == 0) {
        rc = raw_data_set(p_data, di->num_backhaul_down_mac);
    } else {
        printf("Invalid param: %s\n", param);
        rc = bus_error_invalid_input;
    }

    return rc;
}

bus_error_t ssid_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    (void) user_data;
    const char *name = event_name;
    const char *param;
    char instance[MAX_INSTANCE_LEN] = { 0 };
    bool is_num;
    char val_str[1024] = { 0 };
    bus_error_t rc;

    if (!name || !p_data) {
        return bus_error_invalid_input;
    }

    param = strrchr(name, '.');
    if (param == NULL) {
        return bus_error_invalid_input;
    }
    ++param;

    dm_easy_mesh_t *dm = g_ctrl.get_first_dm();
    if (dm == NULL) {
        printf("data model is NULL\n");
        return bus_error_invalid_input;
    }

    name += sizeof(DATAELEMS_NETWORK);
    name = get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    if (!is_num) {
        return bus_error_invalid_input;
    }
    unsigned int idx = static_cast<unsigned int>(atoi(instance));
    if (!idx || idx > dm->get_num_network_ssid()) {
        return bus_error_invalid_input;
    }

    dm_network_ssid_t *ssid = dm->get_network_ssid(idx - 1);
    if (ssid == NULL) {
        printf("ssid is NULL\n");
        return bus_error_invalid_input;
    }
    em_network_ssid_info_t *si = ssid->get_network_ssid_info();

    if (strcmp(param, "SSID") == 0) {
        rc = raw_data_set(p_data, si->ssid);
    } else if (strcmp(param, "Band") == 0) {
        fill_comma_sep(si->band, ARRAY_SIZE(si->band), val_str);
        rc = raw_data_set(p_data, val_str);
    } else if (strcmp(param, "Enable") == 0) {
        rc = raw_data_set(p_data, si->enable);
    } else if (strcmp(param, "AKMsAllowed") == 0) {
        fill_comma_sep(si->akm, ARRAY_SIZE(si->akm), val_str);
        rc = raw_data_set(p_data, val_str);
    } else if (strcmp(param, "SuiteSelector") == 0) {
        rc = raw_data_set(p_data, si->suite_select);
    } else if (strcmp(param, "AdvertisementEnabled") == 0) {
        rc = raw_data_set(p_data, si->advertisement);
    } else if (strcmp(param, "MFPConfig") == 0) {
        rc = raw_data_set(p_data, si->mfp);
    } else if (strcmp(param, "MobilityDomain") == 0) {
        rc = raw_data_set(p_data, si->mobility_domain);
    } else if (strcmp(param, "HaulType") == 0) {
        fill_haul_type(si->haul_type, si->num_hauls, val_str);
        rc = raw_data_set(p_data, val_str);
    } else {
        printf("Invalid param: %s\n", param);
        rc = bus_error_invalid_input;
    }

    return rc;
}

bus_error_t ssid_tget_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    const char *root = event_name;
    char val_str[1024] = { 0 };
    bus_data_prop_t *property = NULL;

    dm_easy_mesh_t *dm = g_ctrl.get_first_dm();
    if (dm == NULL) {
        printf("data model is NULL\n");
        return bus_error_invalid_input;
    }

    for (unsigned int idx = 1; idx <= dm->get_num_network_ssid(); idx++) {
        dm_network_ssid_t *ssid = dm->get_network_ssid(idx - 1);
        if (ssid == NULL) {
            printf("SSID is NULL\n");
            continue;
        }
        em_network_ssid_info_t *si = ssid->get_network_ssid_info();

        property_append_tail(&property, root, idx, "SSID", si->ssid);
        memset(val_str, 0, sizeof(val_str));
        fill_comma_sep(si->band, ARRAY_SIZE(si->band), val_str);
        property_append_tail(&property, root, idx, "Band", val_str);
        property_append_tail(&property, root, idx, "Enable", si->enable);
        memset(val_str, 0, sizeof(val_str));
        fill_comma_sep(si->akm, ARRAY_SIZE(si->akm), val_str);
        property_append_tail(&property, root, idx, "AKMsAllowed", val_str);
        property_append_tail(&property, root, idx, "SuiteSelector", si->suite_select);
        property_append_tail(&property, root, idx, "AdvertisementEnabled", si->advertisement);
        property_append_tail(&property, root, idx, "MFPConfig", si->mfp);
        property_append_tail(&property, root, idx, "MobilityDomain", si->mobility_domain);
        memset(val_str, 0, sizeof(val_str));
        fill_haul_type(si->haul_type, si->num_hauls, val_str);
        property_append_tail(&property, root, idx, "HaulType", val_str);
    }

    if (property) {
        raw_data_set(p_data, property);
    }

    return bus_error_success;
}

bus_error_t device_tget_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    (void) user_data;
    const char *root = event_name;
    char path[512] = { 0 };
    bus_data_prop_t *property = NULL;
    bus_error_t rc = bus_error_success;

    if (!event_name || !p_data) {
        return bus_error_invalid_input;
    }

    dm_easy_mesh_t *dm = g_ctrl.get_first_dm();
    if (dm == NULL) {
        printf("data model is NULL\n");
        return bus_error_invalid_input;
    }

    unsigned int idx = 0;
    while (dm != NULL) {
        dm_device_t *dev = dm->get_device();
        if (dev == NULL) {
            dm = g_ctrl.get_next_dm(dm);
            continue;
        }
        em_device_info_t *di = dev->get_device_info();
        if (memcmp(di->id.dev_mac, ZERO_MAC_ADDR, sizeof(di->id.dev_mac)) == 0) {
            dm = g_ctrl.get_next_dm(dm);
            continue;
        }
        ++idx;

        property_append_tail(&property, root, idx, "ID", di->id.dev_mac);
        property_append_tail(&property, root, idx, "Manufacturer", di->manufacturer);
        property_append_tail(&property, root, idx, "SerialNumber", di->serial_number);
        property_append_tail(&property, root, idx, "ManufacturerModel", di->manufacturer_model);
        property_append_tail(&property, root, idx, "SoftwareVersion", di->software_ver);
        property_append_tail(&property, root, idx, "ExecutionEnv", di->exec_env);
        property_append_tail(&property, root, idx, "CountryCode", di->country_code);
        if (memcmp(di->backhaul_mac.mac, ZERO_MAC_ADDR, sizeof(ZERO_MAC_ADDR)) == 0) {
            property_append_tail(&property, root, idx, "BackhaulMACAddress", "");
        } else {
            property_append_tail(&property, root, idx, "BackhaulMACAddress", di->backhaul_mac.mac);
        }
        if (memcmp(di->backhaul_mac.mac, ZERO_MAC_ADDR, sizeof(ZERO_MAC_ADDR)) == 0) {
            property_append_tail(&property, root, idx, "BackhaulALID", "");
        } else {
            dm_device_t *bhdev = get_dm_dev(di->id.dev_mac, di->backhaul_mac.mac);
            if (bhdev == NULL) {
                property_append_tail(&property, root, idx, "BackhaulALID", "");
            } else {
                em_device_info_t *bhdi = bhdev->get_device_info();
                property_append_tail(&property, root, idx, "BackhaulALID", bhdi->id.dev_mac);
            }
        }
        if (memcmp(di->backhaul_mac.mac, ZERO_MAC_ADDR, sizeof(ZERO_MAC_ADDR)) == 0) {
            property_append_tail(&property, root, idx, "BackhaulMediaType", di->backhaul_media_type);
        } else {
            property_append_tail(&property, root, idx, "BackhaulMediaType", WIFI_80211_VARIANT_AC);
        }
        property_append_tail(&property, root, idx, "RadioNumberOfEntries", dm->get_num_radios());
        property_append_tail(&property, root, idx, "CACStatusNumberOfEntries", 0U);
        property_append_tail(&property, root, idx, "BackhaulDownNumberOfEntries", di->num_backhaul_down_mac);

        snprintf(path, sizeof(path) - 1, "%s%d.Radio.", root, idx);
        radio_tget_params(dm, path, &property);

        dm = g_ctrl.get_next_dm(dm);
    }

    if (property) {
        raw_data_set(p_data, property);
    }

    return rc;
}

char *get_ht_caps_str(em_ap_ht_cap_t *ht, char *buf, size_t buf_len)
{
    uint8_t data;

    /* Prepare data */
    data  = static_cast<uint8_t>((ht->max_sprt_tx_streams - 1) << 6);
    data |= static_cast<uint8_t>((ht->max_sprt_rx_streams - 1) << 4);
    data |= static_cast<uint8_t>(ht->gi_sprt_20mhz << 3);
    data |= static_cast<uint8_t>(ht->gi_sprt_40mhz << 2);
    data |= static_cast<uint8_t>(ht->ht_sprt_40mhz << 1);

#if 0 // enable when libubox is added
    /* Now encode as base64 */
    if (b64_encode(&data, sizeof(data), buf, buf_len) < 0) {
        printf("b64_encode failed\n");
    }
#endif

    return buf;
}

char *get_vht_caps_str(em_ap_vht_cap_t *vht, char *buf, size_t buf_len)
{
    uint8_t data[6] = {0};

    /* Prepare data */
    data[0]  = static_cast<uint8_t>(vht->sprt_tx_mcs >> 8);
    data[1]  = static_cast<uint8_t>(vht->sprt_tx_mcs &  0xff);
    data[2]  = static_cast<uint8_t>(vht->sprt_rx_mcs >> 8);
    data[3]  = static_cast<uint8_t>(vht->sprt_rx_mcs &  0xff);
    data[4]  = static_cast<uint8_t>((vht->max_sprt_tx_streams - 1) << 5);
    data[4] |= static_cast<uint8_t>((vht->max_sprt_rx_streams - 1) << 2);
    data[4] |= static_cast<uint8_t>(vht->gi_sprt_80mhz << 1);
    data[4] |= static_cast<uint8_t>(vht->gi_sprt_160mhz);
    data[5]  = static_cast<uint8_t>(vht->sprt_80_80_mhz << 7);
    data[5] |= static_cast<uint8_t>(vht->sprt_160mhz << 6);
    data[5] |= static_cast<uint8_t>(vht->su_beamformer_cap << 5);
    data[5] |= static_cast<uint8_t>(vht->mu_beamformer_cap << 4);

#if 0 // enable when libubox is added
    /* Now encode as base64 */
    if (b64_encode(&data, sizeof(data), buf, buf_len) < 0) {
        printf("b64_encode failed\n");
    }
#endif

    return buf;
}

bus_error_t radio_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    (void) user_data;
    const char *name = event_name;
    const char *param;
    char instance[MAX_INSTANCE_LEN] = { 0 };
    bool is_num;
    bus_error_t rc;

    if (!name || !p_data) {
        return bus_error_invalid_input;
    }

    param = strrchr(name, '.');
    if (param == NULL) {
        return bus_error_invalid_input;
    }
    ++param;

    name += sizeof(DATAELEMS_NETWORK);
    name = get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    dm_easy_mesh_t *dm = get_dm_easy_mesh(instance, is_num);
    if (dm == NULL) {
        printf("data model is NULL\n");
        return bus_error_invalid_input;
    }

    name = get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    dm_radio_t *radio = get_dm_radio(dm, instance, is_num);
    if (radio == NULL) {
        printf("radio is NULL\n");
        return bus_error_invalid_input;
    }
    em_radio_info_t *ri = radio->get_radio_info();

    if (strcmp(param, "ID") == 0) {
#if 0 // enable when libubox is added
        char id_str[16] = { 0 };
        b64_encode(ri->id.ruid, sizeof(ri->id.ruid), id_str, sizeof(id_str));
        rc = raw_data_set(p_data, id_str);
#else
        rc = raw_data_set(p_data, ri->id.ruid);
#endif
    } else if (strcmp(param, "Enabled") == 0) {
        rc = raw_data_set(p_data, ri->enabled);
    } else if (strcmp(param, "Noise") == 0) {
        rc = raw_data_set(p_data, static_cast<unsigned int> (ri->noise));
    } else if (strcmp(param, "Utilization") == 0) {
        rc = raw_data_set(p_data, ri->utilization);
    } else if (strcmp(param, "Transmit") == 0) {
        rc = raw_data_set(p_data, 0U);
    } else if (strcmp(param, "ReceiveSelf") == 0) {
        rc = raw_data_set(p_data, 0U);
    } else if (strcmp(param, "ReceiveOther") == 0) {
        rc = raw_data_set(p_data, 0U);
    } else if (strcmp(param, "ChipsetVendor") == 0) {
        rc = raw_data_set(p_data, ri->chip_vendor);
    } else if (strcmp(param, "CurrentOperatingClassProfileNumberOfEntries") == 0) {
        rc = raw_data_set(p_data, 0U);
    } else if (strcmp(param, "BSSNumberOfEntries") == 0) {
        rc = raw_data_set(p_data, ri->number_of_bss);
    } else {
        printf("Invalid param: %s\n", param);
        rc = bus_error_invalid_input;
    }

    return rc;
}

bus_error_t radio_tget_params(dm_easy_mesh_t *dm, const char *root, bus_data_prop_t **property)
{
    char path[512];
    char caps_str[MAX_CAPS_STR_LEN] = { 0 };
    bus_error_t rc = bus_error_success;

    for (unsigned int idx = 1; idx <= dm->get_num_radios(); idx++) {
        dm_radio_t *radio = dm->get_radio(idx - 1);
        if (radio == NULL) {
            continue;
        }
        em_radio_info_t *ri = radio->get_radio_info();
#if 0 // enable when libubox is added
        char id_str[16] = { 0 };

        b64_encode(ri->id.ruid, sizeof(ri->id.ruid), id_str, sizeof(id_str));
        property_append_tail(property, root, idx, "ID", id_str);
#else
        property_append_tail(property, root, idx, "ID", ri->id.ruid);
#endif
        property_append_tail(property, root, idx, "Enabled", ri->enabled);
        property_append_tail(property, root, idx, "Noise", static_cast<unsigned int> (ri->noise));
        property_append_tail(property, root, idx, "Utilization", ri->utilization);
        property_append_tail(property, root, idx, "Transmit", 0U);
        property_append_tail(property, root, idx, "ReceiveSelf", 0U);
        property_append_tail(property, root, idx, "ReceiveOther", 0U);
        property_append_tail(property, root, idx, "ChipsetVendor", ri->chip_vendor);
        property_append_tail(property, root, idx, "CurrentOperatingClassProfileNumberOfEntries", 0U);
        property_append_tail(property, root, idx, "BSSNumberOfEntries", ri->number_of_bss);

        dm_sta_t *bh_sta = get_dm_bh_sta(dm, radio);
        if (bh_sta == NULL) {
            property_append_tail(property, root, idx, "BackhaulSta.MACAddress", "");
        } else {
            em_sta_info_t *si = bh_sta->get_sta_info();
            if (ri->number_of_bss != 4) { /* Very nasty hack, only report backhaulsta for radio with 4 bss */
                property_append_tail(property, root, idx, "BackhaulSta.MACAddress", "");
            } else {
                property_append_tail(property, root, idx, "BackhaulSta.MACAddress", si->id);
            }
        }

        dm_radio_cap_t *radio_cap = dm->get_radio_cap(ri->id.ruid);
        if (radio_cap != NULL) {
            em_radio_cap_info_t *rci = radio_cap->get_radio_cap_info();
            get_ht_caps_str(&rci->ht_cap, caps_str, sizeof(caps_str));
            property_append_tail(property, root, idx, "Capabilities.HTCapabilities", caps_str);
            get_vht_caps_str(&rci->vht_cap, caps_str, sizeof(caps_str));
            property_append_tail(property, root, idx, "Capabilities.VHTCapabilities", caps_str);
            property_append_tail(property, root, idx, "Capabilities.CapableOperatingClassProfileNumberOfEntries", 0U);
        } else {
            property_append_tail(property, root, idx, "Capabilities.HTCapabilities", "");
            property_append_tail(property, root, idx, "Capabilities.VHTCapabilities", "");
            property_append_tail(property, root, idx, "Capabilities.CapableOperatingClassProfileNumberOfEntries", 0U);
        }

        snprintf(path, sizeof(path) - 1, "%s%d.CurrentOperatingClassProfile.", root, idx);
        curops_tget_params(dm, path, ri, property);

        snprintf(path, sizeof(path) - 1, "%s%d.BSS.", root, idx);
        bss_tget_params(dm, path, ri, property);
    }

    return rc;
}

bus_error_t radio_tget_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    (void) user_data;
    const char *name = event_name;
    const char *root = name;
    char instance[MAX_INSTANCE_LEN] = { 0 };
    bool is_num;
    bus_data_prop_t *property = NULL;
    bus_error_t rc;

    if (!name || !p_data) {
        return bus_error_invalid_input;
    }

    name += sizeof(DATAELEMS_NETWORK);
    name = get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    dm_easy_mesh_t *dm = get_dm_easy_mesh(instance, is_num);
    if (dm == NULL) {
        printf("data model is NULL\n");
        return bus_error_invalid_input;
    }

    rc = radio_tget_params(dm, root, &property);
    if (rc == bus_error_success && property) {
        raw_data_set(p_data, property);
    }

    return rc;
}

bus_error_t rbhsta_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    (void) user_data;
    const char *name = event_name;
    const char *param;
    char instance[MAX_INSTANCE_LEN] = { 0 };
    bool is_num;
    bus_error_t rc;

    if (!name || !p_data) {
        return bus_error_invalid_input;
    }

    param = strrchr(name, '.');
    if (param == NULL) {
        return bus_error_invalid_input;
    }
    ++param;

    name += sizeof(DATAELEMS_NETWORK);
    name = get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    dm_easy_mesh_t *dm = get_dm_easy_mesh(instance, is_num);
    if (dm == NULL) {
        printf("data model is NULL\n");
        return bus_error_invalid_input;
    }

    name = get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    dm_radio_t *radio = get_dm_radio(dm, instance, is_num);
    if (radio == NULL) {
        printf("radio is NULL\n");
        return bus_error_invalid_input;
    }
    dm_sta_t *bh_sta = get_dm_bh_sta(dm, radio);

    if (strcmp(param, "MACAddress") == 0) {
        if (bh_sta == NULL || radio->get_radio_info()->number_of_bss != 4) {
            /* Very nasty hack, only report backhaulsta for radio with 4 bss */
            rc = raw_data_set(p_data, "");
        } else {
            em_sta_info_t *si = bh_sta->get_sta_info();
            rc = raw_data_set(p_data, si->id);
        }
    } else {
        printf("Invalid param: %s\n", param);
        rc = bus_error_invalid_input;
    }

    return rc;
}

bus_error_t rcaps_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    (void) user_data;
    const char *name = event_name;
    const char *param;
    char instance[MAX_INSTANCE_LEN] = { 0 };
    bool is_num;
    char caps_str[MAX_CAPS_STR_LEN] = { 0 };
    bus_error_t rc;

    if (!name || !p_data) {
        return bus_error_invalid_input;
    }

    param = strrchr(name, '.');
    if (param == NULL) {
        return bus_error_invalid_input;
    }
    ++param;

    name += sizeof(DATAELEMS_NETWORK);
    name = get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    dm_easy_mesh_t *dm = get_dm_easy_mesh(instance, is_num);
    if (dm == NULL) {
        printf("data model is NULL\n");
        return bus_error_invalid_input;
    }

    name = get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    dm_radio_t *radio = get_dm_radio(dm, instance, is_num);
    if (radio == NULL) {
        printf("radio is NULL\n");
        return bus_error_invalid_input;
    }
    em_radio_info_t *ri = radio->get_radio_info();

    dm_radio_cap_t *radio_cap = dm->get_radio_cap(ri->id.ruid);
    if (radio_cap == NULL) {
        printf("radio_cap is NULL\n");
        return bus_error_invalid_input;
    }
    em_radio_cap_info_t *rci = radio_cap->get_radio_cap_info();

    if (strcmp(param, "HTCapabilities") == 0) {
        get_ht_caps_str(&rci->ht_cap, caps_str, sizeof(caps_str));
        rc = raw_data_set(p_data, caps_str);
    } else if (strcmp(param, "VHTCapabilities") == 0) {
        get_vht_caps_str(&rci->vht_cap, caps_str, sizeof(caps_str));
        rc = raw_data_set(p_data, caps_str);
    } else if (strcmp(param, "CapableOperatingClassProfileNumberOfEntries") == 0) {
        rc = raw_data_set(p_data, 0U);
    } else {
        printf("Invalid param: %s\n", param);
        rc = bus_error_invalid_input;
    }

    return rc;
}

#if 0
bus_error_t capops_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    (void) user_data;
    const char *name = event_name;
    const char *param;
    char instance[MAX_INSTANCE_LEN] = { 0 };
    bool is_num;
    bus_error_t rc;

    if (!name || !p_data) {
        return bus_error_invalid_input;
    }

    param = strrchr(name, '.');
    if (param == NULL) {
        return bus_error_invalid_input;
    }
    ++param;

    name += sizeof(DATAELEMS_NETWORK);
    name = get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    dm_easy_mesh_t *dm = get_dm_easy_mesh(instance, is_num);
    if (dm == NULL) {
        printf("data model is NULL\n");
        return bus_error_invalid_input;
    }

    name = get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    dm_radio_t *radio = get_dm_radio(dm, instance, is_num);
    if (radio == NULL) {
        printf("radio is NULL\n");
        return bus_error_invalid_input;
    }
    em_radio_info_t *ri = radio->get_radio_info();

    /* TODO: Get capable op */

    if (strcmp(param, "Class") == 0) {
        rc = raw_data_set(p_data, 0U);
    } else if (strcmp(param, "MaxTxPower") == 0) {
        rc = raw_data_set(p_data, 0);
    } else if (strcmp(param, "NonOperable") == 0) {
        rc = raw_data_set(p_data, "");
    } else if (strcmp(param, "NumberOfNonOperChan") == 0) {
        rc = raw_data_set(p_data, 0U);
    } else {
        printf("Invalid param: %s\n", param);
        rc = bus_error_invalid_input;
    }

    return rc;
}
#endif

bus_error_t curops_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    (void) user_data;
    const char *name = event_name;
    const char *param;
    char instance[MAX_INSTANCE_LEN] = { 0 };
    bool is_num;
    bus_error_t rc;

    if (!name || !p_data) {
        return bus_error_invalid_input;
    }

    param = strrchr(name, '.');
    if (param == NULL) {
        return bus_error_invalid_input;
    }
    ++param;

    name += sizeof(DATAELEMS_NETWORK);
    name = get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    dm_easy_mesh_t *dm = get_dm_easy_mesh(instance, is_num);
    if (dm == NULL) {
        printf("data model is NULL\n");
        return bus_error_invalid_input;
    }

    name = get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    dm_radio_t *radio = get_dm_radio(dm, instance, is_num);
    if (radio == NULL) {
        printf("radio is NULL\n");
        return bus_error_invalid_input;
    }

    name = get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    dm_op_class_t *op_class = get_dm_curop(dm, radio, instance, is_num);
    if (op_class == NULL) {
        printf("op_class is NULL\n");
        return bus_error_invalid_input;
    }
    em_op_class_info_t *oci = op_class->get_op_class_info();

    if (strcmp(param, "Class") == 0) {
        rc = raw_data_set(p_data, oci->op_class);
    } else if (strcmp(param, "Channel") == 0) {
        rc = raw_data_set(p_data, oci->channel);
    } else if (strcmp(param, "TxPower") == 0) {
        rc = raw_data_set(p_data, oci->tx_power);
    } else {
        printf("Invalid param: %s\n", param);
        rc = bus_error_invalid_input;
    }

    return rc;
}

bus_error_t curops_tget_params(dm_easy_mesh_t *dm, const char *root, em_radio_info_t *ri, bus_data_prop_t **property)
{
    bus_error_t rc = bus_error_success;

    unsigned int idx = 0;
    for (unsigned int i = 0; i < dm->get_num_op_class(); i++) {
        dm_op_class_t *op_class = dm->get_op_class(i);
        if (op_class == NULL) {
            continue;
        }
        em_op_class_info_t *oci = op_class->get_op_class_info();
        if (oci->id.type != em_op_class_type_current) {
            continue;
        }
        if (memcmp(ri->id.ruid, oci->id.ruid, sizeof(oci->id.ruid)) != 0) {
            continue;
        }
        ++idx;

        property_append_tail(property, root, idx, "Class", oci->op_class);
        property_append_tail(property, root, idx, "Channel", oci->channel);
        property_append_tail(property, root, idx, "TxPower", oci->tx_power);
    }

    return rc;
}

bus_error_t curops_tget_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    (void) user_data;
    const char *name = event_name;
    const char *root = name;
    char instance[MAX_INSTANCE_LEN] = { 0 };
    bool is_num;
    bus_data_prop_t *property = NULL;
    bus_error_t rc;

    if (!name || !p_data) {
        return bus_error_invalid_input;
    }

    name += sizeof(DATAELEMS_NETWORK);
    name = get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    dm_easy_mesh_t *dm = get_dm_easy_mesh(instance, is_num);
    if (dm == NULL) {
        printf("data model is NULL\n");
        return bus_error_invalid_input;
    }

    name = get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    dm_radio_t *radio = get_dm_radio(dm, instance, is_num);
    if (radio == NULL) {
        printf("radio is NULL\n");
        return bus_error_invalid_input;
    }
    em_radio_info_t *ri = radio->get_radio_info();

    rc = curops_tget_params(dm, root, ri, &property);
    if (rc == bus_error_success && property) {
        raw_data_set(p_data, property);
    }

    return rc;
}

bus_error_t bss_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    (void) user_data;
    const char *name = event_name;
    const char *param;
    char instance[MAX_INSTANCE_LEN] = { 0 };
    bool is_num;
    char val_str[1024] = { 0 };
    bus_error_t rc;

    if (!name || !p_data) {
        return bus_error_invalid_input;
    }

    param = strrchr(name, '.');
    if (param == NULL) {
        return bus_error_invalid_input;
    }
    ++param;

    name += sizeof(DATAELEMS_NETWORK);
    name = get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    dm_easy_mesh_t *dm = get_dm_easy_mesh(instance, is_num);
    if (dm == NULL) {
        printf("data model is NULL\n");
        return bus_error_invalid_input;
    }

    name = get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    dm_radio_t *radio = get_dm_radio(dm, instance, is_num);
    if (radio == NULL) {
        printf("radio is NULL\n");
        return bus_error_invalid_input;
    }

    name = get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    dm_bss_t *bss = get_dm_bss(dm, radio, instance, is_num);
    if (bss == NULL) {
        printf("bss is NULL\n");
        return bus_error_invalid_input;
    }
    em_bss_info_t *bi = bss->get_bss_info();

    if (strcmp(param, "BSSID") == 0) {
        rc = raw_data_set(p_data, bi->bssid.mac);
    } else if (strcmp(param, "SSID") == 0) {
        rc = raw_data_set(p_data, bi->ssid);
    } else if (strcmp(param, "Enabled") == 0) {
        rc = raw_data_set(p_data, bi->enabled);
    } else if (strcmp(param, "ByteCounterUnits") == 0) {
        rc = raw_data_set(p_data, bi->byte_counter_units);
    } else if (strcmp(param, "BackhaulUse") == 0) {
        rc = raw_data_set(p_data, (bi->id.haul_type == em_haul_type_backhaul));
    } else if (strcmp(param, "FronthaulUse") == 0) {
        rc = raw_data_set(p_data, (bi->id.haul_type == em_haul_type_fronthaul));
    } else if (strcmp(param, "FronthaulAKMsAllowed") == 0) {
        fill_comma_sep(bi->fronthaul_akm, ARRAY_SIZE(bi->fronthaul_akm), val_str);
        rc = raw_data_set(p_data, val_str);
    } else if (strcmp(param, "FronthaulSuiteSelector") == 0) {
        rc = raw_data_set(p_data, 0U);
    } else if (strcmp(param, "BackhaulAKMsAllowed") == 0) {
        fill_comma_sep(bi->backhaul_akm, ARRAY_SIZE(bi->backhaul_akm), val_str);
        rc = raw_data_set(p_data, val_str);
    } else if (strcmp(param, "BackhaulSuiteSelector") == 0) {
        rc = raw_data_set(p_data, 0U);
    } else if (strcmp(param, "STANumberOfEntries") == 0) {
        rc = raw_data_set(p_data, bi->numberofsta);
    } else {
        printf("Invalid param: %s\n", param);
        rc = bus_error_invalid_input;
    }

    return rc;
}

bus_error_t bss_tget_params(dm_easy_mesh_t *dm, const char *root, em_radio_info_t *ri, bus_data_prop_t **property)
{
    char path[512];
    char val_str[1024];
    bus_error_t rc = bus_error_success;

    unsigned int idx = 0;
    for (unsigned int i = 0; i < dm->get_num_bss(); i++) {
        dm_bss_t *bss = dm->get_bss(i);
        if (bss == NULL) {
            continue;
        }
        em_bss_info_t *bi = bss->get_bss_info();
        if (memcmp(bi->bssid.mac, ZERO_MAC_ADDR, sizeof(ZERO_MAC_ADDR)) == 0 ||
            memcmp(ri->id.ruid, bi->ruid.mac, sizeof(bi->ruid.mac)) != 0) {
            continue;
        }
        ++idx;
        if (idx == 4) {
            /* A very nasy hack, to prevent bss index 4 */
            continue;
        }

        property_append_tail(property, root, idx, "BSSID", bi->bssid.mac);
        property_append_tail(property, root, idx, "SSID", bi->ssid);
        property_append_tail(property, root, idx, "Enabled", bi->enabled);
        property_append_tail(property, root, idx, "ByteCounterUnits", bi->byte_counter_units);
        property_append_tail(property, root, idx, "BackhaulUse", (bi->id.haul_type == em_haul_type_backhaul));
        property_append_tail(property, root, idx, "FronthaulUse", (bi->id.haul_type == em_haul_type_fronthaul));
        memset(val_str, 0, sizeof(val_str));
        fill_comma_sep(bi->fronthaul_akm, ARRAY_SIZE(bi->fronthaul_akm), val_str);
        property_append_tail(property, root, idx, "FronthaulAKMsAllowed", val_str);
        property_append_tail(property, root, idx, "FronthaulSuiteSelector", 0U);
        memset(val_str, 0, sizeof(val_str));
        fill_comma_sep(bi->fronthaul_akm, ARRAY_SIZE(bi->backhaul_akm), val_str);
        property_append_tail(property, root, idx, "BackhaulAKMsAllowed", val_str);
        property_append_tail(property, root, idx, "BackhaulSuiteSelector", 0U);
        property_append_tail(property, root, idx, "STANumberOfEntries", bi->numberofsta);

        snprintf(path, sizeof(path) - 1, "%s%d.STA.", root, idx);
        sta_tget_params(dm, path, bi, property);
    }

    return rc;
}

bus_error_t bss_tget_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    (void) user_data;
    const char *name = event_name;
    const char *root = name;
    char instance[MAX_INSTANCE_LEN] = { 0 };
    bool is_num;
    bus_data_prop_t *property = NULL;
    bus_error_t rc;

    if (!name || !p_data) {
        return bus_error_invalid_input;
    }

    name += sizeof(DATAELEMS_NETWORK);
    name = get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    dm_easy_mesh_t *dm = get_dm_easy_mesh(instance, is_num);
    if (dm == NULL) {
        printf("data model is NULL\n");
        return bus_error_invalid_input;
    }

    name = get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    dm_radio_t *radio = get_dm_radio(dm, instance, is_num);
    if (radio == NULL) {
        printf("radio is NULL\n");
        return bus_error_invalid_input;
    }
    em_radio_info_t *ri = radio->get_radio_info();

    rc = bss_tget_params(dm, root, ri, &property);
    if (rc == bus_error_success && property) {
        raw_data_set(p_data, property);
    }

    return rc;
}

bus_error_t sta_get_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    (void) user_data;
    const char *name = event_name;
    const char *param;
    char instance[MAX_INSTANCE_LEN] = { 0 };
    bool is_num;
    bus_error_t rc;

    if (!name || !p_data) {
        return bus_error_invalid_input;
    }

    param = strrchr(name, '.');
    if (param == NULL) {
        return bus_error_invalid_input;
    }
    ++param;

    name += sizeof(DATAELEMS_NETWORK);
    name = get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    dm_easy_mesh_t *dm = get_dm_easy_mesh(instance, is_num);
    if (dm == NULL) {
        printf("data model is NULL\n");
        return bus_error_invalid_input;
    }

    name = get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    dm_radio_t *radio = get_dm_radio(dm, instance, is_num);
    if (radio == NULL) {
        printf("radio is NULL\n");
        return bus_error_invalid_input;
    }

    name = get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    dm_bss_t *bss = get_dm_bss(dm, radio, instance, is_num);
    if (bss == NULL) {
        printf("bss is NULL\n");
        return bus_error_invalid_input;
    }

    name = get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    dm_sta_t *sta = get_dm_sta(dm, bss, instance, is_num);
    if (sta == NULL) {
        printf("sta is NULL\n");
        return bus_error_invalid_input;
    }
    em_sta_info_t *si = sta->get_sta_info();

    if (strcmp(param, "MACAddress") == 0) {
        rc = raw_data_set(p_data, si->id);
    } else if (strcmp(param, "HTCapabilities") == 0) {
        rc = raw_data_set(p_data, si->ht_cap);
    } else if (strcmp(param, "VHTCapabilities") == 0) {
        rc = raw_data_set(p_data, si->vht_cap);
    } else if (strcmp(param, "ClientCapabilities") == 0) {
        rc = raw_data_set(p_data, "");
    } else if (strcmp(param, "LastDataDownlinkRate") == 0) {
        rc = raw_data_set(p_data, si->last_dl_rate);
    } else if (strcmp(param, "LastDataUplinkRate") == 0) {
        rc = raw_data_set(p_data, si->last_ul_rate);
    } else if (strcmp(param, "UtilizationReceive") == 0) {
        rc = raw_data_set(p_data, si->util_rx);
    } else if (strcmp(param, "UtilizationTransmit") == 0) {
        rc = raw_data_set(p_data, si->util_tx);
    } else if (strcmp(param, "EstMACDataRateDownlink") == 0) {
        rc = raw_data_set(p_data, si->est_dl_rate);
    } else if (strcmp(param, "EstMACDataRateUplink") == 0) {
        rc = raw_data_set(p_data, si->est_ul_rate);
    } else if (strcmp(param, "SignalStrength") == 0) {
        rc = raw_data_set(p_data, si->signal_strength);
    } else if (strcmp(param, "LastConnectTime") == 0) {
        rc = raw_data_set(p_data, si->last_conn_time);
    } else if (strcmp(param, "BytesSent") == 0) {
        rc = raw_data_set(p_data, si->bytes_tx);
    } else if (strcmp(param, "BytesReceived") == 0) {
        rc = raw_data_set(p_data, si->bytes_rx);
    } else if (strcmp(param, "PacketsSent") == 0) {
        rc = raw_data_set(p_data, si->pkts_tx);
    } else if (strcmp(param, "PacketsReceived") == 0) {
        rc = raw_data_set(p_data, si->pkts_rx);
    } else if (strcmp(param, "ErrorsSent") == 0) {
        rc = raw_data_set(p_data, si->errors_tx);
    } else if (strcmp(param, "ErrorsReceived") == 0) {
        rc = raw_data_set(p_data, si->errors_rx);
    } else if (strcmp(param, "RetransCount") == 0) {
        rc = raw_data_set(p_data, si->retrans_count);
    } else if (strcmp(param, "IPV4Address") == 0) {
        rc = raw_data_set(p_data, "");
    } else if (strcmp(param, "IPV6Address") == 0) {
        rc = raw_data_set(p_data, "");
    } else if (strcmp(param, "Hostname") == 0) {
        rc = raw_data_set(p_data, "");
    } else if (strcmp(param, "PairwiseAKM") == 0) {
        rc = raw_data_set(p_data, 0U);
    } else if (strcmp(param, "PairwiseCipher") == 0) {
        rc = raw_data_set(p_data, 0U);
    } else if (strcmp(param, "RSNCapabilities") == 0) {
        rc = raw_data_set(p_data, 0U);
    } else {
        printf("Invalid param: %s\n", param);
        rc = bus_error_invalid_input;
    }

    return rc;
}

bus_error_t sta_tget_params(dm_easy_mesh_t *dm, const char *root, em_bss_info_t *bi, bus_data_prop_t **property)
{
    bus_error_t rc = bus_error_success;

    unsigned int idx = 0;
    dm_sta_t *sta = static_cast<dm_sta_t *> (hash_map_get_first(dm->m_sta_map));
    while (sta != NULL) {
        em_sta_info_t *si = sta->get_sta_info();
        if (si->associated == 0 ||
            memcmp(bi->bssid.mac, si->bssid, sizeof(si->bssid)) != 0) {
            sta = static_cast<dm_sta_t *> (hash_map_get_next(dm->m_sta_map, sta));
            continue;
        }
        ++idx;

        property_append_tail(property, root, idx, "MACAddress", si->id);
        property_append_tail(property, root, idx, "HTCapabilities", si->ht_cap);
        property_append_tail(property, root, idx, "VHTCapabilities", si->vht_cap);
        property_append_tail(property, root, idx, "ClientCapabilities", "");
        property_append_tail(property, root, idx, "LastDataDownlinkRate", si->last_dl_rate);
        property_append_tail(property, root, idx, "LastDataUplinkRate", si->last_ul_rate);
        property_append_tail(property, root, idx, "UtilizationReceive", si->util_rx);
        property_append_tail(property, root, idx, "UtilizationTransmit", si->util_tx);
        property_append_tail(property, root, idx, "EstMACDataRateDownlink", si->est_dl_rate);
        property_append_tail(property, root, idx, "EstMACDataRateUplink", si->est_ul_rate);
        property_append_tail(property, root, idx, "SignalStrength", si->signal_strength);
        property_append_tail(property, root, idx, "LastConnectTime", si->last_conn_time);
        property_append_tail(property, root, idx, "BytesSent", si->bytes_tx);
        property_append_tail(property, root, idx, "BytesReceived", si->bytes_rx);
        property_append_tail(property, root, idx, "PacketsSent", si->pkts_tx);
        property_append_tail(property, root, idx, "PacketsReceived", si->pkts_rx);
        property_append_tail(property, root, idx, "ErrorsSent", si->errors_tx);
        property_append_tail(property, root, idx, "ErrorsReceived", si->errors_rx);
        property_append_tail(property, root, idx, "RetransCount", si->retrans_count);
        property_append_tail(property, root, idx, "IPV4Address", "");
        property_append_tail(property, root, idx, "IPV6Address", "");
        property_append_tail(property, root, idx, "Hostname", "");
        property_append_tail(property, root, idx, "PairwiseAKM", 0U);
        property_append_tail(property, root, idx, "PairwiseCipher", 0U);
        property_append_tail(property, root, idx, "RSNCapabilities", 0U);
        sta = static_cast<dm_sta_t *> (hash_map_get_next(dm->m_sta_map, sta));
    }

    return rc;
}

bus_error_t sta_tget_inner(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    (void) user_data;
    const char *name = event_name;
    const char *root = name;
    char instance[MAX_INSTANCE_LEN] = { 0 };
    bool is_num;
    bus_data_prop_t *property = NULL;
    bus_error_t rc;

    if (!name || !p_data) {
        return bus_error_invalid_input;
    }

    name += sizeof(DATAELEMS_NETWORK);
    name = get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    dm_easy_mesh_t *dm = get_dm_easy_mesh(instance, is_num);
    if (dm == NULL) {
        printf("data model is NULL\n");
        return bus_error_invalid_input;
    }

    name = get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    dm_radio_t *radio = get_dm_radio(dm, instance, is_num);
    if (radio == NULL) {
        printf("radio is NULL\n");
        return bus_error_invalid_input;
    }

    name = get_table_instance(name, instance, MAX_INSTANCE_LEN, &is_num);
    dm_bss_t *bss = get_dm_bss(dm, radio, instance, is_num);
    if (bss == NULL) {
        printf("bss is NULL\n");
        return bus_error_invalid_input;
    }
    em_bss_info_t *bi = bss->get_bss_info();

    rc = sta_tget_params(dm, root, bi, &property);
    if (rc == bus_error_success && property) {
        raw_data_set(p_data, property);
    }

    return rc;
}

/* Rbus runs callbacks from a different thread. Accessing data in controller
   directly may result in race condition. Requested callback is forwarded to
   event queue for safe procesing */
bus_error_t bus_get_cb_fwd(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data, bus_get_handler_t cb)
{
    uint32_t s_id;
    bus_error_t err = bus_error_success;
    em_event_t *req;
    bus_resp_get_t *resp = NULL;
    uintptr_t buf;

    do {
        req = (em_event_t *) malloc(sizeof(em_event_t));
        if (!req) {
            err = bus_error_out_of_resources;
            break;
        }
        s_id = g_ctrl.get_next_nb_evt_id();
        req->type = em_event_type_nb;
        req->u.nevt.id = s_id;
        req->u.nevt.type = NB_REQTYPE_GET;
        req->u.nevt.u.get.name = event_name;
        req->u.nevt.u.get.property = p_data;
        req->u.nevt.cb = (void *) cb;

        g_ctrl.push_to_queue(req);

        ssize_t len = read(g_ctrl.get_nb_pipe_rd(), &buf, sizeof(buf));
        assert(len == sizeof(buf));
        resp = (bus_resp_get_t *) buf;
        assert(resp->id == s_id);
        err = resp->rc;
    } while (0);

    free(resp);
    return err;
}

bus_error_t network_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    return bus_get_cb_fwd(event_name, p_data, user_data, network_get_inner);
}

bus_error_t ssid_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    return bus_get_cb_fwd(event_name, p_data, user_data, ssid_get_inner);
}

bus_error_t ssid_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    return bus_get_cb_fwd(event_name, p_data, user_data, ssid_tget_inner);
}

bus_error_t device_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    return bus_get_cb_fwd(event_name, p_data, user_data, device_get_inner);
}

bus_error_t device_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    return bus_get_cb_fwd(event_name, p_data, user_data, device_tget_inner);
}

bus_error_t radio_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    return bus_get_cb_fwd(event_name, p_data, user_data, radio_get_inner);
}

bus_error_t radio_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    return bus_get_cb_fwd(event_name, p_data, user_data, radio_tget_inner);
}

bus_error_t rbhsta_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    return bus_get_cb_fwd(event_name, p_data, user_data, rbhsta_get_inner);
}

bus_error_t rcaps_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    return bus_get_cb_fwd(event_name, p_data, user_data, rcaps_get_inner);
}

bus_error_t curops_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    return bus_get_cb_fwd(event_name, p_data, user_data, curops_get_inner);
}

bus_error_t curops_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    return bus_get_cb_fwd(event_name, p_data, user_data, curops_tget_inner);
}

bus_error_t bss_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    return bus_get_cb_fwd(event_name, p_data, user_data, bss_get_inner);
}

bus_error_t bss_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    return bus_get_cb_fwd(event_name, p_data, user_data, bss_tget_inner);
}

bus_error_t sta_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    return bus_get_cb_fwd(event_name, p_data, user_data, sta_get_inner);
}

bus_error_t sta_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    return bus_get_cb_fwd(event_name, p_data, user_data, sta_tget_inner);
}

/* Device.WiFi.DataElements.Network */
#define DE_NETWORK_ID           DATAELEMS_NETWORK       "ID"
#define DE_NETWORK_CTRLID       DATAELEMS_NETWORK       "ControllerID"
#define DE_NETWORK_COLAGTID     DATAELEMS_NETWORK       "ColocatedAgentID"
#define DE_NETWORK_DEVNOE       DATAELEMS_NETWORK       "DeviceNumberOfEntries"
#define DE_NETWORK_SETSSID      DATAELEMS_NETWORK       "SetSSID()"
/* Device.WiFi.DataElements.Network.SSID */
#define DE_NETWORK_SSID         DATAELEMS_NETWORK       "SSID.{i}."
#define DE_SSID_TABLE           DE_NETWORK_SSID
#define DE_SSID_SSID            DE_NETWORK_SSID         "SSID"
#define DE_SSID_BAND            DE_NETWORK_SSID         "Band"
#define DE_SSID_ENABLE          DE_NETWORK_SSID         "Enable"
#define DE_SSID_AKMALLOWE       DE_NETWORK_SSID         "AKMsAllowed"
#define DE_SSID_SUITESEL        DE_NETWORK_SSID         "SuiteSelector"
#define DE_SSID_ADVENABLED      DE_NETWORK_SSID         "AdvertisementEnabled"
#define DE_SSID_MFPCONFIG       DE_NETWORK_SSID         "MFPConfig"
#define DE_SSID_MOBDOMAIN       DE_NETWORK_SSID         "MobilityDomain"
#define DE_SSID_HAULTYPE        DE_NETWORK_SSID         "HaulType"
/* Device.WiFi.DataElements.Network.Device */
#define DE_NETWORK_DEVICE       DATAELEMS_NETWORK       "Device.{i}."
#define DE_DEVICE_TABLE         DE_NETWORK_DEVICE
#define DE_DEVICE_ID            DE_NETWORK_DEVICE       "ID"
#define DE_DEVICE_MANUFACT      DE_NETWORK_DEVICE       "Manufacturer"
#define DE_DEVICE_SERIALNO      DE_NETWORK_DEVICE       "SerialNumber"
#define DE_DEVICE_MFCMODEL      DE_NETWORK_DEVICE       "ManufacturerModel"
#define DE_DEVICE_SWVERSION     DE_NETWORK_DEVICE       "SoftwareVersion"
#define DE_DEVICE_EXECENV       DE_NETWORK_DEVICE       "ExecutionEnv"
#define DE_DEVICE_COUNTRCODE    DE_NETWORK_DEVICE       "CountryCode"
#define DE_DEVICE_BHMACADDR     DE_NETWORK_DEVICE       "BackhaulMACAddress"
#define DE_DEVICE_BHALID        DE_NETWORK_DEVICE       "BackhaulALID"
#define DE_DEVICE_BHMEDIATYPE   DE_NETWORK_DEVICE       "BackhaulMediaType"
#define DE_DEVICE_RADIONOE      DE_NETWORK_DEVICE       "RadioNumberOfEntries"
#define DE_DEVICE_CACSTATNOE    DE_NETWORK_DEVICE       "CACStatusNumberOfEntries"
#define DE_DEVICE_BHDOWNNOE     DE_NETWORK_DEVICE       "BackhaulDownNumberOfEntries"
/* Device.WiFi.DataElements.Network.Device.CACStatus */
#define DE_DEVICE_CACSTAT       DE_NETWORK_DEVICE       "CACStatus.{i}."
#define DE_CACSTAT_TABLE        DE_DEVICE_CACSTAT
#define DE_CACSTAT_NONOCCNOE    DE_DEVICE_CACSTAT       "CACNonOccupancyChannelNumberOfEntries"
/* Device.WiFi.DataElements.Network.Device.CACStatus.CACNonOccupancyChannel */
#define DE_CACSTAT_CACNON       DE_DEVICE_CACSTAT       "CACNonOccupancyChannel.{i}."
#define DE_CACNON_TABLE         DE_CACSTAT_CACNON
#define DE_CACNON_OPCLASS       DE_CACSTAT_CACNON       "OpClass"
#define DE_CACNON_CHANNEL       DE_CACSTAT_CACNON       "Channel"
#define DE_CACNON_SECONDS       DE_CACSTAT_CACNON       "Seconds"
/* Device.WiFi.DataElements.Network.Device.BackhaulDown */
#define DE_DEVICE_BHDOWN        DE_NETWORK_DEVICE       "BackhaulDown.{i}."
#define DE_BHDOWN_TABLE         DE_DEVICE_BHDOWN
#define DE_BHDOWN_ALID          DE_DEVICE_BHDOWN        "BackhaulDownALID"
#define DE_BHDOWN_MACADDR       DE_DEVICE_BHDOWN        "BackhaulDownMACAddress"
/* Device.WiFi.DataElements.Network.Device.MultiAPDevice */
#define DE_DEVICE_MAPDEV        DE_NETWORK_DEVICE       "MultiAPDevice."
/* Device.WiFi.DataElements.Network.Device.MultiAPDevice.Backhaul */
#define DE_MAPDEV_BACKHAUL      DE_DEVICE_MAPDEV        "Backhaul."
/* Device.WiFi.DataElements.Network.Device.MultiAPDevice.Backhaul.Stats */
#define DE_MAPDEVBH_STATS       DE_MAPDEV_BACKHAUL      "Stats."
#define DE_MDBHSTATS_BYTESSNT   DE_MAPDEVBH_STATS       "BytesSent"
#define DE_MDBHSTATS_BYTESRCV   DE_MAPDEVBH_STATS       "BytesReceived"
#define DE_MDBHSTATS_PCKTSSNT   DE_MAPDEVBH_STATS       "PacketsSent"
#define DE_MDBHSTATS_PCKTSRCV   DE_MAPDEVBH_STATS       "PacketsReceived"
#define DE_MDBHSTATS_ERRSSNT    DE_MAPDEVBH_STATS       "ErrorsSent"
#define DE_MDBHSTATS_ERRSRCV    DE_MAPDEVBH_STATS       "ErrorsReceived"
#define DE_MDBHSTATS_LINKUTIL   DE_MAPDEVBH_STATS       "LinkUtilization"
#define DE_MDBHSTATS_SIGNALSTR  DE_MAPDEVBH_STATS       "SignalStrength"
#define DE_MDBHSTATS_LSTDTADLR  DE_MAPDEVBH_STATS       "LastDataDownlinkRate"
#define DE_MDBHSTATS_LSTDTAULR  DE_MAPDEVBH_STATS       "LastDataUplinkRate"
/* Device.WiFi.DataElements.Network.Device.Radio */
#define DE_DEVICE_RADIO         DE_NETWORK_DEVICE       "Radio.{i}."
#define DE_RADIO_TABLE          DE_DEVICE_RADIO
#define DE_RADIO_ID             DE_DEVICE_RADIO         "ID"
#define DE_RADIO_ENABLED        DE_DEVICE_RADIO         "Enabled"
#define DE_RADIO_NOISE          DE_DEVICE_RADIO         "Noise"
#define DE_RADIO_UTILIZATION    DE_DEVICE_RADIO         "Utilization"
#define DE_RADIO_TRANSMIT       DE_DEVICE_RADIO         "Transmit"
#define DE_RADIO_RECEIVESELF    DE_DEVICE_RADIO         "ReceiveSelf"
#define DE_RADIO_RECEIVEOTHER   DE_DEVICE_RADIO         "ReceiveOther"
#define DE_RADIO_CHIPVENDOR     DE_DEVICE_RADIO         "ChipsetVendor"
#define DE_RADIO_CURROPNOE      DE_DEVICE_RADIO         "CurrentOperatingClassProfileNumberOfEntries"
#define DE_RADIO_BSSNOE         DE_DEVICE_RADIO         "BSSNumberOfEntries"
/* Device.WiFi.DataElements.Network.Device.Radio.BackhaulSta */
#define DE_RADIO_BHSTA          DE_DEVICE_RADIO         "BackhaulSta."
#define DE_BHSTA_MACADDR        DE_RADIO_BHSTA          "MACAddress"
/* Device.WiFi.DataElements.Network.Device.Radio.Capabilities */
#define DE_RADIO_CAPS           DE_DEVICE_RADIO         "Capabilities."
#define DE_RCAPS_HTCAPS         DE_RADIO_CAPS           "HTCapabilities"
#define DE_RCAPS_VHTCAPS        DE_RADIO_CAPS           "VHTCapabilities"
#define DE_RCAPS_CAPOPNOE       DE_RADIO_CAPS           "CapableOperatingClassProfileNumberOfEntries"
/* Device.WiFi.DataElements.Network.Device.Radio.Capabilities.WiFi6APRole */
#define DE_CAPS_WF6AP           DE_RADIO_CAPS           "WiFi6APRole."
#define DE_WF6AP_HE160          DE_CAPS_WF6AP           "HE160"
#define DE_WF6AP_MCSNSS         DE_CAPS_WF6AP           "MCSNSS"
/* Device.WiFi.DataElements.Network.Device.Radio.Capabilities.WiFi6bSTARole */
#define DE_CAPS_WF6BSTA         DE_RADIO_CAPS           "WiFi6bSTARole."
#define DE_WF6BSTA_HE160        DE_CAPS_WF6BSTA         "HE160"
#define DE_WF6BSTA_MCSNSS       DE_CAPS_WF6BSTA         "MCSNSS"
/* Device.WiFi.DataElements.Network.Device.Radio.Capabilities.CapableOperatingClassProfile */
#define DE_CAPS_CAPOP           DE_RADIO_CAPS           "CapableOperatingClassProfile.{i}."
#define DE_CAPOP_TABLE          DE_CAPS_CAPOP
#define DE_CAPOP_CLASS          DE_CAPS_CAPOP           "Class"
#define DE_CAPOP_MAXTXPOWER     DE_CAPS_CAPOP           "MaxTxPower"
#define DE_CAPOP_NONOPERABLE    DE_CAPS_CAPOP           "NonOperable"
#define DE_CAPOP_NONOPCNT       DE_CAPS_CAPOP           "NumberOfNonOperChan"
/* Device.WiFi.DataElements.Network.Device.Radio.CurrentOperatingClassProfile */
#define DE_RADIO_CUROP          DE_DEVICE_RADIO         "CurrentOperatingClassProfile.{i}."
#define DE_CUROP_TABLE          DE_RADIO_CUROP
#define DE_CUROP_CLASS          DE_RADIO_CUROP          "Class"
#define DE_CUROP_CHANNEL        DE_RADIO_CUROP          "Channel"
#define DE_CUROP_TXPOWER        DE_RADIO_CUROP          "TxPower"
/* Device.WiFi.DataElements.Network.Device.Radio.BSS */
#define DE_RADIO_BSS            DE_DEVICE_RADIO         "BSS.{i}."
#define DE_BSS_TABLE            DE_RADIO_BSS
#define DE_BSS_BSSID            DE_RADIO_BSS            "BSSID"
#define DE_BSS_SSID             DE_RADIO_BSS            "SSID"
#define DE_BSS_ENABLED          DE_RADIO_BSS            "Enabled"
#define DE_BSS_BYTCNTUNITS      DE_RADIO_BSS            "ByteCounterUnits"
#define DE_BSS_BHAULUSE         DE_RADIO_BSS            "BackhaulUse"
#define DE_BSS_FHAULUSE         DE_RADIO_BSS            "FronthaulUse"
#define DE_BSS_FHAULAKMS        DE_RADIO_BSS            "FronthaulAKMsAllowed"
#define DE_BSS_FHSUITESEL       DE_RADIO_BSS            "FronthaulSuiteSelector"
#define DE_BSS_BHAULAKMS        DE_RADIO_BSS            "BackhaulAKMsAllowed"
#define DE_BSS_BHSUITESEL       DE_RADIO_BSS            "BackhaulSuiteSelector"
#define DE_BSS_STANOE           DE_RADIO_BSS            "STANumberOfEntries"
/* Device.WiFi.DataElements.Network.Device.Radio.BSS.STA */
#define DE_BSS_STA              DE_RADIO_BSS            "STA.{i}."
#define DE_STA_TABLE            DE_BSS_STA
#define DE_STA_MACADDR          DE_BSS_STA              "MACAddress"
#define DE_STA_HTCAPS           DE_BSS_STA              "HTCapabilities"
#define DE_STA_VHTCAPS          DE_BSS_STA              "VHTCapabilities"
#define DE_STA_CLIENTCAPS       DE_BSS_STA              "ClientCapabilities"
#define DE_STA_LSTDTADLR        DE_BSS_STA              "LastDataDownlinkRate"
#define DE_STA_LSTDTAULR        DE_BSS_STA              "LastDataUplinkRate"
#define DE_STA_UTILRECV         DE_BSS_STA              "UtilizationReceive"
#define DE_STA_UTILTRMT         DE_BSS_STA              "UtilizationTransmit"
#define DE_STA_ESTMACDTARDL     DE_BSS_STA              "EstMACDataRateDownlink"
#define DE_STA_ESTMACDTARUL     DE_BSS_STA              "EstMACDataRateUplink"
#define DE_STA_SIGNALSTR        DE_BSS_STA              "SignalStrength"
#define DE_STA_LASTCONNTIME     DE_BSS_STA              "LastConnectTime"
#define DE_STA_BYTESSNT         DE_BSS_STA              "BytesSent"
#define DE_STA_BYTESRCV         DE_BSS_STA              "BytesReceived"
#define DE_STA_PCKTSSNT         DE_BSS_STA              "PacketsSent"
#define DE_STA_PCKTSRCV         DE_BSS_STA              "PacketsReceived"
#define DE_STA_ERRSSNT          DE_BSS_STA              "ErrorsSent"
#define DE_STA_ERRSRCV          DE_BSS_STA              "ErrorsReceived"
#define DE_STA_RETRANSCNT       DE_BSS_STA              "RetransCount"
#define DE_STA_IPV4ADDR         DE_BSS_STA              "IPV4Address"
#define DE_STA_IPV6ADDR         DE_BSS_STA              "IPV6Address"
#define DE_STA_HOSTNAME         DE_BSS_STA              "Hostname"
#define DE_STA_PAIRWSAKM        DE_BSS_STA              "PairwiseAKM"
#define DE_STA_PAIRWSCIPHER     DE_BSS_STA              "PairwiseCipher"
#define DE_STA_RSNCAPS          DE_BSS_STA              "RSNCapabilities"
/* Device.WiFi.DataElements.Network.Device.Radio.BSS.STA.WiFi6Capabilities */
#define DE_STA_WIFI6CAPS        DE_BSS_STA              "WiFi6Capabilities."
#define DE_STAWF6CAPS_HE160     DE_STA_WIFI6CAPS        "HE160"
#define DE_STAWF6CAPS_MCSNSS    DE_STA_WIFI6CAPS        "MCSNSS"

#define ELEMENT_DEFAULTS(t)         slow_speed, ZERO_TABLE, {t, false, 0L, 0L, 0U, NULL}
#define CALLBACK_GETTER(f)          {f, NULL, NULL, NULL, NULL, NULL}
#define CALLBACK_METHOD(f)          {NULL, NULL, NULL, NULL, NULL, f}
#define ELEMENT_PROPERTY(n, f, t)   {n, bus_element_type_property, CALLBACK_GETTER(f), ELEMENT_DEFAULTS(t)}
#define ELEMENT_METHOD(n, f, t)     {n, bus_element_type_method, CALLBACK_METHOD(f), ELEMENT_DEFAULTS(t)}
#define ELEMENT_TABLE(n, f, t)      {n, bus_element_type_table, CALLBACK_GETTER(f), ELEMENT_DEFAULTS(t)}

int em_ctrl_t::tr181_reg_data_elements(bus_handle_t *bus_handle)
{
    uint32_t count;
    bus_error_t rc;
    wifi_bus_desc_t *bus_desc;
    bus_data_element_t elements[] = {
        ELEMENT_PROPERTY(DE_NETWORK_ID,        network_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_NETWORK_CTRLID,    network_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_NETWORK_COLAGTID,  network_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_NETWORK_DEVNOE,    network_get, bus_data_type_uint32),
        ELEMENT_TABLE(DE_SSID_TABLE,           ssid_tget, bus_data_type_string),
        ELEMENT_PROPERTY(DE_SSID_SSID,         ssid_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_SSID_BAND,         ssid_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_SSID_ENABLE,       ssid_get, bus_data_type_boolean),
        ELEMENT_PROPERTY(DE_SSID_AKMALLOWE,    ssid_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_SSID_SUITESEL,     ssid_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_SSID_ADVENABLED,   ssid_get, bus_data_type_boolean),
        ELEMENT_PROPERTY(DE_SSID_MFPCONFIG,    ssid_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_SSID_MOBDOMAIN,    ssid_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_SSID_HAULTYPE,     ssid_get, bus_data_type_string),
        ELEMENT_TABLE(DE_DEVICE_TABLE,         device_tget, bus_data_type_string),
        ELEMENT_PROPERTY(DE_DEVICE_ID,         device_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_DEVICE_MANUFACT,   device_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_DEVICE_SERIALNO,   device_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_DEVICE_MFCMODEL,   device_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_DEVICE_SWVERSION,  device_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_DEVICE_EXECENV,    device_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_DEVICE_COUNTRCODE, device_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_DEVICE_BHMACADDR,  device_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_DEVICE_BHALID,     device_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_DEVICE_BHMEDIATYPE, device_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_DEVICE_RADIONOE,   device_get, bus_data_type_uint32),
        ELEMENT_PROPERTY(DE_DEVICE_CACSTATNOE, device_get, bus_data_type_uint32),
        ELEMENT_PROPERTY(DE_DEVICE_BHDOWNNOE,  device_get, bus_data_type_uint32),
        ELEMENT_TABLE(DE_RADIO_TABLE,          radio_tget, bus_data_type_string),
        ELEMENT_PROPERTY(DE_RADIO_ID,          radio_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_RADIO_ENABLED,     radio_get, bus_data_type_boolean),
        ELEMENT_PROPERTY(DE_RADIO_NOISE,       radio_get, bus_data_type_uint32),
        ELEMENT_PROPERTY(DE_RADIO_UTILIZATION, radio_get, bus_data_type_uint32),
        ELEMENT_PROPERTY(DE_RADIO_TRANSMIT,    radio_get, bus_data_type_uint32),
        ELEMENT_PROPERTY(DE_RADIO_RECEIVESELF, radio_get, bus_data_type_uint32),
        ELEMENT_PROPERTY(DE_RADIO_RECEIVEOTHER, radio_get, bus_data_type_uint32),
        ELEMENT_PROPERTY(DE_RADIO_CHIPVENDOR,  radio_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_RADIO_CURROPNOE,   radio_get, bus_data_type_uint32),
        ELEMENT_PROPERTY(DE_RADIO_BSSNOE,      radio_get, bus_data_type_uint32),
        ELEMENT_PROPERTY(DE_BHSTA_MACADDR,     rbhsta_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_RCAPS_HTCAPS,      rcaps_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_RCAPS_VHTCAPS,     rcaps_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_RCAPS_CAPOPNOE,    rcaps_get, bus_data_type_uint32),
        ELEMENT_TABLE(DE_CUROP_TABLE,          curops_tget, bus_data_type_string),
        ELEMENT_PROPERTY(DE_CUROP_CLASS,       curops_get, bus_data_type_uint32),
        ELEMENT_PROPERTY(DE_CUROP_CHANNEL,     curops_get, bus_data_type_uint32),
        ELEMENT_PROPERTY(DE_CUROP_TXPOWER,     curops_get, bus_data_type_int32),
        ELEMENT_TABLE(DE_BSS_TABLE,            bss_tget, bus_data_type_string),
        ELEMENT_PROPERTY(DE_BSS_BSSID,         bss_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_BSS_SSID,          bss_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_BSS_ENABLED,       bss_get, bus_data_type_boolean),
        ELEMENT_PROPERTY(DE_BSS_BYTCNTUNITS,   bss_get, bus_data_type_uint32),
        ELEMENT_PROPERTY(DE_BSS_BHAULUSE,      bss_get, bus_data_type_boolean),
        ELEMENT_PROPERTY(DE_BSS_FHAULUSE,      bss_get, bus_data_type_boolean),
        ELEMENT_PROPERTY(DE_BSS_FHAULAKMS,     bss_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_BSS_FHSUITESEL,    bss_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_BSS_BHAULAKMS,     bss_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_BSS_BHSUITESEL,    bss_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_BSS_STANOE,        bss_get, bus_data_type_uint32),
        ELEMENT_TABLE(DE_STA_TABLE,            sta_tget, bus_data_type_string),
        ELEMENT_PROPERTY(DE_STA_MACADDR,       sta_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_STA_HTCAPS,        sta_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_STA_VHTCAPS,       sta_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_STA_CLIENTCAPS,    sta_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_STA_LSTDTADLR,     sta_get, bus_data_type_uint32),
        ELEMENT_PROPERTY(DE_STA_LSTDTAULR,     sta_get, bus_data_type_uint32),
        ELEMENT_PROPERTY(DE_STA_UTILRECV,      sta_get, bus_data_type_uint64),
        ELEMENT_PROPERTY(DE_STA_UTILTRMT,      sta_get, bus_data_type_uint64),
        ELEMENT_PROPERTY(DE_STA_ESTMACDTARDL,  sta_get, bus_data_type_uint32),
        ELEMENT_PROPERTY(DE_STA_ESTMACDTARUL,  sta_get, bus_data_type_uint32),
        ELEMENT_PROPERTY(DE_STA_SIGNALSTR,     sta_get, bus_data_type_uint32),
        ELEMENT_PROPERTY(DE_STA_LASTCONNTIME,  sta_get, bus_data_type_uint32),
        ELEMENT_PROPERTY(DE_STA_BYTESSNT,      sta_get, bus_data_type_uint64),
        ELEMENT_PROPERTY(DE_STA_BYTESRCV,      sta_get, bus_data_type_uint64),
        ELEMENT_PROPERTY(DE_STA_PCKTSSNT,      sta_get, bus_data_type_uint64),
        ELEMENT_PROPERTY(DE_STA_PCKTSRCV,      sta_get, bus_data_type_uint64),
        ELEMENT_PROPERTY(DE_STA_ERRSSNT,       sta_get, bus_data_type_uint64),
        ELEMENT_PROPERTY(DE_STA_ERRSRCV,       sta_get, bus_data_type_uint64),
        ELEMENT_PROPERTY(DE_STA_RETRANSCNT,    sta_get, bus_data_type_uint64),
        ELEMENT_PROPERTY(DE_STA_IPV4ADDR,      sta_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_STA_IPV6ADDR,      sta_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_STA_HOSTNAME,      sta_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_STA_PAIRWSAKM,     sta_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_STA_PAIRWSCIPHER,  sta_get, bus_data_type_string),
        ELEMENT_PROPERTY(DE_STA_RSNCAPS,       sta_get, bus_data_type_uint32)
    };

    bus_desc = get_bus_descriptor();
    if (bus_desc == NULL) {
        printf("Bus is not initialized\n");
        return -1;
    }

    count = sizeof(elements) / sizeof(bus_data_element_t);
    rc = bus_desc->bus_reg_data_element_fn(bus_handle, elements, count);
    if (rc != bus_error_success) {
        printf("Bus register elements failed: %d\n", rc);
        return -1;
    }

    return 0;
}
