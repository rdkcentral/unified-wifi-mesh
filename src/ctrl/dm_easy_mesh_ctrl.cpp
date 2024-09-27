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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <unistd.h>
#include "dm_easy_mesh_ctrl.h"
#include "dm_easy_mesh.h"
#include <cjson/cJSON.h>
#include "em_cmd_reset.h"

extern char *global_netid;

int dm_easy_mesh_ctrl_t::analyze_radio_metrics_req(em_cmd_t *cmd[])
{
    return 0;
}

int dm_easy_mesh_ctrl_t::analyze_ap_metrics_req(em_cmd_t *cmd[])
{
    return 0;
}

int dm_easy_mesh_ctrl_t::analyze_client_metrics_req(em_cmd_t *cmd[])
{
    return 0;
}

int dm_easy_mesh_ctrl_t::analyze_reset(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    unsigned int num = 0, dev_idx = 0, num_devices = 0, i;
    em_subdoc_info_t *subdoc;
    dm_easy_mesh_t  dm;
    em_cmd_t *tmp;

    subdoc = &evt->u.subdoc;
    num_devices = dm.decode_num_devices(subdoc);

    dm.decode_config(subdoc, "Network", 0);
    //dm.print_config();

    pcmd[num] = new em_cmd_reset_t(evt->params, dm);
    tmp = pcmd[num];
    num++;

    while ((pcmd[num] = tmp->clone_for_next()) != NULL) {
        if (pcmd[num]->get_orch_op() == dm_orch_type_db_cfg) {
            tmp = pcmd[num];
            tmp->m_data_model.print_config();
            num++;
            for (i = 0; i < num_devices - 1; i++) {
                dm.decode_config(subdoc, "Network", dev_idx);
                //dm.print_config();
                pcmd[num] = tmp->clone();
                //pcmd[num]->m_data_model.print_config();
                tmp = pcmd[num];
                num++;
            }
        } else {
            tmp = pcmd[num];
            num++;
        }
    }
    printf("%s:%d: Number of commands:%d\n", __func__, __LINE__, num);

    return num;

}

int dm_easy_mesh_ctrl_t::analyze_client_steer(em_bus_event_t *evt, em_cmd_t *cmd[])
{
    cJSON *obj, *steer_obj;
    unsigned int num = 0;
    em_subdoc_info_t *subdoc;

    subdoc = &evt->u.subdoc;

    obj = cJSON_Parse(subdoc->buff);
    if (obj == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        return 0;
    }

    steer_obj = cJSON_GetObjectItem(obj, "ClientSteer");
    if (steer_obj == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        return 0;
    }

    num = m_sta_list.analyze_config(steer_obj, NULL, cmd, &evt->params);

    cJSON_free(obj);

    return num;
}

int dm_easy_mesh_ctrl_t::analyze_dpp_start(em_bus_event_t *evt, em_cmd_t *cmd[])
{
    cJSON *obj, *dpp_obj;
    unsigned int num = 0;
    em_subdoc_info_t *subdoc;

    subdoc = &evt->u.subdoc;

    obj = cJSON_Parse(subdoc->buff);
    if (obj == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        return 0;
    }

    dpp_obj = cJSON_GetObjectItem(obj, "URI");
    if (dpp_obj == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        return 0;
    }

    num = m_dpp.analyze_config(dpp_obj, NULL, cmd, &evt->params);
    cJSON_free(obj);

    return num;
}

int dm_easy_mesh_ctrl_t::analyze_network_ssid_list(em_bus_event_t *evt, em_cmd_t *cmd[])
{
    cJSON *obj, *netssid_list_obj;
    unsigned int num = 0;
    em_subdoc_info_t *subdoc;

    subdoc = &evt->u.subdoc;

    obj = cJSON_Parse(subdoc->buff);
    if (obj == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        return 0;
    }

    netssid_list_obj = cJSON_GetObjectItem(obj, "NetworkSSIDList");
    if (netssid_list_obj == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        return 0;
    }

    num = m_network_ssid_list.analyze_config(netssid_list_obj, (void *)global_netid, cmd, &evt->params);
    cJSON_free(obj);

    return num;
}

int dm_easy_mesh_ctrl_t::set_op_class_list(cJSON *op_class_list_obj, mac_address_t *radio_mac)
{
    m_op_class_list.set_config(m_db_client, op_class_list_obj, radio_mac);
    return 0;
}

int dm_easy_mesh_ctrl_t::set_radio_cap_list(cJSON *radio_cap_list_obj, mac_address_t *radio_mac)
{
    m_radio_cap_list.set_config(m_db_client, radio_cap_list_obj, radio_mac);
    return 0;
}

int dm_easy_mesh_ctrl_t::set_bss_list(cJSON *bss_list_obj, mac_address_t *radio_mac)
{
    m_bss_list.set_config(m_db_client, bss_list_obj, radio_mac);
    return 0;
}

int dm_easy_mesh_ctrl_t::set_radio_list(cJSON *radio_list_obj, mac_address_t *dev_mac)
{
    unsigned int i, num;
    cJSON *obj, *radio_obj, *bss_list_obj, *op_class_list_obj, *radio_cap_list_obj;
    mac_address_t radio_mac;

    m_radio_list.set_config(m_db_client, radio_list_obj, dev_mac);

    num = cJSON_GetArraySize(radio_list_obj);
    printf("%s:%d: Number of devices: %d\n", __func__, __LINE__, num);
    for (i = 0; i < num; i++) {
        if ((radio_obj = cJSON_GetArrayItem(radio_list_obj, i)) != NULL) {

            obj = cJSON_GetObjectItem(radio_obj, "ID");
            dm_easy_mesh_t::string_to_macbytes(cJSON_GetStringValue(obj), radio_mac);
            printf("%s:%d: BSSList for radio[%d]: %s\n", __func__, __LINE__, i, cJSON_GetStringValue(obj));

            if ((bss_list_obj = cJSON_GetObjectItem(radio_obj, "BSSList")) != NULL) {
                set_bss_list(bss_list_obj, &radio_mac);
            }

            if ((op_class_list_obj = cJSON_GetObjectItem(radio_obj, "CurrentOperatingClasses")) != NULL) {
                set_op_class_list(op_class_list_obj, &radio_mac);
            }

            if ((radio_cap_list_obj = cJSON_GetObjectItem(radio_obj, "Capabilities")) != NULL) {
                set_radio_cap_list(radio_cap_list_obj, &radio_mac);
            }

        }
    }

    return 0;
}

int dm_easy_mesh_ctrl_t::set_device_list(cJSON *dev_list_obj)
{
    unsigned int i, num;
    cJSON *obj, *dev_obj, *radio_list_obj;
    mac_address_t dev_mac;

    m_device_list.set_config(m_db_client, dev_list_obj, (void *)global_netid);

    num = cJSON_GetArraySize(dev_list_obj);
    printf("%s:%d: Number of devices: %d\n", __func__, __LINE__, num);
    for (i = 0; i < num; i++) {
        if (((dev_obj = cJSON_GetArrayItem(dev_list_obj, i)) != NULL) &&
           ((radio_list_obj = cJSON_GetObjectItem(dev_obj, "RadioList")) != NULL)) {
            obj = cJSON_GetObjectItem(dev_obj, "ID");
            dm_easy_mesh_t::string_to_macbytes(cJSON_GetStringValue(obj), dev_mac);
            printf("%s:%d: RadioList for device[%d]: %s\n", __func__, __LINE__, i, cJSON_GetStringValue(obj));
            set_radio_list(radio_list_obj, &dev_mac);
        }
    }

    return 0;
}

int dm_easy_mesh_ctrl_t::reset_config()
{
    m_network_list.delete_list();
    m_device_list.delete_list();
    m_network_ssid_list.delete_list();
    m_ieee_1905_security_list.delete_list();
    m_radio_list.delete_list();
    m_radio_cap_list.delete_list();
    m_op_class_list.delete_list();
    m_bss_list.delete_list();
    m_sta_list.delete_list();

    m_network_list.delete_table(m_db_client);
    m_device_list.delete_table(m_db_client);
    m_network_ssid_list.delete_table(m_db_client);
    m_ieee_1905_security_list.delete_table(m_db_client);
    m_radio_list.delete_table(m_db_client);
    m_radio_cap_list.delete_table(m_db_client);
    m_op_class_list.delete_table(m_db_client);
    m_bss_list.delete_table(m_db_client);
    m_sta_list.delete_table(m_db_client);

    m_network_list.load_table(m_db_client);
    m_device_list.load_table(m_db_client);
    m_network_ssid_list.load_table(m_db_client);
    m_ieee_1905_security_list.load_table(m_db_client);
    m_radio_list.load_table(m_db_client);
    m_radio_cap_list.load_table(m_db_client);
    m_op_class_list.load_table(m_db_client);
    m_bss_list.load_table(m_db_client);
    m_sta_list.load_table(m_db_client);

    return 0;
}

int dm_easy_mesh_ctrl_t::get_config(em_subdoc_info_t *subdoc)
{
    cJSON *parent, *net_obj, *dev_list_obj, *netssid_list_obj, *radio_list_obj;
    cJSON *obj, *dev_obj;
    char *tmp;
    unsigned int i, num;
    mac_address_t dev_mac;

    parent = cJSON_CreateObject();

    printf("%s:%d: Name:%s\n", __func__, __LINE__, subdoc->name);

    if (strncmp(subdoc->name, "Network", strlen("Network")) == 0) {
        net_obj = cJSON_AddObjectToObject(parent, "Network");
        m_network_list.get_config(net_obj, this);
        dev_list_obj = cJSON_AddArrayToObject(net_obj, "DeviceList");
        m_device_list.get_config(dev_list_obj, this);
        netssid_list_obj = cJSON_AddArrayToObject(net_obj, "NetworkSSIDList");
        m_network_ssid_list.get_config(netssid_list_obj, this);
        num = cJSON_GetArraySize(dev_list_obj);
        for (i = 0; i < num; i++) {
            if (((dev_obj = cJSON_GetArrayItem(dev_list_obj, i)) != NULL) &&
                    ((obj = cJSON_GetObjectItem(dev_obj, "ID")) != NULL)) {
                radio_list_obj = cJSON_AddArrayToObject(dev_obj, "RadioList");
                dm_easy_mesh_t::string_to_macbytes(cJSON_GetStringValue(obj), dev_mac);
                m_radio_list.get_config(radio_list_obj, &dev_mac);
            }

        }
    } else if (strncmp(subdoc->name, "DeviceList", strlen("DeviceList")) == 0) {

    }

    tmp = cJSON_Print(parent);
    printf("%s:%d: Subdoc: %s\n", __func__, __LINE__, tmp);
    snprintf(subdoc->buff, sizeof(subdoc->buff), "%s", tmp);
    cJSON_free(parent);
}

int dm_easy_mesh_ctrl_t::copy_config(dm_easy_mesh_t *dm, em_long_string_t net_id)
{
    dm_network_t *network;

    network = m_network_list.get_network(net_id);
    if (network == NULL) {
        printf("%s%%d: Network with id:%d not found\n", __func__, __LINE__, net_id);
        return -1;
    }

    dm->set_network(*network);

    return 0;
}

int dm_easy_mesh_ctrl_t::set_config(dm_easy_mesh_t *dm)
{
    m_network_list.set_config(m_db_client, dm->get_network_by_reference(), global_netid);
    m_device_list.set_config(m_db_client, dm->get_device_by_reference(), NULL );
    return 0;
}

int dm_easy_mesh_ctrl_t::init(const char *data_model_path)
{
    dm_device_t *dev;
    void *res;

    m_network_list.init();
    m_device_list.init();
    m_network_ssid_list.init();
    m_ieee_1905_security_list.init();
    m_radio_cap_list.init();
    m_radio_list.init();
    m_op_class_list.init();
    m_bss_list.init();
    m_sta_list.init();

    if (m_db_client.init(data_model_path) != 0) {
        printf("%s:%d db init failed\n", __func__, __LINE__);
        return -1;
    }

    m_network_list.load_table(m_db_client);
    m_device_list.load_table(m_db_client);
    m_network_ssid_list.load_table(m_db_client);
    m_ieee_1905_security_list.load_table(m_db_client);
    m_radio_list.load_table(m_db_client);
    m_radio_cap_list.load_table(m_db_client);
    m_op_class_list.load_table(m_db_client);
    m_bss_list.load_table(m_db_client);
    m_sta_list.load_table(m_db_client);

    return 0;
}

dm_easy_mesh_ctrl_t::dm_easy_mesh_ctrl_t()
{

}

dm_easy_mesh_ctrl_t::~dm_easy_mesh_ctrl_t()
{

}


