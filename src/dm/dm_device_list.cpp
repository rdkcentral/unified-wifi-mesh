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
#include "em_cmd.h"
#include "dm_device_list.h"
#include "dm_easy_mesh.h"
#include "dm_easy_mesh_ctrl.h"

int dm_device_list_t::get_config(cJSON *obj_arr, void *parent, bool summary)
{
    dm_device_t *pdev;
    em_device_info_t *info;
    char *net_id = static_cast<char *> (parent);
    cJSON *obj;
	
    pdev = get_first_device();
    while (pdev != NULL) {
        info = pdev->get_device_info();
        if (strncmp(info->id.net_id, net_id, strlen(net_id)) == 0) {
            obj = cJSON_CreateObject();

            pdev->encode(obj, summary);
            cJSON_AddItemToArray(obj_arr, obj);
        }
        pdev = get_next_device(pdev);
    }
	
    return 0;
}

int dm_device_list_t::set_config(db_client_t& db_client, dm_device_t& device, void *key)
{
    dm_orch_type_t op;

	dm_device_t::parse_device_id_from_key(static_cast<char *> (key), &device.m_device_info.id);
 
    update_db(db_client, (op = get_dm_orch_type(db_client, device)), device.get_device_info());
    update_list(device, op);

    return 0;
}

int dm_device_list_t::set_config(db_client_t& db_client, const cJSON *obj_arr, void *key)
{
    cJSON *obj;
    int i, size;
    dm_device_t	device;
    dm_orch_type_t op;

    size = cJSON_GetArraySize(obj_arr);

    for (i = 0; i < size; i++) {
        obj = cJSON_GetArrayItem(obj_arr, i);
        device.decode(obj, key);
        update_db(db_client, (op = get_dm_orch_type(db_client, device)), device.get_device_info());
        update_list(device, op);
    }

    return 0;
}

dm_orch_type_t dm_device_list_t::get_dm_orch_type(db_client_t& db_client, const dm_device_t& dev)
{
    dm_device_t *pdev;
    mac_addr_str_t  mac_str;
    em_2xlong_string_t	key;

    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (dev.m_device_info.id.dev_mac), mac_str);
    snprintf(key, sizeof(em_2xlong_string_t), "%s@%s@%d", dev.m_device_info.id.net_id, mac_str, dev.m_device_info.id.media);

    pdev = get_device(key);
    
    if (pdev != NULL) {
        
        if (entry_exists_in_table(db_client, key) == false) {
            //printf("%s:%d: Device: %s does not exist in db\n", __func__, __LINE__, 
                         //dm_easy_mesh_t::macbytes_to_string(pdev->m_device_info.id.dev_mac, mac_str));
            return dm_orch_type_db_insert;
        }

        if (*pdev == dev) { 
            //printf("%s:%d: Device: %s already in list\n", __func__, __LINE__, 
                        //dm_easy_mesh_t::macbytes_to_string(pdev->m_device_info.id.dev_mac, mac_str));
            if (compare_db(db_client, dev) != true) {
                em_printfout("Dev and DB data mismatch, needs an update");
                return dm_orch_type_db_update;
            }
            return dm_orch_type_none;
        }


        //printf("%s:%d: Device: %s in list but needs update\n", __func__, __LINE__,
            //dm_easy_mesh_t::macbytes_to_string(pdev->m_device_info.id.dev_mac, mac_str));
        return dm_orch_type_db_update;
    }  

    return dm_orch_type_db_insert;
}

void dm_device_list_t::update_list(const dm_device_t& dev, dm_orch_type_t op)
{
    dm_device_t *pdev;
    mac_addr_str_t	mac_str;
    em_2xlong_string_t	key;

    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (dev.m_device_info.id.dev_mac), mac_str);
    snprintf(key, sizeof(em_2xlong_string_t), "%s@%s@%d", dev.m_device_info.id.net_id, mac_str, dev.m_device_info.id.media);

    switch (op) {
        case dm_orch_type_db_insert:
            put_device(key, &dev);
            break;

        case dm_orch_type_db_update:
            pdev = get_device(key);
            memcpy(&pdev->m_device_info, &dev.m_device_info, sizeof(em_device_info_t));
            break;

        case dm_orch_type_db_delete:
            remove_device(key);            
            break;

        default:
            break;
    }
}

void dm_device_list_t::delete_list()
{       
    dm_device_t *pdev, *tmp;
	em_2xlong_string_t key;
	mac_addr_str_t	dev_mac_str;
    
    pdev = get_first_device();
    while (pdev != NULL) {
        tmp = pdev;
        pdev = get_next_device(pdev);
    
		dm_easy_mesh_t::macbytes_to_string(tmp->m_device_info.id.dev_mac, dev_mac_str);
		snprintf(key, sizeof(em_2xlong_string_t), "%s@%s@%d", tmp->m_device_info.id.net_id, dev_mac_str, tmp->m_device_info.id.media);

        remove_device(key);
    }
}   

bool dm_device_list_t::operator == (const db_easy_mesh_t& obj)
{
	return true;
}

int dm_device_list_t::update_db(db_client_t& db_client, dm_orch_type_t op, void *data)
{
    mac_addr_str_t mac_str, bk_mac_str, alid_str, bsta_str;
    const char *media_str = "802.11 n";
    em_device_info_t *info = static_cast<em_device_info_t *> (data);
	int ret = 0;
	em_2xlong_string_t key;

	dm_easy_mesh_t::macbytes_to_string(info->id.dev_mac, mac_str);
	snprintf(key, sizeof(em_2xlong_string_t), "%s@%s@%d", info->id.net_id, mac_str, info->id.media);
    dm_easy_mesh_t::macbytes_to_string(info->backhaul_alid.mac, alid_str);
    dm_easy_mesh_t::macbytes_to_string(info->backhaul_sta, bsta_str);

    //printf("dm_device_list_t:%s:%d: Operation: %s\n", __func__, __LINE__, em_cmd_t::get_orch_op_str(op));
    switch (op) {
        case dm_orch_type_db_insert:
            ret = insert_row(db_client, key, mac_str,
                    info->profile, info->multi_ap_cap, info->coll_interval, info->report_unsuccess_assocs,
                    info->max_reporting_rate, info->ap_metrics_reporting_interval, info->manufacturer, info->serial_number,
                    info->manufacturer_model, info->software_ver, info->exec_env, info->country_code, info->traffic_sep_allowed,
                    info->svc_prio_allowed, info->dfs_enable, info->max_unsuccessful_assoc_report_rate, info->sta_steer_state,
                    info->coord_cac_allowed, dm_easy_mesh_t::macbytes_to_string(info->backhaul_mac.mac, bk_mac_str), media_str,
                    alid_str, bsta_str, info->traffic_sep_cap, info->easy_conn_cap,
                    info->test_cap);
            break;

        case dm_orch_type_db_update:
            ret = update_row(db_client, mac_str, info->profile, info->multi_ap_cap, info->coll_interval, info->report_unsuccess_assocs,
                    info->max_reporting_rate, info->ap_metrics_reporting_interval, info->manufacturer, info->serial_number,
                    info->manufacturer_model, info->software_ver, info->exec_env, info->country_code, info->traffic_sep_allowed,
                    info->svc_prio_allowed, info->dfs_enable, info->max_unsuccessful_assoc_report_rate, info->sta_steer_state,
                    info->coord_cac_allowed, dm_easy_mesh_t::macbytes_to_string(info->backhaul_mac.mac, bk_mac_str), media_str,
                    alid_str, bsta_str, info->traffic_sep_cap, info->easy_conn_cap,
                    info->test_cap, key);
            break;

        case dm_orch_type_db_delete:
            ret = delete_row(db_client, key);
            break;

        default:
            break;
    }

    return ret;
}

bool dm_device_list_t::search_db(db_client_t& db_client, void *ctx, void *key)
{
    em_long_string_t	str;

    while (db_client.next_result(ctx)) {
        db_client.get_string(ctx, str, 1);

        if (strncmp(str, static_cast<char *> (key), strlen(static_cast<char *> (key))) == 0) {
            return true;
        }
    }

	return false;
}

int dm_device_list_t::sync_db(db_client_t& db_client, void *ctx)
{
    em_device_info_t info;
    mac_addr_str_t	mac;
    em_long_string_t   str;
    int rc = 0;

    while (db_client.next_result(ctx)) {
        memset(&info, 0, sizeof(em_device_info_t));

        db_client.get_string(ctx, str, 1);
        dm_device_t::parse_device_id_from_key(str, &info.id);
        
		db_client.get_string(ctx, mac, 2);
		dm_easy_mesh_t::string_to_macbytes(mac, info.intf.mac);

        info.profile = static_cast<em_profile_type_t> (db_client.get_number(ctx, 3));
        db_client.get_string(ctx, info.multi_ap_cap, 4);
        info.coll_interval = static_cast<unsigned int> (db_client.get_number(ctx, 5));
        info.report_unsuccess_assocs = static_cast<unsigned int> (db_client.get_number(ctx, 6));
        info.max_reporting_rate = static_cast<short unsigned int> (db_client.get_number(ctx, 7));
        info.ap_metrics_reporting_interval = static_cast<short unsigned int> (db_client.get_number(ctx, 8));
        db_client.get_string(ctx, info.manufacturer, 9);
        db_client.get_string(ctx, info.serial_number, 10);
        db_client.get_string(ctx, info.manufacturer_model, 11);
        db_client.get_string(ctx, info.software_ver, 12);
        db_client.get_string(ctx, info.exec_env, 13);
        db_client.get_string(ctx, info.country_code, 14);
        info.traffic_sep_allowed = db_client.get_number(ctx, 15);
        info.svc_prio_allowed = db_client.get_number(ctx, 16);
        info.dfs_enable = db_client.get_number(ctx, 17);
        info.max_unsuccessful_assoc_report_rate = static_cast<short unsigned int> (db_client.get_number(ctx, 18));
        info.sta_steer_state = db_client.get_number(ctx, 19);
        info.coord_cac_allowed = db_client.get_number(ctx, 20);

        db_client.get_string(ctx, mac, 21);
        dm_easy_mesh_t::string_to_macbytes(mac, info.backhaul_mac.mac);

        db_client.get_string(ctx, str, 22);
    
        db_client.get_string(ctx, mac, 23);
        dm_easy_mesh_t::string_to_macbytes(mac, info.backhaul_alid.mac);

        db_client.get_string(ctx, mac, 24);
        dm_easy_mesh_t::string_to_macbytes(mac, info.backhaul_sta);

        info.traffic_sep_cap = db_client.get_number(ctx, 25);
        info.easy_conn_cap = db_client.get_number(ctx, 26);
        info.test_cap = static_cast<unsigned char> (db_client.get_number(ctx, 27));

        update_list(dm_device_t(&info), dm_orch_type_db_insert);
    }

    return rc;

}

bool dm_device_list_t::compare_db(db_client_t& db_client, const dm_device_t& sta)
{
    em_device_info_t info;
    mac_addr_str_t mac;
    em_long_string_t   str;
    db_query_t    query;
    void *ctx;

    memset(query, 0, sizeof(db_query_t));
    snprintf(query, sizeof(db_query_t), "select * from %s", m_table_name);

    ctx = db_client.execute(query);

    while (db_client.next_result(ctx)) {
        memset(&info, 0, sizeof(em_device_info_t));

        db_client.get_string(ctx, str, 1);
        dm_device_t::parse_device_id_from_key(str, &info.id);

        db_client.get_string(ctx, str, 2);
        dm_easy_mesh_t::string_to_macbytes(mac, info.intf.mac);

        info.profile = static_cast<em_profile_type_t> (db_client.get_number(ctx, 3));
        db_client.get_string(ctx, info.multi_ap_cap, 4);
        info.coll_interval = static_cast<unsigned int> (db_client.get_number(ctx, 5));
        info.report_unsuccess_assocs = static_cast<unsigned int> (db_client.get_number(ctx, 6));
        info.max_reporting_rate = static_cast<short unsigned int> (db_client.get_number(ctx, 7));
        info.ap_metrics_reporting_interval = static_cast<short unsigned int> (db_client.get_number(ctx, 8));
        db_client.get_string(ctx, info.manufacturer, 9);
        db_client.get_string(ctx, info.serial_number, 10);
        db_client.get_string(ctx, info.manufacturer_model, 11);
        db_client.get_string(ctx, info.software_ver, 12);
        db_client.get_string(ctx, info.exec_env, 13);
        db_client.get_string(ctx, info.country_code, 14);
        info.traffic_sep_allowed = db_client.get_number(ctx, 15);
        info.svc_prio_allowed = db_client.get_number(ctx, 16);
        info.dfs_enable = db_client.get_number(ctx, 17);
        info.max_unsuccessful_assoc_report_rate = static_cast<short unsigned int> (db_client.get_number(ctx, 18));
        info.sta_steer_state = db_client.get_number(ctx, 19);
        info.coord_cac_allowed = db_client.get_number(ctx, 20);

        db_client.get_string(ctx, mac, 21);
        dm_easy_mesh_t::string_to_macbytes(mac, info.backhaul_mac.mac);

        db_client.get_string(ctx, str, 22);

        db_client.get_string(ctx, mac, 23);
        dm_easy_mesh_t::string_to_macbytes(mac, info.backhaul_alid.mac);

        db_client.get_string(ctx, mac, 24);
        dm_easy_mesh_t::string_to_macbytes(mac, info.backhaul_sta);

        info.traffic_sep_cap = db_client.get_number(ctx, 25);
        info.easy_conn_cap = db_client.get_number(ctx, 26);
        info.test_cap = static_cast<unsigned char> (db_client.get_number(ctx, 27));

        if (memcmp(static_cast<const void*>(&sta.m_device_info), static_cast<const void*>(&info), sizeof(em_device_info_t)) == 0) {
            return true;
        }
    }

    return false;
}

void dm_device_list_t::init_table()
{
    snprintf(m_table_name, sizeof(m_table_name), "%s", "DeviceList");
}

void dm_device_list_t::init_columns()
{
    m_num_cols = 0;

    m_columns[m_num_cols++] = db_column_t("ID", db_data_type_char, 128);
    m_columns[m_num_cols++] = db_column_t("DeviceID", db_data_type_char, 17);
    m_columns[m_num_cols++] = db_column_t("Profile", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("MultiAPCapabilities", db_data_type_char, 64);
    m_columns[m_num_cols++] = db_column_t("CollectionInterval", db_data_type_smallint, 0);
    m_columns[m_num_cols++] = db_column_t("ReportUnsuccessfulAssociations", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("MaxReportingRate", db_data_type_smallint, 0);
    m_columns[m_num_cols++] = db_column_t("APMetricsReportingInterval", db_data_type_smallint, 0);
    m_columns[m_num_cols++] = db_column_t("Manufacturer", db_data_type_char, 64);
    m_columns[m_num_cols++] = db_column_t("SerialNumber", db_data_type_char, 64);
    m_columns[m_num_cols++] = db_column_t("ManufacturerModel", db_data_type_char, 64);
    m_columns[m_num_cols++] = db_column_t("SoftwareVersion", db_data_type_char, 16);
    m_columns[m_num_cols++] = db_column_t("ExecutionEnv", db_data_type_char, 16);
    m_columns[m_num_cols++] = db_column_t("CountryCode", db_data_type_char, 4);
    m_columns[m_num_cols++] = db_column_t("TrafficSeparationAllowed", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("ServicePrioritizationAllowed", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("DFSEnable", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("MaxUnsuccessfulAssociationReportingRate", db_data_type_smallint, 0);
    m_columns[m_num_cols++] = db_column_t("STASteeringState", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("CoordinatedCACAllowed", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("BackhaulMACAddress", db_data_type_char, 17);
    m_columns[m_num_cols++] = db_column_t("BackhaulMediaType", db_data_type_char, 32);
    m_columns[m_num_cols++] = db_column_t("BackhaulALID", db_data_type_char, 17);
    m_columns[m_num_cols++] = db_column_t("BackhaulSTA", db_data_type_char, 17);
    m_columns[m_num_cols++] = db_column_t("TrafficSeparationCapability", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("EasyConnectCapability", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("TestCapabilities", db_data_type_tinyint, 0);
}

int dm_device_list_t::init()
{
    init_table();
    init_columns();
    return 0;
}
