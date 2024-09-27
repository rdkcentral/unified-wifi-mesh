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
#include "dm_device_list.h"
#include "dm_easy_mesh.h"
#include "dm_easy_mesh_ctrl.h"

int dm_device_list_t::get_config(cJSON *obj_arr, void *parent)
{
	dm_device_t *pdev;
	cJSON *obj, *sec_obj;
	dm_easy_mesh_ctrl_t *dm = (dm_easy_mesh_ctrl_t *)parent;
	dm_ieee_1905_security_list_t *ieee_1905_security_list = dm->get_ieee_1905_security_list();
	
	pdev = (dm_device_t *)hash_map_get_first(m_list);
    while (pdev != NULL) {
       	obj = cJSON_CreateObject(); 

		pdev->encode(obj);

		sec_obj = cJSON_AddObjectToObject(obj, "IEEE1905Security");
		ieee_1905_security_list->get_config(sec_obj, &pdev->m_device_info.id.mac);
	
		cJSON_AddItemToArray(obj_arr, obj);
		pdev = (dm_device_t *)hash_map_get_next(m_list, pdev);
    }
    
	
	return 0;
}

int dm_device_list_t::set_config(db_client_t& db_client, dm_device_t& device, void *parent_id)
{
	dm_orch_type_t op;
	mac_addr_str_t  mac_str;	

	dm_easy_mesh_t::macbytes_to_string((unsigned char *)device.m_device_info.id.mac, mac_str);
	
	//printf("%s:%d: Enter: device id:%s\n", __func__, __LINE__, mac_str);
 
	update_db(db_client, (op = get_dm_orch_type(device)), device.get_device_info());
	update_list(device, op);

    return 0;
}

int dm_device_list_t::set_config(db_client_t& db_client, const cJSON *obj_arr, void *parent_id)
{
    cJSON *obj;
    unsigned int i, size;
	dm_device_t	device;
	dm_orch_type_t op;

    size = cJSON_GetArraySize(obj_arr);

    for (i = 0; i < size; i++) {
        obj = cJSON_GetArrayItem(obj_arr, i);
		device.decode(obj, parent_id);
		update_db(db_client, (op = get_dm_orch_type(device)), device.get_device_info());
		update_list(device, op);
    }

    return 0;
}


dm_orch_type_t dm_device_list_t::get_dm_orch_type(const dm_device_t& dev)
{
    dm_device_t *pdev;
    mac_addr_str_t  mac_str;

	dm_easy_mesh_t::macbytes_to_string((unsigned char *)dev.m_device_info.id.mac, mac_str);
    pdev = (dm_device_t *)hash_map_get(m_list, mac_str);
    
    if (pdev != NULL) {
        if (*pdev == dev) { 
            printf("%s:%d: Device: %s already in list\n", __func__, __LINE__, 
                        dm_easy_mesh_t::macbytes_to_string(pdev->m_device_info.id.mac, mac_str));
            return dm_orch_type_none;
        }


        printf("%s:%d: Device: %s in list but needs update\n", __func__, __LINE__,
            dm_easy_mesh_t::macbytes_to_string(pdev->m_device_info.id.mac, mac_str));
        return dm_orch_type_dev_update;
    }  

    return dm_orch_type_dev_insert;
}

void dm_device_list_t::update_list(const dm_device_t& dev, dm_orch_type_t op)
{
	dm_device_t *pdev;
	mac_addr_str_t	mac_str;

	dm_easy_mesh_t::macbytes_to_string((unsigned char *)dev.m_device_info.id.mac, mac_str);

    switch (op) {
        case dm_orch_type_dev_insert:
			hash_map_put(m_list, strdup(mac_str), new dm_device_t(dev));	
            break;

        case dm_orch_type_dev_update:
            pdev = (dm_device_t *)hash_map_get(m_list, mac_str);
            memcpy(&pdev->m_device_info, &dev.m_device_info, sizeof(em_device_info_t));
            break;

        case dm_orch_type_dev_delete:
            pdev = (dm_device_t *)hash_map_remove(m_list, mac_str);
            delete(pdev);
            break;
    }
}

void dm_device_list_t::delete_list()
{       
    dm_device_t *pdev, *tmp;
	mac_addr_str_t	mac_str;
    
    pdev = (dm_device_t *)hash_map_get_first(m_list);
    while (pdev != NULL) {
        tmp = pdev;
        pdev = (dm_device_t *)hash_map_get_next(m_list, pdev);       
    
		dm_easy_mesh_t::macbytes_to_string((unsigned char *)tmp->m_device_info.id.mac, mac_str);
        hash_map_remove(m_list, mac_str);
        delete(tmp);
    }
}   

bool dm_device_list_t::operator == (const db_easy_mesh_t& obj)
{
	return true;
}

int dm_device_list_t::update_db(db_client_t& db_client, dm_orch_type_t op, void *data)
{
    mac_addr_str_t mac_str, bk_mac_str, alid_str;
    const char *media_str = "802.11 n";
    em_device_info_t *info = (em_device_info_t *)data;
	int ret = 0;

	//printf("%s:%d: Opeartion:%d\n", __func__, __LINE__, op);
	switch (op) {
		case dm_orch_type_dev_insert:
			ret = insert_row(db_client, dm_easy_mesh_t::macbytes_to_string(info->id.mac, mac_str),
            			info->net_id, info->multi_ap_cap, info->coll_interval, info->num_radios, info->report_unsuccess_assocs, 
						info->max_reporting_rate, info->ap_metrics_reporting_interval, info->manufacturer, info->serial_number, 
            			info->manufacturer_model, info->software_ver, info->exec_env, info->country_code, info->traffic_sep_allowed,
            			info->svc_prio_allowed, info->dfs_enable, info->max_unsuccessful_assoc_report_rate, info->sta_steer_state, 
            			info->coord_cac_allowed, dm_easy_mesh_t::macbytes_to_string(info->backhaul_mac.mac, bk_mac_str), media_str,
            			dm_easy_mesh_t::macbytes_to_string(info->backhaul_alid.mac, alid_str), info->traffic_sep_cap, info->easy_conn_cap,
            			info->test_cap);
			break;

		case dm_orch_type_dev_update:
			ret = update_row(db_client, info->net_id, info->multi_ap_cap, info->coll_interval, info->num_radios, info->report_unsuccess_assocs, 
						info->max_reporting_rate, info->ap_metrics_reporting_interval, info->manufacturer, info->serial_number,
						info->manufacturer_model, info->software_ver, info->exec_env, info->country_code, info->traffic_sep_allowed,
						info->svc_prio_allowed, info->dfs_enable, info->max_unsuccessful_assoc_report_rate, info->sta_steer_state,
						info->coord_cac_allowed, dm_easy_mesh_t::macbytes_to_string(info->backhaul_mac.mac, bk_mac_str), media_str,
						dm_easy_mesh_t::macbytes_to_string(info->backhaul_alid.mac, alid_str), info->traffic_sep_cap, info->easy_conn_cap,
						info->test_cap, dm_easy_mesh_t::macbytes_to_string(info->id.mac, mac_str));
			break;

		case dm_orch_type_dev_delete:
			ret = delete_row(db_client, dm_easy_mesh_t::macbytes_to_string(info->id.mac, mac_str));
			break;

		default:
			break;
	}

    return ret;
}

void dm_device_list_t::sync_db(db_client_t& db_client, void *ctx)
{
	em_device_info_t info;
	mac_addr_str_t	mac;
    em_short_string_t   str;

    while (db_client.next_result(ctx)) {
		memset(&info, 0, sizeof(em_device_info_t));

		db_client.get_string(ctx, mac, 1);
		dm_easy_mesh_t::string_to_macbytes(mac, info.id.mac);

		db_client.get_string(ctx, info.net_id, 2);
		db_client.get_string(ctx, info.multi_ap_cap, 3);
        info.coll_interval = db_client.get_number(ctx, 4);
		info.num_radios = db_client.get_number(ctx, 5);	
		info.report_unsuccess_assocs = db_client.get_number(ctx, 6);	
		info.max_reporting_rate = db_client.get_number(ctx, 7);	
		info.ap_metrics_reporting_interval = db_client.get_number(ctx, 8);	
		db_client.get_string(ctx, info.manufacturer, 9);
        db_client.get_string(ctx, info.serial_number, 10);
        db_client.get_string(ctx, info.manufacturer_model, 11);
        db_client.get_string(ctx, info.software_ver, 12);
        db_client.get_string(ctx, info.exec_env, 13);
        db_client.get_string(ctx, info.country_code, 14);
		info.traffic_sep_allowed = db_client.get_number(ctx, 15);
		info.svc_prio_allowed = db_client.get_number(ctx, 16);
		info.dfs_enable = db_client.get_number(ctx, 17);
		info.max_unsuccessful_assoc_report_rate = db_client.get_number(ctx, 18);
		info.sta_steer_state = db_client.get_number(ctx, 19);
		info.coord_cac_allowed = db_client.get_number(ctx, 20);

		db_client.get_string(ctx, mac, 21);
		dm_easy_mesh_t::string_to_macbytes(mac, info.backhaul_mac.mac);

		db_client.get_string(ctx, str, 22);

		db_client.get_string(ctx, mac, 23);
		dm_easy_mesh_t::string_to_macbytes(mac, info.backhaul_alid.mac);

		info.traffic_sep_cap = db_client.get_number(ctx, 24);
		info.easy_conn_cap = db_client.get_number(ctx, 25);
		info.test_cap = db_client.get_number(ctx, 26);
        
		update_list(dm_device_t(&info), dm_orch_type_dev_insert);
    }
}

void dm_device_list_t::init_table()
{
    snprintf(m_table_name, sizeof(m_table_name), "%s", "DeviceList");
}

void dm_device_list_t::init_columns()
{
    m_num_cols = 0;

    m_columns[m_num_cols++] = db_column_t("ID", db_data_type_char, 17);
    m_columns[m_num_cols++] = db_column_t("NetworkID", db_data_type_char, 64);
    m_columns[m_num_cols++] = db_column_t("MultiAPCapabilities", db_data_type_char, 64);
    m_columns[m_num_cols++] = db_column_t("CollectionInterval", db_data_type_smallint, 0);
    m_columns[m_num_cols++] = db_column_t("NumberOfRadios", db_data_type_tinyint, 0);
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
    m_columns[m_num_cols++] = db_column_t("TrafficSeparationCapability", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("EasyConnectCapability", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("TestCapabilities", db_data_type_tinyint, 0);
}

int dm_device_list_t::init()
{
	m_list = hash_map_create();
    init_table();
    init_columns();
    return 0;
}
