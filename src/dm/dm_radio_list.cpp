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
#include "dm_radio_list.h"
#include "dm_easy_mesh.h"
#include "dm_easy_mesh_ctrl.h"

int dm_radio_list_t::get_config(cJSON *obj_arr, void *parent)
{
	dm_radio_t *pradio;
	cJSON *obj, *sec_obj;
	mac_addr_str_t  mac_str;
	mac_address_t *dev_mac = (mac_address_t *)parent;
	
	pradio = (dm_radio_t *)hash_map_get_first(m_list);
    while (pradio != NULL) {
		if (memcmp(dev_mac, &pradio->m_radio_info.id.mac, sizeof(mac_address_t)) != 0) {
			pradio = (dm_radio_t *)hash_map_get_next(m_list, pradio);
			continue;
		}
       	obj = cJSON_CreateObject(); 

		dm_easy_mesh_t::macbytes_to_string(pradio->m_radio_info.id.mac, mac_str);
		cJSON_AddStringToObject(obj, "ID", mac_str);

		cJSON_AddBoolToObject(obj, "Enabled", pradio->m_radio_info.enabled);
		cJSON_AddNumberToObject(obj, "NumberOfBSS", pradio->m_radio_info.number_of_bss);
		cJSON_AddNumberToObject(obj, "NumberOfUnassocSta", pradio->m_radio_info.number_of_unassoc_sta);
		cJSON_AddNumberToObject(obj, "Noise", pradio->m_radio_info.noise);
		cJSON_AddNumberToObject(obj, "Utilization", pradio->m_radio_info.utilization);
		cJSON_AddNumberToObject(obj, "NumberOfCurrOpClass", pradio->m_radio_info.number_of_curr_op_classes);
		cJSON_AddBoolToObject(obj, "TrafficSeparationCombinedFronthaul", pradio->m_radio_info.traffic_sep_combined_fronthaul);
		cJSON_AddBoolToObject(obj, "TrafficSeparationCombinedBackhaul", pradio->m_radio_info.traffic_sep_combined_backhaul);
		cJSON_AddNumberToObject(obj, "SteeringPolicy", pradio->m_radio_info.steering_policy);
		cJSON_AddNumberToObject(obj, "ChannelUtilizationThreshold", pradio->m_radio_info.channel_util_threshold);
		cJSON_AddNumberToObject(obj, "RCPISteeringThreshold", pradio->m_radio_info.rcpi_steering_threshold);
		cJSON_AddNumberToObject(obj, "STAReportingRCPIThreshold", pradio->m_radio_info.sta_reporting_rcpi_threshold);
		cJSON_AddNumberToObject(obj, "STAReportingRCPIHysteresisMarginOverride", pradio->m_radio_info.sta_reporting_hysteresis_margin_override);
		cJSON_AddNumberToObject(obj, "ChannelUtilizationReportingThreshold", pradio->m_radio_info.channel_utilization_reporting_threshold);
		cJSON_AddBoolToObject(obj, "AssociatedSTATrafficStatsInclusionPolicy", pradio->m_radio_info.associated_sta_traffic_stats_inclusion_policy);
		cJSON_AddBoolToObject(obj, "AssociatedSTALinkMetricsInclusionPolicy", pradio->m_radio_info.associated_sta_link_mterics_inclusion_policy);
			
		cJSON_AddStringToObject(obj, "ChipsetVendor", pradio->m_radio_info.chip_vendor);

	
		cJSON_AddItemToArray(obj_arr, obj);
		pradio = (dm_radio_t *)hash_map_get_next(m_list, pradio);
    }
    
	
	return 0;
}

int dm_radio_list_t::set_config(db_client_t& db_client, const cJSON *obj_arr, void *parent_id)
{
    cJSON *obj;
    unsigned int i, size;
	dm_radio_t radio;
	dm_orch_type_t op;

    size = cJSON_GetArraySize(obj_arr);

    for (i = 0; i < size; i++) {
        obj = cJSON_GetArrayItem(obj_arr, i);
		radio.decode(obj, parent_id);
		update_db(db_client, (op = get_dm_orch_type(radio)), radio.get_radio_info());
		update_list(radio, op);
    }

    return 0;
}

dm_orch_type_t dm_radio_list_t::get_dm_orch_type(const dm_radio_t& radio)
{
	dm_radio_t *pradio;
    mac_addr_str_t  mac_str = {0};

	dm_easy_mesh_t::macbytes_to_string((unsigned char *)radio.m_radio_info.id.mac, mac_str);
	pradio = (dm_radio_t *)hash_map_get(m_list, mac_str);
    if (pradio != NULL) {
        if (*pradio == radio) {
            printf("%s:%d: Device: %s already in list\n", __func__, __LINE__,
                        dm_easy_mesh_t::macbytes_to_string(pradio->m_radio_info.id.mac, mac_str));
            return dm_orch_type_none;
        }


        printf("%s:%d: Device: %s in list but needs update\n", __func__, __LINE__,
            dm_easy_mesh_t::macbytes_to_string(pradio->m_radio_info.id.mac, mac_str));
        return dm_orch_type_rd_update;
    }  

    return dm_orch_type_rd_insert;

}

void dm_radio_list_t::update_list(const dm_radio_t& radio, dm_orch_type_t op)
{
	dm_radio_t *pradio;
	mac_addr_str_t	mac_str = {0};

	dm_easy_mesh_t::macbytes_to_string((unsigned char *)radio.m_radio_info.id.mac, mac_str);

    switch (op) {
        case dm_orch_type_rd_insert:
            hash_map_put(m_list, strdup(mac_str), new dm_radio_t(radio));
            break;

        case dm_orch_type_rd_update:
            pradio = (dm_radio_t *)hash_map_get(m_list, mac_str);
            memcpy(&pradio->m_radio_info, &radio.m_radio_info, sizeof(em_radio_info_t));
            break;

        case dm_orch_type_rd_delete:
            pradio = (dm_radio_t *)hash_map_remove(m_list, mac_str);
            delete(pradio);
            break;
    }

}

void dm_radio_list_t::delete_list()
{       
    dm_radio_t *pradio, *tmp;
	mac_addr_str_t	mac_str = {0};
    
    pradio = (dm_radio_t *)hash_map_get_first(m_list);
    while (pradio != NULL) {
        tmp = pradio;
        pradio = (dm_radio_t *)hash_map_get_next(m_list, pradio);       
		dm_easy_mesh_t::macbytes_to_string((unsigned char *)tmp->m_radio_info.id.mac, mac_str);
    
        hash_map_remove(m_list, mac_str);
        delete(tmp);
    }
}   


bool dm_radio_list_t::operator == (const db_easy_mesh_t& obj)
{
	return true;
}

int dm_radio_list_t::update_db(db_client_t& db_client, dm_orch_type_t op, void *data)
{
    mac_addr_str_t mac_str, dev_mac_str;
    em_radio_info_t *info = (em_radio_info_t *)data;
	int ret = 0;

	printf("%s:%d: Opeartion:%d\n", __func__, __LINE__, op);
	switch (op) {
		case dm_orch_type_rd_insert:
			ret = insert_row(db_client, dm_easy_mesh_t::macbytes_to_string(info->id.mac, mac_str), 
						dm_easy_mesh_t::macbytes_to_string(info->id.mac, dev_mac_str), info->enabled,
            			info->number_of_bss, info->number_of_unassoc_sta, info->noise, info->utilization, 
						info->number_of_curr_op_classes, info->traffic_sep_combined_fronthaul, 
						info->traffic_sep_combined_backhaul, info->steering_policy, info->channel_util_threshold, info->rcpi_steering_threshold, 
            			info->sta_reporting_rcpi_threshold, info->sta_reporting_hysteresis_margin_override, info->channel_utilization_reporting_threshold, 
						info->associated_sta_traffic_stats_inclusion_policy, info->associated_sta_link_mterics_inclusion_policy,
            			info->chip_vendor); 
			break;

		case dm_orch_type_rd_update:
			ret = update_row(db_client, dm_easy_mesh_t::macbytes_to_string(info->id.mac, dev_mac_str), info->enabled,
                        info->number_of_bss, info->number_of_unassoc_sta, info->noise, info->utilization,
                        info->number_of_curr_op_classes, info->traffic_sep_combined_fronthaul,
                        info->traffic_sep_combined_backhaul, info->steering_policy, info->channel_util_threshold, info->rcpi_steering_threshold,
                        info->sta_reporting_rcpi_threshold, info->sta_reporting_hysteresis_margin_override, info->channel_utilization_reporting_threshold, 
                        info->associated_sta_traffic_stats_inclusion_policy, info->associated_sta_link_mterics_inclusion_policy,
                        info->chip_vendor, dm_easy_mesh_t::macbytes_to_string(info->id.mac, mac_str));
			break;

		case dm_orch_type_rd_delete:
			ret = delete_row(db_client, dm_easy_mesh_t::macbytes_to_string(info->id.mac, mac_str));
			break;

		default:
			break;
	}

    return ret;
}

void dm_radio_list_t::sync_db(db_client_t& db_client, void *ctx)
{
	em_radio_info_t info;
	mac_addr_str_t	mac;
    em_short_string_t   str;

    while (db_client.next_result(ctx)) {
		memset(&info, 0, sizeof(em_radio_info_t));

		db_client.get_string(ctx, mac, 1);
		dm_easy_mesh_t::string_to_macbytes(mac, info.id.mac);

		db_client.get_string(ctx, mac, 2);
		dm_easy_mesh_t::string_to_macbytes(mac, info.id.mac);

        info.enabled = db_client.get_number(ctx, 3);
        info.number_of_bss = db_client.get_number(ctx, 4);
        info.number_of_unassoc_sta = db_client.get_number(ctx, 5);
        info.noise = db_client.get_number(ctx, 6);
        info.utilization = db_client.get_number(ctx, 7);
        info.number_of_curr_op_classes = db_client.get_number(ctx, 8);
        info.traffic_sep_combined_fronthaul = db_client.get_number(ctx, 9);
        info.traffic_sep_combined_backhaul = db_client.get_number(ctx, 10);
        info.steering_policy = db_client.get_number(ctx, 11);
        info.channel_util_threshold = db_client.get_number(ctx, 12);
        info.rcpi_steering_threshold = db_client.get_number(ctx, 13);
        info.sta_reporting_rcpi_threshold = db_client.get_number(ctx, 14);
        info.sta_reporting_hysteresis_margin_override = db_client.get_number(ctx, 15);
        info.channel_utilization_reporting_threshold = db_client.get_number(ctx, 16);
        info.associated_sta_traffic_stats_inclusion_policy = db_client.get_number(ctx, 17);
        info.associated_sta_link_mterics_inclusion_policy = db_client.get_number(ctx, 18);
        
		db_client.get_string(ctx, info.chip_vendor, 19);
		
		update_list(dm_radio_t(&info), dm_orch_type_rd_insert);
    }
}

void dm_radio_list_t::init_table()
{
    snprintf(m_table_name, sizeof(m_table_name), "%s", "RadioList");
}

void dm_radio_list_t::init_columns()
{
    m_num_cols = 0;

    m_columns[m_num_cols++] = db_column_t("ID", db_data_type_char, 17);
    m_columns[m_num_cols++] = db_column_t("DeviceID", db_data_type_char, 17);
    m_columns[m_num_cols++] = db_column_t("Enabled", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("NumberOfBSS", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("NumberOfUnassocSta", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("Noise", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("Utilization", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("NumberOfCurrOpClass", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("TrafficSeparationCombinedFronthaul", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("TrafficSeparationCombinedBackhaul", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("SteeringPolicy", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("ChannelUtilizationThreshold", db_data_type_smallint, 0);
    m_columns[m_num_cols++] = db_column_t("RCPISteeringThreshold", db_data_type_smallint, 0);
    m_columns[m_num_cols++] = db_column_t("STAReportingRCPIThreshold", db_data_type_smallint, 0);
    m_columns[m_num_cols++] = db_column_t("STAReportingRCPIHysteresisMarginOverride", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("ChannelUtilizationReportingThreshold", db_data_type_smallint, 0);
    m_columns[m_num_cols++] = db_column_t("AssociatedSTATrafficStatsInclusionPolicy", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("AssociatedSTALinkMetricsInclusionPolicy", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("ChipsetVendor", db_data_type_char, 64);
}

int dm_radio_list_t::init()
{
	m_list = hash_map_create();
    init_table();
    init_columns();
    return 0;
}
