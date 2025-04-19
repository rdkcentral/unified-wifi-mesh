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
#include "dm_policy_list.h"
#include "dm_easy_mesh.h"
#include "dm_easy_mesh_ctrl.h"

int dm_policy_list_t::get_config(cJSON *parent_obj, void *parent, bool summary)
{
    dm_policy_t *policy;
	cJSON *obj, *radio_metrics_arr_obj, *radio_steer_arr_obj;
	mac_addr_str_t radio_mac_str;
	mac_address_t dev_mac;
	mac_address_t null_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	dm_easy_mesh_t::string_to_macbytes(static_cast<char *>(parent), dev_mac);

	// first report the global policies for the device, for global the radio id will be NULL
    policy = static_cast<dm_policy_t *>(get_first_policy());
    while (policy != NULL) {
		if (memcmp(policy->m_policy.id.dev_mac, dev_mac, sizeof(mac_address_t)) != 0) {
	    	policy = get_next_policy(policy);
	    	continue;
		}

		if (memcmp(policy->m_policy.id.radio_mac, null_mac, sizeof(mac_address_t)) != 0) {
	    	policy = get_next_policy(policy);
	    	continue;
		}

       	obj = cJSON_CreateObject(); 

		if (policy->m_policy.id.type == em_policy_id_type_steering_local) {
			policy->encode(obj, em_policy_id_type_steering_local);
			cJSON_AddItemToObject(parent_obj, "Local Steering Disallowed Policy", obj);
		} else if (policy->m_policy.id.type == em_policy_id_type_steering_btm) {
			policy->encode(obj, em_policy_id_type_steering_btm);
			cJSON_AddItemToObject(parent_obj, "BTM Steering Disallowed Policy", obj);
		} else if (policy->m_policy.id.type == em_policy_id_type_ap_metrics_rep) {
			policy->encode(obj, em_policy_id_type_ap_metrics_rep);
			cJSON_AddItemToObject(parent_obj, "AP Metrics Reporting Policy", obj);
		} else if (policy->m_policy.id.type == em_policy_id_type_channel_scan) {
			policy->encode(obj, em_policy_id_type_channel_scan);
			cJSON_AddItemToObject(parent_obj, "Channel Scan Reporting Policy", obj);
		} else if (policy->m_policy.id.type == em_policy_id_type_backhaul_bss_config) {
			policy->encode(obj, em_policy_id_type_backhaul_bss_config);
			cJSON_AddItemToObject(parent_obj, "Backhaul BSS Configuration Policy", obj);
		}

		policy = get_next_policy(policy);

    }

	// then report the policies of the radios of this device
	
	radio_metrics_arr_obj = cJSON_CreateArray();
	cJSON_AddItemToObject(parent_obj, "Radio Specific Metrics Policy", radio_metrics_arr_obj);
	radio_steer_arr_obj = cJSON_CreateArray();
	cJSON_AddItemToObject(parent_obj, "Radio Steering Parameters", radio_steer_arr_obj);

    policy = static_cast<dm_policy_t *>(get_first_policy());
    while (policy != NULL) {
		if (memcmp(policy->m_policy.id.dev_mac, dev_mac, sizeof(mac_address_t)) != 0) {
	    	policy = get_next_policy(policy);
	    	continue;
		}

		if (memcmp(policy->m_policy.id.radio_mac, null_mac, sizeof(mac_address_t)) == 0) {
	    	policy = get_next_policy(policy);
	    	continue;
		}

		dm_easy_mesh_t::macbytes_to_string(policy->m_policy.id.radio_mac, radio_mac_str);
		obj = cJSON_CreateObject(); 
		cJSON_AddStringToObject(obj, "ID", radio_mac_str);	

		if (policy->m_policy.id.type == em_policy_id_type_steering_param) {
			policy->encode(obj, em_policy_id_type_steering_param);
			cJSON_AddItemToArray(radio_steer_arr_obj, obj);
		} else if (policy->m_policy.id.type == em_policy_id_type_radio_metrics_rep) {
			policy->encode(obj, em_policy_id_type_radio_metrics_rep);
			cJSON_AddItemToArray(radio_metrics_arr_obj, obj);
		}

		policy = get_next_policy(policy);

    }

    return 0;
}

int dm_policy_list_t::set_config(db_client_t& db_client, const cJSON *obj_arr, void *parent_id)
{
    cJSON *obj;
    dm_policy_t policy;
    dm_orch_type_t op;
	int i, size;

    size = cJSON_GetArraySize(obj_arr);

    for (i = 0; i < size; i++) {
        obj = cJSON_GetArrayItem(obj_arr, i);
        policy.decode(obj, parent_id);
        update_db(db_client, (op = get_dm_orch_type(db_client, policy)), policy.get_policy());
        update_list(policy, op);
    }

    return 0;
}

int dm_policy_list_t::set_config(db_client_t& db_client, dm_policy_t& policy, void *parent_id)
{
    dm_orch_type_t op;

    update_db(db_client, (op = get_dm_orch_type(db_client, policy)), policy.get_policy());
    update_list(policy, op);

    return 0;
}

dm_orch_type_t dm_policy_list_t::get_dm_orch_type(db_client_t& db_client, const dm_policy_t& policy)
{
    dm_policy_t *ppolicy;
    mac_addr_str_t	dev_mac_str, radio_mac_str;
	em_2xlong_string_t key;

    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *>(policy.m_policy.id.dev_mac), dev_mac_str);
    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *>(policy.m_policy.id.radio_mac), radio_mac_str);
    snprintf(key, sizeof(key), "%s@%s@%s@%d", policy.m_policy.id.net_id, dev_mac_str, radio_mac_str, policy.m_policy.id.type);

    ppolicy = get_policy(key);
    if (ppolicy != NULL) {

        if (entry_exists_in_table(db_client, key) == false) {
            return dm_orch_type_db_insert;
        }

        if (*ppolicy == policy) {
            return dm_orch_type_db_update;
        }

        return dm_orch_type_db_update;
    }  

    return dm_orch_type_db_insert;
}

void dm_policy_list_t::update_list(const dm_policy_t& policy, dm_orch_type_t op)
{
    dm_policy_t *ppolicy;
    mac_addr_str_t	dev_mac_str, radio_mac_str;
	em_2xlong_string_t key;

    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *>(policy.m_policy.id.dev_mac), dev_mac_str);
    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *>(policy.m_policy.id.radio_mac), radio_mac_str);
    snprintf(key, sizeof(key), "%s@%s@%s@%d", policy.m_policy.id.net_id, dev_mac_str, radio_mac_str, policy.m_policy.id.type);

	//printf("%s:%d: Operation: %d for key: %s\n", __func__, __LINE__, op, key);

    switch (op) {
        case dm_orch_type_db_insert:
            put_policy(key, &policy);
            break;

        case dm_orch_type_db_update:
            ppolicy = get_policy(key);
            memcpy(&ppolicy->m_policy, &policy.m_policy, sizeof(em_policy_t));
            break;

        case dm_orch_type_db_delete:
            remove_policy(key);
            break;

        default:
            break;
    }
}

void dm_policy_list_t::delete_list()
{   
    dm_policy_t *policy, *tmp;
	mac_addr_str_t dev_mac_str, radio_mac_str;
    em_2xlong_string_t key;
  
    policy = get_first_policy();
    while (policy != NULL) {
        tmp = policy;
        policy = get_next_policy(policy);

		dm_easy_mesh_t::macbytes_to_string(tmp->m_policy.id.dev_mac, dev_mac_str);
    	dm_easy_mesh_t::macbytes_to_string(tmp->m_policy.id.radio_mac, radio_mac_str);

        snprintf(key, sizeof(key), "%s@%s@%s@%d", tmp->m_policy.id.net_id, dev_mac_str, radio_mac_str, tmp->m_policy.id.type);
  
        remove_policy(key);
    }
}

bool dm_policy_list_t::operator == (const db_easy_mesh_t& obj)
{
    return true;
}

int dm_policy_list_t::update_db(db_client_t& db_client, dm_orch_type_t op, void *data)
{
    mac_addr_str_t dev_mac_str, radio_mac_str;
	em_2xlong_string_t key;
    em_policy_t *policy = static_cast<em_policy_t *>(data);
    int ret = 0;
    unsigned int i = 0;
	mac_addr_str_t	sta_mac_str;
	char sta_mac_list_str[1024];

    dm_easy_mesh_t::macbytes_to_string(policy->id.dev_mac, dev_mac_str);
    dm_easy_mesh_t::macbytes_to_string(policy->id.radio_mac, radio_mac_str);

	snprintf(key, sizeof(key), "%s@%s@%s@%d", policy->id.net_id, dev_mac_str, radio_mac_str, policy->id.type);

	memset(sta_mac_list_str, 0, sizeof(sta_mac_list_str));
    for (i = 0; i < policy->num_sta; i++) {
		dm_easy_mesh_t::macbytes_to_string(policy->sta_mac[i], sta_mac_str);
        strncat(sta_mac_list_str, sta_mac_str, strlen(sta_mac_str));
        strncat(sta_mac_list_str, ",", strlen(",")+1);
    }

	if (strlen(sta_mac_list_str) > 0)
	{
		sta_mac_list_str[strlen(sta_mac_list_str) - 1] = 0;
	}

    switch (op) {
        case dm_orch_type_db_insert:
            ret = insert_row(db_client, key, sta_mac_list_str, policy->policy, policy->interval, policy->rcpi_threshold, 
											policy->rcpi_hysteresis, policy->util_threshold, policy->sta_traffic_stats, 
											policy->sta_link_metric, policy->sta_status, policy->managed_sta_marker,
											policy->independent_scan_report, policy->profile_1_sta_disallowed, policy->profile_2_sta_disallowed);
            break;

	    case dm_orch_type_db_update:
            ret = update_row(db_client, sta_mac_list_str, policy->policy, policy->interval, policy->rcpi_threshold, 
                                            policy->rcpi_hysteresis, policy->util_threshold, policy->sta_traffic_stats, 
                                            policy->sta_link_metric, policy->sta_status, policy->managed_sta_marker,
                                            policy->independent_scan_report, policy->profile_1_sta_disallowed, 
											policy->profile_2_sta_disallowed, key);
            break;

	    case dm_orch_type_db_delete:
	        ret = delete_row(db_client, key);
            break;

	    default:
	        break;
	}

    return ret;
}

bool dm_policy_list_t::search_db(db_client_t& db_client, void *ctx, void *key)
{
    em_long_string_t  str;

    while (db_client.next_result(ctx)) {
        db_client.get_string(ctx, str, 1);
		//printf("%s:%d: Comparing source: %s target: %s\n", __func__, __LINE__, str, (char *)key);

        if (strncmp(str, static_cast<char *>(key), strlen(static_cast<char *>(key))) == 0) {
            return true;
        }
    }
    return false;
}

int dm_policy_list_t::sync_db(db_client_t& db_client, void *ctx)
{
    em_policy_t policy;
	em_policy_id_t	id;
    em_long_string_t   str;
	char sta_mac_list_str[1024] = {0};
	char   *token_parts[EM_MAX_STA_PER_STEER_POLICY];
	em_short_string_t	sta_mac_str[EM_MAX_STA_PER_STEER_POLICY];	
	unsigned int i;
    int rc = 0;

    while (db_client.next_result(ctx)) {
        memset(&policy, 0, sizeof(em_policy_t));

        db_client.get_string(ctx, str, 1);
		dm_policy_t::parse_dev_radio_mac_from_key(str, &id);
		memcpy(policy.id.dev_mac, id.dev_mac, sizeof(mac_address_t));
		memcpy(policy.id.radio_mac, id.radio_mac, sizeof(mac_address_t));
		policy.id.type = id.type;

		db_client.get_string(ctx, sta_mac_list_str, 2);
		for (i = 0; i < EM_MAX_STA_PER_STEER_POLICY; i++) {
            token_parts[i] = sta_mac_str[i];
        }

        policy.num_sta = static_cast<unsigned int>(get_strings_by_token(sta_mac_list_str, ',', EM_MAX_STA_PER_STEER_POLICY, token_parts));
		for (i = 0; i < policy.num_sta; i++) {
			dm_easy_mesh_t::string_to_macbytes(sta_mac_str[i], policy.sta_mac[i]);
		}		

		policy.policy = static_cast<em_steering_policy_type_t>(db_client.get_number(ctx, 3));
		policy.interval = static_cast<short unsigned int>(db_client.get_number(ctx, 4));
		policy.rcpi_threshold = static_cast<short unsigned int>(db_client.get_number(ctx, 5));
		policy.rcpi_hysteresis = static_cast<short unsigned int>(db_client.get_number(ctx, 6));
		policy.util_threshold = static_cast<short unsigned int>(db_client.get_number(ctx, 7));
		policy.sta_traffic_stats = db_client.get_number(ctx, 8);
		policy.sta_link_metric = db_client.get_number(ctx, 9);
		policy.sta_status = db_client.get_number(ctx, 10);
		db_client.get_string(ctx, policy.managed_sta_marker, 11);
		policy.independent_scan_report = db_client.get_number(ctx, 12);
		policy.profile_1_sta_disallowed = db_client.get_number(ctx, 13);
		policy.profile_2_sta_disallowed = db_client.get_number(ctx, 14);
        
		update_list(dm_policy_t(&policy), dm_orch_type_db_insert);
    }

    return rc;
}

void dm_policy_list_t::init_table()
{
    snprintf(m_table_name, sizeof(m_table_name), "%s", "PolicyList");
}

void dm_policy_list_t::init_columns()
{
    m_num_cols = 0;

    m_columns[m_num_cols++] = db_column_t("ID", db_data_type_char, 64);
    m_columns[m_num_cols++] = db_column_t("STAList", db_data_type_text, 512);
    m_columns[m_num_cols++] = db_column_t("SteeringPolicyType", db_data_type_smallint, 0);
    m_columns[m_num_cols++] = db_column_t("RepInterval", db_data_type_smallint, 0);
    m_columns[m_num_cols++] = db_column_t("STARCPIThresold", db_data_type_smallint, 0);
    m_columns[m_num_cols++] = db_column_t("STARCPIHysteresis", db_data_type_smallint, 0);
    m_columns[m_num_cols++] = db_column_t("APUtilThreshold", db_data_type_smallint, 0);
    m_columns[m_num_cols++] = db_column_t("STATrafficStats", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("STALinkMetrics", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("STAStats", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("ManagedClientMarker", db_data_type_char, 64);
    m_columns[m_num_cols++] = db_column_t("IndependentScanRep", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("Profile_1_Disallowed", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("Profile_2_Disallowed", db_data_type_tinyint, 0);
}

int dm_policy_list_t::init()
{
    init_table();
    init_columns();
    return 0;
}
