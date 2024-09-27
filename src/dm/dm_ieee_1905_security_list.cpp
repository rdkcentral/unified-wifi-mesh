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
#include "dm_ieee_1905_security_list.h"
#include "dm_easy_mesh.h"

int dm_ieee_1905_security_list_t::get_config(cJSON *obj, void *parent_id)
{
	dm_ieee_1905_security_t *pieee_1905_security;
	mac_address_t *mac = (mac_address_t *)parent_id;
	bool found = false;

	pieee_1905_security = (dm_ieee_1905_security_t *)hash_map_get_first(m_list);
	while (pieee_1905_security != NULL) {
		if (memcmp(mac, &pieee_1905_security->m_ieee_1905_security_info.id, sizeof(mac_address_t)) == 0) {
			found = true;
			break;
		}	
		pieee_1905_security = (dm_ieee_1905_security_t *)hash_map_get_next(m_list, pieee_1905_security);
	}

	if (found == false) {
		return -1;
	}

	cJSON_AddNumberToObject(obj, "OnboardingProtocol", 	pieee_1905_security->m_ieee_1905_security_info.sec_cap.onboarding_proto);
	cJSON_AddNumberToObject(obj, "IntegrityAlgorithm", 	pieee_1905_security->m_ieee_1905_security_info.sec_cap.integrity_algo);
	cJSON_AddNumberToObject(obj, "EncryptionAlgorithm", 	pieee_1905_security->m_ieee_1905_security_info.sec_cap.encryption_algo);
	
	return 0;
}

int dm_ieee_1905_security_list_t::set_config(db_client_t& db_client, const cJSON *obj_arr, void *parent_id)
{
	cJSON *tmp, *obj;
	mac_address_t dev_mac;
	mac_addr_str_t  mac_str;
    unsigned int i, size;
    dm_ieee_1905_security_t ieee_1905_security;
	dm_orch_type_t op;

    size = cJSON_GetArraySize(obj_arr);

    for (i = 0; i < size; i++) {

        obj = cJSON_GetArrayItem(obj_arr, i);
		if ((tmp = cJSON_GetObjectItem(obj, "ID")) != NULL) {
			snprintf(mac_str, sizeof(mac_str), "%s", cJSON_GetStringValue(tmp));
            dm_easy_mesh_t::string_to_macbytes(mac_str, dev_mac);
        }

		if ((obj = cJSON_GetObjectItem(obj, "IEEE1905Security")) == NULL) {
			assert(1);
		}

		ieee_1905_security.decode(obj);		

		update_db(db_client, (op = get_dm_orch_type(ieee_1905_security)), ieee_1905_security.get_ieee_1905_security_info());
		update_list(ieee_1905_security, op);
	}


    return 0;
}


dm_orch_type_t dm_ieee_1905_security_list_t::get_dm_orch_type(const dm_ieee_1905_security_t& ieee_1905_security)
{
    dm_ieee_1905_security_t *pieee_1905_security;
    mac_addr_str_t  mac_str;

	dm_easy_mesh_t::macbytes_to_string((unsigned char *)ieee_1905_security.m_ieee_1905_security_info.id, mac_str);

    pieee_1905_security = (dm_ieee_1905_security_t *)hash_map_get(m_list, mac_str);
    if (pieee_1905_security != NULL) {
        if (*pieee_1905_security == ieee_1905_security) {
            printf("%s:%d: Network SSID: %s already in list\n", __func__, __LINE__, pieee_1905_security->m_ieee_1905_security_info.id);
            return dm_orch_type_none;
        }
   
 
        printf("%s:%d: Network SSID: %s in list but needs update\n", __func__, __LINE__, pieee_1905_security->m_ieee_1905_security_info.id);
        return dm_orch_type_sec_update;
    }  

    return dm_orch_type_sec_insert;

}

void dm_ieee_1905_security_list_t::update_list(const dm_ieee_1905_security_t& ieee_1905_security, dm_orch_type_t op)
{
	dm_ieee_1905_security_t *pieee_1905_security;
    mac_addr_str_t  mac_str;
    
    dm_easy_mesh_t::macbytes_to_string((unsigned char *)ieee_1905_security.m_ieee_1905_security_info.id, mac_str);

    switch (op) {
        case dm_orch_type_sec_insert:
			hash_map_put(m_list, strdup(mac_str), new dm_ieee_1905_security_t(ieee_1905_security));	
            break;

        case dm_orch_type_sec_update:
    		pieee_1905_security = (dm_ieee_1905_security_t *)hash_map_get(m_list, mac_str);
            memcpy(&pieee_1905_security->m_ieee_1905_security_info, &ieee_1905_security.m_ieee_1905_security_info, sizeof(em_ieee_1905_security_info_t));
            break;
    
        case dm_orch_type_sec_delete:
    		pieee_1905_security = (dm_ieee_1905_security_t *)hash_map_remove(m_list, mac_str);
            delete(pieee_1905_security);
            break;
    }   


}

void dm_ieee_1905_security_list_t::delete_list()
{       
    dm_ieee_1905_security_t *pieee_1905_security, *tmp;
    mac_addr_str_t  mac_str;
    
    pieee_1905_security = (dm_ieee_1905_security_t *)hash_map_get_first(m_list);
    while (pieee_1905_security != NULL) {
        tmp = pieee_1905_security;
        pieee_1905_security = (dm_ieee_1905_security_t *)hash_map_get_next(m_list, pieee_1905_security);       
    	dm_easy_mesh_t::macbytes_to_string((unsigned char *)tmp->m_ieee_1905_security_info.id, mac_str);
        hash_map_remove(m_list, mac_str);
        delete(tmp);
    }
}   


bool dm_ieee_1905_security_list_t::operator == (const db_easy_mesh_t& obj)
{

	return true;
}

int dm_ieee_1905_security_list_t::update_db(db_client_t& db_client, dm_orch_type_t op, void *data)
{
    mac_addr_str_t mac_str;
    em_ieee_1905_security_info_t *info = (em_ieee_1905_security_info_t *)data;
	int ret = 0;

	//printf("%s:%d: Opeartion:%d\n", __func__, __LINE__, op);
	
	switch (op) {
		case dm_orch_type_sec_insert:
			ret = insert_row(db_client, dm_easy_mesh_t::macbytes_to_string(info->id, mac_str), 
						info->sec_cap.onboarding_proto, info->sec_cap.integrity_algo, info->sec_cap.encryption_algo);
			break;

		case dm_orch_type_sec_update:
			ret = update_row(db_client, info->sec_cap.onboarding_proto, info->sec_cap.integrity_algo, info->sec_cap.encryption_algo,
						dm_easy_mesh_t::macbytes_to_string(info->id, mac_str));
			break;

		case dm_orch_type_sec_delete:
			ret = delete_row(db_client, dm_easy_mesh_t::macbytes_to_string(info->id, mac_str));
			break;

		default:
			break;
	}

    return ret;
}

void dm_ieee_1905_security_list_t::sync_db(db_client_t& db_client, void *ctx)
{
	em_ieee_1905_security_info_t info;
	mac_addr_str_t	mac;
    em_long_string_t   str;
	char *tmp;
	unsigned int i;

    while (db_client.next_result(ctx)) {
		memset(&info, 0, sizeof(em_ieee_1905_security_info_t));

		db_client.get_string(ctx, mac, 1);
        dm_easy_mesh_t::string_to_macbytes(mac, info.id);

        info.sec_cap.onboarding_proto = db_client.get_number(ctx, 2);
        info.sec_cap.integrity_algo = db_client.get_number(ctx, 3);
        info.sec_cap.encryption_algo = db_client.get_number(ctx, 4);
        
		update_list(dm_ieee_1905_security_t(&info), dm_orch_type_sec_insert);
    }
}

void dm_ieee_1905_security_list_t::init_table()
{
    snprintf(m_table_name, sizeof(m_table_name), "%s", "IEEE1905Security");
}

void dm_ieee_1905_security_list_t::init_columns()
{
    m_num_cols = 0;

    m_columns[m_num_cols++] = db_column_t("ID", db_data_type_char, 17);
    m_columns[m_num_cols++] = db_column_t("OnboardingProtocol", db_data_type_mediumint, 0);
    m_columns[m_num_cols++] = db_column_t("IntegrityAlgorithm", db_data_type_mediumint, 0);
    m_columns[m_num_cols++] = db_column_t("EncryptionAlgorithm", db_data_type_mediumint, 0);
}

int dm_ieee_1905_security_list_t::init()
{
	m_list = hash_map_create();
    init_table();
    init_columns();
    return 0;
}
