
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
#include <cjson/cJSON.h>
#include "em.h"
#include "em_msg.h"
#include "em_ctrl.h"
#include "em_cmd_ctrl.h"
#include "util.h"

void em_dev_test_t::encode(em_subdoc_info_t *subdoc, hash_map_t *m_em_map, bool update, bool testinprogress)
{
	cJSON *parent, *em_jlist, *em_j, *em_j_info, *em_state, *em_data, *dev_test, *dev_test_param;
	char *tmp;
	em_t *em = NULL;
	int i = 0;
	mac_addr_str_t mac_str;
	em_small_string_t enable;
	em_short_string_t haul_type_str;

	parent = cJSON_CreateObject();
	if (!update){

		em_jlist = cJSON_AddObjectToObject(parent, "em_list");
		em = static_cast<em_t *> (hash_map_get_first(m_em_map));
		while(em != NULL) {
			mac_addr_str_t mac_str;
			if (em->is_al_interface_em() == false) {
				em_data = cJSON_AddArrayToObject(em_jlist, "em");
				dm_easy_mesh_t::macbytes_to_string(em->get_radio_interface_mac(), mac_str);
				cJSON_AddStringToObject(em_data, "mac_str", mac_str);
				cJSON_AddStringToObject(em_data, "state", em_t::state_2_str(em->get_state()));
				snprintf(enable, sizeof(enable),"%s:%d","Test_Enabled", em->get_devteststatus());
				cJSON_AddStringToObject(em_data, "Debug/Test_Enabled", enable);
			
				if ((em->get_state() == em_state_ctrl_misconfigured) && (em->get_devteststatus() == false)) {
					cJSON_AddStringToObject(em_data, "Debug/Test_Enabled", "Down");
				} else if ((em->get_state() >= em_state_ctrl_configured) && (em->get_state() != em_state_ctrl_misconfigured) && (testinprogress == false)) {
					cJSON_AddStringToObject(em_data, "Debug/Test_Enabled", "Online");
				} else if ((em->get_state() == em_state_ctrl_misconfigured) && (em->get_devteststatus() == true) && (testinprogress == false)
						  && (em->get_renew_tx_count() == 0)) {
					cJSON_AddStringToObject(em_data, "Debug/Test_Enabled", "Config-failed");
				} else {
					cJSON_AddStringToObject(em_data, "Debug/Test_Enabled", "Offline");
				}

			}
			em = static_cast<em_t *> (hash_map_get_next(m_em_map, em));
		}
	}

	dev_test = cJSON_AddArrayToObject(parent, "dev_test");
	for (i = 0; i < em_dev_test_type_max; i++) {
		dev_test_param = cJSON_CreateObject();
		cJSON_AddItemToArray(dev_test, dev_test_param);
		if (dev_test_info.test_type[i] == em_dev_test_type_ssid) {
			cJSON_AddStringToObject(dev_test_param, "Test_type", "ssid_change");
			if(!update) {

				switch (dev_test_info.haul_type) {
					case em_haul_type_fronthaul:
						strncpy(haul_type_str, "[Fronthaul]", strlen("[Fronthaul]") + 1);
						break;
					case em_haul_type_backhaul:
						strncpy(haul_type_str, "[Backhaul]", strlen("[Backhaul]") + 1);
						break;
					case em_haul_type_iot:
						strncpy(haul_type_str, "[IoT]", strlen("[IoT]") + 1);
						break;
					case em_haul_type_configurator:
						strncpy(haul_type_str, "[Configurator]", strlen("[Configurator]") + 1);
						break;
					case em_haul_type_hotspot:
						strncpy(haul_type_str, "[Hotspot]", strlen("[Hotspot]") + 1);
						break;
					default:
					   break;
				}
				cJSON_AddStringToObject(dev_test_param, "HaulType", haul_type_str);

			} else {
				cJSON_AddNumberToObject(dev_test_param, "Haul_type:[Fronthault:0,Backhaul:1,IOT:2,Configurator:3,Hotspot:4]", dev_test_info.haul_type);
			}
		} else if(dev_test_info.test_type[i] == em_dev_test_type_channel) {
			cJSON_AddStringToObject(dev_test_param, "Test_type", "channel_change");

			if (dev_test_info.freq_band == em_freq_band_24) {
				cJSON_AddStringToObject(dev_test_param, "Freq_band", "2.4");
			} else {
				cJSON_AddStringToObject(dev_test_param, "Freq_band", "5");
			}

		}
		cJSON_AddNumberToObject(dev_test_param, "No_of_iteration", dev_test_info.num_iteration[i]);
		cJSON_AddNumberToObject(dev_test_param, "Test_enabled", dev_test_info.enabled[i]);

		if(!update) {
			cJSON_AddNumberToObject(dev_test_param, "Num_of_iteration_completed", dev_test_info.num_of_iteration_completed[i]);
			cJSON_AddNumberToObject(dev_test_param, "Current_iteration_inprogress", dev_test_info.test_inprogress[i]);
			if (dev_test_info.test_status[i] == em_dev_test_status_inprogess) {
				cJSON_AddStringToObject(dev_test_param, "Test_status", "In-Progress");
			} else if (dev_test_info.test_status[i] == em_dev_test_status_complete){
				cJSON_AddStringToObject(dev_test_param, "Test_status", "Complete");
			} else if (dev_test_info.test_status[i] == em_dev_test_status_failed){
				cJSON_AddStringToObject(dev_test_param, "Test_status", "Failed");
			} else	{
				cJSON_AddStringToObject(dev_test_param, "Test_status", "Idle");
			}
		}
		cJSON_AddNumberToObject(dev_test_param, "Configure_active_em", 0);
	}

	tmp = cJSON_Print(parent);
	//printf("%s:%d: Subdoc: %s\n", __func__, __LINE__, tmp);
	strncpy(subdoc->buff, tmp, strlen(tmp) + 1);
	cJSON_free(parent);
}

void em_dev_test_t:: decode(em_subdoc_info_t *subdoc, hash_map_t *m_em_map, const char *str)
{
   cJSON *parent_obj, *dev_test_obj, *obj, *tmp, *test;
   int index = 0, arr_size = 0, i = 0;
   char str_type[32];
   em_t *em = NULL;

	parent_obj = cJSON_Parse(subdoc->buff);
	if (parent_obj == NULL) {
		printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
		return;
	}
	if ((test = cJSON_GetObjectItem(parent_obj, "wfa-dataelements:SetDevTest")) == NULL) {
	printf("%s:%d: wfa-dataelements:SetDevTest not present\n", __func__, __LINE__);
	cJSON_Delete(parent_obj);
		return;
	}
	if (test == NULL) {
		printf("%s:%d:	test info not present\n", __func__, __LINE__);
		cJSON_Delete(parent_obj);
		return;
	}

	if ((dev_test_obj = cJSON_GetObjectItem(test, "dev_test")) == NULL) {
	printf("%s:%d: wfa-dataelements:SetDevTest not present\n", __func__, __LINE__);
	cJSON_Delete(parent_obj);
		return;
	}
	if (dev_test_obj == NULL) {
		printf("%s:%d: dev test info not present\n", __func__, __LINE__);
		cJSON_Delete(parent_obj);
		return;
	}

	arr_size = static_cast<unsigned int> (cJSON_GetArraySize(dev_test_obj));
	if (arr_size != em_dev_test_type_max) {
		printf("%s:%d: Invalid configuration:\n", __func__, __LINE__);
		cJSON_Delete(parent_obj);
		return;
	}
	for (i = 0; i < arr_size; i++) {
		if ((obj = cJSON_GetArrayItem(dev_test_obj, i)) == NULL) {
		   printf("%s:%d: Type: Dev Test has no memebers\n", __func__, __LINE__);
		   return;
		}
		if ((tmp = cJSON_GetObjectItem(obj, "Test_type")) != NULL) {
		   snprintf(str_type, sizeof(str_type), "%s", cJSON_GetStringValue(tmp));
		}
		if (strncmp(str_type, "ssid_change", sizeof(str_type)) == 0) {
		   index = (int) em_dev_test_type_ssid;
		} else {
		   index = (int) em_dev_test_type_channel;
		}
		if ((tmp = cJSON_GetObjectItem(obj, "No_of_iteration")) != NULL) {
			dev_test_info.num_iteration[index] = static_cast<unsigned int> (tmp->valuedouble);
		}

		if ((tmp = cJSON_GetObjectItem(obj, "Current_iteration_inprogress")) != NULL) {
			dev_test_info.test_inprogress[index] = static_cast<unsigned int> (tmp->valuedouble);
		}
		if ((tmp = cJSON_GetObjectItem(obj, "Num_of_iteration_completed")) != NULL) {
			dev_test_info.num_of_iteration_completed[index] = static_cast<unsigned int> (tmp->valuedouble);
		}
		if ((tmp = cJSON_GetObjectItem(obj, "Haul_type:[Fronthault:0,Backhaul:1,IOT:2,Configurator:3,Hotspot:4]")) != NULL) {
			dev_test_info.haul_type = static_cast<em_haul_type_t> (tmp->valuedouble);
		}
		if ((tmp = cJSON_GetObjectItem(obj, "Test_enabled")) != NULL) {
			dev_test_info.enabled[index] = static_cast<unsigned int> (tmp->valuedouble);
			if (dev_test_info.enabled[index] == 0) {
				dev_test_info.test_status[index] = em_dev_test_status_idle;
				dev_test_info.test_inprogress[index] = 0;
			}

		}

		if ((tmp = cJSON_GetObjectItem(obj, "Test_status")) != NULL) {
			if(strncmp(tmp->valuestring, "Inprogress", sizeof("Inprogress")) == 0) {
				dev_test_info.test_status[index] = em_dev_test_status_inprogess;
			} else if(strncmp(tmp->valuestring, "Complete", sizeof("Complete")) == 0) {
				dev_test_info.test_status[index] = em_dev_test_status_complete;
			} else if(strncmp(tmp->valuestring, "Failed", sizeof("Failed")) == 0) {
				dev_test_info.test_status[index] = em_dev_test_status_failed;
			}
		}

		if ((tmp = cJSON_GetObjectItem(obj, "Configure_active_em")) != NULL) {
			if (tmp->valuedouble == 1) {
				em = static_cast<em_t *> (hash_map_get_first(m_em_map));
				while(em != NULL) {
					if ((em->get_state() >= em_state_ctrl_configured) && (em->get_state() != em_state_ctrl_misconfigured)) {
							em->set_devteststatus(true);
					} else {
							em->set_devteststatus(false);
					}
					em = static_cast<em_t *> (hash_map_get_next(m_em_map, em));
				}
				dev_test_info.test_status[index] = em_dev_test_status_inprogess;
				dev_test_info.num_of_iteration_completed[index] = 0;
			}
		}

/* Need to be implemented TBD
		if ((tmp = cJSON_GetObjectItem(obj, "Freq_band")) != NULL) {
				dev_test_info.freq_band =  (em_freq_band_t) (tmp->valuedouble);
		}
*/
	}
}

void em_dev_test_t:: analyze_set_dev_test(em_bus_event_t *evt, hash_map_t *m_em_map)
{
	em_subdoc_info_t *subdoc;
	subdoc = &evt->u.subdoc;
	decode(subdoc, m_em_map, "SetDevTest");
}

em_dev_test_t::em_dev_test_t()
{

}
em_dev_test_t::~em_dev_test_t()
{

}
