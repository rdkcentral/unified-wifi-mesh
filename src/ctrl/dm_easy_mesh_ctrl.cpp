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
#include <math.h>
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
#include "em_cmd_exec.h"
#include "em_cmd_reset.h"
#include "em_cmd_dev_test.h"
#include "em_cmd_remove_device.h"
#include "em_cmd_set_ssid.h"
#include "em_cmd_set_channel.h"
#include "em_cmd_scan_channel.h"
#include "em_cmd_set_radio.h"
#include "em_cmd_set_policy.h"
#include "em_cmd_topo_sync.h"
#include "em_cmd_em_config.h"
#include "em_cmd_cfg_renew.h"
#include "em_cmd_sta_assoc.h"
#include "em_cmd_sta_link_metrics.h"
#include "em_cmd_sta_steer.h"
#include "em_cmd_sta_disassoc.h"
#include "em_cmd_get_mld_config.h"
#include "em_cmd_mld_reconfig.h"

extern char *global_netid;

int dm_easy_mesh_ctrl_t::analyze_sta_link_metrics(em_cmd_t *pcmd[])
{
    int num = 0;
    em_cmd_t *tmp;

    dm_easy_mesh_t dm = *this;

    pcmd[num] = new em_cmd_sta_link_metrics_t(dm);
    tmp = pcmd[num];
    num++;

    while ((pcmd[num] = tmp->clone_for_next()) != NULL) {
        tmp = pcmd[num];
        num++;
    }

    return num;
}


int dm_easy_mesh_ctrl_t::analyze_config_renew(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    mac_addr_str_t  radio_str;
    em_bus_event_type_cfg_renew_params_t *params;
    int num = 0;
    dm_easy_mesh_t  dm;
    em_cmd_t *tmp;

    if (evt == NULL) {
        printf("%s:%d: NULL event\n", __func__, __LINE__);
        return -1;
    }

    params = reinterpret_cast<em_bus_event_type_cfg_renew_params_t *> (evt->u.raw_buff);
    dm_easy_mesh_t::macbytes_to_string(params->radio, radio_str);
    printf("%s:%d: Radio: %s\n", __func__, __LINE__, radio_str);

    evt->params.u.args.num_args = 1;
    strncpy(evt->params.u.args.args[0], radio_str, sizeof(em_long_string_t));
    pcmd[num] = new em_cmd_cfg_renew_t(em_service_type_ctrl, evt->params, dm);

    tmp = pcmd[num];
    num++;

    while ((pcmd[num] = tmp->clone_for_next()) != NULL) {
        tmp = pcmd[num];
        num++;
    }

    return num;
}

int dm_easy_mesh_ctrl_t::analyze_sta_assoc_event(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    mac_addr_str_t  dev_mac_str, sta_mac_str, bss_mac_str, radio_mac_str, ruid_str;
    em_bus_event_type_client_assoc_params_t *params;
    int num = 0;
    size_t len;
    unsigned int i;
    dm_easy_mesh_t  dm, *pdm;
    em_cmd_t *tmp;
    dm_bss_t *pbss;
    bool radio_matched = false, found;
    em_sta_info_t sta_info;
    em_orch_desc_t desc;
    em_2xlong_string_t	key;

    if (evt == NULL) {
        printf("%s:%d: NULL event\n", __func__, __LINE__);
        return -1;
    }

    params = reinterpret_cast<em_bus_event_type_client_assoc_params_t *> (evt->u.raw_buff);
    dm_easy_mesh_t::macbytes_to_string(params->dev, dev_mac_str);
    dm_easy_mesh_t::macbytes_to_string(params->assoc.cli_mac_address, sta_mac_str);
    dm_easy_mesh_t::macbytes_to_string(params->assoc.bssid, bss_mac_str);
    
    //printf("%s:%d: Client:%s %s BSS: %s of Device: %s\n", __func__, __LINE__,
        //sta_mac_str, (params->assoc.assoc_event == 1)?"associated with":"disassociated from", bss_mac_str, dev_mac_str);

    evt->params.u.args.num_args = 4;
    strncpy(evt->params.u.args.args[0], dev_mac_str, sizeof(em_long_string_t));
    strncpy(evt->params.u.args.args[1], bss_mac_str, sizeof(em_long_string_t));
    strncpy(evt->params.u.args.args[2], sta_mac_str, sizeof(em_long_string_t));
    len = (params->assoc.assoc_event == 1)?strlen("Assoc") + 1:strlen("Disassoc") + 1;
    strncpy(evt->params.u.args.args[3], (params->assoc.assoc_event == 1)?"Assoc":"Disassoc", len);
    pdm = get_data_model(global_netid, params->dev);
    if (pdm == NULL) {
        printf("%s:%d: Could not find data model for dev: %s\n", __func__, __LINE__, dev_mac_str);
        return -1;
    }

    for (i = 0; i < pdm->get_num_radios(); i++) {
        found = true;
        pbss = pdm->get_bss(pdm->get_radio_info(i)->id.ruid, params->assoc.bssid);
        if (pbss == NULL) {
            found = false;
            continue;
        }
        break;
    }
    if (found == false) {
        printf("%s:%d: Could not find bss: %s\n", __func__, __LINE__, bss_mac_str);
        return -1;
    }

    dm_easy_mesh_t::macbytes_to_string(pbss->m_bss_info.ruid.mac, radio_mac_str);

    // confirm that the radio is on this device
    for (i = 0; i < pdm->m_num_radios; i++) {
        if (memcmp(pbss->m_bss_info.ruid.mac, pdm->m_radio[i].m_radio_info.intf.mac, sizeof(mac_address_t)) == 0) {
            radio_matched = true;
            break;
        }
    }

    if (radio_matched == false) {
        printf("%s:%d: Could not find bss: %s on radio: %s\n", __func__, __LINE__, bss_mac_str, radio_mac_str);
        return -1;
    }

    memcpy(sta_info.id, params->assoc.cli_mac_address, sizeof(mac_address_t));
    memcpy(sta_info.bssid, params->assoc.bssid, sizeof(mac_address_t));
    memcpy(sta_info.radiomac, pbss->m_bss_info.ruid.mac, sizeof(mac_address_t));

    pcmd[num] = new em_cmd_sta_assoc_t(evt->params, dm);
    tmp = pcmd[num];
    num++;

    snprintf(key, sizeof(em_long_string_t), "%s@%s@%s", sta_mac_str, bss_mac_str, radio_mac_str);
    if ((get_sta(key) != NULL) && (params->assoc.assoc_event == false)){
        desc.op = dm_orch_type_sta_update;
        desc.submit = false;
        pcmd[num - 1]->override_op(0, &desc);
    }

    while ((pcmd[num] = tmp->clone_for_next()) != NULL) {
        tmp = pcmd[num];
        num++;
    }

    return num;
}

int dm_easy_mesh_ctrl_t::analyze_m2_tx(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    mac_addr_str_t  radio_str, al_str;
    em_bus_event_type_m2_tx_params_t *params;
    int num = 0;
    dm_easy_mesh_t  dm;
    em_cmd_t *tmp;

    if (evt == NULL) {
        printf("%s:%d: NULL event\n", __func__, __LINE__);
        return -1;
    }

    params = reinterpret_cast<em_bus_event_type_m2_tx_params_t *> (evt->u.raw_buff);
    dm_easy_mesh_t::macbytes_to_string(params->al, al_str);
    dm_easy_mesh_t::macbytes_to_string(params->radio, radio_str);
    printf("%s:%d: Radio: %s AL MAC: %s\n", __func__, __LINE__, radio_str, al_str);

    evt->params.u.args.num_args = 2;
    strncpy(evt->params.u.args.args[0], radio_str, sizeof(em_long_string_t));
    strncpy(evt->params.u.args.args[1], al_str, sizeof(em_long_string_t));
    pcmd[num] = new em_cmd_em_config_t(evt->params, dm);
    tmp = pcmd[num];
    num++;

    while ((pcmd[num] = tmp->clone_for_next()) != NULL) {
        tmp = pcmd[num];
        num++;
    }

    return num;
}

int dm_easy_mesh_ctrl_t::analyze_dev_test(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    int num = 0;
    em_subdoc_info_t *subdoc;
    dm_easy_mesh_t  dm;
    em_cmd_t *tmp;

    subdoc = &evt->u.subdoc;

    dm.decode_config(subdoc, "Test");
    //dm.print_config();

    dm.set_db_cfg_param(db_cfg_type_device_list_update, "");
	dm.set_db_cfg_param(db_cfg_type_radio_list_update, "");
	dm.set_db_cfg_param(db_cfg_type_bss_list_update, "");
	dm.set_db_cfg_param(db_cfg_type_op_class_list_update, "");

    pcmd[num] = new em_cmd_dev_test_t(evt->params, dm);
    tmp = pcmd[num];
    num++;

    while ((pcmd[num] = tmp->clone_for_next()) != NULL) {
		tmp = pcmd[num];
		num++;
    }
    printf("%s:%d: Number of commands:%d\n", __func__, __LINE__, num);

    return num;

}

int dm_easy_mesh_ctrl_t::analyze_reset(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    int num = 0;
    em_subdoc_info_t *subdoc;
    dm_easy_mesh_t  dm;
    em_cmd_t *tmp;

    subdoc = &evt->u.subdoc;

    dm.decode_config(subdoc, "Reset");
    //dm.print_config();

    dm.set_db_cfg_param(db_cfg_type_network_list_update, "");
    dm.set_db_cfg_param(db_cfg_type_network_ssid_list_update, "");

    pcmd[num] = new em_cmd_reset_t(evt->params, dm);
    tmp = pcmd[num];
    num++;

    while ((pcmd[num] = tmp->clone_for_next()) != NULL) {
		tmp = pcmd[num];
		num++;
    }

    return num;

}

int dm_easy_mesh_ctrl_t::analyze_sta_steer(em_cmd_steer_params_t &params, em_cmd_t *pcmd[])
{
    int num = 0;
    em_cmd_t *tmp;

    pcmd[num] = new em_cmd_sta_steer_t(params);
    tmp = pcmd[num];
    num++;

    while ((pcmd[num] = tmp->clone_for_next()) != NULL) {
        tmp = pcmd[num];
        num++;
    }

    return num;
}

int dm_easy_mesh_ctrl_t::analyze_command_steer(em_bus_event_t *evt, em_cmd_t *cmd[])
{
    cJSON *obj, *wfa_obj, *net_obj, *dev_list_obj, *dev_obj;
    cJSON *radio_list_obj, *radio_obj, *bss_list_obj, *bss_obj, *bss_id_obj;
    cJSON *sta_list_obj, *sta_obj, *sta_mac_obj, *assoc_obj, *steer_obj;
    cJSON *target_obj, *request_mode_obj, *imminent_obj, *bridged_obj;
    cJSON *link_obj, *opportunity_obj, *timer_obj, *op_class_obj, *channel_obj;
    int num = 0;
    em_subdoc_info_t *subdoc;
    int i, j, k, l;
    em_long_string_t wfa;
    em_cmd_steer_params_t	steer_param;

    subdoc = &evt->u.subdoc;
    obj = cJSON_Parse(subdoc->buff);
    if (obj == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        return 0;
    }

    snprintf(wfa, sizeof(wfa), "wfa-dataelements:ClientSteer");

    if ((wfa_obj = cJSON_GetObjectItem(obj, wfa)) == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        cJSON_free(obj);
        return 0;
    }

    if ((net_obj = cJSON_GetObjectItem(wfa_obj, "Network")) == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        cJSON_free(obj);
        return 0;
    }

    if ((dev_list_obj = cJSON_GetObjectItem(net_obj, "DeviceList")) == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        cJSON_free(obj);
        return 0;
    }

    for (i = 0; i < cJSON_GetArraySize(dev_list_obj); i++) {
        dev_obj = cJSON_GetArrayItem(dev_list_obj, i);
        if ((radio_list_obj = cJSON_GetObjectItem(dev_obj, "RadioList")) == NULL) {
            continue;
        }

        for (j = 0; j < cJSON_GetArraySize(radio_list_obj); j++) {
            radio_obj = cJSON_GetArrayItem(radio_list_obj, j);

            if ((bss_list_obj = cJSON_GetObjectItem(radio_obj, "BSSList")) == NULL) {
                continue;
            }

            for (k = 0; k < cJSON_GetArraySize(bss_list_obj); k++) {
                bss_obj = cJSON_GetArrayItem(bss_list_obj, k);
                bss_id_obj = cJSON_GetObjectItem(bss_obj, "BSSID");

                if ((sta_list_obj = cJSON_GetObjectItem(bss_obj, "STAList")) == NULL) {
                    continue;
                }

                for (l = 0; l < cJSON_GetArraySize(sta_list_obj); l++) {
                    sta_obj = cJSON_GetArrayItem(sta_list_obj, l);
                    memset(&steer_param, 0, sizeof(em_cmd_steer_params_t));

                    if ((sta_mac_obj = cJSON_GetObjectItem(sta_obj, "MACAddress")) == NULL) {
                        continue;
                    }
                    if ((assoc_obj = cJSON_GetObjectItem(sta_obj, "Associated")) == NULL) {
                        continue;
                    }

                    if ((steer_obj = cJSON_GetObjectItem(sta_obj, "ClientSteer")) == NULL) {
                        continue;
                    }

                    dm_easy_mesh_t::string_to_macbytes(cJSON_GetStringValue(sta_mac_obj), steer_param.sta_mac);
                    dm_easy_mesh_t::string_to_macbytes(cJSON_GetStringValue(bss_id_obj), steer_param.source);
                    target_obj = cJSON_GetObjectItem(steer_obj, "TargetBSSID");
                    dm_easy_mesh_t::string_to_macbytes(cJSON_GetStringValue(target_obj), steer_param.target);
                    request_mode_obj = cJSON_GetObjectItem(steer_obj, "RequestMode");
                    // Check for "Steering_Opportunity"
                    if (cJSON_GetObjectItem(request_mode_obj, "Steering_Opportunity") != NULL) {
                        cJSON *steer_opp = cJSON_GetObjectItem(request_mode_obj, "Steering_Opportunity");
                        steer_param.request_mode = static_cast<unsigned int> (cJSON_GetNumberValue(steer_opp));
                    }
                    // Check for "Steering_Mandate"
                    else if (cJSON_GetObjectItem(request_mode_obj, "Steering_Mandate") != NULL) {
                        cJSON *steer_mandate = cJSON_GetObjectItem(request_mode_obj, "Steering_Mandate");
                        steer_param.request_mode = static_cast<unsigned int> (cJSON_GetNumberValue(steer_mandate));
                    }

                    imminent_obj = cJSON_GetObjectItem(steer_obj, "BTMDisassociationImminent");
                    steer_param.disassoc_imminent = (cJSON_IsTrue(imminent_obj) == true) ? true:false;
                    bridged_obj = cJSON_GetObjectItem(steer_obj, "BTMAbridged");
                    steer_param.btm_abridged = (cJSON_IsTrue(bridged_obj) == true) ? true:false;
                    link_obj = cJSON_GetObjectItem(steer_obj, "LinkRemovalImminent");
                    steer_param.link_removal_imminent = (cJSON_IsTrue(link_obj) == true) ? true:false;
                    opportunity_obj = cJSON_GetObjectItem(steer_obj, "SteeringOpportunityWindow");
                    steer_param.steer_opportunity_win = static_cast<unsigned int> (cJSON_GetNumberValue(opportunity_obj));
                    timer_obj = cJSON_GetObjectItem(steer_obj, "BTMDisassociationTimer");
                    steer_param.btm_disassociation_timer = static_cast<unsigned int> (cJSON_GetNumberValue(timer_obj));
                    op_class_obj = cJSON_GetObjectItem(steer_obj, "TargetBSSOperatingClass");
                    steer_param.target_op_class = static_cast<unsigned int> (cJSON_GetNumberValue(op_class_obj));
                    channel_obj = cJSON_GetObjectItem(steer_obj, "TargetBSSChannel");
                    steer_param.target_channel = static_cast<unsigned int> (cJSON_GetNumberValue(channel_obj));

                    num += analyze_sta_steer(steer_param, cmd);
                }
            }
        }
    }
    cJSON_free(obj);

    return num;
}

int dm_easy_mesh_ctrl_t::analyze_sta_disassoc(em_cmd_disassoc_params_t &params, em_cmd_t *pcmd[])
{
    int num = 0;
    em_cmd_t *tmp;

    pcmd[num] = new em_cmd_sta_disassoc_t(params);
    tmp = pcmd[num];
    num++;

    while ((pcmd[num] = tmp->clone_for_next()) != NULL) {
        tmp = pcmd[num];
        num++;
    }

    return num;
}

int dm_easy_mesh_ctrl_t::analyze_command_disassoc(em_bus_event_t *evt, em_cmd_t *cmd[])
{
    cJSON *obj, *wfa_obj, *net_obj, *dev_list_obj, *dev_obj;
    cJSON *radio_list_obj, *radio_obj, *bss_list_obj, *bss_obj, *bss_id_obj;
    cJSON *sta_list_obj, *sta_obj, *sta_mac_obj, *assoc_obj, *disassoc_obj;
    cJSON *timer_obj, *reason_obj, *silent_obj;
    int num = 0;
    em_subdoc_info_t *subdoc;
    int i, j, k, l;
    em_long_string_t wfa;
    em_cmd_disassoc_params_t	disassoc_param;

    memset(&disassoc_param, 0, sizeof(em_cmd_disassoc_params_t));

    subdoc = &evt->u.subdoc;
    obj = cJSON_Parse(subdoc->buff);
    if (obj == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        return 0;
    }

    snprintf(wfa, sizeof(wfa), "wfa-dataelements:Disassociate");

    if ((wfa_obj = cJSON_GetObjectItem(obj, wfa)) == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        cJSON_free(obj);
        return 0;
    }

    if ((net_obj = cJSON_GetObjectItem(wfa_obj, "Network")) == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        cJSON_free(obj);
        return 0;
    }

    if ((dev_list_obj = cJSON_GetObjectItem(net_obj, "DeviceList")) == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        cJSON_free(obj);
        return 0;
    }

    for (i = 0; i < cJSON_GetArraySize(dev_list_obj); i++) {
        dev_obj = cJSON_GetArrayItem(dev_list_obj, i);
        if ((radio_list_obj = cJSON_GetObjectItem(dev_obj, "RadioList")) == NULL) {
            continue;
        }

        for (j = 0; j < cJSON_GetArraySize(radio_list_obj); j++) {
            radio_obj = cJSON_GetArrayItem(radio_list_obj, j);

            if ((bss_list_obj = cJSON_GetObjectItem(radio_obj, "BSSList")) == NULL) {
                continue;
            }

            for (k = 0; k < cJSON_GetArraySize(bss_list_obj); k++) {
                bss_obj = cJSON_GetArrayItem(bss_list_obj, k);
                bss_id_obj = cJSON_GetObjectItem(bss_obj, "BSSID");

                if ((sta_list_obj = cJSON_GetObjectItem(bss_obj, "STAList")) == NULL) {
                    continue;
                }

                for (l = 0; l < cJSON_GetArraySize(sta_list_obj); l++) {
                    sta_obj = cJSON_GetArrayItem(sta_list_obj, l);

                    if ((sta_mac_obj = cJSON_GetObjectItem(sta_obj, "MACAddress")) == NULL) {
                        continue;
                    }
                    if ((assoc_obj = cJSON_GetObjectItem(sta_obj, "Associated")) == NULL) {
                        continue;
                    }

                    if ((disassoc_obj = cJSON_GetObjectItem(sta_obj, "Disassociate")) == NULL) {
                        continue;
                    }

                    dm_easy_mesh_t::string_to_macbytes(cJSON_GetStringValue(sta_mac_obj), 
                        disassoc_param.params[disassoc_param.num].sta_mac);
                    dm_easy_mesh_t::string_to_macbytes(cJSON_GetStringValue(bss_id_obj), 
                        disassoc_param.params[disassoc_param.num].bssid);

                    timer_obj = cJSON_GetObjectItem(disassoc_obj, "DisassociationTimer");
                    disassoc_param.params[disassoc_param.num].disassoc_time = static_cast<unsigned int> (cJSON_GetNumberValue(timer_obj));

                    reason_obj = cJSON_GetObjectItem(disassoc_obj, "ReasonCode");
                    disassoc_param.params[disassoc_param.num].reason = static_cast<unsigned int> (cJSON_GetNumberValue(reason_obj));

                    silent_obj = cJSON_GetObjectItem(disassoc_obj, "Silent");
                    disassoc_param.params[disassoc_param.num].silent = (cJSON_IsTrue(silent_obj) == true) ? true:false;

                    disassoc_param.num++;
                }
            }
        }
    }
    cJSON_free(obj);

    num = analyze_sta_disassoc(disassoc_param, cmd);
    return num;
}

int dm_easy_mesh_ctrl_t::analyze_command_btm(em_bus_event_t *evt, em_cmd_t *cmd[])
{
    cJSON *obj;
    unsigned int num = 0;
    em_subdoc_info_t *subdoc;

    printf("%s:%d: Enter\n", __func__, __LINE__);
    subdoc = &evt->u.subdoc;

    obj = cJSON_Parse(subdoc->buff);
    if (obj == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        return 0;
    }

    cJSON_free(obj);

    return static_cast<int> (num);
}

int dm_easy_mesh_ctrl_t::analyze_dpp_start(em_bus_event_t *evt, em_cmd_t *cmd[])
{
    cJSON *dpp_obj;
    int num = 0;
    em_subdoc_info_t *subdoc;
    dm_easy_mesh_t dm;
    em_tiny_string_t country_code = "US";
	em_cmd_params_t params = evt->params;

    subdoc = &evt->u.subdoc;

    dpp_obj = cJSON_Parse(subdoc->buff);
    if (dpp_obj == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        return 0;
    }

    dm_device_t *dev = get_first_device();
    if (dev != NULL && dev->m_device_info.country_code[0] != '\0') {
        strncpy(country_code, dev->m_device_info.country_code, sizeof(em_tiny_string_t));
    }
    

    num = dm.get_dpp()->analyze_config(dpp_obj, NULL, cmd, &params, static_cast<void*> (country_code));
    cJSON_free(dpp_obj);

    return num;
}

int dm_easy_mesh_ctrl_t::analyze_set_policy(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
	int ret;
	unsigned int num = 0, num_devices = 0;
	em_subdoc_info_t *subdoc;
	dm_easy_mesh_t dm;
	unsigned int i = 0;
    em_cmd_t *tmp;
	dm_radio_t *radio;
	mac_addr_str_t mac_str;
	
	subdoc = &evt->u.subdoc;

	do {
		dm.reset();

		if ((ret = dm.decode_config(subdoc, "SetPolicy", i, &num_devices)) < 0) {
        	return ret;
    	}
			
		dm_easy_mesh_t::macbytes_to_string(dm.m_device.m_device_info.intf.mac, mac_str);
		//printf("%s:%d: Network: %s\tDevice MAC: %s\n", __func__, __LINE__, dm.m_network.m_net_info.id, mac_str);

		radio = m_data_model_list.get_first_radio(dm.m_network.m_net_info.id, dm.m_device.m_device_info.intf.mac);
		while (radio != NULL) {
			memcpy(dm.m_radio[dm.m_num_radios].m_radio_info.intf.mac, radio->m_radio_info.intf.mac, sizeof(mac_address_t));
			dm.m_num_radios++;
			radio = m_data_model_list.get_next_radio(dm.m_network.m_net_info.id, dm.m_device.m_device_info.intf.mac, radio);
		}

   		pcmd[num] = new em_cmd_set_policy_t(evt->params, dm);
   		tmp = pcmd[num];
   		num++;

   		while ((pcmd[num] = tmp->clone_for_next()) != NULL) {
       		tmp = pcmd[num];
       		num++;
   		}

		i++;
	} while (i < num_devices);

	return static_cast<int> (num);
}

int dm_easy_mesh_ctrl_t::analyze_scan_channel(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    int ret;
    em_subdoc_info_t *subdoc;
    dm_easy_mesh_t dm, *pdm;
    em_cmd_t *tmp;
    unsigned int num = 0, num_devices = 0, i = 0;
        
    subdoc = &evt->u.subdoc;
        
    if ((ret = dm.decode_config(subdoc, "ChannelScanRequest", i, &num_devices)) < 0) {
        return ret;
    } 
        
    assert(dm.get_num_op_class() == EM_MAX_BANDS);
        
    pdm = m_data_model_list.get_first_dm();
    while (pdm != NULL) {
        pdm->set_channels_list(dm.m_op_class, dm.get_num_op_class());
    
        pdm->set_db_cfg_param(db_cfg_type_op_class_list_update, "");
        pdm = m_data_model_list.get_next_dm(pdm);
    }


    pcmd[num] = new em_cmd_scan_channel_t(evt->params, dm);
    tmp = pcmd[num];
    num++;

    while ((pcmd[num] = tmp->clone_for_next()) != NULL) {
        tmp = pcmd[num];
        num++;
    }

    return static_cast<int> (num);

}

int dm_easy_mesh_ctrl_t::analyze_set_channel(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    int ret;
    em_subdoc_info_t *subdoc;
	dm_easy_mesh_t dm, *pdm;
    em_cmd_t *tmp;
	unsigned int num = 0, num_devices = 0, i = 0, j = 0, k = 0;
	dm_op_class_t *updated_oclass, *current_oclass;
	unsigned int band, already_added;
    
	subdoc = &evt->u.subdoc;

   	if ((ret = dm.decode_config(subdoc, "SetAnticipatedChannelPreference", i, &num_devices)) < 0) {
       	return ret;
   	}

	assert(dm.get_num_op_class() == EM_MAX_BANDS);

	evt->params.u.args.num_args = 0;
	pdm = m_data_model_list.get_first_dm();
	while (pdm != NULL) {
        for (i = 0; i < dm.get_num_op_class(); i++) {
			updated_oclass = &dm.m_op_class[i];
			memcpy(updated_oclass->m_op_class_info.id.ruid, pdm->get_device_info()->intf.mac, sizeof(mac_addr_t));

			for (j = 0; j < pdm->get_num_op_class(); j++) {
				current_oclass = &pdm->m_op_class[j];

				if ((memcmp(updated_oclass->m_op_class_info.id.ruid, current_oclass->m_op_class_info.id.ruid, sizeof(mac_address_t)) == 0) &&
					(updated_oclass->m_op_class_info.id.type == current_oclass->m_op_class_info.id.type) &&
					(updated_oclass->m_op_class_info.id.op_class == current_oclass->m_op_class_info.id.op_class)) {

					// Check if the channel has changed or not
					if (updated_oclass->m_op_class_info.channels[0] != current_oclass->m_op_class_info.channels[0]) {
						already_added = 0;
						band = dm_easy_mesh_t::get_freq_band_by_op_class(static_cast<int>(updated_oclass->m_op_class_info.id.op_class));

						// Check if the band is already added to event parameters
						for (k = 0; k < evt->params.u.args.num_args; k++) {
							if (static_cast<unsigned int>(atoi(evt->params.u.args.args[k])) == band) {
								already_added = 1;
								break;
							}
						}

						// If the band is not already added, add it to the event parameters
						if (!already_added) {
							snprintf(evt->params.u.args.args[evt->params.u.args.num_args], sizeof(em_long_string_t), "%u", band);
							evt->params.u.args.num_args++;
						}
					}
					break;
				}
			}
        }
		pdm->set_channels_list(dm.m_op_class, dm.get_num_op_class());

		pdm->set_db_cfg_param(db_cfg_type_op_class_list_update, "");
		pdm = m_data_model_list.get_next_dm(pdm);
	}
	

   	pcmd[num] = new em_cmd_set_channel_t(evt->params, dm);
   	tmp = pcmd[num];
   	num++;

   	while ((pcmd[num] = tmp->clone_for_next()) != NULL) {
       	tmp = pcmd[num];
       	num++;
   	}

	return static_cast<int> (num);
}

int dm_easy_mesh_ctrl_t::analyze_set_radio(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    int ret;
    unsigned int num = 0, num_devices = 0;
    em_subdoc_info_t *subdoc;
    dm_easy_mesh_t dm, tgt, *pdm;
    unsigned int i = 0, j, k;
    em_cmd_t *tmp;
    dm_radio_t *radio, *pradio;
    mac_addr_str_t mac_str;
   
    subdoc = &evt->u.subdoc;

    do {
        dm.reset();

        if ((ret = dm.decode_config(subdoc, "RadioEnable", i, &num_devices)) < 0) {
            return ret;
        }

		dm_easy_mesh_t::macbytes_to_string(dm.m_device.m_device_info.intf.mac, mac_str);

		// Now check the difference with existing
		if ((pdm = get_data_model(dm.m_network.m_net_info.id, dm.m_device.m_device_info.intf.mac)) == NULL) {
			printf("%s:%d: Getting data model for Network:%s and Device:%s failed\n", __func__, __LINE__, 
				dm.m_network.m_net_info.id, mac_str);
			return 0;
		}

		//Copy the networlk information to target
		tgt.m_network = dm.m_network;
		tgt.m_device = dm.m_device;

		dm_easy_mesh_t::macbytes_to_string(dm.m_device.m_device_info.intf.mac, mac_str);
		//printf("%s:%d: Decoded device: %s, Radios: %d\n", __func__, __LINE__, mac_str, dm.get_num_radios());
		dm_easy_mesh_t::macbytes_to_string(pdm->m_device.m_device_info.intf.mac, mac_str);
		//printf("%s:%d: Datamodel device: %s, Radios: %d\n", __func__, __LINE__, mac_str, pdm->get_num_radios());
		
		assert(memcmp(dm.m_device.m_device_info.intf.mac, pdm->m_device.m_device_info.intf.mac, sizeof(mac_address_t)) == 0);

		for (j = 0; j < dm.get_num_radios(); j++) {
			radio = &dm.m_radio[j];	
			for (k = 0; k < pdm->get_num_radios(); k++) {
				pradio = &pdm->m_radio[k];
				if (memcmp(radio->m_radio_info.intf.mac, pradio->m_radio_info.intf.mac, sizeof(mac_address_t)) == 0) {
					if (radio->m_radio_info.enabled != pradio->m_radio_info.enabled) {
						printf("%s:%d: Radio: %s changed, adding to target\n", __func__, __LINE__, mac_str);
						tgt.m_radio[tgt.m_num_radios] = dm.m_radio[j];
						tgt.m_num_radios++;	
					} else {
						dm_easy_mesh_t::macbytes_to_string(radio->m_radio_info.intf.mac, mac_str);
						printf("%s:%d: Radio: %s hasn't changed, not adding\n", __func__, __LINE__, mac_str);
					}
				}
			}
		}	

        pcmd[num] = new em_cmd_set_radio_t(evt->params, tgt);
        tmp = pcmd[num];
        num++;

        while ((pcmd[num] = tmp->clone_for_next()) != NULL) {
            tmp = pcmd[num];
            num++;
        }

        i++;
    } while (i < num_devices);

    return static_cast<int> (num);

}

int dm_easy_mesh_ctrl_t::analyze_set_ssid(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    int ret;
    em_subdoc_info_t *subdoc;
	dm_easy_mesh_t dm, *pdm;;
	dm_network_ssid_t *tgt, *src;
    em_cmd_t *tmp;
	int i, j, num = 0;
	int bit_mask = 0;

    subdoc = &evt->u.subdoc;
	if ((ret = dm.decode_config(subdoc, "SetSSID")) < 0) {
		return ret;
	}

	pdm = m_data_model_list.get_first_dm();
	if (pdm == NULL) {
		assert(pdm != NULL);
		return EM_PARSE_ERR_CONFIG;
	}

	for (i = 0; i < EM_MAX_NET_SSIDS; i++) {	
		tgt = &dm.m_network_ssid[i];
		for (j = 0; j < EM_MAX_NET_SSIDS; j++) {	
			src = &pdm->m_network_ssid[j];
			if (*tgt == *src) {
				printf("%s:%d: Target[%d] matched with Source[%d]\n", __func__, __LINE__, i, j);
				bit_mask |= (1 << i);
				break;
			}
		}
	}

	if (bit_mask == (pow(2, EM_MAX_NET_SSIDS) - 1)) {
		printf("%s:%d: No change detected\n", __func__, __LINE__);
		return EM_PARSE_ERR_NO_CHANGE;
	}

	printf("%s:%d: Start taking action on SetSSID\n", __func__, __LINE__);	
	dm.set_db_cfg_param(db_cfg_type_network_ssid_list_update, "");
    pcmd[num] = new em_cmd_set_ssid_t(evt->params, dm);
    tmp = pcmd[num];
    num++;

    while ((pcmd[num] = tmp->clone_for_next()) != NULL) {
        tmp = pcmd[num];
        num++;
    }
    printf("%s:%d: Number of commands:%d\n", __func__, __LINE__, num);


    return num;
}

int dm_easy_mesh_ctrl_t::analyze_remove_device(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    cJSON *obj, *wfa_obj, *net_obj, *dev_list_obj, *id_obj;
    int i, num = 0;
    em_subdoc_info_t *subdoc;
	mac_address_t dev_mac_to_keep[32];
	int num_devs_to_keep = 0;
	dm_device_t *devices_to_delete[32];
	int num_devs_to_delete = 0;
	char *tmp;
	bool keep = false;
	dm_device_t *device;
	mac_addr_str_t	mac_str;
	dm_easy_mesh_t *dm = NULL;
	em_cmd_t *tmp_cmd;
	em_long_string_t wfa;	

    subdoc = &evt->u.subdoc;
	obj = cJSON_Parse(subdoc->buff);
    if (obj == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
        return 0;
    }

	snprintf(wfa, sizeof(wfa), "wfa-dataelements:RemoveDevice");

	if ((wfa_obj = cJSON_GetObjectItem(obj, wfa)) == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
    	cJSON_free(obj);
        return 0;
	}

	if ((net_obj = cJSON_GetObjectItem(wfa_obj, "Network")) == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
    	cJSON_free(obj);
        return 0;
	}

	if ((dev_list_obj = cJSON_GetObjectItem(net_obj, "DeviceList")) == NULL) {
        printf("%s:%d: Failed to parse: %s\n", __func__, __LINE__, subdoc->buff);
    	cJSON_free(obj);
        return 0;
	}

	for (i = 0; i < cJSON_GetArraySize(dev_list_obj); i++) {
		id_obj = cJSON_GetObjectItem(cJSON_GetArrayItem(dev_list_obj, i), "ID");
		tmp = cJSON_GetStringValue(id_obj);
		dm_easy_mesh_t::string_to_macbytes(tmp, dev_mac_to_keep[i]);
	}

	num_devs_to_keep = i;

    cJSON_free(obj);

	device = m_data_model_list.get_first_device();
	while (device != NULL) {
		for (i = 0; i < num_devs_to_keep; i++) {
			if (memcmp(device->m_device_info.intf.mac, dev_mac_to_keep[i], sizeof(mac_address_t)) == 0) {
				keep = true;
				break;
			}
		}

		if (keep == true) {
			keep = false;
		} else {
			devices_to_delete[num_devs_to_delete] = device;
			num_devs_to_delete++;
		}
		device = m_data_model_list.get_next_device(device);
	}

	for (i = 0; i < num_devs_to_delete; i++) {
		device = devices_to_delete[i];
		dm_easy_mesh_t::macbytes_to_string(device->m_device_info.intf.mac, mac_str);
		printf("%s:%d: Device: %s should be deleted\n", __func__, __LINE__, mac_str);	
		dm = m_data_model_list.get_data_model(device->m_device_info.id.net_id, device->m_device_info.intf.mac);
		if (dm != NULL) {
    		pcmd[num] = new em_cmd_remove_device_t(evt->params, *dm);
    		tmp_cmd = pcmd[num];
    		num++;

    		while ((pcmd[num] = tmp_cmd->clone_for_next()) != NULL) {
        		tmp_cmd = pcmd[num];
        		num++;
    		}
		}	
	}

    return num;
}

int dm_easy_mesh_ctrl_t::analyze_mld_reconfig(em_cmd_t *pcmd[])
{
    int num = 0;
    em_cmd_t *tmp;

    pcmd[num] = new em_cmd_mld_reconfig_t();
    tmp = pcmd[num];
    num++;

    while ((pcmd[num] = tmp->clone_for_next()) != NULL) {
        tmp = pcmd[num];
        num++;
    }

    return num;
}

/*int dm_easy_mesh_ctrl_t::analyze_network_ssid_list(em_bus_event_t *evt, em_cmd_t *cmd[])
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

    num = dm_network_ssid_list_t::analyze_config(netssid_list_obj, (void *)global_netid, cmd, &evt->params);
    cJSON_free(obj);

    return num;
}*/

int dm_easy_mesh_ctrl_t::set_op_class_list(cJSON *op_class_list_obj, mac_address_t *radio_mac)
{
    dm_op_class_list_t::set_config(m_db_client, op_class_list_obj, radio_mac);
    return 0;
}

int dm_easy_mesh_ctrl_t::set_radio_cap_list(cJSON *radio_cap_list_obj, mac_address_t *radio_mac)
{
    dm_radio_cap_list_t::set_config(m_db_client, radio_cap_list_obj, radio_mac);
    return 0;
}

int dm_easy_mesh_ctrl_t::set_bss_list(cJSON *bss_list_obj, mac_address_t *radio_mac)
{
    dm_bss_list_t::set_config(m_db_client, bss_list_obj, radio_mac);
    return 0;
}

int dm_easy_mesh_ctrl_t::set_radio_list(cJSON *radio_list_obj, mac_address_t *dev_mac)
{
    int i, num;
    cJSON *obj, *radio_obj, *bss_list_obj, *op_class_list_obj, *radio_cap_list_obj;
    mac_address_t radio_mac;

    dm_radio_list_t::set_config(m_db_client, radio_list_obj, dev_mac);

    num = cJSON_GetArraySize(radio_list_obj);
    //printf("%s:%d: Number of devices: %d\n", __func__, __LINE__, num);
    for (i = 0; i < num; i++) {
        if ((radio_obj = cJSON_GetArrayItem(radio_list_obj, i)) != NULL) {

            obj = cJSON_GetObjectItem(radio_obj, "ID");
            dm_easy_mesh_t::string_to_macbytes(cJSON_GetStringValue(obj), radio_mac);
            //printf("%s:%d: BSSList for radio[%d]: %s\n", __func__, __LINE__, i, cJSON_GetStringValue(obj));

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
    int i, num;
    cJSON *obj, *dev_obj, *radio_list_obj;
    mac_address_t dev_mac;

    dm_device_list_t::set_config(m_db_client, dev_list_obj, static_cast<void *> (global_netid));

    num = cJSON_GetArraySize(dev_list_obj);
    //printf("%s:%d: Number of devices: %d\n", __func__, __LINE__, num);
    for (i = 0; i < num; i++) {
        if (((dev_obj = cJSON_GetArrayItem(dev_list_obj, i)) != NULL) &&
           ((radio_list_obj = cJSON_GetObjectItem(dev_obj, "RadioList")) != NULL)) {
            obj = cJSON_GetObjectItem(dev_obj, "ID");
            dm_easy_mesh_t::string_to_macbytes(cJSON_GetStringValue(obj), dev_mac);
            //printf("%s:%d: RadioList for device[%d]: %s\n", __func__, __LINE__, i, cJSON_GetStringValue(obj));
            set_radio_list(radio_list_obj, &dev_mac);
        }
    }

    return 0;
}

int dm_easy_mesh_ctrl_t::reset_config()
{
    
    dm_network_list_t::delete_list();
    dm_device_list_t::delete_list();
    dm_radio_list_t::delete_list();
    dm_network_ssid_list_t::delete_list();
    //dm_ieee_1905_security_list_t::delete_list();
    //dm_radio_cap_list_t::delete_list();
    dm_op_class_list_t::delete_list();
    dm_bss_list_t::delete_list();
    dm_sta_list_t::delete_list();
    dm_policy_list_t::delete_list();
    
    dm_network_list_t::delete_table(m_db_client);
    dm_device_list_t::delete_table(m_db_client);
    dm_radio_list_t::delete_table(m_db_client);    
    dm_network_ssid_list_t::delete_table(m_db_client);   
    //dm_ieee_1905_security_list_t::delete_table(m_db_client);
    //dm_radio_cap_list_t::delete_table(m_db_client);
    dm_op_class_list_t::delete_table(m_db_client);
    dm_bss_list_t::delete_table(m_db_client);
    dm_sta_list_t::delete_table(m_db_client);
    dm_policy_list_t::delete_table(m_db_client);

    dm_network_list_t::load_table(m_db_client);
    dm_device_list_t::load_table(m_db_client);
    dm_radio_list_t::load_table(m_db_client);    
    dm_network_ssid_list_t::load_table(m_db_client);    
    //dm_ieee_1905_security_list_t::load_table(m_db_client);
    //dm_radio_cap_list_t::load_table(m_db_client);
    dm_op_class_list_t::load_table(m_db_client);
    dm_bss_list_t::load_table(m_db_client);
    dm_sta_list_t::load_table(m_db_client);
    dm_policy_list_t::load_table(m_db_client);
    dm_scan_result_list_t::load_table(m_db_client);

    return 0;
}

int dm_easy_mesh_ctrl_t::get_bss_config(cJSON *parent, char *key)
{
    cJSON *net_obj, *dev_list_obj, *dev_obj, *radio_list_obj, *radio_obj, *bss_list_obj;
    int i, j;
    char *tmp;

    net_obj = cJSON_AddObjectToObject(parent, "Network");
    dm_network_list_t::get_config(net_obj, key, true);

    dev_list_obj = cJSON_AddArrayToObject(net_obj, "DeviceList");
    dm_device_list_t::get_config(dev_list_obj, key, true);

    for (i = 0; i < cJSON_GetArraySize(dev_list_obj); i++) {
        dev_obj = cJSON_GetArrayItem(dev_list_obj, i);
        radio_list_obj = cJSON_AddArrayToObject(dev_obj, "RadioList");
        dm_radio_list_t::get_config(radio_list_obj, cJSON_GetStringValue(cJSON_GetObjectItem(dev_obj, "ID")), 
				em_get_radio_list_reason_radio_summary);
        for (j = 0; j < cJSON_GetArraySize(radio_list_obj); j++) {
            radio_obj = cJSON_GetArrayItem(radio_list_obj, j);
            tmp = cJSON_GetStringValue(cJSON_GetObjectItem(radio_obj, "ID"));
            bss_list_obj = cJSON_AddArrayToObject(radio_obj, "BSSList");
            dm_bss_list_t::get_config(bss_list_obj, tmp);
        }
    }

    return 0;
}

int dm_easy_mesh_ctrl_t::get_reference_config(cJSON *parent, char *net_id)
{
	char *buff;
	cJSON *obj;

	buff = static_cast<char *> (malloc(EM_MAX_EVENT_DATA_LEN));

	if (em_cmd_exec_t::load_params_file("DevTest.json", buff) < 0) {
		printf("%s:%d: Failed to load test file\n", __func__, __LINE__);
		free(buff);
		return -1;
	}

	if ((obj = cJSON_Parse(buff)) == NULL) {
		printf("%s:%d: Failed to load test file\n", __func__, __LINE__);
		free(buff);
		return -1;
	}

	free(buff);

	cJSON_AddItemToObject(parent, "Reference", obj);
	
	return 0;
}

int dm_easy_mesh_ctrl_t::get_scan_result(cJSON *parent, char *key)
{
    cJSON *net_obj, *dev_list_obj, *dev_obj, *radio_list_obj, *radio_obj;
	cJSON *bss_obj, *bss_list_obj, *sta_list_obj;
	int i, j, k;
	em_long_string_t	scan_parent;
	char *dev_id, *radio_id, *bss_id;
	mac_addr_str_t	null_mac_str;
	mac_address_t null_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	dm_easy_mesh_t::macbytes_to_string(null_mac, null_mac_str);
		
	net_obj = cJSON_AddObjectToObject(parent, "Network");
	dm_network_list_t::get_config(net_obj, key);

	dev_list_obj = cJSON_AddArrayToObject(net_obj, "DeviceList");
	dm_device_list_t::get_config(dev_list_obj, key, true);

	for (i = 0; i < cJSON_GetArraySize(dev_list_obj); i++) {	
		dev_obj = cJSON_GetArrayItem(dev_list_obj, i);
		dev_id = cJSON_GetStringValue(cJSON_GetObjectItem(dev_obj, "ID"));
		radio_list_obj = cJSON_AddArrayToObject(dev_obj, "RadioList");
		dm_radio_list_t::get_config(radio_list_obj, dev_id, em_get_radio_list_reason_radio_summary);

		for (j = 0; j < cJSON_GetArraySize(radio_list_obj); j++) {
			radio_obj = cJSON_GetArrayItem(radio_list_obj, j);
			radio_id = cJSON_GetStringValue(cJSON_GetObjectItem(radio_obj, "ID"));

			snprintf(scan_parent, sizeof(em_long_string_t), "%s@%s@%s@0@0@1@%s", key, dev_id, radio_id, null_mac_str);
			//printf("%s:%d: Scan Parent ID: %s\n", __func__, __LINE__, scan_parent);
			dm_scan_result_list_t::get_config(radio_obj, scan_parent);

			bss_list_obj = cJSON_AddArrayToObject(radio_obj, "BSSList");
			dm_bss_list_t::get_config(bss_list_obj, radio_id, true);

			for (k = 0; k < cJSON_GetArraySize(bss_list_obj); k++) {
				bss_obj = cJSON_GetArrayItem(bss_list_obj, k);
				bss_id = cJSON_GetStringValue(cJSON_GetObjectItem(bss_obj, "BSSID"));

				sta_list_obj = cJSON_AddArrayToObject(bss_obj, "STAList");	
				dm_sta_list_t::get_config(sta_list_obj, bss_id, em_get_sta_list_reason_neighbors);
			}
		} 
	}

	return 0;
}

int dm_easy_mesh_ctrl_t::get_policy_config(cJSON *parent, char *net_id)
{
    cJSON *net_obj, *dev_list_obj, *dev_obj, *policy_obj;
    int i;
	char *tmp;

    net_obj = cJSON_AddObjectToObject(parent, "Network");
    dm_network_list_t::get_config(net_obj, net_id, true);

    dev_list_obj = cJSON_AddArrayToObject(net_obj, "DeviceList");
    dm_device_list_t::get_config(dev_list_obj, net_id, true);

    for (i = 0; i < cJSON_GetArraySize(dev_list_obj); i++) {
        dev_obj = cJSON_GetArrayItem(dev_list_obj, i);
        tmp = cJSON_GetStringValue(cJSON_GetObjectItem(dev_obj, "ID"));
        policy_obj = cJSON_AddObjectToObject(dev_obj, "Policy");
		dm_policy_list_t::get_config(policy_obj, tmp);
    }

    return 0;

}

int dm_easy_mesh_ctrl_t::get_sta_config(cJSON *parent, char *key, em_get_sta_list_reason_t reason)
{
    cJSON *net_obj, *dev_list_obj, *dev_obj, *radio_list_obj, *radio_obj, *bss_list_obj;
    cJSON *bss_obj, *sta_list_obj;
    int i, j, k;
    char *tmp;

    net_obj = cJSON_AddObjectToObject(parent, "Network");
    dm_network_list_t::get_config(net_obj, key, true);

    dev_list_obj = cJSON_AddArrayToObject(net_obj, "DeviceList");
    dm_device_list_t::get_config(dev_list_obj, key, true);

    for (i = 0; i < cJSON_GetArraySize(dev_list_obj); i++) {
        dev_obj = cJSON_GetArrayItem(dev_list_obj, i);
        radio_list_obj = cJSON_AddArrayToObject(dev_obj, "RadioList");
        dm_radio_list_t::get_config(radio_list_obj, cJSON_GetStringValue(cJSON_GetObjectItem(dev_obj, "ID")), 
				em_get_radio_list_reason_radio_summary);
        for (j = 0; j < cJSON_GetArraySize(radio_list_obj); j++) {
            radio_obj = cJSON_GetArrayItem(radio_list_obj, j);
            tmp = cJSON_GetStringValue(cJSON_GetObjectItem(radio_obj, "ID"));
            bss_list_obj = cJSON_AddArrayToObject(radio_obj, "BSSList");
            dm_bss_list_t::get_config(bss_list_obj, tmp, true);

            for (k = 0; k < cJSON_GetArraySize(bss_list_obj); k++) {
                bss_obj = cJSON_GetArrayItem(bss_list_obj, k);
                tmp = cJSON_GetStringValue(cJSON_GetObjectItem(bss_obj, "bssid"));
                sta_list_obj = cJSON_AddArrayToObject(bss_obj, "STAList");
                dm_sta_list_t::get_config(sta_list_obj, tmp, reason);
            }
        }
    }

    return 0;
}

int dm_easy_mesh_ctrl_t::get_network_ssid_config(cJSON *parent, char *key)
{
    cJSON *netssid_list_obj;

    netssid_list_obj = cJSON_AddArrayToObject(parent, "NetworkSSIDList");
    dm_network_ssid_list_t::get_config(netssid_list_obj, key);
	
    return 0;
}

int dm_easy_mesh_ctrl_t::get_channel_config(cJSON *parent, char *key, em_get_channel_list_reason_t reason)
{
    cJSON *net_obj, *dev_list_obj, *dev_obj, *radio_list_obj, *radio_obj, *op_class_list_obj;
	cJSON *preferred_channels_list_obj, *channel_list_obj;
    int i, j;
    char *tmp;
    em_long_string_t op_key;

    net_obj = cJSON_AddObjectToObject(parent, "Network");
    dm_network_list_t::get_config(net_obj, key, true);

	if (reason == em_get_channel_list_reason_set_anticipated) {
    	channel_list_obj = cJSON_AddArrayToObject(net_obj, "AnticipatedChannelPreference");
    	dm_op_class_list_t::get_config(channel_list_obj, em_op_class_type_anticipated);
	} else if (reason == em_get_channel_list_reason_scan_params) {
    	channel_list_obj = cJSON_AddArrayToObject(net_obj, "ChannelScanParameters");
    	dm_op_class_list_t::get_config(channel_list_obj, em_op_class_type_scan_param);
	}

    dev_list_obj = cJSON_AddArrayToObject(net_obj, "DeviceList");
    dm_device_list_t::get_config(dev_list_obj, key, true);

    for (i = 0; i < cJSON_GetArraySize(dev_list_obj); i++) {	
        dev_obj = cJSON_GetArrayItem(dev_list_obj, i);
        radio_list_obj = cJSON_AddArrayToObject(dev_obj, "RadioList");
        dm_radio_list_t::get_config(radio_list_obj, cJSON_GetStringValue(cJSON_GetObjectItem(dev_obj, "ID")), 
				em_get_radio_list_reason_radio_summary);
        for (j = 0; j < cJSON_GetArraySize(radio_list_obj); j++) {
            radio_obj = cJSON_GetArrayItem(radio_list_obj, j);
            tmp = cJSON_GetStringValue(cJSON_GetObjectItem(radio_obj, "ID"));
            op_class_list_obj = cJSON_AddArrayToObject(radio_obj, "CurrentOperatingClasses");
            snprintf(op_key, sizeof(op_key), "%s@%d@%d", tmp, em_op_class_type_current, 0);
            dm_op_class_list_t::get_config(op_class_list_obj, op_key);
        }
        preferred_channels_list_obj = cJSON_AddArrayToObject(dev_obj, "PreferredChannels");
        tmp = cJSON_GetStringValue(cJSON_GetObjectItem(dev_obj, "ID"));
        snprintf(op_key, sizeof(op_key), "%s@%d@%d", tmp, em_op_class_type_preference, 0);
        dm_op_class_list_t::get_config(preferred_channels_list_obj, op_key);
    }

    return 0;
}

int dm_easy_mesh_ctrl_t::get_radio_config(cJSON *parent, char *key, em_get_radio_list_reason_t reason)
{
    cJSON *net_obj, *dev_list_obj, *dev_obj, *radio_list_obj, *radio_obj, *op_class_list_obj;
	cJSON *bss_list_obj;
	int i, j;
    em_long_string_t op_key;
	char *tmp;
		
	net_obj = cJSON_AddObjectToObject(parent, "Network");
	dm_network_list_t::get_config(net_obj, key);

	dev_list_obj = cJSON_AddArrayToObject(net_obj, "DeviceList");
	dm_device_list_t::get_config(dev_list_obj, key, true);

	for (i = 0; i < cJSON_GetArraySize(dev_list_obj); i++) {	
		dev_obj = cJSON_GetArrayItem(dev_list_obj, i);
		radio_list_obj = cJSON_AddArrayToObject(dev_obj, "RadioList");
		dm_radio_list_t::get_config(radio_list_obj, cJSON_GetStringValue(cJSON_GetObjectItem(dev_obj, "ID")), reason);
        for (j = 0; j < cJSON_GetArraySize(radio_list_obj); j++) {
            radio_obj = cJSON_GetArrayItem(radio_list_obj, j);
            tmp = cJSON_GetStringValue(cJSON_GetObjectItem(radio_obj, "ID"));
			op_class_list_obj = cJSON_AddArrayToObject(radio_obj, "CurrentOperatingClasses");
            snprintf(op_key, sizeof(op_key), "%s@%d@%d", tmp, em_op_class_type_current, 0);
            dm_op_class_list_t::get_config(op_class_list_obj, op_key);
            bss_list_obj = cJSON_AddArrayToObject(radio_obj, "BSSList");
            dm_bss_list_t::get_config(bss_list_obj, tmp, true);
        }
	}

	return 0;
}

int dm_easy_mesh_ctrl_t::get_device_config(cJSON *parent, char *key, bool summary)
{
    cJSON *net_obj, *dev_list_obj;
		
	net_obj = cJSON_AddObjectToObject(parent, "Network");
	dm_network_list_t::get_config(net_obj, key, true);

	dev_list_obj = cJSON_AddArrayToObject(net_obj, "DeviceList");
	dm_device_list_t::get_config(dev_list_obj, key, summary);

	return 0;
}

int dm_easy_mesh_ctrl_t::get_network_config(cJSON *parent, char *key)
{
	// get the data from topology
	m_topology->encode(parent);   	 
	return 0;
}

int dm_easy_mesh_ctrl_t::get_mld_config(cJSON *parent, char *key)
{
	return 0;
}

void dm_easy_mesh_ctrl_t::get_config(em_long_string_t net_id, em_subdoc_info_t *subdoc)
{
    cJSON *parent;
    char *tmp;

    parent = cJSON_CreateObject();

    //printf("%s:%d: Subdoc Name: %s\n", __func__, __LINE__, subdoc->name);
    if (strncmp(subdoc->name, "Network", strlen(subdoc->name)) == 0) {
        get_network_config(parent, net_id);
    } else if (strncmp(subdoc->name, "DeviceList", strlen(subdoc->name)) == 0) {
        get_device_config(parent, net_id);
    } else if (strncmp(subdoc->name, "DeviceListSummary", strlen(subdoc->name)) == 0) {
        get_device_config(parent, net_id, true);
    } else if (strncmp(subdoc->name, "RadioList", strlen(subdoc->name)) == 0) {
        get_radio_config(parent, net_id, em_get_radio_list_reason_radio_summary);
    } else if (strncmp(subdoc->name, "RadioListSummary@RadioEnable", strlen(subdoc->name)) == 0) {
        get_radio_config(parent, net_id, em_get_radio_list_reason_radio_enable);
    } else if (strncmp(subdoc->name, "NetworkSSIDList", strlen(subdoc->name)) == 0) {
        get_network_ssid_config(parent, net_id);
    } else if (strncmp(subdoc->name, "ChannelList", strlen(subdoc->name)) == 0) {
        get_channel_config(parent, net_id);
    } else if (strncmp(subdoc->name, "ChannelListSummary@SetAnticipatedChannelPreference", strlen(subdoc->name)) == 0) {
        get_channel_config(parent, net_id, em_get_channel_list_reason_set_anticipated);
    } else if (strncmp(subdoc->name, "ChannelListSummary@ScanChannel", strlen(subdoc->name)) == 0) {
        get_channel_config(parent, net_id, em_get_channel_list_reason_scan_params);
    } else if (strncmp(subdoc->name, "BSSList", strlen(subdoc->name)) == 0) {
        get_bss_config(parent, net_id);
    } else if (strncmp(subdoc->name, "STAList", strlen(subdoc->name)) == 0) {
        get_sta_config(parent, net_id);
    } else if (strncmp(subdoc->name, "STAListSummary@Steer", strlen(subdoc->name)) == 0) {
        get_sta_config(parent, net_id, em_get_sta_list_reason_steer);
    } else if (strncmp(subdoc->name, "STAListSummary@Disassociate", strlen(subdoc->name)) == 0) {
        get_sta_config(parent, net_id, em_get_sta_list_reason_disassoc);
    } else if (strncmp(subdoc->name, "STAListSummary@BTM", strlen(subdoc->name)) == 0) {
        get_sta_config(parent, net_id, em_get_sta_list_reason_btm);
    } else if (strncmp(subdoc->name, "Policy", strlen(subdoc->name)) == 0) {
        get_policy_config(parent, net_id);
    } else if (strncmp(subdoc->name, "ScanResult", strlen(subdoc->name)) == 0) {
        get_scan_result(parent, net_id);
    } else if (strncmp(subdoc->name, "DevTest", strlen(subdoc->name)) == 0) {
        get_reference_config(parent, net_id);
    } else if (strncmp(subdoc->name, "MLDConfig", strlen(subdoc->name)) == 0) {
        get_mld_config(parent, net_id);
    }

    tmp = cJSON_Print(parent);
    //printf("%s:%d: Subdoc: %s\n", __func__, __LINE__, tmp);
    strncpy(subdoc->buff, tmp, strlen(tmp) + 1);
    cJSON_free(parent);
}

int dm_easy_mesh_ctrl_t::copy_config(dm_easy_mesh_t *dm, em_long_string_t net_id)
{
    dm_network_t *network;

    network = m_data_model_list.get_network(net_id);
    if (network == NULL) {
        printf("%s:%d: Network with id:%s not found\n", __func__, __LINE__, net_id);
        return -1;
    }

    dm->set_network(*network);

    return 0;
}

int dm_easy_mesh_ctrl_t::set_config(dm_easy_mesh_t *dm)
{
    return update_tables(dm);
}

dm_easy_mesh_t *dm_easy_mesh_ctrl_t::create_data_model(const char *net_id, const em_interface_t *al_intf, em_profile_type_t profile)
{
    
    return m_data_model_list.create_data_model(net_id, al_intf, profile);
}

void dm_easy_mesh_ctrl_t::handle_dirty_dm()
{
    dm_easy_mesh_t *dm;

    dm = m_data_model_list.get_first_dm();
    while (dm != NULL) {
		if (dm->db_cfg_type_is_set()) {
	    	set_config(dm);		
		}
		dm = m_data_model_list.get_next_dm(dm);
    }
}

dm_easy_mesh_t  *dm_easy_mesh_ctrl_t::get_data_model(const char *net_id, const unsigned char *al_mac) 
{
    if (al_mac == NULL) {
        return reinterpret_cast<dm_easy_mesh_t *> (this);
    } else {
        return m_data_model_list.get_data_model(net_id, al_mac);
    }
}

void dm_easy_mesh_ctrl_t::init_tables()
{
    dm_network_list_t::init();
    dm_device_list_t::init();
    dm_network_ssid_list_t::init();
    dm_ieee_1905_security_list_t::init();
    dm_radio_cap_list_t::init();
    dm_radio_list_t::init();
    dm_op_class_list_t::init();
    dm_bss_list_t::init();
    dm_sta_list_t::init();
    dm_policy_list_t::init();
    dm_scan_result_list_t::init();
}

int dm_easy_mesh_ctrl_t::load_net_ssid_table()
{
	return dm_network_ssid_list_t::load_table(m_db_client);
}

int dm_easy_mesh_ctrl_t::load_tables()
{
    db_cfg_type_t type = db_cfg_type_none;
    
    if (dm_network_list_t::load_table(m_db_client) != 0) {
        type = db_cfg_type_network_list_update;
    } else if (dm_device_list_t::load_table(m_db_client) != 0) {
        type = db_cfg_type_device_list_update;
    } else if (dm_radio_list_t::load_table(m_db_client) != 0) {
        type = db_cfg_type_radio_list_update;
    } else if (dm_network_ssid_list_t::load_table(m_db_client) != 0) {
		type = db_cfg_type_network_ssid_list_update;
	} else if (dm_op_class_list_t::load_table(m_db_client) != 0) {
		type = db_cfg_type_op_class_list_update;
	} else if (dm_bss_list_t::load_table(m_db_client) != 0) {
		type = db_cfg_type_bss_list_update;
	} else if (dm_sta_list_t::load_table(m_db_client) != 0) {
		type = db_cfg_type_sta_list_update;
	} else if (dm_policy_list_t::load_table(m_db_client) != 0) {
		type = db_cfg_type_policy_list_update;
	} else if (dm_scan_result_list_t::load_table(m_db_client) != 0) {
		type = db_cfg_type_scan_result_list_update;
    }

	if (type != db_cfg_type_none) {
		return type;
	}

    if (dm_network_list_t::is_table_empty(m_db_client) == true) {
        printf("%s:%d: data base empty ... needs reset\n", __func__, __LINE__);
        return -1;
    }

	set_initialized();

    return 0;
}

int dm_easy_mesh_ctrl_t::update_tables(dm_easy_mesh_t *dm)
{
    //dm_orch_type_t type = dm_orch_type_none;
    dm_device_t device;
    dm_radio_t radio;
    dm_op_class_t op_class;
	dm_policy_t	policy;
	dm_scan_result_t	*scan_result;
	db_update_scan_result_t res;
    dm_bss_t bss;
    dm_sta_t *sta, *tmp;
    dm_network_ssid_t net_ssid;
    mac_addr_str_t	sta_mac_str, bssid_str, radio_mac_str, dev_mac_str, scanner_mac_str;
    unsigned int i, j;
    em_2xlong_string_t parent, key;
    em_string_t haul_str;
    bool at_least_one_failed = false;
	char *criteria;

    //printf("%s:%d: Database Config Bitmask: 0x%08x\n", __func__, __LINE__, dm->get_db_cfg_type());

    if (dm->db_cfg_type_is_set(db_cfg_type_network_list_update)) {
		criteria = dm->db_cfg_type_get_criteria(db_cfg_type_network_list_update);
        if (dm_network_list_t::set_config(m_db_client, dm->get_network_by_ref(), global_netid) == 0) {
            dm->reset_db_cfg_type(db_cfg_type_network_list_update);
        }
    }

    if (dm->db_cfg_type_is_set(db_cfg_type_network_list_delete)) {
		criteria = dm->db_cfg_type_get_criteria(db_cfg_type_network_list_delete);
        if (dm_network_list_t::update_db(m_db_client, dm_orch_type_db_delete, dm->get_network_info()) == 0) {
            dm->reset_db_cfg_type(db_cfg_type_network_list_delete);
        }
    }

    if (dm->db_cfg_type_is_set(db_cfg_type_device_list_update)) {
		criteria = dm->db_cfg_type_get_criteria(db_cfg_type_device_list_update);
		dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (dm->m_device.m_device_info.intf.mac), dev_mac_str);
    	snprintf(key, sizeof(em_2xlong_string_t), "%s@%s@%d", dm->m_network.m_net_info.id, 
					dev_mac_str, dm->m_device.m_device_info.id.media);
        if (dm_device_list_t::set_config(m_db_client, dm->get_device_by_ref(), key) == 0) {
            dm->reset_db_cfg_type(db_cfg_type_device_list_update);
        }
    }

    if (dm->db_cfg_type_is_set(db_cfg_type_device_list_delete)) {
		criteria = dm->db_cfg_type_get_criteria(db_cfg_type_device_list_delete);
        if (dm_device_list_t::update_db(m_db_client, dm_orch_type_db_delete, dm->get_device_info()) != 0) {
            dm->reset_db_cfg_type(db_cfg_type_device_list_delete);
        }
    }

    if (dm->db_cfg_type_is_set(db_cfg_type_radio_list_update)) {
        device = dm->get_device_by_ref();
        dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (device.m_device_info.intf.mac), dev_mac_str);
        for (i = 0; i < dm->get_num_radios(); i++) {
            radio = dm->get_radio_by_ref(i);
        	dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (radio.m_radio_info.intf.mac), radio_mac_str);
            snprintf(parent, sizeof(em_2xlong_string_t), "%s@%s@%s", device.m_device_info.id.net_id, dev_mac_str, radio_mac_str);
			criteria = dm->db_cfg_type_get_criteria(db_cfg_type_radio_list_update);
            if (dm_radio_list_t::set_config(m_db_client, radio, parent) != 0) {
                at_least_one_failed = true;;
            }
        }
        if (at_least_one_failed == true) {
            at_least_one_failed = false;
        } else {
            dm->reset_db_cfg_type(db_cfg_type_radio_list_update);
        }
    } 

    if (dm->db_cfg_type_is_set(db_cfg_type_radio_list_delete)) {
        device = dm->get_device_by_ref();
        dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (device.m_device_info.intf.mac), dev_mac_str);
        for (i = 0; i < dm->get_num_radios(); i++) {
            radio = dm->get_radio_by_ref(i);
        	dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (radio.m_radio_info.intf.mac), radio_mac_str);
            snprintf(parent, sizeof(em_2xlong_string_t), "%s@%s@%s", device.m_device_info.id.net_id, dev_mac_str, radio_mac_str);
			criteria = dm->db_cfg_type_get_criteria(db_cfg_type_radio_list_delete);
            if (dm_radio_list_t::update_db(m_db_client, dm_orch_type_db_delete, dm->get_radio(i)) != 0) {
                at_least_one_failed = true;
            }
			dm_radio_list_t::update_list(radio, dm_orch_type_db_delete);
        }
        if (at_least_one_failed == true) {
            at_least_one_failed = false;
        } else {
            dm->reset_db_cfg_type(db_cfg_type_radio_list_delete);
        }
    } 

    if (dm->db_cfg_type_is_set(db_cfg_type_bss_list_update)) {
        for (i = 0; i < dm->get_num_bss(); i++) {
            bss = dm->get_bss_by_ref(i);
    		dm_easy_mesh_t::macbytes_to_string(dm->m_device.m_device_info.intf.mac, dev_mac_str);
    		dm_easy_mesh_t::macbytes_to_string(bss.m_bss_info.ruid.mac, radio_mac_str);
			dm_easy_mesh_t::macbytes_to_string(bss.m_bss_info.bssid.mac, bssid_str);
			snprintf(parent, sizeof(em_2xlong_string_t), "%s@%s@%s@%s@%d", dm->m_network.m_net_info.id, 
					dev_mac_str, radio_mac_str, bssid_str, bss.m_bss_info.id.haul_type);
			criteria = dm->db_cfg_type_get_criteria(db_cfg_type_bss_list_update);
            if (dm_bss_list_t::set_config(m_db_client, bss, parent) != 0) {
                at_least_one_failed = true;
            }
        }
        if (at_least_one_failed == true) {
            at_least_one_failed = false;
        } else {
            dm->reset_db_cfg_type(db_cfg_type_bss_list_update);
        }
    } 

    if (dm->db_cfg_type_is_set(db_cfg_type_bss_list_delete)) {
        for (i = 0; i < dm->get_num_bss(); i++) {
            bss = dm->get_bss_by_ref(i);
			criteria = dm->db_cfg_type_get_criteria(db_cfg_type_bss_list_delete);
            if ((bss.match_criteria(criteria) == true) && 
					(dm_bss_list_t::update_db(m_db_client, dm_orch_type_db_delete, dm->get_bss(i)) != 0)) {
                at_least_one_failed = true;
            }
			dm_bss_list_t::update_list(bss, dm_orch_type_db_delete);
        }
        if (at_least_one_failed == true) {
            at_least_one_failed = false;
        } else {
            dm->reset_db_cfg_type(db_cfg_type_bss_list_delete);
        }
    } 

	if (dm->db_cfg_type_is_set(db_cfg_type_op_class_list_update)) {
        for (i = 0; i < dm->get_num_op_class(); i++) {
            op_class = dm->get_op_class_by_ref(i);
            dm_easy_mesh_t::macbytes_to_string(dm->m_op_class[i].m_op_class_info.id.ruid, radio_mac_str);
            printf("%s:%d: Op Class[%d] ruid: %s\tType: %d\tClass: %d\tClass: %d\n", __func__, __LINE__, i,
            	radio_mac_str, dm->m_op_class[i].m_op_class_info.id.type, dm->m_op_class[i].m_op_class_info.id.op_class,
				dm->m_op_class[i].m_op_class_info.op_class);
            snprintf(parent, sizeof(em_2xlong_string_t), "%s@%d@%d", radio_mac_str, dm->m_op_class[i].m_op_class_info.id.type, 
					dm->m_op_class[i].m_op_class_info.id.op_class);
			criteria = dm->db_cfg_type_get_criteria(db_cfg_type_op_class_list_update);
            if (dm_op_class_list_t::set_config(m_db_client, dm->m_op_class[i], parent) != 0) {
                at_least_one_failed = true;
            }
        }
        if (at_least_one_failed == true) {
            at_least_one_failed = false;
        } else {
            dm->reset_db_cfg_type(db_cfg_type_op_class_list_update);
        }
		printf("\n");
    } 

    if (dm->db_cfg_type_is_set(db_cfg_type_op_class_list_delete)) {
        for (i = 0; i < dm->get_num_op_class(); i++) {
            op_class = dm->get_op_class_by_ref(i);
            dm_easy_mesh_t::macbytes_to_string(op_class.m_op_class_info.id.ruid, radio_mac_str);
            printf("%s:%d: Op Class[%d] ruid: %s\tType: %d\tClass: %d\n", __func__, __LINE__, i,
            	radio_mac_str, op_class.m_op_class_info.id.type, op_class.m_op_class_info.id.op_class);
            snprintf(parent, sizeof(em_2xlong_string_t), "%s@%d@%d", radio_mac_str, op_class.m_op_class_info.id.type, op_class.m_op_class_info.id.op_class);
			criteria = dm->db_cfg_type_get_criteria(db_cfg_type_op_class_list_delete);
            if (dm_op_class_list_t::update_db(m_db_client, dm_orch_type_db_delete, dm->get_op_class(i)) != 0) {
                at_least_one_failed = true;
            }
			dm_op_class_list_t::update_list(op_class, dm_orch_type_db_delete);
        }
        
		if (at_least_one_failed == true) {
            at_least_one_failed = false;
        } else {
            dm->reset_db_cfg_type(db_cfg_type_op_class_list_delete);
        }
    } 

    if (dm->db_cfg_type_is_set(db_cfg_type_sta_list_update)) {
        sta = static_cast<dm_sta_t *> (hash_map_get_first(dm->m_sta_assoc_map));
        while (sta != NULL) {
			criteria = dm->db_cfg_type_get_criteria(db_cfg_type_sta_list_update);
            if (dm_sta_list_t::set_config(m_db_client, *sta, NULL) == 0) {
                dm->reset_db_cfg_type(db_cfg_type_sta_list_update);
            }
            sta = static_cast<dm_sta_t *> (hash_map_get_next(dm->m_sta_assoc_map, sta));
        }

        sta = static_cast<dm_sta_t *> (hash_map_get_first(dm->m_sta_assoc_map));
        while (sta != NULL) {
            tmp = sta;
			criteria = dm->db_cfg_type_get_criteria(db_cfg_type_sta_list_update);
            if (dm_sta_list_t::set_config(m_db_client, *sta, NULL) == 0) {
                dm->reset_db_cfg_type(db_cfg_type_sta_list_update);
            }

            dm_easy_mesh_t::macbytes_to_string(sta->m_sta_info.id, sta_mac_str);
            dm_easy_mesh_t::macbytes_to_string(sta->m_sta_info.bssid, bssid_str);
            dm_easy_mesh_t::macbytes_to_string(sta->m_sta_info.radiomac, radio_mac_str);
            snprintf(key, sizeof(em_2xlong_string_t), "%s@%s@%s", sta_mac_str, bssid_str, radio_mac_str);
            sta = static_cast<dm_sta_t *> (hash_map_get_next(dm->m_sta_assoc_map, sta));
            hash_map_remove(dm->m_sta_assoc_map, key);
            delete tmp;
        }
            
		dm->reset_db_cfg_type(db_cfg_type_sta_list_update);
    }

    if (dm->db_cfg_type_is_set(db_cfg_type_sta_list_delete)) {
        sta = static_cast<dm_sta_t *> (hash_map_get_first(dm->m_sta_dassoc_map));
        while (sta != NULL) {
			criteria = dm->db_cfg_type_get_criteria(db_cfg_type_sta_list_delete);
            if (dm_sta_list_t::update_db(m_db_client, dm_orch_type_db_delete, sta) != 0) {
                dm->reset_db_cfg_type(db_cfg_type_sta_list_delete);
            }
            sta = static_cast<dm_sta_t *> (hash_map_get_next(dm->m_sta_dassoc_map, sta));
        }

        sta = static_cast<dm_sta_t *> (hash_map_get_first(dm->m_sta_dassoc_map));
        while (sta != NULL) {
            tmp = sta;
			criteria = dm->db_cfg_type_get_criteria(db_cfg_type_sta_list_delete);
            if (dm_sta_list_t::update_db(m_db_client, dm_orch_type_db_delete, sta) != 0) {
                dm->reset_db_cfg_type(db_cfg_type_sta_list_delete);
            }
            dm_easy_mesh_t::macbytes_to_string(sta->m_sta_info.id, sta_mac_str);
            dm_easy_mesh_t::macbytes_to_string(sta->m_sta_info.bssid, bssid_str);
            dm_easy_mesh_t::macbytes_to_string(sta->m_sta_info.radiomac, radio_mac_str);
            snprintf(key, sizeof(em_2xlong_string_t), "%s@%s@%s", sta_mac_str, bssid_str, radio_mac_str);
            sta = static_cast<dm_sta_t *> (hash_map_get_next(dm->m_sta_dassoc_map, sta));

            hash_map_remove(dm->m_sta_dassoc_map, key);
            delete tmp;
        }
		dm->reset_db_cfg_type(db_cfg_type_sta_list_delete);

    }

    if (dm->db_cfg_type_is_set(db_cfg_type_sta_metrics_update)) {
        sta = static_cast<dm_sta_t *> (hash_map_get_first(dm->m_sta_map));
        while (sta != NULL) {
			criteria = dm->db_cfg_type_get_criteria(db_cfg_type_sta_metrics_update);
            if (dm_sta_list_t::set_config(m_db_client, *sta, NULL) == 0) {
                dm->reset_db_cfg_type(db_cfg_type_sta_metrics_update);
            }
            sta = static_cast<dm_sta_t *> (hash_map_get_next(dm->m_sta_map, sta));
        }
		dm->reset_db_cfg_type(db_cfg_type_sta_metrics_update);
    }

    if (dm->db_cfg_type_is_set(db_cfg_type_network_ssid_list_update)) {
        for (i = 0; i < dm->get_num_network_ssid(); i++) {
            net_ssid = dm->get_network_ssid_by_ref(i);
            snprintf(parent, sizeof(em_2xlong_string_t), "%s@%s",
                    global_netid, dm_network_ssid_t::haul_type_to_string(net_ssid.m_network_ssid_info.haul_type[0], haul_str));
            //printf("%s:%d: Key: %s\n", __func__, __LINE__, parent);
			criteria = dm->db_cfg_type_get_criteria(db_cfg_type_network_ssid_list_update);
            if (dm_network_ssid_list_t::set_config(m_db_client, dm->get_network_ssid_by_ref(i), parent) != 0) {
                at_least_one_failed = true;
            }
        }
        if (at_least_one_failed == true) {
            at_least_one_failed = false;
        } else {
            dm->reset_db_cfg_type(db_cfg_type_network_ssid_list_update);
        }
    }

    if (dm->db_cfg_type_is_set(db_cfg_type_policy_list_update)) {
        for (i = 0; i < dm->get_num_policy(); i++) {
			policy = dm->get_policy_by_ref(i);
			dm_easy_mesh_t::macbytes_to_string(policy.m_policy.id.dev_mac, dev_mac_str);
			dm_easy_mesh_t::macbytes_to_string(policy.m_policy.id.radio_mac, radio_mac_str);
            snprintf(parent, sizeof(em_2xlong_string_t), "%s@%s@%s@%d", global_netid, dev_mac_str, radio_mac_str, policy.m_policy.id.type);
            //printf("%s:%d: Key: %s\n", __func__, __LINE__, parent);
			criteria = dm->db_cfg_type_get_criteria(db_cfg_type_policy_list_update);
            if (dm_policy_list_t::set_config(m_db_client, dm->get_policy_by_ref(i), parent) != 0) {
                at_least_one_failed = true;
            }
        }
        if (at_least_one_failed == true) {
            at_least_one_failed = false;
        } else {
            dm->reset_db_cfg_type(db_cfg_type_policy_list_update);
        }
    }

	if (dm->db_cfg_type_is_set(db_cfg_type_scan_result_list_update)) {
        for (i = 0; i < dm->get_num_scan_results(); i++) {
            scan_result = dm->get_scan_result(i);
			dm_easy_mesh_t::macbytes_to_string(scan_result->m_scan_result.id.dev_mac, dev_mac_str);
			dm_easy_mesh_t::macbytes_to_string(scan_result->m_scan_result.id.scanner_mac, scanner_mac_str);
            snprintf(parent, sizeof(em_2xlong_string_t), "%s@%s@%s@%d@%d@%d",
                    scan_result->m_scan_result.id.net_id, dev_mac_str, scanner_mac_str, scan_result->m_scan_result.id.op_class, 
					scan_result->m_scan_result.id.channel, scan_result->m_scan_result.id.scanner_type);
            //printf("%s:%d: Key: %s\n", __func__, __LINE__, parent);
			criteria = dm->db_cfg_type_get_criteria(db_cfg_type_scan_result_list_update);
            if (dm_scan_result_list_t::set_config(m_db_client, *scan_result, parent) != 0) {
                at_least_one_failed = true;
            }
        }
        if (at_least_one_failed == true) {
            at_least_one_failed = false;
        } else {
            dm->reset_db_cfg_type(db_cfg_type_scan_result_list_update);
        }
    }

	if (dm->db_cfg_type_is_set(db_cfg_type_scan_result_list_delete)) {
        while (dm->get_num_scan_results() > 0) {
            scan_result = dm->get_scan_result(0);
            criteria = dm->db_cfg_type_get_criteria(db_cfg_type_scan_result_list_delete);
			// first delect self
			res.result = scan_result->get_scan_result();
        	res.index = scan_result_self_index;		
            if (dm_scan_result_list_t::update_db(m_db_client, dm_orch_type_db_delete, &res) != 0) {
                at_least_one_failed = true;
            }
			for (j = 0; j < scan_result->m_scan_result.num_neighbors; j++) {
				res.result = scan_result->get_scan_result();
        		res.index = j;		
            	if (dm_scan_result_list_t::update_db(m_db_client, dm_orch_type_db_delete, &res) != 0) {
                	at_least_one_failed = true;
            	}
			}
			dm_scan_result_list_t::update_list(*scan_result, scan_result_self_index, dm_orch_type_db_delete);
        }
        if (at_least_one_failed == true) {
            at_least_one_failed = false;
        } else {
            dm->reset_db_cfg_type(db_cfg_type_scan_result_list_delete);
        }
    }

    return 0;
}

void dm_easy_mesh_ctrl_t::update_network_topology()
{
    dm_easy_mesh_t *dm;

    assert(m_topology != NULL);
    dm = get_first_dm();
    while (dm != NULL) {
        if (dm->get_colocated() == false) {
            if (m_topology->find_topology(dm) == NULL) {
                m_topology->add(dm);
            }
        }
        dm = get_next_dm(dm);
    }

}

void dm_easy_mesh_ctrl_t::init_network_topology()
{
    dm_easy_mesh_t *dm;
    mac_addr_str_t dev_mac_str;

    dm = get_first_dm();
    while (dm != NULL) {
        if (dm->get_colocated() == true) {
            m_topology = new em_network_topo_t(dm);
            set_network_initialized();
            dm_easy_mesh_t::macbytes_to_string(dm->m_device.m_device_info.intf.mac, dev_mac_str);
            printf("%s:%d: Root: %s  added to network topology\n", __func__, __LINE__, dev_mac_str);
            break;
        }
        dm = get_next_dm(dm);
    }

    assert(m_topology != NULL);

    dm = get_first_dm();
    while (dm != NULL) {
        if (dm->get_colocated() == false) {
            if (m_topology->find_topology(dm) == NULL) {
                m_topology->add(dm);
            }
        }
        dm = get_next_dm(dm);
    }
}


int dm_easy_mesh_ctrl_t::init(const char *data_model_path, em_mgr_t *mgr)
{
    int rc;

    m_data_model_list.init(mgr);
    init_tables();

    if (m_db_client.init(data_model_path) != 0) {
        printf("%s:%d db init failed\n", __func__, __LINE__);
        return -1;
    }

    if ((rc = load_tables()) != 0) {
        printf("%s:%d: Load operation failed, err: %s\n", __func__, __LINE__, em_cmd_t::get_orch_op_str(static_cast<dm_orch_type_t> (rc)));
        return -1;
    }
    return 0;
}

dm_easy_mesh_ctrl_t::dm_easy_mesh_ctrl_t()
{
    m_initialized = false;
}

dm_easy_mesh_ctrl_t::~dm_easy_mesh_ctrl_t()
{

}

