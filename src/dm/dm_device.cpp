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
#include "dm_device.h"
#include "dm_easy_mesh.h"
#include "dm_easy_mesh_ctrl.h"
//#include "util.h"

int dm_device_t::decode(const cJSON *obj, void *parent_id)
{
    cJSON *tmp, *tmp_arr;
    mac_addr_str_t  mac_str;
    unsigned int i;

    char *net_id = (char *)parent_id;
	
    memset(&m_device_info, 0, sizeof(em_device_info_t));
    if ((tmp = cJSON_GetObjectItem(obj, "ID")) != NULL) {
        snprintf(mac_str, sizeof(mac_str), "%s", cJSON_GetStringValue(tmp));
       	dm_easy_mesh_t::string_to_macbytes(mac_str, m_device_info.id.mac);
	dm_easy_mesh_t::name_from_mac_address(&m_device_info.id.mac, m_device_info.id.name);
    }
    snprintf(m_device_info.net_id, sizeof(m_device_info.net_id), "%s", net_id);
    if ((tmp = cJSON_GetObjectItem(obj, "MultiAPCapabilities")) != NULL) {
        snprintf(m_device_info.multi_ap_cap, sizeof(m_device_info.multi_ap_cap), "%s", cJSON_GetStringValue(tmp));
    }
    if ((tmp = cJSON_GetObjectItem(obj, "CollectionInterval")) != NULL) {
       	m_device_info.coll_interval = tmp->valuedouble;
   	}
    if ((tmp = cJSON_GetObjectItem(obj, "NumberOfRadios")) != NULL) {
        m_device_info.num_radios = tmp->valuedouble;
    }
    if ((tmp = cJSON_GetObjectItem(obj, "ReportUnsuccessfulAssociations")) != NULL) {
       	m_device_info.report_unsuccess_assocs = cJSON_IsTrue(tmp);
    }
    if ((tmp = cJSON_GetObjectItem(obj, "MaxReportingRate")) != NULL) {
        m_device_info.max_reporting_rate = tmp->valuedouble;
    }
    if ((tmp = cJSON_GetObjectItem(obj, "APMetricsReportingInterval")) != NULL) {
       m_device_info.ap_metrics_reporting_interval = tmp->valuedouble;
    }
    if ((tmp = cJSON_GetObjectItem(obj, "Manufacturer")) != NULL) {
        snprintf(m_device_info.manufacturer, sizeof(m_device_info.manufacturer), "%s", cJSON_GetStringValue(tmp));
    }
    if ((tmp = cJSON_GetObjectItem(obj, "SerialNumber")) != NULL) {
        snprintf(m_device_info.serial_number, sizeof(m_device_info.serial_number), "%s", cJSON_GetStringValue(tmp));
    }
    if ((tmp = cJSON_GetObjectItem(obj, "ManufacturerModel")) != NULL) {
        snprintf(m_device_info.manufacturer_model, sizeof(m_device_info.manufacturer_model), "%s", cJSON_GetStringValue(tmp));
    }
    if ((tmp = cJSON_GetObjectItem(obj, "SoftwareVersion")) != NULL) {
    	snprintf(m_device_info.software_ver, sizeof(m_device_info.software_ver), "%s", cJSON_GetStringValue(tmp));
    }
    if ((tmp = cJSON_GetObjectItem(obj, "ExecutionEnv")) != NULL) {
        snprintf(m_device_info.exec_env, sizeof(m_device_info.exec_env), "%s", cJSON_GetStringValue(tmp));
    }
    if ((tmp = cJSON_GetObjectItem(obj, "DSCPMap")) != NULL) {
        snprintf(m_device_info.dscp_map, sizeof(m_device_info.dscp_map), "%s", cJSON_GetStringValue(tmp));
    }
    if ((tmp = cJSON_GetObjectItem(obj, "MaxPrioritizationRules")) != NULL) {
        m_device_info.max_pri_rules = tmp->valuedouble;
    }
    if ((tmp = cJSON_GetObjectItem(obj, "MaxVIDs")) != NULL) {
        m_device_info.max_vids = tmp->valuedouble;
    }
    if ((tmp = cJSON_GetObjectItem(obj, "CountryCode")) != NULL) {
       snprintf(m_device_info.country_code, sizeof(m_device_info.country_code), "%s", cJSON_GetStringValue(tmp));
    }
    if ((tmp = cJSON_GetObjectItem(obj, "PrioritizationSupport")) != NULL) {
       m_device_info.prioritization_sup = cJSON_IsTrue(tmp);
    }
    if ((tmp = cJSON_GetObjectItem(obj, "ReportIndependentScans")) != NULL) {
       m_device_info.report_ind_scans = cJSON_IsTrue(tmp);
    }
    if ((tmp = cJSON_GetObjectItem(obj, "TrafficSeparationAllowed")) != NULL) {
       m_device_info.traffic_sep_allowed = cJSON_IsTrue(tmp);
    }
    if ((tmp = cJSON_GetObjectItem(obj, "ServicePrioritizationAllowed")) != NULL) {
        m_device_info.svc_prio_allowed = cJSON_IsTrue(tmp);
    }
    if ((tmp = cJSON_GetObjectItem(obj, "DFSEnable")) != NULL) {
        m_device_info.dfs_enable = cJSON_IsTrue(tmp);
    }
    if ((tmp = cJSON_GetObjectItem(obj, "MaxUnsuccessfulAssociationReportingRate")) != NULL) {
        m_device_info.max_unsuccessful_assoc_report_rate = tmp->valuedouble;
    }
    if ((tmp = cJSON_GetObjectItem(obj, "STASteeringState")) != NULL) {
        m_device_info.sta_steer_state = cJSON_IsTrue(tmp);
    }
    if ((tmp = cJSON_GetObjectItem(obj, "CoordinatedCACAllowed")) != NULL) {
        m_device_info.coord_cac_allowed = cJSON_IsTrue(tmp);
    }
	
    if ((tmp = cJSON_GetObjectItem(obj, "ControllerOperationMode")) != NULL) {
        snprintf(m_device_info.ctrl_operation_mode, sizeof(m_device_info.ctrl_operation_mode), "%s", cJSON_GetStringValue(tmp));
    }
    if ((tmp = cJSON_GetObjectItem(obj, "BackhaulMACAddress")) != NULL) {
        snprintf(mac_str, sizeof(mac_str), "%s", cJSON_GetStringValue(tmp));
        dm_easy_mesh_t::string_to_macbytes(mac_str, m_device_info.backhaul_mac.mac);
	dm_easy_mesh_t::name_from_mac_address(&m_device_info.backhaul_mac.mac, m_device_info.backhaul_mac.name);
    }
  
    if ((tmp_arr = cJSON_GetObjectItem(obj, "BackhaulDownMACAddress")) != NULL) {
        m_device_info.num_backhaul_down_mac = cJSON_GetArraySize(tmp_arr);
        for (i = 0; i < m_device_info.num_backhaul_down_mac; i++) {
            tmp = cJSON_GetArrayItem(tmp_arr, i);
            snprintf(m_device_info.backhaul_down_mac[i], sizeof(m_device_info.backhaul_down_mac[i]), "%s", cJSON_GetStringValue(tmp));
        }
    }

    if ((tmp = cJSON_GetObjectItem(obj, "BackhaulMediaType")) != NULL) {
        //strncpy(m_device_info.backhaul_media_type, cJSON_GetStringValue(tmp), strlen(cJSON_GetStringValue(tmp))); //need to check with soumya
    }
	
    if ((tmp = cJSON_GetObjectItem(obj, "BackhaulPHYRate")) != NULL) {
        m_device_info.backhaul_phyrate = tmp->valuedouble;
    }
    if ((tmp = cJSON_GetObjectItem(obj, "BackhaulALID")) != NULL) {
        snprintf(mac_str, sizeof(mac_str), "%s", cJSON_GetStringValue(tmp));
        dm_easy_mesh_t::string_to_macbytes(mac_str, m_device_info.backhaul_alid.mac);
	dm_easy_mesh_t::name_from_mac_address(&m_device_info.backhaul_alid.mac, m_device_info.backhaul_alid.name);
    }
    if ((tmp = cJSON_GetObjectItem(obj, "TrafficSeparationCapability")) != NULL) {
        m_device_info.traffic_sep_cap = cJSON_IsTrue(tmp);
    }
    if ((tmp = cJSON_GetObjectItem(obj, "EasyConnectCapability")) != NULL) {
        m_device_info.easy_conn_cap = cJSON_IsTrue(tmp);
    }
    if ((tmp = cJSON_GetObjectItem(obj, "TestCapabilities")) != NULL) {
        m_device_info.test_cap = tmp->valuedouble;
    }
    if ((tmp = cJSON_GetObjectItem(obj, "APMLDMaxLinks")) != NULL) {
        m_device_info.apmld_maxlinks = tmp->valuedouble;
    }
	
    if ((tmp = cJSON_GetObjectItem(obj, "TIDLinkMapping")) != NULL) {
        snprintf(m_device_info.tidlink_map, sizeof(m_device_info.tidlink_map), "%s", cJSON_GetStringValue(tmp));
    }
	
    if ((tmp = cJSON_GetObjectItem(obj, "AssociatedSTAReportingInterval")) != NULL) {
        m_device_info.assoc_sta_reporting_int = tmp->valuedouble;
    }
    if ((tmp = cJSON_GetObjectItem(obj, "MaxNumMLDs")) != NULL) {
        m_device_info.max_nummlds = tmp->valuedouble;
    }
    if ((tmp = cJSON_GetObjectItem(obj, "bSTAMLDMaxLinks")) != NULL) {
        m_device_info.bstamld_maxlinks = tmp->valuedouble;
    }
    return 0;
}
void dm_device_t::encode(cJSON *obj)
{
    mac_addr_str_t  mac_str;
    unsigned int i;

    dm_easy_mesh_t::macbytes_to_string(m_device_info.id.mac, mac_str);
    cJSON_AddStringToObject(obj, "ID", mac_str);
    cJSON_AddStringToObject(obj, "MultiAPCapabilities", m_device_info.multi_ap_cap);
    cJSON_AddNumberToObject(obj, "CollectionInterval", m_device_info.coll_interval);
    cJSON_AddNumberToObject(obj, "NumberOfRadios", m_device_info.num_radios);
    cJSON_AddBoolToObject(obj, "ReportUnsuccessfulAssociations", m_device_info.report_unsuccess_assocs);
    cJSON_AddNumberToObject(obj, "MaxReportingRate", m_device_info.max_reporting_rate);
    cJSON_AddNumberToObject(obj, "APMetricsReportingInterval", m_device_info.ap_metrics_reporting_interval);
    cJSON_AddStringToObject(obj, "Manufacturer", m_device_info.manufacturer);
    cJSON_AddStringToObject(obj, "SerialNumber", m_device_info.serial_number);
    cJSON_AddStringToObject(obj, "ManufacturerModel", m_device_info.manufacturer_model);
    cJSON_AddStringToObject(obj, "SoftwareVersion", m_device_info.software_ver);
    cJSON_AddStringToObject(obj, "ExecutionEnv", m_device_info.exec_env);
    cJSON_AddStringToObject(obj, "DSCPMap", m_device_info.dscp_map);
    cJSON_AddNumberToObject(obj, "MaxPrioritizationRules", m_device_info.max_pri_rules);
    cJSON_AddNumberToObject(obj, "MaxVIDs", m_device_info.max_vids);
    cJSON_AddStringToObject(obj, "CountryCode", m_device_info.country_code);
    cJSON_AddBoolToObject(obj, "PrioritizationSupport", m_device_info.prioritization_sup);
    cJSON_AddBoolToObject(obj, "ReportIndependentScans", m_device_info.report_ind_scans);
    cJSON_AddBoolToObject(obj, "TrafficSeparationAllowed", m_device_info.traffic_sep_allowed);
    cJSON_AddBoolToObject(obj, "ServicePrioritizationAllowed", m_device_info.svc_prio_allowed);
    cJSON_AddBoolToObject(obj, "DFSEnable", m_device_info.dfs_enable);
    cJSON_AddNumberToObject(obj, "MaxUnsuccessfulAssociationReportingRate", m_device_info.max_unsuccessful_assoc_report_rate);
    cJSON_AddBoolToObject(obj, "STASteeringState", m_device_info.sta_steer_state);
    cJSON_AddBoolToObject(obj, "CoordinatedCACAllowed", m_device_info.coord_cac_allowed);
    cJSON_AddStringToObject(obj, "ControllerOperationMode", m_device_info.ctrl_operation_mode);
    dm_easy_mesh_t::macbytes_to_string(m_device_info.backhaul_mac.mac, mac_str);
    cJSON_AddStringToObject(obj, "BackhaulMACAddress", mac_str);

    cJSON *backhaul_downmacArray = cJSON_CreateArray();
    for (i = 0; i < m_device_info.num_backhaul_down_mac; i++) {
        cJSON_AddItemToArray(backhaul_downmacArray, cJSON_CreateString(m_device_info.backhaul_down_mac[i]));
    }
    // Add the array to the object
    cJSON_AddItemToObject(obj, "BackhaulDownMACAddress", backhaul_downmacArray);

    //dm_easy_mesh_t::macbytes_to_string(m_device_info.backhaul_down_mac.mac, mac_str);
    //cJSON_AddStringToObject(obj, "BackhaulDownMACAddress", mac_str);
    //cJSON_AddStringToObject(obj, "BackhaulMediaType", m_device_info.backhaul_media_type); //need to check with soumya
    dm_easy_mesh_t::macbytes_to_string(m_device_info.backhaul_alid.mac, mac_str);
    cJSON_AddNumberToObject(obj, "BackhaulPHYRate", m_device_info.backhaul_phyrate);
    cJSON_AddStringToObject(obj, "BackhaulALID", mac_str);
    cJSON_AddBoolToObject(obj, "TrafficSeparationCapability", m_device_info.traffic_sep_cap);
    cJSON_AddBoolToObject(obj, "EasyConnectCapability", m_device_info.easy_conn_cap);
    cJSON_AddNumberToObject(obj, "TestCapabilities", m_device_info.test_cap);
    cJSON_AddNumberToObject(obj, "APMLDMaxLinks", m_device_info.apmld_maxlinks);
    cJSON_AddStringToObject(obj, "TIDLinkMapping", m_device_info.tidlink_map);
    cJSON_AddNumberToObject(obj, "AssociatedSTAReportingInterval", m_device_info.assoc_sta_reporting_int);
    cJSON_AddNumberToObject(obj, "MaxNumMLDs", m_device_info.max_nummlds);
    cJSON_AddNumberToObject(obj, "bSTAMLDMaxLinks", m_device_info.bstamld_maxlinks);
}

dm_orch_type_t dm_device_t::get_dm_orch_type(const dm_device_t& device)
{
    if ( this == &device) {
         dm_orch_type_none;
    } else {
        return dm_orch_type_dev_update;
    }
    return dm_orch_type_dev_insert;
}   

void dm_device_t::operator = (const dm_device_t& obj) {

    memcpy(&this->m_device_info.id.mac ,&obj.m_device_info.id.mac,sizeof(mac_address_t));
    memcpy(&this->m_device_info.id.name,&obj.m_device_info.id.name,sizeof(em_interface_name_t));
    memcpy(&this->m_device_info.net_id,&obj.m_device_info.net_id,sizeof(em_long_string_t));
    memcpy(&this->m_device_info.multi_ap_cap,&obj.m_device_info.multi_ap_cap,sizeof(em_long_string_t));
    this->m_device_info.coll_interval = obj.m_device_info.coll_interval;
    this->m_device_info.num_radios = obj.m_device_info.num_radios;
    this->m_device_info.report_unsuccess_assocs = obj.m_device_info.report_unsuccess_assocs;
    this->m_device_info.max_reporting_rate = obj.m_device_info.max_reporting_rate;
    this->m_device_info.ap_metrics_reporting_interval = obj.m_device_info.ap_metrics_reporting_interval;
    memcpy(&this->m_device_info.manufacturer,&obj.m_device_info.manufacturer,sizeof(em_long_string_t));
    memcpy(&this->m_device_info.serial_number,&obj.m_device_info.serial_number,sizeof(em_long_string_t));
    memcpy(&this->m_device_info.manufacturer_model,&obj.m_device_info.manufacturer_model,sizeof(em_long_string_t));
    memcpy(&this->m_device_info.software_ver,&obj.m_device_info.software_ver,sizeof(em_string_t));
    memcpy(&this->m_device_info.exec_env,&obj.m_device_info.exec_env,sizeof(em_string_t));
    memcpy(&this->m_device_info.country_code,&obj.m_device_info.country_code,sizeof(em_tiny_string_t));
    //this->m_device_info.country_code = obj.m_device_info.country_code;
    this->m_device_info.traffic_sep_allowed = obj.m_device_info.traffic_sep_allowed;
    this->m_device_info.svc_prio_allowed = obj.m_device_info.svc_prio_allowed;
    this->m_device_info.dfs_enable = obj.m_device_info.dfs_enable;
    this->m_device_info.max_unsuccessful_assoc_report_rate = obj.m_device_info.max_unsuccessful_assoc_report_rate;
    this->m_device_info.sta_steer_state = obj.m_device_info.sta_steer_state;
    this->m_device_info.coord_cac_allowed = obj.m_device_info.coord_cac_allowed;
    memcpy(&this->m_device_info.backhaul_mac.mac ,&obj.m_device_info.backhaul_mac.mac,sizeof(mac_address_t));
    memcpy(&this->m_device_info.backhaul_mac.name,&obj.m_device_info.backhaul_mac.name,sizeof(em_interface_name_t));
    memcpy(&this->m_device_info.backhaul_media_type,&obj.m_device_info.backhaul_media_type,sizeof(wifi_ieee80211Variant_t));
    this->m_device_info.backhaul_media_type = obj.m_device_info.backhaul_media_type;
    memcpy(&this->m_device_info.backhaul_alid.mac ,&obj.m_device_info.backhaul_alid.mac,sizeof(mac_address_t));
    memcpy(&this->m_device_info.backhaul_alid.name,&obj.m_device_info.backhaul_alid.name,sizeof(em_interface_name_t));
    this->m_device_info.traffic_sep_cap = obj.m_device_info.traffic_sep_cap;
    this->m_device_info.easy_conn_cap = obj.m_device_info.easy_conn_cap;
    this->m_device_info.test_cap = obj.m_device_info.test_cap;
    memcpy(&this->m_device_info.primary_device_type,&obj.m_device_info.primary_device_type,sizeof(em_small_string_t));
    memcpy(&this->m_device_info.backhaul_media_type,&obj.m_device_info.secondary_device_type,sizeof(em_small_string_t));
}

bool dm_device_t::operator == (const dm_device_t& obj)
{
    int ret = 0;
    ret += (memcmp(&this->m_device_info.id.mac ,&obj.m_device_info.id.mac,sizeof(mac_address_t)) != 0);
    ret += (memcmp(&this->m_device_info.id.name,&obj.m_device_info.id.name,sizeof(em_interface_name_t)) != 0);
    ret += (memcmp(&this->m_device_info.net_id,&obj.m_device_info.net_id,sizeof(em_long_string_t)) != 0);
    ret += (memcmp(&this->m_device_info.multi_ap_cap,&obj.m_device_info.multi_ap_cap,sizeof(em_long_string_t)) != 0);
    ret += !(this->m_device_info.coll_interval == obj.m_device_info.coll_interval);
    ret += !(this->m_device_info.num_radios == obj.m_device_info.num_radios);
    ret += !(this->m_device_info.report_unsuccess_assocs == obj.m_device_info.report_unsuccess_assocs);
    ret += !(this->m_device_info.max_reporting_rate == obj.m_device_info.max_reporting_rate);
    ret += !(this->m_device_info.ap_metrics_reporting_interval == obj.m_device_info.ap_metrics_reporting_interval);
    ret += (memcmp(&this->m_device_info.manufacturer,&obj.m_device_info.manufacturer,sizeof(em_long_string_t)) != 0);
    ret += (memcmp(&this->m_device_info.serial_number,&obj.m_device_info.serial_number,sizeof(em_long_string_t)) != 0);
    ret += (memcmp(&this->m_device_info.manufacturer_model,&obj.m_device_info.manufacturer_model,sizeof(em_long_string_t)) != 0);
    ret += (memcmp(&this->m_device_info.software_ver,&obj.m_device_info.software_ver,sizeof(em_string_t)) != 0);
    ret += (memcmp(&this->m_device_info.exec_env,&obj.m_device_info.exec_env,sizeof(em_string_t)) != 0);
    ret += (memcmp(&this->m_device_info.country_code,&obj.m_device_info.country_code,sizeof(em_tiny_string_t)) != 0);
    ret += !(this->m_device_info.traffic_sep_allowed == obj.m_device_info.traffic_sep_allowed);
    ret += !(this->m_device_info.svc_prio_allowed == obj.m_device_info.svc_prio_allowed);
    ret += !(this->m_device_info.dfs_enable == obj.m_device_info.dfs_enable);
    ret += !(this->m_device_info.max_unsuccessful_assoc_report_rate == obj.m_device_info.max_unsuccessful_assoc_report_rate);
    ret += !(this->m_device_info.sta_steer_state == obj.m_device_info.sta_steer_state);
    ret += !(this->m_device_info.coord_cac_allowed == obj.m_device_info.coord_cac_allowed);
    ret += (memcmp(&this->m_device_info.backhaul_mac.mac ,&obj.m_device_info.backhaul_mac.mac,sizeof(mac_address_t)) != 0);
    ret += (memcmp(&this->m_device_info.backhaul_mac.name,&obj.m_device_info.backhaul_mac.name,sizeof(em_interface_name_t)) != 0);
    ret += (memcmp(&this->m_device_info.backhaul_media_type,&obj.m_device_info.backhaul_media_type,sizeof(wifi_ieee80211Variant_t)) != 0);
    ret += (memcmp(&this->m_device_info.backhaul_alid.mac ,&obj.m_device_info.backhaul_alid.mac,sizeof(mac_address_t)) != 0);
    ret += (memcmp(&this->m_device_info.backhaul_alid.name,&obj.m_device_info.backhaul_alid.name,sizeof(em_interface_name_t)) != 0);
    ret += !(this->m_device_info.backhaul_alid.name == obj.m_device_info.backhaul_alid.name);
    ret += !(this->m_device_info.backhaul_alid.mac == obj.m_device_info.backhaul_alid.mac);
    ret += !(this->m_device_info.traffic_sep_cap == obj.m_device_info.traffic_sep_cap);
    ret += !(this->m_device_info.easy_conn_cap == obj.m_device_info.easy_conn_cap);
    ret += !(this->m_device_info.test_cap == obj.m_device_info.test_cap);
    ret += !(this->m_device_info.primary_device_type == obj.m_device_info.primary_device_type);
    ret += !(this->m_device_info.secondary_device_type == obj.m_device_info.secondary_device_type);
    ret += (memcmp(&this->m_device_info.primary_device_type,&obj.m_device_info.primary_device_type,sizeof(em_small_string_t)) != 0);;
    ret += (memcmp(&this->m_device_info.backhaul_media_type,&obj.m_device_info.secondary_device_type,sizeof(em_small_string_t)) != 0);

    if (ret > 0)
        return false;
    else
        return true;
}

dm_device_t::dm_device_t(em_device_info_t *dev)
{
    memcpy(&m_device_info, dev, sizeof(em_device_info_t));
}

dm_device_t::dm_device_t(const dm_device_t& dev)
{
	memcpy(&m_device_info, &dev.m_device_info, sizeof(em_device_info_t));
}

dm_device_t::dm_device_t()
{

}

dm_device_t::~dm_device_t()
{

}
