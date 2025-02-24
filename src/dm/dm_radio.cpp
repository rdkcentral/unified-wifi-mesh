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
#include "dm_radio.h"
#include "dm_easy_mesh.h"
#include "dm_easy_mesh_ctrl.h"



int dm_radio_t::decode(const cJSON *obj, void *parent_id)
{
    cJSON *tmp;
    mac_addr_str_t  mac_str, dev_mac;

    memset(&m_radio_info, 0, sizeof(em_radio_info_t));

    if ((tmp = cJSON_GetObjectItem(obj, "ID")) != NULL) {
        snprintf(mac_str, sizeof(mac_str), "%s", cJSON_GetStringValue(tmp));
        dm_easy_mesh_t::string_to_macbytes(mac_str, m_radio_info.intf.mac);
        dm_easy_mesh_t::name_from_mac_address(&m_radio_info.intf.mac, m_radio_info.intf.name);
    }

    dm_radio_t::parse_radio_id_from_key((char *)parent_id, &m_radio_info.id);
    dm_easy_mesh_t::macbytes_to_string(m_radio_info.id.ruid, mac_str);
    dm_easy_mesh_t::macbytes_to_string(m_radio_info.id.dev_mac, dev_mac);

    printf("%s:%d: Radio: %s Device: %s Network: %s\n", __func__, __LINE__, mac_str, dev_mac, m_radio_info.id.net_id);

    if ((tmp = cJSON_GetObjectItem(obj, "Enabled")) != NULL) {
        m_radio_info.enabled = cJSON_IsTrue(tmp);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "NumberOfBSS")) != NULL) {
        m_radio_info.number_of_bss = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "NumberOfUnassocSta")) != NULL) {
        m_radio_info.number_of_unassoc_sta = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "Noise")) != NULL) {
        m_radio_info.noise = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "Utilization")) != NULL) {
        m_radio_info.utilization = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "TrafficSeparationCombinedFronthaul")) != NULL) {
        m_radio_info.traffic_sep_combined_fronthaul = cJSON_IsTrue(tmp);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "TrafficSeparationCombinedBackhaul")) != NULL) {
        m_radio_info.traffic_sep_combined_backhaul = cJSON_IsTrue(tmp);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "SteeringPolicy")) != NULL) {
        m_radio_info.steering_policy = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "ChannelUtilizationThreshold")) != NULL) {
        m_radio_info.channel_util_threshold = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "RCPISteeringThreshold")) != NULL) {
        m_radio_info.rcpi_steering_threshold = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "STAReportingRCPIThreshold")) != NULL) {
        m_radio_info.sta_reporting_rcpi_threshold = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "STAReportingRCPIHysteresisMarginOverride")) != NULL) {
        m_radio_info.sta_reporting_hysteresis_margin_override = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "ChannelUtilizationReportingThreshold")) != NULL) {
        m_radio_info.channel_utilization_reporting_threshold = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "AssociatedSTATrafficStatsInclusionPolicy")) != NULL) {
        m_radio_info.associated_sta_traffic_stats_inclusion_policy = cJSON_IsTrue(tmp);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "AssociatedSTALinkMetricsInclusionPolicy")) != NULL) {
        m_radio_info.associated_sta_link_mterics_inclusion_policy = cJSON_IsTrue(tmp);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "ChipsetVendor")) != NULL) {
        snprintf(m_radio_info.chip_vendor, sizeof(m_radio_info.chip_vendor), "%s", cJSON_GetStringValue(tmp));
    }

    if ((tmp = cJSON_GetObjectItem(obj, "APMetricsWiFi6")) != NULL) {
        m_radio_info.ap_metrics_wifi6 = cJSON_IsTrue(tmp);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "TransmitPowerLimit")) != NULL) {
        m_radio_info.transmit_power_limit = tmp->valuedouble;;
    }

    return 0;
}

void dm_radio_t::encode(cJSON *obj, em_get_radio_list_reason_t reason)
{
    mac_addr_str_t  mac_str;

    dm_easy_mesh_t::macbytes_to_string(m_radio_info.intf.mac, mac_str);
    cJSON_AddStringToObject(obj, "ID", mac_str);
    cJSON_AddBoolToObject(obj, "Enabled", m_radio_info.enabled);

    if (reason == em_get_radio_list_reason_radio_enable) {
        return;
    }

    cJSON_AddNumberToObject(obj, "NumberOfBSS", m_radio_info.number_of_bss);
    cJSON_AddNumberToObject(obj, "NumberOfUnassocSta", m_radio_info.number_of_unassoc_sta);
    cJSON_AddNumberToObject(obj, "Noise", m_radio_info.noise);
    cJSON_AddNumberToObject(obj, "Utilization", m_radio_info.utilization);

	if (reason == em_get_radio_list_reason_radio_summary) {
		return;
	}

    cJSON_AddBoolToObject(obj, "TrafficSeparationCombinedFronthaul", m_radio_info.traffic_sep_combined_fronthaul);
    cJSON_AddBoolToObject(obj, "TrafficSeparationCombinedBackhaul", m_radio_info.traffic_sep_combined_backhaul);
    cJSON_AddNumberToObject(obj, "SteeringPolicy", m_radio_info.steering_policy);
    cJSON_AddNumberToObject(obj, "ChannelUtilizationThreshold", m_radio_info.channel_util_threshold);
    cJSON_AddNumberToObject(obj, "RCPISteeringThreshold", m_radio_info.rcpi_steering_threshold);
    cJSON_AddNumberToObject(obj, "STAReportingRCPIThreshold", m_radio_info.sta_reporting_rcpi_threshold);
    cJSON_AddNumberToObject(obj, "STAReportingRCPIHysteresisMarginOverride", m_radio_info.sta_reporting_hysteresis_margin_override);
    cJSON_AddNumberToObject(obj, "ChannelUtilizationReportingThreshold", m_radio_info.channel_utilization_reporting_threshold);
    cJSON_AddBoolToObject(obj, "AssociatedSTATrafficStatsInclusionPolicy", m_radio_info.associated_sta_traffic_stats_inclusion_policy);
    cJSON_AddBoolToObject(obj, "AssociatedSTALinkMetricsInclusionPolicy", m_radio_info.associated_sta_link_mterics_inclusion_policy);
    cJSON_AddStringToObject(obj, "ChipsetVendor", m_radio_info.chip_vendor);
    cJSON_AddBoolToObject(obj, "APMetricsWiFi6", m_radio_info.ap_metrics_wifi6);
    cJSON_AddNumberToObject(obj, "TransmitPowerLimit", m_radio_info.transmit_power_limit);
}

dm_orch_type_t dm_radio_t::get_dm_orch_type(const dm_radio_t& radio)
{
    if ( this == &radio) {
        dm_orch_type_none;
    } else {
        return dm_orch_type_db_update;
    }
    return dm_orch_type_db_insert;
}

bool dm_radio_t::operator == (const dm_radio_t& obj) {   

    int ret = 0;

	ret += strncmp(this->m_radio_info.id.net_id, obj.m_radio_info.id.net_id, strlen(obj.m_radio_info.id.net_id));
    ret += (memcmp(&this->m_radio_info.id.dev_mac, &obj.m_radio_info.id.dev_mac, sizeof(mac_address_t)) != 0);
    ret += (memcmp(&this->m_radio_info.id.ruid, &obj.m_radio_info.id.ruid, sizeof(mac_address_t)) != 0);

    ret += (memcmp(&this->m_radio_info.intf.mac, &obj.m_radio_info.intf.mac, sizeof(mac_address_t)) != 0);
    ret += (memcmp(&this->m_radio_info.intf.name, &obj.m_radio_info.intf.name, sizeof(em_interface_name_t)) != 0);
    ret += !(this->m_radio_info.enabled == obj.m_radio_info.enabled);
	ret += !(this->m_radio_info.band == obj.m_radio_info.band);
    ret += !(this->m_radio_info.media_data.media_type == obj.m_radio_info.media_data.media_type);
    ret += !(this->m_radio_info.media_data.band == obj.m_radio_info.media_data.band);
    ret += !(this->m_radio_info.number_of_unassoc_sta == obj.m_radio_info.number_of_unassoc_sta);
    ret += !(this->m_radio_info.noise == obj.m_radio_info.noise);
    ret += !(this->m_radio_info.utilization == obj.m_radio_info.utilization);
    ret += !(this->m_radio_info.traffic_sep_combined_fronthaul == obj.m_radio_info.traffic_sep_combined_fronthaul);
    ret += !(this->m_radio_info.traffic_sep_combined_backhaul == obj.m_radio_info.traffic_sep_combined_backhaul);
    ret += !(this->m_radio_info.steering_policy == obj.m_radio_info.steering_policy);
    ret += !(this->m_radio_info.channel_util_threshold == obj.m_radio_info.channel_util_threshold);
    ret += !(this->m_radio_info.rcpi_steering_threshold == obj.m_radio_info.rcpi_steering_threshold);
    ret += !(this->m_radio_info.sta_reporting_rcpi_threshold == obj.m_radio_info.sta_reporting_rcpi_threshold);
    ret += !(this->m_radio_info.sta_reporting_hysteresis_margin_override  == obj.m_radio_info.sta_reporting_hysteresis_margin_override);
    ret += !(this->m_radio_info.channel_utilization_reporting_threshold  == obj.m_radio_info.channel_utilization_reporting_threshold);
    ret += !(this->m_radio_info.associated_sta_traffic_stats_inclusion_policy == obj.m_radio_info.associated_sta_traffic_stats_inclusion_policy);
    ret += !(this->m_radio_info.associated_sta_link_mterics_inclusion_policy == obj.m_radio_info.associated_sta_link_mterics_inclusion_policy);
    ret += (memcmp(&this->m_radio_info.chip_vendor,&obj.m_radio_info.chip_vendor,sizeof(em_long_string_t)) != 0);
    //ret += !(this->m_radio_info.ap_metrics_wifi6 == obj.m_radio_info.ap_metrics_wifi6);
    ret += !(this->m_radio_info.transmit_power_limit == obj.m_radio_info.transmit_power_limit);

    if (ret > 0)
        return false;
    else
        return true;
}

void dm_radio_t::operator = (const dm_radio_t& obj)
{
	if (this == &obj) { return; }
	strncpy(this->m_radio_info.id.net_id, obj.m_radio_info.id.net_id, strlen(obj.m_radio_info.id.net_id) + 1);
	memcpy(this->m_radio_info.id.dev_mac, obj.m_radio_info.id.dev_mac, sizeof(mac_address_t));
	memcpy(this->m_radio_info.id.ruid, obj.m_radio_info.id.ruid, sizeof(mac_address_t));
	
    memcpy(&this->m_radio_info.intf.mac, &obj.m_radio_info.intf.mac, sizeof(mac_address_t));
    memcpy(&this->m_radio_info.intf.name, &obj.m_radio_info.intf.name, sizeof(em_interface_name_t));
    
	this->m_radio_info.enabled = obj.m_radio_info.enabled;
	this->m_radio_info.band = obj.m_radio_info.band;
    this->m_radio_info.media_data.media_type = obj.m_radio_info.media_data.media_type;
    this->m_radio_info.media_data.band = obj.m_radio_info.media_data.band;
    this->m_radio_info.number_of_unassoc_sta = obj.m_radio_info.number_of_unassoc_sta;
    this->m_radio_info.noise = obj.m_radio_info.noise;
    this->m_radio_info.utilization = obj.m_radio_info.utilization;
    this->m_radio_info.traffic_sep_combined_fronthaul = obj.m_radio_info.traffic_sep_combined_fronthaul;
    this->m_radio_info.traffic_sep_combined_backhaul = obj.m_radio_info.traffic_sep_combined_backhaul;
    this->m_radio_info.steering_policy = obj.m_radio_info.steering_policy;
    this->m_radio_info.channel_util_threshold = obj.m_radio_info.channel_util_threshold;
    this->m_radio_info.rcpi_steering_threshold = obj.m_radio_info.rcpi_steering_threshold;
    this->m_radio_info.sta_reporting_rcpi_threshold = obj.m_radio_info.sta_reporting_rcpi_threshold;
    this->m_radio_info.sta_reporting_hysteresis_margin_override  = obj.m_radio_info.sta_reporting_hysteresis_margin_override;
    this->m_radio_info.channel_utilization_reporting_threshold  = obj.m_radio_info.channel_utilization_reporting_threshold;
    this->m_radio_info.associated_sta_traffic_stats_inclusion_policy = obj.m_radio_info.associated_sta_traffic_stats_inclusion_policy;
    this->m_radio_info.associated_sta_link_mterics_inclusion_policy = obj.m_radio_info.associated_sta_link_mterics_inclusion_policy;
    memcpy(&this->m_radio_info.chip_vendor,&obj.m_radio_info.chip_vendor,sizeof(em_long_string_t));
    //this->m_radio_info.ap_metrics_wifi6 = obj.m_radio_info.ap_metrics_wifi6;
    this->m_radio_info.transmit_power_limit = obj.m_radio_info.transmit_power_limit;
}

int dm_radio_t::parse_radio_id_from_key(const char *key, em_radio_id_t *id)
{
	em_long_string_t   str;
    char *tmp, *remain;
    unsigned int i = 0;
   
    strncpy(str, key, strlen(key) + 1);
    remain = str;
    while ((tmp = strchr(remain, '@')) != NULL) {
        if (i == 0) {
            *tmp = 0;
            strncpy(id->net_id, remain, strlen(remain) + 1);
            tmp++;
            remain = tmp;
        } else if (i == 1) {
            *tmp = 0;
            dm_easy_mesh_t::string_to_macbytes(remain, id->dev_mac);
            tmp++;
            dm_easy_mesh_t::string_to_macbytes(tmp, id->ruid);
        }  
        i++;
    }
   

    return 0;

}

void dm_radio_t::dump_radio_info()
{
	mac_addr_str_t dev_mac_str, ruid_str, radio_mac_str;
	
	dm_easy_mesh_t::macbytes_to_string(m_radio_info.id.dev_mac, dev_mac_str);
	dm_easy_mesh_t::macbytes_to_string(m_radio_info.id.ruid, radio_mac_str);
	dm_easy_mesh_t::macbytes_to_string(m_radio_info.intf.mac, ruid_str);

	printf("%s:%d: Id: %s@%s@%s\tmac: %s\tenabled: %d\tbss: %d\n", __func__, __LINE__, 
		m_radio_info.id.net_id, dev_mac_str, radio_mac_str, ruid_str, m_radio_info.enabled, m_radio_info.number_of_bss); 
}

dm_radio_t::dm_radio_t(em_radio_info_t *radio)
{
    memcpy(&m_radio_info, radio, sizeof(em_radio_info_t));
}

dm_radio_t::dm_radio_t(const dm_radio_t& radio)
{
    memcpy(&m_radio_info, &radio.m_radio_info, sizeof(em_radio_info_t));
}

dm_radio_t::dm_radio_t()
{

}

dm_radio_t::~dm_radio_t()
{

}
