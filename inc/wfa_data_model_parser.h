/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2025 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 **************************************************************************/

#ifndef WFA_DATA_MODEL_PARSE_H
#define WFA_DATA_MODEL_PARSE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cjson/cJSON.h"
#include "bus_common.h"

/* Prefixed WFA_ defines added; original names aliased for compatibility */
#define WFA_WIFI_OBJ_DEFINITIONS_NAME  "definitions"
#define WFA_DEVICELIST_OBJ_NAME       "DeviceList"
#define WFA_RADIOLIST_OBJ_NAME             "RadioList"
#define WFA_MAX_NUM_OF_OBJECTS_NAME    "Num_Of_Objects"

// #define WFA_NETWORK_OBJ_TREE_NAME         "Device.WiFi.DataElements.Network"
#define WFA_NETWORK_OBJ_TREE_NAME         "Network"
#define WFA_DEVICE_OBJ_TREE_NAME         "Network.DeviceList.{i}."
#define WFA_RADIO_OBJ_TREE_NAME        "Network.DeviceList.{i}.RadioList.{i}"
#define RADIO_OBJ_TREE_NAME WFA_RADIO_OBJ_TREE_NAME
#define WFA_BSSLIST_OBJ_TREE_NAME  "Network.DeviceList.{i}.RadioList.{i}.BSSList.{i}"


/*
Network.DeviceList.{i}.BTMSteeringDisallowedSTAList.{i}
Network.DeviceList.{i}.Default8021Q.PrimaryVID
Network.DeviceList.{i}.Default8021Q.DefaultPCP
Network.DeviceList.{i}.Default8021Q.Enable
Network.DeviceList.{i}.SSIDtoVIDMapping.{i}
Network.DeviceList.{i}.SSIDtoVIDMapping.{i}.SSID
Network.DeviceList.{i}.SSIDtoVIDMapping.{i}.VID
Network.DeviceList.{i}.CACStatus.TimeStamp
Network.DeviceList.{i}.CACStatus.AvailableChannelList.{i}
Network.DeviceList.{i}.CACStatus.AvailableChannelList.{i}.OpClass
Network.DeviceList.{i}.CACStatus.AvailableChannelList.{i}.Channel
Network.DeviceList.{i}.CACStatus.AvailableChannelList.{i}.Minutes
Network.DeviceList.{i}.CACStatus.NonOccupancyChannelList.{i}
Network.DeviceList.{i}.CACStatus.NonOccupancyChannelList.{i}.OpClass
Network.DeviceList.{i}.CACStatus.NonOccupancyChannelList.{i}.Channel
Network.DeviceList.{i}.CACStatus.NonOccupancyChannelList.{i}.Seconds
Network.DeviceList.{i}.CACStatus.ActiveChannelList.{i}.OpClass
Network.DeviceList.{i}.CACStatus.ActiveChannelList.{i}.Channel
Network.DeviceList.{i}.CACStatus.ActiveChannelList.{i}.Countdown
Network.DeviceList.{i}.PrioritizationSupport
Network.DeviceList.{i}.SPRule.{i}
Network.DeviceList.{i}.SPRule.{i}.ID
Network.DeviceList.{i}.SPRule.{i}.Precedence
Network.DeviceList.{i}.SPRule.{i}.Output
Network.DeviceList.{i}.SPRule.{i}.AlwaysMatch
Network.DeviceList.{i}.DSCPMap
Network.DeviceList.{i}.MaxPrioritizationRules
Network.DeviceList.{i}.MaxVIDs
Network.DeviceList.{i}.IEEE1905Security.OnboardingProtocol
Network.DeviceList.{i}.IEEE1905Security.IntegrityAlgorithm
Network.DeviceList.{i}.IEEE1905Security.EncryptionAlgorithm
Network.DeviceList.{i}.CountryCode
Network.DeviceList.{i}.ReportIndependentScans
Network.DeviceList.{i}.AnticipatedChannels.{i}
Network.DeviceList.{i}.AnticipatedChannels.{i}.OpClass

Network.DeviceList.{i}.AnticipatedChannelUsage.{i}.Entry.{i}.PowerLevel
Network.DeviceList.{i}.AnticipatedChannelUsage.{i}.Entry.{i}.ChannelUsag

etwork.DeviceList.{i}.APMLD.AffiliatedAP.{i}
Network.DeviceList.{i}.RadioList.{i}.BackhaulSta.MACAddress
Network.DeviceList.{i}.RadioList.{i}.UnassociatedStaList.{i}
Network.DeviceList.{i}.RadioList.{i}.ChannelUtilizationReportingThreshold
Network.DeviceList.{i}.RadioList.{i}.AssociatedSTATrafficStatsInclusionPolicy
Network.DeviceList.{i}.RadioList.{i}.AssociatedSTALinkMetricsInclusionPolicy
Network.DeviceList.{i}.RadioList.{i}.ChipsetVendor
Network.DeviceList.{i}.RadioList.{i}.ScanCapability.OnBootOnly
Network.DeviceList.{i}.RadioList.{i}.ScanCapability.Impact
Network.DeviceList.{i}.RadioList.{i}.ScanCapability.MinimumInterval
Network.DeviceList.{i}.RadioList.{i}.ScanCapability.OpClassList.{i}
Network.DeviceList.{i}.RadioList.{i}.ScanCapability.OpClassList.{i}.OpClass
Network.DeviceList.{i}.RadioList.{i}.ScanCapability.OpClassList.{i}.ChannelList.{i}
Network.DeviceList.{i}.RadioList.{i}.CurrentOperatingClasses.{i}
Network.DeviceList.{i}.RadioList.{i}.CurrentOperatingClasses.{i}
Network.DeviceList.{i}.RadioList.{i}.Capabilities.WiFi6bSTARole.MUEDCA
Network.DeviceList.{i}.RadioList.{i}.Capabilities.WiFi6bSTARole.TWTRequestor
Network.DeviceList.{i}.RadioList.{i}.Capabilities.WiFi6bSTARole.TWTResponder
Network.DeviceList.{i}.RadioList.{i}.Capabilities.AKMFrontHaul.{i}
Network.DeviceList.{i}.RadioList.{i}.Capabilities.AKMFrontHaul.{i}.OUI
Network.DeviceList.{i}.RadioList.{i}.Capabilities.AKMFrontHaul.{i}.Type
Network.DeviceList.{i}.RadioList.{i}.Capabilities.AKMBackhaul.{i}
Network.DeviceList.{i}.RadioList.{i}.Capabilities.AKMBackhaul.{i}.OUI
Network.DeviceList.{i}.RadioList.{i}.Capabilities.AKMBackhaul.{i}
Network.DeviceList.{i}.RadioList.{i}.Capabilities.OperatingClasses.{i}.NonOperable.{i}
Network.DeviceList.{i}.RadioList.{i}.Capabilities.WiFi7APRole.EMLMRFreqSeparation.{i}.FreqSeparation
Network.DeviceList.{i}.RadioList.{i}.Capabilities.WiFi7APRole.EMLSRFreqSeparation.{i}
Network.DeviceList.{i}.RadioList.{i}.Capabilities.WiFi7APRole.STRFreqSeparation.{i}
Network.DeviceList.{i}.RadioList.{i}.Capabilities.WiFi7APRole.STRFreqSeparation.{i}.RUID
Network.DeviceList.{i}.RadioList.{i}.Capabilities.WiFi7APRole.STRFreqSeparation.{i}.FreqSeparation
Network.DeviceList.{i}.RadioList.{i}.Capabilities.WiFi7APRole.NSTRFreqSeparation.{i}
Network.DeviceList.{i}.RadioList.{i}.Capabilities.WiFi7bSTARole.EMLMRSupport
Network.DeviceList.{i}.RadioList.{i}.Capabilities.WiFi7bSTARole.EMLSRSupport
Network.DeviceList.{i}.RadioList.{i}.Capabilities.WiFi7bSTARole.STRSupport
Network.DeviceList.{i}.RadioList.{i}.Capabilities.WiFi7bSTARole.NSTRSupport
Network.DeviceList.{i}.RadioList.{i}.Capabilities.WiFi7bSTARole.TIDLinkMapNegotiation
Network.DeviceList.{i}.RadioList.{i}.Capabilities.WiFi7bSTARole.EMLMRFreqSeparation.{i}
Network.DeviceList.{i}.RadioList.{i}.Capabilities.WiFi7bSTARole.EMLMRFreqSeparation.{i}.RUID
Network.DeviceList.{i}.RadioList.{i}.Capabilities.WiFi7bSTARole.EMLMRFreqSeparation.{i}.FreqSeparation
Network.DeviceList.{i}.RadioList.{i}.Capabilities.WiFi7bSTARole.EMLSRFreqSeparation.{i}
Network.DeviceList.{i}.RadioList.{i}.Capabilities.WiFi7bSTARole.STRFreqSeparation.{i}
Network.DeviceList.{i}.RadioList.{i}.Capabilities.WiFi7bSTARole.STRFreqSeparation.{i}.RUID
Network.DeviceList.{i}.RadioList.{i}.Capabilities.WiFi7bSTARole.STRFreqSeparation.{i}.FreqSeparation
Network.DeviceList.{i}.RadioList.{i}.Capabilities.WiFi7bSTARole.NSTRFreqSeparation.{i}
Network.DeviceList.{i}.RadioList.{i}.BSSList.{i}.MUStats.ULRU106PPDUCount
Network.DeviceList.{i}.RadioList.{i}.BSSList.{i}.MUStats.ULRU242PPDUCount
Network.DeviceList.{i}.RadioList.{i}.BSSList.{i}.MUStats.ULRU484PPDUCount
Network.DeviceList.{i}.RadioList.{i}.BSSList.{i}.MUStats.ULRU996PPDUCount
Network.DeviceList.{i}.RadioList.{i}.BSSList.{i}.MUStats.ULRU1992PPDUCount
Network.DeviceList.{i}.RadioList.{i}.BackhaulSta.MACAddress
Network.DeviceList.{i}.RadioList.{i}.UnassociatedStaList.{i}
Network.DeviceList.{i}.RadioList.{i}.UnassociatedStaList.{i}.
Network.DeviceList.{i}.RadioList.{i}.ScanCapability.OpClassList.{i}.ChannelList.{i}
Network.DeviceList.{i}.RadioList.{i}.DisAllowedOpClassChannels.{i}.ChannelList.{i}
Network.MSCSDisallowedStaList.{i}
Network.SCSDisallowedStaList.{i}
Network.NetworkSSIDList.{i}.HaulType.{i}
Network.STABlock.{i}
Network.STABlock.{i}.BlockedSTA
Network.STABlock.{i}.BSSID.{i}
Network.STABlock.{i}.Schedule.{i}
Network.STABlock.{i}.Schedule.{i}.Alias
Network.STABlock.{i}.Schedule.{i}.Day.{i}
Network.STABlock.{i}.Schedule.{i}.StartTime
Network.STABlock.{i}.Schedule.{i}.Duration
Network.PreferredBackhauls.{i}
Network.ColocatedAgentID

*/

#define WFA_DML_GET_CB                 1
#define DML_GET_CB WFA_DML_GET_CB

#define WFA_DML_SET_CB                 2
#define DML_SET_CB WFA_DML_SET_CB

#ifdef __cplusplus
extern "C" {
#endif

#define decode_json_param_object(json, key, value) \
{   \
    value = cJSON_GetObjectItem(json, key);     \
    if ((value == NULL) || (cJSON_IsObject(value) == false)) {  \
        em_printfout(" Validation failed for key:%s\n", __func__, __LINE__, key);   \
        return RETURN_ERR;  \
    }   \
}   \

#define decode_json_param_string(json, key, value) \
{   \
    value = cJSON_GetObjectItem(json, key);     \
    if ((value == NULL) || (cJSON_IsString(value) == false) ||  \
            (value->valuestring == NULL) || (strcmp(value->valuestring, "") == 0)) {    \
        em_printfout(" Validation failed for key:%s\n", __func__, __LINE__, key);   \
        return RETURN_ERR;  \
    }   \
}   \

#define decode_json_param_integer(json, key, value) \
{   \
    value = cJSON_GetObjectItem(json, key);     \
    if ((value == NULL) || (cJSON_IsNumber(value) == false)) {  \
        em_printfout(" Validation failed for key:%s\n", __func__, __LINE__, key);   \
        return RETURN_ERR;  \
    }   \
}   \

#define validate_current_json_obj_param_name(json) \
{   \
    if (json == NULL || json->string == NULL) {  \
        em_printfout(" current json obj param name not found\n", __func__, __LINE__);   \
        return RETURN_ERR;  \
    }   \
}   \

#define decode_json_param_bool(json, key, value) \
{   \
    value = cJSON_GetObjectItem(json, key);     \
    if ((value == NULL) || (cJSON_IsBool(value) == false)) {    \
        em_printfout(" Validation failed for key:%s\n", __func__, __LINE__, key);   \
        return RETURN_ERR;  \
    }   \
}   \

#define  WFA_get_func_address    dlsym
#define  get_func_address WFA_get_func_address

typedef struct bus_data_cb_func {
    char                  *cb_table_name;
    bus_callback_table_t  cb_func;
} bus_data_cb_func_t;

// int register_wfa_dml(bus_handle_t *handle, const char *json_name);

// //remove later
// int wfa_set_bus_callbackfunc_pointers(const char *full_namespace, bus_callback_table_t *cb_table);
// int wfa_bus_register_namespace(bus_handle_t *handle, const char *full_namespace, bus_element_type_t element_type,
//                             bus_callback_table_t cb_table, data_model_properties_t  data_model_value, int num_of_rows);
#ifdef __cplusplus
}
#endif
#endif //WFA_DATA_MODEL_PARSE_H
