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

#ifndef TR_181_H
#define TR_181_H

// #include "em_ctrl.h"
#include "bus.h"
#include <string>
#include <memory>
#include <cjson/cJSON.h>
#include <unistd.h>

#define DEVICE_WIFI_DATAELEMENTS_NETWORK_COLOCATEDAGENTID   "Device.WiFi.DataElements.Network.ColocatedAgentID"
#define DEVICE_WIFI_DATAELEMENTS_NETWORK_CONTROLLERID       "Device.WiFi.DataElements.Network.ControllerID"
//#define DEVICE_WIFI_DATAELEMENTS_NETWORK_SETSSID_CMD "Device.WiFi.DataElements.Network.SetSSID()"
#define DEVICE_WIFI_DATAELEMENTS_NETWORK_SETSSID_CMD        "Device.WiFi.DataElements.Network.SetSSID"
//Orchestrator
#define DEVICE_WIFI_DATAELEMENTS_NETWORK_TOPOLOGY           "Device.WiFi.DataElements.Network.Topology"
#define DEVICE_WIFI_DATAELEMENTS_NETWORK_NODE_SYNC          "Device.WiFi.DataElements.Network.NodeSynchronize"
#define DEVICE_WIFI_DATAELEMENTS_NETWORK_NODE_CFG_POLICY    "Device.WiFi.DataElements.Network.NodeConfigurePolicy"

#define LIST_OF_DEFINITION_NAME "List_Of_Def"
#define MAX_NUM_OF_OBJECTS_NAME "Num_Of_Objects"

// typedef struct {
//     em_short_string_t ssid;
//     bool enable;
//     em_short_string_t add_remove_change;
//     em_short_string_t passphrase;
//     em_short_string_t band;
//     em_short_string_t akms_allowed;
//     bool advertisement_enabled;
//     em_short_string_t mfp_config;
//     em_short_string_t mobility_domain;
//     em_short_string_t haul_type;
// } tr_cmd_setssid;

typedef struct {
    uint32_t id;
    bus_error_t rc;
} bus_resp_get_t;
// Callback function typedefs
// typedef bool (*dml_get_bool_cb_t)    (void *obj_ins_context, char *param_name, bool *value);
// typedef bool (*dml_set_bool_cb_t)    (void *obj_ins_context, char *param_name, bool value);
// typedef bool (*dml_get_int_cb_t)     (void *obj_ins_context, char *param_name, int *value);
// typedef bool (*dml_set_int_cb_t)     (void *obj_ins_context, char *param_name, int value);
// typedef bool (*dml_get_uint_cb_t)    (void *obj_ins_context, char *param_name, uint32_t *value);
// typedef bool (*dml_set_uint_cb_t)    (void *obj_ins_context, char *param_name, uint32_t value);
// typedef bool (*dml_get_string_cb_t)  (void *obj_ins_context, char *param_name, scratch_data_buff_t *value);
// typedef bool (*dml_set_string_cb_t)  (void *obj_ins_context, char *param_name, scratch_data_buff_t *value);

// typedef struct dml_callback_table {
//     dml_get_bool_cb_t    get_bool_value;
//     dml_get_int_cb_t     get_int_value;
//     dml_set_bool_cb_t    set_bool_value;
//     dml_set_int_cb_t     set_int_value;
//     dml_set_uint_cb_t    set_uint_value;
//     dml_set_string_cb_t  set_string_value;
// } dml_callback_table_t;

typedef struct bus_data_cb_func {
    char                  *cb_table_name;
    bus_callback_table_t  cb_func;
} bus_data_cb_func_t;


// #define DATAELEMS_NETWORK       "Device.WiFi.DataElements.Network."
#define DATAELEMS_NETWORK       "Network."

#define MAX_INSTANCE_LEN        32
#define MAX_CAPS_STR_LEN        32
#define ARRAY_SIZE(a)           (sizeof(a) / sizeof(a[0]))



/* Device.WiFi.DataElements.Network */
#define DE_NETWORK_ID           DATAELEMS_NETWORK       "ID"
#define DE_NETWORK_CTRLID       DATAELEMS_NETWORK       "ControllerID"
#define DE_NETWORK_COLAGTID     DATAELEMS_NETWORK       "ColocatedAgentID"
#define DE_NETWORK_DEVNOE       DATAELEMS_NETWORK       "DeviceNumberOfEntries"
#define DE_NETWORK_SETSSID      DATAELEMS_NETWORK       "SetSSID()"
/* Device.WiFi.DataElements.Network.SSID */
// #define DE_NETWORK_SSID         DATAELEMS_NETWORK       "SSID.{i}."
#define DE_NETWORK_SSID         DATAELEMS_NETWORK       "SSIDList.{i}."
#define DE_SSID_TABLE           DE_NETWORK_SSID
#define DE_SSID_SSID            DE_NETWORK_SSID         "SSID"
#define DE_SSID_BAND            DE_NETWORK_SSID         "Band"
#define DE_SSID_ENABLE          DE_NETWORK_SSID         "Enable"
#define DE_SSID_AKMALLOWE       DE_NETWORK_SSID         "AKMsAllowed"
#define DE_SSID_SUITESEL        DE_NETWORK_SSID         "SuiteSelector"
#define DE_SSID_ADVENABLED      DE_NETWORK_SSID         "AdvertisementEnabled"
#define DE_SSID_MFPCONFIG       DE_NETWORK_SSID         "MFPConfig"
#define DE_SSID_MOBDOMAIN       DE_NETWORK_SSID         "MobilityDomain"
#define DE_SSID_HAULTYPE        DE_NETWORK_SSID         "HaulType"
/* Device.WiFi.DataElements.Network.Device */
// #define DE_NETWORK_DEVICE       DATAELEMS_NETWORK       "Device.{i}."
#define DE_NETWORK_DEVICE       DATAELEMS_NETWORK       "DeviceList.{i}."
#define DE_DEVICE_TABLE         DE_NETWORK_DEVICE
#define DE_DEVICE_ID            DE_NETWORK_DEVICE       "ID"
#define DE_DEVICE_MANUFACT      DE_NETWORK_DEVICE       "Manufacturer"
#define DE_DEVICE_SERIALNO      DE_NETWORK_DEVICE       "SerialNumber"
#define DE_DEVICE_MFCMODEL      DE_NETWORK_DEVICE       "ManufacturerModel"
#define DE_DEVICE_SWVERSION     DE_NETWORK_DEVICE       "SoftwareVersion"
#define DE_DEVICE_EXECENV       DE_NETWORK_DEVICE       "ExecutionEnv"
#define DE_DEVICE_COUNTRCODE    DE_NETWORK_DEVICE       "CountryCode"
#define DE_DEVICE_BHMACADDR     DE_NETWORK_DEVICE       "BackhaulMACAddress"
#define DE_DEVICE_BHALID        DE_NETWORK_DEVICE       "BackhaulALID"
#define DE_DEVICE_BHMEDIATYPE   DE_NETWORK_DEVICE       "BackhaulMediaType"
#define DE_DEVICE_RADIONOE      DE_NETWORK_DEVICE       "RadioNumberOfEntries"
#define DE_DEVICE_CACSTATNOE    DE_NETWORK_DEVICE       "CACStatusNumberOfEntries"
#define DE_DEVICE_BHDOWNNOE     DE_NETWORK_DEVICE       "BackhaulDownNumberOfEntries"
/* Device.WiFi.DataElements.Network.Device.CACStatus */
#define DE_DEVICE_CACSTAT       DE_NETWORK_DEVICE       "CACStatus.{i}."
#define DE_CACSTAT_TABLE        DE_DEVICE_CACSTAT
#define DE_CACSTAT_NONOCCNOE    DE_DEVICE_CACSTAT       "CACNonOccupancyChannelNumberOfEntries"
/* Device.WiFi.DataElements.Network.Device.CACStatus.CACNonOccupancyChannel */
#define DE_CACSTAT_CACNON       DE_DEVICE_CACSTAT       "CACNonOccupancyChannel.{i}."
#define DE_CACNON_TABLE         DE_CACSTAT_CACNON
#define DE_CACNON_OPCLASS       DE_CACSTAT_CACNON       "OpClass"
#define DE_CACNON_CHANNEL       DE_CACSTAT_CACNON       "Channel"
#define DE_CACNON_SECONDS       DE_CACSTAT_CACNON       "Seconds"
/* Device.WiFi.DataElements.Network.Device.BackhaulDown */
#define DE_DEVICE_BHDOWN        DE_NETWORK_DEVICE       "BackhaulDown.{i}."
#define DE_BHDOWN_TABLE         DE_DEVICE_BHDOWN
#define DE_BHDOWN_ALID          DE_DEVICE_BHDOWN        "BackhaulDownALID"
#define DE_BHDOWN_MACADDR       DE_DEVICE_BHDOWN        "BackhaulDownMACAddress"
/* Device.WiFi.DataElements.Network.Device.MultiAPDevice */
#define DE_DEVICE_MAPDEV        DE_NETWORK_DEVICE       "MultiAPDevice."
/* Device.WiFi.DataElements.Network.Device.MultiAPDevice.Backhaul */
#define DE_MAPDEV_BACKHAUL      DE_DEVICE_MAPDEV        "Backhaul."
/* Device.WiFi.DataElements.Network.Device.MultiAPDevice.Backhaul.Stats */
#define DE_MAPDEVBH_STATS       DE_MAPDEV_BACKHAUL      "Stats."
#define DE_MDBHSTATS_BYTESSNT   DE_MAPDEVBH_STATS       "BytesSent"
#define DE_MDBHSTATS_BYTESRCV   DE_MAPDEVBH_STATS       "BytesReceived"
#define DE_MDBHSTATS_PCKTSSNT   DE_MAPDEVBH_STATS       "PacketsSent"
#define DE_MDBHSTATS_PCKTSRCV   DE_MAPDEVBH_STATS       "PacketsReceived"
#define DE_MDBHSTATS_ERRSSNT    DE_MAPDEVBH_STATS       "ErrorsSent"
#define DE_MDBHSTATS_ERRSRCV    DE_MAPDEVBH_STATS       "ErrorsReceived"
#define DE_MDBHSTATS_LINKUTIL   DE_MAPDEVBH_STATS       "LinkUtilization"
#define DE_MDBHSTATS_SIGNALSTR  DE_MAPDEVBH_STATS       "SignalStrength"
#define DE_MDBHSTATS_LSTDTADLR  DE_MAPDEVBH_STATS       "LastDataDownlinkRate"
#define DE_MDBHSTATS_LSTDTAULR  DE_MAPDEVBH_STATS       "LastDataUplinkRate"
/* Device.WiFi.DataElements.Network.Device.Radio */
// #define DE_DEVICE_RADIO         DE_NETWORK_DEVICE       "Radio.{i}."
#define DE_DEVICE_RADIO         DE_NETWORK_DEVICE       "RadioList.{i}."
#define DE_RADIO_TABLE          DE_DEVICE_RADIO
#define DE_RADIO_ID             DE_DEVICE_RADIO         "ID"
#define DE_RADIO_ENABLED        DE_DEVICE_RADIO         "Enabled"
#define DE_RADIO_NOISE          DE_DEVICE_RADIO         "Noise"
#define DE_RADIO_UTILIZATION    DE_DEVICE_RADIO         "Utilization"
#define DE_RADIO_TRANSMIT       DE_DEVICE_RADIO         "Transmit"
#define DE_RADIO_RECEIVESELF    DE_DEVICE_RADIO         "ReceiveSelf"
#define DE_RADIO_RECEIVEOTHER   DE_DEVICE_RADIO         "ReceiveOther"
#define DE_RADIO_CHIPVENDOR     DE_DEVICE_RADIO         "ChipsetVendor"
#define DE_RADIO_CURROPNOE      DE_DEVICE_RADIO         "CurrentOperatingClassProfileNumberOfEntries"
#define DE_RADIO_BSSNOE         DE_DEVICE_RADIO         "BSSNumberOfEntries"
/* Device.WiFi.DataElements.Network.Device.Radio.BackhaulSta */
#define DE_RADIO_BHSTA          DE_DEVICE_RADIO         "BackhaulSta."
#define DE_BHSTA_MACADDR        DE_RADIO_BHSTA          "MACAddress"
/* Device.WiFi.DataElements.Network.Device.Radio.Capabilities */
#define DE_RADIO_CAPS           DE_DEVICE_RADIO         "Capabilities."
#define DE_RCAPS_HTCAPS         DE_RADIO_CAPS           "HTCapabilities"
#define DE_RCAPS_VHTCAPS        DE_RADIO_CAPS           "VHTCapabilities"
#define DE_RCAPS_CAPOPNOE       DE_RADIO_CAPS           "CapableOperatingClassProfileNumberOfEntries"
/* Device.WiFi.DataElements.Network.Device.Radio.Capabilities.WiFi6APRole */
#define DE_CAPS_WF6AP           DE_RADIO_CAPS           "WiFi6APRole."
#define DE_WF6AP_HE160          DE_CAPS_WF6AP           "HE160"
#define DE_WF6AP_MCSNSS         DE_CAPS_WF6AP           "MCSNSS"
/* Device.WiFi.DataElements.Network.Device.Radio.Capabilities.WiFi6bSTARole */
#define DE_CAPS_WF6BSTA         DE_RADIO_CAPS           "WiFi6bSTARole."
#define DE_WF6BSTA_HE160        DE_CAPS_WF6BSTA         "HE160"
#define DE_WF6BSTA_MCSNSS       DE_CAPS_WF6BSTA         "MCSNSS"
/* Device.WiFi.DataElements.Network.Device.Radio.Capabilities.CapableOperatingClassProfile */
#define DE_CAPS_CAPOP           DE_RADIO_CAPS           "CapableOperatingClassProfile.{i}."
#define DE_CAPOP_TABLE          DE_CAPS_CAPOP
#define DE_CAPOP_CLASS          DE_CAPS_CAPOP           "Class"
#define DE_CAPOP_MAXTXPOWER     DE_CAPS_CAPOP           "MaxTxPower"
#define DE_CAPOP_NONOPERABLE    DE_CAPS_CAPOP           "NonOperable"
#define DE_CAPOP_NONOPCNT       DE_CAPS_CAPOP           "NumberOfNonOperChan"
/* Device.WiFi.DataElements.Network.Device.Radio.CurrentOperatingClassProfile */
#define DE_RADIO_CUROP          DE_DEVICE_RADIO         "CurrentOperatingClassProfile.{i}."
#define DE_CUROP_TABLE          DE_RADIO_CUROP
#define DE_CUROP_CLASS          DE_RADIO_CUROP          "Class"
#define DE_CUROP_CHANNEL        DE_RADIO_CUROP          "Channel"
#define DE_CUROP_TXPOWER        DE_RADIO_CUROP          "TxPower"
/* Device.WiFi.DataElements.Network.Device.Radio.BSS */
// #define DE_RADIO_BSS            DE_DEVICE_RADIO         "BSS.{i}."
#define DE_RADIO_BSS            DE_DEVICE_RADIO         "BSSList.{i}."
#define DE_BSS_TABLE            DE_RADIO_BSS
#define DE_BSS_BSSID            DE_RADIO_BSS            "BSSID"
#define DE_BSS_SSID             DE_RADIO_BSS            "SSID"
#define DE_BSS_ENABLED          DE_RADIO_BSS            "Enabled"
#define DE_BSS_BYTCNTUNITS      DE_RADIO_BSS            "ByteCounterUnits"
#define DE_BSS_BHAULUSE         DE_RADIO_BSS            "BackhaulUse"
#define DE_BSS_FHAULUSE         DE_RADIO_BSS            "FronthaulUse"
#define DE_BSS_FHAULAKMS        DE_RADIO_BSS            "FronthaulAKMsAllowed"
#define DE_BSS_FHSUITESEL       DE_RADIO_BSS            "FronthaulSuiteSelector"
#define DE_BSS_BHAULAKMS        DE_RADIO_BSS            "BackhaulAKMsAllowed"
#define DE_BSS_BHSUITESEL       DE_RADIO_BSS            "BackhaulSuiteSelector"
#define DE_BSS_STANOE           DE_RADIO_BSS            "STANumberOfEntries"
/* Device.WiFi.DataElements.Network.Device.Radio.BSS.STA */
#define DE_BSS_STA              DE_RADIO_BSS            "STA.{i}."
#define DE_STA_TABLE            DE_BSS_STA
#define DE_STA_MACADDR          DE_BSS_STA              "MACAddress"
#define DE_STA_HTCAPS           DE_BSS_STA              "HTCapabilities"
#define DE_STA_VHTCAPS          DE_BSS_STA              "VHTCapabilities"
#define DE_STA_CLIENTCAPS       DE_BSS_STA              "ClientCapabilities"
#define DE_STA_LSTDTADLR        DE_BSS_STA              "LastDataDownlinkRate"
#define DE_STA_LSTDTAULR        DE_BSS_STA              "LastDataUplinkRate"
#define DE_STA_UTILRECV         DE_BSS_STA              "UtilizationReceive"
#define DE_STA_UTILTRMT         DE_BSS_STA              "UtilizationTransmit"
#define DE_STA_ESTMACDTARDL     DE_BSS_STA              "EstMACDataRateDownlink"
#define DE_STA_ESTMACDTARUL     DE_BSS_STA              "EstMACDataRateUplink"
#define DE_STA_SIGNALSTR        DE_BSS_STA              "SignalStrength"
#define DE_STA_LASTCONNTIME     DE_BSS_STA              "LastConnectTime"
#define DE_STA_BYTESSNT         DE_BSS_STA              "BytesSent"
#define DE_STA_BYTESRCV         DE_BSS_STA              "BytesReceived"
#define DE_STA_PCKTSSNT         DE_BSS_STA              "PacketsSent"
#define DE_STA_PCKTSRCV         DE_BSS_STA              "PacketsReceived"
#define DE_STA_ERRSSNT          DE_BSS_STA              "ErrorsSent"
#define DE_STA_ERRSRCV          DE_BSS_STA              "ErrorsReceived"
#define DE_STA_RETRANSCNT       DE_BSS_STA              "RetransCount"
#define DE_STA_IPV4ADDR         DE_BSS_STA              "IPV4Address"
#define DE_STA_IPV6ADDR         DE_BSS_STA              "IPV6Address"
#define DE_STA_HOSTNAME         DE_BSS_STA              "Hostname"
#define DE_STA_PAIRWSAKM        DE_BSS_STA              "PairwiseAKM"
#define DE_STA_PAIRWSCIPHER     DE_BSS_STA              "PairwiseCipher"
#define DE_STA_RSNCAPS          DE_BSS_STA              "RSNCapabilities"
/* Device.WiFi.DataElements.Network.Device.Radio.BSS.STA.WiFi6Capabilities */
#define DE_STA_WIFI6CAPS        DE_BSS_STA              "WiFi6Capabilities."
#define DE_STAWF6CAPS_HE160     DE_STA_WIFI6CAPS        "HE160"
#define DE_STAWF6CAPS_MCSNSS    DE_STA_WIFI6CAPS        "MCSNSS"

#define ELEMENT_DEFAULTS(t)         slow_speed, ZERO_TABLE, {t, false, 0L, 0L, 0U, NULL}
#define CALLBACK_GETTER(f)          {f, NULL, NULL, NULL, NULL, NULL}
#define CALLBACK_METHOD(f)          {NULL, NULL, NULL, NULL, NULL, f}
#define ELEMENT_PROPERTY(n, f, t)   {n, bus_element_type_property, CALLBACK_GETTER(f), ELEMENT_DEFAULTS(t)}
#define ELEMENT_METHOD(n, f, t)     {n, bus_element_type_method, CALLBACK_METHOD(f), ELEMENT_DEFAULTS(t)}
#define ELEMENT_TABLE(n, f, t)      {n, bus_element_type_table, CALLBACK_GETTER(f), ELEMENT_DEFAULTS(t)}


#define CALLBACK_ADD_ROW(f)          {NULL, NULL, f, NULL, NULL, NULL}
#define CB(...)                      (bus_callback_table_t){ __VA_ARGS__ }
#define ELEMENT(n, f)                {n, f}
#define ELEMENT_TABLE_ROW(n, f)      {n, f}

class dm_easy_mesh_ctrl_t;

class tr_181_t {
private:
    bus_handle_t m_bus_handle;
    //static dm_easy_mesh_ctrl_t* m_ctrl;

public:

    tr_181_t() {
    }
    
    ~tr_181_t() {
    }
bus_handle_t *get_bus_hdl(){
        return &m_bus_handle;
    }
    
    // Delete copy constructor and assignment
    tr_181_t(const tr_181_t&) = delete;
    tr_181_t& operator=(const tr_181_t&) = delete;
    
    // Initialization
    //void initialize(bus_handle_t* handle, dm_easy_mesh_ctrl_t& dm_ctrl);
    void init(void* ptr);
    
    // WFA DML interface
    int register_wfa_dml();
    int wfa_set_bus_callbackfunc_pointers(const char* full_namespace, bus_callback_table_t* cb_table);
    int wfa_bus_register_namespace(char* full_namespace, 
                                 bus_element_type_t element_type,
                                 bus_callback_table_t cb_table, 
                                 data_model_properties_t data_model_value, 
                                 int num_of_rows);
    bus_error_t raw_data_set(raw_data_t *p_data, bool b);
    bus_error_t raw_data_set(raw_data_t *p_data, int32_t i);
    bus_error_t raw_data_set(raw_data_t *p_data, uint8_t u);
    bus_error_t raw_data_set(raw_data_t *p_data, uint16_t u);
    bus_error_t raw_data_set(raw_data_t *p_data, uint32_t u);
    bus_error_t raw_data_set(raw_data_t *p_data, const char *str);
    bus_error_t raw_data_set(raw_data_t *p_data, mac_address_t mac);
    bus_error_t raw_data_set(raw_data_t *p_data, wifi_ieee80211Variant_t var);
    bus_error_t raw_data_set(raw_data_t *p_data, bus_data_prop_t *property);

    virtual bus_error_t bus_get_cb_fwd(char *event_name, raw_data_t *p_data, bus_get_handler_t cb) = 0;
    
    //Table callback handlers
    static bus_error_t add_table_row(char const *name, dm_easy_mesh_t *dm);
    bus_error_t reg_table_row(char *name, int index);

    // Bus callback handlers
    static bus_error_t default_get_param_value(char* event_name, raw_data_t* p_data, struct bus_user_data* user_data);
    static bus_error_t default_set_param_value(char* event_name, raw_data_t* p_data, struct bus_user_data* user_data);
    static bus_error_t default_table_add_row_handler(const char* tableName, const char* aliasName, uint32_t* instNum);
    static bus_error_t default_table_remove_row_handler(const char* rowName);
    static bus_error_t default_event_sub_handler(char* eventName, bus_event_sub_action_t action, int32_t interval, bool* autoPublish);

    //Network
    static bus_error_t network_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    
    //SSID
    static bus_error_t ssid_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    static bus_error_t ssid_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    static bus_error_t ssid_table_add_row_handler(const char* table_name, const char* alias_name, uint32_t* instance_number);

    //Device Callbacks
    static bus_error_t device_tget(char* event_name, raw_data_t* p_data, struct bus_user_data* user_data);
    static bus_error_t device_table_add_row_handler(const char* table_name, const char* alias_name, uint32_t* instance_number);

    //Radio
    static bus_error_t radio_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    static bus_error_t radio_table_add_row_handler(const char* table_name, const char* alias_name, uint32_t* instance_number);

    //BSS
    static bus_error_t bss_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    static bus_error_t bss_table_add_row_handler(const char* table_name, const char* alias_name, uint32_t* instance_number);

    //STA
    static bus_error_t sta_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    static bus_error_t sta_table_add_row_handler(const char* table_name, const char* alias_name, uint32_t* instance_number);

    virtual bus_error_t network_get(char *event_name, raw_data_t *p_data) = 0;
    virtual bus_error_t device_tget(char *event_name, raw_data_t *p_data) = 0;
    // virtual bus_error_t radio_tget_impl(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data) = 0;
    // virtual bus_error_t bss_tget_impl(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data) = 0;
    // virtual bus_error_t ssid_tget_impl(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data) = 0;

	// int get_nb_pipe_rd() { return m_nb_pipe_rd; }
	// int get_nb_pipe_wr() { return m_nb_pipe_wr; }
    // uint32_t get_next_nb_evt_id() { return m_nb_evt_id++; }

    // Data model access
    // wfa_dml_data_model_t* get_dml_data_model_param();
    bus_error_t wifi_elem_num_of_table_row(char* event_name, uint32_t* table_row_size);
    
    // File operations
    void generate_namespaces_without_lib_refined(const std::string& filename);
    void register_cjson_namespace(cJSON *node, const std::string &prefix);

    //Data_Elements_JSON_Schema_v3.0 parsing related functions
    bool tr_181_t::parseFile(const std::string& filePath);
    bool tr_181_t::decodeJsonObject(cJSON* root);
    void tr_181_t::processDefinitions(cJSON* definitions);
    void tr_181_t::decodeObjectsRecursive(cJSON* node, cJSON* defObj, const std::string& namePrefix);
    void tr_181_t::constructNamespaceAndRegister(cJSON* cfgParam, cJSON* defObj, const std::string& namePrefix);
    void tr_181_t::addArrayNodeElements(cJSON* arrayObj, int numElements, const std::string& namePrefix, cJSON* defObj, bus_callback_table_t cbTable);
    void tr_181_t::registerNamespace(const std::string& fullNamespace, const data_model_properties_t& props, bus_element_type_t type, bus_callback_table_t cbTable, int numRows);
    void tr_181_t::getDataModelProperties(cJSON* defObj, const char* typeStr, data_model_properties_t& props);
};

#endif // TR_181_H
