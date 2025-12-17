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

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <map>
#include <unistd.h>
#include <fcntl.h>
#include "tr_181.h"
// #include "wfa_data_model_parser.h"
// #include "wfa_data_model.h"
#include "util.h"
#include "dm_easy_mesh_ctrl.h"
#include "em_ctrl.h"

void tr_181_t::init(void* ptr)
{
    wifi_bus_desc_t *desc;
    char service_name[] = "tr_181_service";
    int pipefd[2];
	int rcp;

	rcp = pipe2(pipefd, O_DIRECT);
	if (rcp == -1) {
		return;
	}

    bus_init(&m_bus_handle);

    if((desc = get_bus_descriptor()) == NULL) {
        em_printfout("descriptor is null");
    }
    
    if (desc->bus_open_fn(&m_bus_handle, service_name) != 0) {
        em_printfout("bus open failed");
        return;
    }

    register_wfa_dml();
}

int tr_181_t::wfa_set_bus_callbackfunc_pointers(const char *full_namespace, bus_callback_table_t *cb_table)
{
    bus_data_cb_func_t bus_data_cb[] = {
        ELEMENT(DE_NETWORK_ID, CB(.get_handler = network_get)),
        ELEMENT(DE_NETWORK_CTRLID, CB(.get_handler = network_get)),
        ELEMENT(DE_NETWORK_COLAGTID, CB(.get_handler = network_get)),
        ELEMENT(DE_NETWORK_DEVNOE, CB(.get_handler = network_get)),
        ELEMENT(DE_SSID_TABLE, CB(.get_handler = ssid_tget)),
        ELEMENT(DE_SSID_SSID, CB(.get_handler = ssid_get)),
        ELEMENT(DE_SSID_BAND, CB(.get_handler = ssid_get)),
        ELEMENT(DE_SSID_ENABLE, CB(.get_handler = ssid_get)),
        ELEMENT(DE_SSID_AKMALLOWE, CB(.get_handler = ssid_get)),
        ELEMENT(DE_SSID_SUITESEL, CB(.get_handler = ssid_get)),
        ELEMENT(DE_SSID_ADVENABLED, CB(.get_handler = ssid_get)),
        ELEMENT(DE_SSID_MFPCONFIG, CB(.get_handler = ssid_get)),
        ELEMENT(DE_SSID_MOBDOMAIN, CB(.get_handler = ssid_get)),
        ELEMENT(DE_SSID_HAULTYPE, CB(.get_handler = ssid_get)),
        ELEMENT(DE_DEVICE_TABLE, CB(.get_handler = device_tget)),
        ELEMENT(DE_RADIO_TABLE, CB(.get_handler = radio_tget)),
        ELEMENT(DE_BSS_TABLE, CB(.get_handler = bss_tget)),
        ELEMENT(DE_STA_TABLE, CB(.get_handler = sta_tget)),
        ELEMENT(DE_DEVICE_ID, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_MAPCAP,    CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_NUMRADIO,  CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_COLLINT,   CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_RUASSOC,   CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_MAXRRATE,  CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_MAPPROF,   CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_APMERINT,  CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_MANUFACT,  CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_SERIALNO,  CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_MFCMODEL,  CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_SWVERSION, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_EXECENV, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_LSDSTALIST, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_BTMSDSTALIST, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_MAXVIDS, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_BPRIO, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_EPRIO, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_TSEPPOLI, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_STVMAP, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_DSCPM, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_MAXPRIRULE, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_COUNTRCODE, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_PRIOSUPP, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_REPINDSCAN, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_TRASEPALW, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_SERPRIOALW, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_STASDISALW, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_DFSENABLE, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_MAXUSASSOCREPRATE, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_STASSTATE, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_COORCACALW, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_CONOPMODE, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_BHMACADDR, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_BHDMACADDR, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_BHPHYRATE, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_TRSEPCAP, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_EASYCCAP, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_TESTCAP, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_BSTAMLDMACLINK, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_MACNUMMLDS, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_BHALID, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_TIDLMAP, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_ASSOCSTAREPINT, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_BHMEDIATYPE, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_RADIONOE, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_CACSTATNOE, CB(.get_handler = device_get)),
        ELEMENT(DE_DEVICE_BHDOWNNOE, CB(.get_handler = device_get)),
        ELEMENT(DE_RADIO_ID,          CB(.get_handler = radio_get)),
        ELEMENT(DE_RADIO_ENABLED,     CB(.get_handler = radio_get)),
        ELEMENT(DE_RADIO_NOISE,       CB(.get_handler = radio_get)),
        ELEMENT(DE_RADIO_UTILIZATION, CB(.get_handler = radio_get)),
        ELEMENT(DE_RADIO_TRANSMIT,    CB(.get_handler = radio_get)),
        ELEMENT(DE_RADIO_RECEIVESELF, CB(.get_handler = radio_get)),
        ELEMENT(DE_RADIO_RECEIVEOTHER,CB(.get_handler = radio_get)),
        ELEMENT(DE_RADIO_CHIPVENDOR,  CB(.get_handler = radio_get)),
        ELEMENT(DE_RADIO_CURROPNOE,   CB(.get_handler = radio_get)),
        ELEMENT(DE_RADIO_BSSNOE,      CB(.get_handler = radio_get)),
        ELEMENT(DE_RCAPS_HTCAPS,      CB(.get_handler = rcaps_get)),
        ELEMENT(DE_RCAPS_VHTCAPS,     CB(.get_handler = rcaps_get)),
        ELEMENT(DE_RCAPS_CAPOPNOE,    CB(.get_handler = rcaps_get)),
        ELEMENT(DE_CUROP_TABLE,       CB(.get_handler = curops_tget)),
        ELEMENT(DE_CUROP_CLASS,       CB(.get_handler = curops_get)),
        ELEMENT(DE_CUROP_CHANNEL,     CB(.get_handler = curops_get)),
        ELEMENT(DE_CUROP_TXPOWER,     CB(.get_handler = curops_get)),
        ELEMENT(DE_BSS_BSSID,         CB(.get_handler = bss_get)),
        ELEMENT(DE_BSS_SSID,          CB(.get_handler = bss_get)),
        ELEMENT(DE_BSS_ENABLED,       CB(.get_handler = bss_get)),
        ELEMENT(DE_BSS_LASTCHG,       CB(.get_handler = bss_get)),
        ELEMENT(DE_BSS_TS,            CB(.get_handler = bss_get)),
        ELEMENT(DE_BSS_UCAST_TX,      CB(.get_handler = bss_get)),
        ELEMENT(DE_BSS_UCAST_RX,      CB(.get_handler = bss_get)),
        ELEMENT(DE_BSS_MCAST_TX,      CB(.get_handler = bss_get)),
        ELEMENT(DE_BSS_MCAST_RX,      CB(.get_handler = bss_get)),
        ELEMENT(DE_BSS_BCAST_TX,      CB(.get_handler = bss_get)),
        ELEMENT(DE_BSS_BCAST_RX,      CB(.get_handler = bss_get)),
        ELEMENT(DE_BSS_EST_BE,        CB(.get_handler = bss_get)),
        ELEMENT(DE_BSS_EST_BK,        CB(.get_handler = bss_get)),
        ELEMENT(DE_BSS_EST_VI,        CB(.get_handler = bss_get)),
        ELEMENT(DE_BSS_EST_VO,        CB(.get_handler = bss_get)),
        ELEMENT(DE_BSS_BYTCNTUNITS,   CB(.get_handler = bss_get)),
        ELEMENT(DE_BSS_PROF1_DIS,     CB(.get_handler = bss_get)),
        ELEMENT(DE_BSS_PROF2_DIS,     CB(.get_handler = bss_get)),
        ELEMENT(DE_BSS_ASSOC_STAT,    CB(.get_handler = bss_get)),
        ELEMENT(DE_BSS_BHAULUSE,      CB(.get_handler = bss_get)),
        ELEMENT(DE_BSS_FHAULUSE,      CB(.get_handler = bss_get)),
        ELEMENT(DE_BSS_R1_DIS,        CB(.get_handler = bss_get)),
        ELEMENT(DE_BSS_R2_DIS,        CB(.get_handler = bss_get)),
        ELEMENT(DE_BSS_MULTI_BSSID,   CB(.get_handler = bss_get)),
        ELEMENT(DE_BSS_TX_BSSID,      CB(.get_handler = bss_get)),
        ELEMENT(DE_BSS_FHAULAKMS,     CB(.get_handler = bss_get)),
        ELEMENT(DE_BSS_BHAULAKMS,     CB(.get_handler = bss_get)),
        ELEMENT(DE_BSS_QM_DESC,       CB(.get_handler = bss_get)),
        ELEMENT(DE_BSS_NUM_STA,       CB(.get_handler = bss_get)),
        ELEMENT(DE_BSS_LINK_IMM,      CB(.get_handler = bss_get)),
        ELEMENT(DE_BSS_FH_SUITE,      CB(.get_handler = bss_get)),
        ELEMENT(DE_BSS_BH_SUITE,      CB(.get_handler = bss_get)),
        ELEMENT(DE_STA_MACADDR,       CB(.get_handler = sta_get)),
        ELEMENT(DE_STA_HTCAPS,        CB(.get_handler = sta_get)),
        ELEMENT(DE_STA_VHTCAPS,       CB(.get_handler = sta_get)),
        ELEMENT(DE_STA_CLIENTCAPS,    CB(.get_handler = sta_get)),
        ELEMENT(DE_STA_LSTDTADLR,     CB(.get_handler = sta_get)),
        ELEMENT(DE_STA_LSTDTAULR,     CB(.get_handler = sta_get)),
        ELEMENT(DE_STA_UTILRECV,      CB(.get_handler = sta_get)),
        ELEMENT(DE_STA_UTILTRMT,      CB(.get_handler = sta_get)),
        ELEMENT(DE_STA_ESTMACDTARDL,  CB(.get_handler = sta_get)),
        ELEMENT(DE_STA_ESTMACDTARUL,  CB(.get_handler = sta_get)),
        ELEMENT(DE_STA_SIGNALSTR,     CB(.get_handler = sta_get)),
        ELEMENT(DE_STA_LASTCONNTIME,  CB(.get_handler = sta_get)),
        ELEMENT(DE_STA_BYTESSNT,      CB(.get_handler = sta_get)),
        ELEMENT(DE_STA_BYTESRCV,      CB(.get_handler = sta_get)),
        ELEMENT(DE_STA_PCKTSSNT,      CB(.get_handler = sta_get)),
        ELEMENT(DE_STA_PCKTSRCV,      CB(.get_handler = sta_get)),
        ELEMENT(DE_STA_ERRSSNT,       CB(.get_handler = sta_get)),
        ELEMENT(DE_STA_ERRSRCV,       CB(.get_handler = sta_get)),
        ELEMENT(DE_STA_RETRANSCNT,    CB(.get_handler = sta_get)),
        ELEMENT(DE_STA_IPV4ADDR,      CB(.get_handler = sta_get)),
        ELEMENT(DE_STA_IPV6ADDR,      CB(.get_handler = sta_get)),
        ELEMENT(DE_STA_HOSTNAME,      CB(.get_handler = sta_get)),
        ELEMENT(DE_STA_PAIRWSAKM,     CB(.get_handler = sta_get)),
        ELEMENT(DE_STA_PAIRWSCIPHER,  CB(.get_handler = sta_get)),
        ELEMENT(DE_STA_RSNCAPS,       CB(.get_handler = sta_get))
    };

    bus_data_cb_func_t bus_default_data_cb = { const_cast<char*>(" "),
        { default_get_param_value, default_set_param_value, default_table_add_row_handler,
          default_table_remove_row_handler, default_event_sub_handler, NULL }
    };

    uint32_t index = 0;
    bool     table_found = false;

    for (index = 0; index < static_cast<uint32_t>(ARRAY_SIZE(bus_data_cb)); index++) {
        if (strcmp(full_namespace, bus_data_cb[index].cb_table_name) == 0) {
            memcpy(cb_table, &bus_data_cb[index].cb_func, sizeof(bus_callback_table_t));
            table_found = true;
            break;
        }
    }

    if (table_found == false) {
        memcpy(cb_table, &bus_default_data_cb.cb_func, sizeof(bus_callback_table_t));
    }

    return RETURN_OK;
}

int tr_181_t::wfa_bus_register_namespace(char *full_namespace, bus_element_type_t element_type,
                            bus_callback_table_t cb_table, data_model_properties_t  data_model_value, int num_of_rows)
{   
    bus_data_element_t dataElements = {};

    dataElements.full_name       = full_namespace;
    dataElements.type            = element_type;
    dataElements.cb_table        = cb_table;
    dataElements.bus_speed       = slow_speed;
    dataElements.data_model_prop = data_model_value;

    if (element_type == bus_element_type_table) {
        uint32_t num_of_table_rows;
        if (wifi_elem_num_of_table_row(full_namespace, &num_of_table_rows) == bus_error_success) {
            dataElements.num_of_table_row = num_of_table_rows;
        } else {
            dataElements.num_of_table_row = static_cast<uint32_t>(num_of_rows);
        }
    }

    uint32_t num_elements = 1;
    bus_error_t rc = get_bus_descriptor()->bus_reg_data_element_fn(&m_bus_handle, &dataElements, num_elements);
    if (rc != bus_error_success) {
        em_printfout("bus: bus_regDataElements failed:%s\n", full_namespace);
    }
    em_printfout("bus: bus_regDataElements success:%s", full_namespace);

    return RETURN_OK;
}

bus_error_t tr_181_t::raw_data_set(raw_data_t *p_data, bool b)
{
    p_data->data_type = bus_data_type_boolean;
    p_data->raw_data.b = b;
    return bus_error_success;
}

bus_error_t tr_181_t::raw_data_set(raw_data_t *p_data, int32_t i)
{
    p_data->data_type = bus_data_type_int32;
    p_data->raw_data.i32 = i;
    return bus_error_success;
}

bus_error_t tr_181_t::raw_data_set(raw_data_t *p_data, uint8_t u)
{
    p_data->data_type = bus_data_type_uint8;
    p_data->raw_data.u8 = u;
    return bus_error_success;
}

bus_error_t tr_181_t::raw_data_set(raw_data_t *p_data, uint16_t u)
{
    p_data->data_type = bus_data_type_uint16;
    p_data->raw_data.u16 = u;
    return bus_error_success;
}

bus_error_t tr_181_t::raw_data_set(raw_data_t *p_data, uint32_t u)
{
    p_data->data_type = bus_data_type_uint32;
    p_data->raw_data.u32 = u;
    return bus_error_success;
}

bus_error_t tr_181_t::raw_data_set(raw_data_t *p_data, const char *str)
{
    uint32_t str_size;

    str_size = strlen(str) + 1;
    p_data->data_type = bus_data_type_string;
    p_data->raw_data.bytes = malloc(str_size);
    if (p_data->raw_data.bytes == NULL) {
        return bus_error_out_of_resources;
    }
    memcpy(p_data->raw_data.bytes, str, str_size);
    p_data->raw_data_len = str_size;

    return bus_error_success;
}

bus_error_t tr_181_t::raw_data_set(raw_data_t *p_data, mac_address_t mac)
{
    mac_addr_str_t mac_str;

    p_data->data_type = bus_data_type_string;
    p_data->raw_data.bytes = malloc(sizeof(mac_addr_str_t));
    if (p_data->raw_data.bytes == NULL) {
        return bus_error_out_of_resources;
    }
    dm_easy_mesh_t::macbytes_to_string(mac, mac_str);
    memcpy(p_data->raw_data.bytes, mac_str, sizeof(mac_addr_str_t));
    p_data->raw_data_len = sizeof(mac_addr_str_t);

    return bus_error_success;
}

bus_error_t tr_181_t::raw_data_set(raw_data_t *p_data, wifi_ieee80211Variant_t var)
{
    const char *var_str;

    switch (var) {
        case WIFI_80211_VARIANT_A:
            var_str = "IEEE 802.11a";
            break;
        case WIFI_80211_VARIANT_B:
            var_str = "IEEE 802.11b";
            break;
        case WIFI_80211_VARIANT_G:
            var_str = "IEEE 802.11g";
            break;
        case WIFI_80211_VARIANT_N:
            var_str = "IEEE 802.11n 2.4";
            break;
        case WIFI_80211_VARIANT_H:
            var_str = "IEEE 802.11n 5.0";
            break;
        case WIFI_80211_VARIANT_AC:
            var_str = "IEEE 802.11ac";
            break;
        case WIFI_80211_VARIANT_AD:
            var_str = "IEEE 802.11ad";
            break;
        case WIFI_80211_VARIANT_AX:
            var_str = "IEEE 802.11ax";
            break;
        case WIFI_80211_VARIANT_BE:
            var_str = "IEEE 802.11be";
            break;
        default:
            var_str = "Generic PHY";
            break;
    }

    return raw_data_set(p_data, var_str);
}

bus_error_t tr_181_t::raw_data_set(raw_data_t *p_data, bus_data_prop_t *property)
{
    p_data->data_type = bus_data_type_property;
    p_data->raw_data.bytes = malloc(sizeof(bus_data_prop_t));
    if (p_data->raw_data.bytes == NULL) {
        return bus_error_out_of_resources;
    }
    memcpy(p_data->raw_data.bytes, property, sizeof(bus_data_prop_t));
    p_data->raw_data_len = sizeof(bus_data_prop_t);

    return bus_error_success;
}

bus_error_t tr_181_t::default_get_param_value(char* event_name, raw_data_t* p_data, struct bus_user_data* user_data) {
    // Default implementation for get parameter value

    p_data->data_type = bus_data_type_boolean;
    p_data->raw_data.b = 0;
    p_data->raw_data_len = sizeof(bool);

    (void)user_data;
    return bus_error_success;
}

bus_error_t tr_181_t::default_set_param_value(char* event_name, raw_data_t* p_data, struct bus_user_data* user_data) {
    //(void)p_data;
    p_data->data_type = bus_data_type_boolean;
    p_data->raw_data.b = 0;
    p_data->raw_data_len = sizeof(bool);

    (void)user_data;
    return bus_error_success;
}

bus_error_t tr_181_t::default_table_add_row_handler(const char* tableName, const char* aliasName, uint32_t* instNum) {
    (void)aliasName;
    // Set a dummy instance number for testing
    if (instNum != NULL) {
        *instNum = 1; 
    }

    return bus_error_success;
}

bus_error_t tr_181_t::default_table_remove_row_handler(const char* rowName) {
    return bus_error_success;
}

bus_error_t tr_181_t::default_event_sub_handler(char* eventName, bus_event_sub_action_t action, 
                                               int32_t interval, bool* autoPublish) {
    (void)autoPublish;

    return bus_error_success;
}


bus_error_t tr_181_t::network_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL)
    {
        em_ctrl->get_dm_ctrl()->network_get(event_name, p_data);
        return bus_error_success;
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::ssid_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL)
    {
        em_ctrl->get_dm_ctrl()->ssid_tget(event_name, p_data);
        return bus_error_success;
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::ssid_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL)
    {
        em_ctrl->get_dm_ctrl()->ssid_get(event_name, p_data);
        return bus_error_success;
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::device_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL)
    {
        em_ctrl->get_dm_ctrl()->device_get(event_name, p_data);
        return bus_error_success;
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::device_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL)
    {
        em_ctrl->get_dm_ctrl()->device_tget(event_name, p_data);
        return bus_error_success;
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::radio_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL)
    {
        em_ctrl->get_dm_ctrl()->radio_get(event_name, p_data);
        return bus_error_success;
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::bss_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL)
    {
        em_ctrl->get_dm_ctrl()->bss_get(event_name, p_data);
        return bus_error_success;
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::rcaps_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL)
    {
        em_ctrl->get_dm_ctrl()->rcaps_get(event_name, p_data);
        return bus_error_success;
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::curops_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL)
    {
        em_ctrl->get_dm_ctrl()->curops_get(event_name, p_data);
        return bus_error_success;
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::curops_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL)
    {
        em_ctrl->get_dm_ctrl()->curops_tget(event_name, p_data);
        return bus_error_success;
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::sta_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL)
    {
        em_ctrl->get_dm_ctrl()->sta_get(event_name, p_data);
        return bus_error_success;
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::radio_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL)
    {
        em_ctrl->get_dm_ctrl()->radio_tget(event_name, p_data);
        return bus_error_success;
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::rbhsta_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL)
    {
        em_ctrl->get_dm_ctrl()->rbhsta_get(event_name, p_data);
        return bus_error_success;
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::bss_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL)
    {
        em_ctrl->get_dm_ctrl()->device_get(event_name, p_data);
        return bus_error_success;
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::sta_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL)
    {
        em_ctrl->get_dm_ctrl()->device_get(event_name, p_data);
        return bus_error_success;
    }

    return bus_error_general;
}

bus_error_t tr_181_t::wifi_elem_num_of_table_row(char* event_name, uint32_t* table_row_size)
{
    // Return 0 rows for all tables for now
    if (table_row_size != NULL) {
        *table_row_size = 0;
    }

    return bus_error_success;
}

// Resolve $ref if present on the node; otherwise return the node itself.
cJSON* tr_181_t::follow_ref_if_any(cJSON* root, cJSON* node)
{
    if (!node) return nullptr;

    /* resolve $ref */
    cJSON* ref = cJSON_GetObjectItem(node, "$ref");
    if (ref && cJSON_IsString(ref)) {
        cJSON* resolved = resolve_ref(root, ref->valuestring);
        if (resolved)
            return follow_ref_if_any(root, resolved);
    }

    /* unwrap oneOf / anyOf, skip null */
    cJSON* comb = cJSON_GetObjectItem(node, "oneOf");
    if (!comb)
        comb = cJSON_GetObjectItem(node, "anyOf");

    if (comb && cJSON_IsArray(comb)) {
        cJSON* it = comb->child;
        while (it) {
            cJSON* type = cJSON_GetObjectItem(it, "type");

            /* skip null-only variants */
            if (type) {
                if (cJSON_IsString(type) &&
                    strcmp(type->valuestring, "null") == 0) {
                    it = it->next;
                    continue;
                }
                if (cJSON_IsArray(type)) {
                    bool onlyNull = true;
                    cJSON* t = type->child;
                    while (t) {
                        if (strcmp(t->valuestring, "null") != 0) {
                            onlyNull = false;
                            break;
                        }
                        t = t->next;
                    }
                    if (onlyNull) {
                        it = it->next;
                        continue;
                    }
                }
            }
            return follow_ref_if_any(root, it);
        }
    }
    return node;
}

// ------------------------------------------------------------
// Resolve $ref like "#/definitions/Default8021Q_g"
// ------------------------------------------------------------
cJSON* tr_181_t::resolve_ref(cJSON* root, const char* refStr)
{
    if (!root || !refStr || refStr[0] != '#') return nullptr;

    std::string ref(refStr);
    // strip "#/"
    if (ref.rfind("#/", 0) == 0) ref = ref.substr(2);

    cJSON* node = root;
    size_t pos = 0;
    while ((pos = ref.find('/')) != std::string::npos)
    {
        std::string key = ref.substr(0, pos);
        ref.erase(0, pos + 1);
        node = cJSON_GetObjectItem(node, key.c_str());
        if (!node) return nullptr;
    }
    if (!ref.empty())
        node = cJSON_GetObjectItem(node, ref.c_str());

    return node;
}

// ------------------------------------------------------------
// Extract min/max range, type, read/write from leaf node
// ------------------------------------------------------------
void tr_181_t::parse_property_constraints(cJSON* schemaNode, data_model_properties_t& props)
{
    // min / max from JSON schema
    cJSON* minimum = cJSON_GetObjectItem(schemaNode, "minimum");
    cJSON* maximum = cJSON_GetObjectItem(schemaNode, "maximum");

    if (minimum && cJSON_IsNumber(minimum))
        props.min_data_range = minimum->valuedouble;

    if (maximum && cJSON_IsNumber(maximum))
        props.max_data_range = maximum->valuedouble;
}

void tr_181_t::parse_readwrite(cJSON* schemaNode, data_model_properties_t& props)
{
    cJSON* writable = cJSON_GetObjectItem(schemaNode, "writable");
    if (writable && writable->type == cJSON_True)
        props.data_permission = 1;
    else
        props.data_permission = 0;
}

bool tr_181_t::schema_has_type(cJSON* schema, const char* want)
{
    if (!schema) return false;

    cJSON* type = cJSON_GetObjectItem(schema, "type");
    if(!type) return false;

    if(cJSON_IsString(type))
        return strcmp(type->valuestring, want) == 0;

    if(cJSON_IsArray(type)) {
        cJSON* it = type->child;
        while(it) {
            if(strcmp(it->valuestring, want) == 0)
                return true;
            it = it->next;
        }
    }
    return false;
}

// ------------------------------------------------------------
// Handle ANY property under an object: decide if TABLE or PROPERTY
// ------------------------------------------------------------
void tr_181_t::handle_property_node(cJSON* root, const std::string& fullPath, cJSON* propertySchema)
{
    if (!propertySchema) return;

    bus_callback_table_t cbTable = {};
    data_model_properties_t data_model_value;
    memset(&data_model_value, 0, sizeof(data_model_value));

    // 1) follow top-level $ref / combiners if present
    cJSON* effective = follow_ref_if_any(root, propertySchema);
    if (!effective) return;

    // 2) If effective has properties -> expand (this handles $ref -> object with properties)
    cJSON* propsObj = cJSON_GetObjectItem(effective, "properties");
    if (propsObj && cJSON_IsObject(propsObj)) {
        traverse_schema(root, effective, fullPath);
        return;
    }

    // 3) If type is array -> register TABLE and examine items
    if (schema_has_type(effective, "array")) {
        std::string tableName = fullPath + ".{i}";

        // register table namespace
        wfa_set_bus_callbackfunc_pointers(tableName.c_str(), &cbTable);
        // reset and fill constraints for the array property itself
        memset(&data_model_value, 0, sizeof(data_model_value));
        parse_property_constraints(effective, data_model_value);
        parse_readwrite(effective, data_model_value);
        wfa_bus_register_namespace(const_cast<char*>(tableName.c_str()), bus_element_type_table, cbTable, data_model_value, 1);

        // now inspect items
        cJSON* items = cJSON_GetObjectItem(effective, "items");
        if (!items) return;

        cJSON* itemsEff = follow_ref_if_any(root, items);
        if (!itemsEff) return;

        cJSON* itemProps = cJSON_GetObjectItem(itemsEff, "properties");
        if (itemProps && cJSON_IsObject(itemProps)) {
            // expand row children under tableName
            traverse_schema(root, itemsEff, tableName);
        } else {
            // primitive array -> register the row as property
            memset(&data_model_value, 0, sizeof(data_model_value));
            parse_property_constraints(itemsEff, data_model_value);
            parse_readwrite(itemsEff, data_model_value);
            wfa_set_bus_callbackfunc_pointers(tableName.c_str(), &cbTable);
            wfa_bus_register_namespace(const_cast<char*>(tableName.c_str()), bus_element_type_property, cbTable, data_model_value, 1);
        }
        return;
    }

    // 4) If type is object (but had no direct properties above),
    // try to resolve any nested $ref and check again
    if (schema_has_type(effective, "object")) {
        // we've already tried follow_ref_if_any at top-level; if still no properties, treat as leaf object
        memset(&data_model_value, 0, sizeof(data_model_value));
        parse_property_constraints(effective, data_model_value);
        parse_readwrite(effective, data_model_value);
        wfa_set_bus_callbackfunc_pointers(fullPath.c_str(), &cbTable);
        wfa_bus_register_namespace(const_cast<char*>(fullPath.c_str()), bus_element_type_property, cbTable, data_model_value, 1);
        return;
    }

    // 5) Fallback: primitive (string/number/boolean/enum) - register as property
    memset(&data_model_value, 0, sizeof(data_model_value));
    parse_property_constraints(effective, data_model_value);
    parse_readwrite(effective, data_model_value);
    wfa_set_bus_callbackfunc_pointers(fullPath.c_str(), &cbTable);
    wfa_bus_register_namespace(const_cast<char*>(fullPath.c_str()), bus_element_type_property, cbTable, data_model_value, 1);
}

// ------------------------------------------------------------
// Traverse object schema and process all "properties"
// ------------------------------------------------------------
void tr_181_t::traverse_schema(cJSON* root, cJSON* schemaNode, const std::string& basePath)
{
    if (!schemaNode) return;

    // ensure we operate on resolved node (if schemaNode is a wrapper with $ref)
    cJSON* effective = follow_ref_if_any(root, schemaNode);
    if (!effective) return;

    cJSON* props = cJSON_GetObjectItem(effective, "properties");
    if (!props || !cJSON_IsObject(props)) return;

    cJSON* child = props->child;
    while (child) {
        if (child->string) {
            std::string newPath;
            if (!basePath.empty() && basePath.back() != '.')
                newPath = basePath + "." + child->string;
            else
                newPath = basePath + child->string;

            // pass the child's schema node (not child->child) because child is a property pair
            handle_property_node(root, newPath, child);
        }
        child = child->next;
    }
}

// ------------------------------------------------------------
// Entry function
// ------------------------------------------------------------
bool tr_181_t::parse_and_register_schema(const char *filename)
{
    // Load file
    FILE* f = fopen(filename, "rb");
    if (!f) return false;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size < 0) {
        fclose(f);
        return false;
    }
    const size_t uSize = static_cast<size_t>(size);
    std::vector<char> buf(uSize + 1);
    const size_t read = std::fread(buf.data(), 1, uSize, f);
    fclose(f);
    buf[(read < uSize) ? read : uSize] = '\0';

    cJSON* root = cJSON_Parse(buf.data());
    if (!root) return false;

    // Find top-level Network element
    cJSON* props = cJSON_GetObjectItem(root, "properties");
    if (!props) {
        cJSON_Delete(root);
        return false;
    }

    cJSON* child = props->child;
    while (child)
    {
        if (child->string &&
            std::string(child->string).find("Network") != std::string::npos)
        {
            traverse_schema(root, child, "Network");
            break;
        }
        child = child->next;
    }

    cJSON_Delete(root);
    return true;
}

int tr_181_t::register_wfa_dml()
{
    const char *filename = "Data_Elements_JSON_Schema_v3.0.json";
    parse_and_register_schema(filename);

    return RETURN_OK;
}
