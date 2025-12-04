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

// class dm_easy_mesh_ctrl_t;
// class em_ctrl_t;

// dm_easy_mesh_ctrl_t *tr_181_t::m_ctrl = NULL;

void tr_181_t::init(void* ptr)
{
    wifi_bus_desc_t *desc;
    char service_name[] = "tr_181_service";
    int pipefd[2];
	int rcp;

    // tr_181_t::m_ctrl = static_cast<dm_easy_mesh_ctrl_t*>(ptr);

	rcp = pipe2(pipefd, O_DIRECT);
	if (rcp == -1) {
		return;
	}

	// m_nb_pipe_rd = pipefd[0];
	// m_nb_pipe_wr = pipefd[1];


    bus_init(&m_bus_handle);

    if((desc = get_bus_descriptor()) == NULL) {
        printf("%s:%d descriptor is null\n", __func__, __LINE__);
    }
    
    if (desc->bus_open_fn(&m_bus_handle, service_name) != 0) {
        printf("%s:%d bus open failed\n",__func__, __LINE__);
        return;
    }

    register_wfa_dml();
}

int tr_181_t::wfa_set_bus_callbackfunc_pointers(const char *full_namespace, bus_callback_table_t *cb_table)
{
    em_printfout(" namespace:[%s]\n", full_namespace);
    bus_data_cb_func_t bus_data_cb[] = {
        ELEMENT(DE_NETWORK_ID, CB(.get_handler = network_get)),
        ELEMENT(DE_NETWORK_CTRLID, CB(.get_handler = network_get)),
        ELEMENT(DE_NETWORK_COLAGTID, CB(.get_handler = network_get)),
        ELEMENT(DE_NETWORK_DEVNOE, CB(.get_handler = network_get)),
        //ELEMENT_TABLE_ROW(DE_SSID_TABLE, CB(.get_handler = ssid_tget, .table_add_row_handler = ssid_table_add_row_handler)),
        ELEMENT_TABLE_ROW(DE_SSID_TABLE, CB(.table_add_row_handler = ssid_table_add_row_handler)),
        ELEMENT(DE_SSID_SSID, CB(.get_handler = ssid_get)),
        ELEMENT(DE_SSID_BAND, CB(.get_handler = ssid_get)),
        ELEMENT(DE_SSID_ENABLE, CB(.get_handler = ssid_get)),
        ELEMENT(DE_SSID_AKMALLOWE, CB(.get_handler = ssid_get)),
        ELEMENT(DE_SSID_SUITESEL, CB(.get_handler = ssid_get)),
        ELEMENT(DE_SSID_ADVENABLED, CB(.get_handler = ssid_get)),
        ELEMENT(DE_SSID_MFPCONFIG, CB(.get_handler = ssid_get)),
        ELEMENT(DE_SSID_MOBDOMAIN, CB(.get_handler = ssid_get)),
        ELEMENT(DE_SSID_HAULTYPE, CB(.get_handler = ssid_get)),
        // ELEMENT_TABLE_ROW(DE_DEVICE_TABLE, CB(.get_handler = device_tget, .table_add_row_handler = device_table_add_row_handler)),
        // ELEMENT_TABLE_ROW(DE_RADIO_TABLE, CB(.get_handler = radio_tget, .table_add_row_handler = radio_table_add_row_handler)),
        // ELEMENT_TABLE_ROW(DE_BSS_TABLE, CB(.get_handler = bss_tget, .table_add_row_handler = bss_table_add_row_handler)),
        // ELEMENT(DE_STA_TABLE, CB(.get_handler = sta_tget, .table_add_row_handler = sta_table_add_row_handler)),
        ELEMENT_TABLE_ROW(DE_DEVICE_TABLE, CB(.table_add_row_handler = device_table_add_row_handler)),
        ELEMENT_TABLE_ROW(DE_RADIO_TABLE, CB(.table_add_row_handler = radio_table_add_row_handler)),
        ELEMENT_TABLE_ROW(DE_BSS_TABLE, CB(.table_add_row_handler = bss_table_add_row_handler)),
        ELEMENT(DE_STA_TABLE, CB(.table_add_row_handler = sta_table_add_row_handler)),
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
        ELEMENT(DE_BSS_BSSID,            CB(.get_handler = bss_get)),
		ELEMENT(DE_BSS_SSID,             CB(.get_handler = bss_get)),
		ELEMENT(DE_BSS_ENABLED,          CB(.get_handler = bss_get)),
		ELEMENT(DE_BSS_LASTCHG,          CB(.get_handler = bss_get)),
		ELEMENT(DE_BSS_TS,               CB(.get_handler = bss_get)),
		ELEMENT(DE_BSS_UCAST_TX,         CB(.get_handler = bss_get)),
		ELEMENT(DE_BSS_UCAST_RX,         CB(.get_handler = bss_get)),
		ELEMENT(DE_BSS_MCAST_TX,         CB(.get_handler = bss_get)),
		ELEMENT(DE_BSS_MCAST_RX,         CB(.get_handler = bss_get)),
		ELEMENT(DE_BSS_BCAST_TX,         CB(.get_handler = bss_get)),
		ELEMENT(DE_BSS_BCAST_RX,         CB(.get_handler = bss_get)),
		ELEMENT(DE_BSS_EST_BE,           CB(.get_handler = bss_get)),
		ELEMENT(DE_BSS_EST_BK,           CB(.get_handler = bss_get)),
		ELEMENT(DE_BSS_EST_VI,           CB(.get_handler = bss_get)),
		ELEMENT(DE_BSS_EST_VO,           CB(.get_handler = bss_get)),
		ELEMENT(DE_BSS_BYTCNTUNITS,      CB(.get_handler = bss_get)),
		ELEMENT(DE_BSS_PROF1_DIS,        CB(.get_handler = bss_get)),
		ELEMENT(DE_BSS_PROF2_DIS,        CB(.get_handler = bss_get)),
		ELEMENT(DE_BSS_ASSOC_STAT,       CB(.get_handler = bss_get)),
		ELEMENT(DE_BSS_BHAULUSE,         CB(.get_handler = bss_get)),
		ELEMENT(DE_BSS_FHAULUSE,         CB(.get_handler = bss_get)),
		ELEMENT(DE_BSS_R1_DIS,           CB(.get_handler = bss_get)),
		ELEMENT(DE_BSS_R2_DIS,           CB(.get_handler = bss_get)),
		ELEMENT(DE_BSS_MULTI_BSSID,      CB(.get_handler = bss_get)),
		ELEMENT(DE_BSS_TX_BSSID,         CB(.get_handler = bss_get)),
		ELEMENT(DE_BSS_FHAULAKMS,        CB(.get_handler = bss_get)),
		ELEMENT(DE_BSS_BHAULAKMS,        CB(.get_handler = bss_get)),
		ELEMENT(DE_BSS_QM_DESC,          CB(.get_handler = bss_get)),
		ELEMENT(DE_BSS_NUM_STA,          CB(.get_handler = bss_get)),
		ELEMENT(DE_BSS_LINK_IMM,         CB(.get_handler = bss_get)),
		ELEMENT(DE_BSS_FH_SUITE,         CB(.get_handler = bss_get)),
		ELEMENT(DE_BSS_BH_SUITE,         CB(.get_handler = bss_get)),
    };

    bus_data_cb_func_t bus_default_data_cb = { " ",
        { default_get_param_value, default_set_param_value, default_table_add_row_handler,
          default_table_remove_row_handler, default_event_sub_handler, NULL }
    };

    uint32_t index = 0;
    bool     table_found = false;

    for (index = 0; index < (uint32_t)ARRAY_SIZE(bus_data_cb); index++) {
	    //em_printfout("comparing %s--%s", full_namespace, bus_data_cb[index].cb_table_name);
        if (strcmp(full_namespace, bus_data_cb[index].cb_table_name) == 0) {
            memcpy(cb_table, &bus_data_cb[index].cb_func, sizeof(bus_callback_table_t));
            table_found = true;
            //  em_printfout("strcmp namespace:[%s]\n", full_namespace);
            break;
        }
    }

    if (table_found == false) {
        // em_printfout("default cb set for namespace:[%s]\n", full_namespace);
        memcpy(cb_table, &bus_default_data_cb.cb_func, sizeof(bus_callback_table_t));
    }

    return RETURN_OK;
}

int tr_181_t::wfa_bus_register_namespace(char *full_namespace, bus_element_type_t element_type,
                            bus_callback_table_t cb_table, data_model_properties_t  data_model_value, int num_of_rows)
{   
    bus_data_element_t dataElements = { 0 };

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
            dataElements.num_of_table_row = num_of_rows;
        }
        // em_printfout("Add number of row:%d input value:%d\n", dataElements.num_of_table_row, num_of_rows);
    }

    uint32_t num_elements = 1;
    bus_error_t rc = get_bus_descriptor()->bus_reg_data_element_fn(&m_bus_handle, &dataElements, num_elements);
    if (rc != bus_error_success) {
        em_printfout("bus: bus_regDataElements failed:%s\n", full_namespace);
    }
    // em_printfout("bus: bus_regDataElements success:%s", full_namespace);

    return RETURN_OK;
}

bus_error_t tr_181_t::raw_data_set(raw_data_t *p_data, bool b)
{
    em_printfout("Inside raw_data_set bool:%d", b);
    p_data->data_type = bus_data_type_boolean;
    p_data->raw_data.b = b;
    return bus_error_success;
}

bus_error_t tr_181_t::raw_data_set(raw_data_t *p_data, int32_t i)
{
    em_printfout("Inside raw_data_set int32:%d", i);
    p_data->data_type = bus_data_type_int32;
    p_data->raw_data.i32 = i;
    return bus_error_success;
}

bus_error_t tr_181_t::raw_data_set(raw_data_t *p_data, uint8_t u)
{
    em_printfout("Inside raw_data_set uint8:%d", u);
    p_data->data_type = bus_data_type_uint8;
    p_data->raw_data.u8 = u;
    return bus_error_success;
}

bus_error_t tr_181_t::raw_data_set(raw_data_t *p_data, uint16_t u)
{
    em_printfout("Inside raw_data_set uint16:%d", u);
    p_data->data_type = bus_data_type_uint16;
    p_data->raw_data.u16 = u;
    return bus_error_success;
}

bus_error_t tr_181_t::raw_data_set(raw_data_t *p_data, uint32_t u)
{
    em_printfout("Inside raw_data_set uint32:%d", u);
    p_data->data_type = bus_data_type_uint32;
    p_data->raw_data.u32 = u;
    return bus_error_success;
}

bus_error_t tr_181_t::raw_data_set(raw_data_t *p_data, const char *str)
{
    em_printfout("Inside raw_data_set const char:%s", str);
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
    em_printfout("Inside");
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
    em_printfout("Inside");
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
    em_printfout("Inside");
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
    em_printfout("enter:%s\\r\\n", event_name);
    return bus_error_success;
}

bus_error_t tr_181_t::default_set_param_value(char* event_name, raw_data_t* p_data, struct bus_user_data* user_data) {
    //(void)p_data;
    p_data->data_type = bus_data_type_boolean;
    p_data->raw_data.b = 0;
    p_data->raw_data_len = sizeof(bool);

    (void)user_data;
    // em_printfout("enter:%s\\r\\n", event_name);
    return bus_error_success;
}

bus_error_t tr_181_t::default_table_add_row_handler(const char* tableName, const char* aliasName, uint32_t* instNum) {
    (void)aliasName;
    // Set a dummy instance number for testing
    if (instNum != NULL) {
        *instNum = 1; 
    }
    em_printfout("Added table:%s\\r\\n", tableName);
    return bus_error_success;
}

bus_error_t tr_181_t::default_table_remove_row_handler(const char* rowName) {
    em_printfout("Removed row:%s\\r\\n",  rowName);
    return bus_error_success;
}

bus_error_t tr_181_t::default_event_sub_handler(char* eventName, bus_event_sub_action_t action, 
                                               int32_t interval, bool* autoPublish) {
    (void)autoPublish;
    em_printfout("enter:%s: action:%d interval:%d\r\n", eventName, action, interval);
    return bus_error_success;
}


bus_error_t tr_181_t::network_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    em_printfout("event name: %s\n", event_name);
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

    em_printfout("event name: %s\n", event_name);
    if (em_ctrl != NULL)
    {
        //m_ctrl->device_tget(event_name, p_data, user_data, device_tget_inner);
        em_ctrl->get_dm_ctrl()->device_get(event_name, p_data);
        return bus_error_success;
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::ssid_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    em_printfout("event name: %s", event_name);
    if (em_ctrl != NULL)
    {
        em_ctrl->get_dm_ctrl()->device_get(event_name, p_data);
        return bus_error_success;
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::device_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    em_printfout("event name: %s", event_name);
    if (em_ctrl != NULL)
    {
        em_ctrl->get_dm_ctrl()->device_get(event_name, p_data);
        return bus_error_success;
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::radio_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    em_printfout("event name: %s", event_name);
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

    em_printfout("event name: %s", event_name);
    if (em_ctrl != NULL)
    {
        em_ctrl->get_dm_ctrl()->bss_get(event_name, p_data);
        return bus_error_success;
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::radio_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    em_printfout("event name: %s", event_name);
    if (em_ctrl != NULL)
    {
        em_ctrl->get_dm_ctrl()->device_get(event_name, p_data);
        return bus_error_success;
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::bss_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    em_printfout("event name: %s", event_name);
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

    em_printfout("event name: %s", event_name);
    if (em_ctrl != NULL)
    {
        em_ctrl->get_dm_ctrl()->device_get(event_name, p_data);
        return bus_error_success;
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::device_table_add_row_handler(const char* table_name, const char* alias_name, uint32_t* instance_number)
{
    em_printfout("table name: %s", table_name);
    return bus_error_success;
}

bus_error_t tr_181_t::radio_table_add_row_handler(const char* table_name, const char* alias_name, uint32_t* instance_number)
{
    em_printfout("table name: %s", table_name);
    return bus_error_success;
}

bus_error_t tr_181_t::bss_table_add_row_handler(const char* table_name, const char* alias_name, uint32_t* instance_number)
{
    em_printfout("table name: %s", table_name);
    return bus_error_success;
}

bus_error_t tr_181_t::ssid_table_add_row_handler(const char* table_name, const char* alias_name, uint32_t* instance_number)
{
    em_printfout("table name: %s", table_name);
    return bus_error_success;
}

bus_error_t tr_181_t::sta_table_add_row_handler(const char* table_name, const char* alias_name, uint32_t* instance_number)
{
    em_printfout("table name: %s", table_name);
    return bus_error_success;
}

bool remove_substring(char *str)
{
    size_t len = strlen(str);
    if (len > strlen(".{i}.")) {
        if(strcmp(str + (len - strlen(".{i}.")), ".{i}.") == 0) {
            str[(len - strlen("{i}."))] = 0;
        } else if(strcmp(str + (len - strlen(".{i}")), ".{i}") == 0) {
            str[(len - strlen("{i}"))] = 0;
        } else {
            return false;
        }
        em_printfout("%s:%d: bus: removeSubstring is matched with %s\n",
            __func__, __LINE__, str);
        return true;
    }

    return false;
}

#define DEVICE_LIST "DeviceList."
#define RADIO_LIST  "RadioList."
#define BSS_LIST    "BSSList."

bus_error_t tr_181_t::reg_table_row(char *name, int index)
{
    wifi_bus_desc_t *desc;
    bus_error_t rc = bus_error_invalid_input;

    if((desc = get_bus_descriptor()) == NULL) {
        printf("%s:%d descriptor is null\n", __func__, __LINE__);
    }

    // rc = desc->bus_data_get_fn(&m_bus_handle, name, NULL);
    // em_printfout("Table row add  get rc: %d", rc);
    // if (rc == bus_error_success) {
    //     em_printfout("Table row already exists for name:%s index:%d, rc:%d", name, index, rc);
    //     return bus_error_success;
    // }

    rc = desc->bus_data_get_fn(&m_bus_handle, name, NULL);
    em_printfout(" ====>>> Before Table row add  get rc: %d", rc);

    em_printfout("Calling reg_table for name:%s index:%d", name, index);
    rc = desc->bus_reg_table_row_fn(&m_bus_handle, name, index, NULL);
    

    rc = desc->bus_data_get_fn(&m_bus_handle, name, NULL);
    em_printfout(" ====>>> Table row add  get rc: %d", rc);

    return rc;
}

int tr_181_t::find_radio(dm_easy_mesh_t *dm)
{
    unsigned int idx = 0;
    mac_addr_str_t  radio_str, bss_str;

    dm_easy_mesh_t::macbytes_to_string(dm->m_bss[(dm->m_num_bss - 1)].m_bss_info.ruid.mac, bss_str);
    for (idx = 1; idx <= dm->get_num_radios(); idx++) {
        //DEBUG
        dm_easy_mesh_t::macbytes_to_string(dm->get_radio_info(idx - 1)->id.ruid, radio_str);
        em_printfout("Comparing i:%d mac radio:%s bss:%s", idx, radio_str, bss_str);

        if (strcmp(bss_str, radio_str) == 0) {
            em_printfout("Match found, returning %d", idx);
            return idx;
        }
    }

    em_printfout("No match found for bss:%s", bss_str);
    return 0;
}

bus_error_t tr_181_t::add_table_row(char const *name, dm_easy_mesh_t *dm)
{
    int device_index = -1;
    int i = 0, radio_num = 0;
    bus_error_t rc = bus_error_invalid_input;
    char namespace_full[256], temp[256];
    int index = 0;
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();
    
    em_printfout("add_table_row with Device instance : %d\n", dm->get_id());
    device_index = dm->get_id();
    em_printfout("Name:%s device_num:%d", name, device_index);

    if(strcmp(name, DE_DEVICE_TABLE) == 0) {
        em_printfout("Inside DeviceList. device_num:%d", device_index);
        snprintf(namespace_full, sizeof(namespace_full), "%s%s",
            DATAELEMS_NETWORK, DEVICE_LIST);
        index = device_index;
    } else if(strcmp(name, DE_RADIO_TABLE) == 0) {
        em_printfout("Inside RadioList. radio_num:%d", dm->m_num_radios);
        snprintf(namespace_full, sizeof(namespace_full), "%s%s%d.%s", 
            DATAELEMS_NETWORK, DEVICE_LIST, device_index, RADIO_LIST);
        index = device_index;
    } else if(strcmp(name, DE_BSS_TABLE) == 0) {
        em_printfout("Inside BSSList. bss_num:%d", dm->m_num_bss);
        radio_num = em_ctrl->get_dm_ctrl()->find_radio(dm);
        snprintf(namespace_full, sizeof(namespace_full), "%s%s%d.%s%d.%s", 
            DATAELEMS_NETWORK, DEVICE_LIST, device_index, RADIO_LIST, radio_num, BSS_LIST);
        index = ++dm->m_radio[radio_num-1].m_num_bss;
    }

    rc = em_ctrl->get_dm_ctrl()->reg_table_row(namespace_full, index);    

    return rc;
}

bus_error_t tr_181_t::wifi_elem_num_of_table_row(char* event_name, uint32_t* table_row_size)
{
    // Return 0 rows for all tables for now
    if (table_row_size != NULL) {
        *table_row_size = 0;
    }
    //em_printfout("enter:%s\\r\\n", event_name);
    return bus_error_success;
}

#if 0
void tr_181_t::register_cjson_namespace(cJSON *node, const std::string &prefix)
{
    if (!node)
        return;

    bus_callback_table_t cb_table = {0};
    data_model_properties_t data_model_value;

    for (cJSON *child = node->child; child; child = child->next)
    {
        std::string key = child->string ? child->string : "";
        std::string full_path;
        if(prefix.empty()) {
            full_path = key;
        } else if(prefix.back() == '.') {
            full_path = prefix + key;
        } else {
            full_path = prefix + "." + key;
        }

        if (cJSON_IsObject(child))
        {
            em_printfout("%s", full_path.c_str());
            wfa_set_bus_callbackfunc_pointers(full_path.c_str(), &cb_table);
            memset(&data_model_value, 0, sizeof(data_model_value));
            wfa_bus_register_namespace((char *)full_path.c_str(),
                                       bus_element_type_property, cb_table, data_model_value, 1);

            // Recurse into the object's children
            register_cjson_namespace(child, full_path);
        }
        else if (cJSON_IsArray(child))
        {
            std::string array_path;
            if(prefix.empty()) {
                array_path = key + ".{i}.";
            } else if(prefix.back() == '.') {
                array_path = prefix + key + ".{i}.";
            } else {
                array_path = prefix + "." + key + ".{i}.";
            }

            em_printfout("%s", array_path.c_str());
            wfa_set_bus_callbackfunc_pointers(array_path.c_str(), &cb_table);
            memset(&data_model_value, 0, sizeof(data_model_value));

            // Now inspect the first element of the array
            cJSON *first_item = cJSON_GetArrayItem(child, 0);
            if (first_item && cJSON_IsObject(first_item))
            {
                //set the get and set handlers NULL for table entries
                cb_table.get_handler = NULL;
                cb_table.set_handler = NULL;
                wfa_bus_register_namespace((char *)array_path.c_str(),
                                       bus_element_type_table, cb_table, data_model_value, 0);
                register_cjson_namespace(first_item, array_path);
            }
            else if (first_item && (cJSON_IsString(first_item) || cJSON_IsNumber(first_item)))
            {
                std::string prop_path;
                if(prefix.empty())
                    prop_path = key;
                else if(prefix.back() == '.')
                    prop_path = prefix + key;
                else
                    prop_path = prefix + "." + key;

                em_printfout("%s Primitive array as property", prop_path.c_str());
                wfa_set_bus_callbackfunc_pointers(prop_path.c_str(), &cb_table);
                memset(&data_model_value, 0, sizeof(data_model_value));
                wfa_bus_register_namespace((char *)prop_path.c_str(),
                                       bus_element_type_property, cb_table, data_model_value, 1);
            }
        }
        else if (cJSON_IsString(child) || cJSON_IsNumber(child) || cJSON_IsBool(child))
        {
            em_printfout("%s", full_path.c_str());
            wfa_set_bus_callbackfunc_pointers(full_path.c_str(), &cb_table);
            memset(&data_model_value, 0, sizeof(data_model_value));
            wfa_bus_register_namespace((char *)full_path.c_str(),
                                       bus_element_type_property, cb_table, data_model_value, 1);
        }
        else
        {
            em_printfout("Ignoring unsupported node: %s", full_path.c_str());
        }
    }
}

/**
 * Main entry: Parse JSON file and register Network hierarchy into RBUS.
 * Root key: "wfa-dataelements:Network"
 */
void tr_181_t::generate_namespaces_without_lib_refined(const std::string &filename)
{
    std::ifstream file(filename);
    if (!file.is_open())
    {
        std::cerr << "Error: Could not open " << filename << std::endl;
        return;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string json_str = buffer.str();

    cJSON *root = cJSON_Parse(json_str.c_str());
    if (!root)
    {
        std::cerr << "Error parsing JSON" << std::endl;
        return;
    }

    // Root node of interest: wfa-dataelements:Network
    cJSON *network_node = cJSON_GetObjectItem(root, "wfa-dataelements:Network");
    if (!network_node)
    {
        std::cerr << "Root key 'wfa-dataelements:Network' not found." << std::endl;
        cJSON_Delete(root);
        return;
    }

    bus_callback_table_t cb_table = {0};
    data_model_properties_t data_model_value;
    std::string root_path = "Network";

    // Register the root property node
    em_printfout("%s", root_path.c_str());
    wfa_set_bus_callbackfunc_pointers(root_path.c_str(), &cb_table);
    memset(&data_model_value, 0, sizeof(data_model_value));
    wfa_bus_register_namespace((char *)root_path.c_str(),
                               bus_element_type_property, cb_table, data_model_value, 1);

    // Recurse through the full JSON hierarchy
    register_cjson_namespace(network_node, root_path);

    //print_registered_elems(get_bus_mux_reg_cb_map(), 0);
    cJSON_Delete(root);
    std::cout << "\nJSON namespace registration complete.\n";
}
#endif

/*bool tr_181_t::parseFile(const std::string& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        std::cerr << "Error opening file: " << filePath << std::endl;
        return false;
    }

    std::string rawJson((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    cJSON* root = cJSON_Parse(rawJson.c_str());
    if (!root) {
        std::cerr << "JSON parse error: " << cJSON_GetErrorPtr() << std::endl;
        return false;
    }

    bool result = decodeJsonObject(root);
    cJSON_Delete(root);
    return result;
}

bool tr_181_t::decodeJsonObject(cJSON* root) {
    cJSON* properties = cJSON_GetObjectItem(root, "properties");
    if (!properties) {
        std::cerr << "Missing 'properties' in schema." << std::endl;
        return false;
    }

    cJSON* networkObj = cJSON_GetObjectItem(properties, "wfa-dataelements:Network");
    if (networkObj) {
        cJSON* networkProps = cJSON_GetObjectItem(networkObj, "properties");
        if (networkProps) {
            decodeObjectsRecursive(networkProps, nullptr, "Network");
        }
    }
    return true;
}

void tr_181_t::processDefinitions(cJSON* definitions) {
    // For now, just log definitions
    cJSON* def = definitions->child;
    while (def) {
        std::cout << "Definition found: " << def->string << std::endl;
        def = def->next;
    }
}

void tr_181_t::decodeObjectsRecursive(cJSON* node, cJSON* defObj, const std::string& namePrefix) {
    if (!node) return;

    cJSON* child = node->child;
    while (child) {
        if (!child->string) {
            child = child->next;
            continue;
        }

        // Strip wfa-dataelements: prefix if present
        std::string keyName = child->string;
        if (keyName.find("wfa-dataelements:") == 0) {
            keyName = keyName.substr(strlen("wfa-dataelements:"));
        }

        std::string currentName = namePrefix.empty() ? keyName : namePrefix + "." + keyName;

        bus_callback_table_t cbTable = {0};
        data_model_properties_t data_model_value{};

        // Register container object
        wfa_set_bus_callbackfunc_pointers(currentName.c_str(), &cbTable);
        memset(&data_model_value, 0, sizeof(data_model_value));
        registerNamespace(currentName, data_model_value, bus_element_type_property, cbTable, 0);

        // Check type
        cJSON* typeItem = cJSON_GetObjectItem(child, "type");
        if (typeItem && cJSON_IsString(typeItem)) {
            const char* typeVal = typeItem->valuestring;

            if (strcmp(typeVal, "array") == 0) {
                // Array of objects → table
                std::string arrayNamespace = currentName + ".{i}";
                wfa_set_bus_callbackfunc_pointers(arrayNamespace.c_str(), &cbTable);
                cbTable.get_handler = NULL;
                cbTable.set_handler = NULL;
                memset(&data_model_value, 0, sizeof(data_model_value));
                registerNamespace(arrayNamespace, data_model_value, bus_element_type_table, cbTable, 0);

                // Dive into items
                cJSON* items = cJSON_GetObjectItem(child, "items");
                if (items) {
                    cJSON* itemProps = cJSON_GetObjectItem(items, "properties");
                    if (itemProps) {
                        decodeObjectsRecursive(itemProps, defObj, arrayNamespace);
                    }
                }
            }
            else if (strcmp(typeVal, "object") != 0) {
                // Leaf property
                wfa_set_bus_callbackfunc_pointers(currentName.c_str(), &cbTable);
                memset(&data_model_value, 0, sizeof(data_model_value));
                registerNamespace(currentName, data_model_value, bus_element_type_property, cbTable, 0);
            }
        }

        // Dive into nested properties
        cJSON* properties = cJSON_GetObjectItem(child, "properties");
        if (properties && cJSON_IsObject(properties)) {
            decodeObjectsRecursive(properties, defObj, currentName);
        }

        child = child->next;
    }
}

void tr_181_t::constructNamespaceAndRegister(cJSON* cfgParam, cJSON* defObj, const std::string& namePrefix) {
    if (cJSON_IsObject(cfgParam)) {
        cJSON* currentElement = cfgParam->child;
        bus_callback_table_t cbTable = {0};
        data_model_properties_t data_model_value;

        while (currentElement) {
            std::string fullNamespace = namePrefix + "." + currentElement->string;

            if (cJSON_IsArray(currentElement)) {
                int numTables = 1;
                if (currentElement->prev && strcmp(currentElement->prev->string, MAX_NUM_OF_OBJECTS_NAME) == 0) {
                    numTables = currentElement->prev->valuedouble;
                }
                cbTable.get_handler = nullptr;
                cbTable.set_handler = nullptr;

                memset(&data_model_value, 0, sizeof(data_model_value));
                std::string arrayNamespace = fullNamespace + ".{i}";
                wfa_set_bus_callbackfunc_pointers(arrayNamespace.c_str(), &cbTable);
                registerNamespace(fullNamespace + ".{i}", data_model_value, bus_element_type_table, cbTable, numTables);
                addArrayNodeElements(currentElement, cJSON_GetArraySize(currentElement), fullNamespace, defObj, cbTable);
            } else {
                data_model_properties_t props = {};
                cJSON* typeItem = cJSON_GetObjectItem(currentElement, "type");
                if (typeItem && cJSON_IsString(typeItem)) {
                    getDataModelProperties(defObj, typeItem->valuestring, props);
                }
                cJSON* writableItem = cJSON_GetObjectItem(currentElement, "writable");
                props.data_permission = (writableItem && writableItem->type == cJSON_True);
                wfa_set_bus_callbackfunc_pointers(fullNamespace.c_str(), &cbTable);
                registerNamespace(fullNamespace, props, bus_element_type_property, cbTable, 0);
            }
            currentElement = currentElement->next;
        }
    }
}

void tr_181_t::addArrayNodeElements(cJSON* arrayObj, int numElements, const std::string& namePrefix, cJSON* defObj, bus_callback_table_t cbTable) {
    for (int i = 0; i < numElements; i++) {
        cJSON* currentElement = cJSON_GetArrayItem(arrayObj, i);
        if (!currentElement) continue;

        std::string fullNamespace = namePrefix + "." + currentElement->string;
        data_model_properties_t props = {};
        cJSON* typeItem = cJSON_GetObjectItem(currentElement, "type");
        if (typeItem && cJSON_IsString(typeItem)) {
            getDataModelProperties(defObj, typeItem->valuestring, props);
        }
        cJSON* writableItem = cJSON_GetObjectItem(currentElement, "writable");
        props.data_permission = (writableItem && writableItem->type == cJSON_True);
        wfa_set_bus_callbackfunc_pointers(fullNamespace.c_str(), &cbTable);
        registerNamespace(fullNamespace, props, bus_element_type_property, cbTable, 0);
    }
}

void tr_181_t::registerNamespace(const std::string& fullNamespace, const data_model_properties_t& props, bus_element_type_t type, bus_callback_table_t cbTable, int numRows) {
    std::cout << "Registering namespace: " << fullNamespace << std::endl;
    wfa_bus_register_namespace(const_cast<char*>(fullNamespace.c_str()), type, cbTable, props, numRows);
}

void tr_181_t::getDataModelProperties(cJSON* defObj, const char* typeStr, data_model_properties_t& props) {
    cJSON* param = cJSON_GetObjectItem(defObj, typeStr);
    if (!param) return;

    cJSON* child = param->child;
    while (child) {
        if (strcmp(child->string, "minimum") == 0) {
            props.min_data_range = child->valuedouble;
        } else if (strcmp(child->string, "maximum") == 0) {
            props.max_data_range = child->valuedouble;
        }
        child = child->next;
    }
}*/

// Resolve $ref if present on the node; otherwise return the node itself.
// This uses your existing resolve_ref method.
cJSON* tr_181_t::follow_ref_if_any(cJSON* root, cJSON* node)
{
    if (!node) return nullptr;
    cJSON* r = cJSON_GetObjectItem(node, "$ref");
    if (r && cJSON_IsString(r)) {
        cJSON* resolved = resolve_ref(root, r->valuestring);
        return resolved ? resolved : node;
    }
    // handle combiners with refs like oneOf/anyOf: prefer first ref/object
    cJSON* comb = cJSON_GetObjectItem(node, "oneOf");
    if (!comb) comb = cJSON_GetObjectItem(node, "anyOf");
    if (comb && cJSON_IsArray(comb)) {
        cJSON* it = comb->child;
        while (it) {
            cJSON* maybeRef = cJSON_GetObjectItem(it, "$ref");
            if (maybeRef && cJSON_IsString(maybeRef)) {
                cJSON* resolved = resolve_ref(root, maybeRef->valuestring);
                if (resolved) return resolved;
            }
            // if the variant itself has properties, prefer it
            if (cJSON_GetObjectItem(it, "properties"))
                return it;
            it = it->next;
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

// ------------------------------------------------------------
// Handle ANY property under an object: decide if TABLE or PROPERTY
// ------------------------------------------------------------
void tr_181_t::handle_property_node(cJSON* root, const std::string& fullPath, cJSON* propertySchema)
{
    if (!propertySchema) return;

    bus_callback_table_t cbTable = {0};
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
    cJSON* typeNode = cJSON_GetObjectItem(effective, "type");
    if (typeNode && cJSON_IsString(typeNode) && strcmp(typeNode->valuestring, "array") == 0) {
        std::string tableName = fullPath + ".{i}";

        // register table namespace
        wfa_set_bus_callbackfunc_pointers(tableName.c_str(), &cbTable);
        // reset and fill constraints for the array property itself
        memset(&data_model_value, 0, sizeof(data_model_value));
        parse_property_constraints(effective, data_model_value);
        parse_readwrite(effective, data_model_value);
        cbTable.get_handler = NULL;
        cbTable.set_handler = NULL;
        wfa_bus_register_namespace((char*)tableName.c_str(), bus_element_type_table, cbTable, data_model_value, 1);

        // now inspect items
        cJSON* items = cJSON_GetObjectItem(effective, "items");
        if (!items) return;

        cJSON* itemsEff = follow_ref_if_any(root, items);
        if (!itemsEff) return;

        cJSON* itemProps = cJSON_GetObjectItem(itemsEff, "properties");
        if (itemProps && cJSON_IsObject(itemProps)) {
            // expand row children under tableName (no trailing dot)
            traverse_schema(root, itemsEff, tableName);
        } else {
            // primitive array -> register the row as property
            memset(&data_model_value, 0, sizeof(data_model_value));
            parse_property_constraints(itemsEff, data_model_value);
            parse_readwrite(itemsEff, data_model_value);
            wfa_set_bus_callbackfunc_pointers(tableName.c_str(), &cbTable);
            wfa_bus_register_namespace((char*)tableName.c_str(), bus_element_type_property, cbTable, data_model_value, 1);
        }
        return;
    }

    // 4) If type is object (but had no direct properties above),
    // try to resolve any nested $ref and check again
    if (typeNode && cJSON_IsString(typeNode) && strcmp(typeNode->valuestring, "object") == 0) {
        // we've already tried follow_ref_if_any at top-level; if still no properties, treat as leaf object
        memset(&data_model_value, 0, sizeof(data_model_value));
        parse_property_constraints(effective, data_model_value);
        parse_readwrite(effective, data_model_value);
        wfa_set_bus_callbackfunc_pointers(fullPath.c_str(), &cbTable);
        wfa_bus_register_namespace((char*)fullPath.c_str(), bus_element_type_property, cbTable, data_model_value, 1);
        return;
    }

    // 5) Fallback: primitive (string/number/boolean/enum) - register as property
    memset(&data_model_value, 0, sizeof(data_model_value));
    parse_property_constraints(effective, data_model_value);
    parse_readwrite(effective, data_model_value);
    wfa_set_bus_callbackfunc_pointers(fullPath.c_str(), &cbTable);
    wfa_bus_register_namespace((char*)fullPath.c_str(), bus_element_type_property, cbTable, data_model_value, 1);
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
// Entry function you call from parseFile()
// ------------------------------------------------------------
bool tr_181_t::parse_and_register_schema(const char *filename)
{
    // Load file
    FILE* f = fopen(filename, "rb");
    if (!f) return false;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    std::vector<char> buf(size + 1);
    fread(buf.data(), 1, size, f);
    buf[size] = 0;
    fclose(f);

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
    //const std::string filename = "Data_Elements_MultiAP_Example_JSON_v3.0.json";
    const char *filename = "Data_Elements_JSON_Schema_v3.0.json";
    parse_and_register_schema(filename);
    return RETURN_OK;
}
