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

//todo: test code remove after node sync is implemented
mac_addr_str_t g_temp_node_mac = {0};

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
        ELEMENT(DE_NETWORK_ID,            CALLBACK_GETTER(network_get)),
        ELEMENT(DE_NETWORK_CTRLID,        CALLBACK_GETTER(network_get)),
        ELEMENT(DE_NETWORK_COLAGTID,      CALLBACK_GETTER(network_get)),
        ELEMENT(DE_NETWORK_DEVNOE,        CALLBACK_GETTER(network_get)),
        ELEMENT(DE_SSID_TABLE,            CALLBACK_GETTER(ssid_tget)),
        ELEMENT(DE_SSID_SSID,             CALLBACK_GETTER(ssid_get)),
        ELEMENT(DE_SSID_BAND,             CALLBACK_GETTER(ssid_get)),
        ELEMENT(DE_SSID_ENABLE,           CALLBACK_GETTER(ssid_get)),
        ELEMENT(DE_SSID_AKMALLOWE,        CALLBACK_GETTER(ssid_get)),
        ELEMENT(DE_SSID_SUITESEL,         CALLBACK_GETTER(ssid_get)),
        ELEMENT(DE_SSID_ADVENABLED,       CALLBACK_GETTER(ssid_get)),
        ELEMENT(DE_SSID_MFPCONFIG,        CALLBACK_GETTER(ssid_get)),
        ELEMENT(DE_SSID_MOBDOMAIN,        CALLBACK_GETTER(ssid_get)),
        ELEMENT(DE_SSID_HAULTYPE,         CALLBACK_GETTER(ssid_get)),
        ELEMENT(DE_DEVICE_TABLE,          CALLBACK_GETTER(device_tget)),
        ELEMENT(DE_DEVICE_ID,                     CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_MAPCAP,                 CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_NUMRADIO,               CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_COLLINT,                CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_RUASSOC,                CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_MAXRRATE,               CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_MAPPROF,                CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_APMERINT,               CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_MANUFACT,               CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_SERIALNO,               CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_MFCMODEL,               CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_SWVERSION,              CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_EXECENV,                CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_LSDSTALIST,             CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_BTMSDSTALIST,           CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_MAXVIDS,                CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_BPRIO,                  CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_EPRIO,                  CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_TSEPPOLI,               CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_STVMAP,                 CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_DSCPM,                  CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_MAXPRIRULE,             CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_COUNTRCODE,             CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_PRIOSUPP,               CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_REPINDSCAN,             CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_TRASEPALW,              CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_SERPRIOALW,             CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_STASDISALW,             CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_DFSENABLE,              CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_MAXUSASSOCREPRATE,      CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_STASSTATE,              CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_COORCACALW,             CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_CONOPMODE,              CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_BHMACADDR,              CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_BHDMACADDR,             CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_BHPHYRATE,              CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_TRSEPCAP,               CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_EASYCCAP,               CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_TESTCAP,                CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_BSTAMLDMACLINK,         CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_MACNUMMLDS,             CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_BHALID,                 CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_TIDLMAP,                CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_ASSOCSTAREPINT,         CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_BHMEDIATYPE,            CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_RADIONOE,               CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_CACSTATNOE,             CALLBACK_GETTER(device_get)),
        ELEMENT(DE_DEVICE_BHDOWNNOE,              CALLBACK_GETTER(device_get)),
        ELEMENT(DE_RADIO_TABLE,            CALLBACK_GETTER(radio_tget)),
        ELEMENT(DE_RADIO_ID,               CALLBACK_GETTER(radio_get)),
        ELEMENT(DE_RADIO_ENABLED,          CALLBACK_GETTER(radio_get)),
        ELEMENT(DE_RADIO_NOISE,            CALLBACK_GETTER(radio_get)),
        ELEMENT(DE_RADIO_UTILIZATION,      CALLBACK_GETTER(radio_get)),
        ELEMENT(DE_RADIO_TRANSMIT,         CALLBACK_GETTER(radio_get)),
        ELEMENT(DE_RADIO_RECEIVESELF,      CALLBACK_GETTER(radio_get)),
        ELEMENT(DE_RADIO_RECEIVEOTHER,     CALLBACK_GETTER(radio_get)),
        ELEMENT(DE_RADIO_CHIPVENDOR,       CALLBACK_GETTER(radio_get)),
        ELEMENT(DE_RADIO_CURROPNOE,        CALLBACK_GETTER(radio_get)),
        ELEMENT(DE_RADIO_BSSNOE,           CALLBACK_GETTER(radio_get)),
        ELEMENT(DE_RCAPS_HTCAPS,           CALLBACK_GETTER(rcaps_get)),
        ELEMENT(DE_RCAPS_VHTCAPS,          CALLBACK_GETTER(rcaps_get)),
        ELEMENT(DE_RCAPS_CAPOPNOE,         CALLBACK_GETTER(rcaps_get)),
        ELEMENT(DE_CAPS_WF6AP,             CALLBACK_GETTER(wf6ap_tget)),
        ELEMENT(DE_WF6AP_HE160,            CALLBACK_GETTER(wf6ap_get)),
        ELEMENT(DE_WF6AP_HE8080,           CALLBACK_GETTER(wf6ap_get)),
        ELEMENT(DE_WF6AP_MCSNSS,           CALLBACK_GETTER(wf6ap_get)),
        ELEMENT(DE_WF6AP_SU_BFER,          CALLBACK_GETTER(wf6ap_get)),
        ELEMENT(DE_WF6AP_SU_BFEE,          CALLBACK_GETTER(wf6ap_get)),
        ELEMENT(DE_WF6AP_MU_BFER,          CALLBACK_GETTER(wf6ap_get)),
        ELEMENT(DE_WF6AP_BFEE_80L,         CALLBACK_GETTER(wf6ap_get)),
        ELEMENT(DE_WF6AP_BFEE_80A,         CALLBACK_GETTER(wf6ap_get)),
        ELEMENT(DE_WF6AP_UL_MUMIMO,        CALLBACK_GETTER(wf6ap_get)),
        ELEMENT(DE_WF6AP_UL_OFDMA,         CALLBACK_GETTER(wf6ap_get)),
        ELEMENT(DE_WF6AP_DL_OFDMA,         CALLBACK_GETTER(wf6ap_get)),
        ELEMENT(DE_WF6AP_MAX_DL_MUMIMO,    CALLBACK_GETTER(wf6ap_get)),
        ELEMENT(DE_WF6AP_MAX_UL_MUMIMO,    CALLBACK_GETTER(wf6ap_get)),
        ELEMENT(DE_WF6AP_MAX_DL_OF,        CALLBACK_GETTER(wf6ap_get)),
        ELEMENT(DE_WF6AP_MAX_UL_OF,        CALLBACK_GETTER(wf6ap_get)),
        ELEMENT(DE_WF6AP_RTS,              CALLBACK_GETTER(wf6ap_get)),
        ELEMENT(DE_WF6AP_MU_RTS,           CALLBACK_GETTER(wf6ap_get)),
        ELEMENT(DE_WF6AP_MULTI_BSS,        CALLBACK_GETTER(wf6ap_get)),
        ELEMENT(DE_WF6AP_MU_EDCA,          CALLBACK_GETTER(wf6ap_get)),
        ELEMENT(DE_WF6AP_TWT_REQ,          CALLBACK_GETTER(wf6ap_get)),
        ELEMENT(DE_WF6AP_TWT_RSP,          CALLBACK_GETTER(wf6ap_get)),
        ELEMENT(DE_WF6AP_SPAT_REUSE,       CALLBACK_GETTER(wf6ap_get)),
        ELEMENT(DE_WF6AP_ANT_CH_USE,       CALLBACK_GETTER(wf6ap_get)),
        ELEMENT(DE_CAPS_WF7AP,             CALLBACK_GETTER(wf7ap_tget)),
        ELEMENT(DE_WF7AP_EMLMR,            CALLBACK_GETTER(wf7ap_get)),
        ELEMENT(DE_WF7AP_EMLSR,            CALLBACK_GETTER(wf7ap_get)),
        ELEMENT(DE_WF7AP_STR,              CALLBACK_GETTER(wf7ap_get)),
        ELEMENT(DE_WF7AP_NSTR,             CALLBACK_GETTER(wf7ap_get)),
        ELEMENT(DE_WF7AP_TID_MAP,          CALLBACK_GETTER(wf7ap_get)),
        ELEMENT(DE_CUROP_TABLE,            CALLBACK_GETTER(curops_tget)),
        ELEMENT(DE_CUROP_CLASS,            CALLBACK_GETTER(curops_get)),
        ELEMENT(DE_CUROP_CHANNEL,          CALLBACK_GETTER(curops_get)),
        ELEMENT(DE_CUROP_TXPOWER,          CALLBACK_GETTER(curops_get)),
        ELEMENT(DE_BSS_TABLE,              CALLBACK_GETTER(bss_tget)),
        ELEMENT(DE_BSS_BSSID,              CALLBACK_GETTER(bss_get)),
        ELEMENT(DE_BSS_SSID,               CALLBACK_GETTER(bss_get)),
        ELEMENT(DE_BSS_ENABLED,            CALLBACK_GETTER(bss_get)),
        ELEMENT(DE_BSS_LASTCHG,            CALLBACK_GETTER(bss_get)),
        ELEMENT(DE_BSS_TS,                 CALLBACK_GETTER(bss_get)),
        ELEMENT(DE_BSS_UCAST_TX,           CALLBACK_GETTER(bss_get)),
        ELEMENT(DE_BSS_UCAST_RX,           CALLBACK_GETTER(bss_get)),
        ELEMENT(DE_BSS_MCAST_TX,           CALLBACK_GETTER(bss_get)),
        ELEMENT(DE_BSS_MCAST_RX,           CALLBACK_GETTER(bss_get)),
        ELEMENT(DE_BSS_BCAST_TX,           CALLBACK_GETTER(bss_get)),
        ELEMENT(DE_BSS_BCAST_RX,           CALLBACK_GETTER(bss_get)),
        ELEMENT(DE_BSS_EST_BE,             CALLBACK_GETTER(bss_get)),
        ELEMENT(DE_BSS_EST_BK,             CALLBACK_GETTER(bss_get)),
        ELEMENT(DE_BSS_EST_VI,             CALLBACK_GETTER(bss_get)),
        ELEMENT(DE_BSS_EST_VO,             CALLBACK_GETTER(bss_get)),
        ELEMENT(DE_BSS_BYTCNTUNITS,        CALLBACK_GETTER(bss_get)),
        ELEMENT(DE_BSS_PROF1_DIS,          CALLBACK_GETTER(bss_get)),
        ELEMENT(DE_BSS_PROF2_DIS,          CALLBACK_GETTER(bss_get)),
        ELEMENT(DE_BSS_ASSOC_STAT,         CALLBACK_GETTER(bss_get)),
        ELEMENT(DE_BSS_BHAULUSE,           CALLBACK_GETTER(bss_get)),
        ELEMENT(DE_BSS_FHAULUSE,           CALLBACK_GETTER(bss_get)),
        ELEMENT(DE_BSS_R1_DIS,             CALLBACK_GETTER(bss_get)),
        ELEMENT(DE_BSS_R2_DIS,             CALLBACK_GETTER(bss_get)),
        ELEMENT(DE_BSS_MULTI_BSSID,        CALLBACK_GETTER(bss_get)),
        ELEMENT(DE_BSS_TX_BSSID,           CALLBACK_GETTER(bss_get)),
        ELEMENT(DE_BSS_FHAULAKMS,          CALLBACK_GETTER(bss_get)),
        ELEMENT(DE_BSS_BHAULAKMS,          CALLBACK_GETTER(bss_get)),
        ELEMENT(DE_BSS_QM_DESC,            CALLBACK_GETTER(bss_get)),
        ELEMENT(DE_BSS_NUM_STA,            CALLBACK_GETTER(bss_get)),
        ELEMENT(DE_BSS_LINK_IMM,           CALLBACK_GETTER(bss_get)),
        ELEMENT(DE_BSS_FH_SUITE,           CALLBACK_GETTER(bss_get)),
        ELEMENT(DE_BSS_BH_SUITE,           CALLBACK_GETTER(bss_get)),
        ELEMENT(DE_STA_TABLE,              CALLBACK_GETTER(sta_tget)),
        ELEMENT(DE_STA_MACADDR,            CALLBACK_GETTER(sta_get)),
        ELEMENT(DE_STA_HTCAPS,             CALLBACK_GETTER(sta_get)),
        ELEMENT(DE_STA_VHTCAPS,            CALLBACK_GETTER(sta_get)),
        ELEMENT(DE_STA_CLIENTCAPS,         CALLBACK_GETTER(sta_get)),
        ELEMENT(DE_STA_LSTDTADLR,          CALLBACK_GETTER(sta_get)),
        ELEMENT(DE_STA_LSTDTAULR,          CALLBACK_GETTER(sta_get)),
        ELEMENT(DE_STA_UTILRECV,           CALLBACK_GETTER(sta_get)),
        ELEMENT(DE_STA_UTILTRMT,           CALLBACK_GETTER(sta_get)),
        ELEMENT(DE_STA_ESTMACDTARDL,       CALLBACK_GETTER(sta_get)),
        ELEMENT(DE_STA_ESTMACDTARUL,       CALLBACK_GETTER(sta_get)),
        ELEMENT(DE_STA_SIGNALSTR,          CALLBACK_GETTER(sta_get)),
        ELEMENT(DE_STA_LASTCONNTIME,       CALLBACK_GETTER(sta_get)),
        ELEMENT(DE_STA_BYTESSNT,           CALLBACK_GETTER(sta_get)),
        ELEMENT(DE_STA_BYTESRCV,           CALLBACK_GETTER(sta_get)),
        ELEMENT(DE_STA_PCKTSSNT,           CALLBACK_GETTER(sta_get)),
        ELEMENT(DE_STA_PCKTSRCV,           CALLBACK_GETTER(sta_get)),
        ELEMENT(DE_STA_ERRSSNT,            CALLBACK_GETTER(sta_get)),
        ELEMENT(DE_STA_ERRSRCV,            CALLBACK_GETTER(sta_get)),
        ELEMENT(DE_STA_RETRANSCNT,         CALLBACK_GETTER(sta_get)),
        ELEMENT(DE_STA_IPV4ADDR,           CALLBACK_GETTER(sta_get)),
        ELEMENT(DE_STA_IPV6ADDR,           CALLBACK_GETTER(sta_get)),
        ELEMENT(DE_STA_HOSTNAME,           CALLBACK_GETTER(sta_get)),
        ELEMENT(DE_STA_PAIRWSAKM,          CALLBACK_GETTER(sta_get)),
        ELEMENT(DE_STA_PAIRWSCIPHER,       CALLBACK_GETTER(sta_get)),
        ELEMENT(DE_STA_RSNCAPS,            CALLBACK_GETTER(sta_get)),
        ELEMENT(DE_APMLD_TABLE,            CALLBACK_GETTER(apmld_tget)),
        ELEMENT(DE_APMLD_MACADDRESS,       CALLBACK_GETTER(apmld_get)),
        ELEMENT(DE_APMLD_AFFAPNOE,         CALLBACK_GETTER(apmld_get)),
        ELEMENT(DE_APMLD_STAMLDNOE,        CALLBACK_GETTER(apmld_get)),
        ELEMENT(DE_APMLDCFG_EMLMR,         CALLBACK_GETTER(apmldcfg_get)),
        ELEMENT(DE_APMLDCFG_EMLSR,         CALLBACK_GETTER(apmldcfg_get)),
        ELEMENT(DE_APMLDCFG_STR,           CALLBACK_GETTER(apmldcfg_get)),
        ELEMENT(DE_APMLDCFG_NSTR,          CALLBACK_GETTER(apmldcfg_get)),
        ELEMENT(DE_AFFAP_TABLE,            CALLBACK_GETTER(affap_tget)),
        ELEMENT(DE_AFFAP_BSSID,            CALLBACK_GETTER(affap_get)),
        ELEMENT(DE_AFFAP_LINKID,           CALLBACK_GETTER(affap_get)),
        ELEMENT(DE_AFFAP_RUID,             CALLBACK_GETTER(affap_get)),
        ELEMENT(DE_AFFAP_PCKTSSNT,         CALLBACK_GETTER(affap_get)),
        ELEMENT(DE_AFFAP_PCKTSRCV,         CALLBACK_GETTER(affap_get)),
        ELEMENT(DE_AFFAP_ERRSSNT,          CALLBACK_GETTER(affap_get)),
        ELEMENT(DE_AFFAP_UCBYTESSNT,       CALLBACK_GETTER(affap_get)),
        ELEMENT(DE_AFFAP_UCBYTESRCV,       CALLBACK_GETTER(affap_get)),
        ELEMENT(DE_AFFAP_MCBYTESSNT,       CALLBACK_GETTER(affap_get)),
        ELEMENT(DE_AFFAP_MCBYTESRCV,       CALLBACK_GETTER(affap_get)),
        ELEMENT(DE_AFFAP_BCBYTESSNT,       CALLBACK_GETTER(affap_get)),
        ELEMENT(DE_AFFAP_BCBYTESRCV,       CALLBACK_GETTER(affap_get)),

        ELEMENT(DEVICE_WIFI_DATAELEMENTS_NETWORK_TOPOLOGY,              CB(NULL, NULL, NULL, NULL, NULL, NULL)),
        ELEMENT(DEVICE_WIFI_DATAELEMENTS_NETWORK_NODE_SYNC,             CB(.get_handler = get_node_sync, .set_handler = set_node_sync)),
        //ELEMENT(DEVICE_WIFI_DATAELEMENTS_NETWORK_NODE_CFG_POLICY,       CB(.set_handler = policy_config))
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

    if (em_ctrl != NULL) {
        return em_ctrl->get_dm_ctrl()->network_get(event_name, p_data);
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::ssid_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL) {
        return em_ctrl->get_dm_ctrl()->ssid_tget(event_name, p_data);
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::ssid_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL) {
        return em_ctrl->get_dm_ctrl()->ssid_get(event_name, p_data);
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::device_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL) {
        return em_ctrl->get_dm_ctrl()->device_get(event_name, p_data);
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::device_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL) {
        return em_ctrl->get_dm_ctrl()->device_tget(event_name, p_data);
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::policy_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_printfout("Inside");
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL) {
        return em_ctrl->get_dm_ctrl()->policy_get(event_name, p_data);
    }

    return bus_error_general;
}

bus_error_t tr_181_t::radio_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL) {
        return em_ctrl->get_dm_ctrl()->radio_get(event_name, p_data);
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::bss_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL) {
        return em_ctrl->get_dm_ctrl()->bss_get(event_name, p_data);
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::rcaps_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL) {
        return em_ctrl->get_dm_ctrl()->rcaps_get(event_name, p_data);
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::wf6ap_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL) {
        return em_ctrl->get_dm_ctrl()->wf6ap_get(event_name, p_data);
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::wf6ap_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL) {
        return em_ctrl->get_dm_ctrl()->wf6ap_tget(event_name, p_data);
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::wf7ap_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL) {
        return em_ctrl->get_dm_ctrl()->wf7ap_get(event_name, p_data);
    }

    return bus_error_general;
}

bus_error_t tr_181_t::wf7ap_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL) {
        return em_ctrl->get_dm_ctrl()->wf7ap_tget(event_name, p_data);
    }

    return bus_error_general;
}

bus_error_t tr_181_t::curops_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL) {
        return em_ctrl->get_dm_ctrl()->curops_get(event_name, p_data);
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::curops_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL) {
        return em_ctrl->get_dm_ctrl()->curops_tget(event_name, p_data);
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::sta_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL) {
        return em_ctrl->get_dm_ctrl()->sta_get(event_name, p_data);
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::radio_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL) {
        return em_ctrl->get_dm_ctrl()->radio_tget(event_name, p_data);
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::rbhsta_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL) {
        return em_ctrl->get_dm_ctrl()->rbhsta_get(event_name, p_data);
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::bss_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL) {
        return em_ctrl->get_dm_ctrl()->bss_tget(event_name, p_data);
    }
    
    return bus_error_general;
}

bus_error_t tr_181_t::sta_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL) {
        return em_ctrl->get_dm_ctrl()->sta_tget(event_name, p_data);
    }

    return bus_error_general;
}

bus_error_t tr_181_t::apmld_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL) {
        return em_ctrl->get_dm_ctrl()->apmld_get(event_name, p_data);
    }

    return bus_error_general;
}

bus_error_t tr_181_t::apmld_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL) {
        return em_ctrl->get_dm_ctrl()->apmld_tget(event_name, p_data);
    }

    return bus_error_general;
}

bus_error_t tr_181_t::apmldcfg_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL) {
        return em_ctrl->get_dm_ctrl()->apmldcfg_get(event_name, p_data);
    }

    return bus_error_general;
}

bus_error_t tr_181_t::affap_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL) {
        return em_ctrl->get_dm_ctrl()->affap_get(event_name, p_data);
    }

    return bus_error_general;
}

bus_error_t tr_181_t::affap_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL) {
        return em_ctrl->get_dm_ctrl()->affap_tget(event_name, p_data);
    }

    return bus_error_general;
}

bus_error_t tr_181_t::get_node_sync(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    p_data->data_type       = bus_data_type_string;
    p_data->raw_data.bytes  = malloc(sizeof(mac_addr_str_t));
    if (p_data->raw_data.bytes == NULL) {
        em_printfout("Memory allocation is failed");
        return bus_error_out_of_resources;
    }
    em_printfout(" get_node_sync: node mac len: %d", sizeof(mac_addr_str_t));

    strncpy((char *)p_data->raw_data.bytes, (const char *)g_temp_node_mac, sizeof(mac_addr_str_t));
    p_data->raw_data_len    = sizeof(mac_addr_str_t);

    em_printfout(" get_node_sync: node mac: %s", p_data->raw_data.bytes);

    return bus_error_success;
}

bus_error_t tr_181_t::set_node_sync(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    wifi_bus_desc_t *desc = NULL;
    raw_data_t raw;

    em_printfout(" Event rcvd: %s for node mac: %s", event_name, p_data->raw_data.bytes);

    snprintf(g_temp_node_mac, sizeof(mac_addr_str_t), "%s", (char *)p_data->raw_data.bytes);

    if((desc = get_bus_descriptor()) == NULL) {
        em_printfout("descriptor is null");
    }

    //TODO: Temp code to publish node sync once received
    raw.data_type    = bus_data_type_string;
    raw.raw_data.bytes = reinterpret_cast<unsigned char *> (g_temp_node_mac);
    raw.raw_data_len = static_cast<unsigned int> (strlen(g_temp_node_mac));

    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    if (em_ctrl != NULL)
    {
        if (desc->bus_event_publish_fn(&em_ctrl->get_dm_ctrl()->m_bus_handle, DEVICE_WIFI_DATAELEMENTS_NETWORK_NODE_SYNC, &raw)== 0) {
            em_printfout("Node sync published successfull");
        } else {
            em_printfout("Node sync publish fail");
        }

        return bus_error_success;
    }

    return bus_error_invalid_input;
}

bus_error_t tr_181_t::subs_policy_config(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    //todo: remove test code
    if (strncmp(event_name,DEVICE_WIFI_DATAELEMENTS_NETWORK_NODE_LINKSTATS_ALARM, strlen(DEVICE_WIFI_DATAELEMENTS_NETWORK_NODE_LINKSTATS_ALARM)) == 0) {
        em_printfout(" link stats alarm report Subs Event rcvd: %s", p_data->raw_data.bytes);
        return bus_error_success;
    }
    em_printfout(" Subs Event rcvd: %s\n Policy cfg is of len: %d and : \n%s", event_name, p_data->raw_data_len, p_data->raw_data.bytes);

    //send it to decode and apply policy
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    em_ctrl->io_process(em_bus_event_type_set_policy,  reinterpret_cast<char*>(p_data->raw_data.bytes), p_data->raw_data_len);
    return bus_error_success;
}

bus_error_t tr_181_t::policy_config(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    em_printfout(" Event rcvd: %s\n Policy cfg is of len: %d and : \n%s", event_name, p_data->raw_data_len, p_data->raw_data.bytes);

    //send it to decode and apply policy
    em_ctrl_t *em_ctrl = em_ctrl_t::get_em_ctrl_instance();

    em_ctrl->io_process(em_bus_event_type_set_policy,  reinterpret_cast<char*>(p_data->raw_data.bytes), p_data->raw_data_len);
    return bus_error_success;
}

bus_error_t tr_181_t::wifi_elem_num_of_table_row(char* event_name, uint32_t* table_row_size)
{
    // Return 0 rows for all tables for now
    if (table_row_size != NULL) {
        *table_row_size = 0;
    }

    return bus_error_success;
}

//Helper to convert YANG path to TR-181 path
std::string tr_181_t::yang_to_tr181_path(const std::string& in)
{
    std::string out = in;
    em_printfout("Converting YANG path: %s", in.c_str());

    for (int i = 0; g_yang_map[i].yang; ++i) {
        const std::string from = g_yang_map[i].yang;
        const std::string to = g_yang_map[i].tr181;

        size_t pos = 0;
        while ((pos = out.find(from, pos)) != std::string::npos) {
            /* ensure whole-token replacement */
            bool left_ok = (pos == 0 || out[pos - 1] == '.');
            bool right_ok = (pos + from.size() == out.size() ||
                              out[pos + from.size()] == '.');

            if (left_ok && right_ok) {
                out.replace(pos, from.size(), to);
                pos += to.size();
            } else {
                pos += from.size();
            }
        }
    }

    return out;
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

    // 3) If type is array -> register TABLE, and examine items, only if array type is object
    if (schema_has_type(effective, "array")) {
        // now inspect items
        cJSON* items = cJSON_GetObjectItem(effective, "items");
        if (!items) return;

        cJSON* itemsEff = follow_ref_if_any(root, items);
        if (!itemsEff) return;

        cJSON* itemProps = cJSON_GetObjectItem(itemsEff, "properties");
        if (itemProps && cJSON_IsObject(itemProps)) {
            std::string tableName = fullPath + ".{i}";

            // reset and fill constraints for the array property itself
            memset(&data_model_value, 0, sizeof(data_model_value));
            parse_property_constraints(effective, data_model_value);
            parse_readwrite(effective, data_model_value);
            std::string tr181Path = yang_to_tr181_path(tableName);
            wfa_set_bus_callbackfunc_pointers(tr181Path.c_str(), &cbTable);
            wfa_bus_register_namespace(const_cast<char*>(tr181Path.c_str()), bus_element_type_table, cbTable, data_model_value, 1);

            // expand row children under tableName
            traverse_schema(root, itemsEff, tableName);
        } else {
            // primitive array -> register the row as property
            memset(&data_model_value, 0, sizeof(data_model_value));
            parse_property_constraints(itemsEff, data_model_value);
            parse_readwrite(itemsEff, data_model_value);
            std::string tr181Path = yang_to_tr181_path(fullPath);
            wfa_set_bus_callbackfunc_pointers(tr181Path.c_str(), &cbTable);
            wfa_bus_register_namespace(const_cast<char*>(tr181Path.c_str()), bus_element_type_property, cbTable, data_model_value, 1);
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
        std::string tr181Path = yang_to_tr181_path(fullPath);
        wfa_set_bus_callbackfunc_pointers(tr181Path.c_str(), &cbTable);
        wfa_bus_register_namespace(const_cast<char*>(tr181Path.c_str()), bus_element_type_property, cbTable, data_model_value, 1);
        return;
    }

    // 5) Fallback: primitive (string/number/boolean/enum) - register as property
    memset(&data_model_value, 0, sizeof(data_model_value));
    parse_property_constraints(effective, data_model_value);
    parse_readwrite(effective, data_model_value);
    std::string tr181Path = yang_to_tr181_path(fullPath);
    wfa_set_bus_callbackfunc_pointers(tr181Path.c_str(), &cbTable);
    wfa_bus_register_namespace(const_cast<char*>(tr181Path.c_str()), bus_element_type_property, cbTable, data_model_value, 1);
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
            traverse_schema(root, child, "Device.WiFi.DataElements.Network");
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
