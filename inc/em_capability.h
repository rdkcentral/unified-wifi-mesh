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

#ifndef EM_CAPABILITY_H
#define EM_CAPABILITY_H

#include "em_base.h"
#include "dm_easy_mesh.h"
#include "em.h"

class em_cmd_t;
class em_capability_t {

    virtual int send_frame(unsigned char *buff, unsigned int len, bool multicast = false) = 0;
    virtual dm_easy_mesh_t *get_data_model() = 0;
    virtual em_state_t get_state() = 0;
    virtual void set_state(em_state_t state) = 0;
    virtual em_service_type_t get_service_type() = 0;
    virtual em_profile_type_t   get_profile_type() = 0;
    virtual void    set_profile_type(em_profile_type_t profile) = 0;
    virtual unsigned char   *get_radio_interface_mac() = 0;
    virtual em_interface_t  *get_radio_interface() = 0;
    virtual unsigned char *get_al_interface_mac() = 0;
    virtual rdk_wifi_radio_t    *get_radio_data(em_interface_t *radio) = 0;
    virtual em_ieee_1905_security_cap_t *get_ieee_1905_security_cap() = 0;
    virtual em_device_info_t    *get_device_info() = 0;
    virtual unsigned char *get_peer_mac() = 0;
    virtual em_crypto_info_t    *get_crypto_info() = 0;
    virtual em_crypto_t   *get_crypto() = 0;
    virtual em_cmd_t *get_current_cmd() = 0;
    virtual short create_ap_radio_basic_cap(unsigned char *buff) = 0;
    virtual short create_ap_cap_tlv(unsigned char *buff) = 0;
    virtual short create_ht_tlv(unsigned char *buff) = 0;
    virtual short create_vht_tlv(unsigned char *buff) = 0;
    virtual short create_he_tlv(unsigned char *buff) = 0;
    virtual short create_wifi6_tlv(unsigned char *buff) = 0;
    virtual short create_channelscan_tlv(unsigned char *buff) = 0;
    virtual short create_prof_2_tlv(unsigned char *buff) = 0;
    virtual short create_device_inventory_tlv(unsigned char *buff) = 0;
    virtual short create_radioad_tlv(unsigned char *buff) = 0;
    virtual short create_metric_col_int_tlv(unsigned char *buff) = 0;
    virtual short create_cac_cap_tlv(unsigned char *buff) = 0;

    int send_client_cap_query();
    int send_client_cap_report_msg(mac_address_t sta, bssid_t bss);
    int create_ap_cap_report_msg(unsigned char *buff);
 
    // state handlers 
    void handle_state_ap_cap_report();
    int handle_ctrl_cap_query(unsigned char *buff, unsigned int len, em_bus_event_type_t msg_type);
    void handle_state_client_cap_report();

    //TLV
    short create_error_code_tlv(unsigned char *buff, mac_address_t sta, bssid_t bssid);
    short create_client_cap_tlv(unsigned char *buff, mac_address_t sta, bssid_t bssid);
    short create_client_info_tlv(unsigned char *buff, mac_address_t sta, bssid_t bssid);

    void handle_client_cap_query(unsigned char *data, unsigned int len);
    int handle_client_cap_report(unsigned char *data, unsigned int len);

public:
    void    process_msg(unsigned char *data, unsigned int len);
    void    process_state();

    int get_cap_query_tx_count() { return m_cap_query_tx_cnt; }
    void set_cap_query_tx_count(unsigned int cnt) { m_cap_query_tx_cnt = cnt; }

    unsigned int m_cap_query_tx_cnt;

    em_capability_t();
    ~em_capability_t();

};

#endif
