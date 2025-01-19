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

#ifndef EM_CHANNEL_H
#define EM_CHANNEL_H

#include "em_base.h"

class em_cmd_t;
class em_channel_t {

    virtual int send_frame(unsigned char *buff, unsigned int len, bool multicast = false) = 0;
	virtual int push_event(em_event_t *evt) = 0;

public:
	virtual em_mgr_t *get_mgr() = 0;
    virtual dm_easy_mesh_t *get_data_model() = 0;
    virtual unsigned char *get_radio_interface_mac() = 0;
    virtual em_state_t get_state() = 0;
    virtual void set_state(em_state_t state) = 0;
    virtual em_service_type_t get_service_type() = 0;
    virtual em_device_info_t *get_device_info() = 0;
    virtual em_cmd_t *get_current_cmd() = 0;

    short create_channel_scan_req_tlv(unsigned char *buff);
    short create_channel_scan_res_tlv(unsigned char *buff, unsigned int index);
    short create_channel_pref_tlv(unsigned char *buff);
    short create_operating_channel_report_tlv(unsigned char *buff);
    short create_spatial_reuse_report_tlv(unsigned char *buff);
    short create_radio_op_restriction_tlv(unsigned char *buff);
    short create_cac_complete_report_tlv(unsigned char *buff);
    short create_cac_status_report_tlv(unsigned char *buff);
    short create_channel_pref_tlv_agent(unsigned char *buff);
    short create_transmit_power_limit_tlv(unsigned char *buff);
    short create_spatial_reuse_req_tlv(unsigned char *buff);
    short create_eht_operations_tlv(unsigned char *buff);

    int send_channel_scan_request_msg();
    int send_channel_scan_report_msg(unsigned int *last_inex);
    int send_channel_sel_request_msg();
    int send_channel_sel_response_msg(em_chan_sel_resp_code_type_t code, unsigned short msg_id);
	int send_operating_channel_report_msg();
	int send_channel_pref_query_msg();
	int send_channel_pref_report_msg();
    int send_available_spectrum_inquiry_msg();

    int handle_channel_scan_req(unsigned char *buff, unsigned int len);
    int handle_channel_scan_rprt(unsigned char *buff, unsigned int len);
    int handle_channel_scan_result(unsigned char *buff, unsigned int len);
    int handle_channel_pref_rprt(unsigned char *buff, unsigned int len);
    int handle_channel_pref_query(unsigned char *buff, unsigned int len);
    int handle_channel_sel_rsp(unsigned char *buff, unsigned int len);
    int handle_operating_channel_rprt(unsigned char *buff, unsigned int len);
    int handle_channel_sel_req(unsigned char *buff, unsigned int len);
    int handle_channel_pref_tlv(unsigned char *buff, op_class_channel_sel *op_class);
    int handle_channel_pref_tlv_ctrl(unsigned char *buff, unsigned int len);
    int handle_op_channel_report(unsigned char *buff, unsigned int len);
    int handle_spatial_reuse_report(unsigned char *buff, unsigned int len);
    int handle_eht_operations_tlv(unsigned char *buff, em_eht_operations_t *eht_ops);
    int handle_eht_operations_tlv_ctrl(unsigned char *buff, unsigned int len);

    int get_channel_pref_query_tx_count() { return m_channel_pref_query_tx_cnt; }
    void set_channel_pref_query_tx_count(unsigned int cnt) { m_channel_pref_query_tx_cnt = cnt; }
    int get_channel_sel_req_tx_count() { return m_channel_sel_req_tx_cnt; }
    void set_channel_sel_req_tx_count(unsigned int cnt) { m_channel_sel_req_tx_cnt = cnt; }

	void fill_scan_result(dm_scan_result_t *scan_res, em_channel_scan_result_t *res);

    void    process_msg(unsigned char *data, unsigned int len);
    void    process_ctrl_state();
    void    process_state();

    unsigned int m_channel_pref_query_tx_cnt;
    unsigned int m_channel_sel_req_tx_cnt;
	virtual em_freq_band_t get_band() = 0;

    em_channel_t();
    ~em_channel_t();

};

#endif
