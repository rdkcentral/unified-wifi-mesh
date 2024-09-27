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
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>
#include <cjson/cJSON.h>
#include "em_cmd.h"

int em_cmd_t::load_params_file(char *buff)
{
    FILE *fp;
    char tmp[1024];
    unsigned int sz = 0;

    if ((fp = fopen(m_param.fixed_args, "r")) == NULL) {
        printf("%s:%d: failed to open file at location:%s error:%d\n", __func__, __LINE__, m_param.fixed_args, errno);
        return -1;
    } else {

        memset(buff, 0, sizeof(buff));
        while (fgets(tmp, sizeof(tmp), fp) != NULL) {
            strncat(buff, tmp, sizeof(tmp));
            sz += strlen(tmp);
        }

        fclose(fp);
    }

    return sz;
}

bool em_cmd_t::validate()
{
    if ((m_type == em_cmd_type_none) || (m_type >= em_cmd_type_max)) {
        return false;
    }

    return true;

}

char *em_cmd_t::status_to_string(em_cmd_out_status_t status, em_status_string_t str)
{
    cJSON *obj;
    em_long_string_t status_str;

    obj = cJSON_CreateObject();

    switch (status) {
        case em_cmd_out_status_success:
            snprintf(status_str, sizeof(status_str), "%s", "Success");
            break;

        case em_cmd_out_status_not_ready:
            snprintf(status_str, sizeof(status_str), "%s", "Error_Not_Ready");
            break;

        case em_cmd_out_status_invalid_input:
            snprintf(status_str, sizeof(status_str), "%s", "Error_Invalid_Input");
            break;

        case em_cmd_out_status_timeout:
            snprintf(status_str, sizeof(status_str), "%s", "Error_Timeout");
            break;

        case em_cmd_out_status_invalid_mac:
            snprintf(status_str, sizeof(status_str), "%s", "Error_Invalid_Mac");
            break;

        case em_cmd_out_status_interface_down:
            snprintf(status_str, sizeof(status_str), "%s", "Error_Interface_Down");
            break;

        case em_cmd_out_status_other:
            snprintf(status_str, sizeof(status_str), "%s", "Error_Other");
            break;

        case em_cmd_out_status_prev_cmd_in_progress:
            snprintf(status_str, sizeof(status_str), "%s", "Error_Prev_Cmd_In_Progress");
            break;

        case em_cmd_out_status_no_change:
            snprintf(status_str, sizeof(status_str), "%s", "Error_No_Config_Change_Detected");
            break;
    }	

    cJSON_AddStringToObject(obj, "Status", status_str);

    cJSON_PrintPreallocated(obj, str, sizeof(em_status_string_t), true);
    cJSON_Delete(obj);

    return str;
}

void em_cmd_t::set_rd_freq_band(unsigned int i)
{
    unsigned int num_curr_opclass = 0;

    em_freq_band_t freq_band;
    dm_op_class_t *op_class_info;
    em_op_class_info_t em_op_class;
    num_curr_opclass = m_data_model.get_num_opclass();
    printf("number of op_class = %d\n",num_curr_opclass);

    op_class_info = m_data_model.get_curr_op_class(i);
    if (op_class_info == NULL) {
        printf("op_class_info is NULL\n");
    }
    em_op_class = op_class_info->m_op_class_info;
    printf("opclass = %d\n",em_op_class.op_class);
    m_rd_op_class = em_op_class.op_class;
    m_rd_channel = em_op_class.channel;
    if (em_op_class.op_class >= EM_MIN_OP_CLASS_24 && em_op_class.op_class <= EM_MAX_OP_CLASS_24) {
        freq_band = em_freq_band_24;
    } else if (em_op_class.op_class >= EM_MIN_OP_CLASS_5  && em_op_class.op_class<= EM_MAX_OP_CLASS_5) {
        freq_band = em_freq_band_5;
    } else {
        freq_band = em_freq_band_60;
    }
    m_rd_freq_band = freq_band;

}

void em_cmd_t::deinit()
{
    queue_destroy(m_em_candidates);
    m_data_model.deinit();
}

void em_cmd_t::init(dm_easy_mesh_t *dm)
{
    m_em_candidates = queue_create();
    m_data_model.init();
    m_data_model = *dm;
}

em_cmd_t *em_cmd_t::clone()
{   
    em_cmd_t *out = NULL;
    unsigned int i;
    em_cmd_ctx_t *pctx, ctx;

    out = new em_cmd_t(m_type, m_param, m_data_model);

    out->m_data_model = m_data_model;
    out->set_orch_op_index(m_orch_op_idx);
    out->m_num_orch_ops = m_num_orch_ops;
    for (i = 0; i < m_num_orch_ops; i++) {
        out->m_orch_op_array[i] = m_orch_op_array[i];
    }

    pctx = m_data_model.get_cmd_ctx();	
    memcpy(&ctx, pctx, sizeof(em_cmd_ctx_t));	
    ctx.arr_index += 1;
    out->m_data_model.set_cmd_ctx(&ctx);
    return out;
}

em_cmd_t *em_cmd_t::clone_for_next()
{
    em_cmd_t *out = NULL;
    unsigned int i;
    em_cmd_ctx_t ctx;

    if (m_orch_op_idx == (m_num_orch_ops - 1)) {
        return NULL;
    }

    out = new em_cmd_t(m_type, m_param, m_data_model);

    out->m_data_model = m_data_model;
    out->set_orch_op_index(m_orch_op_idx + 1);
    out->m_num_orch_ops = m_num_orch_ops;
    for (i = 0; i < m_num_orch_ops; i++) {
        out->m_orch_op_array[i] = m_orch_op_array[i];
    }

    memset(&ctx, 0, sizeof(em_cmd_ctx_t));
    ctx.type = out->get_orch_op();
    out->m_data_model.set_cmd_ctx(&ctx);

    return out;
}

void em_cmd_t::override_op(unsigned int index, dm_orch_type_t op)
{
    em_cmd_ctx_t *ctx;

    m_orch_op_array[index] = op;
    ctx = m_data_model.get_cmd_ctx();
    ctx->type = op;
    printf("%s:%d: op = %d\n", __func__, __LINE__,op);
    m_data_model.set_cmd_ctx(ctx);
}

void em_cmd_t::init()
{
    switch (m_type) {
        case em_cmd_type_none:
            snprintf(m_name, sizeof(m_name), "%s", "none");
            m_svc = em_service_type_none;
            break;

        case em_cmd_type_reset:
            snprintf(m_name, sizeof(m_name), "%s", "reset");
            m_svc = em_service_type_ctrl;
            break;

        case em_cmd_type_getdb:
            snprintf(m_name, sizeof(m_name), "%s", "getdb");
            m_svc = em_service_type_ctrl;
            break;

        case em_cmd_type_set_ssid:
            snprintf(m_name, sizeof(m_name), "%s", "set_ssid");
            m_svc = em_service_type_ctrl;
            break;

        case em_cmd_type_dev_init:
            snprintf(m_name, sizeof(m_name), "%s", "dev_init");
            m_svc = em_service_type_agent;
            break;

        case em_cmd_type_cfg_renew:
            snprintf(m_name, sizeof(m_name), "%s", "cfg_renew");
            m_svc = em_service_type_agent;
            break;

        case em_cmd_type_vap_config:
            snprintf(m_name, sizeof(m_name), "%s", "vap_config");
            m_svc = em_service_type_agent;
            break;

        case em_cmd_type_radio_config:
            snprintf(m_name, sizeof(m_name), "%s", "radio_config");
            m_svc = em_service_type_agent;
            break;

        case em_cmd_type_sta_list:
            snprintf(m_name, sizeof(m_name), "%s", "sta_list");
            m_svc = em_service_type_agent;
            break;

        case em_cmd_type_ap_cap_query:
            snprintf(m_name, sizeof(m_name), "%s", "ap_cap");
            m_svc = em_service_type_agent;
            break;

    	case em_cmd_type_client_cap_query:
	        snprintf(m_name, sizeof(m_name), "%s", "client_cap");
            m_svc = em_service_type_agent;
    	    break;

        case em_cmd_type_start_dpp:
            snprintf(m_name, sizeof(m_name), "%s", "start_dpp");
            m_svc = em_service_type_ctrl;
            break;

        case em_cmd_type_client_steer:
            snprintf(m_name, sizeof(m_name), "%s", "client_steer");
            m_svc = em_service_type_ctrl;
            break;

        case em_cmd_type_max:
            snprintf(m_name, sizeof(m_name), "%s", "max");
            m_svc = em_service_type_none;
            break;

    }
}
em_cmd_t::em_cmd_t(em_cmd_type_t type, em_cmd_params_t param, dm_easy_mesh_t& dm)
{
    m_type = type;
    memcpy(&m_param, &param, sizeof(em_cmd_params_t));
    init(&dm);
    init();
}

em_cmd_t::em_cmd_t(em_cmd_type_t type, em_cmd_params_t param)
{
    m_type = type;
    memcpy(&m_param, &param, sizeof(em_cmd_params_t));
    init();
}

em_cmd_t::em_cmd_t()
{

}

em_cmd_t::~em_cmd_t()
{

}

const char *em_cmd_t::get_orch_op_str(dm_orch_type_t type)
{
#define ORCH_TYPE_2S(x) case x: return #x;
    switch (type) {
        ORCH_TYPE_2S(dm_orch_type_none)
        ORCH_TYPE_2S(dm_orch_type_net_insert)
        ORCH_TYPE_2S(dm_orch_type_net_update)
        ORCH_TYPE_2S(dm_orch_type_net_delete)
        ORCH_TYPE_2S(dm_orch_type_rd_insert)
        ORCH_TYPE_2S(dm_orch_type_rd_update)
        ORCH_TYPE_2S(dm_orch_type_rd_delete)
        ORCH_TYPE_2S(dm_orch_type_dev_insert)
        ORCH_TYPE_2S(dm_orch_type_dev_update)
        ORCH_TYPE_2S(dm_orch_type_dev_delete)
        ORCH_TYPE_2S(dm_orch_type_bss_insert)
        ORCH_TYPE_2S(dm_orch_type_bss_update)
        ORCH_TYPE_2S(dm_orch_type_bss_delete)
        ORCH_TYPE_2S(dm_orch_type_ssid_insert)
        ORCH_TYPE_2S(dm_orch_type_ssid_update)
        ORCH_TYPE_2S(dm_orch_type_ssid_delete)
        ORCH_TYPE_2S(dm_orch_type_sta_insert)
        ORCH_TYPE_2S(dm_orch_type_sta_update)
        ORCH_TYPE_2S(dm_orch_type_sta_delete)
        ORCH_TYPE_2S(dm_orch_type_sec_insert)
        ORCH_TYPE_2S(dm_orch_type_sec_update)
        ORCH_TYPE_2S(dm_orch_type_sec_delete)
        ORCH_TYPE_2S(dm_orch_type_cap_insert)
        ORCH_TYPE_2S(dm_orch_type_cap_update)
        ORCH_TYPE_2S(dm_orch_type_cap_delete)
        ORCH_TYPE_2S(dm_orch_type_op_class_insert)
        ORCH_TYPE_2S(dm_orch_type_op_class_update)
        ORCH_TYPE_2S(dm_orch_type_op_class_delete)
        ORCH_TYPE_2S(dm_orch_type_ssid_vid_insert)
        ORCH_TYPE_2S(dm_orch_type_ssid_vid_update)
        ORCH_TYPE_2S(dm_orch_type_ssid_vid_delete)
        ORCH_TYPE_2S(dm_orch_type_dpp_insert)
        ORCH_TYPE_2S(dm_orch_type_dpp_update)
        ORCH_TYPE_2S(dm_orch_type_dpp_delete)
        ORCH_TYPE_2S(dm_orch_type_em_reset)
        ORCH_TYPE_2S(dm_orch_type_db_reset)
        ORCH_TYPE_2S(dm_orch_type_db_cfg)
        ORCH_TYPE_2S(dm_orch_type_tx_cfg_renew)
        ORCH_TYPE_2S(dm_orch_type_owconfig_req)
        ORCH_TYPE_2S(dm_orch_type_owconfig_cnf)
        ORCH_TYPE_2S(dm_orch_type_ctrl_notify)
        ORCH_TYPE_2S(dm_orch_type_ap_cap_report)
	ORCH_TYPE_2S(dm_orch_type_client_cap_report)
    }

    return "dm_orch_type_unknown";
}

em_cmd_type_t em_cmd_t::bus_2_cmd_type(em_bus_event_type_t etype)
{
    em_cmd_type_t type = em_cmd_type_none;

    switch (etype) {
        case em_bus_event_type_reset_subdoc:
            type = em_cmd_type_reset;
            break;

        case em_bus_event_type_set_ssid:
            type = em_cmd_type_set_ssid;
            break;

        case em_bus_event_type_dev_init:
            type = em_cmd_type_dev_init;
            break;

        case em_bus_event_type_cfg_renew:
            type = em_cmd_type_cfg_renew;
            break;			

        case em_bus_event_type_sta_list:
            type = em_cmd_type_sta_list;
            break;

        case em_bus_event_type_ap_cap_query:
            type = em_cmd_type_ap_cap_query;
            break;

	case em_bus_event_type_client_cap_query:
	    type = em_cmd_type_client_cap_query;
	    break;

    }

    return type;
}

em_bus_event_type_t em_cmd_t::cmd_2_bus_event_type(em_cmd_type_t ctype)
{
    em_bus_event_type_t type = em_bus_event_type_none;

    switch (ctype) {
        case em_cmd_type_reset:
            type = em_bus_event_type_reset_subdoc;
            break;

        case em_cmd_type_set_ssid:
            type = em_bus_event_type_set_ssid;;
            break;

        case em_cmd_type_dev_init:
            type = em_bus_event_type_dev_init;
            break;

        case em_cmd_type_cfg_renew:
            type = em_bus_event_type_cfg_renew;
            break;

        case em_cmd_type_sta_list:
            type = em_bus_event_type_sta_list;
            break;
    }

    return type;
}

