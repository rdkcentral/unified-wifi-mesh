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
#include "em_cli.h"
#include "em_cmd_cli.h"
#include <readline/readline.h>
#include <readline/history.h>

em_cmd_t em_cmd_cli_t::m_client_cmd_spec[] = {
    em_cmd_t(em_cmd_type_none, {0, {"", "", "", "", ""}, "none"}),
    // arguments are AL MAC, model
    em_cmd_t(em_cmd_type_reset, {3, {"", "", "", "", ""}, "Reset.json"}),
    em_cmd_t(em_cmd_type_ap_cap_query, {1, {"", "", "", "", ""}, "Radiocap.json"}),
    em_cmd_t(em_cmd_type_dev_test, {3, {"", "", "", "", ""}, "DevTest.json"}),
    em_cmd_t(em_cmd_type_cfg_renew, {1, {"", "", "", "", ""}, "CfgRenew.json"}),
    em_cmd_t(em_cmd_type_radio_config, {1, {"", "", "", "", ""}, "RadioConfig.json"}),
    em_cmd_t(em_cmd_type_vap_config, {1, {"", "", "", "", ""}, "VapConfig.json"}),
    em_cmd_t(em_cmd_type_sta_list, {1, {"", "", "", "", ""}, "STAList.json"}),
    em_cmd_t(em_cmd_type_get_network, {2, {"", "", "", "", ""}, "Network"}),
    em_cmd_t(em_cmd_type_get_ssid, {2, {"", "", "", "", ""}, "NetworkSSIDList"}),
    em_cmd_t(em_cmd_type_set_ssid, {2, {"", "", "", "", ""}, "NetworkSSID.json"}),
    em_cmd_t(em_cmd_type_get_channel, {2, {"", "", "", "", ""}, "ChannelList"}),
    em_cmd_t(em_cmd_type_set_channel, {2, {"", "", "", "", ""}, "Channel.json"}),
    em_cmd_t(em_cmd_type_get_bss, {2, {"", "", "", "", ""}, "BSSList"}),
    em_cmd_t(em_cmd_type_get_sta, {2, {"", "", "", "", ""}, "STAList"}),
    em_cmd_t(em_cmd_type_start_dpp, {1, {"", "", "", "", ""}, "DPPURI.json"}),
    em_cmd_t(em_cmd_type_client_steer, {1, {"", "", "", "", ""}, "ClientSteer.json"}),
    em_cmd_t(em_cmd_type_client_cap_query, {1, {"", "", "", "", ""}, "Clientcap.json"}),
    em_cmd_t(em_cmd_type_max, {0, {"", "", "", "", ""}, "max"}),
};

int em_cmd_cli_t::update_platform_defaults(em_subdoc_info_t *subdoc, em_cmd_params_t *param, em_cmd_type_t cmd_type)
{
    mac_address_t   al_mac;
    dm_easy_mesh_t dm;
    mac_addr_str_t  ctrl_mac, ctrl_al_mac, agent_al_mac;
    em_string_t key;
    
    strncpy(key, (cmd_type == em_cmd_type_reset) ? "Reset":"Test", sizeof(key));
    dm.init();
    dm.decode_config(subdoc, key);

    //dm.print_config();

    if (dm_easy_mesh_t::mac_address_from_name(param->args[1], al_mac) != 0) {
        return -1;
    }
    
    dm.set_ctrl_al_interface_mac(al_mac);
    dm.set_ctrl_al_interface_name(param->args[1]);

    if (cmd_type == em_cmd_type_dev_test) {
        dm.set_agent_al_interface_mac(al_mac);
        dm.set_agent_al_interface_name(param->args[1]);
    }

    //dm.print_config();

    // Now empty the buffer and encode again
    memset(subdoc->buff, 0, EM_SUBDOC_BUFF_SZ);
    subdoc->sz = EM_SUBDOC_BUFF_SZ;
    dm.encode_config(subdoc, key);

    return 0;
}

int em_cmd_cli_t::execute(em_string_t res)
{
    struct sockaddr_un addr;
    int dsock, ret;
    em_bus_event_t *bevt;
    em_subdoc_info_t    *info;
    em_event_t *evt;
    em_cmd_params_t *param;
    dm_easy_mesh_t dm;
    unsigned int sz = sizeof(em_event_t);
    unsigned char *tmp;
    em_long_string_t	in;
    em_status_string_t out;

    evt = get_event();
    param = get_param();

    evt->type = em_event_type_bus;
    bevt = &evt->u.bevt;
    memcpy(&bevt->params, param, sizeof(em_cmd_params_t));

    switch (get_type()) {

        case em_cmd_type_dev_test:
            bevt->type = em_bus_event_type_dev_test;
            info = &bevt->u.subdoc;
            snprintf(info->name, sizeof(info->name), "%s", param->fixed_args);
            if ((info->sz = get_cmd()->load_params_file(info->buff)) < 0) {
                printf("%s:%d: failed to open file at location:%s error:%d\n", __func__, __LINE__,
                param->fixed_args, errno);
                return -1;
            }
            if (update_platform_defaults(info, param, em_cmd_type_dev_test) != 0) {
                printf("%s:%d: failed to update default parameters\n", __func__, __LINE__);
                return -1;
            }
            break;

        case em_cmd_type_cfg_renew:
            bevt->type = em_bus_event_type_cfg_renew;
            info = &bevt->u.subdoc;
            snprintf(info->name, sizeof(info->name), "%s", param->fixed_args);
            if ((info->sz = get_cmd()->load_params_file(info->buff)) < 0) {
                printf("%s:%d: failed to open file at location:%s error:%d\n", __func__, __LINE__,
                param->fixed_args, errno);
                return -1;
            }
            break;

        case em_cmd_type_sta_list:
            bevt->type = em_bus_event_type_sta_list;
            info = &bevt->u.subdoc;
            snprintf(info->name, sizeof(info->name), "%s", param->fixed_args);
            if ((info->sz = get_cmd()->load_params_file(info->buff)) < 0) {
                printf("%s:%d: failed to open file at location:%s error:%d\n", __func__, __LINE__,
                param->fixed_args, errno);
                return -1;
            }
            break;

        case em_cmd_type_ap_cap_query:
            bevt->type = em_bus_event_type_ap_cap_query;
            info = &bevt->u.subdoc;
            snprintf(info->name, sizeof(info->name), "%s", param->fixed_args);
            if ((info->sz = get_cmd()->load_params_file(info->buff)) < 0) {
                printf("%s:%d: failed to open file at location:%s error:%d\n", __func__, __LINE__,
                param->fixed_args, errno);
                return -1;
            }
            break;

        case em_cmd_type_client_cap_query:
            bevt->type = em_bus_event_type_client_cap_query;
            info = &bevt->u.subdoc;
            snprintf(info->name, sizeof(info->name), "%s", param->fixed_args);
            if ((info->sz = get_cmd()->load_params_file(info->buff)) < 0) {
                printf("%s:%d: failed to open file at location:%s error:%d\n", __func__, __LINE__,
                param->fixed_args, errno);
                return -1;
            }
            break;

        case em_cmd_type_reset:
            bevt->type = em_bus_event_type_reset;
            info = &bevt->u.subdoc;
            snprintf(info->name, sizeof(info->name), "%s", param->fixed_args);
            if ((info->sz = get_cmd()->load_params_file(info->buff)) < 0) {
                printf("%s:%d: failed to open file at location:%s error:%d\n", __func__, __LINE__,
                param->fixed_args, errno);
                return -1;
            }
            if (update_platform_defaults(info, param, em_cmd_type_reset) != 0) {
                printf("%s:%d: failed to update default parameters\n", __func__, __LINE__);
                return -1;
            }
            break;

        case em_cmd_type_get_network:
            bevt->type = em_bus_event_type_get_network;
            info = &bevt->u.subdoc;
            strncpy(info->name, param->fixed_args, strlen(param->fixed_args) + 1);
            break;

        case em_cmd_type_get_ssid:
            bevt->type = em_bus_event_type_get_ssid;
            info = &bevt->u.subdoc;
            snprintf(info->name, sizeof(info->name), "%s", param->fixed_args);
            break;

        case em_cmd_type_set_ssid:
            snprintf(in, sizeof(in), "get_ssid %s", m_cmd.m_param.args[1]);
            get_cli()->exec(in, strlen(in), out);
            get_cmd()->write_params_file(out);
            bevt->type = em_bus_event_type_set_ssid;
			if (get_cmd()->edit_params_file() != 0) {
                printf("%s:%d: failed to open file at location:%s error:%d\n", __func__, __LINE__, param->fixed_args, errno);
                return -1;
			}	
            info = &bevt->u.subdoc;
            strncpy(info->name, param->fixed_args, strlen(param->fixed_args) + 1);
            if ((info->sz = get_cmd()->load_params_file(info->buff)) < 0) {
                printf("%s:%d: failed to open file at location:%s error:%d\n", __func__, __LINE__, param->fixed_args, errno);
                return -1;
            }
            break;

        case em_cmd_type_get_channel:
            bevt->type = em_bus_event_type_get_channel;
            info = &bevt->u.subdoc;
            strncpy(info->name, param->fixed_args, strlen(param->fixed_args) + 1);
            break;

        case em_cmd_type_set_channel:
			snprintf(in, sizeof(in), "get_channel %s", m_cmd.m_param.args[1]);
			get_cli()->exec(in, strlen(in), out);
			get_cmd()->write_params_file(out);
            bevt->type = em_bus_event_type_set_channel;
			if (get_cmd()->edit_params_file() != 0) {
                printf("%s:%d: failed to open file at location:%s error:%d\n", __func__, __LINE__, param->fixed_args, errno);
                return -1;
			}	
            info = &bevt->u.subdoc;
            strncpy(info->name, param->fixed_args, strlen(param->fixed_args) + 1);
            if ((info->sz = get_cmd()->load_params_file(info->buff)) < 0) {
                printf("%s:%d: failed to open file at location:%s error:%d\n", __func__, __LINE__, param->fixed_args, errno);
                return -1;
            }
            break;

        case em_cmd_type_get_bss:
            bevt->type = em_bus_event_type_get_bss;
            info = &bevt->u.subdoc;
            strncpy(info->name, param->fixed_args, strlen(param->fixed_args) + 1);
            break;

        case em_cmd_type_get_sta:
            bevt->type = em_bus_event_type_get_sta;
            info = &bevt->u.subdoc;
            strncpy(info->name, param->fixed_args, strlen(param->fixed_args) + 1);
            break;

        case em_cmd_type_start_dpp:
            bevt->type = em_bus_event_type_start_dpp;
            info = &bevt->u.subdoc;
            snprintf(info->name, sizeof(info->name), "%s", param->fixed_args);
            if ((info->sz = get_cmd()->load_params_file(info->buff)) < 0) {
                printf("%s:%d: failed to open file at location:%s error:%d\n", __func__, __LINE__,
                param->fixed_args, errno);
                return -1;
            }
            break;

        case em_cmd_type_client_steer:
            bevt->type = em_bus_event_type_client_steer;
            info = &bevt->u.subdoc;
            snprintf(info->name, sizeof(info->name), "%s", param->fixed_args);
            if ((info->sz = get_cmd()->load_params_file(info->buff)) < 0) {
                printf("%s:%d: failed to open file at location:%s error:%d\n", __func__, __LINE__,
                param->fixed_args, errno);
                return -1;
            }
            break;

        case em_cmd_type_onewifi_private_subdoc:
            bevt->type = em_bus_event_type_onewifi_private_subdoc;
            info = &bevt->u.subdoc;
            strncpy(info->name, param->fixed_args, strlen(param->fixed_args) + 1);
            if ((info->sz = get_cmd()->load_params_file(info->buff)) < 0) {
                printf("%s:%d: failed to open file at location:%s error:%d\n", __func__, __LINE__,
                param->fixed_args, errno);
                return -1;
            }
            break;

        default:
            break;
    }

    get_cmd()->init(&dm);
  
    if ((dsock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        snprintf(res, sizeof(em_long_string_t), "%s:%d: error opening socket, err:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    setsockopt(dsock, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz)); // Send buffer 1K
    setsockopt(dsock, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz)); // Receive buffer 1K

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", get_path());
    if ((ret = connect(dsock, (const struct sockaddr *) &addr, sizeof(struct sockaddr_un))) != 0) {
        snprintf(res, sizeof(em_long_string_t), "%s:%d: connect error on socket, err:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    tmp = (unsigned char *)get_event();

    if ((ret = send(dsock, tmp, sizeof(em_event_t), 0)) <= 0) {
        return -1;
	}
    
    /* Receive result. */
    if ((ret = recv(dsock, (unsigned char *)res, sizeof(em_status_string_t), 0)) <= 0) {
        snprintf(res, sizeof(em_long_string_t), "%s:%d: result read error on socket, err:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    close(dsock);

    return 0;
}

em_cmd_cli_t::em_cmd_cli_t(em_cmd_t& obj)
{
    m_cmd.m_type = obj.m_type;
    m_cmd.m_svc = obj.m_svc;
    memcpy(&m_cmd.m_param, &obj.m_param, sizeof(em_cmd_params_t));

}
