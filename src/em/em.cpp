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
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
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
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include "em.h"
#include "em_cmd.h"
#include "em_cmd_exec.h"


void em_t::orch_execute(em_cmd_t *pcmd)
{
    em_cmd_type_t cmd_type;
    mac_addr_str_t	mac_str;

    m_cmd = pcmd;
    m_orch_state = em_orch_state_progress;

    dm_easy_mesh_t::macbytes_to_string(get_radio_interface_mac(), mac_str);
	//printf("%s:%d: Radio: %s State: 0x%04x\n", __func__, __LINE__, mac_str, get_state());

    // now set the em state to start message exchages with peer 
    cmd_type = pcmd->m_type;
    switch (cmd_type) {
        case em_cmd_type_sta_list:
            m_sm.set_state(em_state_agent_topology_notify);
			break;

        case em_cmd_type_set_ssid:
        case em_cmd_type_set_radio:
            m_sm.set_state(em_state_ctrl_misconfigured);
			break;

        case em_cmd_type_dev_init:
			m_sm.set_state(em_state_agent_unconfigured);
            break;

        case em_cmd_type_cfg_renew:
            m_sm.set_state((m_service_type == em_service_type_agent) ? 
							em_state_agent_autoconfig_renew_pending:em_state_ctrl_misconfigured);
			break;

        case em_cmd_type_start_dpp:
            break;

        case em_cmd_type_ap_cap_query:
            m_sm.set_state(em_state_agent_ap_cap_report);
			break;

        case em_cmd_type_client_cap_query:
			m_sm.set_state(em_state_agent_client_cap_report);
            break;

        case em_cmd_type_em_config:
            printf("%s:%d: %s(%s) state: %s\n", __func__, __LINE__,
                    em_cmd_t::get_orch_op_str(pcmd->get_orch_op()), em_cmd_t::get_cmd_type_str(pcmd->m_type), 
					em_t::state_2_str(get_state()));
            if ((pcmd->get_orch_op() == dm_orch_type_topo_sync) && (m_sm.get_state() == em_state_ctrl_wsc_m2_sent)) {
                m_sm.set_state(em_state_ctrl_topo_sync_pending);
            } else if ((pcmd->get_orch_op() == dm_orch_type_channel_pref) && (m_sm.get_state() == em_state_ctrl_topo_synchronized)) {
                m_sm.set_state(em_state_ctrl_channel_query_pending);
            } else if ((pcmd->get_orch_op() == dm_orch_type_channel_sel) && (m_sm.get_state() == em_state_ctrl_channel_queried)) {
                m_sm.set_state(em_state_ctrl_channel_select_pending);
            } else if ((pcmd->get_orch_op() == dm_orch_type_channel_cnf) && (m_sm.get_state() == em_state_ctrl_channel_selected)) {
                m_sm.set_state(em_state_ctrl_channel_cnf_pending);
            }
            break;

        case em_cmd_type_dev_test:
            m_sm.set_state(em_state_ctrl_channel_query_pending);
            break;
        case em_cmd_type_onewifi_cb:
            m_sm.set_state(em_state_agent_onewifi_bssconfig_ind);
            break;
        case em_cmd_type_sta_assoc:
            m_sm.set_state(em_state_ctrl_sta_cap_pending);
            break;
		
        case em_cmd_type_channel_pref_query:
            m_sm.set_state(em_state_agent_channel_pref_query);
            break;

        case em_cmd_type_op_channel_report:
            m_sm.set_state(em_state_agent_channel_report_pending);
            break;

        case em_cmd_type_sta_link_metrics:
            m_sm.set_state(em_state_ctrl_sta_link_metrics_pending);
            break;

        case em_cmd_type_set_channel:
            m_sm.set_state(em_state_ctrl_channel_select_pending);
            break;

        case em_cmd_type_scan_channel:
            m_sm.set_state(em_state_ctrl_channel_scan_pending);
            break;

        case em_cmd_type_sta_steer:
            m_sm.set_state(em_state_ctrl_sta_steer_pending);
            break;

        case em_cmd_type_sta_disassoc:
            m_sm.set_state(em_state_ctrl_sta_disassoc_pending);
            break;
        
		case em_cmd_type_set_policy:
            set_state(em_state_ctrl_set_policy_pending);
            break;
    }
}

void em_t::set_orch_state(em_orch_state_t state)
{
    if ((state == em_orch_state_fini) && (m_service_type == em_service_type_agent)) {
        // commit the parameters of command into data model
        // m_data_model->commit_config(m_cmd->m_data_model, em_commit_target_em);
    } else if (state == em_orch_state_cancel) {
        state = em_orch_state_fini;
    }

    m_orch_state = state;
}

void em_t::handle_timeout()
{
    //printf("%s:%d: em timeout\n", __func__, __LINE__);
}

void em_t::proto_process(unsigned char *data, unsigned int len)
{
    em_raw_hdr_t *hdr;
    em_cmdu_t *cmdu;
    unsigned char *tlvs;
    unsigned int tlvs_len;
    mac_addr_str_t mac_str;

    hdr = (em_raw_hdr_t *)data;
    cmdu = (em_cmdu_t *)(data + sizeof(em_raw_hdr_t));

    dm_easy_mesh_t::macbytes_to_string(get_radio_interface_mac(), mac_str);
    switch (htons(cmdu->type)) {
        case em_msg_type_autoconf_search:
        case em_msg_type_autoconf_resp:
        case em_msg_type_autoconf_wsc:
        case em_msg_type_autoconf_renew:
        case em_msg_type_topo_resp:
        case em_msg_type_topo_query:
        case em_msg_type_topo_notif:
            em_configuration_t::process_msg(data, len);
            break;

        case em_msg_type_ap_cap_query:
        case em_msg_type_client_cap_query:
        case em_msg_type_client_cap_rprt:
            em_capability_t::process_msg(data, len);
            break;

        case em_msg_type_channel_pref_query:
        case em_msg_type_channel_pref_rprt:
        case em_msg_type_channel_sel_req:
        case em_msg_type_channel_sel_rsp:
        case em_msg_type_op_channel_rprt:
            em_channel_t::process_msg(data, len);
            break;

        case em_msg_type_assoc_sta_link_metrics_query:
        case em_msg_type_assoc_sta_link_metrics_rsp:
            em_metrics_t::process_msg(data, len);
            break;

        case em_msg_type_dpp_cce_ind:
        case em_msg_type_proxied_encap_dpp:
        case em_msg_type_direct_encap_dpp:
        case em_msg_type_reconfig_trigger:
        case em_msg_type_bss_config_req:
        case em_msg_type_bss_config_rsp:
        case em_msg_type_bss_config_res:
        case em_msg_type_chirp_notif:
        case em_msg_type_dpp_bootstrap_uri_notif:
            em_provisioning_t::process_msg(data, len);
            break;

        default:
            break;  
    }

    free(data);
}

void em_t::handle_agent_state()
{
    em_cmd_type_t cmd_type;

    // no state handling is allowd if orch state is not in progress
    if (m_orch_state != em_orch_state_progress) {
        return;
    }

    assert(m_cmd != NULL);

    cmd_type = m_cmd->m_type;
    switch (cmd_type) {
        case em_cmd_type_dev_init:
        case em_cmd_type_cfg_renew:
            if ((m_sm.get_state() >= em_state_agent_unconfigured) && (m_sm.get_state() < em_state_agent_configured)) {
				em_configuration_t::process_agent_state();
            }
            break;

        case em_cmd_type_sta_list:
            em_configuration_t::process_agent_state();
            break;

        case em_cmd_type_start_dpp:
            if ((m_sm.get_state() >= em_state_agent_unconfigured) && (m_sm.get_state() < em_state_agent_configured)) {
				em_provisioning_t::process_agent_state();
            }
            break;
        case em_cmd_type_ap_cap_query:
        case em_cmd_type_client_cap_query:
			if ((m_sm.get_state() >= em_state_agent_configured)) {
                em_capability_t::process_state();
            }
            break;
        case em_cmd_type_channel_pref_query:
        case em_cmd_type_op_channel_report:
            em_channel_t::process_state();
            break;
        default:
            break;
    }

}

void em_t::handle_ctrl_state()
{
    em_cmd_type_t cmd_type;

    // no state handling is allowd if orch state is not in progress
    if (m_orch_state != em_orch_state_progress) {
        return;
    }

    assert(m_cmd != NULL);

    //printf("%s:%d: Cmd: %s State: %s\n", __func__, __LINE__, 
        //em_cmd_t::get_cmd_type_str(m_cmd->m_type), em_t::state_2_str(get_state()));
    cmd_type = m_cmd->m_type;
    switch (cmd_type) {
        case em_cmd_type_set_ssid:
        case em_cmd_type_set_radio:
        case em_cmd_type_cfg_renew:
            em_configuration_t::process_ctrl_state();
            break;

        case em_cmd_type_em_config:
        case em_cmd_type_set_channel:
            em_configuration_t::process_ctrl_state();
            em_channel_t::process_ctrl_state();
            break;

		case em_cmd_type_scan_channel:
            em_channel_t::process_ctrl_state();
			break;

        case em_cmd_type_dev_test:
            em_channel_t::process_ctrl_state();
            break;

        case em_cmd_type_sta_assoc:
            em_capability_t::process_state();
            break;

        case em_cmd_type_sta_link_metrics:
            em_metrics_t::process_ctrl_state();
			break;

        case em_cmd_type_sta_steer:
            em_steering_t::process_ctrl_state();
            break;

        case em_cmd_type_sta_disassoc:
            em_steering_t::process_ctrl_state();
            break;
        
		case em_cmd_type_set_policy:
            em_policy_cfg_t::process_ctrl_state();
            break;
    }
}

void em_t::proto_timeout()
{
    if (m_service_type == em_service_type_agent) {
        handle_agent_state();
    } else if (m_service_type == em_service_type_ctrl) {
        handle_ctrl_state();
    }
}

void em_t::proto_exit()
{
    m_exit = true;
    pthread_cond_signal(&m_iq.cond);
    sched_yield();
}

void em_t::proto_run()
{
    int rc;
    em_event_t *evt;
    struct timespec time_to_wait;
    struct timeval tm;

    pthread_mutex_lock(&m_iq.lock);
    while (m_exit == false) {
        rc = 0;

        gettimeofday(&tm, NULL);
        time_to_wait.tv_sec = tm.tv_sec;
        time_to_wait.tv_nsec = tm.tv_usec * 1000;
        time_to_wait.tv_sec += m_iq.timeout;

        if (queue_count(m_iq.queue) == 0) {
            rc = pthread_cond_timedwait(&m_iq.cond, &m_iq.lock, &time_to_wait);
        }
        if ((rc == 0) || (queue_count(m_iq.queue) != 0)) {
            // dequeue data
            while (queue_count(m_iq.queue)) {
                evt = (em_event_t *)queue_pop(m_iq.queue);
                if (evt == NULL) {
                    continue;
                }
                pthread_mutex_unlock(&m_iq.lock);
                assert(evt->type == em_event_type_frame);
                proto_process(evt->u.fevt.frame, evt->u.fevt.len);
                free(evt);
                pthread_mutex_lock(&m_iq.lock);
            }
        } else if (rc == ETIMEDOUT) {
            pthread_mutex_unlock(&m_iq.lock);
            proto_timeout();
            pthread_mutex_lock(&m_iq.lock);
        } else {
            printf("%s:%d em exited with rc - %d",__func__,__LINE__,rc);
            pthread_mutex_unlock(&m_iq.lock);
            return;
        }
    }
    pthread_mutex_unlock(&m_iq.lock);

}

void *em_t::em_func(void *arg)
{
    em_t *m = (em_t *)arg;

    m->proto_run();
    return NULL;
}

void em_t::deinit()
{
    m_exit = true;
    pthread_cond_destroy(&m_iq.cond);
    pthread_mutex_destroy(&m_iq.lock);
    close(m_fd);

    queue_destroy(m_iq.queue);
}

int em_t::set_bp_filter()
{
    struct packet_mreq mreq;
#define OP_LDH (BPF_LD  | BPF_H   | BPF_ABS)
#define OP_LDB (BPF_LD  | BPF_B   | BPF_ABS)
#define OP_JEQ (BPF_JMP | BPF_JEQ | BPF_K)
#define OP_RET (BPF_RET | BPF_K)
    static struct sock_filter bpfcode[4] = {
        { OP_LDH, 0, 0, 12          },  // ldh [12]
        { OP_JEQ, 0, 1, ETH_P_1905  },  // jeq #0x893a, L2, L3
        { OP_RET, 0, 0, 0xffffffff,         },  // ret #0xffffffff
        { OP_RET, 0, 0, 0           },  // ret #0x0
    };
    struct sock_fprog bpf = { 4, bpfcode };

    if (setsockopt(m_fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf))) {
        printf("%s:%d: Error in attaching filter, err:%d\n", __func__, __LINE__, errno);
        close(m_fd);
        return -1;
    }

    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_type = PACKET_MR_PROMISC;
    mreq.mr_ifindex = if_nametoindex(m_ruid.name);
    if (setsockopt(m_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq))) {
        printf("%s:%d: Error setting promisuous for interface:%s, err:%d\n", __func__, __LINE__, m_ruid.name, errno);
        close(m_fd);
        return -1;
    }

    return 0;
}

int em_t::start_al_interface()
{
    int optval = 1, sock_fd;
    struct sockaddr_ll addr_ll;
    struct sockaddr_un addr_un;
    struct sockaddr *addr;
    socklen_t   slen;

    memset(&addr_ll, 0, sizeof(struct sockaddr_ll));
    addr_ll.sll_family   = AF_PACKET;
    addr_ll.sll_protocol = htons(ETH_P_ALL);
    addr_ll.sll_ifindex  = if_nametoindex(m_ruid.name);
    addr = (struct sockaddr *)&addr_ll;
    slen = sizeof(struct sockaddr_ll);

    if ((sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        printf("%s:%d: Error opening socket, err:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    if (bind(sock_fd, addr, slen) < 0) {
        printf("%s:%d: Error binding to interface, err:%d\n", __func__, __LINE__, errno);
        close(sock_fd);
        return -1;
    }

    m_fd = sock_fd;

    set_bp_filter();

    return 0;
}

int em_t::send_cmd(em_cmd_type_t type, em_service_type_t svc, unsigned char *buff, unsigned int len)
{
    return em_cmd_exec_t::execute(type, svc, buff, len);
}

int em_t::send_frame(unsigned char *buff, unsigned int len, bool multicast)
{
    em_interface_t *al;
    em_short_string_t   ifname;
    struct sockaddr_ll sadr_ll;
    int sock, ret;
    mac_address_t   multi_addr = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x13};
    em_raw_hdr_t *hdr = (em_raw_hdr_t *)buff;

    dm_easy_mesh_t::name_from_mac_address((mac_address_t *)get_al_interface_mac(), ifname);

    sock = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        return -1;
    }

    sadr_ll.sll_ifindex = if_nametoindex(ifname);
    sadr_ll.sll_halen = ETH_ALEN; // length of destination mac address
    sadr_ll.sll_protocol = htons(ETH_P_ALL);
    memcpy(sadr_ll.sll_addr, (multicast == true) ? multi_addr:hdr->dst, sizeof(mac_address_t));

    ret = sendto(sock, buff, len, 0, (const struct sockaddr*)&sadr_ll, sizeof(struct sockaddr_ll));   

    close(sock);

    return ret;
}

bool em_t::is_matching_freq_band(em_freq_band_t *band)
{
    return (get_band() == *band);
}

void em_t::push_to_queue(em_event_t *evt)
{
    pthread_mutex_lock(&m_iq.lock);
    queue_push(m_iq.queue, evt);
    pthread_cond_signal(&m_iq.cond);
    pthread_mutex_unlock(&m_iq.lock);
}

em_event_t *em_t::pop_from_queue()
{
    return (em_event_t *)queue_pop(m_iq.queue);
}

dm_sta_t *em_t::find_sta(mac_address_t sta_mac, bssid_t bssid)
{
    dm_sta_t *sta;

    sta = get_data_model()->find_sta(sta_mac, bssid);
    if (sta == NULL) {
        return NULL;
    }

    // the sta can be from a different radio
    if (memcmp(sta->m_sta_info.radiomac, get_radio_interface_mac(), sizeof(mac_address_t)) == 0) {
        return sta;
    }

    return NULL;
}

// Used to convert freq band from Onewifi to IEEE-1905-1-2013 table 6-23 & IEEE-1905-1-2013 table 6-23 to Wi-Fi Simple Configuration Technical Specification v2 table 44
em_freq_band_t em_t::convert_freq_band(em_freq_band_t band)
{
    unsigned int int_band;
    int_band = (int)band;

    if (int_band == 1) {
        return em_freq_band_24; // Return 2.4 GHz band
    } else if (int_band == 2) {
        return em_freq_band_5;  // Return 5 GHz band
    } else if (int_band == 32 || band == 4) {
        return em_freq_band_60;	// Return 60 GHz band
    } else {
        return em_freq_band_unknown; // Return unknown for other values
    }
}

// Used to convert freq band from Wi-Fi Simple Configuration Technical Specification v2 table 44 to IEEE-1905-1-2013 table 6-23
em_rd_freq_band_t em_t::map_freq_band_to_rf_band(em_freq_band_t band)
{
    unsigned int int_band;
    int_band = (int)band;

    if (int_band == 0) {
        return em_rd_freq_band_24; // Return 2.4 GHz band
    } else if (int_band == 1) {
        return em_rd_freq_band_5; // Return 5 GHz band
    } else if (int_band == 2) {
        return em_rd_freq_band_60; // Return 60 GHz band
    } else {
        return em_rd_freq_band_unknown; // Return unknown for other values
    }
}

dm_radio_t *em_t::get_radio_from_dm(bool command_dm)
{
	dm_easy_mesh_t *dm;
	bool match_found = false;
	dm_radio_t *radio;
	unsigned int i;

	if (command_dm == false) {
		dm = get_data_model();
	} else {
		if (get_current_cmd() == NULL) {
			return NULL;
		}

		dm = get_current_cmd()->get_data_model();
		if (dm == NULL) {
			return NULL;
		}
	}

	for (i = 0; i < dm->get_num_radios(); i++) {
		radio = &dm->m_radio[i];
		if (memcmp(get_radio_interface_mac(), radio->m_radio_info.id.mac, sizeof(mac_address_t)) == 0) {
			match_found = true;
			break;
		}
	}

	return (match_found == true) ? radio:NULL;
}

short em_t::create_ap_radio_basic_cap(unsigned char *buff) {
	short len = 0;
	em_ap_radio_basic_cap_t *cap = (em_ap_radio_basic_cap_t *)buff;
	em_channels_list_t *channel_list;
	em_op_class_t *op_class;
	unsigned int all_channel_len = 0;
	int i = 0;
	len = sizeof(em_ap_radio_basic_cap_t);

	memcpy(&cap->ruid, get_radio_interface_mac(), sizeof(mac_address_t));

	em_interface_t* radio_interface = get_radio_interface();
	cap->num_bss = get_current_cmd()->get_data_model()->get_num_bss();
	cap->op_class_num = 0;
	op_class = cap->op_classes;
	for (i = 0; i < get_current_cmd()->get_data_model()->get_num_op_class(); i++) {
		if (memcmp(get_radio_interface_mac(), get_current_cmd()->get_data_model()->get_op_class_info(i)->id.ruid, sizeof(mac_address_t)) == 0) {
			em_op_class_info_t *op_class_info = get_current_cmd()->get_data_model()->get_op_class_info(i);
			if ((op_class_info != NULL) && (op_class_info->id.type == em_op_class_type_capability)){
				cap->op_class_num++;
				op_class->op_class = op_class_info->op_class;
				op_class->max_tx_eirp = op_class_info->max_tx_power;
				op_class->num = op_class_info->num_channels;
				len += sizeof(em_op_class_t);
				if (op_class_info->num_channels != 0) {
					channel_list = &op_class->channels;
					for (int j = 0; j < op_class_info->num_channels; j++) {
						memcpy( (unsigned char *)&channel_list->channel, (unsigned char *)&op_class_info->channels[j], sizeof(unsigned char));
						all_channel_len = all_channel_len + sizeof(unsigned char);
						channel_list = (em_channels_list_t *)((unsigned char *)channel_list + sizeof(em_channels_list_t) + sizeof(unsigned char) );
									   len += sizeof(unsigned char);
					}
				}
				printf("Op Class %d: %d, max_tx_eirp: %d, channels.num: %d\n",
					   i, op_class_info->op_class, op_class_info->max_tx_power, op_class_info->num_channels);
				printf(" cap->op_classes[%d].op_class: %d, cap->op_classes[%d].max_tx_eirp %d,	cap->op_classes[%d].channels.num %d\n",
					   i, cap->op_classes[i].op_class, i, cap->op_classes[i].max_tx_eirp, i, cap->op_classes[i].num);

			}
			op_class = (em_op_class_t *)((unsigned char *)op_class + sizeof(em_op_class_t) + all_channel_len);
			all_channel_len = 0;
		}
	}
	return len;
}

short em_t::create_ap_cap_tlv(unsigned char *buff)
{
    short len = 0;
    dm_radio_t* radio = get_data_model()->get_radio(get_radio_interface_mac());
    em_radio_info_t* radio_info = radio->get_radio_info();
    em_ap_capability_t *ap_cap = (em_ap_capability_t *)buff;

    if ((ap_cap == NULL) || (radio_info == NULL)) {
        printf("%s:%d No data Found\n", __func__, __LINE__);
        return 0;
    }

    ap_cap->unassociated_client_link_metrics_non_op_channels = radio_info->unassociated_sta_link_mterics_nonopclass_inclusion_policy;
    ap_cap->unassociated_client_link_metrics_op_channels =  radio_info->unassociated_sta_link_mterics_opclass_inclusion_policy;
    ap_cap->rcpi_steering = radio_info->support_rcpi_steering;
    // ap_cap->reserved - Future implementation
    len = sizeof(em_ap_capability_t);
    return len;
}

short em_t::create_ht_tlv(unsigned char *buff)
{
    short len = 0;
    em_radio_cap_info_t* cap_info = get_data_model()->get_radio_cap(get_radio_interface_mac())->get_radio_cap_info();
    em_ap_ht_cap_t *ht_cap = (em_ap_ht_cap_t *)buff;

    if ((ht_cap == NULL) || (cap_info == NULL)) {
        printf("%s:%d No data Found\n", __func__, __LINE__);
        return 0;
    }

    memcpy(&ht_cap,&cap_info->ht_cap,sizeof(em_ap_ht_cap_t));
    len = sizeof(em_ap_ht_cap_t);
    return len;
}

short em_t::create_vht_tlv(unsigned char *buff)
{
    short len = 0;
    em_radio_cap_info_t* cap_info = get_data_model()->get_radio_cap(get_radio_interface_mac())->get_radio_cap_info();
    em_ap_vht_cap_t *vht_cap = (em_ap_vht_cap_t *)buff;

    if ((vht_cap == NULL) || (cap_info == NULL)) {
        printf("%s:%d No data Found\n", __func__, __LINE__);
        return 0;
    }
    memcpy(&vht_cap,&cap_info->vht_cap,sizeof(em_ap_vht_cap_t));
    len = sizeof(em_ap_vht_cap_t);
    return len;
}

short em_t::create_he_tlv(unsigned char *buff)
{
    short len = 0;
    em_radio_cap_info_t* cap_info = get_data_model()->get_radio_cap(get_radio_interface_mac())->get_radio_cap_info();
    em_ap_he_cap_t *he_cap = (em_ap_he_cap_t *)buff;

    if ((he_cap == NULL) || (cap_info == NULL)) {
        printf("%s:%d No data Found\n", __func__, __LINE__);
        return 0;
    }
    memcpy(&he_cap,&cap_info->he_cap,sizeof(em_ap_he_cap_t));
    len = sizeof(em_ap_he_cap_t);
    return len;
}


short em_t::create_wifi6_tlv(unsigned char *buff)
{
    short len = 0;
    em_radio_cap_info_t* cap_info = get_data_model()->get_radio_cap(get_radio_interface_mac())->get_radio_cap_info();
    em_radio_wifi6_cap_data_t *wifi6_cap = (em_radio_wifi6_cap_data_t *)buff;

    if ((wifi6_cap == NULL) || (cap_info == NULL)) {
        printf("%s:%d No data Found\n", __func__, __LINE__);
        return 0;
    }
    memcpy(&wifi6_cap,&cap_info->wifi6_cap,sizeof(em_radio_wifi6_cap_data_t));
    len = sizeof(em_radio_wifi6_cap_data_t);
    return len;
}

short em_t::create_wifi7_tlv(unsigned char *buff)
{
    short len = 0;
    em_radio_cap_info_t* cap_info = get_data_model()->get_radio_cap(get_radio_interface_mac())->get_radio_cap_info();
    em_wifi7_agent_cap_t *wifi7_cap = (em_wifi7_agent_cap_t *)buff;

    if ((wifi7_cap == NULL) || (cap_info == NULL)) {
        printf("%s:%d No data Found\n", __func__, __LINE__);
        return 0;
    }
    memcpy(&wifi7_cap,&cap_info->wifi7_cap,sizeof(em_wifi7_agent_cap_t));
    len = sizeof(em_wifi7_agent_cap_t);
    return len;
}

short em_t::create_eht_operations_tlv(unsigned char *buff)
{
    short len = 0;
    em_radio_cap_info_t* cap_info = get_data_model()->get_radio_cap(get_radio_interface_mac())->get_radio_cap_info();
    em_eht_operations_t *eht_ops = (em_eht_operations_t *)buff;

    if ((eht_ops == NULL) || (cap_info == NULL)) {
        printf("%s:%d No data Found\n", __func__, __LINE__);
        return 0;
    }
    memcpy(&eht_ops,&cap_info->eht_ops,sizeof(em_eht_operations_t));
    len = sizeof(em_eht_operations_t);
    return len;
}

short em_t::create_channelscan_tlv(unsigned char *buff)
{
    short len = 0;
    em_radio_cap_info_t* cap_info = get_data_model()->get_radio_cap(get_radio_interface_mac())->get_radio_cap_info();
    em_channel_scan_cap_radio_t *scan = (em_channel_scan_cap_radio_t *)buff;

    if ((scan == NULL) || (cap_info == NULL)) {
        printf("%s:%d No data Found\n", __func__, __LINE__);
        return 0;
    }
    memcpy(&scan,&cap_info->ch_scan,sizeof(em_channel_scan_cap_radio_t));
    len = sizeof(em_channel_scan_cap_radio_t);
    return len;
}

short em_t::create_prof_2_tlv(unsigned char *buff)
{
    short len = 0;
    em_radio_cap_info_t* cap_info = get_data_model()->get_radio_cap(get_radio_interface_mac())->get_radio_cap_info();
    em_profile_2_ap_cap_t *prof = (em_profile_2_ap_cap_t *)buff;

    if ((prof == NULL) || (cap_info == NULL)) {
        printf("%s:%d No data Found\n", __func__, __LINE__);
        return 0;
    }

    memcpy(&prof,&cap_info->prof_2_ap_cap,sizeof(em_profile_2_ap_cap_t));
    len = sizeof(em_profile_2_ap_cap_t);
    return len;
}

short em_t::create_device_inventory_tlv(unsigned char *buff)
{
    short len = 0;
    dm_radio_t* radio = get_data_model()->get_radio(get_radio_interface_mac());
    em_radio_info_t* radio_info = radio->get_radio_info();
    em_device_inventory_t *invent = (em_device_inventory_t *)buff;

    if ((invent == NULL) || (radio_info == NULL)) {
        printf("%s:%d No data Found\n", __func__, __LINE__);
        return 0;
    }

    memcpy(&invent,&radio_info->inventory_info,sizeof(em_device_inventory_t));
    len = sizeof(em_device_inventory_t);
    return len;
}

short em_t::create_radioad_tlv(unsigned char *buff)
{
    short len = 0;
    em_radio_cap_info_t* cap_info = get_data_model()->get_radio_cap(get_radio_interface_mac())->get_radio_cap_info();
    em_ap_radio_advanced_cap_t *ad = (em_ap_radio_advanced_cap_t *)buff;

    if ((ad == NULL) || (cap_info == NULL)) {
        printf("%s:%d No data Found\n", __func__, __LINE__);
        return 0;
    }

    memcpy(&ad,&cap_info->radio_ad_cap,sizeof(em_ap_radio_advanced_cap_t));
    len = sizeof(em_ap_radio_advanced_cap_t);
    return len;
}

short em_t::create_metric_col_int_tlv(unsigned char *buff)
{
    short len = 0;
    em_radio_cap_info_t* cap_info = get_data_model()->get_radio_cap(get_radio_interface_mac())->get_radio_cap_info();
    em_metric_cltn_interval_t *clt = (em_metric_cltn_interval_t *)buff;

    if ((clt == NULL) || (cap_info == NULL)) {
        printf("%s:%d No data Found\n", __func__, __LINE__);
        return 0;
    }

    memcpy(&clt,&cap_info->metric_interval,sizeof(em_metric_cltn_interval_t));
    len = sizeof(em_metric_cltn_interval_t);
    return len;
}

short em_t::create_cac_cap_tlv(unsigned char *buff)
{
    short len = 0;
    em_radio_cap_info_t* cap_info = get_data_model()->get_radio_cap(get_radio_interface_mac())->get_radio_cap_info();
    em_cac_cap_t *cac = (em_cac_cap_t *)buff;

    if ((cac == NULL) || (cap_info == NULL)) {
        printf("%s:%d No data Found\n", __func__, __LINE__);
        return 0;
    }

    memcpy(&cac->radios[0],&cap_info->cac_cap,sizeof(em_cac_cap_radio_t));
    cac->radios_num = 1;
    len = sizeof(em_cac_cap_t);
    return len;
}

int em_t::push_event(em_event_t *evt)
{
	em_event_t *e;

    e = (em_event_t *)malloc(sizeof(em_event_t));
    memcpy(e, evt, sizeof(em_event_t));

    m_mgr->push_to_queue(e);
}

int em_t::init()
{
    //m_data_model->print_config();
    m_data_model->set_em(this);

    if (is_al_interface_em() == true) {
        if (start_al_interface() != 0) {
            return -1;
        }   

    }

    m_exit = false;

    // initialize the ingress queue
    m_iq.queue = queue_create();
    pthread_mutex_init(&m_iq.lock, NULL);
    pthread_cond_init(&m_iq.cond, NULL);
    m_iq.timeout = EM_PROTO_TOUT;

    // initialize the crypto
    m_crypto.init();

    if (pthread_create(&m_tid, NULL, em_t::em_func, this) != 0) {
        printf("%s:%d: Failed to start em thread\n", __func__, __LINE__);
        close(m_fd);
        pthread_mutex_destroy(&m_iq.lock);
        pthread_cond_destroy(&m_iq.cond);
        return -1; 
    }

    return 0;

}

const char *em_t::state_2_str(em_state_t state)
{
#define EM_STATE_2S(x) case x: return #x;
    switch (state) {
		EM_STATE_2S(em_state_ctrl_unconfigured)
		EM_STATE_2S(em_state_ctrl_wsc_m1_pending)
		EM_STATE_2S(em_state_ctrl_wsc_m2_sent)
		EM_STATE_2S(em_state_ctrl_topo_sync_pending)
		EM_STATE_2S(em_state_ctrl_topo_synchronized)
		EM_STATE_2S(em_state_ctrl_channel_query_pending)
		EM_STATE_2S(em_state_ctrl_channel_pref_report_pending)
		EM_STATE_2S(em_state_ctrl_channel_queried)
		EM_STATE_2S(em_state_ctrl_channel_select_pending)
		EM_STATE_2S(em_state_ctrl_channel_selected)
		EM_STATE_2S(em_state_ctrl_channel_report_pending)
		EM_STATE_2S(em_state_ctrl_channel_cnf_pending)
		EM_STATE_2S(em_state_ctrl_channel_scan_pending)
		EM_STATE_2S(em_state_ctrl_configured)
		EM_STATE_2S(em_state_ctrl_misconfigured)
		EM_STATE_2S(em_state_ctrl_sta_cap_pending)
		EM_STATE_2S(em_state_ctrl_sta_cap_confirmed)
		EM_STATE_2S(em_state_ctrl_sta_link_metrics_pending)
		EM_STATE_2S(em_state_ctrl_sta_steer_pending)
		EM_STATE_2S(em_state_ctrl_sta_disassoc_pending)
		EM_STATE_2S(em_state_ctrl_set_policy_pending)
    }

    return "em_state_unknown";
}

const char *em_t::get_band_type_str(em_freq_band_t band)
{
#define BAND_TYPE_2S(x) case x: return #x;
    switch (band) {
        BAND_TYPE_2S(em_freq_band_24)
        BAND_TYPE_2S(em_freq_band_5)
        BAND_TYPE_2S(em_freq_band_60)
    }

    return "band_type_unknown";
}

em_t::em_t(em_interface_t *ruid, em_freq_band_t band, dm_easy_mesh_t *dm, em_mgr_t *mgr, em_profile_type_t profile, em_service_type_t type)
{
    memcpy(&m_ruid, ruid, sizeof(em_interface_t));
    m_band = band;  
    m_service_type = type;
    m_profile_type = profile;
    m_sm.init_sm(type);
	m_orch_state = em_orch_state_idle;
    m_cmd = NULL;
    
    RAND_bytes(get_crypto_info()->e_nonce, sizeof(em_nonce_t));
    RAND_bytes(get_crypto_info()->r_nonce, sizeof(em_nonce_t));
    m_data_model = dm;
	m_mgr = mgr;
}

em_t::~em_t()
{

}
