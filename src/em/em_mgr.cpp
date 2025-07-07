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
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <openssl/bio.h> /* BasicInput/Output streams */
#include <openssl/err.h> /* errors */
#include <openssl/ssl.h> /* core library */
#include "em.h"
#include "em_mgr.h"
#include "em_msg.h"
#include "em_cmd.h"
#include "util.h"

#ifdef AL_SAP
#include "al_service_access_point.h"

extern char *global_netid;
extern AlServiceAccessPoint* g_sap;
#endif

void em_mgr_t::io_process(em_bus_event_type_t type, char *data, unsigned int len, em_cmd_params_t *params)
{
    em_event_t *evt;
    em_bus_event_t *bevt;

    evt = static_cast<em_event_t *>(malloc(sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN));
    evt->type = em_event_type_bus;
    bevt = &evt->u.bevt;
    bevt->type = type;
    bevt->data_len = len;

	if (data != NULL) {
    	memcpy(bevt->u.subdoc.buff, data, len);
	}

	if (params != NULL) {
		memcpy(&bevt->params, params, sizeof(em_cmd_params_t));
	}

    push_to_queue(evt);
}

void em_mgr_t::io_process(em_bus_event_type_t type, unsigned char *data, unsigned int len, em_cmd_params_t *params)
{
    em_event_t *evt;
    em_bus_event_t *bevt;

    evt = static_cast<em_event_t *>(malloc(sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN));
    evt->type = em_event_type_bus;
    bevt = &evt->u.bevt;
    bevt->type = type;
    bevt->data_len = len;

	if (data != NULL) {
    	memcpy(bevt->u.raw_buff, data, len);
	}

	if (params != NULL) {
		memcpy(&bevt->params, params, sizeof(em_cmd_params_t));
	}

    push_to_queue(evt);
}

bool em_mgr_t::io_process(em_event_t *evt)
{
    em_event_t *e;
    em_bus_event_t *bevt;
    bool should_wait;

    bevt = &evt->u.bevt;
    //em_cmd_t::dump_bus_event(bevt);

    e = static_cast<em_event_t *>(malloc(sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN));
    memcpy(reinterpret_cast<unsigned char *>(e), reinterpret_cast<unsigned char *>(evt), sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN);

    push_to_queue(e);

    // check if the server should wait
    should_wait = false;

    switch (evt->type) {
        case em_event_type_bus:
            bevt = &evt->u.bevt;
            if (bevt->type != em_bus_event_type_dm_commit) {
                should_wait = true;
            }
            break;

        default:
            break;
    }

    return should_wait;
}

void em_mgr_t::proto_process(unsigned char *data, unsigned int len, em_t *al_em)
{
    em_event_t	*evt;
    em_t *em = NULL;

	em = find_em_for_msg_type(data, len, al_em);
	if (em == NULL) {
		return;
	}

    evt = static_cast<em_event_t *>(malloc(sizeof(em_event_t)));
    evt->type = em_event_type_frame;
    evt->u.fevt.frame = static_cast<unsigned char *>(malloc(len));
    memcpy(evt->u.fevt.frame, data, len);
    evt->u.fevt.frame_len = len;
    em->push_to_queue(evt);
}

void em_mgr_t::delete_nodes()
{
    em_t *em = NULL, *tmp;

    em = static_cast<em_t *>(hash_map_get_first(m_em_map));
    while (em != NULL) {
        tmp = em;
        em = static_cast<em_t *>(hash_map_get_next(m_em_map, em));
        if (tmp->is_al_interface_em() == false) {
            delete_node(tmp->get_radio_interface());
        }

    }
}

void em_mgr_t::delete_node(em_interface_t *ruid)
{
    em_t *em = NULL;
    mac_addr_str_t	mac_str;

    dm_easy_mesh_t::macbytes_to_string(ruid->mac, mac_str);

    if ((em = static_cast<em_t *>(hash_map_get(m_em_map, mac_str))) == NULL) {
        printf("%s:%d: Can not find node with key:%s\n", __func__, __LINE__, mac_str);
        return;
    }

    em->stop();
    em->deinit();
	pthread_mutex_lock(&m_mutex);
	hash_map_remove(m_em_map, mac_str);
	pthread_mutex_unlock(&m_mutex);
    delete em;

}

em_t *em_mgr_t::create_node(em_interface_t *ruid, em_freq_band_t band, dm_easy_mesh_t *dm, bool is_al_mac,em_profile_type_t profile, em_service_type_t type)
{
    em_t *em = NULL;
    char mac_str[32];

    if (ruid == NULL) {
        printf("%s:%d: Invalid ruid\n", __func__, __LINE__);
        return NULL;
    }

    if (dm_easy_mesh_t::name_from_mac_address(&ruid->mac, ruid->name) != 0) {
        printf("%s:%d: ruid name cannot be determined\n", __func__, __LINE__);
    }

    dm_easy_mesh_t::macbytes_to_string(ruid->mac, mac_str);
	if (is_al_mac) {
		strcat(mac_str, "_al");
	}
	printf("%s:%d key value used:%s\n", __func__, __LINE__, mac_str);
    em = static_cast<em_t *>(hash_map_get(m_em_map, mac_str));

    if (em != NULL) {
        // update the em
        printf("%s:%d: node with key:%s already exists\n", __func__, __LINE__, mac_str);
        return em;
    }

    em = new em_t(ruid, band, dm, this, profile, type, is_al_mac);
    if (em->init() != 0) {
        delete em;

        return NULL;
    }

    // add this em to hash map
	pthread_mutex_lock(&m_mutex);
    hash_map_put(m_em_map, strdup(mac_str), em);
	pthread_mutex_unlock(&m_mutex);
    printf("%s:%d: created entry for key:%s\n", __func__, __LINE__, mac_str);

    return em;
}

em_t *em_mgr_t::get_node_by_freq_band(em_freq_band_t *band)
{
    em_t *em = NULL;
    bool found = false;

    em = static_cast<em_t *>(hash_map_get_first(m_em_map));
    while (em != NULL) {
        if (em->is_matching_freq_band(band) == true) {
            found = true;
            break;
        }
        em = static_cast<em_t *>(hash_map_get_next(m_em_map, em));
    }

    return (found == true) ? em:NULL;
}

em_t *em_mgr_t::get_al_node()
{
    em_t *em;
    bool found = false;

    em = static_cast<em_t *>(hash_map_get_first(m_em_map));
    while (em != NULL) {
        if (em->is_al_interface_em() == true) {
            found = true;
            break;
        }
        em = static_cast<em_t *>(hash_map_get_next(m_em_map, em));
    }

    return (found == true) ? em:NULL;
}

em_t *em_mgr_t::get_phy_al_node()
{
    // al_node is the fake ("_al") node
    em_t* al_node = get_al_node();
    if (al_node == NULL) return NULL;
    uint8_t* al_mac = al_node->get_radio_interface_mac();

    // al_mac_str is the real MAC (no "_al" suffix)
    // al_mac_str will be the key for the real `em_t` in the `m_em_map`
    char al_mac_str[EM_MAC_STR_LEN+1] = {0};
    dm_easy_mesh_t::macbytes_to_string(al_mac, al_mac_str);
    em_t *phy_al_em = reinterpret_cast<em_t *>(hash_map_get(m_em_map, al_mac_str));
    if (phy_al_em == NULL) {
        printf("%s:%d: Can not find phy al node with key:%s\n", __func__, __LINE__, al_mac_str);
        return NULL;
    }
    return phy_al_em;
}

void *em_mgr_t::mgr_input_listen(void *arg)
{
    size_t stack_size2;
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_getstacksize(&attr, &stack_size2);
    pthread_attr_destroy(&attr);
    printf("%s:%d Thread stack size = %ld bytes \n", __func__, __LINE__, stack_size2);
    em_mgr_t *mgr = static_cast<em_mgr_t *>(arg);

    mgr->input_listener();
    return NULL;
}

int em_mgr_t::input_listen()
{
    size_t stack_size = 0x800000; /* 8MB */
    pthread_attr_t attr;
    pthread_attr_t *attrp = NULL;
    int ret = 0;
    attrp = &attr;
    pthread_attr_init(&attr);
    // Setting explicitly stacksize as in few platforms(e.g. openwrt) if not called, the
    // new thread will inherit the default stack size which is significantly less
    // leading to stack overflow.
    ret = pthread_attr_setstacksize(&attr, stack_size);
    if (ret != 0) {
        printf("%s:%d pthread_attr_setstacksize failed for size:%ld ret:%d\n",
                __func__, __LINE__, stack_size, ret);
    }
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    if (pthread_create(&m_tid, attrp, em_mgr_t::mgr_input_listen, this) != 0) {
        printf("%s:%d: Failed to start em mgr thread\n", __func__, __LINE__);
        if(attrp != NULL) {
            pthread_attr_destroy(attrp);
        }
        return -1;
    }

    if(attrp != NULL) {
        pthread_attr_destroy(attrp);
    }
    return 0;
}

int em_mgr_t::reset_listeners()
{
    int highest_fd = 0, num = 0;
    em_t *em = NULL;

    FD_ZERO(&m_rset);

	pthread_mutex_lock(&m_mutex);
    em = static_cast<em_t *>(hash_map_get_first(m_em_map));
    while (em != NULL) {
        if (em->is_al_interface_em() == true) {
            FD_SET(em->get_fd(), &m_rset);
            num++;
            highest_fd = (em->get_fd() > highest_fd) ? em->get_fd():highest_fd;
        }
        em = static_cast<em_t *>(hash_map_get_next(m_em_map, em));
    }
	pthread_mutex_unlock(&m_mutex);
    return highest_fd;

}

void em_mgr_t::nodes_listener()
{
    em_t *em = NULL;
    struct timeval tm;
    int rc, highest_fd = 0;

    tm.tv_sec = 0;
    tm.tv_usec = m_timeout * 1000;
    highest_fd = reset_listeners();

    while ((rc = select(highest_fd + 1, &m_rset, NULL, NULL, &tm)) >= 0) {
        if (rc == 0) {
            tm.tv_sec = 0;
            tm.tv_usec = m_timeout * 1000;
            highest_fd = reset_listeners();

            continue;
        }

        em = static_cast<em_t *>(hash_map_get_first(m_em_map));
        while (em != NULL) {
            if (em->is_al_interface_em() == true) {
#ifdef AL_SAP
                try{
                    AlServiceDataUnit sdu = g_sap->serviceAccessPointDataIndication();
                    std::vector<unsigned char> payload = sdu.getPayload();
                    // Original implementation expects whole ethernet frame
                    // not just CMDU, so we have to reconstruct it
                    std::vector<unsigned char> reconstructed_eth_frame;
                    auto first_mac = sdu.getSourceAlMacAddress();
                    reconstructed_eth_frame.insert(reconstructed_eth_frame.end(),first_mac.begin(),first_mac.end());
                    auto second_mac = sdu.getDestinationAlMacAddress();
                    reconstructed_eth_frame.insert(reconstructed_eth_frame.end(),second_mac.begin(),second_mac.end());

                    reconstructed_eth_frame.push_back(0x89);
                    reconstructed_eth_frame.push_back(0x3A);

                    reconstructed_eth_frame.insert(reconstructed_eth_frame.end(),payload.begin(),payload.end());
#ifdef DEBUG_MODE
                    em_printfout("First MAC Address: " MACSTRFMT, MAC2STR(first_mac));
                    em_printfout("Second MAC Address: " MACSTRFMT, MAC2STR(second_mac));
                    em_printfout("RECONSTRUCTED_ETH_FRAME: \t");
                    util::print_hex_dump(reconstructed_eth_frame);
#endif
                    proto_process(reconstructed_eth_frame.data(), static_cast<unsigned int>(reconstructed_eth_frame.size()), em);
                } catch (const AlServiceException& e) {
                    if (e.getPrimitiveError() == PrimitiveError::InvalidMessage) {
                        em_printfout("%s. Dropping packet", e.what());
                    } else {
                        em_printfout("%s", e.what());
                        throw e; // rethrow the exception if it's not an indication failure
                    }
                }
#else
                unsigned char buff[MAX_EM_BUFF_SZ];
                pthread_mutex_lock(&m_mutex);
                int ret = FD_ISSET(em->get_fd(), &m_rset);
                pthread_mutex_unlock(&m_mutex);
                if (ret)
                {
                    // receive data from this interface
                    memset(buff, 0, MAX_EM_BUFF_SZ);
                    ssize_t len = read(em->get_fd(), buff, MAX_EM_BUFF_SZ);
                    if (len) {
                        proto_process(buff, static_cast<unsigned int>(len), em);
                    }
                }
#endif
            }
            em = static_cast<em_t *>(hash_map_get_next(m_em_map, em));
        }
        tm.tv_sec = 0;
        tm.tv_usec = m_timeout * 1000;
        highest_fd = reset_listeners();

    }
}


void *em_mgr_t::mgr_nodes_listen(void *arg)
{
    size_t stack_size2;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_getstacksize(&attr, &stack_size2);
    printf("%s:%d Thread stack size = %ld bytes \n", __func__, __LINE__, stack_size2);
    pthread_attr_destroy(&attr);
    em_mgr_t *mgr = static_cast<em_mgr_t *>(arg);
    mgr->nodes_listener();
    return NULL;
}

int em_mgr_t::nodes_listen()
{
    size_t stack_size = 0x800000; /* 8MB */
    pthread_attr_t attr;
    pthread_attr_t *attrp = NULL;
    int ret = 0;
    attrp = &attr;
    pthread_attr_init(&attr);
    // Setting explicitly stacksize as in few platforms(e.g. openwrt) if not called, the
    // new thread will inherit the default stack size which is significantly less
    // leading to stack overflow.
    ret = pthread_attr_setstacksize(&attr, stack_size);
    if (ret != 0) {
        printf("%s:%d pthread_attr_setstacksize failed for size:%ld ret:%d\n",
                __func__, __LINE__, stack_size, ret);
    }
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&m_tid, attrp, em_mgr_t::mgr_nodes_listen, this) != 0) {
        printf("%s:%d: Failed to start em mgr thread\n", __func__, __LINE__);
        if(attrp != NULL) {
            pthread_attr_destroy(attrp);
        }
        return -1;
    }
    if(attrp != NULL) {
        pthread_attr_destroy(attrp);
    }
    return 0;
}

void em_mgr_t::handle_timeout()
{
	m_tick_demultiplex++;

	handle_500ms_tick();

	if ((m_tick_demultiplex % EM_1_TOUT_MULT) == 0) {
		handle_1s_tick();
	}

	if ((m_tick_demultiplex % EM_2_TOUT_MULT) == 0) {
		handle_2s_tick();
	}

	if ((m_tick_demultiplex % EM_5_TOUT_MULT) == 0) {
		handle_5s_tick();
		m_tick_demultiplex = 0;
	}

}

int em_mgr_t::start()
{
    int rc;
    em_event_t *evt;;
    struct timespec time_to_wait;
    struct timeval tm;
	bool started = false;
    input_listen();
    nodes_listen();
    pthread_mutex_lock(&m_queue.lock);
    while (m_exit == false) {
        rc = 0;

        gettimeofday(&tm, NULL);
        time_to_wait.tv_sec = tm.tv_sec;
       	time_to_wait.tv_nsec = tm.tv_usec * 1000;
		util::add_milliseconds(&time_to_wait, m_queue.timeout);

        if (queue_count(m_queue.queue) == 0) {
            rc = pthread_cond_timedwait(&m_queue.cond, &m_queue.lock, &time_to_wait);
        }
        if ((rc == 0) || (queue_count(m_queue.queue) != 0)) {
            // dequeue data
            while (queue_count(m_queue.queue)) {
                evt = static_cast<em_event_t *>(queue_pop(m_queue.queue));
                if (evt == NULL) {
                    continue;
                }
                pthread_mutex_unlock(&m_queue.lock);
                if (((evt->type == em_event_type_bus) && ((evt->u.bevt.type == em_bus_event_type_reset) ||
                      (evt->u.bevt.type == em_bus_event_type_get_reset))) ||
						(is_data_model_initialized() == true)) {

                    handle_event(evt);
                }
                free(evt);
                pthread_mutex_lock(&m_queue.lock);
            }
        } else if (rc == ETIMEDOUT) {
            pthread_mutex_unlock(&m_queue.lock);
            //printf("%s:%d: Timeout secs: %d\n", __func__, __LINE__, time_to_wait.tv_sec);
            if (is_data_model_initialized() == true) {
				if (started == false) {
					start_complete();
					started = true;
				}
                handle_timeout();
            }
            pthread_mutex_lock(&m_queue.lock);
        } else {
            printf("%s:%d em exited with rc - %d\n",__func__,__LINE__, rc);
            pthread_mutex_unlock(&m_queue.lock);
            return -1;
        }
    }
    pthread_mutex_unlock(&m_queue.lock);
    return 0;
}

void em_mgr_t::push_to_queue(em_event_t *evt)
{
    pthread_mutex_lock(&m_queue.lock);
    queue_push(m_queue.queue, evt);
    pthread_cond_signal(&m_queue.cond);
    pthread_mutex_unlock(&m_queue.lock);
}

em_event_t *em_mgr_t::pop_from_queue()
{
    return static_cast<em_event_t *>(queue_pop(m_queue.queue));
}

int em_mgr_t::init(const char *data_model_path)
{
    SSL_load_error_strings();
    SSL_library_init();

    m_em_map = hash_map_create();

    // initialize the egress queue
    m_queue.queue = queue_create();
    pthread_mutex_init(&m_queue.lock, NULL);
    pthread_cond_init(&m_queue.cond, NULL);

    m_queue.timeout = EM_MGR_TOUT;

    orch_init();
    return data_model_init(data_model_path);
}

em_mgr_t::em_mgr_t()
{
    m_exit = false;
    m_timeout = EM_MGR_TOUT;
	m_tick_demultiplex = 0;
}

em_mgr_t::~em_mgr_t()
{

}
