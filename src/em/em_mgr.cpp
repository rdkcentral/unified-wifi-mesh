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

extern char *global_netid;

void em_mgr_t::proto_process(unsigned char *data, unsigned int len, em_t *em)
{
    em_raw_hdr_t *hdr;
    em_cmdu_t *cmdu;
    em_event_t	*evt;
    mac_address_t ruid;
    em_freq_band_t band;
    em_profile_type_t profile;
    mac_addr_str_t mac_str1, mac_str2;
    em_interface_t intf;
    em_t *radio_em = NULL;
    em_t *al_em = em;
    bool found = false;
    dm_easy_mesh_t *dm;

    assert(len > ((sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))));
    if (len < ((sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)))) {
        return;
    }

    hdr = (em_raw_hdr_t *)data;

    if (hdr->type != htons(ETH_P_1905)) {
        return;
    }

    cmdu = (em_cmdu_t *)(data + sizeof(em_raw_hdr_t));
    if (((get_service_type() == em_service_type_agent) && (htons(cmdu->type) == em_msg_type_autoconf_resp)) == true) {
        if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                    len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_freq_band(&band) == false) {
            printf("%s:%d: Could not find frequency band\n", __func__, __LINE__);
            return;
        }
        radio_em = (em_t *)hash_map_get_first(m_em_map);
        while (radio_em != NULL) {
            if (radio_em->is_matching_freq_band(&band) == true) {
                found = true;
                break;
            }
            radio_em = (em_t *)hash_map_get_next(m_em_map, radio_em);
        }  

        if (found == true) {
            dm_easy_mesh_t::macbytes_to_string(radio_em->get_radio_interface_mac(), mac_str1);
            //printf("%s:%d: Found em:%s with matching frequency band:%d\n", __func__, __LINE__, mac_str, band);
            em = radio_em;
        } else {
            printf("%s:%d: Could not find em with matching band%d\n", __func__, __LINE__, band);
            return;
        }

    } else if (((get_service_type() == em_service_type_ctrl) && (htons(cmdu->type) == em_msg_type_autoconf_search)) == true) {
        if ((em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)), len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_freq_band(&band) == true) && (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)), len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_al_mac_address(intf.mac) == true)) {
            dm_easy_mesh_t::macbytes_to_string(intf.mac, mac_str1);
            printf("%s:%d: Received autoconfig search from agenti al mac: %s\n", __func__, __LINE__, mac_str1);
            if ((dm = get_data_model((const char *)global_netid, (const unsigned char *)intf.mac)) == NULL) {
                if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)), len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_profile(&profile) == false) {
                    profile = em_profile_type_1;
                }
                dm = create_data_model((const char *)global_netid, (const unsigned char *)intf.mac, profile);
                printf("%s:%d: Created data model for mac: %s net: %s\n", __func__, __LINE__, mac_str1, global_netid);
            } else {
                dm_easy_mesh_t::macbytes_to_string(dm->get_agent_al_interface_mac(), mac_str1);
                printf("%s:%d: Found existing data model for mac: %s net: %s\n", __func__, __LINE__, mac_str1, global_netid);
            }
            em = al_em;
        } 

    } else if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_radio_id(&ruid) == true) {
        dm_easy_mesh_t::macbytes_to_string(ruid, mac_str1);
        if ((radio_em = (em_t *)hash_map_get(m_em_map, mac_str1)) != NULL) {
            em = radio_em;
            printf("%s:%d: Found existing radio:%s\n", __func__, __LINE__, mac_str1);
            em->set_state(em_state_ctrl_wsc_m1_pending);
        } else if (((get_service_type() == em_service_type_ctrl) && (htons(cmdu->type) == em_msg_type_autoconf_wsc)) == true) {
            if ((dm = get_data_model((const char *)global_netid, (const unsigned char *)hdr->src)) == NULL) {
                printf("%s:%d: Can not find data model\n", __func__, __LINE__);
            }

            dm_easy_mesh_t::macbytes_to_string(hdr->src, mac_str1);
            dm_easy_mesh_t::macbytes_to_string(ruid, mac_str2);

            printf("%s:%d: Found data model for mac: %s, creating node for ruid: %s\n", __func__, __LINE__, mac_str1, mac_str2);

            memcpy(intf.mac, ruid, sizeof(mac_address_t));
            if ((radio_em = create_node(&intf, em_freq_band_unknown, dm, false,  dm->get_device()->m_device_info.profile, 
					em_service_type_ctrl)) != NULL) {                
                em = radio_em;
                em->set_state(em_state_ctrl_wsc_m1_pending);
            } else {
                em = al_em;
            } 	
        }

    } else if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_freq_band(&band) == true) {
        if ((radio_em = get_node_by_freq_band(&band)) != NULL) {
            em = radio_em;
        }
    } else {
        em = al_em;	
    }

    evt = (em_event_t *)malloc(sizeof(em_event_t));
    evt->type = em_event_type_frame;
    evt->u.fevt.frame = (unsigned char *)malloc(len);
    memcpy(evt->u.fevt.frame, data, len);
    evt->u.fevt.len = len;
    em->push_to_queue(evt);
}

void em_mgr_t::delete_nodes()
{
    em_t *em = NULL, *tmp;

    em = (em_t *)hash_map_get_first(m_em_map);
    while (em != NULL) {
        tmp = em;
        em = (em_t *)hash_map_get_next(m_em_map, em);
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

    if ((em = (em_t *)hash_map_get(m_em_map, mac_str)) == NULL) {
        printf("%s:%d: Can not find node with key:%s\n", __func__, __LINE__, mac_str);
        return;
    }

    em->stop();
    em->deinit();
    hash_map_remove(m_em_map, mac_str);
    delete em;

}

em_t *em_mgr_t::create_node(em_interface_t *ruid, em_freq_band_t band, dm_easy_mesh_t *dm, bool is_al_mac,em_profile_type_t profile, em_service_type_t type)
{
    em_t *em = NULL;
    mac_addr_str_t  mac_str;

    if (ruid == NULL) {
        printf("%s:%d: Invalid ruid\n", __func__, __LINE__);
        return NULL;
    }

    if (dm_easy_mesh_t::name_from_mac_address(&ruid->mac, ruid->name) != 0) {
        printf("%s:%d: ruid name cannot be determined\n", __func__, __LINE__);
    }

    dm_easy_mesh_t::macbytes_to_string(ruid->mac, mac_str);
    em = (em_t *)hash_map_get(m_em_map, mac_str);

    if (em != NULL) {
        // update the em
        printf("%s:%d: node with key:%s already exists\n", __func__, __LINE__, mac_str);
        return em;
    }

    em = new em_t(ruid, band, dm, profile, type);
    em->set_al_type(is_al_mac);
    if (em->init() != 0) {
        delete em;

        return NULL;
    }

    // add this em to hash map 
    hash_map_put(m_em_map, strdup(mac_str), em);
    printf("%s:%d: created entry for key:%s\n", __func__, __LINE__, mac_str);

    return em;
}

em_t *em_mgr_t::get_node_by_freq_band(em_freq_band_t *band)
{
    em_t *em = NULL;
    bool found = false;

    em = (em_t *)hash_map_get_first(m_em_map);
    while (em != NULL) {
        if (em->is_matching_freq_band(band) == true) {
            found = true;
            break;
        }
        em = (em_t *)hash_map_get_next(m_em_map, em);
    }

    return (found == true) ? em:NULL;
}

em_t *em_mgr_t::get_al_node()
{
    em_t *em;
    bool found = false;

    em = (em_t *)hash_map_get_first(m_em_map);
    while (em != NULL) {
        if (em->is_al_interface_em() == true) {
            found = true;
            break;
        }
        em = (em_t *)hash_map_get_next(m_em_map, em);
    }

    return (found == true) ? em:NULL;	
}

void *em_mgr_t::mgr_input_listen(void *arg)
{
    em_mgr_t *mgr = (em_mgr_t *)arg;

    mgr->input_listener();
    return NULL;
}

int em_mgr_t::input_listen()
{
    if (pthread_create(&m_tid, NULL, em_mgr_t::mgr_input_listen, this) != 0) {
        printf("%s:%d: Failed to start em mgr thread\n", __func__, __LINE__);
        return -1;
    }

    return 0;
}

int em_mgr_t::reset_listeners()
{
    int highest_fd = 0, num = 0;
    em_t *em = NULL;

    FD_ZERO(&m_rset);

    em = (em_t *)hash_map_get_first(m_em_map);
    while (em != NULL) {
        if (em->is_al_interface_em() == true) {
            FD_SET(em->get_fd(), &m_rset);
            num++;
            highest_fd = (em->get_fd() > highest_fd) ? em->get_fd():highest_fd;
        }
        em = (em_t *)hash_map_get_next(m_em_map, em);
    }

    return highest_fd;

}

void em_mgr_t::nodes_listener()
{
    em_t *em = NULL;
    struct timeval tm;
    int rc, len, highest_fd = 0;
    unsigned char buff[MAX_EM_BUFF_SZ];
    em_raw_hdr_t *hdr;

    tm.tv_sec = m_timeout;
    tm.tv_usec = 0;
    highest_fd = reset_listeners();

    while ((rc = select(highest_fd + 1, &m_rset, NULL, NULL, &tm)) >= 0) {
        if (rc == 0) {
            tm.tv_sec = m_timeout;
            tm.tv_usec = 0;
            highest_fd = reset_listeners();

            continue;
        }

        em = (em_t *)hash_map_get_first(m_em_map);
        while (em != NULL) {
            if (em->is_al_interface_em() == true) {
                if (FD_ISSET(em->get_fd(), &m_rset)) {
                    // receive data from this interface
                    memset(buff, 0, MAX_EM_BUFF_SZ);
                    len = read(em->get_fd(), buff, MAX_EM_BUFF_SZ);
                    if (len) {
                        hdr = (em_raw_hdr_t *)buff;
                        proto_process(buff, len, em);
                    }
                }
            }
            em = (em_t *)hash_map_get_next(m_em_map, em);
        }

        tm.tv_sec = m_timeout;
        tm.tv_usec = 0;
        highest_fd = reset_listeners();

    }


}


void *em_mgr_t::mgr_nodes_listen(void *arg)
{
    em_mgr_t *mgr = (em_mgr_t *)arg;

    mgr->nodes_listener();
    return NULL;
}

int em_mgr_t::nodes_listen()
{
    if (pthread_create(&m_tid, NULL, em_mgr_t::mgr_nodes_listen, this) != 0) {
        printf("%s:%d: Failed to start em mgr thread\n", __func__, __LINE__);
        return -1;
    }

    return 0;
}

int em_mgr_t::start()
{
    int rc;
    em_event_t *evt;;
    struct timespec time_to_wait;
    struct timeval tm;

    input_listen();
    nodes_listen();

    pthread_mutex_lock(&m_queue.lock);
    while (m_exit == false) {
        rc = 0;

        gettimeofday(&tm, NULL);
        time_to_wait.tv_sec = tm.tv_sec;
        time_to_wait.tv_nsec = tm.tv_usec * 1000;
        time_to_wait.tv_sec += m_queue.timeout;

        if (queue_count(m_queue.queue) == 0) {
            rc = pthread_cond_timedwait(&m_queue.cond, &m_queue.lock, &time_to_wait);
        }
        if ((rc == 0) || (queue_count(m_queue.queue) != 0)) {
            // dequeue data
            while (queue_count(m_queue.queue)) {
                evt = (em_event_t *)queue_pop(m_queue.queue);
                if (evt == NULL) {
                    continue;
                }
                pthread_mutex_unlock(&m_queue.lock);
                if (((evt->type == em_event_type_bus) && (evt->u.bevt.type == em_bus_event_type_reset)) || (is_data_model_initialized() == true)) {
                    handle_event(evt);
                }
                free(evt);
                pthread_mutex_lock(&m_queue.lock);
            }
        } else if (rc == ETIMEDOUT) {
            pthread_mutex_unlock(&m_queue.lock);
            //printf("%s:%d: Timeout secs: %d\n", __func__, __LINE__, time_to_wait.tv_sec);
            if (is_data_model_initialized() == true) {            
                handle_timeout();
            }
            pthread_mutex_lock(&m_queue.lock);
        } else {
            printf("%s:%d em exited with rc - %d",__func__,__LINE__,rc);
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
    return (em_event_t *)queue_pop(m_queue.queue);
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
}

em_mgr_t::~em_mgr_t()
{

}
