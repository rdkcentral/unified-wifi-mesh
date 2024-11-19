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
#include <ctype.h>
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
#include <sys/types.h>
#include <ifaddrs.h> 
#include "dm_easy_mesh.h"
#include "em_cmd_dev_init.h"
#include <cjson/cJSON.h>
#include "em_cmd_sta_list.h"
#include "em_cmd_ap_cap.h" 

dm_network_t *dm_easy_mesh_list_t::get_first_network()
{
    unsigned int i;
    dm_network_t *net = NULL;
    dm_easy_mesh_t *dm;
    bool found = false;

    if (m_num_networks == 0) {
        return NULL;
    }

    dm = (dm_easy_mesh_t *)hash_map_get_first(m_list);
    while (dm != NULL) {
        net = dm->get_network();
	if (strncmp(net->m_net_info.id, m_network_list[0], strlen(m_network_list[0])) == 0) {
	    found = true;
	    break;
	}
	dm = (dm_easy_mesh_t *)hash_map_get_next(m_list, dm);
    }
	
    return (found == true) ? net:NULL;
}

dm_network_t *dm_easy_mesh_list_t::get_next_network(dm_network_t *net)
{
    dm_network_t *pnet = NULL;
    unsigned int i;
    char *net_id_to_find;
    dm_easy_mesh_t *dm;
    bool found = false;

    for (i = 0; i < m_num_networks; i++) {
        if (strncmp(net->m_net_info.id, m_network_list[i], strlen(m_network_list[i])) == 0) {
	    break;
	}
    }

    if ((i + 1) >= m_num_networks) {
        return NULL;
    }

    net_id_to_find = m_network_list[i + 1];

    dm = (dm_easy_mesh_t *)hash_map_get_first(m_list);
    while (dm != NULL) {
        pnet = dm->get_network();
		if (strncmp(pnet->m_net_info.id, net_id_to_find, strlen(net_id_to_find)) == 0) {
			found = true;
			break;
		}
		dm = (dm_easy_mesh_t *)hash_map_get_next(m_list, dm);
	}
	

	return (found == true) ? pnet:NULL;
}

dm_network_t *dm_easy_mesh_list_t::get_network(const char *key)
{
    dm_network_t *net = NULL;
    dm_easy_mesh_t *dm = NULL;
    bool found = false;

    dm = (dm_easy_mesh_t *)hash_map_get_first(m_list);
    while (dm != NULL) {
        net = dm->get_network();
	if (strncmp(net->m_net_info.id, key, strlen(key)) == 0) {
	    found = true;
	    break;
	}
	dm = (dm_easy_mesh_t *)hash_map_get_next(m_list, dm);
    }

    return (found == true) ? net:NULL;
}

void dm_easy_mesh_list_t::remove_network(const char *key)
{
}

void dm_easy_mesh_list_t::put_network(const char *key, const dm_network_t *net)
{
    dm_easy_mesh_t *dm = NULL;
    dm_network_t *pnet;
    mac_addr_str_t	mac_str;
    em_network_info_t *net_info;

    net_info = &((dm_network_t *)net)->m_net_info;
    dm_easy_mesh_t::macbytes_to_string(net_info->colocated_agent_id.mac, mac_str);


    /* try to find any data model with this network, if exists, the colocated dm must be there, otherwise create one */
    if ((dm = get_data_model(key, net_info->colocated_agent_id.mac)) == NULL) {
	dm = create_data_model(key, net_info->colocated_agent_id.mac, em_profile_type_3, true);
	pnet = dm->get_network();
	*pnet = *net;	
	strncpy(m_network_list[m_num_networks], key, strlen(key));
	m_num_networks++;
    } else {
        dm = (dm_easy_mesh_t *)hash_map_get_first(m_list);
        while (dm != NULL) {
            pnet = dm->get_network();
            if (strncmp(net->m_net_info.id, key, strlen(key)) == 0) {
	        *pnet = *net;	
            }
            dm = (dm_easy_mesh_t *)hash_map_get_next(m_list, dm);
        }
    }
}

dm_device_t *dm_easy_mesh_list_t::get_first_device()
{
    dm_easy_mesh_t *dm;

    dm = (dm_easy_mesh_t *)hash_map_get_first(m_list);
    if (dm == NULL) {
	return NULL;
    }

    return dm->get_device();
}

dm_device_t *dm_easy_mesh_list_t::get_next_device(dm_device_t *dev)
{   
	dm_easy_mesh_t *dm;
	bool return_next = false;


	dm = (dm_easy_mesh_t *)hash_map_get_first(m_list);
	while (dm != NULL) {
		if (return_next == true) {
			break;
		}
		if (dm->get_device() == dev) {
			return_next = true;
		}	
		dm = (dm_easy_mesh_t *)hash_map_get_next(m_list, dm);
	}

    return ((return_next == true) && (dm != NULL)) ? dm->get_device():NULL;
}

dm_device_t *dm_easy_mesh_list_t::get_device(const char *key)
{   
    dm_easy_mesh_t *dm;

    //printf("%s:%d: Getting device at key: %s\n", __func__, __LINE__, key);
	
    dm = (dm_easy_mesh_t *)hash_map_get(m_list, key);

    if (dm != NULL) {
        return dm->get_device();
    }

    return NULL;
}

void dm_easy_mesh_list_t::remove_device(const char *key)
{
    dm_easy_mesh_t *dm;
    dm = (dm_easy_mesh_t *)hash_map_remove(m_list, key);
	if (dm != NULL) {
		delete dm;
	}
}

void dm_easy_mesh_list_t::put_device(const char *key, const dm_device_t *dev)
{
    dm_easy_mesh_t *dm;
    dm_device_t *pdev;
    mac_address_t mac;

    //printf("%s:%d: Putting device at key: %s\n", __func__, __LINE__, key);

    if ((pdev = get_device(key)) == NULL) {
        //printf("%s:%d: device at key: %s not found\n", __func__, __LINE__, key);
	    dm = create_data_model(dev->m_device_info.net_id, dev->m_device_info.id.mac, dev->m_device_info.profile);
        pdev = dm->get_device();
    }
    *pdev = *dev;
    //printf("%s:%d: Putting device at key: %s\n", __func__, __LINE__, key);
}

dm_radio_t *dm_easy_mesh_list_t::get_first_radio()
{
    dm_radio_t *radio = NULL;
    dm_easy_mesh_t *dm;

	
	dm = (dm_easy_mesh_t *)hash_map_get_first(m_list);
	while (dm != NULL) {
        //printf("%s:%d: Number of radios:%d\n", __func__, __LINE__, dm->get_num_radios());
		if (dm->get_num_radios() > 0) {
			radio = dm->get_radio((unsigned int)0);
		}
		dm = (dm_easy_mesh_t *)hash_map_get_next(m_list, dm);
	}

    return radio;
}   

dm_radio_t *dm_easy_mesh_list_t::get_next_radio(dm_radio_t *radio)
{  
    dm_radio_t *pradio = NULL;
    dm_easy_mesh_t *dm;
	bool return_next = false;
	unsigned int i;

	
	dm = (dm_easy_mesh_t *)hash_map_get_first(m_list);
	while (dm != NULL) {
        if (return_next == true) {
            if (dm->get_num_radios()) {
                pradio = dm->get_radio(i = 0);
            } else {
				return_next = false;
			}

			break;
		}
		for (i = 0; i < dm->get_num_radios(); i++) {
			pradio = dm->get_radio(i);
			if (radio == pradio) {
				return_next = true;	
			}

			if (return_next && ((i + 1) < dm->get_num_radios())) {
				return dm->get_radio(i + 1);
		
			}
		}

		dm = (dm_easy_mesh_t *)hash_map_get_next(m_list, dm);
        
        if ((dm == NULL) && (return_next == true)) {
            return_next = false;
        }
	}

    return (return_next == true) ? pradio:NULL;
}

dm_radio_t *dm_easy_mesh_list_t::get_radio(const char *key)
{  
    dm_radio_t *radio = NULL;
    dm_easy_mesh_t *dm;
	unsigned int i;
	bool found = false;
	mac_address_t mac;

	dm_easy_mesh_t::string_to_macbytes((char *)key, mac);
	
	dm = (dm_easy_mesh_t *)hash_map_get_first(m_list);
	while (dm != NULL) {
		for (i = 0;  i < dm->get_num_radios(); i++) {
			radio = dm->get_radio(i);
			if (memcmp(radio->m_radio_info.id.mac, mac, sizeof(mac_address_t)) == 0) {
				found = true;
				break;
			}
		}

		if (found == true) {
			break;
		}
		dm = (dm_easy_mesh_t *)hash_map_get_next(m_list, dm);
	}

    return (found == true) ? radio:NULL;
}

void dm_easy_mesh_list_t::remove_radio(const char *key)
{

}

void dm_easy_mesh_list_t::put_radio(const char *key, const dm_radio_t *radio)
{
    dm_radio_t *pradio = NULL;
    dm_easy_mesh_t	*dm = NULL;
    mac_addr_str_t	radio_mac, dev_mac;
    em_t *em = NULL;

    //printf("%s:%d: Radio: %s\n", __func__, __LINE__, key);

    if ((pradio = get_radio(key)) == NULL) {
        dm = get_data_model(radio->m_radio_info.net_id, radio->m_radio_info.dev_id);
        dm_easy_mesh_t::macbytes_to_string((unsigned char *)radio->m_radio_info.dev_id, dev_mac);
		//printf("%s:%d: dm: %p net: %s device: %s\n", __func__, __LINE__, dm, radio->m_radio_info.net_id, dev_mac);
        if (dm == NULL) {
            return;
        }

        //printf("%s:%d: Current Number of Radios: %d\n", __func__, __LINE__, dm->get_num_radios());
        dm->set_num_radios(dm->get_num_radios() + 1);
        pradio = dm->get_radio(dm->get_num_radios() - 1);
    }
    *pradio = *radio;

    if ((em = m_mgr->create_node(&pradio->m_radio_info.id, (em_freq_band_t)pradio->m_radio_info.media_data.band, dm, false,
            em_profile_type_3, em_service_type_ctrl)) != NULL) {
        printf("%s:%d Node created successfully\n", __func__, __LINE__);
    }

    dm_easy_mesh_t::macbytes_to_string(pradio->m_radio_info.id.mac, radio_mac);
    dm_easy_mesh_t::macbytes_to_string(pradio->m_radio_info.dev_id, dev_mac);

}

dm_bss_t *dm_easy_mesh_list_t::get_first_bss()
{
    dm_bss_t *bss = NULL;
    dm_easy_mesh_t *dm;
    bool found = false;

    dm = (dm_easy_mesh_t *)hash_map_get_first(m_list);
    while (dm != NULL) {
        //printf("%s:%d: Here: Num BSS: %d\n", __func__, __LINE__, dm->get_num_bss());
        if (dm->get_num_bss() > 0) {
            bss = dm->get_bss((unsigned int)0);
			found = true;
			break;
        }
        dm = (dm_easy_mesh_t *)hash_map_get_next(m_list, dm);
    }
    return (found == true) ? bss:NULL;
    
}

dm_bss_t *dm_easy_mesh_list_t::get_next_bss(dm_bss_t *bss)
{ 
    dm_bss_t *pbss = NULL;
    dm_easy_mesh_t *dm;
    bool return_next = false;
    unsigned int i;

    dm = (dm_easy_mesh_t *)hash_map_get_first(m_list);
    while (dm != NULL) {
        if (return_next == true) {
            if (dm->get_num_bss()) {
                pbss = dm->get_bss(i = 0);
            } else {
                return_next = false;
            }
        
            break;
        } 
        for (i = 0; i < dm->get_num_bss(); i++) {
            pbss = dm->get_bss(i);
            if (bss == pbss) {
                return_next = true;
            }   
            
            if (return_next && ((i + 1) < dm->get_num_bss())) {
                return dm->get_bss(i + 1);
            }
        }

        dm = (dm_easy_mesh_t *)hash_map_get_next(m_list, dm);
        if ((dm == NULL) && (return_next == true)) {
            return_next = false;
        }
    }

    return (return_next == true) ? pbss:NULL;  
}

dm_bss_t *dm_easy_mesh_list_t::get_bss(const char *key)
{ 
    dm_bss_t *bss = NULL;
    dm_easy_mesh_t *dm;
    unsigned int i;
    bool found = false;
    mac_address_t mac;

    dm_easy_mesh_t::string_to_macbytes((char *)key, mac);

    dm = (dm_easy_mesh_t *)hash_map_get_first(m_list);
    while (dm != NULL) {
        for (i = 0;  i < dm->get_num_bss(); i++) {
            bss = dm->get_bss(i);
            if (memcmp(bss->m_bss_info.bssid.mac, mac, sizeof(mac_address_t)) == 0) {
                found = true;
                break;
            }
        }

        if (found == true) {
            break;
        }
        dm = (dm_easy_mesh_t *)hash_map_get_next(m_list, dm);
    }

    return (found == true) ? bss:NULL;   
}

void dm_easy_mesh_list_t::remove_bss(const char *key)
{
}

void dm_easy_mesh_list_t::put_bss(const char *key, const dm_bss_t *bss)
{
    dm_bss_t *pbss = NULL;
	dm_radio_t *radio;
    dm_easy_mesh_t  *dm = NULL;
    mac_addr_str_t  radio_mac, dev_mac;

    //printf("%s:%d: Assigning BSS to radio: %s\n", __func__, __LINE__, key);
    if ((pbss = get_bss(key)) == NULL) {
        dm_easy_mesh_t::macbytes_to_string((unsigned char *)bss->m_bss_info.ruid.mac, radio_mac);
        radio = get_radio(radio_mac);
        if (radio != NULL) {
            dm_easy_mesh_t::macbytes_to_string(radio->m_radio_info.dev_id, dev_mac);
            //printf("%s:%d: Finding dm for radio: %s Device: %s in network: %s\n", __func__, __LINE__, 
                    //radio_mac, dev_mac, radio->m_radio_info.net_id);
            dm = get_data_model(radio->m_radio_info.net_id, radio->m_radio_info.dev_id);
            if (dm == NULL) {
                //printf("%s:%d: Could not find dm for radio: %s Device: %s in network: %s\n", __func__, __LINE__, 
                    //radio_mac, dev_mac, radio->m_radio_info.net_id);
                return;
            }
        } else {
            //printf("%s:%d: Could not find radio: %s\n", __func__, __LINE__, radio_mac);
            return;
        }

        dm->set_num_bss(dm->get_num_bss() + 1);
        pbss = dm->get_bss(dm->get_num_bss() - 1);
    }
    *pbss = *bss;

}

dm_sta_t *dm_easy_mesh_list_t::get_first_sta()
{
    dm_sta_t *sta = NULL;
    dm_easy_mesh_t *dm;

    dm = (dm_easy_mesh_t *)hash_map_get_first(m_list);
    while (dm != NULL) {
        sta = (dm_sta_t *)hash_map_get_first(dm->m_sta_map);
        if (sta != NULL) {
            return sta;
        }
        dm = (dm_easy_mesh_t *)hash_map_get_next(m_list, dm);
    }

    return sta;
}

dm_sta_t *dm_easy_mesh_list_t::get_next_sta(dm_sta_t *psta)
{
    dm_sta_t *sta = NULL;
    dm_easy_mesh_t *dm;
    bool return_next = false;

    dm = (dm_easy_mesh_t *)hash_map_get_first(m_list);
    while (dm != NULL) {
        sta = (dm_sta_t *)hash_map_get_first(dm->m_sta_map);
        while (sta != NULL) {
            if (return_next == true) {
                return sta;
            }
            if (sta == psta) {
                return_next = true;
            }
            sta = (dm_sta_t *)hash_map_get_next(dm->m_sta_map, sta);
        }
        dm = (dm_easy_mesh_t *)hash_map_get_next(m_list, dm);
    }

    return NULL;
}   
    
dm_sta_t *dm_easy_mesh_list_t::get_sta(const char *key)
{   
    dm_sta_t *sta;
    dm_easy_mesh_t *dm;
    mac_address_t sta_mac, ruid;
    mac_addr_str_t	sta_mac_str, radio_mac_str, bssid_str;
    bssid_t	bssid;
    bool found = false;
    unsigned int i;

    dm_sta_t::parse_sta_bss_radio_from_key(key, sta_mac, bssid, ruid);

    dm = (dm_easy_mesh_t *)hash_map_get_first(m_list);
    while (dm != NULL) {
        for (i = 0; i < dm->m_num_radios; i++) {
            if (memcmp(dm->m_radio[i].m_radio_info.id.mac, ruid, sizeof(mac_address_t)) == 0) {
                found = true;
                break;
            }
        }

        if (found == true) {
            break;
        }
        dm = (dm_easy_mesh_t *)hash_map_get_next(m_list, dm);
    }

    if (found == false) {
        return NULL;
    }

    dm_easy_mesh_t::macbytes_to_string(sta_mac, sta_mac_str);
    dm_easy_mesh_t::macbytes_to_string(bssid, bssid_str);
    dm_easy_mesh_t::macbytes_to_string(ruid, radio_mac_str);

    if ((sta = (dm_sta_t *)hash_map_get(dm->m_sta_map, key)) != NULL) {
        //printf("%s:%d: STA:%s found on BSS:%s of radio:%s\n", __func__, __LINE__,
        //sta_mac_str, bssid_str, radio_mac_str);
        return sta;
    }

    return NULL;
}

void dm_easy_mesh_list_t::remove_sta(const char *key)
{

}

void dm_easy_mesh_list_t::put_sta(const char *key, const dm_sta_t *sta)
{
    dm_sta_t *psta;
    dm_easy_mesh_t *dm;
    mac_address_t sta_mac, ruid;
    mac_addr_str_t	sta_mac_str, radio_mac_str, bssid_str;
    bssid_t	bssid;
    bool found = false;
    unsigned int i;

    dm_sta_t::parse_sta_bss_radio_from_key(key, sta_mac, bssid, ruid);
    dm_easy_mesh_t::macbytes_to_string(sta_mac, sta_mac_str);
    dm_easy_mesh_t::macbytes_to_string(bssid, bssid_str);
    dm_easy_mesh_t::macbytes_to_string(ruid, radio_mac_str);

    dm = (dm_easy_mesh_t *)hash_map_get_first(m_list);
    while (dm != NULL) {
        for (i = 0; i < dm->m_num_radios; i++) {
            if (memcmp(dm->m_radio[i].m_radio_info.id.mac, ruid, sizeof(mac_address_t)) == 0) {
                found = true;
                break;
            }
        }

        if (found == true) {
            break;
        }
        dm = (dm_easy_mesh_t *)hash_map_get_next(m_list, dm);
    }

    if (found == false) {
        printf("%s:%d: Could not find dm with radio:%s\n", __func__, __LINE__, radio_mac_str);
        return;
    }

    if ((psta = (dm_sta_t *)hash_map_get(dm->m_sta_map, key)) != NULL) {
        //printf("%s:%d: STA:%s already present on BSS:%s of radio:%s\n", __func__, __LINE__,
        //		sta_mac_str, bssid_str, radio_mac_str);
        memcpy(&psta->m_sta_info, &sta->m_sta_info, sizeof(em_sta_info_t));
        return;
    }

    psta = new dm_sta_t(*sta);
    hash_map_put(dm->m_sta_map, strdup(key), psta);

    //printf("%s:%d: STA:%s added to BSS:%s of radio:%s\n", __func__, __LINE__,
            //sta_mac_str, bssid_str, radio_mac_str);
}

dm_network_ssid_t *dm_easy_mesh_list_t::get_first_network_ssid()
{
    dm_network_ssid_t *net_ssid = NULL;
    dm_easy_mesh_t *dm;

	
	dm = (dm_easy_mesh_t *)hash_map_get_first(m_list);
	while (dm != NULL) {
		if (dm->get_num_network_ssid() > 0) {
			net_ssid = dm->get_network_ssid((unsigned int)0);
		}
		dm = (dm_easy_mesh_t *)hash_map_get_next(m_list, dm);
	}

    return net_ssid;
}

dm_network_ssid_t *dm_easy_mesh_list_t::get_next_network_ssid(dm_network_ssid_t *net_ssid)
{
    dm_network_ssid_t *pnet_ssid = NULL;
    dm_easy_mesh_t *dm;
    bool return_next = false;
    unsigned int i;

    dm = (dm_easy_mesh_t *)hash_map_get_first(m_list);
    while (dm != NULL) {
        if (return_next == true) {
            if (dm->get_num_network_ssid()) {
				pnet_ssid = dm->get_network_ssid(i = 0);
			} else {
				return_next = false;
			}

            break;
        }
            
        for (i = 0; i < EM_MAX_NET_SSIDS; i++) {
            pnet_ssid = dm->get_network_ssid(i);
            if (net_ssid == pnet_ssid) {
                return_next = true;
            }
            if (return_next && ((i + 1) < EM_MAX_NET_SSIDS)) {
                pnet_ssid = dm->get_network_ssid(i + 1);
                return dm->get_network_ssid(i + 1);
               
            }
        }

        dm = (dm_easy_mesh_t *)hash_map_get_next(m_list, dm);
        if ((dm == NULL) && (return_next == true)) {
            return_next = false;
        }
    }

    return (return_next == true) ? pnet_ssid:NULL;
}

dm_network_ssid_t *dm_easy_mesh_list_t::get_network_ssid(const char *key)
{
    dm_network_ssid_t *net_ssid = NULL;
    dm_easy_mesh_t *dm;
    unsigned int i;
    bool found = false;
    mac_address_t mac;

    dm = (dm_easy_mesh_t *)hash_map_get_first(m_list);
    while (dm != NULL) {
        for (i = 0;  i < dm->get_num_network_ssid(); i++) {
            net_ssid = dm->get_network_ssid(i);
            if (strncmp(net_ssid->m_network_ssid_info.id, key, strlen(key)) == 0) {
                found = true;
                break;
            }
        }

        if (found == true) {
            break;
        }
        dm = (dm_easy_mesh_t *)hash_map_get_next(m_list, dm);
    }
    return (found == true) ? net_ssid:NULL;
}

void dm_easy_mesh_list_t::debug_probe()
{
    dm_easy_mesh_t *dm;
    mac_addr_str_t  mac_str;

    dm = (dm_easy_mesh_t *)hash_map_get_first(m_list);
    while (dm != NULL) {
        dm_easy_mesh_t::macbytes_to_string(dm->get_agent_al_interface_mac(), mac_str);
        //printf("%s:%d: Dst AL MAC: %s\n", __func__, __LINE__, mac_str);
        //printf("%s:%d: Number of radios:%d Number of BSS: %d\n", __func__, __LINE__, dm->get_num_radios(), dm->get_num_bss());
        dm = (dm_easy_mesh_t *)hash_map_get_next(m_list, dm);
    }
}

void dm_easy_mesh_list_t::remove_network_ssid(const char *key)
{
    dm_network_ssid_t *net_ssid = NULL, *tgt;
    dm_easy_mesh_t *dm;
    unsigned int i;
    bool found = false;

    //printf("%s:%d: Remove: %s\n", __func__, __LINE__, key);
    dm = (dm_easy_mesh_t *)hash_map_get_first(m_list);
    while (dm != NULL) {
        for (i = 0;  i < EM_MAX_NET_SSIDS; i++) {
            net_ssid = dm->get_network_ssid(i);
            if (strncmp(net_ssid->m_network_ssid_info.id, key, strlen(key)) == 0) {
                found = true;
                break;
            }
        }

        if (found == true) {
            //printf("%s:%d: Removing at index: %d\n", __func__, __LINE__, i);
            tgt = dm->get_network_ssid(i);
            memset((unsigned char *)&tgt->m_network_ssid_info, 0, sizeof(em_network_ssid_info_t)); 
            dm->set_num_network_ssid(dm->get_num_network_ssid() - 1);
        }

        dm = (dm_easy_mesh_t *)hash_map_get_next(m_list, dm);
    }
}

void dm_easy_mesh_list_t::put_network_ssid(const char *key, const dm_network_ssid_t *net_ssid)
{
    dm_network_ssid_t *pnet_ssid = NULL;
    em_string_t net_id;
    em_long_string_t key_copy;
    dm_easy_mesh_t *dm;
    dm_network_t *net;
    char *ptr = NULL;
    unsigned int i;
    bool found = false;

    strncpy(key_copy, key, strlen(key) + 1);

    if ((ptr = strchr(key_copy, '@')) == NULL) {
        //printf("%s:%d: Corrupted id for network ssid\n", __func__, __LINE__);
        return;
    }
    strncpy(net_id, ptr + 1, strlen(ptr));
    *ptr = 0;


    dm = (dm_easy_mesh_t *)hash_map_get_first(m_list);
    while (dm != NULL) {
        net = dm->get_network();
        if (strncmp(net->m_net_info.id, net_id, strlen(net_id)) != 0) {
            dm = (dm_easy_mesh_t *)hash_map_get_next(m_list, dm);
            continue;
        }
        for (i = 0;  i < dm->get_num_network_ssid(); i++) {
            pnet_ssid = dm->get_network_ssid(i);
            if (strncmp(pnet_ssid->m_network_ssid_info.id, key, strlen(key)) == 0) {
                found = true;
                break;
            }
        }

        if (found == true) {
            found = false;
            *pnet_ssid = *net_ssid;
        } else {
            pnet_ssid = dm->get_network_ssid(dm->get_num_network_ssid());
            *pnet_ssid = *net_ssid;
            dm->set_num_network_ssid(dm->get_num_network_ssid() + 1);
        }
        dm = (dm_easy_mesh_t *)hash_map_get_next(m_list, dm);
    }
}

dm_op_class_t *dm_easy_mesh_list_t::get_first_op_class()
{
    dm_op_class_t *op_class = NULL;
    dm_easy_mesh_t *dm;
	bool found = false;
    
    dm = (dm_easy_mesh_t *)hash_map_get_first(m_list);
    while (dm != NULL) {
        if (dm->get_num_op_class() > 0) {
            op_class = dm->get_op_class((unsigned int)0);
			if (op_class->m_op_class_info.id.index == 0) {
				found = true;
				break;
			}
        }
        dm = (dm_easy_mesh_t *)hash_map_get_next(m_list, dm);
    }

    return (found == true) ? op_class:NULL;
}

dm_op_class_t *dm_easy_mesh_list_t::get_next_op_class(dm_op_class_t *op_class)
{
    dm_op_class_t *pop_class = NULL;
    dm_easy_mesh_t *dm;
    bool return_next = false;
    unsigned int i;
        
    dm = (dm_easy_mesh_t *)hash_map_get_first(m_list);
    while (dm != NULL) {
        if (return_next == true) {
            if (dm->get_num_op_class()) {
                pop_class = dm->get_op_class(i = 0);
            } else {
                return_next = false;
            }

            break;
        }
        for (i = 0; i < dm->get_num_op_class(); i++) {
            pop_class = dm->get_op_class(i);
            if (pop_class == op_class) {
                return_next = true;
            }
    
            if (return_next && ((i + 1) < dm->get_num_op_class())) {
                return dm->get_op_class(i + 1);
            }
        }

        dm = (dm_easy_mesh_t *)hash_map_get_next(m_list, dm);
        if ((dm == NULL) && (return_next == true)) {
            return_next = false;
        }
    }

    return (return_next == true) ? pop_class:NULL;

}

dm_op_class_t *dm_easy_mesh_list_t::get_op_class(const char *key)
{
	em_op_class_id_t id;
    dm_easy_mesh_t *dm;
	dm_radio_t *radio;
	bool found_dm = false;
	unsigned int i;
    dm_op_class_t *pop_class;
	
    dm_op_class_t::parse_op_class_id_from_key(key, &id);
	
    dm = (dm_easy_mesh_t *)hash_map_get_first(m_list);
    while (dm != NULL) {
        if (id.type <= em_op_class_type_capability) {
		    for (i = 0; i < dm->get_num_radios(); i++) {
			    radio = dm->get_radio(i);
			    if (memcmp(radio->m_radio_info.id.mac, id.ruid, sizeof(mac_address_t)) == 0) {
				    found_dm = true;
			    	break;
			    }
		    }
        } else {
			if (memcmp(dm->m_device.m_device_info.id.mac, id.ruid, sizeof(mac_address_t)) == 0) {
            	found_dm = true;
           	}
		}	

		if (found_dm == true) {
			break;
		}
        dm = (dm_easy_mesh_t *)hash_map_get_next(m_list, dm);
	}

	if (found_dm == false) {
		return NULL;
	}

    // now check if the op class is already there
	for (i = 0; i < dm->get_num_op_class(); i++) {
		pop_class = &dm->m_op_class[i];
		if (memcmp(&pop_class->m_op_class_info.id, &id, sizeof(em_op_class_id_t)) == 0) {
			return pop_class;
		}	
	}

	return NULL;
}

void dm_easy_mesh_list_t::remove_op_class(const char *key)
{

}

void dm_easy_mesh_list_t::put_op_class(const char *key, const dm_op_class_t *op_class)
{
	em_op_class_id_t id;
	mac_addr_str_t mac_str;
	dm_easy_mesh_t *dm;
	bool found_dm = false;
	unsigned int i;
	dm_op_class_t	*pop_class;
	dm_radio_t *radio;

	dm_easy_mesh_t::macbytes_to_string((unsigned char *)op_class->m_op_class_info.id.ruid, mac_str);
	printf("%s:%d: key: %s, ruid: %s, type: %d, index: %d\n", __func__, __LINE__, 
		key, mac_str, op_class->m_op_class_info.id.type, op_class->m_op_class_info.id.index);
	dm_op_class_t::parse_op_class_id_from_key(key, &id);

	// find the dm that has this radio
    dm = (dm_easy_mesh_t *)hash_map_get_first(m_list);
    while (dm != NULL) {
        if (id.type <= em_op_class_type_capability) {
            for (i = 0; i < dm->get_num_radios(); i++) {
                radio = dm->get_radio(i);
                dm_easy_mesh_t::macbytes_to_string(radio->m_radio_info.id.mac, mac_str);
                //printf("%s:%d: Comparing with radio: %s\n", __func__, __LINE__, mac_str);
                if (memcmp(radio->m_radio_info.id.mac, id.ruid, sizeof(mac_address_t)) == 0) {
                    found_dm = true;
                    break;
                }
            }
        } else {
            if (memcmp(dm->m_device.m_device_info.id.mac, id.ruid, sizeof(mac_address_t)) == 0) {
                found_dm = true;
            }
        }
        if (found_dm == true) {
            break;
        } else {
            if ((memcmp(dm->m_device.m_device_info.id.mac, id.ruid, sizeof(mac_address_t)) && (id.type >= em_op_class_type_cac_available)) == 0) {
                found_dm = true;
                break;
            }
        }
        dm = (dm_easy_mesh_t *)hash_map_get_next(m_list, dm);
    }

    assert(found_dm == true);

    // now check if the op class is already there
    for (i = 0; i < dm->get_num_op_class(); i++) {
        pop_class = &dm->m_op_class[i];
        if (memcmp(&pop_class->m_op_class_info.id, &op_class->m_op_class_info.id, sizeof(em_op_class_id_t)) == 0) {
            if (pop_class->m_op_class_info.op_class == op_class->m_op_class_info.op_class) {
                memcpy(&pop_class->m_op_class_info, &op_class->m_op_class_info, sizeof(em_op_class_info_t));
                return;
            }
        }
    }

    pop_class = &dm->m_op_class[dm->get_num_op_class()];
    memcpy(&pop_class->m_op_class_info, &op_class->m_op_class_info, sizeof(em_op_class_info_t));
    dm->set_num_op_class(dm->get_num_op_class() + 1);
}

void dm_easy_mesh_list_t::delete_all_data_models()
{
	dm_easy_mesh_t *dm = NULL, *tmp;
	dm_device_t *dev;
	mac_addr_str_t mac_str;
	em_long_string_t	key;
	
	dm = (dm_easy_mesh_t *)hash_map_get_first(m_list);
    while (dm != NULL) {
		tmp = dm;
        dm = (dm_easy_mesh_t *)hash_map_get_next(m_list, dm); 

        if (tmp->get_colocated() == true) {
            //printf("%s:%d: Skipping delete as colocated\n", __func__, __LINE__);
            continue;
        }
		dev = tmp->get_device();	
		dm_easy_mesh_t::macbytes_to_string(dev->m_device_info.id.mac, mac_str);
		snprintf(key, sizeof(em_short_string_t), "%s@%s", dev->m_device_info.net_id, mac_str);

		hash_map_remove(m_list, key);
		delete tmp;
    }   

}

void dm_easy_mesh_list_t::delete_data_model(const char *net_id, const unsigned char *al_mac)
{
    dm_easy_mesh_t *dm = NULL;
    mac_addr_str_t mac_str;
    em_long_string_t	key;
	
    dm_easy_mesh_t::macbytes_to_string((unsigned char *)al_mac, mac_str);
    snprintf(key, sizeof(em_short_string_t), "%s@%s", net_id, mac_str);
    //printf("%s:%d: Putting data model at key: %s\n", __func__, __LINE__, key);

    dm = (dm_easy_mesh_t *)hash_map_remove(m_list, key);

    //printf("%s:%d: deleteing data model at key: %s, dm:%p, colocated:%d\n", __func__, __LINE__, key, dm, dm->get_colocated());
    dm->deinit();
    delete dm;
}

dm_easy_mesh_t *dm_easy_mesh_list_t::create_data_model(const char *net_id, const unsigned char *al_mac, em_profile_type_t profile, bool colocated)
{
    dm_easy_mesh_t *dm = NULL, *ref_dm;
    mac_addr_str_t mac_str;
    em_short_string_t	key;
    dm_network_t *net, *pnet;
    dm_device_t *dev;
    dm_network_ssid_t *net_ssid, *pnet_ssid;
    unsigned int i;
	
    dm_easy_mesh_t::macbytes_to_string((unsigned char *)al_mac, mac_str);
    snprintf(key, sizeof(em_short_string_t), "%s@%s", net_id, mac_str);

    dm = new dm_easy_mesh_t();
    dm->init();
    //printf("%s:%d: Created data model for net_id: %s mac: %s, coloc:%d\n", __func__, __LINE__, net_id, mac_str, colocated);
    dm->set_colocated(colocated);

    dev = dm->get_device();
    memcpy(dev->m_device_info.id.mac, al_mac, sizeof(mac_address_t));
    strncpy(dev->m_device_info.net_id, net_id, strlen(net_id) + 1);
    dev->m_device_info.profile = profile;

    // is this the first data model
    if ((net = get_network(net_id)) != NULL) {
        pnet = dm->get_network();
        *pnet = *net;

        ref_dm = get_data_model(net->m_net_info.id, net->m_net_info.colocated_agent_id.mac);
        assert(ref_dm != NULL);
        dm->set_num_network_ssid(ref_dm->get_num_network_ssid());
        //printf("%s:%d: Number of network ssid in reference data model: %d\n", __func__, __LINE__, ref_dm->get_num_network_ssid());
        for (i = 0; i < ref_dm->get_num_network_ssid(); i++) {
            pnet_ssid = dm->get_network_ssid(i);
            net_ssid = ref_dm->get_network_ssid(i);
            *pnet_ssid = *net_ssid;
        }
    }
    //printf("%s:%d: Putting data model at key: %s\n", __func__, __LINE__, key);
    hash_map_put(m_list, strdup(key), dm);	

    return dm;
}

dm_easy_mesh_t *dm_easy_mesh_list_t::get_data_model(const char *net_id, const unsigned char *al_mac)
{
    dm_easy_mesh_t *dm = NULL;
    mac_addr_str_t mac_str;
    em_short_string_t	key;

    dm_easy_mesh_t::macbytes_to_string((unsigned char *)al_mac, mac_str);
    snprintf(key, sizeof(em_short_string_t), "%s@%s", net_id, mac_str);
    //printf("%s:%d: Retrieve data model at key: %s\n", __func__, __LINE__, key);
    dm = (dm_easy_mesh_t *)hash_map_get(m_list, key);

    return dm;
}

void dm_easy_mesh_list_t::init(em_mgr_t *mgr)
{
    m_list = hash_map_create();	
    m_num_networks = 0;
    m_mgr = mgr;
}

dm_easy_mesh_list_t::dm_easy_mesh_list_t()
{

}

dm_easy_mesh_list_t::~dm_easy_mesh_list_t()
{

}
