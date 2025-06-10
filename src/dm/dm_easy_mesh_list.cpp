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
    dm_network_t *net = NULL;
    dm_easy_mesh_t *dm;
    bool found = false;

    if (m_num_networks == 0) {
        return NULL;
    }

    dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
    while (dm != NULL) {
        net = dm->get_network();
	if (strncmp(net->m_net_info.id, m_network_list[0], strlen(m_network_list[0])) == 0) {
	    found = true;
	    break;
	}
	dm = static_cast<dm_easy_mesh_t *> (hash_map_get_next(m_list, dm));
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

    dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
    while (dm != NULL) {
        pnet = dm->get_network();
		if (strncmp(pnet->m_net_info.id, net_id_to_find, strlen(net_id_to_find)) == 0) {
			found = true;
			break;
		}
		dm = static_cast<dm_easy_mesh_t *> (hash_map_get_next(m_list, dm));
	}
	

	return (found == true) ? pnet:NULL;
}

dm_network_t *dm_easy_mesh_list_t::get_network(const char *key)
{
    dm_network_t *net = NULL;
    dm_easy_mesh_t *dm = NULL;
    bool found = false;

    dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
    while (dm != NULL) {
        net = dm->get_network();
		if (strncmp(net->m_net_info.id, key, strlen(key)) == 0) {
	    	found = true;
	    	break;
		}
		dm = static_cast<dm_easy_mesh_t *> (hash_map_get_next(m_list, dm));
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

    net_info = &(const_cast<dm_network_t *> (net))->m_net_info;
    dm_easy_mesh_t::macbytes_to_string(net_info->colocated_agent_id.mac, mac_str);
			
    /* try to find any data model with this network, if exists, the colocated dm must be there, otherwise create one */
    if ((dm = get_data_model(key, net_info->colocated_agent_id.mac)) == NULL) {
		dm = create_data_model(key, &net_info->colocated_agent_id, em_profile_type_3, true);
		pnet = dm->get_network();
		*pnet = *net;	
		strncpy(m_network_list[m_num_networks], key, strlen(key));
		m_num_networks++;
    } else {
        dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
        while (dm != NULL) {
            pnet = dm->get_network();
            if (strncmp(net->m_net_info.id, key, strlen(key)) == 0) {
	        	*pnet = *net;	
            }
            dm = static_cast<dm_easy_mesh_t *> (hash_map_get_next(m_list, dm));
        }
    }
}

dm_device_t *dm_easy_mesh_list_t::get_first_device()
{
    dm_easy_mesh_t *dm;

    dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
    if (dm == NULL) {
		return NULL;
    }

    return dm->get_device();
}

dm_device_t *dm_easy_mesh_list_t::get_next_device(dm_device_t *dev)
{   
	dm_easy_mesh_t *dm;
	bool return_next = false;


	dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
	while (dm != NULL) {
		if (return_next == true) {
			break;
		}
		if (dm->get_device() == dev) {
			return_next = true;
		}	
		dm = static_cast<dm_easy_mesh_t *> (hash_map_get_next(m_list, dm));
	}

    return ((return_next == true) && (dm != NULL)) ? dm->get_device():NULL;
}

dm_device_t *dm_easy_mesh_list_t::get_device(const char *key)
{   
    dm_easy_mesh_t *dm;
	em_device_id_t	id;

	dm_device_t::parse_device_id_from_key(key, &id);

    //printf("%s:%d: Getting device at key: %s\n", __func__, __LINE__, key);
	
    if ((dm = get_data_model(id.net_id, id.dev_mac)) != NULL) {
        return dm->get_device();
    }

    return NULL;
}

void dm_easy_mesh_list_t::remove_device(const char *key)
{
    dm_easy_mesh_t *dm;
    dm = static_cast<dm_easy_mesh_t *> (hash_map_remove(m_list, key));
	if (dm != NULL) {
		delete dm;
	}
}

void dm_easy_mesh_list_t::put_device(const char *key, const dm_device_t *dev)
{
    dm_easy_mesh_t *dm;
    dm_device_t *pdev;
    mac_addr_str_t mac_str;
	em_device_id_t	id;

	dm_device_t::parse_device_id_from_key(key, &id);
	dm_easy_mesh_t::macbytes_to_string(id.dev_mac, mac_str);

    if ((pdev = get_device(key)) == NULL) {
        //printf("%s:%d: device at key: %s not found\n", __func__, __LINE__, key);
	    dm = create_data_model(dev->m_device_info.id.net_id, &dev->m_device_info.intf, dev->m_device_info.profile);
        pdev = dm->get_device();
    }
    *pdev = *dev;
	
	if ((dm = get_data_model(id.net_id, id.dev_mac)) == NULL) {
		printf("%s:%d: Could not find data model for network: %s, mac: %s\n", __func__, __LINE__, id.net_id, mac_str);
	} else {
		printf("%s:%d: Device:%s inserted in network:%s\n", __func__, __LINE__, mac_str, id.net_id);
		dm->m_network.m_net_info.num_of_devices++;
	}
}

dm_radio_t *dm_easy_mesh_list_t::get_first_radio()
{
    dm_radio_t *radio = NULL;
    dm_easy_mesh_t *dm;

    dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
    while (dm != NULL) {
        //printf("%s:%d: Number of radios:%d\n", __func__, __LINE__, dm->get_num_radios());
        if (dm->get_num_radios() > 0) {
            radio = dm->get_radio(static_cast<unsigned int> (0));
            break;
        }
        dm = static_cast<dm_easy_mesh_t *> (hash_map_get_next(m_list, dm));
    }

    return radio;
}

dm_radio_t *dm_easy_mesh_list_t::get_next_radio(dm_radio_t *radio)
{  
    dm_radio_t *pradio = NULL;
    dm_easy_mesh_t *dm;
	bool return_next = false;
	unsigned int i;

	
	dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
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

		dm = static_cast<dm_easy_mesh_t *> (hash_map_get_next(m_list, dm));
        
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

	dm_easy_mesh_t::string_to_macbytes(const_cast<char *> (key), mac);
	
	dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
	while (dm != NULL) {
		for (i = 0;  i < dm->get_num_radios(); i++) {
			radio = dm->get_radio(i);
			if (memcmp(radio->m_radio_info.intf.mac, mac, sizeof(mac_address_t)) == 0) {
				found = true;
				break;
			}
		}

		if (found == true) {
			break;
		}
		dm = static_cast<dm_easy_mesh_t *> (hash_map_get_next(m_list, dm));
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
        dm = get_data_model(radio->m_radio_info.id.net_id, radio->m_radio_info.id.dev_mac);
        dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (radio->m_radio_info.id.dev_mac), dev_mac);
		//printf("%s:%d: dm: %p net: %s device: %s\n", __func__, __LINE__, dm, radio->m_radio_info.net_id, dev_mac);
        if (dm == NULL) {
            return;
        }

        //printf("%s:%d: Current Number of Radios: %d\n", __func__, __LINE__, dm->get_num_radios());
        dm->set_num_radios(dm->get_num_radios() + 1);
        pradio = dm->get_radio(dm->get_num_radios() - 1);
    }
    *pradio = *radio;

    if ((em = m_mgr->create_node(&pradio->m_radio_info.intf, static_cast<em_freq_band_t> (pradio->m_radio_info.media_data.band), dm, false,
            em_profile_type_3, em_service_type_ctrl)) != NULL) {
        printf("%s:%d Node created successfully\n", __func__, __LINE__);
    }

    dm_easy_mesh_t::macbytes_to_string(pradio->m_radio_info.intf.mac, radio_mac);
    dm_easy_mesh_t::macbytes_to_string(pradio->m_radio_info.id.dev_mac, dev_mac);

}

dm_radio_t *dm_easy_mesh_list_t::get_first_radio(const char *net_id, mac_address_t al_mac)
{
	dm_easy_mesh_t *dm;

	dm = get_data_model(net_id, al_mac);
	if ((dm != NULL) && (dm->get_num_radios() > 0)) {
		return &dm->m_radio[0];
	}

	return NULL;
}

dm_radio_t *dm_easy_mesh_list_t::get_next_radio(const char *net_id, mac_address_t al_mac, dm_radio_t *radio)
{
	dm_easy_mesh_t *dm;
	unsigned int i;
	bool found_match = false;

	dm = get_data_model(net_id, al_mac);
	if ((dm == NULL) || (dm->get_num_radios() == 0)) {
		return NULL;
	}

	for (i = 0; i < dm->get_num_radios(); i++) {
		if (&dm->m_radio[i] == radio) {
			found_match = true;
			break;
		}
	}

	if ((found_match == true) && (i < (dm->get_num_radios() - 1))) {
		return &dm->m_radio[i + 1];
	}

	return NULL;

}

dm_bss_t *dm_easy_mesh_list_t::get_first_bss()
{
    dm_bss_t *bss = NULL;
    dm_easy_mesh_t *dm;
    bool found = false;

    dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
    while (dm != NULL) {
        if (dm->get_num_bss() > 0) {
            bss = dm->get_bss(static_cast<unsigned int> (0));
			found = true;
			break;
        }
        dm = static_cast<dm_easy_mesh_t *> (hash_map_get_next(m_list, dm));
    }
    return (found == true) ? bss:NULL;
    
}

dm_bss_t *dm_easy_mesh_list_t::get_next_bss(dm_bss_t *bss)
{ 
    dm_bss_t *pbss = NULL;
    dm_easy_mesh_t *dm;
    bool return_next = false;
    unsigned int i;

    dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
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

        dm = static_cast<dm_easy_mesh_t *> (hash_map_get_next(m_list, dm));
        if ((dm == NULL) && (return_next == true)) {
            return_next = false;
        }
    }

    return (return_next == true) ? pbss:NULL;  
}

dm_bss_t *dm_easy_mesh_list_t::get_bss(const char *key)
{
	em_bss_id_t id;
	mac_addr_str_t dev_mac_str;
	dm_easy_mesh_t *dm;

	dm_bss_t::parse_bss_id_from_key(key, &id);
	dm_easy_mesh_t::macbytes_to_string(id.dev_mac, dev_mac_str);	
	
	if ((dm = get_data_model(id.net_id, id.dev_mac)) == NULL) {
		printf("%s:%d: Could not find data model for Network: %s and dev: %s\n", __func__, __LINE__, id.net_id, dev_mac_str);
		return NULL;
	}

	return dm->find_matching_bss(&id);
}

void dm_easy_mesh_list_t::remove_bss(const char *key)
{
	em_bss_id_t id;
	dm_easy_mesh_t *dm;
	unsigned int i;
	mac_addr_str_t  radio_mac_str, dev_mac_str;
	
	dm_bss_t::parse_bss_id_from_key(key, &id);
	dm_easy_mesh_t::macbytes_to_string(id.dev_mac, dev_mac_str);	
	dm_easy_mesh_t::macbytes_to_string(id.ruid, radio_mac_str);	

	if ((dm = get_data_model(id.net_id, id.dev_mac)) == NULL) {
		printf("%s:%d: Could not find data model for Network: %s and dev: %s\n", __func__, __LINE__, id.net_id, dev_mac_str);
		return;
	}

	for (i = 0; i < dm->m_num_bss; i++) {
		if (memcmp(dm->m_bss[i].m_bss_info.bssid.mac, id.bssid, sizeof(bssid_t)) == 0) {
			return dm->remove_bss_by_index(i);
		}
	}
}

void dm_easy_mesh_list_t::put_bss(const char *key, const dm_bss_t *bss)
{
	em_bss_id_t id;
	mac_addr_str_t	dev_mac_str, radio_mac_str, bssid_str;
	dm_easy_mesh_t *dm;
	dm_bss_t *pbss;

	dm_bss_t::parse_bss_id_from_key(key, &id);
	dm_easy_mesh_t::macbytes_to_string(id.dev_mac, dev_mac_str);
	dm_easy_mesh_t::macbytes_to_string(id.ruid, radio_mac_str);
	dm_easy_mesh_t::macbytes_to_string(id.bssid, bssid_str);

	if ((dm = get_data_model(id.net_id, id.dev_mac)) == NULL) {
		printf("%s:%d: Could not find data model for Network: %s and dev: %s\n", __func__, __LINE__, id.net_id, dev_mac_str);
		return;
	}

	if ((pbss = dm->find_matching_bss(&id)) == NULL) {
		pbss = &dm->m_bss[dm->m_num_bss];
		dm->m_num_bss++;
	}	

	*pbss = *bss;
}

dm_sta_t *dm_easy_mesh_list_t::get_first_sta()
{
    dm_sta_t *sta = NULL;
    dm_easy_mesh_t *dm;

    dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
    while (dm != NULL) {
        sta = static_cast<dm_sta_t *> (hash_map_get_first(dm->m_sta_map));
        if (sta != NULL) {
            return sta;
        }
        dm = static_cast<dm_easy_mesh_t *> (hash_map_get_next(m_list, dm));
    }

    return sta;
}

dm_sta_t *dm_easy_mesh_list_t::get_next_sta(dm_sta_t *psta)
{
    dm_sta_t *sta = NULL;
    dm_easy_mesh_t *dm;
    bool return_next = false;

    dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
    while (dm != NULL) {
        sta = static_cast<dm_sta_t *> (hash_map_get_first(dm->m_sta_map));
        while (sta != NULL) {
            if (return_next == true) {
                return sta;
            }
            if (sta == psta) {
                return_next = true;
            }
            sta = static_cast<dm_sta_t *> (hash_map_get_next(dm->m_sta_map, sta));
        }
        dm = static_cast<dm_easy_mesh_t *> (hash_map_get_next(m_list, dm));
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

    dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
    while (dm != NULL) {
        for (i = 0; i < dm->m_num_radios; i++) {
            if (memcmp(dm->m_radio[i].m_radio_info.intf.mac, ruid, sizeof(mac_address_t)) == 0) {
                found = true;
                break;
            }
        }

        if (found == true) {
            break;
        }
        dm = static_cast<dm_easy_mesh_t *> (hash_map_get_next(m_list, dm));
    }

    if (found == false) {
        return NULL;
    }

    dm_easy_mesh_t::macbytes_to_string(sta_mac, sta_mac_str);
    dm_easy_mesh_t::macbytes_to_string(bssid, bssid_str);
    dm_easy_mesh_t::macbytes_to_string(ruid, radio_mac_str);

    if ((sta = static_cast<dm_sta_t *> (hash_map_get(dm->m_sta_map, key))) != NULL) {
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

    dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
    while (dm != NULL) {
        for (i = 0; i < dm->m_num_radios; i++) {
            if (memcmp(dm->m_radio[i].m_radio_info.intf.mac, ruid, sizeof(mac_address_t)) == 0) {
                found = true;
                break;
            }
        }

        if (found == true) {
            break;
        }
        dm = static_cast<dm_easy_mesh_t *> (hash_map_get_next(m_list, dm));
    }

    if (found == false) {
        printf("%s:%d: Could not find dm with radio:%s\n", __func__, __LINE__, radio_mac_str);
        return;
    }

    if ((psta = static_cast<dm_sta_t *> (hash_map_get(dm->m_sta_map, key))) != NULL) {
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

	
	dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
	while (dm != NULL) {
		if (dm->get_num_network_ssid() > 0) {
			net_ssid = dm->get_network_ssid(static_cast<unsigned int> (0));
		}
		dm = static_cast<dm_easy_mesh_t *> (hash_map_get_next(m_list, dm));
	}

    return net_ssid;
}

dm_network_ssid_t *dm_easy_mesh_list_t::get_next_network_ssid(dm_network_ssid_t *net_ssid)
{
    dm_network_ssid_t *pnet_ssid = NULL;
    dm_easy_mesh_t *dm;
    bool return_next = false;
    unsigned int i;

    dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
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

        dm = static_cast<dm_easy_mesh_t *> (hash_map_get_next(m_list, dm));
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

    dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
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
        dm = static_cast<dm_easy_mesh_t *> (hash_map_get_next(m_list, dm));
    }
    return (found == true) ? net_ssid:NULL;
}

void dm_easy_mesh_list_t::debug_probe()
{
    dm_easy_mesh_t *dm;
    mac_addr_str_t  mac_str;

    dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
    while (dm != NULL) {
        dm_easy_mesh_t::macbytes_to_string(dm->get_agent_al_interface_mac(), mac_str);
        //printf("%s:%d: Dst AL MAC: %s\n", __func__, __LINE__, mac_str);
        //printf("%s:%d: Number of radios:%d Number of BSS: %d\n", __func__, __LINE__, dm->get_num_radios(), dm->get_num_bss());
        dm = static_cast<dm_easy_mesh_t *> (hash_map_get_next(m_list, dm));
    }
}

void dm_easy_mesh_list_t::remove_network_ssid(const char *key)
{
    dm_network_ssid_t *net_ssid = NULL, *tgt;
    dm_easy_mesh_t *dm;
    unsigned int i;
    bool found = false;

    //printf("%s:%d: Remove: %s\n", __func__, __LINE__, key);
    dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
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
            memset(reinterpret_cast<unsigned char *> (&tgt->m_network_ssid_info), 0, sizeof(em_network_ssid_info_t)); 
            dm->set_num_network_ssid(dm->get_num_network_ssid() - 1);
        }

        dm = static_cast<dm_easy_mesh_t *> (hash_map_get_next(m_list, dm));
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


    dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
    while (dm != NULL) {
        net = dm->get_network();
        if (strncmp(net->m_net_info.id, net_id, strlen(net_id)) != 0) {
            dm = static_cast<dm_easy_mesh_t *> (hash_map_get_next(m_list, dm));
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
        dm = static_cast<dm_easy_mesh_t *> (hash_map_get_next(m_list, dm));
    }
}

dm_op_class_t *dm_easy_mesh_list_t::get_first_op_class()
{
    dm_op_class_t *op_class = NULL;
    dm_easy_mesh_t *dm;
	bool found = false;
    
    dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
    while (dm != NULL) {
        if (dm->get_num_op_class() > 0) {
            op_class = dm->get_op_class(static_cast<unsigned int> (0));
			found = true;
			break;
        }
        dm = static_cast<dm_easy_mesh_t *> (hash_map_get_next(m_list, dm));
    }

    return (found == true) ? op_class:NULL;
}

dm_op_class_t *dm_easy_mesh_list_t::get_next_op_class(dm_op_class_t *op_class)
{
    dm_op_class_t *pop_class = NULL;
    dm_easy_mesh_t *dm;
    bool return_next = false;
    unsigned int i;
        
    dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
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

        dm = static_cast<dm_easy_mesh_t *> (hash_map_get_next(m_list, dm));
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
	mac_addr_str_t	mac_str;
	
    dm_op_class_t::parse_op_class_id_from_key(key, &id);

	dm_easy_mesh_t::macbytes_to_string(id.ruid, mac_str);
	//printf("%s:%d: MAC: %s\tType: %d\tClass: %d\n", __func__, __LINE__, mac_str, id.type, id.op_class);
	
    dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
    while (dm != NULL) {
        if (id.type <= em_op_class_type_capability) {
		    for (i = 0; i < dm->get_num_radios(); i++) {
			    radio = dm->get_radio(i);
			    if (memcmp(radio->m_radio_info.intf.mac, id.ruid, sizeof(mac_address_t)) == 0) {
				    found_dm = true;
			    	break;
			    }
		    }
        } else {
			if (memcmp(dm->m_device.m_device_info.intf.mac, id.ruid, sizeof(mac_address_t)) == 0) {
            	found_dm = true;
           	}
		}	

		if (found_dm == true) {
			break;
		}
        dm = static_cast<dm_easy_mesh_t *> (hash_map_get_next(m_list, dm));
	}

	if (found_dm == false) {
		return NULL;
	}
	//printf("%s:%d: Number of op classes: %d\n", __func__, __LINE__, dm->get_num_op_class());

    // now check if the op class is already there
	for (i = 0; i < dm->get_num_op_class(); i++) {
		pop_class = &dm->m_op_class[i];
		dm_easy_mesh_t::macbytes_to_string(pop_class->m_op_class_info.id.ruid, mac_str);
		//printf("%s:%d: MAC: %s\tType: %d\tClass: %d\n", __func__, __LINE__, 
				//mac_str, pop_class->m_op_class_info.id.type, pop_class->m_op_class_info.id.op_class);
		if ((memcmp(pop_class->m_op_class_info.id.ruid, id.ruid, sizeof(mac_address_t)) == 0) && 
					(pop_class->m_op_class_info.id.type == id.type) &&
					(pop_class->m_op_class_info.id.op_class == id.op_class)) {
			//printf("%s:%d: Found match\n\n\n", __func__, __LINE__);
			return pop_class;
		}	
	}

	//printf("%s:%d: Match not found\n\n\n", __func__, __LINE__);
	return NULL;
}

dm_op_class_t *dm_easy_mesh_list_t::get_first_pre_set_op_class_by_type(em_op_class_type_t type)
{
	dm_easy_mesh_t *dm;
	dm_op_class_t *op_class;
	unsigned int i;
    
	dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
    if (dm == NULL) {
		return NULL;
    }

	for (i = 0; i < dm->get_num_op_class(); i++) {
		op_class = &dm->m_op_class[i];
		if (op_class->m_op_class_info.id.type == type) {
			return op_class;
		}
	}	

	return NULL;
}

dm_op_class_t *dm_easy_mesh_list_t::get_next_pre_set_op_class_by_type(em_op_class_type_t type, dm_op_class_t *op_class)
{
	dm_easy_mesh_t *dm;
	dm_op_class_t *pop_class;
	unsigned int i;
	bool return_next = false;
    
	dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
    if (dm == NULL) {
		return NULL;
    }

	for (i = 0; i < dm->get_num_op_class(); i++) {
		pop_class = &dm->m_op_class[i];

		if ((return_next == true) && (pop_class->m_op_class_info.id.type == type)) {
			return pop_class;
		}

		if ((pop_class->m_op_class_info.id.type == type) &&
				(pop_class == op_class)) {
			return_next = true;
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

	dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (op_class->m_op_class_info.id.ruid), mac_str);
	//printf("%s:%d: key: %s, ruid: %s, type: %d, op_class: %d\n", __func__, __LINE__, 
		//key, mac_str, op_class->m_op_class_info.id.type, op_class->m_op_class_info.id.op_class);
	dm_op_class_t::parse_op_class_id_from_key(key, &id);

	// find the dm that has this radio
    dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
    while (dm != NULL) {
        if (id.type <= em_op_class_type_capability) {
            for (i = 0; i < dm->get_num_radios(); i++) {
                radio = dm->get_radio(i);
                dm_easy_mesh_t::macbytes_to_string(radio->m_radio_info.intf.mac, mac_str);
                //printf("%s:%d: Comparing with radio: %s\n", __func__, __LINE__, mac_str);
                if (memcmp(radio->m_radio_info.intf.mac, id.ruid, sizeof(mac_address_t)) == 0) {
                    found_dm = true;
                    break;
                }
            }
        } else {
            if (memcmp(dm->m_device.m_device_info.intf.mac, id.ruid, sizeof(mac_address_t)) == 0) {
                found_dm = true;
            }
        }
        if (found_dm == true) {
            break;
        } else {
            if ((memcmp(dm->m_device.m_device_info.intf.mac, id.ruid, sizeof(mac_address_t)) == 0) && (id.type >= em_op_class_type_cac_available)) {
                found_dm = true;
                break;
            }
        }
        dm = static_cast<dm_easy_mesh_t *> (hash_map_get_next(m_list, dm));
    }

    assert(found_dm == true);

    // now check if the op class is already there
    for (i = 0; i < dm->get_num_op_class(); i++) {
        pop_class = &dm->m_op_class[i];
        if ((memcmp(pop_class->m_op_class_info.id.ruid, op_class->m_op_class_info.id.ruid, sizeof(mac_address_t)) == 0) &&
					(pop_class->m_op_class_info.id.type == op_class->m_op_class_info.id.type) &&
					(pop_class->m_op_class_info.id.op_class == op_class->m_op_class_info.id.op_class)) {
        	memcpy(&pop_class->m_op_class_info, &op_class->m_op_class_info, sizeof(em_op_class_info_t));
        	return;
        }
    }

    pop_class = &dm->m_op_class[dm->get_num_op_class()];
    memcpy(&pop_class->m_op_class_info, &op_class->m_op_class_info, sizeof(em_op_class_info_t));
	dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (pop_class->m_op_class_info.id.ruid), mac_str);
	//printf("%s:%d: ruid: %s, type: %d, op_class: %d\n", __func__, __LINE__, 
		//mac_str, pop_class->m_op_class_info.id.type, pop_class->m_op_class_info.id.op_class);
    dm->set_num_op_class(dm->get_num_op_class() + 1);
	//printf("%s:%d: Number of op classes: %d\n", __func__, __LINE__, dm->get_num_op_class());
}

dm_policy_t *dm_easy_mesh_list_t::get_first_policy()
{
	dm_easy_mesh_t *dm;

	dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
    while (dm != NULL) {
		if (dm->m_num_policy > 0) {
			return &dm->m_policy[0];
		}	

        dm = static_cast<dm_easy_mesh_t *> (hash_map_get_next(m_list, dm));
    }

	return NULL;
}

dm_policy_t *dm_easy_mesh_list_t::get_next_policy(dm_policy_t *policy)
{
	dm_easy_mesh_t *dm;
	bool return_next = false;
	unsigned int i;

	dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
    while (dm != NULL) {
		if (dm->m_num_policy == 0) {
			dm = static_cast<dm_easy_mesh_t *> (hash_map_get_next(m_list, dm));
			continue;		
		}

		if (return_next == true) {
			return &dm->m_policy[0];
		}

		for (i = 0; i < dm->m_num_policy; i++) {
			if (policy == &dm->m_policy[i]) {
				return_next = true;
				break;
			}
		}

		if ((return_next == true) && ((i + 1) < dm->m_num_policy)) {
			return &dm->m_policy[i + 1];
		}
	
        dm = static_cast<dm_easy_mesh_t *> (hash_map_get_next(m_list, dm));
    }
	return NULL;
}

dm_policy_t *dm_easy_mesh_list_t::get_policy(const char *key)
{
	em_policy_id_t	id;
	dm_easy_mesh_t	*dm;
	mac_addr_str_t	dev_mac_str, radio_mac_str;
	unsigned int i;
	dm_policy_t *policy;
	
	dm_policy_t::parse_dev_radio_mac_from_key(key, &id);
	dm_easy_mesh_t::macbytes_to_string(id.dev_mac, dev_mac_str);
	dm_easy_mesh_t::macbytes_to_string(id.radio_mac, radio_mac_str);
	//printf("%s:%d: Net id: %s\tdev: %s\tradio: %s\tType: %d\n", __func__, __LINE__, id.net_id, dev_mac_str, radio_mac_str, id.type);
	dm_easy_mesh_t::macbytes_to_string(id.dev_mac, dev_mac_str);

	if ((dm = get_data_model(id.net_id, id.dev_mac)) == NULL) {
		printf("%s:%d: Could not find data model for Network: %s and dev: %s\n", __func__, __LINE__, id.net_id, dev_mac_str);
		return NULL;
	} 

	for (i = 0; i < dm->get_num_policy(); i++) {
		policy = &dm->m_policy[i];
		if ((strncmp(policy->m_policy.id.net_id, id.net_id, strlen(id.net_id)) == 0) && 
				(memcmp(policy->m_policy.id.dev_mac, id.dev_mac, sizeof(mac_address_t)) == 0) && 
				(memcmp(policy->m_policy.id.radio_mac, id.radio_mac, sizeof(mac_address_t)) == 0) && 
				(policy->m_policy.id.type == id.type)) {
			//printf("%s:%d: Policy found for key: %s\n", __func__, __LINE__, key);
			return policy;
		}
	}

	printf("%s:%d: Policy not found for key: %s\n", __func__, __LINE__, key);
	return NULL;
}

void dm_easy_mesh_list_t::remove_policy(const char *key)
{

}

void dm_easy_mesh_list_t::put_policy(const char *key, const dm_policy_t *policy)
{
	em_policy_id_t	id;
	dm_easy_mesh_t	*dm;
	mac_addr_str_t	dev_mac_str;
	
	dm_policy_t::parse_dev_radio_mac_from_key(key, &id);
	dm_easy_mesh_t::macbytes_to_string(id.dev_mac, dev_mac_str);
	if ((dm = get_data_model(id.net_id, id.dev_mac)) == NULL) {
		printf("%s:%d: Could not find data model for Network: %s and dev: %s\n", __func__, __LINE__, id.net_id, dev_mac_str);
		return;
	} 

	dm->set_policy(*policy);		
}

dm_scan_result_t *dm_easy_mesh_list_t::get_first_scan_result()
{
	dm_easy_mesh_t *dm;
	dm_scan_result_t *res;

    dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
    while (dm != NULL) {
		res = static_cast<dm_scan_result_t *> (hash_map_get_first(dm->m_scan_result_map));
		if (res != NULL) {
			return res;
		}
		
		dm = static_cast<dm_easy_mesh_t *> (hash_map_get_next(m_list, dm));
	}

	return NULL;
}

dm_scan_result_t *dm_easy_mesh_list_t::get_next_scan_result(dm_scan_result_t *scan_result)
{
    dm_easy_mesh_t *dm;
	dm_scan_result_t *res;
    bool return_next = false;

    dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
    while (dm != NULL) {
		res = static_cast<dm_scan_result_t *> (hash_map_get_first(dm->m_scan_result_map));
		while (res != NULL) {
			if (return_next == true) {
				return res;
			}
			if (res == scan_result) {
				return_next = true;
			}
			res = static_cast<dm_scan_result_t *> (hash_map_get_next(dm->m_scan_result_map, res));
		}

        dm = static_cast<dm_easy_mesh_t *> (hash_map_get_next(m_list, dm));
    }
    return NULL;

}

dm_scan_result_t *dm_easy_mesh_list_t::get_scan_result(const char *key)
{
	em_scan_result_id_t	id;
	dm_easy_mesh_t	*dm;
	mac_addr_str_t	dev_mac_str, scanner_mac_str;
	dm_scan_result_t *res;
	em_2xlong_string_t list_key;
	
	dm_scan_result_t::parse_scan_result_id_from_key(key, &id);
	dm_easy_mesh_t::macbytes_to_string(id.dev_mac, dev_mac_str);
	dm_easy_mesh_t::macbytes_to_string(id.scanner_mac, scanner_mac_str);	
	
	if ((dm = get_data_model(id.net_id, id.dev_mac)) == NULL) {
		printf("%s:%d: Could not find data model for Network: %s and dev: %s\n", __func__, __LINE__, id.net_id, dev_mac_str);
		return NULL;
	} 

	snprintf(list_key, sizeof(em_2xlong_string_t), "%s@%s@%s@%d@%d@%d", id.net_id, dev_mac_str, scanner_mac_str,
		id.op_class, id.channel, id.scanner_type);	

	res = static_cast<dm_scan_result_t *> (hash_map_get(dm->m_scan_result_map, list_key));

	return res;
}

void dm_easy_mesh_list_t::remove_scan_result(const char *key)
{
    em_scan_result_id_t id;
    mac_addr_str_t	dev_mac_str, scanner_mac_str, bssid_str;
    bssid_t bssid;
    dm_easy_mesh_t *dm;
    dm_scan_result_t *res;
    dm_sta_t *sta;
    int i;
    int index_to_remove = -1;
    em_2xlong_string_t list_key;
    bool found_sta = false;
    wifi_BeaconReport_t *rprt;

    dm_scan_result_t::parse_scan_result_id_from_key(key, &id, bssid);

    dm_easy_mesh_t::macbytes_to_string(id.dev_mac, dev_mac_str);
    dm_easy_mesh_t::macbytes_to_string(id.scanner_mac, scanner_mac_str);
    dm_easy_mesh_t::macbytes_to_string(bssid, bssid_str);

    if ((dm = get_data_model(id.net_id, id.dev_mac)) == NULL) {
        printf("%s:%d: Could not find data model for Network: %s and dev: %s\n", __func__, __LINE__, id.net_id, dev_mac_str);
        return;
    }

    snprintf(list_key, sizeof(em_2xlong_string_t), "%s@%s@%s@%d@%d@%d", id.net_id, dev_mac_str, scanner_mac_str,
        id.op_class, id.channel, id.scanner_type);

    if ((res = static_cast<dm_scan_result_t *> (hash_map_remove(dm->m_scan_result_map, list_key))) != NULL) {
        delete res;
    }

    // now if the result is from sta beacon report, find the sta and populate the structure
    if (id.scanner_type == em_scanner_type_radio) {
        return;
    }

    sta = static_cast<dm_sta_t *> (hash_map_get_first(dm->m_sta_map));
        while (sta != NULL) {
            if (memcmp(sta->m_sta_info.id, id.scanner_mac, sizeof(mac_address_t)) == 0) {
                found_sta = true;
                break;
            }
        sta = static_cast<dm_sta_t *> (hash_map_get_next(dm->m_sta_map, sta));
    }

    if (found_sta == false) {
        return;
    }

    for (i = 0; i < static_cast<int> (sta->m_sta_info.num_beacon_meas_report); i++) {
        dm_sta_t::decode_beacon_report(sta);
        rprt = &sta->m_sta_info.beacon_reports[i];

        if (memcmp(rprt->bssid, bssid, sizeof(bssid_t)) == 0) {
            index_to_remove = i;
            break;
        }
    }

    if (index_to_remove == -1) {
        return;
    }

    for (i = index_to_remove; i < static_cast<int> (sta->m_sta_info.num_beacon_meas_report) - 1; i++) {
        memcpy(&sta->m_sta_info.beacon_report_elem[i], &sta->m_sta_info.beacon_report_elem[i + 1], sta->m_sta_info.beacon_report_len);
    }

    sta->m_sta_info.num_beacon_meas_report--;
}

void dm_easy_mesh_list_t::put_scan_result(const char *key, const dm_scan_result_t *scan_result, unsigned int index)
{
	em_scan_result_id_t	id;
	dm_easy_mesh_t	*dm;
	mac_addr_str_t	dev_mac_str, scanner_mac_str;
	dm_scan_result_t *res;
	dm_sta_t *sta;
	bssid_t bssid;
	bool found_neighbor = false, found_sta = false;
	unsigned int i;
	em_neighbor_t *nbr;
	em_2xlong_string_t list_key;
	wifi_BeaconReport_t *rprt;
	
	dm_scan_result_t::parse_scan_result_id_from_key(key, &id, bssid);

	dm_easy_mesh_t::macbytes_to_string(id.dev_mac, dev_mac_str);
	dm_easy_mesh_t::macbytes_to_string(id.scanner_mac, scanner_mac_str);

	if ((dm = get_data_model(id.net_id, id.dev_mac)) == NULL) {
		printf("%s:%d: Could not find data model for Network: %s and dev: %s\n", __func__, __LINE__, id.net_id, dev_mac_str);
		return;
	}
		
	snprintf(list_key, sizeof(em_2xlong_string_t), "%s@%s@%s@%d@%d@%d", id.net_id, dev_mac_str, scanner_mac_str, 
    							id.op_class, id.channel, id.scanner_type);

	if ((res = static_cast<dm_scan_result_t *> (hash_map_get(dm->m_scan_result_map, list_key))) == NULL) {
		//printf("%s:%d: New Scan Result\tnetwork: %s\tdevice: %s\tradio: %s\topclass: %d\tchannel: %d\tScanner Type: %d\n", 
				//__func__, __LINE__, id.net_id, dev_mac_str, scanner_mac_str, id.op_class, id.channel, id.scanner_type);	
		res = new dm_scan_result_t();
		
		hash_map_put(dm->m_scan_result_map, strdup(list_key), res);

		memcpy(&res->m_scan_result, &scan_result->m_scan_result, sizeof(em_scan_result_t));
		
		// increase the neighbors by 1
		res->m_scan_result.num_neighbors++;		
	} else {
		//printf("%s:%d: Existing Scan Result\tnetwork: %s\tdevice: %s\tradio: %s\topclass: %d\tchannel: %d\tScanner Type: %d\n", 
				//__func__, __LINE__, id.net_id, dev_mac_str, scanner_mac_str, id.op_class, id.channel, id.scanner_type);	
		for (i = 0; i < res->m_scan_result.num_neighbors; i++) {
			nbr = &res->m_scan_result.neighbor[i];

			if (memcmp(nbr->bssid, bssid, sizeof(mac_address_t)) == 0) {
				found_neighbor = true;
				memcpy(nbr, &scan_result->m_scan_result.neighbor[index], sizeof(em_neighbor_t));
				break;
			}
		}

		if (found_neighbor == false) {
			if (res->m_scan_result.num_neighbors >= EM_MAX_NEIGHBORS) {
				return;
			}
			nbr = &res->m_scan_result.neighbor[res->m_scan_result.num_neighbors];
			memcpy(nbr, &scan_result->m_scan_result.neighbor[index], sizeof(em_neighbor_t));
			res->m_scan_result.num_neighbors++;
		}
	}

	// now if the result is from sta beacon report, find the sta and populate the structure
	if (id.scanner_type == em_scanner_type_radio) {
		return;
	} 

	sta = static_cast<dm_sta_t *> (hash_map_get_first(dm->m_sta_map));
	while (sta != NULL) {

		if (memcmp(sta->m_sta_info.id, id.scanner_mac, sizeof(mac_address_t)) == 0) {
			found_sta = true;
			break;
		}
		sta = static_cast<dm_sta_t *> (hash_map_get_next(dm->m_sta_map, sta));
	}		

	if (found_sta == false) {
		return;
	}

	rprt = &sta->m_sta_info.beacon_reports[sta->m_sta_info.num_beacon_meas_report];
	rprt->opClass = scan_result->m_scan_result.id.op_class;
	rprt->channel = scan_result->m_scan_result.id.channel;
	memcpy(rprt->bssid, &bssid, sizeof(bssid_t));
		
	sta->m_sta_info.num_beacon_meas_report++;

}

void dm_easy_mesh_list_t::delete_all_data_models()
{
	dm_easy_mesh_t *dm = NULL, *tmp;
	dm_device_t *dev;
	mac_addr_str_t mac_str;
	em_2xlong_string_t	key;
	
	dm = static_cast<dm_easy_mesh_t *> (hash_map_get_first(m_list));
    while (dm != NULL) {
		tmp = dm;
        dm = static_cast<dm_easy_mesh_t *> (hash_map_get_next(m_list, dm)); 

        if (tmp->get_colocated() == true) {
            //printf("%s:%d: Skipping delete as colocated\n", __func__, __LINE__);
            continue;
        }
		dev = tmp->get_device();	
		dm_easy_mesh_t::macbytes_to_string(dev->m_device_info.intf.mac, mac_str);
		snprintf(key, sizeof(em_2xlong_string_t), "%s@%s", dev->m_device_info.id.net_id, mac_str);

		hash_map_remove(m_list, key);
		delete tmp;
    }   

}

void dm_easy_mesh_list_t::delete_data_model(const char *net_id, const unsigned char *al_mac)
{
    dm_easy_mesh_t *dm = NULL;
    mac_addr_str_t mac_str;
    em_long_string_t	key;
	
    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (al_mac), mac_str);
    snprintf(key, sizeof(em_short_string_t), "%s@%s", net_id, mac_str);
    //printf("%s:%d: Putting data model at key: %s\n", __func__, __LINE__, key);

    dm = static_cast<dm_easy_mesh_t *> (hash_map_remove(m_list, key));

    //printf("%s:%d: deleteing data model at key: %s, dm:%p, colocated:%d\n", __func__, __LINE__, key, dm, dm->get_colocated());
    dm->deinit();
    delete dm;
}

dm_easy_mesh_t *dm_easy_mesh_list_t::create_data_model(const char *net_id, const em_interface_t *al_intf, em_profile_type_t profile, bool colocated)
{
    dm_easy_mesh_t *dm = NULL, *ref_dm;
    mac_addr_str_t mac_str;
    em_short_string_t	key;
    dm_network_t *net, *pnet;
    dm_device_t *dev;
    dm_network_ssid_t *net_ssid, *pnet_ssid;
	const em_policy_t	em_policy[] = {
						{{"OneWifiMesh", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 
							em_policy_id_type_ap_metrics_rep}, 0, {}, em_steering_policy_type_unknown, 
							0, 0, 120, 0, false, false, false, "", false, false, false},
						{{"OneWifiMesh", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 
							em_policy_id_type_radio_metrics_rep}, 0, {}, em_steering_policy_type_unknown, 
							60, 120, 0, 5, false, false, false, "", false, false, false},
						{{"OneWifiMesh", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 
							em_policy_id_type_steering_local}, 1, {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}, 
							em_steering_policy_type_unknown, 
							0, 0, 0, 0, false, false, false, "", false, false, false},
						{{"OneWifiMesh", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 
							em_policy_id_type_steering_btm}, 1, {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}, 
							em_steering_policy_type_unknown, 
							0, 0, 0, 0, false, false, false, "", false, false, false},
						{{"OneWifiMesh", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 
							em_policy_id_type_steering_param}, 1, {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}, 
							em_steering_policy_type_rcpi_allowed, 
							60, 120, 0, 0, false, false, false, "", false, false, false},
						{{"OneWifiMesh", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 
							em_policy_id_type_channel_scan}, 0, {}, em_steering_policy_type_unknown, 
							0, 0, 0, 0, false, false, false, "", false, false, false}
					};
    unsigned int i;
	dm_op_class_t	op_class[EM_MAX_PRE_SET_CHANNELS] 	= 	{
		dm_op_class_t({{{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, em_op_class_type_anticipated, 81}, 81, 0, 0, 0, 1, {6}, 0, 0, 0}), 
		dm_op_class_t({{{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, em_op_class_type_anticipated, 115}, 115, 0, 0, 0, 1, {36}, 0, 0, 0}), 
		dm_op_class_t({{{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, em_op_class_type_anticipated, 135}, 135, 0, 0, 0, 1, {1}, 0, 0, 0}),
		dm_op_class_t({{{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, em_op_class_type_scan_param, 81}, 81, 0, 0, 0, 3, {3, 6, 9}, 0, 0, 0}),
		dm_op_class_t({{{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, em_op_class_type_scan_param, 115}, 115, 0, 0, 0, 9, {36, 40, 44, 48, 149, 153, 157, 161, 165}, 0, 0, 0}),
		dm_op_class_t({{{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, em_op_class_type_scan_param, 135}, 135, 0, 0, 0, 1, {1}, 0, 0, 0})
									};
	dm_policy_t	policy[] = {
								dm_policy_t(em_policy[0]), dm_policy_t(em_policy[1]), 
								dm_policy_t(em_policy[2]), dm_policy_t(em_policy[3]), 
								dm_policy_t(em_policy[4]), dm_policy_t(em_policy[5])
						};
	
    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (al_intf->mac), mac_str);
    snprintf(key, sizeof(em_short_string_t), "%s@%s", net_id, mac_str);

    dm = new dm_easy_mesh_t();
    dm->init();
    printf("%s:%d: Created data model for net_id: %s mac: %s, coloc:%d\n", __func__, __LINE__, net_id, mac_str, colocated);
    dm->set_colocated(colocated);

    dev = dm->get_device();
    memcpy(dev->m_device_info.intf.mac, al_intf->mac, sizeof(mac_address_t));
    strncpy(dev->m_device_info.id.net_id, net_id, strlen(net_id) + 1);
	if (colocated == true) {
		dev->m_device_info.id.media = dm->m_network.m_net_info.media;
		memcpy(dev->m_device_info.backhaul_mac.mac, al_intf->mac, sizeof(mac_address_t));
		dev->m_device_info.backhaul_mac.media = dm->m_network.m_net_info.media;
		//Update the easymesh configuration file
		dev->update_easymesh_json_cfg(colocated);
	}
    dev->m_device_info.profile = profile;
	dm->set_channels_list(op_class, EM_MAX_PRE_SET_CHANNELS);
	
	for (i = 0; i < sizeof(em_policy)/sizeof(em_policy_t); i++) {
		dm->set_policy(policy[i]);
	}

	printf("%s:%d: Number of policies: %d\n", __func__, __LINE__, dm->get_num_policy());

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
    printf("%s:%d: Putting data model at key: %s\n", __func__, __LINE__, key);
    hash_map_put(m_list, strdup(key), dm);	

    return dm;
}

dm_easy_mesh_t *dm_easy_mesh_list_t::get_data_model(const char *net_id, const unsigned char *al_mac)
{
    dm_easy_mesh_t *dm = NULL;
    mac_addr_str_t mac_str;
    em_2xlong_string_t	key;

    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (al_mac), mac_str);
    snprintf(key, sizeof(key), "%s@%s", net_id, mac_str);
    //printf("%s:%d: Retrieve data model at key: %s\n", __func__, __LINE__, key);
    dm = static_cast<dm_easy_mesh_t *> (hash_map_get(m_list, key));

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
