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
#include <algorithm>
#include <string>
#include <vector>
#include "em_cmd.h"
#include "dm_bss_list.h"
#include "dm_easy_mesh.h"
#include "dm_easy_mesh_ctrl.h"

// Ownership transfers only after queue_push succeeds, unlike hash_map_put's mixed failure behavior.
static int acl_map_insert(hash_map_t *map, char *key, em_acl_sta_t *data)
{
    hash_element_t *entry = static_cast<hash_element_t *> (calloc(1, sizeof(hash_element_t)));
    if ((map == NULL) || (map->queue == NULL) || (key == NULL) || (data == NULL) || (entry == NULL)) {
        free(entry);
        return -1;
    }

    entry->key = key;
    entry->data = data;
    map->itr = NULL;
    if (queue_push(map->queue, entry) < 0) {
        free(entry);
        return -1;
    }

    return 0;
}

static int persist_bss_ssid_if_changed(db_client_t& db_client, const char *bss_key, const char *ssid)
{
    em_2xlong_string_t escaped_key;
    char escaped_ssid[EM_MAX_SSID_LEN * 2];
    em_short_string_t stored_ssid;
    db_query_t query;
    void *ctx;
    bool succeeded = false;

    if (!db_client.escape_string(bss_key, escaped_key, sizeof(escaped_key)) ||
            !db_client.escape_string(ssid, escaped_ssid, sizeof(escaped_ssid))) {
        em_printfout("Failed to escape BSSList key or SSID for key %s", bss_key);
        return -1;
    }

    snprintf(query, sizeof(query), "SELECT SSID FROM BSSList WHERE ID = '%s'", escaped_key);
    ctx = db_client.execute(query, &succeeded);
    if (!succeeded) {
        db_client.free_result(ctx);
        em_printfout("Failed to read current SSID for BSSList key %s", bss_key);
        return -1;
    }
    // A missing row is handled by the caller through the normal insert path.
    if (!db_client.next_result(ctx)) {
        return 1;
    }
    if (db_client.get_string(ctx, stored_ssid, 1, sizeof(stored_ssid)) == NULL) {
        db_client.free_result(ctx);
        em_printfout("Failed to read SSID for BSSList key %s", bss_key);
        return -1;
    }
    db_client.free_result(ctx);

    if (strcmp(stored_ssid, ssid) == 0) {
        return 0;
    }

    snprintf(query, sizeof(query), "UPDATE BSSList SET SSID = '%s' WHERE ID = '%s'",
            escaped_ssid, escaped_key);
    ctx = db_client.execute(query, &succeeded);
    db_client.free_result(ctx);
    if (!succeeded) {
        em_printfout("Failed to update SSID for BSSList key %s", bss_key);
        return -1;
    }

    return 0;
}

dm_bss_list_t::~dm_bss_list_t()
{
    acl_clear();
    hash_map_destroy(m_acl_sta_map);
    m_acl_sta_map = NULL;
}

void dm_bss_list_t::encode_acl(dm_bss_t *pbss, cJSON *obj)
{
    std::lock_guard<std::recursive_mutex> lock(m_acl_mutex);
    mac_addr_str_t dev_mac_str, radio_mac_str, bss_mac_str, mac_str;
    em_2xlong_string_t key;
    mac_address_t macs[EM_MAX_ACL_JSON_STAS];
    unsigned int num, i;

    dm_easy_mesh_t::macbytes_to_string(pbss->m_bss_info.id.dev_mac, dev_mac_str);
    dm_easy_mesh_t::macbytes_to_string(pbss->m_bss_info.ruid.mac, radio_mac_str);
    dm_easy_mesh_t::macbytes_to_string(pbss->m_bss_info.bssid.mac, bss_mac_str);
    snprintf(key, sizeof(key), "%s@%s@%s@%s@%d", pbss->m_bss_info.id.net_id, dev_mac_str,
                radio_mac_str, bss_mac_str, pbss->m_bss_info.id.haul_type);

    cJSON *blocked_arr = cJSON_CreateArray();
    num = acl_get_macs(key, true, 0, EM_MAX_ACL_JSON_STAS, macs);
    for (i = 0; i < num; i++) {
        dm_easy_mesh_t::macbytes_to_string(macs[i], mac_str);
        cJSON_AddItemToArray(blocked_arr, cJSON_CreateString(mac_str));
    }
    cJSON_AddItemToObject(obj, "MACsDisallowed", blocked_arr);

    cJSON *allowed_arr = cJSON_CreateArray();
    num = acl_get_macs(key, false, 0, EM_MAX_ACL_JSON_STAS, macs);
    for (i = 0; i < num; i++) {
        dm_easy_mesh_t::macbytes_to_string(macs[i], mac_str);
        cJSON_AddItemToArray(allowed_arr, cJSON_CreateString(mac_str));
    }
    cJSON_AddItemToObject(obj, "MACsAllowed", allowed_arr);
}

int dm_bss_list_t::get_config(cJSON *obj_arr, void *parent, bool summary)
{
    dm_bss_t *pbss;
    cJSON *obj;
    mac_addr_str_t  mac_str;
    mac_address_t	ruid;

    dm_easy_mesh_t::string_to_macbytes(static_cast<char *> (parent), ruid);

    pbss = get_first_bss();
    //printf("%s:%d: pbss: %p\n", __func__, __LINE__, pbss);
    
    while (pbss != NULL) {
        dm_easy_mesh_t::macbytes_to_string(pbss->m_bss_info.ruid.mac, mac_str);
        //printf("%s:%d: Parent Radio: %s, Current BSS Radio: %s\n", __func__, __LINE__, (char *)parent, mac_str);
        if (memcmp(pbss->m_bss_info.ruid.mac, ruid, sizeof(mac_address_t)) != 0) {
            pbss = get_next_bss(pbss);
            continue;
        }

        obj = cJSON_CreateObject(); 

        pbss->encode(obj, summary);
        if (summary == false) {
            encode_acl(pbss, obj);
        }

        cJSON_AddItemToArray(obj_arr, obj);
        pbss = get_next_bss(pbss);
    }
    
	
    return 0;
}

int dm_bss_list_t::set_config(db_client_t& db_client, dm_bss_t& bss, void *parent_id)
{
    std::lock_guard<std::recursive_mutex> lock(m_acl_mutex);
    dm_orch_type_t op;  
    int rc;
    em_2xlong_string_t new_key, old_key;
    mac_addr_str_t dev_mac_str, radio_mac_str, bss_mac_str;
    std::vector<dm_bss_t> stale_bsses;
    std::vector<std::string> stale_bss_keys;
    std::vector<std::string> stale_retained_keys;
    dm_bss_t *existing_bss;
    em_bss_info_t *existing_info;
    mac_address_t zero_mac = {0};

    //printf("%s:%d: Parent: %s \n", __func__, __LINE__, (char *)parent_id);
	parse_bss_id_from_key(static_cast<char *> (parent_id), &bss.m_bss_info.id);
    if (bss.m_bss_info.vap_mode != em_vap_mode_ap) {
        return 0;
    }
    if ((bss.m_bss_info.id.haul_type >= em_haul_type_max) ||
            (memcmp(bss.m_bss_info.bssid.mac, zero_mac, sizeof(mac_address_t)) == 0) ||
            (memcmp(bss.m_bss_info.ruid.mac, zero_mac, sizeof(mac_address_t)) == 0)) {
        return -1;
    }
    snprintf(new_key, sizeof(new_key), "%s", static_cast<char *>(parent_id));

    // Haul type is part of the row ID, so remove an older key for this same interface
    // before inserting its corrected haul type.
    for (existing_bss = get_first_bss(); existing_bss != NULL;
            existing_bss = get_next_bss(existing_bss)) {
            existing_info = existing_bss->get_bss_info();
            if ((existing_info->id.haul_type == bss.m_bss_info.id.haul_type) ||
                    (strcmp(existing_info->id.net_id, bss.m_bss_info.id.net_id) != 0) ||
                    (memcmp(existing_info->id.dev_mac, bss.m_bss_info.id.dev_mac, sizeof(mac_address_t)) != 0) ||
                    (memcmp(existing_info->id.ruid, bss.m_bss_info.id.ruid, sizeof(mac_address_t)) != 0) ||
                    (memcmp(existing_info->id.bssid, bss.m_bss_info.id.bssid, sizeof(mac_address_t)) != 0)) {
                continue;
            }

            dm_easy_mesh_t::macbytes_to_string(existing_info->id.dev_mac, dev_mac_str);
            dm_easy_mesh_t::macbytes_to_string(existing_info->id.ruid, radio_mac_str);
            dm_easy_mesh_t::macbytes_to_string(existing_info->id.bssid, bss_mac_str);
            snprintf(old_key, sizeof(old_key), "%s@%s@%s@%s@%d", existing_info->id.net_id,
                    dev_mac_str, radio_mac_str, bss_mac_str, existing_info->id.haul_type);

            stale_bsses.emplace_back(*existing_bss);
            stale_bss_keys.emplace_back(old_key);

            if (acl_copy(old_key, new_key) != 0) {
                return -1;
            }
    }

    // The same applies to a retained row (removed from the list for rebuilding) of this
    // interface that comes back with a different haul type.
    for (const std::string& retained_key : m_retained_bss_keys) {
        em_bss_id_t retained_id;
        if ((retained_key == new_key) ||
                (dm_bss_t::parse_bss_id_from_key(retained_key.c_str(), &retained_id) != 0) ||
                (strcmp(retained_id.net_id, bss.m_bss_info.id.net_id) != 0) ||
                (memcmp(retained_id.dev_mac, bss.m_bss_info.id.dev_mac, sizeof(mac_address_t)) != 0) ||
                (memcmp(retained_id.ruid, bss.m_bss_info.id.ruid, sizeof(mac_address_t)) != 0) ||
                (memcmp(retained_id.bssid, bss.m_bss_info.id.bssid, sizeof(mac_address_t)) != 0)) {
            continue;
        }
        if (acl_copy(retained_key.c_str(), new_key) != 0) {
            return -1;
        }
        stale_retained_keys.push_back(retained_key);
    }

    op = get_dm_orch_type(db_client, bss);
    const std::string bss_key(static_cast<char *> (parent_id));
    const bool acl_persistence_pending =
            (m_pending_acl_persistence_keys.find(bss_key) != m_pending_acl_persistence_keys.end());
    if (acl_persistence_pending) {
        if (op == dm_orch_type_none) {
            op = dm_orch_type_db_update;
        }
    }
    rc = update_db(db_client, op, bss.get_bss_info());
    if (rc != 0) {
        return rc;
    }
    if (acl_persistence_pending) {
        m_pending_acl_persistence_keys.erase(bss_key);
    }
    // The BSS returned, so its row is no longer a reconciliation candidate.
    m_retained_bss_keys.erase(bss_key);
    update_list(bss, op);

    for (const std::string& retained_key : stale_retained_keys) {
        if (delete_bss_row(db_client, retained_key.c_str()) != 0) {
            em_printfout("Failed to delete retained BSSList key %s after persisting replacement %s",
                    retained_key.c_str(), new_key);
            rc = -1;
        }
    }

    for (size_t stale_index = 0; stale_index < stale_bsses.size(); stale_index++) {
        dm_bss_t& stale_bss = stale_bsses[stale_index];
        if (update_db(db_client, dm_orch_type_db_delete, stale_bss.get_bss_info()) != 0) {
            em_printfout("Failed to delete stale BSSList key %s after persisting replacement %s",
                    stale_bss_keys[stale_index].c_str(), new_key);
            rc = -1;
            continue;
        }
        update_list(stale_bss, dm_orch_type_db_delete);
    }
                        
    return rc;
}

int dm_bss_list_t::update_ssid_if_changed(db_client_t& db_client, dm_bss_t& bss, void *parent_id)
{
    std::lock_guard<std::recursive_mutex> lock(m_acl_mutex);
    em_2xlong_string_t bss_key;
    mac_address_t zero_mac = {0};
    int rc;

    if (parent_id == NULL) {
        em_printfout("Cannot update BSS SSID without its database key");
        return -1;
    }
    if (bss.m_bss_info.vap_mode != em_vap_mode_ap) {
        return 0;
    }
    if ((bss.m_bss_info.id.haul_type >= em_haul_type_max) ||
            (memcmp(bss.m_bss_info.bssid.mac, zero_mac, sizeof(mac_address_t)) == 0) ||
            (memcmp(bss.m_bss_info.ruid.mac, zero_mac, sizeof(mac_address_t)) == 0)) {
        em_printfout("Cannot update SSID for BSS with invalid haul type, BSSID, or radio");
        return -1;
    }
    snprintf(bss_key, sizeof(bss_key), "%s", static_cast<char *>(parent_id));
    if (m_pending_acl_persistence_keys.find(bss_key) != m_pending_acl_persistence_keys.end()) {
        return set_config(db_client, bss, bss_key);
    }

    rc = persist_bss_ssid_if_changed(db_client, bss_key, bss.m_bss_info.ssid);
    if (rc == 1) {
        return set_config(db_client, bss, bss_key);
    }
    return rc;
}

int dm_bss_list_t::set_config(db_client_t& db_client, const cJSON *obj_arr, void *parent_id)
{
    (void)db_client;
    (void)obj_arr;
    (void)parent_id;
    em_printfout("BSSList JSON update requires device and radio MAC context");
    return -1;
}

int dm_bss_list_t::set_config(db_client_t& db_client, const cJSON *obj_arr,
		mac_address_t *dev_mac, mac_address_t *radio_mac)
{
    std::lock_guard<std::recursive_mutex> lock(m_acl_mutex);
    cJSON *obj;
    int size;
    dm_bss_t bss;
    mac_addr_str_t dev_mac_str, radio_mac_str, bss_mac_str;
    em_2xlong_string_t bss_key;
    mac_address_t zero_mac = {0};
    std::vector<std::string> seen_bssids;
    dm_bss_t *existing_bss, *next_bss;
    em_bss_info_t *existing_info;
    bool snapshot_complete = true;
    int rc = 0;

    if ((obj_arr == NULL) || !cJSON_IsArray(obj_arr) || (dev_mac == NULL) || (radio_mac == NULL)) {
        return -1;
    }

    size = cJSON_GetArraySize(obj_arr);
    if (size < 0) {
        em_printfout("Invalid BSSList snapshot for radio");
        return -1;
    }

    dm_easy_mesh_t::macbytes_to_string(*dev_mac, dev_mac_str);
    dm_easy_mesh_t::macbytes_to_string(*radio_mac, radio_mac_str);
    seen_bssids.reserve(static_cast<size_t>(size));

    for (int i = 0; i < size; i++) {
        obj = cJSON_GetArrayItem(obj_arr, i);
        if (!cJSON_IsObject(obj)) {
            em_printfout("Ignoring malformed BSSList entry %d from radio %s", i, radio_mac_str);
            snapshot_complete = false;
            continue;
        }

        bss.decode(obj, radio_mac_str);
        if (bss.m_bss_info.vap_mode != em_vap_mode_ap) {
            continue;
        }
        if ((bss.m_bss_info.id.haul_type >= em_haul_type_max) ||
                (memcmp(bss.m_bss_info.bssid.mac, zero_mac, sizeof(mac_address_t)) == 0)) {
            em_printfout("Ignoring BSSList entry %d with invalid haul type or BSSID from radio %s",
                    i, radio_mac_str);
            snapshot_complete = false;
            continue;
        }

        dm_easy_mesh_t::macbytes_to_string(bss.m_bss_info.bssid.mac, bss_mac_str);
        seen_bssids.emplace_back(bss_mac_str);
        snprintf(bss_key, sizeof(bss_key), "%s@%s@%s@%s@%d", GLOBAL_NET_ID,
                dev_mac_str, radio_mac_str, bss_mac_str, bss.m_bss_info.id.haul_type);
        if (set_config(db_client, bss, bss_key) != 0) {
            em_printfout("Failed to update BSSList row %s", bss_key);
            rc = -1;
        }
    }

    if ((rc == 0) && snapshot_complete && !seen_bssids.empty()) {
        for (existing_bss = get_first_bss(); existing_bss != NULL; existing_bss = next_bss) {
            next_bss = get_next_bss(existing_bss);
            existing_info = existing_bss->get_bss_info();
                if ((existing_info->vap_mode != em_vap_mode_ap) ||
                    (strcmp(existing_info->id.net_id, GLOBAL_NET_ID) != 0) ||
                    (memcmp(existing_info->id.dev_mac, *dev_mac, sizeof(mac_address_t)) != 0) ||
                    (memcmp(existing_info->id.ruid, *radio_mac, sizeof(mac_address_t)) != 0)) {
                continue;
            }

            dm_easy_mesh_t::macbytes_to_string(existing_info->id.bssid, bss_mac_str);
            if (std::find(seen_bssids.begin(), seen_bssids.end(), bss_mac_str) != seen_bssids.end()) {
                continue;
            }

            if (update_db(db_client, dm_orch_type_db_delete, existing_info) != 0) {
                em_printfout("Failed to delete stale BSSList row for radio %s BSSID %s",
                        radio_mac_str, bss_mac_str);
                rc = -1;
                continue;
            }
            update_list(*existing_bss, dm_orch_type_db_delete);
        }
    }

    return rc;
}

dm_orch_type_t dm_bss_list_t::get_dm_orch_type(db_client_t& db_client, const dm_bss_t& bss)
{
    dm_bss_t *pbss;
    mac_addr_str_t  bss_mac_str, radio_mac_str, dev_mac_str;
	em_2xlong_string_t key;

    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (bss.m_bss_info.id.dev_mac), dev_mac_str);
    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (bss.m_bss_info.bssid.mac), bss_mac_str);
    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (bss.m_bss_info.ruid.mac), radio_mac_str);

	snprintf(key, sizeof(em_2xlong_string_t), "%s@%s@%s@%s@%d", bss.m_bss_info.id.net_id, dev_mac_str, 
					radio_mac_str, bss_mac_str, bss.m_bss_info.id.haul_type);

    pbss = get_bss(key);

    if (pbss != NULL) {
        if (entry_exists_in_table(db_client, key) == false) {
            return dm_orch_type_db_insert;
        }

        if (*pbss == bss) {
            //em_printfout("BSS: %s Radio: %s already in list\n", 
                //dm_easy_mesh_t::macbytes_to_string(pbss->m_bss_info.bssid.mac, bss_mac_str),
                //dm_easy_mesh_t::macbytes_to_string(pbss->m_bss_info.ruid.mac, radio_mac_str));
            return dm_orch_type_none;
        }


        //em_printfout("BSS: %s Radio: %s in list but needs update\n",
            //dm_easy_mesh_t::macbytes_to_string(pbss->m_bss_info.bssid.mac, bss_mac_str),
            //dm_easy_mesh_t::macbytes_to_string(pbss->m_bss_info.ruid.mac, radio_mac_str));
        return dm_orch_type_db_update;
    }

    return (entry_exists_in_table(db_client, key) == true) ?
            dm_orch_type_db_update : dm_orch_type_db_insert;
}


void dm_bss_list_t::update_list(const dm_bss_t& bss, dm_orch_type_t op)
{
    dm_bss_t *pbss;
    mac_addr_str_t	bss_mac_str, radio_mac_str, dev_mac_str;
	em_2xlong_string_t	key;

    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (bss.m_bss_info.id.dev_mac), dev_mac_str);
    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (bss.m_bss_info.ruid.mac), radio_mac_str);
    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (bss.m_bss_info.bssid.mac), bss_mac_str);

	snprintf(key, sizeof(em_2xlong_string_t), "%s@%s@%s@%s@%d", bss.m_bss_info.id.net_id, dev_mac_str, 
					radio_mac_str, bss_mac_str, bss.m_bss_info.id.haul_type);

    switch (op) {
        case dm_orch_type_db_insert:
            put_bss(key, &bss);
            break;

        case dm_orch_type_db_update:
            pbss = get_bss(key);
            if (pbss == NULL) {
                put_bss(key, &bss);
            } else {
                memcpy(&pbss->m_bss_info, &bss.m_bss_info, sizeof(em_bss_info_t));
            }
            break;

        case dm_orch_type_db_delete:
            remove_bss(key);            
            break;

        default:
            break;
    }

}

void dm_bss_list_t::delete_list()
{       
    dm_bss_t *pbss, *tmp;
    mac_addr_str_t	bss_mac_str, radio_mac_str, dev_mac_str;
    em_2xlong_string_t key;
    
    pbss = get_first_bss();
    while (pbss != NULL) {
        tmp = pbss;
        pbss = get_next_bss(pbss);
    
        dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (tmp->m_bss_info.id.dev_mac), dev_mac_str);
        dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (tmp->m_bss_info.ruid.mac), radio_mac_str);
        dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (tmp->m_bss_info.bssid.mac), bss_mac_str);
        snprintf(key, sizeof (em_2xlong_string_t), "%s@%s@%s@%s@%d", tmp->m_bss_info.id.net_id, dev_mac_str, 
						radio_mac_str, bss_mac_str, tmp->m_bss_info.id.haul_type);

        remove_bss(key);
    }

    // Reset must not leave whitelist state behind for BSSIDs that onboard again.
    std::lock_guard<std::recursive_mutex> lock(m_acl_mutex);
    acl_clear();
    m_retained_bss_keys.clear();
}


bool dm_bss_list_t::operator == (const db_easy_mesh_t& obj)
{
    return true;
}

hash_map_t *dm_bss_list_t::get_acl_map()
{
    std::lock_guard<std::recursive_mutex> lock(m_acl_mutex);
    if (m_acl_sta_map == NULL) {
        m_acl_sta_map = hash_map_create();
    }

    return m_acl_sta_map;
}

void dm_bss_list_t::acl_clear()
{
    std::lock_guard<std::recursive_mutex> lock(m_acl_mutex);
    hash_map_t *map = m_acl_sta_map;
    em_acl_sta_t *entry, *next;
    em_3xlong_string_t acl_key;

    m_pending_acl_persistence_keys.clear();

    if (map == NULL) {
        return;
    }

    entry = static_cast<em_acl_sta_t *> (hash_map_get_first(map));
    while (entry != NULL) {
        next = static_cast<em_acl_sta_t *> (hash_map_get_next(map, entry));
        make_acl_key(entry->bss_key, entry->mac, acl_key, sizeof(acl_key));
        free(hash_map_remove(map, acl_key));
        entry = next;
    }
}

void dm_bss_list_t::make_acl_key(const char *bss_key, const unsigned char *mac, char *out, unsigned int sz)
{
    mac_addr_str_t mac_str;

    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (mac), mac_str);
    snprintf(out, sz, "%s@%s", bss_key, mac_str);
}

int dm_bss_list_t::acl_copy(const char *from_key, const char *to_key)
{
    std::lock_guard<std::recursive_mutex> lock(m_acl_mutex);
    mac_address_t macs[EM_MAX_ACL_JSON_STAS];
    unsigned int count, offset;
    const bool lists[] = {true, false};

    for (bool blocked : lists) {
        count = acl_get_macs(from_key, blocked, 0, EM_MAX_ACL_JSON_STAS, macs);
        for (offset = 0; offset < count; offset += MAX_STA_LIST) {
            unsigned char chunk = static_cast<unsigned char>(
                    (count - offset > MAX_STA_LIST) ? MAX_STA_LIST : count - offset);
            if (acl_update(to_key, blocked ? ASSOC_CONTROL_BLOCK : ASSOC_CONTROL_UNBLOCK,
                    chunk, &macs[offset]) != 0) {
                em_printfout("Failed to migrate %s ACL entries from %s to %s",
                        blocked ? "blocked" : "allowed", from_key, to_key);
                return -1;
            }
        }
    }

    return 0;
}

int dm_bss_list_t::delete_bss_row(db_client_t& db_client, const char *key)
{
    std::lock_guard<std::recursive_mutex> lock(m_acl_mutex);

    if (delete_row(db_client, key) != 0) {
        return -1;
    }
    acl_remove(key);
    m_pending_acl_persistence_keys.erase(key);
    m_retained_bss_keys.erase(key);

    return 0;
}

void dm_bss_list_t::retain_bss_row(const em_bss_info_t *info)
{
    std::lock_guard<std::recursive_mutex> lock(m_acl_mutex);
    mac_addr_str_t dev_mac_str, radio_mac_str, bss_mac_str;
    em_2xlong_string_t key;

    if (info == NULL) {
        return;
    }
    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (info->id.dev_mac), dev_mac_str);
    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (info->ruid.mac), radio_mac_str);
    dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (info->bssid.mac), bss_mac_str);
    snprintf(key, sizeof(key), "%s@%s@%s@%s@%d", info->id.net_id, dev_mac_str,
            radio_mac_str, bss_mac_str, info->id.haul_type);
    m_retained_bss_keys.insert(key);
}

int dm_bss_list_t::reconcile_retained_bss_rows(db_client_t& db_client, const unsigned char *radio_mac)
{
    std::lock_guard<std::recursive_mutex> lock(m_acl_mutex);
    std::vector<std::string> keys(m_retained_bss_keys.begin(), m_retained_bss_keys.end());
    em_bss_id_t id;
    int rc = 0;

    for (const std::string& key : keys) {
        if ((dm_bss_t::parse_bss_id_from_key(key.c_str(), &id) != 0) ||
                (memcmp(id.ruid, radio_mac, sizeof(mac_address_t)) != 0)) {
            continue;
        }
        if (get_bss(key.c_str()) != NULL) {
            // Rebuilt under the same key; its row was already rewritten.
            m_retained_bss_keys.erase(key);
            continue;
        }
        // The same BSSID may have returned under another haul type without its row having
        // been rewritten (for example set_config failed earlier). Persist the live entry now:
        // set_config moves this retained key's ACL onto it and deletes the retained row.
        bool returned = false;
        for (int haul = 0; haul < em_haul_type_max; haul++) {
            em_2xlong_string_t live_key;
            char *haul_sep;
            dm_bss_t *live_bss;

            if (haul == id.haul_type) {
                continue;
            }
            snprintf(live_key, sizeof(live_key), "%s", key.c_str());
            if ((haul_sep = strrchr(live_key, '@')) == NULL) {
                break;
            }
            snprintf(haul_sep + 1, sizeof(live_key) - static_cast<size_t>(haul_sep + 1 - live_key), "%d", haul);
            if ((live_bss = get_bss(live_key)) != NULL) {
                dm_bss_t live_copy(*live_bss);
                returned = true;
                if (set_config(db_client, live_copy, live_key) != 0) {
                    em_printfout("Failed to persist BSSList row %s replacing retained %s", live_key, key.c_str());
                    rc = -1;
                }
                break;
            }
        }
        if (returned) {
            continue;
        }
        em_printfout("Deleting BSSList row %s: BSS did not return after reconfiguration", key.c_str());
        if (delete_bss_row(db_client, key.c_str()) != 0) {
            em_printfout("Failed to delete stale BSSList row %s", key.c_str());
            rc = -1;
        }
    }

    return rc;
}

void dm_bss_list_t::acl_mark_dirty(const char *bss_key)
{
    std::lock_guard<std::recursive_mutex> lock(m_acl_mutex);
    if (bss_key != NULL) {
        m_pending_acl_persistence_keys.insert(bss_key);
    }
}

int dm_bss_list_t::acl_update(const char *bss_key, unsigned char assoc_control,
            unsigned char sta_count, const mac_address_t *sta_list)
{
    std::lock_guard<std::recursive_mutex> lock(m_acl_mutex);
    hash_map_t *map = get_acl_map();
    em_3xlong_string_t acl_key;
    em_acl_sta_t *entry;
    std::set<std::string> updated_stas;
    unsigned int blocked_count;
    unsigned int allowed_count;
    const bool blocked = (assoc_control == ASSOC_CONTROL_BLOCK);

    if ((map == NULL) || (bss_key == NULL) || (sta_list == NULL) ||
            ((assoc_control != ASSOC_CONTROL_BLOCK) && (assoc_control != ASSOC_CONTROL_UNBLOCK)) ||
            (sta_count == 0)) {
        em_printfout("Cannot update ACL: invalid BSS key, station list, control value, or map");
        return -1;
    }

    blocked_count = acl_num_macs(bss_key, true);
    allowed_count = acl_num_macs(bss_key, false);

    // Validate the final list sizes before changing any entries, including duplicate
    // station MACs in the request only once.
    for (unsigned char i = 0; i < sta_count; i++) {
        make_acl_key(bss_key, sta_list[i], acl_key, sizeof(acl_key));
        if (!updated_stas.insert(acl_key).second) {
            continue;
        }

        entry = static_cast<em_acl_sta_t *> (hash_map_get(map, acl_key));
        if (entry == NULL) {
            blocked ? ++blocked_count : ++allowed_count;
        } else if (entry->blocked != blocked) {
            if (entry->blocked) {
                --blocked_count;
                ++allowed_count;
            } else {
                --allowed_count;
                ++blocked_count;
            }
        }
    }

    if ((blocked_count > EM_MAX_ACL_JSON_STAS) || (allowed_count > EM_MAX_ACL_JSON_STAS)) {
        em_printfout("ACL list limit reached for BSS %s; update rejected without applying partial changes", bss_key);
        return -1;
    }

    for (unsigned char i = 0; i < sta_count; i++) {
        make_acl_key(bss_key, sta_list[i], acl_key, sizeof(acl_key));
        entry = static_cast<em_acl_sta_t *> (hash_map_get(map, acl_key));
        if (entry == NULL) {
            entry = static_cast<em_acl_sta_t *> (calloc(1, sizeof(em_acl_sta_t)));
            if (entry == NULL) {
                em_printfout("Failed to allocate ACL entry for BSS %s", bss_key);
                return -1;
            }
            snprintf(entry->bss_key, sizeof(entry->bss_key), "%s", bss_key);
            memcpy(entry->mac, sta_list[i], sizeof(mac_address_t));
            char *key_copy = strdup(acl_key);
            if (key_copy == NULL) {
                free(entry);
                em_printfout("Failed to allocate ACL key for BSS %s", bss_key);
                return -1;
            }
            if (acl_map_insert(map, key_copy, entry) != 0) {
                free(key_copy);
                free(entry);
                em_printfout("Failed to insert ACL entry for BSS %s", bss_key);
                return -1;
            }
        }
        entry->blocked = blocked;
    }

    acl_mark_dirty(bss_key);
    return 0;
}

bool dm_bss_list_t::acl_can_update(const char *bss_key, unsigned char assoc_control,
            unsigned char sta_count, const mac_address_t *sta_list)
{
    std::lock_guard<std::recursive_mutex> lock(m_acl_mutex);
    em_3xlong_string_t acl_key;
    std::set<std::string> updated_stas;
    unsigned int blocked_count;
    unsigned int allowed_count;
    const bool blocked = (assoc_control == ASSOC_CONTROL_BLOCK);

    if ((bss_key == NULL) || (sta_list == NULL) || (sta_count == 0) ||
            ((assoc_control != ASSOC_CONTROL_BLOCK) && (assoc_control != ASSOC_CONTROL_UNBLOCK))) {
        return false;
    }

    blocked_count = acl_num_macs(bss_key, true);
    allowed_count = acl_num_macs(bss_key, false);
    for (unsigned char i = 0; i < sta_count; i++) {
        make_acl_key(bss_key, sta_list[i], acl_key, sizeof(acl_key));
        if (!updated_stas.insert(acl_key).second) {
            continue;
        }
        em_acl_sta_t *entry = static_cast<em_acl_sta_t *>(
            (m_acl_sta_map != NULL) ? hash_map_get(m_acl_sta_map, acl_key) : NULL);
        if (entry == NULL) {
            blocked ? ++blocked_count : ++allowed_count;
        } else if (entry->blocked != blocked) {
            if (entry->blocked) {
                --blocked_count;
                ++allowed_count;
            } else {
                --allowed_count;
                ++blocked_count;
            }
        }
    }

    return (blocked_count <= EM_MAX_ACL_JSON_STAS) &&
        (allowed_count <= EM_MAX_ACL_JSON_STAS);
}

int dm_bss_list_t::acl_remove_stas(const char *bss_key, unsigned char sta_count,
            const mac_address_t *sta_list)
{
    std::lock_guard<std::recursive_mutex> lock(m_acl_mutex);
    hash_map_t *map = m_acl_sta_map;
    em_3xlong_string_t acl_key;

    if ((bss_key == NULL) || ((sta_count > 0) && (sta_list == NULL))) {
        em_printfout("Cannot remove ACL entries: invalid BSS key or station list");
        return -1;
    }

    if (map != NULL) {
        for (unsigned char i = 0; i < sta_count; i++) {
            make_acl_key(bss_key, sta_list[i], acl_key, sizeof(acl_key));
            free(hash_map_remove(map, acl_key));
        }
    }

    if (sta_count > 0) {
        acl_mark_dirty(bss_key);
    }

    return 0;
}

unsigned int dm_bss_list_t::acl_num_macs(const char *bss_key, bool blocked)
{
    std::lock_guard<std::recursive_mutex> lock(m_acl_mutex);
    return acl_get_macs(bss_key, blocked, 0, 0xFFFFFFFFU, NULL);
}

unsigned int dm_bss_list_t::acl_get_macs(const char *bss_key, bool blocked, unsigned int skip,
            unsigned int max, mac_address_t *list)
{
    std::lock_guard<std::recursive_mutex> lock(m_acl_mutex);
    hash_map_t *map = m_acl_sta_map;
    em_acl_sta_t *entry;
    unsigned int matched = 0, copied = 0;

    if ((map == NULL) || (bss_key == NULL)) {
        return 0;
    }

    entry = static_cast<em_acl_sta_t *> (hash_map_get_first(map));
    while ((entry != NULL) && (copied < max)) {
        if ((entry->blocked == blocked) && (strcmp(entry->bss_key, bss_key) == 0)) {
            if (matched >= skip) {
                if (list != NULL) {
                    memcpy(list[copied], entry->mac, sizeof(mac_address_t));
                }
                copied++;
            }
            matched++;
        }
        entry = static_cast<em_acl_sta_t *> (hash_map_get_next(map, entry));
    }

    return (list == NULL) ? matched : copied;
}

void dm_bss_list_t::acl_to_string(const char *bss_key, bool blocked, char *str, unsigned int sz)
{
    std::lock_guard<std::recursive_mutex> lock(m_acl_mutex);
    hash_map_t *map = m_acl_sta_map;
    em_acl_sta_t *entry;
    mac_addr_str_t mac_str;

    str[0] = 0;
    if ((map == NULL) || (bss_key == NULL)) {
        return;
    }

    entry = static_cast<em_acl_sta_t *> (hash_map_get_first(map));
    while (entry != NULL) {
        if ((entry->blocked == blocked) && (strcmp(entry->bss_key, bss_key) == 0)) {
            unsigned int used = static_cast<unsigned int> (strlen(str));
            if (used + 1 >= sz) {
                break;
            }
            dm_easy_mesh_t::macbytes_to_string(entry->mac, mac_str);
            snprintf(str + used, sz - used, "%s%s", (used == 0) ? "" : ",", mac_str);
        }
        entry = static_cast<em_acl_sta_t *> (hash_map_get_next(map, entry));
    }
}

void dm_bss_list_t::acl_from_string(const char *bss_key, bool blocked, const char *str)
{
    std::lock_guard<std::recursive_mutex> lock(m_acl_mutex);
    char copy[EM_MAX_ACL_LIST_CHARS + 1];
    mac_address_t mac;
    char *save = NULL, *token;

    if ((str == NULL) || (*str == 0)) {
        return;
    }

    snprintf(copy, sizeof(copy), "%s", str);

    token = strtok_r(copy, ",", &save);
    while (token != NULL) {
        if (strlen(token) != 0) {
            dm_easy_mesh_t::string_to_macbytes(token, mac);
            if (acl_update(bss_key, blocked ? ASSOC_CONTROL_BLOCK : ASSOC_CONTROL_UNBLOCK, 1, &mac) != 0) {
                em_printfout("Failed to load persisted ACL entry for BSS %s", bss_key);
            }
        }
        token = strtok_r(NULL, ",", &save);
    }
}

void dm_bss_list_t::acl_remove(const char *bss_key)
{
    std::lock_guard<std::recursive_mutex> lock(m_acl_mutex);
    hash_map_t *map = m_acl_sta_map;
    em_acl_sta_t *entry, *tmp;
    em_3xlong_string_t acl_key;

    if ((map == NULL) || (bss_key == NULL)) {
        return;
    }

    entry = static_cast<em_acl_sta_t *> (hash_map_get_first(map));
    while (entry != NULL) {
        tmp = entry;
        entry = static_cast<em_acl_sta_t *> (hash_map_get_next(map, entry));

        if (strcmp(tmp->bss_key, bss_key) == 0) {
            make_acl_key(bss_key, tmp->mac, acl_key, sizeof(acl_key));
            free(hash_map_remove(map, acl_key));
        }
    }
}

int dm_bss_list_t::update_db(db_client_t& db_client, dm_orch_type_t op, void *data)
{
    std::lock_guard<std::recursive_mutex> lock(m_acl_mutex);
    mac_addr_str_t dev_mac_str, bss_mac_str, radio_mac_str;
    em_bss_info_t *info = static_cast<em_bss_info_t *> (data);
    int ret = 0;
    unsigned int i;
	em_2xlong_string_t key;
    em_long_string_t	front_akms, back_akms;
    char blocked_macs[EM_MAX_ACL_LIST_CHARS + 1];
    char allowed_macs[EM_MAX_ACL_LIST_CHARS + 1];
        const char *mac_filter_mode = (info->acl_filter_mode == EM_ACL_MODE_WHITELIST) ?
            "whitelist" : (info->acl_filter_mode == EM_ACL_MODE_BLACKLIST) ? "blacklist" : "No Info";
        
	dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (info->id.dev_mac), dev_mac_str);
	dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (info->ruid.mac), radio_mac_str);
	dm_easy_mesh_t::macbytes_to_string(const_cast<unsigned char *> (info->bssid.mac), bss_mac_str);
	snprintf(key, sizeof (em_2xlong_string_t), "%s@%s@%s@%s@%d", info->id.net_id, dev_mac_str, 
					radio_mac_str, bss_mac_str, info->id.haul_type);

    //printf("dm_bss_list_t:%s:%d: Operation: %s\n", __func__, __LINE__, em_cmd_t::get_orch_op_str(op));
    memset(front_akms, 0, sizeof(em_long_string_t));
    for (i = 0; i < info->num_fronthaul_akms; i++) {
        strncat(front_akms, info->fronthaul_akm[i], strlen(info->fronthaul_akm[i]));
        strncat(front_akms, ",", strlen(",") + 1);
    }
    memset(back_akms, 0, sizeof(em_long_string_t));
    for (i = 0; i < info->num_backhaul_akms; i++) {
        strncat(back_akms, info->backhaul_akm[i], strlen(info->backhaul_akm[i]));
        strncat(back_akms, ",", strlen(",") + 1);
    }

    acl_to_string(key, true, blocked_macs, sizeof(blocked_macs));
    acl_to_string(key, false, allowed_macs, sizeof(allowed_macs));
	
	switch (op) {
		case dm_orch_type_db_insert:
			ret = insert_row(db_client, key, dm_easy_mesh_t::macbytes_to_string(info->bssid.mac, bss_mac_str),
						dm_easy_mesh_t::macbytes_to_string(info->ruid.mac, radio_mac_str), info->ssid, info->enabled,
						info->est_svc_params_be, info->est_svc_params_bk, info->est_svc_params_vi, info->est_svc_params_vo,
						front_akms, back_akms, info->profile_1b_sta_allowed, info->profile_2b_sta_allowed, info->assoc_allowed_status,
						info->backhaul_use, info->fronthaul_use, info->r1_disallowed, info->r2_disallowed, 
						info->multi_bssid, info->transmitted_bssid, info->vlan_id,
                        mac_filter_mode, info->acl_validity_period, blocked_macs, allowed_macs);
							
			break;

		case dm_orch_type_db_update:
			ret = update_row(db_client, dm_easy_mesh_t::macbytes_to_string(info->bssid.mac, bss_mac_str),
                        dm_easy_mesh_t::macbytes_to_string(info->ruid.mac, radio_mac_str), info->ssid, info->enabled,
                        info->est_svc_params_be, info->est_svc_params_bk, info->est_svc_params_vi, info->est_svc_params_vo,
                        front_akms, back_akms, info->profile_1b_sta_allowed, info->profile_2b_sta_allowed, info->assoc_allowed_status,
                        info->backhaul_use, info->fronthaul_use, info->r1_disallowed, info->r2_disallowed, 
                        info->multi_bssid, info->transmitted_bssid, info->vlan_id,
                        mac_filter_mode, info->acl_validity_period, blocked_macs, allowed_macs, key);
			break;

		case dm_orch_type_db_delete:
			ret = delete_row(db_client, key);
            if (ret == 0) {
                acl_remove(key);
		        m_pending_acl_persistence_keys.erase(key);
		    }
			break;

		default:
			break;
	}

    return ret;
}

bool dm_bss_list_t::search_db(db_client_t& db_client, void *ctx, void *key)
{
    em_long_string_t str = {};
    bool found = false;

    if (key == NULL) {
        while (db_client.next_result(ctx)) {
        }
        return false;
    }

    // Drain all rows so next_result() frees the result set
    while (db_client.next_result(ctx)) {
        if (db_client.get_string(ctx, str, 1) != NULL &&
                strcmp(str, static_cast<char *> (key)) == 0) {
            found = true;
        }
    }

    return found;
}

int dm_bss_list_t::sync_db(db_client_t& db_client, void *ctx)
{
    std::lock_guard<std::recursive_mutex> lock(m_acl_mutex);
    em_bss_info_t info;
    mac_addr_str_t	mac;
    em_long_string_t   str;
    em_2xlong_string_t bss_key;
    char acl_str[EM_MAX_ACL_LIST_CHARS + 1];
    char mac_filter_mode[10];
    unsigned int i;
    char   *token_parts[EM_MAX_AKMS];
    mac_address_t zero_mac = {0};
    std::vector<std::string> invalid_bss_ids;
    int rc = 0;
    unsigned int row = 0;

    // sync_table() reports query failures; a NULL context here is an empty BSSList.
    acl_clear();

    while (db_client.next_result(ctx)) {
        memset(&info, 0, sizeof(em_bss_info_t));

        row++;
        db_client.get_string(ctx, str, 1, sizeof(str));
		dm_bss_t::parse_bss_id_from_key(str, &info.id);
        snprintf(bss_key, sizeof(bss_key), "%s", str);

        db_client.get_string(ctx, mac, 2);
        dm_easy_mesh_t::string_to_macbytes(mac, info.bssid.mac);

        db_client.get_string(ctx, mac, 3);
        dm_easy_mesh_t::string_to_macbytes(mac, info.ruid.mac);

        db_client.get_string(ctx, info.ssid, 4);
        info.enabled = db_client.get_number(ctx, 5);

        if ((static_cast<unsigned int>(info.id.haul_type) >= em_haul_type_max) ||
                (memcmp(info.bssid.mac, zero_mac, sizeof(mac_address_t)) == 0) ||
                (memcmp(info.ruid.mac, zero_mac, sizeof(mac_address_t)) == 0) ||
                (info.ssid[0] == '\0')) {
            invalid_bss_ids.emplace_back(bss_key);
            continue;
        }

        db_client.get_string(ctx, info.est_svc_params_be, 6);
        db_client.get_string(ctx, info.est_svc_params_bk, 7);
        db_client.get_string(ctx, info.est_svc_params_vi, 8);
        db_client.get_string(ctx, info.est_svc_params_vo, 9);

        db_client.get_string(ctx, str, 10);
        for (i = 0; i < EM_MAX_AKMS; i++) {
            token_parts[i] = info.fronthaul_akm[i];
        }
        info.num_fronthaul_akms = static_cast<unsigned char> (get_strings_by_token(str, ',', EM_MAX_AKMS, token_parts));

        db_client.get_string(ctx, str, 11);

        for (i = 0; i < EM_MAX_AKMS; i++) {
            token_parts[i] = info.backhaul_akm[i];
        }
        info.num_backhaul_akms = static_cast<unsigned char> (get_strings_by_token(str, ',', EM_MAX_AKMS, token_parts));

        info.profile_1b_sta_allowed = db_client.get_number(ctx, 12);
        info.profile_2b_sta_allowed = db_client.get_number(ctx, 13);
        info.assoc_allowed_status = static_cast<unsigned int> (db_client.get_number(ctx, 14));
        info.backhaul_use = db_client.get_number(ctx, 15);
        info.fronthaul_use = db_client.get_number(ctx, 16);
        info.r1_disallowed = db_client.get_number(ctx, 17);
        info.r2_disallowed = db_client.get_number(ctx, 18);
        info.multi_bssid = db_client.get_number(ctx, 19);
        info.transmitted_bssid = db_client.get_number(ctx, 20);
        info.vlan_id = static_cast<unsigned int> (db_client.get_number(ctx, 21));

        memset(mac_filter_mode, 0, sizeof(mac_filter_mode));
        db_client.get_string(ctx, mac_filter_mode, 22, sizeof(mac_filter_mode));
        if (strcmp(mac_filter_mode, "whitelist") == 0 || strcmp(mac_filter_mode, "1") == 0) {
            info.acl_filter_mode = EM_ACL_MODE_WHITELIST;
        } else if (strcmp(mac_filter_mode, "blacklist") == 0 || strcmp(mac_filter_mode, "0") == 0) {
            info.acl_filter_mode = EM_ACL_MODE_BLACKLIST;
        } else {
            info.acl_filter_mode = EM_ACL_MODE_UNKNOWN;
        }
        info.acl_validity_period = static_cast<unsigned short> (db_client.get_number(ctx, 23));

        memset(acl_str, 0, sizeof(acl_str));
        db_client.get_string(ctx, acl_str, 24, sizeof(acl_str));
        if (info.acl_validity_period == 0) {
            acl_from_string(bss_key, true, acl_str);
        }

        memset(acl_str, 0, sizeof(acl_str));
        db_client.get_string(ctx, acl_str, 25, sizeof(acl_str));
        if (info.acl_validity_period == 0) {
            acl_from_string(bss_key, false, acl_str);
        }

        update_list(dm_bss_t(&info), dm_orch_type_db_insert);
    }

    for (const std::string& bss_id : invalid_bss_ids) {
        if (delete_row(db_client, bss_id.c_str()) != 0) {
            em_printfout("Failed to remove invalid BSSList row %s", bss_id.c_str());
            rc = -1;
        }
    }

    // Loading from the DB is not a change that needs writing back
    m_pending_acl_persistence_keys.clear();

    return rc;

}

void dm_bss_list_t::init_table()
{
    snprintf(m_table_name, sizeof(m_table_name), "%s", "BSSList");
}

void dm_bss_list_t::init_columns()
{
    m_num_cols = 0;

    m_columns[m_num_cols++] = db_column_t("ID", db_data_type_char, 128);
	m_columns[m_num_cols++] = db_column_t("BSSID", db_data_type_char, 17);
	m_columns[m_num_cols++] = db_column_t("RUID", db_data_type_char, 17);
    m_columns[m_num_cols++] = db_column_t("SSID", db_data_type_char, 32);
    m_columns[m_num_cols++] = db_column_t("Enabled", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("EstServiceParametersBE", db_data_type_char, 16);
    m_columns[m_num_cols++] = db_column_t("EstServiceParametersBK", db_data_type_char, 16);
    m_columns[m_num_cols++] = db_column_t("EstServiceParametersVI", db_data_type_char, 16);
    m_columns[m_num_cols++] = db_column_t("EstServiceParametersVO", db_data_type_char, 16);
    m_columns[m_num_cols++] = db_column_t("FronthaulAKMsAllowed", db_data_type_char, 64);
    m_columns[m_num_cols++] = db_column_t("BackhaulAKMsAllowed", db_data_type_char, 64);
    m_columns[m_num_cols++] = db_column_t("Profile1bSTAsDisallowed", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("Profile2bSTAsDisallowed", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("AssociationAllowanceStatus", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("FronthaulUse", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("BackhaulUse", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("R1disallowed", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("R2disallowed", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("MultiBSSID", db_data_type_tinyint, 0);
    m_columns[m_num_cols++] = db_column_t("TransmittedBSSID", db_data_type_tinyint, 0);
    // VLAN ID Range 1 to 4094 IEEE 802.1Q standard
    m_columns[m_num_cols++] = db_column_t("VlanID", db_data_type_smallint, 0);
    // MACFilterMode stores "blacklist" or "whitelist".
    m_columns[m_num_cols++] = db_column_t("MACFilterMode", db_data_type_char, 9);
    m_columns[m_num_cols++] = db_column_t("ACLValidityPeriod", db_data_type_int, 0);
    m_columns[m_num_cols++] = db_column_t("MACsDisallowed", db_data_type_varchar, EM_MAX_ACL_LIST_CHARS);
    m_columns[m_num_cols++] = db_column_t("MACsAllowed", db_data_type_varchar, EM_MAX_ACL_LIST_CHARS);
}

int dm_bss_list_t::init()
{
    init_table();
    init_columns();
    return 0;
}
