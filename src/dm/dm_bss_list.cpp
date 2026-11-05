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
#include <mutex>
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
#include "util.h"

// The ACL map is mutated by the orchestration thread (CACR persistence) and read by the em
// state-machine thread (ACL replay), so every acl_* access takes this lock. File-static because
// the ACL map is shared by all dm_bss_list_t users; recursive because acl_update() calls acl_num_macs().
static std::recursive_mutex g_acl_mutex;

static time_t acl_now()
{
    struct timespec ts;
    util::monotonic_now(&ts);
    return ts.tv_sec;
}

// A timed block whose period has run out is treated as absent everywhere.
static bool acl_entry_live(const em_acl_sta_t *entry, time_t now)
{
    return !(entry->blocked && (entry->expiry != 0) && (entry->expiry <= now));
}

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

dm_bss_list_t::~dm_bss_list_t()
{
    std::lock_guard<std::recursive_mutex> lock(g_acl_mutex);
    acl_clear();
    hash_map_destroy(m_acl_sta_map);
    m_acl_sta_map = NULL;
}

void dm_bss_list_t::encode_acl(dm_bss_t *pbss, cJSON *obj)
{
    mac_addr_str_t mac_str;
    em_2xlong_string_t key;
    mac_address_t macs[EM_MAX_ACL_JSON_STAS];
    unsigned int num, i;

    dm_bss_t::make_bss_key(&pbss->m_bss_info, key, sizeof(key));

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
    dm_orch_type_t op;  
    int rc;
    em_2xlong_string_t new_key, old_key;
    mac_address_t blocked_macs[EM_MAX_ACL_JSON_STAS];
    unsigned short blocked_remaining[EM_MAX_ACL_JSON_STAS];
    mac_address_t allowed_macs[EM_MAX_ACL_JSON_STAS];
    unsigned int blocked_count, allowed_count, offset;
    std::vector<dm_bss_t> stale_bsses;
    std::vector<std::string> stale_bss_keys;
    dm_bss_t *existing_bss;
    em_bss_info_t *existing_info;

    //printf("%s:%d: Parent: %s \n", __func__, __LINE__, (char *)parent_id);
	parse_bss_id_from_key(static_cast<char *> (parent_id), &bss.m_bss_info.id);
    if (bss.m_bss_info.vap_mode != em_vap_mode_ap) {
        return 0;
    }
    if ((bss.m_bss_info.id.haul_type >= em_haul_type_max) ||
            (memcmp(bss.m_bss_info.bssid.mac, ZERO_MAC_ADDR, sizeof(mac_address_t)) == 0) ||
            (memcmp(bss.m_bss_info.ruid.mac, ZERO_MAC_ADDR, sizeof(mac_address_t)) == 0)) {
        return -1;
    }
    snprintf(new_key, sizeof(new_key), "%s", static_cast<char *>(parent_id));

    // Haul type is part of the row ID, so remove an older key for this same interface
    // before inserting its corrected haul type. A BSS already stored under its key (the usual
    // case) has nothing to migrate, so the whole list is only scanned for a new key.
    for (existing_bss = (get_bss(new_key) == NULL) ? get_first_bss() : NULL; existing_bss != NULL;
            existing_bss = get_next_bss(existing_bss)) {
            existing_info = existing_bss->get_bss_info();
            if ((existing_info->id.haul_type == bss.m_bss_info.id.haul_type) ||
                    (strcmp(existing_info->id.net_id, bss.m_bss_info.id.net_id) != 0) ||
                    (memcmp(existing_info->id.dev_mac, bss.m_bss_info.id.dev_mac, sizeof(mac_address_t)) != 0) ||
                    (memcmp(existing_info->id.ruid, bss.m_bss_info.id.ruid, sizeof(mac_address_t)) != 0) ||
                    (memcmp(existing_info->id.bssid, bss.m_bss_info.id.bssid, sizeof(mac_address_t)) != 0)) {
                continue;
            }

            dm_bss_t::make_bss_key(existing_info->id.net_id, existing_info->id.dev_mac,
                    existing_info->id.ruid, existing_info->id.bssid, existing_info->id.haul_type,
                    old_key, sizeof(old_key));

            blocked_count = acl_get_macs(old_key, true, 0, EM_MAX_ACL_JSON_STAS, blocked_macs,
                    blocked_remaining);
            allowed_count = acl_get_macs(old_key, false, 0, EM_MAX_ACL_JSON_STAS, allowed_macs);
            stale_bsses.emplace_back(*existing_bss);
            stale_bss_keys.emplace_back(old_key);

            // One entry at a time so each block keeps its own remaining time (0 = permanent)
            for (offset = 0; offset < blocked_count; offset++) {
                if (acl_update(new_key, ASSOC_CONTROL_BLOCK, 1, &blocked_macs[offset],
                        blocked_remaining[offset]) != 0) {
                    em_printfout("Failed to migrate blocked ACL entries from %s to %s", old_key, new_key);
                    return -1;
                }
            }
            for (offset = 0; offset < allowed_count; offset += MAX_STA_LIST) {
                unsigned char count = static_cast<unsigned char>(
                        (allowed_count - offset > MAX_STA_LIST) ? MAX_STA_LIST : allowed_count - offset);
                if (acl_update(new_key, ASSOC_CONTROL_UNBLOCK, count, &allowed_macs[offset]) != 0) {
                    em_printfout("Failed to migrate allowed ACL entries from %s to %s", old_key, new_key);
                    return -1;
                }
            }
    }

    op = get_dm_orch_type(db_client, bss);
    rc = update_db(db_client, op, bss.get_bss_info());
    if (rc != 0) {
        return rc;
    }
    update_list(bss, op);

    for (size_t stale_index = 0; stale_index < stale_bsses.size(); stale_index++) {
        dm_bss_t& stale_bss = stale_bsses[stale_index];
        acl_remove(stale_bss_keys[stale_index].c_str());
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
    cJSON *obj;
    int size;
    dm_bss_t bss;
    mac_addr_str_t radio_mac_str, bss_mac_str;
    em_2xlong_string_t bss_key;
    std::vector<std::string> seen_bssids;
    std::vector<em_bss_info_t> stale;
    dm_bss_t *existing_bss;
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
                (memcmp(bss.m_bss_info.bssid.mac, ZERO_MAC_ADDR, sizeof(mac_address_t)) == 0)) {
            em_printfout("Ignoring BSSList entry %d with invalid haul type or BSSID from radio %s",
                    i, radio_mac_str);
            snapshot_complete = false;
            continue;
        }

        dm_easy_mesh_t::macbytes_to_string(bss.m_bss_info.bssid.mac, bss_mac_str);
        seen_bssids.emplace_back(bss_mac_str);
        dm_bss_t::make_bss_key(GLOBAL_NET_ID, *dev_mac, *radio_mac, bss.m_bss_info.bssid.mac,
                bss.m_bss_info.id.haul_type, bss_key, sizeof(bss_key));
        if (set_config(db_client, bss, bss_key) != 0) {
            em_printfout("Failed to update BSSList row %s", bss_key);
            rc = -1;
        }
    }

    if ((rc == 0) && snapshot_complete && !seen_bssids.empty()) {
        // Collect first and delete afterwards: a delete shifts the list, so deleting while
        // walking it would skip the entry that moves into the freed slot
        for (existing_bss = get_first_bss(); existing_bss != NULL; existing_bss = get_next_bss(existing_bss)) {
            existing_info = existing_bss->get_bss_info();
            if ((strcmp(existing_info->id.net_id, GLOBAL_NET_ID) != 0) ||
                    (memcmp(existing_info->id.dev_mac, *dev_mac, sizeof(mac_address_t)) != 0) ||
                    (memcmp(existing_info->id.ruid, *radio_mac, sizeof(mac_address_t)) != 0)) {
                continue;
            }

            dm_easy_mesh_t::macbytes_to_string(existing_info->id.bssid, bss_mac_str);
            if (std::find(seen_bssids.begin(), seen_bssids.end(), bss_mac_str) != seen_bssids.end()) {
                continue;
            }

            dm_bss_t::make_bss_key(existing_info, bss_key, sizeof(bss_key));
            // Same rule as update_tables: a BSS carrying an ACL stays in the DB and in memory, so
            // its persisted ACL is never lost; it is only marked not operational until reported again
            if ((acl_num_macs(bss_key, true) + acl_num_macs(bss_key, false)) > 0) {
                if (existing_info->enabled) {
                    existing_info->enabled = false;
                    if (update_db(db_client, dm_orch_type_db_update, existing_info) != 0) {
                        em_printfout("Failed to mark kept BSSList row %s not operational", bss_key);
                        rc = -1;
                    }
                }
                continue;
            }
            stale.push_back(*existing_info);
        }

        for (em_bss_info_t& info : stale) {
            if (update_db(db_client, dm_orch_type_db_delete, &info) != 0) {
                em_printfout("Failed to delete stale BSSList row for radio %s BSSID %s", radio_mac_str,
                        dm_easy_mesh_t::macbytes_to_string(info.bssid.mac, bss_mac_str));
                rc = -1;
                continue;
            }
            update_list(dm_bss_t(&info), dm_orch_type_db_delete);
        }
    }

    return rc;
}

dm_orch_type_t dm_bss_list_t::get_dm_orch_type(db_client_t& db_client, const dm_bss_t& bss)
{
    dm_bss_t *pbss;
	em_2xlong_string_t key;

    dm_bss_t::make_bss_key(&bss.m_bss_info, key, sizeof(key));

    pbss = get_bss(key);

    if (pbss != NULL) {
        if (entry_exists_in_table(db_client, key) == false) {
            return dm_orch_type_db_insert;
        }

        // The controller list hands back the device DM's own entry, so an in-place change can't be diffed.
        if (pbss == &bss) {
            return dm_orch_type_db_update;
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
	em_2xlong_string_t	key;

    dm_bss_t::make_bss_key(&bss.m_bss_info, key, sizeof(key));

    switch (op) {
        case dm_orch_type_db_insert:
            put_bss(key, &bss);
            break;

        case dm_orch_type_db_update:
            pbss = get_bss(key);
            if (pbss == NULL) {
                put_bss(key, &bss);
            } else if (pbss != &bss) {
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
    em_2xlong_string_t key;
    
    // Only a reset gets here, and it drops the table too, so sync_db will not clear this map
    acl_clear();

    pbss = get_first_bss();
    while (pbss != NULL) {
        tmp = pbss;
        pbss = get_next_bss(pbss);
    
        dm_bss_t::make_bss_key(&tmp->m_bss_info, key, sizeof(key));

        remove_bss(key);
    }
}   


bool dm_bss_list_t::operator == (const db_easy_mesh_t& obj)
{
    return true;
}

hash_map_t *dm_bss_list_t::get_acl_map()
{
    std::lock_guard<std::recursive_mutex> lock(g_acl_mutex);
    if (m_acl_sta_map == NULL) {
        m_acl_sta_map = hash_map_create();
    }

    return m_acl_sta_map;
}

void dm_bss_list_t::acl_clear()
{
    std::lock_guard<std::recursive_mutex> lock(g_acl_mutex);
    hash_map_t *map = m_acl_sta_map;
    em_acl_sta_t *entry, *next;
    em_3xlong_string_t acl_key;

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

int dm_bss_list_t::acl_update(const char *bss_key, unsigned char assoc_control,
            unsigned char sta_count, const mac_address_t *sta_list, unsigned short validity_period)
{
    std::lock_guard<std::recursive_mutex> lock(g_acl_mutex);
    hash_map_t *map = get_acl_map();
    em_3xlong_string_t acl_key;
    em_acl_sta_t *entry;

    if ((map == NULL) || (bss_key == NULL) || (sta_list == NULL) ||
            ((assoc_control != ASSOC_CONTROL_BLOCK) && (assoc_control != ASSOC_CONTROL_UNBLOCK)) ||
            (sta_count == 0)) {
        em_printfout("Cannot update ACL: invalid BSS key, station list, control value, or map");
        return -1;
    }

    // All or nothing: a request the list cannot take (limit, memory) must leave the ACL as it was,
    // or a multi-STA CACR that is then refused would still have changed some of its STAs
    bool blocked = (assoc_control == ASSOC_CONTROL_BLOCK);
    std::vector<em_acl_sta_t *> fresh;
    std::vector<char *> fresh_keys;
    unsigned int joining = 0;

    auto release = [&fresh, &fresh_keys](size_t from) {
        for (size_t k = from; k < fresh.size(); k++) {
            free(fresh[k]);
            free(fresh_keys[k]);
        }
    };

    for (unsigned char i = 0; i < sta_count; i++) {
        bool repeated = false;
        for (unsigned char j = 0; (j < i) && !repeated; j++) {
            repeated = (memcmp(sta_list[j], sta_list[i], sizeof(mac_address_t)) == 0);
        }
        if (repeated) {
            continue;
        }
        make_acl_key(bss_key, sta_list[i], acl_key, sizeof(acl_key));
        entry = static_cast<em_acl_sta_t *> (hash_map_get(map, acl_key));
        if ((entry != NULL) && (entry->blocked == blocked)) {
            continue;
        }
        joining++;
        if (entry != NULL) {
            continue;
        }
        em_acl_sta_t *added = static_cast<em_acl_sta_t *> (calloc(1, sizeof(em_acl_sta_t)));
        char *key_copy = strdup(acl_key);
        if ((added == NULL) || (key_copy == NULL)) {
            free(added);
            free(key_copy);
            release(0);
            em_printfout("Failed to allocate ACL entry for BSS %s", bss_key);
            return -1;
        }
        snprintf(added->bss_key, sizeof(added->bss_key), "%s", bss_key);
        memcpy(added->mac, sta_list[i], sizeof(mac_address_t));
        fresh.push_back(added);
        fresh_keys.push_back(key_copy);
    }
    if ((acl_num_macs(bss_key, blocked) + joining) > EM_MAX_ACL_JSON_STAS) {
        release(0);
        em_printfout("ACL list limit reached for BSS %s (%u more needed)", bss_key, joining);
        return -1;
    }

    for (size_t k = 0; k < fresh.size(); k++) {
        if (acl_map_insert(map, fresh_keys[k], fresh[k]) != 0) {
            // Take back what this call inserted; the existing entries are untouched so far
            for (size_t m = 0; m < k; m++) {
                make_acl_key(bss_key, fresh[m]->mac, acl_key, sizeof(acl_key));
                free(hash_map_remove(map, acl_key));
            }
            release(k);
            em_printfout("Failed to insert ACL entry for BSS %s", bss_key);
            return -1;
        }
    }

    // Nothing can fail from here
    for (unsigned char i = 0; i < sta_count; i++) {
        make_acl_key(bss_key, sta_list[i], acl_key, sizeof(acl_key));
        entry = static_cast<em_acl_sta_t *> (hash_map_get(map, acl_key));
        if (entry == NULL) {
            continue;
        }
        entry->blocked = blocked;
        entry->period = blocked ? validity_period : 0;
        entry->expiry = (blocked && (validity_period > 0)) ? (acl_now() + validity_period) : 0;
    }

    return 0;
}

void dm_bss_list_t::acl_save(const char *bss_key, unsigned char sta_count,
            const mac_address_t *sta_list, em_acl_undo_t *undo)
{
    std::lock_guard<std::recursive_mutex> lock(g_acl_mutex);
    hash_map_t *map = get_acl_map();
    em_3xlong_string_t acl_key;

    memset(undo, 0, sizeof(*undo));
    for (unsigned char i = 0; (i < sta_count) && (sta_list != NULL) && (undo->count < MAX_STA_LIST); i++) {
        em_acl_undo_sta_t *s = &undo->sta[undo->count++];
        em_acl_sta_t *entry = NULL;

        memcpy(s->mac, sta_list[i], sizeof(mac_address_t));
        if ((map != NULL) && (bss_key != NULL)) {
            make_acl_key(bss_key, sta_list[i], acl_key, sizeof(acl_key));
            entry = static_cast<em_acl_sta_t *> (hash_map_get(map, acl_key));
        }
        if (entry != NULL) {
            s->existed = true;
            s->blocked = entry->blocked;
            s->period = entry->period;
            s->expiry = entry->expiry;
        }
    }
}

void dm_bss_list_t::acl_restore(const char *bss_key, const em_acl_undo_t *undo)
{
    std::lock_guard<std::recursive_mutex> lock(g_acl_mutex);
    hash_map_t *map = get_acl_map();
    em_3xlong_string_t acl_key;

    if ((map == NULL) || (bss_key == NULL) || (undo == NULL)) {
        return;
    }
    // Backwards, so a STA listed twice ends with the state recorded first
    for (int i = static_cast<int>(undo->count) - 1; i >= 0; i--) {
        const em_acl_undo_sta_t *s = &undo->sta[i];

        make_acl_key(bss_key, s->mac, acl_key, sizeof(acl_key));
        em_acl_sta_t *entry = static_cast<em_acl_sta_t *> (hash_map_get(map, acl_key));
        if (!s->existed) {
            free(hash_map_remove(map, acl_key));
            continue;
        }
        if (entry == NULL) {
            char *key_copy = strdup(acl_key);
            entry = static_cast<em_acl_sta_t *> (calloc(1, sizeof(em_acl_sta_t)));
            if ((entry == NULL) || (key_copy == NULL) || (acl_map_insert(map, key_copy, entry) != 0)) {
                free(entry);
                free(key_copy);
                em_printfout("Failed to restore ACL entry on BSS %s", bss_key);
                continue;
            }
            snprintf(entry->bss_key, sizeof(entry->bss_key), "%s", bss_key);
            memcpy(entry->mac, s->mac, sizeof(mac_address_t));
        }
        entry->blocked = s->blocked;
        entry->period = s->period;
        entry->expiry = s->expiry;
    }
}

int dm_bss_list_t::acl_remove_stas(const char *bss_key, unsigned char sta_count,
            const mac_address_t *sta_list)
{
    std::lock_guard<std::recursive_mutex> lock(g_acl_mutex);
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

    return 0;
}

unsigned int dm_bss_list_t::acl_num_macs(const char *bss_key, bool blocked)
{
    return acl_get_macs(bss_key, blocked, 0, 0xFFFFFFFFU, NULL);
}

unsigned int dm_bss_list_t::acl_get_macs(const char *bss_key, bool blocked, unsigned int skip,
            unsigned int max, mac_address_t *list, unsigned short *remaining)
{
    std::lock_guard<std::recursive_mutex> lock(g_acl_mutex);
    hash_map_t *map = m_acl_sta_map;
    em_acl_sta_t *entry;
    unsigned int matched = 0, copied = 0;
    time_t now = acl_now();

    if ((map == NULL) || (bss_key == NULL)) {
        return 0;
    }

    entry = static_cast<em_acl_sta_t *> (hash_map_get_first(map));
    while ((entry != NULL) && (copied < max)) {
        if ((entry->blocked == blocked) && (strcmp(entry->bss_key, bss_key) == 0) &&
                acl_entry_live(entry, now)) {
            if (matched >= skip) {
                if (list != NULL) {
                    memcpy(list[copied], entry->mac, sizeof(mac_address_t));
                }
                if (remaining != NULL) {
                    remaining[copied] = (entry->expiry == 0) ? 0 :
                            static_cast<unsigned short> (entry->expiry - now);
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
    std::lock_guard<std::recursive_mutex> lock(g_acl_mutex);
    hash_map_t *map = m_acl_sta_map;
    em_acl_sta_t *entry;
    mac_addr_str_t mac_str;
    time_t now = acl_now();

    str[0] = 0;
    if ((map == NULL) || (bss_key == NULL)) {
        return;
    }

    entry = static_cast<em_acl_sta_t *> (hash_map_get_first(map));
    while (entry != NULL) {
        // Expired timed blocks are dropped from the persisted list on the next write
        if ((entry->blocked == blocked) && (strcmp(entry->bss_key, bss_key) == 0) &&
                acl_entry_live(entry, now)) {
            unsigned int used = static_cast<unsigned int> (strlen(str));
            if (used + 1 >= sz) {
                break;
            }
            dm_easy_mesh_t::macbytes_to_string(entry->mac, mac_str);
            if (entry->blocked && (entry->period > 0)) {
                snprintf(str + used, sz - used, "%s%s/%u", (used == 0) ? "" : ",", mac_str,
                        static_cast<unsigned int> (entry->period));
            } else {
                snprintf(str + used, sz - used, "%s%s", (used == 0) ? "" : ",", mac_str);
            }
        }
        entry = static_cast<em_acl_sta_t *> (hash_map_get_next(map, entry));
    }
}

void dm_bss_list_t::acl_from_string(const char *bss_key, bool blocked, const char *str)
{
    std::lock_guard<std::recursive_mutex> lock(g_acl_mutex);
    char copy[EM_MAX_ACL_DENY_LIST_CHARS + 1];
    mac_address_t mac;
    char *save = NULL, *token, *sep;
    unsigned short period;

    if ((str == NULL) || (*str == 0)) {
        return;
    }

    snprintf(copy, sizeof(copy), "%s", str);

    // Entries are "mac" (permanent) or, on the deny list, "mac/period" (timed block)
    token = strtok_r(copy, ",", &save);
    while (token != NULL) {
        if (strlen(token) != 0) {
            period = 0;
            if ((sep = strchr(token, '/')) != NULL) {
                *sep = 0;
                unsigned long val = strtoul(sep + 1, NULL, 10);
                period = static_cast<unsigned short> ((val > 0xFFFF) ? 0xFFFF : val);
            }
            dm_easy_mesh_t::string_to_macbytes(token, mac);
            if (acl_update(bss_key, blocked ? ASSOC_CONTROL_BLOCK : ASSOC_CONTROL_UNBLOCK, 1, &mac,
                    blocked ? period : 0) != 0) {
                em_printfout("Failed to load persisted ACL entry for BSS %s", bss_key);
            }
        }
        token = strtok_r(NULL, ",", &save);
    }
}

void dm_bss_list_t::acl_find_allowed(const mac_address_t mac, std::vector<std::string>& bss_keys)
{
    std::lock_guard<std::recursive_mutex> lock(g_acl_mutex);
    em_acl_sta_t *entry;

    if (m_acl_sta_map == NULL) {
        return;
    }

    for (entry = static_cast<em_acl_sta_t *> (hash_map_get_first(m_acl_sta_map)); entry != NULL;
            entry = static_cast<em_acl_sta_t *> (hash_map_get_next(m_acl_sta_map, entry))) {
        if (!entry->blocked && (memcmp(entry->mac, mac, sizeof(mac_address_t)) == 0)) {
            bss_keys.emplace_back(entry->bss_key);
        }
    }
}

int dm_bss_list_t::persist_acl(db_client_t& db_client, em_bss_info_t *info, const char *bss_key)
{
    dm_orch_type_t op = entry_exists_in_table(db_client, const_cast<char *>(bss_key)) ?
            dm_orch_type_db_update : dm_orch_type_db_insert;

    return update_db(db_client, op, info);
}

void dm_bss_list_t::acl_remove(const char *bss_key)
{
    std::lock_guard<std::recursive_mutex> lock(g_acl_mutex);
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

void dm_bss_list_t::acl_purge_expired()
{
    std::lock_guard<std::recursive_mutex> lock(g_acl_mutex);
    hash_map_t *map = m_acl_sta_map;
    em_acl_sta_t *entry;
    em_3xlong_string_t acl_key;
    std::vector<std::string> dead;
    time_t now = acl_now();

    if (map == NULL) {
        return;
    }

    for (entry = static_cast<em_acl_sta_t *> (hash_map_get_first(map)); entry != NULL;
            entry = static_cast<em_acl_sta_t *> (hash_map_get_next(map, entry))) {
        if (!acl_entry_live(entry, now)) {
            make_acl_key(entry->bss_key, entry->mac, acl_key, sizeof(acl_key));
            dead.emplace_back(acl_key);
        }
    }

    // Removed after the walk so the iteration is not disturbed
    for (const std::string& k : dead) {
        free(hash_map_remove(map, k.c_str()));
    }
}

int dm_bss_list_t::update_db(db_client_t& db_client, dm_orch_type_t op, void *data)
{
    mac_addr_str_t bss_mac_str, radio_mac_str;
    em_bss_info_t *info = static_cast<em_bss_info_t *> (data);
    int ret = 0;
    unsigned int i;
	em_2xlong_string_t key;
    em_long_string_t	front_akms, back_akms;
    char blocked_macs[EM_MAX_ACL_DENY_LIST_CHARS + 1];
    char allowed_macs[EM_MAX_ACL_LIST_CHARS + 1];
        const char *mac_filter_mode = (info->acl_filter_mode == EM_ACL_MODE_WHITELIST) ?
            "whitelist" : (info->acl_filter_mode == EM_ACL_MODE_BLACKLIST) ? "blacklist" : "No Info";
        
	dm_bss_t::make_bss_key(info, key, sizeof(key));

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

    // Every CACR ends in a BSS write, so expired timed blocks are freed here
    acl_purge_expired();
    acl_to_string(key, true, blocked_macs, sizeof(blocked_macs));
    acl_to_string(key, false, allowed_macs, sizeof(allowed_macs));
	
    if (prepare_db_operation(db_client, op) != 0) {
        return -1;
    }
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
            // Startup and re-onboarding drop BSS rows; keep ones carrying an ACL until the agent reports them again
            if ((acl_num_macs(key, true) + acl_num_macs(key, false)) > 0) {
                ret = 0;
                break;
            }
			ret = delete_row(db_client, key);
			break;

		default:
			break;
	}

    return ret;
}

bool dm_bss_list_t::search_db(db_client_t& db_client, void *ctx, void *key)
{
    em_long_string_t str = {};

    if (key == NULL) {
        while (db_client.next_result(ctx)) {
        }
        return false;
    }

    while (db_client.next_result(ctx)) {
        if (db_client.get_string(ctx, str, 1) != NULL &&
                strcmp(str, static_cast<char *> (key)) == 0) {
            db_client.free_result(ctx);
            return true;
        }
    }

    return false;
}

int dm_bss_list_t::sync_db(db_client_t& db_client, void *ctx)
{
    em_bss_info_t info;
    mac_addr_str_t	mac;
    em_long_string_t   str;
    em_2xlong_string_t bss_key;
    char acl_str[EM_MAX_ACL_DENY_LIST_CHARS + 1];
    char mac_filter_mode[10];
    unsigned int i;
    char   *token_parts[EM_MAX_AKMS];
    std::vector<std::string> invalid_bss_ids;
    int rc = 0;

    // sync_table() skips the call when the query fails, so a NULL ctx is an empty BSSList: no ACL
    acl_clear();

    while (db_client.next_result(ctx)) {
        memset(&info, 0, sizeof(em_bss_info_t));

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
                (memcmp(info.bssid.mac, ZERO_MAC_ADDR, sizeof(mac_address_t)) == 0) ||
                (memcmp(info.ruid.mac, ZERO_MAC_ADDR, sizeof(mac_address_t)) == 0)) {
            // An empty SSID alone is not invalid: a disabled/unconfigured BSS can still carry a
            // persisted ACL (e.g. a backhaul whitelist), which must survive a reload.
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
        acl_from_string(bss_key, true, acl_str);

        memset(acl_str, 0, sizeof(acl_str));
        db_client.get_string(ctx, acl_str, 25, sizeof(acl_str));
        acl_from_string(bss_key, false, acl_str);

        update_list(dm_bss_t(&info), dm_orch_type_db_insert);
    }

    for (const std::string& bss_id : invalid_bss_ids) {
        if (delete_row(db_client, bss_id.c_str()) != 0) {
            em_printfout("Failed to remove invalid BSSList row %s", bss_id.c_str());
            rc = -1;
        }
    }

    // Loading from the DB is not a change that needs writing back

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
    m_columns[m_num_cols++] = db_column_t("ACLValidityPeriod", db_data_type_smallint, 0);
    m_columns[m_num_cols++] = db_column_t("MACsDisallowed", db_data_type_varchar, EM_MAX_ACL_DENY_LIST_CHARS);
    m_columns[m_num_cols++] = db_column_t("MACsAllowed", db_data_type_varchar, EM_MAX_ACL_LIST_CHARS);
}

int dm_bss_list_t::init()
{
    init_table();
    init_columns();
    return 0;
}
