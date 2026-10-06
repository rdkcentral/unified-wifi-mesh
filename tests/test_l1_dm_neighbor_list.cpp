
/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2025 RDK Management
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
 */
#include <gtest/gtest.h>
#include <stdio.h>
#include <cstring>
#include <string>
#include <vector>
#include "dm_easy_mesh_ctrl.h"

/* Covers NeighborList TLV validation, the composite key that keeps entries isolated, the
 * in-memory reconciliation, and the failure path that must stop a failed database write
 * from being reflected in memory.
 *
 * Loading rows back after a restart (sync_db) is deliberately absent: it reads result sets
 * from a live MariaDB instance and cannot be exercised here, so it belongs in integration
 * coverage.
 */

namespace {

const unsigned int NBR_MAC_LEN = 6;
/* IEEE1905 entries are MAC + bridge flag, non-IEEE1905 entries are MAC only. */
const unsigned int ENTRY_LEN_1905 = 7;
const unsigned int ENTRY_LEN_NON_1905 = 6;

const unsigned char DEV_AL_MAC[NBR_MAC_LEN] = {0x02, 0x01, 0x00, 0x5e, 0x3b, 0xb0};
const unsigned char DEV_AL_MAC_2[NBR_MAC_LEN] = {0x02, 0x01, 0x00, 0x5e, 0x3b, 0xb1};
const unsigned char IFACE_MAC[NBR_MAC_LEN] = {0x02, 0x01, 0x00, 0x5e, 0x3b, 0xa1};
const unsigned char IFACE_MAC_2[NBR_MAC_LEN] = {0x02, 0x01, 0x00, 0x5e, 0x3b, 0xa2};
const unsigned char NBR_A[NBR_MAC_LEN]     = {0x02, 0x01, 0x00, 0x5e, 0x3b, 0x90};
const unsigned char NBR_B[NBR_MAC_LEN]     = {0x02, 0x01, 0x00, 0x5e, 0x3b, 0x91};

/* Build a NeighborList TLV payload: local interface MAC followed by fixed size entries. */
std::vector<unsigned char> build_payload(const std::vector<const unsigned char *>& neighbors,
        unsigned int entry_len)
{
    std::vector<unsigned char> payload(IFACE_MAC, IFACE_MAC + NBR_MAC_LEN);

    for (size_t i = 0; i < neighbors.size(); i++) {
        payload.insert(payload.end(), neighbors[i], neighbors[i] + NBR_MAC_LEN);
        /* Pad out the remainder of the entry (the IEEE1905 bridge flag). */
        payload.resize(payload.size() + (entry_len - NBR_MAC_LEN), 0);
    }

    return payload;
}

bool validate(const std::vector<unsigned char>& payload, bool is_1905, unsigned int *count)
{
    return dm_easy_mesh_ctrl_t::validate_neighbor_list(payload.data(),
            static_cast<unsigned int>(payload.size()), is_1905, count);
}

em_neighbor_info_t make_info(const unsigned char *dev_al_mac, const unsigned char *iface_mac,
        const unsigned char *nbr_mac, bool is_1905)
{
    em_neighbor_info_t info;

    memset(&info, 0, sizeof(info));
    memcpy(info.dev_al_mac, dev_al_mac, NBR_MAC_LEN);
    memcpy(info.local_iface_mac, iface_mac, NBR_MAC_LEN);
    memcpy(info.nbr, nbr_mac, NBR_MAC_LEN);
    memcpy(info.next_hop, nbr_mac, NBR_MAC_LEN);
    info.num_hops = 1;
    info.is_ieee1905neighbor = is_1905;

    return info;
}

std::string key_of(const em_neighbor_info_t& info)
{
    em_long_string_t key;

    dm_neighbor_list_t::make_key(&info, key);

    return std::string(key);
}

} // namespace

/**!
 * @brief A NULL payload is rejected.
 */
TEST(dm_neighbor_list_validate, rejects_null_payload) {
    unsigned int count = 0xffffffff;

    EXPECT_FALSE(dm_easy_mesh_ctrl_t::validate_neighbor_list(NULL, NBR_MAC_LEN, true, &count));
    EXPECT_FALSE(dm_easy_mesh_ctrl_t::validate_neighbor_list(NULL, NBR_MAC_LEN, false, &count));
}

/**!
 * @brief A payload shorter than the local interface MAC header is rejected.
 *
 * Without the header the interface the list belongs to is unknown, so no row may be written
 * and no stale row may be purged.
 */
TEST(dm_neighbor_list_validate, rejects_payload_shorter_than_header) {
    unsigned char payload[NBR_MAC_LEN] = {0};

    for (unsigned int len = 0; len < NBR_MAC_LEN; len++) {
        EXPECT_FALSE(dm_easy_mesh_ctrl_t::validate_neighbor_list(payload, len, true, NULL))
                << "len=" << len;
        EXPECT_FALSE(dm_easy_mesh_ctrl_t::validate_neighbor_list(payload, len, false, NULL))
                << "len=" << len;
    }
}

/**!
 * @brief A header-only payload is well formed and reports zero entries.
 *
 * This is how an agent reports that an interface has no neighbors left.
 */
TEST(dm_neighbor_list_validate, accepts_header_only_payload) {
    unsigned int count = 0xffffffff;

    ASSERT_TRUE(validate(build_payload({}, ENTRY_LEN_1905), true, &count));
    EXPECT_EQ(0u, count);

    count = 0xffffffff;
    ASSERT_TRUE(validate(build_payload({}, ENTRY_LEN_NON_1905), false, &count));
    EXPECT_EQ(0u, count);
}

/**!
 * @brief Well formed lists report the correct entry count for both list types.
 */
TEST(dm_neighbor_list_validate, counts_entries_for_both_list_types) {
    unsigned int count = 0;

    ASSERT_TRUE(validate(build_payload({NBR_A, NBR_B}, ENTRY_LEN_1905), true, &count));
    EXPECT_EQ(2u, count);

    ASSERT_TRUE(validate(build_payload({NBR_A, NBR_B}, ENTRY_LEN_NON_1905), false, &count));
    EXPECT_EQ(2u, count);
}

/**!
 * @brief A trailing partial entry is rejected.
 *
 * There is no count field, so a truncated tail means the list is not the complete set for
 * the interface and must not be allowed to drive the stale-row purge.
 */
TEST(dm_neighbor_list_validate, rejects_partial_trailing_entry) {
    std::vector<unsigned char> truncated = build_payload({NBR_A}, ENTRY_LEN_1905);
    truncated.pop_back();
    EXPECT_FALSE(validate(truncated, true, NULL));

    /* Every length that leaves a partial entry must be rejected. */
    std::vector<unsigned char> two = build_payload({NBR_A, NBR_B}, ENTRY_LEN_1905);
    for (unsigned int extra = 1; extra < ENTRY_LEN_1905; extra++) {
        std::vector<unsigned char> partial(two.begin(), two.end() - extra);
        EXPECT_FALSE(validate(partial, true, NULL)) << "trimmed=" << extra;
    }
}

/**!
 * @brief The entry size, not the byte count alone, decides whether a payload is valid.
 *
 * A 13 byte payload holds one whole IEEE1905 entry but leaves a partial non-IEEE1905 one.
 */
TEST(dm_neighbor_list_validate, entry_size_distinguishes_list_types) {
    std::vector<unsigned char> payload = build_payload({NBR_A}, ENTRY_LEN_1905);
    unsigned int count = 0;

    ASSERT_EQ(NBR_MAC_LEN + ENTRY_LEN_1905, payload.size());

    EXPECT_TRUE(validate(payload, true, &count));
    EXPECT_EQ(1u, count);

    /* 7 bytes of entries is not a multiple of the 6 byte non-IEEE1905 entry. */
    EXPECT_FALSE(validate(payload, false, NULL));
}

/**!
 * @brief The entry count is left untouched when the payload is rejected.
 */
TEST(dm_neighbor_list_validate, leaves_count_untouched_on_rejection) {
    std::vector<unsigned char> truncated = build_payload({NBR_A}, ENTRY_LEN_1905);
    truncated.pop_back();

    unsigned int count = 0xdeadbeef;
    EXPECT_FALSE(validate(truncated, true, &count));
    EXPECT_EQ(0xdeadbeefu, count);
}

/* The same neighbor MAC is reported by different devices, on different interfaces, and in
 * both list types. Each of those must be a distinct entry, so every component of the tuple
 * has to change the key on its own. */

/**!
 * @brief The reporting device AL MAC takes part in the key.
 */
TEST(dm_neighbor_list_key, device_al_mac_isolates_entries) {
    EXPECT_NE(key_of(make_info(DEV_AL_MAC, IFACE_MAC, NBR_A, true)),
              key_of(make_info(DEV_AL_MAC_2, IFACE_MAC, NBR_A, true)));
}

/**!
 * @brief The local interface MAC takes part in the key.
 */
TEST(dm_neighbor_list_key, local_interface_isolates_entries) {
    EXPECT_NE(key_of(make_info(DEV_AL_MAC, IFACE_MAC, NBR_A, true)),
              key_of(make_info(DEV_AL_MAC, IFACE_MAC_2, NBR_A, true)));
}

/**!
 * @brief The neighbor MAC takes part in the key.
 */
TEST(dm_neighbor_list_key, neighbor_mac_isolates_entries) {
    EXPECT_NE(key_of(make_info(DEV_AL_MAC, IFACE_MAC, NBR_A, true)),
              key_of(make_info(DEV_AL_MAC, IFACE_MAC, NBR_B, true)));
}

/**!
 * @brief The IEEE1905 flag takes part in the key.
 *
 * A device can appear in both lists; collapsing them would let one purge the other.
 */
TEST(dm_neighbor_list_key, list_type_isolates_entries) {
    EXPECT_NE(key_of(make_info(DEV_AL_MAC, IFACE_MAC, NBR_A, true)),
              key_of(make_info(DEV_AL_MAC, IFACE_MAC, NBR_A, false)));
}

/**!
 * @brief Identical records produce identical keys, so a re-report updates instead of duplicating.
 */
TEST(dm_neighbor_list_key, identical_records_share_a_key) {
    EXPECT_EQ(key_of(make_info(DEV_AL_MAC, IFACE_MAC, NBR_A, true)),
              key_of(make_info(DEV_AL_MAC, IFACE_MAC, NBR_A, true)));
}

/**!
 * @brief The key fits the buffer it is written into even with every byte at its widest.
 */
TEST(dm_neighbor_list_key, key_fits_buffer) {
    const unsigned char wide[NBR_MAC_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    em_neighbor_info_t info = make_info(wide, wide, wide, true);
    em_long_string_t key;

    memset(key, 0xaa, sizeof(key));
    dm_neighbor_list_t::make_key(&info, key);

    EXPECT_LT(strlen(key), sizeof(em_long_string_t));
}

/* The controller carries the neighbor hash map, so the reconciliation below runs against a
 * real dm_easy_mesh_ctrl_t with no database behind it. */
class dm_neighbor_list_mem_test : public ::testing::Test {
protected:
    /* db_easy_mesh_t's constructor leaves m_table_name uninitialised. */
    void SetUp() override { m_ctrl.init_tables(); }

    void add(const em_neighbor_info_t& info)
    {
        em_neighbor_info_t copy = info;
        m_ctrl.dm_neighbor_list_t::update_list(dm_neighbor_t(&copy), dm_orch_type_db_insert);
    }

    void remove(const em_neighbor_info_t& info)
    {
        em_neighbor_info_t copy = info;
        m_ctrl.dm_neighbor_list_t::update_list(dm_neighbor_t(&copy), dm_orch_type_db_delete);
    }

    unsigned int count()
    {
        unsigned int total = 0;

        for (dm_neighbor_t *n = m_ctrl.get_first_neighbor(); n != NULL;
                n = m_ctrl.get_next_neighbor(n)) {
            total++;
        }

        return total;
    }

    bool holds(const em_neighbor_info_t& info)
    {
        em_long_string_t key;

        dm_neighbor_list_t::make_key(&info, key);

        return m_ctrl.get_neighbor(key) != NULL;
    }

    dm_easy_mesh_ctrl_t m_ctrl;
};

/**!
 * @brief Entries differing only in list type coexist rather than overwrite each other.
 */
TEST_F(dm_neighbor_list_mem_test, both_list_types_coexist) {
    em_neighbor_info_t as_1905 = make_info(DEV_AL_MAC, IFACE_MAC, NBR_A, true);
    em_neighbor_info_t as_non_1905 = make_info(DEV_AL_MAC, IFACE_MAC, NBR_A, false);

    add(as_1905);
    add(as_non_1905);

    EXPECT_EQ(2u, count());
    EXPECT_TRUE(holds(as_1905));
    EXPECT_TRUE(holds(as_non_1905));
}

/**!
 * @brief Removing an entry leaves the other interfaces and list types intact.
 */
TEST_F(dm_neighbor_list_mem_test, removal_is_confined_to_the_composite_key) {
    em_neighbor_info_t target = make_info(DEV_AL_MAC, IFACE_MAC, NBR_A, true);
    em_neighbor_info_t other_iface = make_info(DEV_AL_MAC, IFACE_MAC_2, NBR_A, true);
    em_neighbor_info_t other_dev = make_info(DEV_AL_MAC_2, IFACE_MAC, NBR_A, true);
    em_neighbor_info_t other_type = make_info(DEV_AL_MAC, IFACE_MAC, NBR_A, false);

    add(target);
    add(other_iface);
    add(other_dev);
    add(other_type);
    ASSERT_EQ(4u, count());

    remove(target);

    EXPECT_EQ(3u, count());
    EXPECT_FALSE(holds(target));
    EXPECT_TRUE(holds(other_iface));
    EXPECT_TRUE(holds(other_dev));
    EXPECT_TRUE(holds(other_type));
}

/**!
 * @brief Re-reporting a neighbor updates the entry in place instead of duplicating it.
 */
TEST_F(dm_neighbor_list_mem_test, repeat_report_does_not_duplicate) {
    em_neighbor_info_t info = make_info(DEV_AL_MAC, IFACE_MAC, NBR_A, true);

    add(info);
    info.path_loss = 42;
    m_ctrl.dm_neighbor_list_t::update_list(dm_neighbor_t(&info), dm_orch_type_db_update);

    ASSERT_EQ(1u, count());
    EXPECT_EQ(42, m_ctrl.get_first_neighbor()->get_neighbor_info()->path_loss);
}

/* With no connection behind it every statement must report failure, which is what the
 * callers rely on to keep memory and the table from diverging. */
class dm_neighbor_list_db_failure_test : public dm_neighbor_list_mem_test {
protected:
    /* Never init()ed, so m_con stays NULL and every statement fails. */
    db_client_t m_down;
};

/**!
 * @brief An insert against a down database reports failure.
 */
TEST_F(dm_neighbor_list_db_failure_test, insert_reports_failure) {
    em_neighbor_info_t info = make_info(DEV_AL_MAC, IFACE_MAC, NBR_A, true);

    EXPECT_NE(0, m_ctrl.dm_neighbor_list_t::update_db(m_down, dm_orch_type_db_insert, &info));
}

/**!
 * @brief An update against a down database reports failure.
 */
TEST_F(dm_neighbor_list_db_failure_test, update_reports_failure) {
    em_neighbor_info_t info = make_info(DEV_AL_MAC, IFACE_MAC, NBR_A, true);

    EXPECT_NE(0, m_ctrl.dm_neighbor_list_t::update_db(m_down, dm_orch_type_db_update, &info));
}

/**!
 * @brief A delete against a down database reports failure.
 */
TEST_F(dm_neighbor_list_db_failure_test, delete_reports_failure) {
    em_neighbor_info_t info = make_info(DEV_AL_MAC, IFACE_MAC, NBR_A, true);

    EXPECT_NE(0, m_ctrl.dm_neighbor_list_t::update_db(m_down, dm_orch_type_db_delete, &info));
}

/**!
 * @brief A failed write is not reflected in memory.
 *
 * set_config() must return before update_list() runs, otherwise the hash map would claim a
 * neighbor the table never received.
 */
TEST_F(dm_neighbor_list_db_failure_test, failed_write_leaves_memory_untouched) {
    em_neighbor_info_t info = make_info(DEV_AL_MAC, IFACE_MAC, NBR_A, true);
    dm_neighbor_t neighbor(&info);

    ASSERT_NE(0, m_ctrl.dm_neighbor_list_t::set_config(m_down, neighbor, NULL));

    EXPECT_EQ(0u, count());
    EXPECT_FALSE(holds(info));
}
