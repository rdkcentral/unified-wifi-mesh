// SPDX-License-Identifier: Apache-2.0

#include <cstring>
#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include "dm_easy_mesh.h"

class StationUpdatesTest : public ::testing::Test {
protected:
    std::unique_ptr<dm_easy_mesh_t> dm;
    em_sta_info_t info = {};
    const char *key = "00:00:00:00:00:02@00:00:00:00:00:03@00:00:00:00:00:01";

    void SetUp() override
    {
        dm.reset(new dm_easy_mesh_t());
        ASSERT_EQ(dm->init(), 0);
        info.id[5] = 2;
        info.bssid[5] = 3;
        info.radiomac[5] = 1;
        info.associated = true;
        info.pkts_tx = 123;
        dm->set_num_radios(1);
        memcpy(dm->get_radio_info(0)->id.ruid, info.radiomac, sizeof(mac_address_t));
        dm->set_num_bss(1);
        memcpy(dm->get_bss(0)->m_bss_info.bssid.mac, info.bssid, sizeof(mac_address_t));
        memcpy(dm->get_bss(0)->m_bss_info.ruid.mac, info.radiomac, sizeof(mac_address_t));
    }

    void seed_station(unsigned int length)
    {
        std::vector<unsigned char> body(length, 0x7f);
        info.frame_body_len = length;
        info.frame_body = body.data();
        hash_map_put(dm->m_sta_map, strdup(key), new dm_sta_t(&info));
        info.frame_body = nullptr;
        info.frame_body_len = 0;
    }
};

TEST_F(StationUpdatesTest, DisassociationPreservesOwnedFrameAndMetrics)
{
    seed_station(1500);
    em_client_assoc_event_t event = {};
    memcpy(event.cli_mac_address, info.id, sizeof(mac_address_t));
    memcpy(event.bssid, info.bssid, sizeof(mac_address_t));
    dm->apply_sta_disassociation(event);

    dm_sta_t *sta = static_cast<dm_sta_t *>(hash_map_get(dm->m_sta_map, key));
    dm_sta_t *pending = static_cast<dm_sta_t *>(hash_map_get(dm->m_sta_assoc_map, key));
    ASSERT_NE(sta, nullptr);
    ASSERT_NE(pending, nullptr);
    EXPECT_FALSE(sta->m_sta_info.associated);
    EXPECT_FALSE(pending->m_sta_info.associated);
    EXPECT_EQ(pending->m_sta_info.pkts_tx, 123u);
    ASSERT_EQ(pending->m_sta_info.frame_body_len, 1500u);
    EXPECT_NE(pending->m_sta_info.frame_body, sta->m_sta_info.frame_body);
    EXPECT_EQ(memcmp(pending->m_sta_info.frame_body, sta->m_sta_info.frame_body, 1500), 0);

    delete static_cast<dm_sta_t *>(hash_map_remove(dm->m_sta_assoc_map, key));
    dm->apply_sta_disassociation(event);
    pending = static_cast<dm_sta_t *>(hash_map_get(dm->m_sta_assoc_map, key));
    ASSERT_NE(pending, nullptr);
    ASSERT_EQ(pending->m_sta_info.frame_body_len, 1500u);
    EXPECT_EQ(pending->m_sta_info.frame_body[1499], 0x7f);
}

TEST_F(StationUpdatesTest, MldUpdateClearsStaleLinkAndPreservesCurrentLinkData)
{
    seed_station(1500);
    em_assoc_sta_mld_info_t update = {};
    memcpy(update.mac_addr, info.id, sizeof(mac_address_t));
    update.num_affiliated_sta = 1;
    memcpy(update.affiliated_sta[0].bssid, info.bssid, sizeof(mac_address_t));
    dm->apply_sta_mld_association(update);
    dm_sta_t *pending = static_cast<dm_sta_t *>(hash_map_get(dm->m_sta_assoc_map, key));
    ASSERT_NE(pending, nullptr);
    EXPECT_TRUE(pending->m_sta_info.associated);
    EXPECT_EQ(pending->m_sta_info.pkts_tx, 123u);
    ASSERT_EQ(pending->m_sta_info.frame_body_len, 1500u);
    EXPECT_EQ(pending->m_sta_info.frame_body[1499], 0x7f);

    dm->get_bss(0)->m_bss_info.bssid.mac[5] = 4;
    update.affiliated_sta[0].bssid[5] = 4;
    dm->apply_sta_mld_association(update);
    EXPECT_FALSE(pending->m_sta_info.associated);
    EXPECT_EQ(pending->m_sta_info.pkts_tx, 123u);
    EXPECT_EQ(pending->m_sta_info.frame_body_len, 1500u);
    dm_sta_t *current = static_cast<dm_sta_t *>(hash_map_get(dm->m_sta_assoc_map,
        "00:00:00:00:00:02@00:00:00:00:00:04@00:00:00:00:00:01"));
    ASSERT_NE(current, nullptr);
    EXPECT_TRUE(current->m_sta_info.associated);
    EXPECT_EQ(current->m_sta_info.frame_body_len, 0u);
}

TEST_F(StationUpdatesTest, MldDisassociationFallsBackWhenLinkCannotBeResolved)
{
    seed_station(1500);
    dm->m_num_assoc_sta_mld = 1;
    em_assoc_sta_mld_info_t &mld = dm->m_assoc_sta_mld[0].m_assoc_sta_mld_info;
    memcpy(mld.mac_addr, info.id, sizeof(mac_address_t));
    memcpy(mld.affiliated_sta[0].bssid, info.bssid, sizeof(mac_address_t));
    mld.num_affiliated_sta = 1;
    em_client_assoc_event_t event = {};
    memcpy(event.cli_mac_address, info.id, sizeof(mac_address_t));
    memcpy(event.bssid, info.bssid, sizeof(mac_address_t));

    const unsigned char link_bssids[] = {3, 99};
    for (unsigned char link_bssid : link_bssids) {
        mld.affiliated_sta[0].bssid[5] = link_bssid;
        dm->apply_sta_disassociation(event);
        dm_sta_t *pending = static_cast<dm_sta_t *>(hash_map_get(dm->m_sta_assoc_map, key));
        ASSERT_NE(pending, nullptr);
        EXPECT_FALSE(pending->m_sta_info.associated);
        EXPECT_EQ(pending->m_sta_info.pkts_tx, 123u);
        ASSERT_EQ(pending->m_sta_info.frame_body_len, 1500u);
        EXPECT_EQ(pending->m_sta_info.frame_body[1499], 0x7f);
        delete static_cast<dm_sta_t *>(hash_map_remove(dm->m_sta_assoc_map, key));
    }
}

TEST_F(StationUpdatesTest, CapabilityReplacementSurvivesPendingEntryDeletion)
{
    seed_station(1500);
    const unsigned int lengths[] = {EM_MAX_FRAME_BODY_LEN, 4, 0};
    for (unsigned int length : lengths) {
        std::vector<unsigned char> body(length, 0x7f);
        info.frame_body_len = length;
        info.frame_body = length == 0 ? nullptr : body.data();
        dm->apply_sta_cap_to_maps(key, &info);
        dm_sta_t *sta = static_cast<dm_sta_t *>(hash_map_get(dm->m_sta_map, key));
        dm_sta_t *pending = static_cast<dm_sta_t *>(hash_map_get(dm->m_sta_assoc_map, key));
        ASSERT_NE(sta, nullptr);
        ASSERT_NE(pending, nullptr);
        ASSERT_EQ(sta->m_sta_info.frame_body_len, length);
        ASSERT_EQ(pending->m_sta_info.frame_body_len, length);
        if (length > 0) {
            EXPECT_NE(sta->m_sta_info.frame_body, body.data());
            EXPECT_NE(pending->m_sta_info.frame_body, body.data());
            EXPECT_NE(sta->m_sta_info.frame_body, pending->m_sta_info.frame_body);
        }
        delete static_cast<dm_sta_t *>(hash_map_remove(dm->m_sta_assoc_map, key));
        body.clear();
        body.shrink_to_fit();
        if (length > 0) {
            EXPECT_EQ(sta->m_sta_info.frame_body[length - 1], 0x7f);
        } else {
            EXPECT_EQ(sta->m_sta_info.frame_body, nullptr);
        }
        EXPECT_EQ(sta->m_sta_info.pkts_tx, 123u);
    }
}
