// SPDX-License-Identifier: Apache-2.0

#include <cstring>
#include <atomic>
#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <thread>
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

TEST_F(StationUpdatesTest, AssociationChangesPreservePendingOnlyStationData)
{
    std::vector<unsigned char> body(1500, 0x7f);
    info.frame_body = body.data();
    info.frame_body_len = static_cast<unsigned int>(body.size());
    dm->apply_sta_cap_to_maps(key, &info);
    info.frame_body = nullptr;
    info.frame_body_len = 0;
    ASSERT_EQ(hash_map_get(dm->m_sta_map, key), nullptr);
    dm_sta_t *pending = static_cast<dm_sta_t *>(hash_map_get(dm->m_sta_assoc_map, key));
    ASSERT_NE(pending, nullptr);
    unsigned char *owned_body = pending->m_sta_info.frame_body;

    em_client_assoc_event_t event = {};
    memcpy(event.cli_mac_address, info.id, sizeof(mac_address_t));
    memcpy(event.bssid, info.bssid, sizeof(mac_address_t));
    dm->apply_sta_disassociation(event);
    EXPECT_FALSE(pending->m_sta_info.associated);
    EXPECT_EQ(pending->m_sta_info.pkts_tx, 123u);
    EXPECT_EQ(pending->m_sta_info.frame_body, owned_body);
    ASSERT_EQ(pending->m_sta_info.frame_body_len, 1500u);
    EXPECT_EQ(pending->m_sta_info.frame_body[1499], 0x7f);

    em_assoc_sta_mld_info_t update = {};
    memcpy(update.mac_addr, info.id, sizeof(mac_address_t));
    update.num_affiliated_sta = 1;
    memcpy(update.affiliated_sta[0].bssid, info.bssid, sizeof(mac_address_t));
    dm->apply_sta_mld_association(update);
    EXPECT_TRUE(pending->m_sta_info.associated);
    EXPECT_EQ(pending->m_sta_info.pkts_tx, 123u);
    EXPECT_EQ(pending->m_sta_info.frame_body, owned_body);
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
    ASSERT_EQ(current->m_sta_info.frame_body_len, 1500u);
    EXPECT_EQ(current->m_sta_info.frame_body[1499], 0x7f);
    EXPECT_EQ(current->m_sta_info.pkts_tx, 0u);
    EXPECT_NE(current->m_sta_info.frame_body, pending->m_sta_info.frame_body);
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

TEST_F(StationUpdatesTest, MetricsSnapshotSurvivesStationDeletion)
{
    seed_station(1500);
    std::vector<dm_sta_t> stations;
    dm->copy_sta_snapshot(stations);
    ASSERT_EQ(stations.size(), 1u);
    dm_sta_t *live = static_cast<dm_sta_t *>(hash_map_get(dm->m_sta_map, key));
    ASSERT_NE(live, nullptr);
    EXPECT_NE(stations[0].m_sta_info.frame_body, live->m_sta_info.frame_body);

    dm_easy_mesh_t update;
    ASSERT_EQ(update.init(), 0);
    hash_map_put(update.m_sta_dassoc_map, strdup(key), new dm_sta_t(&info));
    dm->merge_assoc_sta_updates(update);
    EXPECT_EQ(hash_map_get(dm->m_sta_map, key), nullptr);
    EXPECT_EQ(dm->get_num_bss_for_associated_sta(info.id), 0);
    EXPECT_EQ(stations[0].m_sta_info.pkts_tx, 123u);
    ASSERT_EQ(stations[0].m_sta_info.frame_body_len, 1500u);
    EXPECT_EQ(stations[0].m_sta_info.frame_body[1499], 0x7f);
    dm->copy_sta_snapshot(stations);
    EXPECT_TRUE(stations.empty());
}

TEST_F(StationUpdatesTest, MetricsSnapshotDuringAssociationAndDeletion)
{
    dm_easy_mesh_t update;
    dm_easy_mesh_t removal;
    ASSERT_EQ(update.init(), 0);
    ASSERT_EQ(removal.init(), 0);
    std::vector<unsigned char> body(1500, 0x7f);
    info.frame_body = body.data();
    info.frame_body_len = static_cast<unsigned int>(body.size());
    hash_map_put(update.m_sta_assoc_map, strdup(key), new dm_sta_t(&info));
    hash_map_put(removal.m_sta_dassoc_map, strdup(key), new dm_sta_t(&info));
    info.frame_body = nullptr;
    info.frame_body_len = 0;

    std::atomic<bool> stop(false);
    std::atomic<unsigned int> updates(0);
    std::thread writer([&]() {
        while (!stop.load()) {
            dm->merge_assoc_sta_updates(update);
            dm->merge_assoc_sta_updates(removal);
            updates.fetch_add(1);
        }
    });
    while (updates.load() == 0) {
        std::this_thread::yield();
    }
    std::vector<dm_sta_t> stations;
    for (unsigned int i = 0; i < 1000; i++) {
        dm->copy_sta_snapshot(stations);
        EXPECT_LE(stations.size(), 1u);
        for (const dm_sta_t &station : stations) {
            EXPECT_EQ(station.m_sta_info.pkts_tx, 123u);
            EXPECT_EQ(station.m_sta_info.frame_body_len, 1500u);
            if (station.m_sta_info.frame_body != nullptr && station.m_sta_info.frame_body_len == 1500u) {
                EXPECT_EQ(station.m_sta_info.frame_body[1499], 0x7f);
            } else {
                ADD_FAILURE() << "Snapshot lost the owned frame body";
            }
        }
        const int count = dm->get_num_bss_for_associated_sta(info.id);
        EXPECT_TRUE(count == 0 || count == 1);
    }
    stop.store(true);
    writer.join();
}

TEST_F(StationUpdatesTest, MldTableSnapshotOwnsCountAndRows)
{
    em_assoc_sta_mld_info_t rows[EM_MAX_ASSOC_STA_MLD];
    EXPECT_EQ(dm->copy_assoc_sta_mld_info(rows), 0u);

    em_assoc_sta_mld_info_t mld = {};
    mld.num_affiliated_sta = 1;
    mld.affiliated_sta[0].bssid[5] = 10;
    for (unsigned int i = 0; i < EM_MAX_ASSOC_STA_MLD; i++) {
        mld.mac_addr[5] = static_cast<unsigned char>(i + 1);
        dm->replace_assoc_sta_mld_info(mld);
    }
    const unsigned int count = dm->copy_assoc_sta_mld_info(rows);
    ASSERT_EQ(count, static_cast<unsigned int>(EM_MAX_ASSOC_STA_MLD));
    mld.num_affiliated_sta = 0;
    dm->replace_assoc_sta_mld_info(mld);
    for (unsigned int i = 0; i < count; i++) {
        EXPECT_EQ(rows[i].mac_addr[5], i + 1);
        EXPECT_EQ(rows[i].num_affiliated_sta, 1);
        EXPECT_EQ(rows[i].affiliated_sta[0].bssid[5], 10);
    }
    EXPECT_EQ(dm->copy_assoc_sta_mld_info(rows), count);
    EXPECT_EQ(rows[count - 1].num_affiliated_sta, 0);
}

TEST_F(StationUpdatesTest, MldTableSnapshotPreservesLinkVersionDuringReplacement)
{
    em_assoc_sta_mld_info_t mld = {};
    mld.mac_addr[5] = 1;
    mld.num_affiliated_sta = 1;
    mld.affiliated_sta[0].bssid[5] = 1;
    dm->replace_assoc_sta_mld_info(mld);

    std::atomic<bool> stop(false);
    std::atomic<unsigned int> updates(0);
    std::thread writer([&]() {
        while (!stop.load()) {
            mld.num_affiliated_sta = mld.num_affiliated_sta == 1 ? 2 : 1;
            for (unsigned int j = 0; j < mld.num_affiliated_sta; j++) {
                mld.affiliated_sta[j].bssid[5] = mld.num_affiliated_sta;
                mld.affiliated_sta[j].link_addr[5] = mld.num_affiliated_sta;
            }
            dm->replace_assoc_sta_mld_info(mld);
            updates.fetch_add(1);
        }
    });
    while (updates.load() == 0) {
        std::this_thread::yield();
    }
    for (unsigned int i = 0; i < 1000; i++) {
        em_assoc_sta_mld_info_t rows[EM_MAX_ASSOC_STA_MLD];
        const unsigned int count = dm->copy_assoc_sta_mld_info(rows);
        EXPECT_EQ(count, 1u);
        if (count == 1) {
            const em_assoc_sta_mld_info_t &row = rows[0];
            EXPECT_TRUE(row.num_affiliated_sta == 1 || row.num_affiliated_sta == 2);
            for (unsigned int j = 0; j < row.num_affiliated_sta; j++) {
                EXPECT_EQ(row.affiliated_sta[j].bssid[5], row.num_affiliated_sta);
                EXPECT_EQ(row.affiliated_sta[j].link_addr[5], row.num_affiliated_sta);
            }
        }
    }
    stop.store(true);
    writer.join();
}
