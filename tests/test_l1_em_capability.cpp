// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>
#include <atomic>
#include <cstring>
#include <memory>
#include <vector>
#include <thread>
#include "dm_easy_mesh.h"
#include "em.h"
#include "em_msg.h"

class CapabilityReportTest : public em_capability_t {
public:
    dm_easy_mesh_t *dm = nullptr;
    em_state_t state = em_state_agent_configured;
    std::vector<unsigned char> report;

    void query(mac_address_t sta, bssid_t bssid)
    {
        em_msg_builder_t msg;
        mac_address_t source = {};
        msg.add_1905_header(source, source, em_msg_type_client_cap_query, 0x1234);
        unsigned char *tlv = msg.tlv_value();
        memcpy(tlv, bssid, sizeof(bssid_t));
        memcpy(tlv + sizeof(bssid_t), sta, sizeof(mac_address_t));
        msg.commit_tlv(em_tlv_type_client_info, 2 * sizeof(mac_address_t));
        if (!msg.add_eom()) {
            ADD_FAILURE() << "Failed to build capability query";
            return;
        }
        process_msg(msg.get_buff(), msg.get_len());
    }

    int send_frame(unsigned char *buff, unsigned int len, bool) override
    {
        report.assign(buff, buff + len);
        return static_cast<int>(len);
    }

    em_mgr_t *get_mgr() override { return nullptr; }
    dm_easy_mesh_t *get_data_model() override { return dm; }
    em_state_t get_state() override { return state; }
    void set_state(em_state_t value) override { state = value; }
    em_service_type_t get_service_type() override { return em_service_type_agent; }
    em_profile_type_t get_profile_type() override { return em_profile_type_3; }
    void set_profile_type(em_profile_type_t) override {}
    unsigned char *get_radio_interface_mac() override { return nullptr; }
    em_interface_t *get_radio_interface() override { return nullptr; }
    unsigned char *get_al_interface_mac() override { return nullptr; }
    rdk_wifi_radio_t *get_radio_data(em_interface_t *) override { return nullptr; }
    em_ieee_1905_security_cap_t *get_ieee_1905_security_cap() override { return nullptr; }
    em_device_info_t *get_device_info() override { return nullptr; }
    unsigned char *get_peer_mac() override { return nullptr; }
    em_crypto_info_t *get_crypto_info() override { return nullptr; }
    em_crypto_t *get_crypto() override { return nullptr; }
    em_cmd_t *get_current_cmd() override { return nullptr; }
    short create_ap_radio_basic_cap(unsigned char *) override { return 0; }
    short create_ap_cap_tlv(unsigned char *) override { return 0; }
    int create_akm_suite_cap_tlv(uint8_t *) override { return 0; }
    short create_ht_tlv(unsigned char *) override { return 0; }
    short create_vht_tlv(unsigned char *) override { return 0; }
    short create_he_tlv(unsigned char *) override { return 0; }
    short create_wifi6_tlv(unsigned char *) override { return 0; }
    short create_airties_radio_capability_tlv(unsigned char *) override { return 0; }
    int handle_wifi6_cap_tlv(unsigned char *) override { return 0; }
    int handle_wifi7_agent_cap_tlv(unsigned char *) override { return 0; }
    short create_wifi7_tlv(unsigned char *) override { return 0; }
    unsigned short create_eht_operations_tlv(unsigned char *) override { return 0; }
    short create_channelscan_tlv(unsigned char *) override { return 0; }
    short create_prof_2_tlv(unsigned char *) override { return 0; }
    short create_device_inventory_tlv(unsigned char *) override { return 0; }
    short create_ap_radio_advanced_cap_tlv(unsigned char *) override { return 0; }
    short create_metric_col_int_tlv(unsigned char *) override { return 0; }
    short create_cac_cap_tlv(unsigned char *) override { return 0; }
    int handle_eht_operations_tlv(unsigned char *, unsigned short) override { return 0; }
};

TEST(AgentCapabilityReport, UsesCurrentStationAfterReplacement)
{
    std::unique_ptr<dm_easy_mesh_t> dm(new dm_easy_mesh_t());
    ASSERT_EQ(dm->init(), 0);
    em_sta_info_t info = {};
    info.id[5] = 2;
    info.bssid[5] = 3;
    info.radiomac[5] = 1;
    std::vector<unsigned char> old_body(1500, 0x7f);
    info.frame_body = old_body.data();
    info.frame_body_len = static_cast<unsigned int>(old_body.size());
    dm_easy_mesh_t src;
    ASSERT_EQ(src.init(), 0);
    auto stage = [&src](em_sta_info_t &station, hash_map_t *map) {
        const char *src_key = "update";
        delete static_cast<dm_sta_t *>(hash_map_remove(map, src_key));
        hash_map_put(map, strdup(src_key), new dm_sta_t(&station));
    };
    stage(info, src.m_sta_assoc_map);
    dm->merge_assoc_sta_updates(src);

    CapabilityReportTest capability;
    capability.dm = dm.get();
    constexpr unsigned int report_overhead = sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t) +
        4 * sizeof(em_tlv_t) + 3 * sizeof(mac_address_t) + 2;
    constexpr unsigned int report_body_limit = EM_MAX_MSG_SZ - report_overhead;
    constexpr unsigned int body_limit = report_body_limit < EM_MAX_FRAME_BODY_LEN ?
        report_body_limit : EM_MAX_FRAME_BODY_LEN;
    const unsigned int lengths[] = {body_limit, EM_MAX_FRAME_BODY_LEN, 4, 1400};
    for (unsigned int length : lengths) {
        SCOPED_TRACE(length);
        std::vector<unsigned char> body(length, 0x5a);
        info.frame_body = body.data();
        info.frame_body_len = length;
        stage(info, src.m_sta_assoc_map);
        dm->merge_assoc_sta_updates(src);
        capability.report.clear();
        capability.query(info.id, info.bssid);

        const unsigned int retained = length > body_limit ? body_limit : length;
        ASSERT_EQ(capability.report.size(), report_overhead + retained);
        EXPECT_LE(capability.report.size(), static_cast<size_t>(EM_MAX_MSG_SZ));
        const unsigned char *frame = capability.report.data();
        const em_cmdu_t *cmdu = reinterpret_cast<const em_cmdu_t *>(frame + sizeof(em_raw_hdr_t));
        EXPECT_EQ(ntohs(cmdu->id), 0x1234);
        const em_tlv_t *client_info = reinterpret_cast<const em_tlv_t *>(
            frame + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
        ASSERT_EQ(client_info->type, em_tlv_type_client_info);
        ASSERT_EQ(ntohs(client_info->len), 2 * sizeof(mac_address_t));
        const em_tlv_t *cap = reinterpret_cast<const em_tlv_t *>(
            client_info->value + ntohs(client_info->len));
        ASSERT_EQ(cap->type, em_tlv_type_client_cap_report);
        ASSERT_EQ(ntohs(cap->len), retained + 1);
        EXPECT_EQ(cap->value[0], 0);
        EXPECT_EQ(memcmp(cap->value + 1, body.data(), retained), 0);
        const em_tlv_t *error = reinterpret_cast<const em_tlv_t *>(cap->value + ntohs(cap->len));
        ASSERT_EQ(error->type, em_tlv_type_error_code);
        ASSERT_EQ(ntohs(error->len), 1 + sizeof(mac_address_t));
        EXPECT_EQ(error->value[0], 0);
        EXPECT_EQ(memcmp(error->value + 1, info.id, sizeof(mac_address_t)), 0);
        const em_tlv_t *eom = reinterpret_cast<const em_tlv_t *>(error->value + ntohs(error->len));
        EXPECT_EQ(eom->type, em_tlv_type_eom);
        EXPECT_EQ(ntohs(eom->len), 0);
        EXPECT_EQ(reinterpret_cast<const unsigned char *>(eom) + sizeof(em_tlv_t),
            frame + capability.report.size());
        EXPECT_EQ(capability.state, em_state_agent_configured);
    }

    constexpr unsigned int update_count = 5000;
    constexpr unsigned int updates_per_checkpoint = 99;
    constexpr unsigned int checkpoint_count =
        (update_count + updates_per_checkpoint - 1) / updates_per_checkpoint;
    std::atomic<bool> start(false);
    std::atomic<bool> writer_done(false);
    std::atomic<unsigned int> completed_updates(0);
    std::atomic<unsigned int> completed_queries(0);
    std::thread writer([&]() {
        while (!start.load()) {
            std::this_thread::yield();
        }
        em_sta_info_t replacement = info;
        dm_easy_mesh_t updates;
        if (updates.init() != 0) {
            writer_done.store(true);
            return;
        }
        for (unsigned int i = 0; i < update_count; i++) {
            std::vector<unsigned char> body(i % 2 == 0 ? 4 : 1400, 0x5a);
            replacement.frame_body = body.data();
            replacement.frame_body_len = static_cast<unsigned int>(body.size());
            if (i % 7 == 0) {
                auto *removed = new dm_sta_t(&replacement);
                hash_map_put(updates.m_sta_dassoc_map, strdup("removed"), removed);
                dm->merge_assoc_sta_updates(updates);
                delete static_cast<dm_sta_t *>(hash_map_remove(updates.m_sta_dassoc_map, "removed"));
            }
            delete static_cast<dm_sta_t *>(hash_map_remove(updates.m_sta_assoc_map, "update"));
            hash_map_put(updates.m_sta_assoc_map, strdup("update"), new dm_sta_t(&replacement));
            dm->merge_assoc_sta_updates(updates);
            unsigned int updates_finished = i + 1;
            completed_updates.store(updates_finished);
            if (updates_finished % updates_per_checkpoint == 0 ||
                    updates_finished == update_count) {
                unsigned int checkpoint =
                    (updates_finished + updates_per_checkpoint - 1) / updates_per_checkpoint;
                while (completed_queries.load() < checkpoint) {
                    std::this_thread::yield();
                }
            }
        }
        delete static_cast<dm_sta_t *>(hash_map_remove(updates.m_sta_assoc_map, "update"));
        writer_done.store(true);
    });
    start.store(true);
    for (unsigned int checkpoint = 1; checkpoint <= checkpoint_count; checkpoint++) {
        const unsigned int target_updates = checkpoint * updates_per_checkpoint < update_count ?
            checkpoint * updates_per_checkpoint : update_count;
        while (completed_updates.load() < target_updates && !writer_done.load()) {
            std::this_thread::yield();
        }
        if (completed_updates.load() < target_updates) {
            ADD_FAILURE() << "Writer stopped after " << completed_updates.load()
                << " updates";
            break;
        }
        capability.report.clear();
        capability.query(info.id, info.bssid);
        completed_queries.store(checkpoint);
        if (capability.report.empty()) {
            ADD_FAILURE() << "Capability report is empty after " << target_updates
                << " writer updates";
            continue;
        }
        const size_t cap_offset = sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t) +
            sizeof(em_tlv_t) + 2 * sizeof(mac_address_t);
        if (capability.report.size() <= cap_offset + sizeof(em_tlv_t)) {
            ADD_FAILURE() << "Capability report is truncated";
            continue;
        }
        const em_tlv_t *cap = reinterpret_cast<const em_tlv_t *>(
            capability.report.data() + cap_offset);
        unsigned int cap_len = ntohs(cap->len);
        const unsigned int update_index = target_updates - 1;
        const unsigned int expected_body_len = update_index % 2 == 0 ? 4 : 1400;
        if (cap_len != expected_body_len + 1 ||
                cap_offset + sizeof(em_tlv_t) + cap_len > capability.report.size()) {
            ADD_FAILURE() << "Inconsistent frame snapshot length: " << cap_len;
            continue;
        }
        EXPECT_EQ(cap->value[0], 0);
        for (unsigned int j = 1; j < cap_len; j++) {
            EXPECT_EQ(cap->value[j], 0x5a);
        }
    }
    writer.join();
    EXPECT_EQ(completed_updates.load(), update_count);
    EXPECT_EQ(completed_queries.load(), checkpoint_count);

    delete static_cast<dm_sta_t *>(hash_map_remove(src.m_sta_assoc_map, "update"));
    info.frame_body = nullptr;
    info.frame_body_len = 0;
    hash_map_put(src.m_sta_dassoc_map, strdup("removed"), new dm_sta_t(&info));
    dm->merge_assoc_sta_updates(src);
    capability.report.clear();
    capability.query(info.id, info.bssid);
    EXPECT_TRUE(capability.report.empty());
    delete static_cast<dm_sta_t *>(hash_map_remove(src.m_sta_dassoc_map, "removed"));
}
