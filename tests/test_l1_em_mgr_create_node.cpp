/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2026 RDK Management
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
#include <cstring>
#include <string>
#include "em_mgr.h"
#include "em.h"

/*
 * em_mgr_t::create_node(): the em_t constructor throws std::runtime_error for the AL node when its EC
 * manager cannot be initialised (here: a NULL data model makes initialize_ec_manager() fail). The
 * exception must not escape create_node(): it returns NULL, constructs the node once, and leaves no
 * node registered under the key.
 */

class CreateNodeTestMgr : public em_mgr_t {
public:
    CreateNodeTestMgr() { m_em_map = hash_map_create(); }
    ~CreateNodeTestMgr() override {
        if (m_em_map != nullptr) {
            hash_map_destroy(m_em_map);
        }
    }
    bool has_node(const char *key) { return hash_map_get(m_em_map, key) != nullptr; }

    bool is_data_model_initialized() override { return true; }
    em_t *find_em_for_msg_type(unsigned char *, unsigned int, em_t *) override { return nullptr; }
    int data_model_init(const char *) override { return 0; }
    int orch_init() override { return 0; }
    void input_listener() override {}
    void start_complete() override {}
    void handle_event(em_event_t *) override {}
    void handle_5s_tick() override {}
    void handle_2s_tick() override {}
    void handle_1s_tick() override {}
    void handle_250ms_tick() override {}
    void io(void *, bool) override {}
    void update_network_topology() override {}
    void publish_network_topology() override {}
    dm_easy_mesh_t *get_first_dm() override { return nullptr; }
    dm_easy_mesh_t *get_next_dm(dm_easy_mesh_t *) override { return nullptr; }
    dm_easy_mesh_t *get_data_model(const char *, const unsigned char *) override { return nullptr; }
    dm_easy_mesh_t *create_data_model(const char *, const em_interface_t *, em_profile_type_t) override { return nullptr; }
    void delete_data_model(const char *, const unsigned char *) override {}
    void delete_all_data_models() override {}
    int update_tables(dm_easy_mesh_t *) override { return 0; }
    int load_net_ssid_table() override { return 0; }
    void debug_probe() override {}
    em_service_type_t get_service_type() override { return em_service_type_ctrl; }
};

class em_mgr_create_node_Test : public ::testing::Test {
protected:
    CreateNodeTestMgr mgr;
    em_interface_t ruid;
    dm_easy_mesh_t dm;

    void SetUp() override {
        memset(&ruid, 0, sizeof(ruid));
        snprintf(ruid.name, sizeof(ruid.name), "wlan0");
        ruid.mac[0] = 0x02;
        ruid.mac[5] = 0x01;
    }
    void TearDown() override {
        /* removes a node created by a test (stops it, removes the map entry, deletes it); no-op when absent */
        mgr.delete_node(&ruid);
    }
};

TEST_F(em_mgr_create_node_Test, ConstructorExceptionOfTheAlNodeIsCaught) {
    em_t *node = reinterpret_cast<em_t *>(0x1);
    EXPECT_NO_THROW(node = mgr.create_node(&ruid, em_freq_band_24, nullptr, true, em_profile_type_1, em_service_type_ctrl));
    EXPECT_EQ(node, nullptr);
}

TEST_F(em_mgr_create_node_Test, FailedNodeIsNotRegistered) {
    EXPECT_EQ(mgr.create_node(&ruid, em_freq_band_24, nullptr, true, em_profile_type_1, em_service_type_ctrl), nullptr);
    EXPECT_FALSE(mgr.has_node("02:00:00:00:00:01_al"));
    EXPECT_FALSE(mgr.has_node("02:00:00:00:00:01"));
}

TEST_F(em_mgr_create_node_Test, CreationCanBeRetriedAfterAFailure) {
    for (int i = 0; i < 3; i++) {
        em_t *node = reinterpret_cast<em_t *>(0x1);
        EXPECT_NO_THROW(node = mgr.create_node(&ruid, em_freq_band_24, nullptr, true, em_profile_type_1, em_service_type_ctrl));
        EXPECT_EQ(node, nullptr) << "attempt " << i;
        EXPECT_FALSE(mgr.has_node("02:00:00:00:00:01_al")) << "attempt " << i;
    }
}

TEST_F(em_mgr_create_node_Test, NullRuidIsRejected) {
    EXPECT_EQ(mgr.create_node(nullptr, em_freq_band_24, nullptr, true, em_profile_type_1, em_service_type_ctrl), nullptr);
}

/* Success path: a radio (non-AL) node is built once, initialised and registered under its MAC. */
TEST_F(em_mgr_create_node_Test, SuccessfulCreationReturnsTheRegisteredNode) {
    em_t *node = mgr.create_node(&ruid, em_freq_band_24, &dm, false, em_profile_type_1, em_service_type_ctrl);
    ASSERT_NE(node, nullptr);
    EXPECT_TRUE(mgr.has_node("02:00:00:00:00:01"));
    EXPECT_FALSE(mgr.has_node("02:00:00:00:00:01_al"));
}

TEST_F(em_mgr_create_node_Test, CreatingTheSameNodeAgainReturnsTheExistingNode) {
    em_t *first = mgr.create_node(&ruid, em_freq_band_24, &dm, false, em_profile_type_1, em_service_type_ctrl);
    ASSERT_NE(first, nullptr);
    EXPECT_EQ(mgr.create_node(&ruid, em_freq_band_24, &dm, false, em_profile_type_1, em_service_type_ctrl), first);
}

/* A constructor failure must not leave the manager unusable: the next creation succeeds. */
TEST_F(em_mgr_create_node_Test, NodeCanBeCreatedAfterAConstructorFailure) {
    EXPECT_EQ(mgr.create_node(&ruid, em_freq_band_24, nullptr, true, em_profile_type_1, em_service_type_ctrl), nullptr);
    EXPECT_FALSE(mgr.has_node("02:00:00:00:00:01_al"));

    em_t *node = mgr.create_node(&ruid, em_freq_band_24, &dm, false, em_profile_type_1, em_service_type_ctrl);
    ASSERT_NE(node, nullptr);
    EXPECT_TRUE(mgr.has_node("02:00:00:00:00:01"));
    EXPECT_FALSE(mgr.has_node("02:00:00:00:00:01_al"));
}
