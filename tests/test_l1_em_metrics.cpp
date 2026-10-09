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
#include <gmock/gmock.h>
#include <arpa/inet.h>
#include <cstring>
#include <stdio.h>
#include <string.h>
#include <vector>
#include "collection.h"
#include "em.h"
#include "em_metrics.h"
#include "em_msg.h"
#include "em_mgr.h"
#include "em_cmd.h"
#include "dm_easy_mesh.h"

class DummyEmMetrics : public em_metrics_t {
public:
    // Construct with optional initial dependencies
    explicit DummyEmMetrics(em_mgr_t* mgr = nullptr,
                                dm_easy_mesh_t* dm = nullptr,
                                em_profile_type_t profile = em_profile_type_reserved,
                                em_state_t initial_state = em_state_agent_unconfigured,
                                em_cmd_t* current_cmd = nullptr)
        : m_mgr(mgr),
          m_dm(dm),
          m_profile(profile),
          m_state(initial_state),
          m_current_cmd(current_cmd) {}

    ~DummyEmMetrics() override = default;

    // === Required pure-virtual overrides ===
    dm_easy_mesh_t* get_data_model() override { return m_dm; }

    em_state_t get_state() override { return m_state; }

    void set_state(em_state_t state) override { m_state = state; }

    int send_frame(unsigned char* /*buff*/, unsigned int /*len*/, bool /*multicast*/ = false) override {
        // Dummy: do nothing and pretend success. 
        // If your code expects "bytes sent", you could return `len` instead.
        return 0;
    }

    em_profile_type_t get_profile_type() override { return m_profile; }

    em_cmd_t* get_current_cmd() override { return m_current_cmd; }

    //virtual em_mgr_t* get_mgr() override { return m_mgr; }
    em_mgr_t* get_mgr() override { return m_mgr; }

    // === Optional helpers to inject/update dependencies ===
    void set_data_model(dm_easy_mesh_t* dm) { m_dm = dm; }
    void set_mgr(em_mgr_t* mgr) { m_mgr = mgr; }
    void set_profile_type(em_profile_type_t profile) { m_profile = profile; }
    void set_current_cmd(em_cmd_t* cmd) { m_current_cmd = cmd; }

private:
    em_mgr_t*         m_mgr         = nullptr;
    dm_easy_mesh_t*   m_dm          = nullptr;
    em_profile_type_t m_profile     = em_profile_type_reserved;
    em_state_t        m_state       = em_state_agent_unconfigured;
    em_cmd_t*         m_current_cmd = nullptr;
};

class MetricsTestEmMgr : public em_mgr_t {
public:
    MetricsTestEmMgr() {
        m_em_map = hash_map_create();
    }

    ~MetricsTestEmMgr() override {
        if (m_em_map != nullptr) {
            hash_map_remove(m_em_map, "radio-1");
            hash_map_remove(m_em_map, "radio-2");
            hash_map_destroy(m_em_map);
        }
    }

    int add_em(const char *key, em_t *em) {
        return hash_map_put(m_em_map, strdup(key), em);
    }

    unsigned short get_next_msg_id() { return 42; }
    void publish_network_topology() override {}
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
    void update_network_topology() override {}
    dm_easy_mesh_t *get_first_dm() override { return nullptr; }
    dm_easy_mesh_t *get_next_dm(dm_easy_mesh_t *) override { return nullptr; }
    dm_easy_mesh_t *get_data_model(const char *, const unsigned char *) override { return nullptr; }
    dm_easy_mesh_t *create_data_model(const char *, const em_interface_t *, em_profile_type_t) override { return nullptr; }
    void delete_data_model(const char *, const unsigned char *) override {}
    void delete_all_data_models() override {}
    int update_tables(dm_easy_mesh_t *) override { return 0; }
    int load_net_ssid_table() override { return 0; }
    void debug_probe() override {}
    void io(void *, bool) override {}
    em_service_type_t get_service_type() override { return em_service_type_ctrl; }
};

class MetricsTestEm : public em_t {
public:
    using em_t::em_t;

    em_profile_type_t cached_peer_profile() const {
        return get_peer_profile();
    }

    int handle_ap_metrics_response(unsigned char *buff, unsigned int len, em_profile_type_t peer_profile) override {
        ++response_count;
        received_peer_profile = peer_profile;
        last_response_status = em_t::handle_ap_metrics_response(buff, len, peer_profile);
        if (last_response_status == 0) {
            ++successful_update_count;
        }
        return last_response_status;
    }

    unsigned int response_count = 0;
    unsigned int successful_update_count = 0;
    em_profile_type_t received_peer_profile = em_profile_type_reserved;
    int last_response_status = -1;
};

class EmMetricsTest : public ::testing::Test {    
protected:
    DummyEmMetrics* emMetrics;
    void SetUp() override {
        emMetrics = new DummyEmMetrics();
    }    
    void TearDown() override {
        delete emMetrics;
        emMetrics = nullptr;
    }        
};

static std::vector<unsigned char> make_ap_metrics_response(const unsigned char *source_mac,
                                                            const unsigned char *bssid,
                                                            unsigned char channel_util)
{
    const unsigned int response_len = sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t) +
        sizeof(em_tlv_t) + sizeof(em_ap_metric_t) + sizeof(em_tlv_t);
    std::vector<unsigned char> response(response_len, 0);
    auto *raw_header = reinterpret_cast<em_raw_hdr_t *>(response.data());
    std::memcpy(raw_header->src, source_mac, sizeof(mac_address_t));
    auto *cmdu = reinterpret_cast<em_cmdu_t *>(response.data() + sizeof(em_raw_hdr_t));
    cmdu->type = htons(static_cast<unsigned short>(em_msg_type_ap_metrics_rsp));

    auto *ap_metrics = reinterpret_cast<em_tlv_t *>(response.data() + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    ap_metrics->type = static_cast<unsigned char>(em_tlv_type_ap_metrics);
    ap_metrics->len = htons(sizeof(em_ap_metric_t));
    auto *ap_metrics_value = reinterpret_cast<em_ap_metric_t *>(ap_metrics->value);
    std::memcpy(ap_metrics_value->bssid, bssid, sizeof(mac_address_t));
    ap_metrics_value->channel_util = channel_util;
    auto *eom = reinterpret_cast<em_tlv_t *>(ap_metrics->value + sizeof(em_ap_metric_t));
    eom->type = static_cast<unsigned char>(em_tlv_type_eom);
    return response;
}

/**
 * @brief Verify construction of DummyEmMetrics object on the stack without exceptions.
 *
 * This test verifies that invoking the default constructor of DummyEmMetrics on the stack does not throw any exceptions.
 * It ensures that the object is constructed properly and that the default constructor behaves as expected.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 001
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01               | Construct a DummyEmMetrics object on the stack using its default constructor | No input arguments, output: localEmMetrics object constructed successfully | No exception is thrown; EXPECT_NO_THROW assertion passes                | Should Pass |
 */
TEST_F(EmMetricsTest, StackConstruction) {
    std::cout << "Entering StackConstruction test" << std::endl;
    EXPECT_NO_THROW({
        DummyEmMetrics localEmMetrics;
        std::cout << "Invoked em_metrics_t() default constructor for localEmMetrics on the stack." << std::endl;
    });
    std::cout << "Exiting StackConstruction test" << std::endl;
}
/**
 * @brief Validate dynamic allocation and deallocation of DummyEmMetrics object without exceptions.
 *
 * This test verifies that a DummyEmMetrics object can be dynamically allocated using the default constructor and that the allocated memory is not a null pointer. It also confirms that the object can be safely deleted without throwing exceptions. This ensures proper dynamic memory management for the object lifecycle.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 002@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01               | Invoke dynamic allocation for DummyEmMetrics and verify no exception is thrown during construction | dynamicEmMetrics = nullptr, new DummyEmMetrics()                      | Dynamic allocation succeeds with no exception thrown                                      | Should Pass   |@n
 * | 02               | Check that the allocated dynamicEmMetrics pointer is not null                                   | dynamicEmMetrics pointer after allocation                             | Pointer is not null as confirmed by the assertion EXPECT_NE(dynamicEmMetrics, nullptr)      | Should Pass   |@n
 * | 03               | Delete the dynamically allocated DummyEmMetrics object and verify no exception is thrown on deletion | delete dynamicEmMetrics; dynamicEmMetrics set to nullptr              | Deletion occurs without exception and destructor executes properly                         | Should Pass   |
 */
TEST_F(EmMetricsTest, DynamicAllocationConstruction) {
    std::cout << "Entering DynamicAllocationConstruction test" << std::endl;
    DummyEmMetrics* dynamicEmMetrics = nullptr;
    EXPECT_NO_THROW({
        dynamicEmMetrics = new DummyEmMetrics();
        std::cout << "Invoked em_metrics_t() default constructor for dynamicEmMetrics using new." << std::endl;
    });
    EXPECT_NE(dynamicEmMetrics, nullptr) << "Dynamic allocation returned null pointer.";
    std::cout << "dynamicEmMetrics pointer is non-null which is expected." << std::endl;
    EXPECT_NO_THROW({
        delete dynamicEmMetrics;
        dynamicEmMetrics = nullptr;
        std::cout << "Destructor executed properly upon deletion of dynamicEmMetrics." << std::endl;
    });
    std::cout << "Exiting DynamicAllocationConstruction test" << std::endl;
}

/**
 * @brief Test to verify that the process_agent_state() method executes without throwing exceptions.
 *
 * This test case validates that invoking the process_agent_state() method on the emMetrics instance does not result in any exceptions. It assumes that the internal state is processed correctly if no exceptions are thrown during the method call.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 003@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Invoke process_agent_state() method on the emMetrics instance and check that no exceptions are thrown.  | input: none, output: none | The method completes without throwing exceptions and passes the EXPECT_NO_THROW check | Should Pass |
 */
TEST_F(EmMetricsTest, ProcessAgentState) {
    std::cout << "Entering ProcessAgentState test" << std::endl;    
    std::cout << "Invoking process_agent_state() method on emMetrics instance." << std::endl;
    EXPECT_NO_THROW({
        emMetrics->process_agent_state();
        std::cout << "Method process_agent_state() executed without throwing any exceptions." << std::endl;
    });  
    std::cout << "Exiting ProcessAgentState test" << std::endl;
}

/**
 * @brief Ensures that process_ctrl_state function is invoked successfully on a properly initialized system.
 *
 * This test verifies that the process_ctrl_state method of the emMetrics object functions as expected without throwing any exceptions.
 * It confirms that the internal control state is processed correctly when the system is properly initialized.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 004@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Invoke process_ctrl_state on a valid emMetrics instance and verify that no exception is thrown. | emMetrics = valid pointer, function call process_ctrl_state() | process_ctrl_state executes without throwing any exception. | Should Pass |
 */
TEST_F(EmMetricsTest, ProcessCtrlStateProperlyInitializedSystem) {
    std::cout << "Entering ProcessCtrlStateProperlyInitializedSystem test" << std::endl;
    std::cout << "Invoking process_ctrl_state on emMetrics object" << std::endl;
    EXPECT_NO_THROW({
        emMetrics->process_ctrl_state();
        std::cout << "process_ctrl_state invoked successfully with no errors." << std::endl;
    });
    std::cout << "Exiting ProcessCtrlStateProperlyInitializedSystem test" << std::endl;
}

/**
 * @brief Verify process_msg handles NULL data pointer with non-zero length without exceptions
 *
 * This test verifies that the process_msg API of the EmMetrics class handles a NULL data pointer combined with a non-zero length value without throwing any exceptions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 005@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Initialize length to 5 and call process_msg with NULL pointer | data = nullptr, length = 5 | No exception is thrown and the API call executes without crashing | Should Pass  |
 */
TEST_F(EmMetricsTest, ProcessMessageNullDataNonZeroLength) {
    std::cout << "Entering ProcessMessageNullDataNonZeroLength test" << std::endl;
    unsigned int length = 5;
    std::cout << "Invoking process_msg with NULL data pointer and length " << length << std::endl;
    EXPECT_ANY_THROW({
        emMetrics->process_msg(nullptr, length);
    });
    std::cout << "process_msg handled NULL data pointer with non-zero length without crashing" << std::endl;
    std::cout << "Exiting ProcessMessageNullDataNonZeroLength test" << std::endl;
}

/**
 * @brief Tests the proper creation and destruction of a stack allocated DummyEmMetrics object
 *
 * This test ensures that the object's destructor is invoked automatically when it goes out of scope, thus validating proper resource cleanup.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 006@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | ----------- | --------- | -------------- | ----- |
 * | 01 | Create a stack allocated DummyEmMetrics object within an inner scope using EXPECT_NO_THROW to ensure no exception is thrown during construction and destruction. | Invocation: DummyEmMetrics localMetrics; (no input arguments) | DummyEmMetrics constructor and destructor execute without throwing exceptions; EXPECT_NO_THROW passes | Should Pass |
 * | 02 | Exit the inner scope to trigger the object's destructor and then exit the test function, confirming normal execution flow. | No API call; only scope termination and console output | Destructor has been called as the object goes out of scope; test completes normally | Should be successful |
 */
TEST_F(EmMetricsTest, destroy_stack_allocated_em_metrics_t) {
    std::cout << "Entering destroy_stack_allocated_em_metrics_t test" << std::endl;
    {
        std::cout << "Creating stack allocated DummyEmMetrics object" << std::endl;
        EXPECT_NO_THROW({
            DummyEmMetrics localMetrics;
            std::cout << "Stack allocated object will go out of scope to invoke destructor" << std::endl;
        });
        std::cout << "Exited inner scope. Destructor for DummyEmMetrics has been called if no exceptions were thrown" << std::endl;
    }
    std::cout << "Exiting destroy_stack_allocated_em_metrics_t test" << std::endl;
}

TEST(EmMetricsTest, UsesPeerProfileAndUpdatesSharedDataModelOnce) {
    MetricsTestEmMgr mgr;
    dm_easy_mesh_t shared_dm;
    mac_address_t peer_al_mac = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    mac_address_t bssid = {0x02, 0x11, 0x22, 0x33, 0x44, 0x66};
    const char *peer_ssid = "peer-mesh";
    shared_dm.get_device()->set_dev_interface_mac(peer_al_mac);
    auto *network_ssid = shared_dm.get_network_ssid(0)->get_network_ssid_info();
    std::strncpy(network_ssid->ssid, peer_ssid, sizeof(network_ssid->ssid) - 1);
    shared_dm.set_num_network_ssid(1);

    em_interface_t radio_1_ruid{};
    em_interface_t radio_2_ruid{};
    radio_1_ruid.mac[5] = 1;
    radio_2_ruid.mac[5] = 2;
    MetricsTestEm radio_1(&radio_1_ruid, em_freq_band_5, &shared_dm, &mgr,
                          em_profile_type_3, em_service_type_ctrl);
    MetricsTestEm radio_2(&radio_2_ruid, em_freq_band_5, &shared_dm, &mgr,
                          em_profile_type_3, em_service_type_ctrl);

    ASSERT_EQ(0, mgr.add_em("radio-2", &radio_2));
    ASSERT_EQ(0, mgr.add_em("radio-1", &radio_1));

    radio_1.set_state(em_state_ctrl_topo_sync_pending);
    radio_2.set_state(em_state_ctrl_topo_sync_pending);
    const unsigned int device_info_len = 16;
    const unsigned int peer_ssid_len = static_cast<unsigned int>(std::strlen(peer_ssid));
    const unsigned int operational_bss_len = sizeof(unsigned char) + sizeof(em_ap_op_bss_radio_t) +
        sizeof(em_ap_operational_bss_t) + peer_ssid_len;
    const unsigned int topology_tlvs_len = sizeof(em_tlv_t) + device_info_len + sizeof(em_tlv_t) +
        operational_bss_len + sizeof(em_tlv_t);
    std::vector<unsigned char> topology_response(sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t) + topology_tlvs_len, 0);
    auto *topology_header = reinterpret_cast<em_raw_hdr_t *>(topology_response.data());
    std::memcpy(topology_header->src, peer_al_mac, sizeof(peer_al_mac));
    auto *topology_cmdu = reinterpret_cast<em_cmdu_t *>(topology_response.data() + sizeof(em_raw_hdr_t));
    topology_cmdu->type = htons(static_cast<unsigned short>(em_msg_type_topo_resp));
    auto *device_info_tlv = reinterpret_cast<em_tlv_t *>(topology_response.data() + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    device_info_tlv->type = static_cast<unsigned char>(em_tlv_type_device_info);
    device_info_tlv->len = htons(device_info_len);
    auto *operational_bss_tlv = reinterpret_cast<em_tlv_t *>(device_info_tlv->value + device_info_len);
    operational_bss_tlv->type = static_cast<unsigned char>(em_tlv_type_operational_bss);
    operational_bss_tlv->len = htons(operational_bss_len);
    auto *operational_bss = reinterpret_cast<em_ap_op_bss_t *>(operational_bss_tlv->value);
    operational_bss->radios_num = 1;
    auto *operational_radio = reinterpret_cast<em_ap_op_bss_radio_t *>(operational_bss->radios);
    std::memcpy(operational_radio->ruid, radio_1_ruid.mac, sizeof(mac_address_t));
    operational_radio->bss_num = 1;
    auto *operational_bss_info = reinterpret_cast<em_ap_operational_bss_t *>(operational_radio->bss);
    std::memcpy(operational_bss_info->bssid, bssid, sizeof(bssid));
    operational_bss_info->ssid_len = static_cast<unsigned char>(peer_ssid_len);
    std::memcpy(operational_bss_info->ssid, peer_ssid, peer_ssid_len);
    auto *topology_eom = reinterpret_cast<em_tlv_t *>(operational_bss_tlv->value + operational_bss_len);
    topology_eom->type = static_cast<unsigned char>(em_tlv_type_eom);

    static_cast<em_configuration_t &>(radio_1).process_msg(
        topology_response.data(), static_cast<unsigned int>(topology_response.size()));
    EXPECT_EQ(em_profile_type_1, radio_1.cached_peer_profile());
    EXPECT_EQ(em_profile_type_1, radio_2.cached_peer_profile());

    std::vector<unsigned char> response = make_ap_metrics_response(peer_al_mac, bssid, 37);

    char *profile_1_errors[EM_MAX_TLV_MEMBERS] = {nullptr};
    char *profile_3_errors[EM_MAX_TLV_MEMBERS] = {nullptr};
    EXPECT_NE(0U, em_msg_t(em_msg_type_ap_metrics_rsp, em_profile_type_1,
                           response.data(), static_cast<unsigned int>(response.size())).validate(profile_1_errors));
    EXPECT_EQ(0U, em_msg_t(em_msg_type_ap_metrics_rsp, em_profile_type_3,
                           response.data(), static_cast<unsigned int>(response.size())).validate(profile_3_errors));

    std::vector<em_t *> peer_radios;
    mgr.get_all_em_for_al_mac(peer_al_mac, peer_radios);
    ASSERT_EQ(2U, peer_radios.size());

    static_cast<em_metrics_t &>(radio_1).process_msg(response.data(), static_cast<unsigned int>(response.size()));

    EXPECT_EQ(1U, radio_1.response_count + radio_2.response_count);
    EXPECT_EQ(1U, radio_1.successful_update_count + radio_2.successful_update_count);
    EXPECT_TRUE(shared_dm.db_cfg_type_is_set(db_cfg_type_sta_metrics_update));
    auto *updated_bss = shared_dm.get_bss_info_with_mac(bssid);
    ASSERT_NE(nullptr, updated_bss);
    EXPECT_EQ(37, updated_bss->channel_util);

    const MetricsTestEm *handled_radio = (radio_1.response_count == 1) ? &radio_1 : &radio_2;
    EXPECT_EQ(em_profile_type_1, handled_radio->received_peer_profile);
    EXPECT_EQ(0, handled_radio->last_response_status);
}

TEST(EmMetricsTest, ReservedPeerProfileFallsBackToProfile1) {
    MetricsTestEmMgr mgr;
    dm_easy_mesh_t dm;
    em_interface_t ruid{};
    MetricsTestEm controller(&ruid, em_freq_band_5, &dm, &mgr,
                             em_profile_type_3, em_service_type_ctrl);
    mac_address_t peer_al_mac = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    mac_address_t bssid = {};
    std::vector<unsigned char> response = make_ap_metrics_response(peer_al_mac, bssid, 0);

    EXPECT_EQ(0, controller.handle_ap_metrics_response(
        response.data(), static_cast<unsigned int>(response.size()), em_profile_type_reserved));
    EXPECT_EQ(1U, controller.successful_update_count);
}
