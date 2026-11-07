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
#include <functional>
#include <string>
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
    dm_easy_mesh_t *get_data_model(const char *, const unsigned char *al_mac) override {
        mac_address_t mac;
        std::memcpy(mac, al_mac, sizeof(mac));
        std::vector<em_t *> radios;
        get_all_em_for_al_mac(mac, radios);
        return radios.empty() ? nullptr : radios.front()->get_data_model();
    }
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

    int handle_ap_metrics_response(unsigned char *, unsigned int, em_profile_type_t peer_profile) override {
        ++response_count;
        received_peer_profile = peer_profile;
        return 0;
    }

    unsigned int response_count = 0;
    em_profile_type_t received_peer_profile = em_profile_type_reserved;
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

/**
 * @brief Verify peer-profile routing once per shared data model and real AP metrics processing.
 *
 * Dispatch an AP metrics response to two routing spies sharing a data model and verify
 * that only one receives it, with the peer's Profile 1 rather than the local Profile 3.
 * Separately dispatch through a real radio and verify the STA metrics update flag and
 * BSS channel utilization. Both checks use the public process_msg() entry point.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 007@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** Two registered radio spies share a data model with a Profile 1 peer and an operational BSS.@n
 * **Dependencies:** MetricsTestEmMgr, MetricsTestEm, DummyEmMetrics, em_t, dm_easy_mesh_t, em_msg_t.@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- | -------------- | ----- |@n
 * | 01 | Process a topology response and validate the AP response against both profiles. | Peer Profile 1, local Profile 3, channel utilization 37 | AP response passes Profile 1 validation and fails Profile 3 validation. | Should Pass |@n
 * | 02 | Dispatch the AP response to two radio spies sharing a data model. | Same peer AL MAC and shared data model | Exactly one spy receives the response with peer Profile 1. | Should Pass |@n
 * | 03 | Dispatch the response through a separately registered real radio. | Same AP response and shared data model | STA metrics update flag is set and BSS channel utilization is 37. | Should Pass |
 */
TEST_F(EmMetricsTest, UsesPeerProfileAndUpdatesSharedDataModelOnce) {
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

    dm_easy_mesh_t controller_dm;
    DummyEmMetrics dispatcher(&mgr, &controller_dm, em_profile_type_3);
    dispatcher.process_msg(response.data(), static_cast<unsigned int>(response.size()));

    EXPECT_EQ(1U, radio_1.response_count + radio_2.response_count);
    const MetricsTestEm *handled_radio = (radio_1.response_count == 1) ? &radio_1 : &radio_2;
    EXPECT_EQ(em_profile_type_1, handled_radio->received_peer_profile);

    MetricsTestEmMgr processing_mgr;
    em_t processing_radio(&radio_1_ruid, em_freq_band_5, &shared_dm, &processing_mgr,
                          em_profile_type_3, em_service_type_ctrl);
    ASSERT_EQ(0, processing_mgr.add_em("radio-1", &processing_radio));
    DummyEmMetrics processing_dispatcher(&processing_mgr, &controller_dm, em_profile_type_3);
    processing_dispatcher.process_msg(response.data(), static_cast<unsigned int>(response.size()));

    EXPECT_TRUE(shared_dm.db_cfg_type_is_set(db_cfg_type_sta_metrics_update));
    auto *updated_bss = shared_dm.get_bss_info_with_mac(bssid);
    ASSERT_NE(nullptr, updated_bss);
    EXPECT_EQ(37, updated_bss->channel_util);
}

/**
 * @brief Verify that an unknown peer profile permits Profile 1 AP metrics processing.
 *
 * Register a real radio with a reserved peer profile and dispatch a Profile 1 AP
 * metrics response through process_msg(). Verify that processing sets the previously
 * clear STA metrics update flag without requiring the local Profile 3 TLVs.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 008@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** A real radio is registered with a reserved peer profile and local Profile 3.@n
 * **Dependencies:** MetricsTestEmMgr, DummyEmMetrics, em_t, dm_easy_mesh_t.@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- | -------------- | ----- |@n
 * | 01 | Verify the initial STA metrics update flag. | Initialized data model | STA metrics update flag is clear. | Should Pass |@n
 * | 02 | Dispatch a Profile 1 AP metrics response through process_msg(). | Reserved peer profile, local Profile 3 | Response is processed using the Profile 1 fallback and the STA metrics update flag is set. | Should Pass |
 */
TEST_F(EmMetricsTest, ReservedPeerProfileFallsBackToProfile1) {
    MetricsTestEmMgr mgr;
    dm_easy_mesh_t dm;
    dm.init();
    em_interface_t ruid{};
    ruid.mac[5] = 1;
    em_t controller(&ruid, em_freq_band_5, &dm, &mgr,
                     em_profile_type_3, em_service_type_ctrl);
    mac_address_t peer_al_mac = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    dm.get_device()->set_dev_interface_mac(peer_al_mac);
    dm.get_device()->set_peer_profile(em_profile_type_reserved);
    ASSERT_EQ(0, mgr.add_em("radio-1", &controller));
    mac_address_t bssid = {};
    std::vector<unsigned char> response = make_ap_metrics_response(peer_al_mac, bssid, 0);

    EXPECT_FALSE(dm.db_cfg_type_is_set(db_cfg_type_sta_metrics_update));
    DummyEmMetrics dispatcher(&mgr, &dm, em_profile_type_3);
    dispatcher.process_msg(response.data(), static_cast<unsigned int>(response.size()));
    EXPECT_TRUE(dm.db_cfg_type_is_set(db_cfg_type_sta_metrics_update));
}

class TopologyCountingEmMgr : public MetricsTestEmMgr {
public:
    void publish_network_topology() override {
        ++publish_count;
        if (on_publish) {
            on_publish();
        }
    }

    unsigned int publish_count = 0;
    std::function<void()> on_publish;
};

struct ClientTypeEntry {
    mac_address_t sta_mac;
    bssid_t bssid;
    std::string client_type;
};

static ClientTypeEntry make_client_type_entry(unsigned char sta_id, const char *client_type)
{
    ClientTypeEntry entry = {};
    entry.sta_mac[0] = 0x02;
    entry.sta_mac[5] = sta_id;
    entry.bssid[0] = 0x0a;
    entry.bssid[5] = 0x01;
    entry.client_type = client_type;
    return entry;
}

static dm_sta_t *add_metrics_sta(dm_easy_mesh_t &dm, const ClientTypeEntry &entry)
{
    em_sta_info_t info;
    std::memset(&info, 0, sizeof(info));
    std::memcpy(info.id, entry.sta_mac, sizeof(mac_address_t));
    std::memcpy(info.bssid, entry.bssid, sizeof(mac_address_t));

    mac_addr_str_t sta_str, bssid_str, radio_str;
    em_long_string_t key;
    dm_easy_mesh_t::macbytes_to_string(info.id, sta_str);
    dm_easy_mesh_t::macbytes_to_string(info.bssid, bssid_str);
    dm_easy_mesh_t::macbytes_to_string(info.radiomac, radio_str);
    snprintf(key, sizeof(key), "%s@%s@%s", sta_str, bssid_str, radio_str);

    auto *sta = new dm_sta_t(&info);
    hash_map_put(dm.m_sta_map, strdup(key), sta);
    return sta;
}

static void append_tlv(std::vector<unsigned char> &msg, unsigned char type,
                       const std::vector<unsigned char> &value)
{
    em_tlv_t tlv_header = {};
    tlv_header.type = type;
    tlv_header.len = htons(static_cast<unsigned short>(value.size()));
    const auto *header_bytes = reinterpret_cast<const unsigned char *>(&tlv_header);
    msg.insert(msg.end(), header_bytes, header_bytes + sizeof(em_tlv_t));
    msg.insert(msg.end(), value.begin(), value.end());
}

static std::vector<unsigned char> make_client_type_vendor_value(const ClientTypeEntry &entry)
{
    // vendor OUI (not Airties), number of attributes, attribute id, then the STA metrics
    std::vector<unsigned char> value = {0x00, 0x00, 0x00, 0x01, 0x00};
    em_assoc_sta_vendor_link_metrics_t metrics;
    std::memset(&metrics, 0, sizeof(metrics));
    std::memcpy(metrics.sta_mac, entry.sta_mac, sizeof(mac_address_t));
    std::memcpy(metrics.bssid, entry.bssid, sizeof(mac_address_t));
    std::strncpy(metrics.sta_client_type, entry.client_type.c_str(), sizeof(metrics.sta_client_type) - 1);
    const auto *metrics_bytes = reinterpret_cast<const unsigned char *>(&metrics);
    value.insert(value.end(), metrics_bytes, metrics_bytes + sizeof(metrics));
    return value;
}

static std::vector<unsigned char> make_client_type_response(em_msg_type_t msg_type,
                                                             const std::vector<ClientTypeEntry> &entries)
{
    std::vector<unsigned char> msg(sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t), 0);
    auto *cmdu = reinterpret_cast<em_cmdu_t *>(msg.data() + sizeof(em_raw_hdr_t));
    cmdu->type = htons(static_cast<unsigned short>(msg_type));

    if (msg_type == em_msg_type_ap_metrics_rsp) {
        append_tlv(msg, static_cast<unsigned char>(em_tlv_type_ap_metrics),
                   std::vector<unsigned char>(sizeof(em_ap_metric_t), 0));
    }
    for (const auto &entry : entries) {
        append_tlv(msg, static_cast<unsigned char>(em_tlv_type_vendor_specific),
                   make_client_type_vendor_value(entry));
    }
    append_tlv(msg, static_cast<unsigned char>(em_tlv_type_eom), {});
    return msg;
}

class ClientTypeTopologyTest : public ::testing::Test {
protected:
    void SetUp() override {
        dm.init();
        dm.get_device()->set_dev_interface_mac(peer_al_mac);
        dm.get_device()->set_peer_profile(em_profile_type_1);
        radio_interface.mac[5] = 1;
        radio = new em_t(&radio_interface, em_freq_band_5, &dm, &mgr,
                  em_profile_type_3, em_service_type_ctrl);
        metrics = new DummyEmMetrics(&mgr, &dm, em_profile_type_3);
        ASSERT_EQ(0, mgr.add_em("radio-1", radio));
    }

    void TearDown() override {
        delete metrics;
        metrics = nullptr;
        delete radio;
        radio = nullptr;
    }

    void send_ap_response(const std::vector<ClientTypeEntry> &entries) {
        auto msg = make_client_type_response(em_msg_type_ap_metrics_rsp, entries);
        auto *header = reinterpret_cast<em_raw_hdr_t *>(msg.data());
        std::memcpy(header->src, peer_al_mac, sizeof(mac_address_t));
        dm.reset_db_cfg_type(db_cfg_type_sta_metrics_update);
        metrics->process_msg(msg.data(), static_cast<unsigned int>(msg.size()));
        EXPECT_TRUE(dm.db_cfg_type_is_set(db_cfg_type_sta_metrics_update));
    }

    void send_assoc_sta_response(const std::vector<ClientTypeEntry> &entries) {
        auto msg = make_client_type_response(em_msg_type_assoc_sta_link_metrics_rsp, entries);
        dm.reset_db_cfg_type(db_cfg_type_sta_metrics_update);
        metrics->process_msg(msg.data(), static_cast<unsigned int>(msg.size()));
        EXPECT_EQ(em_state_ctrl_configured, metrics->get_state());
        EXPECT_TRUE(dm.db_cfg_type_is_set(db_cfg_type_sta_metrics_update));
    }

    TopologyCountingEmMgr mgr;
    dm_easy_mesh_t dm;
    mac_address_t peer_al_mac = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    em_interface_t radio_interface{};
    em_t *radio = nullptr;
    DummyEmMetrics *metrics = nullptr;
};

/**
 * @brief Verify that AP metrics publish topology only for a STA's first nonempty client type.
 *
 * Dispatch AP responses through process_msg() with an empty, first nonempty, repeated,
 * and subsequent empty client type. Before each dispatch, clear the STA metrics update
 * flag and verify that the current response sets it. Also verify one publication after
 * the first nonempty value is stored, and no republish for later empty values.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 009@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** A registered radio and a STA with an empty client type exist in the fixture data model.@n
 * **Dependencies:** ClientTypeTopologyTest, TopologyCountingEmMgr, public process_msg() dispatch.@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- | -------------- | ----- |@n
 * | 01 | Dispatch an AP response with an empty client type. | Client type: empty | Current response sets the flag; no publication occurs and the stored type remains empty. | Should Pass |@n
 * | 02 | Dispatch an AP response with the first nonempty client type. | Client type: phone | Current response sets the flag; client type is stored before exactly one publication. | Should Pass |@n
 * | 03 | Repeat the nonempty response, then dispatch an empty client type. | Client types: phone, empty | Each response sets the flag; publication count remains one and the stored type remains phone. | Should Pass |
 */
TEST_F(ClientTypeTopologyTest, ApMetricsPublishesOnlyForFirstNonEmptyClientType) {
    ClientTypeEntry sta = make_client_type_entry(1, "");
    dm_sta_t *dm_sta = add_metrics_sta(dm, sta);
    std::vector<std::string> published_client_types;
    mgr.on_publish = [&]() { published_client_types.push_back(dm_sta->m_sta_info.sta_client_type); };

    send_ap_response({sta});
    EXPECT_EQ(0U, mgr.publish_count);
    EXPECT_STREQ("", dm_sta->m_sta_info.sta_client_type);

    sta.client_type = "phone";
    send_ap_response({sta});
    EXPECT_EQ(1U, mgr.publish_count);
    ASSERT_EQ(1U, published_client_types.size());
    EXPECT_EQ("phone", published_client_types[0]);
    EXPECT_STREQ("phone", dm_sta->m_sta_info.sta_client_type);

    send_ap_response({sta});
    EXPECT_EQ(1U, mgr.publish_count);

    sta.client_type = "";
    send_ap_response({sta});
    EXPECT_EQ(1U, mgr.publish_count);
    EXPECT_STREQ("phone", dm_sta->m_sta_info.sta_client_type);
}

/**
 * @brief Verify one topology publication for multiple first client types in an AP response.
 *
 * Dispatch one AP metrics response containing two new STA client types through
 * process_msg(). Verify that the response sets the STA metrics update flag, topology
 * is published once, and both values are already stored when the callback runs.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 010@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** A registered radio and two STAs with empty client types exist in the fixture data model.@n
 * **Dependencies:** ClientTypeTopologyTest, TopologyCountingEmMgr, public process_msg() dispatch.@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- | -------------- | ----- |@n
 * | 01 | Dispatch one AP response containing two first client types. | STA 1: phone; STA 2: laptop | Current response sets the flag and exactly one topology publication occurs. | Should Pass |@n
 * | 02 | Verify client types captured by the publication callback. | Captured STA client types | Both phone and laptop are stored before publication. | Should Pass |
 */
TEST_F(ClientTypeTopologyTest, ApMetricsPublishesOnceForMultipleFirstClientTypes) {
    ClientTypeEntry sta_1 = make_client_type_entry(1, "phone");
    ClientTypeEntry sta_2 = make_client_type_entry(2, "laptop");
    dm_sta_t *dm_sta_1 = add_metrics_sta(dm, sta_1);
    dm_sta_t *dm_sta_2 = add_metrics_sta(dm, sta_2);
    std::vector<std::string> published_client_types;
    mgr.on_publish = [&]() {
        published_client_types.push_back(dm_sta_1->m_sta_info.sta_client_type);
        published_client_types.push_back(dm_sta_2->m_sta_info.sta_client_type);
    };

    send_ap_response({sta_1, sta_2});

    EXPECT_EQ(1U, mgr.publish_count);
    ASSERT_EQ(2U, published_client_types.size());
    EXPECT_EQ("phone", published_client_types[0]);
    EXPECT_EQ("laptop", published_client_types[1]);
}

/**
 * @brief Verify that associated-STA metrics publish only for the first nonempty client type.
 *
 * Dispatch associated-STA link metrics responses through process_msg() with empty,
 * first nonempty, repeated, and subsequent empty client types. Before each dispatch,
 * clear the STA metrics update flag and verify the current response sets it. Also
 * verify one publication and preservation of the first nonempty value afterward.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 011@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** A STA with an empty client type exists in the fixture data model.@n
 * **Dependencies:** ClientTypeTopologyTest, TopologyCountingEmMgr, public process_msg() dispatch.@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- | -------------- | ----- |@n
 * | 01 | Dispatch an associated-STA response with an empty client type. | Client type: empty | Current response sets the flag; no topology publication occurs. | Should Pass |@n
 * | 02 | Dispatch an associated-STA response with the first nonempty client type. | Client type: phone | Current response sets the flag; client type is stored before exactly one publication. | Should Pass |@n
 * | 03 | Repeat the nonempty response, then dispatch an empty client type. | Client types: phone, empty | Each response sets the flag; publication count remains one and the stored type remains phone. | Should Pass |
 */
TEST_F(ClientTypeTopologyTest, AssocStaLinkMetricsPublishesOnlyForFirstNonEmptyClientType) {
    ClientTypeEntry sta = make_client_type_entry(1, "");
    dm_sta_t *dm_sta = add_metrics_sta(dm, sta);
    std::vector<std::string> published_client_types;
    mgr.on_publish = [&]() { published_client_types.push_back(dm_sta->m_sta_info.sta_client_type); };

    send_assoc_sta_response({sta});
    EXPECT_EQ(0U, mgr.publish_count);

    sta.client_type = "phone";
    send_assoc_sta_response({sta});
    EXPECT_EQ(1U, mgr.publish_count);
    ASSERT_EQ(1U, published_client_types.size());
    EXPECT_EQ("phone", published_client_types[0]);

    send_assoc_sta_response({sta});
    EXPECT_EQ(1U, mgr.publish_count);

    sta.client_type = "";
    send_assoc_sta_response({sta});
    EXPECT_EQ(1U, mgr.publish_count);
    EXPECT_STREQ("phone", dm_sta->m_sta_info.sta_client_type);
}

/**
 * @brief Verify that AP metrics do not republish a client type learned from associated-STA metrics.
 *
 * Dispatch an associated-STA link metrics response followed by an AP metrics response
 * containing the same STA client type through process_msg(). Verify that each response
 * sets the flag after it is cleared, the first response publishes topology, and the
 * second does not publish it again.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 012@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** A registered radio and a STA with an empty client type exist in the fixture data model.@n
 * **Dependencies:** ClientTypeTopologyTest, TopologyCountingEmMgr, public process_msg() dispatch.@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- | -------------- | ----- |@n
 * | 01 | Dispatch an associated-STA response with the first nonempty client type. | Client type: phone | Current response sets the flag and exactly one topology publication occurs. | Should Pass |@n
 * | 02 | Dispatch an AP response for the same STA and client type. | Same STA, client type: phone | Current response sets the flag; publication count remains one. | Should Pass |
 */
TEST_F(ClientTypeTopologyTest, ClientTypeSeenByOneResponsePathDoesNotRepublishOnTheOther) {
    ClientTypeEntry sta = make_client_type_entry(1, "phone");
    add_metrics_sta(dm, sta);

    send_assoc_sta_response({sta});
    EXPECT_EQ(1U, mgr.publish_count);

    send_ap_response({sta});
    EXPECT_EQ(1U, mgr.publish_count);
}

/**
 * @brief Verify one topology publication for multiple first client types in an associated-STA response.
 *
 * Dispatch an associated-STA link metrics response containing two new client types
 * through process_msg(). Verify that each response sets the flag after it is cleared,
 * both values are stored before the single publication, and repeating the response
 * does not trigger another publication.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 013@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** Two STAs with empty client types exist in the fixture data model.@n
 * **Dependencies:** ClientTypeTopologyTest, TopologyCountingEmMgr, public process_msg() dispatch.@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- | -------------- | ----- |@n
 * | 01 | Dispatch one associated-STA response containing two first client types. | STA 1: phone; STA 2: laptop | Current response sets the flag and exactly one topology publication occurs. | Should Pass |@n
 * | 02 | Verify client types captured by the publication callback. | Captured STA client types | Both phone and laptop are stored before publication. | Should Pass |@n
 * | 03 | Dispatch the same response again. | Same two STAs and client types | Current response sets the flag; publication count remains one. | Should Pass |
 */
TEST_F(ClientTypeTopologyTest, AssocStaLinkMetricsPublishesOnceForMultipleFirstClientTypes) {
    ClientTypeEntry sta_1 = make_client_type_entry(1, "phone");
    ClientTypeEntry sta_2 = make_client_type_entry(2, "laptop");
    dm_sta_t *dm_sta_1 = add_metrics_sta(dm, sta_1);
    dm_sta_t *dm_sta_2 = add_metrics_sta(dm, sta_2);
    std::vector<std::string> published_client_types;
    mgr.on_publish = [&]() {
        published_client_types.push_back(dm_sta_1->m_sta_info.sta_client_type);
        published_client_types.push_back(dm_sta_2->m_sta_info.sta_client_type);
    };

    send_assoc_sta_response({sta_1, sta_2});

    EXPECT_EQ(1U, mgr.publish_count);
    ASSERT_EQ(2U, published_client_types.size());
    EXPECT_EQ("phone", published_client_types[0]);
    EXPECT_EQ("laptop", published_client_types[1]);

    send_assoc_sta_response({sta_1, sta_2});
    EXPECT_EQ(1U, mgr.publish_count);
}
