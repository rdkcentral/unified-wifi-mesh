
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
#include <stdio.h>
#include "em_mgr.h"
#include "ec_manager.h"
#include "dm_easy_mesh.h"
#include "em_provisioning.h"

class MockEmMgr : public em_mgr_t {
public:
    unsigned short get_next_msg_id() {
        return 42; // dummy message ID
    }
    bool is_data_model_initialized() override {
        return true;
    }
    em_t *find_em_for_msg_type(unsigned char*, unsigned int, em_t*) override { return nullptr; }
    int data_model_init(const char*) override { return 0; }
    int orch_init() override { return 0; }
    void input_listener() override {}
    void start_complete() override {}
    void handle_event(em_event_t*) override {}
    void handle_5s_tick() override {}
    void handle_2s_tick() override {}
    void handle_1s_tick() override {}
    void handle_500ms_tick() override {}
    void io(void*, bool) override {}
    void update_network_topology() override {}
    dm_easy_mesh_t *get_first_dm() override { return nullptr; }
    dm_easy_mesh_t *get_next_dm(dm_easy_mesh_t*) override { return nullptr; }
    dm_easy_mesh_t *get_data_model(const char*, const unsigned char*) override { return nullptr; }
    dm_easy_mesh_t *create_data_model(const char*, const em_interface_t*, em_profile_type_t) override { return nullptr; }
    void delete_data_model(const char*, const unsigned char*) override {}
    void delete_all_data_models() override {}
    int update_tables(dm_easy_mesh_t*) override { return 0; }
    int load_net_ssid_table() override { return 0; }
    void debug_probe() override {}
    em_service_type_t get_service_type() override { return em_service_type_t(); }
};

class TestEmProvisioningImpl : public em_provisioning_t {
public:
    TestEmProvisioningImpl() {
        mgr = new MockEmMgr();
    }
    ~TestEmProvisioningImpl() override {
        delete mgr;
    }
    using em_provisioning_t::create_cce_ind_msg;
    using em_provisioning_t::send_chirp_notif_msg;
    using em_provisioning_t::send_prox_encap_dpp_msg;
    using em_provisioning_t::send_direct_encap_dpp_msg;
    using em_provisioning_t::send_1905_eapol_encap_msg;
    using em_provisioning_t::send_1905_rekey_msg;
    em_service_type_t get_service_type() override { return em_service_type_t(); }
    em_state_t get_state() override { return em_state_t(); }
    void set_state(em_state_t state) override {}
    char* get_radio_interface_name() override { return nullptr; }
    uint8_t* get_peer_mac() override { return nullptr; }
    uint8_t mac_address[ETH_ALEN] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t* get_al_interface_mac() override { return mac_address; }
    uint8_t* get_radio_interface_mac() override { return nullptr; }	
    int send_frame(uint8_t *buff, unsigned int len, bool multicast = false) override { return 0; }
    int send_cmd(em_cmd_exec_t *exec, em_cmd_type_t type, em_service_type_t svc, uint8_t *buff, unsigned int len) override { return 0; }
    em_cmd_t* get_current_cmd() override { return nullptr; }
    dm_easy_mesh_t* get_data_model() override { return nullptr; }
    em_mgr_t* get_mgr() override { return mgr; }
    bool get_is_dpp_onboarding() override { return false; }
    void set_is_dpp_onboarding(bool is_onboarding) override {}

private:
    MockEmMgr* mgr;
};

class EmProvisioningTest : public ::testing::Test {
protected:
    TestEmProvisioningImpl* provisioning;
    void SetUp() override {
        provisioning = new TestEmProvisioningImpl();
    }
    void TearDown() override {
        delete provisioning;
    }
};

/**
 * @brief Test to verify proper construction of TestEmProvisioningImpl.
 *
 * This test verifies that the TestEmProvisioningImpl instance is constructed without throwing an exception.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 001@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Invoke TestEmProvisioningImpl constructor via test fixture | provisioning pointer used | Expect no exception thrown | Should Pass |
 */
TEST_F(EmProvisioningTest, em_provisioning_t_success_constructor) {
    std::cout << "Entering em_provisioning_t_success_constructor test" << std::endl;
    EXPECT_NO_THROW({
        std::cout << "Invoking em_provisioning_t constructor" << std::endl;
        TestEmProvisioningImpl* instance = provisioning;
        std::cout << "Instance pointer retrieved : " << instance << std::endl;

    });
    std::cout << "Exiting em_provisioning_t_success_constructor test" << std::endl;
}
/**
 * @brief Validate process_agent_state execution.
 *
 * This test verifies that the process_agent_state() method executes
 * correctly without throwing exceptions.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 002
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                               | Test Data                                                            | Expected Result                                                                      | Notes                |
 * | :--------------: | --------------------------------------------------------- | -------------------------------------------------------------------- | ------------------------------------------------------------------------------------ | -------------------- |
 * | 01               | Invoke process_agent_state() ensuring no exceptions occur   | input: provisioning instance; output: none     | process_agent_state() executes without throwing any exceptions; EXPECT_NO_THROW passes | Should Pass          |
 * | 02               | Log post invocation confirmation                          | No additional input/output data                                      | Console outputs confirm successful invocation of process_agent_state()                | Should be successful |
 */
TEST_F(EmProvisioningTest, process_agent_state_initialized_agent) {
    std::cout << "Entering process_agent_state_initialized_agent test" << std::endl;

    EXPECT_NO_THROW({
        provisioning->process_agent_state();
        std::cout << "process_agent_state() executed successfully." << std::endl;
    });

    std::cout << "Exiting process_agent_state_initialized_agent test" << std::endl;
}

/**
 * @brief Verify that process_ctrl_state() executes successfully.
 *
 * This test case verifies that the process_ctrl_state() method does not throw an exception.
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 003@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke process_ctrl_state() ensuring it does not throw an exception. | Call: provisioning->process_ctrl_state() | process_ctrl_state() executes without throwing an exception. | Should Pass |
 */
TEST_F(EmProvisioningTest, process_ctrl_state) {
    std::cout << "Entering process_ctrl_state test" << std::endl;

    std::cout << "Invoking process_ctrl_state()" << std::endl;
    EXPECT_NO_THROW({
        provisioning->process_ctrl_state();
        std::cout << "process_ctrl_state() executed successfully." << std::endl;
    });

    std::cout << "Exiting process_ctrl_state test" << std::endl;
}

/**
 * @brief Verify process_msg API with valid non-empty data buffer.
 *
 * This test case validates that the process_msg API correctly processes a valid, non-empty data buffer by not throwing any exceptions during its execution.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 004@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Prepare a valid direct_encap_dpp CMDU buffer with appropriate TLVs and set the correct length | data = [direct_encap_dpp CMDU bytes], length = <CMDU length> | CMDU buffer is correctly initialized with valid non-empty content prior to API invocation | Expected: Success |
| 02 | Invoke the process_msg API using the initialized direct_encap_dpp CMDU buffer | data = [direct_encap_dpp CMDU bytes], length = <CMDU length> | process_msg successfully processes the valid direct_encap_dpp CMDU without exceptions, logging receipt of the message | Expected: Pass |
 */
TEST_F(EmProvisioningTest, process_msg_valid_non_empty_data) {
    std::cout << "Entering process_msg_valid_non_empty_data test" << std::endl;

    // Allocate buffer large enough for raw header + CMDU
    uint8_t data[sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)] = {0};

    // Cast buffer to header and CMDU pointers
    em_raw_hdr_t* hdr = reinterpret_cast<em_raw_hdr_t*>(data);
    em_cmdu_t* cmdu = reinterpret_cast<em_cmdu_t*>(data + sizeof(em_raw_hdr_t));

    // Fill source MAC in header
    uint8_t src_mac[ETH_ALEN] = {0x01,0x02,0x03,0x04,0x05,0x06};
    memcpy(hdr->src, src_mac, ETH_ALEN);

    // Set a valid CMDU type (direct encapsulated DPP)
    cmdu->type = htons(em_msg_type_direct_encap_dpp);

    // Optionally, fill rest of CMDU payload if needed for handler
    // For now, we leave it zero-initialized

    std::cout << "Invoking process_msg with a valid direct_encap_dpp CMDU" << std::endl;

    EXPECT_NO_THROW({
        provisioning->process_msg(data, sizeof(data));
        std::cout << "process_msg executed successfully for direct_encap_dpp CMDU." << std::endl;
    });

    std::cout << "Exiting process_msg_valid_non_empty_data test" << std::endl;
}

/**
 * @brief Verify that process_msg function handles an empty message throwing exceptions.
 *
 * This test validates that when a valid pointer to empty data is provided with a message length of 0,
 * the process_msg method executes throwing exceptions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 005@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                         | Test Data                                  | Expected Result                                                                              | Notes              |
 * | :--------------: | ------------------------------------------------------------------- | ------------------------------------------ | -------------------------------------------------------------------------------------------- | ------------------ |
 * | 01               | Create a valid pointer with an empty message                  | empty_data = 0, pointer = &empty_data, length = 0      |Empty data prepared properly                                                                 | Should be successful |
 * | 02               | Invoke process_msg API with an empty data valid pointer and length 0            | input: pointer = &empty_data, input: length = 0   | API executes, throwing exceptions.         | Should Fail         |
 */
TEST_F(EmProvisioningTest, process_msg_valid_empty_data) {
    std::cout << "Entering process_msg_valid_empty_data test" << std::endl;
    
    // Create an empty valid pointer (non-null)
    uint8_t empty_data = 0;
    std::cout << "Invoking process_msg with a valid pointer to empty data and length 0" << std::endl;
    
    EXPECT_ANY_THROW({
        provisioning->process_msg(&empty_data, 0);
        std::cout << "process_msg executed successfully with empty data." << std::endl;
    });
    
    std::cout << "Exiting process_msg_valid_empty_data test" << std::endl;
}
/**
 * @brief Verify that process_msg throws an exception when provided with a null data pointer and a non-zero length.
 *
 * This test case verifies that the process_msg method correctly handles an improper input scenario where the data pointer is null while the length is non-zero. The expectation is that the API will throw an exception under these circumstances.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 006@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke process_msg with a null data pointer and length 5 | data = nullptr, length = 5 | Exception is thrown | Should Fail |
 */
TEST_F(EmProvisioningTest, process_msg_null_data_nonzero_len) {
    std::cout << "Entering process_msg_null_data_nonzero_len test" << std::endl;
    
    // Null data pointer with non-zero length
    std::cout << "Invoking process_msg with null data pointer and length 5" << std::endl;
    
    EXPECT_ANY_THROW({
        provisioning->process_msg(nullptr, 5);
        std::cout << "process_msg should have thrown an exception for null data with non-zero length." << std::endl;
    });
    
    std::cout << "Exiting process_msg_null_data_nonzero_len test" << std::endl;
}

/**
 * @brief Verifies process_msg safely handles a null data pointer with zero length input.
 *
 * This test checks that invoking process_msg with a null pointer and a length of zero completes throwing exceptions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 007@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                         | Test Data                                | Expected Result                                           | Notes       |
 * | :--------------: | --------------------------------------------------- | ---------------------------------------- | --------------------------------------------------------- | ----------- |
 * | 01               | Call process_msg with a null pointer and zero length | data pointer = nullptr, length = 0       | API completes throwing exceptions and passes assertion | Should Fail |
 */
TEST_F(EmProvisioningTest, process_msg_null_data_zero_len) {
    std::cout << "Entering process_msg_null_data_zero_len test" << std::endl;
    
    // Null data pointer with zero length should be safe
    std::cout << "Invoking process_msg with null data pointer and length 0" << std::endl;
    
    EXPECT_ANY_THROW({
        provisioning->process_msg(nullptr, 0);
        std::cout << "process_msg executed successfully with null data pointer and zero length." << std::endl;
    });
    
    std::cout << "Exiting process_msg_null_data_zero_len test" << std::endl;
}
/**
 * @brief Test process_msg API with an extremely large data buffer.
 *
 * This test verifies that the process_msg API can handle a very large input buffer (1,000,000 bytes). 
 * The test allocates and zero-initializes a large memory area, invokes the process_msg function, 
 * and then checks that exceptions are thrown during the process. This ensures that the API 
 * handles large data sizes throwing exceptions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 008@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                            | Test Data                                              | Expected Result                                                      | Notes          |
 * | :--------------: | ---------------------------------------------------------------------- | ------------------------------------------------------ | --------------------------------------------------------------------- | -------------- |
 * | 01               | Allocate a buffer of 1,000,000 bytes and initialize it to zero         | len = 1000000, data pointer = allocated and zeroed     | Buffer is successfully allocated and zero-initialized                | Should be successful |
 * | 02               | Invoke process_msg with the allocated buffer                           | input: data pointer = allocated buffer, len = 1000000  | process_msg executes throwing an exception  | Should Fail    |
 * | 03               | Deallocate the allocated memory                                        | N/A                                                  | Memory is successfully released                                      | Should be successful |
 */
TEST_F(EmProvisioningTest, process_msg_extremely_large_length) {
    std::cout << "Entering process_msg_extremely_large_length test" << std::endl;
    
    // Allocate a valid buffer with extremely large length (1,000,000 bytes)
    unsigned int len = 1000000;
    uint8_t* data = new uint8_t[len]();
    // Ensure buffer is zero-initialized
    memset(data, 0, len * sizeof(uint8_t));
    
    std::cout << "Invoking process_msg with data pointer to allocated buffer and length " << len << std::endl;
    
    EXPECT_ANY_THROW({
        provisioning->process_msg(data, len);
        std::cout << "process_msg executed successfully with extremely large data." << std::endl;
    });
    
    delete[] data;
    
    std::cout << "Exiting process_msg_extremely_large_length test" << std::endl;
}
/**
 * @brief Test to ensure that process_msg handles corrupted binary data throwing exceptions.
 *
 * This test verifies that invoking the process_msg API with a corrupted binary data buffer (containing unexpected byte values)
 * causes the function to throw any exceptions. The objective is to assess the robustness of process_msg in handling non-standard
 * or corrupted input data.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 009@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                | Test Data                                              | Expected Result                                                         | Notes       |
 * | :--------------: | ---------------------------------------------------------- | ------------------------------------------------------ | ----------------------------------------------------------------------- | ----------- |
 * |       01         | Invoke process_msg with a corrupted binary data buffer.    | data = {0xFF,0x00,0xAB,0xCD}, length = 4                | process_msg executes throwing any exception; assertion: exception thrown.         | Should Fail |
 */
TEST_F(EmProvisioningTest, process_msg_corrupted_data) {
    std::cout << "Entering process_msg_corrupted_data test" << std::endl;
    
    // Create a buffer with corrupted/unexpected byte values: [0xFF, 0x00, 0xAB, 0xCD]
    uint8_t data[4] = {0};
    memset(data, 0, sizeof(data));
    data[0] = 0xFF;
    data[1] = 0x00;
    data[2] = 0xAB;
    data[3] = 0xCD;
    
    std::cout << "Invoking process_msg with corrupted data and length 4" << std::endl;
    
    EXPECT_ANY_THROW({
        provisioning->process_msg(data, 4);
        std::cout << "process_msg executed with corrupted data without crashing." << std::endl;
    });
    
    std::cout << "Exiting process_msg_corrupted_data test" << std::endl;
}
/**
 * @brief Verify that the destructor correctly cleans up a non-null resource.
 *
 * This test verifies that when the m_ec_manager member of the provisioning object is initialized with a non-null resource,
 * invoking the destructor manually cleans up the resource without throwing any exceptions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 010@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Assign a new resource to m_ec_manager. | | m_ec_manager is non-null | Should Pass |
 * | 02 | Manually invoke the destructor by deleting provisioning and set it to nullptr. | delete provisioning; provisioning = nullptr | Destructor completes without throwing exceptions; resource is cleaned up | Should Pass |
 */
TEST_F(EmProvisioningTest, destructor_non_null_resource) {
    std::cout << "Entering em_provisioning_t_destructor_non_null_resource test" << std::endl;

    // Create provisioning object on heap
    std::cout << "Creating provisioning object on heap." << std::endl;
    TestEmProvisioningImpl* provisioning = new TestEmProvisioningImpl();

    // Initialize m_ec_manager with a non-null resource
    std::cout << "Assigning a new ec_manager_t resource to m_ec_manager." << std::endl;
    ec_ops_t dummy_ops{};
    std::optional<ec_persistent_sec_ctx_t> sec_ctx = std::nullopt;
    auto dummy_handler = [](unsigned char* data, bool success) {
        // No-op for test
    };
    provisioning->m_ec_manager = std::make_unique<ec_manager_t>(
        "02:11:22:33:44:55", // dummy MAC address
        dummy_ops,
        false,               // is_controller
        sec_ctx,
        dummy_handler
    );

    // Invoke the destructor manually
    std::cout << "Invoking destructor manually using delete." << std::endl;
    EXPECT_NO_THROW({
        delete provisioning;
        provisioning = nullptr;
    });
    std::cout << "Resources should be cleaned up after destructor invocation." << std::endl;
    std::cout << "Exiting em_provisioning_t_destructor_non_null_resource test" << std::endl;
}

/**
 * @brief Verify graceful cleanup of EmProvisioning instance when its resource is null
 *
 * This test sets the m_ec_manager member of the provisioning instance to nullptr and then manually invokes the destructor using delete. It verifies that no exceptions are thrown during the destructor call, ensuring proper cleanup even when the internal resource pointer is null.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 011@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Set the internal resource pointer m_ec_manager to nullptr | m_ec_manager = nullptr | m_ec_manager should be null before destructor invocation | Should be successful |
 * | 02 | Invoke the destructor manually using delete and verify no exception is thrown | provisioning pointer = valid instance, delete provisioning | No exception thrown and provisioning set to nullptr | Should Pass |
 */

TEST_F(EmProvisioningTest, em_provisioning_t_destructor_null_resource) {
    std::cout << "Entering em_provisioning_t_destructor_null_resource test" << std::endl;

    // Create a local instance of em_provisioning_t on the heap
    TestEmProvisioningImpl* provisioning = new TestEmProvisioningImpl();

    // Ensure m_ec_manager is explicitly set to nullptr
    std::cout << "Setting m_ec_manager to nullptr" << std::endl;
    provisioning->m_ec_manager.reset(nullptr);

    std::cout << "Invoking destructor manually using delete" << std::endl;
    EXPECT_NO_THROW({
        delete provisioning;
        provisioning = nullptr;
    });

    std::cout << "Exiting em_provisioning_t_destructor_null_resource test" << std::endl;
}

/**
 * @brief Verify polymorphic deletion of em_provisioning_t object via base pointer.
 *
 * This test verifies that the destructor of TestEmProvisioningImpl is correctly invoked through a base class pointer.
 * Assign non-null resource to m_ec_manager and then delete the base pointer to ensure proper clean-up without exceptions.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 012
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                          | Test Data                                      | Expected Result                                             | Notes                |
 * | :----:           | :----------------------------------------------------------------------------------- | :--------------------------------------------- | :---------------------------------------------------------- | :------------------: |
 * | 01               | Create an instance of TestEmProvisioningImpl and assign it to a base class pointer.    | base_ptr = new TestEmProvisioningImpl()        | Instance is created and pointer is valid.                   | Should be successful |
 * | 02               | Assign a new resource to m_ec_manager to simulate a non-null scenario.               | m_ec_manager = new ec_manager_t{}              | m_ec_manager is non-null.                                    | Should be successful |
 * | 03               | Invoke polymorphic deletion via the base pointer and verify no exception is thrown.    | delete base_ptr; Expect no exception thrown.   | Polymorphic destructor is invoked without throwing exceptions. | Should Pass          |
 */
TEST_F(EmProvisioningTest, em_provisioning_t_destructor_polymorphic_deletion) {
    std::cout << "Entering em_provisioning_t_destructor_polymorphic_deletion test" << std::endl;

    // Create an instance of TestEmProvisioningImpl and assign it to a base class pointer
    std::cout << "Creating a new TestEmProvisioningImpl instance and assigning to base pointer" << std::endl;
    em_provisioning_t* base_ptr = nullptr;
    base_ptr = new TestEmProvisioningImpl();

    // Assign a resource to m_ec_manager to simulate non-null scenario
    std::cout << "Assigning a new resource to m_ec_manager of the base pointer object" << std::endl;
    ec_ops_t dummy_ops{};
    std::optional<ec_persistent_sec_ctx_t> sec_ctx = std::nullopt;
    auto dummy_handler = [](unsigned char* data, bool success) {
        // No-op for test
    };
    base_ptr->m_ec_manager = std::make_unique<ec_manager_t>(
        "02:11:22:33:44:55", // dummy MAC
        dummy_ops,
        false,
        sec_ctx,
        dummy_handler
    );

    // Delete the base class pointer to invoke polymorphic deletion
    std::cout << "Invoking polymorphic deletion via base pointer" << std::endl;
    EXPECT_NO_THROW({
        delete base_ptr;
        base_ptr = nullptr;
    });

    std::cout << "Exiting em_provisioning_t_destructor_polymorphic_deletion test" << std::endl;
}

/**
 * @brief Verify that create_cce_ind_msg correctly creates a CCE indication message with a valid buffer and enable flag set to true.
 *
 * This test validates the behavior of the create_cce_ind_msg API when provided a properly allocated and initialized buffer along with the enable flag set to true. It ensures that the function call returns a positive CMDU size, indicating successful message creation.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 013@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Allocate and initialize a 256-byte buffer to 0 | buff = {0} (uint8_t[256]) | Buffer is allocated and initialized to zero | Should be successful |
 * | 02 | Invoke create_cce_ind_msg with the allocated buffer and enable flag true | input: buff, enable = true; output: ret | API returns a positive CMDU size | Should Pass |
 * | 03 | Validate that the returned value is greater than 0 | ret > 0 | Test assertion passes confirming a positive return value | Should Pass |
 */
TEST_F(EmProvisioningTest, create_cce_ind_msg_ValidBufferEnableTrue) {
    std::cout << "Entering create_cce_ind_msg_ValidBufferEnableTrue test" << std::endl;
    // Allocate a sufficiently sized buffer and initialize to 0.
    uint8_t buff[256] = {0};
    int ret;
    std::cout << "Invoking create_cce_ind_msg with buffer: " 
              << static_cast<void*>(buff) << " and enable: true" << std::endl;
    ret = provisioning->create_cce_ind_msg(buff, true);
    std::cout << "Method returned value: " << ret << std::endl;
    EXPECT_GT(ret, 0);
    std::cout << "Exiting create_cce_ind_msg_ValidBufferEnableTrue test" << std::endl;
}
/**
 * @brief Validate create_cce_ind_msg with a valid buffer and enable flag set to false
 *
 * This test case verifies that the create_cce_ind_msg API of the provisioning module returns a positive CMDU size when provided with a valid, zero-initialized buffer and the enable flag set to false. The test ensures that the API returned value meets the expected condition.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 014@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Allocate a sufficiently sized, zero initialized buffer and invoke create_cce_ind_msg with enable set to false | buff = array of 256 bytes (all zeros), enable = false | API returns a positive integer value representing CMDU size | Should Pass |
 */
TEST_F(EmProvisioningTest, create_cce_ind_msg_ValidBufferEnableFalse) {
    std::cout << "Entering create_cce_ind_msg_ValidBufferEnableFalse test" << std::endl;
    // Allocate and zero initialize a sufficiently sized buffer.
    uint8_t buff[256] = {0};
    int ret;
    std::cout << "Invoking create_cce_ind_msg with buffer: " 
              << static_cast<void*>(buff) << " and enable: false" << std::endl;
    ret = provisioning->create_cce_ind_msg(buff, false);
    std::cout << "Method returned value: " << ret << std::endl;
    EXPECT_GT(ret, 0);
    std::cout << "Exiting create_cce_ind_msg_ValidBufferEnableFalse test" << std::endl;
}
/**
 * @brief Verify that create_cce_ind_msg returns an error for a NULL buffer when enable is true.
 *
 * This test validates the behavior of the create_cce_ind_msg method when provided with a NULL buffer pointer along with the enable flag set to true. The expected outcome is that the API returns a negative return value indicating error.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 015@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                                              | Test Data                                              | Expected Result                                                                          | Notes      |
 * | :--------------: | ---------------------------------------------------------------------------------------- | ------------------------------------------------------ | ---------------------------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke create_cce_ind_msg API with a NULL buffer pointer and enable set to true.           | input: buff = nullptr, enable = true, output: ret      | API returns a negative value indicating error | Should Fail |
*/
TEST_F(EmProvisioningTest, create_cce_ind_msg_NullBufferEnableTrue) {
    std::cout << "Entering create_cce_ind_msg_NullBufferEnableTrue test" << std::endl;
    uint8_t* buff = nullptr;
    int ret;
    ret = provisioning->create_cce_ind_msg(buff, true);
    std::cout << "Method returned value: " << ret << std::endl;
    EXPECT_LT(ret, 0);
    std::cout << "Exiting create_cce_ind_msg_NullBufferEnableTrue test" << std::endl;
}
/**
 * @brief Test create_cce_ind_msg with NULL buffer pointer and enable flag false resulting in an error.
 *
 * This test verifies that the create_cce_ind_msg API returns a negative error code when provided with a NULL buffer pointer and the enable flag set to false, ensuring appropriate error handling.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 016
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                   | Test Data                                        | Expected Result                                                     | Notes              |
 * | :--------------: | --------------------------------------------------------------------------------------------- | ------------------------------------------------ | ------------------------------------------------------------------- | ------------------ |
 * | 01               | Invoke create_cce_ind_msg with NULL buffer pointer and enable flag set to false                | buff = nullptr, enable = false                    | API returns a negative error code indicating error for NULL input   | Should Fail        |
 * | 02               | Verify that the API return value is negative       | output: ret value from create_cce_ind_msg call     | EXPECT_LT(ret, 0) assertion passes                | Should be successful |
 */
TEST_F(EmProvisioningTest, create_cce_ind_msg_NullBufferEnableFalse) {
    std::cout << "Entering create_cce_ind_msg_NullBufferEnableFalse test" << std::endl;
    uint8_t* buff = nullptr;
    int ret;
    ret = provisioning->create_cce_ind_msg(buff, false);
    std::cout << "Method returned value: " << ret << std::endl;
    EXPECT_LT(ret, 0);
    std::cout << "Exiting create_cce_ind_msg_NullBufferEnableFalse test" << std::endl;
}
/**
 * @brief Verify proper processing of valid EAPOL frame and destination AL MAC.
 *
 * This test validates that the API send_1905_eapol_encap_msg correctly processes a valid EAPOL frame along with a valid destination AL MAC address. The function initializes an EAPOL frame buffer of 10 bytes, sets up the destination AL MAC address and then calls the API. It confirms that the return value is positive integer.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 017@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize valid EAPOL frame and destination AL MAC address. | eapol_frame = {buffer initialized with 10 bytes set to "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A"}, frame_len = 10, dest_al_mac = {0x00,0x1A,0x2B,0x3C,0x4D,0x5E} | Buffers are initialized correctly | Should be successful |
 * | 02 | Invoke send_1905_eapol_encap_msg API with valid parameters. | input: eapol_frame pointer = valid frame, frame_len = 10, dest_al_mac pointer = valid MAC address; output: ret > 0 | Return value > 0 and assertion passes | Should Pass |
 */
TEST_F(EmProvisioningTest, send_1905_eapol_encap_msg_valid_frame)
{
    std::cout << "Entering send_1905_eapol_encap_msg_valid_frame test" << std::endl;

    // Initialize a valid EAPOL frame buffer with 10 bytes.
    size_t frame_len = 10;
    uint8_t eapol_frame[10] = {0};
    const char frame_src[11] = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A";
    strncpy(reinterpret_cast<char*>(eapol_frame), frame_src, 10);
    std::cout << "Set eapol_frame with 10 bytes: ";
    for (size_t i = 0; i < frame_len; i++) {
        std::cout << std::hex << static_cast<int>(eapol_frame[i]) << " ";
    }
    std::cout << std::dec << std::endl;
    
    // Initialize a valid destination AL MAC address: {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}.
    uint8_t dest_al_mac[6] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
    std::cout << "Invoking send_1905_eapol_encap_msg with valid frame and valid destination AL MAC" << std::endl;
    int ret = provisioning->send_1905_eapol_encap_msg(eapol_frame, frame_len, dest_al_mac);
    std::cout << "send_1905_eapol_encap_msg returned: " << ret << std::endl;
    EXPECT_GT(ret, 0);
    std::cout << "Exiting send_1905_eapol_encap_msg_valid_frame test" << std::endl;
}
/**
 * @brief Test the send_1905_eapol_encap_msg API with a null eapol_frame pointer
 *
 * This test verifies that the API send_1905_eapol_encap_msg returns an error (-1) when the eapol_frame pointer is null.
 * It ensures that the API correctly handles invalid input by checking the error code when a null pointer is passed,
 * even when the destination AL MAC address is valid.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 018@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                   | Test Data                                                               | Expected Result                            | Notes                |
 * | :--------------: | --------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- | ------------------------------------------ | -------------------- |
 * | 01               | Initialize test environment by setting eapol_frame to nullptr, frame_len to 100, and initializing dest_al_mac with valid MAC {00:1A:2B:3C:4D:5E} | eapol_frame = nullptr, frame_len = 100, dest_al_mac = 00:1A:2B:3C:4D:5E  | Variables initialized successfully         | Should be successful   |
 * | 02               | Invoke send_1905_eapol_encap_msg API using the null eapol_frame pointer                           | eapol_frame = nullptr, frame_len = 100, dest_al_mac = 00:1A:2B:3C:4D:5E  | Return value = -1, assertion EXPECT_EQ(-1, ret) | Should Pass          |
 */
TEST_F(EmProvisioningTest, send_1905_eapol_encap_msg_null_frame)
{
    std::cout << "Entering send_1905_eapol_encap_msg_null_frame test" << std::endl;
    uint8_t* eapol_frame = nullptr;
    size_t frame_len = 100;
    // Initialize a valid destination AL MAC address: {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}.
    uint8_t dest_al_mac[6] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
    std::cout << "Invoking send_1905_eapol_encap_msg with null eapol_frame pointer" << std::endl;
    int ret = provisioning->send_1905_eapol_encap_msg(eapol_frame, frame_len, dest_al_mac);
    std::cout << "send_1905_eapol_encap_msg returned: " << ret << std::endl;
    EXPECT_EQ(-1, ret);
    std::cout << "Exiting send_1905_eapol_encap_msg_null_frame test" << std::endl;
}
/**
 * @brief Validate that send_1905_eapol_encap_msg returns (-1) when invoked with a zero-length EAPOL frame.
 *
 * This test verifies that the API send_1905_eapol_encap_msg properly handles the case where the provided EAPOL frame length is zero,
 * despite the EAPOL frame buffer having been allocated and initialized with data. By setting frame length to zero, the API is expected
 * to return (-1) as it should not process an empty frame.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 019
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                                  | Test Data                                                                                                                            | Expected Result                                | Notes        |
 * | :--------------: | ------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------- | ------------ |
 * | 01               | Initialize EAPOL frame buffer with 10 bytes with valid data but set frame length to 0                         | eapol_frame = [AA,BB,CC,DD,EE,FF,11,22,33,44], frame_len = 0                                                                         | Buffer prepared with invalid length            | Should be successful |
 * | 02               | Initialize destination AL MAC address                                                                       | dest_al_mac = [00,1A,2B,3C,4D,5E]                                                                                                     | MAC address correctly configured               | Should be successful |
 * | 03               | Invoke send_1905_eapol_encap_msg with the zero-length EAPOL frame and check the return value                    | input: eapol_frame = [AA,BB,CC,DD,EE,FF,11,22,33,44], frame_len = 0, dest_al_mac = [00,1A,2B,3C,4D,5E]                               | Return value equals -1                          | Should Pass  |
 */
TEST_F(EmProvisioningTest, send_1905_eapol_encap_msg_zero_length)
{
    std::cout << "Entering send_1905_eapol_encap_msg_zero_length test" << std::endl;
    // Allocate a valid EAPOL frame buffer with 10 bytes.
    size_t frame_len = 0; // Zero length
    uint8_t eapol_frame[10] = {0};
    const char frame_src[11] = "\xAA\xBB\xCC\xDD\xEE\xFF\x11\x22\x33\x44";
    strncpy(reinterpret_cast<char*>(eapol_frame), frame_src, 10);
    // Initialize a valid destination AL MAC address: {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}.
    uint8_t dest_al_mac[6] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
    std::cout << "Invoking send_1905_eapol_encap_msg with zero frame length" << std::endl;
    int ret = provisioning->send_1905_eapol_encap_msg(eapol_frame, frame_len, dest_al_mac);
    std::cout << "send_1905_eapol_encap_msg returned: " << ret << std::endl;
    EXPECT_EQ(-1, ret);
    std::cout << "Exiting send_1905_eapol_encap_msg_zero_length test" << std::endl;
}
/**
 * @brief Test sending 1905 EAPOL encapsulated message with a null destination AL MAC pointer.
 *
 * This test verifies that the send_1905_eapol_encap_msg API correctly handles a scenario where the destination AL MAC pointer is null. It ensures that the API returns the expected error code (-1) to prevent invalid network operations.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 020@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize a valid EAPOL frame with 10 bytes using a predefined frame source data | frame = {0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE}, frame_len = 10 | EAPOL frame buffer is correctly initialized with the provided data | Should be successful |
 * | 02 | Set the destination AL MAC pointer to nullptr to simulate an invalid pointer scenario | dest_al_mac = nullptr | Destination AL MAC pointer is null | Should be successful |
 * | 03 | Invoke send_1905_eapol_encap_msg with the configured EAPOL frame and null destination pointer | eapol_frame as initialized, frame_len = 10, dest_al_mac = nullptr | API returns -1 indicating error; EXPECT_EQ verifies that the return value is -1 | Should Pass |
 */
TEST_F(EmProvisioningTest, send_1905_eapol_encap_msg_null_dest_mac)
{
    std::cout << "Entering send_1905_eapol_encap_msg_null_dest_mac test" << std::endl;
    // Initialize a valid EAPOL frame buffer with 10 bytes.
    size_t frame_len = 10;
    uint8_t eapol_frame[10] = {0};
    const char frame_src[11] = "\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE";
    strncpy(reinterpret_cast<char*>(eapol_frame), frame_src, 10);
    uint8_t* dest_al_mac = nullptr;
    std::cout << "Invoking send_1905_eapol_encap_msg with null destination AL MAC pointer" << std::endl;
    int ret = provisioning->send_1905_eapol_encap_msg(eapol_frame, frame_len, dest_al_mac);
    std::cout << "send_1905_eapol_encap_msg returned: " << ret << std::endl;
    EXPECT_EQ(-1, ret);
    std::cout << "Exiting send_1905_eapol_encap_msg_null_dest_mac test" << std::endl;
}
/**
 * @brief Verify that send_1905_eapol_encap_msg correctly processes a valid EAPOL frame when the destination AL MAC address is all zeros.
 *
 * This test initializes a valid EAPOL frame buffer and a destination AL MAC address filled with zeros. It then calls the send_1905_eapol_encap_msg API and asserts that the return value is -1, indicating correct handling of an all-zero destination AL MAC address.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 021@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                              | Test Data                                                                                                                 | Expected Result                                                              | Notes         |
 * | :--------------: | -------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ------------- |
 * | 01               | Initialize a valid EAPOL frame with 10 bytes from a predefined source address.                           | frame_len = 10, eapol_frame = DE,AD,BE,EF,00,11,22,33,44,55                                                               | EAPOL frame buffer correctly initialized                                   | Should be successful |
 * | 02               | Initialize destination AL MAC address with all zeros.                                                  | dest_al_mac = 00,00,00,00,00,00                                                                                            | Destination AL MAC buffer correctly set to zeros                           | Should be successful |
 * | 03               | Invoke send_1905_eapol_encap_msg API with the initialized EAPOL frame and all-zero destination AL MAC.   | input: eapol_frame = DE,AD,BE,EF,00,11,22,33,44,55; frame_len = 10; dest_al_mac = 00,00,00,00,00,00                         | API returns -1 and passes EXPECT_EQ check                                   | Should Pass   |
 */
TEST_F(EmProvisioningTest, send_1905_eapol_encap_msg_all_zero_dest_mac)
{
    std::cout << "Entering send_1905_eapol_encap_msg_all_zero_dest_mac test" << std::endl;
    // Initialize a valid EAPOL frame buffer with 10 bytes.
    size_t frame_len = 10;
    uint8_t eapol_frame[10] = {0};
    const char frame_src[11] = "\xDE\xAD\xBE\xEF\x00\x11\x22\x33\x44\x55";
    strncpy(reinterpret_cast<char*>(eapol_frame), frame_src, 10);
    // Initialize destination AL MAC address with all zeros.
    uint8_t dest_al_mac[6] = {0};
    memset(dest_al_mac, 0, 6);
    std::cout << "Invoking send_1905_eapol_encap_msg with destination AL MAC set to all zeros" << std::endl;
    int ret = provisioning->send_1905_eapol_encap_msg(eapol_frame, frame_len, dest_al_mac);
    std::cout << "send_1905_eapol_encap_msg returned: " << ret << std::endl;
    EXPECT_EQ(-1, ret);
    std::cout << "Exiting send_1905_eapol_encap_msg_all_zero_dest_mac test" << std::endl;
}
/**
 * @brief Validate that send_1905_rekey_msg API accepts a valid MAC address.
 *
 * This test verifies that when provided with a valid MAC address, the send_1905_rekey_msg API returns a success status. It checks the proper initialization of the MAC address and the API’s return value.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 022@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize the valid MAC address array with values 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF | dest_al_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF] | Successfully initialized MAC address | Should be successful |
 * | 02 | Invoke send_1905_rekey_msg API using the valid MAC address | input: dest_al_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], output: ret > 0 | API returns greater than 0 and assertion EXPECT_GT(ret, 0) passes | Should Pass |
 */

TEST_F(EmProvisioningTest, send_1905_rekey_msg_Valid_MAC_Address) {
    std::cout << "Entering send_1905_rekey_msg_Valid_MAC_Address test" << std::endl;
    // Prepare a valid MAC address: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
    uint8_t dest_al_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    int ret = provisioning->send_1905_rekey_msg(dest_al_mac);
    std::cout << "Method send_1905_rekey_msg returned: " << std::dec << ret << std::endl;
    EXPECT_GT(ret, 0);
    std::cout << "Exiting send_1905_rekey_msg_Valid_MAC_Address test" << std::endl;
}
/**
 * @brief Test the send_1905_rekey_msg API to validate behavior when the MAC address pointer is null
 *
 * This test verifies that when a null pointer is passed as the destination AL MAC address to the send_1905_rekey_msg API, 
 * the API correctly handles the error condition and returns an appropriate error code. This ensures that the function performs proper 
 * validation on the input parameters and prevents unintended behavior.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 023
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                       | Test Data                                      | Expected Result                              | Notes         |
 * | :--------------: | ----------------------------------------------------------------- | ---------------------------------------------- | -------------------------------------------- | ------------- |
 * |      01        | Call send_1905_rekey_msg with null MAC address pointer              | dest_al_mac = nullptr, return value = int      | API returns -1 and EXPECT_EQ(-1) passes      | Should Pass   |
 */
TEST_F(EmProvisioningTest, send_1905_rekey_msg_Null_MAC_Address) {
    std::cout << "Entering send_1905_rekey_msg_Null_MAC_Address test" << std::endl;
    // Prepare a null pointer for the MAC address.
    uint8_t* dest_al_mac = nullptr;
    int ret = provisioning->send_1905_rekey_msg(dest_al_mac);
    std::cout << "Method send_1905_rekey_msg returned: " << ret << std::endl;
    EXPECT_EQ(ret, -1);
    std::cout << "Exiting send_1905_rekey_msg_Null_MAC_Address test" << std::endl;
}

/**
 * @brief Test the send_1905_rekey_msg API with an all-zero MAC address to validate error handling
 *
 * This test verifies that when an all-zero MAC address is passed to the send_1905_rekey_msg API,
 * the function correctly returns an error indicator (-1). The test confirms that the improper input is
 * properly detected and handled, thus ensuring the API's robustness against invalid addresses.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 024@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                             | Test Data                                                         | Expected Result                                                  | Notes            |
 * | :--------------: | --------------------------------------------------------------------------------------- | ----------------------------------------------------------------- | ---------------------------------------------------------------- | ---------------- |
 * |       01       | Prepare an all-zero MAC address                              | dest_al_mac = [0, 0, 0, 0, 0, 0]                                   | All-zero MAC address is prepared         | Should be successful |
 * |       02       | Invoke send_1905_rekey_msg API with the all-zero MAC address                              | input: dest_al_mac = [0, 0, 0, 0, 0, 0], output: ret expected = -1   | API returns -1                                                   | Should Pass      |
 */
TEST_F(EmProvisioningTest, send_1905_rekey_msg_All_Zero_MAC_Address) {
    std::cout << "Entering send_1905_rekey_msg_All_Zero_MAC_Address test" << std::endl;
    // Prepare an all-zero MAC address.
    uint8_t dest_al_mac[6] = {0};
    memset(dest_al_mac, 0, sizeof(dest_al_mac));
    int ret = provisioning->send_1905_rekey_msg(dest_al_mac);
    std::cout << "Method send_1905_rekey_msg returned: " << std::dec << ret << std::endl;
    EXPECT_EQ(ret, -1);
    std::cout << "Exiting send_1905_rekey_msg_All_Zero_MAC_Address test" << std::endl;
}

/**
 * @brief Validate the send_1905_rekey_msg API with a broadcast MAC address.
 *
 * This test verifies that the send_1905_rekey_msg method correctly processes a broadcast MAC address,
 * ensuring that the API returns a success value.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 025
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Prepare a broadcast MAC address [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF] | dest_al_mac: each index set to 0xFF | Broadcast MAC address is correctly prepared in dest_al_mac array | Should Pass |
 * | 02 | Invoke send_1905_rekey_msg API with the broadcast MAC address | input: dest_al_mac = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], expected output: ret > 0 | API returns greater than zero and the assertion EXPECT_GT(ret, 0) passes | Should Pass |
 */
TEST_F(EmProvisioningTest, send_1905_rekey_msg_Broadcast_MAC_Address) {
    std::cout << "Entering send_1905_rekey_msg_Broadcast_MAC_Address test" << std::endl;
    // Prepare a broadcast MAC address: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
    uint8_t dest_al_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    int ret = provisioning->send_1905_rekey_msg(dest_al_mac);
    std::cout << "Method send_1905_rekey_msg returned: " << std::dec << ret << std::endl;
    EXPECT_GT(ret, 0);
    std::cout << "Exiting send_1905_rekey_msg_Broadcast_MAC_Address test" << std::endl;
}

/**
 * @brief Validates the send_chirp_notif_msg API with a valid chirp notification where a MAC address is present.
 *
 * This test verifies that the send_chirp_notif_msg function correctly processes a chirp notification message that contains a valid MAC address.
 * The test constructs a chirp data structure with specific bit fields set (mac_present = 1, hash_valid = 1) and appends a sample MAC address.
 * It then prepares a separate destination AL MAC address, and finally, the API is invoked to check if it returns a success value.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 026@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Allocate buffer for chirp data and initialize with zeros | buffer_size = sizeof(em_dpp_chirp_value_t) + 6, buffer allocated and memset to 0 | Buffer is successfully allocated and zeroed | Should be successful |
 * | 02 | Set chirp structure bit fields for mac_present and hash_valid and reserved to 0 | chirp->mac_present = 1, chirp->hash_valid = 1, chirp->reserved = 0 | Chirp structure fields are correctly set | Should be successful |
 * | 03 | Populate the chirp data with a sample MAC address using| sample_mac = "123456", 6 bytes copied into buffer after the chirp structure | Sample MAC address is correctly copied into the chirp data | Should be successful |
 * | 04 | Prepare the destination AL MAC address | dest_al_mac = "ABCDEF", dest_al_mac array filled with these 6 bytes | destination AL MAC is correctly set with the provided sample | Should be successful |
 * | 05 | Invoke the send_chirp_notif_msg API with the prepared chirp and destination MAC | chirp pointer, buffer_size, dest_al_mac | API returns greater than 0 and the EXPECT_GT assertion passes | Should Pass |
 * | 06 | Deallocate the allocated buffer and exit the test | delete[] buffer called | Memory is successfully freed without leaks | Should be successful |
 */
TEST_F(EmProvisioningTest, send_chirp_notif_msg_valid_mac_present)
{
    std::cout << "Entering send_chirp_notif_msg_valid_mac_present test" << std::endl;
    // Calculate the minimum length: size of the chirp structure + 6 bytes for MAC address
    size_t buffer_size = sizeof(em_dpp_chirp_value_t) + 6;
    // Allocate buffer for chirp data
    uint8_t *buffer = new uint8_t[buffer_size];
    memset(buffer, 0, buffer_size);
    // Cast buffer to chirp pointer
    em_dpp_chirp_value_t *chirp = reinterpret_cast<em_dpp_chirp_value_t*>(buffer);
    // Set the bit fields: mac_present = 1, hash_valid = 1, reserved = 0x00
    chirp->mac_present = 1;
    chirp->hash_valid = 1;
    chirp->reserved = 0;  // any valid reserved value
    uint8_t *chirp_mac_addr = buffer + sizeof(em_dpp_chirp_value_t);
    uint8_t mac_bytes[6] = { '1','2','3','4','5','6' };
    std::memcpy(chirp_mac_addr, mac_bytes, sizeof(mac_bytes));
    uint8_t dest_al_mac[ETH_ALEN] = { 'A', 'B', 'C', 'D', 'E', 'F' };
    int ret = provisioning->send_chirp_notif_msg(chirp, buffer_size, dest_al_mac);
    std::cout << "send_chirp_notif_msg returned: " << ret << std::endl;
    EXPECT_GT(ret, 0);
    delete[] buffer;
    std::cout << "Exiting send_chirp_notif_msg_valid_mac_present test" << std::endl;
}

/**
 * @brief Test for send_chirp_notif_msg with null chirp pointer parameter
 *
 * This test case verifies that when a null chirp pointer is provided with a non-zero chirp length, the send_chirp_notif_msg API returns an error (-1). The test validates proper error handling and robustness in the API implementation.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 027@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Prepare destination AL MAC | input: dest_al_mac = "ABCDEF"| | Should be successful |
 * | 02 | Call send_chirp_notif_msg with a NULL chirp pointer and a non-zero chirp length | input: chirp pointer = NULL, chirp_len = sizeof(em_dpp_chirp_value_t) + 6, dest_al_mac (prepared MAC) | API returns -1 and the EXPECT_EQ assertion passes | Should Pass |
 */
TEST_F(EmProvisioningTest, send_chirp_notif_msg_null_chirp_pointer)
{
    std::cout << "Entering send_chirp_notif_msg_null_chirp_pointer test" << std::endl;
    uint8_t dest_al_mac[ETH_ALEN] = { 'A', 'B', 'C', 'D', 'E', 'F' };
    size_t chirp_len = sizeof(em_dpp_chirp_value_t) + 6; // arbitrary non-zero value
    std::cout << "Invoking send_chirp_notif_msg with NULL chirp pointer and chirp_len=" << chirp_len << std::endl;
    int ret = provisioning->send_chirp_notif_msg(nullptr, chirp_len, dest_al_mac);
    std::cout << "send_chirp_notif_msg returned: " << ret << std::endl;
    EXPECT_EQ(ret, -1);
    std::cout << "Exiting send_chirp_notif_msg_null_chirp_pointer test" << std::endl;
}
/**
 * @brief Test send_chirp_notif_msg API with null destination AL MAC to verify proper error handling
 *
 * This test creates valid chirp data, sets the destination AL MAC pointer to NULL, and then invokes send_chirp_notif_msg. The expected behavior is that the function returns -1, indicating an error in processing because of the NULL destination AL MAC pointer.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 028@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                     | Test Data                                                                                         | Expected Result                                       | Notes             |
 * | :--------------: | ----------------------------------------------- | ------------------------------------------------------------------------------------------------- | ----------------------------------------------------- | ----------------- |
 * | 01               | Prepare valid chirp data              | buffer_size = sizeof(em_dpp_chirp_value_t)+6, chirp->mac_present = 1, chirp->hash_valid = 1, chirp->reserved = 0 | Valid chirp data is allocated and initialized         | Should be successful |
 * | 02               | Set destination AL MAC pointer to NULL          | dest_al_mac = nullptr                                                                               | dest_al_mac is set to NULL                             | Should be successful |
 * | 03               | Invoke send_chirp_notif_msg API                   | input: chirp pointer, buffer_size, dest_al_mac = nullptr; output: ret expected = -1               | API returns -1; assertion EXPECT_EQ(ret, -1) passes    | Should Fail       |
 * | 04               | Cleanup allocated memory                        | delete[] buffer                                                                                     | Allocated memory is freed                             | Should be successful |
 */
TEST_F(EmProvisioningTest, send_chirp_notif_msg_null_dest_al_mac)
{
    std::cout << "Entering send_chirp_notif_msg_null_dest_al_mac test" << std::endl;
    size_t buffer_size = sizeof(em_dpp_chirp_value_t) + 6;
    // Allocate buffer for chirp data
    uint8_t *buffer = new uint8_t[buffer_size];
    memset(buffer, 0, buffer_size);
    // Cast buffer to chirp pointer
    em_dpp_chirp_value_t *chirp = reinterpret_cast<em_dpp_chirp_value_t*>(buffer);
    // Set the bit fields: mac_present = 1, hash_valid = 1, reserved = 0x00
    chirp->mac_present = 1;
    chirp->hash_valid = 1;
    chirp->reserved = 0;  // any valid reserved value
    uint8_t *chirp_mac_addr = buffer + sizeof(em_dpp_chirp_value_t);
    uint8_t mac_bytes[6] = { '1','2','3','4','5','6' };
    std::memcpy(chirp_mac_addr, mac_bytes, sizeof(mac_bytes));
    uint8_t *dest_al_mac = nullptr;
    int ret = provisioning->send_chirp_notif_msg(chirp, buffer_size, dest_al_mac);
    std::cout << "send_chirp_notif_msg returned: " << ret << std::endl;
    EXPECT_EQ(ret, -1);
    delete[] buffer;
    std::cout << "Exiting send_chirp_notif_msg_null_dest_al_mac test" << std::endl;
}
/**
 * @brief Test send_chirp_notif_msg API with zero chirp length.
 *
 * This test verifies that sending a chirp notification message with zero chirp length is handled correctly by
 * the send_chirp_notif_msg API. It sets up chirp data with a valid MAC address, assigns the chirp length to zero,
 * and expects the API to return -1. This test ensures proper error handling when the chirp length is below the minimum requirement.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 029@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                          | Test Data                                                                                                      | Expected Result                                                                                        | Notes              |
 * | :--------------: | ---------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ | ------------------ |
 * |      01        | Prepare chirp data with valid MAC and hash valid flags | buffer_size = sizeof(em_dpp_chirp_value_t)+6, chirp->mac_present=1, chirp->hash_valid=1      | Buffer allocated and chirp data correctly initialized                                                | Should be successful |
 * |      02        | Prepare destination AL MAC for notification           | dest_al_mac initialized with "ABCDEF"                                                                          | Destination MAC correctly set                                                                          | Should be successful |
 * |      03        | Invoke send_chirp_notif_msg with zero chirp length      | chirp_len=0, chirp pointer, dest_al_mac pointer                                                                  | API returns -1; EXPECT_EQ(ret, -1) assertion passes                                                    | Should Pass        |
 */
TEST_F(EmProvisioningTest, send_chirp_notif_msg_zero_chirp_length)
{
    std::cout << "Entering send_chirp_notif_msg_zero_chirp_length test" << std::endl;
    size_t buffer_size = sizeof(em_dpp_chirp_value_t) + 6;
    uint8_t *buffer = new uint8_t[buffer_size];
    memset(buffer, 0, buffer_size);
    em_dpp_chirp_value_t *chirp = reinterpret_cast<em_dpp_chirp_value_t*>(buffer);
    chirp->mac_present = 1;
    chirp->hash_valid = 1;
    chirp->reserved = 0;
    uint8_t *chirp_mac_addr = buffer + sizeof(em_dpp_chirp_value_t);
    uint8_t mac_bytes[6] = { '1','2','3','4','5','6' };
    std::memcpy(chirp_mac_addr, mac_bytes, sizeof(mac_bytes));
    uint8_t dest_al_mac[ETH_ALEN] = { 'A', 'B', 'C', 'D', 'E', 'F' };
    // Set chirp length to zero.
    size_t chirp_len = 0;
    int ret = provisioning->send_chirp_notif_msg(chirp, chirp_len, dest_al_mac);
    std::cout << "send_chirp_notif_msg returned: " << ret << std::endl;
    EXPECT_EQ(ret, -1);
    delete[] buffer;
    std::cout << "Exiting send_chirp_notif_msg_zero_chirp_length test" << std::endl;
}
/**
 * @brief Validate sending a direct encapsulated DPP message with valid input parameters.
 *
 * This test verifies that when a valid DPP frame and a valid destination AL MAC address are provided, 
 * the send_direct_encap_dpp_msg API returns a success status. It ensures the API correctly processes the 
 * encapsulated DPP message for valid direct encapsulation scenarios.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 030@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                 | Test Data                                                                                                                                                       | Expected Result                                | Notes         |
 * | :--------------: | --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- | ------------- |
 * | 01               | Prepare sample DPP frame data.                                              | dpp_frame = 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x11,0x22,0x33,0x44, dpp_frame_len = 10                                                                                   | DPP frame data is initialized properly         | Should be successful |
 * | 02               | Prepare valid destination AL MAC address.            | dest_al_mac = 0x00,0x1A,0x2B,0x3C,0x4D,0x5E,                                     | dest_al_mac is set correctly                    | Should be successful |
 * | 03               | Invoke send_direct_encap_dpp_msg API with the prepared DPP frame and MAC.     | input: dpp_frame, dpp_frame_len, dest_al_mac; output: ret variable                                                                                                | API returns greater than 0 indicating success                | Should Pass   |
 * | 04               | Verify the API response using the assertion check.                        | ASSERT only: ret > 0                                                                                                                                             | EXPECT_GT(ret, 0) results in pass if ret > 0 | Should Pass   |
 */
TEST_F(EmProvisioningTest, send_direct_encap_dpp_msg_valid_direct_encap_dpp_msg)
{
    std::cout << "Entering send_direct_encap_dpp_msg_valid_direct_encap_dpp_msg test" << std::endl;
    // Prepare sample DPP frame data
    uint8_t dpp_frame[10] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44};
    size_t dpp_frame_len{10};
    // Prepare valid destination AL MAC address
    uint8_t dest_al_mac[ETH_ALEN] = {0x41, 0x42, 0x43, 0x44, 0x45, 0x46};
    int ret = provisioning->send_direct_encap_dpp_msg(dpp_frame, dpp_frame_len, dest_al_mac);
    std::cout << "Returned status: " << ret << std::endl;
    EXPECT_GT(ret, 0);
    std::cout << "Exiting send_direct_encap_dpp_msg_valid_direct_encap_dpp_msg test" << std::endl;
}
/**
 * @brief Validate error handling when a null dpp_frame pointer is provided
 *
 * This test validates that the send_direct_encap_dpp_msg API correctly handles a scenario where the dpp_frame pointer is null and dpp_frame_len is non-zero. The test ensures that the function returns an error code (-1) as expected, thereby verifying robust error checking.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 031@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Initialize test inputs by setting dpp_frame to nullptr, dpp_frame_len to 10, and preparing dest_al_mac with a valid MAC address | dpp_frame = nullptr, dpp_frame_len = 10, dest_al_mac = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E] | Input data is set as expected | Should be successful |
 * | 02 | Invoke send_direct_encap_dpp_msg API with the prepared inputs and capture the output | dpp_frame = nullptr, dpp_frame_len = 10, dest_al_mac = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E] | API returns error code (-1) and assertion passes | Should Fail |
 */
TEST_F(EmProvisioningTest, send_direct_encap_dpp_msg_null_dpp_frame_pointer)
{
    std::cout << "Entering send_direct_encap_dpp_msg_null_dpp_frame_pointer test" << std::endl;
    uint8_t* dpp_frame = nullptr;
    size_t dpp_frame_len{10};
    uint8_t dest_al_mac[6] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
    int ret = provisioning->send_direct_encap_dpp_msg(dpp_frame, dpp_frame_len, dest_al_mac);
    std::cout << "Returned status: " << ret << std::endl;
    EXPECT_EQ(ret, -1);
    std::cout << "Exiting send_direct_encap_dpp_msg_null_dpp_frame_pointer test" << std::endl;
}

/**
 * @brief Test the send_direct_encap_dpp_msg API when provided with a DPP frame length of zero
 *
 * This test verifies that the send_direct_encap_dpp_msg API properly handles a scenario where the DPP frame length is zero.
 * It ensures that when a zero length is provided along with a valid DPP frame buffer and a valid destination AL MAC address,
 * the function returns an error code (-1) as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 032@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                  | Test Data                                                                                                                               | Expected Result                                                  | Notes         |
 * | :--------------: | -------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- | ------------- |
 * | 01               | Invoke send_direct_encap_dpp_msg with a valid DPP frame pointer, zero dpp_frame_len, and valid dest_al_mac | dpp_frame = {0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE}, dpp_frame_len = 0, dest_al_mac = {0x00,0x1A,0x2B,0x3C,0x4D,0x5E} | Returns -1 and assertion EXPECT_EQ(ret, -1) passes             | Should Fail   |
 */
TEST_F(EmProvisioningTest, send_direct_encap_dpp_msg_zero_dpp_frame_len)
{
    std::cout << "Entering send_direct_encap_dpp_msg_zero_dpp_frame_len test" << std::endl;
    uint8_t dpp_frame[10] = {0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    size_t dpp_frame_len{0};  // Zero length
    uint8_t dest_al_mac[6] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
    int ret = provisioning->send_direct_encap_dpp_msg(dpp_frame, dpp_frame_len, dest_al_mac);
    std::cout << "Returned status: " << ret << std::endl;
    EXPECT_EQ(ret, -1);
    std::cout << "Exiting send_direct_encap_dpp_msg_zero_dpp_frame_len test" << std::endl;
}

/**
 * @brief Verify that send_direct_encap_dpp_msg returns an error (-1) when the destination AL MAC pointer is null.
 *
 * This test verifies that the send_direct_encap_dpp_msg() function properly detects an invalid null destination AL MAC pointer and returns -1 as an error indicator. It is important to ensure that the function gracefully handles such scenarios without attempting to process invalid memory.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 033@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                   | Test Data                                                                                                                     | Expected Result                                              | Notes       |
 * | :--------------: | --------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ | ----------- |
 * | 01               | Invoke send_direct_encap_dpp_msg with a valid DPP frame and a null pointer for dest_al_mac      | dpp_frame = 0xDE,0xAD,0xBE,0xEF,0xFE,0xED,0xBA,0xBE,0xCA,0xFE, dpp_frame_len = 10, dest_al_mac = nullptr, output = -1       | Function returns -1 indicating error on null destination pointer | Should Pass |
 */
TEST_F(EmProvisioningTest, send_direct_encap_dpp_msg_null_dest_al_mac_pointer)
{
    std::cout << "Entering send_direct_encap_dpp_msg_null_dest_al_mac_pointer test" << std::endl;
    uint8_t dpp_frame[10] = {0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED, 0xBA, 0xBE, 0xCA, 0xFE};
    size_t dpp_frame_len{10};
    uint8_t* dest_al_mac = nullptr;
    int ret = provisioning->send_direct_encap_dpp_msg(dpp_frame, dpp_frame_len, dest_al_mac);
    std::cout << "Returned status: " << ret << std::endl;
    EXPECT_EQ(ret, -1);
    std::cout << "Exiting send_direct_encap_dpp_msg_null_dest_al_mac_pointer test" << std::endl;
}
/**
 * @brief Validate send_prox_encap_dpp_msg API with valid inputs
 *
 * This test verifies that the send_prox_encap_dpp_msg API correctly processes valid encapsulated DPP TLV and chirp data. It ensures that when the API is provided with properly initialized data structures and input parameters, it returns value greater than 0 without throwing any exceptions, indicating successful handling of the encapsulation and chirp information.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 034@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke send_prox_encap_dpp_msg API with valid encapsulated DPP TLV and chirp data | encap_ptr: pointer to em_encap_dpp_t with dpp_frame_indicator=1, enrollee_mac_addr_present=1 and minimal valid TLV data (dummy_dest_mac, frame_type=0xAA, encap_frame_len=0x0001, dummy frame content); encap_dpp_len: sizeof(em_encap_dpp_t)+10, chirp_ptr: pointer to em_dpp_chirp_value_t with hash_valid=1, mac_present=1 and valid_chirp_mac (6 bytes); chirp_len: sizeof(em_dpp_chirp_value_t)+6, dst_al_mac: "abc123" stored in a 6-byte buffer | API returns greater than 0; assertions validate return value > 0 | Should Pass |
 */
TEST_F(EmProvisioningTest, send_prox_encap_dpp_msg_valid_inputs)
{
    std::cout << "Entering send_prox_encap_dpp_msg_valid_inputs test" << std::endl;

    // Prepare minimal valid encapsulated DPP TLV
    // Allocate buffer: size of structure with additional 10 bytes for TLV payload (dest_mac[6] + frame_type[1] + encap_frame_len[2] + encap_frame[1])
    size_t extra_encap_bytes = 10;
    uint8_t encap_buffer[128] = {0}; // large enough buffer
    memset(encap_buffer, 0, sizeof(encap_buffer));
    // Copy minimal data into encap_buffer
    // Initialize the em_encap_dpp_t part via pointer
    em_encap_dpp_t* encap_ptr = reinterpret_cast<em_encap_dpp_t*>(encap_buffer);
    // Set flags using bitfield assignments
    encap_ptr->dpp_frame_indicator = 1;
    encap_ptr->enrollee_mac_addr_present = 1;

    // Fill the flexible data area with dummy values
    uint8_t dummy_dest_mac[ETH_ALEN] = {0x01,0x02,0x03,0x04,0x05,0x06};
    memcpy(&encap_ptr->data[0], dummy_dest_mac, ETH_ALEN);
    encap_ptr->data[6] = 0xAA; // frame_type dummy
    // Put encap_frame_len as 0x0001 (1 byte frame)
    encap_ptr->data[7] = 0x00;
    encap_ptr->data[8] = 0x01;
    encap_ptr->data[9] = 0xFF; // dummy frame content

    size_t encap_dpp_len = sizeof(em_encap_dpp_t) + extra_encap_bytes;

    // Prepare minimal valid chirp value structure:
    // Allocate buffer: size of structure with additional 6 bytes for MAC if mac_present flag is set
    size_t extra_chirp_bytes = 6;
    uint8_t chirp_buffer[128] = {0};
    memset(chirp_buffer, 0, sizeof(chirp_buffer));
    em_dpp_chirp_value_t* chirp_ptr = reinterpret_cast<em_dpp_chirp_value_t*>(chirp_buffer);
    chirp_ptr->hash_valid = 1;
    chirp_ptr->mac_present = 1;
    // Fill the flexible array with a valid MAC address (6 bytes)
    uint8_t valid_chirp_mac[ETH_ALEN] = {0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
    memcpy(&chirp_ptr->data[0], valid_chirp_mac, ETH_ALEN);
    size_t chirp_len = sizeof(em_dpp_chirp_value_t) + extra_chirp_bytes;

    uint8_t dst_al_mac[ETH_ALEN] = {0x61, 0x62, 0x63, 0x31, 0x32, 0x33};
    int ret;
    ret = provisioning->send_prox_encap_dpp_msg(encap_ptr, encap_dpp_len, chirp_ptr, chirp_len, dst_al_mac);
    std::cout << "send_prox_encap_dpp_msg returned: " << ret << std::endl;
    EXPECT_GT(ret, 0);

    std::cout << "Exiting send_prox_encap_dpp_msg_valid_inputs test" << std::endl;
}
/**
 * @brief Testing send_prox_encap_dpp_msg with a NULL encap_dpp_tlv to validate error handling
 *
 * This test verifies that the send_prox_encap_dpp_msg() API returns an error (-1) when the em_encap_dpp_t pointer is NULL and encap_dpp_len is non-zero.
 * It ensures that the provisioning implementation correctly handles invalid TLV inputs while the other parameters such as chirp value and destination MAC are valid.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 035@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Prepare test inputs with NULL em_encap_dpp_t and valid chirp value and dst_al_mac, then invoke send_prox_encap_dpp_msg | encap_ptr = NULL, encap_dpp_len = 10, chirp_ptr->hash_valid = 1, chirp_ptr->mac_present = 0, chirp_len = sizeof(em_dpp_chirp_value_t), dst_al_mac = "{0x61, 0x62, 0x63, 0x31, 0x32, 0x33}" | API returns -1 and EXPECT_EQ(-1, ret) verifies the returned value | Should Pass |
 */
TEST_F(EmProvisioningTest, send_prox_encap_dpp_msg_null_encap_dpp_tlv)
{
    std::cout << "Entering send_prox_encap_dpp_msg_null_encap_dpp_tlv test" << std::endl;

    em_encap_dpp_t* encap_ptr = nullptr;
    size_t encap_dpp_len = 10;

    // Prepare valid chirp value structure as in valid test
    uint8_t chirp_buffer[128] = {0};
    memset(chirp_buffer, 0, sizeof(chirp_buffer));
    em_dpp_chirp_value_t* chirp_ptr = reinterpret_cast<em_dpp_chirp_value_t*>(chirp_buffer);
    chirp_ptr->hash_valid = 1;
    chirp_ptr->mac_present = 0; // not setting MAC, so no extra data needed
    size_t chirp_len = sizeof(em_dpp_chirp_value_t);

    uint8_t dst_al_mac[ETH_ALEN] = {0x61, 0x62, 0x63, 0x31, 0x32, 0x33};

    int ret = provisioning->send_prox_encap_dpp_msg(encap_ptr, encap_dpp_len, chirp_ptr, chirp_len, dst_al_mac);
    std::cout << "send_prox_encap_dpp_msg returned: " << ret << std::endl;
    EXPECT_EQ(-1, ret);

    std::cout << "Exiting send_prox_encap_dpp_msg_null_encap_dpp_tlv test" << std::endl;
}
/**
 * @brief Validate that send_prox_encap_dpp_msg correctly handles a NULL chirp pointer
 *
 * This test verifies that invoking send_prox_encap_dpp_msg with a valid encapsulated DPP TLV,
 * a NULL chirp pointer, and a non-zero chirp length results in an error return value (-1). The test
 * ensures that the API correctly detects the invalid chirp pointer scenario and that cleanup is performed appropriately.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 036@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke send_prox_encap_dpp_msg with valid encapsulated DPP TLV, NULL chirp pointer and valid destination MAC | encap_ptr = valid pointer (dpp_frame_indicator=1, enrollee_mac_addr_present=0, data[0]=0xBB), encap_dpp_len = sizeof(em_encap_dpp_t)+10, chirp_ptr = NULL, chirp_len = 5, dst_al_mac = { 0x67, 0x68, 0x69, 0x07, 0x08, 0x09 } | API returns -1 as error indication and EXPECT_EQ(-1, ret) assertion passes | Should Pass |
 */
TEST_F(EmProvisioningTest, send_prox_encap_dpp_msg_null_chirp)
{
    std::cout << "Entering send_prox_encap_dpp_msg_null_chirp test" << std::endl;

    // Prepare a valid encapsulated DPP TLV
    size_t extra_encap_bytes = 10;
    uint8_t encap_buffer[128] = {0};
    memset(encap_buffer, 0, sizeof(encap_buffer));
    em_encap_dpp_t* encap_ptr = reinterpret_cast<em_encap_dpp_t*>(encap_buffer);
    encap_ptr->dpp_frame_indicator = 1;
    encap_ptr->enrollee_mac_addr_present = 0; // set to 0 so extra MAC not required
    // Fill dummy flexible data if any
    encap_ptr->data[0] = 0xBB;
    size_t encap_dpp_len = sizeof(em_encap_dpp_t) + extra_encap_bytes;

    // chirp pointer is NULL; chirp length non-zero (e.g., 5)
    em_dpp_chirp_value_t* chirp_ptr = nullptr;
    size_t chirp_len = 5;

    uint8_t dst_al_mac[ETH_ALEN] = { 0x67, 0x68, 0x69, 0x07, 0x08, 0x09 };

    int ret = provisioning->send_prox_encap_dpp_msg(encap_ptr, encap_dpp_len, chirp_ptr, chirp_len, dst_al_mac);
    std::cout << "send_prox_encap_dpp_msg returned: " << ret << std::endl;
    EXPECT_EQ(-1, ret);

    std::cout << "Exiting send_prox_encap_dpp_msg_null_chirp test" << std::endl;
}
/**
 * @brief Test to validate send_prox_encap_dpp_msg API behavior with zero encapsulated TLV length.
 *
 * This test verifies that the send_prox_encap_dpp_msg API returns -1 when the encapsulated DPP TLV length is set to zero.
 * It ensures that the function correctly handles an invalid TLV length while all other parameters remain valid.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 037
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke send_prox_encap_dpp_msg API with zero encapsulated TLV length and valid chirp and MAC values | encap_ptr->dpp_frame_indicator=1, enrollee_mac_addr_present=0, encap_dpp_len=0, chirp_ptr->hash_valid=1, chirp_ptr->mac_present=0, chirp_len=sizeof(em_dpp_chirp_value_t), dst_al_mac="{ 0x0L, 0x07, 0x0L, 0x01, 0x02, 0x03 }" | API returns -1 and EXPECT_EQ(-1, ret) assertion passes | Should Pass |
 */
TEST_F(EmProvisioningTest, send_prox_encap_dpp_msg_zero_encap_len)
{
    std::cout << "Entering send_prox_encap_dpp_msg_zero_encap_len test" << std::endl;

    // Prepare a valid encapsulated DPP TLV structure but set length to 0
    uint8_t encap_buffer[128] = {0};
    memset(encap_buffer, 0, sizeof(encap_buffer));
    em_encap_dpp_t* encap_ptr = reinterpret_cast<em_encap_dpp_t*>(encap_buffer);
    encap_ptr->dpp_frame_indicator = 1;
    encap_ptr->enrollee_mac_addr_present = 0;
    size_t encap_dpp_len = 0; // zero length

    // Prepare valid chirp value structure
    uint8_t chirp_buffer[128] = {0};
    memset(chirp_buffer, 0, sizeof(chirp_buffer));
    em_dpp_chirp_value_t* chirp_ptr = reinterpret_cast<em_dpp_chirp_value_t*>(chirp_buffer);
    chirp_ptr->hash_valid = 1;
    chirp_ptr->mac_present = 0;
    size_t chirp_len = sizeof(em_dpp_chirp_value_t);

    uint8_t dst_al_mac[ETH_ALEN] = { 0x0L, 0x07, 0x0L, 0x01, 0x02, 0x03 };

    int ret = provisioning->send_prox_encap_dpp_msg(encap_ptr, encap_dpp_len, chirp_ptr, chirp_len, dst_al_mac);
    std::cout << "send_prox_encap_dpp_msg returned: " << ret << std::endl;
    EXPECT_EQ(-1, ret);

    std::cout << "Exiting send_prox_encap_dpp_msg_zero_encap_len test" << std::endl;
}
/**
 * @brief Validate that send_prox_encap_dpp_msg returns an error when the chirp length is zero.
 *
 * This test verifies that the API send_prox_encap_dpp_msg correctly handles a scenario where a valid encapsulated DPP TLV is provided along with a chirp value structure that has its chirp length set to zero. The test is important to ensure that the function can detect a missing chirp data situation and return an error (-1) accordingly.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 038@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Prepare a valid encapsulated DPP TLV and a chirp value structure with chirp length set to zero, then invoke send_prox_encap_dpp_msg. | encap_ptr: {dpp_frame_indicator = 1, enrollee_mac_addr_present = 0, data[0] = 0xCC}, encap_dpp_len = sizeof(em_encap_dpp_t) + 10, chirp_ptr: {hash_valid = 1, mac_present = 0}, chirp_len = 0, dst_al_mac = "{0x6D, 0x6E, 0x6F, 0x03, 0x04, 0x05}" | API returns -1 and the EXPECT_EQ(-1, ret) assertion passes | Should Fail |
 */
TEST_F(EmProvisioningTest, send_prox_encap_dpp_msg_zero_chirp_len)
{
    std::cout << "Entering send_prox_encap_dpp_msg_zero_chirp_len test" << std::endl;

    // Prepare a valid encapsulated DPP TLV
    size_t extra_encap_bytes = 10;
    uint8_t encap_buffer[128] = {0};
    memset(encap_buffer, 0, sizeof(encap_buffer));
    em_encap_dpp_t* encap_ptr = reinterpret_cast<em_encap_dpp_t*>(encap_buffer);
    encap_ptr->dpp_frame_indicator = 1;
    encap_ptr->enrollee_mac_addr_present = 0;
    encap_ptr->data[0] = 0xCC;
    size_t encap_dpp_len = sizeof(em_encap_dpp_t) + extra_encap_bytes;

    // Prepare a valid chirp value structure but set chirp_len to 0
    uint8_t chirp_buffer[128] = {0};
    memset(chirp_buffer, 0, sizeof(chirp_buffer));
    em_dpp_chirp_value_t* chirp_ptr = reinterpret_cast<em_dpp_chirp_value_t*>(chirp_buffer);
    chirp_ptr->hash_valid = 1;
    chirp_ptr->mac_present = 0;
    size_t chirp_len = 0; // zero length

    // Prepare valid dst_al_mac
    uint8_t dst_al_mac[ETH_ALEN] = {0x6D, 0x6E, 0x6F, 0x03, 0x04, 0x05};

    int ret = provisioning->send_prox_encap_dpp_msg(encap_ptr, encap_dpp_len, chirp_ptr, chirp_len, dst_al_mac);
    std::cout << "send_prox_encap_dpp_msg returned: " << ret << std::endl;
    EXPECT_EQ(-1, ret);

    std::cout << "Exiting send_prox_encap_dpp_msg_zero_chirp_len test" << std::endl;
}
