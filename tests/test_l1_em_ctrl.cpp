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
#include <sanitizer/lsan_interface.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <stdio.h>
#include "em_ctrl.h"

class em_ctrl_t_Test : public ::testing::Test {
protected:
    em_ctrl_t ctrl;
    void SetUp() override {
	__lsan_disable();
        const char* data_model_path = "/tmp/test_config.db";
	ctrl.init(data_model_path);
	ctrl.orch_init();
    }
    void TearDown() override {
        __lsan_enable();
    }    
    void setup_interface(em_interface_t &intf, const char* name, const unsigned char mac[6]) {
        strncpy(intf.name, name, sizeof(intf.name)-1);
        intf.name[sizeof(intf.name)-1] = '\0';
        memcpy(intf.mac, mac, sizeof(intf.mac));
    }
};

/**
 * @brief To validate that the get_em_ctrl_instance method returns a valid instance.
 *
 * This test verifies that calling the get_em_ctrl_instance method of the em_ctrl_t class returns a non-null pointer instance. It ensures the API properly instantiates and provides access to the em_ctrl_t instance.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 001@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                           | Test Data                                         | Expected Result                                                              | Notes       |
 * | :--------------: | --------------------------------------------------------------------- | ------------------------------------------------- | ---------------------------------------------------------------------------- | ----------- |
 * | 01               | Call get_em_ctrl_instance and verify the returned pointer is non-null. | input = None, output = pointer returned from API  | API returns a non-null pointer; EXPECT_NE(ctrl, nullptr) assertion passes     | Should Pass |
 */
TEST(em_ctrl_t, get_em_ctrl_instance_default) {
    std::cout << "Entering get_em_ctrl_instance_default test" << std::endl;
    em_ctrl_t* ctrl = em_ctrl_t::get_em_ctrl_instance();
    EXPECT_NE(ctrl, nullptr);
    std::cout << "Exiting get_em_ctrl_instance_default test" << std::endl;
}
/**
 * @brief Validate that ctrl.get_dm_ctrl() returns a valid non-null pointer.
 *
 * This test checks that the get_dm_ctrl() API of the controller (ctrl) returns a non-null pointer to dm_ctrl, ensuring the controller is properly initialized and the control data model is correctly retrieved.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 002@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call the API ctrl.get_dm_ctrl() to retrieve the dm_ctrl pointer. | input: none, output: dm_ctrl pointer | API returns a non-null pointer; EXPECT_NE(dm_ctrl, nullptr) passes. | Should Pass |
 */
TEST_F(em_ctrl_t_Test, get_dm_ctrl_default) {
    std::cout << "Entering get_dm_ctrl_default test" << std::endl;
    dm_easy_mesh_ctrl_t* dm_ctrl = ctrl.get_dm_ctrl();
    EXPECT_NE(dm_ctrl, nullptr);
    std::cout << "Exiting get_dm_ctrl_default test" << std::endl;
}
/**
 * @brief Tests the initialization of the data model with a valid configuration file path.
 *
 * This test validates that the data_model_init function returns a success status (0) when provided with a valid data model path. It ensures that the data model initialization is properly performed using the given configuration database path.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 003
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                   | Test Data                                                       | Expected Result                                                                                       | Notes       |
 * | :--------------: | --------------------------------------------------------------------------------------------- | --------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Call data_model_init with a valid data model path "/tmp/test_config.db" to initialize the model. | data_model_path = "/tmp/test_config.db", result = return value of data_model_init | data_model_init should return 0 and EXPECT_EQ(result, 0) should pass.                                   | Should Pass |
 */
TEST_F(em_ctrl_t_Test, data_model_init_valid_path) {
    std::cout << "Entering data_model_init_valid_path test" << std::endl;
    em_ctrl_t ctrl;
    const char* data_model_path = "/tmp/test_config.db";
    int result = ctrl.data_model_init(data_model_path);
    EXPECT_EQ(result, 0);
    std::cout << "Exiting data_model_init_valid_path test" << std::endl;
}
/**
 * @brief Verify that data_model_init returns an error when a null pointer is provided as the data model path.
 *
 * This test verifies that providing a nullptr as the data model path to the data_model_init API function results in a non-zero error code. The test ensures that the API handles invalid input correctly and fails gracefully.
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
 * | Variation / Step | Description                                                                          | Test Data                                             | Expected Result                                                         | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------ | ----------------------------------------------------- | ----------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke data_model_init API with a nullptr for the data_model_path argument.            | data_model_path = nullptr, output result from API call| data_model_init returns a non-zero error code as validated by EXPECT_NE(result, 0) | Should Fail |
 */
TEST_F(em_ctrl_t_Test, data_model_init_nullptr_path) {
    std::cout << "Entering data_model_init_nullptr_path test" << std::endl;
    em_ctrl_t ctrl;
    const char* data_model_path = nullptr;
    int result = ctrl.data_model_init(data_model_path);
    EXPECT_NE(result, 0);
    std::cout << "Exiting data_model_init_nullptr_path test" << std::endl;
}
/**
 * @brief Validate the behavior of data_model_init when provided with an empty data model path.
 *
 * This test verifies that the data_model_init function of the em_ctrl_t class returns a non-zero error code when passed an empty string as the data model path. This case is critical to ensure the API correctly handles invalid configuration inputs.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 005
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                          | Test Data                                      | Expected Result                                                               | Notes       |
 * | :--------------: | ---------------------------------------------------- | ---------------------------------------------- | ----------------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke data_model_init with an empty data model path | data_model_path = ""                           | API returns a non-zero value indicating an error, and EXPECT_NE(result, 0) passes | Should Pass |
 */
TEST_F(em_ctrl_t_Test, data_model_init_empty_path) {
    std::cout << "Entering data_model_init_empty_path test" << std::endl;
    em_ctrl_t ctrl;
    const char* data_model_path = "";
    int result = ctrl.data_model_init(data_model_path);
    EXPECT_NE(result, 0);
    std::cout << "Exiting data_model_init_empty_path test" << std::endl;
}
/**
 * @brief Test to verify that the data model is not initialized by default.
 *
 * This test verifies that ctrl.is_data_model_initialized() returns false, indicating that the data model is not initialized in its default state.
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
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke ctrl.is_data_model_initialized() to verify that the data model is not initialized by default | ctrl: Instance with data_model_path="/tmp/test_config.db", output: expected return value = false | The API returns false and the assertion EXPECT_FALSE passes | Should Pass |
 */
TEST_F(em_ctrl_t_Test, is_data_model_initialized_default) {
    std::cout << "Entering is_data_model_initialized_default test" << std::endl;
    EXPECT_FALSE(ctrl.is_data_model_initialized());
    std::cout << "Exiting is_data_model_initialized_default test" << std::endl;
}
/**
 * @brief Verifies that the network topology is correctly initialized after creating a data model and setting up the network interface.
 *
 * This test sets up the network interface using the setup_interface helper, creates a data model via create_data_model, and then calls init_network_topology. It asserts that the returned data model is not null and verifies that is_network_topology_initialized returns true, ensuring the proper initialization of the network topology.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 007@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Setup network interface using setup_interface helper function | intf, name="eth0", mac=0x11,0x22,0x33,0x04,0x05,0x01 | Interface properties set accordingly | Should be successful |@n
 * | 02 | Create data model by invoking create_data_model API | ctrl, "Network2", intf, em_profile_type_1 | Valid data model pointer returned (not null) | Should Pass |@n
 * | 03 | Set the m_colocated flag for the data model | dm->m_colocated = true | m_colocated flag set to true | Should be successful |@n
 * | 04 | Initialize network topology and validate using is_network_topology_initialized | ctrl, topology status check | is_network_topology_initialized returns true | Should Pass |
 */
TEST_F(em_ctrl_t_Test, is_network_topology_initialized_valid)
{
    std::cout << "Entering is_network_topology_initialized_valid test" << std::endl;
    em_interface_t intf;
    unsigned char mac[6] = {0x11,0x22,0x33,0x04,0x05,0x01};
    setup_interface(intf, "eth0", mac);
    dm_easy_mesh_t* dm = ctrl.create_data_model("Network2", &intf, em_profile_type_1);
    dm->m_colocated = true;
    ASSERT_NE(dm, nullptr);
    ctrl.init_network_topology();
    EXPECT_TRUE(ctrl.is_network_topology_initialized());
    std::cout << "Exiting is_network_topology_initialized_valid test" << std::endl;
}
/**
 * @brief Verify that the network topology is not initialized by default.
 *
 * This test checks that immediately after initialization, before any network configuration,
 * the network topology status remains uninitialized. It validates the proper use of logging
 * messages as well as the correct default return value from is_network_topology_initialized().
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 008@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                   | Test Data                                                                                      | Expected Result                                                                            | Notes            |
 * | :--------------: | --------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ | ---------------- |
 * | 01               | Log entry message and verify default topology initialization status                           | output1 = "Entering is_network_topology_initialized_default test", ctrl initialized via SetUp   | ctrl.is_network_topology_initialized() returns false and EXPECT_FALSE passes                | Should Pass      |
 * | 02               | Log exit message                                                                              | output1 = "Exiting is_network_topology_initialized_default test"                               | Proper log exit message is printed                                                         | Should be successful |
 */
TEST_F(em_ctrl_t_Test, is_network_topology_initialized_default)
{
    std::cout << "Entering is_network_topology_initialized_default test" << std::endl;
    EXPECT_FALSE(ctrl.is_network_topology_initialized());
    std::cout << "Exiting is_network_topology_initialized_default test" << std::endl;
}
/**
 * @brief Validate that the start_complete API behaves as expected under default configuration.
 *
 * This test validates that invoking start_complete successfully processes the data model creation and initialization without throwing exceptions, ensuring that the data model is not null and that the colocated flag is set appropriately.
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
 * | Variation / Step | Description                                                      | Test Data                                                                 | Expected Result                                                    | Notes            |
 * | :--------------: | ---------------------------------------------------------------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------ | ---------------- |
 * | 01               | Initialize the interface with name "eth0" and provided MAC value   | name = "eth0", mac = {0x11,0x22,0x33,0x04,0x05,0x01}                      | Interface is setup correctly                                       | Should be successful  |
 * | 02               | Create a data model for "Network2" with the initialized interface and profile type em_profile_type_1 | network = "Network2", interface pointer, profile_type = em_profile_type_1 | Data model is created (dm != nullptr)                              | Should Pass      |
 * | 03               | Set the m_colocated flag in the data model to true                 | dm->m_colocated = true                                                    | m_colocated flag is updated to true                                | Should be successful  |
 * | 04               | Invoke the start_complete() API and ensure no exceptions are thrown  | API call: ctrl.start_complete()                                           | API completes execution without throwing any exceptions; assertion passes | Should Pass      |
 */
TEST_F(em_ctrl_t_Test, start_complete_default)
{
    std::cout << "Entering start_complete_default test" << std::endl;
    em_interface_t intf;
    unsigned char mac[6] = {0x11,0x22,0x33,0x04,0x05,0x01};
    setup_interface(intf, "eth0", mac);
    dm_easy_mesh_t* dm = ctrl.create_data_model("Network2", &intf, em_profile_type_1);
    dm->m_colocated = true;
    ASSERT_NE(dm, nullptr);
    EXPECT_NO_THROW(ctrl.start_complete());
    std::cout << "Exiting start_complete_default test" << std::endl;
}
/**
 * @brief Verify that orch_init() returns 0 for a default controller instance.
 *
 * This test validates that invoking the orch_init() method on a default constructed
 * em_ctrl_t object results in a successful initialization, indicated by a return value of 0.
 * It ensures that the basic initialization flow of the orchestration component is functioning correctly.
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
 * | Variation / Step | Description                                                        | Test Data                                                         | Expected Result                           | Notes       |
 * | :--------------: | -------------------------------------------------------------------| ----------------------------------------------------------------- | ------------------------------------------|-------------|
 * | 01               | Create a default em_ctrl_t instance and invoke orch_init().         | ctrl instance = default, orch_init() called with no parameters    | orch_init() returns 0                     | Should Pass |
 */
TEST_F(em_ctrl_t_Test, orch_init_default)
{
    std::cout << "Entering orch_init_default test" << std::endl;
    em_ctrl_t ctrl;
    int ret = ctrl.orch_init();
    EXPECT_EQ(ret, 0);
    std::cout << "Exiting orch_init_default test" << std::endl;
}
/**
 * @brief Verifies that handle_500ms_tick() executes without throwing an exception.
 *
 * This test verifies that the em_ctrl_t object's handle_500ms_tick() method does not throw any exceptions when invoked.
 * It ensures that the periodic tick processing in the control module is handled correctly under normal operating conditions.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 011
 * **Priority:** High
 * 
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                           | Test Data                                              | Expected Result                                  | Notes      |
 * | :--------------: | --------------------------------------------------------------------- | ------------------------------------------------------ | ----------------------------------------------- | ---------- |
 * | 01               | Invoke handle_500ms_tick() method of the em_ctrl_t object.             | ctrl.handle_500ms_tick() with default internal state   | EXPECT_NO_THROW passes, no exception thrown     | Should Pass |
 */
TEST_F(em_ctrl_t_Test, handle_500ms_tick_default) {
    std::cout << "Entering handle_500ms_tick_default test" << std::endl;
    EXPECT_NO_THROW(ctrl.handle_500ms_tick());
    std::cout << "Exiting handle_500ms_tick_default test" << std::endl;
}
/**
 * @brief Validate the execution of handle_dirty_dm for a single data model instance.
 *
 * This test verifies that the controller correctly processes a single created data model.
 * It sets up an interface with a specific MAC and name ("eth0"), creates a data model ("Network1")
 * using the em_profile_type_1 profile, and then calls handle_dirty_dm. The test asserts that the
 * data model pointer returned is not null and that handle_dirty_dm executes without throwing any exception.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 012@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                                                                        | Test Data                                                                                                                                                  | Expected Result                                                              | Notes      |
 * | :--------------: | -------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ---------- |
 * | 01               | Set up the interface and create a single data model using create_data_model, then invoke handle_dirty_dm and verify proper execution.            | data_model_path = /tmp/test_config.db, name = eth0, mac = 0x01,0x02,0x03,0x04,0x05,0x01, profile_type = em_profile_type_1, output(dm) should be non-null | dm pointer is non-null and handle_dirty_dm does not throw any exception       | Should Pass |
 */
TEST_F(em_ctrl_t_Test, handle_dirty_dm_single_dm) {
    std::cout << "Entering handle_dirty_dm_single_dm test" << std::endl;
    em_interface_t intf;
    unsigned char mac[6] = {0x01,0x02,0x03,0x04,0x05,0x01};
    setup_interface(intf, "eth0", mac);
    dm_easy_mesh_t* dm = ctrl.create_data_model("Network1", &intf, em_profile_type_1);
    ASSERT_NE(dm, nullptr);
    EXPECT_NO_THROW(ctrl.handle_dirty_dm());
    std::cout << "Exiting handle_dirty_dm_single_dm test" << std::endl;
}
/**
 * @brief Validates that multiple data models are processed correctly by the controller.
 *
 * This test verifies that after initializing two distinct data models with different interfaces and profiles, the controller's handle_dirty_dm function processes them without exceptions. It tests the successful creation of data models and ensures that handle_dirty_dm handles the dirty data models appropriately.
 *
 * **Test Group ID:** Basic: 01 / Module (L2): 02 / Stress (L2): 03
 * **Test Case ID:** 013
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Configure first interface and create data model with profile type em_profile_type_1 | intf1: name = "eth0", mac = 0x01,0x02,0x03,0x04,0x05,0x01; Data Model: "Network1", profile = em_profile_type_1 | dm1 is not nullptr (valid pointer returned) | Should Pass |
 * | 02 | Configure second interface and create data model with profile type em_profile_type_2 | intf2: name = "eth1", mac = 0x06,0x07,0x08,0x09,0x0A,0x02; Data Model: "Network2", profile = em_profile_type_2 | dm2 is not nullptr (valid pointer returned) | Should Pass |
 * | 03 | Invoke handle_dirty_dm to process the created dirty data models | No additional input arguments | No exception thrown during the invocation of handle_dirty_dm | Should Pass |
 */
TEST_F(em_ctrl_t_Test, handle_dirty_dm_multiple_dms) {
    std::cout << "Entering handle_dirty_dm_multiple_dms test" << std::endl;
    em_interface_t intf1;
    unsigned char mac1[6] = {0x01,0x02,0x03,0x04,0x05,0x01};
    setup_interface(intf1, "eth0", mac1);
    dm_easy_mesh_t* dm1 = ctrl.create_data_model("Network1", &intf1, em_profile_type_1);
    ASSERT_NE(dm1, nullptr);
    em_interface_t intf2;
    unsigned char mac2[6] = {0x06,0x07,0x08,0x09,0x0A,0x02};
    setup_interface(intf2, "eth1", mac2);
    dm_easy_mesh_t* dm2 = ctrl.create_data_model("Network2", &intf2, em_profile_type_2);
    ASSERT_NE(dm2, nullptr);
    EXPECT_NO_THROW(ctrl.handle_dirty_dm());
    std::cout << "Exiting handle_dirty_dm_multiple_dms test" << std::endl;
}
/**
 * @brief Verify that ctrl.handle_dirty_dm() executes correctly when the dirty data model list is empty.
 *
 * This test verifies that the handle_dirty_dm() method of the controller (ctrl) does not throw any exceptions when the dirty data model list is empty. This helps ensure stability in scenarios where no dirty entries are present.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 014@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                           | Test Data                     | Expected Result                                                         | Notes       |
 * | :--------------: | ----------------------------------------------------- | ----------------------------- | ----------------------------------------------------------------------- | ----------- |
 * | 01               | Call ctrl.handle_dirty_dm() with an empty dirty list. | input = none, output = none   | Function executes without throwing an exception; EXPECT_NO_THROW passes | Should Pass |
 */
TEST_F(em_ctrl_t_Test, handle_dirty_dm_empty_list) {
    std::cout << "Entering handle_dirty_dm_empty_list test" << std::endl;
    EXPECT_NO_THROW(ctrl.handle_dirty_dm());
    std::cout << "Exiting handle_dirty_dm_empty_list test" << std::endl;
}
/**
 * @brief Test the handle_event API with a null pointer input
 *
 * This test case verifies that invoking the handle_event function with a null pointer correctly throws an exception. The test ensures that the API handles erroneous input appropriately by not proceeding with invalid memory references.
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
 * | Variation / Step | Description                                       | Test Data                     | Expected Result                                                  | Notes       |
 * | :--------------: | ------------------------------------------------- | ----------------------------- | ---------------------------------------------------------------- | ----------- |
 * | 01               | Call ctrl.handle_event with a null pointer input  | input = nullptr               | Exception is thrown as indicated by EXPECT_ANY_THROW assertion     | Should Pass |
 */
TEST_F(em_ctrl_t_Test, handle_event_null_pointer) {
    std::cout << "Entering handle_event_null_pointer test" << std::endl;
    EXPECT_ANY_THROW(ctrl.handle_event(nullptr));
    std::cout << "Exiting handle_event_null_pointer test" << std::endl;
}
/**
 * @brief Verify that the event handler processes non-bus events without throwing exceptions
 *
 * This test verifies that the ctrl.handle_event API correctly handles non-bus event types
 * (frame, device, and node) by ensuring that no exceptions are thrown during processing.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 016@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                          | Test Data                                                                                                  | Expected Result                              | Notes            |
 * | :--------------: | ---------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | -------------------------------------------- | ---------------- |
 * | 01               | Log the entry message indicating the start of the test                                               | No input parameters                                                                                        | "Entering handle_event_NonBusEvents test" printed | Should be successful |
 * | 02               | For each non-bus event type (em_event_type_frame, em_event_type_device, em_event_type_node), create an event, set the type, and call ctrl.handle_event ensuring no exception is thrown | input: evt.type = em_event_type_frame, em_event_type_device, em_event_type_node; output: none expected         | API call completes without throwing exceptions | Should Pass      |
 * | 03               | Log the exit message indicating the end of the test                                                  | No input parameters                                                                                        | "Exiting handle_event_NonBusEvents test" printed  | Should be successful |
 */
TEST_F(em_ctrl_t_Test, handle_event_NonBusEvents) {
    std::cout << "Entering handle_event_NonBusEvents test" << std::endl;
    em_event_type_t nonBusTypes[] = {
        em_event_type_frame,
        em_event_type_device,
        em_event_type_node
    };
    for (size_t i = 0; i < sizeof(nonBusTypes)/sizeof(nonBusTypes[0]); ++i) {
        em_event_t evt = {};
        evt.type = nonBusTypes[i];
        EXPECT_NO_THROW(ctrl.handle_event(&evt));
    }
    std::cout << "Exiting handle_event_NonBusEvents test" << std::endl;
}
/**
 * @brief Validate that handle_start_dpp throws an exception when given a null event pointer.
 *
 * This test verifies that the handle_start_dpp API method robustly handles invalid inputs by throwing an exception when provided with a null event pointer. The test ensures the controller correctly identifies the erroneous input and does not process a null pointer, thus maintaining system stability.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 017
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                      | Test Data                                                       | Expected Result                                       | Notes             |
 * | :--------------: | ---------------------------------------------------------------- | --------------------------------------------------------------- | ----------------------------------------------------- | ----------------- |
 * | 01               | Log entry message indicating test start                          | message = "Entering handle_start_dpp_null_event_pointer test"    | Message is logged to the console                      | Should be successful |
 * | 02               | Invoke handle_start_dpp with a null pointer using EXPECT_ANY_THROW  | input event pointer = nullptr                                     | Exception is thrown and caught by EXPECT_ANY_THROW    | Should Fail       |
 * | 03               | Log exit message indicating test completion                        | message = "Exiting handle_start_dpp_null_event_pointer test"     | Message is logged to the console                      | Should be successful |
 */
TEST_F(em_ctrl_t_Test, handle_start_dpp_null_event_pointer)
{
    std::cout << "Entering handle_start_dpp_null_event_pointer test" << std::endl;
    EXPECT_ANY_THROW({
        ctrl.handle_start_dpp(nullptr);
    });
    std::cout << "Exiting handle_start_dpp_null_event_pointer test" << std::endl;
}
/**
 * @brief Tests the handle_client_steer API with a null event pointer to validate proper exception handling.
 *
 * This test verifies that invoking handle_client_steer with a null event pointer results in an exception being thrown. This
 * ensures that the API properly guards against null pointer access and handles error conditions as expected.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 018
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                        | Test Data                        | Expected Result                                             | Notes      |
 * | :--------------: | -------------------------------------------------- | -------------------------------- | ----------------------------------------------------------- | ---------- |
 * | 01               | Invoke handle_client_steer with a null event pointer | event pointer = nullptr          | API throws an exception; EXPECT_ANY_THROW assertion passes   | Should Pass|
 */
TEST_F(em_ctrl_t_Test, handle_client_steer_null_event_pointer)
{
    std::cout << "Entering handle_client_steer_null_event_pointer test" << std::endl;
    EXPECT_ANY_THROW({
        ctrl.handle_client_steer(nullptr);
    });
    std::cout << "Exiting handle_client_steer_null_event_pointer test" << std::endl;
}
/**
 * @brief Verify that handle_client_disassoc throws an exception when provided with a null event pointer.
 *
 * This test ensures that the em_ctrl_t::handle_client_disassoc function correctly handles the case
 * when it is given a null pointer as an event. The function is expected to throw an exception to signal
 * an error in client disassociation due to invalid input.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 019@n
 * **Priority:** (High) High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                        | Test Data                                 | Expected Result                                       | Notes      |
 * | :--------------: | ------------------------------------------------------------------ | ----------------------------------------- | ----------------------------------------------------- | ---------- |
 * | 01               | Invoke ctrl.handle_client_disassoc with a null event pointer         | input (event pointer) = nullptr           | API throws an exception; assertion verifies exception | Should Pass |
 */
TEST_F(em_ctrl_t_Test, handle_client_disassoc_null_event_pointer)
{
    std::cout << "Entering handle_client_disassoc_null_event_pointer test" << std::endl;
    EXPECT_ANY_THROW({
        ctrl.handle_client_disassoc(nullptr);
    });
    std::cout << "Exiting handle_client_disassoc_null_event_pointer test" << std::endl;
}
/**
 * @brief Verify that handle_client_btm throws an exception when a null event pointer is provided.
 *
 * This test checks that the handle_client_btm API correctly identifies a null pointer passed as the event parameter
 * and throws an exception accordingly. The objective is to validate the error handling mechanism for invalid inputs.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 020
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                               | Test Data                         | Expected Result                                 | Notes       |
 * | :--------------: | --------------------------------------------------------- | --------------------------------- | ----------------------------------------------- | ----------- |
 * | 01               | Call handle_client_btm with a null event pointer          | event pointer = nullptr           | API call should throw an exception              | Should Pass |
 */
TEST_F(em_ctrl_t_Test, handle_client_btm_null_event_pointer)
{
    std::cout << "Entering handle_client_btm_null_event_pointer test" << std::endl;
    EXPECT_ANY_THROW({
        ctrl.handle_client_btm(nullptr);
    });
    std::cout << "Exiting handle_client_btm_null_event_pointer test" << std::endl;
}
/**
 * @brief Validate that the handle_set_radio API correctly handles a null event pointer input.
 *
 * This test verifies that the API handle_set_radio, when invoked with a null event pointer,
 * correctly throws an exception as expected. The test is essential to ensure that the function
 * handles invalid (null) inputs robustly, thereby preventing undefined behavior.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 021@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                    | Test Data                                      | Expected Result                                        | Notes       |
 * | :--------------: | ---------------------------------------------- | ---------------------------------------------- | ------------------------------------------------------ | ----------- |
 * | 01               | Call handle_set_radio with a null pointer input | input = nullptr                                | API throws an exception (detected via EXPECT_ANY_THROW) | Should Pass |
 */
TEST_F(em_ctrl_t_Test, handle_set_radio_null_event_pointer)
{
    std::cout << "Entering handle_set_radio_null_event_pointer test" << std::endl;
    EXPECT_ANY_THROW({
        ctrl.handle_set_radio(nullptr);
    });
    std::cout << "Exiting handle_set_radio_null_event_pointer test" << std::endl;
}
/**
 * @brief Validate that handle_set_ssid_list handles a null pointer event for SSID list.
 *
 * This test is designed to validate that the API handle_set_ssid_list properly handles the negative scenario when a null pointer is passed. The test ensures that an exception is thrown when the method is invoked with a null event pointer.
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
 * | 01 | Invoke handle_set_ssid_list with a null pointer to validate exception handling | input: event pointer = nullptr, output: exception thrown | Exception is thrown and EXPECT_ANY_THROW assertion passes | Should Pass |
 */
TEST_F(em_ctrl_t_Test, handle_set_ssid_list_null_event_pointer)
{
    std::cout << "Entering handle_set_ssid_list_null_event_pointer test" << std::endl;
    EXPECT_ANY_THROW({
        ctrl.handle_set_ssid_list(nullptr);
    });
    std::cout << "Exiting handle_set_ssid_list_null_event_pointer test" << std::endl;
}
/**
 * @brief Test handle_remove_device with null event pointer
 *
 * This test checks that the handle_remove_device API correctly handles the scenario when a null event pointer is provided. It verifies that the function throws an exception as expected for invalid input.
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
 * | Variation / Step | Description                                    | Test Data                       | Expected Result                                             | Notes       |
 * | :--------------: | ---------------------------------------------- | ------------------------------- | ----------------------------------------------------------- | ----------- |
 * | 01               | Invoke handle_remove_device with null pointer  | event pointer = nullptr         | API should throw an exception as per assertion check         | Should Fail |
 */
TEST_F(em_ctrl_t_Test, handle_remove_device_null_event_pointer)
{
    std::cout << "Entering handle_remove_device_null_event_pointer test" << std::endl;
    EXPECT_ANY_THROW({
        ctrl.handle_remove_device(nullptr);
    });
    std::cout << "Exiting handle_remove_device_null_event_pointer test" << std::endl;
}
/**
 * @brief Verify that handle_set_channel_list throws an exception when provided with a null event pointer.
 *
 * This test ensures that the handle_set_channel_list API of the ctrl object correctly handles invalid input by throwing an exception when a null pointer is passed. This behavior is critical to prevent undefined behavior and potential crashes in the system.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 024@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description                                               | Test Data                                | Expected Result                                                 | Notes         |
 * | :--------------: | --------------------------------------------------------- | ---------------------------------------- | --------------------------------------------------------------- | ------------- |
 * | 01               | Invoke handle_set_channel_list with a null event pointer  | input: event pointer = nullptr           | API is expected to throw an exception as a result of invalid input | Should Fail   |
 */
TEST_F(em_ctrl_t_Test, handle_set_channel_list_null_event_pointer)
{
    std::cout << "Entering handle_set_channel_list_null_event_pointer test" << std::endl;
    EXPECT_ANY_THROW({
        ctrl.handle_set_channel_list(nullptr);
    });
    std::cout << "Exiting handle_set_channel_list_null_event_pointer test" << std::endl;
}
/**
 * @brief Test that the handle_scan_channel_list function throws an exception when passed a null event pointer.
 *
 * This test validates that the handle_scan_channel_list function properly handles an invalid null input by throwing an exception.
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
 * | Variation / Step | Description                                                            | Test Data                             | Expected Result                                                                   | Notes      |
 * | :--------------: | ---------------------------------------------------------------------- | ------------------------------------- | --------------------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke handle_scan_channel_list API with a null pointer as input value.  | input = event pointer = nullptr       | Exception is thrown as expected (validated by EXPECT_ANY_THROW)                   | Should Fail |
 */
TEST_F(em_ctrl_t_Test, handle_scan_channel_list_null_event_pointer)
{
    std::cout << "Entering handle_scan_channel_list_null_event_pointer test" << std::endl;
    EXPECT_ANY_THROW({
        ctrl.handle_scan_channel_list(nullptr);
    });
    std::cout << "Exiting handle_scan_channel_list_null_event_pointer test" << std::endl;
}
/**
 * @brief Validate that handle_set_policy throws an exception when provided with a null event pointer.
 *
 * This test verifies that the handle_set_policy API correctly handles erroneous input by throwing an exception when a null pointer is passed as its argument. This ensures that the system enforces valid policy event data and maintains robustness in error conditions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 026@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                              | Test Data                                     | Expected Result                                        | Notes        |
 * | :--------------: | -------------------------------------------------------- | --------------------------------------------- | -------------------------------------------------------| ------------ |
 * | 01               | Call ctrl.handle_set_policy with null event pointer      | input1 = event pointer = nullptr, output = exception thrown | API call throws an exception as validated by EXPECT_ANY_THROW | Should Fail  |
 */
TEST_F(em_ctrl_t_Test, handle_set_policy_null_event_pointer)
{
    std::cout << "Entering handle_set_policy_null_event_pointer test" << std::endl;
    EXPECT_ANY_THROW({
        ctrl.handle_set_policy(nullptr);
    });
    std::cout << "Exiting handle_set_policy_null_event_pointer test" << std::endl;
}
/**
 * @brief Test handle_reset function with a null event pointer.
 *
 * Verify that calling handle_reset with a null pointer correctly throws an exception, ensuring proper error handling in the API.
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
 * | Variation / Step | Description                                                      | Test Data                               | Expected Result                                           | Notes      |
 * | :--------------: | ---------------------------------------------------------------- | --------------------------------------- | --------------------------------------------------------- | ---------- |
 * | 01               | Invoke ctrl.handle_reset with nullptr to validate exception throw  | input: event pointer = nullptr          | API throws an exception and EXPECT_ANY_THROW assertion passes | Should Pass |
 */
TEST_F(em_ctrl_t_Test, handle_reset_null_event_pointer)
{
    std::cout << "Entering handle_reset_null_event_pointer test" << std::endl;
    EXPECT_ANY_THROW({
        ctrl.handle_reset(nullptr);
    });
    std::cout << "Exiting handle_reset_null_event_pointer test" << std::endl;
}
/**
 * @brief Test the handle_get_dev_test API with a null event pointer to ensure that it throws an exception.
 *
 * This test invokes the handle_get_dev_test API of the em_ctrl_t object with a null event pointer, which is expected to trigger an exception.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 028@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                          | Test Data                       | Expected Result                                       | Notes       |
 * | :--------------: | -------------------------------------------------------------------- | ------------------------------- | ----------------------------------------------------- | ----------- |
 * | 01               | Invoke handle_get_dev_test with a null event pointer and validate exception is thrown | input: event pointer = nullptr  | API is expected to throw an exception as asserted by EXPECT_ANY_THROW | Should Pass |
 */
TEST_F(em_ctrl_t_Test, handle_get_dev_test_null_event_pointer)
{
    std::cout << "Entering handle_get_dev_test_null_event_pointer test" << std::endl;
    EXPECT_ANY_THROW({
        ctrl.handle_get_dev_test(nullptr);
    });
    std::cout << "Exiting handle_get_dev_test_null_event_pointer test" << std::endl;
}
/**
 * @brief Validate that handle_set_dev_test correctly throws an exception on receiving a null event pointer.
 *
 * This test verifies that the ctrl.handle_set_dev_test API handles an invalid null event pointer by throwing an exception, ensuring robustness in the error handling mechanism of the API.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 029@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                    | Test Data                    | Expected Result                   | Notes       |
 * | :--------------: | ---------------------------------------------------------------| ---------------------------- | --------------------------------- | ----------- |
 * | 01               | Invoke ctrl.handle_set_dev_test with a null event pointer.       | event pointer = nullptr      | API should throw an exception.    | Should Fail |
 */
TEST_F(em_ctrl_t_Test, handle_set_dev_test_null_event_pointer)
{
    std::cout << "Entering handle_set_dev_test_null_event_pointer test" << std::endl;
    EXPECT_ANY_THROW({
        ctrl.handle_set_dev_test(nullptr);
    });
    std::cout << "Exiting handle_set_dev_test_null_event_pointer test" << std::endl;
}
/**
 * @brief Verify that handle_get_dm_data properly handles a null event pointer.
 *
 * This test case checks that passing a null pointer to the handle_get_dm_data method results in an exception being thrown.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 030@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                              | Test Data                                   | Expected Result                                      | Notes       |
 * | :--------------: | -------------------------------------------------------- | ------------------------------------------- | ---------------------------------------------------- | ----------- |
 * | 01               | Call handle_get_dm_data with a null pointer              | input: event pointer = nullptr              | API throws an exception as detected by EXPECT_ANY_THROW | Should Fail |
 */
TEST_F(em_ctrl_t_Test, handle_get_dm_data_null_event_pointer)
{
    std::cout << "Entering handle_get_dm_data_null_event_pointer test" << std::endl;
    EXPECT_ANY_THROW({
        ctrl.handle_get_dm_data(nullptr);
    });
    std::cout << "Exiting handle_get_dm_data_null_event_pointer test" << std::endl;
}
/**
 * @brief Validates data model commit handling for a valid data model
 *
 * This test verifies that the commit event for a valid data model is correctly handled without throwing exceptions.
 * The test first establishes an interface with its MAC address, then creates a data model associated with the interface.
 * It then constructs a commit event with matching MAC address and network ID and calls the commit handler to ensure no exceptions occur.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 031@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                               | Test Data                                                              | Expected Result                                                              | Notes          |
 * | :----:          |---------------------------------------------------------------------------|------------------------------------------------------------------------|------------------------------------------------------------------------------|----------------|
 * | 01              | Set up interface with name and MAC address                                | input: name = "eth0", mac = 0x01,0x02,0x03,0x04,0x05,0x01              | Interface is correctly initialized                                           | Should be successful |
 * | 02              | Create a data model for the interface with a given network name and profile | input: network name = "Network1", interface pointer, profile = em_profile_type_1 | Data model pointer is not null                                               | Should Pass    |
 * | 03              | Prepare commit event with matching MAC and network ID                     | input: evt.type = em_bus_event_type_dm_commit, commit.mac = 0x01,0x02,0x03,0x04,0x05,0x01, commit.net_id = "Network1" | Commit event is properly initialized                                         | Should Pass    |
 * | 04              | Invoke the commit handler with the prepared event                         | input: function call ctrl.handle_dm_commit(&evt)                       | The method does not throw any exception; EXPECT_NO_THROW is satisfied         | Should Pass    |
 */
TEST_F(em_ctrl_t_Test, handle_dm_commit_valid_dm) {
    std::cout << "Entering handle_dm_commit_valid_dm test" << std::endl;
    em_interface_t intf;
    unsigned char mac[6] = {0x01,0x02,0x03,0x04,0x05,0x01};
    setup_interface(intf, "eth0", mac);
    dm_easy_mesh_t* dm = ctrl.create_data_model("Network1", &intf, em_profile_type_1);
    ASSERT_NE(dm, nullptr);
    em_bus_event_t evt = {};
    evt.type = em_bus_event_type_dm_commit;
    memcpy(evt.u.commit.mac, mac, sizeof(mac));
    strncpy(evt.u.commit.net_id, "Network1", sizeof(evt.u.commit.net_id));
    EXPECT_NO_THROW(ctrl.handle_dm_commit(&evt));
    std::cout << "Exiting handle_dm_commit_valid_dm test" << std::endl;
}
/**
 * @brief Verify that the handle_dm_commit API correctly handles a DM commit for a non-existent network.
 *
 * This test verifies that calling ctrl.handle_dm_commit with an event containing a non-existent network name does not throw any exceptions.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Print start log and initialize event structure with DM commit type, non-existent network name, and MAC address. | evt.type = em_bus_event_type_dm_commit, evt.u.commit.mac = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}, evt.u.commit.net_id = "NonExistentNetwork" | Event structure is initialized with the correct parameters. | Should be successful |
 * | 02 | Invoke ctrl.handle_dm_commit with the prepared event and assert that no exception is thrown. | Input: &evt | API call completes without throwing an exception. | Should Pass |
 * | 03 | Print exit log to conclude the test execution. | - | Log statement executed successfully. | Should be successful |
 */
TEST_F(em_ctrl_t_Test, handle_dm_commit_nonexistent_dm) {
    std::cout << "Entering handle_dm_commit_nonexistent_dm test" << std::endl;
    em_bus_event_t evt = {};
    evt.type = em_bus_event_type_dm_commit;
    unsigned char mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    memcpy(evt.u.commit.mac, mac, sizeof(mac));
    strncpy(evt.u.commit.net_id, "NonExistentNetwork", sizeof(evt.u.commit.net_id));
    EXPECT_NO_THROW(ctrl.handle_dm_commit(&evt));
    std::cout << "Exiting handle_dm_commit_nonexistent_dm test" << std::endl;
}
/**
 * @brief Verify that handle_dm_commit correctly processes commit events for multiple data models.
 *
 * This test verifies that when two different data models are created and associated with unique interfaces,
 * commit events for each data model are processed without any exceptions. It ensures that both data models are
 * correctly set up and that their respective commit events are handled as expected.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup first interface and create first data model for "Network1". | input: intf1.name = "eth0", intf1.mac = {0x01,0x02,0x03,0x04,0x05,0x01}; API: create_data_model("Network1", intf1, em_profile_type_1) | Return value (dm1) is not nullptr | Should Pass |
 * | 02 | Setup second interface and create second data model for "Network2". | input: intf2.name = "eth1", intf2.mac = {0x06,0x07,0x08,0x09,0x0A,0x02}; API: create_data_model("Network2", intf2, em_profile_type_2) | Return value (dm2) is not nullptr | Should Pass |
 * | 03 | Process commit event for first data model "Network1". | input: evt1.type = em_bus_event_type_dm_commit, evt1.u.commit.mac = {0x01,0x02,0x03,0x04,0x05,0x01}, evt1.u.commit.net_id = "Network1" | No exception thrown; commit is successfully handled | Should Pass |
 * | 04 | Process commit event for second data model "Network2". | input: evt2.type = em_bus_event_type_dm_commit, evt2.u.commit.mac = {0x06,0x07,0x08,0x09,0x0A,0x02}, evt2.u.commit.net_id = "Network2" | No exception thrown; commit is successfully handled | Should Pass |
 */
TEST_F(em_ctrl_t_Test, handle_dm_commit_multiple_dms) {
    std::cout << "Entering handle_dm_commit_multiple_dms test" << std::endl;
    em_interface_t intf1;
    unsigned char mac1[6] = {0x01,0x02,0x03,0x04,0x05,0x01};
    setup_interface(intf1, "eth0", mac1);
    dm_easy_mesh_t* dm1 = ctrl.create_data_model("Network1", &intf1, em_profile_type_1);
    ASSERT_NE(dm1, nullptr);
    em_interface_t intf2;
    unsigned char mac2[6] = {0x06,0x07,0x08,0x09,0x0A,0x02};
    setup_interface(intf2, "eth1", mac2);
    dm_easy_mesh_t* dm2 = ctrl.create_data_model("Network2", &intf2, em_profile_type_2);
    ASSERT_NE(dm2, nullptr);
    em_bus_event_t evt1 = {};
    evt1.type = em_bus_event_type_dm_commit;
    memcpy(evt1.u.commit.mac, mac1, sizeof(mac1));
    strncpy(evt1.u.commit.net_id, "Network1", sizeof(evt1.u.commit.net_id));
    EXPECT_NO_THROW(ctrl.handle_dm_commit(&evt1));
    em_bus_event_t evt2 = {};
    evt2.type = em_bus_event_type_dm_commit;
    memcpy(evt2.u.commit.mac, mac2, sizeof(mac2));
    strncpy(evt2.u.commit.net_id, "Network2", sizeof(evt2.u.commit.net_id));
    EXPECT_NO_THROW(ctrl.handle_dm_commit(&evt2));
    std::cout << "Exiting handle_dm_commit_multiple_dms test" << std::endl;
}
/**
 * @brief Verify that handle_m2_tx properly handles a null event pointer.
 *
 * This test ensures that when a null event pointer is passed to the API handle_m2_tx, the function correctly throws an exception to safeguard against null dereferencing. This behavior is crucial to maintain application stability.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 034@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                   | Test Data                             | Expected Result                                               | Notes      |
 * | :--------------: | ------------------------------------------------------------- | ------------------------------------- | ------------------------------------------------------------- | ---------- |
 * | 01               | Invoke handle_m2_tx with a null event pointer and expect an exception | input = event pointer: nullptr        | Exception is thrown as asserted by EXPECT_ANY_THROW            | Should Pass |
 */
TEST_F(em_ctrl_t_Test, handle_m2_tx_null_event_pointer)
{
    std::cout << "Entering handle_m2_tx_null_event_pointer test" << std::endl;
    EXPECT_ANY_THROW({
        ctrl.handle_m2_tx(nullptr);
    });
    std::cout << "Exiting handle_m2_tx_null_event_pointer test" << std::endl;
}
/**
 * @brief Validate that handle_config_renew() throws an exception when invoked with a nullptr event pointer
 *
 * This test verifies that the handle_config_renew() method correctly handles an invalid input by throwing an exception when a nullptr is passed as the event pointer. This behavior is required to ensure that the API robustly handles null inputs.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 035@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                     | Test Data                                | Expected Result                                                  | Notes       |
 * | :--------------: | ---------------------------------------------------------------- | ---------------------------------------- | ---------------------------------------------------------------- | ----------- |
 * | 01               | Invoke ctrl.handle_config_renew with a null event pointer         | event pointer = nullptr                   | API should throw an exception; EXPECT_ANY_THROW assertion passes   | Should Pass |
 */
TEST_F(em_ctrl_t_Test, handle_config_renew_null_event_pointer)
{
    std::cout << "Entering handle_config_renew_null_event_pointer test" << std::endl;
    EXPECT_ANY_THROW({
        ctrl.handle_config_renew(nullptr);
    });
    std::cout << "Exiting handle_config_renew_null_event_pointer test" << std::endl;
}
/**
 * @brief Validates that ctrl.handle_sta_assoc_event throws an exception when a null pointer is passed.
 *
 * This test verifies that the handle_sta_assoc_event API correctly identifies a null event pointer input and responds by throwing an exception. This behavior helps ensure robust error handling and prevents null pointer dereferences.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 036
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                  | Test Data                                | Expected Result                                                  | Notes       |
 * | :--------------: | ------------------------------------------------------------ | ---------------------------------------- | ---------------------------------------------------------------- | ----------- |
 * | 01               | Call handle_sta_assoc_event with a null pointer as input.    | input = nullptr, output = exception thrown | Exception is thrown and caught by EXPECT_ANY_THROW macro.         | Should Pass |
 */
TEST_F(em_ctrl_t_Test, handle_sta_assoc_event_null_event_pointer)
{
    std::cout << "Entering handle_sta_assoc_event_null_event_pointer test" << std::endl;
    EXPECT_ANY_THROW({
        ctrl.handle_sta_assoc_event(nullptr);
    });
    std::cout << "Exiting handle_sta_assoc_event_null_event_pointer test" << std::endl;
}
/**
 * @brief Verify that handle_mld_reconfig gracefully handles null event pointer input by throwing an exception
 *
 * This test invokes handle_mld_reconfig with a nullptr to ensure that the method throws an exception as expected. 
 * It verifies that the API properly handles erroneous null pointers thereby maintaining robustness.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 037@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                          | Test Data                          | Expected Result                               | Notes      |
 * | :--------------: | ---------------------------------------------------- | ---------------------------------- | --------------------------------------------- | ---------- |
 * | 01               | Invoke handle_mld_reconfig with nullptr input        | input: event pointer = nullptr     | API should throw an exception and be caught   | Should Pass|
 */
TEST_F(em_ctrl_t_Test, handle_mld_reconfig_null_event_pointer)
{
    std::cout << "Entering handle_mld_reconfig_null_event_pointer test" << std::endl;
    EXPECT_ANY_THROW({
        ctrl.handle_mld_reconfig(nullptr);
    });
    std::cout << "Exiting handle_mld_reconfig_null_event_pointer test" << std::endl;
}
/**
 * @brief Test for handling null event pointer in handle_bsta_cap_req
 *
 * This test validates that the function handle_bsta_cap_req correctly throws an exception when provided with a null event pointer. The test ensures that the API handles improper input (i.e., a null pointer) by throwing an exception, thereby maintaining robust error handling.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 038@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                | Test Data                                            | Expected Result                                                       | Notes        |
 * | :--------------: | -------------------------------------------------------------------------- | ---------------------------------------------------- | --------------------------------------------------------------------- | ------------ |
 * | 01               | Invoke handle_bsta_cap_req with a null event pointer                         | event pointer = nullptr                              | API throws an exception as verified using EXPECT_ANY_THROW              | Should Pass  |
 */
TEST_F(em_ctrl_t_Test, handle_bsta_cap_req_null_event_pointer)
{
    std::cout << "Entering handle_bsta_cap_req_null_event_pointer test" << std::endl;
    EXPECT_ANY_THROW({
        ctrl.handle_bsta_cap_req(nullptr);
    });
    std::cout << "Exiting handle_bsta_cap_req_null_event_pointer test" << std::endl;
}
/**
 * @brief Test to validate the default initialization of the network topology.
 *
 * This test verifies that the network topology initialization function correctly creates a data model with a valid interface configuration and that no exceptions are thrown during the initialization process. The test sets up a network interface using a given MAC address and interface name, creates a data model via the API, and then initializes the network topology.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 039@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                              | Test Data                                                                                                                      | Expected Result                                            | Notes           |
 * | :--------------: | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------- | --------------- |
 * | 01               | Set up network interface with name "eth0" and MAC address 01,02,03,04,05,01              | input: name = "eth0", mac = 0x01,0x02,0x03,0x04,0x05,0x01                                                                     | Interface structure is correctly populated               | Should be successful |
 * | 02               | Invoke create_data_model API to create a data model for the network topology               | input: network_name = "Network1", interface = intf, profile_type = em_profile_type_1                                             | Returns a non-null data model pointer                      | Should Pass     |
 * | 03               | Set the m_colocated flag in the created data model to true                               | input: dm->m_colocated = true                                                                                                  | The data model property is updated correctly               | Should be successful |
 * | 04               | Invoke init_network_topology API to initialize the network topology                        | No additional input parameters; utilizes the previously created data model                                                     | No exceptions thrown during initialization                 | Should Pass     |
 * | 05               | Log the exit from the test case                                                          | N/A                                                                                                                            | Exit log is printed successfully                           | Should be successful |
 */
TEST_F(em_ctrl_t_Test, init_network_topology_default)
{
    std::cout << "Entering init_network_topology_default test" << std::endl;
    em_interface_t intf;
    unsigned char mac[6] = {0x01,0x02,0x03,0x04,0x05,0x01};
    setup_interface(intf, "eth0", mac);
    dm_easy_mesh_t* dm = ctrl.create_data_model("Network1", &intf, em_profile_type_1);
    dm->m_colocated = true;
    ASSERT_NE(dm, nullptr);
    EXPECT_NO_THROW(ctrl.init_network_topology());
    std::cout << "Exiting init_network_topology_default test" << std::endl;
}
/**
 * @brief Ensure that update_network_topology works correctly for a colocated network topology scenario
 *
 * This test verifies that the update_network_topology API functions correctly when the data model is configured with m_colocated set to true.
 * It sets up the network interface, creates a data model with the "Network1" identifier and a specific profile type, initializes the network topology, and checks that the update operation does not trigger any exceptions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 040@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                 | Test Data                                                                                              | Expected Result                                        | Notes            |
 * | :--------------: | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ | ------------------------------------------------------ | ---------------- |
 * | 01               | Call setup_interface to configure the interface "eth0" with given MAC      | name = "eth0", mac = 0x11,0x22,0x33,0x44,0x55,0x01                                                     | Interface configured successfully                      | Should be successful |
 * | 02               | Create data model using create_data_model with network name "Network1", interface, and profile type, then set m_colocated to true  | network_name = "Network1", intf pointer, profile_type = em_profile_type_1, m_colocated = true            | Data model instance created with m_colocated attribute set  | Should Pass      |
 * | 03               | Initialize network topology by calling init_network_topology               | No explicit input parameters                                                                           | Network topology is initialized                        | Should be successful |
 * | 04               | Check network topology initialization using is_network_topology_initialized  | Invocation of is_network_topology_initialized()                                                        | Returns true (assertion passes)                        | Should Pass      |
 * | 05               | Update network topology by calling update_network_topology and ensure no exceptions are thrown  | Invocation of update_network_topology()                                                                  | No exception thrown (update successful)                | Should Pass      |
 */
TEST_F(em_ctrl_t_Test, update_network_topology_colocated)
{
    std::cout << "Entering update_network_topology_colocated test" << std::endl;
    em_interface_t intf;
    unsigned char mac[6] = {0x11,0x22,0x33,0x44,0x55,0x01};
    setup_interface(intf, "eth0", mac);
    dm_easy_mesh_t* dm = ctrl.create_data_model("Network1", &intf, em_profile_type_1);
    dm->m_colocated = true;
    ctrl.init_network_topology();
    EXPECT_TRUE(ctrl.is_network_topology_initialized());
    EXPECT_NO_THROW({
        ctrl.update_network_topology();
    });
    std::cout << "Exiting update_network_topology_colocated test" << std::endl;
}
/**
 * @brief Test to update network topology in a non-colocated scenario
 *
 * This test verifies that the network topology is correctly updated when one data model is marked as colocated and the other as non-colocated. It ensures that the network topology initialization and update operations execute properly without throwing exceptions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 041@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Configure interface intf1 using setup_interface for "eth0" with MAC {0x11,0x22,0x33,0x44,0x55,0x01} and create data model "Network1" with profile em_profile_type_1. Set m_colocated = true. | intf1: name="eth0", mac="0x11,0x22,0x33,0x44,0x55,0x01", data_model="Network1", profile=em_profile_type_1 | dm1 is not nullptr | Should Pass |
 * | 02 | Configure interface intf2 using setup_interface for "eth1" with MAC {0x11,0x22,0x33,0x44,0x55,0x02} and create data model "Network2" with profile em_profile_type_1. Set m_colocated = false. | intf2: name="eth1", mac="0x11,0x22,0x33,0x44,0x55,0x02", data_model="Network2", profile=em_profile_type_1 | dm2 is not nullptr | Should Pass |
 * | 03 | Initialize the network topology by calling init_network_topology, then verify via is_network_topology_initialized. | No input arguments | is_network_topology_initialized() returns true | Should Pass |
 * | 04 | Update the network topology by calling update_network_topology and ensure no exception is thrown. | No input arguments | update_network_topology executes without throwing exceptions | Should Pass |
 */
TEST_F(em_ctrl_t_Test, update_network_topology_non_colocated)
{
    std::cout << "Entering update_network_topology_non_colocated test" << std::endl;
    em_interface_t intf1;
    unsigned char mac1[6] = {0x11,0x22,0x33,0x44,0x55,0x01};
    setup_interface(intf1, "eth0", mac1);
    dm_easy_mesh_t* dm1 = ctrl.create_data_model("Network1", &intf1, em_profile_type_1);
    dm1->m_colocated = true;
    ASSERT_NE(dm1, nullptr);
    em_interface_t intf2;
    unsigned char mac2[6] = {0x11,0x22,0x33,0x44,0x55,0x02};
    setup_interface(intf2, "eth1", mac2);
    dm_easy_mesh_t* dm2 = ctrl.create_data_model("Network2", &intf2, em_profile_type_1);
    dm2->m_colocated = false;
    ASSERT_NE(dm2, nullptr);
    ctrl.init_network_topology();
    EXPECT_TRUE(ctrl.is_network_topology_initialized());
    EXPECT_NO_THROW({
        ctrl.update_network_topology();
    });
    std::cout << "Exiting update_network_topology_non_colocated test" << std::endl;
}
/**
 * @brief Validate retrieval of the first data model instance after creation
 *
 * This test verifies that after creating a data model using ctrl.create_data_model with a valid network identifier, interface details, and profile, the first data model returned by ctrl.get_first_dm is correctly populated. It checks that the network ID, profile, and MAC address in the retrieved data model match the expected values.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 042@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                                                          | Test Data                                                                                                                       | Expected Result                                                                                      | Notes         |
 * | :--------------: | ------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- | ------------- |
 * | 01               | Initialize test parameters and set interface using setup_interface                                                                   | net_id = TestNetwork, interface name = eth0, mac = 0x10,0x11,0x12,0x13,0x12,0x15                                                   | Interface structure is initialized correctly                                                        | Should be successful |
 * | 02               | Create a data model by invoking ctrl.create_data_model with valid net_id, interface, and profile                                       | input: net_id = TestNetwork, intf (from step 01), profile = em_profile_type_3                                                  | dm is not nullptr (data model creation successful)                                                  | Should Pass   |
 * | 03               | Retrieve the first data model instance using ctrl.get_first_dm                                                                       | No additional input besides the state set from step 02                                                                         | firstElement is not nullptr (data model retrieval successful)                                       | Should Pass   |
 * | 04               | Validate the returned data model by checking its network ID, profile, and MAC address against the expected values                      | firstElement->m_device.m_device_info.id.net_id = TestNetwork, profile = em_profile_type_3, MAC = 0x10,0x11,0x12,0x13,0x12,0x15          | Network ID, profile and MAC address match the expected values                                       | Should Pass   |
 */
TEST_F(em_ctrl_t_Test, get_first_dm_valid) {
    std::cout << "Entering get_first_dm_valid test" << std::endl;
    const char* net_id = "TestNetwork";
    em_interface_t intf;
    unsigned char mac[6] = {0x10,0x11,0x12,0x13,0x12,0x15};
    setup_interface(intf, "eth0", mac);
    dm_easy_mesh_t* dm = ctrl.create_data_model(net_id, &intf, em_profile_type_3);
    ASSERT_NE(dm, nullptr);
    dm_easy_mesh_t* firstElement = ctrl.get_first_dm();
    ASSERT_NE(firstElement, nullptr);
    EXPECT_STREQ(firstElement->m_device.m_device_info.id.net_id, net_id);
    EXPECT_EQ(firstElement->m_device.m_device_info.profile, em_profile_type_3);
    EXPECT_EQ(memcmp(firstElement->m_device.m_device_info.intf.mac, mac, 6), 0);
    std::cout << "Exiting get_first_dm_valid test" << std::endl;
}
/**
 * @brief Validate that get_first_dm returns a null pointer when no data mesh elements exist
 *
 * This test verifies that when no data mesh elements are available, invoking the get_first_dm API on the control object returns a nullptr. This ensures that the control correctly handles empty data mesh states.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 043
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- | -------------- | ----- |
 * | 01 | Invoke the get_first_dm API on the ctrl object | output: firstElement = undefined | The API returns a nullptr and the assertion EXPECT_EQ(firstElement, nullptr) passes | Should Pass |
 */
TEST_F(em_ctrl_t_Test, get_first_dm_null) {
    std::cout << "Entering get_first_dm_null test" << std::endl;
    dm_easy_mesh_t* firstElement = ctrl.get_first_dm();
    EXPECT_EQ(firstElement, nullptr);
    std::cout << "Exiting get_first_dm_null test" << std::endl;
}
/**
 * @brief Test get_next_dm API with nullptr input.
 *
 * This test verifies that invoking the get_next_dm API with a nullptr correctly returns a nullptr.
 * It ensures that the API gracefully handles invalid (nullptr) input without causing errors.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 044@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                    | Test Data                           | Expected Result                                                         | Notes       |
 * | :--------------: | ---------------------------------------------- | ----------------------------------- | ----------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke get_next_dm with a nullptr argument     | input = nullptr                     | Return value is nullptr; EXPECT_EQ(next, nullptr) passes                | Should Pass |
 */
TEST_F(em_ctrl_t_Test, get_next_dm_nullptr) {
    std::cout << "Entering get_next_dm_nullptr test" << std::endl;
    dm_easy_mesh_t* next = ctrl.get_next_dm(nullptr);
    EXPECT_EQ(next, nullptr);
    std::cout << "Exiting get_next_dm_nullptr test" << std::endl;
}
/**
 * @brief Validate get_next_dm API for a single-element data model
 *
 * This test verifies that the API get_next_dm returns nullptr when only a single data model is present.
 * The test initializes an interface using a known MAC address and creates a data model via create_data_model.
 * It then asserts the data model creation and confirms that no subsequent (next) data model exists.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 045@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                 | Test Data                                                                              | Expected Result                                   | Notes           |
 * | :--------------: | --------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- | ------------------------------------------------- | --------------- |
 * | 01               | Log the entry message to indicate the start of the test                     | None                                                                                   | "Entering get_next_dm_single_element test" printed | Should be successful |
 * | 02               | Set up the interface with name "eth0" and MAC {0x01,0x02,0x03,0x04,0x05,0x01} | input: name = "eth0", mac = 0x01,0x02,0x03,0x04,0x05,0x01                                | Interface structure is properly initialized       | Should be successful |
 * | 03               | Create a data model for "Network1" with the initialized interface and em_profile_type_1 | input: network name = "Network1", interface = {name="eth0", mac=0x01,0x02,0x03,0x04,0x05,0x01}, profile = em_profile_type_1 | dm is not nullptr                                  | Should Pass      |
 * | 04               | Invoke get_next_dm with the created data model to retrieve the next element | input: dm = pointer to data model created in step 03                                  | next is nullptr                                  | Should Pass      |
 * | 05               | Log the exit message to indicate the end of the test                          | None                                                                                   | "Exiting get_next_dm_single_element test" printed  | Should be successful |
 */
TEST_F(em_ctrl_t_Test, get_next_dm_single_element) {
    std::cout << "Entering get_next_dm_single_element test" << std::endl;
    em_interface_t intf;
    unsigned char mac[6] = {0x01,0x02,0x03,0x04,0x05,0x01};
    setup_interface(intf, "eth0", mac);
    dm_easy_mesh_t* dm = ctrl.create_data_model("Network1", &intf, em_profile_type_1);
    ASSERT_NE(dm, nullptr);
    dm_easy_mesh_t* next = ctrl.get_next_dm(dm);
    EXPECT_EQ(next, nullptr);
    std::cout << "Exiting get_next_dm_single_element test" << std::endl;
}
/**
 * @brief Verify the iteration over all data models returns the expected sequence and content.
 *
 * This test verifies that after creating three data models with distinct network IDs and associated interface details,
 * the API iterates over these models and returns each model with the correctly matching interface MAC and profile type.
 * It uses assertions to ensure each data model is created successfully, checks that the attributes match for each model,
 * and validates that the total number of models iterated equals the number created.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 046@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize three interfaces using setup_interface with distinct names and MAC addresses. | intf1: name = eth0, mac = 0x01,0x02,0x03,0x04,0x05,0x01; intf2: name = eth1, mac = 0x06,0x07,0x08,0x09,0x0A,0x02; intf3: name = eth2, mac = 0x0B,0x0C,0x0D,0x0E,0x0F,0x03 | Interfaces are configured correctly with proper names and MAC addresses | Should be successful |
 * | 02 | Create data models using the configured interfaces and assigned network IDs with specific profile types. | create_data_model("Network1", intf1, em_profile_type_1), create_data_model("Network2", intf2, em_profile_type_2), create_data_model("Network3", intf3, em_profile_type_3) | Data models (dm1, dm2, dm3) are created and pointers are returned not NULL | Should Pass |
 * | 03 | Validate that the created data models are not null using assertions. | ASSERT_NE(dm1, nullptr), ASSERT_NE(dm2, nullptr), ASSERT_NE(dm3, nullptr) | All data model pointers are non-null | Should Pass |
 * | 04 | Iteratively access each data model using get_first_dm and get_next_dm, and validate each model's data (network ID, MAC, profile). | For each DM: if net_id = "Network1" then compare MAC with 0x01,0x02,0x03,0x04,0x05,0x01 and profile = em_profile_type_1; similarly for "Network2" and "Network3" | Each DM's data matches the expected MAC address and profile type based on its network ID | Should Pass |
 * | 05 | Verify that the total count of iterated data models equals 3. | count variable expected to be 3 after iteration | The count equals 3 confirming all data models have been iterated | Should Pass |
 */
TEST_F(em_ctrl_t_Test, get_next_dm_iterate_all_dms) {
    std::cout << "Entering get_next_dm_iterate_all_dms test" << std::endl;
    em_interface_t intf1, intf2, intf3;
    unsigned char mac1[6] = {0x01,0x02,0x03,0x04,0x05,0x01};
    unsigned char mac2[6] = {0x06,0x07,0x08,0x09,0x0A,0x02};
    unsigned char mac3[6] = {0x0B,0x0C,0x0D,0x0E,0x0F,0x03};
    setup_interface(intf1, "eth0", mac1);
    setup_interface(intf2, "eth1", mac2);
    setup_interface(intf3, "eth2", mac3);
    dm_easy_mesh_t* dm1 = ctrl.create_data_model("Network1", &intf1, em_profile_type_1);
    dm_easy_mesh_t* dm2 = ctrl.create_data_model("Network2", &intf2, em_profile_type_2);
    dm_easy_mesh_t* dm3 = ctrl.create_data_model("Network3", &intf3, em_profile_type_3);
    ASSERT_NE(dm1, nullptr);
    ASSERT_NE(dm2, nullptr);
    ASSERT_NE(dm3, nullptr);
    dm_easy_mesh_t* current = ctrl.get_first_dm();
    int count = 0;
    while (current) {
        if (strcmp(current->m_device.m_device_info.id.net_id, "Network1") == 0) {
            EXPECT_EQ(memcmp(current->m_device.m_device_info.intf.mac, mac1, 6), 0);
            EXPECT_EQ(current->m_device.m_device_info.profile, em_profile_type_1);
        } else if (strcmp(current->m_device.m_device_info.id.net_id, "Network2") == 0) {
            EXPECT_EQ(memcmp(current->m_device.m_device_info.intf.mac, mac2, 6), 0);
            EXPECT_EQ(current->m_device.m_device_info.profile, em_profile_type_2);
        } else if (strcmp(current->m_device.m_device_info.id.net_id, "Network3") == 0) {
            EXPECT_EQ(memcmp(current->m_device.m_device_info.intf.mac, mac3, 6), 0);
            EXPECT_EQ(current->m_device.m_device_info.profile, em_profile_type_3);
        } else {
            FAIL() << "Unexpected net_id: " << current->m_device.m_device_info.id.net_id;
        }
        current = ctrl.get_next_dm(current);
        count++;
    }
    EXPECT_EQ(count, 3); // Ensure all 3 DMs were iterated
    std::cout << "Exiting get_next_dm_iterate_all_dms test" << std::endl;
}
/**
 * @brief Validate that a data model is properly created and fetched using a valid network ID and MAC address.
 *
 * This test ensures that when a valid network ID and MAC address are provided, the data model is created 
 * using ctrl.create_data_model, and subsequently, ctrl.get_data_model retrieves the correct model instance 
 * with matching network ID, profile type, and interface MAC address.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 047@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke ctrl.create_data_model with net_id = "TestNetwork", interface name "eth0", MAC = {0x01,0x02,0x03,0x04,0x05,0x01} and profile = em_profile_type_1. | net_id = "TestNetwork", intf.name = "eth0", intf.mac = "01,02,03,04,05,01", profile = em_profile_type_1 | Return pointer (dm) is not null. | Should Pass |
 * | 02 | Invoke ctrl.get_data_model with net_id = "TestNetwork" and MAC = {0x01,0x02,0x03,0x04,0x05,0x01} and validate that the retrieved model's net_id, profile and MAC match the expected values. | net_id = "TestNetwork", mac = "01,02,03,04,05,01" | Return pointer (fetched) is not null; fetched->m_device.m_device_info.id.net_id equals "TestNetwork", fetched->m_device.m_device_info.profile equals em_profile_type_1, and memcmp of MAC returns 0. | Should Pass |
 */
TEST_F(em_ctrl_t_Test, get_data_model_valid_al_mac) {
    std::cout << "Entering get_data_model_valid_al_mac test" << std::endl;
    const char* net_id = "TestNetwork";
    em_interface_t intf;
    unsigned char mac[6] = {0x01,0x02,0x03,0x04,0x05,0x01};
    setup_interface(intf, "eth0", mac);
    dm_easy_mesh_t* dm = ctrl.create_data_model(net_id, &intf, em_profile_type_1);
    ASSERT_NE(dm, nullptr);
    dm_easy_mesh_t* fetched = ctrl.get_data_model(net_id, mac);
    ASSERT_NE(fetched, nullptr);
    EXPECT_STREQ(fetched->m_device.m_device_info.id.net_id, net_id);
    EXPECT_EQ(fetched->m_device.m_device_info.profile, em_profile_type_1);
    EXPECT_EQ(memcmp(fetched->m_device.m_device_info.intf.mac, mac, 6), 0);
    std::cout << "Exiting get_data_model_valid_al_mac test" << std::endl;
}
/**
 * @brief Validate behavior of get_data_model when the interface mac pointer is NULL
 *
 * This test verifies that the get_data_model API returns a valid pointer when it is invoked with a valid network ID but a NULL interface pointer which is optional argument. The test first creates a data model using the create_data_model API and then calls get_data_model with a NULL interface mac pointer to ensure that the retrieval works as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 048@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                               | Test Data                                                                                         | Expected Result                                            | Notes        |
 * | :--------------: | ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- | ------------ |
 * | 01               | Invoke create_data_model API to create a new data model with valid inputs   | input: net_id = "TestNetwork", intf = {name = "eth0", mac = 0x01,0x02,0x03,0x04,0x05,0x01}, profile = em_profile_type_1, output: dm                | dm is not nullptr; Assertion check for non-null value      | Should Pass  |
 * | 02               | Invoke get_data_model API with a valid network ID and a NULL interface pointer | input: net_id = "TestNetwork", interface = nullptr, output: fetched                                 | fetched is not nullptr as al_mac is optional only;         | Should Pass  |
 */
TEST_F(em_ctrl_t_Test, get_data_model_null_al_mac) {
    std::cout << "Entering get_data_model_null_al_mac test" << std::endl;
    const char* net_id = "TestNetwork";
    em_interface_t intf;
    unsigned char mac[6] = {0x01,0x02,0x03,0x04,0x05,0x01};
    setup_interface(intf, "eth0", mac);
    dm_easy_mesh_t* dm = ctrl.create_data_model(net_id, &intf, em_profile_type_1);
    ASSERT_NE(dm, nullptr);
    dm_easy_mesh_t* fetched = ctrl.get_data_model(net_id, nullptr);
    ASSERT_NE(fetched, nullptr);
    std::cout << "Exiting get_data_model_null_al_mac test" << std::endl;
}
/**
 * @brief Verify that get_data_model returns nullptr for a non-existent network
 *
 * This test ensures that when get_data_model is invoked with a network ID 
 * that does not exist in the data model, the API correctly returns a nullptr. 
 * This is important to confirm that the system handles unknown network queries gracefully.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 049@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                               | Test Data                                                       | Expected Result                                            | Notes             |
 * | :--------------: | --------------------------------------------------------- | --------------------------------------------------------------- | ---------------------------------------------------------- | ----------------- |
 * | 01               | Print entering log message                                | N/A                                                             | "Entering get_data_model_nonexistent test" is printed      | Should be successful |
 * | 02               | Call get_data_model with non-existent network ID and MAC  | input: net_id = NonExistentNetwork, mac = 0x01,0x02,0x03,0x04,0x05,0x01; output: fetched pointer expected | fetched pointer is nullptr and assertion passes            | Should Fail       |
 * | 03               | Print exiting log message                                 | N/A                                                             | "Exiting get_data_model_nonexistent test" is printed       | Should be successful |
 */
TEST_F(em_ctrl_t_Test, get_data_model_nonexistent) {
    std::cout << "Entering get_data_model_nonexistent test" << std::endl;
    const char* net_id = "NonExistentNetwork";
    unsigned char mac[6] = {0x01,0x02,0x03,0x04,0x05,0x01};
    dm_easy_mesh_t* fetched = ctrl.get_data_model(net_id, mac);
    ASSERT_EQ(fetched, nullptr);
    std::cout << "Exiting get_data_model_nonexistent test" << std::endl;
}
/**
 * @brief Test get_data_model handling when net_id is null.
 *
 * This test verifies that when a null net_id is provided to the ctrl.get_data_model API along with a valid mac address, the API correctly returns a nullptr. This ensures that the function handles invalid net_id inputs as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 050@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke get_data_model API with net_id as nullptr and a valid MAC address | net_id = nullptr, mac = 0x01,0x02,0x03,0x04,0x05,0x01 | API returns nullptr and ASSERT_EQ verifies fetched equals nullptr | Should Fail |
 */
TEST_F(em_ctrl_t_Test, get_data_model_null_net_id) {
    std::cout << "Entering get_data_model_null_net_id test" << std::endl;
    const char* net_id = nullptr;
    unsigned char mac[6] = {0x01,0x02,0x03,0x04,0x05,0x01};
    dm_easy_mesh_t* fetched = ctrl.get_data_model(net_id, mac);
    ASSERT_EQ(fetched, nullptr);
    std::cout << "Exiting get_data_model_null_net_id test" << std::endl;
}
/**
 * @brief Validate creation of a data model for a single profile
 *
 * This test examines the functionality of the create_data_model API by creating a data model using a valid network ID, interface parameters (name "eth0" and MAC address {0x01,0x02,0x03,0x04,0x05,0x01}), and profile type em_profile_type_1. It validates that the returned data model is non-null and that its device information correctly reflects the provided network ID and profile type.
 *
 * **Test Group ID:** Basic: 01 / Module (L2): 02 / Stress (L2): 03
 * **Test Case ID:** 051
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call create_data_model with valid network ID, interface configuration, and profile type | net_id = "TestNetwork1", intf.name = "eth0", intf.mac = {0x01,0x02,0x03,0x04,0x05,0x01}, profile = em_profile_type_1 | Data model pointer is not null; device info net_id equals "TestNetwork1"; device profile equals em_profile_type_1 | Should Pass |
 */
TEST_F(em_ctrl_t_Test, create_data_model_single_profile) {
    std::cout << "Entering create_data_model_single_profile test" << std::endl;
    const char* net_id = "TestNetwork1";
    em_interface_t intf;
    unsigned char mac[6] = {0x01,0x02,0x03,0x04,0x05,0x01};
    setup_interface(intf, "eth0", mac);
    dm_easy_mesh_t* dm = ctrl.create_data_model(net_id, &intf, em_profile_type_1);
    ASSERT_NE(dm, nullptr);
    EXPECT_STREQ(dm->m_device.m_device_info.id.net_id, net_id);
    EXPECT_EQ(dm->m_device.m_device_info.profile, em_profile_type_1);
    std::cout << "Entering create_data_model_single_profile test" << std::endl;
}
/**
 * @brief Validate creation of data models for multiple profiles.
 *
 * This test verifies that the API correctly creates data models for a range of profiles. It loops through the profile types (from reserved up to type 3), invokes the create_data_model API, and checks that:
 * - The returned pointer is not null.
 * - The network ID of the created data model matches the input "TestNetwork2".
 * - The profile value of the created data model matches the expected profile type during each iteration.
 * 
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 052@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize test parameters and interface using setup_interface helper function. | net_id = "TestNetwork2", interface name = "eth1", mac = 0x02,0x02,0x03,0x04,0x05,0x02 | Interface structure populated correctly and ready for use. | Should be successful |
 * | 02 | Invoke ctrl.create_data_model for profiles from em_profile_type_reserved to em_profile_type_3 and validate the output data model. | For each iteration: input: net_id = "TestNetwork2", interface pointer, profile = em_profile_type_reserved, em_profile_type_1, em_profile_type_2, em_profile_type_3; output: pointer to dm_easy_mesh_t. | Returned pointer is non-null; dm->m_device.m_device_info.id.net_id equals "TestNetwork2"; dm->m_device.m_device_info.profile equals the current profile value. | Should Pass |
 */
TEST_F(em_ctrl_t_Test, create_data_model_multiple_profiles) {
    std::cout << "Entering create_data_model_multiple_profiles test" << std::endl;
    const char* net_id = "TestNetwork2";
    em_interface_t intf;
    unsigned char mac[6] = {0x02,0x02,0x03,0x04,0x05,0x02};
    setup_interface(intf, "eth1", mac);
    std::vector<dm_easy_mesh_t*> dms;
    for (int i = em_profile_type_reserved; i <= em_profile_type_3; ++i) {
        dm_easy_mesh_t* dm = ctrl.create_data_model(net_id, &intf, static_cast<em_profile_type_t>(i));
        ASSERT_NE(dm, nullptr);
        EXPECT_STREQ(dm->m_device.m_device_info.id.net_id, net_id);
        EXPECT_EQ(dm->m_device.m_device_info.profile, i);
        dms.push_back(dm);
    }
    std::cout << "Exiting create_data_model_multiple_profiles test" << std::endl;
}
/**
 * @brief Verify that create_data_model returns nullptr when invoked with a null network identifier.
 *
 * This test validates that when a null network identifier is passed to the create_data_model API, the service
 * responds correctly by returning a nullptr. It ensures that the API properly handles edge cases with invalid input.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 053@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                        | Test Data                                                                                     | Expected Result                                          | Notes         |
 * | :--------------: | ---------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | -------------------------------------------------------- | ------------- |
 * | 01               | Setup the interface using helper function with valid MAC address and name.         | name = "eth2", mac = 0x03,0x02,0x03,0x04,0x05,0x03                                             | Interface structure should be correctly configured.    | Should be successful |
 * | 02               | Invoke create_data_model API with a null network ID and the prepared interface.      | network_id = nullptr, intf pointer, profile type = em_profile_type_1                           | API returns nullptr indicating proper error handling.  | Should Fail   |
 * | 03               | Assert that the returned data model pointer is nullptr, confirming the API behavior. | output dm pointer = value returned by create_data_model (expected: nullptr)                     | ASSERT_EQ verifies that dm is exactly nullptr.           | Should be successful |
 */
TEST_F(em_ctrl_t_Test, create_data_model_null_net_id) {
    std::cout << "Entering create_data_model_null_net_id test" << std::endl;
    em_interface_t intf;
    unsigned char mac[6] = {0x03,0x02,0x03,0x04,0x05,0x03};
    setup_interface(intf, "eth2", mac);
    dm_easy_mesh_t* dm = ctrl.create_data_model(nullptr, &intf, em_profile_type_1);
    ASSERT_EQ(dm, nullptr);
    std::cout << "Exiting  create_data_model_null_net_id test" << std::endl;
}
/**
 * @brief Validate that create_data_model returns nullptr when a null interface pointer is provided.
 *
 * This test verifies that creating a data model using a valid network identifier but a null interface pointer
 * correctly fails by returning a nullptr. It ensures that the API properly handles cases where an invalid
 * (null) interface is supplied, preventing potential misbehavior.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 054@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke create_data_model with net_id 'TestNetwork4', a null interface, and profile type em_profile_type_1 | net_id = TestNetwork4, interface = nullptr, profile = em_profile_type_1 | dm_easy_mesh_t pointer returned is nullptr; ASSERT_EQ check passes | Should Pass |
 */
TEST_F(em_ctrl_t_Test, create_data_model_null_interface) {
    std::cout << "Entering create_data_model_null_interface test" << std::endl;
    const char* net_id = "TestNetwork4";
    dm_easy_mesh_t* dm = ctrl.create_data_model(net_id, nullptr, em_profile_type_1);
    ASSERT_EQ(dm, nullptr);
    std::cout << "Exiting create_data_model_null_interface test" << std::endl;
}
/**
 * @brief Verify that the create_data_model API accepts a network identifier at its maximum allowed length.
 *
 * This test verifies that when a network identifier of maximum length is provided, along with a valid network interface
 * configuration and an appropriate profile, the create_data_model API returns a non-null pointer. It ensures the function
 * can handle boundary conditions for input string length.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 055@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                       | Test Data                                                                                           | Expected Result                                                         | Notes        |
 * | :--------------: | ----------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- | ------------ |
 * | 01               | Initialize a maximum-length network ID, set up a valid interface, and invoke the create_data_model API | netid = A repeated 127 times (127 'A's), interface name = eth1, MAC = 0x22,0x33,0x44,0x55,0x66,0x22, profile = em_profile_type_3  | Return value (dm) is not nullptr; Assert check passes                   | Should Pass  |
 */
TEST_F(em_ctrl_t_Test, create_data_model_max_length_netid) {
    std::cout << "Entering create_data_model_max_length_netid test" << std::endl;
    char maxNetID[128];
    memset(maxNetID, 'A', 127);
    maxNetID[127] = '\0';
    em_interface_t intf;
    unsigned char mac[6] = {0x22, 0x33, 0x44, 0x55, 0x66, 0x22};
    setup_interface(intf, "eth1", mac);
    dm_easy_mesh_t* dm = ctrl.create_data_model(maxNetID, &intf, em_profile_type_3);
    ASSERT_NE(dm, nullptr);
    std::cout << "Exiting create_data_model_max_length_netid test" << std::endl;
}
/**
 * @brief Verify delete_data_model function deletes the data model when invoked with valid parameters.
 *
 * This test verifies that the delete_data_model API correctly deletes an existing data model associated with a given network ID and MAC address. It first creates a data model using valid parameters and then deletes it, ensuring no exceptions are thrown.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 056
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * |01| Set up the interface and create a valid data model using the helper function, then verify the data model pointer is non-null. | input: net_id = "Net1", mac = {0x00,0x1A,0x2B,0x3C,0x4D,0x5E}, interface name = "eth0", profile type = em_profile_type_1; output: dm pointer initially null | Data model is successfully created and dm is not nullptr (ASSERT_NE(dm, nullptr) passes) | Should be successful |
 * |02| Invoke the delete_data_model API with valid parameters and confirm that it completes without throwing exceptions. | input: net_id = "Net1", mac = {0x00,0x1A,0x2B,0x3C,0x4D,0x5E} | delete_data_model executes without exceptions (EXPECT_NO_THROW passes) | Should Pass |
 */
TEST_F(em_ctrl_t_Test, delete_data_model_valid_params)
{
    std::cout << "Entering delete_data_model_valid_params test" << std::endl;
    const char* net_id = "Net1";
    unsigned char mac[6] = {0x00,0x1A,0x2B,0x3C,0x4D,0x5E};
    em_interface_t intf;
    setup_interface(intf, "eth0", mac);
    dm_easy_mesh_t* dm = ctrl.create_data_model(net_id, &intf, em_profile_type_1);
    ASSERT_NE(dm, nullptr);
    EXPECT_NO_THROW(ctrl.delete_data_model(net_id, mac));
    std::cout << "Exiting delete_data_model_valid_params test" << std::endl;
}
/**
 * @brief Verify that delete_data_model throws an exception when provided a null network ID.
 *
 * This test verifies that the delete_data_model API properly handles an erroneous input scenario,
 * where the network identifier is passed as nullptr. The test ensures that the API enforces a valid
 * network ID by throwing an exception when a null value is provided, thereby preventing undefined behavior.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 057@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                            | Test Data                                                                                               | Expected Result                                     | Notes         |
 * | :--------------: | ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | --------------------------------------------------- | ------------- |
 * | 01               | Setup interface configuration for the test by initializing interface.  | name = eth1, mac = 0x10,0x11,0x12,0x13,0x14,0x15                                                      | Interface is properly configured.                 | Should be successful |
 * | 02               | Create a valid data model using a proper network id and the configured interface. | net_id = Net2, interface pointer = intf, profile type = em_profile_type_1                                 | Returns a non-null data model pointer (dm != nullptr). | Should Pass   |
 * | 03               | Invoke delete_data_model with a null network id to validate error handling. | net_id = nullptr, mac = 0x10,0x11,0x12,0x13,0x14,0x15                                                  | Throws an exception.                                | Should Fail   |
 */
TEST_F(em_ctrl_t_Test, delete_data_model_null_net_id)
{
    std::cout << "Entering delete_data_model_null_net_id test" << std::endl;
    unsigned char mac[6] = {0x10,0x11,0x12,0x13,0x14,0x15};
    em_interface_t intf;
    setup_interface(intf, "eth1", mac);
    dm_easy_mesh_t* dm = ctrl.create_data_model("Net2", &intf, em_profile_type_1);
    ASSERT_NE(dm, nullptr);
    EXPECT_ANY_THROW(ctrl.delete_data_model(nullptr, mac));
    std::cout << "Exiting delete_data_model_null_net_id test" << std::endl;
}
/**
 * @brief Validate deletion of data model using a null AL MAC pointer
 *
 * This test verifies that attempting to delete a data model with a valid network ID but a null AL MAC pointer throws an exception. The test first creates a data model using a valid em_interface_t setup and then confirms that deletion with an invalid pointer fails as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 058@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                       | Test Data                                                                                                                   | Expected Result                                                                 | Notes        |
 * | :--------------: | ------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- | ------------ |
 * | 01               | Invoke create_data_model API with valid net_id, interface, and profile                            | net_id = Net3, intf = {name = "eth2", mac = [0x20,0x21,0x22,0x23,0x24,0x25]}, profile = em_profile_type_2                     | Returns a non-null pointer; ASSERT_NE(dm, nullptr) passes                         | Should Pass  |
 * | 02               | Invoke delete_data_model API with valid net_id but null AL MAC pointer to validate exception throwing | net_id = Net3, al_mac = nullptr                                                                                             | Throws an exception; EXPECT_ANY_THROW(ctrl.delete_data_model(net_id, nullptr))    | Should Fail  |
 */
TEST_F(em_ctrl_t_Test, delete_data_model_null_al_mac)
{
    std::cout << "Entering delete_data_model_null_al_mac test" << std::endl;
    const char* net_id = "Net3";
    unsigned char mac[6] = {0x20,0x21,0x22,0x23,0x24,0x25};
    em_interface_t intf;
    setup_interface(intf, "eth2", mac);
    dm_easy_mesh_t* dm = ctrl.create_data_model(net_id, &intf, em_profile_type_2);
    ASSERT_NE(dm, nullptr);
    EXPECT_ANY_THROW(ctrl.delete_data_model(net_id, nullptr));
    std::cout << "Exiting delete_data_model_null_al_mac test" << std::endl;
}
/**
 * @brief Verify delete_data_model throws exception when provided with an empty network id
 *
 * This test validates that when an empty string is provided as the network id while attempting to delete a data model,
 * the API correctly throws an exception to indicate invalid input. It first creates a data model with valid parameters,
 * ensuring that the model is set up properly, before invoking the deletion with an empty network id to verify error handling.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 059@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                | Test Data                                                                                                                        | Expected Result                                                       | Notes          |
 * | :--------------: | ------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | -------------- |
 * | 01               | Create a data model with valid network id "Net4" and interface "eth3" using specified MAC      | input: network id = Net4, interface name = eth3, mac = 0x30,0x31,0x32,0x33,0x34,0x35, profile = em_profile_type_3; output: dm != nullptr | Data model is created successfully and is not null                     | Should be successful |
 * | 02               | Call delete_data_model with an empty network id and verify that it throws an exception         | input: network id = "", mac = 0x30,0x31,0x32,0x33,0x34,0x35                                                                          | Exception is thrown                                                   | Should Fail    |
 */
TEST_F(em_ctrl_t_Test, delete_data_model_empty_net_id)
{
    std::cout << "Entering delete_data_model_empty_net_id test" << std::endl;
    unsigned char mac[6] = {0x30,0x31,0x32,0x33,0x34,0x35};
    em_interface_t intf;
    setup_interface(intf, "eth3", mac);
    dm_easy_mesh_t* dm = ctrl.create_data_model("Net4", &intf, em_profile_type_3);
    ASSERT_NE(dm, nullptr);
    EXPECT_ANY_THROW(ctrl.delete_data_model("", mac));
    std::cout << "Exiting delete_data_model_empty_net_id test" << std::endl;
}
/**
 * @brief Validate that attempting to delete a data model entry with a non-existing MAC address throws an exception.
 *
 * This test first initializes an interface "eth4" with an existing MAC address and creates a data model using 
 * the provided configuration. It then attempts to delete the data model entry by specifying a MAC address that does not exist,
 * verifying that the API throws an exception as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 060@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize interface "eth4" with mac [0x40,0x41,0x42,0x43,0x44,0x45] and invoke create_data_model with data model name "Net5" and profile em_profile_type_1 | name = "eth4", mac = 0x40,0x41,0x42,0x43,0x44,0x45, data_model_name = "Net5", profile = em_profile_type_1 | Returns non-null data model pointer | Should Pass |
 * | 02 | Invoke delete_data_model with data model name "Net5" and non-existent mac [0x50,0x51,0x52,0x53,0x54,0x55] | data_model_name = "Net5", mac = 0x50,0x51,0x52,0x53,0x54,0x55 | Throws exception | Should Fail |
 */
TEST_F(em_ctrl_t_Test, delete_data_model_non_existing_entry)
{
    std::cout << "Entering delete_data_model_non_existing_entry test" << std::endl;
    unsigned char mac_existing[6] = {0x40,0x41,0x42,0x43,0x44,0x45};
    unsigned char mac_nonexist[6] = {0x50,0x51,0x52,0x53,0x54,0x55};
    em_interface_t intf;
    setup_interface(intf, "eth4", mac_existing);
    dm_easy_mesh_t* dm = ctrl.create_data_model("Net5", &intf, em_profile_type_1);
    ASSERT_NE(dm, nullptr);
    EXPECT_ANY_THROW(ctrl.delete_data_model("Net5", mac_nonexist));
    std::cout << "Exiting delete_data_model_non_existing_entry test" << std::endl;
}
/**
 * @brief Test deletion of a single data model using delete_all_data_models API
 *
 * This test validates that after a single data model is created using create_data_model,
 * invoking delete_all_data_models successfully deletes the model without throwing any exceptions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 061@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Set up network interface using setup_interface function. | input: name = eth0, mac = 01,02,03,04,05,01 | Interface is correctly initialized with the given name and MAC address. | Should be successful |
 * | 02 | Create a single data model using ctrl.create_data_model. | input: data_model_name = Network1, interface pointer = &intf, profile = em_profile_type_1; output: dm pointer | Returns a non-null pointer indicating successful creation of the data model; Assertion dm != nullptr. | Should Pass |
 * | 03 | Invoke ctrl.delete_all_data_models to delete the created data model. | No input; calling ctrl.delete_all_data_models() | Method executes without throwing an exception. | Should Pass |
 */
TEST_F(em_ctrl_t_Test, delete_all_data_models_single_dm) {
    std::cout << "Entering delete_all_data_models_single_dm test" << std::endl;
    em_interface_t intf;
    unsigned char mac1[6] = {0x01,0x02,0x03,0x04,0x05,0x01};
    setup_interface(intf, "eth0", mac1);
    dm_easy_mesh_t* dm = ctrl.create_data_model("Network1", &intf, em_profile_type_1);
    ASSERT_NE(dm, nullptr);
    EXPECT_NO_THROW(ctrl.delete_all_data_models());
    std::cout << "Exiting delete_all_data_models_single_dm test" << std::endl;
}
/**
 * @brief Verify deletion of all data models when multiple data models exist
 *
 * This test creates two data models using different interfaces and profile types, verifies that the models are successfully created, and then calls the delete_all_data_models API to remove them. The test checks that the data models are not null upon creation and that the deletion operation does not throw any exceptions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 062@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                   | Test Data                                                                                                          | Expected Result                                              | Notes         |
 * | :--------------: | ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------ | ------------- |
 * | 01               | Create first data model with interface "eth0" and profile type 1| input: name = Network1, interface.name = eth0, interface.mac = {0x01,0x02,0x03,0x04,0x05,0x02}, profile = em_profile_type_1, output: dm1 pointer | dm1 is not nullptr                                          | Should Pass   |
 * | 02               | Create second data model with interface "eth1" and profile type 2 | input: name = Network2, interface.name = eth1, interface.mac = {0x01,0x02,0x03,0x04,0x05,0x03}, profile = em_profile_type_2, output: dm2 pointer | dm2 is not nullptr                                          | Should Pass   |
 * | 03               | Delete all data models and verify no exceptions are thrown      | input: function call = ctrl.delete_all_data_models()                                                               | Method completes without throwing any exception            | Should Pass   |
 */
TEST_F(em_ctrl_t_Test, delete_all_data_models_multiple_dms) {
    std::cout << "Entering delete_all_data_models_multiple_dms test" << std::endl;
    em_interface_t intf1, intf2;
    unsigned char mac1[6] = {0x01,0x02,0x03,0x04,0x05,0x02};
    unsigned char mac2[6] = {0x01,0x02,0x03,0x04,0x05,0x03};
    setup_interface(intf1, "eth0", mac1);
    setup_interface(intf2, "eth1", mac2);
    dm_easy_mesh_t* dm1 = ctrl.create_data_model("Network1", &intf1, em_profile_type_1);
    dm_easy_mesh_t* dm2 = ctrl.create_data_model("Network2", &intf2, em_profile_type_2);
    ASSERT_NE(dm1, nullptr);
    ASSERT_NE(dm2, nullptr);
    EXPECT_NO_THROW(ctrl.delete_all_data_models());
    std::cout << "Exiting delete_all_data_models_multiple_dms test" << std::endl;
}
/**
 * @brief Verify that delete_all_data_models() does not throw an exception when called on an empty list
 *
 * This test ensures that when there are no data models present, invoking ctrl.delete_all_data_models() completes without throwing any exceptions.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 063
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                              | Test Data                                             | Expected Result                                                             | Notes      |
 * | :--------------: | ------------------------------------------------------------------------ | ----------------------------------------------------- | --------------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke delete_all_data_models() on an empty list                         | ctrl.delete_all_data_models()                         | API completes without throwing exception; EXPECT_NO_THROW assertion passes  | Should Pass |
 */
TEST_F(em_ctrl_t_Test, delete_all_data_models_empty_list) {
    std::cout << "Entering delete_all_data_models_empty_list test" << std::endl;
    EXPECT_NO_THROW(ctrl.delete_all_data_models());
    std::cout << "Exiting delete_all_data_models_empty_list test" << std::endl;
}
/**
 * @brief Verify that debug_probe handles an empty probe list gracefully
 *
 * This test ensures that the ctrl.debug_probe() API does not throw any exceptions
 * when there are no probes in the list. This behavior is crucial for stability,
 * ensuring that the system remains robust even when no probes are available.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 064
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                         | Test Data                                 | Expected Result                                                    | Notes      |
 * | :----:           | :-------------------------------------------------- | :---------------------------------------- | :----------------------------------------------------------------- | :--------- |
 * | 01               | Invoke the debug_probe API on an empty probe list   | No input arguments; ctrl.debug_probe() invoked | API call should not throw any exception; EXPECT_NO_THROW check       | Should Pass |
 */
TEST_F(em_ctrl_t_Test, debug_probe_empty_list) {
    std::cout << "Entering debug_probe_empty_list test" << std::endl;
    EXPECT_NO_THROW({
        ctrl.debug_probe();
    });
    std::cout << "Exiting debug_probe_empty_list test" << std::endl;
}
/**
 * @brief Test to validate that debug_probe() executes correctly with a valid data model.
 *
 * This test verifies that after setting up a valid network interface and creating a data model using create_data_model(), 
 * the debug_probe() function operates without throwing exceptions. The objective is to ensure that the system's debugging operations 
 * on a valid data model are stable and do not result in runtime errors.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 065@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                       | Test Data                                                                                              | Expected Result                                                                               | Notes           |
 * | :--------------: | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------- | --------------- |
 * | 01               | Print the entering test message                                                                   | N/A                                                                                                    | Console outputs "Entering debug_probe_valid_dm test"                                          | Should be successful |
 * | 02               | Setup network interface configuration using setup_interface                                     | name = eth0, mac = 0x01,0x02,0x03,0x04,0x05,0x06                                                       | Interface (intf) is configured correctly                                                      | Should be successful |
 * | 03               | Create a data model by calling create_data_model with valid parameters                            | network_name = TestNetwork, interface = intf, profile_type = em_profile_type_1                           | Returns a non-null pointer (dm) validated by ASSERT_NE                                        | Should Pass     |
 * | 04               | Invoke debug_probe and verify that no exceptions are thrown                                      | N/A                                                                                                    | debug_probe() executes without throwing exceptions as verified by EXPECT_NO_THROW              | Should Pass     |
 * | 05               | Print the exiting test message                                                                    | N/A                                                                                                    | Console outputs "Exiting debug_probe_valid_dm test"                                           | Should be successful |
 */
TEST_F(em_ctrl_t_Test, debug_probe_valid_dm) {
    std::cout << "Entering debug_probe_valid_dm test" << std::endl;
    em_interface_t intf;
    unsigned char mac[6] = {0x01,0x02,0x03,0x04,0x05,0x06};
    setup_interface(intf, "eth0", mac);
    dm_easy_mesh_t* dm = ctrl.create_data_model("TestNetwork", &intf, em_profile_type_1);
    ASSERT_NE(dm, nullptr);
    EXPECT_NO_THROW({
        ctrl.debug_probe();
    });
    std::cout << "Exiting debug_probe_valid_dm test" << std::endl;
}
/**
 * @brief Verify that the controller returns the default service type
 *
 * This test verifies that calling the get_service_type API on the controller returns the default 
 * service type value. It checks whether the returned value equals em_service_type_ctrl.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 066
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                             | Test Data                                                   | Expected Result                                                                       | Notes      |
 * | :--------------: | ----------------------------------------------------------------------- | ----------------------------------------------------------- | ------------------------------------------------------------------------------------- | ---------- |
 * | 01               | Call ctrl.get_service_type() and check its return against em_service_type_ctrl | output1 = serviceType (expected value: em_service_type_ctrl)   | The API should return em_service_type_ctrl and the EXPECT_EQ assertion should pass        | Should Pass |
 */
TEST_F(em_ctrl_t_Test, get_service_type_default) {
    std::cout << "Entering get_service_type_default test" << std::endl;
    em_service_type_t serviceType = ctrl.get_service_type();
    EXPECT_EQ(serviceType, em_service_type_ctrl);
    std::cout << "Exiting get_service_type_default test" << std::endl;
}
/**
 * @brief Verify that the controller command retrieval function returns a valid non-null pointer.
 *
 * This test case verifies that the get_ctrl_cmd() API of the control module returns a non-null pointer,
 * ensuring that the internal control command structure is correctly initialized for further operations.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 067
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                         | Test Data                                                        | Expected Result                                                        | Notes       |
 * | :--------------: | ------------------------------------------------------------------- | ---------------------------------------------------------------- | ---------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke ctrl.get_ctrl_cmd() and verify the returned pointer is valid   | ctrl.get_ctrl_cmd() invoked, no input parameters, output: cmd_ctrl pointer | Returned pointer should not be nullptr (EXPECT_NE(cmd_ctrl, nullptr))    | Should Pass |
 */
TEST_F(em_ctrl_t_Test, get_ctrl_cmd_default)
{
    std::cout << "Entering get_ctrl_cmd_default test" << std::endl;
    em_cmd_ctrl_t* cmd_ctrl = ctrl.get_ctrl_cmd();
    EXPECT_NE(cmd_ctrl, nullptr);
    std::cout << "Exiting get_ctrl_cmd_default test" << std::endl;
}
/**
 * @brief Validate default constructor creation for em_ctrl_t object does not throw exceptions.
 *
 * This test ensures that the default constructor of em_ctrl_t functions correctly by creating an object and verifying that no exceptions are thrown. This confirms that the underlying resources and initializations are correctly handled within the default constructor.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 068
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                      | Test Data                           | Expected Result                                                   | Notes       |
 * | :--------------: | -------------------------------------------------------------------------------- | ----------------------------------- | ----------------------------------------------------------------- | ----------- |
 * | 01               | Invoke the default constructor for em_ctrl_t and verify no exceptions are thrown. | Constructor call with no input data | Object is created successfully with no exceptions thrown; Assertion: no throw | Should Pass |
 */
TEST_F(em_ctrl_t_Test, em_ctrl_t_default_constructor)
{
    std::cout << "Entering em_ctrl_t_default_constructor test" << std::endl;
    std::cout << "Invoking em_ctrl_t() constructor" << std::endl;
    EXPECT_NO_THROW({
        em_ctrl_t instance;
        std::cout << "em_ctrl_t object created using default constructor" << std::endl;
    });
    std::cout << "Exiting em_ctrl_t_default_constructor test" << std::endl;
}
/**
 * @brief Verify that em_ctrl_t is destructed without throwing exceptions.
 *
 * This test verifies that an instance of em_ctrl_t created using the default constructor
 * is properly destructed when it goes out of scope, ensuring that no exceptions are thrown
 * during destruction. This test ensures that both the constructor and destructor behave as expected.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 069
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                              | Test Data                                              | Expected Result                                                                              | Notes       |
 * | :--------------: | ---------------------------------------------------------------------------------------- | ------------------------------------------------------ | -------------------------------------------------------------------------------------------- | ----------- |
 * |       01         | Invoke the default constructor of em_ctrl_t to create an instance within a local scope.    | No input parameters; object creation invoked           | Instance is created successfully without any exceptions during construction.               | Should Pass |
 * |       02         | Exit the scope to trigger the automatic invocation of the destructor ~em_ctrl_t().         | No input parameters; implicit destructor invocation    | Destructor is invoked when the object goes out of scope and completes execution without errors. | Should Pass |
 */
TEST_F(em_ctrl_t_Test, em_ctrl_t_valid_destruction)
{
    std::cout << "Entering em_ctrl_t_valid_destruction test" << std::endl;
    std::cout << "Invoking constructor of em_ctrl_t" << std::endl;
    EXPECT_NO_THROW({
        em_ctrl_t instance;
        std::cout << "em_ctrl_t object created using default constructor" << std::endl;
	std::cout << "Leaving inner scope. Destructor ~em_ctrl_t() will be automatically invoked." << std::endl;
    });
    std::cout << "Exited inner scope; em_ctrl_t destructor should have been invoked without exception." << std::endl;
    std::cout << "Exiting em_ctrl_t_valid_destruction test" << std::endl;
}
/**
 * @brief Validate basic initialization of the control object using a valid test configuration file.
 *
 * This test verifies that the em_ctrl_t object initializes successfully when provided with a valid test configuration 
 * database file path. It ensures that the init function returns the expected value, confirming that the initialization 
 * process works correctly.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 070@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                       | Test Data                               | Expected Result                                  | Notes      |
 * | :--------------: | ----------------------------------------------------------------- | --------------------------------------- | ------------------------------------------------ | ---------- |
 * | 01               | Invoke ctrl.init() with a valid test database path for initialization | test_db_path = /tmp/test_config.db      | Returns 0 and EXPECT_EQ assertion passes         | Should Pass|
 */
TEST_F(em_ctrl_t_Test, basic_initialization) {
    std::cout << "Entering basic_initialization test" << std::endl;
    const char *test_db_path = "/tmp/test_config.db";
    int ret = ctrl.init(test_db_path);
    EXPECT_EQ(ret, 0);
    std::cout << "Exiting basic_initialization test" << std::endl;
}
/**
 * @brief Validate behavior of ctrl.init when provided with a null data_model_path.
 *
 * This test verifies that the ctrl.init API correctly handles a null data_model_path by returning a non-zero error code, ensuring that the function properly detects invalid input.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 071
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                          | Test Data                                                        | Expected Result                                                               | Notes       |
 * | :--------------: | ---------------------------------------------------- | ---------------------------------------------------------------- | ----------------------------------------------------------------------------- | ----------- |
 * | 01               | Call ctrl.init with a null data_model_path pointer   | data_model_path = nullptr, output: ret from ctrl.init            | Return value should not be 0, EXPECT_NE assertion succeeds                     | Should Fail |
 */
TEST_F(em_ctrl_t_Test, init_null_data_model_path) {
    std::cout << "Entering init_null_data_model_path test" << std::endl;
    const char* data_model_path = nullptr;
    int ret = ctrl.init(data_model_path);
    EXPECT_NE(0, ret);
    std::cout << "Exiting init_null_data_model_path test" << std::endl;
}
/**
 * @brief Test to verify that initializing with an empty data model path fails.
 *
 * This test confirms that when an empty string is provided as the data model path to the ctrl.init() API, 
 * the API returns a non-zero value indicating a failure in initialization.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 072
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                      | Test Data                   | Expected Result                                 | Notes       |
 * | :--------------: | ------------------------------------------------ | --------------------------- | ----------------------------------------------- | ----------- |
 * | 01               | Call ctrl.init() with an empty data model path.  | data_model_path = ""        | API returns a non-zero error code indicating failure. | Should Fail |
 */
TEST_F(em_ctrl_t_Test, init_empty_data_model_path) {
    std::cout << "Entering init_empty_data_model_path test" << std::endl;
    const char* data_model_path = "";
    int ret = ctrl.init(data_model_path);
    EXPECT_NE(0, ret);
    std::cout << "Exiting init_empty_data_model_path test" << std::endl;
}
/**
 * @brief Validate initialization with a non-existent file path returns an error code
 *
 * This test verifies that the ctrl.init method handles an erroneous input correctly by returning a non-zero error code when provided with a file path that does not exist. Ensuring that the API fails as expected under invalid conditions is critical for robust error handling.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 073@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                | Test Data                                                               | Expected Result                                           | Notes      |
 * | :----:           | ---------------------------------------------------------- | ----------------------------------------------------------------------- | --------------------------------------------------------- | ---------- |
 * | 01               | Invoke ctrl.init with a non-existent file path             | data_model_path = /non/existent/path/data_model.file, ret = return value from ctrl.init | API returns non-zero error code validating failure exit   | Should Fail |
 */
TEST_F(em_ctrl_t_Test, init_non_existent_file_path) {
    std::cout << "Entering init_non_existent_file_path test" << std::endl;
    const char* data_model_path = "/non/existent/path/data_model.file";
    int ret = ctrl.init(data_model_path);
    EXPECT_NE(0, ret);
    std::cout << "Exiting init_non_existent_file_path test" << std::endl;
}
/**
 * @brief Validates that push_to_queue accepts valid event types without throwing exceptions.
 *
 * This test verifies that for each valid event type (frame, device, node, and bus), an event is properly allocated, initialized, and pushed to the queue without raising any exceptions. The test ensures that the system can handle different valid event types correctly.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 074@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Allocate and initialize event with type em_event_type_frame and push to queue | evt->type = em_event_type_frame, allocation = malloc(sizeof(em_event_t)+EM_MAX_EVENT_DATA_LEN) | Allocation returns non-null pointer and push_to_queue does not throw an exception | Should Pass |
 * | 02 | Allocate and initialize event with type em_event_type_device and push to queue | evt->type = em_event_type_device, allocation = malloc(sizeof(em_event_t)+EM_MAX_EVENT_DATA_LEN) | Allocation returns non-null pointer and push_to_queue does not throw an exception | Should Pass |
 * | 03 | Allocate and initialize event with type em_event_type_node and push to queue | evt->type = em_event_type_node, allocation = malloc(sizeof(em_event_t)+EM_MAX_EVENT_DATA_LEN) | Allocation returns non-null pointer and push_to_queue does not throw an exception | Should Pass |
 * | 04 | Allocate and initialize event with type em_event_type_bus and push to queue | evt->type = em_event_type_bus, allocation = malloc(sizeof(em_event_t)+EM_MAX_EVENT_DATA_LEN) | Allocation returns non-null pointer and push_to_queue does not throw an exception | Should Pass |
 */
TEST_F(em_ctrl_t_Test, push_to_queue_valid_event_types)
{
    std::cout << "Entering push_to_queue_valid_event_types test" << std::endl;
    em_event_type_t validTypes[] = {
        em_event_type_frame,
        em_event_type_device,
        em_event_type_node,
        em_event_type_bus
    };
    const int numTypes = sizeof(validTypes) / sizeof(validTypes[0]);
    for (int i = 0; i < numTypes; ++i)
    {
        auto *evt = static_cast<em_event_t *>(malloc(sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN));
        ASSERT_NE(evt, nullptr);
        memset(evt, 0, sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN);
        evt->type = validTypes[i];
        EXPECT_NO_THROW({
            ctrl.push_to_queue(evt);
        });
    }
    std::cout << "Exiting push_to_queue_valid_event_types test" << std::endl;
}
/**
 * @brief Verifies that passing an event with an invalid event type to push_to_queue results in an exception.
 *
 * This test checks that the push_to_queue API correctly handles an event whose type exceeds the valid range
 * by triggering an exception. It ensures that the event type validation within the API prevents invalid events
 * from being processed.
 *
 * **Test Group ID:** Basic: 01  
 * **Test Case ID:** 075  
 * **Priority:** High  
 *
 * **Pre-Conditions:** None  
 * **Dependencies:** None  
 * **User Interaction:** None  
 *
 * **Test Procedure:**  
 * | Variation / Step | Description | Test Data | Expected Result | Notes |  
 * | :--------------: | ----------- | --------- | ------------- | ----- |  
 * | 01 | Create and initialize an event structure with invalid event type | evt allocated with malloc(sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN), memset with zeros, evt->type = (em_event_type_max + 1) | Event structure is created with an invalid type | Should be successful |  
 * | 02 | Invoke push_to_queue API with the invalid event | ctrl.push_to_queue(evt) with evt->type set to invalid value | API throws an exception as captured by EXPECT_ANY_THROW | Should Pass |  
 */
TEST_F(em_ctrl_t_Test, push_to_queue_invalid_event_type)
{
    std::cout << "Entering push_to_queue_invalid_event_type test" << std::endl;
    auto *evt = static_cast<em_event_t *>(malloc(sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN));
    memset(evt, 0, sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN);
    evt->type = static_cast<em_event_type_t>(em_event_type_max + 1);
    EXPECT_ANY_THROW({
        ctrl.push_to_queue(evt);
    });
    std::cout << "Exiting push_to_queue_invalid_event_type test" << std::endl;
}
/**
 * @brief Verify that push_to_queue properly handles a null event pointer.
 *
 * This test case verifies that calling the push_to_queue method with a null pointer correctly triggers an exception. 
 * The test ensures that the API performs input validation and throws an exception as expected when provided with a null event.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 076@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:** 
 * | Variation / Step | Description                                                            | Test Data                                   | Expected Result                                                     | Notes           |
 * | :--------------: | ---------------------------------------------------------------------- | ------------------------------------------- | ------------------------------------------------------------------- | --------------- |
 * | 01               | Log the entry message for initiating the push_to_queue_null_event test   | No input arguments                          | Entry message "Entering push_to_queue_null_event test" is printed     | Should be successful |
 * | 02               | Invoke push_to_queue with a null pointer to test exception handling      | input: event = nullptr                        | Exception is thrown and caught by EXPECT_ANY_THROW macro             | Should Pass     |
 * | 03               | Log the exit message indicating the completion of the test               | No input arguments                          | Exit message "Exiting push_to_queue_null_event test" is printed       | Should be successful |
 */
TEST_F(em_ctrl_t_Test, push_to_queue_null_event)
{
    std::cout << "Entering push_to_queue_null_event test" << std::endl;
    EXPECT_ANY_THROW({
        ctrl.push_to_queue(nullptr);
    });
    std::cout << "Exiting push_to_queue_null_event test" << std::endl;
}
/**
 * @brief Test to verify that a single event is successfully pushed into and popped out from the event queue.
 *
 * This test allocates memory for an event, initializes it, pushes the event into the queue via the push_to_queue API,
 * and then retrieves it using the pop_from_queue API. The test verifies that the pushed event is correctly returned
 * and that the queue is empty after the event is popped. This ensures the correct functionality of the event queue handling.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 077
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                            | Test Data                                                                                   | Expected Result                                                                                       | Notes       |
 * | :--------------: | ------------------------------------------------------ | ------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Allocate and initialize the event structure.         | evt = malloc(sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN), memory set to zero                  | Memory is allocated successfully; evt is non-null.                                                  | Should Pass |
 * | 02               | Set the event type and push the event into the queue.  | evt->type = em_event_type_bus                                                               | Event is successfully pushed to the queue.                                                         | Should Pass |
 * | 03               | Pop the event from the queue and verify the outcome.   | popped_evt = ctrl.pop_from_queue; subsequent pop returns nullptr                             | The popped event equals the pushed event and the queue is empty afterwards.                          | Should Pass |
 */
TEST_F(em_ctrl_t_Test, push_and_pop_single_event) {
    std::cout << "Entering push_and_pop_single_event test" << std::endl;
    auto *evt = static_cast<em_event_t *>(malloc(sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN));
    ASSERT_NE(evt, nullptr);
    memset(evt, 0, sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN);
    evt->type = em_event_type_bus;
    ctrl.push_to_queue(evt);
    em_event_t *popped_evt = ctrl.pop_from_queue();
    ASSERT_NE(popped_evt, nullptr);
    EXPECT_EQ(popped_evt, evt);
    EXPECT_EQ(ctrl.pop_from_queue(), nullptr);
    free(popped_evt);
    std::cout << "Exiting push_and_pop_single_event test" << std::endl;
}
/**
 * @brief Verify that multiple events can be pushed to the queue and popped in order
 *
 * This test verifies that when multiple events are pushed into the controller's queue, they are stored 
 * and retrieved in the same order. First, it allocates and initializes two event objects, pushes them into 
 * the processing queue, and then pops them to check if the order is maintained and the queue behaves as 
 * expected. This ensures that the internal queue mechanism functions correctly for multiple events.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 078@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Allocate memory, initialize first event, set event type, and push it to the queue using ctrl.push_to_queue() | events[0] = malloc(sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN), type = em_event_type_bus | events[0] pointer is not null and pushed successfully | Should Pass |
 * | 02 | Allocate memory, initialize second event, set event type, and push it to the queue using ctrl.push_to_queue() | events[1] = malloc(sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN), type = em_event_type_bus | events[1] pointer is not null and pushed successfully | Should Pass |
 * | 03 | Pop the first event from the queue using ctrl.pop_from_queue() | No input arguments, expected output: first event pointer | Should return events[0] pointer | Should Pass |
 * | 04 | Pop the second event from the queue using ctrl.pop_from_queue() | No input arguments, expected output: second event pointer | Should return events[1] pointer | Should Pass |
 * | 05 | Attempt to pop an event from the queue when it is empty using ctrl.pop_from_queue() | No input arguments, expected output: nullptr | Should return nullptr indicating the queue is empty | Should Pass |
 * | 06 | Free the allocated memory for both events | Free memory for events[0] and events[1] | Memory resources correctly released | Should be successful |
 */
TEST_F(em_ctrl_t_Test, push_and_pop_multiple_events) {
    std::cout << "Entering push_and_pop_multiple_events test" << std::endl;
    em_event_t *events[2];
    for (int i = 0; i < 2; ++i) {
        events[i] = static_cast<em_event_t *>(malloc(sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN));
        ASSERT_NE(events[i], nullptr);
        memset(events[i], 0, sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN);
        events[i]->type = em_event_type_bus;
        ctrl.push_to_queue(events[i]);
    }
    em_event_t *first = ctrl.pop_from_queue();
    ASSERT_NE(first, nullptr);
    EXPECT_EQ(first, events[0]);
    em_event_t *second = ctrl.pop_from_queue();
    ASSERT_NE(second, nullptr);
    EXPECT_EQ(second, events[1]);
    EXPECT_EQ(ctrl.pop_from_queue(), nullptr);
    free(first);
    free(second);
    std::cout << "Exiting push_and_pop_multiple_events test" << std::endl;
}
/**
 * @brief Testing the behavior of pop_from_queue when the queue is empty.
 *
 * This test verifies that the pop_from_queue function returns a nullptr when the event queue is empty.
 *
 * **Test Group ID:** Basic: 01 / Module (L2): 02 / Stress (L2): 03
 * **Test Case ID:** 079
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                    | Test Data                                | Expected Result                                               | Notes       |
 * | :--------------: | --------------------------------------------------------------- | ---------------------------------------- | ------------------------------------------------------------- | ----------- |
 * | 01               | Invoke pop_from_queue on an empty queue                         | input: none, output: evt = nullptr       | Returns a nullptr and assertion EXPECT_EQ(evt, nullptr) passes  | Should Pass |
 */
TEST_F(em_ctrl_t_Test, pop_from_empty_queue) {
    std::cout << "Entering pop_from_empty_queue test" << std::endl;
    em_event_t *evt = ctrl.pop_from_queue();
    EXPECT_EQ(evt, nullptr);
    std::cout << "Exiting pop_from_empty_queue test" << std::endl;
}
/**
 * @brief Validate that nodes_listen returns a success value for a default control instance.
 *
 * This test case verifies the default functionality of the nodes_listen API by invoking it on a freshly instantiated control object.
 * It checks whether the API returns a success code (0) indicating that the node listener has been initialized correctly.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 080@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                             | Test Data                                                                  | Expected Result                               | Notes      |
 * | :--------------: | ----------------------------------------------------------------------- | -------------------------------------------------------------------------- | --------------------------------------------- | ---------- |
 * | 01               | Invoke nodes_listen on a default control instance                       | ctrl = instance (default state), no input parameters, output: ret_value      | ret_value equals 0 as verified by EXPECT_EQ    | Should Pass|
 */
TEST_F(em_ctrl_t_Test, nodes_listen_default)
{
    std::cout << "Entering nodes_listen_default test" << std::endl;
    em_ctrl_t ctrl;
    int ret_value = ctrl.nodes_listen();
    EXPECT_EQ(ret_value, 0);
    std::cout << "Exiting nodes_listen_default test" << std::endl;
}
/**
 * @brief Verify that the input_listen function returns a successful result.
 *
 * This test verifies that when the input_listen function is invoked on the controller object,
 * it returns the expected success value (0) and the API functions as intended.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 081
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                    | Test Data                         | Expected Result                                                       | Notes      |
 * | :--------------: | -------------------------------------------------------------- | --------------------------------- | --------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke ctrl.input_listen() and capture the return value into ret | input: None, output: ret = 0        | The function returns 0 and EXPECT_EQ(ret, 0) assertion passes           | Should Pass|
 */
TEST_F(em_ctrl_t_Test, input_listen_default)
{
    std::cout << "Entering input_listen_default test" << std::endl;
    int ret = ctrl.input_listen();
    EXPECT_EQ(ret, 0);
    std::cout << "Exiting input_listen_default test" << std::endl;
}
/**
 * @brief Validate that create_node returns a valid node pointer for valid input parameters.
 *
 * This test validates the create_node API by providing a set of valid input parameters, including a properly initialized interface structure with a valid MAC address, name, and media type. The test then checks that the API returns a non-null pointer, indicating successful node creation.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 082@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                      | Test Data                                                                                                                                                       | Expected Result                                                                  | Notes       |
 * | :--------------: | ---------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | ----------- |
 * | 01               | Call create_node API with a valid interface and parameters       | ruid.mac = {0x28, 0x11, 0x22, 0x33, 0x44, 0x55}, ruid.name = "eth0", ruid.media = em_media_type_ieee8023ab, freq_band = em_freq_band_5, dm = initialized, flag = false, profile = em_profile_type_3, service = em_service_type_agent | Function returns a non-null node pointer and the assertion passes                | Should Pass |
 */
TEST_F(em_ctrl_t_Test, create_node_valid)
{
    std::cout << "Entering create_node_valid test" << std::endl;
    em_interface_t ruid{};
    unsigned char mac[6] = {0x28, 0x11, 0x22, 0x33, 0x44, 0x55};
    memcpy(ruid.mac, mac, sizeof(mac));
    strncpy(ruid.name, "eth0", sizeof(ruid.name));
    ruid.media = em_media_type_ieee8023ab;
    dm_easy_mesh_t dm;
    em_t* node = ctrl.create_node(&ruid, em_freq_band_5, &dm, false, em_profile_type_3, em_service_type_agent);
    ASSERT_NE(node, nullptr);
    std::cout << "Exiting create_node_valid test" << std::endl;
}
/**
 * @brief Verify that create_node returns nullptr when provided with a null ruid.
 *
 * This test checks that calling the create_node API with a null ruid parameter correctly results in a nullptr,
 * ensuring that the API properly handles invalid node unique identifier inputs.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 083@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                       | Test Data                                                                                                      | Expected Result                                                             | Notes       |
 * | :--------------: | ----------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke create_node with a null ruid to verify proper error handling | ruid = nullptr, frequency band = em_freq_band_5, dm = &dm, flag = false, profile = em_profile_type_3, service = em_service_type_agent | API returns nullptr and assertion (EXPECT_EQ) confirms this outcome         | Should Fail |
 */
TEST_F(em_ctrl_t_Test, create_node_nullruid)
{
    std::cout << "Entering create_node_nullruid test" << std::endl;
    dm_easy_mesh_t dm;
    em_t* node = ctrl.create_node(nullptr, em_freq_band_5, &dm, false, em_profile_type_3, em_service_type_agent);
    EXPECT_EQ(node, nullptr);
    std::cout << "Exiting create_node_nullruid test" << std::endl;
}
/**
 * @brief Verify that creating nodes with different MAC addresses results in unique node instances.
 *
 * This test function verifies that when two nodes with distinct MAC addresses are created using the create_node API, the resulting nodes are non-null and uniquely identified. It tests the proper differentiation of nodes based on their hardware identifiers.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 084@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Set unique MAC addresses and names for two nodes | For node1: input: mac = 0x21,0x11,0x22,0x33,0x44,0x05, name = "eth1", media = em_media_type_ieee80211n_24; For node2: input: mac = 0x22,0x11,0x22,0x33,0x44,0x06, name = "eth2", media = em_media_type_ieee80211n_24 | Both nodes' setup should be successful | Should Pass |
 * | 02 | Create nodes using create_node API with provided data | Input: node1 using ruid1 and node2 using ruid2, frequency band = em_freq_band_24, dm, join flag = false, profile type = em_profile_type_1, service type = em_service_type_agent | API returns non-null pointers; node1 and node2 are distinct | Should Pass |
 */
TEST_F(em_ctrl_t_Test, create_node_different_mac)
{
    std::cout << "Entering create_node_different_mac test" << std::endl;
    em_interface_t ruid1{};
    em_interface_t ruid2{};
    unsigned char mac1[6] = {0x21,0x11,0x22,0x33,0x44,0x05};
    unsigned char mac2[6] = {0x22,0x11,0x22,0x33,0x44,0x06};
    memcpy(ruid1.mac, mac1, sizeof(mac1));
    memcpy(ruid2.mac, mac2, sizeof(mac2));
    strncpy(ruid1.name, "eth1", sizeof(ruid1.name));
    strncpy(ruid2.name, "eth2", sizeof(ruid2.name));
    ruid1.media = em_media_type_ieee80211n_24;
    ruid2.media = em_media_type_ieee80211n_24;
    dm_easy_mesh_t dm;
    em_t* node1 = ctrl.create_node(&ruid1,em_freq_band_24,&dm,false,em_profile_type_1,em_service_type_agent);
    em_t* node2 = ctrl.create_node(&ruid2,em_freq_band_24,&dm,false,em_profile_type_1,em_service_type_agent);
    ASSERT_NE(node1, nullptr);
    ASSERT_NE(node2, nullptr);
    EXPECT_NE(node1, node2);
    std::cout << "Exiting create_node_different_mac test" << std::endl;
}
/**
 * @brief Verify that an existing IEEE802.3ab node can be successfully deleted.
 *
 * This test creates a node with the IEEE8023ab interface, asserts that the node is created (i.e., not a null pointer), 
 * and then deletes the node without throwing any exceptions. This ensures that the delete_node API works as expected 
 * when provided with a valid node.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 085@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                           | Test Data                                                                                                                                                           | Expected Result                                         | Notes        |
 * | :--------------: | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- | ------------ |
 * | 01               | Invoke ctrl.create_node with a valid IEEE8023ab interface node creation call          | input: ruid.mac = 0x10,0x20,0x30,0x40,0x50,0x60; ruid.name = "Node_ieee8023ab"; ruid.media = em_media_type_ieee8023ab; freq_band = em_freq_band_5; dm = dm_easy_mesh_t object; flag = false; profile = em_profile_type_1; service = em_service_type_agent | Returned node pointer should not be nullptr              | Should Pass  |
 * | 02               | Invoke ctrl.delete_node with the previously created node and ensure no exception is thrown | input: ruid structure with previously set values                                                                                                                    | Function call completes without throwing an exception   | Should Pass  |
 */
TEST_F(em_ctrl_t_Test, delete_node_existing_ieee8023ab)
{
    std::cout << "Entering delete_node_existing_ieee8023ab test" << std::endl;
    em_interface_t ruid{};
    unsigned char mac[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
    memcpy(ruid.mac, mac, sizeof(mac));
    strncpy(ruid.name, "Node_ieee8023ab", sizeof(ruid.name));
    ruid.media = em_media_type_ieee8023ab;
    dm_easy_mesh_t dm;
    em_t* node = ctrl.create_node(&ruid, em_freq_band_5, &dm, false, em_profile_type_1, em_service_type_agent);
    ASSERT_NE(node, nullptr);
    EXPECT_NO_THROW({
        ctrl.delete_node(&ruid);
    });
    std::cout << "Exiting delete_node_existing_ieee8023ab test" << std::endl;
}
/**
 * @brief Test deletion of an existing node with IEEE 802.11b 24 configuration.
 *
 * This test verifies that a node configured with IEEE 802.11b 24 media type can be created and then deleted without throwing any exceptions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 086@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                 | Test Data                                                                                                                                                                            | Expected Result                                                           | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- | ----------- |
 * | 01               | Create a node using a configured em_interface_t with IEEE 802.11b 24 media type.            | input: ruid.name = "Node_ieee80211b_24", ruid.mac = {0x11,0x21,0x31,0x41,0x51,0x61}, ruid.media = em_media_type_ieee80211b_24, freq_band = em_freq_band_5, profile = em_profile_type_1, service = em_service_type_agent | Node pointer is not null indicating successful creation.                | Should Pass |
 * | 02               | Delete the created node using ctrl.delete_node and verify no exceptions occur.               | input: ruid as defined above                                                                                                                     | Node deletion is successful with no exceptions thrown.                  | Should Pass |
 */
TEST_F(em_ctrl_t_Test, delete_node_existing_ieee80211b_24)
{
    std::cout << "Entering delete_node_existing_ieee80211b_24 test" << std::endl;
    em_interface_t ruid{};
    unsigned char mac[6] = {0x11,0x21,0x31,0x41,0x51,0x61};
    memcpy(ruid.mac, mac, sizeof(mac));
    strncpy(ruid.name, "Node_ieee80211b_24", sizeof(ruid.name));
    ruid.media = em_media_type_ieee80211b_24;
    dm_easy_mesh_t dm;
    em_t* node = ctrl.create_node(&ruid, em_freq_band_5, &dm, false, em_profile_type_1, em_service_type_agent);
    ASSERT_NE(node, nullptr);
    EXPECT_NO_THROW({
        ctrl.delete_node(&ruid);
    });
    std::cout << "Exiting delete_node_existing_ieee80211b_24 test" << std::endl;
}
/**
 * @brief Test delete_node function for an existing ieee80211g 2.4 node.
 *
 * This test verifies that deleting an existing node with ieee80211g 2.4 configuration works correctly by first creating a node using ctrl.create_node and then deleting it using ctrl.delete_node without throwing any exceptions.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 087
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a node with ieee80211g 2.4 parameters using ctrl.create_node | input: ruid.mac = {0x12,0x22,0x32,0x42,0x52,0x62}, ruid.name = "Node_ieee80211g_24", ruid.media = em_media_type_ieee80211g_24; additional inputs: em_freq_band_5, dm_easy_mesh_t instance, flag = false, em_profile_type_1, em_service_type_agent; output: node pointer != nullptr | Node is successfully created and node pointer is not null | Should Pass |
 * | 02 | Delete the created node using ctrl.delete_node | input: ruid with same configuration as created earlier; no explicit output parameter | Deletion function executes without throwing any exception | Should Pass |
 */
TEST_F(em_ctrl_t_Test, delete_node_existing_ieee80211g_24)
{
    std::cout << "Entering delete_node_existing_ieee80211g_24 test" << std::endl;
    em_interface_t ruid{};
    unsigned char mac[6] = {0x12,0x22,0x32,0x42,0x52,0x62};
    memcpy(ruid.mac, mac, sizeof(mac));
    strncpy(ruid.name, "Node_ieee80211g_24", sizeof(ruid.name));
    ruid.media = em_media_type_ieee80211g_24;
    dm_easy_mesh_t dm;
    em_t* node = ctrl.create_node(&ruid, em_freq_band_5, &dm, false, em_profile_type_1, em_service_type_agent);
    ASSERT_NE(node, nullptr);
    EXPECT_NO_THROW({
        ctrl.delete_node(&ruid);
    });
    std::cout << "Exiting delete_node_existing_ieee80211g_24 test" << std::endl;
}
/**
 * @brief Test the deletion of an existing node with media type ieee80211a_5
 *
 * This test verifies that a node created with specific parameters (name, MAC address, media type) is properly deleted using the delete_node API with no exceptions thrown. It confirms the functionality of both node creation and deletion APIs.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 088@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                  | Test Data                                                                                                                                                                                                                                          | Expected Result                                                                                       | Notes         |
 * | :--------------: | -------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | ------------- |
 * | 01               | Create a node using ctrl.create_node with initialized interface details                      | ruid.name = "Node_ieee80211a_5", ruid.mac = 0x13,0x23,0x33,0x43,0x53,0x63, ruid.media = em_media_type_ieee80211a_5, input: em_freq_band_5, dm = dm_easy_mesh_t, flag = false, profile = em_profile_type_1, service = em_service_type_agent | API call returns a non-null pointer indicating successful creation of the node                        | Should Pass   |
 * | 02               | Delete the same node using ctrl.delete_node                                                    | input: ruid (with previously set name, MAC, and media type)                                                                                                                                                                                        | No exception thrown during delete_node API call                                                       | Should Pass   |
 */
TEST_F(em_ctrl_t_Test, delete_node_existing_ieee80211a_5)
{
    std::cout << "Entering delete_node_existing_ieee80211a_5 test" << std::endl;
    em_interface_t ruid{};
    unsigned char mac[6] = {0x13,0x23,0x33,0x43,0x53,0x63};
    memcpy(ruid.mac, mac, sizeof(mac));
    strncpy(ruid.name, "Node_ieee80211a_5", sizeof(ruid.name));
    ruid.media = em_media_type_ieee80211a_5;
    dm_easy_mesh_t dm;
    em_t* node = ctrl.create_node(&ruid, em_freq_band_5, &dm, false, em_profile_type_1, em_service_type_agent);
    ASSERT_NE(node, nullptr);
    EXPECT_NO_THROW({
        ctrl.delete_node(&ruid);
    });
    std::cout << "Exiting delete_node_existing_ieee80211a_5 test" << std::endl;
}
/**
 * @brief Tests the deletion of an existing IEEE80211n 2.4GHz node.
 *
 * This test creates a node with IEEE80211n 2.4GHz characteristics and then deletes it.
 * It verifies that the node is correctly created (non-null pointer) and that the deletion operation
 * throws no exception.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 089
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                       | Test Data                                                                                                                                                                          | Expected Result                                                                                     | Notes       |
 * | :--------------: | --------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Create node with IEEE80211n 2.4GHz interface settings                             | input: ruid.name = "Node_ieee80211n_24", ruid.mac = {0x14,0x24,0x34,0x44,0x54,0x64}, ruid.media = em_media_type_ieee80211n_24; other inputs: freq_band = em_freq_band_5, dm, false, em_profile_type_1, em_service_type_agent; output: node  | The node pointer should not be nullptr after node creation.                                         | Should Pass |
 * | 02               | Delete the node using the same IEEE80211n 2.4GHz interface settings                 | input: ruid with same values as above; no additional output parameter                                                                                                               | The deletion operation should complete without throwing an exception (EXPECT_NO_THROW should pass) | Should Pass |
 */
TEST_F(em_ctrl_t_Test, delete_node_existing_ieee80211n_24)
{
    std::cout << "Entering delete_node_existing_ieee80211n_24 test" << std::endl;
    em_interface_t ruid{};
    unsigned char mac[6] = {0x14,0x24,0x34,0x44,0x54,0x64};
    memcpy(ruid.mac, mac, sizeof(mac));
    strncpy(ruid.name, "Node_ieee80211n_24", sizeof(ruid.name));
    ruid.media = em_media_type_ieee80211n_24;
    dm_easy_mesh_t dm;
    em_t* node = ctrl.create_node(&ruid, em_freq_band_5, &dm, false, em_profile_type_1, em_service_type_agent);
    ASSERT_NE(node, nullptr);
    EXPECT_NO_THROW({
        ctrl.delete_node(&ruid);
    });
    std::cout << "Exiting delete_node_existing_ieee80211n_24 test" << std::endl;
}
/**
 * @brief Validate deletion of an existing IEEE80211n_5 node
 *
 * This test verifies that an existing node with media type IEEE80211n_5 is successfully deleted.
 * It ensures that the node is created correctly and that invoking delete_node does not throw any exceptions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 090@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                                                 | Test Data                                                                                                                                                                  | Expected Result                                  | Notes       |
 * | :--------------: | --------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------ | ----------- |
 * | 01               | Create a node with a specific MAC, name, media type, and associated parameters using create_node API.                     | input: mac = 0x15,0x25,0x35,0x45,0x55,0x65; name = Node_ieee80211n_5; media = em_media_type_ieee80211n_5; freq = em_freq_band_5; dm = &dm; flag = false; profile = em_profile_type_1; service = em_service_type_agent | create_node returns a non-null pointer           | Should Pass |
 * | 02               | Delete the previously created node using delete_node API and verify that no exceptions are thrown during the deletion.       | input: ruid instance with the same MAC, name, and media type values as above                                                                                               | No exception thrown; node is deleted successfully  | Should Pass |
 */
TEST_F(em_ctrl_t_Test, delete_node_existing_ieee80211n_5)
{
    std::cout << "Entering delete_node_existing_ieee80211n_5 test" << std::endl;
    em_interface_t ruid{};
    unsigned char mac[6] = {0x15,0x25,0x35,0x45,0x55,0x65};
    memcpy(ruid.mac, mac, sizeof(mac));
    strncpy(ruid.name, "Node_ieee80211n_5", sizeof(ruid.name));
    ruid.media = em_media_type_ieee80211n_5;
    dm_easy_mesh_t dm;
    em_t* node = ctrl.create_node(&ruid, em_freq_band_5, &dm, false, em_profile_type_1, em_service_type_agent);
    ASSERT_NE(node, nullptr);
    EXPECT_NO_THROW({
        ctrl.delete_node(&ruid);
    });
    std::cout << "Exiting delete_node_existing_ieee80211n_5 test" << std::endl;
}
/**
 * @brief Test deletion of an existing node with media type ieee80211ac_5.
 *
 * This test verifies that an existing node can be deleted successfully from the control instance using the delete_node API. 
 * It creates a node with specific MAC address, name, and media type, then deletes the node while ensuring no exception is thrown.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 091@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                  | Test Data                                                                                                      | Expected Result                                              | Notes       |
 * | :--------------: | -------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ | ----------- |
 * | 01               | Initialize node parameters and create node via create_node API                                | ruid.mac = 16,26,36,46,56,66, ruid.name = "Node_ieee80211ac_5", ruid.media = em_media_type_ieee80211ac_5, dm instance created, freq band = em_freq_band_5, profile = em_profile_type_1, service = em_service_type_agent | Node pointer returned from create_node should not be nullptr   | Should Pass |
 * | 02               | Delete the created node by invoking delete_node API                                           | Input: ruid                                                                                                    | No exception thrown during delete_node invocation              | Should Pass |
 */
TEST_F(em_ctrl_t_Test, delete_node_existing_ieee80211ac_5)
{
    std::cout << "Entering delete_node_existing_ieee80211ac_5 test" << std::endl;
    em_interface_t ruid{};
    unsigned char mac[6] = {0x16,0x26,0x36,0x46,0x56,0x66};
    memcpy(ruid.mac, mac, sizeof(mac));
    strncpy(ruid.name, "Node_ieee80211ac_5", sizeof(ruid.name));
    ruid.media = em_media_type_ieee80211ac_5;
    dm_easy_mesh_t dm;
    em_t* node = ctrl.create_node(&ruid, em_freq_band_5, &dm, false, em_profile_type_1, em_service_type_agent);
    ASSERT_NE(node, nullptr);
    EXPECT_NO_THROW({
        ctrl.delete_node(&ruid);
    });
    std::cout << "Exiting delete_node_existing_ieee80211ac_5 test" << std::endl;
}
/**
 * @brief Verify that an existing node with IEEE80211ad_60 media type is successfully deleted
 *
 * This test creates a node with the IEEE80211ad_60 media type using a valid interface configuration and then deletes it.
 * The test ensures that the node creation returns a non-null pointer and that the deletion completes without throwing an exception.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 092@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize the interface structure (ruid) with the specified MAC address and name, and set the appropriate media type. | ruid.name = "Node_ieee80211ad_60", ruid.mac = 0x17,0x27,0x37,0x47,0x57,0x67, ruid.media = em_media_type_ieee80211ad_60 | The interface structure is correctly initialized with the provided values. | Should be successful |
 * | 02 | Create a node using the ctrl.create_node API with the configured interface and additional parameters. | input: &ruid, em_freq_band_5, &dm, false, em_profile_type_1, em_service_type_agent; output: node pointer | Returns a non-null pointer indicating successful node creation. | Should Pass |
 * | 03 | Delete the previously created node using the ctrl.delete_node API. | input: &ruid; output: none (void function call) | The deletion is executed without throwing any exceptions. | Should Pass |
 */
TEST_F(em_ctrl_t_Test, delete_node_existing_ieee80211ad_60)
{
    std::cout << "Entering delete_node_existing_ieee80211ad_60 test" << std::endl;
    em_interface_t ruid{};
    unsigned char mac[6] = {0x17,0x27,0x37,0x47,0x57,0x67};
    memcpy(ruid.mac, mac, sizeof(mac));
    strncpy(ruid.name, "Node_ieee80211ad_60", sizeof(ruid.name));
    ruid.media = em_media_type_ieee80211ad_60;
    dm_easy_mesh_t dm;
    em_t* node = ctrl.create_node(&ruid, em_freq_band_5, &dm, false, em_profile_type_1, em_service_type_agent);
    ASSERT_NE(node, nullptr);
    EXPECT_NO_THROW({
        ctrl.delete_node(&ruid);
    });
    std::cout << "Exiting delete_node_existing_ieee80211ad_60 test" << std::endl;
}
/**
 * @brief Validates deletion of an existing IEEE80211af node.
 *
 * This test verifies that a node, created with IEEE80211af media type, can be successfully deleted using ctrl.delete_node() without throwing any exceptions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 093@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Create a node with specified parameters including MAC, name, media type, frequency band, profile, and service type. | input: ruid (name = "Node_ieee80211af", mac = {0x18,0x28,0x38,0x48,0x58,0x68}, media = em_media_type_ieee80211af), em_freq_band_5, dm, false, em_profile_type_1, em_service_type_agent | Returned node pointer should not be null (ASSERT_NE(node, nullptr)) | Should Pass |
 * | 02 | Delete the created node using the control delete function. | input: ruid (same as used for node creation) | delete_node() should execute without throwing any exceptions (EXPECT_NO_THROW) | Should Pass |
 */
TEST_F(em_ctrl_t_Test, delete_node_existing_ieee80211af)
{
    std::cout << "Entering delete_node_existing_ieee80211af test" << std::endl;
    em_interface_t ruid{};
    unsigned char mac[6] = {0x18,0x28,0x38,0x48,0x58,0x68};
    memcpy(ruid.mac, mac, sizeof(mac));
    strncpy(ruid.name, "Node_ieee80211af", sizeof(ruid.name));
    ruid.media = em_media_type_ieee80211af;
    dm_easy_mesh_t dm;
    em_t* node = ctrl.create_node(&ruid, em_freq_band_5, &dm, false, em_profile_type_1, em_service_type_agent);
    ASSERT_NE(node, nullptr);
    EXPECT_NO_THROW({
        ctrl.delete_node(&ruid);
    });
    std::cout << "Exiting delete_node_existing_ieee80211af test" << std::endl;
}
/**
 * @brief Test the deletion of one node among multiple nodes.
 *
 * This test verifies that when multiple nodes are created, deleting one node using the delete_node API works correctly. 
 * It creates two nodes, validates their creation, and then deletes one node, ensuring that no exception is thrown during removal.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 094@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:** 
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create two nodes using the create_node API | ruid1: mac = {0x01,0x01,0x01,0x01,0x01,0x01}, name = "eth0", media = em_media_type_ieee8023ab, freq_band = em_freq_band_5, node flag = false, profile = em_profile_type_1, service = em_service_type_agent; ruid2: mac = {0x02,0x02,0x02,0x02,0x02,0x02}, name = "wlan0", media = em_media_type_ieee80211n_5, freq_band = em_freq_band_5, node flag = false, profile = em_profile_type_1, service = em_service_type_agent; dm = dm_easy_mesh_t object | Non-null pointers returned from both create_node calls | Should be successful |
 * | 02 | Delete the first node using the delete_node API | input: ruid1 | No exception thrown during deletion | Should Pass |
 */
TEST_F(em_ctrl_t_Test, delete_node_one_of_multiple_nodes)
{
    std::cout << "Entering delete_node_one_of_multiple_nodes test" << std::endl;
    em_interface_t ruid1{}, ruid2{};
    unsigned char mac1[6] = {0x01,0x01,0x01,0x01,0x01,0x01};
    unsigned char mac2[6] = {0x02,0x02,0x02,0x02,0x02,0x02};
    memcpy(ruid1.mac, mac1, sizeof(mac1));
    strncpy(ruid1.name, "eth0", sizeof(ruid1.name));
    ruid1.media = em_media_type_ieee8023ab;
    memcpy(ruid2.mac, mac2, sizeof(mac2));
    strncpy(ruid2.name, "wlan0", sizeof(ruid2.name));
    ruid2.media = em_media_type_ieee80211n_5;
    dm_easy_mesh_t dm;
    ASSERT_NE(ctrl.create_node(&ruid1, em_freq_band_5, &dm, false,
                               em_profile_type_1, em_service_type_agent), nullptr);
    ASSERT_NE(ctrl.create_node(&ruid2, em_freq_band_5, &dm, false,
                               em_profile_type_1, em_service_type_agent), nullptr);
    EXPECT_NO_THROW({
        ctrl.delete_node(&ruid1);
    });
    std::cout << "Exiting delete_node_one_of_multiple_nodes test" << std::endl;
}
/**
 * @brief Test deletion of a non-existent node.
 *
 * This test verifies that calling delete_node on a node that does not exist in the system does not throw an exception.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 095@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke ctrl.delete_node() with a non-existent em_interface_t node (ruid) | ruid.name = ethX, ruid.mac = 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF, ruid.media = em_media_type_ieee8023ab | No exception is thrown | Should Pass |
 */
TEST_F(em_ctrl_t_Test, delete_node_nonexistent_node)
{
    std::cout << "Entering delete_node_nonexistent_node test" << std::endl;
    em_interface_t ruid{};
    unsigned char mac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    memcpy(ruid.mac, mac, sizeof(mac));
    strncpy(ruid.name, "ethX", sizeof(ruid.name));
    ruid.media = em_media_type_ieee8023ab;
    EXPECT_NO_THROW({
        ctrl.delete_node(&ruid);
    });
    std::cout << "Exiting delete_node_nonexistent_node test" << std::endl;
}
/**
 * @brief Test to verify that ctrl.delete_node throws an exception when a null pointer is provided.
 *
 * This test case checks the behavior of the delete_node API when it is invoked with a nullptr.
 * It ensures that the API correctly handles an invalid input by throwing an exception, thereby
 * preventing undefined behavior.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 096@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                           | Test Data                     | Expected Result                                         | Notes      |
 * | :--------------: | ----------------------------------------------------- | ----------------------------- | ------------------------------------------------------- | ---------- |
 * | 01               | Invoke ctrl.delete_node with a null pointer           | input = nullptr               | API throws an exception as defined by the API behavior  | Should Fail|
 */
TEST_F(em_ctrl_t_Test, delete_node_null_pointer)
{
    std::cout << "Entering delete_node_null_pointer test" << std::endl;
    EXPECT_ANY_THROW(ctrl.delete_node(nullptr));
    std::cout << "Exiting delete_node_null_pointer test" << std::endl;
}
/**
 * @brief Validate the deletion of nodes functionality.
 *
 * This test verifies that nodes created using ctrl.create_node are properly deleted by ctrl.delete_nodes.
 * It ensures that the API correctly removes nodes without throwing exceptions and that the created nodes are valid prior to deletion.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 097
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create first node with valid parameters using ctrl.create_node. | input: node1.name = "radio1", node1.mac = {0x10,0x20,0x30,0x40,0x50,0x60}, node1.media = em_media_type_ieee8023ab; additional: freqBand = em_freq_band_5, dm pointer, boolean flag = false, profile = em_profile_type_1, service = em_service_type_agent; output: n1 pointer | n1 is not nullptr as asserted by ASSERT_NE(n1, nullptr). | Should Pass |
 * | 02 | Create second node with valid parameters using ctrl.create_node. | input: node2.name = "radio2", node2.mac = {0x11,0x21,0x31,0x41,0x51,0x61}, node2.media = em_media_type_ieee8023ab; additional: freqBand = em_freq_band_5, dm pointer, boolean flag = false, profile = em_profile_type_1, service = em_service_type_agent; output: n2 pointer | n2 is not nullptr as asserted by ASSERT_NE(n2, nullptr). | Should Pass |
 * | 03 | Invoke the ctrl.delete_nodes method to delete all created nodes. | No additional input parameters; API: delete_nodes() | No exception thrown as verified by EXPECT_NO_THROW; all nodes should be removed. | Should Pass |
 */
TEST_F(em_ctrl_t_Test, delete_nodes_valid)
{
    std::cout << "Entering delete_nodes_valid test" << std::endl;
    dm_easy_mesh_t dm;
    em_interface_t node1{};
    unsigned char mac1[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
    memcpy(node1.mac, mac1, sizeof(mac1));
    strncpy(node1.name, "radio1", sizeof(node1.name));
    node1.media = em_media_type_ieee8023ab;
    em_t* n1 = ctrl.create_node(&node1, em_freq_band_5, &dm, false, em_profile_type_1, em_service_type_agent);
    ASSERT_NE(n1, nullptr);
    em_interface_t node2{};
    unsigned char mac2[6] = {0x11,0x21,0x31,0x41,0x51,0x61};
    memcpy(node2.mac, mac2, sizeof(node2.mac));
    strncpy(node2.name, "radio2", sizeof(node2.name));
    node2.media = em_media_type_ieee8023ab;
    em_t* n2 = ctrl.create_node(&node2, em_freq_band_5, &dm, false, em_profile_type_1, em_service_type_agent);
    ASSERT_NE(n2, nullptr);
    EXPECT_NO_THROW({
        ctrl.delete_nodes();
    });
    std::cout << "Exiting delete_nodes_valid test" << std::endl;
}
/**
 * @brief Test delete_nodes() for handling an empty node list.
 *
 * This test validates that the delete_nodes() method in the em_ctrl_t object does not throw any exceptions when invoked in a scenario where no nodes exist. The objective is to ensure that the API gracefully handles an empty state without errors.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 98@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                         | Test Data                                                  | Expected Result                                                  | Notes       |
 * | :--------------: | --------------------------------------------------- | ---------------------------------------------------------- | ---------------------------------------------------------------- | ----------- |
 * | 01               | Invoke ctrl.delete_nodes() on an object with an empty node set | No input arguments, output: void; exception: none expected  | delete_nodes() executes without throwing any exceptions (verified via EXPECT_NO_THROW) | Should Pass |
 */
TEST_F(em_ctrl_t_Test, delete_nodes_empty)
{
    std::cout << "Entering delete_nodes_empty test" << std::endl;
    EXPECT_NO_THROW({
        ctrl.delete_nodes();
    });
    std::cout << "Exiting delete_nodes_empty test" << std::endl;
}
/**
 * @brief Verify that get_node_by_freq_band returns nullptr when no nodes are present
 *
 * This test case evaluates the behavior of the get_node_by_freq_band API when the internal node map is empty.
 * It ensures that the function correctly returns a nullptr, which is expected when there are no nodes configured 
 * in the system for the given frequency band.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 99@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                               | Test Data                                      | Expected Result                                                 | Notes       |
 * | :--------------: | ----------------------------------------------------------------------------------------- | ---------------------------------------------- | -------------------------------------------------------------- | ----------- |
 * | 01               | Invoke get_node_by_freq_band with em_freq_band_24 on an empty node map                     | band = em_freq_band_24                         | API returns nullptr and the assertion (EXPECT_EQ(result, nullptr)) passes | Should Pass |
 */
TEST_F(em_ctrl_t_Test, get_node_by_freq_band_empty_map) {
    std::cout << "Entering get_node_by_freq_band_empty_map test" << std::endl;
    em_freq_band_t band = em_freq_band_24;
    // No nodes created yet
    em_t* result = ctrl.get_node_by_freq_band(&band);
    EXPECT_EQ(result, nullptr);
    std::cout << "Exiting get_node_by_freq_band_empty_map test" << std::endl;
}
/**
 * @brief Verifies that get_node_by_freq_band returns nullptr when no matching node exists.
 *
 * This test case creates two nodes with distinct frequency bands (em_freq_band_5 and em_freq_band_60) using the setup_interface and ctrl.create_node APIs. It then searches for a node with the frequency band em_freq_band_24, which does not match any of the created nodes. The objective is to ensure that the get_node_by_freq_band API correctly returns a nullptr in a no-match scenario.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 100
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create two nodes using setup_interface and ctrl.create_node with distinct frequency bands | node1: name = radio1, mac = 0xAA,0xBB,0xCC,0xDD,0xEE,0x01, frequency band = em_freq_band_5; node2: name = radio2, mac = 0xAA,0xBB,0xCC,0xDD,0xEE,0x02, frequency band = em_freq_band_60 | Nodes created successfully | Should be successful |
 * | 02 | Invoke get_node_by_freq_band with em_freq_band_24 to search for a node with no matching frequency band | search_band = em_freq_band_24 | Returns nullptr and EXPECT_EQ verifies result is nullptr | Should Pass |
 */
TEST_F(em_ctrl_t_Test, get_node_by_freq_band_no_match) {
    std::cout << "Entering get_node_by_freq_band_no_match test" << std::endl;
    em_interface_t node1{}, node2{};
    unsigned char mac1[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0x01};
    unsigned char mac2[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0x02};
    setup_interface(node1, "radio1", mac1);
    setup_interface(node2, "radio2", mac2);
    dm_easy_mesh_t dm1, dm2;
    ctrl.create_node(&node1, em_freq_band_5, &dm1, false, em_profile_type_1, em_service_type_agent);
    ctrl.create_node(&node2, em_freq_band_60, &dm2, false, em_profile_type_1, em_service_type_agent);
    em_freq_band_t search_band = em_freq_band_24;
    em_t* result = ctrl.get_node_by_freq_band(&search_band);
    EXPECT_EQ(result, nullptr);
    std::cout << "Exiting get_node_by_freq_band_no_match test" << std::endl;
}
/**
 * @brief Validate retrieval of 2.4GHz node from created nodes.
 *
 * This test verifies that the em_ctrl_t API correctly retrieves the node operating in the 2.4GHz frequency band. The test creates two nodes with different frequency bands and confirms that get_node_by_freq_band returns the pointer to the node with a 2.4GHz frequency.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 101
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                       | Test Data                                                                                                             | Expected Result                                              | Notes       |
 * | :--------------: | ----------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ | ----------- |
 * | 01               | Create first radio interface node with 2.4GHz frequency band.       | node1: name = "radio1", mac = AA:BB:CC:DD:EE:11; frequency = em_freq_band_24; dm structure, false, em_profile_type_1, em_service_type_agent | Node is created and pointer returned.                        | Should Pass |
 * | 02               | Create second radio interface node with 5GHz frequency band.        | node2: name = "radio2", mac = AA:BB:CC:DD:EE:22; frequency = em_freq_band_5; dm structure, false, em_profile_type_1, em_service_type_agent  | Node is created but not eligible for 2.4GHz search.          | Should Pass |
 * | 03               | Invoke get_node_by_freq_band to retrieve node by 2.4GHz band.         | search_band = em_freq_band_24, expected output = pointer to node created in step 01                                    | Returned pointer matches the pointer of the node from step 01. | Should Pass |
 */
TEST_F(em_ctrl_t_Test, get_node_by_freq_band_24GHz) {
    std::cout << "Entering get_node_by_freq_band_24GHz test" << std::endl;
    em_interface_t node1{}, node2{};
    unsigned char mac1[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0x11};
    unsigned char mac2[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0x22};
    setup_interface(node1, "radio1", mac1);
    setup_interface(node2, "radio2", mac2);
    dm_easy_mesh_t dm1, dm2;
    em_t* created1 = ctrl.create_node(&node1, em_freq_band_24, &dm1, false, em_profile_type_1, em_service_type_agent);
    ctrl.create_node(&node2, em_freq_band_5, &dm2, false, em_profile_type_1, em_service_type_agent);
    em_freq_band_t search_band = em_freq_band_24;
    em_t* result = ctrl.get_node_by_freq_band(&search_band);
    EXPECT_EQ(result, created1);
    std::cout << "Exiting get_node_by_freq_band_24GHz test" << std::endl;
}
/**
 * @brief Validate that the controller returns the correct node for the 5GHz frequency band
 *
 * This test verifies that when two nodes are created with different frequency bands,
 * invoking get_node_by_freq_band with the 5GHz band returns the node created for the 5GHz frequency.
 * It ensures that the API can correctly differentiate nodes based on their frequency assignments.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 102@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                           | Test Data                                                                                                                                                               | Expected Result                                                       | Notes         |
 * | :--------------: | ----------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ------------- |
 * | 01               | Configure the first node's interface with name "radio1" and MAC address 0xAA,0xBB,0xCC,0xDD,0xEE,0x33 | input: node1, name = radio1, mac1 = 0xAA,0xBB,0xCC,0xDD,0xEE,0x33                                                                                                     | node1 interface properly configured                                   | Should be successful |
 * | 02               | Configure the second node's interface with name "radio2" and MAC address 0xAA,0xBB,0xCC,0xDD,0xEE,0x44| input: node2, name = radio2, mac2 = 0xAA,0xBB,0xCC,0xDD,0xEE,0x44                                                                                                     | node2 interface properly configured                                   | Should be successful |
 * | 03               | Create the first node with frequency band 5GHz using the configured node1 interface                   | input: node = node1, frequency = em_freq_band_5, dm = dm1, flag = false, profile = em_profile_type_1, service = em_service_type_agent                                     | Returns a valid pointer (created1) representing the 5GHz node          | Should Pass   |
 * | 04               | Create the second node with frequency band 2.4GHz using the configured node2 interface                | input: node = node2, frequency = em_freq_band_24, dm = dm2, flag = false, profile = em_profile_type_1, service = em_service_type_agent                                    | Returns a valid pointer representing the 2.4GHz node                   | Should Pass   |
 * | 05               | Retrieve the node based on the 5GHz frequency band and verify it returns the first created node        | input: search_band = em_freq_band_5                                                                                                                                        | Returns pointer equal to created1 and assertion EXPECT_EQ passes       | Should Pass   |
 */
TEST_F(em_ctrl_t_Test, get_node_by_freq_band_5GHz) {
    std::cout << "Entering get_node_by_freq_band_5GHz test" << std::endl;
    em_interface_t node1{}, node2{};
    unsigned char mac1[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0x33};
    unsigned char mac2[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0x44};
    setup_interface(node1, "radio1", mac1);
    setup_interface(node2, "radio2", mac2);
    dm_easy_mesh_t dm1, dm2;
    em_t* created1 = ctrl.create_node(&node1, em_freq_band_5, &dm1, false, em_profile_type_1, em_service_type_agent);
    ctrl.create_node(&node2, em_freq_band_24, &dm2, false, em_profile_type_1, em_service_type_agent);
    em_freq_band_t search_band = em_freq_band_5;
    em_t* result = ctrl.get_node_by_freq_band(&search_band);
    EXPECT_EQ(result, created1);
    std::cout << "Exiting get_node_by_freq_band_5GHz test" << std::endl;
}
/**
 * @brief Validates the get_node_by_freq_band functionality by ensuring that a node created with a specific frequency band is properly retrieved.
 *
 * This test creates two nodes with different frequency bands (60GHz and 24GHz) and then retrieves a node using the 60GHz band.
 * It verifies that the retrieved node matches the node created with the 60GHz band.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 103
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize node1 using setup_interface with radio1 and MAC {AA,BB,CC,DD,EE,55} | node1: name = "radio1", mac = "0xAA,0xBB,0xCC,0xDD,0xEE,0x55" | node1 is correctly initialized | Should be successful |
 * | 02 | Initialize node2 using setup_interface with radio2 and MAC {AA,BB,CC,DD,EE,66} | node2: name = "radio2", mac = "0xAA,0xBB,0xCC,0xDD,0xEE,0x66" | node2 is correctly initialized | Should be successful |
 * | 03 | Create node1 by invoking ctrl.create_node with frequency band 60GHz along with dm1 and additional parameters | input: node1, freq_band = em_freq_band_60, dm1, false, em_profile_type_1, em_service_type_agent; output: created1 pointer | node1 is created and a valid pointer (created1) is returned | Should Pass |
 * | 04 | Create node2 by invoking ctrl.create_node with frequency band 24GHz along with dm2 and additional parameters | input: node2, freq_band = em_freq_band_24, dm2, false, em_profile_type_1, em_service_type_agent | node2 is created and a valid pointer is returned | Should Pass |
 * | 05 | Retrieve a node by invoking ctrl.get_node_by_freq_band with the search band set to 60GHz | input: search_band = em_freq_band_60; output: result pointer | result pointer matches the pointer returned in step 03 (created1) | Should Pass |
 */
TEST_F(em_ctrl_t_Test, get_node_by_freq_band_6GHz) {
    std::cout << "Entering get_node_by_freq_band_6GHz test" << std::endl;
    em_interface_t node1{}, node2{};
    unsigned char mac1[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x55};
    unsigned char mac2[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x66};
    setup_interface(node1, "radio1", mac1);
    setup_interface(node2, "radio2", mac2);
    dm_easy_mesh_t dm1, dm2;
    em_t* created1 = ctrl.create_node(&node1, em_freq_band_60, &dm1, false, em_profile_type_1, em_service_type_agent);
    ctrl.create_node(&node2, em_freq_band_24, &dm2, false, em_profile_type_1, em_service_type_agent);
    em_freq_band_t search_band = em_freq_band_60;
    em_t* result = ctrl.get_node_by_freq_band(&search_band);
    EXPECT_EQ(result, created1);
    std::cout << "Exiting get_node_by_freq_band_6GHz test" << std::endl;
}
/**
 * @brief Verify that get_al_node returns nullptr when no AL node exists
 *
 * This test verifies that after creating two non-AL nodes using create_node, the function 
 * get_al_node correctly returns a nullptr as there is no AL node created in the controller.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 104
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize first interface with name "radio1" and MAC address 0x10,0x20,0x30,0x40,0x50,0x60; set media type to em_media_type_ieee8023ab | node1.name = "radio1", node1.mac = 10,20,30,40,50,60, node1.media = em_media_type_ieee8023ab | Interface node1 configured as per input | Should be successful |
 * | 02 | Invoke create_node API for the first interface with frequency band em_freq_band_5, profile em_profile_type_1, and service type em_service_type_agent | input: node1, freq_band = em_freq_band_5, dm pointer, flag = false, profile = em_profile_type_1, service = em_service_type_agent; output: n1 | n1 != nullptr; node creation successful | Should Pass |
 * | 03 | Initialize second interface with name "radio2" and MAC address 0x11,0x21,0x31,0x41,0x51,0x61; set media type to em_media_type_ieee8023ab | node2.name = "radio2", node2.mac = 11,21,31,41,51,61, node2.media = em_media_type_ieee8023ab | Interface node2 configured as per input | Should be successful |
 * | 04 | Invoke create_node API for the second interface with frequency band em_freq_band_5, profile em_profile_type_1, and service type em_service_type_agent | input: node2, freq_band = em_freq_band_5, dm pointer, flag = false, profile = em_profile_type_1, service = em_service_type_agent; output: n2 | n2 != nullptr; node creation successful | Should Pass |
 * | 05 | Invoke get_al_node API to obtain the AL node from the controller | No direct input; uses internal state of ctrl | Returns nullptr indicating no AL node is present | Should Pass |
 */
TEST_F(em_ctrl_t_Test, get_al_node_non_al_nodes) {
    std::cout << "Entering get_al_node_non_al_nodes test" << std::endl;
    dm_easy_mesh_t dm;
    em_interface_t node1{};
    unsigned char mac1[6] = {0x10,0x20,0x30,0x40,0x50,0x60};
    setup_interface(node1, "radio1", mac1);
    node1.media = em_media_type_ieee8023ab;
    em_t* n1 = ctrl.create_node(&node1, em_freq_band_5, &dm, false, em_profile_type_1, em_service_type_agent);
    ASSERT_NE(n1, nullptr);
    em_interface_t node2{};
    unsigned char mac2[6] = {0x11,0x21,0x31,0x41,0x51,0x61};
    setup_interface(node2, "radio2", mac2);
    node2.media = em_media_type_ieee8023ab;
    em_t* n2 = ctrl.create_node(&node2, em_freq_band_5, &dm, false, em_profile_type_1, em_service_type_agent);
    ASSERT_NE(n2, nullptr);
    em_t* result = ctrl.get_al_node();
    EXPECT_EQ(result, nullptr);
    std::cout << "Exiting get_al_node_non_al_nodes test" << std::endl;
}
/**
 * @brief Test to validate that get_al_node() returns a nullptr when no node exists.
 *
 * This test validates that the get_al_node() method returns a nullptr when the AL node list is empty. It ensures that the API properly handles the case where no node is available.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 105
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                      | Test Data                                                   | Expected Result                                           | Notes      |
 * | :--------------: | ---------------------------------------------------------------- | ----------------------------------------------------------- | --------------------------------------------------------- | ---------- |
 * | 01               | Invoke the get_al_node() API on the ctrl object to retrieve node.  | No input arguments; Output: result (expected value: nullptr)| The API returns a nullptr, verified via EXPECT_EQ(result, nullptr). | Should Pass |
 */
TEST_F(em_ctrl_t_Test, get_al_node_empty) {
    std::cout << "Entering get_al_node_empty test" << std::endl;
    em_t* result = ctrl.get_al_node();
    EXPECT_EQ(result, nullptr);
    std::cout << "Exiting get_al_node_empty test" << std::endl;
}
/**
 * @brief Verify that get_phy_al_node returns a null pointer when no physical active node is present.
 *
 * The test validates that when the physical active node map is empty, invoking get_phy_al_node on the controller
 * returns a null pointer. This behavior is critical to ensure that the system properly handles scenarios where no
 * active node is available.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 106@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                            | Test Data                                                      | Expected Result                                           | Notes       |
 * | :--------------: | ---------------------------------------------------------------------- | -------------------------------------------------------------- | --------------------------------------------------------- | ----------- |
 * | 01               | Call ctrl.get_phy_al_node() to retrieve the physical active node pointer | No input arguments, output: result pointer expected to be nullptr | API returns nullptr and assertion EXPECT_EQ confirms it    | Should Pass |
 */
TEST_F(em_ctrl_t_Test, get_phy_al_node_emptymap) {
    std::cout << "Entering get_phy_al_node_emptymap test" << std::endl;
    em_t* result = ctrl.get_phy_al_node();
    EXPECT_EQ(result, nullptr);
    std::cout << "Exiting get_phy_al_node_emptymap test" << std::endl;
}
/**
 * @brief Validate that get_phy_al_node returns nullptr when no virtual access layer node is present.
 *
 * This test verifies that after creating two radio nodes using create_node (with non-virtual access layer settings), the get_phy_al_node API correctly returns a nullptr, indicating that no virtual access layer node exists.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 107@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Configure two radio nodes by calling setup_interface and invoke create_node API for both nodes | node1: name=radio1, mac=AA:BB:CC:DD:EE:FF, media=em_media_type_ieee8023ab, freq_band=em_freq_band_5, profile=em_profile_type_1, service=em_service_type_agent; node2: name=radio2, mac=11:22:33:44:55:66, media=em_media_type_ieee8023ab, freq_band=em_freq_band_5, profile=em_profile_type_1, service=em_service_type_agent | Both nodes are created successfully | Should Pass |@n
 * | 02 | Invoke get_phy_al_node to retrieve the physical access layer node | No input arguments | Returned pointer is nullptr | Should Pass |
 */
TEST_F(em_ctrl_t_Test, get_phy_al_node_no_virtual_al) {
    std::cout << "Entering get_phy_al_node_noVirtualAL test" << std::endl;
    em_interface_t node1{}, node2{};
    unsigned char mac1[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    unsigned char mac2[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    setup_interface(node1, "radio1", mac1);
    node1.media = em_media_type_ieee8023ab;
    setup_interface(node2, "radio2", mac2);
    node2.media = em_media_type_ieee8023ab;
    dm_easy_mesh_t dm1, dm2;
    ctrl.create_node(&node1, em_freq_band_5, &dm1, false, em_profile_type_1, em_service_type_agent);
    ctrl.create_node(&node2, em_freq_band_5, &dm2, false, em_profile_type_1, em_service_type_agent);
    em_t* result = ctrl.get_phy_al_node();
    EXPECT_EQ(result, nullptr);
    std::cout << "Exiting get_phy_al_node_no_virtual_al test" << std::endl;
}
/**
 * @brief Test get_all_em_for_al_mac API with an empty radios vector.
 *
 * This test verifies that when calling the get_all_em_for_al_mac API with a valid AL MAC address and an empty radios vector,
 * the function executes without throwing any exceptions. This ensures that the API can handle an empty map scenario gracefully.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 108@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Print entering message for test initiation. | None | "Entering get_all_em_for_al_mac_empty_map test" is printed. | Should be successful |
 * | 02 | Invoke get_all_em_for_al_mac API with a valid AL MAC address and an empty radios vector. | al_mac = {0x00,0x1A,0x2B,0x3C,0x4D,0x5E}, radios = empty vector | API executes without throwing any exceptions. | Should Pass |
 * | 03 | Print exiting message for test termination. | None | "Exiting get_all_em_for_al_mac_empty_map test" is printed. | Should be successful |
 */
TEST_F(em_ctrl_t_Test, get_all_em_for_al_mac_empty_map)
{
    std::cout << "Entering get_all_em_for_al_mac_empty_map test" << std::endl;
    mac_address_t al_mac = {0x00,0x1A,0x2B,0x3C,0x4D,0x5E};
    std::vector<em_t*> radios;
    EXPECT_NO_THROW({
        ctrl.get_all_em_for_al_mac(al_mac, radios);
    });
    std::cout << "Exiting get_all_em_for_al_mac_empty_map test" << std::endl;
}
/**
 * @brief Verify that reset_listeners returns 0 for an empty list of listeners
 *
 * This test verifies that when the controller's listener map is empty, invoking the reset_listeners function returns a highest file descriptor value of 0. The test ensures that the controller handles the empty state correctly by resetting the listeners and returning the expected value.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 109@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                      | Test Data                                                     | Expected Result                                                  | Notes        |
 * | :--------------: | ---------------------------------------------------------------- | ------------------------------------------------------------- | ---------------------------------------------------------------- | ------------ |
 * | 01               | Invoke reset_listeners on the controller with an empty listeners map | No input parameters, output: highest_fd = 0                   | The API returns 0 and the EXPECT_EQ assertion passes              | Should Pass  |
 */
TEST_F(em_ctrl_t_Test, reset_listeners_empty_map) {
    std::cout << "Entering reset_listeners_empty_map test" << std::endl;
    int highest_fd = ctrl.reset_listeners();
    EXPECT_EQ(highest_fd, 0);
    std::cout << "Exiting reset_listeners_empty_map test" << std::endl;
}
/**
 * @brief Test the reset_listeners() function for handling non-al nodes
 *
 * This test verifies that when nodes that are not AL nodes are created and registered, 
 * the reset_listeners() function resets the listeners correctly and returns the expected highest file descriptor. 
 * It creates two nodes with distinct MAC addresses, ensures that the nodes are successfully created, 
 * and then checks that the reset_listeners operation returns a file descriptor value of 0.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 110@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Initialize radio1 node with MAC 0x10,0x20,0x30,0x40,0x50,0x60, set media type to em_media_type_ieee8023ab, create node and verify node creation | node1.name = radio1, mac = 0x10,0x20,0x30,0x40,0x50,0x60, media = em_media_type_ieee8023ab, frequency = em_freq_band_5, profile = em_profile_type_1, service = em_service_type_agent | node1 is created successfully (not nullptr) and assertion passes | Should Pass |
 * | 02 | Initialize radio2 node with MAC 0x11,0x21,0x31,0x41,0x51,0x61, set media type to em_media_type_ieee8023ab, create node and verify node creation | node2.name = radio2, mac = 0x11,0x21,0x31,0x41,0x51,0x61, media = em_media_type_ieee8023ab, frequency = em_freq_band_5, profile = em_profile_type_1, service = em_service_type_agent | node2 is created successfully (not nullptr) and assertion passes | Should Pass |
 * | 03 | Invoke the reset_listeners function and verify the returned highest file descriptor value | function = reset_listeners | highest_fd equals 0 and assertion passes | Should Pass |
 */
TEST_F(em_ctrl_t_Test, reset_listeners_only_non_al_nodes) {
    std::cout << "Entering reset_listeners_only_non_al_nodes test" << std::endl;
    dm_easy_mesh_t dm;
    em_interface_t node1{};
    unsigned char mac1[6] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60};
    setup_interface(node1, "radio1", mac1);
    node1.media = em_media_type_ieee8023ab;
    em_t* n1 = ctrl.create_node(&node1, em_freq_band_5, &dm, false, em_profile_type_1, em_service_type_agent);
    ASSERT_NE(n1, nullptr);
    em_interface_t node2{};
    unsigned char mac2[6] = {0x11, 0x21, 0x31, 0x41, 0x51, 0x61};
    setup_interface(node2, "radio2", mac2);
    node2.media = em_media_type_ieee8023ab;
    em_t* n2 = ctrl.create_node(&node2, em_freq_band_5, &dm, false, em_profile_type_1, em_service_type_agent);
    ASSERT_NE(n2, nullptr);
    int highest_fd = ctrl.reset_listeners();
    EXPECT_EQ(highest_fd, 0);
    std::cout << "Exiting reset_listeners_only_non_al_nodes test" << std::endl;
}
/**
 * @brief Validate that the handle_timeout function executes without throwing an exception.
 *
 * This test verifies that calling the ctrl.handle_timeout() function does not throw any exceptions,
 * ensuring that the default timeout handling logic in the control module works as expected.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 111
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                   | Test Data                                 | Expected Result                                            | Notes      |
 * | :--------------: | ------------------------------------------------------------- | ----------------------------------------- | ---------------------------------------------------------- | ---------- |
 * |       01       | Invoke the ctrl.handle_timeout() method within a try-catch block | input: none, output: void, exception: none | Function executes without throwing any exceptions | Should Pass |
 */
TEST_F(em_ctrl_t_Test, handle_timeout_default) {
    std::cout << "Entering handle_timeout_default test" << std::endl;
    EXPECT_NO_THROW({
        ctrl.handle_timeout();
    });
    std::cout << "Exiting handle_timeout_default test" << std::endl;
}
/**
 * @brief Validate that the message ID generation increments by one on consecutive calls
 *
 * This test verifies that the API em_ctrl_t::get_next_msg_id correctly returns incrementing message IDs on subsequent invocations. It ensures that the first call returns 1 and the second call returns 2 so that the underlying counter is functioning as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 112@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                        | Test Data                                    | Expected Result                | Notes        |
 * | :----:           | ------------------------------------------------------------------ | -------------------------------------------- | ------------------------------ | ------------ |
 * | 01               | Invoke ctrl.get_next_msg_id() to obtain the first message ID       | output1 = id1                                | id1 equals 1                   | Should Pass  |
 * | 02               | Invoke ctrl.get_next_msg_id() to obtain the second message ID      | output1 = id2                                | id2 equals 2                   | Should Pass  |
 */
TEST_F(em_ctrl_t_Test, get_next_msg_id_basic_increment) {
    std::cout << "Entering get_next_msg_id_basic_increment test" << std::endl;
    unsigned short id1 = ctrl.get_next_msg_id();
    EXPECT_EQ(id1, 1u);
    unsigned short id2 = ctrl.get_next_msg_id();
    EXPECT_EQ(id2, 2u);
    std::cout << "Exiting get_next_msg_id_via_ctrl_BasicIncrement test" << std::endl;
}
/**
 * @brief Validate sequential message ID generation using get_next_msg_id.
 *
 * This test verifies that consecutive calls to get_next_msg_id produce sequential message IDs, meaning each new ID is exactly one greater than the previous. This behavior is critical to ensure proper message ordering and uniqueness in the system.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 113@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                              | Test Data                    | Expected Result                                                  | Notes         |
 * | :--------------: | -------------------------------------------------------- | ---------------------------- | ---------------------------------------------------------------- | ------------- |
 * | 01               | Invoke get_next_msg_id to retrieve the first message ID  | output1 = id1                | First message ID is retrieved successfully                       | Should be successful |
 * | 02               | Invoke get_next_msg_id to retrieve the second message ID | output2 = id2                | Second message ID equals first message ID + 1 (id2 == id1 + 1)     | Should Pass   |
 * | 03               | Invoke get_next_msg_id to retrieve the third message ID  | output3 = id3                | Third message ID equals second message ID + 1 (id3 == id2 + 1)     | Should Pass   |
 */
TEST_F(em_ctrl_t_Test, get_next_msg_id_sequential_calls) {
    std::cout << "Entering get_next_msg_id_sequential_calls test" << std::endl;
    unsigned short id1 = ctrl.get_next_msg_id();
    unsigned short id2 = ctrl.get_next_msg_id();
    unsigned short id3 = ctrl.get_next_msg_id();
    EXPECT_EQ(id1 + 1, id2);
    EXPECT_EQ(id2 + 1, id3);
    std::cout << "Sequential msg_ids = " << id1 << ", " << id2 << ", " << id3 << std::endl;
    std::cout << "Exiting get_next_msg_id_sequential_calls test" << std::endl;
}
/**
 * @brief Verify that io_process properly processes valid data and parameters.
 *
 * This test verifies that the io_process function can process valid data and parameters without throwing exceptions. The test uses a valid command string and parameters to simulate a commit event operation.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 114@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call the io_process API with valid data and parameters | data = "dm-commit-event", params.net_node = nullptr, params.u.args.num_args = 1, params.u.args.args[0] = "commit", params.u.args.fixed_args = "apply" | API call completes without throwing an exception | Should Pass |
 */
TEST_F(em_ctrl_t_Test, io_process_valid_data_and_params)
{
    std::cout << "Entering io_process_valid_data_and_params test" << std::endl;
    char data[] = "dm-commit-event";
    em_cmd_params_t params{};
    params.net_node = nullptr;
    params.u.args.num_args = 1;
    snprintf(params.u.args.args[0], sizeof(params.u.args.args[0]), "commit");
    snprintf(params.u.args.fixed_args, sizeof(params.u.args.fixed_args), "apply");
    EXPECT_NO_THROW({
        ctrl.io_process(em_bus_event_type_dm_commit, reinterpret_cast<char*>(data), sizeof(data), &params);
    });
    std::cout << "Exiting io_process_valid_data_and_params test" << std::endl;
}
/**
 * @brief To verify that io_process handles null data pointers and valid parameters without throwing exceptions.
 *
 * This test calls the io_process API with a null network node pointer and other valid parameters to ensure that the API does not throw any exceptions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 115@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                       | Test Data                                                                                                          | Expected Result                                                  | Notes        |
 * | :--------------: | ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------- | ------------ |
 * | 01               | Invoke io_process with null network node and valid parameters     | input: bus_event_type = em_bus_event_type_dm_commit, data_ptr = nullptr, data_len = 0, params.net_node = nullptr, params.u.args.num_args = 0 | API call should not throw any exception; Expect successful execution | Should Pass  |
 */
TEST_F(em_ctrl_t_Test, io_process_null_data_valid_params)
{
    std::cout << "Entering io_process_null_data_valid_params test" << std::endl;
    em_cmd_params_t params{};
    params.net_node = nullptr;
    params.u.args.num_args = 0;
    EXPECT_NO_THROW({
        ctrl.io_process(em_bus_event_type_dm_commit,static_cast<char*>(nullptr),0,&params);
    });
    std::cout << "Exiting io_process_null_data_valid_params test" << std::endl;
}
/**
 * @brief Test to ensure io_process correctly handles valid input data with null parameters.
 *
 * This test invokes the io_process API with a valid data string and a null parameter for one of the arguments.
 * It verifies that the API does not throw any exceptions when provided with these valid inputs, ensuring robustness.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 116@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                             | Test Data                                                                                   | Expected Result                                                          | Notes      |
 * | :--------------: | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ | ---------- |
 * | 01               | Call io_process with valid data and null for the last parameter         | input1 = em_bus_event_type_dm_commit, input2 = "dm-commit-event", input3 = sizeof(data), input4 = nullptr | API should complete without throwing exceptions; assertion EXPECT_NO_THROW passed | Should Pass |
 */
TEST_F(em_ctrl_t_Test, io_process_valid_data_null_params)
{
    std::cout << "Entering io_process_valid_data_null_params test" << std::endl;
    char data[] = "dm-commit-event";
    EXPECT_NO_THROW({
        ctrl.io_process(em_bus_event_type_dm_commit,reinterpret_cast<char*>(data),sizeof(data),nullptr);
    });
    std::cout << "Exiting io_process_valid_data_null_params test" << std::endl;
}
/**
 * @brief Test io_process API with valid parameters
 *
 * This test validates that the io_process function of the control class processes the valid input data and command parameters
 * correctly without throwing any exceptions. It verifies that correct string commands ("scan" and "start") are passed within the
 * command parameters structure and that the function handles the provided data buffer without error.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 117@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                             | Test Data                                                                                                                       | Expected Result                                                | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- | ----------- |
 * | 01               | Setup test data and parameters, then invoke ctrl.io_process with valid parameters                       | data = {0x01, 0x02, 0x03}, params.net_node = nullptr, params.u.args.num_args = 1, params.u.args.args[0] = "scan", params.u.args.fixed_args = "start" | ctrl.io_process should execute without throwing any exception | Should Pass |
 */
TEST_F(em_ctrl_t_Test, io_process_data_valid_params)
{
    std::cout << "Entering io_process_data_valid_params test" << std::endl;
    unsigned char data[] = {0x01, 0x02, 0x03};
    em_cmd_params_t params{};
    params.net_node = nullptr;
    params.u.args.num_args = 1;
    snprintf(params.u.args.args[0], sizeof(params.u.args.args[0]), "scan");
    snprintf(params.u.args.fixed_args, sizeof(params.u.args.fixed_args), "start");
    EXPECT_NO_THROW({
        ctrl.io_process(em_bus_event_type_dm_commit, reinterpret_cast<unsigned char*>(data), sizeof(data), &params);
    });
    std::cout << "Exiting io_process_uchar_data_valid_params test" << std::endl;
}
/**
 * @brief Tests io_process API with a null data pointer and valid command parameters.
 *
 * This test case verifies that invoking the io_process API with a nullptr for the data pointer,
 * while providing valid command parameters, does not throw any exceptions. The test is designed
 * to ensure that the API can gracefully handle a scenario where the data pointer is null, which is
 * a valid input condition in certain contexts.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 118@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- | -------------- | ----- |@n
 * | 01 | Initialize em_cmd_params_t with net_node as nullptr and num_args as 0; call io_process with em_bus_event_type_dm_commit, nullptr as data, 0 as data size, and the parameters | event type = em_bus_event_type_dm_commit, data pointer = nullptr, data size = 0, net_node = nullptr, num_args = 0 | The function call completes without throwing any exception | Should Pass |
 */
TEST_F(em_ctrl_t_Test, io_process_nullptr_data_valid_params)
{
    std::cout << "Entering io_process_nullptr_data_valid_params test" << std::endl;
    em_cmd_params_t params{};
    params.net_node = nullptr;
    params.u.args.num_args = 0;
    EXPECT_NO_THROW({
        ctrl.io_process(em_bus_event_type_dm_commit, static_cast<unsigned char*>(nullptr), 0, &params);
    });
    std::cout << "Exiting io_process_nullptr_data_valid_params test" << std::endl;
}
/**
 * @brief Validate io_process handling with valid data and nullptr output parameter.
 *
 * This test verifies that the io_process API correctly processes input data when the output parameter is provided as a nullptr, ensuring that the function does not throw any exceptions. This is important to check to guarantee robust error handling and prevent crashes when optional parameters are omitted.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 119@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke io_process API with em_bus_event_type_dm_commit, valid data array, and nullptr for the output parameter. | input1 = em_bus_event_type_dm_commit, input2 = pointer to data array {0x01, 0x02, 0x03}, input3 = sizeof(data), input4 = nullptr | The API call should not throw any exception (EXPECT_NO_THROW) | Should Pass |
 */
TEST_F(em_ctrl_t_Test, io_process_data_valid_nullptr_params)
{
    std::cout << "Entering io_process_data_valid_nullptr_params test" << std::endl;
    unsigned char data[] = {0x01, 0x02, 0x03};
    EXPECT_NO_THROW({
        ctrl.io_process(em_bus_event_type_dm_commit, reinterpret_cast<unsigned char*>(data), sizeof(data), nullptr);
    });
    std::cout << "Exiting io_process_data_valid_nullptr_params test" << std::endl;
}
/**
 * @brief Test to verify that io_process handles frame events correctly by returning false.
 *
 * This test allocates and initializes an event object as a frame event and then invokes
 * the io_process API. The primary objective is to confirm that the API returns false
 * when processing a frame event, which represents a negative scenario as per the expected behavior.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 120@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Allocate memory for event and initialize it as a frame event | evt allocated with malloc, memset initialized, evt->type = em_event_type_frame | Event structure is correctly prepared for processing | Should be successful |
 * | 02 | Invoke the io_process API with the frame event | input: evt->type = em_event_type_frame, output: ret returned from io_process | API returns false as asserted by EXPECT_FALSE(ret) | Should Fail |
 * | 03 | Free the allocated event memory | free(evt) called on the allocated event | Memory is successfully freed | Should be successful |
 */
TEST_F(em_ctrl_t_Test, io_process_frame_event)
{
    std::cout << "Entering io_process_frame_event test" << std::endl;
    auto *evt = static_cast<em_event_t *>(malloc(sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN));
    memset(evt, 0, sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN);
    evt->type = em_event_type_frame;
    bool ret = ctrl.io_process(evt);
    EXPECT_FALSE(ret);
    free(evt);
    std::cout << "Exiting io_process_frame_event test" << std::endl;
}
/**
 * @brief Verify that io_process handles non-dm commit bus events correctly
 *
 * This test verifies that the io_process API correctly processes various bus events that are not part of the device model commit operations. It iterates over a list of predefined bus event types, sets up the corresponding event structure, and asserts that the processing of each event returns true.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 121@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | For each non-dm commit bus event type, allocate and initialize an event structure, set evt->type = em_event_type_bus, set evt->u.bevt.type to the current bus event type, and set evt->u.bevt.data_len = 0, then invoke io_process API. | evt->type = em_event_type_bus, evt->u.bevt.type = <bus_event_type>, evt->u.bevt.data_len = 0 | io_process returns true for each event; verified with EXPECT_TRUE(ret) | Should Pass |
 */
TEST_F(em_ctrl_t_Test, io_process_bus_event_non_dm_commit)
{
    std::cout << "Entering io_process_bus_event_non_dm_commit test" << std::endl;
    em_bus_event_type_t bus_event_types[] = {
        em_bus_event_type_chirp,
        em_bus_event_type_reset,
        em_bus_event_type_dev_test,
        em_bus_event_type_set_dev_test,
        em_bus_event_type_get_network,
        em_bus_event_type_get_device,
        em_bus_event_type_remove_device,
        em_bus_event_type_get_radio,
        em_bus_event_type_get_ssid,
        em_bus_event_type_set_ssid,
        em_bus_event_type_get_channel,
        em_bus_event_type_set_channel,
        em_bus_event_type_scan_channel,
        em_bus_event_type_scan_result,
        em_bus_event_type_get_bss,
        em_bus_event_type_get_sta,
        em_bus_event_type_steer_sta,
        em_bus_event_type_disassoc_sta,
        em_bus_event_type_get_policy,
        em_bus_event_type_set_policy,
        em_bus_event_type_btm_sta,
        em_bus_event_type_start_dpp,
        em_bus_event_type_dev_init,
        em_bus_event_type_cfg_renew,
        em_bus_event_type_radio_config,
        em_bus_event_type_vap_config,
        em_bus_event_type_sta_list,
        em_bus_event_type_ap_cap_query,
        em_bus_event_type_client_cap_query,
        em_bus_event_type_listener_stop,
        em_bus_event_type_m2_tx,
        em_bus_event_type_topo_sync,
        em_bus_event_type_onewifi_private_cb,
        em_bus_event_type_onewifi_mesh_sta_cb,
        em_bus_event_type_onewifi_radio_cb,
        em_bus_event_type_m2ctrl_configuration,
        em_bus_event_type_sta_assoc,
        em_bus_event_type_channel_pref_query,
        em_bus_event_type_channel_sel_req,
        em_bus_event_type_sta_link_metrics,
        em_bus_event_type_set_radio,
        em_bus_event_type_bss_tm_req,
        em_bus_event_type_btm_response,
        em_bus_event_type_channel_scan_params,
        em_bus_event_type_get_mld_config,
        em_bus_event_type_mld_reconfig,
        em_bus_event_type_beacon_report,
        em_bus_event_type_recv_wfa_action_frame,
        em_bus_event_type_recv_gas_frame,
        em_bus_event_type_get_sta_client_type,
        em_bus_event_type_assoc_status,
        em_bus_event_type_ap_metrics_report,
        em_bus_event_type_bss_info,
        em_bus_event_type_get_reset,
        em_bus_event_type_recv_csa_beacon_frame,
        em_bus_event_type_bsta_cap_req
    };
    for (auto type : bus_event_types) {
        auto *evt = static_cast<em_event_t *>(malloc(sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN));
        memset(evt, 0, sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN);
        evt->type = em_event_type_bus;
        evt->u.bevt.type = type;
        evt->u.bevt.data_len = 0;
        bool ret = ctrl.io_process(evt);
        EXPECT_TRUE(ret);
        free(evt);
    }
    std::cout << "Exiting io_process_bus_event_non_dm_commit test" << std::endl;
}
/**
 * @brief Test the behavior of io_process with a dm_commit bus event.
 *
 * This test verifies that the io_process function correctly handles a bus event of type dm_commit.
 * It ensures that when an event with bus type and dm_commit subtype is processed, the function returns false.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 122
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | ------------- | ----- |
 * | 01 | Allocate memory, initialize event with type bus and subtype dm_commit, and invoke ctrl.io_process() | evt->type = em_event_type_bus, evt->u.bevt.type = em_bus_event_type_dm_commit, evt->u.bevt.data_len = 0 | ctrl.io_process(evt) returns false; EXPECT_FALSE(ret) assertion passes | Should Pass |
 */
TEST_F(em_ctrl_t_Test, io_process_bus_event_dm_commit)
{
    std::cout << "Entering io_process_bus_event_dm_commit test" << std::endl;
    auto *evt = static_cast<em_event_t *>(malloc(sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN));
    memset(evt, 0, sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN);
    evt->type = em_event_type_bus;
    evt->u.bevt.type = em_bus_event_type_dm_commit;
    evt->u.bevt.data_len = 0;
    bool ret = ctrl.io_process(evt);
    EXPECT_FALSE(ret);
    free(evt);
    std::cout << "Exiting io_process_bus_event_dm_commit test" << std::endl;
}
/**
 * @brief To verify that io_process returns false when provided with a null event pointer.
 *
 * This test case validates that the io_process method of the em_ctrl_t class correctly handles a null event pointer. By invoking io_process with a null pointer, the test ensures the function returns false as expected, thereby confirming its robustness against invalid inputs.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 123
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                              | Test Data                                               | Expected Result                                             | Notes       |
 * | :--------------: | ---------------------------------------------------------| --------------------------------------------------------| ----------------------------------------------------------- | ----------- |
 * |       01         | Invoke io_process on a null event pointer                | input = event pointer, value = nullptr; output = false  | Function returns false and EXPECT_FALSE validates the output| Should Pass |
 */
TEST_F(em_ctrl_t_Test, io_process_null_event_pointer)
{
    std::cout << "Entering io_process_null_event_pointer test" << std::endl;
    bool ret = ctrl.io_process(nullptr);
    EXPECT_FALSE(ret);
    std::cout << "Exiting io_process_null_event_pointer test" << std::endl;
}
/**
 * @brief Test invalid event type handling in the io_process function
 *
 * This test verifies that the io_process function returns false when provided with an event having an invalid event type (em_event_type_max). It validates that the function correctly handles invalid inputs by rejecting the event processing.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 124@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                | Test Data                                                                                     | Expected Result                                          | Notes       |
 * | :--------------: | ---------------------------------------------------------- | --------------------------------------------------------------------------------------------- | -------------------------------------------------------- | ----------- |
 * | 01               | Invoke io_process with an event of invalid type            | evt->type = em_event_type_max, memory allocated (em_event_t + EM_MAX_EVENT_DATA_LEN), memset to 0 | Returns false from io_process, assertion EXPECT_FALSE(ret) | Should Fail |
 */
TEST_F(em_ctrl_t_Test, io_process_invalid_event_type)
{
    std::cout << "Entering io_process_invalid_event_type test" << std::endl;
    auto *evt = static_cast<em_event_t *>(malloc(sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN));
    memset(evt, 0, sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN);
    evt->type = em_event_type_max;  // invalid type
    bool ret = ctrl.io_process(evt);
    EXPECT_FALSE(ret);
    free(evt);
    std::cout << "Exiting io_process_invalid_event_type test" << std::endl;
}
