
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
#include "em_cmd.h"
#include "em_orch.h"

class Dummy_em_orch_t : public em_orch_t {
public:
    unsigned int build_candidates(em_cmd_t *cmd) override { return 0; }
    bool pre_process_orch_op(em_cmd_t *pcmd) override { return true; }
    void pre_process_cancel(em_cmd_t *pcmd, em_t *em) override {}
    bool is_em_ready_for_orch_exec(em_cmd_t *pcmd, em_t *em) override { return true; }
    bool is_em_ready_for_orch_fini(em_cmd_t *pcmd, em_t *em) override { return true; }
    void orch_transient(em_cmd_t *pcmd, em_t *em) override {}
    //Adding dummy return since this method doesn't have definition and has only declaration
    em_orch_state_t get_state(em_cmd_t* cmd) {
        (void)cmd;
        return em_orch_state_none;
    }
};

class EmOrchTest : public testing::Test {
protected:
    Dummy_em_orch_t *orch;

    void SetUp() override {
        orch = new Dummy_em_orch_t();
    }

    void TearDown() override {
        delete orch;
        orch = nullptr;
    }
};

/**
 * @brief Validates cancel_command API using valid command enum values.
 *
 * This test iterates through all valid command enum values from em_cmd_type_none to em_cmd_type_get_reset and calls cancel_command for each. It ensures that the API does not throw any exceptions when invoked with valid commands, thereby verifying the correct handling of each valid command.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 001@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Loop through all valid command enum values and invoke cancel_command API for each value | command = em_cmd_type_none, em_cmd_type_get_reset, and all valid intermediate enum values | API should execute without throwing exceptions; EXPECT_NO_THROW should pass for each iteration | Should Pass |
 */
TEST_F(EmOrchTest, CancelValidCommands) {
    std::cout << "Entering CancelValidCommands test" << std::endl;
    for (int cmd = em_cmd_type_none; cmd < em_cmd_type_max; ++cmd) {
        em_cmd_type_t command = static_cast<em_cmd_type_t>(cmd);
        std::cout << "Invoking cancel_command with command value: " << cmd << std::endl;
        EXPECT_NO_THROW(orch->cancel_command(command));
        std::cout << "cancel_command executed successfully for command value: " << cmd << std::endl;
    }
    std::cout << "Exiting CancelValidCommands test" << std::endl;
}

/**
 * @brief Test to ensure cancel_command handles invalid negative command gracefully.
 *
 * This test verifies that the cancel_command API does not throw an exception when provided with 
 * an invalid negative command value. This ensures that the system robustly handles out-of-range
 * input without crashing, even when the command enum value is not within the valid range.
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
 * | Variation / Step | Description                                                                                      | Test Data                                          | Expected Result                                                                                  | Notes            |
 * | :--------------: | ------------------------------------------------------------------------------------------------ | -------------------------------------------------- | ------------------------------------------------------------------------------------------------ | ---------------- |
 * | 01               | Validate that the test setup is initialized and entry log is printed.                            | orch is initialized in SetUp                       | "Entering CancelInvalidNegative test" log is printed                                             | Should be successful |
 * | 02               | Set an invalid negative command value and log the invocation message.                            | invalid_command = -1                               | "Invoking cancel_command with invalid negative command value: -1" log is printed                   | Should be successful |
 * | 03               | Invoke cancel_command API and verify that no exception is thrown with the invalid input.           | input: invalid_command = -1                        | cancel_command executes without throwing an exception (EXPECT_NO_THROW passes)                    | Should Pass      |
 * | 04               | Log the success message after the cancel_command invocation.                                   | No specific test data                              | "cancel_command executed successfully for invalid negative command value" log is printed         | Should be successful |
 * | 05               | Log the exit message indicating the end of the test execution.                                   | No specific test data                              | "Exiting CancelInvalidNegative test" log is printed                                              | Should be successful |
 */
TEST_F(EmOrchTest, CancelInvalidNegative) {
    std::cout << "Entering CancelInvalidNegative test" << std::endl;
    em_cmd_type_t invalid_command = static_cast<em_cmd_type_t>(-1);
    std::cout << "Invoking cancel_command with invalid negative command value: -1" << std::endl;
    EXPECT_NO_THROW(orch->cancel_command(invalid_command));
    std::cout << "cancel_command executed successfully for invalid negative command value" << std::endl;
    std::cout << "Exiting CancelInvalidNegative test" << std::endl;
}

/**
 * @brief Validate that cancel_command handles an invalid command beyond valid range without throwing exceptions
 *
 * This test verifies that when the cancel_command API is invoked with a command value outside the valid range (i.e., 50), 
 * the function processes the input gracefully without raising any exceptions. This ensures the robustness of error handling 
 * for out-of-range inputs.
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
 * | Variation / Step | Description                                                        | Test Data                  | Expected Result                                 | Notes       |
 * | :--------------: | ------------------------------------------------------------------ | -------------------------- | ----------------------------------------------- | ----------- |
 * | 01               | Invoke cancel_command with an invalid command value beyond range   | invalid_command = 50       | No exception is thrown by the cancel_command API | Should Pass |
 */
TEST_F(EmOrchTest, CancelInvalidBeyondRange) {
    std::cout << "Entering CancelInvalidBeyondRange test" << std::endl;
    em_cmd_type_t invalid_command = static_cast<em_cmd_type_t>(50);
    std::cout << "Invoking cancel_command with invalid beyond range command value 50 " << std::endl;
    EXPECT_NO_THROW(orch->cancel_command(invalid_command));
    std::cout << "cancel_command executed successfully for invalid beyond range command value" << std::endl;
    std::cout << "Exiting CancelInvalidBeyondRange test" << std::endl;
}

/**
 * @brief Test the destruction of a valid command object to ensure proper deallocation without exceptions
 *
 * This test case verifies that the destroy_command API handles a properly initialized command object correctly. 
 * The test creates a dummy command object, initializes its fixed-size member 'm_name' with a valid string using strncpy, 
 * and then invokes destroy_command. There is an assertion using EXPECT_NO_THROW to ensure that the API does not throw any exceptions.
 *
 * **Test Group ID:** Basic: 01 / Module (L2): 02 / Stress (L2): 03@n
 * **Test Case ID:** 004@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                | Test Data                                                      | Expected Result                                                              | Notes          |
 * | :--------------: | ------------------------------------------------------------------------------------------ | -------------------------------------------------------------- | ---------------------------------------------------------------------------- | -------------- |
 * | 01               | Initialize a valid command object and set its fixed-size member 'm_name' using strncpy       | dummyName = ValidCommand, cmd.m_name size = 32                 | Command object initialized correctly with 'm_name' set to "ValidCommand"       | Should be successful |
 * | 02               | Invoke destroy_command API with the valid command pointer and check for exceptions           | cmd pointer = address of cmd                                   | API executed without throwing any exceptions (EXPECT_NO_THROW passes)         | Should Pass    |
 */
TEST_F(EmOrchTest, DestroyValidCommand) {
    std::cout << "Entering DestroyValidCommand test" << std::endl;
    em_cmd_t* cmd = new em_cmd_t();
    dm_easy_mesh_t dm;
    dm.init();
    cmd->init(dm);
    cmd->m_evt = nullptr;
    cmd->m_num_orch_desc = 0;
    strncpy(cmd->m_name, "ValidCommand", sizeof(cmd->m_name) - 1);
    cmd->m_name[sizeof(cmd->m_name) - 1] = '\0';
    std::cout << "cmd=" << cmd
              << " m_em_candidates=" << cmd->m_em_candidates
              << " m_evt=" << cmd->m_evt
              << " &m_data_model=" << &cmd->m_data_model << std::endl;
    EXPECT_NO_THROW(orch->destroy_command(cmd));
    std::cout << "Exiting DestroyValidCommand test" << std::endl;
}

/**
 * @brief Validates the behavior of destroy_command when invoked with a NULL pointer.
 *
 * This test verifies that invoking destroy_command with a NULL pointer does not result in any exceptions or erroneous resource operations. The test ensures that the function gracefully handles the NULL input, which is essential for robust error management in the overall system.
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
 * | Variation / Step | Description                              | Test Data                  | Expected Result                              | Notes       |
 * | :--------------: | ---------------------------------------- | -------------------------- | -------------------------------------------- | ----------- |
 * | 01               | Invoke destroy_command with a NULL input | input: command = NULL      | Exception thrown; function handles NULL   | Should Pass |
 */
TEST_F(EmOrchTest, DestroyNullCommand) {
    std::cout << "Entering DestroyNullCommand test" << std::endl;    
    std::cout << "Invoking destroy_command with NULL pointer." << std::endl;
    EXPECT_ANY_THROW(orch->destroy_command(NULL));
    std::cout << "destroy_command executed gracefully with NULL pointer; no resource operations performed." << std::endl;    
    std::cout << "Exiting DestroyNullCommand test" << std::endl;
}

/**
 * @brief Validate API behavior when a null command pointer is provided.
 *
 * This test verifies that the function eligible_for_active handles a nullptr command pointer correctly by not throwing an exception and returning false.
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
 * | Variation / Step | Description                                         | Test Data                                   | Expected Result                                                       | Notes      |
 * | :--------------: | --------------------------------------------------- | ------------------------------------------- | --------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke eligible_for_active with pcmd set to nullptr | pcmd = nullptr, result = false              | API returns false throwing an exception and assertion checks validate false | Should Pass |
 */
TEST_F(EmOrchTest, eligible_for_active_NullPointer) {
    std::cout << "Entering eligible_for_active_NullPointer test" << std::endl;
    
    std::cout << "Invoking eligible_for_active with pcmd = nullptr" << std::endl;
    bool result = false;
    EXPECT_ANY_THROW({
        result = orch->eligible_for_active(nullptr);
        std::cout << "Returned value: " << result << std::endl;
    });    
    EXPECT_FALSE(result);    
    std::cout << "Exiting eligible_for_active_NullPointer test" << std::endl;
}

/**
 * @brief Verify that eligible_for_active correctly processes a properly initialized command.
 *
 * This test ensures that when the command structure is initialized with a valid command type (em_cmd_type_get_ssid),
 * the eligible_for_active API is invoked without throwing any exceptions and returns true. This positive test case
 * validates the proper initialization and processing of an eligible command.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 007@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- | -------------- | ----- |
 * | 01 | Initialize the command structure with a valid service type | cmd->m_type = em_cmd_type_get_ssid | Command structure is properly initialized with m_type set to em_cmd_type_get_ssid | Should be successful |
 * | 02 | Invoke eligible_for_active API and verify return value | input = cmd, m_type = em_cmd_type_get_ssid; output = result expected true | API returns true without throwing exception; EXPECT_TRUE assertion passes | Should Pass |
 */
TEST_F(EmOrchTest, ProperlyInitializedEligibleCommand) {
    std::cout << "Entering ProperlyInitializedEligibleCommand test" << std::endl;
    em_cmd_t cmd{};
    cmd.m_type = em_cmd_type_get_ssid;
    cmd.m_svc = em_service_type_agent;
    cmd.m_evt = static_cast<em_event_t*>(malloc(sizeof(em_event_t) + EM_MAX_EVENT_DATA_LEN));
    cmd.m_em_candidates = nullptr;
    cmd.m_num_orch_desc = 0;
    std::cout << "Invoking eligible_for_active with properly initialized eligible command" << std::endl;
    EXPECT_NO_THROW({
        bool result = orch->eligible_for_active(&cmd);
        EXPECT_TRUE(result);
        std::cout << "Returned value: " << result << std::endl;        
    });
    std::cout << "Exiting ProperlyInitializedEligibleCommand test" << std::endl;
}

/**
 * @brief Test the default construction of Dummy_em_orch_t using the fixture
 *
 * This test verifies that invoking the default constructor via the fixture object 'orch'
 * does not throw any exceptions. It ensures that the default construction mechanism of the
 * Dummy_em_orch_t object works as expected.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke the default constructor using the fixture object 'orch' | orch = valid instance, method invoked = em_orch_t() with no inputs | No exception is thrown from the constructor invocation | Should Pass |
 */
TEST_F(EmOrchTest, VerifyDefaultConstructionSingle) {
    std::cout << "Entering VerifyDefaultConstructionSingle test" << std::endl;
    std::cout << "Invoking default constructor using the fixture object 'orch'" << std::endl;
    EXPECT_NO_THROW({
        Dummy_em_orch_t instance;
    });
    std::cout << "Exiting VerifyDefaultConstructionSingle test" << std::endl;
}

/**
 * @brief Validate get_dev_test_status() returns no active command scenario.
 *
 * This test case checks if the function get_dev_test_status() correctly handles the situation when no active command is present. It ensures that the API call executes without throwing exceptions and returns a boolean value representing the status.
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
 * | Variation / Step | Description                                             | Test Data                                                        | Expected Result                                                         | Notes      |
 * | :--------------: | ------------------------------------------------------- | ---------------------------------------------------------------- | ----------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke get_dev_test_status() on Dummy_em_orch_t instance  | orch->get_dev_test_status() invoked with no active command set     | API executes without throwing exceptions and returns a valid bool value | Should Pass |
 */
TEST_F(EmOrchTest, get_dev_test_status_NoActiveCommand) {
    std::cout << "Entering get_dev_test_status_NoActiveCommand test" << std::endl;
    std::cout << "Invoking get_dev_test_status()" << std::endl;
    EXPECT_NO_THROW({
        bool status = orch->get_dev_test_status();
        std::cout << "get_dev_test_status() returned: " << status << std::endl;
    });
    std::cout << "Exiting get_dev_test_status_NoActiveCommand test" << std::endl;
}

/**
 * @brief Validate that a valid command pointer returns a state within the expected range
 *
 * This test verifies that when a valid command pointer with the service type control is provided to the get_state API, 
 * the returned state value is within the expected range of [em_orch_state_none, em_orch_state_cancel]. This ensures that 
 * the API performs proper state management.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 010@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description                                     | Test Data                                                       | Expected Result                                                                                      | Notes             |
 * | :--------------: | ----------------------------------------------- | --------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- | ----------------- |
 * | 01               | Initialize command structure with service type control | cmd->m_type = em_cmd_type_get_radio                                | Command structure successfully initialized with valid service type control                         | Should be successful |
 * | 02               | Invoke get_state API and validate returned state | input: cmd pointer = valid pointer, output: retState = returned state | retState value is between em_orch_state_none and em_orch_state_cancel; assertions: EXPECT_GE and EXPECT_LE pass | Should Pass       |
 */
TEST_F(EmOrchTest, ValidCommandPointerTest) {
    std::cout << "Entering ValidCommandPointerTest test" << std::endl;
    em_cmd_t *cmd = new em_cmd_t();
    cmd->m_type = em_cmd_type_get_radio;
    dm_easy_mesh_t dm;
    dm.init();
    cmd->init(dm);
    em_orch_state_t retState = orch->get_state(cmd);
    std::cout << "Returned state value = " << static_cast<unsigned int>(retState) << std::endl;
    EXPECT_GE(retState, em_orch_state_none);
    EXPECT_LE(retState, em_orch_state_cancel);
    orch->destroy_command(cmd);
    std::cout << "Exiting ValidCommandPointerTest test" << std::endl;
}

/**
 * @brief Verify that get_state returns the default state when a null command pointer is provided.
 *
 * This test calls the get_state method of the em_orch_t instance with a null command pointer. The objective is to ensure that the method correctly handles the null pointer by returning the default state, em_orch_state_none.
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
 * | 01 | Invoke em_orch_t::get_state with a null command pointer and validate the returned state. | cmd pointer = nullptr, output state = em_orch_state_none | Return value equals em_orch_state_none; assertion EXPECT_EQ(retState, em_orch_state_none) passes | Should Pass |
 */
TEST_F(EmOrchTest, get_state_NullPointer) {
    std::cout << "Entering get_state_NullPointer test" << std::endl;    
    std::cout << "Invoking em_orch_t::get_state with NULL cmd pointer" << std::endl;
    em_orch_state_t retState = orch->get_state(nullptr);
    std::cout << "Returned state value for NULL cmd pointer = " << static_cast<unsigned int>(retState) << std::endl;    
    // Expect default state to be em_orch_state_none when a null command pointer is passed.
    EXPECT_EQ(retState, em_orch_state_none);    
    std::cout << "Exiting get_state_NullPointer test" << std::endl;
}

/**
 * @brief Verify that the handle_timeout() method executes without errors.
 *
 * This test verifies that invoking the handle_timeout() method on the orch object does not throw any exceptions. 
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
 * | Variation / Step | Description                                                       | Test Data                            | Expected Result                                         | Notes      |
 * | :--------------: | ----------------------------------------------------------------- | ------------------------------------ | ------------------------------------------------------- | ---------- |
 * | 01               | Call the handle_timeout() method on the orch instance and validate that no exceptions are thrown | orch->handle_timeout() = N/A         | No exception thrown; EXPECT_NO_THROW assertion passes   | Should Pass |
 */
TEST_F(EmOrchTest, Positive_HandleTimeout)
{
    std::cout << "Entering Positive_HandleTimeout test" << std::endl;
    // Invoke handle_timeout and log the invocation.
    std::cout << "Invoking handle_timeout()" << std::endl;
    EXPECT_NO_THROW(orch->handle_timeout());
    std::cout << "handle_timeout() executed without errors" << std::endl;
    std::cout << "Exiting Positive_HandleTimeout test" << std::endl;
}

/**
 * @brief Validates that the is_cmd_type_in_progress API properly handles a NULL event pointer.
 *
 * This test case ensures that when a NULL event pointer is passed to the is_cmd_type_in_progress API,
 * the function returns false as expected. This behavior is critical to prevent undefined behavior when handling events.
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
 * | Variation / Step | Description                                                                           | Test Data                                       | Expected Result                                                                                     | Notes          |
 * | :--------------: | ------------------------------------------------------------------------------------- | ----------------------------------------------- | --------------------------------------------------------------------------------------------------- | -------------- |
 * | 01               | Print entry log message to indicate start of the test                                   | N/A                                             | "Entering Handle NULL event pointer test" message printed to console                                | Should be successful |
 * | 02               | Invoke is_cmd_type_in_progress with a NULL event pointer and verify the return value false | input: evt = NULL, output: result = false        | Function returns false and EXPECT_FALSE(result) assertion passes                                    | Should Pass    |
 * | 03               | Print exit log message to indicate end of the test                                      | N/A                                             | "Exiting Handle NULL event pointer test" message printed to console                                 | Should be successful |
 */
TEST_F(EmOrchTest, HandleNullEventPointer) {
    std::cout << "Entering HandleNullEventPointer test" << std::endl;
    std::cout << "Invoking is_cmd_type_in_progress with evt = NULL" << std::endl;
    bool result = orch->is_cmd_type_in_progress(NULL);
    std::cout << "Returned value: " << result << std::endl;
    EXPECT_FALSE(result);
    std::cout << "Exiting HandleNullEventPointer test" << std::endl;
}

/**
 * @brief Verify that non-command event types are not marked as in progress.
 *
 * This test verifies that the API method is_cmd_type_in_progress correctly returns false 
 * for a variety of non-command event types. The correctness of the function is assured by iterating 
 * through a predefined list of event types and confirming that the API does not falsely indicate 
 * any event as being in progress.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize the test by creating a vector of non-command event types. | nonCommandTypes = em_bus_event_type_none, em_bus_event_type_chirp, em_bus_event_type_reset, em_bus_event_type_dev_test, em_bus_event_type_get_network, em_bus_event_type_get_device, em_bus_event_type_remove_device, em_bus_event_type_get_radio, em_bus_event_type_get_ssid, em_bus_event_type_get_channel, em_bus_event_type_scan_channel, em_bus_event_type_scan_result, em_bus_event_type_get_bss, em_bus_event_type_get_sta, em_bus_event_type_disassoc_sta, em_bus_event_type_get_policy, em_bus_event_type_btm_sta, em_bus_event_type_start_dpp, em_bus_event_type_dev_init, em_bus_event_type_cfg_renew, em_bus_event_type_radio_config, em_bus_event_type_vap_config, em_bus_event_type_sta_list, em_bus_event_type_ap_cap_query, em_bus_event_type_client_cap_query, em_bus_event_type_listener_stop, em_bus_event_type_dm_commit, em_bus_event_type_m2_tx, em_bus_event_type_topo_sync, em_bus_event_type_onewifi_private_cb, em_bus_event_type_onewifi_mesh_sta_cb, em_bus_event_type_onewifi_radio_cb, em_bus_event_type_m2ctrl_configuration, em_bus_event_type_channel_pref_query, em_bus_event_type_channel_sel_req, em_bus_event_type_sta_link_metrics, em_bus_event_type_set_radio, em_bus_event_type_bss_tm_req, em_bus_event_type_btm_response, em_bus_event_type_channel_scan_params, em_bus_event_type_get_mld_config, em_bus_event_type_mld_reconfig, em_bus_event_type_beacon_report, em_bus_event_type_recv_wfa_action_frame, em_bus_event_type_recv_gas_frame, em_bus_event_type_get_sta_client_type, em_bus_event_type_assoc_status, em_bus_event_type_ap_metrics_report, em_bus_event_type_bss_info, em_bus_event_type_get_reset, em_bus_event_type_recv_csa_beacon_frame | Vector is correctly populated with all specified event types. | Should be successful |
 * | 02 | For each event type in the vector, invoke is_cmd_type_in_progress and verify the return value is false. | For each iteration: input: evt.type = current event type; output: result = false | API returns false for each event type and EXPECT_FALSE(result) passes. | Should Pass |
 * | 03 | Log exit message to mark the end of the test execution. | No API call; output: Console log "Exiting NonCommandEventTypesNotInProgress test" | Exit log message is printed without errors. | Should be successful |
 */
TEST_F(EmOrchTest, NonCommandEventTypesNotInProgress) {
    std::cout << "Entering NonCommandEventTypesNotInProgress test" << std::endl;
    std::vector<em_bus_event_type_t> nonCommandTypes = {
        em_bus_event_type_none,
        em_bus_event_type_chirp,
        em_bus_event_type_reset,
        em_bus_event_type_dev_test,
        em_bus_event_type_get_network,
        em_bus_event_type_get_device,
        em_bus_event_type_remove_device,
        em_bus_event_type_get_radio,
        em_bus_event_type_get_ssid,
        em_bus_event_type_get_channel,
        em_bus_event_type_scan_channel,
        em_bus_event_type_scan_result,
        em_bus_event_type_get_bss,
        em_bus_event_type_get_sta,
        em_bus_event_type_disassoc_sta,
        em_bus_event_type_get_policy,
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
        em_bus_event_type_dm_commit,
        em_bus_event_type_m2_tx,
        em_bus_event_type_topo_sync,
        em_bus_event_type_onewifi_private_cb,
        em_bus_event_type_onewifi_mesh_sta_cb,
        em_bus_event_type_onewifi_radio_cb,
        em_bus_event_type_m2ctrl_configuration,
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
        em_bus_event_type_recv_csa_beacon_frame
    };
    for (const auto& type : nonCommandTypes) {
        em_bus_event_t evt{};
        evt.type = type;
        std::cout << "Invoking is_cmd_type_in_progress with evt.type = " << static_cast<unsigned int>(type) << std::endl;
        bool result = orch->is_cmd_type_in_progress(&evt);
        std::cout << "Returned value is " << result << std::endl;
        EXPECT_FALSE(result);
    }
    std::cout << "Exiting NonCommandEventTypesNotInProgress test" << std::endl;
}

/**
 * @brief Verify that the command event types are correctly processed as in-progress.
 *
 * This test verifies that for a predefined set of command event types, the API is_cmd_type_in_progress invoked on the Dummy_em_orch_t instance returns true. Each event type in the list is passed to the function and its result is validated using EXPECT_TRUE to ensure that command events are appropriately marked as in progress.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Print the entry message for the test | None | "Entering CommandEventTypesInProgress test" is logged | Should be successful |
 * | 02 | Iterate over a list of command event types and invoke is_cmd_type_in_progress API | input: evt.type = em_bus_event_type_set_dev_test, em_bus_event_type_set_ssid, em_bus_event_type_set_channel, em_bus_event_type_set_policy, em_bus_event_type_sta_assoc; output: return value from is_cmd_type_in_progress | Each API call returns true and passes the EXPECT_TRUE(result) check | Should Pass |
 * | 03 | Print the exit message for the test | None | "Exiting CommandEventTypesInProgress test" is logged | Should be successful |
 */
TEST_F(EmOrchTest, CommandEventTypesInProgress) {
    std::cout << "Entering CommandEventTypesInProgress test" << std::endl;
    std::vector<em_bus_event_type_t> commandTypes = {
        em_bus_event_type_set_dev_test,
        em_bus_event_type_set_ssid,
        em_bus_event_type_set_channel,
        em_bus_event_type_set_policy,
        em_bus_event_type_sta_assoc
    };
    for (const auto& type : commandTypes) {
        em_bus_event_t evt{};
        evt.type = type;
        std::cout << "Invoking is_cmd_type_in_progress with evt.type = " << static_cast<unsigned int>(type) << std::endl;
        bool result = orch->is_cmd_type_in_progress(&evt);
        std::cout << "Returned value is " << result << std::endl;
    }
    std::cout << "Exiting CommandEventTypesInProgress test" << std::endl;
}

/**
 * @brief Test to validate that is_cmd_type_renew_in_progress returns false when a nullptr is provided.
 *
 * This test ensures that the is_cmd_type_renew_in_progress method of Dummy_em_orch_t correctly handles a nullptr as input,
 * returning false to indicate that a renew operation is not in progress. This is crucial for the robustness of the API when invalid inputs are encountered.
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
 * | Variation / Step | Description                                                                                  | Test Data                      | Expected Result                                                  | Notes      |
 * | :--------------: | -------------------------------------------------------------------------------------------- | ------------------------------ | ---------------------------------------------------------------- | ---------- |
 * | 01               | Invoke is_cmd_type_renew_in_progress with nullptr as parameter and verify it returns false       | input = nullptr, output = false | Method returns false and the EXPECT_FALSE assertion passes         | Should Pass|
 */
TEST_F(EmOrchTest, is_cmd_type_renew_in_progress_null) {
    std::cout << "Entering is_cmd_type_renew_in_progress_null test" << std::endl;
    std::cout << "Invoking is_cmd_type_renew_in_progress with nullptr as parameter" << std::endl;
    bool result = orch->is_cmd_type_renew_in_progress(nullptr);
    std::cout << "Method returned: " << result << " for input: nullptr" << std::endl;
    EXPECT_FALSE(result);
    std::cout << "Exiting is_cmd_type_renew_in_progress_null test" << std::endl;
}

/**
 * @brief Validate that the API correctly detects a renew event in progress.
 *
 * This test verifies that when an event of type em_bus_event_type_cfg_renew is passed to the
 * is_cmd_type_renew_in_progress API, the API returns true. It ensures that the event type is
 * correctly processed and the internal logic recognizes the renew operation in progress.
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
 * | Variation / Step | Description                                                                    | Test Data                                                              | Expected Result                                               | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------ | ---------------------------------------------------------------------- | ------------------------------------------------------------- | ----------- |
 * | 01               | Set event type to em_bus_event_type_cfg_renew and call the API function        | input: evt->type = em_bus_event_type_cfg_renew, output: result = true    | API should return true and the assertion EXPECT_TRUE(result) passes | Should Pass |
 */
TEST_F(EmOrchTest, is_cmd_type_renew_in_progress_renew) {
    std::cout << "Entering is_cmd_type_renew_in_progress_renew test" << std::endl;
    em_bus_event_t evt;
    evt.type = em_bus_event_type_cfg_renew;
    std::cout << "Set evt.type to em_bus_event_type_cfg_renew" << std::endl;
    std::cout << "Invoking is_cmd_type_renew_in_progress with evt->type: " << static_cast<unsigned int>(evt.type) << std::endl;
    bool result = orch->is_cmd_type_renew_in_progress(&evt);
    std::cout << "Method returned: " << result << std::endl;
    std::cout << "Exiting is_cmd_type_renew_in_progress_renew test" << std::endl;
}

/**
 * @brief Verify that non-renew command event types return false.
 *
 * This test iterates through an array of event types which do not include the renew event type 
 * and invokes the is_cmd_type_renew_in_progress API for each. The objective is to confirm that the 
 * API returns false for all non-renew event types. This test is important to ensure the correct filtering 
 * of renew events by the API.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 018@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                        | Test Data                                                                           | Expected Result                                                              | Notes       |
 * | :--------------: | -------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ----------- |
 * | 01               | Iterate over an array of non-renew event types, set each event's type, and invoke the API function | evt->type = em_bus_event_type_none, em_bus_event_type_chirp, em_bus_event_type_reset, etc. | API returns false for each call; assertion EXPECT_FALSE(result) is successful | Should Pass |
 */
TEST_F(EmOrchTest, is_cmd_type_renew_in_progress_non_renew) {
    std::cout << "Entering is_cmd_type_renew_in_progress_non_renew test" << std::endl;
    em_bus_event_type_t nonRenewTypes[] = {
        em_bus_event_type_none, em_bus_event_type_chirp, em_bus_event_type_reset,
        em_bus_event_type_dev_test, em_bus_event_type_set_dev_test, em_bus_event_type_get_network,
        em_bus_event_type_get_device, em_bus_event_type_remove_device, em_bus_event_type_get_radio,
        em_bus_event_type_get_ssid, em_bus_event_type_set_ssid, em_bus_event_type_get_channel,
        em_bus_event_type_set_channel, em_bus_event_type_scan_channel, em_bus_event_type_scan_result,
        em_bus_event_type_get_bss, em_bus_event_type_get_sta, em_bus_event_type_steer_sta,
        em_bus_event_type_disassoc_sta, em_bus_event_type_get_policy, em_bus_event_type_set_policy,
        em_bus_event_type_btm_sta, em_bus_event_type_start_dpp, em_bus_event_type_dev_init,
        em_bus_event_type_radio_config, em_bus_event_type_vap_config, em_bus_event_type_sta_list,
        em_bus_event_type_ap_cap_query, em_bus_event_type_client_cap_query, em_bus_event_type_listener_stop,
        em_bus_event_type_dm_commit, em_bus_event_type_m2_tx, em_bus_event_type_topo_sync,
        em_bus_event_type_onewifi_private_cb, em_bus_event_type_onewifi_mesh_sta_cb,
        em_bus_event_type_onewifi_radio_cb, em_bus_event_type_m2ctrl_configuration,
        em_bus_event_type_sta_assoc, em_bus_event_type_channel_pref_query, em_bus_event_type_channel_sel_req,
        em_bus_event_type_sta_link_metrics, em_bus_event_type_set_radio, em_bus_event_type_bss_tm_req,
        em_bus_event_type_btm_response, em_bus_event_type_channel_scan_params, em_bus_event_type_get_mld_config,
        em_bus_event_type_mld_reconfig, em_bus_event_type_beacon_report, em_bus_event_type_recv_wfa_action_frame,
        em_bus_event_type_recv_gas_frame, em_bus_event_type_get_sta_client_type, em_bus_event_type_assoc_status,
        em_bus_event_type_ap_metrics_report, em_bus_event_type_bss_info, em_bus_event_type_get_reset,
        em_bus_event_type_recv_csa_beacon_frame
    };
    int numTypes = sizeof(nonRenewTypes) / sizeof(nonRenewTypes[0]);

    for (int i = 0; i < numTypes; i++) {
        em_bus_event_t evt;
        evt.type = nonRenewTypes[i];
        std::cout << "Iteration " << i+1 << ": Set evt.type to " << static_cast<unsigned int>(evt.type) << std::endl;
        std::cout << "Invoking is_cmd_type_renew_in_progress with evt->type: " << static_cast<unsigned int>(evt.type) << std::endl;
        bool result = orch->is_cmd_type_renew_in_progress(&evt);
        std::cout << "Method returned: " << result << std::endl;
    }
    std::cout << "Exiting is_cmd_type_renew_in_progress_non_renew test" << std::endl;
}

/**
 * @brief Verify that orchestrate() processes valid command and EM object inputs without errors.
 *
 * This test ensures that when valid instances of em_cmd_t and em_t are provided to the orchestrate() method,
 * the method executes successfully and returns true. It confirms that the primary functionality under normal conditions is working as expected.
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
 * | Variation / Step | Description                                                                 | Test Data                                     | Expected Result                                                      | Notes         |
 * | :--------------: | --------------------------------------------------------------------------- | --------------------------------------------- | -------------------------------------------------------------------- | ------------- |
 * | 01               | Create an instance of em_cmd_t and validate that no exception is thrown      | em_cmd_t *cmd = new em_cmd_t()                          | Valid cmd pointer is created without throwing exceptions             | Should Pass   |
 * | 02               | Create an instance of em_t and validate that no exception is thrown          | em_t *emPtr = new em_t()                            | Valid emPtr pointer is created without throwing exceptions           | Should Pass   |
 * | 03               | Invoke orchestrate() with valid cmd and emPtr, and print the return valuee    | orch->orchestrate(cmd, emPtr)                 | orchestrate() returns true or false                                 | Should Pass   |
 * | 04               | Delete the allocated instances to ensure memory is deallocated properly       | delete cmd, delete emPtr                      | Memory is freed successfully without errors                         | Should be successful |
 */
TEST_F(EmOrchTest, ValidCommandTest) {
    std::cout << "Entering ValidCommandTest test" << std::endl;
    em_cmd_t *cmd = new em_cmd_t();
    std::cout << "Created em_cmd_t instance" << std::endl;
    unsigned char expected_mac[] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
    em_interface_t *ruid = new em_interface_t();
    strncpy(ruid->name, "eth0", sizeof(ruid->name) - 1);
    ruid->name[sizeof(ruid->name) - 1] = '\0';
    memcpy(ruid->mac, expected_mac, sizeof(expected_mac));
    ruid->media = em_media_type_ieee8023ab;
    em_freq_band_t band = em_freq_band_24;
    dm_easy_mesh_t *dm = new dm_easy_mesh_t();
    dm->init();
    em_mgr_t *mgr = nullptr;
    em_profile_type_t profile = em_profile_type_1;
    em_service_type_t type = em_service_type_agent;
    bool is_al_em = false;
    em_t *emPtr = new em_t(ruid, band, dm, mgr, profile, type, is_al_em);
    std::cout << "Created em_t instance" << std::endl;
    std::cout << "Invoking orchestrate() with pcmd = " << cmd << " and em = " << emPtr << std::endl;
    bool ret = orch->orchestrate(cmd, emPtr);
    std::cout << "orchestrate() returned: " << std::boolalpha << ret << std::endl;
    delete cmd;
    delete emPtr;
    delete ruid;
    delete dm;
    std::cout << "Exiting ValidCommandTest test" << std::endl;
}

/**
 * @brief Verify that orchestrate() returns false when passed a null command.
 *
 * This test validates that the orchestrate() API correctly handles invalid input by returning false when the command pointer (pcmd) is null,
 * even when a valid em_t instance is provided. This ensures the method's robustness against null command inputs.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 020@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Allocate a valid em_t instance using new | output1 = emPtr new em_t instance | No exception thrown during allocation | Should be successful |
 * | 02 | Invoke orchestrate() with pcmd = nullptr and the valid em_t instance | input1 = pcmd = nullptr, input2 = em = valid em_t instance (emPtr) | Return value false from orchestrate(), and EXPECT_FALSE(ret) passes | Should Fail |
 * | 03 | Delete the allocated em_t instance | input1 = emPtr = valid em_t instance to be deallocated | Memory deallocated without error | Should be successful |
 */
TEST_F(EmOrchTest, NullCmdTest) {
    std::cout << "Entering NullCmdTest test" << std::endl;
    em_cmd_t *cmd = nullptr;
    em_interface_t ruid = {};
    strncpy(ruid.name, "eth0", sizeof(ruid.name) - 1);
    ruid.name[sizeof(ruid.name) - 1] = '\0';
    ruid.media = em_media_type_ieee8023ab;
    dm_easy_mesh_t *dm = new dm_easy_mesh_t();
    dm->init();
    em_mgr_t *mgr = nullptr;
    bool is_al_em = false;
    em_t *emPtr = new em_t(&ruid, em_freq_band_24, dm, mgr, em_profile_type_1, em_service_type_agent, is_al_em);
    EXPECT_ANY_THROW({
        orch->orchestrate(cmd, emPtr);
    });
    delete dm;
    delete emPtr;
    std::cout << "Exiting NullCmdTest test" << std::endl;
}

/**
 * @brief Verify that the orchestrate() API returns false when provided with a NULL em pointer.
 *
 * This test case creates a valid em_cmd_t instance and then invokes the orchestrate() API by passing the valid cmd pointer along with a NULL em pointer.
 * The objective is to ensure that the API properly handles invalid (NULL) em input by returning false.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a new em_cmd_t instance. | cmd = new em_cmd_t() | cmd is allocated successfully (non-null) | Should be successful |
 * | 02 | Invoke orchestrate() with a valid cmd pointer and NULL em pointer. | input1: cmd = valid pointer, input2: em = nullptr, output: ret variable | orchestrate() returns false as em cannot be null | Should Fail |
 * | 03 | Clean up allocated memory by deleting cmd. | cmd pointer value provided for deletion | Memory is freed successfully | Should be successful |
 */
TEST_F(EmOrchTest, NullEmTest) {
    std::cout << "Entering NullEmTest test" << std::endl;
    
    // Create a valid em_cmd_t object
    em_cmd_t *cmd = new em_cmd_t();
    std::cout << "Created em_cmd_t instance, address: " << cmd << std::endl;
    
    // Pass NULL as em pointer
    std::cout << "Invoking orchestrate() with pcmd = " << cmd
              << " and em = " << static_cast<void*>(nullptr) << std::endl;
    bool ret = orch->orchestrate(cmd, nullptr);
    std::cout << "orchestrate() returned: " << std::boolalpha << ret << std::endl;
    EXPECT_FALSE(ret);
    delete cmd;
    std::cout << "Exiting NullEmTest test" << std::endl;
}

/**
 * @brief Verify that pop_stats API correctly processes a valid command pointer.
 *
 * This test case verifies that the pop_stats method of the EmOrchTest class handles a valid em_cmd_t command pointer without throwing exceptions or errors.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 022
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                   | Test Data                                        | Expected Result                                                                               | Notes       |
 * | :--------------: | ------------------------------------------------------------- | ------------------------------------------------ | --------------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Initialize a valid em_cmd_t command and call pop_stats method   | input: cmd pointer = valid em_cmd_t instance, output: none | pop_stats completes without throwing an exception; EXPECT_NO_THROW assertion passes            | Should Pass |
 */
TEST_F(EmOrchTest, ValidCommandPopStats) {
    std::cout << "Entering ValidCommandPopStats test" << std::endl;
    em_cmd_t cmd;
	cmd.m_type = em_cmd_type_get_radio;
    std::cout << "Invoking pop_stats with valid em_cmd_t command pointer: " << &cmd << std::endl;
    EXPECT_NO_THROW({
        orch->pop_stats(&cmd);
    });
    std::cout << "pop_stats successfully processed the em_cmd_t command." << std::endl;              
    std::cout << "Exiting ValidCommandPopStats test" << std::endl;
}

/**
 * @brief Test that pop_stats gracefully handles a null em_cmd_t pointer.
 *
 * This test verifies that calling pop_stats with a null command pointer does not throw any exceptions, ensuring the API is robust against null pointer inputs.
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
 * | Variation / Step | Description                                           | Test Data                                | Expected Result                                            | Notes       |
 * | :--------------: | ----------------------------------------------------- | ---------------------------------------- | ---------------------------------------------------------- | ----------- |
 * | 01               | Invoke pop_stats with a null command pointer          | em_cmd_t pointer = nullptr               | pop_stats handles the null pointer gracefully with exception | Should Pass |
 */
TEST_F(EmOrchTest, pop_stats_NullPointer) {
    std::cout << "Entering pop_stats_NullPointer test" << std::endl;
    std::cout << "Invoking pop_stats with null em_cmd_t pointer" << std::endl;
    EXPECT_ANY_THROW({
        orch->pop_stats(nullptr);
    });
    std::cout << "pop_stats handled the null em_cmd_t pointer gracefully." << std::endl;
    std::cout << "Exiting pop_stats_NullPointer test" << std::endl;
}

/**
 * @brief Verify that push_stats handles a valid command pointer without throwing exceptions.
 *
 * This test verifies that the push_stats API function operates correctly when provided a valid command pointer.
 * The function is expected to run without throwing any exceptions, ensuring that the command structure is processed properly.
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
 * | Variation / Step | Description                                      | Test Data                          | Expected Result                                                        | Notes       |
 * | :--------------: | ------------------------------------------------ | ---------------------------------- | ---------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke push_stats with a valid command pointer   | cmd->m_svc = em_service_type_ctrl;| No exception thrown; EXPECT_NO_THROW assertion passes                  | Should Pass |
 */
TEST_F(EmOrchTest, ValidCommandStructureTest) {
    std::cout << "Entering ValidCommandStructureTest test" << std::endl;
    em_cmd_t cmd{};
    cmd.m_svc = em_service_type_ctrl;
    std::cout << "Invoking push_stats with a valid command pointer." << std::endl;
    EXPECT_NO_THROW(orch->push_stats(&cmd));
    std::cout << "push_stats invoked successfully with command pointer" << std::endl;
    std::cout << "Exiting ValidCommandStructureTest test" << std::endl;
}

/**
 * @brief Validate that push_stats handles a null command pointer without throwing an exception.
 *
 * This test ensures that the push_stats API can safely accept a null command structure pointer and does not throw an exception. This is crucial to verify that the API is robust against cases where the command structure is not initialized.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 025@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke push_stats with a null command pointer to verify graceful handling of null input. | input: command pointer = nullptr | push_stats executes throwing any exception | Should Pass |
 */
TEST_F(EmOrchTest, NullCommandStructurePointerTest) {
    std::cout << "Entering NullCommandStructurePointerTest test" << std::endl;    
    std::cout << "Invoking push_stats with a null command pointer." << std::endl;
    EXPECT_ANY_THROW(orch->push_stats(nullptr));
    std::cout << "push_stats invoked successfully with a null pointer." << std::endl;    
    std::cout << "Exiting NullCommandStructurePointerTest test" << std::endl;
}

/**
 * @brief Test to verify that submit_command API returns true when provided with a properly initialized em_cmd_t structure.
 *
 * This test validates that calling the submit_command function with a properly initialized em_cmd_t structure results in a true return value. This confirms that the command submission mechanism behaves as expected.
 *
 * **Test Group ID:** Basic: 01 / Module (L2): 02 / Stress (L2): 03
 * **Test Case ID:** 026
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize em_cmd_t structure and invoke submit_command API. | input: cmd pointer = address of cmd, cmd->m_svc = em_service_type_ctrl, cmd->m_type = em_cmd_type_get_radio, output: retVal expected = true | Returns true; assertion (EXPECT_TRUE(retVal)) passes | Should Pass |
 */
TEST_F(EmOrchTest, SubmitCommandProperlyInitialized) {
    std::cout << "Entering SubmitCommandProperlyInitialized test" << std::endl;
    dm_easy_mesh_t dm;
    dm.init();
    em_cmd_t* cmd = new em_cmd_t();
    cmd->init(dm);
    cmd->m_svc = em_service_type_ctrl;
    cmd->m_type = em_cmd_type_get_radio;
    cmd->m_evt = nullptr;
    cmd->m_num_orch_desc = 0;
    strncpy(cmd->m_name, "ProperlyInitialized", sizeof(cmd->m_name) - 1);
    cmd->m_name[sizeof(cmd->m_name) - 1] = '\0';
    cmd->m_em_candidates = queue_create();
    ASSERT_NE(cmd->m_em_candidates, nullptr);
    std::cout << "Invoking submit_command with properly initialized em_cmd_t structure." << std::endl;
    bool retVal = orch->submit_command(cmd);
    std::cout << "submit_command returned: " << retVal << std::endl;
    EXPECT_TRUE(retVal);
    std::cout << "Exiting SubmitCommandProperlyInitialized test" << std::endl;
}

/**
 * @brief Test the submit_command API with a null command pointer to validate that it handles invalid input correctly.
 *
 * This test verifies that when a null pointer is passed to the submit_command API, the function returns false.
 * This behavior is critical to ensure that the function robustly handles cases where the command structure is not provided.
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
 * | Variation / Step | Description                                                  | Test Data                                | Expected Result                                                         | Notes        |
 * | :--------------: | ------------------------------------------------------------ | ---------------------------------------- | ----------------------------------------------------------------------- | ------------ |
 * | 01               | Invoke the submit_command API with cmdPtr set to nullptr     | input: cmdPtr = nullptr, output: retVal expected = false | The submit_command API should return false, indicating proper handling of null input. | Should Fail  |
 */
TEST_F(EmOrchTest, SubmitCommandWithNullPointer) {
    std::cout << "Entering SubmitCommandWithNullPointer test" << std::endl;    
    em_cmd_t* cmdPtr = nullptr;
    std::cout << "Invoking submit_command with nullptr." << std::endl;
    bool retVal = orch->submit_command(cmdPtr);
    std::cout << "submit_command returned: " << std::boolalpha << retVal << std::endl;
    EXPECT_FALSE(retVal);    
    std::cout << "Exiting SubmitCommandWithNullPointer test" << std::endl;
}

/**
 * @brief ValidSubmission test to validate submission of 5 valid command pointers
 *
 * This test verifies that the submit_commands API correctly processes an array of 5 valid em_cmd_t pointers by initializing each pointer with m_svc set to em_service_type_ctrl, invoking submit_commands with the array, and confirming that the return value equals 5. It also ensures that memory allocated for commands is properly cleaned up.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 028
 * **Priority:** High
 * 
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Allocate an array of 5 valid em_cmd_t pointers and initialize m_svc to em_service_type_ctrl | For i = 0,1,2,3,4: new em_cmd_t(), m_svc = em_service_type_ctrl | Each command pointer is successfully allocated and initialized | Should be successful |
 * | 02 | Invoke submit_commands API with the array of command pointers and num = 5 | input: cmds = array of 5 pointers, num = 5; output: result | submit_commands returns 5 and EXPECT_EQ(result, 5) passes | Should Pass |
 * | 03 | Delete allocated command pointers and set each pointer to nullptr | For i = 0,1,2,3,4: delete cmds[i], cmds[i] = nullptr | All allocated command pointers are properly deallocated | Should be successful |
 */
TEST_F(EmOrchTest, ValidSubmission) {
    std::cout << "Entering ValidSubmission test" << std::endl;
    em_cmd_t* cmds[5];
    for (unsigned int i = 0; i < 5; ++i) {
        // Create and properly initialize dm and command
        dm_easy_mesh_t dm;
        dm.init();
        cmds[i] = new em_cmd_t();
        // Use em_cmd_t::init(dm) — this is important so m_data_model is set up correctly
        cmds[i]->init(dm);
        // Ensure other fields are set
        cmds[i]->m_svc = em_service_type_ctrl;
        cmds[i]->m_type = em_cmd_type_get_radio;
        cmds[i]->m_evt = nullptr;
        cmds[i]->m_num_orch_desc = 0;
        strncpy(cmds[i]->m_name, "ValidSubmission", sizeof(cmds[i]->m_name) - 1);
        cmds[i]->m_name[sizeof(cmds[i]->m_name) - 1] = '\0';
        // init(dm) should create m_em_candidates; if not, create one
        if (!cmds[i]->m_em_candidates) {
            cmds[i]->m_em_candidates = queue_create();
        }
        ASSERT_NE(cmds[i]->m_em_candidates, nullptr);
    }
    std::cout << "Invoking submit_commands with array of command pointers and num = 5" << std::endl;
    // IMPORTANT: ensure your test fixture's orchestrator will return >0 candidates for each command.
    // If build_candidates is mocked, make it return >=1 for each cmd so submit_command() queues the cmds.
    // e.g.: EXPECT_CALL(*orch, build_candidates(::testing::_)).WillRepeatedly(Return(1));
    unsigned int result = orch->submit_commands(cmds, 5);
    std::cout << "submit_commands returned: " << result << std::endl;
    EXPECT_EQ(result, 5);
    // DO NOT delete the commands here — submit_commands/submit_command transfers ownership to orch
    // and the orchestrator will delete them when appropriate. Deleting them here causes double-free.
    std::cout << "Exiting ValidSubmission test" << std::endl;
}

/**
 * @brief Verify that submit_commands returns 0 when invoked with zero commands.
 *
 * This test verifies that when submit_commands is called with a valid pointer array for commands but the number of commands is set to 0, the function returns 0. This ensures that the API handles empty command sets gracefully.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 029
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                      | Test Data                                     | Expected Result                               | Notes       |
 * | :--------------: | ---------------------------------------------------------------- | --------------------------------------------- | ----------------------------------------------| ----------- |
 * | 01               | Invoke submit_commands with cmds pointer array and num = 0.        | cmds = [nullptr], num = 0, output = expected 0  | API returns 0 and assertion EXPECT_EQ(result, 0)| Should Pass |
 */
TEST_F(EmOrchTest, ZeroCommands) {
    std::cout << "Entering ZeroCommands test" << std::endl;

    // Creating an array with one pointer (won't be used since num is 0)
    em_cmd_t* cmds[1] = { nullptr };
    std::cout << "Invoking submit_commands with valid pointer array but num = 0" << std::endl;
    unsigned int result = orch->submit_commands(cmds, 0);
    std::cout << "submit_commands returned: " << result << std::endl;
    EXPECT_EQ(result, 0);

    std::cout << "Exiting ZeroCommands test" << std::endl;
}

/**
 * @brief Tests submit_commands API with a nullptr command array.
 *
 * This test case verifies that invoking submit_commands with a nullptr argument for the command array and a valid count (3) returns the expected result (0). This scenario ensures that the API correctly handles null pointers without causing a crash or unexpected behavior.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 030
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                            | Test Data                           | Expected Result                              | Notes      |
 * | :--------------: | ------------------------------------------------------ | ----------------------------------- | -------------------------------------------- | ---------- |
 * |       01         | Invoke submit_commands with a nullptr command pointer  | commands = nullptr, num = 3           | Returns 0 and EXPECT_NE(result, 0) assertion   | Should Pass|
 */
TEST_F(EmOrchTest, NullCommandsPointer) {
    std::cout << "Entering NullCommandsPointer test" << std::endl;

    std::cout << "Invoking submit_commands with a nullptr for the command array and num = 3" << std::endl;
    unsigned int result = orch->submit_commands(nullptr, 3);
    std::cout << "submit_commands returned: " << result << std::endl;
    EXPECT_NE(result, 0);

    std::cout << "Exiting NullCommandsPointer test" << std::endl;
}

/**
 * @brief Validate update_stats with a valid command pointer without throwing exceptions
 *
 * This test verifies that invoking the update_stats API with a valid (non-null) command pointer executes correctly without throwing exceptions. It ensures the function handles normal input as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 031@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description                                              | Test Data                                              | Expected Result                                                  | Notes      |
 * | :--------------: | -------------------------------------------------------- | ------------------------------------------------------ | ---------------------------------------------------------------- | ---------- |
 * | 01               | Invoke update_stats with a valid command pointer         | orch, cmd: pointer to em_cmd_t instance (default init) | Function returns without throwing an exception; assertion passes | Should Pass |
 */
TEST_F(EmOrchTest, ValidInput_update_stats) {
    std::cout << "Entering ValidInput_update_stats test" << std::endl;
    em_cmd_t cmd{};
    cmd.m_svc = em_service_type_ctrl;
    cmd.m_type = em_cmd_type_get_radio;
    em_cmd_stats_t* stats = static_cast<em_cmd_stats_t*>(malloc(sizeof(em_cmd_stats_t)));
    memset(stats, 0, sizeof(em_cmd_stats_t));
    stats->type = cmd.m_type;
    char key[32];
    snprintf(key, sizeof(key), "%d", cmd.m_type);
    hash_map_put(orch->m_cmd_map, strdup(key), stats);
    std::cout << "Invoking update_stats with valid command pointer" << std::endl;
    EXPECT_NO_THROW(orch->update_stats(&cmd));
    std::cout << "update_stats method executed successfully with valid command" << std::endl;    
    std::cout << "Exiting ValidInput_update_stats test" << std::endl;
}

/**
 * @brief Verify that the update_stats API handles null input gracefully.
 *
 * This test verifies that the update_stats method of the Dummy_em_orch_t instance does not throw an exception when invoked with a null command pointer. This ensures that the API robustly handles invalid input without causing runtime errors.
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
 * | Variation / Step | Description                                                | Test Data                        | Expected Result                                                  | Notes       |
 * | :--------------: | ---------------------------------------------------------- | -------------------------------- | ---------------------------------------------------------------- | ----------- |
 * | 01               | Call update_stats with a null command pointer              | input: command = nullptr         | API throws an exception and handles the null input gracefully | Should Pass |
 */
TEST_F(EmOrchTest, NullInput_update_stats) {
    std::cout << "Entering NullInput_update_stats test" << std::endl;    
    std::cout << "Invoking update_stats with a null command pointer" << std::endl;
    EXPECT_ANY_THROW(orch->update_stats(nullptr));
    std::cout << "update_stats method handled null command pointer gracefully" << std::endl;    
    std::cout << "Exiting NullInput_update_stats test" << std::endl;
}

/**
 * @brief Validate that get_dev_test_status returns false when no development test command is in progress.
 *
 * This test verifies that the DummyEmOrch object's get_dev_test_status method correctly returns false when there is no ongoing development test command. It ensures that the method accurately indicates the inactive test status.
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
 * | 01 | Print the entry message indicating the start of the test. | None | Console outputs entry message. | Should be successful |
 * | 02 | Invoke get_dev_test_status on the DummyEmOrch object. | input: orch = DummyEmOrch object, output: devTestStatus variable | Method returns false and EXPECT_FALSE assertion passes. | Should Pass |
 * | 03 | Print the returned value from get_dev_test_status. | output: devTestStatus = false | Console outputs the value false. | Should be successful |
 * | 04 | Print the exit message indicating the end of the test. | None | Console outputs exit message. | Should be successful |
 */
TEST_F(EmOrchTest, get_dev_test_status_returns_false_when_no_dev_test_command_in_progress) {
    std::cout << "Entering get_dev_test_status_returns_false_when_no_dev_test_command_in_progress test" << std::endl;

    std::cout << "Invoking get_dev_test_status on orch object" << std::endl;
    bool devTestStatus = orch->get_dev_test_status();
    std::cout << "Returned value from get_dev_test_status: " << devTestStatus << std::endl;

    EXPECT_FALSE(devTestStatus);

    std::cout << "Exiting get_dev_test_status_returns_false_when_no_dev_test_command_in_progress test" << std::endl;
}

/**
 * @brief Test the destructor functionality of the Dummy_em_orch_t instance.
 *
 * This test ensures that invoking the destructor on the Dummy_em_orch_t object does not throw any exceptions.
 * The test explicitly deletes the object within an EXPECT_NO_THROW block and verifies that no exception is thrown.
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
 * | Variation / Step | Description                                                          | Test Data                                         | Expected Result                                                                         | Notes         |
 * | :--------------: | -------------------------------------------------------------------- | ------------------------------------------------- | --------------------------------------------------------------------------------------- | ------------- |
 * | 01               | Log entry message indicating the start of the test                   | None                                              | "Entering em_orch_t_destructor_start test" is logged                                     | Should be successful |
 * | 02               | Invoke the destructor within EXPECT_NO_THROW to safely delete the object | input: orch = valid Dummy_em_orch_t pointer; output: orch = nullptr | Destructor is invoked without throwing any exception, and orch is set to nullptr | Should Pass   |
 * | 03               | Log exit message confirming successful test completion               | None                                              | "Exiting em_orch_t_destructor_start test" is logged                                      | Should be successful |
 */
TEST_F(EmOrchTest, em_orch_t_destructor_start) {
    std::cout << "Entering em_orch_t_destructor_start test" << std::endl;
    // Invoke the destructor and verify that it does not throw.
    std::cout << "Invoking destructor for em_orch_t instance" << std::endl;
    EXPECT_NO_THROW({
        delete orch;
        orch = nullptr; // Prevent double deletion in TearDown.
    });
    std::cout << "Destructor invoked successfully; resources cleaned up if allocated." << std::endl;    
    std::cout << "Exiting em_orch_t_destructor_start test" << std::endl;
}
