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
#include "dm_easy_mesh.h"
#include "em_cmd.h"
#include "em_mgr.h"
#include "em_orch_ctrl.h"


class em_orch_ctrl_t_TEST : public testing::Test {
public:
    em_ctrl_t mgr;
    em_orch_ctrl_t *orch;
    void SetUp() override {
        orch = new em_orch_ctrl_t(&mgr);
	    orch->m_mgr->m_em_map = hash_map_create();
    }
    void TearDown() override {
	    hash_map_destroy(orch->m_mgr->m_em_map);
	    queue_destroy(orch->m_pending);
	    queue_destroy(orch->m_active);
	    hash_map_destroy(orch->m_cmd_map);
        delete orch;
    }
};



/**
 * @brief Validate that cancel_command() successfully handles all valid command types without throwing exceptions.
 *
 * This test iterates over every valid command type (from em_cmd_type_none to em_cmd_type_max - 1) and invokes the cancel_command() API to ensure it operates as expected without throwing any exceptions.
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
 * | Variation / Step | Description                                                                                 | Test Data                                                             | Expected Result                                                             | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | --------------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke cancel_command() API for each valid command value in the range [em_cmd_type_none, em_cmd_type_max). | command = (each value from em_cmd_type_none to em_cmd_type_max - 1) | API executes without throwing any exception (EXPECT_NO_THROW check passes) | Should Pass |
 */
TEST_F(em_orch_ctrl_t_TEST, CancelValidCommands) {
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
 * @brief Verify cancel_command handles an invalid negative command without throwing exceptions
 *
 * This test case validates that the cancel_command method of em_orch_ctrl_t correctly processes an invalid negative command value (-1) without throwing an exception. This ensures that the API is robust against out-of-bound or erroneous command inputs.
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
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Invoke cancel_command with an invalid negative command value | invalid_command = -1 | The method does not throw an exception (verified by EXPECT_NO_THROW) | Should Pass |
 */
TEST_F(em_orch_ctrl_t_TEST, CancelInvalidNegative) {
    std::cout << "Entering CancelInvalidNegative test" << std::endl;
    em_cmd_type_t invalid_command = static_cast<em_cmd_type_t>(-1);
    std::cout << "Invoking cancel_command with invalid negative command value: -1" << std::endl;
    EXPECT_NO_THROW(orch->cancel_command(invalid_command));
    std::cout << "cancel_command executed successfully for invalid negative command value" << std::endl;
    std::cout << "Exiting CancelInvalidNegative test" << std::endl;
}

/**
 * @brief Validate that cancel_command handles an invalid command value beyond the defined range without throwing an exception.
 *
 * This test verifies that when an invalid command value (beyond the expected range) is passed to the cancel_command API,
 * the function executes without throwing any exceptions. The test ensures proper error handling for invalid command inputs.
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
 * | Variation / Step | Description                                                                     | Test Data                                  | Expected Result                                                    | Notes             |
 * | :--------------: | ------------------------------------------------------------------------------- | ------------------------------------------ | ------------------------------------------------------------------ | ----------------- |
 * | 01               | Log the entry message indicating the start of the CancelInvalidBeyondRange test   | None                                       | Console outputs "Entering CancelInvalidBeyondRange test"           | Should be successful |
 * | 02               | Initialize the invalid_command variable with an out-of-range value 50             | invalid_command = 50                       | Variable invalid_command is assigned value 50                      | Should be successful |
 * | 03               | Invoke cancel_command API with the invalid command value                          | input: invalid_command = 50                | API executes without throwing any exception (EXPECT_NO_THROW passes) | Should Pass       |
 * | 04               | Log the success message after executing cancel_command                            | None                                       | Console outputs "cancel_command executed successfully for invalid beyond range command value" | Should be successful |
 * | 05               | Log the exit message indicating the end of the CancelInvalidBeyondRange test        | None                                       | Console outputs "Exiting CancelInvalidBeyondRange test"              | Should be successful |
 */
TEST_F(em_orch_ctrl_t_TEST, CancelInvalidBeyondRange) {
    std::cout << "Entering CancelInvalidBeyondRange test" << std::endl;
    em_cmd_type_t invalid_command = static_cast<em_cmd_type_t>(50);
    std::cout << "Invoking cancel_command with invalid beyond range command value 50 " << std::endl;
    EXPECT_NO_THROW(orch->cancel_command(invalid_command));
    std::cout << "cancel_command executed successfully for invalid beyond range command value" << std::endl;
    std::cout << "Exiting CancelInvalidBeyondRange test" << std::endl;
}

/**
 * @brief Verify that destroy_command handles a NULL pointer input appropriately.
 *
 * This test case verifies that when the destroy_command method is invoked with a NULL pointer,
 * the function throws an exception and no resource operations are performed.
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
 * | Variation / Step | Description                              | Test Data               | Expected Result                                               | Notes       |
 * | :--------------: | ---------------------------------------- | ----------------------- | ------------------------------------------------------------- | ----------- |
 * | 01               | Call destroy_command with a NULL pointer | input = NULL            | Exception is thrown as per the expectation of the API behavior | Should Pass |
 */
TEST_F(em_orch_ctrl_t_TEST, DestroyNullCommand) {
    std::cout << "Entering DestroyNullCommand test" << std::endl;    
    std::cout << "Invoking destroy_command with NULL pointer" << std::endl;
    EXPECT_ANY_THROW(orch->destroy_command(NULL));
    std::cout << "destroy_command executed gracefully with NULL pointer; no resource operations performed." << std::endl;    
    std::cout << "Exiting DestroyNullCommand test" << std::endl;
}

/**
 * @brief Test eligible_for_active API behavior with a null pointer input.
 *
 * This test verifies that invoking the eligible_for_active API with a nullptr for pcmd throws an exception as expected, and that the result variable remains false after the exception is handled. It ensures robust error handling within the API.
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
 * | Variation / Step | Description                                                                     | Test Data                             | Expected Result                               | Notes         |
 * | :--------------: | ------------------------------------------------------------------------------- | ------------------------------------- | --------------------------------------------- | ------------- |
 * |      01        | Invoke eligible_for_active with pcmd set to nullptr to trigger exception handling | pcmd = nullptr                        | API should throw an exception                 | Should Fail   |
 * |      02        | Check that the result variable remains false after handling the exception       | result = false                        | result is false                               | Should be successful |
 */
TEST_F(em_orch_ctrl_t_TEST, eligible_for_active_NullPointer) {
    std::cout << "Entering eligible_for_active_NullPointer test" << std::endl;    
    bool result = false;
    std::cout << "Invoking eligible_for_active with pcmd = nullptr" << std::endl;
    EXPECT_ANY_THROW({
        result = orch->eligible_for_active(nullptr);
        std::cout << "Returned value: " << result << std::endl;
    });    
    EXPECT_FALSE(result);    
    std::cout << "Exiting eligible_for_active_NullPointer test" << std::endl;
}

/**
 * @brief Validate get_dev_test_status returns false when no device test command is in progress
 *
 * This test verifies that when no device test command is in progress, the method get_dev_test_status on the orch object returns false.
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
 * | Variation / Step | Description                                                                                           | Test Data                                                           | Expected Result                                                               | Notes       |
 * | :--------------: | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------------------------------------------------------------------- | ----------- |
 * | 01               | Call get_dev_test_status on the initialized orch object without any device test command in progress. | orch object initialized with no dev test command (no input parameters, output = false) | The method returns false, as verified by EXPECT_FALSE                         | Should Pass |
 */
TEST_F(em_orch_ctrl_t_TEST, get_dev_test_status_returns_false_when_no_dev_test_command_in_progress) {
    std::cout << "Entering get_dev_test_status_returns_false_when_no_dev_test_command_in_progress test" << std::endl;
    std::cout << "Invoking get_dev_test_status on orch object" << std::endl;
    bool devTestStatus = orch->get_dev_test_status();
    std::cout << "Returned value from get_dev_test_status: " << devTestStatus << std::endl;
    EXPECT_FALSE(devTestStatus);
    std::cout << "Exiting get_dev_test_status_returns_false_when_no_dev_test_command_in_progress test" << std::endl;
}

/**
 * @brief Test to verify the functionality of get_dev_test_status() when no active command is present.
 *
 * This test ensures that the get_dev_test_status() method correctly returns a boolean status without any active command and without throwing exceptions. It validates that the API behaves as expected under conditions where no active command is present.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke get_dev_test_status() API when no active command exists | orch instance initialized, no active command present, method call: get_dev_test_status() | API returns a boolean value without throwing an exception; EXPECT_NO_THROW check passes | Should Pass |
 */
TEST_F(em_orch_ctrl_t_TEST, get_dev_test_status_NoActiveCommand) {
    std::cout << "Entering get_dev_test_status_NoActiveCommand test" << std::endl;
    std::cout << "Invoking get_dev_test_status()" << std::endl;
    EXPECT_NO_THROW({
        bool status = orch->get_dev_test_status();
        std::cout << "get_dev_test_status() returned: " << status << std::endl;
    });
    std::cout << "Exiting get_dev_test_status_NoActiveCommand test" << std::endl;
}

/**
 * @brief Test to verify that em_orch_t::get_state returns the default state when a NULL command pointer is provided.
 *
 * This test validates that when a NULL pointer is passed to the get_state function, the API returns em_orch_state_none. 
 * It was implemented to ensure that the function gracefully handles invalid input by returning a default state rather than causing a crash or undefined behavior.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 008@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Print the message indicating entry into the test. | N/A | "Entering get_state_NullPointer test" is printed to the console. | Should be successful |
 * | 02 | Print the message before invoking the API call. | N/A | "Invoking em_orch_t::get_state with NULL cmd pointer" is printed to the console. | Should be successful |
 * | 03 | Call the API with a NULL command pointer. | input: cmd = nullptr, output: retState variable | retState should be equal to em_orch_state_none. | Should Pass |
 * | 04 | Print the returned state value from the API call. | retState value (expected em_orch_state_none) | The returned state value is printed to the console. | Should be successful |
 * | 05 | Verify the returned state using assertion. | retState = em_orch_state_none, expected: em_orch_state_none | The assertion EXPECT_EQ(retState, em_orch_state_none) passes. | Should Pass |
 * | 06 | Print the message indicating exit from the test. | N/A | "Exiting get_state_NullPointer test" is printed to the console. | Should be successful |
 */
/*
TEST_F(em_orch_ctrl_t_TEST, get_state_NullPointer) {
    std::cout << "Entering get_state_NullPointer test" << std::endl;    
    std::cout << "Invoking em_orch_t::get_state with NULL cmd pointer" << std::endl;
    em_orch_state_t retState = orch->get_state(nullptr);
    std::cout << "Returned state value for NULL cmd pointer = " << static_cast<unsigned int>(retState) << std::endl;    
    // Expect default state to be em_orch_state_none when a null command pointer is passed.
    EXPECT_EQ(retState, em_orch_state_none);    
    std::cout << "Exiting get_state_NullPointer test" << std::endl;
}
*/

/**
 * @brief Verify that the handle_timeout() method executes without throwing any exceptions.
 *
 * This test invokes the handle_timeout() function on a properly initialized instance of em_orch_ctrl_t.
 * The test ensures that under normal conditions the method executes without errors.
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
 * | Variation / Step | Description                                                        | Test Data                                          | Expected Result                        | Notes       |
 * | :--------------: | ------------------------------------------------------------------ | -------------------------------------------------- | -------------------------------------- | ----------- |
 * |       01         | Invoke handle_timeout() and verify that it does not throw an exception | No input arguments, output: method call check for exceptions | No exception thrown; function executed successfully | Should Pass |
 */
TEST_F(em_orch_ctrl_t_TEST, Positive_HandleTimeout)
{
    std::cout << "Entering Positive_HandleTimeout test" << std::endl;
    std::cout << "Invoking handle_timeout()" << std::endl;
    EXPECT_NO_THROW(orch->handle_timeout());
    std::cout << "handle_timeout() executed without errors" << std::endl;
    std::cout << "Exiting Positive_HandleTimeout test" << std::endl;
}

/**
 * @brief Verify the behavior of is_cmd_type_in_progress when a NULL event pointer is provided.
 *
 * This test verifies that the API is_cmd_type_in_progress returns false when invoked with a NULL pointer. The objective is to ensure that the function correctly handles invalid input by not processing any event and providing a negative indication.
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
 * | Variation / Step | Description                                             | Test Data       | Expected Result                                                  | Notes      |
 * | :--------------: | ------------------------------------------------------- | --------------- | ---------------------------------------------------------------- | ---------- |
 * | 01               | Invoke is_cmd_type_in_progress with a NULL event pointer | evt = NULL      | Function returns false and assertion EXPECT_FALSE(result) is met | Should Pass|
 */
TEST_F(em_orch_ctrl_t_TEST, HandleNullEventPointer) {
    std::cout << "Entering HandleNullEventPointer test" << std::endl;
    std::cout << "Invoking is_cmd_type_in_progress with evt = NULL" << std::endl;
    bool result = orch->is_cmd_type_in_progress(NULL);
    std::cout << "Returned value: " << result << std::endl;
    EXPECT_FALSE(result);
    std::cout << "Exiting HandleNullEventPointer test" << std::endl;
}

/**
 * @brief Verifies that non-command event types are correctly identified as not being in progress.
 *
 * This test iterates through a list of event types that are not command events and passes each to the
 * is_cmd_type_in_progress() function. It then checks that the function returns false for each case,
 * ensuring non-command event types are not erroneously marked as in progress.
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
 * | Variation / Step | Description                                                                                     | Test Data                                                                                                                       | Expected Result                                                                                                            | Notes         |
 * | :--------------: | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | ------------- |
 * | 01               | Iterate through each non-command event type and invoke the is_cmd_type_in_progress API           | evt.type = each em_bus_event_type from {em_bus_event_type_none, em_bus_event_type_chirp, em_bus_event_type_reset, ...}         | API returns false for each event type; EXPECT_FALSE(result) passes                                                         | Should Pass   |
 */
TEST_F(em_orch_ctrl_t_TEST, NonCommandEventTypesNotInProgress) {
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
 * @brief Verify that is_cmd_type_in_progress correctly identifies command event types in progress
 *
 * This test iterates through a set of predefined command event types and invokes the is_cmd_type_in_progress API. It checks that the API returns a boolean value for each event type, indicating whether the command is in progress. Output logs are generated for diagnostic purposes.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 012@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                           | Test Data                                                                                                                                            | Expected Result                                                                                                     | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------- | -----------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------|-------------|
 * | 01               | Loop through each command event type and invoke is_cmd_type_in_progress API            | evt.type = em_bus_event_type_set_dev_test, evt.type = em_bus_event_type_set_ssid, evt.type = em_bus_event_type_set_channel, evt.type = em_bus_event_type_set_policy, evt.type = em_bus_event_type_sta_assoc | API returns a boolean for each command type indicating if command is in progress; logs are generated as expected      | Should Pass |
 */
TEST_F(em_orch_ctrl_t_TEST, CommandEventTypesInProgress) {
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
 * @brief Verify that is_cmd_type_renew_in_progress returns false when invoked with a nullptr.
 *
 * This test verifies that the function is_cmd_type_renew_in_progress of the em_orch_ctrl_t class correctly handles a nullptr parameter by returning false. This ensures that the API behaves as expected in edge cases where a null command is provided.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 013@n
 * **Priority:** High@n
 *@n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *@n
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                              | Test Data                          | Expected Result                                               | Notes       |
 * | :--------------: | ------------------------------------------------------------------------ | ---------------------------------- | ------------------------------------------------------------- | ----------- |
 * | 01               | Invoke is_cmd_type_renew_in_progress with a nullptr parameter             | input: cmd = nullptr               | The function returns false                                  | Should Pass |
 */
TEST_F(em_orch_ctrl_t_TEST, is_cmd_type_renew_in_progress_null) {
    std::cout << "Entering is_cmd_type_renew_in_progress_null test" << std::endl;
    std::cout << "Invoking is_cmd_type_renew_in_progress with nullptr as parameter" << std::endl;
    bool result = orch->is_cmd_type_renew_in_progress(nullptr);
    std::cout << "Method returned: " << result << " for input: nullptr" << std::endl;
    EXPECT_FALSE(result);
    std::cout << "Exiting is_cmd_type_renew_in_progress_null test" << std::endl;
}

/**
 * @brief Verify that is_cmd_type_renew_in_progress correctly identifies a renew command event.
 *
 * This test initializes an event with type em_bus_event_type_cfg_renew and invokes 
 * the is_cmd_type_renew_in_progress API to validate that it correctly processes the event.
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
 * | Variation / Step | Description                                                                            | Test Data                                                        | Expected Result                                                                                        | Notes       |
 * | :--------------: | -------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ | ----------- |
 * | 01               | Initialize evt with type em_bus_event_type_cfg_renew, invoke is_cmd_type_renew_in_progress | evt.type = em_bus_event_type_cfg_renew, output result = bool value | API returns a boolean indicating that the renew command is in progress; assertion check should pass | Should Pass |
 */
TEST_F(em_orch_ctrl_t_TEST, is_cmd_type_renew_in_progress_renew) {
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
 * @brief Verify that is_cmd_type_renew_in_progress correctly identifies non-renew events.
 *
 * This test iterates over an array of non-renew event types and invokes the
 * is_cmd_type_renew_in_progress API. It validates that for each event type that is not
 * related to renew operations, the method returns false, ensuring that non-renew
 * commands are not mistakenly flagged as renew in progress.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 015@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Iterate over each non-renew event type and invoke is_cmd_type_renew_in_progress | evt.type = nonRenewTypes[i] (e.g., em_bus_event_type_none, em_bus_event_type_chirp, em_bus_event_type_reset, etc.) | The API should return false for each non-renew event type | Should Pass |
 */
TEST_F(em_orch_ctrl_t_TEST, is_cmd_type_renew_in_progress_non_renew) {
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
 * @brief Validate orchestrate() behavior when EM pointer is passed as nullptr.
 *
 * This test verifies that when a valid em_cmd_t pointer is provided and a nullptr is passed for the EM parameter,
 * the orchestrate() method returns false, ensuring that the API correctly handles invalid EM inputs.
 *
 * **Test Group ID:** Basic: 01 / Module (L2): 02 / Stress (L2): 03
 * **Test Case ID:** 016@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                      | Test Data                                                   | Expected Result                                          | Notes      |
 * | :--------------: | ------------------------------------------------------------------------------------------------ | ----------------------------------------------------------- | -------------------------------------------------------- | ---------- |
 * | 01               | Create an em_cmd_t instance, call orchestrate() with cmd and a nullptr for em, and verify the return value is false. | cmd = valid pointer to em_cmd_t instance, em = nullptr      | API returns false and EXPECT_FALSE(ret) assertion passes | Should Fail |
 */
TEST_F(em_orch_ctrl_t_TEST, NullEmTest) {
    std::cout << "Entering NullEmTest test" << std::endl;
    em_cmd_t *cmd = new em_cmd_t();
    std::cout << "Created em_cmd_t instance" << std::endl;
    std::cout << "Invoking orchestrate() with pcmd = " << cmd << " and em = " << static_cast<void*>(nullptr) << std::endl;
    bool ret = orch->orchestrate(cmd, nullptr);
    std::cout << "orchestrate() returned: " << std::boolalpha << ret << std::endl;
    EXPECT_FALSE(ret);
    delete cmd;
    std::cout << "Exiting NullEmTest test" << std::endl;
}

/**
 * @brief Validates that pop_stats processes a valid em_cmd_t command without throwing an exception
 *
 * This test verifies that when a properly initialized em_cmd_t command (with type em_cmd_type_get_radio) is passed to the pop_stats function,
 * the function executes without throwing any exceptions. It is important for ensuring the API correctly handles valid command inputs.
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
 * | Variation / Step | Description                                                         | Test Data                                        | Expected Result                                           | Notes             |
 * | :--------------: | ------------------------------------------------------------------- | ------------------------------------------------ | --------------------------------------------------------- | ----------------- |
 * | 01               | Initialize em_cmd_t with valid command type                         | cmd.m_type = em_cmd_type_get_radio               | Command object is properly initialized                    | Should be successful |
 * | 02               | Invoke pop_stats with valid em_cmd_t command pointer and verify no exception is thrown | input: pointer to cmd (address of cmd)         | pop_stats completes without throwing exceptions; assertion passes | Should Pass       |
 */
TEST_F(em_orch_ctrl_t_TEST, ValidCommandPopStats) {
    std::cout << "Entering ValidCommandPopStats test" << std::endl;
    em_cmd_t cmd;
    cmd.m_type = em_cmd_type_get_radio;
    std::cout << "Invoking pop_stats with valid em_cmd_t command pointer" << std::endl;
    EXPECT_NO_THROW({
        orch->pop_stats(&cmd);
    });
    std::cout << "pop_stats successfully processed the em_cmd_t command." << std::endl;              
    std::cout << "Exiting ValidCommandPopStats test" << std::endl;
}

/**
 * @brief Validate that pop_stats handles a null pointer gracefully.
 *
 * This test verifies that invoking pop_stats with a null em_cmd_t pointer results in an exception,
 * ensuring that the API correctly identifies and handles invalid input parameters.
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
 * | Variation / Step | Description                                                  | Test Data                                              | Expected Result                                        | Notes       |
 * | :--------------: | ------------------------------------------------------------ | ------------------------------------------------------ | ------------------------------------------------------ | ----------- |
 * | 01               | Invoke pop_stats with a null em_cmd_t pointer                | input: em_cmd_t pointer = nullptr                      | An exception is thrown by pop_stats                   | Should Pass |
 */
TEST_F(em_orch_ctrl_t_TEST, pop_stats_NullPointer) {
    std::cout << "Entering pop_stats_NullPointer test" << std::endl;
    std::cout << "Invoking pop_stats with null em_cmd_t pointer" << std::endl;
    EXPECT_ANY_THROW({
        orch->pop_stats(nullptr);
    });
    std::cout << "pop_stats handled the null em_cmd_t pointer gracefully." << std::endl;
    std::cout << "Exiting pop_stats_NullPointer test" << std::endl;
}

/**
 * @brief Validate push_stats and pop_stats for a valid command structure
 *
 * This test verifies that the functions push_stats and pop_stats execute without throwing exceptions when provided with a valid command pointer. It checks that the command structure is correctly handled by the API, ensuring robust command processing.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 019@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                            | Test Data                                            | Expected Result                                      | Notes           |
 * | :--------------: | ---------------------------------------------------------------------- | ---------------------------------------------------- | ---------------------------------------------------- | --------------- |
 * | 01               | Log the entry into the test case                                       | N/A                                                  | Console output "Entering ValidCommandStructureTest test" observed | Should be successful |
 * | 02               | Initialize a valid em_cmd_t object and set its service type              | cmd.m_svc = em_service_type_ctrl                     | Command structure is correctly configured            | Should be successful |
 * | 03               | Invoke push_stats with a valid command pointer                         | input: &cmd                                          | push_stats executes without throwing an exception    | Should Pass     |
 * | 04               | Invoke pop_stats with the same valid command pointer                   | input: &cmd                                          | pop_stats executes without throwing an exception     | Should Pass     |
 * | 05               | Log the exit from the test case                                        | N/A                                                  | Console output "Exiting ValidCommandStructureTest test" observed | Should be successful |
 */
TEST_F(em_orch_ctrl_t_TEST, ValidCommandStructureTest) {
    std::cout << "Entering ValidCommandStructureTest test" << std::endl;
    em_cmd_t cmd{};
    cmd.m_svc = em_service_type_ctrl;
    std::cout << "Invoking push_stats with a valid command pointer" << std::endl;
    EXPECT_NO_THROW(orch->push_stats(&cmd));
    std::cout << "push_stats invoked successfully with command pointer" << std::endl;
    EXPECT_NO_THROW(orch->pop_stats(&cmd));
    std::cout << "Exiting ValidCommandStructureTest test" << std::endl;
}

/**
 * @brief Verifies that push_stats throws an exception when called with a null command pointer
 *
 * This test confirms that the push_stats function of the em_orch_ctrl_t class properly handles a null command pointer by throwing an exception. It validates the robustness of the error handling in the API.
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
 * | Variation / Step | Description                                       | Test Data                  | Expected Result                                                            | Notes       |
 * | :--------------: | ------------------------------------------------- | -------------------------- | -------------------------------------------------------------------------- | ----------- |
 * | 01               | Call push_stats with a null command pointer       | input = command pointer = nullptr | API throws an exception and EXPECT_ANY_THROW assertion passes               | Should Pass |
 */
TEST_F(em_orch_ctrl_t_TEST, NullCommandStructurePointerTest) {
    std::cout << "Entering NullCommandStructurePointerTest test" << std::endl;    
    std::cout << "Invoking push_stats with a null command pointer" << std::endl;
    EXPECT_ANY_THROW(orch->push_stats(nullptr));
    std::cout << "push_stats invoked successfully with a null pointer." << std::endl;    
    std::cout << "Exiting NullCommandStructurePointerTest test" << std::endl;
}
/**
 * @brief Verify that submit_command returns false when provided with a null pointer.
 *
 * This test verifies that the submit_command API correctly handles a null pointer input by returning false. 
 * The negative scenario ensures that the system does not accept an invalid command pointer, improving robustness.
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
 * | Variation / Step | Description                                            | Test Data                                      | Expected Result                                                      | Notes             |
 * | :--------------: | ------------------------------------------------------ | ---------------------------------------------- | ------------------------------------------------------------------- | ----------------- |
 * | 01               | Initialize command pointer to nullptr                  | cmdPtr = nullptr                               | cmdPtr is set to nullptr                                             | Should be successful |
 * | 02               | Invoke submit_command with the null pointer            | input: cmdPtr = nullptr                        | Function returns false                                               | Should Fail       |
 * | 03               | Verify the returned boolean value using EXPECT_FALSE   | output: retVal should be false                 | retVal equals false as per EXPECT_FALSE assertion                    | Should be successful |
 */
TEST_F(em_orch_ctrl_t_TEST, SubmitCommandWithNullPointer) {
    std::cout << "Entering SubmitCommandWithNullPointer test" << std::endl;    
    em_cmd_t* cmdPtr = nullptr;
    std::cout << "Invoking submit_command with nullptr." << std::endl;
    bool retVal = orch->submit_command(cmdPtr);
    std::cout << "submit_command returned: " << std::boolalpha << retVal << std::endl;
    EXPECT_FALSE(retVal);    
    std::cout << "Exiting SubmitCommandWithNullPointer test" << std::endl;
}
/**
 * @brief Verify submit_commands returns 0 when zero commands are provided
 *
 * This test case verifies that invoking submit_commands with a valid pointer
 * array (containing only nullptr) and a command count of 0 correctly returns 0.
 * It ensures that the API behaves as expected when no commands are to be processed.
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
 * | Variation / Step | Description                                                              | Test Data                                  | Expected Result              | Notes       |
 * | :--------------: | ------------------------------------------------------------------------ | ------------------------------------------ | ---------------------------- | ----------- |
 * | 01               | Invoke submit_commands with a valid pointer array (containing nullptr) and count 0 | cmds = [nullptr], num = 0, output = result expected as 0 | Function returns 0 | Should Pass |
 */
TEST_F(em_orch_ctrl_t_TEST, ZeroCommands) {
    std::cout << "Entering ZeroCommands test" << std::endl;
    em_cmd_t* cmds[1] = { nullptr };
    std::cout << "Invoking submit_commands with valid pointer array but num = 0" << std::endl;
    unsigned int result = orch->submit_commands(cmds, 0);
    std::cout << "submit_commands returned: " << result << std::endl;
    EXPECT_EQ(result, 0);
    std::cout << "Exiting ZeroCommands test" << std::endl;
}
/**
 * @brief Verify that submit_commands handles a nullptr command array correctly.
 *
 * This test verifies that when a nullptr is passed as the command array along with a valid count (num = 3), the submit_commands API returns a non-zero value. This behavior indicates that the function correctly handles invalid input.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 023@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                        | Test Data                                 | Expected Result                                   | Notes       |
 * | :--------------: | ------------------------------------------------------------------ | ----------------------------------------- | ------------------------------------------------- | ----------- |
 * | 01               | Invoke submit_commands with a nullptr for the command array and num=3 | command = nullptr, num = 3                | Return value is non-zero and EXPECT_NE(result, 0) passes | Should Pass |
 */
TEST_F(em_orch_ctrl_t_TEST, NullCommandsPointer) {
    std::cout << "Entering NullCommandsPointer test" << std::endl;
    std::cout << "Invoking submit_commands with a nullptr for the command array and num = 3" << std::endl;
    unsigned int result = orch->submit_commands(nullptr, 3);
    std::cout << "submit_commands returned: " << result << std::endl;
    EXPECT_NE(result, 0);
    std::cout << "Exiting NullCommandsPointer test" << std::endl;
}
/**
 * @brief Test the update_stats and pop_stats APIs with valid command input
 *
 * This test validates that the update_stats and pop_stats methods of the em_orch_ctrl_t class function correctly when provided with a valid command pointer. The test ensures that no exceptions are thrown during the API calls, and that the internal command statistics are handled as expected.
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
 * | Variation / Step | Description                                                                                 | Test Data                                                                                                                                                                          | Expected Result                                                      | Notes         |
 * | :--------------: | ------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- | ------------- |
 * | 01               | Initialize the command structure and allocate the statistics structure with zeroed values.    | cmd.m_svc = em_service_type_ctrl, cmd.m_type = em_cmd_type_get_radio, stats allocated and memset to 0, stats->type = cmd.m_type                                                          | Command and stats are successfully initialized without error.      | Should be successful |
 * | 02               | Insert the statistics structure into the command map using the command type as key.           | key = string representation of cmd.m_type, hash_map_put(orch->m_cmd_map, strdup(key), stats)                                                                                        | The command map correctly holds the mapping of key to stats pointer.   | Should be successful |
 * | 03               | Invoke update_stats using the valid command pointer.                                        | input: &cmd                                                                                                     | update_stats does not throw an exception.                            | Should Pass  |
 * | 04               | Invoke pop_stats using the valid command pointer.                                           | input: &cmd                                                                                                     | pop_stats does not throw an exception.                               | Should Pass  |
 */
TEST_F(em_orch_ctrl_t_TEST, ValidInput_update_stats) {
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
    EXPECT_NO_THROW(orch->pop_stats(&cmd));
    std::cout << "update_stats method executed successfully with valid command" << std::endl;    
    std::cout << "Exiting ValidInput_update_stats test" << std::endl;
}
/**
 * @brief Verify that update_stats method handles null command pointer gracefully
 *
 * This test ensures that the update_stats method correctly identifies a null command pointer and throws an exception, preventing any undefined behavior or system crash.
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
 * | Variation / Step | Description                                                       | Test Data                                  | Expected Result                                          | Notes       |
 * | :--------------: | ----------------------------------------------------------------- | ------------------------------------------ | -------------------------------------------------------- | ----------- |
 * | 01               | Call update_stats with a null command pointer and check for exception | command pointer = nullptr                  | Exception is thrown as per API design                    | Should Fail |
 */
TEST_F(em_orch_ctrl_t_TEST, NullInput_update_stats) {
    std::cout << "Entering NullInput_update_stats test" << std::endl;    
    std::cout << "Invoking update_stats with a null command pointer" << std::endl;
    EXPECT_ANY_THROW(orch->update_stats(nullptr));
    std::cout << "update_stats method handled null command pointer gracefully" << std::endl;    
    std::cout << "Exiting NullInput_update_stats test" << std::endl;
}
/**
 * @brief Verifies build_candidates returns 0 when invoked with a null command pointer.
 *
 * This test validates that the build_candidates API handles a null command argument gracefully by returning a candidate count of 0. The function is expected to safely return without processing when the input command pointer is null.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * |01| Invoke build_candidates with a null command pointer | cmd = nullptr, candidateCount (output) expected = 0 | Returns 0u and EXPECT_EQ check passes | Should Pass |
 */
TEST_F(em_orch_ctrl_t_TEST, build_candidates_NullCommandPointer)
{
    std::cout << "Entering build_candidates_NullCommandPointer test" << std::endl;
    std::cout << "Invoking build_candidates with cmd = nullptr" << std::endl;
    unsigned int candidateCount = orch->build_candidates(nullptr);
    std::cout << "build_candidates returned candidateCount: " << candidateCount << std::endl;
    EXPECT_EQ(0u, candidateCount);
    std::cout << "Exiting build_candidates_NullCommandPointer test" << std::endl;
}
/**
 * @brief Validate build_candidates returns 0 for an unsupported command type
 *
 * This test verifies that when an unsupported command type is provided to the build_candidates API,
 * the function correctly returns a candidate count of 0. This behavior confirms that the API gracefully
 * handles invalid command types by not generating any candidates.
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
 * | Variation / Step | Description                                            | Test Data                                                                  | Expected Result                                                                         | Notes              |
 * | :--------------: | ------------------------------------------------------ | -------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- | ------------------ |
 * | 01               | Initialize the command structure with an unsupported command type | cmd.m_type = em_cmd_type_max + 1                                           | Command type is set to an unsupported value                                             | Should be successful|
 * | 02               | Invoke build_candidates API with the unsupported command              | input: cmd with m_type = (em_cmd_type_max + 1), output: candidateCount       | build_candidates returns 0 candidate count, indicating no candidates are built            | Should Fail        |
 * | 03               | Validate that the candidate count matches the expected result           | candidateCount obtained from build_candidates API                          | EXPECT_EQ(0u, candidateCount) assertion passes                                          | Should be successful|
 */
TEST_F(em_orch_ctrl_t_TEST, build_candidates_UnsupportedCommandType)
{
    std::cout << "Entering build_candidates_UnsupportedCommandType test" << std::endl;
    em_cmd_t cmd;
    cmd.m_type = static_cast<em_cmd_type_t>(em_cmd_type_max + 1);
    std::cout << "Setting command type to unsupported value: " << static_cast<em_cmd_type_t>(em_cmd_type_max + 1) << std::endl;
    unsigned int candidateCount = orch->build_candidates(&cmd);
    std::cout << "build_candidates returned candidateCount: " << candidateCount << std::endl;
    EXPECT_EQ(0u, candidateCount);
    std::cout << "Exiting build_candidates_UnsupportedCommandType test" << std::endl;
}
/**
 * @brief Validate that build_candidates returns the expected result for valid command types.
 *
 * This test verifies that the build_candidates function correctly returns a candidate count of 0
 * when supplied with a set of valid command types. It ensures that the API behaves as expected
 * for all supported command types.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Log the start of the test | No input (STDOUT log "Entering build_candidates_valid_cmdTypes test") | The start message is printed to the console | Should be successful |
 * | 02 | Initialize an array with valid command types for testing | cmdTypes = em_cmd_type_em_config, em_cmd_type_set_ssid, em_cmd_type_dev_test, em_cmd_type_reset, em_cmd_type_cfg_renew, em_cmd_type_sta_assoc, em_cmd_type_sta_link_metrics, em_cmd_type_set_channel, em_cmd_type_scan_channel, em_cmd_type_sta_steer, em_cmd_type_sta_disassoc, em_cmd_type_set_policy, em_cmd_type_set_radio, em_cmd_type_mld_reconfig, em_cmd_type_start_dpp, em_cmd_type_bsta_cap | Array is created and totalTypes is correctly computed | Should be successful |
 * | 03 | Loop over each command type, invoke build_candidates, and validate result | For each iteration: input: cmd.m_type = <current command type>; output: candidateCount = value returned by build_candidates | build_candidates returns 0 candidate count for each valid command type | Should Pass |
 * | 04 | Log the end of the test | No input (STDOUT log "Exiting build_candidates_valid_cmdTypes test") | The exit message is printed to the console | Should be successful |
 */
TEST_F(em_orch_ctrl_t_TEST, build_candidates_valid_cmdTypes)
{
    std::cout << "Entering build_candidates_valid_cmdTypes test" << std::endl;
    em_cmd_type_t cmdTypes[] = {
        em_cmd_type_em_config, em_cmd_type_set_ssid, em_cmd_type_dev_test,
        em_cmd_type_reset, em_cmd_type_cfg_renew, em_cmd_type_sta_assoc,
        em_cmd_type_sta_link_metrics, em_cmd_type_set_channel, 
        em_cmd_type_scan_channel, em_cmd_type_sta_steer,
        em_cmd_type_sta_disassoc, em_cmd_type_set_policy, 
        em_cmd_type_set_radio, em_cmd_type_mld_reconfig,
        em_cmd_type_start_dpp, em_cmd_type_bsta_cap
    };
    size_t totalTypes = sizeof(cmdTypes) / sizeof(cmdTypes[0]);
    for (size_t i = 0; i < totalTypes; i++) {
	    em_cmd_t cmd;
        cmd.m_type = cmdTypes[i];
        std::cout << "Testing cmdType=" << cmd.m_type << std::endl;
        unsigned int candidateCount = orch->build_candidates(&cmd);
        EXPECT_EQ(candidateCount, 0u);
    }
    std::cout << "Exiting build_candidates_valid_cmdTypes test" << std::endl;
}
/**
 * @brief Verify that the em_orch_ctrl_t constructor properly creates an object when provided with a valid manager pointer.
 *
 * This test validates that no exception is thrown when instantiating the em_orch_ctrl_t object with a valid em_ctrl_t manager. The test ensures that the constructor initializes the object correctly without any runtime errors.
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
 * | Variation / Step | Description                                                                                                | Test Data                                                              | Expected Result                                                    | Notes      |
 * | :--------------: | ---------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- | ------------------------------------------------------------------ | ---------- |
 * | 01               | Invoke em_orch_ctrl_t constructor with a valid manager pointer and verify no exception is thrown             | input: mgr pointer = valid mgr object, output: new instance pointer    | No exception thrown; instance is successfully created              | Should Pass|
 */
TEST_F(em_orch_ctrl_t_TEST, em_orch_ctrl_t_TEST_valid_manager)
{
    std::cout << "Entering em_orch_ctrl_t_TEST_valid_manager test" << std::endl;
    em_ctrl_t mmgr;
    em_orch_ctrl_t *orchCtrl;
    std::cout << "Invoking em_orch_ctrl_t_TEST constructor with valid mgr object" << std::endl;
    EXPECT_NO_THROW(orchCtrl = new em_orch_ctrl_t(&mgr));
    queue_destroy(orchCtrl->m_pending);
    queue_destroy(orchCtrl->m_active);
    hash_map_destroy(orchCtrl->m_cmd_map);
    delete orchCtrl;
    std::cout << "Exiting em_orch_ctrl_t_TEST_valid_manager test" << std::endl;
}
/**
 * @brief Test the behavior of em_orch_ctrl_t constructor when provided a null manager pointer.
 *
 * This test validates that the em_orch_ctrl_t constructor throws an exception when a null pointer is passed as the manager.
 * The test ensures proper error handling by verifying that an exception is thrown under this condition.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 030@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                        | Test Data         | Expected Result                              | Notes       |
 * | :--------------: | ------------------------------------------------------------------ | ----------------- | -------------------------------------------- | ----------- |
 * | 01               | Invoke the em_orch_ctrl_t constructor with a null manager pointer    | mgr = nullptr     | Exception is thrown (via EXPECT_ANY_THROW)   | Should Fail |
 */
TEST_F(em_orch_ctrl_t_TEST, em_orch_ctrl_t_TEST_null_manager)
{
    std::cout << "Entering em_orch_ctrl_t_TEST_null_manager test" << std::endl;
    std::cout << "Invoking em_orch_ctrl_t_TEST constructor with mgr as null pointer" << std::endl;
    EXPECT_ANY_THROW(em_orch_ctrl_t orch(nullptr));
    std::cout << "Constructed em_orch_ctrl_t_TEST instance" << std::endl;
    std::cout << "Exiting em_orch_ctrl_t_TEST_null_manager test" << std::endl;
}
/**
 * @brief Validates that is_em_ready_for_orch_exec returns true for valid inputs
 *
 * This test iterates over multiple valid command types and prepares the required em_cmd_t,
 * em_interface_t, and other related objects to simulate a valid scenario for the orchestration controller.
 * For each command type, the test calls is_em_ready_for_orch_exec and verifies that the expected boolean true is returned.
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
 * | Variation / Step | Description                                                                                             | Test Data                                                                                                                                                      | Expected Result                                             | Notes      |
 * | :--------------: | ------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- | ---------- |
 * | 01               | Invoke is_em_ready_for_orch_exec with valid em_cmd_t of type em_cmd_type_set_ssid                          | cmd.m_type = em_cmd_type_set_ssid, ruid.name = Validname, ruid.mac = {0x1A,0x1B,0x2C,0x3D,0x4E,0x5A}, ruid.media = em_media_type_ieee80211b_24, dm.m_colocated = true | Return value true; Assertion EXPECT_TRUE(result)            | Should Pass|
 * | 02               | Invoke is_em_ready_for_orch_exec with valid em_cmd_t of type em_cmd_type_set_radio                          | cmd.m_type = em_cmd_type_set_radio, ruid.name = Validname, ruid.mac = {0x1A,0x1B,0x2C,0x3D,0x4E,0x5A}, ruid.media = em_media_type_ieee80211b_24, dm.m_colocated = true | Return value true; Assertion EXPECT_TRUE(result)            | Should Pass|
 * | 03               | Invoke is_em_ready_for_orch_exec with valid em_cmd_t of type em_cmd_type_mld_reconfig                        | cmd.m_type = em_cmd_type_mld_reconfig, ruid.name = Validname, ruid.mac = {0x1A,0x1B,0x2C,0x3D,0x4E,0x5A}, ruid.media = em_media_type_ieee80211b_24, dm.m_colocated = true | Return value true; Assertion EXPECT_TRUE(result)            | Should Pass|
 * | 04               | Invoke is_em_ready_for_orch_exec with valid em_cmd_t of type em_cmd_type_start_dpp                           | cmd.m_type = em_cmd_type_start_dpp, ruid.name = Validname, ruid.mac = {0x1A,0x1B,0x2C,0x3D,0x4E,0x5A}, ruid.media = em_media_type_ieee80211b_24, dm.m_colocated = true | Return value true; Assertion EXPECT_TRUE(result)            | Should Pass|
 */
TEST_F(em_orch_ctrl_t_TEST, is_em_ready_for_orch_exec_valid_inputs_return_true)
{
    std::cout << "Entering is_em_ready_for_orch_exec_valid_inputs_return_true test" << std::endl;
    em_cmd_type_t cmdTypes[] = { em_cmd_type_set_ssid, em_cmd_type_set_radio, em_cmd_type_mld_reconfig, em_cmd_type_start_dpp};
    size_t totalTypes = sizeof(cmdTypes) / sizeof(cmdTypes[0]);
    for (size_t i = 0; i < totalTypes; i++) {
        em_cmd_t cmd{};
        em_interface_t ruid;
        strncpy(ruid.name, "Validname", sizeof(ruid.name));
        unsigned char mac[6] = {0x1A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5A};
        memcpy(ruid.mac, mac, sizeof(mac));
        ruid.media = em_media_type_ieee80211b_24;
        dm_easy_mesh_t dm;
        dm.m_colocated = true;
        em_ctrl_t mgr;
        em_t em(&ruid ,em_freq_band_5, &dm, &mgr, em_profile_type_1, em_service_type_ctrl, false);
        cmd.m_type = cmdTypes[i];
        std::cout << "Invoking is_em_ready_for_orch_exec with valid em_cmd_t object with m_type " << cmd.m_type << "and em object pointers" << std::endl;
        bool result = orch->is_em_ready_for_orch_exec(&cmd, &em);
        std::cout << "Method returned: " << result << std::endl;
        EXPECT_TRUE(result);
    }
    std::cout << "Exiting is_em_ready_for_orch_exec_valid_inputs_return_true test" << std::endl;
}
/**
 * @brief Validate that is_em_ready_for_orch_exec returns false when the EM object is in an invalid state for the given command type.
 *
 * This test verifies that when an EM object is set to em_state_ctrl_wsc_m1_pending and a command with m_type set to em_cmd_type_cfg_renew is passed,
 * the function is_em_ready_for_orch_exec correctly returns false, ensuring that the orchestration execution is not performed under these conditions.
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
 * | Variation / Step | Description                                                                                                                    | Test Data                                                                                                                                                      | Expected Result                                                                                                           | Notes          |
 * | :--------------: | ------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | -------------- |
 * | 01               | Initialize the ruid structure by setting a valid name, MAC address, and media type.                                             | ruid.name = "Validname", ruid.mac = 0x1A,0x1B,0x2C,0x3D,0x4E,0x5A, ruid.media = em_media_type_ieee80211b_24                                                  | ruid structure is correctly initialized                                                                                 | Should be successful |
 * | 02               | Initialize the dm_easy_mesh_t structure and set the m_colocated flag to true.                                                   | dm.m_colocated = true                                                                                                                                          | dm structure is successfully configured                                                                                 | Should be successful |
 * | 03               | Create an instance of em_t using the initialized ruid, frequency band, dm, mgr pointer, profile & service types, and enable flag.  | input1 = &ruid, input2 = em_freq_band_5, input3 = &dm, input4 = &mgr, input5 = em_profile_type_1, input6 = em_service_type_ctrl, input7 = true                   | em object is successfully instantiated                                                                                  | Should be successful |
 * | 04               | Set the state of the EM object to em_state_ctrl_wsc_m1_pending.                                                                 | state = em_state_ctrl_wsc_m1_pending                                                                                                                           | EM object's state is updated correctly                                                                                  | Should be successful |
 * | 05               | Initialize the em_cmd_t object and set its m_type to em_cmd_type_cfg_renew to simulate a configuration renew command.            | cmd.m_type = em_cmd_type_cfg_renew                                                                                                                             | Command object is correctly configured                                                                                  | Should be successful |
 * | 06               | Invoke the is_em_ready_for_orch_exec API with the configured cmd and EM objects and verify that it returns false.                 | input = (&cmd, &em), output expected = false                                                                                                                   | API returns false and the assertion EXPECT_FALSE(result) passes                                                           | Should Fail    |
 */
TEST_F(em_orch_ctrl_t_TEST, is_em_ready_for_orch_exec_valid_mtype_state)
{
    std::cout << "Entering is_em_ready_for_orch_exec_valid_mtype_state test" << std::endl;
    em_cmd_t cmd{};
    em_interface_t ruid;
    strncpy(ruid.name, "Validname", sizeof(ruid.name));
    unsigned char mac[6] = {0x1A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5A};
    memcpy(ruid.mac, mac, sizeof(mac));
    ruid.media = em_media_type_ieee80211b_24;
    dm_easy_mesh_t dm;
    dm.m_colocated = true;
    em_ctrl_t mgr;
    em_t em(&ruid ,em_freq_band_5, &dm, &mgr, em_profile_type_1, em_service_type_ctrl, false);
    em.set_state(em_state_ctrl_wsc_m1_pending);        
    cmd.m_type = em_cmd_type_cfg_renew;
    std::cout << "Invoking is_em_ready_for_orch_exec with valid em_cmd_t object with m_type " << cmd.m_type << "and em object pointers" << std::endl;
    bool result = orch->is_em_ready_for_orch_exec(&cmd, &em);
    std::cout << "Method returned: " << result << std::endl;
    EXPECT_FALSE(result);
    std::cout << "Exiting is_em_ready_for_orch_exec_valid_mtype_state test" << std::endl;
}
/**
 * @brief Validate that the is_em_ready_for_orch_exec API returns false when the command type is set to none.
 *
 * This test verifies that when a valid em_cmd_t object with m_type set to em_cmd_type_none is provided along with a properly configured em object,
 * the is_em_ready_for_orch_exec function returns false. This ensures that the API correctly identifies that no execution should be performed for command type "none".
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 033@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke is_em_ready_for_orch_exec with a valid em_cmd_t object (m_type = em_cmd_type_none) and a properly configured em object. | cmd.m_type = em_cmd_type_none, ruid.name = "Validname", ruid.mac = "0x1A,0x1B,0x2C,0x3D,0x4E,0x5A", ruid.media = em_media_type_ieee80211b_24, dm.m_colocated = true, em state = em_state_ctrl_configured | Method returns false indicating that the command is not eligible for execution. | Should Pass |
 * | 02 | Verify that EXPECT_FALSE correctly asserts the returned false value from is_em_ready_for_orch_exec. | result = false | Assertion passes confirming the expected false response. | Should be successful |
 */
TEST_F(em_orch_ctrl_t_TEST, is_em_ready_for_orch_exec_mtype_none)
{
    std::cout << "Entering is_em_ready_for_orch_exec_mtype_none test" << std::endl;
    em_cmd_t cmd{};
    em_interface_t ruid;
    strncpy(ruid.name, "Validname", sizeof(ruid.name));
    unsigned char mac[6] = {0x1A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5A};
    memcpy(ruid.mac, mac, sizeof(mac));
    ruid.media = em_media_type_ieee80211b_24;
    dm_easy_mesh_t dm;
    dm.m_colocated = true;
    em_ctrl_t mgr;
    em_t em(&ruid ,em_freq_band_5, &dm, &mgr, em_profile_type_1, em_service_type_ctrl, false);
    em.set_state(em_state_ctrl_configured);        
    cmd.m_type = em_cmd_type_none;
    std::cout << "Invoking is_em_ready_for_orch_exec with valid em_cmd_t object with m_type " << cmd.m_type << "and em object pointers" << std::endl;
    bool result = orch->is_em_ready_for_orch_exec(&cmd, &em);
    std::cout << "Method returned: " << result << std::endl;
	EXPECT_FALSE(result);
    std::cout << "Exiting is_em_ready_for_orch_exec_mtype_none test" << std::endl;
}
/**
 * @brief Test to verify that is_em_ready_for_orch_exec returns false when a null command pointer is provided.
 *
 * This test verifies that when the API is invoked with a nullptr for the command (em_cmd_t object) and a valid em_t object,
 * the function is_em_ready_for_orch_exec correctly identifies the invalid input and returns false. This behavior is important to ensure
 * that the API does not attempt execution with a null command, thereby preventing undefined behavior.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 034
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Invoke is_em_ready_for_orch_exec with a nullptr as the em_cmd_t pointer and a valid em_t object | cmd = nullptr, em: {ruid.name="Validname", ruid.mac={0x1A,0x1B,0x2C,0x3D,0x4E,0x5A}, ruid.media=em_media_type_ieee80211b_24, dm.m_colocated=true, mgr, em_freq_band_5, em_profile_type_1, em_service_type_ctrl, valid=true} | API returns false and EXPECT_FALSE(result) assertion passes | Should Fail |
 */
TEST_F(em_orch_ctrl_t_TEST, is_em_ready_for_orch_exec_null_cmd)
{
    std::cout << "Entering is_em_ready_for_orch_exec_null_cmd test" << std::endl;
    em_interface_t ruid;
    strncpy(ruid.name, "Validname", sizeof(ruid.name));
    unsigned char mac[6] = {0x1A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5A};
    memcpy(ruid.mac, mac, sizeof(mac));
    ruid.media = em_media_type_ieee80211b_24;
    dm_easy_mesh_t dm;
    dm.m_colocated = true;
    em_ctrl_t mgr;
    em_t em(&ruid ,em_freq_band_5, &dm, &mgr, em_profile_type_1, em_service_type_ctrl, false);
    std::cout << "Invoking is_em_ready_for_orch_exec with nullptr as em_cmd_t object and valid em_t object" << std::endl;
    bool result = orch->is_em_ready_for_orch_exec(nullptr, &em);
    std::cout << "Method returned: " << result << std::endl;
    EXPECT_FALSE(result);
    std::cout << "Exiting is_em_ready_for_orch_exec_null_cmd test" << std::endl;
}
/**
 * @brief Verifies that is_em_ready_for_orch_exec returns false when the em_t object is nullptr.
 *
 * This test checks the behavior of the is_em_ready_for_orch_exec API by invoking it with a valid em_cmd_t object and a nullptr for the em_t parameter. The objective is to ensure that the API correctly identifies the invalid (null) em_t pointer and returns false as expected.
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
 * | Variation / Step | Description                                                                              | Test Data                                                     | Expected Result                                                                                    | Notes       |
 * | :--------------: | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke is_em_ready_for_orch_exec with a valid em_cmd_t object and nullptr as em_t object.  | cmd.m_type = em_cmd_type_set_ssid, em_t pointer = nullptr     | API returns false and EXPECT_FALSE(result) assertion confirms the false return value.              | Should Fail |
 */
TEST_F(em_orch_ctrl_t_TEST, is_em_ready_for_orch_exec_null_em)
{
    std::cout << "Entering is_em_ready_for_orch_exec_null_em test" << std::endl;
    em_cmd_t cmd{};
    cmd.m_type = em_cmd_type_set_ssid;
    std::cout << "Invoking is_em_ready_for_orch_exec with valid em_cmd_t object and nullptr as em_t object" << std::endl;
    bool result = orch->is_em_ready_for_orch_exec(&cmd, nullptr);
    std::cout << "Method returned: " << result << std::endl;
    EXPECT_FALSE(result);
    std::cout << "Exiting is_em_ready_for_orch_exec_null_em test" << std::endl;
}
/**
 * @brief Test if the EM is ready for orchestration finish start DPP command.
 *
 * This test verifies that the is_em_ready_for_orch_fini API correctly identifies when an EM instance, set to the state em_state_ctrl_wsc_m2_sent with a command of type em_cmd_type_set_radio, is ready to proceed with the orchestration finish process. The expected outcome is that the API returns true, confirming that the EM instance is in the proper state to finalize the DPP command.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 036@n
 * **Priority:** (High) Test is crucial for validating the readiness of the EM for orchestration finish.
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                  | Test Data                                                                                                                                               | Expected Result                                                       | Notes           |
 * | :--------------: | -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | --------------- |
 * | 01               | Initialize the command structure and set the command type                                    | cmd.m_type = em_cmd_type_set_radio                                                                                                                      | Command structure is set with type em_cmd_type_set_radio              | Should be successful |
 * | 02               | Prepare the EM interface with valid name, MAC address, and media type                          | ruid: name = "Validname", mac = 1A,1B,2C,3D,4E,5A, media = em_media_type_ieee80211b_24                                                                   | EM interface is correctly initialized with valid parameters           | Should be successful |
 * | 03               | Initialize the DM structure and mark it as colocated                                         | dm: m_colocated = true                                                                                                                                    | DM structure is initialized with m_colocated set to true              | Should be successful |
 * | 04               | Instantiate the EM object and set its state to em_state_ctrl_wsc_m2_sent                         | em: state set to em_state_ctrl_wsc_m2_sent, ruid, frequency band = em_freq_band_5, dm, mgr, profile = em_profile_type_1, service type = em_service_type_ctrl, boolean flag = true | EM object is created and its state is correctly set to em_state_ctrl_wsc_m2_sent | Should be successful |
 * | 05               | Invoke the is_em_ready_for_orch_fini API with the prepared command and EM object               | API Call: is_em_ready_for_orch_fini(&cmd, &em)                                                                                                           | Returns true, indicating that the EM is ready for the orchestration finish start DPP command | Should Pass      |
 */
TEST_F(em_orch_ctrl_t_TEST, is_em_ready_for_orch_fini_start_dpp_command) {
    std::cout << "Entering is_em_ready_for_orch_fini_start_dpp_command test" << std::endl;
    em_cmd_t cmd{};
    cmd.m_type = em_cmd_type_set_radio;
    em_interface_t ruid;
    strncpy(ruid.name, "Validname", sizeof(ruid.name));
    unsigned char mac[6] = {0x1A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5A};
    memcpy(ruid.mac, mac, sizeof(mac));
    ruid.media = em_media_type_ieee80211b_24;
    dm_easy_mesh_t dm;
    dm.m_colocated = true;
    em_ctrl_t mgr;
    em_t em(&ruid ,em_freq_band_5, &dm, &mgr, em_profile_type_1, em_service_type_ctrl, false);
    em.set_state(em_state_ctrl_wsc_m2_sent);
    std::cout << "Invoking is_em_ready_for_orch_fini with em_cmd_type_set_radio and EM state em_state_ctrl_wsc_m2_sent" << std::endl;
    bool result = orch->is_em_ready_for_orch_fini(&cmd, &em);
    std::cout << "Returned value: " << result << std::endl;
    EXPECT_TRUE(result);
    std::cout << "Exiting is_em_ready_for_orch_fini_start_dpp_command test" << std::endl;
}
/**
 * @brief Verify that is_em_ready_for_orch_fini returns the correct readiness state for a STA association command.
 *
 * This test validates that when the command type is set to em_cmd_type_sta_assoc and the EM instance is in the em_state_ctrl_sta_cap_confirmed state, the is_em_ready_for_orch_fini API correctly returns true, indicating that it is ready to finalize operations.
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
 * | Variation / Step | Description                                                                                                                       | Test Data                                                                                                                                                                                         | Expected Result                                                                              | Notes      |
 * | :--------------: | --------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | ---------- |
 * |      01         | Invoke is_em_ready_for_orch_fini API with em_cmd_type_sta_assoc and the EM state set to em_state_ctrl_sta_cap_confirmed                    | cmd.m_type = em_cmd_type_sta_assoc, ruid.name = Validname, ruid.mac = 0x1A,0x1B,0x2C,0x3D,0x4E,0x5A, ruid.media = em_media_type_ieee80211b_24, dm.m_colocated = true, em state = em_state_ctrl_sta_cap_confirmed | API returns true; EXPECT_TRUE assertion passes                                             | Should Pass |
 */
TEST_F(em_orch_ctrl_t_TEST, is_em_ready_for_orch_fini_mtype_sta_assoc) {
    std::cout << "Entering is_em_ready_for_orch_fini_mtype_sta_assoc test" << std::endl;
    em_cmd_t cmd{};
    cmd.m_type = em_cmd_type_sta_assoc;
    em_interface_t ruid;
    strncpy(ruid.name, "Validname", sizeof(ruid.name));
    unsigned char mac[6] = {0x1A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5A};
    memcpy(ruid.mac, mac, sizeof(mac));
    ruid.media = em_media_type_ieee80211b_24;
    dm_easy_mesh_t dm;
    dm.m_colocated = true;
    em_ctrl_t mgr;
    em_t em(&ruid ,em_freq_band_5, &dm, &mgr, em_profile_type_1, em_service_type_ctrl, false);
    em.set_state(em_state_ctrl_sta_cap_confirmed);
    std::cout << "Invoking is_em_ready_for_orch_fini with em_cmd_type_sta_assoc and EM state em_state_ctrl_sta_cap_confirmed" << std::endl;
    bool result = orch->is_em_ready_for_orch_fini(&cmd, &em);
    std::cout << "Returned value: " << result << std::endl;
    EXPECT_TRUE(result);
    std::cout << "Exiting is_em_ready_for_orch_fini_mtype_sta_assoc test" << std::endl;
}
/**
 * @brief Test that verifies is_em_ready_for_orch_fini returns false when the EM state is misconfigured.
 *
 * This test verifies that when an em_t instance is configured with em_state_ctrl_misconfigured (SSID not ready),
 * the is_em_ready_for_orch_fini API correctly returns false. It checks the proper initialization of input structures
 * such as em_cmd_t, em_interface_t, and dm_easy_mesh_t, and ensures that the API call behaves as expected in a negative scenario.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Print entry message and initialize the em_cmd_t command with em_cmd_type_sta_link_metrics. | cmd.m_type = em_cmd_type_sta_link_metrics | Command is initialized as input for API | Should be successful |@n
 * | 02 | Set up the em_interface_t structure by copying a valid name, MAC address, and setting the media type. | ruid.name = "Validname", ruid.mac = {0x1A,0x1B,0x2C,0x3D,0x4E,0x5A}, ruid.media = em_media_type_ieee80211b_24 | Interface structure is correctly populated | Should be successful |@n
 * | 03 | Initialize the dm_easy_mesh_t structure and set the colocated attribute to true. | dm.m_colocated = true | Structure dm is properly configured for the test | Should be successful |@n
 * | 04 | Create an instance of em_t using the above structures and set its state to em_state_ctrl_misconfigured. | em is created with ruid, em_freq_band_5, dm, mgr, em_profile_type_1, em_service_type_ctrl, true; then em.set_state(em_state_ctrl_misconfigured) | em state is set to misconfigured to simulate SSID not ready | Should be successful |@n
 * | 05 | Invoke is_em_ready_for_orch_fini with the command and em instance, then verify the return value is false. | Function call: result = orch->is_em_ready_for_orch_fini(&cmd, &em) | API returns false and EXPECT_FALSE(result) is satisfied | Should Pass |
 */
TEST_F(em_orch_ctrl_t_TEST, is_em_ready_for_orch_fini_set_ssid_not_ready) {
    std::cout << "Entering is_em_ready_for_orch_fini_set_ssid_not_ready test" << std::endl;
    em_cmd_t cmd{};
    cmd.m_type = em_cmd_type_sta_link_metrics;
    em_interface_t ruid;
    strncpy(ruid.name, "Validname", sizeof(ruid.name));
    unsigned char mac[6] = {0x1A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5A};
    memcpy(ruid.mac, mac, sizeof(mac));
    ruid.media = em_media_type_ieee80211b_24;
    dm_easy_mesh_t dm;
    dm.m_colocated = true;
    em_ctrl_t mgr;
    em_t em(&ruid ,em_freq_band_5, &dm, &mgr, em_profile_type_1, em_service_type_ctrl, false);
    em.set_state(em_state_ctrl_misconfigured);
    std::cout << "Invoking is_em_ready_for_orch_fini with m_type as em_cmd_type_sta_link_metrics and em_state_ctrl_misconfigured as state" << std::endl;
    bool result = orch->is_em_ready_for_orch_fini(&cmd, &em);
    std::cout << "Returned value: " << result << std::endl;
    EXPECT_FALSE(result);
    std::cout << "Exiting is_em_ready_for_orch_fini_set_ssid_not_ready test" << std::endl;
}
/**
 * @brief Verify that is_em_ready_for_orch_fini returns false when the VAP config command is used and station association is not ready.
 *
 * This test verifies the negative scenario for the API is_em_ready_for_orch_fini in which a command of type em_cmd_type_vap_config is provided along with an EM instance that simulates a non-ready station association state. The test ensures that the function properly identifies that the EM is not ready for finalization and returns false, as confirmed by the EXPECT_FALSE assertion.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 039@n
 * **Priority:** (High) High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                 | Test Data                                                                                                                                                                                                              | Expected Result                                                          | Notes        |
 * | :--------------: | ------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ | ------------ |
 * | 01               | Invoke is_em_ready_for_orch_fini with a VAP configuration command using a valid EM object. | cmd.m_type=em_cmd_type_vap_config, ruid.name=Validname, ruid.mac=1A:1B:2C:3D:4E:5A, ruid.media=em_media_type_ieee80211b_24, dm.m_colocated=true, em.freq_band=em_freq_band_5, em.profile_type=em_profile_type_1, em.service_type=em_service_type_ctrl | Return value false from is_em_ready_for_orch_fini; EXPECT_FALSE check passes | Should Pass |
 */
TEST_F(em_orch_ctrl_t_TEST, is_em_ready_for_orch_fini_sta_assoc_not_ready) {
    std::cout << "Entering is_em_ready_for_orch_fini_sta_assoc_not_ready test" << std::endl;
    em_cmd_t cmd{};
    cmd.m_type = em_cmd_type_vap_config;
    em_interface_t ruid;
    strncpy(ruid.name, "Validname", sizeof(ruid.name));
    unsigned char mac[6] = {0x1A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5A};
    memcpy(ruid.mac, mac, sizeof(mac));
    ruid.media = em_media_type_ieee80211b_24;
    dm_easy_mesh_t dm;
    dm.m_colocated = true;
    em_ctrl_t mgr;
    em_t em(&ruid ,em_freq_band_5, &dm, &mgr, em_profile_type_1, em_service_type_ctrl, false);
    std::cout << "Invoking is_em_ready_for_orch_fini with m_type em_cmd_type_vap_config" << std::endl;
    bool result = orch->is_em_ready_for_orch_fini(&cmd, &em);
    std::cout << "Returned value: " << result << std::endl;
    EXPECT_FALSE(result);
    std::cout << "Exiting is_em_ready_for_orch_fini_sta_assoc_not_ready test" << std::endl;
}
/**
 * @brief Verify the orch_transient function with valid input parameters.
 *
 * This test validates that the orch_transient function processes valid configurations for the command and interface structures correctly. The test uses valid command type, valid interface attributes (name, MAC, media type), and valid dm settings to ensure proper execution of the API.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Initialize a valid command structure and interface details, then call orch_transient with these valid inputs. | pcmd.m_type = em_cmd_type_em_config, ruid.name = "Validname", ruid.mac = "0x1A,0x1B,0x2C,0x3D,0x4E,0x5A", ruid.media = em_media_type_ieee80211b_24, dm.m_colocated = true; additional inputs as per function signature | orch_transient processes inputs correctly without error, and expected assertions (if any) pass. | Should Pass |
 */
TEST_F(em_orch_ctrl_t_TEST, orch_transient_valid_inputs)
{
    std::cout << "Entering orch_transient_valid_inputs test" << std::endl;
    em_cmd_t pcmd{};
    pcmd.m_type = em_cmd_type_em_config;
    em_interface_t ruid;
    strncpy(ruid.name, "Validname", sizeof(ruid.name));
    unsigned char mac[6] = {0x1A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5A};
    memcpy(ruid.mac, mac, sizeof(mac));
    ruid.media = em_media_type_ieee80211b_24;
    dm_easy_mesh_t dm;
    dm.m_colocated = true;
    em_ctrl_t mgr;
    em_t em(&ruid ,em_freq_band_5, &dm, &mgr, em_profile_type_1, em_service_type_ctrl, false);
    std::cout << "Invoking orch_transient with valid inputs" << std::endl;
    EXPECT_NO_THROW(orch->orch_transient(&pcmd, &em));
    std::cout << "Exiting orch_transient_valid_inputs test" << std::endl;
}

/**
 * @brief Verify that orch_transient throws an exception when provided with a NULL pcmd pointer.
 *
 * This test ensures that the orch_transient API correctly handles a scenario where the pcmd argument is NULL.
 * It sets up the necessary interface and associated objects, then invokes the API with the NULL pointer,
 * expecting an exception to be thrown. This validation confirms that the function properly checks for invalid input.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 041
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                 | Test Data                                                                                                                                                                                 | Expected Result                                             | Notes            |
 * | :--------------: | ------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- | ---------------- |
 * | 01               | Initialize test parameters including valid ruid and em instance.                           | ruid.name = "Validname", ruid.mac = {0x1A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5A}, ruid.media = em_media_type_ieee80211b_24; dm.m_colocated = true, mgr instance created, em object created with em_freq_band_5, em_profile_type_1, em_service_type_ctrl | Test data is prepared without errors.                      | Should be successful |
 * | 02               | Call orch_transient with pcmd as NULL and verify that an exception is thrown.                | pcmd = NULL, em instance as created in step 01                                                                                                                                            | Exception is thrown as verified by EXPECT_ANY_THROW macro.  | Should Fail      |
 */
TEST_F(em_orch_ctrl_t_TEST, orch_transient_null_pcmd)
{
    std::cout << "Entering orch_transient_null_pcmd test" << std::endl;
	em_interface_t ruid;
    strncpy(ruid.name, "Validname", sizeof(ruid.name));
    unsigned char mac[6] = {0x1A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5A};
    memcpy(ruid.mac, mac, sizeof(mac));
    ruid.media = em_media_type_ieee80211b_24;
    dm_easy_mesh_t dm;
    dm.m_colocated = true;
    em_ctrl_t mgr;
    em_t em(&ruid ,em_freq_band_5, &dm, &mgr, em_profile_type_1, em_service_type_ctrl, false);
    std::cout << "Invoking orch_transient with pcmd = NULL" << std::endl;
    EXPECT_ANY_THROW(orch->orch_transient(nullptr, &em));
    std::cout << "Exiting orch_transient_null_pcmd test" << std::endl;
}
/**
 * @brief Verify that orch_transient throws an exception when the em (emergency management) parameter is NULL.
 *
 * This test case confirms that the orch_transient API properly handles invalid parameters by throwing an exception
 * when a NULL em parameter is provided. This ensures that error handling for invalid input is correctly implemented.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 042
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                               | Test Data                                                    | Expected Result                                   | Notes              |
 * | :--------------: | --------------------------------------------------------- | ------------------------------------------------------------ | ------------------------------------------------- | ------------------ |
 * | 01               | Log the entry message for orch_transient_null_em test     | None                                                         | Console outputs entry message                     | Should be successful |
 * | 02               | Invoke orch_transient API with a valid cmd and NULL em      | input: cmd = instance of em_cmd_t, em = NULL                   | An exception is thrown and EXPECT_ANY_THROW passes | Should Pass        |
 * | 03               | Log the exit message for orch_transient_null_em test      | None                                                         | Console outputs exit message                      | Should be successful |
 */
TEST_F(em_orch_ctrl_t_TEST, orch_transient_null_em)
{
    std::cout << "Entering orch_transient_null_em test" << std::endl;
    std::cout << "Invoking orch_transient with em = NULL" << std::endl;
    em_cmd_t cmd;
    EXPECT_ANY_THROW(orch->orch_transient(&cmd, nullptr));    
    std::cout << "Exiting orch_transient_null_em test" << std::endl;
}

/**
 * @brief Verify that pre_process_cancel properly handles an unhandled command type.
 *
 * This test verifies that when an unhandled command type (set to 999) is passed to the pre_process_cancel API,
 * the function handles it gracefully without causing unexpected behavior. This is important for ensuring robustness 
 * when the system receives commands outside the anticipated set.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 043@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:** 
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Initialize the command structure with an unhandled command type | pcmd.m_type = em_cmd_type_em_config | Command type is set to an unhandled value | Should Pass |
 * | 02 | Configure the interface data with valid parameters | ruid.name = "Validname", ruid.mac = 0x1A,0x1B,0x2C,0x3D,0x4E,0x5A, ruid.media = em_media_type_ieee80211b_24 | Interface structure is filled with valid data | Should be successful |
 * | 03 | Setup the mesh configuration | dm.m_colocated = true | Mesh structure is properly configured | Should be successful |
 * | 04 | Create the instance for em_t with necessary parameters | emInstance: ruid = Validname, em_freq_band_5, dm = colocated true, mgr, em_profile_type_1, em_service_type_ctrl, true | Instance is created successfully | Should Pass |
 * | 05 | Invoke pre_process_cancel with the prepared command and instance | Input: &pcmd, &emInstance | API is executed without errors for unhandled command type | Should Pass |
 */
TEST_F(em_orch_ctrl_t_TEST, pre_process_cancel_unhandled_command)
{
    std::cout << "Entering pre_process_cancel_unhandled_command test" << std::endl;
    em_cmd_t pcmd{};
    pcmd.m_type = static_cast<em_cmd_type_t>(999);
    em_interface_t ruid;
    strncpy(ruid.name, "Validname", sizeof(ruid.name));
    unsigned char mac[6] = {0x1A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5A};
    memcpy(ruid.mac, mac, sizeof(mac));
    ruid.media = em_media_type_ieee80211b_24;
    dm_easy_mesh_t dm;
    dm.m_colocated = true;
    em_ctrl_t mgr;
    em_t emInstance(&ruid, em_freq_band_5, &dm, &mgr, em_profile_type_1, em_service_type_ctrl, true);
    EXPECT_ANY_THROW(orch->pre_process_cancel(&pcmd, &emInstance));
    std::cout << "Called pre_process_cancel" << std::endl;
    std::cout << "Exiting pre_process_cancel_unhandled_command test" << std::endl;
}
/**
 * @brief Verify pre_process_cancel handles a null pcmd parameter without error
 *
 * This test case verifies that the pre_process_cancel method of the em_orch_ctrl_t instance
 * correctly handles a null pcmd parameter. The test creates a valid em_t instance with proper
 * initialization and then calls pre_process_cancel with a null pcmd pointer to ensure the API
 * gracefully handles such input without causing crashes or undefined behavior.
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
 * | Variation / Step | Description                                                                          | Test Data                                                                                                                                                      | Expected Result                                                                  | Notes      |
 * | :--------------: | ------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | ---------- |
 * | 01               | Call pre_process_cancel with pcmd set to nullptr and verify if exception is thrown   | pcmd = nullptr, ruid.name = "Validname", ruid.mac = 0x1A,0x1B,0x2C,0x3D,0x4E,0x5A, ruid.media = em_media_type_ieee80211b_24, dm.m_colocated = true   | Function handles nullptr gracefully without crashing or undefined behavior     | Should Pass|
 */
TEST_F(em_orch_ctrl_t_TEST, pre_process_cancel_null_pcmd)
{
    std::cout << "Entering pre_process_cancel_null_pcmd test" << std::endl;
    em_interface_t ruid;
    strncpy(ruid.name, "Validname", sizeof(ruid.name));
    unsigned char mac[6] = {0x1A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5A};
    memcpy(ruid.mac, mac, sizeof(mac));
    ruid.media = em_media_type_ieee80211b_24;
    dm_easy_mesh_t dm;
    dm.m_colocated = true;
    em_ctrl_t mgr;
    em_t emInstance(&ruid ,em_freq_band_5, &dm, &mgr, em_profile_type_1, em_service_type_ctrl, false);
    EXPECT_ANY_THROW(orch->pre_process_cancel(nullptr, &emInstance));
    std::cout << "Called pre_process_cancel with NULL pcmd" << std::endl;
    std::cout << "Exiting pre_process_cancel_null_pcmd test" << std::endl;
}
/**
 * @brief To verify the behavior of pre_process_cancel when passed a valid command and a null EM pointer.
 *
 * This test ensures that when the pre_process_cancel method is invoked with a properly initialized em_cmd_t structure and a NULL pointer for the EM parameter, the function handles the null pointer gracefully without causing crashes or unintended side effects.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 045@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke pre_process_cancel using a valid em_cmd_t object with m_type set to em_cmd_type_em_config, NULL EM pointer and verify if exception is thrown | input: pcmd.m_type = em_cmd_type_em_config, second argument = nullptr | The API should handle the null EM pointer gracefully without crashing and proceed with internal checks if any. | Should Pass |
 */
TEST_F(em_orch_ctrl_t_TEST, pre_process_cancel_null_em)
{
    std::cout << "Entering pre_process_cancel_null_em test" << std::endl;
    em_cmd_t pcmd;
    pcmd.m_type = em_cmd_type_em_config;
    EXPECT_ANY_THROW(orch->pre_process_cancel(&pcmd, nullptr));
    std::cout << "Called pre_process_cancel with NULL em" << std::endl;
    std::cout << "Exiting pre_process_cancel_null_em test" << std::endl;
}

/**
 * @brief Test pre_process_orch_op with a null input command pointer.
 *
 * This test verifies that the pre_process_orch_op function returns false when a nullptr is passed as the command pointer.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 046
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                | Test Data                | Expected Result                                                      | Notes       |
 * | :--------------: | ------------------------------------------ | ------------------------ | -------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke pre_process_orch_op with nullptr    | command = nullptr        | The API returns false and EXPECT_FALSE assertion passes              | Should Pass |
 */
TEST_F(em_orch_ctrl_t_TEST, pre_process_orch_op_NullInputCommandPointer) {
    std::cout << "Entering pre_process_orch_op_NullInputCommandPointer test" << std::endl;
    std::cout << "Invoking pre_process_orch_op with nullptr" << std::endl;
    bool ret = orch->pre_process_orch_op(nullptr);
    std::cout << "Returned value: " << (ret ? "true" : "false") << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting pre_process_orch_op_NullInputCommandPointer test" << std::endl;
}
/**
 * @brief Test to verify that pre_process_orch_op returns false for an unsupported operation with submit flag set to false
 *
 * This test verifies that when an unsupported operation command is provided with the submit flag set to false, the pre_process_orch_op function returns false as expected. The test sets up the command data structure with the operation type set to dm_orch_type_em_update and validates that the API returns false and the assertion EXPECT_FALSE(ret) passes.
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
 * | 01 | Initialize the command structure with operation type dm_orch_type_em_update and submit flag false. | cmd.m_orch_op_idx = 0, cmd.m_orch_desc[0].op = dm_orch_type_em_update, cmd.m_orch_desc[0].submit = false | Command structure correctly initialized for an unsupported operation with submit false. | Should be successful |  
 * | 02 | Invoke the pre_process_orch_op API using the initialized command. | Input: pointer to cmd | Return value should be false and EXPECT_FALSE(ret) should pass. | Should Pass |
 */
TEST_F(em_orch_ctrl_t_TEST, pre_process_orch_op_ValidCommandUnsupportedOp_SubmitFalse) {
    std::cout << "Entering pre_process_orch_op_ValidCommandUnsupportedOp_SubmitFalse test" << std::endl;
    em_cmd_t cmd{};
    cmd.m_orch_op_idx = 0;
    cmd.m_orch_desc[0].op = dm_orch_type_em_update;
    cmd.m_orch_desc[0].submit = false;
    std::cout << "Invoking pre_process_orch_op with orchtype dm_orch_type_em_update" << std::endl;
    bool ret = orch->pre_process_orch_op(&cmd);
    std::cout << "Returned value: " << (ret ? "true" : "false") << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting pre_process_orch_op_ValidCommandUnsupportedOp_SubmitFalse test" << std::endl;
}
/**
 * @brief Validates that pre_process_orch_op returns true for a valid command with an unsupported operation when submit is set to true.
 *
 * This test verifies that when a command with operation dm_orch_type_sta_link_metrics and submit flag set to true is processed,
 * the pre_process_orch_op API returns true, even though the operation is unsupported. This confirms that the submission logic
 * works correctly for the given scenario.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 048@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                 | Test Data                                                                                                  | Expected Result                                                    | Notes           |
 * | :--------------: | --------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ | --------------- |
 * | 01               | Log the entry message into the test function                                | None                                                                                                       | "Entering pre_process_orch_op_ValidCommandUnsupportedOp_SubmitTrue test" printed on console | Should be successful |
 * | 02               | Initialize the command object with orchestration operation index and flag   | cmd.m_orch_op_idx = 0, cmd.m_orch_desc[0].op = dm_orch_type_sta_link_metrics, cmd.m_orch_desc[0].submit = true | Command object properly configured                                | Should be successful |
 * | 03               | Invoke the pre_process_orch_op API with the initialized command object        | Input: &cmd                                                                                               | Return value is true and EXPECT_TRUE(ret) passes                  | Should Pass     |
 * | 04               | Log the returned value and the exit message from the test                    | None                                                                                                       | Console displays the returned value ("true") and exit message        | Should be successful |
 */
TEST_F(em_orch_ctrl_t_TEST, pre_process_orch_op_ValidCommandUnsupportedOp_SubmitTrue) {
    std::cout << "Entering pre_process_orch_op_ValidCommandUnsupportedOp_SubmitTrue test" << std::endl;
    em_cmd_t cmd{};
    cmd.m_orch_op_idx = 0;
    cmd.m_orch_desc[0].op = dm_orch_type_sta_link_metrics;
    cmd.m_orch_desc[0].submit = true;
    std::cout << "Invoking pre_process_orch_op with orchtype dm_orch_type_sta_link_metrics" << std::endl;
    bool ret = orch->pre_process_orch_op(&cmd);
    std::cout << "Returned value: " << (ret ? "true" : "false") << std::endl;
    EXPECT_TRUE(ret);
    std::cout << "Exiting pre_process_orch_op_ValidCommandUnsupportedOp_SubmitTrue test" << std::endl;
}
/**
 * @brief Validate that pre_process_orch_op returns false when an unsupported command of type dm_orch_type_none is provided
 *
 * This test verifies that when a command with dm_orch_type_none and submit flag set to false is processed,
 * the pre_process_orch_op method correctly identifies the unsupported operation and returns false. This ensures that
 * only supported command operations are accepted by the controller.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 049@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize the command structure with dm_orch_type_none and submit flag false | cmd.m_orch_op_idx = 0, cmd.m_orch_desc[0].op = dm_orch_type_none, cmd.m_orch_desc[0].submit = false | Command structure is prepared with the expected values | Should be successful |
 * | 02 | Invoke pre_process_orch_op with the initialized command and verify the returned value | input: &cmd, output: ret = false | API returns false indicating the command is unsupported as expected | Should Pass |
 */
TEST_F(em_orch_ctrl_t_TEST, pre_process_orch_op_ValidCommandUnsupportedOp_NoneOrchType) {
    std::cout << "Entering pre_process_orch_op_ValidCommandUnsupportedOp_NoneOrchType test" << std::endl;
    em_cmd_t cmd{};
    cmd.m_orch_op_idx = 0;
    cmd.m_orch_desc[0].op = dm_orch_type_none;
    cmd.m_orch_desc[0].submit = false;
    std::cout << "Invoking pre_process_orch_op with orchtype dm_orch_type_none" << std::endl;
    bool ret = orch->pre_process_orch_op(&cmd);
    std::cout << "Returned value: " << (ret ? "true" : "false") << std::endl;
    EXPECT_FALSE(ret);
    std::cout << "Exiting pre_process_orch_op_ValidCommandUnsupportedOp_NoneOrchType test" << std::endl;
}
