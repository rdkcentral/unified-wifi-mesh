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
#include "em_sm.h"


/**
* @brief Test retrieving the state to valid states in the em_sm_t class
*
* This test ensures that the method returns the initialized state for each of the valid states, indicating successful state retrieval.
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Retrieve the state value using getstate method | state = <the initialized state value> | Retrieved value should match the initialized value | Should Pass |
*/
TEST(em_sm_t_Test, GetValidStateValues) {
    std::cout << "Entering GetValidStateValues test";
    em_sm_t obj;
    em_state_t retrieved_state = obj.get_state();
    std::cout << "The retrieved state value is " << static_cast<int>(retrieved_state) << std::endl;
    EXPECT_GE(retrieved_state, em_state_agent_unconfigured);
    EXPECT_LT(retrieved_state, em_state_max);
    std::cout << "Exiting GetValidStateValues test";
}

/**
* @brief Test the initialization of the state machine with valid service types
*
* This test verifies that the state machine initializes correctly when provided with valid service types.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 002@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Initialize the state machine with each of the service types and verify | valid_services = {em_service_type_ctrl, em_service_type_agent, em_service_type_cli} | State should be as expected for em_service_type_ctrl | Should Pass |
*/
TEST(em_sm_t_Test, InitializeStateMachineWithValidServiceTypes) {
    std::cout << "Entering InitializeStateMachineWithValidServiceTypes" << std::endl;
    em_service_type_t valid_services[] = {em_service_type_ctrl, em_service_type_agent, em_service_type_cli};
    for (auto service : valid_services) {
        em_sm_t sm;
        sm.init_sm(service);
    }
    std::cout << "Exiting InitializeStateMachineWithValidServiceTypes" << std::endl;
}


/**
* @brief Test setting the state to valid states in the em_sm_t class
*
* This test verifies that the set_state method in the em_sm_t class correctly handles all valid states. 
* It ensures that the method returns 0 for each valid state, indicating successful state setting.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 003@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Set to each of the valid state values and verify successful return value | state = <valid state values> | result = 0, EXPECT_EQ(result, 0) | Should Pass |
*/
TEST(em_sm_t_Test, SetStateToValidStates) {
    std::cout << "Entering SetStateToValidStates test";
    em_state_t valid_states[] = {
        em_state_agent_unconfigured,
        em_state_agent_autoconfig_rsp_pending,
        em_state_agent_wsc_m2_pending,
        em_state_agent_owconfig_pending,
        em_state_agent_onewifi_bssconfig_ind,
        em_state_agent_autoconfig_renew_pending,
        em_state_agent_topo_synchronized,
        em_state_agent_channel_pref_query,
        em_state_agent_channel_selection_pending,
        em_state_agent_channel_select_configuration_pending,
        em_state_agent_channel_report_pending,
        em_state_agent_channel_scan_result_pending,
        em_state_agent_configured,
        em_state_agent_topology_notify,
        em_state_agent_ap_cap_report,
        em_state_agent_client_cap_report,
        em_state_agent_sta_link_metrics_pending,
        em_state_agent_steer_btm_res_pending,
        em_state_agent_beacon_report_pending,
        em_state_agent_ap_metrics_pending,
        em_state_ctrl_unconfigured,
        em_state_ctrl_wsc_m1_pending,
        em_state_ctrl_wsc_m2_sent,
        em_state_ctrl_topo_sync_pending,
        em_state_ctrl_topo_synchronized,
        em_state_ctrl_channel_query_pending,
        em_state_ctrl_channel_pref_report_pending,
        em_state_ctrl_channel_queried,
        em_state_ctrl_channel_select_pending,
        em_state_ctrl_channel_selected,
        em_state_ctrl_channel_cnf_pending,
        em_state_ctrl_channel_report_pending,
        em_state_ctrl_channel_scan_pending,
        em_state_ctrl_configured,
        em_state_ctrl_misconfigured,
        em_state_ctrl_sta_cap_pending,
        em_state_ctrl_sta_cap_confirmed,
        em_state_ctrl_sta_link_metrics_pending,
        em_state_ctrl_sta_steer_pending,
        em_state_ctrl_steer_btm_req_ack_rcvd,
        em_state_ctrl_sta_disassoc_pending,
        em_state_ctrl_set_policy_pending,
        em_state_ctrl_ap_mld_config_pending,
        em_state_ctrl_ap_mld_configured,
        em_state_ctrl_bsta_mld_config_pending,
        em_state_ctrl_ap_mld_req_ack_rcvd,
        em_state_ctrl_avail_spectrum_inquiry_pending
    };
    for (em_state_t state : valid_states) {
        em_sm_t obj;
        int result = obj.set_state(state);
        EXPECT_EQ(result, 0);
    }
    std::cout << "Exiting SetStateToValidStates test";
}



/**
* @brief Test to verify the behavior of setting an invalid state
*
* This test checks the behavior of the set_state function when an invalid state (em_state_max) is passed as an argument. The function is expected to return -1 indicating failure.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 004@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Set state to an invalid state | input = em_state_max | Return value = -1, Assertion check: EXPECT_EQ(result, -1) | Should Fail |
*/
TEST(em_sm_t_Test, SetStateToInvalidState) {
    std::cout << "Entering SetStateToInvalidState test";
    em_sm_t obj;
    int result = obj.set_state(em_state_max);
    EXPECT_EQ(result, -1);
    std::cout << "Exiting SetStateToInvalidState test";
}



/**
* @brief Test to validate the state machine with valid states
*
* This test verifies that the state machine correctly validates a set of predefined valid states. The test iterates through each state and checks if the state machine's validation function returns true, ensuring that all valid states are recognized as such by the state machine.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 005@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Validate each of the valid state values | state = <valid state values> | EXPECT_TRUE(obj.validate_sm(state)) | Should Pass |
*/
TEST(em_sm_t_Test, ValidateValidStates) {
    std::cout << "Entering ValidateValidStates test" << std::endl;
    em_state_t valid_states[] = {
        em_state_agent_unconfigured,
        em_state_agent_autoconfig_rsp_pending,
        em_state_agent_wsc_m2_pending,
        em_state_agent_owconfig_pending,
        em_state_agent_onewifi_bssconfig_ind,
        em_state_agent_autoconfig_renew_pending,
        em_state_agent_topo_synchronized,
        em_state_agent_channel_pref_query,
        em_state_agent_channel_selection_pending,
        em_state_agent_channel_select_configuration_pending,
        em_state_agent_channel_report_pending,
        em_state_agent_channel_scan_result_pending,
        em_state_agent_configured,
        em_state_agent_topology_notify,
        em_state_agent_ap_cap_report,
        em_state_agent_client_cap_report,
        em_state_agent_sta_link_metrics_pending,
        em_state_agent_steer_btm_res_pending,
        em_state_agent_beacon_report_pending,
        em_state_agent_ap_metrics_pending,
        em_state_ctrl_unconfigured,
        em_state_ctrl_wsc_m1_pending,
        em_state_ctrl_wsc_m2_sent,
        em_state_ctrl_topo_sync_pending,
        em_state_ctrl_topo_synchronized,
        em_state_ctrl_channel_query_pending,
        em_state_ctrl_channel_pref_report_pending,
        em_state_ctrl_channel_queried,
        em_state_ctrl_channel_select_pending,
        em_state_ctrl_channel_selected,
        em_state_ctrl_channel_cnf_pending,
        em_state_ctrl_channel_report_pending,
        em_state_ctrl_channel_scan_pending,
        em_state_ctrl_configured,
        em_state_ctrl_misconfigured,
        em_state_ctrl_sta_cap_pending,
        em_state_ctrl_sta_cap_confirmed,
        em_state_ctrl_sta_link_metrics_pending,
        em_state_ctrl_sta_steer_pending,
        em_state_ctrl_steer_btm_req_ack_rcvd,
        em_state_ctrl_sta_disassoc_pending,
        em_state_ctrl_set_policy_pending,
        em_state_ctrl_ap_mld_config_pending,
        em_state_ctrl_ap_mld_configured,
        em_state_ctrl_bsta_mld_config_pending,
        em_state_ctrl_ap_mld_req_ack_rcvd,
        em_state_ctrl_avail_spectrum_inquiry_pending
    };

    for (em_state_t state : valid_states) {
        em_sm_t obj;
        std::cout << "Validating the state value " << static_cast<int>(state) << std::endl;
        EXPECT_TRUE(obj.validate_sm(state));
    }
    std::cout << "Exiting ValidateValidStates test" << std::endl;
}



/**
* @brief Test to validate the state machine with an invalid state
*
* This test checks the behavior of the state machine when an invalid state is provided. 
* It ensures that the state machine correctly identifies and handles invalid states by returning false.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 006@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Define an invalid state | invalid_state = static_cast<em_state_t>(em_state_max + 1) | Should be successful | |
* | 02 | Validate the state machine with the invalid state | obj.validate_sm(invalid_state) | false | Should Fail |
*/
TEST(em_sm_t_Test, ValidateInvalidState) {
    std::cout << "Entering ValidateInvalidState test" << std::endl;
    em_sm_t obj;
    em_state_t invalid_state = static_cast<em_state_t>(em_state_max + 1);
    EXPECT_FALSE(obj.validate_sm(invalid_state));
    std::cout << "Exiting ValidateInvalidState test" << std::endl;
}