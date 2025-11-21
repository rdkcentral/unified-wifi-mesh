
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
#include <climits>
#include <iomanip>
#include "em_cmd.h"
#include "dm_network.h"

// Converts em_bus_event_type_t to readable string
const char* bus_event_type_to_str(em_bus_event_type_t type)
{
    switch (type) {
        case em_bus_event_type_none:               return "em_bus_event_type_none";
        case em_bus_event_type_chirp:              return "em_bus_event_type_chirp";
        case em_bus_event_type_reset:              return "em_bus_event_type_reset";
        case em_bus_event_type_dev_test:           return "em_bus_event_type_dev_test";
        case em_bus_event_type_set_dev_test:       return "em_bus_event_type_set_dev_test";
        case em_bus_event_type_get_network:        return "em_bus_event_type_get_network";
        case em_bus_event_type_get_device:         return "em_bus_event_type_get_device";
        case em_bus_event_type_remove_device:      return "em_bus_event_type_remove_device";
        case em_bus_event_type_get_radio:          return "em_bus_event_type_get_radio";
        case em_bus_event_type_get_ssid:           return "em_bus_event_type_get_ssid";
        case em_bus_event_type_set_ssid:           return "em_bus_event_type_set_ssid";
        case em_bus_event_type_get_channel:        return "em_bus_event_type_get_channel";
        case em_bus_event_type_set_channel:        return "em_bus_event_type_set_channel";
        case em_bus_event_type_scan_channel:       return "em_bus_event_type_scan_channel";
        case em_bus_event_type_scan_result:        return "em_bus_event_type_scan_result";
        case em_bus_event_type_get_bss:            return "em_bus_event_type_get_bss";
        case em_bus_event_type_get_sta:            return "em_bus_event_type_get_sta";
        case em_bus_event_type_steer_sta:          return "em_bus_event_type_steer_sta";
        case em_bus_event_type_disassoc_sta:       return "em_bus_event_type_disassoc_sta";
        case em_bus_event_type_get_policy:         return "em_bus_event_type_get_policy";
        case em_bus_event_type_set_policy:         return "em_bus_event_type_set_policy";
        case em_bus_event_type_btm_sta:            return "em_bus_event_type_btm_sta";
        case em_bus_event_type_start_dpp:          return "em_bus_event_type_start_dpp";
        case em_bus_event_type_dev_init:           return "em_bus_event_type_dev_init";
        case em_bus_event_type_cfg_renew:          return "em_bus_event_type_cfg_renew";
        case em_bus_event_type_radio_config:       return "em_bus_event_type_radio_config";
        case em_bus_event_type_vap_config:         return "em_bus_event_type_vap_config";
        case em_bus_event_type_sta_list:           return "em_bus_event_type_sta_list";
        case em_bus_event_type_ap_cap_query:       return "em_bus_event_type_ap_cap_query";
        case em_bus_event_type_client_cap_query:   return "em_bus_event_type_client_cap_query";
        case em_bus_event_type_topo_sync:          return "em_bus_event_type_topo_sync";
        case em_bus_event_type_onewifi_private_cb: return "em_bus_event_type_onewifi_private_cb";
        case em_bus_event_type_onewifi_mesh_sta_cb:return "em_bus_event_type_onewifi_mesh_sta_cb";
        case em_bus_event_type_sta_assoc:          return "em_bus_event_type_sta_assoc";
        case em_bus_event_type_channel_pref_query: return "em_bus_event_type_channel_pref_query";
        case em_bus_event_type_sta_link_metrics:   return "em_bus_event_type_sta_link_metrics";
        case em_bus_event_type_set_radio:          return "em_bus_event_type_set_radio";
        case em_bus_event_type_btm_response:       return "em_bus_event_type_btm_response";
        case em_bus_event_type_get_mld_config:     return "em_bus_event_type_get_mld_config";
        case em_bus_event_type_mld_reconfig:       return "em_bus_event_type_mld_reconfig";
        case em_bus_event_type_beacon_report:      return "em_bus_event_type_beacon_report";
        case em_bus_event_type_ap_metrics_report:  return "em_bus_event_type_ap_metrics_report";
        case em_bus_event_type_get_reset:          return "em_bus_event_type_get_reset";
        default: return "Unknown bus event type";
    }
}

// Converts em_cmd_type_t to readable string
const char* cmd_type_to_str(em_cmd_type_t type)
{
    switch (type) {
        case em_cmd_type_none:              return "em_cmd_type_none";
        case em_cmd_type_reset:             return "em_cmd_type_reset";
        case em_cmd_type_dev_test:          return "em_cmd_type_dev_test";
        case em_cmd_type_set_dev_test:      return "em_cmd_type_set_dev_test";
        case em_cmd_type_get_network:       return "em_cmd_type_get_network";
        case em_cmd_type_get_device:        return "em_cmd_type_get_device";
        case em_cmd_type_remove_device:     return "em_cmd_type_remove_device";
        case em_cmd_type_get_radio:         return "em_cmd_type_get_radio";
        case em_cmd_type_get_ssid:          return "em_cmd_type_get_ssid";
        case em_cmd_type_set_ssid:          return "em_cmd_type_set_ssid";
        case em_cmd_type_get_channel:       return "em_cmd_type_get_channel";
        case em_cmd_type_set_channel:       return "em_cmd_type_set_channel";
        case em_cmd_type_scan_channel:      return "em_cmd_type_scan_channel";
        case em_cmd_type_scan_result:       return "em_cmd_type_scan_result";
        case em_cmd_type_get_bss:           return "em_cmd_type_get_bss";
        case em_cmd_type_get_sta:           return "em_cmd_type_get_sta";
        case em_cmd_type_steer_sta:         return "em_cmd_type_steer_sta";
        case em_cmd_type_disassoc_sta:      return "em_cmd_type_disassoc_sta";
        case em_cmd_type_btm_sta:           return "em_cmd_type_btm_sta";
        case em_cmd_type_start_dpp:         return "em_cmd_type_start_dpp";
        case em_cmd_type_onewifi_cb:        return "em_cmd_type_onewifi_cb";
        case em_cmd_type_topo_sync:         return "em_cmd_type_topo_sync";
        case em_cmd_type_sta_assoc:         return "em_cmd_type_sta_assoc";
        case em_cmd_type_channel_pref_query:return "em_cmd_type_channel_pref_query";
        case em_cmd_type_sta_link_metrics:  return "em_cmd_type_sta_link_metrics";
        case em_cmd_type_set_radio:         return "em_cmd_type_set_radio";
        case em_cmd_type_btm_report:        return "em_cmd_type_btm_report";
        case em_cmd_type_get_mld_config:    return "em_cmd_type_get_mld_config";
        case em_cmd_type_mld_reconfig:      return "em_cmd_type_mld_reconfig";
        case em_cmd_type_beacon_report:     return "em_cmd_type_beacon_report";
        case em_cmd_type_ap_metrics_report: return "em_cmd_type_ap_metrics_report";
        case em_cmd_type_get_reset:         return "em_cmd_type_get_reset";
        default: return "Unknown cmd type";
    }
}

// Converts em_event_type_t to readable string
const char* em_event_type_to_string(em_event_type_t type) {
    switch (type) {
        case em_event_type_frame:  return "em_event_type_frame";
        case em_event_type_device: return "em_event_type_device";
        case em_event_type_node:   return "em_event_type_node";
        case em_event_type_bus:    return "em_event_type_bus";        
        case em_event_type_max:    return "em_event_type_max";
        default:                   return "unknown_em_event_type";
    }
}

/**
 * @brief Validate conversion from bus event type to command type.
 *
 * This test verifies that the static method bus_2_cmd_type of the em_cmd_t class correctly converts various bus event types to their corresponding command types. It ensures that for each defined bus event in the mapping, the returned command type matches the expected value. This is critical to confirm the integrity and correctness of the underlying conversion logic.
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
 * | Variation / Step | Description                                                                                      | Test Data                                                                                       | Expected Result                                                                                              | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ | ----------- |
 * | 01               | Validate that the default constructor of em_cmd_t does not throw an exception.                   | No input; output: Object creation should be successful.                                          | Object is created successfully without exceptions.                                                         | Should Pass |
 * | 02               | Invoke bus_2_cmd_type for each bus event and verify that the returned command type matches expected. | For each test case: input busEvent = em_bus_event_type_x, expectedCmd = em_cmd_type_y (varies per case) | For every input, bus_2_cmd_type returns the correct command type and the assertion EXPECT_EQ passes.         | Should Pass |
 */
TEST(em_cmd_t, bus_2_cmd_type_ValidConversion)
{
    std::cout << "Entering bus_2_cmd_type_ValidConversion test" << std::endl;
    EXPECT_NO_THROW({ em_cmd_t obj; });
    struct BusToCmdMapping {
        em_bus_event_type_t busEvent;
        em_cmd_type_t expectedCmd;
    };
    BusToCmdMapping testCases[] = {
        { em_bus_event_type_none,               em_cmd_type_none },
        { em_bus_event_type_chirp,              em_cmd_type_none },
        { em_bus_event_type_reset,              em_cmd_type_reset },
        { em_bus_event_type_dev_test,           em_cmd_type_dev_test },
        { em_bus_event_type_set_dev_test,       em_cmd_type_set_dev_test },
        { em_bus_event_type_get_network,        em_cmd_type_get_network },
        { em_bus_event_type_get_device,         em_cmd_type_get_device },
        { em_bus_event_type_remove_device,      em_cmd_type_remove_device },
        { em_bus_event_type_get_radio,          em_cmd_type_get_radio },
        { em_bus_event_type_get_ssid,           em_cmd_type_get_ssid },
        { em_bus_event_type_set_ssid,           em_cmd_type_set_ssid },
        { em_bus_event_type_get_channel,        em_cmd_type_get_channel },
        { em_bus_event_type_set_channel,        em_cmd_type_set_channel },
        { em_bus_event_type_scan_channel,       em_cmd_type_scan_channel },
        { em_bus_event_type_scan_result,        em_cmd_type_scan_result },
        { em_bus_event_type_get_bss,            em_cmd_type_get_bss },
        { em_bus_event_type_get_sta,            em_cmd_type_get_sta },
        { em_bus_event_type_steer_sta,          em_cmd_type_steer_sta },
        { em_bus_event_type_disassoc_sta,       em_cmd_type_disassoc_sta },
        { em_bus_event_type_get_policy,         em_cmd_type_get_policy },
        { em_bus_event_type_set_policy,         em_cmd_type_set_policy },
        { em_bus_event_type_btm_sta,            em_cmd_type_btm_sta },
        { em_bus_event_type_dev_init,           em_cmd_type_dev_init },
        { em_bus_event_type_cfg_renew,          em_cmd_type_cfg_renew },
        { em_bus_event_type_radio_config,       em_cmd_type_none },
        { em_bus_event_type_sta_list,           em_cmd_type_sta_list },
        { em_bus_event_type_ap_cap_query,       em_cmd_type_ap_cap_query },
        { em_bus_event_type_client_cap_query,   em_cmd_type_client_cap_query },
        { em_bus_event_type_listener_stop,      em_cmd_type_none },
        { em_bus_event_type_dm_commit,          em_cmd_type_none },
        { em_bus_event_type_m2_tx,              em_cmd_type_none },
        { em_bus_event_type_topo_sync,          em_cmd_type_em_config },
        { em_bus_event_type_onewifi_mesh_sta_cb,em_cmd_type_none },
        { em_bus_event_type_onewifi_radio_cb,   em_cmd_type_none },
        { em_bus_event_type_m2ctrl_configuration, em_cmd_type_none },
        { em_bus_event_type_channel_sel_req,    em_cmd_type_none },
        { em_bus_event_type_set_radio,          em_cmd_type_set_radio },
        { em_bus_event_type_bss_tm_req,         em_cmd_type_none },
        { em_bus_event_type_channel_scan_params, em_cmd_type_none },
        { em_bus_event_type_get_mld_config,     em_cmd_type_get_mld_config },
        { em_bus_event_type_mld_reconfig,       em_cmd_type_mld_reconfig },
        { em_bus_event_type_beacon_report,      em_cmd_type_beacon_report },
        { em_bus_event_type_recv_wfa_action_frame, em_cmd_type_none },
        { em_bus_event_type_recv_gas_frame,     em_cmd_type_none },
        { em_bus_event_type_get_sta_client_type, em_cmd_type_none },
        { em_bus_event_type_assoc_status,       em_cmd_type_none },
        { em_bus_event_type_ap_metrics_report,  em_cmd_type_ap_metrics_report },
        { em_bus_event_type_bss_info,           em_cmd_type_none },
        { em_bus_event_type_get_reset,          em_cmd_type_get_reset },
        { em_bus_event_type_recv_csa_beacon_frame, em_cmd_type_none }
    };

    for (const auto &testCase : testCases)
    {
        std::cout << "Invoking bus_2_cmd_type with bus event: " << bus_event_type_to_str(testCase.busEvent)
              << " (" << static_cast<int>(testCase.busEvent) << ")" << std::endl;
        em_cmd_type_t retVal = em_cmd_t::bus_2_cmd_type(testCase.busEvent);
        std::cout << "Returned command type: " << cmd_type_to_str(retVal)
              << " (" << static_cast<int>(retVal) << ")" << std::endl;
        std::cout << "Expected command type: " << cmd_type_to_str(testCase.expectedCmd)
              << " (" << static_cast<int>(testCase.expectedCmd) << ")" << std::endl;
        EXPECT_EQ(retVal, testCase.expectedCmd);
    }
    
    std::cout << "Exiting bus_2_cmd_type_ValidConversion test" << std::endl;
}
/**
 * @brief This test verifies that an invalid bus event type value (below the valid range) is handled properly.
 *
 * The test converts a bus event type that is below the valid range using the bus_2_cmd_type function, expecting
 * it to return the default command type (em_cmd_type_none). It ensures that the conversion method correctly identifies
 * invalid input and returns the appropriate fallback value.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call em_cmd_t::bus_2_cmd_type with an invalid bus event type value (-1) to check for negative conversion. | invalidInput = -1, output: retVal = em_cmd_type_none | The returned command type (retVal) should equal em_cmd_type_none; assertion EXPECT_EQ passes | Should Fail |
 */
TEST(em_cmd_t, NegativeConversionBelowRange)
{
    std::cout << "Entering NegativeConversionBelowRange test" << std::endl;
    em_cmd_t obj;
    em_bus_event_type_t invalidInput = static_cast<em_bus_event_type_t>(-1);
    std::cout << "Invoking bus_2_cmd_type with invalid bus event type value (below range): " << -1 << std::endl;
    em_cmd_type_t retVal = em_cmd_t::bus_2_cmd_type(invalidInput);
    std::cout << "Returned command type value: " << cmd_type_to_str(retVal) << std::endl;
    EXPECT_EQ(retVal, em_cmd_type_none);
    std::cout << "Exiting NegativeConversionBelowRange test" << std::endl;
}
/**
 * @brief Validate that bus_2_cmd_type returns em_cmd_type_none for an invalid bus event type input.
 *
 * This test verifies that providing an invalid bus event type (above the allowed range) to the bus_2_cmd_type function returns em_cmd_type_none. This ensures that the conversion logic correctly handles inputs that fall outside the valid range.
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
 * | Variation / Step | Description                                                                     | Test Data                                                       | Expected Result                                                         | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------- | --------------------------------------------------------------- | ----------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke bus_2_cmd_type with an invalid bus event type (above valid range)          | invalidInput = (em_bus_event_type_max + 1), expectedRetVal = em_cmd_type_none | Function returns em_cmd_type_none and EXPECT_EQ assertion passes         | Should Fail |
 */
TEST(em_cmd_t, NegativeConversionAboveRange)
{
    std::cout << "Entering NegativeConversionAboveRange test" << std::endl;
    em_cmd_t obj;
    em_bus_event_type_t invalidInput = static_cast<em_bus_event_type_t>(em_bus_event_type_max + 1);
    std::cout << "Invoking bus_2_cmd_type with invalid bus event type value (above range): " << static_cast<int>(em_bus_event_type_max + 1) << std::endl;
    em_cmd_type_t retVal = em_cmd_t::bus_2_cmd_type(invalidInput);
    std::cout << "Returned command type value: " << cmd_type_to_str(retVal) << std::endl;
    EXPECT_EQ(retVal, em_cmd_type_none);
    std::cout << "Exiting NegativeConversionAboveRange test" << std::endl;
}
/**
 * @brief Verify that em_cmd_t::clone() produces an accurate deep copy of a fully initialized object
 *
 * This test initializes an em_cmd_t object with various fields, calls its clone()
 * method, and verifies that the cloned object contains the same data as the original.
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
 * | Variation / Step | Description                                                                                         | Test Data                                                                                                                                                                                                                          | Expected Result                                                                                                   | Notes         |
 * | :--------------: | --------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | ------------- |
 * | 01               | Initialize the original em_cmd_t object with predetermined values                                 | m_type = em_cmd_type_set_policy, m_param.u.args.num_args = 1, fixed_args = "FixedArgs", m_orch_op_idx = 0, m_num_orch_desc = 1, m_orch_desc[0].op = dm_orch_type_net_insert, m_orch_desc[0].submit = true, m_evt = nullptr, m_em_candidates = nullptr | Object fields should be set without errors                                                                        | Should be successful |
 * | 02               | Invoke the clone() method on the original object                                                    | Input: orig, Invocation of clone(); Output: clone pointer                                                                                                                                                                         | clone pointer should not be nullptr                                                                               | Should Pass   |
 * | 03               | Verify that the cloned object's fields match the original object's values                           | Compare clone->m_type with orig.m_type, clone->m_orch_op_idx with orig.m_orch_op_idx, clone->m_num_orch_desc with orig.m_num_orch_desc, clone->m_orch_desc[0].op with orig.m_orch_desc[0].op, clone->m_orch_desc[0].submit with orig.m_orch_desc[0].submit, clone->m_param.u.args.num_args with orig.m_param.u.args.num_args | All corresponding fields should match and assert conditions must be true as per the test case expectations                          | Should Pass   |
 */
TEST(em_cmd_t, CloneFull) 
{
    std::cout << "Entering CloneFull test" << std::endl;
    em_cmd_t orig;
    orig.m_type = em_cmd_type_set_policy;
    orig.m_param.u.args.num_args = 1;
    strncpy(orig.m_param.u.args.fixed_args, "FixedArgs", 
            sizeof(orig.m_param.u.args.fixed_args)-1);
    orig.m_orch_op_idx = 0;
    orig.m_num_orch_desc = 1;
    orig.m_orch_desc[0].op = dm_orch_type_net_insert;
    orig.m_orch_desc[0].submit = true;
    orig.m_evt = nullptr;
    orig.m_em_candidates = nullptr;
    em_cmd_t* clone = orig.clone();
    ASSERT_NE(clone, nullptr);
    EXPECT_EQ(clone->m_type, orig.m_type);
    EXPECT_EQ(clone->m_orch_op_idx, orig.m_orch_op_idx);
    EXPECT_EQ(clone->m_num_orch_desc, orig.m_num_orch_desc);
    EXPECT_EQ(clone->m_orch_desc[0].op, orig.m_orch_desc[0].op);
    EXPECT_EQ(clone->m_orch_desc[0].submit, orig.m_orch_desc[0].submit);
    EXPECT_EQ(clone->m_param.u.args.num_args, orig.m_param.u.args.num_args);
    std::cout << "Exiting CloneFull test" << std::endl;
}
/**
 * @brief Validate the deep copy functionality of the clone method in em_cmd_t
 *
 * This test verifies that the clone method of the em_cmd_t class correctly creates a deep copy of an object. It ensures that all member variables, including complex structures, are duplicated without reference sharing.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create and initialize original em_cmd_t object with preset values | m_num_orch_desc = 0, m_orch_op_idx = 0, m_type = em_cmd_type_get_network, num_args = 0, fixed_args = "OriginalFixed" | Original object initialized with specified values | Should be successful |
 * | 02 | Invoke the clone() method on the original object to perform a deep copy | original object as input | Returns a non-null pointer to a cloned object | Should Pass |
 * | 03 | Validate that the clone object's fields match those of the original | cloneObj->m_type, cloneObj->m_param.u.args.num_args, cloneObj->m_param.u.args.fixed_args; expected values: em_cmd_type_get_network, 0, "OriginalFixed" | Cloned object's m_type, num_args, and fixed_args are identical to the original | Should Pass |
 * | 04 | Log the exit from the test | Console output message | "Exiting CloneDeepCopy test" is printed | Should be successful |
 */
TEST(em_cmd_t, CloneDeepCopy) 
{
    std::cout << "Entering CloneDeepCopy test" << std::endl;
    em_cmd_t original;
    original.m_num_orch_desc = 0;
    original.m_orch_op_idx = 0;
    original.m_type = em_cmd_type_get_network;
    original.m_param.u.args.num_args = 0;
    strncpy(original.m_param.u.args.fixed_args,
            "OriginalFixed",
            sizeof(original.m_param.u.args.fixed_args)-1);
    em_cmd_t* cloneObj = original.clone();
    ASSERT_NE(cloneObj, nullptr);
    EXPECT_EQ(cloneObj->m_type, original.m_type);
    EXPECT_EQ(cloneObj->m_param.u.args.num_args, 0);
    EXPECT_STREQ(cloneObj->m_param.u.args.fixed_args, "OriginalFixed");
    std::cout << "Exiting CloneDeepCopy test" << std::endl;
}
/**
 * @brief Validate that clone_for_next correctly clones and updates the original object's fields
 *
 * This test verifies that when invoking the clone_for_next API on an existing em_cmd_t instance,
 * the cloned instance has its m_type identical to the original and its m_orch_op_idx incremented by one.
 * Additionally, it checks that the m_orch_desc field is properly duplicated. This ensures that the clone
 * process maintains necessary data consistency and correctly computes any field modifications.
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
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize original em_cmd_t object with preset values | orig.m_type = em_cmd_type_reset, orig.m_orch_op_idx = 0, orig.m_num_orch_desc = 2, each m_orch_desc[i].op = dm_orch_type_net_insert, m_orch_desc[i].submit = true | The original object is correctly initialized for cloning | Should be successful |
 * | 02 | Invoke clone_for_next API on original object | Input: original object 'orig' with initialized fields; Output: pointer 'clone' returned from orig.clone_for_next() | Returned clone pointer is not nullptr | Should Pass |
 * | 03 | Validate cloned object fields | Compare clone->m_type with orig.m_type, clone->m_orch_op_idx with (orig.m_orch_op_idx + 1), clone->m_orch_desc[0].op with orig.m_orch_desc[0].op | Clone object's m_type equals original's; m_orch_op_idx is incremented by one; m_orch_desc elements are correctly cloned | Should Pass |
 */
TEST(em_cmd_t, CloneFullFields) 
{
    std::cout << "Entering CloneFullFields test" << std::endl;
    em_cmd_t orig;
    orig.m_type = em_cmd_type_reset;
    orig.m_orch_op_idx = 0;
    orig.m_num_orch_desc = 2;
    for (unsigned int i = 0; i < orig.m_num_orch_desc; i++) {
        orig.m_orch_desc[i].op = dm_orch_type_net_insert;
        orig.m_orch_desc[i].submit = true;
    }
    em_cmd_t* clone = orig.clone_for_next();
    ASSERT_NE(clone, nullptr);
    EXPECT_EQ(clone->m_type, orig.m_type);
    EXPECT_EQ(clone->m_orch_op_idx, orig.m_orch_op_idx + 1);
    EXPECT_EQ(clone->m_orch_desc[0].op, orig.m_orch_desc[0].op);
    std::cout << "Exiting CloneFullFields test" << std::endl;
}
/**
 * @brief Test the clone_for_next function to ensure an object with a null event remains unchanged after cloning.
 *
 * This test verifies that cloning an em_cmd_t object containing a null event pointer produces a clone that also has
 * a null event field. It checks that all essential parameters are correctly copied and that the clone_for_next() API
 * handles null events appropriately.
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
 * | 01 | Initialize original em_cmd_t object with specific values including type, parameters, event as nullptr, and orchestrator details. | m_type = em_cmd_type_reset, m_param.u.args.num_args = 0, m_param.u.args.fixed_args = "SafeArgs", m_orch_op_idx = 0, m_num_orch_desc = 2, m_orch_desc[0].op = dm_orch_type_net_insert, m_orch_desc[0].submit = true, m_orch_desc[1].op = dm_orch_type_net_update, m_orch_desc[1].submit = false, m_evt = nullptr | Object initialized with given parameters | Should be successful |
 * | 02 | Invoke clone_for_next() method to clone the object. | Function call: clone = orig.clone_for_next() | Returns a non-null pointer for the clone | Should Pass |
 * | 03 | Verify that the cloned object's m_evt field remains nullptr. | clone->m_evt after cloning | m_evt field in clone is nullptr as expected | Should Pass |
 */
TEST(em_cmd_t, CloneNullEvent) 
{
    std::cout << "Entering CloneNullEvent test" << std::endl;
    em_cmd_t orig;
    orig.m_type = em_cmd_type_reset;
    orig.m_param.u.args.num_args = 0;
    strncpy(orig.m_param.u.args.fixed_args,
            "SafeArgs",
            sizeof(orig.m_param.u.args.fixed_args)-1);
    orig.m_orch_op_idx = 0;
    orig.m_num_orch_desc = 2;
    orig.m_orch_desc[0].op = dm_orch_type_net_insert;
    orig.m_orch_desc[0].submit = true;
    orig.m_orch_desc[1].op = dm_orch_type_net_update;
    orig.m_orch_desc[1].submit = false;
    orig.m_evt = nullptr;
    em_cmd_t* clone = orig.clone_for_next();
    ASSERT_NE(clone, nullptr);
    EXPECT_EQ(clone->m_evt, nullptr);
    std::cout << "Exiting CloneNullEvent test" << std::endl;
}
/**
 * @brief Verify that modifying a cloned em_cmd_t object does not affect the original instance.
 *
 * This test verifies that the clone_for_next() method creates an independent deep copy of the em_cmd_t object.
 * It tests that modifications made to the cloned object's fields (such as num_args, fixed_args, and orch_desc)
 * do not alter the values of the original object, ensuring clone independence.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 008
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                                                     | Test Data                                                                                                                                                                                                                                                                                                                                        | Expected Result                                                                                                         | Notes           |
 * | :--------------: | -------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- | --------------- |
 * |      01        | Initialize the original em_cmd_t instance with default settings.                                                                | m_type = em_cmd_type_reset, num_args = 1, fixed_args = OriginalFixed, orch_op_idx = 0, num_orch_desc = 2, orch_desc[].op = dm_orch_type_net_insert, orch_desc[].submit = true, evt = nullptr, em_candidates = nullptr                                                                                                                     | Original instance is correctly initialized with provided values.                                                       | Should be successful |
 * |      02        | Clone the original instance using clone_for_next() and verify the cloned pointer is not null.                                      | clone = orig.clone_for_next()                                                                                                                                                                                                                                                                                                                    | clone != nullptr (Assertion passes)                                                                                      | Should Pass     |
 * |      03        | Modify the clone's fields including num_args, fixed_args, and orch_desc[0] parameters.                                             | clone->m_param.u.args.num_args = 42, clone->m_param.u.args.fixed_args = Changed, clone->m_orch_desc[0].op = dm_orch_type_net_delete, clone->m_orch_desc[0].submit = false                                                                                                                                                                          | Clone is updated with new values and changes are isolated from the original.                                             | Should Pass     |
 * |      04        | Assert that the original instance retains its initial values, confirming the clone is independent.                               | orig.m_param.u.args.num_args = 1, orig.m_param.u.args.fixed_args = OriginalFixed, orig.m_orch_desc[0].op = dm_orch_type_net_insert, orig.m_orch_desc[0].submit = true, orig.m_orch_op_idx = 0                                                                                                                                              | Original remains unchanged as per the expected default values.                                                           | Should Pass     |
 */
TEST(em_cmd_t, CloneIndependence) 
{
    std::cout << "Entering CloneIndependence test" << std::endl;
    em_cmd_t orig;
    orig.m_type = em_cmd_type_reset;
    orig.m_param.u.args.num_args = 1;
    strncpy(orig.m_param.u.args.fixed_args,
            "OriginalFixed",
            sizeof(orig.m_param.u.args.fixed_args)-1);
    orig.m_orch_op_idx = 0;
    orig.m_num_orch_desc = 2;
    for (unsigned int i = 0; i < orig.m_num_orch_desc; i++) {
        orig.m_orch_desc[i].op = dm_orch_type_net_insert;
        orig.m_orch_desc[i].submit = true;
    }
    orig.m_evt = nullptr;
    orig.m_em_candidates = nullptr;
    em_cmd_t* clone = orig.clone_for_next();
    ASSERT_NE(clone, nullptr);
    clone->m_param.u.args.num_args = 42;
    strncpy(clone->m_param.u.args.fixed_args,
            "Changed",
            sizeof(clone->m_param.u.args.fixed_args)-1);
    clone->m_orch_desc[0].op = dm_orch_type_net_delete;
    clone->m_orch_desc[0].submit = false;
    EXPECT_EQ(orig.m_param.u.args.num_args, 1);
    EXPECT_STREQ(orig.m_param.u.args.fixed_args, "OriginalFixed");
    EXPECT_EQ(orig.m_orch_desc[0].op, dm_orch_type_net_insert);
    EXPECT_EQ(orig.m_orch_desc[0].submit, true);
    EXPECT_EQ(orig.m_orch_op_idx, 0);
    std::cout << "Exiting CloneIndependence test" << std::endl;
}
/**
 * @brief Verify cloning process maintains string integrity when modifying the clone.
 *
 * This test creates an original em_cmd_t object with predefined values and clones it using clone_for_next(). It then verifies that the clone is not null, that the fixed_args string in the clone matches the expected value, and that modifying the clone's fixed_args does not affect the original object's fixed_args.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 009
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | ------------- | ----- |
 * | 01 | Initialize original em_cmd_t object with test parameters | num_args = 1, fixed_args = "FixedArgs", m_orch_op_idx = 0, m_num_orch_desc = 2, orch_desc[0].op = dm_orch_type_net_insert, orch_desc[0].submit = true, orch_desc[1].op = dm_orch_type_net_update, orch_desc[1].submit = false | Original object is correctly initialized with provided parameters | Should be successful |
 * | 02 | Invoke clone_for_next() to create a clone of the original object | original object as initialized above | Clone is not nullptr | Should Pass |
 * | 03 | Verify the fixed_args member of the cloned object | cloned object's fixed_args, expected value "FixedArgs" | fixed_args in clone is equal to "FixedArgs" | Should Pass |
 * | 04 | Modify the clone's fixed_args and check original remains unchanged | Modify clone->m_param.u.args.fixed_args[0] = 'X'; original fixed_args expected "FixedArgs" | Original object's fixed_args remains "FixedArgs" | Should Pass |
 */
TEST(em_cmd_t, CloneStringIntegrity) 
{
    std::cout << "Entering CloneStringIntegrity test" << std::endl;
    em_cmd_t orig;
    orig.m_param.u.args.num_args = 1;
    strncpy(orig.m_param.u.args.fixed_args, "FixedArgs",
            sizeof(orig.m_param.u.args.fixed_args)-1);
    orig.m_orch_op_idx = 0;
    orig.m_num_orch_desc = 2;
    orig.m_orch_desc[0].op = dm_orch_type_net_insert;
    orig.m_orch_desc[0].submit = true;
    orig.m_orch_desc[1].op = dm_orch_type_net_update;
    orig.m_orch_desc[1].submit = false;
    em_cmd_t* clone = orig.clone_for_next();
    ASSERT_NE(clone, nullptr);
    EXPECT_STREQ(clone->m_param.u.args.fixed_args, "FixedArgs");
    clone->m_param.u.args.fixed_args[0] = 'X';
    EXPECT_STREQ(orig.m_param.u.args.fixed_args, "FixedArgs");
    std::cout << "Exiting CloneStringIntegrity test" << std::endl;
}
/**
 * @brief Verify that clone_for_next returns nullptr at the last index.
 *
 * This test initializes an em_cmd_t object with specific member values and invokes the clone_for_next method.
 * It ensures that when the command's orch_op_idx is at the last valid index, the clone_for_next method returns nullptr,
 * thereby correctly handling the boundary condition.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 010
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize an em_cmd_t instance with m_num_orch_desc set to 3 and m_orch_op_idx set to 2. | m_num_orch_desc = 3, m_orch_op_idx = 2 | Instance is configured with the specified values | Should be successful |
 * | 02 | Invoke the clone_for_next method and validate the returned pointer is nullptr. | Input: em_cmd_t instance; Output: clone pointer from clone_for_next() | Returned pointer equals nullptr | Should Pass |
 */
TEST(em_cmd_t, CloneForNextAtLastIndexReturnsNull)
{
    std::cout << "Entering CloneForNextAtLastIndexReturnsNull test" << std::endl;
    em_cmd_t cmd;
    cmd.m_num_orch_desc = 3;
    cmd.m_orch_op_idx = 2;
    em_cmd_t* clone = cmd.clone_for_next();
    EXPECT_EQ(clone, nullptr);
    std::cout << "Exiting CloneForNextAtLastIndexReturnsNull test" << std::endl;
}
/**
 * @brief Verify that clone_for_next returns nullptr when there are no orchestrator descriptions available.
 *
 * This test verifies that when an em_cmd_t object's m_num_orch_desc is set to 0 and m_orch_op_idx is set to 0, 
 * the clone_for_next method correctly returns a nullptr. The verification is performed by asserting that clone is equal to nullptr.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 011@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Print entering message to indicate the start of the test case | output = "Entering CloneForNextEmptyOrchDescReturnsNull test" | Message is printed to console | Should be successful |
 * | 02 | Instantiate em_cmd_t object and set m_num_orch_desc and m_orch_op_idx to 0 | em_cmd_t cmd; input: m_num_orch_desc = 0, m_orch_op_idx = 0 | Object state is set correctly | Should be successful |
 * | 03 | Call clone_for_next() method on the object and capture the returned pointer | Call: cmd.clone_for_next(); output: clone pointer | Returned clone should be nullptr | Should Pass |
 * | 04 | Assert that the returned pointer is nullptr using EXPECT_EQ | Assertion: EXPECT_EQ(clone, nullptr) | Assertion passes if clone is nullptr | Should Pass |
 * | 05 | Print exiting message to indicate the end of the test case | output = "Exiting CloneForNextEmptyOrchDescReturnsNull test" | Message is printed to console | Should be successful |
 */
TEST(em_cmd_t, CloneForNextEmptyOrchDescReturnsNull)
{
    std::cout << "Entering CloneForNextEmptyOrchDescReturnsNull test" << std::endl;
    em_cmd_t cmd;
    cmd.m_num_orch_desc = 0;
    cmd.m_orch_op_idx = 0;
    em_cmd_t* clone = cmd.clone_for_next();
    EXPECT_EQ(clone, nullptr);
    std::cout << "Exiting CloneForNextEmptyOrchDescReturnsNull test" << std::endl;
}
/**
 * @brief Verify that clone_for_next returns nullptr when invoked on a single element at the last index
 *
 * This test verifies that when an em_cmd_t object, representing a command with only one element (m_num_orch_desc = 1) 
 * and at the starting index (m_orch_op_idx = 0), is processed through the clone_for_next method, the function correctly 
 * returns a nullptr indicating no further commands exist. This scenario is critical to ensure that the method behaves 
 * as expected when there are no additional commands to clone.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |@n
 * | :----: | --------- | ---------- |-------------- | ----- |@n
 * | 01 | Create an instance of em_cmd_t with a single command element and invoke clone_for_next | m_num_orch_desc = 1, m_orch_op_idx = 0; clone_for_next() is invoked | The method should return a nullptr indicating there is no next command | Should Pass |
 */
TEST(em_cmd_t, CloneForNextSingleElementLastIndexReturnsNull)
{
    std::cout << "Entering CloneForNextSingleElementLastIndexReturnsNull test" << std::endl;
    em_cmd_t cmd;
    cmd.m_num_orch_desc = 1;
    cmd.m_orch_op_idx = 0;
    em_cmd_t* clone = cmd.clone_for_next();
    EXPECT_EQ(clone, nullptr);
    std::cout << "Exiting CloneForNextSingleElementLastIndexReturnsNull test" << std::endl;
}
/**
 * @brief Test that validates correct conversion from command type to bus event type.
 *
 * This test case verifies that the cmd_2_bus_event_type API function correctly converts various
 * command types to their corresponding bus event types based on a predefined mapping. The test iterates
 * through each mapping, invokes the API with the command type, and asserts that the returned bus event
 * type matches the expected value.
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
 * | 01 | Invoke cmd_2_bus_event_type for each command-to-bus mapping and verify the result | For each test case: input: cmd = em_cmd_type_<type>, output: expected = em_bus_event_type_<type> (specific mapping values from test data array) | Returned bus event type must match the expected bus event type; ASSERT_EQ is satisfied | Should Pass |
 */
TEST(em_cmd_t, cmd_2_bus_event_type_ValidConversion) {
    std::cout << "Entering ValidConversion test" << std::endl;
    em_cmd_t obj;

    struct CmdToBusMapping {
        em_cmd_type_t cmd;
        em_bus_event_type_t expected;
    };
    CmdToBusMapping testCases[] = {
        { em_cmd_type_none,                em_bus_event_type_none },
        { em_cmd_type_reset,               em_bus_event_type_reset },
        { em_cmd_type_dev_test,            em_bus_event_type_dev_test },
        { em_cmd_type_set_ssid,            em_bus_event_type_set_ssid },
		{ em_cmd_type_em_config,           em_bus_event_type_topo_sync },
		{ em_cmd_type_dev_init,            em_bus_event_type_dev_init },
		{ em_cmd_type_cfg_renew,           em_bus_event_type_cfg_renew },
		{ em_cmd_type_sta_list,            em_bus_event_type_sta_list },
		{ em_cmd_type_get_mld_config,      em_bus_event_type_get_mld_config },
		{ em_cmd_type_mld_reconfig,        em_bus_event_type_mld_reconfig },
		{ em_cmd_type_get_reset,           em_bus_event_type_get_reset}
    };
		
    // Loop through each mapping and invoke the method, then validate the result.
    for (const auto &testCase : testCases) {
        std::cout << "\nInvoking cmd_2_bus_event_type with command type: "
                  << cmd_type_to_str(testCase.cmd)
                  << " (" << static_cast<int>(testCase.cmd) << ")" << std::endl;
        em_bus_event_type_t busEvent = obj.cmd_2_bus_event_type(testCase.cmd);
        std::cout << "Returned bus event type: "
                  << bus_event_type_to_str(busEvent)
                  << " (" << static_cast<int>(busEvent) << ")"
                  << " for command type: " << cmd_type_to_str(testCase.cmd)
                  << std::endl;
        std::cout << "Expected bus event type: "
                  << bus_event_type_to_str(testCase.expected)
                  << " (" << static_cast<int>(testCase.expected) << ")"
                  << std::endl;
        EXPECT_EQ(busEvent, testCase.expected)
            << "Mismatch for command type: " << cmd_type_to_str(testCase.cmd)
            << " — expected " << bus_event_type_to_str(testCase.expected)
            << " but got " << bus_event_type_to_str(busEvent);
    }
    std::cout << "Exiting ValidConversion test" << std::endl;
}
/**
 * @brief Test to validate the conversion function handles negative command values correctly
 *
 * This test verifies that when a negative enumeration value is passed to the conversion API (cmd_2_bus_event_type),
 * the function returns the expected default value, indicating that the negative input is handled gracefully.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 014
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                             | Test Data                                                      | Expected Result                                                                      | Notes        |
 * | :--------------: | ------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- | ------------------------------------------------------------------------------------ | ------------ |
 * | 01               | Invoke cmd_2_bus_event_type with an invalid negative command input to test error handling for negatives | invalidCmd = -1, output: busEvent = em_bus_event_type_none       | Function returns em_bus_event_type_none and assertion (EXPECT_EQ) passes              | Should Fail  |
 */
TEST(em_cmd_t, NegativeConversion_NegativeValue) {
    std::cout << "Entering NegativeConversion_NegativeValue test" << std::endl;
    em_cmd_t obj;
    em_cmd_type_t invalidCmd = static_cast<em_cmd_type_t>(-1);
    std::cout << "Invoking cmd_2_bus_event_type with invalid negative value -1" << std::endl;
    em_bus_event_type_t busEvent;
    busEvent = obj.cmd_2_bus_event_type(invalidCmd);
    std::cout << "Returned bus event type: " << bus_event_type_to_str(busEvent) << " for invalid input value -1 " << std::endl;
    EXPECT_EQ(busEvent, em_bus_event_type_none);
    std::cout << "Exiting NegativeConversion_NegativeValue test" << std::endl;
}
/**
 * @brief Test negative conversion for command value exceeding allowed range
 *
 * This test verifies that when an invalid command value (em_cmd_type_max + 1) is passed to the 
 * cmd_2_bus_event_type function, it returns the expected bus event type "em_bus_event_type_none". 
 * The test ensures that the API correctly handles inputs that exceed the predefined range.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 015
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke cmd_2_bus_event_type with a value exceeding the allowed range (em_cmd_type_max + 1) | invalidCmd = em_cmd_type_max + 1, output (busEvent) expected = em_bus_event_type_none | busEvent should equal em_bus_event_type_none and EXPECT_EQ should pass | Should Fail |
 */
TEST(em_cmd_t, NegativeConversion_ExceedRange) {
    std::cout << "Entering NegativeConversion_ExceedRange test" << std::endl;
    em_cmd_t obj;
    em_cmd_type_t invalidCmd = static_cast<em_cmd_type_t>(em_cmd_type_max + 1);
    std::cout << "Invoking cmd_2_bus_event_type with value exceeding range (em_cmd_type_max + 1)" << std::endl;
    em_bus_event_type_t busEvent;
    busEvent = obj.cmd_2_bus_event_type(invalidCmd);
    std::cout << "Returned bus event type: " << bus_event_type_to_str(busEvent) << " for input value exceeding defined range (em_cmd_type_max + 1)" << std::endl;
    EXPECT_EQ(busEvent, em_bus_event_type_none);
    std::cout << "Exiting NegativeConversion_ExceedRange test" << std::endl;
}
/**
 * @brief Validate that copy_bus_event correctly copies a minimal bus event.
 *
 * This test verifies that the em_cmd_t::copy_bus_event method correctly handles a bus event structure that is minimally initialized. It ensures that no exceptions are thrown during the copy operation, that the internal event pointer (m_evt) is valid, and that the event properties (type and data_len) are correctly copied. 
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 016@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- | -------------- | ----- |
 * | 01 | Initialize a minimal bus event structure with type 'none' and data_len set to 0. | evt: type = em_bus_event_type_none, data_len = 0 | Bus event structure is initialized with the specified minimal values. | Should be successful |
 * | 02 | Instantiate an em_cmd_t object and check that its internal m_evt pointer is not null. | cmd: new instance of em_cmd_t | cmd.m_evt is not nullptr. | Should Pass |
 * | 03 | Invoke copy_bus_event with the minimal bus event ensuring no exceptions are thrown. | input: evt with minimal values (type = em_bus_event_type_none, data_len = 0) | No exception is thrown and m_evt->type is updated to em_event_type_bus. | Should Pass |
 * | 04 | Verify that the copied bus event inside cmd.m_evt has matching type and data_len values compared to the original evt. | output: copied: type and data_len from cmd.m_evt->u.bevt | copied.type equals evt.type and copied.data_len equals evt.data_len. | Should Pass |
 */
TEST(em_cmd_t, PositiveCopyMinimalBusEvent) {
    std::cout << "Entering PositiveCopyMinimalBusEvent test" << std::endl;
    em_bus_event_t evt;
    std::memset(&evt, 0, sizeof(evt));
    evt.type = em_bus_event_type_none;
    evt.data_len = 0;
    EXPECT_NO_THROW({
        em_cmd_t cmd;
        ASSERT_NE(cmd.m_evt, nullptr);
        std::cout << "Invoking copy_bus_event with minimal bus event" << std::endl;
        EXPECT_NO_THROW(cmd.copy_bus_event(&evt));
        ASSERT_NE(cmd.m_evt, nullptr);
        EXPECT_EQ(cmd.m_evt->type, em_event_type_bus);
        const em_bus_event_t &copied = cmd.m_evt->u.bevt;
        EXPECT_EQ(copied.type, evt.type);
        EXPECT_EQ(copied.data_len, evt.data_len);
        std::cout << "Copied m_evt->type = "
                  << cmd.m_evt->type << " (" << em_event_type_to_string(cmd.m_evt->type) << "), "
                  << "bus event type = "
                  << copied.type << " (" << bus_event_type_to_str(copied.type) << "), "
                  << "data_len = " << copied.data_len << std::endl;
    });
    std::cout << "Exiting PositiveCopyMinimalBusEvent test" << std::endl;
}
/**
 * @brief Verify that the copy_bus_event function deep copies a fully populated bus event.
 *
 * This test ensures that when a complete bus event is passed to the copy_bus_event API, the event is deep copied correctly,
 * including event type, data length, sub-document name, and argument details. It validates that no exceptions are thrown and that
 * the copied event contains values identical to the original.
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
 * | 01 | Invoke copy_bus_event with a complete bus event structure featuring valid type, non-zero data_len, populated subdoc name and arguments | evt.type = em_bus_event_type_get_device, evt.data_len = 100, evt.u.subdoc.name = TestSubdoc, evt.params.u.args.num_args = 2, evt.params.u.args.args[0] = arg1_value, evt.params.u.args.args[1] = arg2_value | API does not throw exception; m_evt is not null; m_evt->type is em_event_type_bus; all copied fields match the original event | Should Pass |
 */
TEST(em_cmd_t, PositiveCopyCompleteBusEvent) {
    std::cout << "Entering PositiveCopyCompleteBusEvent test" << std::endl;

    // Prepare a complete bus event with type = em_bus_event_type_get_device, data_len > 0
    em_bus_event_t evt;
    std::memset(&evt, 0, sizeof(evt));
    evt.type = em_bus_event_type_get_device;
    evt.data_len = 100;

    std::cout << "Initialized evt with type = " 
              << bus_event_type_to_str(evt.type)
              << " and data_len = " << evt.data_len << std::endl;

    // Populate one of the union members (subdoc name)
    const char* subdocName = "TestSubdoc";
    strncpy(evt.u.subdoc.name, subdocName, sizeof(evt.u.subdoc.name) - 1);
    evt.u.subdoc.name[sizeof(evt.u.subdoc.name) - 1] = '\0';
    std::cout << "Assigned evt.u.subdoc.name = " << evt.u.subdoc.name << std::endl;

    // Populate parameters (arguments)
    evt.params.u.args.num_args = 2;
    const char* arg1 = "arg1_value";
    const char* arg2 = "arg2_value";
    strncpy(evt.params.u.args.args[0], arg1, sizeof(evt.params.u.args.args[0]) - 1);
    strncpy(evt.params.u.args.args[1], arg2, sizeof(evt.params.u.args.args[1]) - 1);
    evt.params.u.args.args[0][sizeof(evt.params.u.args.args[0]) - 1] = '\0';
    evt.params.u.args.args[1][sizeof(evt.params.u.args.args[1]) - 1] = '\0';

    std::cout << "Assigned evt.params.u.args.num_args = " << evt.params.u.args.num_args << std::endl;
    std::cout << "Assigned evt.params.u.args.args[0] = " << evt.params.u.args.args[0] << std::endl;
    std::cout << "Assigned evt.params.u.args.args[1] = " << evt.params.u.args.args[1] << std::endl;

    EXPECT_NO_THROW({
        em_cmd_t cmd;
        std::cout << "Invoking copy_bus_event with complete bus event" << std::endl;
        EXPECT_NO_THROW(cmd.copy_bus_event(&evt));

        ASSERT_NE(cmd.m_evt, nullptr) << "m_evt is NULL after copy_bus_event";

        // Validate deep copy of the bus event
        EXPECT_EQ(cmd.m_evt->type, em_event_type_bus)
            << "Expected m_evt->type to be em_event_type_bus after copy";

        const em_bus_event_t &copied = cmd.m_evt->u.bevt;

        std::cout << "Copied bus event type: " << bus_event_type_to_str(copied.type) << std::endl;
        std::cout << "Copied data_len: " << copied.data_len << std::endl;
        EXPECT_EQ(copied.type, evt.type);
        EXPECT_EQ(copied.data_len, evt.data_len);

        std::cout << "Copied subdoc name: " << copied.u.subdoc.name << std::endl;
        EXPECT_STREQ(copied.u.subdoc.name, evt.u.subdoc.name);

        std::cout << "Copied args num: " << copied.params.u.args.num_args << std::endl;
        EXPECT_EQ(copied.params.u.args.num_args, evt.params.u.args.num_args);
        std::cout << "Copied arg[0]: " << copied.params.u.args.args[0] << std::endl;
        std::cout << "Copied arg[1]: " << copied.params.u.args.args[1] << std::endl;
        EXPECT_STREQ(copied.params.u.args.args[0], evt.params.u.args.args[0]);
        EXPECT_STREQ(copied.params.u.args.args[1], evt.params.u.args.args[1]);
    });

    std::cout << "Exiting PositiveCopyCompleteBusEvent test" << std::endl;
}
/**
 * @brief Validate that the copy_bus_event API correctly duplicates the bus event for various enum event types.
 *
 * This test iterates through a list of bus event types and for each type, it initializes an event instance, sets its properties
 * (including data length and simple parameter arguments), and then invokes the copy_bus_event function. The test validates
 * that no exceptions are thrown, the copied event pointer is non-null, and the copied event properties match the original.
 * This ensures that the API handles different enum values and correctly replicates the event structure.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 018@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Initialize bus event with a specific event type, data length, and parameter value, then call copy_bus_event. | eventTypes[i] = <various enum values>, data_len = 50, num_args = 1, args[0] = "LoopArg" | API does not throw any exception, copied event pointer (m_evt) is non-null, and copied event fields (type, data_len, num_args, and args[0]) are identical to the original | Should Pass |
 */
TEST(em_cmd_t, PositiveCopyEnumLoop) {
    std::cout << "Entering PositiveCopyEnumLoop test" << std::endl;

    em_bus_event_type_t eventTypes[] = {
        em_bus_event_type_none, em_bus_event_type_chirp, em_bus_event_type_reset,
        em_bus_event_type_dev_test, em_bus_event_type_set_dev_test, em_bus_event_type_get_network,
        em_bus_event_type_get_device, em_bus_event_type_remove_device, em_bus_event_type_get_radio,
        em_bus_event_type_get_ssid, em_bus_event_type_set_ssid, em_bus_event_type_get_channel,
        em_bus_event_type_set_channel, em_bus_event_type_scan_channel, em_bus_event_type_scan_result,
        em_bus_event_type_get_bss, em_bus_event_type_get_sta, em_bus_event_type_steer_sta,
        em_bus_event_type_disassoc_sta, em_bus_event_type_get_policy, em_bus_event_type_set_policy,
        em_bus_event_type_btm_sta, em_bus_event_type_start_dpp, em_bus_event_type_dev_init,
        em_bus_event_type_cfg_renew, em_bus_event_type_radio_config, em_bus_event_type_vap_config,
        em_bus_event_type_sta_list, em_bus_event_type_ap_cap_query, em_bus_event_type_client_cap_query,
        em_bus_event_type_listener_stop, em_bus_event_type_dm_commit, em_bus_event_type_m2_tx,
        em_bus_event_type_topo_sync, em_bus_event_type_onewifi_private_cb, em_bus_event_type_onewifi_mesh_sta_cb,
        em_bus_event_type_onewifi_radio_cb, em_bus_event_type_m2ctrl_configuration, em_bus_event_type_sta_assoc,
        em_bus_event_type_channel_pref_query, em_bus_event_type_channel_sel_req, em_bus_event_type_sta_link_metrics,
        em_bus_event_type_set_radio, em_bus_event_type_bss_tm_req, em_bus_event_type_btm_response,
        em_bus_event_type_channel_scan_params, em_bus_event_type_get_mld_config, em_bus_event_type_mld_reconfig,
        em_bus_event_type_beacon_report, em_bus_event_type_recv_wfa_action_frame, em_bus_event_type_recv_gas_frame,
        em_bus_event_type_get_sta_client_type, em_bus_event_type_assoc_status, em_bus_event_type_ap_metrics_report,
        em_bus_event_type_bss_info, em_bus_event_type_get_reset, em_bus_event_type_recv_csa_beacon_frame
    };

    size_t totalTypes = sizeof(eventTypes) / sizeof(eventTypes[0]);

    for (size_t i = 0; i < totalTypes; i++) {
        em_bus_event_t evt;
        std::memset(&evt, 0, sizeof(evt));
        evt.type = eventTypes[i];
        evt.data_len = 50;

        std::cout << "\n[Loop " << i << "] Initialized evt with type = "
                  << bus_event_type_to_str(evt.type)
                  << " and data_len = " << evt.data_len << std::endl;

        // Populate simple parameter
        evt.params.u.args.num_args = 1;
        const char* loopArg = "LoopArg";
        strncpy(evt.params.u.args.args[0], loopArg, sizeof(evt.params.u.args.args[0]) - 1);
        evt.params.u.args.args[0][sizeof(evt.params.u.args.args[0]) - 1] = '\0';
        std::cout << "[Loop " << i << "] Assigned evt.params.u.args.args[0] = " 
                  << evt.params.u.args.args[0] << std::endl;

        em_cmd_t cmd;
        std::cout << "[Loop " << i << "] Invoking copy_bus_event" << std::endl;
        EXPECT_NO_THROW(cmd.copy_bus_event(&evt));

        ASSERT_NE(cmd.m_evt, nullptr) << "[Loop " << i << "] m_evt is NULL after copy_bus_event";
        EXPECT_EQ(cmd.m_evt->type, em_event_type_bus)
            << "[Loop " << i << "] Expected m_evt->type = em_event_type_bus";

        const em_bus_event_t &copied = cmd.m_evt->u.bevt;

        std::cout << "[Loop " << i << "] Copied bus event type: " 
                  << bus_event_type_to_str(copied.type) << std::endl;
        std::cout << "[Loop " << i << "] Copied data_len: " << copied.data_len << std::endl;
        EXPECT_EQ(copied.type, evt.type);
        EXPECT_EQ(copied.data_len, evt.data_len);

        std::cout << "[Loop " << i << "] Copied args num: " << copied.params.u.args.num_args << std::endl;
        EXPECT_EQ(copied.params.u.args.num_args, evt.params.u.args.num_args);

        std::cout << "[Loop " << i << "] Copied arg[0]: " << copied.params.u.args.args[0] << std::endl;
        EXPECT_STREQ(copied.params.u.args.args[0], evt.params.u.args.args[0]);
    }

    std::cout << "Exiting PositiveCopyEnumLoop test" << std::endl;
}
/**
 * @brief Verify that the copy_bus_event function throws an exception when invoked with a NULL pointer.
 *
 * This test checks the robustness of the copy_bus_event function in handling a NULL pointer argument. The function is expected to throw an exception when provided with an invalid input.
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
 * | Variation / Step | Description                                              | Test Data                           | Expected Result                                   | Notes       |
 * | :--------------: | -------------------------------------------------------- | ----------------------------------- | ------------------------------------------------- | ----------- |
 * | 01               | Instantiate em_cmd_t and invoke copy_bus_event with NULL | input: pointer value = NULL         | Exception is thrown as verified by EXPECT_ANY_THROW | Should Pass |
 */
TEST(em_cmd_t, NegativeCopyNullPointer) {
    std::cout << "Entering NegativeCopyNullPointer test" << std::endl;
    em_cmd_t cmd;
    std::cout << "Invoking copy_bus_event with NULL pointer" << std::endl;
    EXPECT_ANY_THROW(cmd.copy_bus_event(NULL));
    std::cout << "Exiting NegativeCopyNullPointer test" << std::endl;
}
/**
 * @brief Validate default initialization and deep copying of em_cmd_t
 *
 * This test verifies that an instance of em_cmd_t, when initialized by calling copy_frame_event with a properly prepared em_frame_event_t, correctly performs a deep copy of the frame event data. The test checks that the source frame is properly allocated and filled with known data, that copy_frame_event does not throw exceptions, and that the deep copied event's frame and type match the original's.
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
 * | :--------------: | ----------- | --------- | ------------- | ----- |
 * | 01 | Prepare the source frame event by setting frame length and populating with a known pattern | evt.frame_len = 5, evt.frame allocated and filled with values (10, 11, 12, 13, 14) | evt.frame is allocated and filled correctly | Should be successful |
 * | 02 | Invoke copy_frame_event on cmd using the prepared evt | Input: evt pointer with frame_len = 5 and frame pattern (10, 11, 12, 13, 14); Output: cmd.m_evt updated | No exception thrown and deep copy of frame event performed | Should Pass |
 * | 03 | Validate deep copy by checking event type and frame content match | cmd.m_evt->type compared to em_event_type_frame, copied->frame_len = 5, memcmp result comparing copied->frame with evt.frame | cmd.m_evt is not null, type equals em_event_type_frame, and frame content matches source | Should Pass |
 * | 04 | Cleanup allocated memory from source event | free(evt.frame) called | Memory is deallocated without issues | Should be successful |
 */
TEST(em_cmd_t, ValidDefaultInitialization) {
    std::cout << "Entering ValidDefaultInitialization test" << std::endl;

    em_cmd_t cmd;

    // Step 1: Prepare the source frame event
    em_frame_event_t evt{};
    evt.frame_len = 5;
    evt.frame = static_cast<unsigned char*>(malloc(evt.frame_len));
    ASSERT_NE(evt.frame, nullptr);

    // Fill source frame with a known pattern
    for (unsigned int i = 0; i < evt.frame_len; i++) {
        evt.frame[i] = static_cast<unsigned char>(i + 10);
    }

    std::cout << "Source evt.frame_len = " << evt.frame_len << std::endl;
    std::cout << "Source evt.frame contents:";
    for (unsigned int i = 0; i < evt.frame_len; i++) {
        std::cout << " " << static_cast<int>(evt.frame[i]);
    }
    std::cout << std::endl;

    // Step 2: Invoke copy_frame_event
    EXPECT_NO_THROW(cmd.copy_frame_event(&evt));

    // Step 3: Validate deep copy
    ASSERT_NE(cmd.m_evt, nullptr);
    EXPECT_EQ(cmd.m_evt->type, em_event_type_frame);

    em_frame_event_t* copied = &cmd.m_evt->u.fevt;
    EXPECT_EQ(copied->frame_len, evt.frame_len);
    ASSERT_NE(copied->frame, nullptr);

    // Compare content
    EXPECT_EQ(std::memcmp(copied->frame, evt.frame, evt.frame_len), 0)
        << "Copied frame content does not match source";

    std::cout << "Copied frame contents:";
    for (unsigned int i = 0; i < copied->frame_len; i++) {
        std::cout << " " << static_cast<int>(copied->frame[i]);
    }
    std::cout << std::endl;

    // Step 4: Cleanup
    free(evt.frame);

    std::cout << "Exiting ValidDefaultInitialization test" << std::endl;
}
/**
 * @brief Verify that the copy_frame_event API throws an exception when passed a NULL pointer.
 *
 * This test verifies that the copy_frame_event method of the em_cmd_t class correctly handles a NULL pointer argument by throwing an exception. It ensures that the API behaves robustly when faced with invalid input.
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
 * | Variation / Step | Description                                                               | Test Data                                  | Expected Result                              | Notes      |
 * | :--------------: | ------------------------------------------------------------------------- | ------------------------------------------ | -------------------------------------------- | ---------- |
 * | 01               | Invoke copy_frame_event with a NULL pointer on a valid em_cmd_t instance. | cmd = valid em_cmd_t object, pointer = nullptr | API throws an exception as verified by EXPECT_ANY_THROW | Should Fail |
 */
TEST(em_cmd_t, NullPointer) {
    std::cout << "Entering NullPointer test" << std::endl;
    em_cmd_t cmd;
    std::cout << "Invoking copy_frame_event with NULL pointer" << std::endl;
    EXPECT_ANY_THROW(cmd.copy_frame_event(nullptr));
    std::cout << "Exiting NullPointer test" << std::endl;
}
/**
 * @brief Validate dump_bus_event API with valid pointer across multiple event types.
 *
 * This test verifies that the dump_bus_event function of em_cmd_t correctly processes a properly initialized
 * bus event object, where the sub-document name and argument strings are set, across all valid event types.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 022@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize the bus event object with a valid sub-document name and argument strings. | evt_obj.u.subdoc.name = "SubdocName", evt_obj.params.u.args.num_args = 2, evt_obj.params.u.args.args[0] = "arg0", evt_obj.params.u.args.args[1] = "arg1" | Event object fields are correctly initialized. | Should be successful |
 * | 02 | Loop through each event type, assign the current type to the event object, invoke dump_bus_event, and check return status. | For each iteration: evt->type = current event type from em_bus_event_type_none to em_bus_event_type_max-1 | dump_bus_event returns 0 for each event type and EXPECT_EQ verifies the return value. | Should Pass |
 */
TEST(em_cmd_t, DumpBusEvent_ValidPointerLoop) {
    std::cout << "Entering DumpBusEvent_ValidPointerLoop test" << std::endl;
    em_bus_event_t evt_obj;
    memset(&evt_obj, 0, sizeof(evt_obj));
    const char *subdoc_name = "SubdocName";
    strncpy(evt_obj.u.subdoc.name, subdoc_name, sizeof(evt_obj.u.subdoc.name) - 1);
    evt_obj.u.subdoc.name[sizeof(evt_obj.u.subdoc.name) - 1] = '\0';
    evt_obj.params.u.args.num_args = 2;
    const char *arg0 = "arg0";
    const char *arg1 = "arg1";
    strncpy(evt_obj.params.u.args.args[0], arg0, sizeof(evt_obj.params.u.args.args[0]) - 1);
    evt_obj.params.u.args.args[0][sizeof(evt_obj.params.u.args.args[0]) - 1] = '\0';
    strncpy(evt_obj.params.u.args.args[1], arg1, sizeof(evt_obj.params.u.args.args[1]) - 1);
    evt_obj.params.u.args.args[1][sizeof(evt_obj.params.u.args.args[1]) - 1] = '\0';
    for (int type = em_bus_event_type_none; type < em_bus_event_type_max; ++type) {
        em_bus_event_t *evt = &evt_obj;      
        evt->type = static_cast<em_bus_event_type_t>(type);
        std::cout << "Invoking dump_bus_event with event type: " << type << std::endl;
        int ret = em_cmd_t::dump_bus_event(evt);
        std::cout << "Returned status: " << ret << " for event type: " << type << std::endl;
        EXPECT_EQ(ret, 0);
    }
    std::cout << "Exiting DumpBusEvent_ValidPointerLoop test" << std::endl;
}
/**
 * @brief Test dump_bus_event API to validate correct handling of a null pointer.
 *
 * This test verifies that calling dump_bus_event with a null pointer does not throw an exception
 * and returns the expected error code (-1). It ensures that the API handles invalid input gracefully.
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
 * | Variation / Step | Description                                                              | Test Data                                               | Expected Result                                                    | Notes         |
 * | :--------------: | ------------------------------------------------------------------------ | ------------------------------------------------------- | ------------------------------------------------------------------ | ------------- |
 * | 01               | Create an instance of em_cmd_t and invoke dump_bus_event with nullptr      | input: event pointer = nullptr, output: ret = -1        | dump_bus_event returns -1 and EXPECT_EQ assertion passes           | Should Pass   |
 */
TEST(em_cmd_t, DumpBusEvent_NullPointer) {
    std::cout << "Entering DumpBusEvent_NullPointer test" << std::endl;    
    // Create an instance of em_cmd_t using the default constructor.
    EXPECT_NO_THROW({ em_cmd_t obj; });    
    std::cout << "Invoking dump_bus_event with null event pointer" << std::endl;
    int ret = 0;
    EXPECT_NO_THROW({
        ret = em_cmd_t::dump_bus_event(nullptr);
        std::cout << "dump_bus_event invoked with nullptr." << std::endl;
    });
    std::cout << "Returned status: " << ret << " for null event pointer" << std::endl;
    EXPECT_EQ(ret, -1);    
    std::cout << "Exiting DumpBusEvent_NullPointer test" << std::endl;
}
/**
 * @brief Test dump_bus_event function with an invalid event type.
 *
 * This test verifies that the dump_bus_event function correctly handles an invalid event type by not throwing any exceptions and by returning an error code (-1). It ensures that the API can gracefully manage unexpected input.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 024
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                   | Test Data                                           | Expected Result                                                    | Notes                |
 * | :--------------: | --------------------------------------------------------------------------------------------- | --------------------------------------------------- | ------------------------------------------------------------------ | -------------------- |
 * | 01               | Initialize em_cmd_t and em_bus_event_t objects and set an invalid event type                    | evt.type = em_bus_event_type_max                    | em_bus_event_t object configured with invalid event type           | Should be successful |
 * | 02               | Invoke dump_bus_event with the invalid event type using EXPECT_NO_THROW block                   | input: evt.type = em_bus_event_type_max, output: ret | No exception thrown during invocation of dump_bus_event             | Should Pass          |
 * | 03               | Verify that the returned status is -1 using EXPECT_EQ                                          | output: ret = -1                                    | Return value equals -1 as expected by the assertion                | Should Pass          |
 */
TEST(em_cmd_t, DumpBusEvent_InvalidEvent) {
    std::cout << "Entering DumpBusEvent_InvalidEvent test" << std::endl;
    em_cmd_t obj;
    em_bus_event_t evt;
    evt.type = em_bus_event_type_max;    
    std::cout << "Invoking dump_bus_event with invalid event type em_bus_event_type_max" << std::endl;
    int ret = 0;
    EXPECT_NO_THROW({
        ret = em_cmd_t::dump_bus_event(&evt);
        std::cout << "dump_bus_event invoked. Event details dumped with invalid event type value em_bus_event_type_max" << std::endl;
    });
    std::cout << "Returned status: " << ret << " for invalid event type em_bus_event_type_max" << std::endl;
    EXPECT_EQ(-1, ret);    
    std::cout << "Exiting DumpBusEvent_InvalidEvent test" << std::endl;
}
/**
 * @brief To verify that the default constructor of em_cmd_t initializes the object without throwing exceptions.
 *
 * This test creates an instance of em_cmd_t using its default constructor and confirms that no exceptions are thrown during construction.
 * It also logs the state of the object’s member variables to ensure they are initialized with the expected default values.
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
 * | Variation / Step | Description                                                      | Test Data                                                                                              | Expected Result                                                       | Notes                |
 * | :---------------: | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------- | -------------------- |
 * | 01               | Print the message indicating the start of the test               | None                                                                                                   | "Entering DefaultConstruction_Success test" is printed                | Should be successful |
 * | 02               | Invoke the default constructor of em_cmd_t within EXPECT_NO_THROW  | No input; output: m_evt = nullptr, m_em_candidates = nullptr, m_type = default value, m_orch_op_idx = 0 or default | No exception is thrown and object is created in the default state       | Should Pass          |
 * | 03               | Log the state of the object's member variables after construction  | m_evt printed as nullptr, m_em_candidates printed as nullptr, m_type printed as default value, m_orch_op_idx printed as 0 or default | The printed object state matches expected default values                | Should be successful |
 * | 04               | Print the message indicating the end of the test                   | None                                                                                                   | "Exiting DefaultConstruction_Success test" is printed                 | Should be successful |
 */
TEST(em_cmd_t, DefaultConstruction_Success) {
    std::cout << "Entering DefaultConstruction_Success test" << std::endl;
    EXPECT_NO_THROW({
        em_cmd_t obj;
        std::cout << "Invoked em_cmd_t() default constructor." << std::endl;        
        std::cout << "Object state after construction:" << std::endl;
        std::cout << "  m_evt: " << obj.m_evt << " (expected: nullptr)" << std::endl;
        std::cout << "  m_em_candidates: " << obj.m_em_candidates << " (expected: nullptr)" << std::endl;
        std::cout << "  m_type: " << static_cast<int>(obj.m_type) << " (expected: default value)" << std::endl;
        std::cout << "  m_orch_op_idx: " << obj.m_orch_op_idx << " (expected: 0 or initialized default)" << std::endl;
    });    
    std::cout << "Exiting DefaultConstruction_Success test" << std::endl;
}
/**
 * @brief Validates default instantiation of em_cmd_t for various command types.
 *
 * This test verifies that the em_cmd_t object can be successfully instantiated with each of the predefined command types
 * without throwing an exception. It iterates over an array of command types, initializes the em_cmd_params_t structure with
 * net_node set to nullptr, and uses EXPECT_NO_THROW to validate that the constructor for em_cmd_t does not throw.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 026
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Iterate over an array of command types, set em_cmd_params_t.net_node to nullptr, and invoke the constructor of em_cmd_t for each type. | command_type = [em_cmd_type_none, em_cmd_type_reset, em_cmd_type_get_network, em_cmd_type_get_device, em_cmd_type_remove_device, em_cmd_type_get_radio, em_cmd_type_set_radio, em_cmd_type_get_ssid, em_cmd_type_set_ssid, em_cmd_type_get_channel, em_cmd_type_set_channel, em_cmd_type_scan_channel, em_cmd_type_scan_result, em_cmd_type_get_bss, em_cmd_type_get_sta, em_cmd_type_steer_sta, em_cmd_type_disassoc_sta, em_cmd_type_btm_sta, em_cmd_type_dev_init, em_cmd_type_dev_test, em_cmd_type_set_dev_test, em_cmd_type_cfg_renew, em_cmd_type_vap_config, em_cmd_type_sta_list, em_cmd_type_start_dpp, em_cmd_type_ap_cap_query, em_cmd_type_client_cap_query, em_cmd_type_topo_sync, em_cmd_type_em_config, em_cmd_type_onewifi_cb, em_cmd_type_sta_assoc, em_cmd_type_channel_pref_query, em_cmd_type_sta_link_metrics, em_cmd_type_op_channel_report, em_cmd_type_sta_steer, em_cmd_type_btm_report, em_cmd_type_sta_disassoc, em_cmd_type_get_policy, em_cmd_type_set_policy, em_cmd_type_avail_spectrum_inquiry, em_cmd_type_get_mld_config, em_cmd_type_mld_reconfig, em_cmd_type_beacon_report, em_cmd_type_ap_metrics_report, em_cmd_type_get_reset], em_cmd_params_t.net_node = nullptr | No exception is thrown during em_cmd_t instantiation (EXPECT_NO_THROW passes) | Should Pass |
 */
TEST(em_cmd_t, ValidInstantiationDefault) {
    std::cout << "Entering ValidInstantiationDefault test" << std::endl;
    em_cmd_type_t types[] = {
        em_cmd_type_none,
        em_cmd_type_reset,
        em_cmd_type_get_network,
        em_cmd_type_get_device,
        em_cmd_type_remove_device,
        em_cmd_type_get_radio,
        em_cmd_type_set_radio,
        em_cmd_type_get_ssid,
        em_cmd_type_set_ssid,
        em_cmd_type_get_channel,
        em_cmd_type_set_channel,
        em_cmd_type_scan_channel,
        em_cmd_type_scan_result,
        em_cmd_type_get_bss,
        em_cmd_type_get_sta,
        em_cmd_type_steer_sta,
        em_cmd_type_disassoc_sta,
        em_cmd_type_btm_sta,
        em_cmd_type_dev_init,
        em_cmd_type_dev_test,
        em_cmd_type_set_dev_test,
        em_cmd_type_cfg_renew,
        em_cmd_type_vap_config,
        em_cmd_type_sta_list,
        em_cmd_type_start_dpp,
        em_cmd_type_ap_cap_query,
        em_cmd_type_client_cap_query,
        em_cmd_type_topo_sync,
        em_cmd_type_em_config,
        em_cmd_type_onewifi_cb,
        em_cmd_type_sta_assoc,
        em_cmd_type_channel_pref_query,
        em_cmd_type_sta_link_metrics,
        em_cmd_type_op_channel_report,
        em_cmd_type_sta_steer,
        em_cmd_type_btm_report,
        em_cmd_type_sta_disassoc,
        em_cmd_type_get_policy,
        em_cmd_type_set_policy,
        em_cmd_type_avail_spectrum_inquiry,
        em_cmd_type_get_mld_config,
        em_cmd_type_mld_reconfig,
        em_cmd_type_beacon_report,
        em_cmd_type_ap_metrics_report,
        em_cmd_type_get_reset
    };
    for (size_t i = 0; i < sizeof(types)/sizeof(types[0]); i++) {
        em_cmd_params_t param = {};
        param.net_node = nullptr;
        std::cout << "Invoking constructor for command type: " << static_cast<unsigned int>(types[i]) << std::endl;
        EXPECT_NO_THROW({
            em_cmd_t cmd(types[i], param);
        });
    }
    std::cout << "Exiting ValidInstantiationDefault test" << std::endl;
}
/**
 * @brief Verifies that constructing an em_cmd_t with an invalid command type throws an exception.
 *
 * This test ensures that the constructor for em_cmd_t correctly handles an invalid command type (em_cmd_type_max)
 * by throwing an exception. It verifies proper error handling and input validation.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 027
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                      | Test Data                                                              | Expected Result                                                     | Notes               |
 * | :--------------: | ---------------------------------------------------------------- | ---------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------- |
 * | 01               | Log entry message indicating the start of the test execution     | -                                                                      | Message "Entering InvalidCmdTypeMax test" displayed                   | Should be successful  |
 * | 02               | Invoke em_cmd_t constructor with invalid command type            | input: command_type = em_cmd_type_max, input: param = default constructed | API throws an exception; EXPECT_ANY_THROW assertion passes             | Should Fail         |
 * | 03               | Log exit message indicating the end of test execution            | -                                                                      | Message "Exiting InvalidCmdTypeMax test" displayed                    | Should be successful  |
 */
TEST(em_cmd_t, InvalidCmdTypeMax) {
    std::cout << "Entering InvalidCmdTypeMax test" << std::endl;
    em_cmd_params_t param;
    std::cout << "Invoking constructor with invalid command type em_cmd_type_max" << std::endl;
    EXPECT_ANY_THROW({
        em_cmd_t cmd(em_cmd_type_max, param);
    });
    std::cout << "Exiting InvalidCmdTypeMax test" << std::endl;
}
/**
 * @brief Validate construction and type assignment of em_cmd_t across all command types
 *
 * This test verifies that creating em_cmd_t objects with a variety of command types results in the correct assignment of the type within each object. It constructs the em_cmd_t object using a default parameter and a dm_easy_mesh_t instance, then confirms the object type via EXPECT_EQ. This ensures that the constructor correctly initializes the command type for all supported command types.
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
 * | 01 | Initialize test parameters and dependencies, including setting param.u.args.num_args to 0, and initializing the dm_easy_mesh_t instance. | param.u.args.num_args = 0, dm.init() | dm_easy_mesh_t initialized successfully without errors. | Should be successful |
 * | 02 | For each command type in the defined list, create an em_cmd_t object and verify that its type matches the input type. | For each iteration: input: types[i] = em_cmd_type_x, param, dm; output: cmd.get_type() should equal types[i] | Each em_cmd_t object's type equals the corresponding command type provided, and the EXPECT_EQ assertion passes. | Should Pass |
 * | 03 | Deinitialize each em_cmd_t object within the loop and the dm_easy_mesh_t instance after the loop finishes. | cmd.deinit() in loop, dm.deinit() after loop | All objects are deinitialized without errors, and the test completes successfully. | Should be successful |
 */
TEST(em_cmd_t, ValidConstructionAllTypes)
{
    std::cout << "Entering ValidConstructionAllTypes test" << std::endl;
    em_cmd_params_t param{};
    param.u.args.num_args = 0;
    dm_easy_mesh_t dm;
    dm.init();
    em_cmd_type_t types[] = {
        em_cmd_type_none, 
        em_cmd_type_reset, 
        em_cmd_type_get_network,
        em_cmd_type_get_device,
        em_cmd_type_remove_device,
        em_cmd_type_get_radio,
        em_cmd_type_set_radio,
        em_cmd_type_get_ssid,
        em_cmd_type_set_ssid,
        em_cmd_type_get_channel,
        em_cmd_type_set_channel,
        em_cmd_type_scan_channel,
        em_cmd_type_scan_result,
        em_cmd_type_get_bss,
        em_cmd_type_get_sta,
        em_cmd_type_steer_sta,
        em_cmd_type_disassoc_sta,
        em_cmd_type_btm_sta,
        em_cmd_type_dev_init,
        em_cmd_type_dev_test,
        em_cmd_type_set_dev_test,
        em_cmd_type_cfg_renew,
        em_cmd_type_vap_config,
        em_cmd_type_sta_list,
        em_cmd_type_start_dpp,
        em_cmd_type_ap_cap_query,
        em_cmd_type_client_cap_query,
        em_cmd_type_topo_sync,
        em_cmd_type_em_config,
        em_cmd_type_onewifi_cb,
        em_cmd_type_sta_assoc,
        em_cmd_type_channel_pref_query,
        em_cmd_type_sta_link_metrics,
        em_cmd_type_op_channel_report,
        em_cmd_type_sta_steer,
        em_cmd_type_btm_report,
        em_cmd_type_sta_disassoc,
        em_cmd_type_get_policy,
        em_cmd_type_set_policy,
        em_cmd_type_avail_spectrum_inquiry,
        em_cmd_type_get_mld_config,
        em_cmd_type_mld_reconfig,
        em_cmd_type_beacon_report,
        em_cmd_type_ap_metrics_report,
        em_cmd_type_get_reset
    };
    int nTypes = sizeof(types) / sizeof(types[0]);
    for (int i = 0; i < nTypes; i++)
    {
        em_cmd_t cmd(types[i], param, dm);
        EXPECT_EQ(cmd.get_type(), types[i]);
        cmd.deinit();
    }
    dm.deinit();
    std::cout << "Exiting ValidConstructionAllTypes test" << std::endl;
}
/**
 * @brief Validates the proper construction of an em_cmd_t object with non-empty command parameters.
 *
 * This test verifies that an em_cmd_t object is correctly constructed when provided with a valid set of non-empty command parameters and a valid network data model. It checks if all the input parameters and data model fields are accurately assigned in the constructed object@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 029@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * |01| Initialize command parameters with one argument "testArg" and fixed argument "fixedTest". | em_cmd_params_t: num_args = 1, args[0] = "testArg", fixed_args = "fixedTest" | Parameters are correctly assigned in the structure. | Should be successful |
 * |02| Initialize network data model with predefined values. | dm_easy_mesh_t: m_num_radios = 2, m_num_bss = 3, m_num_opclass = 4, m_colocated = true | Data model is populated with valid network info. | Should be successful |
 * |03| Construct em_cmd_t object using the command type em_cmd_type_get_device with the above parameters and data model. | Call: em_cmd_t(em_cmd_type_get_device, param, dm) | Object is constructed successfully with proper assignment of type, parameters, and data model. | Should Pass |
 * |04| Validate each field of the constructed em_cmd_t object via assertions. | Check: m_type, m_param values, and m_data_model fields against expected values. | All assertions pass confirming correct construction. | Should Pass |
 */
TEST(em_cmd_t, ValidConstructionNonEmptyCommandParameters)
{
    std::cout << "Entering ValidConstructionNonEmptyCommandParameters test" << std::endl;
    em_cmd_params_t param{};
    param.u.args.num_args = 1;
    // Set first argument as "testArg"
    const char *testArg = "testArg";
    strncpy(param.u.args.args[0], testArg, sizeof(param.u.args.args[0]));
    // Set fixed_args as "fixedTest"
    const char *fixedTest = "fixedTest";
    strncpy(param.u.args.fixed_args, fixedTest, sizeof(param.u.args.fixed_args));
    // Create a dm_easy_mesh_t object with predefined network id (simulate valid network info)
    dm_easy_mesh_t dm{};
    dm.m_num_radios = 2;
    dm.m_num_bss = 3;
    dm.m_num_opclass = 4; 
    dm.m_colocated = true;
    // Construct em_cmd_t with type em_cmd_type_get_device.
    em_cmd_t cmd(em_cmd_type_get_device, param, dm);
    std::cout << "Constructed em_cmd_t" << std::endl;
    std::cout << "Parameter num_args: " << cmd.m_param.u.args.num_args << std::endl;
    std::cout << "Arg[0]: " << cmd.m_param.u.args.args[0] << std::endl;
    std::cout << "Fixed args: " << cmd.m_param.u.args.fixed_args << std::endl;
    std::cout << "m_num_radios: " << cmd.m_data_model.m_num_radios << std::endl;
    std::cout << "m_num_bss: " << cmd.m_data_model.m_num_bss << std::endl;
    std::cout << "m_num_opclass: " << cmd.m_data_model.m_num_opclass << std::endl;
    std::cout << "m_colocated: " << cmd.m_data_model.m_colocated << std::endl;
    EXPECT_EQ(cmd.m_type, em_cmd_type_get_device);
    EXPECT_EQ(cmd.m_param.u.args.num_args, 1);
    EXPECT_STREQ(cmd.m_param.u.args.args[0], "testArg");
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "fixedTest");
    EXPECT_EQ(cmd.m_data_model.m_num_radios, 2);
    EXPECT_EQ(cmd.m_data_model.m_num_bss, 3);
    EXPECT_EQ(cmd.m_data_model.m_num_opclass, 4);
    EXPECT_TRUE(cmd.m_data_model.m_colocated);
    std::cout << "Exiting ValidConstructionNonEmptyCommandParameters test" << std::endl;
}
/**
 * @brief Validate construction of em_cmd_t with an out-of-range command type.
 *
 * This test verifies that the em_cmd_t object is properly constructed when provided with an out-of-range command type (-1). The test ensures that the object’s m_type correctly reflects the invalid command type, which may help in identifying improper usage or validating range checks.
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
 * | Variation / Step | Description                                                                                  | Test Data                                                            | Expected Result                                                                      | Notes            |
 * | :--------------: | -------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- | ------------------------------------------------------------------------------------ | ---------------- |
 * | 01               | Print entering log message for the test                                                      | std::cout = "Entering ConstructionWithOutOfRangeCmdType test"          | Console displays the entering message                                               | Should be successful |
 * | 02               | Initialize command parameters setting num_args to 1                                          | param.u.args.num_args = 1                                              | Parameter structure is initialized with num_args = 1                                  | Should be successful |
 * | 03               | Initialize dm_easy_mesh instance by calling dm.init()                                        | Call to dm.init()                                                    | dm_easy_mesh instance is successfully initialized                                      | Should be successful |
 * | 04               | Construct em_cmd_t object with an out-of-range command type (-1)                               | Input: type = -1, param with num_args = 1, dm handle from dm instance   | em_cmd_t object is created and m_type is set to -1                                       | Should Pass      |
 * | 05               | Validate the command object's m_type using EXPECT_EQ                                         | Output: cmd.m_type should equal -1                                     | EXPECT_EQ(cmd.m_type, -1) passes                                                        | Should Pass      |
 * | 06               | Deinitialize em_cmd_t and dm_easy_mesh by calling their respective deinit() methods            | Calls: cmd.deinit(), dm.deinit()                                       | Resources are released and the objects are deinitialized                                | Should be successful |
 * | 07               | Print exiting log message for the test                                                       | std::cout = "Exiting ConstructionWithOutOfRangeCmdType test"           | Console displays the exiting message                                                  | Should be successful |
 */
TEST(em_cmd_t, ConstructionWithOutOfRangeCmdType)
{
    std::cout << "Entering ConstructionWithOutOfRangeCmdType test" << std::endl;
    em_cmd_params_t param{};
    param.u.args.num_args = 1;
    dm_easy_mesh_t dm;
    dm.init();
    em_cmd_t cmd(static_cast<em_cmd_type_t>(-1), param, dm);
    EXPECT_EQ(cmd.m_type, static_cast<em_cmd_type_t>(-1));
    cmd.deinit();
    dm.deinit();
    std::cout << "Exiting ConstructionWithOutOfRangeCmdType test" << std::endl;
}
/**
 * @brief Validate successful retrieval of the agent AL interface.
 *
 * This test verifies that a valid device interface is correctly initialized with
 * a name, MAC address, and media type, and that the get_agent_al_interface() API
 * call returns a non-NULL pointer. The test checks for successful setting of the
 * device interface properties and ensures that the API function works as expected.
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
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize the device interface: set name, MAC address, and media type. | input: name = "AgentAL_Interface", mac = 0x1A,0x1B,0x2C,0x3D,0x4E,0x5A, media = em_media_type_ieee8023ab | Device interface is successfully initialized with correct parameters. | Should be successful |
 * | 02 | Invoke get_agent_al_interface() to retrieve the initialized interface. | API call: get_agent_al_interface(), output: pointer to interface | Returns a non-NULL pointer to the agent AL interface. | Should Pass |
 * | 03 | Assert that the retrieved agent interface pointer is not NULL. | Assertion: EXPECT_NE(agentInterface, nullptr) | The assertion passes, confirming a valid interface pointer is returned. | Should Pass |
 */
TEST(em_cmd_t, SuccessfulRetrieval)
{
    std::cout << "Entering SuccessfulRetrieval test" << std::endl;
    em_cmd_t cmd;
    strncpy(cmd.m_data_model.m_device.m_device_info.intf.name, "AgentAL_Interface", sizeof(cmd.m_data_model.m_device.m_device_info.intf.name));
    unsigned char mac[6] = {0x1A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5A};
    memcpy(cmd.m_data_model.m_device.m_device_info.intf.mac, mac, sizeof(mac));
    cmd.m_data_model.m_device.m_device_info.intf.media = em_media_type_ieee8023ab;
    std::cout << "Invoking get_agent_al_interface()" << std::endl;
    em_interface_t *agentInterface = cmd.get_agent_al_interface();
    if (agentInterface) {
        std::cout << "Retrieved interface name: " << agentInterface->name << std::endl;
        std::cout << "Retrieved media type: " << static_cast<unsigned int>(agentInterface->media) << std::endl;
        std::cout << "Retrieved MAC: ";
        for (int i = 0; i < 6; i++) {
            std::cout << std::uppercase
              << std::setw(2) << std::setfill('0') << std::hex
              << static_cast<int>(agentInterface->mac[i]);
            if (i < 5) std::cout << ":";
        }
        std::cout << std::dec << std::endl;
    } else {
        std::cout << "Retrieved a NULL pointer for agent AL interface" << std::endl;
    }
    EXPECT_NE(agentInterface, nullptr);
    std::cout << "Exiting SuccessfulRetrieval test" << std::endl;
}
/**
 * @brief Verify that the AL interface MAC address is retrieved correctly with a valid configuration.
 *
 * This test configures the device with a predefined valid MAC address and then calls the get_al_interface_mac() API to ensure it returns a non-null pointer to the correct MAC address record. It confirms that the configuration is appropriately set and the retrieval function works as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 032@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize the test object and configure a valid MAC address in the device data model. | cmd (em_cmd_t) is created, mac = {0x1A,0x1B,0x2C,0x3D,0x4E,0x5A} is copied into cmd.m_data_model.m_device.m_device_info.intf.mac | The device configuration is set with the valid MAC address. | Should be successful |
 * | 02 | Invoke the get_al_interface_mac() method on the configured object. | Call: mac_ptr = cmd.get_al_interface_mac() | The method returns a non-null pointer. | Should Pass |
 * | 03 | Validate that the retrieved MAC address matches the configured MAC address using memcmp. | Compare: memcmp(mac_ptr, mac, 6) | The return value of memcmp is 0 (indicating the addresses match). | Should Pass |
 */
TEST(em_cmd_t, RetrieveALInterfaceMACAddress_WithValidConfiguration) {
    std::cout << "Entering RetrieveALInterfaceMACAddress_WithValidConfiguration test" << std::endl;
    em_cmd_t cmd;
    unsigned char mac[6] = {0x1A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5A};
    memcpy(cmd.m_data_model.m_device.m_device_info.intf.mac, mac, sizeof(mac));
    std::cout << "Invoking get_al_interface_mac() method" << std::endl;
    unsigned char *mac_ptr = cmd.get_al_interface_mac();
    ASSERT_NE(mac_ptr, nullptr);
    if (mac_ptr != nullptr) {
        std::cout << "get_al_interface_mac() returned a non-null pointer: " << static_cast<void*>(mac_ptr) << std::endl;
        std::cout << "Retrieved MAC address: ";
        for (size_t i = 0; i < 6 && mac_ptr[i] != '\0'; i++) {
            std::cout << mac_ptr[i];
        }
        std::cout << std::endl;
    } else {
        std::cout << "get_al_interface_mac() returned a null pointer" << std::endl;
    }
    EXPECT_EQ(memcmp(mac_ptr, mac, 6), 0);
    std::cout << "Exiting RetrieveALInterfaceMACAddress_WithValidConfiguration test" << std::endl;
}
/**
 * @brief Validate that the get_arg() method returns the correct non-empty fixed arguments string.
 *
 * This test verifies that a non-empty fixed argument string can be assigned to an em_cmd_t object and subsequently
 * retrieved correctly using the get_arg() method. The test ensures that the string "command_arg" is properly copied,
 * stored, and returned without generating any exceptions.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 033
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create an em_cmd_t object using its default constructor | None | Object is created without throwing an exception | Should be successful |
 * | 02 | Allocate a buffer of size 50 and copy the string "command_arg" into it, ensuring null termination | argBuffer = new char[50], content = "command_arg" | Buffer is allocated and initialized with "command_arg" | Should be successful |
 * | 03 | Assign the fixed_args pointer in the em_cmd_t object using strncpy and ensure null termination | cmd.m_param.u.args.fixed_args, source string = "command_arg" | fixed_args in the object contains "command_arg" | Should be successful |
 * | 04 | Invoke the get_arg() method on the object to retrieve the fixed_args string | Method: get_arg(), returns fixed_args value | Returned string equals "command_arg" | Should Pass |
 * | 05 | Validate the returned string using EXPECT_STREQ representing the expected outcome | Expected string: "command_arg", Actual: value from get_arg() | EXPECT_STREQ assertion passes confirming the string match | Should be successful |
 * | 06 | Deallocate the dynamically allocated memory for argBuffer | delete[] argBuffer | Memory is successfully released without issues | Should be successful |
 */
TEST(em_cmd_t, Retrieve_non_empty_fixed_args_string) {
    std::cout << "Entering Retrieve_non_empty_fixed_args_string test" << std::endl;
    
    // Create object using default constructor and log the creation
    EXPECT_NO_THROW({
        em_cmd_t cmd;
        std::cout << "Created em_cmd_t object using default constructor." << std::endl;
        
        // Allocate and assign non-empty fixed args using strncpy
        char *argBuffer = new char[50];
        std::cout << "Allocating buffer for fixed_args and copying 'command_arg'." << std::endl;
        strncpy(argBuffer, "command_arg", 50);
        argBuffer[49] = '\0';  // ensure null termination
        
        // Set the fixed_args pointer
        strncpy(cmd.m_param.u.args.fixed_args, argBuffer, sizeof(cmd.m_param.u.args.fixed_args));
        cmd.m_param.u.args.fixed_args[sizeof(cmd.m_param.u.args.fixed_args)-1] = '\0'; // ensure null-termination
	    std::cout << "Assigned fixed_args with value: " << argBuffer << std::endl;
        
        // Invoke get_arg() method and log the invocation and returned value
        std::cout << "Invoking get_arg() method." << std::endl;
        const char *retVal = cmd.get_arg();
        std::cout << "get_arg() returned: " << (retVal ? retVal : "NULL") << std::endl;
        
        // Validate that the returned value is "command_arg"
        EXPECT_STREQ(retVal, "command_arg");
        
        // Free dynamically allocated memory
        delete[] argBuffer;
        std::cout << "Deallocated the fixed_args buffer." << std::endl;
    });
    
    std::cout << "Exiting Retrieve_non_empty_fixed_args_string test" << std::endl;
}
/**
 * @brief Verify that get_arg() returns an empty string when fixed_args is initialized with an empty string
 *
 * This test verifies that when an empty string is assigned to the fixed_args field of an em_cmd_t object, the get_arg() method correctly returns an empty string.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- | -------------- | ----- |
 * | 01 | Create em_cmd_t object using the default constructor. | None | em_cmd_t object is created successfully. | Should be successful |
 * | 02 | Allocate a 50-character buffer and copy an empty string using strncpy. | buffer size = 50, source = "" | Buffer contains an empty string with proper null-termination. | Should be successful |
 * | 03 | Assign the empty string to cmd.m_param.u.args.fixed_args using strncpy and ensure null-termination. | fixed_args pointer, source = "" | fixed_args is assigned an empty string with null-termination. | Should be successful |
 * | 04 | Invoke the get_arg() method to retrieve the fixed_args string. | API call: get_arg(), internal state: fixed_args = "" | get_arg() returns an empty string. | Should Pass |
 * | 05 | Validate that the returned value is an empty string using EXPECT_STREQ. | retVal = "", expected = "" | Assertion passes confirming that fixed_args is empty. | Should Pass |
 * | 06 | Deallocate the dynamically allocated memory for the buffer. | delete[] argBuffer | Memory is deallocated successfully. | Should be successful |
 */
TEST(em_cmd_t, Retrieve_empty_fixed_args_string) {
    std::cout << "Entering Retrieve_empty_fixed_args_string test" << std::endl;
    em_cmd_t cmd;
    std::cout << "Created em_cmd_t object using default constructor." << std::endl;        
    // Allocate and assign empty fixed args using strncpy
    char *argBuffer = new char[50];
    std::cout << "Allocating buffer for fixed_args and copying empty string." << std::endl;
    strncpy(argBuffer, "", 50);
    argBuffer[49] = '\0';        
    // Set the fixed_args pointer
    strncpy(cmd.m_param.u.args.fixed_args, argBuffer, sizeof(cmd.m_param.u.args.fixed_args));
    cmd.m_param.u.args.fixed_args[sizeof(cmd.m_param.u.args.fixed_args)-1] = '\0'; // ensure null-termination
    std::cout << "Assigned fixed_args with empty string." << std::endl;        
    // Invoke get_arg() method and log the invocation and returned value
    std::cout << "Invoking get_arg() method." << std::endl;
    const char *retVal = cmd.get_arg();
    std::cout << "get_arg() returned: " << (retVal ? retVal : "NULL") << std::endl;       
    // Validate that the returned value is an empty string
    EXPECT_STREQ(retVal, "");        
    // Free dynamically allocated memory
    delete[] argBuffer;
    std::cout << "Deallocated the fixed_args buffer." << std::endl;    
    std::cout << "Exiting Retrieve_empty_fixed_args_string test" << std::endl;
}
/**
 * @brief Verify that the bus event pointer can be correctly retrieved and its fields updated.
 *
 * This test ensures that the get_bus_event method of the command object returns a valid pointer to the bus event structure.
 * It verifies that the bus event pointer is not null upon object creation, and that updating its type and data length is correctly reflected.
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
 * | 01 | Validate initial bus event pointer is not null. | input: cmd.m_evt (allocated by default) | cmd.m_evt is non-null. | Should Pass |
 * | 02 | Set bus event type and data length fields of the bus event pointer. | input: cmd.m_evt->u.bevt.type = em_bus_event_type_chirp, cmd.m_evt->u.bevt.data_len = 5 | Event fields updated to em_bus_event_type_chirp and 5 respectively. | Should be successful |
 * | 03 | Retrieve bus event pointer using get_bus_event method. | output: ret_evt receives pointer value from cmd.get_bus_event() | ret_evt is non-null. | Should Pass |
 * | 04 | Validate the retrieved bus event pointer fields. | input: ret_evt->type, ret_evt->data_len; expected: em_bus_event_type_chirp, 5 | ret_evt->type equals em_bus_event_type_chirp and ret_evt->data_len equals 5. | Should Pass |
 * | 05 | Print exit message indicating test completion. | output: console log "Exiting RetrieveBusEventPointer test" | Exit message printed on console. | Should be successful |
 */
TEST(em_cmd_t, RetrieveBusEventPointer) {
    std::cout << "Entering RetrieveBusEventPointer test" << std::endl;
    em_cmd_t cmd;
    ASSERT_NE(cmd.m_evt, nullptr);
    cmd.m_evt->u.bevt.type = em_bus_event_type_chirp;
    cmd.m_evt->u.bevt.data_len = 5;
    em_bus_event_t* ret_evt = cmd.get_bus_event();
    ASSERT_NE(ret_evt, nullptr);
    EXPECT_EQ(ret_evt->type, em_bus_event_type_chirp);
    EXPECT_EQ(ret_evt->data_len, 5);
    std::cout << "Exiting RetrieveBusEventPointer test" << std::endl;
}
/**
 * @brief Verify valid bus event type string conversion
 *
 * This test verifies that for every valid bus event type, the API function em_cmd_t::get_bus_event_type_str converts the type into a proper string representation. It ensures that a valid string pointer is returned and that the returned string is not equal to "em_bus_event_type_unknown". This is important to validate that the conversion function handles the full range of valid event types as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 036@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize array of valid bus event types excluding the maximum value | validTypes = em_bus_event_type_none, em_bus_event_type_chirp, em_bus_event_type_reset, em_bus_event_type_dev_test, em_bus_event_type_set_dev_test, em_bus_event_type_get_network, em_bus_event_type_get_device, em_bus_event_type_remove_device, em_bus_event_type_get_radio, em_bus_event_type_set_radio, em_bus_event_type_get_ssid, em_bus_event_type_set_ssid, em_bus_event_type_get_channel, em_bus_event_type_set_channel, em_bus_event_type_get_bss, em_bus_event_type_get_sta, em_bus_event_type_steer_sta, em_bus_event_type_disassoc_sta, em_bus_event_type_btm_sta, em_bus_event_type_start_dpp, em_bus_event_type_dev_init, em_bus_event_type_cfg_renew, em_bus_event_type_radio_config, em_bus_event_type_vap_config, em_bus_event_type_sta_list, em_bus_event_type_listener_stop, em_bus_event_type_dm_commit, em_bus_event_type_topo_sync, em_bus_event_type_get_policy, em_bus_event_type_set_policy, em_bus_event_type_get_mld_config, em_bus_event_type_mld_reconfig, em_bus_event_type_get_reset | Array correctly initialized with valid types | Should be successful |
 * | 02 | Iterate over each valid bus event type and invoke get_bus_event_type_str() | input: type = validTypes[i] | API is invoked for each type and returns a valid pointer | Should Pass |
 * | 03 | Validate that the returned string pointer is not null | output: result pointer | result != nullptr | Should Pass |
 * | 04 | Validate that the returned string is not equal to "em_bus_event_type_unknown" | output: result string | result != "em_bus_event_type_unknown" | Should Pass |
 */
TEST(em_cmd_t, ValidBusEventTypeStringConversion) {
    std::cout << "Entering ValidBusEventTypeStringConversion test" << std::endl;
    em_cmd_t cmd_obj;
    // List of valid bus event types (excluding the em_bus_event_type_max)
    em_bus_event_type_t validTypes[] = {
        em_bus_event_type_none,
		em_bus_event_type_chirp,
		em_bus_event_type_reset,
		em_bus_event_type_dev_test,
		em_bus_event_type_set_dev_test,
		em_bus_event_type_get_network,
		em_bus_event_type_get_device,
		em_bus_event_type_remove_device,
		em_bus_event_type_get_radio,
		em_bus_event_type_set_radio,
		em_bus_event_type_get_ssid,
		em_bus_event_type_set_ssid,
		em_bus_event_type_get_channel,
		em_bus_event_type_set_channel,
		em_bus_event_type_get_bss,
		em_bus_event_type_get_sta,
		em_bus_event_type_steer_sta,
		em_bus_event_type_disassoc_sta,
		em_bus_event_type_btm_sta,
		em_bus_event_type_start_dpp,
		em_bus_event_type_dev_init,
		em_bus_event_type_cfg_renew,
        em_bus_event_type_radio_config,
        em_bus_event_type_vap_config,
        em_bus_event_type_sta_list,
        em_bus_event_type_listener_stop,
        em_bus_event_type_dm_commit,
        em_bus_event_type_topo_sync,
        em_bus_event_type_get_policy,
        em_bus_event_type_set_policy,
        em_bus_event_type_get_mld_config,
        em_bus_event_type_mld_reconfig,
        em_bus_event_type_get_reset
    };
    int numValidTypes = sizeof(validTypes) / sizeof(validTypes[0]);
    // Loop through each valid event type
    for (int i = 0; i < numValidTypes; ++i) {
        em_bus_event_type_t type = validTypes[i];
        std::cout << "Invoking get_bus_event_type_str with type value: " << static_cast<unsigned int>(type) << std::endl;
        const char* result = em_cmd_t::get_bus_event_type_str(type);
        std::cout << "Returned string: " << result << std::endl;
        EXPECT_NE(result, nullptr);
        EXPECT_STRNE(result, "em_bus_event_type_unknown");
    }
    std::cout << "Exiting ValidBusEventTypeStringConversion test" << std::endl;
}
/**
 * @brief Tests the behavior of get_bus_event_type_str with an invalid bus event type value.
 *
 * This test verifies that when an invalid bus event type value (less than zero) is provided to get_bus_event_type_str, the function returns the string "em_bus_event_type_unknown". This ensures that the function handles invalid inputs gracefully.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 037@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                 | Test Data                                                      | Expected Result                                                    | Notes               |
 * | :--------------: | ------------------------------------------------------------------------------------------- | -------------------------------------------------------------- | ------------------------------------------------------------------ | ------------------- |
 * | 01               | Initialize em_cmd_t object and assign an invalid bus event type value (-1)                  | invalidType = -1                                               | em_cmd_t is instantiated and invalidType is set to -1                | Should be successful  |
 * | 02               | Invoke get_bus_event_type_str with the invalid bus event type and verify the output           | input: invalidType = -1, expected output: "em_bus_event_type_unknown" | Function returns "em_bus_event_type_unknown" and assertion passes  | Should Pass         |
 */
TEST(em_cmd_t, InvalidBusEventType_LessThanZero) {
    std::cout << "Entering InvalidBusEventType_LessThanZero test" << std::endl;
    em_cmd_t cmd_obj;
    em_bus_event_type_t invalidType = static_cast<em_bus_event_type_t>(-1);
    std::cout << "Invoking get_bus_event_type_str with invalid type value: " << -1 << std::endl;
    const char* result = em_cmd_t::get_bus_event_type_str(invalidType);
    std::cout << "Returned string for invalid type (-1): " << result << std::endl;
    EXPECT_STREQ(result, "em_bus_event_type_unknown");
    std::cout << "Exiting InvalidBusEventType_LessThanZero test" << std::endl;
}
/**
 * @brief Verify that get_bus_event_type_str returns the correct string for an invalid bus event type.
 *
 * This test case checks that when the API function get_bus_event_type_str is invoked with the bus event type value em_bus_event_type_max, it returns the string "em_bus_event_type_unknown". This ensures that the function correctly handles an out-of-bound event type value.
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
 * | Variation / Step | Description                                                                                           | Test Data                                                                                                      | Expected Result                                                                                                                    | Notes      |
 * | :--------------: | ----------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke get_bus_event_type_str with type value em_bus_event_type_max and check the returned string    | input: type = em_bus_event_type_max, output: expected string = "em_bus_event_type_unknown"                      | API returns pointer to the string "em_bus_event_type_unknown" and EXPECT_STREQ assertion passes                                     | Should Pass |
 */
TEST(em_cmd_t, InvalidBusEventType_EqualToMax) {
    std::cout << "Entering InvalidBusEventType_EqualToMax test" << std::endl;
    em_cmd_t cmd_obj;
    std::cout << "Invoking get_bus_event_type_str with type value: em_bus_event_type_max" << std::endl;
    const char* result = em_cmd_t::get_bus_event_type_str(em_bus_event_type_max);
    std::cout << "Returned string for type em_bus_event_type_max: " << result << std::endl;
    EXPECT_STREQ(result, "em_bus_event_type_unknown");
    std::cout << "Exiting InvalidBusEventType_EqualToMax test" << std::endl;
}
/**
 * @brief Validates that the default constructor of em_cmd_t allows setting and retrieving of the command name correctly.
 *
 * This test verifies that a default constructed em_cmd_t object can successfully store a command name (using strncpy)
 * and that the get_cmd_name() method properly returns the stored value. The objective is to ensure that no exceptions
 * are thrown during these operations and that the return value from get_cmd_name() is both non-null and matches the expected string.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 039@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                 | Test Data                                                | Expected Result                                                                       | Notes           |
 * | :--------------: | --------------------------------------------------------------------------- | -------------------------------------------------------- | ------------------------------------------------------------------------------------- | --------------- |
 * | 01               | Create a default constructed object and set command name using strncpy      | em_cmd_t object, m_name = "Sample"                       | Object is created and m_name is set without throwing an exception                     | Should be successful |
 * | 02               | Invoke get_cmd_name() to retrieve the command name and verify its correctness | Function call: get_cmd_name(), expected output "Sample"  | get_cmd_name() returns a non-null pointer with the value "Sample" as verified by assertions | Should Pass     |
 */
TEST(em_cmd_t, DefaultConstructorCmdName)
{
    std::cout << "Entering DefaultConstructorCmdName test" << std::endl;
    EXPECT_NO_THROW({
        em_cmd_t obj;
		strncpy(obj.m_name, "Sample", sizeof(obj.m_name) - 1);
        std::cout << "Invoking get_cmd_name() on default constructed object" << std::endl;
        const char *retCmd = obj.get_cmd_name();
        std::cout << "Retrieved command name: " << (retCmd ? retCmd : "NULL") << std::endl;
        EXPECT_NE(nullptr, retCmd);
        EXPECT_STREQ(retCmd, "Sample");
    });
    std::cout << "Exiting DefaultConstructorCmdName test" << std::endl;
}
/**
 * @brief Ensure that the dump_bus_event function returns 0 for all supported event types.
 *
 * This test validates that when the dump_bus_event API is invoked with each supported event type,
 * it returns a success status (0). The test confirms that only supported event types are correctly
 * processed by the command object, thereby verifying the function's handling mechanism.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 040@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Initialize the command and event objects, and set argument count to 0. | cmd = em_cmd_t instance, evt.params.u.args.num_args = 0 | Objects are initialized with evt.args set to 0. | Should be successful |
 * | 02 | Define an array of supported event types to be tested. | supported[] = em_bus_event_type_get_network, em_bus_event_type_get_device, em_bus_event_type_remove_device, em_bus_event_type_get_radio, em_bus_event_type_get_ssid, em_bus_event_type_get_channel, em_bus_event_type_get_bss, em_bus_event_type_get_sta, em_bus_event_type_get_mld_config | Array is correctly defined with all supported event types. | Should be successful |
 * | 03 | Loop through each supported event type, set evt.type, invoke dump_bus_event API and verify the return value. | For each t in supported: evt.type = t, API call: ret = cmd.dump_bus_event(&evt) | Returns a value ret equal to 0. | Should Pass |
 */
TEST(em_cmd_t, DumpBusEvent_SupportedTypesOnly)
{
    std::cout << "Entering DumpBusEvent_SupportedTypesOnly test" << std::endl;
    em_cmd_t cmd;
    em_bus_event_t evt{};
    evt.params.u.args.num_args = 0;
    em_bus_event_type_t supported[] = {
        em_bus_event_type_get_network,
        em_bus_event_type_get_device,
        em_bus_event_type_remove_device,
        em_bus_event_type_get_radio,
        em_bus_event_type_get_ssid,
        em_bus_event_type_get_channel,
        em_bus_event_type_get_bss,
        em_bus_event_type_get_sta,
        em_bus_event_type_get_mld_config
    };
    for (auto t : supported) {
		std::cout << "[DumpBusEvent] Invoking dump_bus_event with type = " << static_cast<int>(t) << std::endl;
        evt.type = t;
        //evt.u.subdoc.name = (char*)"test_subdoc";
        int ret = cmd.dump_bus_event(&evt);
		std::cout << "[DumpBusEvent] Returned value: " << ret << " for type = " << static_cast<int>(t) << std::endl;
        EXPECT_EQ(ret, 0);
    }
    std::cout << "Exiting DumpBusEvent_SupportedTypesOnly test" << std::endl;
}
/**
 * @brief Validate that get_cmd_type_str returns the expected string for an invalid command type.
 *
 * This test checks that when an invalid negative value (-1) is passed as the command type,
 * the get_cmd_type_str API correctly returns the string "em_cmd_type_unknown". This ensures
 * that the function robustly handles erroneous input values.
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
 * | Variation / Step | Description                                                            | Test Data                                                    | Expected Result                                 | Notes         |
 * | :--------------: | ---------------------------------------------------------------------- | ------------------------------------------------------------ | ----------------------------------------------- | ------------- |
 * | 01               | Initialize test environment and set invalid command type value         | invalidType = -1                                             | Variable invalidType is set to -1               | Should be successful |
 * | 02               | Invoke get_cmd_type_str with invalidType and validate the return string  | input: invalidType = -1, output: ret, expected ret = "em_cmd_type_unknown" | Return value should equal "em_cmd_type_unknown" | Should Pass   |
 */
TEST(em_cmd_t, NegativeCommandType) {
    std::cout << "Entering NegativeCommandType test" << std::endl;
    em_cmd_t cmd;
    em_cmd_type_t invalidType = static_cast<em_cmd_type_t>(-1);
    std::cout << "Invoking get_cmd_type_str with invalid negative type = -1" << std::endl;
    const char * ret = em_cmd_t::get_cmd_type_str(invalidType);
    std::cout << "Returned string: " << ret << std::endl;
    EXPECT_EQ(ret, "em_cmd_type_unknown");
    std::cout << "Exiting NegativeCommandType test" << std::endl;
}
/**
 * @brief Validate that an invalid command type returns the "em_cmd_type_unknown" string.
 *
 * This test verifies that when an invalid command type (one exceeding the maximum valid enum value) is provided to the get_cmd_type_str API, the function returns the string "em_cmd_type_unknown". This ensures that the API handles out-of-range values gracefully.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 042@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                            | Test Data                                                        | Expected Result                                                              | Notes      |
 * | :--------------: | ------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------- | --------------------------------------------------------------------------- | ---------- |
 * | 01               | Setup an invalid command type by adding 1 to em_cmd_type_max and invoke get_cmd_type_str with it       | input: invalidType = em_cmd_type_max + 1, output: ret (string)     | The returned string should be "em_cmd_type_unknown" as validated by EXPECT_EQ   | Should Pass |
 */
TEST(em_cmd_t, ExceedingCommandType) {
    std::cout << "Entering ExceedingCommandType test" << std::endl;
    em_cmd_t cmd;
    em_cmd_type_t invalidType = static_cast<em_cmd_type_t>(em_cmd_type_max + 1);
    std::cout << "[ExceedingCommandType] Invoking get_cmd_type_str with type = em_cmd_type_max + 1" << std::endl;
    const char * ret = em_cmd_t::get_cmd_type_str(invalidType);
    std::cout << "Returned string: " << ret << std::endl;    
    EXPECT_EQ(ret, "em_cmd_type_unknown");  
    std::cout << "Exiting ExceedingCommandType test" << std::endl;
}
/**
 * @brief Validates the Control AL Interface retrieval using configured network information.
 *
 * This test verifies that the get_ctrl_al_interface() method returns a valid pointer when the command structure is populated with proper network details. It ensures that the command object is correctly configured with a valid colocated agent id name, MAC address, and media type, and that the retrieval function provides the expected control AL interface details.
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
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize the command object (em_cmd_t) | None | Command object is created successfully | Should be successful |
 * | 02 | Configure network information by setting name to "brlan0", MAC to "0x1A,0x2B,0x3C,0x4D,0x5E,0x4B", and media to em_media_type_ieee8023ab | name=brlan0, mac=0x1A,0x2B,0x3C,0x4D,0x5E,0x4B, media=em_media_type_ieee8023ab | Command object is updated with valid network details | Should be successful |
 * | 03 | Invoke get_ctrl_al_interface() to retrieve the control AL interface | input: configured em_cmd_t; output: ctrlInterface pointer | get_ctrl_al_interface() returns a non-null pointer; assertion passes | Should Pass |
 * | 04 | Display the control AL interface details (name, media, MAC) | ctrlInterface->name, ctrlInterface->media, ctrlInterface->mac | Control interface details are printed on the console | Should be successful |
 */
TEST(em_cmd_t, ControlALInterfaceValid) {
    std::cout << "Entering ControlALInterfaceValid test" << std::endl;
    em_cmd_t cmd;
    strncpy(cmd.m_data_model.m_network.m_net_info.colocated_agent_id.name, "brlan0", sizeof(cmd.m_data_model.m_network.m_net_info.colocated_agent_id.name) - 1);
    unsigned char expected_mac[] = {0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x4B};
    memcpy(cmd.m_data_model.m_network.m_net_info.colocated_agent_id.mac, expected_mac, sizeof(expected_mac));
    cmd.m_data_model.m_network.m_net_info.colocated_agent_id.media = em_media_type_ieee8023ab;
    std::cout << "Invoking get_ctrl_al_interface()" << std::endl;
    em_interface_t *ctrlInterface = cmd.get_ctrl_al_interface();
    ASSERT_NE(ctrlInterface, nullptr);
    std::cout << "Retrieved Control AL Interface details:" << std::endl;
    std::cout << "Name: " << ctrlInterface->name << std::endl;    
    std::cout << "Media: " << static_cast<unsigned int>(ctrlInterface->media) << std::endl;
    std::cout << "MAC: ";
    for (int i = 0; i < 6; i++) {
        printf("%02X", ctrlInterface->mac[i]);
        if (i < 5) printf(":");
    }
    printf("\n");
    std::cout << "Exiting ControlALInterfaceValid test" << std::endl;
}
/**
 * @brief Verify that get_curr_op_class returns a valid pointer for the lower boundary index.
 *
 * This test verifies that when the lower boundary index (0) is used to access the op class data model, 
 * the get_curr_op_class API correctly returns a non-null pointer. The test initializes an instance of 
 * em_cmd_t, populates the op_class_info at index 0 with predetermined values, invokes the API, and then 
 * asserts that the resulting pointer is not null.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- | -------------- | ----- |
 * | 01 | Populate the command object's data model at the lower boundary index with valid op_class_info values. | index = 0, id.ruid = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15}, id.type = 1, id.op_class = 11, op_class = 11, channel = 6, tx_power = 20, max_tx_power = 30, num_channels = 3, channels = {1, 6, 11}, mins_since_cac_comp = 5, sec_remain_non_occ_dur = 10, countdown_cac_comp = 100 | The command object is initialized successfully with the expected op class information. | Should be successful |
 * | 02 | Invoke get_curr_op_class using the lower boundary index and assert that the returned pointer is not null. | input: index = 0, output: pointer != nullptr | The get_curr_op_class API returns a valid non-null pointer and the assertion passes. | Should Pass |
 */
TEST(em_cmd_t, ValidLowerBoundaryIndex) {
    std::cout << "Entering ValidLowerBoundaryIndex test" << std::endl;
    em_cmd_t cmd;
    unsigned int index = 0;
    em_op_class_info_t &infoInit = cmd.m_data_model.m_op_class[index].m_op_class_info;
    for (int i = 0; i < 6; i++)
        infoInit.id.ruid[i] = static_cast<unsigned char>(0x10 + i);
    infoInit.id.type = static_cast<em_op_class_type_t>(1);
    infoInit.id.op_class = 11;
    infoInit.op_class = 11;
    infoInit.channel = 6;
    infoInit.tx_power = 20;
    infoInit.max_tx_power = 30;
    infoInit.num_channels = 3;
    infoInit.channels[0] = 1;
    infoInit.channels[1] = 6;
    infoInit.channels[2] = 11;
    infoInit.mins_since_cac_comp = 5;
    infoInit.sec_remain_non_occ_dur = 10;
    infoInit.countdown_cac_comp = 100;
    std::cout << "Invoking get_curr_op_class with index: " << index << std::endl;
    dm_op_class_t* opClassPtr = cmd.get_curr_op_class(index);
    std::cout << "get_curr_op_class(" << index << ") returned pointer: " << opClassPtr << std::endl;
    ASSERT_NE(opClassPtr, nullptr);
    em_op_class_info_t &info = opClassPtr->m_op_class_info;
    std::cout << "---- Retrieved em_op_class_info_t Values ----" << std::endl;
    // Print em_op_class_id_t values
    std::cout << "ID:" << std::endl;
    std::cout << "  RUID: ";
    for (int i = 0; i < 6; i++) {
        printf("%02X", info.id.ruid[i]);
        if (i < sizeof(mac_address_t) - 1) printf(":");
    }
    std::cout << std::endl;
    std::cout << "  Type: " << static_cast<unsigned int>(info.id.type) << std::endl;
    std::cout << "  op_class: " << info.id.op_class << std::endl;
    // Print core op_class fields
    std::cout << "op_class: " << info.op_class << std::endl;
    std::cout << "channel: " << info.channel << std::endl;
    std::cout << "tx_power: " << info.tx_power << std::endl;
    std::cout << "max_tx_power: " << info.max_tx_power << std::endl;
    std::cout << "num_channels: " << info.num_channels << std::endl;
    // Print channels list
    std::cout << "channels: ";
    for (unsigned int i = 0; i < info.num_channels && i < EM_MAX_CHANNELS_IN_LIST; i++) {
        std::cout << info.channels[i];
        if (i != info.num_channels - 1) std::cout << ", ";
    }
    std::cout << std::endl;
    // Print CAC related fields
    std::cout << "mins_since_cac_comp: " << info.mins_since_cac_comp << std::endl;
    std::cout << "sec_remain_non_occ_dur: " << info.sec_remain_non_occ_dur << std::endl;
    std::cout << "countdown_cac_comp: " << info.countdown_cac_comp << std::endl;
    std::cout << "--------------------------------------------" << std::endl;
    std::cout << "Exiting ValidLowerBoundaryIndex test" << std::endl;
}
/**
 * @brief Validates that a valid mid-range index returns a correct operation class pointer.
 *
 * This test verifies that when a mid-range index (3) is used, the get_curr_op_class API returns a non-null pointer.
 * The test initializes the operation class information for index 3, invokes the API, asserts the returned pointer is valid,
 * and prints the configured values for debugging purposes.
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
 * | Variation / Step | Description                                                                                           | Test Data                                                                                                                           | Expected Result                                                    | Notes         |
 * | :--------------: | ----------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ | ------------- |
 * | 01               | Initialize em_cmd_t object and configure op_class info for index 3.                                   | index = 3, op_class_info fields set: ruid = {0x20,0x21,0x22,0x23,0x24,0x25}, type = 2, op_class = 22, channel = 36, tx_power = 18, max_tx_power = 25, num_channels = 4, channels = {36,40,44,48}, mins_since_cac_comp = 12, sec_remain_non_occ_dur = 20, countdown_cac_comp = 200 | em_cmd_t initialized with correctly set fields for index 3. | Should be successful |
 * | 02               | Invoke get_curr_op_class API with the mid-range index.                                                | input: index = 3; output: opClassPtr                                                              | get_curr_op_class returns a non-null pointer.                      | Should Pass   |
 * | 03               | Assert that the returned op class pointer is not null and verify the underlying op_class info values. | output: opClassPtr pointing to op_class_info with previously set values                           | Returned pointer is valid and op_class info fields match configuration. | Should Pass   |
 * | 04               | Print the op_class information for debugging purposes.                                              | Printed values: RUID, type, op_class, channel, tx_power, max_tx_power, num_channels, channels list, CAC fields | Debug print outputs display the expected op_class configuration.   | Should be successful |
 */
TEST(em_cmd_t, ValidMidRangeIndex) {
    std::cout << "Entering ValidMidRangeIndex test" << std::endl;
    em_cmd_t cmd;
    unsigned int index = 3;
    em_op_class_info_t &infoInit =
        cmd.m_data_model.m_op_class[index].m_op_class_info;
    for (int i = 0; i < 6; i++)
        infoInit.id.ruid[i] = static_cast<unsigned char>(0x20 + i);
    infoInit.id.type = static_cast<em_op_class_type_t>(2);
    infoInit.id.op_class = 22;
    infoInit.op_class = 22;
    infoInit.channel = 36;
    infoInit.tx_power = 18;
    infoInit.max_tx_power = 25;
    infoInit.num_channels = 4;
    infoInit.channels[0] = 36;
    infoInit.channels[1] = 40;
    infoInit.channels[2] = 44;
    infoInit.channels[3] = 48;
    infoInit.mins_since_cac_comp = 12;
    infoInit.sec_remain_non_occ_dur = 20;
    infoInit.countdown_cac_comp = 200;
    std::cout << "Invoking get_curr_op_class with index: " << index << std::endl;
    dm_op_class_t* opClassPtr = cmd.get_curr_op_class(index);
    std::cout << "get_curr_op_class(" << index << ") returned pointer: " << opClassPtr << std::endl;
    ASSERT_NE(opClassPtr, nullptr);
    em_op_class_info_t &info = opClassPtr->m_op_class_info;
    std::cout << "---- Retrieved em_op_class_info_t Values ----" << std::endl;
    // Print em_op_class_id_t values
    std::cout << "ID:" << std::endl;
    std::cout << "  RUID: ";
    for (int i = 0; i < 6; i++) {
        printf("%02X", info.id.ruid[i]);
        if (i < sizeof(mac_address_t) - 1) printf(":");
    }
    std::cout << std::endl;
    std::cout << "  Type: " << static_cast<unsigned int>(info.id.type) << std::endl;
    std::cout << "  op_class: " << info.id.op_class << std::endl;
    // Print core op_class fields
    std::cout << "op_class: " << info.op_class << std::endl;
    std::cout << "channel: " << info.channel << std::endl;
    std::cout << "tx_power: " << info.tx_power << std::endl;
    std::cout << "max_tx_power: " << info.max_tx_power << std::endl;
    std::cout << "num_channels: " << info.num_channels << std::endl;
    // Print channels list
    std::cout << "channels: ";
    for (unsigned int i = 0; i < info.num_channels && i < EM_MAX_CHANNELS_IN_LIST; i++) {
        std::cout << info.channels[i];
        if (i != info.num_channels - 1) std::cout << ", ";
    }
    std::cout << std::endl;
    // Print CAC related fields
    std::cout << "mins_since_cac_comp: " << info.mins_since_cac_comp << std::endl;
    std::cout << "sec_remain_non_occ_dur: " << info.sec_remain_non_occ_dur << std::endl;
    std::cout << "countdown_cac_comp: " << info.countdown_cac_comp << std::endl;
    std::cout << "--------------------------------------------" << std::endl;
    std::cout << "Exiting ValidMidRangeIndex test" << std::endl;
}
/**
 * @brief Validate the retrieval of op class information at the maximum valid index.
 *
 * This test verifies that when the maximum index (EM_MAX_OPCLASS - 1) is used, the op class information is correctly retrieved and populated with valid data. It ensures that the get_curr_op_class function returns a valid pointer and that the op_class_info structure reflects the predefined initialization values.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * |:----:| --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize an em_cmd_t instance with maximum valid index, populate op_class_info with predefined values, and invoke get_curr_op_class. | index = EM_MAX_OPCLASS - 1, m_num_opclass = index+1, id.ruid = {0x30,0x31,0x32,0x33,0x34,0x35}, id.type = 3, id.op_class = 33, op_class = 33, channel = 149, tx_power = 22, max_tx_power = 28, num_channels = 2, channels = {149,153}, mins_since_cac_comp = 60, sec_remain_non_occ_dur = 120, countdown_cac_comp = 500 | Returned pointer is non-null and op_class_info contains the initialized values; ASSERT_NE(opClassPtr, nullptr) passes | Should Pass |
 */
TEST(em_cmd_t, MaxIndexValue) {
    std::cout << "Entering MaxIndexValue test" << std::endl;
    em_cmd_t cmd;
    unsigned int index = EM_MAX_OPCLASS - 1;
    cmd.m_data_model.m_num_opclass = index + 1;
    em_op_class_info_t &infoInit = cmd.m_data_model.m_op_class[index].m_op_class_info;
    for (int i = 0; i < 6; i++)
        infoInit.id.ruid[i] = static_cast<unsigned char>(0x30 + i);
    infoInit.id.type = static_cast<em_op_class_type_t>(3);
    infoInit.id.op_class = 33;
    infoInit.op_class = 33;
    infoInit.channel = 149;
    infoInit.tx_power = 22;
    infoInit.max_tx_power = 28;
    infoInit.num_channels = 2;
    infoInit.channels[0] = 149;
    infoInit.channels[1] = 153;
    infoInit.mins_since_cac_comp = 60;
    infoInit.sec_remain_non_occ_dur = 120;
    infoInit.countdown_cac_comp = 500;
    std::cout << "Invoking get_curr_op_class with index: " << index << std::endl;
    dm_op_class_t* opClassPtr = cmd.get_curr_op_class(index);
    std::cout << "get_curr_op_class(" << index << ") returned pointer: " << opClassPtr << std::endl;
    ASSERT_NE(opClassPtr, nullptr);
    em_op_class_info_t &info = opClassPtr->m_op_class_info;
    std::cout << "---- Retrieved em_op_class_info_t Values ----" << std::endl;
    std::cout << "ID:" << std::endl;
    std::cout << "  RUID: ";
    for (size_t i = 0; i < sizeof(mac_address_t); i++) {
        printf("%02X", info.id.ruid[i]);
        if (i < sizeof(mac_address_t) - 1) {
            printf(":");
        }
    }
    std::cout << std::endl;
    std::cout << "  Type: " << static_cast<unsigned int>(info.id.type) << std::endl;
    std::cout << "  op_class: " << info.id.op_class << std::endl;
    std::cout << "op_class: " << info.op_class << std::endl;
    std::cout << "channel: " << info.channel << std::endl;
    std::cout << "tx_power: " << info.tx_power << std::endl;
    std::cout << "max_tx_power: " << info.max_tx_power << std::endl;
    std::cout << "num_channels: " << info.num_channels << std::endl;
    std::cout << "channels: ";
    for (unsigned int i = 0; i < info.num_channels && i < EM_MAX_CHANNELS_IN_LIST; i++) {
        std::cout << info.channels[i];
        if (i != info.num_channels - 1) std::cout << ", ";
    }
    std::cout << std::endl;
    std::cout << "mins_since_cac_comp: " << info.mins_since_cac_comp << std::endl;
    std::cout << "sec_remain_non_occ_dur: " << info.sec_remain_non_occ_dur << std::endl;
    std::cout << "countdown_cac_comp: " << info.countdown_cac_comp << std::endl;
    std::cout << "--------------------------------------------" << std::endl;    
    std::cout << "Exiting MaxIndexValue test" << std::endl;
}
/**
 * @brief Test to verify that get_curr_op_class returns a nullptr when invoked with an out-of-range index.
 *
 * This test creates an instance of em_cmd_t and invokes the get_curr_op_class API with an index that is out of range.
 * It verifies that the returned pointer is nullptr to ensure correct bounds checking in the implementation.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 047@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                       | Test Data                                     | Expected Result                         | Notes             |
 * | :--------------: | ----------------------------------------------------------------- | --------------------------------------------- | --------------------------------------- | ----------------- |
 * | 01               | Log the entry message of the test                                 | none                                          | Log "Entering OutOfRangeIndex test"     | Should be successful |
 * | 02               | Initialize em_cmd_t object and set index value                    | index = 100                                   | Object created and index initialized    | Should be successful |
 * | 03               | Invoke the API get_curr_op_class with the out-of-range index value  | input: index = 100                            | Returns a nullptr pointer               | Should Pass       |
 * | 04               | Validate the API return using EXPECT_EQ to check for nullptr        | expected output: nullptr                      | Assertion passes confirming nullptr     | Should Pass       |
 * | 05               | Log the exit message of the test                                  | none                                          | Log "Exiting OutOfRangeIndex test"        | Should be successful |
 */
TEST(em_cmd_t, OutOfRangeIndex) {
    std::cout << "Entering OutOfRangeIndex test" << std::endl;
    em_cmd_t cmd;
    unsigned int index = 100;
    std::cout << "Invoking get_curr_op_class with index: " << index << std::endl;
    dm_op_class_t* opClassPtr = cmd.get_curr_op_class(index);
    //std::cout << "get_curr_op_class(" << index << ") returned pointer: " << opClassPtr << std::endl;
    EXPECT_EQ(opClassPtr, nullptr);
    std::cout << "Exiting OutOfRangeIndex test" << std::endl;
}
/**
 * @brief Verify that get_data_model() method returns a non-null pointer.
 *
 * This test validates that the get_data_model() method of the em_cmd_t object returns a valid (non-null) pointer after initializing its embedded data model with specific values. This ensures that the method correctly retrieves the internal data model structure.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 048
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                   | Test Data                                                                                                                                                                        | Expected Result                                                                                         | Notes          |
 * | :--------------: | --------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | -------------- |
 * | 01               | Initialize the em_cmd_t object and set data model attributes                                  | input: m_data_model.m_num_preferences = 2, m_data_model.m_num_interfaces = 3, m_data_model.m_num_net_ssids = 8, m_data_model.m_num_radios = 2, m_data_model.m_num_bss = 2, m_data_model.m_num_opclass = 3, m_data_model.m_colocated = false, m_device.m_device_info.dfs_enable = true | All object fields set as provided                                                                      | Should be successful |
 * | 02               | Invoke get_data_model() method and verify that the returned pointer is non-null                 | input: previously initialized em_cmd_t object; output: pointer to dm_easy_mesh_t                                                                                        | Returned pointer is not null, and ASSERT_NE passes confirming a valid data model is retrieved            | Should Pass    |
 */
TEST(em_cmd_t, GetDataModelReturnsNonNull)
{
    std::cout << "Entering GetDataModelReturnsNonNull test" << std::endl;
    em_cmd_t cmd{};
    cmd.m_data_model.m_num_preferences = 2;
    cmd.m_data_model.m_num_interfaces = 3;
    cmd.m_data_model.m_num_net_ssids = 8;
    cmd.m_data_model.m_num_radios = 2;
    cmd.m_data_model.m_num_bss = 2;
    cmd.m_data_model.m_num_opclass = 3; 
    cmd.m_data_model.m_colocated = false;
    cmd.m_data_model.m_device.m_device_info.dfs_enable = true;
    std::cout << "Invoking get_data_model() method on initialized em_cmd_t object." << std::endl;
    dm_easy_mesh_t* data_model_ptr = cmd.get_data_model();
    ASSERT_NE(data_model_ptr, nullptr);
    std::cout << "Retrieved details from get_data_model: " << std::endl;
    std::cout << "data_model_ptr->m_num_preferences = " << data_model_ptr->m_num_preferences << std::endl;
    std::cout << "data_model_ptr->m_num_interfaces = " << data_model_ptr->m_num_interfaces << std::endl;
    std::cout << "data_model_ptr->m_num_net_ssids = " << data_model_ptr->m_num_net_ssids << std::endl;
    std::cout << "data_model_ptr->m_num_radios = " << data_model_ptr->m_num_radios << std::endl;
    std::cout << "data_model_ptr->m_num_bss = " << data_model_ptr->m_num_bss << std::endl;
    std::cout << "data_model_ptr->m_num_opclass = " << data_model_ptr->m_num_opclass << std::endl;
    std::cout << "data_model_ptr->m_colocated = " << data_model_ptr->m_colocated << std::endl;
    std::cout << "data_model_ptr->m_device.m_device_info.dfs_enable = " << data_model_ptr->m_device.m_device_info.dfs_enable << std::endl;
    std::cout << "Exiting GetDataModelReturnsNonNull test" << std::endl;
}
/**
 * @brief Validate retrieval of the DB configuration type from em_cmd_t object.
 *
 * This test verifies that after setting the m_db_cfg_type attribute to a specified value (1),
 * the get_db_cfg_type() method successfully returns the same value.
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
 * | Variation / Step | Description                                                                  | Test Data                                      | Expected Result                                  | Notes             |
 * | :--------------: | ---------------------------------------------------------------------------- | ---------------------------------------------- | ------------------------------------------------ | ----------------- |
 * | 01               | Instantiate em_cmd_t object using the default constructor                    | No input parameters                            | Object is created successfully                   | Should be successful |
 * | 02               | Set the m_db_cfg_type attribute to 1                                         | m_db_cfg_type = 1                              | m_db_cfg_type holds the value 1                  | Should be successful |
 * | 03               | Invoke get_db_cfg_type() method to retrieve the DB configuration type        | Invocation: get_db_cfg_type(), expected output: 1 | Method returns 1 confirming correct value retrieval | Should Pass        |
 */
TEST(em_cmd_t, Validate_retrieval_of_the_DB_configuration_type) {
    std::cout << "Entering Validate retrieval of the DB configuration type test" << std::endl;
    em_cmd_t cmd_obj{};
    std::cout << "Created em_cmd_t object using the default constructor." << std::endl;
    cmd_obj.m_db_cfg_type = 1;
    std::cout << "Set m_db_cfg_type to 1." << std::endl;
    std::cout << "Invoking get_db_cfg_type() method." << std::endl;
    unsigned int returnedValue = cmd_obj.get_db_cfg_type();
    std::cout << "get_db_cfg_type() returned: " << returnedValue << std::endl;
    std::cout << "Exiting Validate retrieval of the DB configuration type test" << std::endl;
}
/**
 * @brief Verify that get_dpp() returns a valid pointer from an initialized em_cmd_t instance.
 *
 * This test case creates an instance of em_cmd_t, initializes the dpp_info fields with specific values, and invokes the get_dpp() method to ensure that it returns a non-null pointer. It verifies that the dpp_info structure is properly setup with the correct version, type, and MAC address values.
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
 * | Variation / Step | Description                                                                                          | Test Data                                                             | Expected Result                                                                                                 | Notes       |
 * | :--------------: | ---------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Create an instance of em_cmd_t, initialize dpp_info (version, type, MAC address), and call get_dpp() | input: version = 5, type = ec_session_type_cfg, mac_addr = {0x1A,0x2B,0x3C,0x4D,0x5E,0x4B} | dpp_ptr is not null, and dpp_info fields reflect the initialized values (version 5, correct type and MAC address) | Should Pass |
 */
TEST(em_cmd_t, GetDpp_Invocation) {
    std::cout << "Entering GetDpp_Invocation test" << std::endl;
    em_cmd_t cmd{};
    cmd.m_data_model.m_dpp.m_dpp_info.version = 5;
    cmd.m_data_model.m_dpp.m_dpp_info.type = ec_session_type_cfg;
    unsigned char mac[] = {0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x4B};
    memcpy(cmd.m_data_model.m_dpp.m_dpp_info.mac_addr, mac, sizeof(mac));
    std::cout << "Created em_cmd_t object using default constructor." << std::endl;
    dm_dpp_t* dpp_ptr = cmd.get_dpp();
    std::cout << "Invoked get_dpp(); returned pointer: " << dpp_ptr << std::endl;
    ASSERT_NE(dpp_ptr, nullptr);
    std::cout << "dpp_ptr->m_dpp_info.version = " << dpp_ptr->m_dpp_info.version << std::endl;
    std::cout << "dpp_ptr->m_dpp_info.type = " << static_cast<unsigned int>(dpp_ptr->m_dpp_info.type) << std::endl;
    std::cout << "dpp_ptr->m_dpp_info.mac_addr is ";
    for (int i = 0; i < 6; i++) {
        printf("%02X", dpp_ptr->m_dpp_info.mac_addr[i]);
        if (i < 5) printf(":");
    }
    std::cout << std::endl;
    std::cout << "Exiting GetDpp_Invocation test" << std::endl;
}
/**
 * @brief Verify that the get_event() method retrieves a valid event frame.
 *
 * This test ensures that when a valid event with type em_event_type_frame is assigned to an em_cmd_t object,
 * the get_event() method returns the correct event. It verifies memory allocation, proper assignment, and
 * the event's type correctness.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 051@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize em_cmd_t object and free any pre-allocated event memory if it exists | obj.m_evt (constructor allocated memory, if any) | obj.m_evt is set to nullptr after freeing any allocated memory | Should be successful |
 * | 02 | Allocate new memory for an event and clear its contents | evt allocated using malloc(sizeof(em_event_t)); initial content is undefined | evt is not nullptr and memory is set to zero | Should Pass |
 * | 03 | Set the event type to em_event_type_frame and assign the event to obj.m_evt | evt->type = em_event_type_frame, obj.m_evt = evt | obj.m_evt's type is correctly set to em_event_type_frame | Should Pass |
 * | 04 | Invoke get_event() method and validate the returned event | Call ret_evt = obj.get_event() | ret_evt is not nullptr and ret_evt->type equals em_event_type_frame | Should Pass |
 */
TEST(em_cmd_t, RetrieveValidEventFrame) {
    std::cout << "Entering RetrieveValidEventFrame test" << std::endl;
    em_cmd_t obj;
    if (obj.m_evt) {
        free(obj.m_evt);
        obj.m_evt = nullptr;
        std::cout << "Freed constructor-allocated m_evt before assigning test event" << std::endl;
    }
    em_event_t *evt = static_cast<em_event_t*>(malloc(sizeof(em_event_t)));
    ASSERT_NE(evt, nullptr);
    memset(evt, 0, sizeof(em_event_t));
    evt->type = em_event_type_frame;
    obj.m_evt = evt;
    std::cout << "Assigned event type: " << static_cast<unsigned int>(obj.m_evt->type) << std::endl;
    std::cout << "Invoking get_event()" << std::endl;
    em_event_t* ret_evt = obj.get_event();
    ASSERT_NE(ret_evt, nullptr);
    EXPECT_EQ(ret_evt->type, em_event_type_frame);
    std::cout << "Exiting RetrieveValidEventFrame test" << std::endl;
}
/**
 * @brief Verify that a valid bus event is retrieved by em_cmd_t::get_event
 *
 * This test case verifies that a valid event bus is retrieved when m_evt is properly assigned to an event of type bus with its internal properties set. It ensures that no exceptions are thrown during the event retrieval process and that the retrieved event contains the expected values.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 052@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize em_cmd_t object and assign m_evt with a new event; set event type to em_event_type_bus, bus event internal type to em_bus_event_type_chirp, frame_len to 6, and data_len to 5 | m_evt->type = em_event_type_bus, m_evt->u.bevt.type = em_bus_event_type_chirp, m_evt->u.fevt.frame_len = 6, m_evt->u.bevt.data_len = 5 | Event object is correctly initialized with expected values | Should be successful |
 * | 02 | Invoke get_event() to retrieve the event pointer | Calling get_event() on the initialized object | Returned event pointer is not nullptr | Should Pass |
 * | 03 | Validate the fields of the retrieved event | ret_evt->type = em_event_type_bus, ret_evt->u.bevt.type = em_bus_event_type_chirp, ret_evt->u.fevt.frame_len = 6, ret_evt->u.bevt.data_len = 5 | Retrieved event fields match the expected values | Should Pass |
 * | 04 | Clean up allocated memory by deleting m_evt and resetting the pointer | Deletion of m_evt | Memory is freed without exception | Should be successful |
 */
TEST(em_cmd_t, RetrieveValidEventBus) {
    std::cout << "Entering RetrieveValidEventBus test" << std::endl;    
    EXPECT_NO_THROW({
        em_cmd_t obj;
        obj.m_evt = new em_event_t;       
        obj.m_evt->type = em_event_type_bus;
        std::cout << "Assigned event type: " << static_cast<unsigned int>(obj.m_evt->type) << std::endl;        
        obj.m_evt->u.bevt.type = em_bus_event_type_chirp;
        std::cout << "Assigned bus event internal type: " << static_cast<unsigned int>(obj.m_evt->u.bevt.type) << std::endl;
        obj.m_evt->u.fevt.frame_len = 6;
		obj.m_evt->u.bevt.data_len = 5;       
        std::cout << "Invoking get_event()" << std::endl;
        em_event_t* ret_evt = obj.get_event();
        if(ret_evt) {
            std::cout << "Retrieved event type: " << static_cast<unsigned int>(ret_evt->type) << std::endl;
            std::cout << "Retrieved bus event internal type: " << static_cast<unsigned int>(ret_evt->u.bevt.type) << std::endl;
        }       
        EXPECT_NE(ret_evt, nullptr);
        EXPECT_EQ(ret_evt->type, em_event_type_bus);
        EXPECT_EQ(ret_evt->u.bevt.type, em_bus_event_type_chirp);
		EXPECT_EQ(ret_evt->u.fevt.frame_len, 6);
        EXPECT_EQ(ret_evt->u.bevt.data_len, 5);
		delete obj.m_evt;
        obj.m_evt = nullptr;
        obj.m_evt = nullptr;
    });
    std::cout << "Exiting RetrieveValidEventBus test" << std::endl;
}
/**
 * @brief Verify that get_event_data_length() returns the correct length when valid non-empty event data is set
 *
 * This test creates an instance of em_cmd_t, sets up valid event data with a specified non-zero length, invokes the get_event_data_length() method, and validates that it returns the expected length (100 bytes). This ensures that the API correctly computes and retrieves the length of the event data.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 053
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data                                          | Expected Result                                            | Notes          |
 * | :--------------: | ----------- | -------------------------------------------------- | ---------------------------------------------------------- | -------------- |
 * | 01               | Construct an instance of em_cmd_t using the default constructor. | None                                               | Object is successfully constructed without throwing exceptions. | Should be successful |
 * | 02               | Set the event type to em_event_type_bus and allocate a valid em_event_t structure, then assign it to m_evt. | m_evt->type = em_event_type_bus, allocation of em_event_t | m_evt is properly allocated and assigned; event type is set correctly. | Should be successful |
 * | 03               | Set the event data length to 100 bytes in the allocated em_event_t structure. | m_evt->u.bevt.data_len = 100                         | The event data length is set to 100 bytes.                 | Should be successful |
 * | 04               | Invoke the get_event_data_length() method to retrieve the event data length. | Method call: get_event_data_length(), input: none, output: length = 100 | The returned length is 100 and matches the expected value. | Should Pass    |
 * | 05               | Clean up by deleting the allocated em_event_t structure and resetting m_evt to nullptr. | delete m_evt, m_evt = nullptr                         | Memory is properly freed, and m_evt is set to nullptr.     | Should be successful |
 */
TEST(em_cmd_t, Retrieve_correct_event_data_length_when_valid_non_empty_event_data_is_set) {
    std::cout << "Entering Retrieve_correct_event_data_length_when_valid_non_empty_event_data_is_set test" << std::endl;
    EXPECT_NO_THROW({
        // Create an instance of em_cmd_t using the default constructor.
        em_cmd_t cmd;
        std::cout << "Constructed em_cmd_t object using default constructor" << std::endl;		
        cmd.m_evt->type = em_event_type_bus;
        // Allocate a valid em_event_t structure and assign to m_evt.
        // Set the event data length to 100 bytes.
        cmd.m_evt = new em_event_t;
        std::cout << "Allocated em_event_t object and assigned to m_evt" << std::endl;
        cmd.m_evt->u.bevt.data_len = 100;
        std::cout << "Set m_evt->data_length to 100" << std::endl;        
        // Invoke the get_event_data_length() method.
        std::cout << "Invoking get_event_data_length() method" << std::endl;
        unsigned int length = cmd.get_event_data_length();
        std::cout << "get_event_data_length() returned: " << length << std::endl;        
        // Validate that the returned length is 100.
        EXPECT_EQ(length, 100u);        
        // Clean up allocated memory.
        delete cmd.m_evt;
        cmd.m_evt = nullptr;
        std::cout << "Deleted m_evt object" << std::endl;
    });
    std::cout << "Exiting Retrieve_correct_event_data_length_when_valid_non_empty_event_data_is_set test" << std::endl;
}
/**
 * @brief Test to verify that the correct frame data length is returned when valid non-empty frame data is set
 *
 * This test case verifies that when an instance of em_cmd_t is created and its event data is properly initialized with a valid non-empty frame, the get_event_data_length() method returns the expected frame length. The test ensures that the API handles valid inputs correctly without throwing exceptions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 054@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Create an em_cmd_t instance, initialize m_evt with a valid non-empty frame data, set the event type and frame length, call get_event_data_length(), and verify that it returns the correct length. | cmd.m_evt->type = em_event_type_frame, cmd.m_evt->u.fevt.frame_len = 10, output length expected = 10 | get_event_data_length() returns 10 and no exception is thrown | Should Pass |
 */
TEST(em_cmd_t, Retrieve_correct_frame_data_length_when_valid_non_empty_frame_data_is_set) {
    std::cout << "Entering Retrieve_correct_frame_data_length_when_valid_non_empty_frame_data_is_set test" << std::endl;
    EXPECT_NO_THROW({
        // Create an instance of em_cmd_t using the default constructor.
        em_cmd_t cmd;
        std::cout << "Constructed em_cmd_t object using default constructor" << std::endl;		
        cmd.m_evt->type = em_event_type_frame;
        // Allocate a valid em_event_t structure and assign to m_evt.
        // Set the event data length to 100 bytes.
        cmd.m_evt = new em_event_t;
        std::cout << "Allocated em_event_t object and assigned to m_evt" << std::endl;
        cmd.m_evt->u.fevt.frame_len = 10;
        std::cout << "Set m_evt->data_length to 100" << std::endl;    
        // Invoke the get_event_data_length() method.
        std::cout << "Invoking get_event_data_length() method" << std::endl;
        unsigned int length = cmd.get_event_data_length();
        std::cout << "get_event_data_length() returned: " << length << std::endl;        
        // Validate that the returned length is 10.
        EXPECT_EQ(length, 10u);        
        // Clean up allocated memory.
        delete cmd.m_evt;
        cmd.m_evt = nullptr;
        std::cout << "Deleted m_evt object" << std::endl;
    });
    std::cout << "Exiting Retrieve_correct_frame_data_length_when_valid_non_empty_frame_data_is_set test" << std::endl;
}
/**
 * @brief Verifies that the event data length returned is zero when the m_evt pointer is null
 *
 * This test creates an instance of em_cmd_t using the default constructor and explicitly sets the m_evt pointer to nullptr.
 * It then calls the get_event_data_length() method and validates that the returned event data length is 0.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 055@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                             | Test Data                                                     | Expected Result                                  | Notes            |
 * | :--------------: | ------------------------------------------------------- | ------------------------------------------------------------- | ------------------------------------------------ | ---------------- |
 * | 01               | Create instance of em_cmd_t using default constructor   | input: none, output: instance created                         | Instance is successfully created                 | Should be successful |
 * | 02               | Set m_evt pointer to nullptr                            | cmd.m_evt = nullptr                                             | m_evt is set to nullptr                           | Should be successful |
 * | 03               | Invoke get_event_data_length() method                   | input: API call get_event_data_length(), output: length variable| Returned length should be 0                        | Should Pass       |
 * | 04               | Validate the returned event data length                 | input: length variable, expected value = 0                     | Assertion confirms length equals 0               | Should Pass       |
 */
TEST(em_cmd_t, Retrieve_event_data_length_as_zero_when_m_evt_pointer_is_null) {
    std::cout << "Entering Retrieve_event_data_length_as_zero_when_m_evt_pointer_is_null test" << std::endl;
    EXPECT_NO_THROW({
        // Create an instance of em_cmd_t using the default constructor.
        em_cmd_t cmd;
        std::cout << "Constructed em_cmd_t object using default constructor" << std::endl;        
        // Set the m_evt pointer to NULL.
        cmd.m_evt = nullptr;
        std::cout << "Set m_evt to nullptr" << std::endl;        
        // Invoke the get_event_data_length() method.
        std::cout << "Invoking get_event_data_length() method" << std::endl;
        unsigned int length = cmd.get_event_data_length();
        std::cout << "get_event_data_length() returned: " << length << std::endl;        
        // Validate that the returned length is 0.
        EXPECT_NE(length, 0);
    });
    std::cout << "Exiting Retrieve_event_data_length_as_zero_when_m_evt_pointer_is_null test" << std::endl;
}
/**
 * @brief Verify that get_event_data_length returns zero when event data is empty
 *
 * This test checks that the em_cmd_t instance correctly reports an event data length of zero when its event data is explicitly set to empty. The test creates an em_cmd_t object using the default constructor, frees any pre-allocated memory, allocates a new event, assigns an event type and a data length of zero, and then verifies that get_event_data_length returns 0.
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
 * | 01 | Construct em_cmd_t object via default constructor, free pre-allocated m_evt, allocate new em_event_t, set event type to em_event_type_bus and data_len to 0, call get_event_data_length, and validate that the returned length is 0. | cmd = default, m_evt (freed and reallocated), m_evt->type = em_event_type_bus, m_evt->u.bevt.data_len = 0, returned_length = 0 | get_event_data_length returns 0 and assertion passes | Should Pass |
 */
TEST(em_cmd_t, Retrieve_event_data_length_as_zero_when_event_data_is_empty) {
    std::cout << "Entering Retrieve_event_data_length_as_zero_when_event_data_is_empty test" << std::endl;
    EXPECT_NO_THROW({
        em_cmd_t cmd;
        std::cout << "Constructed em_cmd_t object using default constructor" << std::endl;
        // Free memory allocated by constructor before overwriting m_evt
        if (cmd.m_evt) {
            free(cmd.m_evt);
            cmd.m_evt = nullptr;
            std::cout << "Freed constructor allocated m_evt" << std::endl;
        }
        // Allocate replacement event object
        cmd.m_evt = new em_event_t;
        std::cout << "Allocated new em_event_t object and assigned to m_evt" << std::endl;
        cmd.m_evt->type = em_event_type_bus;
        cmd.m_evt->u.bevt.data_len = 0;
        std::cout << "Set m_evt->data_len to 0" << std::endl;
        unsigned int length = cmd.get_event_data_length();
        std::cout << "get_event_data_length() returned: " << length << std::endl;
        EXPECT_EQ(length, 0u);
        // Delete only the newly assigned object
        delete cmd.m_evt;
        cmd.m_evt = nullptr;
        std::cout << "Deleted m_evt object" << std::endl;
    });
    std::cout << "Exiting Retrieve_event_data_length_as_zero_when_event_data_is_empty test" << std::endl;
}
/**
 * @brief Validate that get_event_length() correctly computes the total event length.
 *
 * This test verifies that the get_event_length() API correctly computes the total event length by adding the size of the event structure (em_event_t) to the frame length when the event type is set to em_event_type_frame. It ensures that memory allocation, event initialization, and arithmetic calculation are properly performed.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 057
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                 | Test Data                                                                                                  | Expected Result                                              | Notes          |
 * | :--------------: | --------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ | -------------- |
 * | 01               | Create command object and free pre-allocated m_evt if it exists              | cmd_obj.m_evt (if not nullptr)                                                                            | m_evt is freed and set to nullptr                            | Should be successful |
 * | 02               | Allocate memory for em_event_t and initialize it with zeros, then set event type and frame length | Allocate evt with size = sizeof(em_event_t), evt->type = em_event_type_frame, evt->u.fevt.frame_len = 100 | evt is allocated with proper initialization                  | Should be successful |
 * | 03               | Assign the allocated event to the command object and invoke get_event_length()  | cmd_obj.m_evt = evt; get_event_length() call yielding ret_val                                               | ret_val computed as sizeof(em_event_t) + 100                   | Should Pass    |
 * | 04               | Validate that the returned event length matches the expected calculation     | ret_val, expected_value = sizeof(em_event_t) + evt->u.fevt.frame_len                                          | EXPECT_EQ(ret_val, expected_value) passes                      | Should Pass    |
 */
TEST(em_cmd_t, ValidateEventLengthTypical) {
    std::cout << "Entering ValidateEventLengthTypical test" << std::endl;
    em_cmd_t cmd_obj;
    if (cmd_obj.m_evt) {
        free(cmd_obj.m_evt);
        cmd_obj.m_evt = nullptr;
        std::cout << "Freed constructor allocated m_evt" << std::endl;
    }
    em_event_t *evt = static_cast<em_event_t*>(malloc(sizeof(em_event_t)));
    ASSERT_NE(evt, nullptr);
    memset(evt, 0, sizeof(em_event_t));
    evt->type = em_event_type_frame;
    evt->u.fevt.frame_len = 100;
    cmd_obj.m_evt = evt;
    std::cout << "Event type set to: em_event_type_frame" << std::endl;
    std::cout << "Configured frame_len = " << evt->u.fevt.frame_len << std::endl;
    std::cout << "Invoking get_event_length()" << std::endl;
    unsigned int ret_val = cmd_obj.get_event_length();
    std::cout << "get_event_length() returned = " << ret_val << std::endl;
    unsigned int expected_value = sizeof(em_event_t) + evt->u.fevt.frame_len;
    std::cout << "Expected = sizeof(em_event_t) (" 
              << sizeof(em_event_t) 
              << ") + frame_len (100) = " 
              << expected_value << std::endl;
    EXPECT_EQ(ret_val, expected_value);
    std::cout << "Exiting ValidateEventLengthTypical test" << std::endl;
}
/**
 * @brief Validate that get_ieee_1905_security_cap correctly retrieves the security capability values
 *
 * This test verifies that the get_ieee_1905_security_cap method correctly returns a valid pointer after setting
 * known values for onboarding_proto, integrity_algo, and encryption_algo in the internal data model. The test
 * ensures that the API does not throw an exception and the retrieved values match the expected constants.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 058
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                      | Test Data                                                                                                             | Expected Result                                                                                                             | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Set security capability values in the command object and invoke get_ieee_1905_security_cap method | onboarding_proto = 1, integrity_algo = 2, encryption_algo = 3, expected_onboarding_proto = 1, expected_integrity_algo = 2, expected_encryption_algo = 3 | API returns a valid pointer with security capability values matching the expected values and assertions pass | Should Pass |
 */
TEST(em_cmd_t, get_ieee_1905_security_cap_Successful) {
    std::cout << "Entering get_ieee_1905_security_cap_Successful test" << std::endl;   
    em_cmd_t cmd_obj;
    cmd_obj.m_data_model.m_ieee_1905_security.m_ieee_1905_security_info.sec_cap.onboarding_proto = 1;
    cmd_obj.m_data_model.m_ieee_1905_security.m_ieee_1905_security_info.sec_cap.integrity_algo   = 2;
    cmd_obj.m_data_model.m_ieee_1905_security.m_ieee_1905_security_info.sec_cap.encryption_algo  = 3;
    std::cout << "Invoking get_ieee_1905_security_cap method" << std::endl;
    em_ieee_1905_security_cap_t *cap_ptr = nullptr;
    EXPECT_NO_THROW(cap_ptr = cmd_obj.get_ieee_1905_security_cap());
    EXPECT_NE(cap_ptr, nullptr);    
    if (cap_ptr) {
        std::cout << "Retrieved security cap values:" << std::endl;
        std::cout << "  onboarding_proto = " << static_cast<int>(cap_ptr->onboarding_proto) << std::endl;
        std::cout << "  integrity_algo   = " << static_cast<int>(cap_ptr->integrity_algo) << std::endl;
        std::cout << "  encryption_algo  = " << static_cast<int>(cap_ptr->encryption_algo) << std::endl;        
        EXPECT_EQ(cap_ptr->onboarding_proto, 1);
        EXPECT_EQ(cap_ptr->integrity_algo,   2);
        EXPECT_EQ(cap_ptr->encryption_algo,  3);
    }    
    std::cout << "Exiting get_ieee_1905_security_cap_Successful test" << std::endl;
}
/**
 * @brief Validate that an em_cmd_t instance with type set to em_cmd_type_none fails validation.
 *
 * This test verifies that when an em_cmd_t object is instantiated with its m_type set to em_cmd_type_none, 
 * the validate() method returns false. This behavior confirms that the validate() function correctly identifies 
 * an invalid command type.
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
 * | Variation / Step | Description                                                                                      | Test Data                                      | Expected Result                                                | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------------------ | ---------------------------------------------- | -------------------------------------------------------------- | ----------- |
 * | 01               | Create an instance of em_cmd_t with m_type set to em_cmd_type_none and invoke validate() method.  | m_type = em_cmd_type_none, result = (false)    | validate() returns false and EXPECT_FALSE assertion verifies it | Should Pass |
 */
TEST(em_cmd_t, validate_cmdtypenone_returns_false)
{
    std::cout << "Entering validate_cmdtypenone_returns_false test" << std::endl;
    em_cmd_t cmd;
	cmd.m_type = em_cmd_type_none;
    std::cout << "Created em_cmd_t instance using default constructor" << std::endl;
    std::cout << "Invoking validate() on default constructed instance" << std::endl;
    bool result = cmd.validate();
    std::cout << "validate() returned: " << result << std::endl;
    EXPECT_FALSE(result);
    std::cout << "Exiting validate_cmdtypenone_returns_false test" << std::endl;
}
/**
 * @brief Validate that the validate() method returns false when m_type is set to em_cmd_type_max
 *
 * This test verifies that an em_cmd_t instance with its m_type field set to em_cmd_type_max is correctly identified as invalid by the validate() method. It ensures that the error handling for an invalid command type is working as expected.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 060
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                          | Test Data                                   | Expected Result                        | Notes            |
 * | :--------------: | -------------------------------------------------------------------- | ------------------------------------------- | -------------------------------------- | ---------------- |
 * | 01               | Create an em_cmd_t instance using the default constructor.           | None                                        | Instance is created successfully.      | Should be successful |
 * | 02               | Set the m_type field of the instance to em_cmd_type_max.               | input: m_type = em_cmd_type_max             | m_type field is updated to em_cmd_type_max. | Should be successful |
 * | 03               | Invoke validate() method on the instance and verify its return value.  | output: result, expected return value = false | validate() returns false as expected.  | Should Fail      |
 */
TEST(em_cmd_t, validate_cmdtypemax_returns_false)
{
    std::cout << "Entering validate_cmdtypemax_returns_false test" << std::endl;
    em_cmd_t cmd;
    cmd.m_type = em_cmd_type_max;
    std::cout << "Created em_cmd_t instance using default constructor" << std::endl;
    std::cout << "Invoking validate() on default constructed instance" << std::endl;
    bool result = cmd.validate();
    std::cout << "validate() returned: " << result << std::endl;
    EXPECT_FALSE(result);
    std::cout << "Exiting validate_cmdtypemax_returns_false test" << std::endl;
}
/**
 * @brief Validate that em_cmd_t::validate returns true for a vap config command type.
 *
 * This test ensures that when an instance of em_cmd_t is created with its m_type member set to em_cmd_type_vap_config,
 * calling validate() returns true, indicating that the command object has been correctly identified as valid for vap configuration.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 061
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create an instance of em_cmd_t, assign m_type to em_cmd_type_vap_config, and invoke validate() method. | m_type = em_cmd_type_vap_config, result = (expected true) | validate() returns true and EXPECT_TRUE assertion passes | Should Pass |
 */
TEST(em_cmd_t, validate_cmdtypevapconfig_returns_true)
{
    std::cout << "Entering validate_cmdtypevapconfig_returns_true test" << std::endl;
    em_cmd_t cmd;
	cmd.m_type = em_cmd_type_vap_config;
    std::cout << "Created em_cmd_t instance using default constructor" << std::endl;
    std::cout << "Invoking validate() on default constructed instance" << std::endl;
    bool result = cmd.validate();
    std::cout << "validate() returned: " << result << std::endl;
    EXPECT_TRUE(result);
    std::cout << "Exiting validate_cmdtypevapconfig_returns_true test" << std::endl;
}
/**
 * @brief Validate the conversion of all valid status codes to their corresponding JSON strings.
 *
 * This test verifies that the status_to_string method correctly converts each valid status code into a JSON string containing the "Status" field with the expected value.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 062
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- | -------------- | ----- |
 * | 01 | Invoke status_to_string with status em_cmd_out_status_success | status = em_cmd_out_status_success, expected = Success, buffer = char[50] | Returns pointer to buffer; JSON "Status" equals "Success" | Should Pass |
 * | 02 | Invoke status_to_string with status em_cmd_out_status_not_ready | status = em_cmd_out_status_not_ready, expected = Error_Not_Ready, buffer = char[50] | Returns pointer to buffer; JSON "Status" equals "Error_Not_Ready" | Should Pass |
 * | 03 | Invoke status_to_string with status em_cmd_out_status_invalid_input | status = em_cmd_out_status_invalid_input, expected = Error_Invalid_Input, buffer = char[50] | Returns pointer to buffer; JSON "Status" equals "Error_Invalid_Input" | Should Pass |
 * | 04 | Invoke status_to_string with status em_cmd_out_status_timeout | status = em_cmd_out_status_timeout, expected = Error_Timeout, buffer = char[50] | Returns pointer to buffer; JSON "Status" equals "Error_Timeout" | Should Pass |
 * | 05 | Invoke status_to_string with status em_cmd_out_status_invalid_mac | status = em_cmd_out_status_invalid_mac, expected = Error_Invalid_Mac, buffer = char[50] | Returns pointer to buffer; JSON "Status" equals "Error_Invalid_Mac" | Should Pass |
 * | 06 | Invoke status_to_string with status em_cmd_out_status_interface_down | status = em_cmd_out_status_interface_down, expected = Error_Interface_Down, buffer = char[50] | Returns pointer to buffer; JSON "Status" equals "Error_Interface_Down" | Should Pass |
 * | 07 | Invoke status_to_string with status em_cmd_out_status_other | status = em_cmd_out_status_other, expected = Error_Other, buffer = char[50] | Returns pointer to buffer; JSON "Status" equals "Error_Other" | Should Pass |
 * | 08 | Invoke status_to_string with status em_cmd_out_status_prev_cmd_in_progress | status = em_cmd_out_status_prev_cmd_in_progress, expected = Error_Prev_Cmd_In_Progress, buffer = char[50] | Returns pointer to buffer; JSON "Status" equals "Error_Prev_Cmd_In_Progress" | Should Pass |
 * | 09 | Invoke status_to_string with status em_cmd_out_status_no_change | status = em_cmd_out_status_no_change, expected = Error_No_Config_Change_Detected, buffer = char[50] | Returns pointer to buffer; JSON "Status" equals "Error_No_Config_Change_Detected" | Should Pass |
 */
TEST(em_cmd_t, status_to_string_convert_all_valid_status) {
    std::cout << "Entering status_to_string_convert_all_valid_status test" << std::endl;
    em_cmd_t cmd;
    struct TestMapping {
        em_cmd_out_status_t status;
        const char* expected;
    };
    TestMapping mappings[] = {
        { em_cmd_out_status_success,                "Success" },
        { em_cmd_out_status_not_ready,              "Error_Not_Ready" },
        { em_cmd_out_status_invalid_input,          "Error_Invalid_Input" },
        { em_cmd_out_status_timeout,                "Error_Timeout" },
        { em_cmd_out_status_invalid_mac,            "Error_Invalid_Mac" },
        { em_cmd_out_status_interface_down,         "Error_Interface_Down" },
        { em_cmd_out_status_other,                  "Error_Other" },
        { em_cmd_out_status_prev_cmd_in_progress,   "Error_Prev_Cmd_In_Progress" },
        { em_cmd_out_status_no_change,              "Error_No_Config_Change_Detected" }
    };
    const size_t num_tests = sizeof(mappings) / sizeof(mappings[0]);    
    for (size_t i = 0; i < num_tests; ++i) {
        char buffer[50] = {0};
        std::cout << "Invoking status_to_string with status value: " << static_cast<unsigned int>(mappings[i].status) 
                  << " and buffer address: " << static_cast<void*>(buffer) << std::endl;
        char* result = cmd.status_to_string(mappings[i].status, buffer);

        std::cout << "Method returned pointer: " << static_cast<void*>(result) << std::endl;
        cJSON* obj = cJSON_Parse(buffer);
        ASSERT_NE(obj, nullptr);
        cJSON* status_item = cJSON_GetObjectItem(obj, "Status");
        ASSERT_NE(status_item, nullptr);
        EXPECT_STREQ(status_item->valuestring, mappings[i].expected);
        cJSON_Delete(obj);
    }
    std::cout << "Exiting status_to_string_convert_all_valid_status test" << std::endl;
}
/**
 * @brief Verify that status_to_string returns a null pointer when provided a null buffer.
 *
 * This test case validates that the status_to_string API correctly handles a null buffer pointer by returning nullptr when invoked with a valid status. It ensures that the implementation gracefully manages null pointers without causing unintended behavior.
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
 * | Variation / Step | Description                                                           | Test Data                                                                | Expected Result                                       | Notes       |
 * | :----:           | :-------------------------------------------------------------------- | :----------------------------------------------------------------------- | :---------------------------------------------------- | :---------: |
 * | 01               | Invoke status_to_string with a valid status and a null buffer pointer.  | testStatus = em_cmd_out_status_success, buffer = nullptr                 | Return value is nullptr and assertion passes          | Should Pass |
 */
TEST(em_cmd_t, status_to_string_handle_null_buffer) {
    std::cout << "Entering status_to_string_handle_null_buffer test" << std::endl;
    em_cmd_t cmd;
    em_cmd_out_status_t testStatus = em_cmd_out_status_success;
    std::cout << "Invoking status_to_string with status value: " << static_cast<unsigned int>(testStatus) 
              << " and buffer pointer as NULL" << std::endl;
    char* retVal = cmd.status_to_string(testStatus, nullptr);
    EXPECT_EQ(retVal, nullptr);
    std::cout << "Exiting status_to_string_handle_null_buffer test" << std::endl;
}
/**
 * @brief Validate the behavior of get_svc() method for the control service type.
 *
 * This test verifies that the get_svc() method of em_cmd_t correctly returns the service type when it is set to em_service_type_ctrl. It ensures that the service type assignment and retrieval work as expected in a positive scenario.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 064@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize the em_cmd_t object | No input parameters | Object is created successfully | Should be successful |
 * | 02 | Set the object's service type member to em_service_type_ctrl | m_svc = em_service_type_ctrl | m_svc is assigned the value em_service_type_ctrl | Should be successful |
 * | 03 | Invoke get_svc() to retrieve the service type | Input: None, Output: svc variable | get_svc() returns em_service_type_ctrl | Should Pass |
 * | 04 | Verify the retrieved service type against the expected value using EXPECT_EQ | Expected: em_service_type_ctrl, Actual: svc | Assertion passes if svc equals em_service_type_ctrl | Should Pass |
 * | 05 | Complete test execution after logging steps | No additional test data | Test ends successfully after logs | Should be successful |
 */
TEST(em_cmd_t, get_svc_valid_ctrl) {
    std::cout << "Entering get_svc_valid_ctrl test" << std::endl;
    em_cmd_t cmd {};
    cmd.m_svc = em_service_type_ctrl;
    std::cout << "Invoking get_svc()" << std::endl;
    em_service_type_t svc = cmd.get_svc();
    std::cout << "get_svc() returned value: " << static_cast<unsigned int>(svc) << std::endl;
    EXPECT_EQ(svc, em_service_type_ctrl);
    std::cout << "Exiting get_svc_valid_ctrl test" << std::endl;
}
/**
 * @brief Validates that the get_svc() method returns the valid agent service type.
 *
 * This test verifies that after initializing an em_cmd_t object and setting its m_svc member to em_service_type_agent, the get_svc() method correctly returns em_service_type_agent. This ensures that the service type is properly stored and retrieved.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- | -------------- | ----- |
 * | 01 | Create an em_cmd_t object, set m_svc to em_service_type_agent, invoke get_svc(), and verify the returned value. | m_svc = em_service_type_agent, svc = result of get_svc() | svc equals em_service_type_agent as per EXPECT_EQ check | Should Pass |
 */
TEST(em_cmd_t, get_svc_valid_agent) {
    std::cout << "Entering get_svc_valid_agent test" << std::endl;
    em_cmd_t cmd {};
    cmd.m_svc = em_service_type_agent;
    std::cout << "Invoking get_svc()" << std::endl;
    em_service_type_t svc = cmd.get_svc();
    std::cout << "get_svc() returned value: " << static_cast<unsigned int>(svc) << std::endl;
    EXPECT_EQ(svc, em_service_type_agent);
    std::cout << "Exiting get_svc_valid_agent test" << std::endl;
}
/**
 * @brief Validate that the get_svc() API returns the correct CLI service type.
 *
 * This test sets the service type to CLI in the command object and then invokes the get_svc() API to ensure that it returns the expected CLI service type.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 066@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create an instance of command and set service type to CLI, then call get_svc() | m_svc = em_service_type_cli, svc (output) = em_service_type_cli | API returns em_service_type_cli and assertion passes | Should Pass |
 */
TEST(em_cmd_t, get_svc_valid_cli) {
    std::cout << "Entering get_svc_valid_cli test" << std::endl;
    em_cmd_t cmd {};
    cmd.m_svc = em_service_type_cli;
    std::cout << "Invoking get_svc()" << std::endl;
    em_service_type_t svc = cmd.get_svc();
    std::cout << "get_svc() returned value: " << static_cast<unsigned int>(svc) << std::endl;
    EXPECT_EQ(svc, em_service_type_cli);
    std::cout << "Exiting get_svc_valid_cli test" << std::endl;
}
/**
 * @brief Test to verify that get_svc() returns em_service_type_none.
 *
 * This test validates that when the m_svc member of em_cmd_t is set to em_service_type_none,
 * the get_svc() function correctly returns em_service_type_none. This ensures that the accessor
 * function behaves as expected when no valid service is assigned.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 067@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                         | Test Data                                                           | Expected Result                                                                                         | Notes        |
 * | :--------------: | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- | ------------ |
 * | 01               | Create an instance of em_cmd_t, set m_svc to em_service_type_none, invoke get_svc(), and verify the returned value | input: m_svc = em_service_type_none, output: svc = em_service_type_none | get_svc() should return em_service_type_none and pass the EXPECT_EQ check                                  | Should Pass  |
 */
TEST(em_cmd_t, get_svc_valid_none) {
    std::cout << "Entering get_svc_valid_none test" << std::endl;
    em_cmd_t cmd {};
    cmd.m_svc = em_service_type_none;
    std::cout << "Invoking get_svc()" << std::endl;
    em_service_type_t svc = cmd.get_svc();
    std::cout << "get_svc() returned value: " << static_cast<unsigned int>(svc) << std::endl;
    EXPECT_EQ(svc, em_service_type_none);
    std::cout << "Exiting get_svc_valid_none test" << std::endl;
}
/**
 * @brief Validate that the get_svc function returns the invalid service type when m_svc is explicitly set to an out-of-range value.
 *
 * This test verifies that when the m_svc member of the em_cmd_t object is assigned an invalid value (-1), the get_svc() method correctly returns this invalid value. This helps ensure that the API does not modify or incorrectly process invalid input values.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 068@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                         | Test Data                               | Expected Result                                            | Notes      |
 * | :--------------: | ------------------------------------------------------------------- | --------------------------------------- | ---------------------------------------------------------- | ---------- |
 * | 01               | Instantiate em_cmd_t, set m_svc to -1, and invoke get_svc() method.   | m_svc = -1, output svc = -1               | get_svc() returns -1 and the EXPECT_EQ assertion passes.   | Should Pass|
 */
TEST(em_cmd_t, get_svc_invalid_value_check) {
    std::cout << "Entering get_svc_invalid_value_check test" << std::endl;
    em_cmd_t cmd {};
    cmd.m_svc = static_cast<em_service_type_t>(-1);
    std::cout << "Invoking get_svc()" << std::endl;
    em_service_type_t svc = cmd.get_svc();
    std::cout << "get_svc() returned value: " << static_cast<unsigned int>(svc) << std::endl;
    EXPECT_EQ(svc, -1);
    std::cout << "Exiting get_svc_invalid_value_check test" << std::endl;
}
/**
 * @brief Test the set_event_data_length function using a zero length value
 *
 * This test verifies that the API function set_event_data_length successfully accepts a zero value without throwing any exception. It ensures that when the event data length is set to zero, the function executes correctly. 
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 069@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                            | Test Data                                              | Expected Result                                           | Notes       |
 * | :--------------: | ---------------------------------------------------------------------- | ------------------------------------------------------ | --------------------------------------------------------- | ----------- |
 * | 01               | Invoke set_event_data_length with value 0 after setting the event type   | m_evt->type = em_event_type_frame, length = 0          | API function executes without throwing any exception      | Should Pass |
 */
TEST(em_cmd_t, set_event_data_length_set_event_data_length_to_zero) {
    std::cout << "Entering set_event_data_length_set_event_data_length_to_zero test" << std::endl;
    em_cmd_t cmd;
	cmd.m_evt->type = em_event_type_frame;
    unsigned int length = 0;
    std::cout << "Invoking set_event_data_length with value: " << length << std::endl;
    EXPECT_NO_THROW({
        cmd.set_event_data_length(length);
        std::cout << "set_event_data_length() executed with input: " << length << std::endl;
    });
    std::cout << "Exiting set_event_data_length_set_event_data_length_to_zero test" << std::endl;
}
/**
 * @brief Tests set_event_data_length with a valid typical length value.
 *
 * This test verifies that set_event_data_length properly sets a typical valid value (500) for event data length. It ensures that no exception is thrown when the API is called with valid input, confirming the function's expected behavior for typical use.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 070@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                     | Test Data                                                      | Expected Result                                              | Notes         |
 * | :--------------: | ----------------------------------------------------------------------------------------------- | -------------------------------------------------------------- | ------------------------------------------------------------ | ------------- |
 * | 01               | Instantiate em_cmd_t object and set event type to em_event_type_bus.                           | cmd.m_evt->type = em_event_type_bus                            | The event type is set correctly in the cmd object.         | Should be successful |
 * | 02               | Invoke set_event_data_length with a valid typical length value and verify no exception is thrown. | length = 500, input: length=500, output: none expected           | Function executes without throwing any exceptions.         | Should Pass   |
 */
TEST(em_cmd_t, set_event_data_length_set_event_data_length_to_valid_typical_value) {
    std::cout << "Entering set_event_data_length_set_event_data_length_to_valid_typical_value test" << std::endl;
    em_cmd_t cmd;
    cmd.m_evt->type = em_event_type_bus;
    unsigned int length = 500;
    std::cout << "Invoking set_event_data_length with value: " << length << std::endl;
    EXPECT_NO_THROW({
        cmd.set_event_data_length(length);
        std::cout << "set_event_data_length() executed with input: " << length << std::endl;
    });
    std::cout << "Exiting set_event_data_length_set_event_data_length_to_valid_typical_value test" << std::endl;
}
/**
 * @brief Validate that set_event_data_length correctly handles the valid upper boundary value.
 *
 * This test verifies that the set_event_data_length API correctly processes an upper boundary value (1024) without throwing any exceptions. It initializes the command object, sets the event type to bus, and then invokes the method with a valid boundary value. This ensures that the function handles extreme yet valid inputs as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 071@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                       | Test Data                                | Expected Result                                                              | Notes         |
 * | :--------------: | ----------------------------------------------------------------- | ---------------------------------------- | --------------------------------------------------------------------------- | ------------- |
 * | 01               | Initialize the command object and set the event type to bus.        | m_evt->type = em_event_type_bus          | Command object initialized with correct event type.                       | Should be successful |
 * | 02               | Invoke set_event_data_length() with a valid upper boundary value.     | length = 1024                            | API method executes without throwing any exceptions; assertion passes.    | Should Pass   |
 */
TEST(em_cmd_t, set_event_data_length_set_event_data_length_to_valid_upper_boundary) {
    std::cout << "Entering set_event_data_length_set_event_data_length_to_valid_upper_boundary test" << std::endl;
    em_cmd_t cmd;
    cmd.m_evt->type = em_event_type_bus;
    unsigned int length = 1024;
    std::cout << "Invoking set_event_data_length with value: " << length << std::endl;
    EXPECT_NO_THROW({
        cmd.set_event_data_length(length);
        std::cout << "set_event_data_length() executed with input: " << length << std::endl;
    });
    std::cout << "Exiting set_event_data_length_set_event_data_length_to_valid_upper_boundary test" << std::endl;
}
/**
 * @brief Validates that the get_param() method returns the expected parameters after initialization
 *
 * This test verifies that after setting up the network node in the em_cmd_t object's parameters,
 * invoking get_param() returns a valid pointer to the parameters structure with all the expected values.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 072@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                                      | Test Data                                                                                                                      | Expected Result                                                                                                          | Notes           |
 * | :--------------: | ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------ | --------------- |
 * | 01               | Initialize an em_cmd_t object and set the network node parameters with valid values.                             | m_param.net_node->value_int = 6, m_param.net_node->value_str = Validstring, m_param.net_node->num_children = 2               | The em_cmd_t object is correctly initialized with a valid network node instance.                                      | Should be successful |
 * | 02               | Invoke the get_param() method on the em_cmd_t object.                                                            | API call: get_param() invoked on the object                                                                                | A non-null pointer to an em_cmd_params_t structure is returned.                                                       | Should Pass     |
 * | 03               | Validate that the returned network node parameters match the initialized values using assertions.                | Returned data: net_node->value_int = 6, net_node->value_str = Validstring, net_node->num_children = 2                        | All assertion checks pass: pointer non-null, value_int equals 6, value_str equals "Validstring", num_children equals 2.     | Should Pass     |
 * | 04               | Clean up the allocated memory for the network node, ensuring proper deletion and nullification.                  | delete operation on m_param.net_node; subsequent assignment: m_param.net_node = nullptr                                     | Memory is freed without error and the network node pointer is set to nullptr.                                           | Should be successful |
 */
TEST(em_cmd_t, get_param_invocation) {
    std::cout << "Entering get_param_invocation test" << std::endl;
    em_cmd_t obj;
    obj.m_param.net_node = new em_network_node_t;
    obj.m_param.net_node->value_int = 6;
    strncpy(obj.m_param.net_node->value_str, "Validstring", sizeof(obj.m_param.net_node->value_str) - 1);
    obj.m_param.net_node->value_str[sizeof(obj.m_param.net_node->value_str) - 1] = '\0';
    obj.m_param.net_node->num_children = 2;
    std::cout << "Invoking get_param() method on default constructed em_cmd_t object." << std::endl;
    em_cmd_params_t *param_ptr = obj.get_param();
    std::cout << "Method get_param() invoked successfully" << std::endl;
    ASSERT_NE(param_ptr, nullptr);
    ASSERT_NE(param_ptr->net_node, nullptr);
    ASSERT_EQ(param_ptr->net_node->value_int, 6);
    ASSERT_STREQ(param_ptr->net_node->value_str, "Validstring");
    ASSERT_EQ(param_ptr->net_node->num_children, 2);
    delete obj.m_param.net_node;
    obj.m_param.net_node = nullptr;
    std::cout << "Exiting get_param_invocation test" << std::endl;
}
/**
 * @brief Test get_radio_interface function with valid index 0
 *
 * This test verifies that the get_radio_interface API returns a non-null pointer when called with index 0. It ensures that the radio interface at index 0 has correctly assigned MAC address, media type, and interface name.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 073@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                   | Test Data                                                                                                                     | Expected Result                                                                                                                                         | Notes         |
 * | :--------------: | --------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- |
 * | 01               | Initialize em_cmd_t instance and configure radio interface at index 0 with MAC, media, and name | em_cmd_t cmd, mac = "0x1A,0x1B,0x2C,0x3D,0x4E,0x5A", media = em_media_type_ieee80211a_5, name = "TestInterface0"               | Instance is configured successfully with the specified MAC address, media type, and interface name                                                     | Should be successful |
 * | 02               | Invoke get_radio_interface with index 0 and validate the returned interface properties          | index = 0, output: retrievedIface->name = "TestInterface0", retrievedIface->media = em_media_type_ieee80211a_5, retrievedIface->mac as above | Non-null pointer returned, interface name, media, and MAC values match expected values as asserted by ASSERT_NE, EXPECT_STREQ, and EXPECT_EQ checks | Should Pass   |
 */
TEST(em_cmd_t, get_radio_interface_valid_index0) {
    std::cout << "Entering get_radio_interface_valid_index0 test" << std::endl;
    em_cmd_t cmd;
	unsigned char mac[6] = {0x1A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5A};
	memcpy(cmd.m_data_model.m_radio[0].m_radio_info.intf.mac, mac, sizeof(mac));
	cmd.m_data_model.m_radio[0].m_radio_info.intf.media = em_media_type_ieee80211a_5;
    const char *ifaceName0 = "TestInterface0";
    strncpy(cmd.m_data_model.m_radio[0].m_radio_info.intf.name, ifaceName0, sizeof(cmd.m_data_model.m_radio[0].m_radio_info.intf.name) - 1);
    unsigned int index = 0;
    std::cout << "Invoking get_radio_interface with index: " << index << std::endl;
    em_interface_t* retrievedIface = cmd.get_radio_interface(index);
	ASSERT_NE(nullptr, retrievedIface);
    if (retrievedIface) {
        std::cout << "Retrieved interface at index " << index << " has name: " << retrievedIface->name << std::endl;
        std::cout << "Media type: " << static_cast<unsigned int>(retrievedIface->media) << std::endl;
		std::cout << "Retrieved MAC address: ";
        for (size_t i = 0; i < 6; i++) {
            printf("%02X", retrievedIface->mac[i]);
            if (i < 5) printf(":");
        }
        std::cout << std::endl;
		EXPECT_STREQ(retrievedIface->name, ifaceName0);
        EXPECT_EQ(retrievedIface->media, em_media_type_ieee80211a_5);
        for (size_t i = 0; i < 6; i++) {
            EXPECT_EQ(retrievedIface->mac[i], mac[i]);
        }
    } else {
        std::cout << "Retrieved interface is nullptr" << std::endl;
    }
    std::cout << "Exiting get_radio_interface_valid_index0 test" << std::endl;
}
/**
 * @brief Validate get_radio_interface returns the correct interface for a valid last index.
 *
 * This test verifies that the get_radio_interface method of em_cmd_t correctly retrieves the radio interface
 * configuration when a valid last index is provided. The test sets the MAC address, media type, and interface name
 * for radio[2] and confirms that the retrieved interface contains the expected details. This ensures proper mapping 
 * and retrieval of radio configuration information.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 074
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Configure em_cmd_t instance with radio[2]'s MAC, media type and interface name, then invoke get_radio_interface with index=2 | input: index = 2, mac = {0x1A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5A}, media = em_media_type_ieee80211n_24, name = "TestInterface0" | Valid interface pointer is returned with matching MAC, media, and interface name; all assertions pass | Should Pass |
 */
TEST(em_cmd_t, get_radio_interface_valid_lastindex) {
    std::cout << "Entering get_radio_interface_valid_lastindex test" << std::endl;
    em_cmd_t cmd;
    // Configure MAC for radio[0]
    unsigned char mac[6] = {0x1A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5A};
    memcpy(cmd.m_data_model.m_radio[2].m_radio_info.intf.mac, mac, sizeof(mac));
    // Configure media type for radio[2]
    cmd.m_data_model.m_radio[2].m_radio_info.intf.media = em_media_type_ieee80211n_24;
    // Set interface name on radio[0] (though index=2 returns radio[2])
    const char *ifaceName0 = "TestInterface0";
    strncpy(cmd.m_data_model.m_radio[2].m_radio_info.intf.name,
            ifaceName0,
            sizeof(cmd.m_data_model.m_radio[2].m_radio_info.intf.name) - 1);
    unsigned int index = 2;
    std::cout << "Invoking get_radio_interface with index: " << index << std::endl;
    em_interface_t* retrievedIface = cmd.get_radio_interface(index);
    ASSERT_NE(nullptr, retrievedIface);
    if (retrievedIface) {
        std::cout << "Retrieved interface at index " << index 
                  << " has name: " << retrievedIface->name << std::endl;
        std::cout << "Media type: " << static_cast<unsigned int>(retrievedIface->media) << std::endl;
        std::cout << "Retrieved MAC address: ";
        for (size_t i = 0; i < 6; i++) {
            printf("%02X", retrievedIface->mac[i]);
            if (i < 5) printf(":");
        }
        std::cout << std::endl;
		EXPECT_STREQ(retrievedIface->name, ifaceName0);
        EXPECT_EQ(retrievedIface->media, em_media_type_ieee80211n_24);
        for (size_t i = 0; i < 6; i++) {
            EXPECT_EQ(retrievedIface->mac[i], mac[i]);
        }
    }
    std::cout << "Exiting get_radio_interface_valid_lastindex test" << std::endl;
}
/**
 * @brief Verify that get_radio_interface returns nullptr for an out-of-range radio index.
 *
 * This test checks that when attempting to retrieve a radio interface using an index that is not valid (i.e., out-of-range for the configuration), the API correctly returns a nullptr. This behavior is critical to ensure that invalid indices do not yield unintended valid pointers.
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
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize the command object and configure the radio interface data at index 4 | cmd instantiated, mac = 0x1A,0x1B,0x2C,0x3D,0x4E,0x5A, media = em_media_type_ieee80211n_24, name = TestInterface0 | Command object and radio interface data are properly set | Should be successful |
 * | 02 | Invoke get_radio_interface with index 4 and validate the return value | index = 4, API call: get_radio_interface(index), expected output: nullptr | get_radio_interface returns nullptr confirming the index is out of range | Should Pass |
 */
TEST(em_cmd_t, get_radio_interface_index_out_of_range) {
    std::cout << "Entering get_radio_interface_index_out_of_range test" << std::endl;
    em_cmd_t cmd;
    unsigned char mac[6] = {0x1A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5A};
    memcpy(cmd.m_data_model.m_radio[4].m_radio_info.intf.mac, mac, sizeof(mac));
    cmd.m_data_model.m_radio[4].m_radio_info.intf.media = em_media_type_ieee80211n_24;
    const char *ifaceName0 = "TestInterface0";
    strncpy(cmd.m_data_model.m_radio[4].m_radio_info.intf.name, ifaceName0, sizeof(cmd.m_data_model.m_radio[0].m_radio_info.intf.name) - 1);
    unsigned int index = 4;
    std::cout << "Invoking get_radio_interface with index: " << index << std::endl;
    em_interface_t* retrievedIface = cmd.get_radio_interface(index);
    ASSERT_EQ(nullptr, retrievedIface);
    std::cout << "Exiting get_radio_interface_index_out_of_range test" << std::endl;
}
/**
 * @brief Validate retrieval of a valid manufacturer name using get_manufacturer API
 *
 * This test verifies that when the manufacturer field is correctly set to a valid string ("Acme Corp") in a command object, the get_manufacturer method returns a non-null pointer and the correct manufacturer name. This ensures that the API correctly retrieves the device manufacturer information.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 076
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                           | Test Data                                                                                                 | Expected Result                                                                                          | Notes      |
 * | :--------------: | ----------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- | ---------- |
 * | 01               | Instantiate em_cmd_t, set the manufacturer to "Acme Corp", and invoke get_manufacturer API             | cmd.m_data_model.m_device.m_device_info.manufacturer = "Acme Corp", get_manufacturer() call              | The API returns a non-null pointer with string equal to "Acme Corp"; assertion passes                     | Should Pass|
 */
TEST(em_cmd_t, get_manufacturer_valid_retrieve_valid_manufacturer_name)
{
    std::cout << "Entering get_manufacturer_valid_retrieve_valid_manufacturer_name test" << std::endl;       
    em_cmd_t cmd{};
    strncpy(cmd.m_data_model.m_device.m_device_info.manufacturer, "Acme Corp", sizeof(cmd.m_data_model.m_device.m_device_info.manufacturer) - 1);
    std::cout << "Invoking get_manufacturer()" << std::endl;
    char *result = nullptr;
    result = cmd.get_manufacturer();
    std::cout << "Retrieved manufacturer: " << (result ? result : "null") << std::endl;
    EXPECT_NE(result, nullptr);
    EXPECT_STREQ(result, "Acme Corp");
    std::cout << "Exiting get_manufacturer_valid_retrieve_valid_manufacturer_name test" << std::endl;
}
/**
 * @brief Verify that get_manufacturer returns an empty string when the manufacturer field is empty.
 *
 * This test verifies that when the manufacturer's value in the device information is set to an empty string, the get_manufacturer() API correctly returns a pointer to a string with a length of zero. This ensures that the API handles empty manufacturer names gracefully.
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
 * | Variation / Step | Description                                                                                | Test Data                                            | Expected Result                                         | Notes           |
 * | :--------------: | ------------------------------------------------------------------------------------------ | ---------------------------------------------------- | ------------------------------------------------------- | --------------- |
 * | 01               | Initialize em_cmd_t object and set manufacturer field to empty using strncpy               | manufacturer = ""                                    | em_cmd_t object manufacturer field contains an empty string | Should be successful |
 * | 02               | Invoke get_manufacturer() on em_cmd_t object to retrieve the manufacturer name             | Input: cmd, Output: result pointer                   | Returns a non-null pointer                              | Should Pass     |
 * | 03               | Validate that the length of the returned manufacturer string is zero                        | Output: result string length, Expected: 0            | API returns an empty string with a length equal to 0     | Should Pass     |
 */
TEST(em_cmd_t, get_manufacturer_empty_retrieve_manufacturer_name_empty)
{
    std::cout << "Entering get_manufacturer_empty_retrieve_manufacturer_name_empty test" << std::endl;
    em_cmd_t cmd{};
    strncpy(cmd.m_data_model.m_device.m_device_info.manufacturer, "", sizeof(cmd.m_data_model.m_device.m_device_info.manufacturer) - 1);
    std::cout << "Invoking get_manufacturer()" << std::endl;
    char *result = cmd.get_manufacturer();
    ASSERT_NE(result, nullptr);
    std::cout << "Retrieved manufacturer: '" << result << std::endl;
    EXPECT_EQ(strlen(result), 0);
    std::cout << "Exiting get_manufacturer_empty_retrieve_manufacturer_name_empty test" << std::endl;
}
/**
 * @brief Tests get_manufacturer() function for retrieving a manufacturer with special characters.
 *
 * This test verifies that the get_manufacturer() API correctly retrieves a manufacturer string 
 * containing special characters, ensuring that the API can handle non-alphanumeric characters without error.
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
 * | Variation / Step | Description                                                                                      | Test Data                                                                                      | Expected Result                                                                                   | Notes        |
 * | :--------------: | ------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- | ------------ |
 * | 01               | Initialize em_cmd_t object and set the manufacturer field with special characters using memcpy.  | manufacturer = !@#$%^&*()_+ (copied to cmd.m_data_model.m_device.m_device_info.manufacturer)   | The manufacturer field in the object is set to "!@#$%^&*()_+"                                      | Should be successful |
 * | 02               | Invoke get_manufacturer() API and verify that the returned string matches the expected manufacturer. | API call: result = cmd.get_manufacturer(), expected output: !@#$%^&*()_+                         | get_manufacturer() returns a non-null pointer and the string exactly equals "!@#$%^&*()_+"         | Should Pass  |
 */
TEST(em_cmd_t, get_manufacturer_RetrieveManufacturerWithSpecialCharacters)
{
    std::cout << "Entering get_manufacturer_RetrieveManufacturerWithSpecialCharacters test" << std::endl;
    em_cmd_t cmd{};
    memcpy(cmd.m_data_model.m_device.m_device_info.manufacturer, "!@#$%^&*()_+", strlen("!@#$%^&*()_+") + 1);
    std::cout << "Invoking get_manufacturer()" << std::endl;
    char *result = cmd.get_manufacturer();
    ASSERT_NE(result, nullptr);
    std::cout << "Retrieved manufacturer: " << result << std::endl;    
    EXPECT_STREQ(result, "!@#$%^&*()_+");
    std::cout << "Exiting get_manufacturer_RetrieveManufacturerWithSpecialCharacters test" << std::endl;
}
/**
 * @brief Validate that the get_manufacturer_model function returns the correct manufacturer model string when a valid model is set.
 *
 * This test sets the manufacturer_model field of the em_cmd_t instance to "TestModel" and then invokes the get_manufacturer_model() function to verify that the returned string is not null and correctly matches "TestModel". This ensures that the function retrieves the properly set manufacturer model.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 079
 * **Priority:** High
 * 
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize the em_cmd_t instance and set manufacturer_model field to "TestModel". | manufacturer_model = TestModel | manufacturer_model field is set correctly | Should be successful |
 * | 02 | Invoke get_manufacturer_model() and verify that a valid pointer is returned and the output matches "TestModel". | output1 (result pointer) = non-null, expected string = TestModel | API returns non-null pointer and matches "TestModel" | Should Pass |
 */
TEST(em_cmd_t, get_manufacturer_model_ValidModelProperlySet)
{
    std::cout << "Entering get_manufacturer_model_ValidModelProperlySet test" << std::endl;
    em_cmd_t cmd;
    strncpy(cmd.m_data_model.m_device.m_device_info.manufacturer_model, "TestModel", sizeof(cmd.m_data_model.m_device.m_device_info.manufacturer_model) - 1);
    std::cout << "Invoking get_manufacturer_model()" << std::endl;
    char *result = cmd.get_manufacturer_model();
    ASSERT_NE(result, nullptr);
    std::cout << "Retrieved manufacturer model: " << result << std::endl;
    EXPECT_STREQ(result, "TestModel");
    std::cout << "Exiting get_manufacturer_model_ValidModelProperlySet test" << std::endl;
}
/**
 * @brief Test the get_manufacturer_model function for an empty manufacturer model.
 *
 * This test verifies that when the manufacturer model field is set to an empty string,
 * the get_manufacturer_model function returns a valid pointer and the corresponding string is empty.
 * It ensures proper handling of the empty string scenario.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 080@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**
 * | Variation / Step | Description                                                            | Test Data                                                                                          | Expected Result                                      | Notes          |
 * | :-------------: | ---------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | ---------------------------------------------------- | -------------- |
 * | 01              | Create an instance of em_cmd_t and set manufacturer_model to an empty string | cmd.m_data_model.m_device.m_device_info.manufacturer_model = ""                                    | Field is set to empty string                         | Should be successful |
 * | 02              | Invoke the get_manufacturer_model function                             | Invocation: char *result = cmd.get_manufacturer_model()                                             | Function returns a non-null pointer                  | Should Pass    |
 * | 03              | Assert that the retrieved manufacturer model is an empty string          | ASSERT_NE(result, nullptr), EXPECT_STREQ(result, "")                                                 | Returned string is empty ("")                        | Should Pass    |
 */
TEST(em_cmd_t, get_manufacturer_model_EmptyModel)
{
    std::cout << "Entering get_manufacturer_model_EmptyModel test" << std::endl;
    em_cmd_t cmd;
    strncpy(cmd.m_data_model.m_device.m_device_info.manufacturer_model, "", sizeof(cmd.m_data_model.m_device.m_device_info.manufacturer_model) - 1);
    std::cout << "Invoking get_manufacturer_model()" << std::endl;
    char *result = cmd.get_manufacturer_model();
    ASSERT_NE(result, nullptr);
    std::cout << "Retrieved manufacturer model (expected empty string): '" << result << "'" << std::endl;
    EXPECT_STREQ(result, "");
    std::cout << "Exiting get_manufacturer_model_EmptyModel test" << std::endl;
}
/**
 * @brief Verify that get_manufacturer_model correctly retrieves a manufacturer model with special characters
 *
 * This test sets the manufacturer model field to a string containing special characters ("!@#$%^&*()") and then
 * calls get_manufacturer_model to verify that it returns a non-null pointer, and the returned string exactly matches
 * the expected special characters. This ensures that the API correctly handles strings with special characters.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 081@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize the manufacturer_model field with the special characters "!@#$%^&*()" | input: manufacturer_model = "!@#$%^&*()" | The API should return a non-null pointer, and the value should match "!@#$%^&*()" | Should Pass |
 */
TEST(em_cmd_t, get_manufacturer_model_RetrieveWithSpecialCharacters)
{
    std::cout << "Entering get_manufacturer_model_RetrieveWithSpecialCharacters test" << std::endl;
    em_cmd_t cmd{};
    memcpy(cmd.m_data_model.m_device.m_device_info.manufacturer_model, "!@#$%^&*()", strlen("!@#$%^&*()") + 1);
    std::cout << "Invoking get_manufacturer_model()" << std::endl;
    char *result = cmd.get_manufacturer_model();
    ASSERT_NE(result, nullptr);
    std::cout << "Retrieved manufacturer model: " << (result ? result : "null") << std::endl;
    EXPECT_STREQ(result, "!@#$%^&*()");
    std::cout << "Exiting get_manufacturer_model_RetrieveWithSpecialCharacters test" << std::endl;
}
/**
 * @brief Tests that get_serial_number() returns a valid serial number string.
 *
 * This test verifies that when a valid serial number ("ABC123") is set in the device info,
 * the get_serial_number() API returns a non-null pointer to the correct serial number string.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 082@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                        | Test Data                                                                                                          | Expected Result                                                      | Notes         |
 * | :--------------: | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------- | ------------- |
 * | 01               | Setup expected serial number in the device info                    | expectedSerial = ABC123, cmd.m_data_model.m_device.m_device_info.serial_number = ABC123                            | Device info serial number is correctly set                           | Should be successful |
 * | 02               | Invoke get_serial_number() on em_cmd_t object                         | cmd object with serial number set to "ABC123"                                                                       | get_serial_number() returns a non-null pointer                         | Should Pass   |
 * | 03               | Validate that the returned serial number matches the expected value    | retSerial = result of get_serial_number(), expectedSerial = ABC123                                                    | ASSERT_NE(retSerial, nullptr) and EXPECT_STREQ(retSerial, expectedSerial) succeed | Should Pass   |
 */
TEST(em_cmd_t, get_serial_number_valid_serial) {
    std::cout << "Entering get_serial_number_valid_serial test" << std::endl;
    const char* expectedSerial = "ABC123";
    em_cmd_t cmd;
    strncpy(cmd.m_data_model.m_device.m_device_info.serial_number, expectedSerial, sizeof(cmd.m_data_model.m_device.m_device_info.serial_number) - 1);
    cmd.m_data_model.m_device.m_device_info.serial_number[sizeof(cmd.m_data_model.m_device.m_device_info.serial_number) - 1] = '\0';
    std::cout << "Invoking get_serial_number() on em_cmd_t object" << std::endl;
    char* retSerial = cmd.get_serial_number();
    ASSERT_NE(retSerial, nullptr);
    std::cout << "Retrieved serial number string: " << retSerial << std::endl;
    EXPECT_STREQ(retSerial, expectedSerial);
    std::cout << "Exiting get_serial_number_valid_serial test" << std::endl;
}
/**
 * @brief Verify that get_serial_number() returns an empty string when the serial number field is empty
 *
 * This test verifies that when the device serial number in the command object's data model is set to an empty string,
 * the get_serial_number() method correctly returns an empty C-string without returning a null pointer. This ensures proper
 * handling of empty serial fields and appropriate memory safety.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 083
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                           | Test Data                                                                                                 | Expected Result                                                                                   | Notes         |
 * | :--------------: | ----------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- | ------------- |
 * | 01               | Set the device serial number to an empty string in the data model of the command object               | expectedSerial = "", cmd.m_data_model.m_device.m_device_info.serial_number = empty                          | The data model's serial number field is configured as an empty string                               | Should be successful |
 * | 02               | Invoke get_serial_number() and check that the returned pointer is not nullptr                          | API call: retSerial = cmd.get_serial_number()                                                              | The returned pointer (retSerial) should not be nullptr                                             | Should Pass   |
 * | 03               | Verify that the returned serial number string is empty                                               | API call: retSerial = cmd.get_serial_number(), expectedSerial = ""                                           | The returned string should match the empty string as expected                                      | Should Pass   |
 */
TEST(em_cmd_t, get_serial_number_empty_serial) {
    std::cout << "Entering get_serial_number_empty_serial test" << std::endl;
    const char* expectedSerial = "";
    em_cmd_t cmd;
    strncpy(cmd.m_data_model.m_device.m_device_info.serial_number, expectedSerial, sizeof(cmd.m_data_model.m_device.m_device_info.serial_number) - 1); 
    std::cout << "Invoking get_serial_number() on em_cmd_t object" << std::endl;
    char* retSerial = cmd.get_serial_number();
    ASSERT_NE(retSerial, nullptr);
    std::cout << "Retrieved serial number string: '" << retSerial << "'" << std::endl;
    EXPECT_STREQ(retSerial, expectedSerial);
    std::cout << "Exiting get_serial_number_empty_serial test" << std::endl;
}
/**
 * @brief Validate that get_serial_number() returns the correct serial number containing special characters
 *
 * This test verifies that the get_serial_number() method successfully retrieves a serial number containing special characters.
 * The test ensures that the API correctly handles strings with alphanumeric and special characters including escape sequences.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 084@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Print entering test statement to indicate test start | None | "Entering get_serial_number_serial_WithSpecialCharacters test" printed to console | Should be successful |
 * | 02 | Setup test data by copying a serial number with special characters in the command object | input: serial_number = SN@#123!$%\n\t\u00A9, length = strlen(u8"SN@#123!$%\n\t\u00A9")+1 | cmd.m_data_model.m_device.m_device_info.serial_number contains the special character serial | Should Pass |
 * | 03 | Invoke get_serial_number() on the em_cmd_t object | No additional input parameters; internal state contains the special serial number | retSerial is not nullptr | Should Pass |
 * | 04 | Compare the retrieved serial number with the expected value | output: retSerial, expected: SN@#123!$%\n\t\u00A9 | EXPECT_STREQ(retSerial, u8"SN@#123!$%\n\t\u00A9") asserts equality | Should Pass |
 * | 05 | Print exiting test statement to indicate test conclusion | None | "Exiting get_serial_number_serial_WithSpecialCharacters test" printed to console | Should be successful |
 */
TEST(em_cmd_t, get_serial_number_serial_WithSpecialCharacters) {
    std::cout << "Entering get_serial_number_serial_WithSpecialCharacters test" << std::endl;
    em_cmd_t cmd;
    memcpy(cmd.m_data_model.m_device.m_device_info.serial_number, u8"SN@#123!$%\n\t\u00A9", strlen(u8"SN@#123!$%\n\t\u00A9") + 1);  
    std::cout << "Invoking get_serial_number() on em_cmd_t object" << std::endl;
    char* retSerial = cmd.get_serial_number();
    ASSERT_NE(retSerial, nullptr);
    std::cout << "Retrieved serial number string: '" << retSerial << "'" << std::endl;
    EXPECT_STREQ(retSerial, u8"SN@#123!$%\n\t\u00A9");
    std::cout << "Exiting get_serial_number_serial_WithSpecialCharacters test" << std::endl;
}
/**
 * @brief Validate retrieval of primary device type from command object.
 *
 * This test verifies that when the primary device type is set in the em_cmd_t object's data model,
 * the get_primary_device_type() API returns the correct device type string ("DEVICE_TYPE_XYZ"). This ensures
 * that the API correctly accesses and returns data from the object's internal structure.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 085@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                 | Test Data                                                                           | Expected Result                                                           | Notes        |
 * | :--------------: | ------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- | ------------------------------------------------------------------------- | ------------ |
 * | 01               | Set primary device type in the object's data model and invoke get_primary_device_type method. | input: primary_device_type = "DEVICE_TYPE_XYZ", output: retVal = "DEVICE_TYPE_XYZ"   | retVal is not nullptr and matches "DEVICE_TYPE_XYZ"                       | Should Pass  |
 */
TEST(em_cmd_t, get_primary_device_type_valid) {
    std::cout << "Entering get_primary_device_type_valid test" << std::endl;
    em_cmd_t cmd;
	memcpy(cmd.m_data_model.m_device.m_device_info.primary_device_type, "DEVICE_TYPE_XYZ", strlen("DEVICE_TYPE_XYZ") + 1);
    std::cout << "Invoking get_primary_device_type() on cmd object" << std::endl;
    char *retVal = cmd.get_primary_device_type();
    std::cout << "Returned value: " << (retVal ? retVal : "NULL") << std::endl;
    ASSERT_NE(retVal, nullptr);
    EXPECT_STREQ(retVal, "DEVICE_TYPE_XYZ");
    std::cout << "Exiting get_primary_device_type_valid test" << std::endl;
}
/**
 * @brief Verify that get_primary_device_type returns an empty string when primary device type is not set
 *
 * This test verifies that when primary_device_type is set to an empty string in the em_cmd_t object's device info,
 * the get_primary_device_type() method returns a non-null pointer to an empty string. This ensures proper handling 
 * of unset or empty device type values.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 086
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                          | Test Data                                                             | Expected Result                                                      | Notes       |
 * | :--------------: | -------------------------------------------------------------------- | --------------------------------------------------------------------- | -------------------------------------------------------------------- | ----------- |
 * | 01               | Set primary_device_type to empty and invoke get_primary_device_type()  | input: primary_device_type = "", output: retVal                         | retVal must be non-null and equal to an empty string ("")             | Should Pass |
 */
TEST(em_cmd_t, get_primary_device_type_empty) {
    std::cout << "Entering get_primary_device_type_empty test" << std::endl;
    em_cmd_t cmd;
    memcpy(cmd.m_data_model.m_device.m_device_info.primary_device_type, "", strlen("") + 1);
    std::cout << "Invoking get_primary_device_type() on cmd object" << std::endl;
    char *retVal = cmd.get_primary_device_type();
    std::cout << "Returned value: " << (retVal ? retVal : "NULL") << std::endl;
    ASSERT_NE(retVal, nullptr);
    EXPECT_STREQ(retVal, "");
    std::cout << "Exiting get_primary_device_type_empty test" << std::endl;
}
/**
 * @brief Verify that get_primary_device_type returns the correct special characters string
 *
 * This test verifies that when primary_device_type is set with a string containing special characters, the get_primary_device_type function returns the expected non-null pointer with the correct string. The test ensures that the device type value is correctly stored and retrieved.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 087@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                        | Test Data                                                              | Expected Result                                                                | Notes       |
 * | :----:           | ------------------------------------------------------------------ | ---------------------------------------------------------------------- | ------------------------------------------------------------------------------ | ----------- |
 * | 01               | Set primary_device_type to "!@#$%^&*()_+" in the cmd object         | input: primary_device_type = "!@#$%^&*()_+"                             | API returns a non-null pointer matching "!@#$%^&*()_+"                          | Should Pass |
 */
TEST(em_cmd_t, get_primary_device_type_SpecialCharacters) {
    std::cout << "Entering get_primary_device_type_SpecialCharacters test" << std::endl;
    em_cmd_t cmd;
    memcpy(cmd.m_data_model.m_device.m_device_info.primary_device_type, "!@#$%^&*()_+", strlen("!@#$%^&*()_+") + 1);
    std::cout << "Invoking get_primary_device_type() on cmd object" << std::endl;
    char *retVal = cmd.get_primary_device_type();
    std::cout << "Returned value: " << (retVal ? retVal : "NULL") << std::endl;
    ASSERT_NE(retVal, nullptr);
    EXPECT_STREQ(retVal, "!@#$%^&*()_+");
    std::cout << "Exiting get_primary_device_type_SpecialCharacters test" << std::endl;
}
/**
 * @brief Verify that get_num_network_ssid returns 0 when there are no network SSIDs available.
 *
 * This test case verifies that the get_num_network_ssid() method returns 0 when the data model indicates that there are no network SSIDs available. This ensures that the function correctly handles the scenario where no networks are configured.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 088
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                | Test Data                                                    | Expected Result                                                | Notes          |
 * | :--------------: | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------ | -------------------------------------------------------------- | -------------- |
 * | 01               | Set the number of network SSIDs to 0 in the data model of em_cmd_t                         | cmd.m_data_model.m_num_net_ssids = 0                           | The internal count is correctly set to 0                       | Should be successful |
 * | 02               | Invoke get_num_network_ssid() method on the em_cmd_t object                                  | API Invocation: get_num_network_ssid(), no additional inputs   | The function returns 0                                          | Should Pass    |
 * | 03               | Verify the return value using EXPECT_EQ assertion                                            | ssidCount = value returned, expected value = 0u                | EXPECT_EQ(ssidCount, 0u) passes                                 | Should Pass    |
 */
TEST(em_cmd_t, get_num_network_ssid_verify_returns_0_when_no_network_ssids_available) {
    std::cout << "Entering get_num_network_ssid_verify_returns_0_when_no_network_ssids_available test" << std::endl;
    em_cmd_t cmd;
    cmd.m_data_model.m_num_net_ssids = 0;
    std::cout << "Invoking get_num_network_ssid() method." << std::endl;
    unsigned int ssidCount = cmd.get_num_network_ssid();
    std::cout << "get_num_network_ssid() returned: " << ssidCount << std::endl;
    EXPECT_EQ(ssidCount, 0u);
    std::cout << "Exiting get_num_network_ssid_verify_returns_0_when_no_network_ssids_available test" << std::endl;
}
/**
 * @brief Verify that get_num_network_ssid() returns the valid count for configured SSIDs
 *
 * This test validates that the get_num_network_ssid() method correctly returns the number of network SSIDs configured in the em_cmd_t object. The test sets the m_num_net_ssids attribute to a known value (3) and then checks that the method returns this same value, ensuring expected functionality.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 089@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                             | Test Data                                                    | Expected Result                                                      | Notes       |
 * | :--------------: | ------------------------------------------------------- | ------------------------------------------------------------ | -------------------------------------------------------------------- | ----------- |
 * | 01               | Set m_num_net_ssids to 3 and invoke get_num_network_ssid()| cmd.m_data_model.m_num_net_ssids = 3, expected output: ssidCount = 3 | get_num_network_ssid() returns 3 which is confirmed by EXPECT_EQ(3, ssidCount) | Should Pass |
 */
TEST(em_cmd_t, get_num_network_ssid_verify_returns_valid_count_for_configured_ssids) {
    std::cout << "Entering get_num_network_ssid_verify_returns_valid_count_for_configured_ssids test" << std::endl;   
    em_cmd_t cmd;
    cmd.m_data_model.m_num_net_ssids = 3;
    std::cout << "Invoking get_num_network_ssid() method." << std::endl;
    unsigned int ssidCount = cmd.get_num_network_ssid();
    std::cout << "get_num_network_ssid() returned: " << ssidCount << std::endl;   
    EXPECT_EQ(ssidCount, 3u);
    std::cout << "Exiting get_num_network_ssid_verify_returns_valid_count_for_configured_ssids test" << std::endl;
}
/**
 * @brief Test get_num_network_ssid returns maximum SSID count boundary condition.
 *
 * This test verifies that the get_num_network_ssid() method correctly returns the maximum boundary value of the number of network SSIDs when the data model is set to UINT_MAX. The test ensures proper handling of boundary condition input.
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
 * | Variation / Step | Description | Test Data | Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize the command object and set the data model's number of network SSIDs to UINT_MAX. | m_data_model.m_num_net_ssids = UINT_MAX | Data model is initialized with the maximum SSID count. | Should be successful |
 * | 02 | Invoke the get_num_network_ssid() method and verify that it returns the maximum SSID count. | input: m_data_model.m_num_net_ssids = UINT_MAX, output: ssidCount, expected: UINT_MAX | get_num_network_ssid() returns UINT_MAX and EXPECT_EQ check passes. | Should Pass |
 */
TEST(em_cmd_t, get_num_network_ssid_verify_returns_maximum_ssid_count_boundary_condition) {
    std::cout << "Entering get_num_network_ssid_verify_returns_maximum_ssid_count_boundary_condition test" << std::endl;
    em_cmd_t cmd;
	unsigned int maxSSIDCount = UINT_MAX;
	cmd.m_data_model.m_num_net_ssids = maxSSIDCount;
    std::cout << "Invoking get_num_network_ssid() method." << std::endl;
    unsigned int ssidCount = cmd.get_num_network_ssid();
    std::cout << "get_num_network_ssid() returned: " << ssidCount << std::endl;   
    EXPECT_EQ(ssidCount, maxSSIDCount);
    std::cout << "Exiting get_num_network_ssid_verify_returns_maximum_ssid_count_boundary_condition test" << std::endl;
}
/**
 * @brief Validate retrieval of network SSID configuration using a valid index
 *
 * This test case verifies that for a valid index (0), the get_network_ssid API
 * correctly returns a pointer to a network SSID data structure populated with the expected values.
 * The network SSID fields (SSID string, number of bands, enable flag, and number of hauls) are set
 * before invoking the API, and assertions confirm that these fields match the expected test data.
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
 * | Variation / Step | Description                                                                              | Test Data                                                                               | Expected Result                                                                               | Notes         |
 * | :--------------: | ---------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | ------------- |
 * | 01               | Initialize the command object and set the network SSID fields for index 0                  | index = 0, ssid = "TestSSID", num_bands = 2, enable = true, num_hauls = 2                  | Data model is updated with the provided test values                                            | Should be successful |
 * | 02               | Invoke the get_network_ssid API with index 0                                               | input: index = 0                                                                        | API returns a non-null pointer pointing to the network SSID data structure                      | Should Pass   |
 * | 03               | Verify that the retrieved network SSID fields match the expected test values                 | output: ssid = "TestSSID", num_bands = 2, enable = true, num_hauls = 2                      | The returned fields exactly match the test data                                               | Should Pass   |
 */
TEST(em_cmd_t, get_network_ssid_valid_index_0)
{
    std::cout << "Entering get_network_ssid_valid_index_0 test" << std::endl;
    em_cmd_t cmdObj;
    unsigned int index = 0;
    memcpy(cmdObj.m_data_model.m_network_ssid[index].m_network_ssid_info.ssid, "TestSSID", strlen("TestSSID") + 1);
    cmdObj.m_data_model.m_network_ssid[index].m_network_ssid_info.num_bands = 2;
    cmdObj.m_data_model.m_network_ssid[index].m_network_ssid_info.enable = true;
    cmdObj.m_data_model.m_network_ssid[index].m_network_ssid_info.num_hauls = 2;
    std::cout << "Invoking get_network_ssid with index = " << index << std::endl;
    dm_network_ssid_t *ssidPtr = cmdObj.get_network_ssid(index);
    ASSERT_NE(ssidPtr, nullptr);
    std::cout << "get_network_ssid() returned values:" << std::endl;
    std::cout << "ssidPtr->m_network_ssid_info.ssid = " << ssidPtr->m_network_ssid_info.ssid << std::endl;
    std::cout << "ssidPtr->m_network_ssid_info.num_bands = " << ssidPtr->m_network_ssid_info.num_bands << std::endl;
    std::cout << "ssidPtr->m_network_ssid_info.enable = " << ssidPtr->m_network_ssid_info.enable << std::endl;
    std::cout << "ssidPtr->m_network_ssid_info.num_hauls = " << ssidPtr->m_network_ssid_info.num_hauls << std::endl;
    EXPECT_STREQ(ssidPtr->m_network_ssid_info.ssid, "TestSSID");
    EXPECT_EQ(ssidPtr->m_network_ssid_info.num_bands, 2);
    EXPECT_EQ(ssidPtr->m_network_ssid_info.enable, true);
    EXPECT_EQ(ssidPtr->m_network_ssid_info.num_hauls, 2);
    std::cout << "Exiting get_network_ssid_valid_index_0 test" << std::endl;
}
/**
 * @brief Verify that get_network_ssid returns the correct SSID details for a valid index.
 *
 * This test initializes an em_cmd_t object with predefined SSID information at index 2,
 * then calls the get_network_ssid API to retrieve the SSID details. The test verifies
 * that the returned pointer is non-null and that the SSID details (SSID string, number of bands,
 * enable flag, and number of hauls) match the initialized values.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 092@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                 | Test Data                                                                                   | Expected Result                                                | Notes         |
 * | :--------------: | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | -------------------------------------------------------------- | ------------- |
 * | 01               | Initialize the em_cmd_t object with test SSID information at index 2        | index = 2, ssid = "TestSSID1", num_bands = 2, enable = true, num_hauls = 2                   | Object initialized with the specified SSID details             | Should be successful |
 * | 02               | Invoke get_network_ssid API with the given index and capture the returned pointer | input: index = 2, output: pointer = ssidPtr                                                   | Returned pointer is not nullptr                                 | Should Pass   |
 * | 03               | Validate that the returned SSID details match the initialized test values     | output: ssid = "TestSSID1", num_bands = 2, enable = true, num_hauls = 2                        | Returned SSID details are exactly as set during initialization   | Should Pass   |
 */
TEST(em_cmd_t, get_network_ssid_valid_index_2)
{
    std::cout << "Entering get_network_ssid_valid_index_2 test" << std::endl;
    em_cmd_t cmdObj;
    unsigned int index = 2;
	memcpy(cmdObj.m_data_model.m_network_ssid[index].m_network_ssid_info.ssid, "TestSSID1", strlen("TestSSID1") + 1);
    cmdObj.m_data_model.m_network_ssid[index].m_network_ssid_info.num_bands = 2;
    cmdObj.m_data_model.m_network_ssid[index].m_network_ssid_info.enable = true;
    cmdObj.m_data_model.m_network_ssid[index].m_network_ssid_info.num_hauls = 2;
    std::cout << "Invoking get_network_ssid with index = " << index << std::endl;
    dm_network_ssid_t *ssidPtr = cmdObj.get_network_ssid(index);
    std::cout << "Method get_network_ssid returned pointer = " << ssidPtr << std::endl;
    ASSERT_NE(ssidPtr, nullptr);
	std::cout << "get_network_ssid() returned values:" << std::endl;
	std::cout << "ssidPtr->m_network_ssid_info.ssid = " << ssidPtr->m_network_ssid_info.ssid << std::endl;
	std::cout << "ssidPtr->m_network_ssid_info.num_bands = " << ssidPtr->m_network_ssid_info.num_bands << std::endl;
	std::cout << "ssidPtr->m_network_ssid_info.enable = " << ssidPtr->m_network_ssid_info.enable << std::endl;
	std::cout << "ssidPtr->m_network_ssid_info.num_hauls = " << ssidPtr->m_network_ssid_info.num_hauls << std::endl;
    EXPECT_STREQ(ssidPtr->m_network_ssid_info.ssid, "TestSSID1");
	EXPECT_EQ(ssidPtr->m_network_ssid_info.num_bands, 2);
	EXPECT_EQ(ssidPtr->m_network_ssid_info.enable, true);
	EXPECT_EQ(ssidPtr->m_network_ssid_info.num_hauls, 2);
    std::cout << "Exiting get_network_ssid_valid_index_2 test" << std::endl;
}
/**
 * @brief Validate get_network_ssid function behavior at boundary index.
 *
 * This test verifies that the get_network_ssid function returns a valid pointer with the correctly assigned network SSID details when accessed at the boundary index. It ensures that all the SSID fields (ssid, num_bands, enable, num_hauls) are properly initialized and retrieved.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 093
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize network SSID at boundary index with test values | boundaryIndex = 4, ssid = "TestSSID2", num_bands = 2, enable = true, num_hauls = 2 | Network SSID model is updated with the provided values | Should be successful |
 * | 02 | Call get_network_ssid with the set boundary index | boundaryIndex = 4 | API returns a non-null pointer to the network SSID structure | Should Pass |
 * | 03 | Verify the returned network SSID fields | Returned structure: ssid = "TestSSID2", num_bands = 2, enable = true, num_hauls = 2 | All the retrieved values match the initialized test data | Should Pass |
 */
TEST(em_cmd_t, get_network_ssid_index_at_boundary)
{
    std::cout << "Entering get_network_ssid_index_beyond_boundary test" << std::endl;
    em_cmd_t cmdObj;
    unsigned int boundaryIndex = 4;
    memcpy(cmdObj.m_data_model.m_network_ssid[boundaryIndex].m_network_ssid_info.ssid, "TestSSID2", strlen("TestSSID2") + 1);
    cmdObj.m_data_model.m_network_ssid[boundaryIndex].m_network_ssid_info.num_bands = 2;
    cmdObj.m_data_model.m_network_ssid[boundaryIndex].m_network_ssid_info.enable = true;
    cmdObj.m_data_model.m_network_ssid[boundaryIndex].m_network_ssid_info.num_hauls = 2;
    std::cout << "Invoking get_network_ssid with index = " << boundaryIndex << std::endl;
    dm_network_ssid_t *ssidPtr = cmdObj.get_network_ssid(boundaryIndex);
    ASSERT_NE(ssidPtr, nullptr);
    std::cout << "get_network_ssid() returned values:" << std::endl;
    std::cout << "ssidPtr->m_network_ssid_info.ssid = " << ssidPtr->m_network_ssid_info.ssid << std::endl;
    std::cout << "ssidPtr->m_network_ssid_info.num_bands = " << ssidPtr->m_network_ssid_info.num_bands << std::endl;
    std::cout << "ssidPtr->m_network_ssid_info.enable = " << ssidPtr->m_network_ssid_info.enable << std::endl;
    std::cout << "ssidPtr->m_network_ssid_info.num_hauls = " << ssidPtr->m_network_ssid_info.num_hauls << std::endl;
    EXPECT_STREQ(ssidPtr->m_network_ssid_info.ssid, "TestSSID2");
    EXPECT_EQ(ssidPtr->m_network_ssid_info.num_bands, 2);
    EXPECT_EQ(ssidPtr->m_network_ssid_info.enable, true);
    EXPECT_EQ(ssidPtr->m_network_ssid_info.num_hauls, 2);
    std::cout << "Exiting get_network_ssid_index_at_boundary test" << std::endl;
}
/**
 * @brief Validate get_network_ssid API behavior when index equals UINT_MAX
 *
 * This test verifies that the get_network_ssid() API returns a null pointer when invoked with an index value of UINT_MAX, ensuring that the API gracefully handles out-of-bound index values.
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
 * | Variation / Step | Description                                                              | Test Data                                      | Expected Result                                                                      | Notes        |
 * | :--------------: | ------------------------------------------------------------------------ | ---------------------------------------------- | ------------------------------------------------------------------------------------ | ------------ |
 * | 01               | Invoke get_network_ssid() with index set to UINT_MAX                     | input: index = UINT_MAX, output: ssidPtr = nullptr | API returns nullptr and the EXPECT_EQ assertion verifies that ssidPtr is nullptr      | Should Pass  |
 */
TEST(em_cmd_t, get_network_ssid_index_uint_max)
{
    std::cout << "Entering get_network_ssid_index_uint_max test" << std::endl;
    em_cmd_t cmdObj;
    unsigned int index = UINT_MAX;
    std::cout << "Invoking get_network_ssid with index = " << index << std::endl;
    dm_network_ssid_t *ssidPtr = cmdObj.get_network_ssid(index);
    EXPECT_EQ(ssidPtr, nullptr);
    std::cout << "Exiting get_network_ssid_index_uint_max test" << std::endl;
}
/**
 * @brief Validate that get_radio returns a valid pointer when provided with a valid index.
 *
 * This test sets specific radio properties for a valid index in the data model and then calls get_radio.
 * It verifies that the returned pointer is not null and that the retrieved radio properties match the expected values.
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
 * | 01 | Set radio properties for valid index in the data model | index = 1, radio.enabled = true, radio.number_of_bss = 2, radio.number_of_unassoc_sta = 1, radio.noise = 4 | Radio properties in index 1 are correctly set | Should be successful |
 * | 02 | Invoke get_radio API with valid index | input: index = 1 | Returned radio pointer is not nullptr | Should Pass |
 * | 03 | Verify the retrieved radio pointer's properties | output: radio->m_radio_info.enabled, radio->m_radio_info.number_of_bss, radio->m_radio_info.number_of_unassoc_sta, radio->m_radio_info.noise | Values are true, 2, 1, 4 respectively | Should Pass |
 */
TEST(em_cmd_t, get_radio_valid_index_returns_valid_radio_pointer)
{
    std::cout << "Entering get_radio_valid_index_returns_valid_radio_pointer test" << std::endl;
    em_cmd_t cmd;
	unsigned int index = 1;
	cmd.m_data_model.m_radio[index].m_radio_info.enabled = true;
	cmd.m_data_model.m_radio[index].m_radio_info.number_of_bss = 2;
	cmd.m_data_model.m_radio[index].m_radio_info.number_of_unassoc_sta = 1;
	cmd.m_data_model.m_radio[index].m_radio_info.noise = 4;
    std::cout << "Invoking get_radio with index 1" << std::endl;
    dm_radio_t* radio = cmd.get_radio(index);
    ASSERT_NE(radio, nullptr);   
    if (radio != nullptr) {
        std::cout << "Retrieved radio info from get_radio(1):" << std::endl;
        std::cout << "  Enabled: " << radio->m_radio_info.enabled << std::endl;
        std::cout << "  Number of BSS: " << radio->m_radio_info.number_of_bss << std::endl;
        std::cout << "  Number of unassoc STA: " << radio->m_radio_info.number_of_unassoc_sta << std::endl;
        std::cout << "  Noise: " << radio->m_radio_info.noise << std::endl;
		EXPECT_TRUE(radio->m_radio_info.enabled);
		EXPECT_EQ(radio->m_radio_info.number_of_bss, 2);
		EXPECT_EQ(radio->m_radio_info.number_of_unassoc_sta, 1);
		EXPECT_EQ(radio->m_radio_info.noise, 4);
    }
    std::cout << "Exiting get_radio_valid_index_returns_valid_radio_pointer test" << std::endl;
}
/**
 * @brief Test to verify that get_radio returns a valid radio pointer for index 0.
 *
 * This test initializes the radio data at index 0 with specific parameters and then invokes the get_radio API.
 * It ensures that the returned pointer is valid and that the radio information matches the preconfigured values.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 096@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize radio data at index 0 with enabled=true, number_of_bss=2, number_of_unassoc_sta=1, noise=4 | index = 0, radio.enabled = true, radio.number_of_bss = 2, radio.number_of_unassoc_sta = 1, radio.noise = 4 | Radio data is set as expected in the command object | Should be successful |
 * | 02 | Invoke get_radio API with index 0 to retrieve the radio pointer | index = 0 | API returns a non-null pointer to the radio structure | Should Pass |
 * | 03 | Validate that the retrieved radio information matches the initialized data | retrieved radio: enabled=true, number_of_bss=2, number_of_unassoc_sta=1, noise=4 | Retrieved radio info fields match the expected values | Should Pass |
 */
TEST(em_cmd_t, get_radio_edge_index_zero_returns_valid_radio_pointer)
{
    std::cout << "Entering get_radio_edge_index_zero_returns_valid_radio_pointer test" << std::endl;
    em_cmd_t cmd;
    unsigned int index = 0;
    cmd.m_data_model.m_radio[index].m_radio_info.enabled = true;
    cmd.m_data_model.m_radio[index].m_radio_info.number_of_bss = 2;
    cmd.m_data_model.m_radio[index].m_radio_info.number_of_unassoc_sta =1;
    cmd.m_data_model.m_radio[index].m_radio_info.noise = 4;
    std::cout << "Invoking get_radio with index 0" << std::endl;
    dm_radio_t* radio = cmd.get_radio(index);
    ASSERT_NE(radio, nullptr);
    if (radio != nullptr) {
        std::cout << "Retrieved radio info from get_radio(0):" << std::endl;
        std::cout << "  Enabled: " << radio->m_radio_info.enabled << std::endl;
        std::cout << "  Number of BSS: " << radio->m_radio_info.number_of_bss << std::endl;
        std::cout << "  Number of unassoc STA: " << radio->m_radio_info.number_of_unassoc_sta << std::endl;
        std::cout << "  Noise: " << radio->m_radio_info.noise << std::endl;
        EXPECT_TRUE(radio->m_radio_info.enabled);
        EXPECT_EQ(radio->m_radio_info.number_of_bss, 2);
        EXPECT_EQ(radio->m_radio_info.number_of_unassoc_sta, 1);
        EXPECT_EQ(radio->m_radio_info.noise, 4);
    }    
    std::cout << "Exiting get_radio_edge_index_zero_returns_valid_radio_pointer test" << std::endl;
}
/**
 * @brief Test get_radio returns nullptr for an out-of-range index
 *
 * This test verifies that the get_radio API correctly handles an out-of-range index by returning a nullptr. It ensures that the API avoids accessing invalid memory and behaves as expected when provided with an invalid index.
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
 * | 01 | Set radio info at an out-of-range index | outOfRangeIndex = 100, m_radio[outOfRangeIndex].enabled = true, number_of_bss = 2, number_of_unassoc_sta = 1, noise = 4 | Radio info is set at the specified index (although out-of-range) | Should be successful |
 * | 02 | Call get_radio with the out-of-range index | input: index = 100 | get_radio returns nullptr as the index is invalid | Should Pass |
 * | 03 | Validate the returned pointer with an assertion | output: radio pointer = nullptr, ASSERT_EQ(radio, nullptr) | The returned pointer must be nullptr | Should Pass |
 */
TEST(em_cmd_t, get_radio_out_of_range_index_returns_nullptr)
{
    std::cout << "Entering get_radio_out_of_range_index_returns_nullptr test" << std::endl;
    em_cmd_t cmd;        
    unsigned int outOfRangeIndex = 100;
    cmd.m_data_model.m_radio[outOfRangeIndex].m_radio_info.enabled = true;
    cmd.m_data_model.m_radio[outOfRangeIndex].m_radio_info.number_of_bss = 2;
    cmd.m_data_model.m_radio[outOfRangeIndex].m_radio_info.number_of_unassoc_sta = 1;
    cmd.m_data_model.m_radio[outOfRangeIndex].m_radio_info.noise = 4;
    std::cout << "Invoking get_radio with out-of-range index " << outOfRangeIndex << std::endl;
    dm_radio_t* radio = cmd.get_radio(outOfRangeIndex);
    std::cout << "Returned pointer from get_radio(" << outOfRangeIndex << "): " << radio << std::endl;    
    EXPECT_EQ(radio, nullptr);    
    std::cout << "Exiting get_radio_out_of_range_index_returns_nullptr test" << std::endl;
}
/**
 * @brief Verify that get_radio_data returns a valid pointer for a radio matching the interface name
 *
 * This test verifies that the get_radio_data API correctly finds and returns a pointer to a radio entry
 * when the provided interface's name matches one of the entries in the wifi data model. It ensures that the
 * API handles valid input as expected and returns a non-null pointer.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 098@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                           | Test Data                                                                                                                                                                                                     | Expected Result                               | Notes       |
 * | :--------------: | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------- | ----------- |
 * | 01               | Invoke get_radio_data with a valid interface matching an allocated radio entry | cmd.m_data_model.m_wifi_data allocated with num_radios=1, radios[0].name="Interface1"; iface.name="Interface1", iface.mac=AA,BB,CC,DD,EE,1A, iface.media=em_media_type_ieee80211n_5 | Returned pointer should be non-null (radio pointer != nullptr) | Should Pass |
 */
TEST(em_cmd_t, get_radio_data_valid_match)
{
    std::cout << "Entering get_radio_data_valid_match test" << std::endl;
    em_cmd_t cmd{};
    cmd.m_data_model.m_wifi_data = static_cast<webconfig_subdoc_data_t*>(calloc(1, sizeof(webconfig_subdoc_data_t)));
    ASSERT_NE(cmd.m_data_model.m_wifi_data, nullptr);
    cmd.m_data_model.m_wifi_data->u.decoded.num_radios = 1;
    strncpy(cmd.m_data_model.m_wifi_data->u.decoded.radios[0].name,
            "Interface1", sizeof(cmd.m_data_model.m_wifi_data->u.decoded.radios[0].name) - 1);
    em_interface_t iface{};	
    strncpy(iface.name, "Interface1", sizeof(iface.name) - 1);
    uint8_t sample_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x1A};
    memcpy(iface.mac, sample_mac, sizeof(sample_mac));
    iface.media = em_media_type_ieee80211n_5;
    std::cout << "Invoking get_radio_data with matching interface name" << std::endl;
    rdk_wifi_radio_t *radio = cmd.m_data_model.get_radio_data(&iface);
    EXPECT_NE(radio, nullptr);
    std::cout << "Returned radio pointer: " << radio << std::endl;
    free(cmd.m_data_model.m_wifi_data);
    std::cout << "Exiting get_radio_data_valid_match test" << std::endl;
}
/**
 * @brief Verify that get_radio_data handles a null interface without causing a crash
 *
 * This test verifies that when a null interface pointer is passed to get_radio_data, the function returns nullptr as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 099@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize em_cmd_t object, allocate memory for wifi data, and invoke get_radio_data with a null interface pointer | input: interface = nullptr, m_wifi_data allocated = calloc(1, sizeof(webconfig_subdoc_data_t)); output: get_radio_data return value expected = nullptr | get_radio_data returns nullptr, and EXPECT_EQ verifies the returned value is nullptr | Should Pass |
 */
TEST(em_cmd_t, get_radio_data_null_interface_crashes)
{
    std::cout << "Entering get_radio_data_null_interface_crashes test" << std::endl;
    em_cmd_t cmd{};
    cmd.m_data_model.m_wifi_data = static_cast<webconfig_subdoc_data_t*>(calloc(1, sizeof(webconfig_subdoc_data_t)));
    rdk_wifi_radio_t *ptr = cmd.m_data_model.get_radio_data(nullptr);
	EXPECT_EQ(ptr, nullptr);
    free(cmd.m_data_model.m_wifi_data);
    std::cout << "Exiting get_radio_data_null_interface_crashes test" << std::endl;
}
/**
 * @brief Verify that get_radio_data returns NULL when there are no radios
 *
 * This test verifies that the get_radio_data API returns a null pointer when the
 * number of radios in the wifi data structure is set to zero. It ensures that the
 * API correctly handles the scenario where no radio configuration is available.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 100@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:** 
 * | Variation / Step | Description                                                                 | Test Data                                                                                                                           | Expected Result                                     | Notes           |
 * | :--------------: | --------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- | --------------- |
 * | 01               | Initialize command object and allocate wifi_data structure                  | cmd.m_data_model.m_wifi_data = calloc(1, sizeof(webconfig_subdoc_data_t))                                                             | Memory allocation successful (not nullptr)          | Should be successful |
 * | 02               | Set num_radios field to 0 in the wifi_data structure                        | cmd.m_data_model.m_wifi_data->u.decoded.num_radios = 0                                                                               | num_radios is set to 0                               | Should be successful |
 * | 03               | Initialize interface with valid name, MAC and media type                    | iface.name = "Interface1", iface.mac = {0xAA,0xBB,0xCC,0xDD,0xEE,0x1A}, iface.media = em_media_type_ieee80211n_5                    | Interface is properly initialized                  | Should be successful |
 * | 04               | Call get_radio_data API with the initialized interface                      | Input: iface, Output: radio pointer                                                                                                  | Returns nullptr                                    | Should Pass     |
 * | 05               | Free the allocated wifi_data memory                                         | free(cmd.m_data_model.m_wifi_data)                                                                                                   | Memory is successfully freed                       | Should be successful |
 */
TEST(em_cmd_t, get_radio_data_no_radios_returns_null)
{
    std::cout << "Entering get_radio_data_no_radios_returns_null test" << std::endl;
    em_cmd_t cmd{};
    cmd.m_data_model.m_wifi_data = static_cast<webconfig_subdoc_data_t*>(calloc(1, sizeof(webconfig_subdoc_data_t)));
    ASSERT_NE(cmd.m_data_model.m_wifi_data, nullptr);
    cmd.m_data_model.m_wifi_data->u.decoded.num_radios = 0;
    em_interface_t iface{};
    strncpy(iface.name, "Interface1", sizeof(iface.name) - 1);
    uint8_t sample_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x1A};
    memcpy(iface.mac, sample_mac, sizeof(sample_mac));
    iface.media = em_media_type_ieee80211n_5;
    rdk_wifi_radio_t *radio = cmd.m_data_model.get_radio_data(&iface);
    EXPECT_EQ(radio, nullptr);
    free(cmd.m_data_model.m_wifi_data);
    std::cout << "Exiting get_radio_data_no_radios_returns_null test" << std::endl;
}
/**
 * @brief Verify that get_rd_op_class() returns the correct positive value
 *
 * This test verifies that after setting the m_rd_op_class member of the em_cmd_t object to a positive value (5),
 * the get_rd_op_class() method returns the expected value. This ensures that the read operation class is properly
 * stored and retrieved, validating the functionality of the setter and getter mechanism for this attribute.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 101@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                    | Test Data                                               | Expected Result                                                      | Notes           |
 * | :--------------: | ------------------------------------------------------------------------------ | ------------------------------------------------------- | -------------------------------------------------------------------- | --------------- |
 * | 01               | Instantiate a default constructed em_cmd_t object                              | No input; output: em_cmd_t object created               | Object is constructed successfully                                   | Should be successful |
 * | 02               | Set the m_rd_op_class member to 5                                              | Input: m_rd_op_class = 5                                  | m_rd_op_class is updated to 5                                         | Should be successful |
 * | 03               | Invoke get_rd_op_class() and store the returned value                          | Input: Call get_rd_op_class() on object with m_rd_op_class = 5; Output: returned value | Returned value is 5 and matches the expected value using EXPECT_EQ    | Should Pass     |
 */
TEST(em_cmd_t, get_rd_op_class_set_positive_value)
{
    std::cout << "Entering get_rd_op_class_set_positive_value test" << std::endl;
    EXPECT_NO_THROW({
        em_cmd_t obj;
        std::cout << "Default constructed em_cmd_t object created." << std::endl;
        obj.m_rd_op_class = 5;
        std::cout << "Invoking get_rd_op_class() after setting value to 5." << std::endl;
        unsigned int rdOpClass = obj.get_rd_op_class();
        std::cout << "Returned read op class value: " << rdOpClass << std::endl;
        EXPECT_EQ(rdOpClass, 5u);
    });   
    std::cout << "Exiting get_rd_op_class_set_positive_value test" << std::endl;
}
/**
 * @brief Validate that get_rd_op_class returns UINT_MAX when m_rd_op_class is set to its boundary value.
 *
 * This test verifies that when the m_rd_op_class member is assigned the maximum unsigned integer value (UINT_MAX),
 * the get_rd_op_class function correctly returns this boundary value. The test also ensures that no exceptions are thrown
 * during the execution of these operations.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 102@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Default construct em_cmd_t object | No input parameters | Object is created without exceptions | Should be successful |
 * | 02 | Set m_rd_op_class to UINT_MAX | m_rd_op_class = UINT_MAX | m_rd_op_class member updated to UINT_MAX | Should be successful |
 * | 03 | Invoke get_rd_op_class and verify the returned value | Call get_rd_op_class(), expected output: UINT_MAX | get_rd_op_class returns UINT_MAX and assertion passes | Should Pass |
 */
TEST(em_cmd_t, get_rd_op_class_set_boundary_value)
{
    std::cout << "Entering get_rd_op_class_set_boundary_value test" << std::endl;
    EXPECT_NO_THROW({
        em_cmd_t obj;
        std::cout << "Default constructed em_cmd_t object created." << std::endl;
        obj.m_rd_op_class = UINT_MAX;
        std::cout << "Invoking get_rd_op_class() after setting value to UINT_MAX." << std::endl;
        unsigned int rdOpClass = obj.get_rd_op_class();
        std::cout << "Returned read op class value: " << rdOpClass << std::endl;
        EXPECT_EQ(rdOpClass, UINT_MAX);
    });    
    std::cout << "Exiting get_rd_op_class_set_boundary_value test" << std::endl;
}
/**
 * @brief Test that get_rd_channel() returns the explicitly set value
 *
 * This test verifies that when the m_rd_channel field of the em_cmd_t object is explicitly set to 42, the get_rd_channel() function correctly returns the value 42. This ensures that the API properly retrieves the read channel value as set.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 103@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                         | Test Data                                    | Expected Result                                             | Notes      |
 * | :--------------: | ------------------------------------------------------------------- | -------------------------------------------- | ----------------------------------------------------------- | ---------- |
 * | 01               | Set m_rd_channel to 42 and call get_rd_channel() to verify the result | cmd.m_rd_channel = 42, expected output = 42  | get_rd_channel() returns 42 (unsigned int value 42)         | Should Pass |
 */
TEST(em_cmd_t, get_rd_channel_explicit_set_value_42)
{
    std::cout << "Entering get_rd_channel_explicit_set_value_42 test" << std::endl;
    em_cmd_t cmd;
    cmd.m_rd_channel = 42;
    std::cout << "Invoking get_rd_channel()" << std::endl;
    unsigned int rd_channel = cmd.get_rd_channel();
    std::cout << "Retrieved read channel value: " << rd_channel << std::endl;   
    EXPECT_EQ(rd_channel, 42u);  
    std::cout << "Exiting get_rd_channel_explicit_set_value_42 test" << std::endl;
}
/**
 * @brief Verify that get_rd_channel returns UINT_MAX when rd_channel is set to its maximum
 *
 * This test sets the m_rd_channel field of an em_cmd_t instance to UINT_MAX, then calls get_rd_channel()
 * to ensure the function correctly returns the maximum unsigned integer value. The objective is to verify
 * proper behavior when handling extreme upper bounds for unsigned int.
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
 * | Variation / Step | Description                                                                          | Test Data                                          | Expected Result                                              | Notes      |
 * | :--------------: | ------------------------------------------------------------------------------------ | -------------------------------------------------- | ------------------------------------------------------------ | ---------- |
 * | 01               | Initialize em_cmd_t, set m_rd_channel to UINT_MAX, call get_rd_channel(), verify value   | m_rd_channel = UINT_MAX, rd_channel expected = UINT_MAX | get_rd_channel() returns UINT_MAX; EXPECT_EQ assertion passes  | Should Pass |
 */
TEST(em_cmd_t, get_rd_channel_max_unsigned_int_value)
{
    std::cout << "Entering get_rd_channel_max_unsigned_int_value test" << std::endl;
    em_cmd_t cmd;
    cmd.m_rd_channel = UINT_MAX;
    std::cout << "Invoking get_rd_channel()" << std::endl;
    unsigned int rd_channel = cmd.get_rd_channel();
    std::cout << "Retrieved read channel value: " << rd_channel << std::endl;    
    EXPECT_EQ(rd_channel, UINT_MAX);    
    std::cout << "Exiting get_rd_channel_max_unsigned_int_value test" << std::endl;
}
/**
 * @brief Verify that calling set_start_time() correctly updates the object's start timestamp.
 *
 * This test case validates that the set_start_time() method of the em_cmd_t class updates the internal m_start_time member variable to a value that falls between the system time captured immediately before and after the method invocation. The test ensures that no exceptions are thrown during the operation and that the recorded timestamp is within an acceptable range (with a tolerance of 1 second).
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 105@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                     | Test Data                                                                                               | Expected Result                                                                                          | Notes            |
 * | :--------------: | -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- | ---------------- |
 * | 01               | Capture the system time before invoking set_start_time()                        | system_time_before: captured current system time                                                        | system_time_before is successfully captured with current system time                                     | Should be successful |
 * | 02               | Invoke the set_start_time() method on the cmd_obj instance                        | cmd_obj instance, API: set_start_time()                                                                  | Method executes without throwing any exception                                                           | Should Pass      |
 * | 03               | Capture the system time after calling set_start_time()                           | system_time_after: captured current system time                                                          | system_time_after is successfully captured with current system time                                      | Should be successful |
 * | 04               | Retrieve m_start_time from cmd_obj and verify it falls within the captured range   | obj_time = cmd_obj.m_start_time, system_time_before, system_time_after (with tolerance of +1 second)       | m_start_time is set such that system_time_before <= m_start_time <= system_time_after + 1 (tolerance)      | Should Pass      |
 */
TEST(em_cmd_t, set_start_time_VerifyTimestampUpdated)
{
    std::cout << "Entering set_start_time_VerifyTimestampUpdated test" << std::endl;
    em_cmd_t cmd_obj;    
    // Capture system time before invoking set_start_time()
    struct timeval system_time_before {0, 0};
    gettimeofday(&system_time_before, nullptr);
    std::cout << "Before invocation, system time (tv_sec): " << system_time_before.tv_sec << ", (tv_usec): " << system_time_before.tv_usec << std::endl;
    std::cout << "Invoking set_start_time()" << std::endl;
    EXPECT_NO_THROW(cmd_obj.set_start_time());    
    // Capture system time after the call
    struct timeval system_time_after {0, 0};
    gettimeofday(&system_time_after, nullptr);
    std::cout << "After invocation, system time (tv_sec): " << system_time_after.tv_sec << ", (tv_usec): " << system_time_after.tv_usec << std::endl;    
    // Retrieve the object's m_start_time
    struct timeval obj_time = cmd_obj.m_start_time;
    std::cout << "Command object start time (tv_sec): " << obj_time.tv_sec << ", (tv_usec): " << obj_time.tv_usec << std::endl;   
    // Check that the object's start time is within the system times captured 
    // Allow a tolerance of 1 second
    bool time_within_range = false;
    if ((obj_time.tv_sec >= system_time_before.tv_sec) && (obj_time.tv_sec <= system_time_after.tv_sec + 1)) {
        time_within_range = true;
    }
    EXPECT_TRUE(time_within_range);
    std::cout << "Exiting set_start_time_VerifyTimestampUpdated test" << std::endl;
}
/**
 * @brief Validate that set_start_time correctly updates the start time when initially set to zero.
 *
 * This test verifies that the m_start_time member of the em_cmd_t object is not left at its
 * default zero value after the set_start_time method is invoked. It sets m_start_time to zero,
 * calls set_start_time, and then asserts that the updated time is non-zero to ensure the method
 * performs the intended initialization.
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
 * | Variation / Step | Description                                                            | Test Data                                           | Expected Result                                                       | Notes         |
 * | :--------------: | ---------------------------------------------------------------------- | --------------------------------------------------- | --------------------------------------------------------------------- | ------------- |
 * |       01       | Create an object using the default constructor and initialize m_start_time to zero using memset | m_start_time (tv_sec = 0, tv_usec = 0)             | m_start_time is set to zero before invoking set_start_time()            | Should be successful |
 * |       02       | Invoke set_start_time on the object to update m_start_time               | Object state prior to invocation                    | Method executes without throwing an exception                         | Should Pass   |
 * |       03       | Retrieve m_start_time and verify it is not left at the default zero       | Output: m_start_time updated by set_start_time()      | Assertion (EXPECT_TRUE) confirms m_start_time is non-zero               | Should Pass   |
 */
TEST(em_cmd_t, set_start_time_NotLeftAtDefaultZero)
{
    std::cout << "Entering set_start_time_NotLeftAtDefaultZero test" << std::endl;    
    // Create an object using default constructor
    em_cmd_t cmd_obj;    
    // Set m_start_time to a known default zero value
    memset(&cmd_obj.m_start_time, 0, sizeof(cmd_obj.m_start_time));
    std::cout << "Initialized m_start_time to zero (tv_sec: " << cmd_obj.m_start_time.tv_sec 
              << ", tv_usec: " << cmd_obj.m_start_time.tv_usec << ")" << std::endl;    
    // Invoke the method
    std::cout << "Invoking set_start_time()" << std::endl;
    EXPECT_NO_THROW(cmd_obj.set_start_time());    
    // Retrieve the object's m_start_time after invocation
    struct timeval obj_time = cmd_obj.m_start_time;
    std::cout << "After invocation, m_start_time (tv_sec): " << obj_time.tv_sec 
              << ", (tv_usec): " << obj_time.tv_usec << std::endl;    
    // Check that m_start_time is not left at zero value
    bool not_zero = ( (obj_time.tv_sec != 0) || (obj_time.tv_usec != 0) );
    EXPECT_TRUE(not_zero);    
    std::cout << "Exiting set_start_time_NotLeftAtDefaultZero test" << std::endl;
}
/**
 * @brief Validate that reset() method correctly resets non-zero event and command parameters
 *
 * This test ensures that the reset() method of the em_cmd_t object correctly zeros out the memory areas of both 
 * the event (m_evt) and command parameters (m_param) that have been prefilled with non-zero values. It verifies that 
 * after invoking reset(), these areas are cleared to all zeros, ensuring correct reset functionality.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 107
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Free constructor allocated memory for m_evt if not null | cmd.m_evt != nullptr | m_evt is freed and set to nullptr | Should be successful |
 * | 02 | Allocate new memory for m_evt | cmd.m_evt = new em_event_t | Memory allocated successfully | Should be successful |
 * | 03 | Fill m_evt memory with non-zero values using memset | memset(cmd.m_evt, 0xFF, sizeof(em_event_t)) | m_evt memory filled with non-zero bytes | Should be successful |
 * | 04 | Fill m_param structure with non-zero data using memset | memset(&cmd.m_param, 0xFF, sizeof(em_cmd_params_t)) | m_param structure filled with non-zero data | Should be successful |
 * | 05 | Invoke reset() method to clear non-zero values | cmd.reset() invocation | reset() does not throw and initiates reset of m_evt and m_param | Should Pass |
 * | 06 | Verify m_evt is reset to zero using memcmp | memcmp(cmd.m_evt, zeroBufferEvt, sizeof(em_event_t)) | memcmp returns 0 indicating m_evt is zeroed | Should Pass |
 * | 07 | Verify m_param is reset to zero using memcmp | memcmp(&cmd.m_param, zeroBufferParam, sizeof(em_cmd_params_t)) | memcmp returns 0 indicating m_param is zeroed | Should Pass |
 * | 08 | Cleanup allocated memory for m_evt | delete cmd.m_evt | Memory freed and cmd.m_evt set to nullptr | Should be successful |
 */
TEST(em_cmd_t, reset_non_zero_event_and_command_params)
{
    std::cout << "Entering reset_non_zero_event_and_command_params test" << std::endl;
    em_cmd_t cmd{};

    // Free constructor allocated memory before overwriting
    if (cmd.m_evt) {
        free(cmd.m_evt);
        cmd.m_evt = nullptr;
        std::cout << "Freed constructor allocated memory for m_evt" << std::endl;
    }

    // Replace with new allocation for test logic
    cmd.m_evt = new em_event_t;
    std::cout << "Allocated memory for m_evt" << std::endl;

    memset(cmd.m_evt, 0xFF, sizeof(em_event_t));
    std::cout << "Filled m_evt memory with non-zero bytes" << std::endl;

    memset(&cmd.m_param, 0xFF, sizeof(em_cmd_params_t));
    std::cout << "Filled m_param structure with non-zero data" << std::endl;

    std::cout << "Before reset: m_evt first byte = "
              << std::hex << static_cast<int>(reinterpret_cast<unsigned char*>(cmd.m_evt)[0]) 
              << std::dec << std::endl;

    std::cout << "Before reset: m_param first byte = "
              << std::hex << static_cast<int>(*(reinterpret_cast<unsigned char*>(&cmd.m_param)))
              << std::dec << std::endl;

    // Test reset
    std::cout << "Invoking reset() method" << std::endl;
    EXPECT_NO_THROW(cmd.reset());
    std::cout << "reset() method invoked" << std::endl;

    unsigned char zeroBufferEvt[sizeof(em_event_t)] = {0};
    unsigned char zeroBufferParam[sizeof(em_cmd_params_t)] = {0};

    EXPECT_EQ(memcmp(cmd.m_evt, zeroBufferEvt, sizeof(em_event_t)), 0);
    EXPECT_EQ(memcmp(&cmd.m_param, zeroBufferParam, sizeof(em_cmd_params_t)), 0);

    // Cleanup for test-allocated memory
    delete cmd.m_evt;
    cmd.m_evt = nullptr;
    std::cout << "Freed memory allocated for m_evt" << std::endl;

    std::cout << "Exiting reset_non_zero_event_and_command_params test" << std::endl;
}
/**
 * @brief Verify that reset_cmd_ctx() properly resets a default constructed object with non-default values.
 *
 * This test sets up an instance of em_cmd_t with pre-assigned non-default values in m_cmd_ctx.
 * The reset_cmd_ctx() function is then invoked to ensure that all members of m_cmd_ctx are reset to their default values.
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
 * | Variation / Step | Description                                                                                                               | Test Data                                                                                                                                                        | Expected Result                                                                                                     | Notes      |
 * | :---------------:| --------------------------------------------------------------------------------------------------------------------------| ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- | ---------- |
 * | 01               | Create a default em_cmd_t object, assign non-default values to cmd_ctx, invoke reset_cmd_ctx(), and validate reset.          | cmd_obj: default constructed, m_cmd_ctx.arr_index = 1, m_cmd_ctx.type = dm_orch_type_topo_sync, m_cmd_ctx.obj_id = "SampleID", expected arr_index = 0, type = 0, obj_id = all 0 | No exceptions thrown; arr_index reset to 0; type reset to 0; obj_id array reset to 0's.                             | Should Pass |
 */
TEST(em_cmd_t, reset_cmd_ctx_default_constructed_object)
{
    std::cout << "Entering reset_cmd_ctx_default_constructed_object test" << std::endl;
    em_cmd_t cmd_obj;
    cmd_obj.m_data_model.m_cmd_ctx.arr_index = 1;
    cmd_obj.m_data_model.m_cmd_ctx.type = dm_orch_type_topo_sync;
    memcpy(cmd_obj.m_data_model.m_cmd_ctx.obj_id, "SampleID", strlen("SampleID") + 1);
    std::cout << "Invoking reset_cmd_ctx" << std::endl;
    EXPECT_NO_THROW({
        cmd_obj.reset_cmd_ctx();
        std::cout << "reset_cmd_ctx() invoked successfully. m_data_model.reset_cmd_ctx() should have been executed without exceptions." << std::endl;
    });
    EXPECT_EQ(cmd_obj.m_data_model.m_cmd_ctx.arr_index, 0u);
    EXPECT_EQ(cmd_obj.m_data_model.m_cmd_ctx.type, 0);
    for (size_t i = 0; i < sizeof(cmd_obj.m_data_model.m_cmd_ctx.obj_id); i++) {
        EXPECT_EQ(cmd_obj.m_data_model.m_cmd_ctx.obj_id[i], 0);
    }
    std::cout << "Exiting reset_cmd_ctx_default_constructed_object test" << std::endl;
}
/**
 * @brief Unit test for verifying that set_db_cfg_type correctly handles a zero value.
 *
 * This test ensures that when the set_db_cfg_type method is invoked with the value zero, 
 * it does not throw any exception and correctly updates the m_db_cfg_type member variable of the object.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 109
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                           | Test Data                                         | Expected Result                                               | Notes             |
 * | :--------------: | ----------------------------------------------------- | ------------------------------------------------- | ------------------------------------------------------------- | ----------------- |
 * | 01               | Create an instance of em_cmd_t.                        | None                                              | Instance of em_cmd_t is created successfully.                 | Should be successful |
 * | 02               | Invoke set_db_cfg_type with test_type set to 0.       | input1 = test_type = 0                            | Method executes without throwing an exception.              | Should Pass       |
 * | 03               | Verify that m_db_cfg_type is updated to 0.             | output1 = m_db_cfg_type = 0                         | m_db_cfg_type equals 0, matching the input value.             | Should Pass       |
 */
TEST(em_cmd_t, set_db_cfg_type_ZeroValue) {
    std::cout << "Entering set_db_cfg_type_ZeroValue test" << std::endl;
    em_cmd_t obj;
    unsigned int test_type = 0;
    std::cout << "Invoking set_db_cfg_type with type: " << test_type << std::endl;
    EXPECT_NO_THROW(obj.set_db_cfg_type(test_type));   
    std::cout << "Method set_db_cfg_type invoked successfully." << std::endl;
    std::cout << "After invocation, m_db_cfg_type = " << obj.m_db_cfg_type << std::endl;   
    EXPECT_EQ(obj.m_db_cfg_type, test_type);
    std::cout << "Exiting set_db_cfg_type_ZeroValue test" << std::endl;
}
/**
 * @brief Validate that set_db_cfg_type accepts a typical positive value without throwing exceptions.
 *
 * This test verifies that invoking the set_db_cfg_type function with a typical positive value (42) does not throw any exceptions and correctly assigns the value to the object's m_db_cfg_type variable. This ensures the method handles typical positive inputs as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 110@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                  | Test Data                                  | Expected Result                                                        | Notes      |
 * | :--------------: | ------------------------------------------------------------ | ------------------------------------------ | ---------------------------------------------------------------------- | ---------- |
 * | 01               | Call set_db_cfg_type with a valid positive value and verify assignment | test_type = 42, m_db_cfg_type = 42           | No exception is thrown and m_db_cfg_type equals 42 after method call     | Should Pass |
 */
TEST(em_cmd_t, set_db_cfg_type_TypicalPositiveValue) {
    std::cout << "Entering set_db_cfg_type_TypicalPositiveValue test" << std::endl;
    em_cmd_t obj;
    unsigned int test_type = 42;
    std::cout << "Invoking set_db_cfg_type with type: " << test_type << std::endl;
    EXPECT_NO_THROW(obj.set_db_cfg_type(test_type));    
    std::cout << "Method set_db_cfg_type invoked successfully." << std::endl;
    std::cout << "After invocation, m_db_cfg_type = " << obj.m_db_cfg_type << std::endl;    
    EXPECT_EQ(obj.m_db_cfg_type, test_type);
    std::cout << "Exiting set_db_cfg_type_TypicalPositiveValue test" << std::endl;
}
/**
 * @brief Test to validate that set_db_cfg_type properly handles maximum unsigned int value.
 *
 * This test verifies that the set_db_cfg_type function of em_cmd_t correctly assigns the maximum unsigned integer value (UINT_MAX) to m_db_cfg_type without throwing any exceptions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 111@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                 | Test Data                                                | Expected Result                                                    | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------------- | -------------------------------------------------------- | ------------------------------------------------------------------ | ----------- |
 * | 01               | Invoke set_db_cfg_type with maximum unsigned int value (UINT_MAX) to set m_db_cfg_type.       | input: test_type = UINT_MAX, output: m_db_cfg_type = UINT_MAX | API should not throw; m_db_cfg_type should equal UINT_MAX.       | Should Pass |
 */
TEST(em_cmd_t, set_db_cfg_type_MaximumUnsignedIntValue) {
    std::cout << "Entering set_db_cfg_type_MaximumUnsignedIntValue test" << std::endl;
    em_cmd_t obj;
    unsigned int test_type = UINT_MAX;
    std::cout << "Invoking set_db_cfg_type with type: " << test_type << std::endl;    
    EXPECT_NO_THROW(obj.set_db_cfg_type(test_type));    
    std::cout << "Method set_db_cfg_type invoked successfully." << std::endl;
    std::cout << "After invocation, m_db_cfg_type = " << obj.m_db_cfg_type << std::endl;    
    EXPECT_EQ(obj.m_db_cfg_type, test_type);
    std::cout << "Exiting set_db_cfg_type_MaximumUnsignedIntValue test" << std::endl;
}
/**
 * @brief Validate get_orch_op_str returns a valid string for each valid orchestration type
 *
 * This test invokes the get_orch_op_str API for each valid orchestration type provided in a predefined list.
 * It verifies that for every valid orchestration type, the returned string pointer is not null.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 112@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke get_orch_op_str for each valid orchestration type in the predefined vector | orchType = dm_orch_type_none, dm_orch_type_net_insert, dm_orch_type_net_update, dm_orch_type_net_delete, dm_orch_type_al_insert, dm_orch_type_al_update, dm_orch_type_al_delete, dm_orch_type_em_insert, dm_orch_type_em_update, dm_orch_type_em_delete, dm_orch_type_em_test, dm_orch_type_bss_insert, dm_orch_type_bss_update, dm_orch_type_bss_delete, dm_orch_type_ssid_insert, dm_orch_type_ssid_update, dm_orch_type_ssid_delete, dm_orch_type_sta_insert, dm_orch_type_sta_update, dm_orch_type_sta_delete, dm_orch_type_sec_insert, dm_orch_type_sec_update, dm_orch_type_sec_delete, dm_orch_type_cap_insert, dm_orch_type_cap_update, dm_orch_type_cap_delete, dm_orch_type_op_class_insert, dm_orch_type_op_class_update, dm_orch_type_op_class_delete, dm_orch_type_ssid_vid_insert, dm_orch_type_ssid_vid_update, dm_orch_type_ssid_vid_delete, dm_orch_type_dpp_insert, dm_orch_type_dpp_update, dm_orch_type_dpp_delete, dm_orch_type_em_reset, dm_orch_type_db_reset, dm_orch_type_db_cfg, dm_orch_type_db_insert, dm_orch_type_db_update, dm_orch_type_db_delete, dm_orch_type_dm_delete, dm_orch_type_tx_cfg_renew, dm_orch_type_owconfig_req, dm_orch_type_owconfig_cnf, dm_orch_type_ctrl_notify, dm_orch_type_ap_cap_report, dm_orch_type_client_cap_report, dm_orch_type_net_ssid_update, dm_orch_type_topo_sync, dm_orch_type_channel_pref, dm_orch_type_channel_sel, dm_orch_type_channel_cnf, dm_orch_type_channel_sel_resp, dm_orch_type_channel_scan_req, dm_orch_type_channel_scan_res, dm_orch_type_sta_cap, dm_orch_type_sta_link_metrics, dm_orch_type_op_channel_report, dm_orch_type_sta_steer, dm_orch_type_sta_steer_btm_report, dm_orch_type_sta_disassoc, dm_orch_type_policy_cfg, dm_orch_type_mld_reconfig, opStr = expected valid string | get_orch_op_str returns a non-null string pointer for every valid orchestration type | Should Pass |
 */
TEST(em_cmd_t, get_orch_op_str_valid_orch_types) {
    const char* testName = "get_orch_op_str_valid_orch_types";
    std::cout << "Entering " << testName << " test" << std::endl;
    em_cmd_t obj{};    
    std::vector<dm_orch_type_t> validTypes = {
        dm_orch_type_none,
        dm_orch_type_net_insert,
        dm_orch_type_net_update,
        dm_orch_type_net_delete,
        dm_orch_type_al_insert,
        dm_orch_type_al_update,
        dm_orch_type_al_delete,
        dm_orch_type_em_insert,
        dm_orch_type_em_update,
        dm_orch_type_em_delete,
        dm_orch_type_em_test,
        dm_orch_type_bss_insert,
        dm_orch_type_bss_update,
        dm_orch_type_bss_delete,
        dm_orch_type_ssid_insert,
        dm_orch_type_ssid_update,
        dm_orch_type_ssid_delete,
        dm_orch_type_sta_insert,
        dm_orch_type_sta_update,
        dm_orch_type_sta_delete,
        dm_orch_type_sec_insert,
        dm_orch_type_sec_update,
        dm_orch_type_sec_delete,
        dm_orch_type_cap_insert,
        dm_orch_type_cap_update,
        dm_orch_type_cap_delete,
        dm_orch_type_op_class_insert,
        dm_orch_type_op_class_update,
        dm_orch_type_op_class_delete,
        dm_orch_type_ssid_vid_insert,
        dm_orch_type_ssid_vid_update,
        dm_orch_type_ssid_vid_delete,
        dm_orch_type_dpp_insert,
        dm_orch_type_dpp_update,
        dm_orch_type_dpp_delete,
        dm_orch_type_em_reset,
        dm_orch_type_db_reset,
        dm_orch_type_db_cfg,
        dm_orch_type_db_insert,
        dm_orch_type_db_update,
        dm_orch_type_db_delete,
        dm_orch_type_dm_delete,
        dm_orch_type_tx_cfg_renew,
        dm_orch_type_owconfig_req,
        dm_orch_type_owconfig_cnf,
        dm_orch_type_ctrl_notify,
        dm_orch_type_ap_cap_report,
        dm_orch_type_client_cap_report,
        dm_orch_type_net_ssid_update,
        dm_orch_type_topo_sync,
        dm_orch_type_channel_pref,
        dm_orch_type_channel_sel,
        dm_orch_type_channel_cnf,
        dm_orch_type_channel_sel_resp,
        dm_orch_type_channel_scan_req,
        dm_orch_type_channel_scan_res,
        dm_orch_type_sta_cap,
        dm_orch_type_sta_link_metrics,
        dm_orch_type_op_channel_report,
        dm_orch_type_sta_steer,
        dm_orch_type_sta_steer_btm_report,
        dm_orch_type_sta_disassoc,
        dm_orch_type_policy_cfg,
        dm_orch_type_mld_reconfig
    };

    for (const auto& orchType : validTypes) {
        std::cout << "Invoking get_orch_op_str for orchestration type value: " << static_cast<unsigned int>(orchType) << std::endl;
        const char* opStr = em_cmd_t::get_orch_op_str(orchType);
		ASSERT_NE(opStr, nullptr);
        std::cout << "Returned string: " << (opStr ? opStr : "NULL") << std::endl;
    }
    std::cout << "Exiting " << testName << " test" << std::endl;
}
/**
 * @brief Test that get_orch_op_str returns "dm_orch_type_unknown" for an invalid orchestration type.
 *
 * This test validates that when an invalid orchestration type is provided, the function get_orch_op_str correctly returns the string "dm_orch_type_unknown". This behavior is critical to ensure the API handles unexpected or out‐of‐range enum values appropriately.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 113
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- | -------------- | ----- |
 * | 01 | Invoke get_orch_op_str with an invalid orchestration type value | invalidType = (dm_orch_type_bsta_cap_query + 1), opStr = output string from get_orch_op_str | Returns "dm_orch_type_unknown" and assertion EXPECT_EQ passes | Should Pass |
 */
TEST(em_cmd_t, get_orch_op_str_invalid_orch_type) {
    const char* testName = "get_orch_op_str_invalid_orch_type";
    std::cout << "Entering " << testName << " test" << std::endl;
    em_cmd_t obj{};
    dm_orch_type_t invalidType = static_cast<dm_orch_type_t>(dm_orch_type_bsta_cap_query + 1);
    std::cout << "Invoking get_orch_op_str for invalid orchestration type value: " << static_cast<unsigned int>(invalidType) << std::endl;
    const char* opStr = em_cmd_t::get_orch_op_str(invalidType);
    std::cout << "Returned string for invalid input: " << opStr << std::endl;
    EXPECT_EQ(opStr, "dm_orch_type_unknown");
    std::cout << "Exiting " << testName << " test" << std::endl;
}
/**
 * @brief Verify that get_orch_submit() returns true when the submission flag is true
 *
 * This test initializes an em_cmd_t object with one valid orch_desc entry, sets the submission flag to true, and then verifies that get_orch_submit() correctly returns true. This ensures that the method behaves as expected when the submission flag is enabled.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 114
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                         | Test Data                                                             | Expected Result                            | Notes         |
 * | :--------------: | --------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ------------------------------------------ | ------------- |
 * | 01               | Initialize the em_cmd_t object and pre-set its attributes including zeroing m_orch_desc, setting m_num_orch_desc to 1, and m_orch_op_idx to 0. | m_orch_desc = {0}, m_num_orch_desc = 1, m_orch_op_idx = 0               | Object is successfully initialized.      | Should be successful |
 * | 02               | Set the submission flag of the first orch_desc element to true.                                     | cmd.m_orch_desc[0].submit = true                                        | Submission flag is set to true.            | Should Pass   |
 * | 03               | Call get_orch_submit() and verify that it returns true.                                             | API Invocation, output: submitStatus                                  | Returns true; assertion passes.            | Should Pass   |
 */
TEST(em_cmd_t, get_orch_submit_returns_true_when_submission_flag_is_true)
{
    std::cout << "Entering get_orch_submit_returns_true_when_submission_flag_is_true test" << std::endl;
    em_cmd_t cmd;
    memset(cmd.m_orch_desc, 0, sizeof(cmd.m_orch_desc));
    cmd.m_num_orch_desc = 1;
    cmd.m_orch_op_idx = 0;
    cmd.m_orch_desc[0].submit = true;  
    std::cout << "Invoking get_orch_submit() method." << std::endl;
    bool submitStatus = cmd.get_orch_submit();
    std::cout << "get_orch_submit() returned: " << submitStatus << std::endl;
    EXPECT_TRUE(submitStatus);
    std::cout << "Exiting get_orch_submit_returns_true_when_submission_flag_is_true test" << std::endl;
}
/**
 * @brief Verify that get_orch_submit returns false when the submission flag is false
 *
 * This test verifies that the get_orch_submit() method correctly returns false when the submission flag 
 * (submit member of m_orch_desc) is set to false. It ensures that the API properly detects the disabled 
 * submission state, which is critical for correct operation flow in command processing.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize the em_cmd_t structure and set the appropriate fields (m_num_orch_desc=1, m_orch_op_idx=1, and m_orch_desc[1].submit=false) | m_num_orch_desc = 1, m_orch_op_idx = 1, m_orch_desc[1].submit = false | em_cmd_t structure is properly initialized with the submission flag set to false | Should be successful |
 * | 02 | Invoke the get_orch_submit() method on the initialized object | cmd object with initialized fields | Method returns false since submission flag is false | Should Pass |
 * | 03 | Assert that the returned value is false | Returned submitStatus value = false | EXPECT_FALSE assertion passes, confirming the expected outcome | Should Pass |
 */
TEST(em_cmd_t, get_orch_submit_returns_false_when_submission_flag_is_false)
{
    std::cout << "Entering get_orch_submit_returns_false_when_submission_flag_is_false test" << std::endl;
    em_cmd_t cmd;
    memset(cmd.m_orch_desc, 0, sizeof(cmd.m_orch_desc));
    cmd.m_num_orch_desc = 1;
    cmd.m_orch_op_idx = 1;
    cmd.m_orch_desc[1].submit = false;
    std::cout << "Invoking get_orch_submit() method." << std::endl;
    bool submitStatus = cmd.get_orch_submit();
    std::cout << "get_orch_submit() returned: " << submitStatus << std::endl;
    EXPECT_FALSE(submitStatus);
    std::cout << "Exiting get_orch_submit_returns_false_when_submission_flag_is_false test" << std::endl;
}
/**
 * @brief Validate that get_orch_desc API properly retrieves a valid orch descriptor
 *
 * This test sets up an instance of em_cmd_t by initializing the orch operation index and descriptor fields. It then calls the get_orch_desc method and verifies that the returned pointer is not null, and that the orch descriptor fields (op and submit) match the expected values (dm_orch_type_none and false respectively).
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 116@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Create an instance of em_cmd_t and initialize orch operation index and descriptor fields | m_orch_op_idx = 1, orchDesc->op = dm_orch_type_none, orchDesc->submit = false | Instance variables initialized with intended values | Should be successful |
 * | 02 | Invoke the get_orch_desc() method to retrieve the orch descriptor pointer | API call: get_orch_desc() | Returned pointer is not nullptr | Should Pass |
 * | 03 | Validate the retrieved orch descriptor fields | Returned orchDesc->op = dm_orch_type_none, Returned orchDesc->submit = false | orchDesc->op equals dm_orch_type_none and orchDesc->submit equals false | Should Pass |
 */
TEST(em_cmd_t, get_orch_desc_retrieval)
{
    std::cout << "Entering get_orch_desc_retrieval test" << std::endl;
    em_cmd_t obj{};
	obj.m_orch_op_idx = 1;
	obj.m_orch_desc[obj.m_orch_op_idx].op = dm_orch_type_none;
	obj.m_orch_desc[obj.m_orch_op_idx].submit = false;
    std::cout << "Invoking get_orch_desc() method." << std::endl;
    em_orch_desc_t* orchDescPtr = obj.get_orch_desc();
    ASSERT_NE(orchDescPtr, nullptr);
    if (orchDescPtr)
    {
        std::cout << "Retrieved orchDesc->op: " << static_cast<unsigned int>(orchDescPtr->op) << std::endl;
        std::cout << "Retrieved orchDesc->submit: " << orchDescPtr->submit << std::endl;
        EXPECT_EQ(orchDescPtr->op, dm_orch_type_none);
        EXPECT_EQ(orchDescPtr->submit, false);
    }

    std::cout << "Exiting get_orch_desc_retrieval test" << std::endl;
}
/**
 * @brief Test to verify that get_orch_desc() returns nullptr when m_orch_op_idx is set to UINT_MAX
 *
 * This test verifies that when the em_cmd_t object's m_orch_op_idx is set to UINT_MAX and m_orch_desc is
 * initialized to zero, the get_orch_desc() method returns a nullptr. This ensures that the method correctly
 * handles scenarios when the index is beyond valid bounds.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | --------------- | ----- |
 * | 01 | Initialize em_cmd_t object: zero out m_orch_desc and set m_orch_op_idx to UINT_MAX | m_orch_desc = all zeros, m_orch_op_idx = UINT_MAX | Object is initialized with the specified state | Should be successful |
 * | 02 | Invoke get_orch_desc() method and validate its return value | Call: orchDescPtr = get_orch_desc() | orchDescPtr is nullptr and ASSERT_EQ validates the condition | Should Pass |
 */
TEST(em_cmd_t, get_orch_desc_maxindex_retrieval)
{
    std::cout << "Entering get_orch_desc_maxindex_retrieval test" << std::endl;
    em_cmd_t obj{};
    memset(obj.m_orch_desc, 0, sizeof(obj.m_orch_desc));
    obj.m_orch_op_idx = UINT_MAX;
    std::cout << "Invoking get_orch_desc() method." << std::endl;
    em_orch_desc_t* orchDescPtr = obj.get_orch_desc();
    ASSERT_EQ(orchDescPtr, nullptr);
    std::cout << "Exiting get_orch_desc_maxindex_retrieval test" << std::endl;
}
/**
 * @brief Validate retrieval of valid orchestration operation from the command object.
 *
 * This test verifies that when a valid orchestration operation is set in the command object, 
 * calling the get_orch_op() method returns the correct operation value. This ensures that both 
 * the initialization and the retrieval mechanism of the command object work as expected.
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
 * | Variation / Step | Description                                                         | Test Data                                                        | Expected Result                                         | Notes         |
 * | :--------------: | ------------------------------------------------------------------- | ---------------------------------------------------------------- | ------------------------------------------------------- | ------------- |
 * | 01               | Initialize the command object with valid orchestration operation details. | m_orch_op_idx = 0, m_orch_desc[0].op = dm_orch_type_net_insert      | Command object initialized with valid orch operation    | Should be successful |
 * | 02               | Invoke get_orch_op() method to retrieve the orchestration operation.      | input: cmd object; output: opStatus, expected value = dm_orch_type_net_insert | get_orch_op() returns dm_orch_type_net_insert             | Should Pass   |
 */
TEST(em_cmd_t, get_orch_op_valid_orch_op_retrieval)
{
    std::cout << "Entering get_orch_op_valid_orch_op_retrieval test" << std::endl;
    em_cmd_t cmd;
    cmd.m_orch_op_idx = 0;
    cmd.m_orch_desc[0].op = dm_orch_type_net_insert;
    std::cout << "Invoking get_orch_op() method." << std::endl;
    dm_orch_type_t opStatus = cmd.get_orch_op();
    std::cout << "get_orch_op() returned: " << static_cast<unsigned int>(opStatus) << std::endl;
    EXPECT_EQ(opStatus, dm_orch_type_net_insert);
    std::cout << "Exiting get_orch_op_valid_orch_op_retrieval test" << std::endl;
}
/**
 * @brief Verify get_orch_op returns the expected error value when provided an invalid orch op value.
 *
 * This test assesses that the get_orch_op method in the em_cmd_t class correctly handles an invalid 
 * orch operation type by returning an error code (-1). This ensures that the API validates the operation type 
 * appropriately to maintain integrity of the command processing.
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
 * | Variation / Step | Description                                                        | Test Data                                                                  | Expected Result                                                         | Notes      |
 * | :--------------: | ------------------------------------------------------------------ | -------------------------------------------------------------------------- | ----------------------------------------------------------------------- | ---------- |
 * | 01               | Set up em_cmd_t object with invalid orch operation type and invoke get_orch_op() | input: cmd.m_orch_op_idx = 1, cmd.m_orch_desc[1].op = -1, output: opStatus expected = -1 | Return value opStatus is -1; EXPECT_EQ(opStatus, -1) assertion passes     | Should Pass|
 */
TEST(em_cmd_t, get_orch_invalid_orch_op_value)
{
    std::cout << "Entering get_orch_invalid_orch_op_value test" << std::endl;
    em_cmd_t cmd;
	cmd.m_orch_op_idx = 1;
	cmd.m_orch_desc[1].op = static_cast<dm_orch_type_t>(-1);
    std::cout << "Invoking get_orch_op() method." << std::endl;
    dm_orch_type_t opStatus = cmd.get_orch_op();
    std::cout << "get_orch_submit() returned: " << static_cast<unsigned int>(opStatus) << std::endl;
    EXPECT_EQ(opStatus, -1);
    std::cout << "Exiting get_orch_invalid_orch_op_value test" << std::endl;
}
/**
 * @brief Test the set_orch_op_index API with a typical valid index value.
 *
 * This test verifies that the set_orch_op_index method in the em_cmd_t class correctly sets the internal member m_orch_op_idx to the provided valid index without throwing any exceptions.
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
 * | 01 | Initialize the em_cmd_t object and define the index value | idx = 10 | Object instantiated and idx initialized to 10 | Should be successful |
 * | 02 | Invoke set_orch_op_index with the valid index and verify results | input: idx = 10, output: m_orch_op_idx expected = 10 | API does not throw exception and m_orch_op_idx equals 10 | Should Pass |
 */
TEST(em_cmd_t, set_orch_op_index_typical_valid)
{
    std::cout << "Entering set_orch_op_index_typical_valid test" << std::endl;
    em_cmd_t cmd;
    unsigned int idx = 10;
    std::cout << "Invoking set_orch_op_index with idx = " << idx << std::endl;
    EXPECT_NO_THROW(cmd.set_orch_op_index(idx));
    std::cout << "After invocation, m_orch_op_idx = " << cmd.m_orch_op_idx << std::endl;
    EXPECT_EQ(cmd.m_orch_op_idx, idx);
    std::cout << "Exiting set_orch_op_index_typical_valid test" << std::endl;
}
/**
 * @brief Verify that setting the orchard operation index with its lower bound does not throw an exception and correctly updates the internal state.
 *
 * This test ensures that when the API set_orch_op_index is invoked with the minimum valid index value (0), it successfully assigns the value to m_orch_op_idx without throwing any exceptions, thereby confirming the correct handling of lower boundary conditions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 121@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                      | Test Data                                 | Expected Result                                                   | Notes       |
 * | :--------------: | ---------------------------------------------------------------- | ----------------------------------------- | ----------------------------------------------------------------- | ----------- |
 * | 01               | Invoke set_orch_op_index with the lowest valid index value (0)     | idx = 0, expected m_orch_op_idx = 0         | No exception thrown and m_orch_op_idx is updated to 0                | Should Pass |
 */
TEST(em_cmd_t, set_orch_op_index_lower_bound)
{
    std::cout << "Entering set_orch_op_index_lower_bound test" << std::endl;
    em_cmd_t cmd;
    unsigned int idx = 0;
    std::cout << "Invoking set_orch_op_index with idx = " << idx << std::endl;
    EXPECT_NO_THROW(cmd.set_orch_op_index(idx));
    std::cout << "After invocation, m_orch_op_idx = " << cmd.m_orch_op_idx << std::endl;
    EXPECT_EQ(cmd.m_orch_op_idx, idx);
    std::cout << "Exiting set_orch_op_index_lower_bound test" << std::endl;
}
/**
 * @brief Tests setting the orch operation index with the upper bound value.
 *
 * This test verifies that the em_cmd_t::set_orch_op_index method can handle the maximum unsigned integer value (UINT_MAX) without throwing an exception and correctly assigns this value to the member variable m_orch_op_idx. This ensures that the function properly manages boundary conditions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 122@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create an em_cmd_t instance and invoke set_orch_op_index with UINT_MAX to test upper boundary handling | input: idx = UINT_MAX, output: m_orch_op_idx = UINT_MAX | No exception is thrown and m_orch_op_idx equals UINT_MAX | Should Pass |
 */
TEST(em_cmd_t, set_orch_op_index_upper_bound)
{
    std::cout << "Entering set_orch_op_index_upper_bound test" << std::endl;
    em_cmd_t cmd;
    unsigned int idx = UINT_MAX;
    std::cout << "Invoking set_orch_op_index with idx = " << idx << std::endl;
    EXPECT_NO_THROW(cmd.set_orch_op_index(idx));
    std::cout << "After invocation, m_orch_op_idx = " << cmd.m_orch_op_idx << std::endl;
    EXPECT_EQ(cmd.m_orch_op_idx, idx);
    std::cout << "Exiting set_orch_op_index_upper_bound test" << std::endl;
}
/**
 * @brief Verify that get_orch_op_index() returns the lower bound value.
 *
 * This test verifies that when the member variable m_orch_op_idx of an em_cmd_t object is set to 0, the get_orch_op_index() method returns 0. This ensures that the lower bound index is handled correctly.
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
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create an em_cmd_t object, set m_orch_op_idx to 0, and call get_orch_op_index() | m_orch_op_idx = 0, orchOpIndex expected = 0 | get_orch_op_index() returns 0 | Should Pass |
 */
TEST(em_cmd_t, get_orch_op_index_retrieve_lower_bound)
{
    std::cout << "Entering get_orch_op_index_retrieve_lower_bound test" << std::endl;
    em_cmd_t obj;
    obj.m_orch_op_idx = 0;
    std::cout << "Invoking get_orch_op_index() method on em_cmd_t object" << std::endl;
    unsigned int orchOpIndex = obj.get_orch_op_index();
    std::cout << "get_orch_op_index() returned value: " << orchOpIndex << std::endl;
    EXPECT_EQ(orchOpIndex, 0u);
    std::cout << "Exiting get_orch_op_index_retrieve_lower_bound test" << std::endl;
}
/**
 * @brief Validate the retrieval of the maximum boundary index using get_orch_op_index()
 *
 * This test verifies that the get_orch_op_index() method correctly returns the value of m_orch_op_idx when it is set to UINT_MAX.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 124@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                          | Test Data                                                            | Expected Result                                           | Notes         |
 * | :--------------: | ------------------------------------------------------------------------------------ | -------------------------------------------------------------------- | --------------------------------------------------------- | ------------- |
 * | 01               | Create an instance of em_cmd_t and set its m_orch_op_idx to the maximum unsigned int | m_orch_op_idx = UINT_MAX                                             | Object's m_orch_op_idx is set to UINT_MAX                  | Should be successful |
 * | 02               | Invoke get_orch_op_index() and validate the returned value                           | Input: em_cmd_t object with m_orch_op_idx set to UINT_MAX; Output: orchOpIndex = UINT_MAX | Returned orchOpIndex equals UINT_MAX and assertion passes | Should Pass   |
 */
TEST(em_cmd_t, get_orch_op_index_retrieve_upper_bound)
{
    std::cout << "Entering get_orch_op_index_retrieve_upper_bound test" << std::endl;
    em_cmd_t obj;
	obj.m_orch_op_idx = UINT_MAX;
    std::cout << "Invoking get_orch_op_index() method on em_cmd_t object" << std::endl;
    unsigned int orchOpIndex = obj.get_orch_op_index();
    std::cout << "get_orch_op_index() returned value: " << orchOpIndex << std::endl;
    EXPECT_EQ(orchOpIndex, UINT_MAX);
    std::cout << "Exiting get_orch_op_index_retrieve_upper_bound test" << std::endl;
}
/**
 * @brief Validate that override_op processes a valid override correctly
 *
 * This test validates that calling override_op with a valid index and a properly prepared descriptor (with op set to dm_orch_type_em_update and submit set to true) does not throw an exception and correctly updates the internal state of the command object.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 125
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke override_op with valid index and descriptor | index = 0, desc.op = dm_orch_type_em_update, desc.submit = true, output: m_orch_desc[index].op and m_orch_desc[index].submit | API should not throw; m_orch_desc[index].op equals dm_orch_type_em_update and m_orch_desc[index].submit equals true | Should Pass |
 */
TEST(em_cmd_t, override_op_valid_override)
{
    std::cout << "Entering override_op_valid_override test" << std::endl;
    em_cmd_t cmd{};
    unsigned int index = 0;
    em_orch_desc_t desc{ dm_orch_type_em_update, true };
    std::cout << "Prepared descriptor with op dm_orch_type_em_update and submit as true" << std::endl;
    std::cout << "Invoking override_op with index = 0 and given descriptor" << std::endl;
    EXPECT_NO_THROW(cmd.override_op(index, &desc));
    std::cout << "After override_op, internal state m_orch_desc: op = " << static_cast<unsigned int>(cmd.m_orch_desc[index].op) << " and submit = " << cmd.m_orch_desc[index].submit << std::endl;
    EXPECT_EQ(cmd.m_orch_desc[index].op, dm_orch_type_em_update);
    EXPECT_EQ(cmd.m_orch_desc[index].submit, true);
    std::cout << "Exiting override_op_valid_override test" << std::endl;
}
/**
 * @brief Test override_op method with an out-of-range index.
 *
 * This test verifies that invoking the override_op method with an invalid index value (UINT_MAX)
 * correctly triggers an exception. The test ensures that the method safely handles indices
 * that are out of the expected range.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 126
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke override_op with UINT_MAX index and a valid descriptor | index = UINT_MAX, desc.op = dm_orch_type_net_insert, desc.submit = true, cmd instance created | An exception is thrown as expected (checked using EXPECT_ANY_THROW) | Should Pass |
 */
TEST(em_cmd_t, override_op_invalid_index_out_of_range)
{
    std::cout << "Entering override_op_invalid_index_out_of_range test" << std::endl;
    em_cmd_t cmd{};
    unsigned int index = UINT_MAX;
    em_orch_desc_t desc{ dm_orch_type_net_insert, true };
    std::cout << "Prepared descriptor with op dm_orch_type_net_insert and submit as true" << std::endl;
    std::cout << "Invoking override_op with index = UINT_MAX and given descriptor" << std::endl;
    EXPECT_ANY_THROW(cmd.override_op(index, &desc));
    std::cout << "Exiting override_op_invalid_index_out_of_range test" << std::endl;
}
/**
 * @brief Test override_op method with a nullptr descriptor to ensure it throws an exception
 *
 * This test verifies that invoking the override_op method on an em_cmd_t object with a valid index and a null descriptor pointer results in an exception being thrown. This is critical to ensure proper error handling and robustness of the API when provided with invalid input parameters.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 127@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke override_op with index = 1 and a nullptr descriptor | input: index = 1, descriptor = nullptr, instance: cmd (em_cmd_t object) | Exception is thrown as verified by EXPECT_ANY_THROW | Should Pass |
 */
TEST(em_cmd_t, override_op_null_descriptor)
{
    std::cout << "Entering override_op_null_descriptor test" << std::endl;
    em_cmd_t cmd{};
    unsigned int index = 1;
    std::cout << "Invoking override_op with index = " << index << " and NULL descriptor pointer" << std::endl;
    EXPECT_ANY_THROW(cmd.override_op(index, nullptr));
    std::cout << "Exiting override_op_null_descriptor test" << std::endl;
}
