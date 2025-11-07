/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2024 RDK Management
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
#include "dm_policy.h"


/**
* @brief Test the decode function with valid JSON object and different policy types.
*
* This test verifies the behavior of the decode function in the dm_policy_t class when provided with a valid JSON object and various policy types. The test ensures that the decode function returns 0 for all the given policy types, indicating successful decoding.
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
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Assign value for parent_id | const char* valid_parent_id_str = "device1@00:11:22:33:44:55@01:23:45:67:89:AB@2" | Should be successful | |
* | 02 | Test decode with em_policy_id_type_steering_local | obj, parent_id, plicy = em_policy_id_type_steering_local | result = 0, EXPECT_EQ(result, 0) | Should Pass |
* | 03 | Test decode with em_policy_id_type_unknown | obj, parent_id, plicy = em_policy_id_type_unknown | result = 0, EXPECT_EQ(result, 0) | Should Pass |
* | 04 | Test decode with em_policy_id_type_steering_local | obj, parent_id, plicy = em_policy_id_type_steering_local | result = 0, EXPECT_EQ(result, 0) | Should Pass |
* | 05 | Test decode with em_policy_id_type_steering_btm | obj, parent_id, plicy = em_policy_id_type_steering_btm | result = 0, EXPECT_EQ(result, 0) | Should Pass |
* | 06 | Test decode with em_policy_id_type_ap_metrics_rep | obj, parent_id, plicy = em_policy_id_type_ap_metrics_rep | result = 0, EXPECT_EQ(result, 0) | Should Pass |
* | 07 | Test decode with em_policy_id_type_channel_scan | obj, parent_id, plicy = em_policy_id_type_channel_scan | result = 0, EXPECT_EQ(result, 0) | Should Pass |
* | 08 | Test decode with em_policy_id_type_radio_metrics_rep | obj, parent_id, plicy = em_policy_id_type_radio_metrics_rep | result = 0, EXPECT_EQ(result, 0) | Should Pass |
* | 09 | Test decode with em_policy_id_type_backhaul_bss_config | obj, parent_id, plicy = em_policy_id_type_backhaul_bss_config | result = 0, EXPECT_EQ(result, 0) | Should Pass |
*/
TEST(dm_policy_t_Test, DecodeWithValidJSONObjectAndDifferentPolicyTypes) {
    std::cout << "Entering DecodeWithValidJSONObjectAndDifferentPolicyTypes test";

    const char* valid_json_str = R"({
        "Disallowed STA": [{"MAC": "AA:BB:CC:DD:EE:FF"}],
        "Steering Policy": 1,
        "Utilization Threshold": 75,
        "RCPI Thresold": 60,
        "Interval": 30,
        "Managed Client Marker": "marker",
        "STA RCPI Threshold": 50,
        "STA RCPI Hysteresis": 5,
        "AP Utilization Thresold": 80,
        "STA Traffic Stats": 1,
        "STA Link Metrics": 1,
        "STA Status": 1,
        "Primay VLAN ID": 100,
        "Default PCP": 3,
        "Traffic Separation": [{"SSID Name": "TestSSID"}],
        "VLAN ID": 200,
        "Report Independent Channel Scans": 1
    })";

    cJSON* obj = cJSON_Parse(valid_json_str);
    ASSERT_NE(obj, nullptr);  // Ensure JSON was parsed correctly

    const char* valid_parent_id_str = "device1@00:11:22:33:44:55@01:23:45:67:89:AB@2";
    void* parent_id = static_cast<void*>(const_cast<char*>(valid_parent_id_str));
    dm_policy_t policy;

    em_policy_id_type_t policy_types[] = {
        em_policy_id_type_steering_local,
        em_policy_id_type_unknown,
        em_policy_id_type_steering_local,
        em_policy_id_type_steering_btm,
        em_policy_id_type_ap_metrics_rep,
        em_policy_id_type_channel_scan,
        em_policy_id_type_radio_metrics_rep,
        em_policy_id_type_backhaul_bss_config
    };

    for (auto plicy : policy_types) {
        int result = policy.decode(obj, parent_id, plicy);
        EXPECT_EQ(result, 0);
    }

    cJSON_Delete(obj);  // Clean up
    std::cout << "Exiting DecodeWithValidJSONObjectAndDifferentPolicyTypes test";
}

/**
* @brief Test the decode function with a null JSON object
*
* This test verifies the behavior of the decode function when provided with a null JSON object. 
* It ensures that the function handles null input gracefully and returns an appropriate error code.@n
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
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Assign value for parent_id | const char* valid_parent_id_str = "device1@00:11:22:33:44:55@01:23:45:67:89:AB@2" | Should be successful |
* | 02 | Call decode with null JSON object | json_object = nullptr, parent_id, policy_id_type = em_policy_id_type_steering_local | result != 0, EXPECT_NE(result, 0) | Should Pass |
*/

TEST(dm_policy_t_Test, DecodeWithNullJSONObject) {
    std::cout << "Entering DecodeWithNullJSONObject test";
    const char* valid_parent_id_str = "device1@00:11:22:33:44:55@01:23:45:67:89:AB@2";
    void* parent_id = static_cast<void*>(const_cast<char*>(valid_parent_id_str));
    dm_policy_t policy;
    int result = policy.decode(nullptr, parent_id, em_policy_id_type_steering_local);
    EXPECT_NE(result, 0);
    std::cout << "Exiting DecodeWithNullJSONObject test";
}

/**
* @brief Test the decode function with a null parent ID
*
* This test checks the behavior of the decode function when the parent ID is null. 
* It ensures that the function returns a non-zero value indicating an error.
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
* | 01| Call decode with null parent ID | obj = cJSON object, parent_id = nullptr, policy_id_type = em_policy_id_type_steering_local | result != 0, EXPECT_NE(result, 0) | Should Fail |
*/
TEST(dm_policy_t_Test, DecodeWithNullParentID) {
    std::cout << "Entering DecodeWithNullParentID test";
    cJSON obj;
    dm_policy_t policy;
    int result = policy.decode(&obj, nullptr, em_policy_id_type_steering_local);
    EXPECT_NE(result, 0);
    std::cout << "Exiting DecodeWithNullParentID test";
}

/**
* @brief Test the decode function with an invalid JSON object
*
* This test checks the behavior of the decode function when provided with a malformed JSON object. The objective is to ensure that the function correctly identifies and handles invalid input, returning an error code as expected.
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create a malformed JSON object | obj.type = -1 | Should be successful | |
* | 02| Assign value for parent_id | const char* parent_id_str = "device1@00:11:22:33:44:55@01:23:45:67:89:AB@2" | Should be successful | |
* | 03| Call the decode function with invalid JSON object | policy.decode(&obj, parent_id, em_policy_id_type_steering_local) | result != 0 | Should Fail |
*/
TEST(dm_policy_t_Test, DecodeWithInvalidJSONObject) {
    std::cout << "Entering DecodeWithInvalidJSONObject test";
    cJSON obj;
    obj.type = -1; // Malformed JSON object
    const char* parent_id_str = "device1@00:11:22:33:44:55@01:23:45:67:89:AB@2";
    void* parent_id = static_cast<void*>(const_cast<char*>(parent_id_str));
    dm_policy_t policy;
    int result = policy.decode(&obj, parent_id, em_policy_id_type_steering_local);
    EXPECT_NE(result, 0);
    std::cout << "Exiting DecodeWithInvalidJSONObject test";
}

/**
* @brief Test the copy constructor of dm_policy_t with a modified policy
*
* This test verifies that the copy constructor of the dm_policy_t class correctly copies the policy from one instance to another, even after the policy has been modified. This ensures that the copy constructor works as expected and the modifications are accurately reflected in the new instance.
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
* | 01| Create an instance of dm_policy_t and modify its policy | policy1.m_policy.sta_traffic_stats = true, policy1.m_policy.sta_link_metric = false, policy1.m_policy.sta_status = true, policy1.m_policy.independent_scan_report = false, policy1.m_policy.profile_1_sta_disallowed = true, policy1.m_policy.profile_2_sta_disallowed = false, policy1.m_policy.num_sta = 5 | Instance created and policy modified | Should be successful |
* | 02| Use the copy constructor to create a new instance from the modified instance | dm_policy_t policy2(policy1) | New instance created with copied policy | Should be successful |
* | 03| Verify that the new instance has the same policy as the original modified instance | EXPECT_EQ(policy2.m_policy.num_sta, 5), EXPECT_EQ(policy2.m_policy.sta_traffic_stats , true), EXPECT_EQ(policy2.m_policy.sta_link_metric, false), EXPECT_EQ(policy2.m_policy.sta_status, true), EXPECT_EQ(policy2.m_policy.independent_scan_report, false), EXPECT_EQ(policy2.m_policy.profile_1_sta_disallowed, true), EXPECT_EQ(policy2.m_policy.profile_2_sta_disallowed, false) | The policy of the new instance matches the original | Should Pass |
*/
TEST(dm_policy_t_Test, CopyConstructorWithModifiedPolicy) {
    std::cout << "Entering CopyConstructorWithModifiedPolicy" << std::endl;
    dm_policy_t policy1 {};
    policy1.m_policy.sta_traffic_stats = true;
    policy1.m_policy.sta_link_metric = false;
    policy1.m_policy.sta_status = true;
    policy1.m_policy.independent_scan_report = false;
    policy1.m_policy.profile_1_sta_disallowed = true;
    policy1.m_policy.profile_2_sta_disallowed = false;    
    policy1.m_policy.num_sta = 5;
    dm_policy_t policy2(policy1);
    EXPECT_EQ(policy2.m_policy.sta_traffic_stats , true);
    EXPECT_EQ(policy2.m_policy.sta_link_metric, false);
    EXPECT_EQ(policy2.m_policy.sta_status, true);
    EXPECT_EQ(policy2.m_policy.independent_scan_report, false);
    EXPECT_EQ(policy2.m_policy.profile_1_sta_disallowed, true);
    EXPECT_EQ(policy2.m_policy.profile_2_sta_disallowed, false);
    EXPECT_EQ(policy2.m_policy.num_sta, 5);

    std::cout << "Exiting CopyConstructorWithModifiedPolicy" << std::endl;
}

/**
* @brief Test the copy constructor of dm_policy_t with a null policy pointer
*
* This test verifies that the copy constructor of the dm_policy_t class throws an exception when it is passed a null policy pointer. This is important to ensure that the class handles invalid input gracefully and does not cause undefined behavior.
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
* | 01 | Initialize policy1 to nullptr | policy1 = nullptr | | Should be successful |
* | 02 | Attempt to copy construct policy2 from policy1 | policy1 = nullptr | std::exception should be thrown | Should Pass |
* | 03 | Catch std::exception | | | Should be successful |
* | 04 | Catch any other exception | | | Should Fail |
*/

TEST(dm_policy_t_Test, CopyConstructorWithNullPolicy) {
    std::cout << "Entering CopyConstructorWithNullPolicy" << std::endl;
    dm_policy_t* policy1 = nullptr;
    try {
        dm_policy_t policy2(*policy1);
        FAIL() << "Expected std::exception";
    } catch (const std::exception& e) {
        SUCCEED();
    } catch (...) {
        FAIL() << "Expected std::exception";
    }
    std::cout << "Exiting CopyConstructorWithNullPolicy" << std::endl;
}

/**
* @brief Test the initialization of dm_policy_t object with a valid em_policy_t object.
*
* This test verifies that the dm_policy_t object is correctly initialized when provided with a valid em_policy_t object. The test ensures that the internal policy of dm_policy_t matches the provided em_policy_t object.
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
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Initialize em_policy_t object with valid values | valid_policy.sta_traffic_stats = true, valid_policy.sta_link_metric = false, valid_policy.sta_status = true, valid_policy.independent_scan_report = false, valid_policy.profile_1_sta_disallowed = true, valid_policy.profile_2_sta_disallowed = false, valid_policy.num_sta = 5 | em_policy_t object should be initialized with valid values | Should be successful |
* | 02 | Initialize dm_policy_t object with the valid em_policy_t object | dm_policy(valid_policy) | dm_policy_t object should be initialized with the valid em_policy_t object | Should Pass |
* | 03 | Verify the internal policy of dm_policy_t matches the provided em_policy_t object | dm_policy.m_policy, valid_policy | EXPECT_EQ should pass | Should Pass |
*/
TEST(dm_policy_t_Test, InitializeWithValidEmPolicyTObject) {
    std::cout << "Entering InitializeWithValidEmPolicyTObject" << std::endl;
    em_policy_t valid_policy {};
    memset(&valid_policy, 0, sizeof(em_policy_t));
    // Initialize valid_policy with valid values
    valid_policy.sta_traffic_stats = true;
    valid_policy.sta_link_metric = false;
    valid_policy.sta_status = true;
    valid_policy.independent_scan_report = false;
    valid_policy.profile_1_sta_disallowed = true;
    valid_policy.profile_2_sta_disallowed = false;
    valid_policy.num_sta = 5;
    dm_policy_t dm_policy(valid_policy);
    EXPECT_EQ(dm_policy.m_policy.sta_traffic_stats, valid_policy.sta_traffic_stats);
    EXPECT_EQ(dm_policy.m_policy.sta_link_metric, valid_policy.sta_link_metric);
    EXPECT_EQ(dm_policy.m_policy.sta_status, valid_policy.sta_status);
    EXPECT_EQ(dm_policy.m_policy.independent_scan_report, valid_policy.independent_scan_report);
    EXPECT_EQ(dm_policy.m_policy.profile_1_sta_disallowed, valid_policy.profile_1_sta_disallowed);
    EXPECT_EQ(dm_policy.m_policy.profile_2_sta_disallowed, valid_policy.profile_2_sta_disallowed);
    EXPECT_EQ(dm_policy.m_policy.num_sta, valid_policy.num_sta);
    std::cout << "Exiting InitializeWithValidEmPolicyTObject" << std::endl;
}

/**
 * @brief Test the initialization of dm_policy_t object with an em_policy_t object having invalid MAC addresses of length 3 bytes.
 *
 * This test verifies that the dm_policy_t object is correctly initialized when provided with an em_policy_t object
 * that contains MAC addresses with invalid length (3 bytes instead of the valid 6 bytes). The test ensures that
 * the dm_policy_t object's m_policy member matches the provided em_policy_t object.
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
 * | Variation / Step | Description                                   | Test Data                 | Expected Result                         | Notes     |
 * | :--------------: | ---------------------------------------------| ------------------------- | ------------------------------------- | --------- |
 * | 01               | Initialize em_policy_t with invalid MAC address values of length 3 bytes | invalid_mac_policy with 3-byte MAC addresses | dm_policy.m_policy should match invalid_mac_policy | Should Pass |
 * | 02               | Initialize dm_policy_t with invalid em_policy_t                   | dm_policy(invalid_mac_policy) | dm_policy.m_policy should match invalid_mac_policy | Should Pass |
 * | 03               | Assert equality of dm_policy.m_policy and invalid_mac_policy       | EXPECT_EQ(dm_policy.m_policy, invalid_mac_policy) | Assertion should be true              | Should Pass |
 */
TEST(dm_policy_t_Test, InitializeWithEmPolicyTObjectHavingInvalidMacAddressT) {
    std::cout << "Entering InitializeWithEmPolicyTObjectHavingInvalidMacAddressT" << std::endl;
    em_policy_t invalid_mac_policy {};
    memset(&invalid_mac_policy, 0, sizeof(em_policy_t));
    // Set invalid MAC addresses: first 3 bytes set, last 3 bytes zero
    for (int i = 0; i < EM_MAX_STA_PER_STEER_POLICY; ++i) {
        invalid_mac_policy.sta_mac[i][0] = 0xAA;
        invalid_mac_policy.sta_mac[i][1] = 0xBB;
        invalid_mac_policy.sta_mac[i][2] = 0xCC;
        invalid_mac_policy.sta_mac[i][3] = 0x00;
        invalid_mac_policy.sta_mac[i][4] = 0x00;
        invalid_mac_policy.sta_mac[i][5] = 0x00;
    }
    dm_policy_t dm_policy(invalid_mac_policy);
    // Check that dm_policy.m_policy.sta_mac matches invalid_mac_policy.sta_mac
    for (int i = 0; i < EM_MAX_STA_PER_STEER_POLICY; ++i) {
        for (int byte = 0; byte < 6; ++byte) {
            EXPECT_EQ(dm_policy.m_policy.sta_mac[i][byte], invalid_mac_policy.sta_mac[i][byte])
                << "Mismatch at sta_mac[" << i << "][" << byte << "]";
        }
    }
    std::cout << "Exiting InitializeWithEmPolicyTObjectHavingInvalidMacAddressT" << std::endl;
}

/**
* @brief Test the initialization of dm_policy_t with a valid em_policy_t object
*
* This test verifies that the dm_policy_t object is correctly initialized when provided with a valid em_policy_t object. The test ensures that the get_policy() method of dm_policy_t returns the same em_policy_t object that was used for initialization.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 009@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Initialize em_policy_t object with valid data | valid_policy.sta_traffic_stats = true, valid_policy.sta_link_metric = false, valid_policy.sta_status = true, valid_policy.independent_scan_report = false, valid_policy.profile_1_sta_disallowed = true, valid_policy.profile_2_sta_disallowed = false, valid_policy.num_sta = 5 | em_policy_t object should be initialized with valid data | Should be successful |
* | 02 | Initialize dm_policy_t with valid em_policy_t object | dm_policy = &valid_policy | dm_policy_t object should be initialized with valid em_policy_t object | Should Pass |
* | 03 | Verify the retrieved values using get_policy() method | dm_policy.get_policy() | Should return &valid_policy | Should Pass |
*/
TEST(dm_policy_t_Test, RetrieveValidEmPolicyObject) {
    std::cout << "Entering RetrieveValidEmPolicyObject" << std::endl;
    em_policy_t valid_policy {};
    memset(&valid_policy, 0, sizeof(em_policy_t));
    // Initialize valid_policy with valid values
    valid_policy.sta_traffic_stats = true;
    valid_policy.sta_link_metric = false;
    valid_policy.sta_status = true;
    valid_policy.independent_scan_report = false;
    valid_policy.profile_1_sta_disallowed = true;
    valid_policy.profile_2_sta_disallowed = false;
    valid_policy.num_sta = 5;    
    // Initialize valid_policy with valid data
    dm_policy_t dm_policy(&valid_policy);
    em_policy_t *retrieved_policy = dm_policy.get_policy();
    EXPECT_EQ(valid_policy.sta_traffic_stats, retrieved_policy->sta_traffic_stats);
    EXPECT_EQ(valid_policy.sta_link_metric, retrieved_policy->sta_link_metric);
    EXPECT_EQ(valid_policy.sta_status, retrieved_policy->sta_status);
    EXPECT_EQ(valid_policy.independent_scan_report, retrieved_policy->independent_scan_report);
    EXPECT_EQ(valid_policy.profile_1_sta_disallowed, retrieved_policy->profile_1_sta_disallowed);
    EXPECT_EQ(valid_policy.profile_2_sta_disallowed, retrieved_policy->profile_2_sta_disallowed);
    EXPECT_EQ(valid_policy.num_sta, retrieved_policy->num_sta);
    std::cout << "Exiting RetrieveValidEmPolicyObject" << std::endl;
}

/**
* @brief Test the initialization of dm_policy_t object with a null em_policy_t object
*
* This test checks the behavior of the dm_policy_t constructor when it is passed a null em_policy_t object. 
* It ensures that the dm_policy_t object correctly handles the null input. 
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Initialize dm_policy_t with null em_policy_t object | null_policy = nullptr | Should throw exception. |
*/

TEST(dm_policy_t_Test, InitializeWithNullEmPolicyTObject) {
    std::cout << "Entering InitializeWithNullEmPolicyTObject" << std::endl;

    em_policy_t* null_policy = nullptr;

    EXPECT_ANY_THROW({
        dm_policy_t dm_policy(null_policy);
        std::cout << "dm_policy_t initialized successfully with nullptr" << std::endl;
    });

    std::cout << "Exiting InitializeWithNullEmPolicyTObject" << std::endl;
}

/**
 * @brief Combined test for encoding functionality of dm_policy_t with multiple policy IDs and JSON inputs.
 *
 * This test iterates through a set of predefined policy IDs, validating that the encode function handles each one
 * correctly when provided with a valid or null JSON object.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 011@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Step | Description | Test Data | Expected Result | Notes |
 * | :--: | ----------- | --------- | ----------------|-------|
 * | 01 | Iterate through policy IDs and invoke encode with valid JSON | policy.encode(&obj, policy_id) | Should Pass | Covers all known policy IDs |
 * | 02 | Encode with null JSON and a valid policy ID | policy.encode(nullptr, policy_id) | Should Pass | Ensures graceful null handling |
 */
TEST(dm_policy_t_Test, EncodeWithVariousPolicyIDs) {
    std::cout << "Entering EncodeWithVariousPolicyIDs" << std::endl;
    dm_policy_t policy;
    em_policy_id_type_t test_cases[] = {
        em_policy_id_type_steering_local,
        em_policy_id_type_unknown,
        em_policy_id_type_steering_btm,
        em_policy_id_type_ap_metrics_rep,
        em_policy_id_type_channel_scan,
        em_policy_id_type_radio_metrics_rep,
        em_policy_id_type_backhaul_bss_config
    };
    for (auto policy_id : test_cases) {
        std::cout << "Testing encode with policy ID: " << static_cast<int>(policy_id) << std::endl;

        EXPECT_NO_THROW({
            cJSON* obj = cJSON_CreateObject();
            policy.encode(obj, policy_id);
	    cJSON_Delete(obj);
            std::cout << "encode() completed without exception for policy ID: " << static_cast<int>(policy_id) << std::endl;
        });
    }
    std::cout << "Exiting EncodeWithVariousPolicyIDs" << std::endl;
}

/**
* @brief Test the encoding function with a valid JSON object and an invalid policy ID.
*
* This test checks the behavior of the encode function when provided with a valid JSON object and an invalid policy ID. The objective is to ensure that the function handles invalid policy IDs gracefully without causing unexpected behavior or crashes.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 012@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create a valid JSON object and an invalid policy ID | obj = cJSON(), policy_id = -1 | Should be successful | |
* | 02| Call the encode function with the valid JSON object and invalid policy ID | policy.encode(&obj, static_cast<em_policy_id_type_t>(-1)) | Should throw an exception. | |
*/

TEST(dm_policy_t_Test, EncodeWithValidJSONObjectAndInvalidPolicyID) {
    std::cout << "Entering EncodeWithValidJSONObjectAndInvalidPolicyID" << std::endl;

    cJSON obj;
    dm_policy_t policy;

    EXPECT_ANY_THROW({
        policy.encode(&obj, static_cast<em_policy_id_type_t>(-1));
    });

    std::cout << "Exiting EncodeWithValidJSONObjectAndInvalidPolicyID" << std::endl;
}

/**
* @brief Test to verify the retrieval of policy after initialization
*
* This test verifies that the policy object is correctly initialized and that all its attributes can be retrieved accurately after initialization. This ensures that the initialization process sets all the necessary fields correctly and that the retrieval function works as expected.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 013@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Initialize policy object and set attributes | id.net_id = "TestNetID", id.dev_mac[0] = 0x01, id.radio_mac[0] = 0x02, id.type = em_policy_id_type_steering_local, num_sta = 5, sta_mac[0][0] = 0x03, policy = em_steering_policy_type_rcpi_allowed, util_threshold = 50, rcpi_threshold = 60, interval = 10, rcpi_hysteresis = 5, sta_traffic_stats = true, sta_link_metric = true, sta_status = true, managed_sta_marker = "TestMarker", independent_scan_report = true, profile_1_sta_disallowed = false, profile_2_sta_disallowed = false | Should be successful | Should Pass |
* | 02 | Retrieve policy object | None | Should be successful | Should Pass |
* | 03 | Verify id.net_id | id.net_id = "TestNetID" | Should be "TestNetID" | Should Pass |
* | 04 | Verify id.dev_mac[0] | id.dev_mac[0] = 0x01 | Should be 0x01 | Should Pass |
* | 05 | Verify id.radio_mac[0] | id.radio_mac[0] = 0x02 | Should be 0x02 | Should Pass |
* | 06 | Verify id.type | id.type = em_policy_id_type_steering_local | Should be em_policy_id_type_steering_local | Should Pass |
* | 07 | Verify num_sta | num_sta = 5 | Should be 5 | Should Pass |
* | 08 | Verify sta_mac[0][0] | sta_mac[0][0] = 0x03 | Should be 0x03 | Should Pass |
* | 09 | Verify policy | policy = em_steering_policy_type_rcpi_allowed | Should be em_steering_policy_type_rcpi_allowed | Should Pass |
* | 10 | Verify util_threshold | util_threshold = 50 | Should be 50 | Should Pass |
* | 11 | Verify rcpi_threshold | rcpi_threshold = 60 | Should be 60 | Should Pass |
* | 12 | Verify interval | interval = 10 | Should be 10 | Should Pass |
* | 13 | Verify rcpi_hysteresis | rcpi_hysteresis = 5 | Should be 5 | Should Pass |
* | 14 | Verify sta_traffic_stats | sta_traffic_stats = true | Should be true | Should Pass |
* | 15 | Verify sta_link_metric | sta_link_metric = true | Should be true | Should Pass |
* | 16 | Verify sta_status | sta_status = true | Should be true | Should Pass |
* | 17 | Verify managed_sta_marker | managed_sta_marker = "TestMarker" | Should be "TestMarker" | Should Pass |
* | 18 | Verify independent_scan_report | independent_scan_report = true | Should be true | Should Pass |
* | 19 | Verify profile_1_sta_disallowed | profile_1_sta_disallowed = false | Should be false | Should Pass |
* | 20 | Verify profile_2_sta_disallowed | profile_2_sta_disallowed = false | Should be false | Should Pass |
*/
TEST(dm_policy_t_Test, RetrievePolicyAfterInitialization) {
    std::cout << "Entering RetrievePolicyAfterInitialization" << std::endl;
    dm_policy_t policy_obj {};
    // Use snprintf to safely copy strings into char arrays
    snprintf(policy_obj.m_policy.id.net_id, sizeof(policy_obj.m_policy.id.net_id), "TestNetID");
    policy_obj.m_policy.id.dev_mac[0] = 0x01;
    policy_obj.m_policy.id.radio_mac[0] = 0x02;
    policy_obj.m_policy.id.type = em_policy_id_type_steering_local;
    policy_obj.m_policy.num_sta = 5;
    policy_obj.m_policy.sta_mac[0][0] = 0x03;
    policy_obj.m_policy.policy = em_steering_policy_type_rcpi_allowed;
    policy_obj.m_policy.util_threshold = 50;
    policy_obj.m_policy.rcpi_threshold = 60;
    policy_obj.m_policy.interval = 10;
    policy_obj.m_policy.rcpi_hysteresis = 5;
    policy_obj.m_policy.sta_traffic_stats = true;
    policy_obj.m_policy.sta_link_metric = true;
    policy_obj.m_policy.sta_status = true;
    snprintf(policy_obj.m_policy.managed_sta_marker, sizeof(policy_obj.m_policy.managed_sta_marker), "TestMarker");
    policy_obj.m_policy.independent_scan_report = true;
    policy_obj.m_policy.profile_1_sta_disallowed = false;
    policy_obj.m_policy.profile_2_sta_disallowed = false;
    em_policy_t* policy = policy_obj.get_policy();
    EXPECT_STREQ(policy->id.net_id, "TestNetID");
    EXPECT_EQ(policy->id.dev_mac[0], 0x01);
    EXPECT_EQ(policy->id.radio_mac[0], 0x02);
    EXPECT_EQ(policy->id.type, em_policy_id_type_steering_local);
    EXPECT_EQ(policy->num_sta, 5);
    EXPECT_EQ(policy->sta_mac[0][0], 0x03);
    EXPECT_EQ(policy->policy, em_steering_policy_type_rcpi_allowed);
    EXPECT_EQ(policy->util_threshold, 50);
    EXPECT_EQ(policy->rcpi_threshold, 60);
    EXPECT_EQ(policy->interval, 10);
    EXPECT_EQ(policy->rcpi_hysteresis, 5);
    EXPECT_TRUE(policy->sta_traffic_stats);
    EXPECT_TRUE(policy->sta_link_metric);
    EXPECT_TRUE(policy->sta_status);
    EXPECT_STREQ(policy->managed_sta_marker, "TestMarker");
    EXPECT_TRUE(policy->independent_scan_report);
    EXPECT_FALSE(policy->profile_1_sta_disallowed);
    EXPECT_FALSE(policy->profile_2_sta_disallowed);
    std::cout << "Exiting RetrievePolicyAfterInitialization" << std::endl;
}

/**
* @brief Test to verify the successful initialization of the policy structure
*
* This test checks if the policy structure is initialized correctly by invoking the init method of dm_policy_t class. It ensures that the init method returns 0 and the policy structure is set to its expected default state.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 014@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create an instance of dm_policy_t and call init method | instance = new dm_policy_t(), policy.init() | result = 0 | Should Pass |
* | 02| Verify the policy structure is initialized to default values | memcmp(&policy.m_policy, &expected_policy, sizeof(em_policy_t)) | result = 0 | Should Pass |
*/
TEST(dm_policy_t_Test, InitializePolicyStructureSuccessfully) {
    std::cout << "Entering InitializePolicyStructureSuccessfully" << std::endl;
    dm_policy_t policy;
    int result = policy.init();
    EXPECT_EQ(result, 0);
    em_policy_t expected_policy = {};
    EXPECT_EQ(memcmp(&policy.m_policy, &expected_policy, sizeof(em_policy_t)), 0);
    std::cout << "Exiting InitializePolicyStructureSuccessfully" << std::endl;
}

/**
* @brief Test the assignment operator of dm_policy_t class with maximum and minimum values
*
* This test verifies that the assignment operator of the dm_policy_t class correctly assigns the values from one object to another, even when the values are at their maximum and minimum limits.@n
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 015@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Create obj1 and set max/min values | obj1.m_policy.num_sta = UINT_MAX, obj1.m_policy.util_threshold = USHRT_MAX, obj1.m_policy.rcpi_threshold = SHRT_MIN, obj1.m_policy.interval = USHRT_MAX, obj1.m_policy.rcpi_hysteresis = USHRT_MIN, obj1.m_policy.sta_traffic_stats = true, obj1.m_policy.sta_link_metric = false, obj1.m_policy.sta_status = true, obj1.m_policy.independent_scan_report = false, obj1.m_policy.profile_1_sta_disallowed = true, obj1.m_policy.profile_2_sta_disallowed = false | Values set successfully | Should be successful |
* | 02 | Assign obj1 to obj2 | obj2 = obj1 | Assignment successful | Should be successful |
* | 03 | Verify num_sta | obj1.m_policy.num_sta, obj2.m_policy.num_sta | EXPECT_EQ(obj1.m_policy.num_sta, obj2.m_policy.num_sta) | Should Pass |
* | 04 | Verify util_threshold | obj1.m_policy.util_threshold, obj2.m_policy.util_threshold | EXPECT_EQ(obj1.m_policy.util_threshold, obj2.m_policy.util_threshold) | Should Pass |
* | 05 | Verify rcpi_threshold | obj1.m_policy.rcpi_threshold, obj2.m_policy.rcpi_threshold | EXPECT_EQ(obj1.m_policy.rcpi_threshold, obj2.m_policy.rcpi_threshold) | Should Pass |
* | 06 | Verify interval | obj1.m_policy.interval, obj2.m_policy.interval | EXPECT_EQ(obj1.m_policy.interval, obj2.m_policy.interval) | Should Pass |
* | 07 | Verify rcpi_hysteresis | obj1.m_policy.rcpi_hysteresis, obj2.m_policy.rcpi_hysteresis | EXPECT_EQ(obj1.m_policy.rcpi_hysteresis, obj2.m_policy.rcpi_hysteresis) | Should Pass |
* | 08 | Verify sta_traffic_stats | obj1.m_policy.sta_traffic_stats, obj2.m_policy.sta_traffic_stats | EXPECT_EQ(obj1.m_policy.sta_traffic_stats, obj2.m_policy.sta_traffic_stats) | Should Pass |
* | 09 | Verify sta_link_metric | obj1.m_policy.sta_link_metric, obj2.m_policy.sta_link_metric | EXPECT_EQ(obj1.m_policy.sta_link_metric, obj2.m_policy.sta_link_metric) | Should Pass |
* | 10 | Verify sta_status | obj1.m_policy.sta_status, obj2.m_policy.sta_status | EXPECT_EQ(obj1.m_policy.sta_status, obj2.m_policy.sta_status) | Should Pass |
* | 11 | Verify independent_scan_report | obj1.m_policy.independent_scan_report, obj2.m_policy.independent_scan_report | EXPECT_EQ(obj1.m_policy.independent_scan_report, obj2.m_policy.independent_scan_report) | Should Pass |
* | 12 | Verify profile_1_sta_disallowed | obj1.m_policy.profile_1_sta_disallowed, obj2.m_policy.profile_1_sta_disallowed | EXPECT_EQ(obj1.m_policy.profile_1_sta_disallowed, obj2.m_policy.profile_1_sta_disallowed) | Should Pass |
* | 13 | Verify profile_2_sta_disallowed | obj1.m_policy.profile_2_sta_disallowed, obj2.m_policy.profile_2_sta_disallowed | EXPECT_EQ(obj1.m_policy.profile_2_sta_disallowed, obj2.m_policy.profile_2_sta_disallowed) | Should Pass |
*/
TEST(dm_policy_t_Test, AssigningDmPolicyObjectWithMaxMinValues) {
    std::cout << "Entering AssigningDmPolicyObjectWithMaxMinValues test";
    dm_policy_t obj1 {};
    obj1.m_policy.num_sta = UINT_MAX;
    obj1.m_policy.util_threshold = USHRT_MAX;
    obj1.m_policy.rcpi_threshold = 0;
    obj1.m_policy.interval = USHRT_MAX;
    obj1.m_policy.rcpi_hysteresis = 0;
    obj1.m_policy.sta_traffic_stats = true;
    obj1.m_policy.sta_link_metric = false;
    obj1.m_policy.sta_status = true;
    obj1.m_policy.independent_scan_report = false;
    obj1.m_policy.profile_1_sta_disallowed = true;
    obj1.m_policy.profile_2_sta_disallowed = false;
    dm_policy_t obj2;
    obj2 = obj1;
    EXPECT_EQ(obj1.m_policy.num_sta, obj2.m_policy.num_sta);
    EXPECT_EQ(obj1.m_policy.util_threshold, obj2.m_policy.util_threshold);
    EXPECT_EQ(obj1.m_policy.rcpi_threshold, obj2.m_policy.rcpi_threshold);
    EXPECT_EQ(obj1.m_policy.interval, obj2.m_policy.interval);
    EXPECT_EQ(obj1.m_policy.rcpi_hysteresis, obj2.m_policy.rcpi_hysteresis);
    EXPECT_EQ(obj1.m_policy.sta_traffic_stats, obj2.m_policy.sta_traffic_stats);
    EXPECT_EQ(obj1.m_policy.sta_link_metric, obj2.m_policy.sta_link_metric);
    EXPECT_EQ(obj1.m_policy.sta_status, obj2.m_policy.sta_status);
    EXPECT_EQ(obj1.m_policy.independent_scan_report, obj2.m_policy.independent_scan_report);
    EXPECT_EQ(obj1.m_policy.profile_1_sta_disallowed, obj2.m_policy.profile_1_sta_disallowed);
    EXPECT_EQ(obj1.m_policy.profile_2_sta_disallowed, obj2.m_policy.profile_2_sta_disallowed);
    std::cout << "Exiting AssigningDmPolicyObjectWithMaxMinValues test";
}

/**
* @brief Test to compare two identical dm_policy_t objects
*
* This test verifies that two default-constructed dm_policy_t objects are considered equal by the equality operator. This is important to ensure that the equality operator is correctly implemented for the dm_policy_t class.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 016@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create two dm_policy_t objects and assign same values for few fields | m_policy.sta_traffic_stats = true, m_policy.sta_link_metric = false,  m_policy.sta_status = true, m_policy.independent_scan_report = false, m_policy.profile_1_sta_disallowed = true, m_policy.profile_2_sta_disallowed = false | Objects should be created successfully | Should be successful |
* | 02| Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_TRUE should pass | Should Pass |
*/
TEST(dm_policy_t_Test, CompareIdenticalObjects) {
    std::cout << "Entering CompareIdenticalObjects test";
    dm_policy_t obj1 {}, obj2 {};
    obj1.m_policy.sta_traffic_stats = obj2.m_policy.sta_traffic_stats = true;
    obj1.m_policy.sta_link_metric = obj2.m_policy.sta_link_metric = false;
    obj1.m_policy.sta_status = obj2.m_policy.sta_status = true;
    obj1.m_policy.independent_scan_report = obj2.m_policy.independent_scan_report = false;
    obj1.m_policy.profile_1_sta_disallowed = obj2.m_policy.profile_1_sta_disallowed = true;
    obj1.m_policy.profile_2_sta_disallowed = obj2.m_policy.profile_2_sta_disallowed = false;
    EXPECT_TRUE(obj1 == obj2);
    std::cout << "Exiting CompareIdenticalObjects test";
}

/**
* @brief Test to compare two dm_policy_t objects with different net_id values
*
* This test verifies that two dm_policy_t objects with different net_id values are not considered equal.@n
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 017@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Create two dm_policy_t objects | obj1, obj2 | Objects created successfully | Should be successful |
* | 02 | Set net_id of obj1 to "Network1" | obj1.m_policy.id.net_id = "Network1" | net_id set successfully | Should be successful |
* | 03 | Set net_id of obj2 to "Network2" | obj2.m_policy.id.net_id = "Network2" | net_id set successfully | Should be successful |
* | 04 | Compare obj1 and obj2 for equality | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_policy_t_Test, CompareDifferentNetId) {
    std::cout << "Entering CompareDifferentNetId test";
    dm_policy_t obj1 {};
    dm_policy_t obj2 {};
    strcpy(obj1.m_policy.id.net_id, "Network1");
    strcpy(obj2.m_policy.id.net_id, "Network2");
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentNetId test";
}

/**
* @brief Test to compare device MAC addresses of two dm_policy_t objects
*
* This test verifies that two dm_policy_t objects with different device MAC addresses are not considered equal.@n
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
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Initialize dm_policy_t objects | obj1, obj2 | Objects initialized | Should be successful |
* | 02 | Set MAC address for obj1 | obj1.m_policy.id.dev_mac = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55} | MAC address set | Should be successful |
* | 03 | Set MAC address for obj2 | obj2.m_policy.id.dev_mac = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB} | MAC address set | Should be successful |
* | 04 | Compare obj1 and obj2 | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_policy_t_Test, CompareDifferentDevMac) {
    std::cout << "Entering CompareDifferentDevMac test" << std::endl;
    dm_policy_t obj1 {};
    dm_policy_t obj2 {};
    unsigned char mac1[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    unsigned char mac2[6] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
    memcpy(obj1.m_policy.id.dev_mac, mac1, sizeof(mac1));
    memcpy(obj2.m_policy.id.dev_mac, mac2, sizeof(mac2));
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentDevMac test" << std::endl;
}

/**
* @brief Test to compare two dm_policy_t objects with different radio_mac values
*
* This test verifies that two dm_policy_t objects with different radio_mac values are not considered equal.@n
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 019@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Initialize dm_policy_t objects | obj1, obj2 | Objects initialized | Should be successful |
* | 02 | Set radio_mac for obj1 | obj1.m_policy.id.radio_mac = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55} | radio_mac set | Should be successful |
* | 03 | Set radio_mac for obj2 | obj2.m_policy.id.radio_mac = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB} | radio_mac set | Should be successful |
* | 04 | Compare obj1 and obj2 | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_policy_t_Test, CompareDifferentRadioMac) {
    std::cout << "Entering CompareDifferentRadioMac test";
    dm_policy_t obj1 {};
    dm_policy_t obj2 {};
    unsigned char mac1[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    unsigned char mac2[6] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
    memcpy(obj1.m_policy.id.radio_mac, mac1, sizeof(mac1));
    memcpy(obj2.m_policy.id.radio_mac, mac2, sizeof(mac2));
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentRadioMac test";
}

/**
* @brief Test to compare two dm_policy_t objects with different policy id types
*
* This test verifies that two dm_policy_t objects with different policy id types are not considered equal.@n
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 020@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Initialize dm_policy_t objects | obj1.m_policy.id.type = em_policy_id_type_steering_local, obj2.m_policy.id.type = em_policy_id_type_steering_btm | Objects initialized | Should be successful |
* | 02 | Compare the two objects | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_policy_t_Test, CompareDifferentType) {
    std::cout << "Entering CompareDifferentType test";
    dm_policy_t obj1 {};
    dm_policy_t obj2 {};
    obj1.m_policy.id.type = em_policy_id_type_steering_local;
    obj2.m_policy.id.type = em_policy_id_type_steering_btm;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentType test";
}

/**
* @brief Test to compare two dm_policy_t objects with different num_sta values
*
* This test verifies that two dm_policy_t objects with different num_sta values are not considered equal.@n
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 021@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Initialize dm_policy_t objects | obj1.m_policy.num_sta = 5, obj2.m_policy.num_sta = 10 | Objects initialized | Should be successful |
* | 02 | Compare obj1 and obj2 | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_policy_t_Test, CompareDifferentNumSta) {
    std::cout << "Entering CompareDifferentNumSta test";
    dm_policy_t obj1 {};
    dm_policy_t obj2 {};
    obj1.m_policy.num_sta = 5;
    obj2.m_policy.num_sta = 10;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentNumSta test";
}

/**
* @brief Test to compare different STA MAC addresses in dm_policy_t objects
*
* This test verifies that two dm_policy_t objects with different STA MAC addresses are not considered equal.@n
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 022@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Initialize two dm_policy_t objects with different STA MAC addresses | obj1.m_policy.sta_mac[0] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, obj2.m_policy.sta_mac[0] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB} | Objects should not be equal | Should Pass |
* | 02 | Compare the two objects using EXPECT_FALSE | obj1 == obj2 | EXPECT_FALSE should pass | Should Pass |
*/
TEST(dm_policy_t_Test, CompareDifferentStaMac) {
    std::cout << "Entering CompareDifferentStaMac test";
    dm_policy_t obj1 {};
    dm_policy_t obj2 {};
    unsigned char mac1[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    unsigned char mac2[6] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
    memcpy(obj1.m_policy.sta_mac[0], mac1, sizeof(mac1));
    memcpy(obj2.m_policy.sta_mac[0], mac2, sizeof(mac2));
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentStaMac test";
}

/**
* @brief Test to compare two different policies in dm_policy_t objects
*
* This test checks the equality operator for dm_policy_t objects with different policy types. It ensures that the equality operator correctly identifies that two objects with different policies are not equal.@n
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 023@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Initialize two dm_policy_t objects with different policies | obj1.m_policy.policy = em_steering_policy_type_disallowed, obj2.m_policy.policy = em_steering_policy_type_rcpi_mandated | Objects should be initialized with different policies | Should be successful |
* | 02 | Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_policy_t_Test, CompareDifferentPolicy) {
    std::cout << "Entering CompareDifferentPolicy test";
    dm_policy_t obj1 {};
    dm_policy_t obj2 {};
    obj1.m_policy.policy = em_steering_policy_type_disallowed;
    obj2.m_policy.policy = em_steering_policy_type_rcpi_mandated;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentPolicy test";
}

/**
* @brief Test to compare different utilization thresholds in dm_policy_t objects
*
* This test verifies that two dm_policy_t objects with different utilization thresholds are not considered equal.@n
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 024@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Create two dm_policy_t objects with different utilization thresholds | obj1.m_policy.util_threshold = 50, obj2.m_policy.util_threshold = 75 | Objects should not be equal | Should Pass |
* | 02 | Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_policy_t_Test, CompareDifferentUtilThreshold) {
    std::cout << "Entering CompareDifferentUtilThreshold test";
    dm_policy_t obj1 {};
    dm_policy_t obj2 {};
    obj1.m_policy.util_threshold = 50;
    obj2.m_policy.util_threshold = 75;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentUtilThreshold test";
}

/**
* @brief Test to compare different RCPI thresholds in dm_policy_t objects
*
* This test verifies that two dm_policy_t objects with different RCPI threshold values are not considered equal.@n
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 025@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Initialize dm_policy_t objects | obj1.m_policy.rcpi_threshold = 30, obj2.m_policy.rcpi_threshold = 60 | Objects initialized | Should be successful |
* | 02 | Compare dm_policy_t objects with different RCPI thresholds | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_policy_t_Test, CompareDifferentRcpiThreshold) {
    std::cout << "Entering CompareDifferentRcpiThreshold test";
    dm_policy_t obj1 {};
    dm_policy_t obj2 {};
    obj1.m_policy.rcpi_threshold = 30;
    obj2.m_policy.rcpi_threshold = 60;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentRcpiThreshold test";
}

/**
* @brief Test to compare two dm_policy_t objects with different intervals
*
* This test verifies that two dm_policy_t objects with different interval values are not considered equal.@n
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 026@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Create two dm_policy_t objects with different intervals | obj1.m_policy.interval = 100, obj2.m_policy.interval = 200 | Objects should not be equal | Should Pass |
* | 02 | Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_policy_t_Test, CompareDifferentInterval) {
    std::cout << "Entering CompareDifferentInterval test";
    dm_policy_t obj1 {};
    dm_policy_t obj2 {};
    obj1.m_policy.interval = 100;
    obj2.m_policy.interval = 200;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentInterval test";
}

/**
* @brief Test to compare different RCPI hysteresis values in dm_policy_t objects
*
* This test checks the equality operator for dm_policy_t objects with different RCPI hysteresis values. 
* It ensures that the equality operator correctly identifies objects with different RCPI hysteresis values as not equal.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 027@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Initialize dm_policy_t objects | obj1.m_policy.rcpi_hysteresis = 10, obj2.m_policy.rcpi_hysteresis = 20 | Objects initialized | Should be successful |
* | 02 | Compare objects with different RCPI hysteresis | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_policy_t_Test, CompareDifferentRcpiHysteresis) {
    std::cout << "Entering CompareDifferentRcpiHysteresis test";
    dm_policy_t obj1 {};
    dm_policy_t obj2 {};
    obj1.m_policy.rcpi_hysteresis = 10;
    obj2.m_policy.rcpi_hysteresis = 20;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentRcpiHysteresis test";
}

/**
* @brief Test to compare different STA traffic stats in dm_policy_t objects
*
* This test checks the equality operator for dm_policy_t objects with different STA traffic stats values.@n
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 028@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Create two dm_policy_t objects with different sta_traffic_stats values | obj1.m_policy.sta_traffic_stats = true, obj2.m_policy.sta_traffic_stats = false | Objects should not be equal | Should Pass |
* | 02 | Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_policy_t_Test, CompareDifferentStaTrafficStats) {
    std::cout << "Entering CompareDifferentStaTrafficStats test";
    dm_policy_t obj1 {};
    dm_policy_t obj2 {};
    obj1.m_policy.sta_traffic_stats = true;
    obj2.m_policy.sta_traffic_stats = false;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentStaTrafficStats test";
}

/**
* @brief Test to compare different STA link metrics in dm_policy_t objects
*
* This test verifies that two dm_policy_t objects with different sta_link_metric values are not considered equal.@n
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
* | 01 | Initialize dm_policy_t objects | obj1.m_policy.sta_link_metric = true, obj2.m_policy.sta_link_metric = false | Objects initialized | Should be successful |
* | 02 | Compare dm_policy_t objects with different sta_link_metric values | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_policy_t_Test, CompareDifferentStaLinkMetric) {
    std::cout << "Entering CompareDifferentStaLinkMetric test";
    dm_policy_t obj1 {};
    dm_policy_t obj2 {};
    obj1.m_policy.sta_link_metric = true;
    obj2.m_policy.sta_link_metric = false;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentStaLinkMetric test";
}

/**
* @brief Test to compare different STA status in dm_policy_t objects
*
* This test checks the equality operator for dm_policy_t objects with different STA status values.@n
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
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Initialize dm_policy_t objects | obj1.m_policy.sta_status = true, obj2.m_policy.sta_status = false | Objects initialized | Should be successful |
* | 02 | Compare objects with different STA status | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_policy_t_Test, CompareDifferentStaStatus) {
    std::cout << "Entering CompareDifferentStaStatus test";
    dm_policy_t obj1 {};
    dm_policy_t obj2 {};
    obj1.m_policy.sta_status = true;
    obj2.m_policy.sta_status = false;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentStaStatus test";
}

/**
* @brief Test to compare different managed_sta_marker values in dm_policy_t objects
*
* This test verifies that two dm_policy_t objects with different managed_sta_marker values are not considered equal.@n
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
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Create two dm_policy_t objects | obj1, obj2 | Objects created successfully | Should be successful |
* | 02 | Set managed_sta_marker for obj1 | obj1.m_policy.managed_sta_marker = "Marker1" | Value set successfully | Should be successful |
* | 03 | Set managed_sta_marker for obj2 | obj2.m_policy.managed_sta_marker = "Marker2" | Value set successfully | Should be successful |
* | 04 | Compare obj1 and obj2 | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_policy_t_Test, CompareDifferentManagedStaMarker) {
    std::cout << "Entering CompareDifferentManagedStaMarker test";
    dm_policy_t obj1 {};
    dm_policy_t obj2 {};
    strcpy(obj1.m_policy.managed_sta_marker, "Marker1");
    strcpy(obj2.m_policy.managed_sta_marker, "Marker2");
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentManagedStaMarker test";
}

/**
* @brief Test to compare two dm_policy_t objects with different independent_scan_report values
*
* This test verifies that two dm_policy_t objects with different independent_scan_report values are not considered equal.@n
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 032@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Create two dm_policy_t objects | obj1.m_policy.independent_scan_report = true, obj2.m_policy.independent_scan_report = false | Objects created successfully | Should be successful |
* | 02 | Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_policy_t_Test, CompareDifferentIndependentScanReport) {
    std::cout << "Entering CompareDifferentIndependentScanReport test";
    dm_policy_t obj1 {};
    dm_policy_t obj2 {};
    obj1.m_policy.independent_scan_report = true;
    obj2.m_policy.independent_scan_report = false;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentIndependentScanReport test";
}

/**
* @brief Test to compare two dm_policy_t objects with different profile_1_sta_disallowed values
*
* This test checks the equality operator for dm_policy_t objects when the profile_1_sta_disallowed attribute is different between the two objects. This ensures that the equality operator correctly identifies objects with different profile_1_sta_disallowed values as not equal.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 033@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Initialize two dm_policy_t objects with different profile_1_sta_disallowed values | obj1.m_policy.profile_1_sta_disallowed = true, obj2.m_policy.profile_1_sta_disallowed = false | Objects should not be equal | Should Pass |
* | 02| Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_policy_t_Test, CompareDifferentProfile1StaDisallowed) {
    std::cout << "Entering CompareDifferentProfile1StaDisallowed test";
    dm_policy_t obj1 {};
    dm_policy_t obj2 {};
    obj1.m_policy.profile_1_sta_disallowed = true;
    obj2.m_policy.profile_1_sta_disallowed = false;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentProfile1StaDisallowed test";
}

/**
* @brief Test to compare two dm_policy_t objects with different profile_2_sta_disallowed values
*
* This test checks the equality operator for dm_policy_t objects when the profile_2_sta_disallowed attribute is different between the two objects. This ensures that the equality operator correctly identifies objects with different profile_2_sta_disallowed values as not equal.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 034@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Initialize dm_policy_t objects | obj1.m_policy.profile_2_sta_disallowed = true, obj2.m_policy.profile_2_sta_disallowed = false | Objects initialized | Should be successful |
* | 02 | Compare objects with different profile_2_sta_disallowed values | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_policy_t_Test, CompareDifferentProfile2StaDisallowed) {
    std::cout << "Entering CompareDifferentProfile2StaDisallowed test";
    dm_policy_t obj1 {};
    dm_policy_t obj2 {};
    obj1.m_policy.profile_2_sta_disallowed = true;
    obj2.m_policy.profile_2_sta_disallowed = false;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentProfile2StaDisallowed test";
}

/**
* @brief Test the parsing of a valid key with correct MAC address format
*
* This test verifies that the function `parse_dev_radio_mac_from_key` correctly parses a valid key containing a MAC address in the correct format. The test ensures that the function returns a success code and that the parsed MAC address matches the expected values.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 035@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Call parse_dev_radio_mac_from_key with valid key | key = "device1@00:11:22:33:44:55@01:23:45:67:89:AB@2", id | result = 0, id.radio_mac = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB} | Should Pass |
*/
TEST(dm_policy_t_Test, ValidKeyWithCorrectMACAddressFormat) {
    std::cout << "Entering ValidKeyWithCorrectMACAddressFormat" << std::endl;
    const char *key = "device1@00:11:22:33:44:55@01:23:45:67:89:AB@2";
    em_policy_id_t id;
    int result = dm_policy_t::parse_dev_radio_mac_from_key(key, &id);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(id.radio_mac[0], 0x01);
    EXPECT_EQ(id.radio_mac[1], 0x23);
    EXPECT_EQ(id.radio_mac[2], 0x45);
    EXPECT_EQ(id.radio_mac[3], 0x67);
    EXPECT_EQ(id.radio_mac[4], 0x89);
    EXPECT_EQ(id.radio_mac[5], 0xAB);
    std::cout << "Exiting ValidKeyWithCorrectMACAddressFormat" << std::endl;
}

/**
* @brief Test to verify the behavior of parse_dev_radio_mac_from_key function when the key does not contain a MAC address.
*
* This test checks the parse_dev_radio_mac_from_key function to ensure it correctly handles a key that does not include a MAC address. The function is expected to return an error code in this scenario.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 036@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Call parse_dev_radio_mac_from_key with a key that does not contain a MAC address | key = "device1@@@2", id = uninitialized | result = -1, EXPECT_EQ(result, -1) | Should Fail |
*/
TEST(dm_policy_t_Test, KeyWithoutMACAddress) {
    std::cout << "Entering KeyWithoutMACAddress" << std::endl;
    const char *key = "device1@@@2";
    em_policy_id_t id;
    int result = dm_policy_t::parse_dev_radio_mac_from_key(key, &id);
    EXPECT_EQ(result, -1);
    std::cout << "Exiting KeyWithoutMACAddress" << std::endl;
}

/**
* @brief Test to validate the behavior of the function when provided with an invalid MAC address format.
*
* This test checks the function `parse_dev_radio_mac_from_key` to ensure it correctly identifies and handles an invalid MAC address format in the key string. The function is expected to return an error code when the MAC address format is incorrect.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 037@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Call parse_dev_radio_mac_from_key with invalid MAC address format | key = "device1@01:23:45:67:89:GH@01:23:ZZ:99:AA:BB@2", id = (uninitialized) | result = -1, EXPECT_EQ(result, -1) | Should Fail |
*/
TEST(dm_policy_t_Test, KeyWithInvalidMACAddressFormat) {
    std::cout << "Entering KeyWithInvalidMACAddressFormat" << std::endl;
    const char *key = "device1@01:23:45:67:89:GH@01:23:ZZ:99:AA:BB@2";
    em_policy_id_t id;
    int result = dm_policy_t::parse_dev_radio_mac_from_key(key, &id);
    EXPECT_EQ(result, -1);
    std::cout << "Exiting KeyWithInvalidMACAddressFormat" << std::endl;
}

/**
* @brief Test to verify the behavior of parse_dev_radio_mac_from_key when a null key is provided.
*
* This test checks the function parse_dev_radio_mac_from_key with a null key input to ensure that it handles invalid input correctly by returning an error code.@n
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 038@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Call parse_dev_radio_mac_from_key with null key | key = nullptr, id = uninitialized | result = -1, EXPECT_EQ(result, -1) | Should Fail |
*/

TEST(dm_policy_t_Test, NullKeyInput) {
    std::cout << "Entering NullKeyInput" << std::endl;
    const char *key = nullptr;
    em_policy_id_t id;
    int result = dm_policy_t::parse_dev_radio_mac_from_key(key, &id);
    EXPECT_EQ(result, -1);
    std::cout << "Exiting NullKeyInput" << std::endl;
}

/**
* @brief Test to verify the behavior of parse_dev_radio_mac_from_key when a null ID is provided.
*
* This test checks the function parse_dev_radio_mac_from_key with a null ID input to ensure that it handles the null pointer correctly and returns the expected error code.@n
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 039@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Call parse_dev_radio_mac_from_key with a null ID | key = "device1@00:11:22:33:44:55@01:23:45:67:89:AB@2", id = nullptr | result = -1, EXPECT_EQ(result, -1) | Should Fail |
*/

TEST(dm_policy_t_Test, NullIdInput) {
    std::cout << "Entering NullIdInput" << std::endl;
    const char *key = "device1@00:11:22:33:44:55@01:23:45:67:89:AB@2";
    em_policy_id_t *id = nullptr;
    int result = dm_policy_t::parse_dev_radio_mac_from_key(key, id);
    EXPECT_EQ(result, -1);
    std::cout << "Exiting NullIdInput" << std::endl;
}

/**
* @brief Test to verify the behavior of parse_dev_radio_mac_from_key with an empty key string.
*
* This test checks the function parse_dev_radio_mac_from_key when provided with an empty key string. 
* The function is expected to return an error code (-1) indicating that the key is invalid.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 040@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Call parse_dev_radio_mac_from_key with an empty key string | key = "", id = uninitialized | result = -1, EXPECT_EQ(result, -1) | Should Fail |
*/
TEST(dm_policy_t_Test, EmptyKeyString) {
    std::cout << "Entering EmptyKeyString" << std::endl;
    const char *key = "";
    em_policy_id_t id;
    int result = dm_policy_t::parse_dev_radio_mac_from_key(key, &id);
    EXPECT_EQ(result, -1);
    std::cout << "Exiting EmptyKeyString" << std::endl;
}

/**
 * @brief Validate that the default constructor of dm_policy_t creates an object without throwing an exception.
 *
 * Validate that the default constructor of dm_policy_t initializes the object , without throwing any exceptions.
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
 * | 01 | Invoke the default constructor of dm_policy_t to create an object and verify no exceptions are thrown. | Constructor invoked with no parameters | Object creation is successful with no exceptions (EXPECT_NO_THROW) | Should Pass |
 * | 02 | Log messages for constructor invocation and internal state initialization. | Console output: "dm_policy_t object created using default constructor." | Expected log messages are printed to indicate successful object creation and initialization | Should be successful |
 */
TEST(dm_policy_t_Test, dm_policy_t_defaultConstructor_success) {
    std::cout << "Entering dm_policy_t::dm_policy_t()_start test" << std::endl;

    std::cout << "Invoking default constructor for dm_policy_t" << std::endl;
    EXPECT_NO_THROW({
        dm_policy_t obj;
        std::cout << "dm_policy_t object created using default constructor." << std::endl;
    });

    std::cout << "Exiting dm_policy_t::dm_policy_t()_end test" << std::endl;
}

/**
 * @brief Validate that the destructor of a default constructed dm_policy_t object is invoked without throwing exceptions.
 *
 * This test verifies that when a dm_policy_t object is created using the default constructor and then goes out of scope, its destructor is called properly without any exceptions.
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
 * | Variation / Step | Description                                                                                     | Test Data                                                              | Expected Result                                                             | Notes        |
 * | :--------------: | ----------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- | --------------------------------------------------------------------------- | ------------ |
 * | 01               | Create a default dm_policy_t object within a scoped block to trigger the destructor upon scope exit. | dm_policy_t object = default constructed (no input arguments provided) | Destructor is invoked without throwing any exception as the object goes out of scope. | Should Pass  |
 */
TEST(dm_policy_t_Test, destructor_default) {
    std::cout << "Entering destructor_default test" << std::endl;
    EXPECT_NO_THROW({
        std::cout << "Creating a default constructed dm_policy_t object." << std::endl;
        {
            dm_policy_t defaultObj;
            std::cout << "dm_policy_t object created " << std::endl;
            std::cout << "About to exit inner scope to invoke destructor of dm_policy_t." << std::endl;
        }
        std::cout << "dm_policy_t destructor has been invoked as object went out of scope." << std::endl;
    });
    std::cout << "Exiting destructor_default test" << std::endl;
}
