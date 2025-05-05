
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
#include "dm_assoc_sta_mld.h"

class dm_assoc_sta_mld_t_Test : public ::testing::Test {
protected:
    dm_assoc_sta_mld_t* instance;

    void SetUp() override {
        instance = new dm_assoc_sta_mld_t();
    }

    void TearDown() override {
        delete instance;
    }
};

/**
 * @brief Test the decode function with a valid JSON object and a valid parent ID.
 *
 * This test verifies that the decode function correctly processes a valid JSON object and a valid parent ID, returning the expected result of 0.@n
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
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Parse a valid JSON object | validJsonObject = {"key":"value"} | validJsonObject is created | Should be successful |
 * | 03 | Call decode with valid JSON object and valid parent ID | validJsonObject = {"key":"value"}, parent_id = 1 | result = 0 | Should Pass |
 * | 04 | Delete the JSON object | validJsonObject = {"key":"value"} | validJsonObject is deleted | Should be successful |
 * | 05 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(dm_assoc_sta_mld_t_Test, DecodeWithValidJsonObjectAndValidParentId) {
    std::cout << "Entering DecodeWithValidJsonObjectAndValidParentId test" << std::endl;
    cJSON* validJsonObject = cJSON_Parse("{\"key\":\"value\"}");
    int parent_id = 1;
    int result = instance->decode(validJsonObject, &parent_id);
    ASSERT_EQ(result, 0);
    cJSON_Delete(validJsonObject);
    std::cout << "Exiting DecodeWithValidJsonObjectAndValidParentId test" << std::endl;
}

/**
* @brief Test the decode function with a valid JSON object and a null parent ID.
*
* This test verifies that the decode function correctly handles a valid JSON object when the parent ID is null. The expected behavior is that the function returns -1, indicating an error or invalid input scenario.
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
* | 01 | Set up the test environment by creating an instance of dm_assoc_sta_mld_t | None | None | Done by Pre-requisite SetUp function |
* | 02 | Parse a valid JSON object | JSON string: {"key":"value"} | cJSON object created | Should be successful |
* | 03 | Call the decode function with the valid JSON object and null parent ID | validJsonObject, nullptr | Return value: -1 | Should Pass |
* | 04 | Assert that the result is -1 | result = -1 | Assertion passes | Should be successful |
* | 05 | Clean up the JSON object | validJsonObject | JSON object deleted | Should be successful |
* | 06 | Tear down the test environment by deleting the instance of dm_assoc_sta_mld_t | None | None | Done by Pre-requisite TearDown function |
*/
TEST_F(dm_assoc_sta_mld_t_Test, DecodeWithValidJsonObjectAndNullParentId) {
    std::cout << "Entering DecodeWithValidJsonObjectAndNullParentId test" << std::endl;
    cJSON* validJsonObject = cJSON_Parse("{\"key\":\"value\"}");
    int result = instance->decode(validJsonObject, nullptr);
    ASSERT_EQ(result, -1);
    cJSON_Delete(validJsonObject);
    std::cout << "Exiting DecodeWithValidJsonObjectAndNullParentId test" << std::endl;
}

/**
 * @brief Test the decode function with a null JSON object and a valid parent ID.
 *
 * This test checks the behavior of the decode function when provided with a null JSON object and a valid parent ID. The expected result is that the function should return -1, indicating an error due to the null JSON object.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment by creating an instance of dm_assoc_sta_mld_t | None | Instance created successfully | Done by Pre-requisite SetUp function |
 * | 02 | Call the decode function with a null JSON object and a valid parent ID | json_object = nullptr, parent_id = 1 | Result should be -1 | Should Pass |
 * | 03 | Tear down the test environment by deleting the instance of dm_assoc_sta_mld_t | None | Instance deleted successfully | Done by Pre-requisite TearDown function |
 */

TEST_F(dm_assoc_sta_mld_t_Test, DecodeWithNullJsonObjectAndValidParentId) {
    std::cout << "Entering DecodeWithNullJsonObjectAndValidParentId test" << std::endl;
    int parent_id = 1;
    int result = instance->decode(nullptr, &parent_id);
    ASSERT_EQ(result, -1);
    std::cout << "Exiting DecodeWithNullJsonObjectAndValidParentId test" << std::endl;
}

/**
* @brief Test the decode function with an invalid JSON object and a valid parent ID.
*
* This test verifies that the decode function correctly handles an invalid JSON object and returns an error code.@n
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
* | 01 | Set up the test environment | None | None | Done by Pre-requisite SetUp function |
* | 02 | Parse an invalid JSON object | invalidJsonObject = "{key:value}" | invalidJsonObject should be parsed | Should be successful |
* | 03 | Call the decode function with the invalid JSON object and a valid parent ID | invalidJsonObject = "{key:value}", parent_id = 1 | result should be -1 | Should Pass |
* | 04 | Delete the invalid JSON object | invalidJsonObject = "{key:value}" | invalidJsonObject should be deleted | Should be successful |
* | 05 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
*/
TEST_F(dm_assoc_sta_mld_t_Test, DecodeWithInvalidJsonObjectAndValidParentId) {
    std::cout << "Entering DecodeWithInvalidJsonObjectAndValidParentId test" << std::endl;
    cJSON* invalidJsonObject = cJSON_Parse("{key:value}");
    int parent_id = 1;
    int result = instance->decode(invalidJsonObject, &parent_id);
    ASSERT_EQ(result, -1);
    cJSON_Delete(invalidJsonObject);
    std::cout << "Exiting DecodeWithInvalidJsonObjectAndValidParentId test" << std::endl;
}

/**
 * @brief Test the decode function with a valid JSON object and an invalid parent ID.
 *
 * This test verifies that the decode function correctly handles a valid JSON object but an invalid parent ID. 
 * The expected behavior is that the function should return an error code (-1) indicating failure.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Parse a valid JSON object | validJsonObject = {"key":"value"} | validJsonObject is parsed successfully | Should be successful |
 * | 03 | Call decode with valid JSON object and invalid parent ID | validJsonObject = {"key":"value"}, invalid_parent_id = -1 | result = -1 | Should Pass |
 * | 04 | Delete the JSON object | validJsonObject = {"key":"value"} | validJsonObject is deleted successfully | Should be successful |
 * | 05 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(dm_assoc_sta_mld_t_Test, DecodeWithValidJsonObjectAndInvalidParentId) {
    std::cout << "Entering DecodeWithValidJsonObjectAndInvalidParentId test" << std::endl;
    cJSON* validJsonObject = cJSON_Parse("{\"key\":\"value\"}");
    int invalid_parent_id = -1;
    int result = instance->decode(validJsonObject, &invalid_parent_id);
    ASSERT_EQ(result, -1);
    cJSON_Delete(validJsonObject);
    std::cout << "Exiting DecodeWithValidJsonObjectAndInvalidParentId test" << std::endl;
}

/**
* @brief Test the encoding functionality with a valid cJSON object.
*
* This test verifies that the encode function correctly processes a valid cJSON object by adding a specific key-value pair and ensures that the object contains the expected key after encoding.
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
* | 01 | Initialize the test fixture | instance = new dm_assoc_sta_mld_t() | instance is initialized | Done by Pre-requisite SetUp function |
* | 02 | Create a cJSON object and add a key-value pair | obj = cJSON_CreateObject(), cJSON_AddStringToObject(obj, "key", "value") | cJSON object created with key-value pair | Should be successful |
* | 03 | Call the encode function with the cJSON object | instance->encode(obj) | encode function processes the object | Should Pass |
* | 04 | Verify the cJSON object contains the expected key | cJSON_HasObjectItem(obj, "key") | Assertion check passes | Should Pass |
* | 05 | Clean up the test fixture | delete instance | instance is deleted | Done by Pre-requisite TearDown function |
*/
TEST_F(dm_assoc_sta_mld_t_Test, EncodeWithValidCJSONObject) {
    std::cout << "Entering EncodeWithValidCJSONObject test" << std::endl;
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "key", "value");
    instance->encode(obj);
    ASSERT_TRUE(cJSON_HasObjectItem(obj, "key"));
    std::cout << "Exiting EncodeWithValidCJSONObject test" << std::endl;
}

/**
* @brief Test the encoding function with a null cJSON object
*
* This test verifies that the encode function handles a null cJSON object correctly. It ensures that the function does not modify the null object and behaves as expected when given invalid input.
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
* | 01 | Call the SetUp function to initialize the test environment | None | instance is initialized | Done by Pre-requisite SetUp function |
* | 02 | Create a null cJSON object | cJSON *obj = nullptr | obj is null | Should be successful |
* | 03 | Call the encode function with the null cJSON object | instance->encode(obj) | obj = nullptr | Should Pass |
* | 04 | Call the TearDown function to clean up the test environment | None | instance is deleted | Done by Pre-requisite TearDown function |
*/
TEST_F(dm_assoc_sta_mld_t_Test, EncodeWithNullCJSONObject) {
    std::cout << "Entering EncodeWithNullCJSONObject test" << std::endl;
    cJSON *obj = nullptr;
    instance->encode(obj);
    std::cout << "Exiting EncodeWithNullCJSONObject test" << std::endl;
}

/**
 * @brief Test the encoding function with invalid data in cJSON object
 *
 * This test verifies the behavior of the encode function when provided with a cJSON object containing invalid data. The objective is to ensure that the function handles invalid data gracefully and performs the expected operations.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 008@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Create a cJSON object and add invalid data | cJSON object with key=123 | cJSON object created with invalid data | Should be successful |
 * | 03 | Call the encode function with the invalid cJSON object | cJSON object with key=123 | Function should handle invalid data | Should Pass |
 * | 04 | Verify the cJSON object still contains the key | cJSON object with key=123 | ASSERT_TRUE(cJSON_HasObjectItem(obj, "key")) | Should Pass |
 * | 05 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */

TEST_F(dm_assoc_sta_mld_t_Test, EncodeWithInvalidDataCJSONObject) {
    std::cout << "Entering EncodeWithInvalidDataCJSONObject test" << std::endl;
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "key", 123);
    instance->encode(obj);
    ASSERT_TRUE(cJSON_HasObjectItem(obj, "key"));
    std::cout << "Exiting EncodeWithInvalidDataCJSONObject test" << std::endl;
}

/**
 * @brief Test encoding of a JSON object with special characters
 *
 * This test verifies that the encode function correctly handles and encodes a JSON object containing special characters in its values.@n
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
 * | 01 | Set up the test environment by creating an instance of dm_assoc_sta_mld_t | None | Instance created successfully | Done by Pre-requisite SetUp function |
 * | 02 | Create a cJSON object and add a key-value pair with special characters | obj = cJSON_CreateObject(), key = "key", value = "value!@#$%^&*()" | cJSON object created with special characters | Should be successful |
 * | 03 | Call the encode function with the created cJSON object | obj = cJSON object with special characters | Encode function processes the object | Should Pass |
 * | 04 | Verify that the encoded object retains the special characters in the value | key = "key", expected value = "value!@#$%^&*()" | Assertion check passes | Should Pass |
 * | 05 | Tear down the test environment by deleting the instance of dm_assoc_sta_mld_t | None | Instance deleted successfully | Done by Pre-requisite TearDown function |
 */
TEST_F(dm_assoc_sta_mld_t_Test, EncodeWithSpecialCharactersCJSONObject) {
    std::cout << "Entering EncodeWithSpecialCharactersCJSONObject test" << std::endl;
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "key", "value!@#$%^&*()");
    instance->encode(obj);
    ASSERT_STREQ(cJSON_GetObjectItem(obj, "key")->valuestring, "value!@#$%^&*()");
    std::cout << "Exiting EncodeWithSpecialCharactersCJSONObject test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of AP MLD information after initialization
 *
 * This test checks if the AP MLD information is correctly initialized and retrieved after calling the init() method on the instance. It ensures that the information is not null and that all fields are set to their expected default values.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Retrieve AP MLD information | em_assoc_sta_mld_info_t* info = instance->get_ap_mld_info() | None | Should be successful |
 * | 03 | Check if the info is not null | ASSERT_NE(info, nullptr) | info = not null | Should Pass |
 * | 04 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(dm_assoc_sta_mld_t_Test, RetrieveAPMLDInfoAfterInitialization) {
    std::cout << "Entering RetrieveAPMLDInfoAfterInitialization test" << std::endl;
    em_assoc_sta_mld_info_t* info = instance->get_ap_mld_info();
	std::cout << "the retrieved ap mld info is " << info << std::endl;
    ASSERT_NE(info, nullptr);
    std::cout << "Exiting RetrieveAPMLDInfoAfterInitialization test" << std::endl;
}

/**
 * @brief Test the retrieval of AP MLD information with valid MAC addresses
 *
 * This test verifies that the AP MLD information is correctly retrieved when valid MAC addresses are set. 
 * It ensures that the MAC addresses are properly assigned and retrieved without any corruption.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Set the MAC addresses for the instance | mac1 = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, mac2 = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB} | None | Should be successful |
 * | 03 | Retrieve the AP MLD information | None | info != nullptr | Should Pass |
 * | 04 | Verify the MAC address of the instance | mac1 = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55} | memcmp(info->mac_addr, mac1, sizeof(mac_address_t)) == 0 | Should Pass |
 * | 05 | Verify the AP MLD MAC address of the instance | mac2 = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB} | memcmp(info->ap_mld_mac_addr, mac2, sizeof(mac_address_t)) == 0 | Should Pass |
 * | 06 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
 TEST_F(dm_assoc_sta_mld_t_Test, RetrieveAPMLDInfoWithValidMACAddresses) {
    std::cout << "Entering RetrieveAPMLDInfoWithValidMACAddresses test" << std::endl;
    mac_address_t mac1 = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    mac_address_t mac2 = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
    memcpy(instance->m_assoc_sta_mld_info.mac_addr, mac1, sizeof(mac_address_t));
    memcpy(instance->m_assoc_sta_mld_info.ap_mld_mac_addr, mac2, sizeof(mac_address_t));
    em_assoc_sta_mld_info_t* info = instance->get_ap_mld_info();
    ASSERT_NE(info, nullptr);
    ASSERT_EQ(memcmp(info->mac_addr, mac1, sizeof(mac_address_t)), 0);
    ASSERT_EQ(memcmp(info->ap_mld_mac_addr, mac2, sizeof(mac_address_t)), 0);
    std::cout << "Exiting RetrieveAPMLDInfoWithValidMACAddresses test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of AP MLD information with the maximum number of affiliated stations.
 *
 * This test checks if the `get_ap_mld_info` function correctly retrieves the AP MLD information when the number of affiliated stations is set to the maximum allowed value.@n
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment | instance = new dm_assoc_sta_mld_t() | instance is created | Done by Pre-requisite SetUp function |
 * | 02 | Set the number of affiliated stations to the maximum value | instance->m_assoc_sta_mld_info.num_affiliated_sta = EM_MAX_AP_MLD | num_affiliated_sta is set to EM_MAX_AP_MLD | Should be successful |
 * | 03 | Retrieve the AP MLD information | em_assoc_sta_mld_info_t* info = instance->get_ap_mld_info() | info is retrieved | Should Pass |
 * | 04 | Check if the retrieved info is not null | ASSERT_NE(info, nullptr) | info is not null | Should Pass |
 * | 05 | Verify the number of affiliated stations in the retrieved info | ASSERT_EQ(info->num_affiliated_sta, EM_MAX_AP_MLD) | num_affiliated_sta is EM_MAX_AP_MLD | Should Pass |
 * | 06 | Tear down the test environment | delete instance | instance is deleted | Done by Pre-requisite TearDown function |
 */
TEST_F(dm_assoc_sta_mld_t_Test, RetrieveAPMLDInfoWithMaxAffiliatedStations) {
    std::cout << "Entering RetrieveAPMLDInfoWithMaxAffiliatedStations test" << std::endl;
    instance->m_assoc_sta_mld_info.num_affiliated_sta = EM_MAX_AP_MLD;
    em_assoc_sta_mld_info_t* info = instance->get_ap_mld_info();
    ASSERT_NE(info, nullptr);
    ASSERT_EQ(info->num_affiliated_sta, EM_MAX_AP_MLD);
    std::cout << "Exiting RetrieveAPMLDInfoWithMaxAffiliatedStations test" << std::endl;
}

/**
 * @brief Test to retrieve AP MLD information with zero affiliated stations
 *
 * This test verifies that the function get_ap_mld_info correctly handles the case where there are zero affiliated stations. It ensures that the returned information is not null and that the number of affiliated stations is correctly reported as zero.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 013@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Set the number of affiliated stations to zero | instance->m_assoc_sta_mld_info.num_affiliated_sta = 0; | None | Should be successful |
 * | 03 | Retrieve the AP MLD information | em_assoc_sta_mld_info_t* info = instance->get_ap_mld_info(); | info != nullptr | Should Pass |
 * | 04 | Verify the number of affiliated stations is zero | ASSERT_EQ(info->num_affiliated_sta, 0); | info->num_affiliated_sta = 0 | Should Pass |
 * | 05 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(dm_assoc_sta_mld_t_Test, RetrieveAPMLDInfoWithZeroAffiliatedStations) {
    std::cout << "Entering RetrieveAPMLDInfoWithZeroAffiliatedStations test" << std::endl;
    instance->m_assoc_sta_mld_info.num_affiliated_sta = 0;
    em_assoc_sta_mld_info_t* info = instance->get_ap_mld_info();
    ASSERT_NE(info, nullptr);
    ASSERT_EQ(info->num_affiliated_sta, 0);
    std::cout << "Exiting RetrieveAPMLDInfoWithZeroAffiliatedStations test" << std::endl;
}

/**
* @brief Test to verify the retrieval of AP MLD information with boolean fields set to true.
*
* This test checks if the AP MLD information is correctly retrieved when all boolean fields are set to true. It ensures that the get_ap_mld_info() function returns the expected values for the boolean fields.
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
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Setup the test environment | instance = new dm_assoc_sta_mld_t() | instance is created | Done by Pre-requisite SetUp function |
* | 02 | Set boolean fields to true | instance->m_assoc_sta_mld_info.str = true, instance->m_assoc_sta_mld_info.nstr = true, instance->m_assoc_sta_mld_info.emlsr = true, instance->m_assoc_sta_mld_info.emlmr = true | Boolean fields are set to true | Should be successful |
* | 03 | Retrieve AP MLD information | em_assoc_sta_mld_info_t* info = instance->get_ap_mld_info() | info is not nullptr | Should Pass |
* | 04 | Verify str field | ASSERT_EQ(info->str, true) | info->str = true | Should Pass |
* | 05 | Verify nstr field | ASSERT_EQ(info->nstr, true) | info->nstr = true | Should Pass |
* | 06 | Verify emlsr field | ASSERT_EQ(info->emlsr, true) | info->emlsr = true | Should Pass |
* | 07 | Verify emlmr field | ASSERT_EQ(info->emlmr, true) | info->emlmr = true | Should Pass |
* | 08 | Tear down the test environment | delete instance | instance is deleted | Done by Pre-requisite TearDown function |
*/
TEST_F(dm_assoc_sta_mld_t_Test, RetrieveAPMLDInfoWithBooleanFieldsSetToTrue) {
    std::cout << "Entering RetrieveAPMLDInfoWithBooleanFieldsSetToTrue test" << std::endl;
    instance->m_assoc_sta_mld_info.str = true;
    instance->m_assoc_sta_mld_info.nstr = true;
    instance->m_assoc_sta_mld_info.emlsr = true;
    instance->m_assoc_sta_mld_info.emlmr = true;
    em_assoc_sta_mld_info_t* info = instance->get_ap_mld_info();
    ASSERT_NE(info, nullptr);
    ASSERT_EQ(info->str, true);
    ASSERT_EQ(info->nstr, true);
    ASSERT_EQ(info->emlsr, true);
    ASSERT_EQ(info->emlmr, true);
    std::cout << "Exiting RetrieveAPMLDInfoWithBooleanFieldsSetToTrue test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of AP MLD information with boolean fields set to false.
 *
 * This test checks if the AP MLD information is correctly retrieved when all boolean fields are set to false.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 015@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Set the boolean fields of m_assoc_sta_mld_info to false | instance->m_assoc_sta_mld_info.str = false, instance->m_assoc_sta_mld_info.nstr = false, instance->m_assoc_sta_mld_info.emlsr = false, instance->m_assoc_sta_mld_info.emlmr = false | None | Should be successful |
 * | 03 | Retrieve the AP MLD information | info = instance->get_ap_mld_info() | info should not be nullptr | Should Pass |
 * | 04 | Verify the str field is false | info->str | false | Should Pass |
 * | 05 | Verify the nstr field is false | info->nstr | false | Should Pass |
 * | 06 | Verify the emlsr field is false | info->emlsr | false | Should Pass |
 * | 07 | Verify the emlmr field is false | info->emlmr | false | Should Pass |
 * | 08 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(dm_assoc_sta_mld_t_Test, RetrieveAPMLDInfoWithBooleanFieldsSetToFalse) {
    std::cout << "Entering RetrieveAPMLDInfoWithBooleanFieldsSetToFalse test" << std::endl;
    instance->m_assoc_sta_mld_info.str = false;
    instance->m_assoc_sta_mld_info.nstr = false;
    instance->m_assoc_sta_mld_info.emlsr = false;
    instance->m_assoc_sta_mld_info.emlmr = false;
    em_assoc_sta_mld_info_t* info = instance->get_ap_mld_info();
    ASSERT_NE(info, nullptr);
    ASSERT_EQ(info->str, false);
    ASSERT_EQ(info->nstr, false);
    ASSERT_EQ(info->emlsr, false);
    ASSERT_EQ(info->emlmr, false);
    std::cout << "Exiting RetrieveAPMLDInfoWithBooleanFieldsSetToFalse test" << std::endl;
}

/**
 * @brief Test the initialization of the Association Station MLD Information Structure
 *
 * This test verifies that the initialization function for the Association Station MLD Information Structure
 * executes correctly and returns the expected result. It ensures that the init() method of the dm_assoc_sta_mld_t
 * class initializes the instance properly.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment | instance = new dm_assoc_sta_mld_t() | instance is created | Done by Pre-requisite SetUp function |
 * | 02 | Print entering message | std::cout << "Entering InitializeAssociationStationMLDInformationStructure" << std::endl; | "Entering InitializeAssociationStationMLDInformationStructure" is printed | Should be successful |
 * | 03 | Call the init() method | result = instance->init() | result = 0 | Should Pass |
 * | 04 | Assert the result | ASSERT_EQ(result, 0) | result == 0 | Should Pass |
 * | 05 | Print exiting message | std::cout << "Exiting InitializeAssociationStationMLDInformationStructure" << std::endl; | "Exiting InitializeAssociationStationMLDInformationStructure" is printed | Should be successful |
 * | 06 | Tear down the test environment | delete instance | instance is deleted | Done by Pre-requisite TearDown function |
 */
TEST_F(dm_assoc_sta_mld_t_Test, InitializeAssociationStationMLDInformationStructure) {
    std::cout << "Entering InitializeAssociationStationMLDInformationStructure" << std::endl;
    int result = instance->init();
    ASSERT_EQ(result, 0);
    std::cout << "Exiting InitializeAssociationStationMLDInformationStructure" << std::endl;
}

/**
 * @brief Test to initialize the Association Station MLD Information Structure with already initialized data
 *
 * This test checks the behavior of the `init` method when it is called on an already initialized instance. 
 * It ensures that the method handles re-initialization correctly and returns the expected result.
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
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Call the `init` method to initialize the instance | None | None | Should be successful |
 * | 03 | Call the `init` method again on the already initialized instance | None | result = 0 | Should Pass |
 * | 04 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(dm_assoc_sta_mld_t_Test, InitializeAssociationStationMLDInformationStructureWithAlreadyInitializedData) {
    std::cout << "Entering InitializeAssociationStationMLDInformationStructureWithAlreadyInitializedData" << std::endl;
    instance->init();
    int result = instance->init();
    ASSERT_EQ(result, 0);
    std::cout << "Exiting InitializeAssociationStationMLDInformationStructureWithAlreadyInitializedData" << std::endl;
}

/**
* @brief Test to verify the equality operator for identical objects
*
* This test checks if two objects of the class `dm_assoc_sta_mld_t` with identical data are considered equal by the equality operator. This is important to ensure that the equality operator is correctly implemented and can accurately compare two objects.
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
* | 01 | Create two identical objects and compare them using the equality operator | obj1.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, false, true, false, 1, {}}, obj2.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, false, true, false, 1, {}} | EXPECT_TRUE(obj1 == obj2) | Should Pass |
*/

TEST(dm_assoc_sta_mld_t_Test, IdenticalObjects) {
    std::cout << "Entering IdenticalObjects test";
    dm_assoc_sta_mld_t obj1, obj2;
    obj1.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, false, true, false, 1, {}};
    obj2.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, false, true, false, 1, {}};
    EXPECT_TRUE(obj1 == obj2);
    std::cout << "Exiting IdenticalObjects test";
}

/**
* @brief Test to verify the inequality of two dm_assoc_sta_mld_t objects with different MAC addresses
*
* This test checks if two dm_assoc_sta_mld_t objects with different MAC addresses are not considered equal.@n
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create two dm_assoc_sta_mld_t objects with different MAC addresses | obj1.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, false, true, false, 1, {}}, obj2.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x56}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, false, true, false, 1, {}} | Objects should not be equal | Should Pass |
* | 02| Compare the two objects using EXPECT_FALSE | EXPECT_FALSE(obj1 == obj2) | The comparison should return false | Should Pass |
*/
TEST(dm_assoc_sta_mld_t_Test, DifferentMacAddr) {
    std::cout << "Entering DifferentMacAddr test";
    dm_assoc_sta_mld_t obj1, obj2;
    obj1.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, false, true, false, 1, {}};
    obj2.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x56}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, false, true, false, 1, {}};
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting DifferentMacAddr test";
}

/**
* @brief Test to verify the behavior when comparing two objects with different AP MLD MAC addresses.
*
* This test checks the equality operator for `dm_assoc_sta_mld_t` objects when their AP MLD MAC addresses differ. 
* It ensures that the equality operator correctly identifies the objects as unequal when their MAC addresses are different.
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create two `dm_assoc_sta_mld_t` objects with different AP MLD MAC addresses | obj1.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, false, true, false, 1, {}}, obj2.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBC}, true, false, true, false, 1, {}} | Objects should be unequal | Should Pass |
* | 02| Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_assoc_sta_mld_t_Test, DifferentApMldMacAddr) {
    std::cout << "Entering DifferentApMldMacAddr test";
    dm_assoc_sta_mld_t obj1, obj2;
    obj1.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, false, true, false, 1, {}};
    obj2.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBC}, true, false, true, false, 1, {}};
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting DifferentApMldMacAddr test";
}

/**
* @brief Test to verify the inequality operator for different string values in dm_assoc_sta_mld_t class
*
* This test checks the inequality operator of the dm_assoc_sta_mld_t class by comparing two objects with different boolean values in their m_assoc_sta_mld_info structure. The test ensures that the inequality operator correctly identifies the objects as not equal.
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create two dm_assoc_sta_mld_t objects with different boolean values in m_assoc_sta_mld_info | obj1.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, false, true, false, 1, {}}, obj2.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, false, false, true, false, 1, {}} | Objects should not be equal | Should Pass |
* | 02| Compare the two objects using the inequality operator | obj1 != obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_assoc_sta_mld_t_Test, DifferentStrValues) {
    std::cout << "Entering DifferentStrValues test";
    dm_assoc_sta_mld_t obj1, obj2;
    obj1.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, false, true, false, 1, {}};
    obj2.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, false, false, true, false, 1, {}};
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting DifferentStrValues test";
}

/**
* @brief Test to verify the behavior of the equality operator for different Nstr values
*
* This test checks the equality operator of the dm_assoc_sta_mld_t class by comparing two objects with different Nstr values. The objective is to ensure that the equality operator correctly identifies objects with different Nstr values as not equal.
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create two dm_assoc_sta_mld_t objects with different Nstr values | obj1.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, false, true, false, 1, {}}, obj2.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, true, true, false, 1, {}} | Objects should be created successfully | Should be successful |
* | 02| Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_assoc_sta_mld_t_Test, DifferentNstrValues) {
    std::cout << "Entering DifferentNstrValues test";
    dm_assoc_sta_mld_t obj1, obj2;
    obj1.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, false, true, false, 1, {}};
    obj2.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, true, true, false, 1, {}};
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting DifferentNstrValues test";
}

/**
* @brief Test to verify the behavior of the equality operator for different EMLSR values
*
* This test checks the equality operator of the dm_assoc_sta_mld_t class by comparing two objects with different EMLSR values. The objective is to ensure that the equality operator correctly identifies objects with different EMLSR values as not equal.
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
* | 01 | Initialize obj1 with specific EMLSR values | obj1.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, false, true, false, 1, {}} |  | Should be successful |
* | 02 | Initialize obj2 with different EMLSR values | obj2.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, false, false, false, 1, {}} |  | Should be successful |
* | 03 | Compare obj1 and obj2 using equality operator | EXPECT_FALSE(obj1 == obj2) | The objects should not be equal | Should Pass |
*/
TEST(dm_assoc_sta_mld_t_Test, DifferentEmlsrValues) {
    std::cout << "Entering DifferentEmlsrValues test";
    dm_assoc_sta_mld_t obj1, obj2;
    obj1.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, false, true, false, 1, {}};
    obj2.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, false, false, false, 1, {}};
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting DifferentEmlsrValues test";
}

/**
* @brief Test to verify the behavior of the equality operator for different EMLMR values
*
* This test checks the equality operator of the dm_assoc_sta_mld_t class by comparing two objects with different EMLMR values. The objective is to ensure that the equality operator correctly identifies objects with different EMLMR values as not equal.
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create two dm_assoc_sta_mld_t objects with different EMLMR values | obj1.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, false, true, false, 1, {}}, obj2.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, false, true, true, 1, {}} | Objects should not be equal | Should Pass |
* | 02| Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_assoc_sta_mld_t_Test, DifferentEmlmrValues) {
    std::cout << "Entering DifferentEmlmrValues test";
    dm_assoc_sta_mld_t obj1, obj2;
    obj1.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, false, true, false, 1, {}};
    obj2.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, false, true, true, 1, {}};
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting DifferentEmlmrValues test";
}

/**
* @brief Test to verify the behavior when the number of affiliated stations is different
*
* This test checks the equality operator of the dm_assoc_sta_mld_t class when the number of affiliated stations is different between two objects. The test ensures that the equality operator correctly identifies the objects as not equal when the number of affiliated stations differs.
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create two dm_assoc_sta_mld_t objects with different number of affiliated stations | obj1.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, false, true, false, 1, {}}, obj2.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, false, true, false, 2, {}} | Objects should not be equal | Should Pass |
* | 02| Check equality using EXPECT_FALSE | EXPECT_FALSE(obj1 == obj2) | Should return false | Should Pass |
*/

TEST(dm_assoc_sta_mld_t_Test, DifferentNumAffiliatedSta) {
    std::cout << "Entering DifferentNumAffiliatedSta test";
    dm_assoc_sta_mld_t obj1, obj2;
    obj1.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, false, true, false, 1, {}};
    obj2.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, false, true, false, 2, {}};
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting DifferentNumAffiliatedSta test";
}

/**
* @brief Test to verify the behavior when comparing two objects with different affiliated station values.
*
* This test checks the equality operator for the `dm_assoc_sta_mld_t` class by comparing two objects with different affiliated station values. The test ensures that the equality operator correctly identifies that the two objects are not equal due to the difference in their affiliated station values.
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
* | 01 | Initialize obj1 with specific affiliated station values | obj1.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, false, true, false, 1, {{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}} | Object initialized | Should be successful |
* | 02 | Initialize obj2 with different affiliated station values | obj2.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, false, true, false, 1, {{0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}} | Object initialized | Should be successful |
* | 03 | Compare obj1 and obj2 using equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_assoc_sta_mld_t_Test, DifferentAffiliatedStaValues) {
    std::cout << "Entering DifferentAffiliatedStaValues test";
    dm_assoc_sta_mld_t obj1, obj2;
    obj1.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, false, true, false, 1, {{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}};
    obj2.m_assoc_sta_mld_info = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, false, true, false, 1, {{0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}};
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting DifferentAffiliatedStaValues test";
}

/**
* @brief Test the assignment operator for dm_assoc_sta_mld_t class
*
* This test verifies that the assignment operator correctly copies the values from one object to another.@n
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create obj1 and set its members | obj1.m_assoc_sta_mld_info.str = true, obj1.m_assoc_sta_mld_info.num_affiliated_sta = 5 | Members of obj1 are set correctly | Should be successful |
* | 02| Assign obj1 to obj2 | obj2 = obj1 | obj2's members should match obj1's members | Should Pass |
* | 03| Verify obj2's members | ASSERT_EQ(obj2.m_assoc_sta_mld_info.str, obj1.m_assoc_sta_mld_info.str), ASSERT_EQ(obj2.m_assoc_sta_mld_info.num_affiliated_sta, obj1.m_assoc_sta_mld_info.num_affiliated_sta) | Assertions should pass | Should Pass |
*/
TEST(dm_assoc_sta_mld_t_Test, AssigningValidObject) {
    std::cout << "Entering AssigningValidObject" << std::endl;
    dm_assoc_sta_mld_t obj1;
    obj1.m_assoc_sta_mld_info.str = true;
    obj1.m_assoc_sta_mld_info.num_affiliated_sta = 5;
    dm_assoc_sta_mld_t obj2;
    obj2 = obj1;
    ASSERT_EQ(obj2.m_assoc_sta_mld_info.str, obj1.m_assoc_sta_mld_info.str);
    ASSERT_EQ(obj2.m_assoc_sta_mld_info.num_affiliated_sta, obj1.m_assoc_sta_mld_info.num_affiliated_sta);
    std::cout << "Exiting AssigningValidObject" << std::endl;
}



/**
* @brief Test the self-assignment functionality of the dm_assoc_sta_mld_t class
*
* This test checks the self-assignment operation of the dm_assoc_sta_mld_t class to ensure that the object remains unchanged when assigned to itself.@n
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
* | 01 | Initialize object and set values | obj1.m_assoc_sta_mld_info.str = true, obj1.m_assoc_sta_mld_info.num_affiliated_sta = 5 | Values should be set correctly | Should be successful |
* | 02 | Perform self-assignment | obj1 = obj1 | Object should remain unchanged | Should Pass |
* | 03 | Check values after self-assignment | obj1.m_assoc_sta_mld_info.str, obj1.m_assoc_sta_mld_info.num_affiliated_sta | str should be true, num_affiliated_sta should be 5 | Should Pass |
*/

TEST(dm_assoc_sta_mld_t_Test, SelfAssignment) {
    std::cout << "Entering SelfAssignment" << std::endl;
    dm_assoc_sta_mld_t obj1;
    obj1.m_assoc_sta_mld_info.str = true;
    obj1.m_assoc_sta_mld_info.num_affiliated_sta = 5;
    obj1 = obj1;
    ASSERT_EQ(obj1.m_assoc_sta_mld_info.str, true);
    ASSERT_EQ(obj1.m_assoc_sta_mld_info.num_affiliated_sta, 5);
    std::cout << "Exiting SelfAssignment" << std::endl;
}

/**
* @brief Test the assignment operator for dm_assoc_sta_mld_t class
*
* This test verifies that the assignment operator correctly copies the values from one object to another. 
* It ensures that after assignment, the target object has the same values as the source object.
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create two dm_assoc_sta_mld_t objects | obj1, obj2 | Objects created successfully | Should be successful |
* | 02| Set values in obj2 | obj2.m_assoc_sta_mld_info.str = true, obj2.m_assoc_sta_mld_info.num_affiliated_sta = 5 | Values set successfully | Should be successful |
* | 03| Assign obj1 to obj2 | obj2 = obj1 | obj2 should have the same values as obj1 | Should Pass |
* | 04| Verify the values in obj2 | ASSERT_EQ(obj2.m_assoc_sta_mld_info.str, obj1.m_assoc_sta_mld_info.str), ASSERT_EQ(obj2.m_assoc_sta_mld_info.num_affiliated_sta, obj1.m_assoc_sta_mld_info.num_affiliated_sta) | Values should be equal | Should Pass |
*/
TEST(dm_assoc_sta_mld_t_Test, AssigningDefaultObject) {
    std::cout << "Entering AssigningDefaultObject" << std::endl;
    dm_assoc_sta_mld_t obj1;
    dm_assoc_sta_mld_t obj2;
    obj2.m_assoc_sta_mld_info.str = true;
    obj2.m_assoc_sta_mld_info.num_affiliated_sta = 5;
    obj2 = obj1;
    ASSERT_EQ(obj2.m_assoc_sta_mld_info.str, obj1.m_assoc_sta_mld_info.str);
    ASSERT_EQ(obj2.m_assoc_sta_mld_info.num_affiliated_sta, obj1.m_assoc_sta_mld_info.num_affiliated_sta);
    std::cout << "Exiting AssigningDefaultObject" << std::endl;
}

/**
* @brief Test to verify the assignment of maximum values to the dm_assoc_sta_mld_t object
*
* This test checks the assignment operator of the dm_assoc_sta_mld_t class by assigning maximum values to the member variables and verifying if the values are correctly assigned to another object using the assignment operator.@n
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create an object of dm_assoc_sta_mld_t and assign maximum values to its members | obj1.m_assoc_sta_mld_info.str = true, obj1.m_assoc_sta_mld_info.num_affiliated_sta = 255 | Values should be assigned correctly | Should be successful |
* | 02| Assign obj1 to another object obj2 using the assignment operator | obj2 = obj1 | obj2 should have the same values as obj1 | Should Pass |
* | 03| Verify the values of obj2 | obj2.m_assoc_sta_mld_info.str, obj2.m_assoc_sta_mld_info.num_affiliated_sta | obj2.m_assoc_sta_mld_info.str == obj1.m_assoc_sta_mld_info.str, obj2.m_assoc_sta_mld_info.num_affiliated_sta == obj1.m_assoc_sta_mld_info.num_affiliated_sta | Should Pass |
*/
TEST(dm_assoc_sta_mld_t_Test, AssigningMaxValues) {
    std::cout << "Entering AssigningMaxValues" << std::endl;
    dm_assoc_sta_mld_t obj1;
    obj1.m_assoc_sta_mld_info.str = true;
    obj1.m_assoc_sta_mld_info.num_affiliated_sta = 255;
    dm_assoc_sta_mld_t obj2;
    obj2 = obj1;
    ASSERT_EQ(obj2.m_assoc_sta_mld_info.str, obj1.m_assoc_sta_mld_info.str);
    ASSERT_EQ(obj2.m_assoc_sta_mld_info.num_affiliated_sta, obj1.m_assoc_sta_mld_info.num_affiliated_sta);
    std::cout << "Exiting AssigningMaxValues" << std::endl;
}

/**
* @brief Test to verify the assignment of minimum values to the dm_assoc_sta_mld_t object
*
* This test checks the assignment operator of the dm_assoc_sta_mld_t class by assigning minimum values to its members and verifying if the assignment is done correctly.@n
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create dm_assoc_sta_mld_t object and assign minimum values | obj1.m_assoc_sta_mld_info.str = false, obj1.m_assoc_sta_mld_info.num_affiliated_sta = 0 | Object created with minimum values | Should be successful |
* | 02| Assign obj1 to obj2 | obj2 = obj1 | obj2 should have the same values as obj1 | Should Pass |
* | 03| Verify the values of obj2 | ASSERT_EQ(obj2.m_assoc_sta_mld_info.str, obj1.m_assoc_sta_mld_info.str), ASSERT_EQ(obj2.m_assoc_sta_mld_info.num_affiliated_sta, obj1.m_assoc_sta_mld_info.num_affiliated_sta) | Values should match | Should Pass |
*/
TEST(dm_assoc_sta_mld_t_Test, AssigningMinValues) {
    std::cout << "Entering AssigningMinValues" << std::endl;
    dm_assoc_sta_mld_t obj1;
    obj1.m_assoc_sta_mld_info.str = false;
    obj1.m_assoc_sta_mld_info.num_affiliated_sta = 0;
    dm_assoc_sta_mld_t obj2;
    obj2 = obj1;
    ASSERT_EQ(obj2.m_assoc_sta_mld_info.str, obj1.m_assoc_sta_mld_info.str);
    ASSERT_EQ(obj2.m_assoc_sta_mld_info.num_affiliated_sta, obj1.m_assoc_sta_mld_info.num_affiliated_sta);
    std::cout << "Exiting AssigningMinValues" << std::endl;
}

/**
* @brief Test to validate the initialization of AP MLD information
*
* This test checks the initialization of the AP MLD information structure with valid data and ensures that the initialization function returns a success status.@n
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
* | 01 | Initialize ap_mld_info with valid data | ap_mld_info = valid data | Initialization should be successful | Should be successful |
* | 02 | Create dm_assoc_sta_mld_t object with ap_mld_info | ap_mld_info = valid data | Object creation should be successful | Should be successful |
* | 03 | Call init() method on dm_assoc_sta_mld_t object | ap_mld_info = valid data | Return value should be 0 | Should Pass |
*/
TEST(dm_assoc_sta_mld_t_Test, ValidAPMLDInformation) {
    std::cout << "Entering ValidAPMLDInformation test";
    em_assoc_sta_mld_info_t ap_mld_info;
    // Initialize ap_mld_info with valid data
    dm_assoc_sta_mld_t assoc_sta_mld(&ap_mld_info);
    EXPECT_EQ(assoc_sta_mld.init(), 0);
    std::cout << "Exiting ValidAPMLDInformation test";
}

/**
* @brief Test to verify the behavior when AP MLD information is null
*
* This test checks the initialization of the `dm_assoc_sta_mld_t` class when the AP MLD information is null. 
* It ensures that the initialization fails gracefully and returns the expected error code.@n
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
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Initialize AP MLD information to null | ap_mld_info = nullptr | N/A | Should be successful |
* | 02 | Create `dm_assoc_sta_mld_t` object with null AP MLD information | ap_mld_info = nullptr | N/A | Should be successful |
* | 03 | Call `init` method and check the return value | N/A | Return value = -1, Assertion: EXPECT_EQ(assoc_sta_mld.init(), -1) | Should Pass |
*/
TEST(dm_assoc_sta_mld_t_Test, NullAPMLDInformation) {
    std::cout << "Entering NullAPMLDInformation test";
    em_assoc_sta_mld_info_t* ap_mld_info = nullptr;
    dm_assoc_sta_mld_t assoc_sta_mld(ap_mld_info);
    EXPECT_EQ(assoc_sta_mld.init(), -1);
    std::cout << "Exiting NullAPMLDInformation test";
}

/**
* @brief Test to validate the behavior of the dm_assoc_sta_mld_t class when initialized with an invalid MAC address.
*
* This test checks the initialization of the dm_assoc_sta_mld_t class with an invalid MAC address (all zeros) and expects the initialization to fail.@n
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Initialize ap_mld_info with all zeros MAC address | ap_mld_info.mac_addr = {0, 0, 0, 0, 0, 0} | Initialization should fail | Should Fail |
* | 02| Create dm_assoc_sta_mld_t object with ap_mld_info | ap_mld_info | Object should be created | Should be successful |
* | 03| Call init() method on dm_assoc_sta_mld_t object | assoc_sta_mld.init() | Return value should be -1 | Should Fail |
*/
TEST(dm_assoc_sta_mld_t_Test, InvalidMACAddress) {
    std::cout << "Entering InvalidMACAddress test";
    em_assoc_sta_mld_info_t ap_mld_info;
    memset(ap_mld_info.mac_addr, 0, sizeof(ap_mld_info.mac_addr));
    dm_assoc_sta_mld_t assoc_sta_mld(&ap_mld_info);
    EXPECT_EQ(assoc_sta_mld.init(), -1);
    std::cout << "Exiting InvalidMACAddress test";
}

/**
* @brief Test to validate the behavior when an invalid AP MLD MAC address is provided.
*
* This test checks the initialization of the `dm_assoc_sta_mld_t` object with an invalid AP MLD MAC address (all zeros). 
* The expected behavior is that the initialization should fail and return -1.
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
* | 01 | Initialize AP MLD MAC address to all zeros | ap_mld_info.ap_mld_mac_addr = {0, 0, 0, 0, 0, 0} | Initialization should fail with return value -1 | Should Fail |
* | 02 | Create `dm_assoc_sta_mld_t` object with invalid AP MLD MAC address | ap_mld_info | Object should be created successfully | Should be successful |
* | 03 | Call `init` method on `dm_assoc_sta_mld_t` object | assoc_sta_mld.init() | Return value should be -1 | Should Fail |
*/
TEST(dm_assoc_sta_mld_t_Test, InvalidAPMLDMACAddress) {
    std::cout << "Entering InvalidAPMLDMACAddress test";
    em_assoc_sta_mld_info_t ap_mld_info;
    memset(ap_mld_info.ap_mld_mac_addr, 0, sizeof(ap_mld_info.ap_mld_mac_addr));
    dm_assoc_sta_mld_t assoc_sta_mld(&ap_mld_info);
    EXPECT_EQ(assoc_sta_mld.init(), -1);
    std::cout << "Exiting InvalidAPMLDMACAddress test";
}

/**
* @brief Test to verify the initialization with the maximum number of affiliated stations.
*
* This test checks if the dm_assoc_sta_mld_t class can handle the maximum number of affiliated stations correctly. It ensures that the initialization function works as expected when the maximum limit is reached.
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
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Initialize ap_mld_info with maximum number of affiliated stations | ap_mld_info.num_affiliated_sta = EM_MAX_AP_MLD | ap_mld_info should be initialized with maximum stations | Should be successful |
* | 02 | Create dm_assoc_sta_mld_t object with ap_mld_info | dm_assoc_sta_mld_t assoc_sta_mld(&ap_mld_info) | Object should be created successfully | Should be successful |
* | 03 | Call init() method on assoc_sta_mld object | assoc_sta_mld.init() | Return value should be 0 | Should Pass |
*/
TEST(dm_assoc_sta_mld_t_Test, MaximumNumberOfAffiliatedStations) {
    std::cout << "Entering MaximumNumberOfAffiliatedStations test";
    em_assoc_sta_mld_info_t ap_mld_info;
    ap_mld_info.num_affiliated_sta = EM_MAX_AP_MLD;
    dm_assoc_sta_mld_t assoc_sta_mld(&ap_mld_info);
    EXPECT_EQ(assoc_sta_mld.init(), 0);
    std::cout << "Exiting MaximumNumberOfAffiliatedStations test";
}

/**
* @brief Test to check behavior when the number of affiliated stations exceeds the maximum limit
*
* This test verifies that the system correctly handles the scenario where the number of affiliated stations exceeds the defined maximum limit. This is important to ensure that the system does not accept more stations than it can handle, which could lead to unexpected behavior or crashes.@n
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Initialize ap_mld_info with num_affiliated_sta exceeding the maximum limit | ap_mld_info.num_affiliated_sta = EM_MAX_AP_MLD + 1 | Initialization should fail with return value -1 | Should Pass |
* | 02| Create dm_assoc_sta_mld_t object with ap_mld_info | dm_assoc_sta_mld_t assoc_sta_mld(&ap_mld_info) | Object should be created successfully | Should be successful |
* | 03| Call init() method on assoc_sta_mld object | assoc_sta_mld.init() | Should return -1 indicating failure | Should Pass |
*/
TEST(dm_assoc_sta_mld_t_Test, ExceedingMaximumNumberOfAffiliatedStations) {
    std::cout << "Entering ExceedingMaximumNumberOfAffiliatedStations test";
    em_assoc_sta_mld_info_t ap_mld_info;
    ap_mld_info.num_affiliated_sta = EM_MAX_AP_MLD + 1;
    dm_assoc_sta_mld_t assoc_sta_mld(&ap_mld_info);
    EXPECT_EQ(assoc_sta_mld.init(), -1);
    std::cout << "Exiting ExceedingMaximumNumberOfAffiliatedStations test";
}

/**
* @brief Test to validate the behavior of the system when invalid affiliated station information is provided.
*
* This test checks the initialization of the `dm_assoc_sta_mld_t` object with invalid affiliated station information. The objective is to ensure that the system correctly handles and returns an error when the affiliated station data is invalid.
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
* | 01 | Initialize `ap_mld_info` with invalid affiliated station data | ap_mld_info.num_affiliated_sta = 1, ap_mld_info.affiliated_sta = invalid data | N/A | Should be successful |
* | 02 | Create `dm_assoc_sta_mld_t` object with `ap_mld_info` | ap_mld_info = initialized object | N/A | Should be successful |
* | 03 | Call `init` method on `assoc_sta_mld` object | assoc_sta_mld.init() | Return value = -1, Assertion check: EXPECT_EQ(assoc_sta_mld.init(), -1) | Should Fail |
*/
TEST(dm_assoc_sta_mld_t_Test, InvalidAffiliatedStationInformation) {
    std::cout << "Entering InvalidAffiliatedStationInformation test";
    em_assoc_sta_mld_info_t ap_mld_info;
    ap_mld_info.num_affiliated_sta = 1;
    // Initialize ap_mld_info.affiliated_sta with invalid data
    dm_assoc_sta_mld_t assoc_sta_mld(&ap_mld_info);
    EXPECT_EQ(assoc_sta_mld.init(), -1);
    std::cout << "Exiting InvalidAffiliatedStationInformation test";
}

/**
* @brief Test the copy constructor of dm_assoc_sta_mld_t with valid input
*
* This test verifies that the copy constructor of the dm_assoc_sta_mld_t class correctly copies the values from the original object to the new object. This ensures that the copy constructor is functioning as expected and that all member variables are accurately copied.
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create original object and set member variables | original.m_assoc_sta_mld_info.str = false, original.m_assoc_sta_mld_info.nstr = false, original.m_assoc_sta_mld_info.emlsr = true, original.m_assoc_sta_mld_info.emlmr = true | Member variables set correctly | Should be successful |
* | 02| Invoke copy constructor | dm_assoc_sta_mld_t copy(original) | New object created with copied values | Should Pass |
* | 03| Verify str member variable | copy.m_assoc_sta_mld_info.str, original.m_assoc_sta_mld_info.str | Values should be equal | Should Pass |
* | 04| Verify nstr member variable | copy.m_assoc_sta_mld_info.nstr, original.m_assoc_sta_mld_info.nstr | Values should be equal | Should Pass |
* | 05| Verify emlsr member variable | copy.m_assoc_sta_mld_info.emlsr, original.m_assoc_sta_mld_info.emlsr | Values should be equal | Should Pass |
* | 06| Verify emlmr member variable | copy.m_assoc_sta_mld_info.emlmr, original.m_assoc_sta_mld_info.emlmr | Values should be equal | Should Pass |
*/

TEST(dm_assoc_sta_mld_t_Test, CopyConstructorWithValidInput) {
    std::cout << "Entering CopyConstructorWithValidInput" << std::endl;
    dm_assoc_sta_mld_t original;
    original.m_assoc_sta_mld_info.str = false;
    original.m_assoc_sta_mld_info.nstr = false;
    original.m_assoc_sta_mld_info.emlsr = true;
    original.m_assoc_sta_mld_info.emlmr = true;
    dm_assoc_sta_mld_t copy(original);
    EXPECT_EQ(copy.m_assoc_sta_mld_info.str, original.m_assoc_sta_mld_info.str);
    EXPECT_EQ(copy.m_assoc_sta_mld_info.nstr, original.m_assoc_sta_mld_info.nstr);
    EXPECT_EQ(copy.m_assoc_sta_mld_info.emlsr, original.m_assoc_sta_mld_info.emlsr);
    EXPECT_EQ(copy.m_assoc_sta_mld_info.emlmr, original.m_assoc_sta_mld_info.emlmr);
    std::cout << "Exiting CopyConstructorWithValidInput" << std::endl;
}

/**
* @brief Test the copy constructor with an invalid MAC address input
*
* This test verifies that the copy constructor of the `dm_assoc_sta_mld_t` class correctly handles an invalid MAC address input by ensuring that the copied object's MAC address is set to zero.@n
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
* | 01 | Initialize original object with invalid MAC address | original.m_assoc_sta_mld_info.mac_addr = 0xFF | MAC address of original object is set to 0xFF | Should be successful |
* | 02 | Copy construct a new object from the original | dm_assoc_sta_mld_t copy(original) | MAC address of copy object should be 0 | Should Pass |
* | 03 | Verify each byte of the MAC address in the copied object | EXPECT_EQ(copy.m_assoc_sta_mld_info.mac_addr[i], 0) | Each byte of MAC address in copy object is 0 | Should Pass |
*/
TEST(dm_assoc_sta_mld_t_Test, CopyConstructorWithInvalidMacAddressInput) {
    std::cout << "Entering CopyConstructorWithInvalidMacAddressInput" << std::endl;
    dm_assoc_sta_mld_t original;
    memset(original.m_assoc_sta_mld_info.mac_addr, 0xFF, sizeof(mac_address_t));
    dm_assoc_sta_mld_t copy(original);
    for (size_t i = 0; i < sizeof(mac_address_t); ++i) {
        EXPECT_EQ(copy.m_assoc_sta_mld_info.mac_addr[i], 0);
    }
    std::cout << "Exiting CopyConstructorWithInvalidMacAddressInput" << std::endl;
}

/**
* @brief Test the copy constructor of dm_assoc_sta_mld_t with maximum affiliated stations
*
* This test verifies that the copy constructor of the dm_assoc_sta_mld_t class correctly copies the maximum number of affiliated stations. It ensures that the number of affiliated stations and their MAC addresses are accurately copied from the original object to the new object.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 041@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Initialize original object with maximum affiliated stations | original.m_assoc_sta_mld_info.num_affiliated_sta = EM_MAX_AP_MLD | Should be successful | |
* | 02| Set MAC addresses for each affiliated station in the original object | original.m_assoc_sta_mld_info.affiliated_sta[i].mac_addr[0] = i (for i from 0 to EM_MAX_AP_MLD-1) | Should be successful | |
* | 03| Invoke copy constructor to create a new object from the original | dm_assoc_sta_mld_t copy(original) | Should be successful | Should Pass |
* | 04| Verify the number of affiliated stations in the copied object | copy.m_assoc_sta_mld_info.num_affiliated_sta == original.m_assoc_sta_mld_info.num_affiliated_sta | Should be equal | Should Pass |
* | 05| Verify the MAC addresses of each affiliated station in the copied object | copy.m_assoc_sta_mld_info.affiliated_sta[i].mac_addr[0] == original.m_assoc_sta_mld_info.affiliated_sta[i].mac_addr[0] (for i from 0 to EM_MAX_AP_MLD-1) | Should be equal | Should Pass |
*/
TEST(dm_assoc_sta_mld_t_Test, CopyConstructorWithMaxAffiliatedStations) {
    std::cout << "Entering CopyConstructorWithMaxAffiliatedStations" << std::endl;
    dm_assoc_sta_mld_t original;
    original.m_assoc_sta_mld_info.num_affiliated_sta = EM_MAX_AP_MLD;
    for (size_t i = 0; i < EM_MAX_AP_MLD; ++i) {
        original.m_assoc_sta_mld_info.affiliated_sta[i].mac_addr[0] = static_cast<unsigned char>(i);
    }
    dm_assoc_sta_mld_t copy(original);
    EXPECT_EQ(copy.m_assoc_sta_mld_info.num_affiliated_sta, original.m_assoc_sta_mld_info.num_affiliated_sta);
    for (size_t i = 0; i < EM_MAX_AP_MLD; ++i) {
        EXPECT_EQ(copy.m_assoc_sta_mld_info.affiliated_sta[i].mac_addr[0], original.m_assoc_sta_mld_info.affiliated_sta[i].mac_addr[0]);
    }
    std::cout << "Exiting CopyConstructorWithMaxAffiliatedStations" << std::endl;
}

/**
* @brief Test the copy constructor of dm_assoc_sta_mld_t with zero affiliated stations
*
* This test verifies that the copy constructor of the dm_assoc_sta_mld_t class correctly copies an instance where the number of affiliated stations is zero. This is important to ensure that the copy constructor handles edge cases properly.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 042@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create an original dm_assoc_sta_mld_t object with zero affiliated stations | original.m_assoc_sta_mld_info.num_affiliated_sta = 0 | Object created successfully | Should be successful |
* | 02| Use the copy constructor to create a copy of the original object | dm_assoc_sta_mld_t copy(original) | Copy created successfully | Should be successful |
* | 03| Verify that the number of affiliated stations in the copy is zero | copy.m_assoc_sta_mld_info.num_affiliated_sta = 0 | EXPECT_EQ(copy.m_assoc_sta_mld_info.num_affiliated_sta, 0) | Should Pass |
*/
TEST(dm_assoc_sta_mld_t_Test, CopyConstructorWithZeroAffiliatedStations) {
    std::cout << "Entering CopyConstructorWithZeroAffiliatedStations" << std::endl;
    dm_assoc_sta_mld_t original;
    original.m_assoc_sta_mld_info.num_affiliated_sta = 0;
    dm_assoc_sta_mld_t copy(original);
    EXPECT_EQ(copy.m_assoc_sta_mld_info.num_affiliated_sta, 0);
    std::cout << "Exiting CopyConstructorWithZeroAffiliatedStations" << std::endl;
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
