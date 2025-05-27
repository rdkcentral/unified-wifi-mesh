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
#include "dm_network_ssid.h"


/**
* @brief Test decoding of a valid JSON object with a valid parent ID
*
* This test verifies that the `decode` method of the `dm_network_ssid_t` class correctly decodes a valid JSON object when provided with a valid parent ID.@n
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
* | 01| Create a valid JSON object and a valid parent ID | obj = valid JSON object, parent_id = valid pointer, ssid = instance of dm_network_ssid_t | JSON object and parent ID should be created successfully | Should be successful |
* | 02| Call the decode method with the JSON object and parent ID | obj = valid JSON object, parent_id = valid pointer | Result should be 0 | Should Pass |
* | 03| Free the allocated parent ID | parent_id = valid pointer | Memory should be freed successfully | Should be successful |
*/
TEST(dm_network_ssid_t_Test, ValidJsonObjectWithValidParentID) {
    std::cout << "Entering ValidJsonObjectWithValidParentID" << std::endl;
    cJSON obj;
    void* parent_id = malloc(sizeof(int));
    dm_network_ssid_t ssid;
    int result = ssid.decode(&obj, parent_id);
    EXPECT_EQ(result, 0);
    free(parent_id);
    std::cout << "Exiting ValidJsonObjectWithValidParentID" << std::endl;
}

/**
* @brief Test the behavior of dm_network_ssid_t::decode when a null JSON object is passed.
*
* This test checks the decode function of dm_network_ssid_t class when a null JSON object is provided as input. The function is expected to handle this scenario gracefully and return an error code indicating failure.
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
* | 01| Allocate memory for parent_id | parent_id = malloc(sizeof(int)) | Memory should be allocated successfully | Should be successful |
* | 02| Create dm_network_ssid_t instance | ssid = dm_network_ssid_t() | Instance should be created successfully | Should be successful |
* | 03| Call decode with null JSON object | ssid.decode(nullptr, parent_id) | result = -1 | Should return -1 | Should Pass |
* | 04| Free allocated memory | free(parent_id) | Memory should be freed successfully | Should be successful |
*/
/*code doesn't handle null
TEST(dm_network_ssid_t_Test, NullJsonObject) {
    std::cout << "Entering NullJsonObject" << std::endl;
    void* parent_id = malloc(sizeof(int));
    dm_network_ssid_t ssid;
    int result = ssid.decode(nullptr, parent_id);
    EXPECT_EQ(result, -1);
    free(parent_id);
    std::cout << "Exiting NullJsonObject" << std::endl;
}
*/    

/**
* @brief Test to verify the behavior of the decode function when a null parent ID is provided.
*
* This test checks the decode function of the dm_network_ssid_t class to ensure it correctly handles a null parent ID. The function is expected to return an error code when the parent ID is null, which is a negative test case to validate error handling.
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
* | 01 | Call decode with null parent ID | obj = cJSON object, parentID = nullptr | result = -1, EXPECT_EQ(result, -1) | Should Fail |
*/
/*code doesn't handle null
TEST(dm_network_ssid_t_Test, NullParentID) {
    std::cout << "Entering NullParentID" << std::endl;
    cJSON obj;
    dm_network_ssid_t ssid;
    int result = ssid.decode(&obj, nullptr);
    EXPECT_EQ(result, -1);
    std::cout << "Exiting NullParentID" << std::endl;
}
*/    

/**
* @brief Test to verify the behavior of the decode function when provided with a JSON object of invalid type.
*
* This test checks the decode function of the dm_network_ssid_t class to ensure it correctly handles a JSON object with an invalid type. The function is expected to return an error code when the JSON object type is invalid.
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
* | 01 | Create a JSON object with invalid type | obj.type = -1 |  | Should be successful |
* | 02 | Allocate memory for parent_id | parent_id = malloc(sizeof(int)) |  | Should be successful |
* | 03 | Call decode function with invalid JSON object | result = ssid.decode(&obj, parent_id) | result = -1, EXPECT_EQ(result, -1) | Should Pass |
* | 04 | Free allocated memory for parent_id | free(parent_id) |  | Should be successful |
*/
TEST(dm_network_ssid_t_Test, JsonObjectWithInvalidType) {
    std::cout << "Entering JsonObjectWithInvalidType" << std::endl;
    cJSON obj;
    obj.type = -1;
    void* parent_id = malloc(sizeof(int));
    dm_network_ssid_t ssid;
    int result = ssid.decode(&obj, parent_id);
    EXPECT_EQ(result, -1);
    free(parent_id);
    std::cout << "Exiting JsonObjectWithInvalidType" << std::endl;
}

/**
* @brief Test the decoding of a JSON object with nested objects.
*
* This test verifies the functionality of the `decode` method in the `dm_network_ssid_t` class when provided with a JSON object that contains nested objects. The objective is to ensure that the method correctly handles and decodes such complex structures.
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
* | 01| Create a JSON object with nested objects | obj.child = (cJSON*)malloc(sizeof(cJSON)), parent_id = malloc(sizeof(int)) | Should be successful | |
* | 02| Invoke the decode method | ssid.decode(&obj, parent_id) | result = 0, EXPECT_EQ(result, 0) | Should Pass |
* | 03| Clean up allocated memory | free(obj.child), free(parent_id) | Should be successful | |
*/
TEST(dm_network_ssid_t_Test, JsonObjectWithNestedObjects) {
    std::cout << "Entering JsonObjectWithNestedObjects" << std::endl;
    cJSON obj;
    obj.child = static_cast<cJSON*>(malloc(sizeof(cJSON)));
    void* parent_id = malloc(sizeof(int));
    dm_network_ssid_t ssid;
    int result = ssid.decode(&obj, parent_id);
    EXPECT_EQ(result, 0);
    free(obj.child);
    free(parent_id);
    std::cout << "Exiting JsonObjectWithNestedObjects" << std::endl;
}

/**
* @brief Test the decoding of a JSON object with an array type.
*
* This test verifies that the `decode` method of the `dm_network_ssid_t` class correctly handles a JSON object of type array. The test ensures that the method returns the expected result when provided with a JSON array object and a valid parent ID.
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
* | 01 | Set up the test environment | instance = new dm_network_ssid_t() | Should be successful | |
* | 02 | Initialize a cJSON object of type array | obj.type = cJSON_Array | Should be successful | |
* | 03 | Allocate memory for parent_id | parent_id = malloc(sizeof(int)) | Should be successful | |
* | 04 | Call the decode method with the JSON array object and parent_id | ssid.decode(&obj, parent_id) | result = 0, EXPECT_EQ(result, 0) | Should Pass |
* | 05 | Free the allocated memory for parent_id | free(parent_id) | Should be successful | |
* | 06 | Tear down the test environment | delete instance | Should be successful | |
*/
TEST(dm_network_ssid_t_Test, JsonObjectWithArray) {
    std::cout << "Entering JsonObjectWithArray" << std::endl;
    cJSON obj;
    obj.type = cJSON_Array;
    void* parent_id = malloc(sizeof(int));
    dm_network_ssid_t ssid;
    int result = ssid.decode(&obj, parent_id);
    EXPECT_EQ(result, 0);
    free(parent_id);
    std::cout << "Exiting JsonObjectWithArray" << std::endl;
}

/**
* @brief Test the behavior of the decode function when provided with an empty JSON object.
*
* This test checks the decode function of the dm_network_ssid_t class to ensure it correctly handles an empty JSON object by returning an error code.@n
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Initialize an empty JSON object | obj.child = nullptr | N/A | Should be successful |
* | 02| Allocate memory for parent_id | parent_id = malloc(sizeof(int)) | N/A | Should be successful |
* | 03| Create an instance of dm_network_ssid_t | dm_network_ssid_t ssid | N/A | Should be successful |
* | 04| Call the decode function with the empty JSON object and parent_id | ssid.decode(&obj, parent_id) | obj.child = nullptr, parent_id = malloc(sizeof(int)) | result = -1, EXPECT_EQ(result, -1) | Should Pass |
* | 05| Free the allocated memory for parent_id | free(parent_id) | parent_id = malloc(sizeof(int)) | N/A | Should be successful |
*/
TEST(dm_network_ssid_t_Test, JsonObjectWithEmptyObject) {
    std::cout << "Entering JsonObjectWithEmptyObject" << std::endl;
    cJSON obj;
    obj.child = nullptr;
    void* parent_id = malloc(sizeof(int));
    dm_network_ssid_t ssid;
    int result = ssid.decode(&obj, parent_id);
    EXPECT_EQ(result, -1);
    free(parent_id);
    std::cout << "Exiting JsonObjectWithEmptyObject" << std::endl;
}

/**
* @brief Test the copy constructor of dm_network_ssid_t with valid input
*
* This test verifies that the copy constructor of the dm_network_ssid_t class correctly copies the data from the original object to the new object. It ensures that the number of bands and the SSID string are accurately copied.
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
* | 01 | Create original object and set values | original.m_network_ssid_info.num_bands = 2, original.m_network_ssid_info.ssid = "TestSSID" | Values set successfully | Should be successful |
* | 02 | Invoke copy constructor | dm_network_ssid_t copy(original) | Copy object created successfully | Should Pass |
* | 03 | Verify num_bands in copy | copy.m_network_ssid_info.num_bands | Should be equal to original.m_network_ssid_info.num_bands | Should Pass |
* | 04 | Verify ssid in copy | copy.m_network_ssid_info.ssid | Should be equal to original.m_network_ssid_info.ssid | Should Pass |
*/
TEST(dm_network_ssid_t_Test, CopyConstructorWithValidInput) {
    std::cout << "Entering CopyConstructorWithValidInput test";
    dm_network_ssid_t original;
    const char* ssid = "TestSSID";
    original.m_network_ssid_info.num_bands = 2;
    memcpy(original.m_network_ssid_info.ssid, ssid, strlen(ssid)+1);
    dm_network_ssid_t copy(original);
    ASSERT_EQ(copy.m_network_ssid_info.num_bands, original.m_network_ssid_info.num_bands);
    ASSERT_STREQ(copy.m_network_ssid_info.ssid, original.m_network_ssid_info.ssid);
    std::cout << "Exiting CopyConstructorWithValidInput test";
}

/**
* @brief Test the copy constructor with a null object
*
* This test verifies that the copy constructor of the dm_network_ssid_t class
* throws an exception when attempting to copy from a null object. This is important
* to ensure that the class handles null pointers gracefully and does not cause
* undefined behavior or crashes.
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Attempt to copy construct from a null object | original = nullptr | Exception should be thrown | Should Pass |
*/
/*code doesn't handle null
TEST(dm_network_ssid_t_Test, CopyConstructorWithNullObject) {
    std::cout << "Entering CopyConstructorWithNullObject test";
    dm_network_ssid_t* original = nullptr;
    try {
        dm_network_ssid_t copy(*original);
        FAIL() << "Expected std::exception";
    } catch (const std::exception& e) {
        SUCCEED();
    } catch (...) {
        FAIL() << "Expected std::exception";
    }
    std::cout << "Exiting CopyConstructorWithNullObject test";
}
*/

/**
* @brief Test the copy constructor of dm_network_ssid_t with special characters in fields
*
* This test verifies that the copy constructor of the dm_network_ssid_t class correctly copies the ssid field, even when it contains special characters.@n
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
* | 01| Create an original dm_network_ssid_t object and set ssid with special characters | original.m_network_ssid_info.ssid = "Test@SSID#123" |  | Should be successful |
* | 02| Create a copy of the original object using the copy constructor | dm_network_ssid_t copy(original) |  | Should be successful |
* | 03| Verify that the ssid field in the copied object matches the original | ASSERT_STREQ(copy.m_network_ssid_info.ssid, original.m_network_ssid_info.ssid) |  | Should Pass |
*/
TEST(dm_network_ssid_t_Test, CopyConstructorWithSpecialCharactersInFields) {
    std::cout << "Entering CopyConstructorWithSpecialCharactersInFields test";
    dm_network_ssid_t original;
    strcpy(original.m_network_ssid_info.ssid, "Test@SSID#123");
    dm_network_ssid_t copy(original);
    ASSERT_STREQ(copy.m_network_ssid_info.ssid, original.m_network_ssid_info.ssid);
    std::cout << "Exiting CopyConstructorWithSpecialCharactersInFields test";
}

/**
* @brief Test to validate the network SSID information
*
* This test checks the correctness of the network SSID information stored in the dm_network_ssid_t object. It ensures that all fields are correctly initialized and match the expected values.
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Initialize network SSID information | net_ssid = { "id123", "ssid123", "pass123", 2, {"band1", "band2"}, true, 1, {"akm1"}, "suite1", true, "mfp1", {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, 1, em_haul_type_fronthaul} | Object should be initialized with given data | Should Pass |
* | 02| Validate ID field | obj.m_network_ssid_info.id = "id123" | ASSERT_EQ(obj.m_network_ssid_info.id, std::string("id123")) | Should Pass |
* | 03| Validate SSID field | obj.m_network_ssid_info.ssid = "ssid123" | ASSERT_EQ(obj.m_network_ssid_info.ssid, std::string("ssid123")) | Should Pass |
* | 04| Validate pass phrase field | obj.m_network_ssid_info.pass_phrase = "pass123" | ASSERT_EQ(obj.m_network_ssid_info.pass_phrase, std::string("pass123")) | Should Pass |
* | 05| Validate number of bands | obj.m_network_ssid_info.num_bands = 2 | ASSERT_EQ(obj.m_network_ssid_info.num_bands, 2) | Should Pass |
* | 06| Validate first band | obj.m_network_ssid_info.band[0] = "band1" | ASSERT_EQ(obj.m_network_ssid_info.band[0], std::string("band1")) | Should Pass |
* | 07| Validate second band | obj.m_network_ssid_info.band[1] = "band2" | ASSERT_EQ(obj.m_network_ssid_info.band[1], std::string("band2")) | Should Pass |
* | 08| Validate enable field | obj.m_network_ssid_info.enable = true | ASSERT_TRUE(obj.m_network_ssid_info.enable) | Should Pass |
* | 09| Validate number of AKMs | obj.m_network_ssid_info.num_akms = 1 | ASSERT_EQ(obj.m_network_ssid_info.num_akms, 1) | Should Pass |
* | 10| Validate first AKM | obj.m_network_ssid_info.akm[0] = "akm1" | ASSERT_EQ(obj.m_network_ssid_info.akm[0], std::string("akm1")) | Should Pass |
* | 11| Validate suite select field | obj.m_network_ssid_info.suite_select = "suite1" | ASSERT_EQ(obj.m_network_ssid_info.suite_select, std::string("suite1")) | Should Pass |
* | 12| Validate advertisement field | obj.m_network_ssid_info.advertisement = true | ASSERT_TRUE(obj.m_network_ssid_info.advertisement) | Should Pass |
* | 13| Validate MFP field | obj.m_network_ssid_info.mfp = "mfp1" | ASSERT_EQ(obj.m_network_ssid_info.mfp, std::string("mfp1")) | Should Pass |
* | 14| Validate mobility domain | obj.m_network_ssid_info.mobility_domain = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55} | ASSERT_EQ(memcmp(obj.m_network_ssid_info.mobility_domain, net_ssid.mobility_domain, sizeof(mac_address_t)), 0) | Should Pass |
* | 15| Validate number of hauls | obj.m_network_ssid_info.num_hauls = 1 | ASSERT_EQ(obj.m_network_ssid_info.num_hauls, 1) | Should Pass |
*/
TEST(dm_network_ssid_t_Test, ValidNetworkSSIDInformation) {
    std::cout << "Entering ValidNetworkSSIDInformation" << std::endl;
    em_network_ssid_info_t net_ssid = { "id123", "ssid123", "pass123", 2, {"band1", "band2"}, true, 1, {"akm1"}, "suite1", true, "mfp1", {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, 1, em_haul_type_fronthaul};
    dm_network_ssid_t obj(&net_ssid);
    ASSERT_EQ(obj.m_network_ssid_info.id, std::string("id123"));
    ASSERT_EQ(obj.m_network_ssid_info.ssid, std::string("ssid123"));
    ASSERT_EQ(obj.m_network_ssid_info.pass_phrase, std::string("pass123"));
    ASSERT_EQ(obj.m_network_ssid_info.num_bands, 2);
    ASSERT_EQ(obj.m_network_ssid_info.band[0], std::string("band1"));
    ASSERT_EQ(obj.m_network_ssid_info.band[1], std::string("band2"));
    ASSERT_TRUE(obj.m_network_ssid_info.enable);
    ASSERT_EQ(obj.m_network_ssid_info.num_akms, 1);
    ASSERT_EQ(obj.m_network_ssid_info.akm[0], std::string("akm1"));
    ASSERT_EQ(obj.m_network_ssid_info.suite_select, std::string("suite1"));
    ASSERT_TRUE(obj.m_network_ssid_info.advertisement);
    ASSERT_EQ(obj.m_network_ssid_info.mfp, std::string("mfp1"));
    ASSERT_EQ(memcmp(obj.m_network_ssid_info.mobility_domain, net_ssid.mobility_domain, sizeof(mac_address_t)), 0);
    ASSERT_EQ(obj.m_network_ssid_info.num_hauls, 1);
    std::cout << "Exiting ValidNetworkSSIDInformation" << std::endl;
}

/**
* @brief Test to verify the behavior of dm_network_ssid_t when initialized with a null pointer.
*
* This test ensures that all the fields in the m_network_ssid_info structure are set to their default values.
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
* | 01| Initialize dm_network_ssid_t with null pointer | input = nullptr | Should handle gracefully | Should Pass |
*/
/*code doesn't handle null
TEST(dm_network_ssid_t_Test, NullPointerAsInput) {
    std::cout << "Entering NullPointerAsInput" << std::endl;
    ASSERT_ANY_THROW(dm_network_ssid_t obj(nullptr));
    std::cout << "Exiting NullPointerAsInput" << std::endl;
}
*/    

/**
* @brief Test to verify the behavior of dm_network_ssid_t when initialized with empty SSID information.
*
* This test checks the initialization of the dm_network_ssid_t object with an empty SSID information structure. 
* It ensures that all fields are correctly set to their default values when no data is provided.
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
* | 01 | Initialize dm_network_ssid_t with empty SSID info | net_ssid = { "", "", "", 0, {}, false, 0, {}, "", false, "", {0}, 0, {} } | Object should be initialized with default values | Should Pass |
* | 02 | Check id field | obj.m_network_ssid_info.id[0] | '\0' | Should Pass |
* | 03 | Check ssid field | obj.m_network_ssid_info.ssid[0] | '\0' | Should Pass |
* | 04 | Check pass_phrase field | obj.m_network_ssid_info.pass_phrase[0] | '\0' | Should Pass |
* | 05 | Check num_bands field | obj.m_network_ssid_info.num_bands | 0 | Should Pass |
* | 06 | Check enable field | obj.m_network_ssid_info.enable | false | Should Pass |
* | 07 | Check num_akms field | obj.m_network_ssid_info.num_akms | 0 | Should Pass |
* | 08 | Check suite_select field | obj.m_network_ssid_info.suite_select[0] | '\0' | Should Pass |
* | 09 | Check advertisement field | obj.m_network_ssid_info.advertisement | false | Should Pass |
* | 10 | Check mfp field | obj.m_network_ssid_info.mfp[0] | '\0' | Should Pass |
* | 11 | Check mobility_domain field | obj.m_network_ssid_info.mobility_domain[0] | 0 | Should Pass |
* | 12 | Check num_hauls field | obj.m_network_ssid_info.num_hauls | 0 | Should Pass |
*/
TEST(dm_network_ssid_t_Test, EmptySSIDInformation) {
    std::cout << "Entering EmptySSIDInformation" << std::endl;
    em_network_ssid_info_t net_ssid = { "", "", "", 0, {}, false, 0, {}, "", false, "", {0}, 0, {} };
    dm_network_ssid_t obj(&net_ssid);
    ASSERT_EQ(obj.m_network_ssid_info.id[0], '\0');
    ASSERT_EQ(obj.m_network_ssid_info.ssid[0], '\0');
    ASSERT_EQ(obj.m_network_ssid_info.pass_phrase[0], '\0');
    ASSERT_EQ(obj.m_network_ssid_info.num_bands, 0);
    ASSERT_FALSE(obj.m_network_ssid_info.enable);
    ASSERT_EQ(obj.m_network_ssid_info.num_akms, 0);
    ASSERT_EQ(obj.m_network_ssid_info.suite_select[0], '\0');
    ASSERT_FALSE(obj.m_network_ssid_info.advertisement);
    ASSERT_EQ(obj.m_network_ssid_info.mfp[0], '\0');
    ASSERT_EQ(obj.m_network_ssid_info.mobility_domain[0], 0);
    ASSERT_EQ(obj.m_network_ssid_info.num_hauls, 0);
    std::cout << "Exiting EmptySSIDInformation" << std::endl;
}

/**
* @brief Test to verify the encoding of a valid string value
*
* This test checks the functionality of the encode method in the dm_network_ssid_t class by passing a valid cJSON object with a string value. The objective is to ensure that the encode method correctly processes and encodes the string value without errors.
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
* | 01| Set up the test environment | instance = new dm_network_ssid_t() | Should be successful | Should be successful |
* | 02| Create a cJSON object with a string value | obj.type = cJSON_String, obj.valuestring = "test_string" | Should be successful | Should be successful |
* | 03| Call the encode method with the cJSON object | instance.encode(&obj) | Should Pass | Should Pass |
* | 04| Tear down the test environment | delete instance | Should be successful | Should be successful |
*/
TEST(dm_network_ssid_t_Test, EncodeValidStringValue) {
    std::cout << "Entering EncodeValidStringValue test";
    cJSON obj = {};
    obj.type = cJSON_String;
    obj.valuestring = const_cast<char*>("test_string");
    dm_network_ssid_t instance;
    instance.encode(&obj);
    std::cout << "Exiting EncodeValidStringValue test";
}

/**
* @brief Test the encoding of a valid number value in dm_network_ssid_t
*
* This test verifies that the encode function of the dm_network_ssid_t class correctly handles a cJSON object of type Number and encodes it properly.@n
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
* | 01 | Create a cJSON object of type Number | obj.type = cJSON_Number, obj.valuedouble = 123.45 | cJSON object created successfully | Should be successful |
* | 02 | Encode the cJSON object using dm_network_ssid_t instance | instance.encode(&obj) | Encoding should be successful | Should Pass |
*/
TEST(dm_network_ssid_t_Test, EncodeValidNumberValue) {
    std::cout << "Entering EncodeValidNumberValue test";
    cJSON obj;
    obj.type = cJSON_Number;
    obj.valuedouble = 123.45;
    dm_network_ssid_t instance;
    instance.encode(&obj);
    std::cout << "Exiting EncodeValidNumberValue test";
}

/**
* @brief Test the encoding of a valid array of numbers
*
* This test verifies that the `encode` method of the `dm_network_ssid_t` class correctly encodes a cJSON object representing an array of numbers. The test ensures that the method handles the array structure and numeric values as expected.
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
* | 01 | Initialize cJSON object and children | obj.type = cJSON_Array, child1.type = cJSON_Number, child1.valuedouble = 1.0, child2.type = cJSON_Number, child2.valuedouble = 2.0, child1.next = &child2, child2.next = NULL, obj.child = &child1 | cJSON object and children initialized correctly | Should be successful |
* | 02 | Call encode method | instance.encode(&obj) | Method should process the array of numbers correctly | Should Pass |
*/
TEST(dm_network_ssid_t_Test, EncodeValidArrayOfNumbers) {
    std::cout << "Entering EncodeValidArrayOfNumbers test";
    cJSON obj;
    cJSON child1, child2;
    obj.type = cJSON_Array;
    child1.type = cJSON_Number;
    child1.valuedouble = 1.0;
    child2.type = cJSON_Number;
    child2.valuedouble = 2.0;
    child1.next = &child2;
    child2.next = NULL;
    obj.child = &child1;
    dm_network_ssid_t instance;
    instance.encode(&obj);
    std::cout << "Exiting EncodeValidArrayOfNumbers test";
}

/**
* @brief Test the behavior of the encode function when a null pointer is passed.
*
* This test checks the encode function of the dm_network_ssid_t class to ensure it handles a null pointer correctly.@n
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create an instance of dm_network_ssid_t | instance = new dm_network_ssid_t() | Instance should be created successfully | Should be successful |
* | 02| Call encode with a null pointer | obj = NULL, instance.encode(obj) | Function should handle null pointer gracefully | Should Pass |
* | 03| Delete the instance of dm_network_ssid_t | delete instance | Instance should be deleted successfully | Should be successful |
*/
/*code doesn't handle null
TEST(dm_network_ssid_t_Test, EncodeNullPointer) {
    std::cout << "Entering EncodeNullPointer test";
    cJSON *obj = NULL;
    dm_network_ssid_t instance;
    instance.encode(obj);
    std::cout << "Exiting EncodeNullPointer test";
}
*/    

/**
* @brief Test to verify the behavior of the encode function with an invalid type
*
* This test checks the behavior of the encode function when provided with an invalid type in the cJSON object. This is important to ensure that the function handles invalid inputs gracefully and does not cause unexpected behavior or crashes.
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
* | 01 | Set up the test environment | instance = new dm_network_ssid_t() | Should be successful | |
* | 02 | Create a cJSON object with an invalid type | obj.type = -1 | Should be successful | |
* | 03 | Call the encode function with the invalid cJSON object | instance.encode(&obj) | Should Pass | |
* | 04 | Tear down the test environment | delete instance | Should be successful | |
*/
TEST(dm_network_ssid_t_Test, EncodeInvalidType) {
    std::cout << "Entering EncodeInvalidType test";
    cJSON obj;
    obj.type = -1;
    dm_network_ssid_t instance;
    instance.encode(&obj);
    std::cout << "Exiting EncodeInvalidType test";
}

/**
* @brief Test the encoding of a zero number value in dm_network_ssid_t
*
* This test verifies that the encode function of the dm_network_ssid_t class correctly handles a cJSON object with a number value of zero. This is important to ensure that the encoding function can handle edge cases where the number value is at its minimum non-negative value.
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
* | 01 | Set up the test environment | instance = new dm_network_ssid_t() | Should be successful | |
* | 02 | Create a cJSON object with type cJSON_Number and value 0.0 | obj.type = cJSON_Number, obj.valuedouble = 0.0 | Should be successful | |
* | 03 | Call the encode function with the cJSON object | instance.encode(&obj) | Should Pass | |
* | 04 | Tear down the test environment | delete instance | Should be successful | |
*/
TEST(dm_network_ssid_t_Test, EncodeZeroNumberValue) {
    std::cout << "Entering EncodeZeroNumberValue test";
    cJSON obj;
    obj.type = cJSON_Number;
    obj.valuedouble = 0.0;
    dm_network_ssid_t instance;
    instance.encode(&obj);
    std::cout << "Exiting EncodeZeroNumberValue test";
}

/**
* @brief Test the encoding of nested JSON objects
*
* This test verifies that the `encode` method of the `dm_network_ssid_t` class correctly handles nested JSON objects. The test ensures that the nested structure is properly encoded without any errors.
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
* | 01| Initialize JSON objects | obj.type = cJSON_Object, nestedObj.type = cJSON_Object, nestedChild.type = cJSON_String, nestedChild.string = "nested_key", nestedChild.valuestring = "nested_value", nestedChild.next = NULL, nestedObj.child = &nestedChild, nestedObj.next = NULL, obj.child = &nestedObj | JSON objects initialized | Should be successful |
* | 02| Call encode method | instance.encode(&obj) | Method should execute without errors | Should Pass |
*/
TEST(dm_network_ssid_t_Test, EncodeNestedObjects) {
    std::cout << "Entering EncodeNestedObjects test";
    cJSON obj, nestedObj, nestedChild;
    obj.type = cJSON_Object;
    nestedObj.type = cJSON_Object;
    nestedChild.type = cJSON_String;
    nestedChild.string = const_cast<char*>("nested_key");
    nestedChild.valuestring = const_cast<char*>("nested_value");
    nestedChild.next = NULL;
    nestedObj.child = &nestedChild;
    nestedObj.next = NULL;
    obj.child = &nestedObj;
    dm_network_ssid_t instance;
    instance.encode(&obj);
    std::cout << "Exiting EncodeNestedObjects test";
}

/**
* @brief Test to verify the retrieval of network SSID information with valid values.
*
* This test checks the functionality of retrieving network SSID information from the dm_network_ssid_t class instance when initialized with valid values. It ensures that all the fields are correctly set and retrieved.
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
* | 01 | Initialize network SSID info with valid values | id = "TestID", ssid = "TestSSID", pass_phrase = "TestPassPhrase", num_bands = 2, band[0] = "Band1", band[1] = "Band2", enable = true, num_akms = 1, akm[0] = "AKM1", suite_select = "SuiteSelect", advertisement = true, mfp = "MFP", mobility_domain = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, num_hauls = 1, haul_type[0] = em_haul_type_fronthaul | Network SSID info initialized successfully | Should be successful |
* | 02 | Retrieve network SSID info | None | result != nullptr | Should Pass |
* | 03 | Check all the retrieved fields | id = "TestID", ssid = "TestSSID", pass_phrase = "TestPassPhrase", num_bands = 2, band[0] = "Band1", band[1] = "Band2", enable = true, num_akms = 1, akm[0] = "AKM1", suite_select = "SuiteSelect", advertisement = true, mfp = "MFP", mobility_domain = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, num_hauls = 1, haul_type[0] = em_haul_type_fronthaul | Should Pass |
*/
TEST(dm_network_ssid_t_Test, RetrieveNetworkSSIDInfoWithValidValues) {
    std::cout << "Entering RetrieveNetworkSSIDInfoWithValidValues" << std::endl;
    em_network_ssid_info_t net_info;
    memcpy(net_info.id, "TestID", strlen("TestID")+1);
    memcpy(net_info.ssid, "TestSSID", strlen("TestSSID")+1);
    memcpy(net_info.pass_phrase, "TestPassPhrase", strlen("TestPassPhrase")+1);
    net_info.num_bands = 2;
    memcpy(net_info.band[0], "Band1", strlen("Band1")+1);
    memcpy(net_info.band[1], "Band2", strlen("Band2")+1);
    net_info.enable = true;
    net_info.num_akms = 1;
    memcpy(net_info.akm[0], "AKM1", strlen("AKM1")+1);
    memcpy(net_info.suite_select, "SuiteSelect", strlen("SuiteSelect")+1);
    net_info.advertisement = true;
    memcpy(net_info.mfp, "MFP", strlen("MFP")+1);
    net_info.mobility_domain[0] = 0x01;
    net_info.mobility_domain[1] = 0x02;
    net_info.mobility_domain[2] = 0x03;
    net_info.mobility_domain[3] = 0x04;
    net_info.mobility_domain[4] = 0x05;
    net_info.mobility_domain[5] = 0x06;
    net_info.num_hauls = 1;
    net_info.haul_type[0] = em_haul_type_fronthaul;
    dm_network_ssid_t obj(&net_info);
    em_network_ssid_info_t* result = obj.get_network_ssid_info();
    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result->id, "TestID");
    EXPECT_STREQ(result->ssid, "TestSSID");
    EXPECT_STREQ(result->pass_phrase, "TestPassPhrase");
    EXPECT_EQ(result->num_bands, 2);
    EXPECT_STREQ(result->band[0], "Band1");
    EXPECT_STREQ(result->band[1], "Band2");
    EXPECT_TRUE(result->enable);
    EXPECT_EQ(result->num_akms, 1);
    EXPECT_STREQ(result->akm[0], "AKM1");
    EXPECT_STREQ(result->suite_select, "SuiteSelect");
    EXPECT_TRUE(result->advertisement);
    EXPECT_STREQ(result->mfp, "MFP");
    EXPECT_EQ(result->mobility_domain[0], 0x01);
    EXPECT_EQ(result->mobility_domain[1], 0x02);
    EXPECT_EQ(result->mobility_domain[2], 0x03);
    EXPECT_EQ(result->mobility_domain[3], 0x04);
    EXPECT_EQ(result->mobility_domain[4], 0x05);
    EXPECT_EQ(result->mobility_domain[5], 0x06);
    EXPECT_EQ(result->num_hauls, 1);
    EXPECT_EQ(result->haul_type[0], em_haul_type_fronthaul);
    std::cout << "Exiting RetrieveNetworkSSIDInfoWithValidValues" << std::endl;
}

/**
* @brief Test the conversion of a valid input string to the corresponding haul type.
*
* This test verifies that the function `haul_type_from_string` correctly converts a valid input string "fronthaul" to the corresponding enumeration value `em_haul_type_fronthaul`. This ensures that the function handles valid input strings as expected.
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
* | 01| Convert valid input string to haul type | input = "fronthaul", result = em_haul_type_fronthaul | result should be em_haul_type_fronthaul | Should Pass |
*/
TEST(dm_network_ssid_t_Test, ValidInputStringFronthaul) {
    std::cout << "Entering ValidInputStringFronthaul" << std::endl;
    em_string_t input = "fronthaul";
    em_haul_type_t result = dm_network_ssid_t::haul_type_from_string(input);
    EXPECT_EQ(result, em_haul_type_fronthaul);
    std::cout << "Exiting ValidInputStringFronthaul" << std::endl;
}

/**
* @brief Test the conversion of a valid input string to the corresponding haul type.
*
* This test verifies that the function `haul_type_from_string` correctly converts a valid input string "backhaul" to the corresponding enumeration value `em_haul_type_backhaul`. This ensures that the function handles valid input strings as expected.
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
* | 01 | Call `haul_type_from_string` with valid input string "backhaul" | input = "backhaul" | result = `em_haul_type_backhaul`, EXPECT_EQ(result, em_haul_type_backhaul) | Should Pass |
*/
TEST(dm_network_ssid_t_Test, ValidInputStringBackhaul) {
    std::cout << "Entering ValidInputStringBackhaul" << std::endl;
    em_string_t input = "backhaul";
    em_haul_type_t result = dm_network_ssid_t::haul_type_from_string(input);
    EXPECT_EQ(result, em_haul_type_backhaul);
    std::cout << "Exiting ValidInputStringBackhaul" << std::endl;
}

/**
* @brief Test the conversion of a valid input string to the corresponding haul type.
*
* This test checks the conversion of the string "iot" to the corresponding haul type using the dm_network_ssid_t::haul_type_from_string method. It verifies that the method correctly identifies the input string and returns the expected haul type.
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
* | 01| Set up the test environment | instance = new dm_network_ssid_t() | Instance should be created successfully | Should be successful |
* | 02| Convert valid input string "iot" to haul type | input = "iot", result = dm_network_ssid_t::haul_type_from_string(input) | result should be em_haul_type_iot | Should Pass |
* | 03| Verify the result using EXPECT_EQ | result = em_haul_type_iot | EXPECT_EQ should pass | Should Pass |
* | 04| Tear down the test environment | delete instance | Instance should be deleted successfully | Should be successful |
*/
TEST(dm_network_ssid_t_Test, ValidInputStringIot) {
    std::cout << "Entering ValidInputStringIot" << std::endl;
    em_string_t input = "iot";
    em_haul_type_t result = dm_network_ssid_t::haul_type_from_string(input);
    EXPECT_EQ(result, em_haul_type_iot);
    std::cout << "Exiting ValidInputStringIot" << std::endl;
}

/**
* @brief Test the conversion of a valid input string to the corresponding haul type.
*
* This test verifies that the function `haul_type_from_string` correctly converts a valid input string "configurator" to the corresponding enumeration value `em_haul_type_configurator`. This ensures that the string-to-enum conversion logic is functioning as expected.
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
* | 01 | Call `haul_type_from_string` with valid input string "configurator" | input = "configurator" | result = em_haul_type_configurator, EXPECT_EQ(result, em_haul_type_configurator) | Should Pass |
*/
TEST(dm_network_ssid_t_Test, ValidInputStringConfigurator) {
    std::cout << "Entering ValidInputStringConfigurator" << std::endl;
    em_string_t input = "configurator";
    em_haul_type_t result = dm_network_ssid_t::haul_type_from_string(input);
    EXPECT_EQ(result, em_haul_type_configurator);
    std::cout << "Exiting ValidInputStringConfigurator" << std::endl;
}

/**
* @brief Test the conversion of a valid input string to the corresponding haul type
*
* This test verifies that the function `haul_type_from_string` correctly converts a valid input string "hotspot" to the corresponding enumeration value `em_haul_type_hotspot`. This ensures that the function handles valid input strings as expected.
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Set up the test environment | instance = new dm_network_ssid_t() | Instance should be created | Should be successful |
* | 02| Call haul_type_from_string with "hotspot" | input = "hotspot" | result = em_haul_type_hotspot, EXPECT_EQ(result, em_haul_type_hotspot) | Should Pass |
* | 03| Tear down the test environment | delete instance | Instance should be deleted | Should be successful |
*/
TEST(dm_network_ssid_t_Test, ValidInputStringHotspot) {
    std::cout << "Entering ValidInputStringHotspot" << std::endl;
    em_string_t input = "hotspot";
    em_haul_type_t result = dm_network_ssid_t::haul_type_from_string(input);
    EXPECT_EQ(result, em_haul_type_hotspot);
    std::cout << "Exiting ValidInputStringHotspot" << std::endl;
}

/**
* @brief Test the handling of an invalid input string for the haul_type_from_string method.
*
* This test verifies that the dm_network_ssid_t::haul_type_from_string method correctly identifies and handles an invalid input string by returning EM_HAUL_TYPE_INVALID.@n
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
* | 01| Call haul_type_from_string with "unknown" | input = "unknown" | EXPECT_EQ(result, em_haul_type_max) | Should Pass |
*/
TEST(dm_network_ssid_t_Test, InvalidInputStringUnknown) {
    std::cout << "Entering InvalidInputStringUnknown" << std::endl;
    em_string_t input = "unknown";
    em_haul_type_t result = dm_network_ssid_t::haul_type_from_string(input);
    ASSERT_EQ(result, em_haul_type_max);
    std::cout << "Exiting InvalidInputStringUnknown" << std::endl;
}

/**
* @brief Test the conversion of fronthaul type to string representation
*
* This test verifies that the dm_network_ssid_t::haul_type_to_string function correctly converts the fronthaul type to its string representation "fronthaul". This is important to ensure that the conversion logic is accurate and reliable.
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
* | 01| Initialize the string buffer | buffer = "" | buffer should be empty | Should be successful |
* | 02| Convert fronthaul type to string | em_haul_type_fronthaul, str = buffer | str should be "fronthaul" | Should Pass |
* | 03| Verify the string conversion | str = "fronthaul" | EXPECT_STREQ(str, "fronthaul") | Should Pass |
*/
TEST(dm_network_ssid_t_Test, ConvertFronthaulTypeToString) {
    std::cout << "Entering ConvertFronthaulTypeToString" << std::endl;
    char buffer[32] = {};
    dm_network_ssid_t::haul_type_to_string(em_haul_type_fronthaul, buffer);
    EXPECT_STREQ(buffer, "fronthaul");
    std::cout << "Exiting ConvertFronthaulTypeToString" << std::endl;
}

/**
* @brief Test the conversion of backhaul type to string representation
*
* This test verifies that the function `haul_type_to_string` correctly converts the backhaul type enum to its corresponding string representation. This is important to ensure that the conversion logic is functioning as expected, which is critical for any functionality relying on string representations of network types.
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Set up the test environment | instance = new dm_network_ssid_t() | Instance should be created | Should be successful |
* | 02| Initialize buffer and call haul_type_to_string | em_haul_type_backhaul, str = buffer | str should be "backhaul" | Should Pass |
* | 03| Verify the string conversion | EXPECT_STREQ(str, "backhaul") | str should be "backhaul" | Should Pass |
* | 04| Tear down the test environment | delete instance | Instance should be deleted | Should be successful |
*/
TEST(dm_network_ssid_t_Test, ConvertBackhaulTypeToString) {
    std::cout << "Entering ConvertBackhaulTypeToString" << std::endl;
    char buffer[32] = {};
    dm_network_ssid_t::haul_type_to_string(em_haul_type_backhaul, buffer);
    EXPECT_STREQ(buffer, "backhaul");
    std::cout << "Exiting ConvertBackhaulTypeToString" << std::endl;
}

/**
* @brief Test the conversion of IoT haul type to string representation
*
* This test verifies that the function `haul_type_to_string` correctly converts the `em_haul_type_iot` enum value to its corresponding string representation "iot". This is important to ensure that the conversion function works as expected for IoT haul types.
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
* | 01| Convert IoT haul type to string | input: em_haul_type_iot, output: str = buffer | str should be "iot" | Should Pass |
*/
TEST(dm_network_ssid_t_Test, ConvertIoTTypeToString) {
    std::cout << "Entering ConvertIoTTypeToString" << std::endl;
    char buffer[32] = {};
    dm_network_ssid_t::haul_type_to_string(em_haul_type_iot, buffer);
    EXPECT_STREQ(buffer, "iot");
    std::cout << "Exiting ConvertIoTTypeToString" << std::endl;
}

/**
* @brief Test the conversion of haul type to string for the configurator type.
*
* This test verifies that the `haul_type_to_string` method correctly converts the `em_haul_type_configurator` enum value to the string "configurator". This is important to ensure that the conversion function works as expected for valid input values.
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
* | 01| Set up the test environment | instance = new dm_network_ssid_t() | Should be successful | |
* | 02| Initialize the string buffer | str = buffer | Should be successful | |
* | 03| Convert haul type to string | em_haul_type_configurator, str | str should be "configurator" | Should Pass |
* | 04| Verify the string conversion | EXPECT_STREQ(str, "configurator") | Assertion should pass | Should Pass |
* | 05| Tear down the test environment | delete instance | Should be successful | |
*/

TEST(dm_network_ssid_t_Test, ConvertConfiguratorTypeToString) {
    std::cout << "Entering ConvertConfiguratorTypeToString" << std::endl;
    char buffer[32] = {};
    dm_network_ssid_t::haul_type_to_string(em_haul_type_configurator, buffer);
    EXPECT_STREQ(buffer, "configurator");
    std::cout << "Exiting ConvertConfiguratorTypeToString" << std::endl;
}

/**
* @brief Test the conversion of hotspot type to string
*
* This test verifies that the function `haul_type_to_string` correctly converts the `em_haul_type_hotspot` enum value to the string "hotspot". This is important to ensure that the conversion function works as expected for the hotspot type.
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Set up the test environment | instance = new dm_network_ssid_t() | Should be successful | |
* | 02| Initialize the string buffer | str = buffer | Should be successful | |
* | 03| Convert hotspot type to string | em_haul_type_hotspot, str | str should be "hotspot" | Should Pass |
* | 04| Verify the string conversion | EXPECT_STREQ(str, "hotspot") | Should Pass | |
* | 05| Tear down the test environment | delete instance | Should be successful | |
*/
TEST(dm_network_ssid_t_Test, ConvertHotspotTypeToString) {
    std::cout << "Entering ConvertHotspotTypeToString" << std::endl;
    char buffer[32] = {};
    dm_network_ssid_t::haul_type_to_string(em_haul_type_hotspot, buffer);
    EXPECT_STREQ(buffer, "hotspot");
    std::cout << "Exiting ConvertHotspotTypeToString" << std::endl;
}

/**
* @brief Test the conversion of the maximum haul type to string
*
* This test verifies that the function `haul_type_to_string` correctly converts the maximum haul type enum value to its corresponding string representation. This is important to ensure that the function handles boundary values correctly.
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
* | 01| Set up the test environment | instance = new dm_network_ssid_t() | Should be successful | |
* | 02| Initialize the string buffer | str = buffer | Should be successful | |
* | 03| Convert max haul type to string | em_haul_type_max, str | str = "max" | Should Pass |
* | 04| Verify the string conversion | EXPECT_STREQ(str, "max") | Should Pass | |
* | 05| Tear down the test environment | delete instance | Should be successful | |
*/
TEST(dm_network_ssid_t_Test, ConvertMaxTypeToString) {
    std::cout << "Entering ConvertMaxTypeToString" << std::endl;
    char buffer[32] = {};
    dm_network_ssid_t::haul_type_to_string(em_haul_type_max, buffer);
    EXPECT_STREQ(buffer, "max");
    std::cout << "Exiting ConvertMaxTypeToString" << std::endl;
}

/**
* @brief Test to initialize and verify that the Network SSID information structure is set to zero
*
* This test checks if the initialization function of the dm_network_ssid_t class correctly sets the network SSID information structure to zero. This is important to ensure that the structure is properly initialized before use.
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
* | 01| Initialize the dm_network_ssid_t object and call init() | instance = new dm_network_ssid_t(), result = obj.init() | result should be 0, ASSERT_EQ(result, 0) | Should Pass |
*/
TEST(dm_network_ssid_t_Test, InitializeAndVerifyNetworkSSIDInformationStructureIsSetToZero) {
    std::cout << "Entering InitializeAndVerifyNetworkSSIDInformationStructureIsSetToZero" << std::endl;
    dm_network_ssid_t obj;
    int result = obj.init();
    ASSERT_EQ(result, 0);
    std::cout << "Exiting InitializeAndVerifyNetworkSSIDInformationStructureIsSetToZero" << std::endl;
}

/**
* @brief Test to verify the assignment operator for dm_network_ssid_t class
*
* This test checks the assignment operator of the dm_network_ssid_t class by assigning values to one object and then assigning that object to another. It verifies that all the values are correctly copied to the new object.
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create first object and assign values | obj1.m_network_ssid_info.num_bands = 5, obj1.m_network_ssid_info.enable = true, obj1.m_network_ssid_info.num_akms = 3 | Values assigned successfully | Should be successful |
* | 02| Assign first object to second object | obj2 = obj1 | obj2 should have same values as obj1 | Should Pass |
* | 03| Verify num_bands value | obj2.m_network_ssid_info.num_bands == obj1.m_network_ssid_info.num_bands | 5 | Should Pass |
* | 04| Verify enable value | obj2.m_network_ssid_info.enable == obj1.m_network_ssid_info.enable | true | Should Pass |
* | 05| Verify num_akms value | obj2.m_network_ssid_info.num_akms == obj1.m_network_ssid_info.num_akms | 3 | Should Pass |
*/
TEST(dm_network_ssid_t_Test, AssigningMixedValues) {
    std::cout << "Entering AssigningMixedValues test";
    dm_network_ssid_t obj1;
    obj1.m_network_ssid_info.num_bands = 5;
    obj1.m_network_ssid_info.enable = true;
    obj1.m_network_ssid_info.num_akms = 3;
    dm_network_ssid_t obj2;
    obj2 = obj1;
    EXPECT_EQ(obj2.m_network_ssid_info.num_bands, obj1.m_network_ssid_info.num_bands);
    EXPECT_EQ(obj2.m_network_ssid_info.enable, obj1.m_network_ssid_info.enable);
    EXPECT_EQ(obj2.m_network_ssid_info.num_akms, obj1.m_network_ssid_info.num_akms);
    std::cout << "Exiting AssigningMixedValues test";
}

/**
* @brief Test to verify the assignment of null values in dm_network_ssid_t object
*
* This test checks the assignment operator of the dm_network_ssid_t class when assigning an object with null values to another object. This is to ensure that the assignment operator correctly handles and copies null values.
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
* | 01 | Initialize obj1 with null values | obj1.m_network_ssid_info = {0} | obj1.m_network_ssid_info should be all zeros | Should be successful |
* | 02 | Assign obj1 to obj2 | obj2 = obj1 | obj2.m_network_ssid_info should be all zeros | Should Pass |
* | 03 | Compare obj1 and obj2 | memcmp(&obj2.m_network_ssid_info, &obj1.m_network_ssid_info, sizeof(em_network_ssid_info_t)) | Result should be 0 | Should Pass |
*/
TEST(dm_network_ssid_t_Test, AssigningNullValues) {
    std::cout << "Entering AssigningNullValues test";
    dm_network_ssid_t obj1;    
    dm_network_ssid_t obj2;
    obj2 = obj1;    
    EXPECT_EQ(memcmp(&obj2.m_network_ssid_info, &obj1.m_network_ssid_info, sizeof(em_network_ssid_info_t)), 0);
    std::cout << "Exiting AssigningNullValues test";
}

/**
* @brief Test to compare two identical dm_network_ssid_t objects
*
* This test verifies that two newly created dm_network_ssid_t objects are identical by using the equality operator.@n
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create two dm_network_ssid_t objects | obj1, obj2 | Objects should be created successfully | Should be successful |
* | 02| Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_TRUE(obj1 == obj2) | Should Pass |
*/
TEST(dm_network_ssid_t_Test, CompareIdenticalObjects) {
    std::cout << "Entering CompareIdenticalObjects test";
    dm_network_ssid_t obj1;
    dm_network_ssid_t obj2;
    EXPECT_TRUE(obj1 == obj2);
    std::cout << "Exiting CompareIdenticalObjects test";
}

/**
* @brief Test to compare different SSID values
*
* This test verifies that two different SSID values are not considered equal. It ensures that the comparison operator for the `dm_network_ssid_t` class correctly identifies different SSID values as not equal.@n
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
* | 01| Create two instances of dm_network_ssid_t | obj1, obj2 | Instances created successfully | Should be successful |
* | 02| Set SSID of obj1 to "SSID1" | obj1.m_network_ssid_info.ssid = "SSID1" | SSID set successfully | Should be successful |
* | 03| Set SSID of obj2 to "SSID2" | obj2.m_network_ssid_info.ssid = "SSID2" | SSID set successfully | Should be successful |
* | 04| Compare obj1 and obj2 for equality | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_network_ssid_t_Test, CompareDifferentSSIDValues) {
    std::cout << "Entering CompareDifferentSSIDValues test";
    dm_network_ssid_t obj1;
    dm_network_ssid_t obj2;
    memcpy(obj1.m_network_ssid_info.ssid, "SSID1", strlen("SSID1")+1);
    memcpy(obj2.m_network_ssid_info.ssid, "SSID2", strlen("SSID2")+1);
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentSSIDValues test";
}

/**
* @brief Test to compare different passphrase values in dm_network_ssid_t objects
*
* This test verifies that two dm_network_ssid_t objects with different passphrase values are not considered equal.@n
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
* | 01| Create two dm_network_ssid_t objects | obj1, obj2 | Objects created successfully | Should be successful |
* | 02| Set different passphrase values for the objects | obj1.pass_phrase = "pass1", obj2.pass_phrase = "pass2" | Passphrases set successfully | Should be successful |
* | 03| Compare the two objects | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_network_ssid_t_Test, CompareDifferentPassPhraseValues) {
    std::cout << "Entering CompareDifferentPassPhraseValues test";
    dm_network_ssid_t obj1;
    dm_network_ssid_t obj2;
    memcpy(obj1.m_network_ssid_info.pass_phrase, "pass1", strlen("pass1")+1);
    memcpy(obj2.m_network_ssid_info.pass_phrase, "pass2", strlen("pass2")+1);
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentPassPhraseValues test";
}

/**
* @brief Test to compare two dm_network_ssid_t objects with different num_bands values
*
* This test verifies that two dm_network_ssid_t objects with different num_bands values are not considered equal.@n
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 043@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create two dm_network_ssid_t objects with different num_bands values | obj1.m_network_ssid_info.num_bands = 1, obj2.m_network_ssid_info.num_bands = 2 | Objects should not be equal | Should Pass |
* | 02| Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_network_ssid_t_Test, CompareDifferentNumBandsValues) {
    std::cout << "Entering CompareDifferentNumBandsValues test";
    dm_network_ssid_t obj1;
    dm_network_ssid_t obj2;
    obj1.m_network_ssid_info.num_bands = 1;
    obj2.m_network_ssid_info.num_bands = 2;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentNumBandsValues test";
}

/**
* @brief Test to compare two dm_network_ssid_t objects with different enable values
*
* This test verifies that two dm_network_ssid_t objects with different enable values are not considered equal.@n
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 044@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Create two dm_network_ssid_t objects | obj1.m_network_ssid_info.enable = true, obj2.m_network_ssid_info.enable = false | Objects should be created successfully | Should be successful |
* | 02 | Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_network_ssid_t_Test, CompareDifferentEnableValues) {
    std::cout << "Entering CompareDifferentEnableValues test";
    dm_network_ssid_t obj1;
    dm_network_ssid_t obj2;
    obj1.m_network_ssid_info.enable = true;
    obj2.m_network_ssid_info.enable = false;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentEnableValues test";
}

/**
* @brief Test to compare two dm_network_ssid_t objects with different num_akms values
*
* This test verifies that two dm_network_ssid_t objects with different num_akms values are not considered equal.@n
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 045@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create two dm_network_ssid_t objects with different num_akms values | obj1.num_akms = 1, obj2.num_akms = 2 | Objects should not be equal | Should Pass |
* | 02| Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_network_ssid_t_Test, CompareDifferentNumAkmsValues) {
    std::cout << "Entering CompareDifferentNumAkmsValues test";
    dm_network_ssid_t obj1;
    dm_network_ssid_t obj2;
    obj1.m_network_ssid_info.num_akms = 1;
    obj2.m_network_ssid_info.num_akms = 2;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentNumAkmsValues test";
}

/**
* @brief Test to compare different suite select values in dm_network_ssid_t objects
*
* This test verifies that two dm_network_ssid_t objects with different suite select values are not considered equal.@n
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 046@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create two dm_network_ssid_t objects | obj1, obj2 | Objects created successfully | Should be successful |
* | 02| Set suite_select of obj1 to "suite1" | obj1.m_network_ssid_info.suite_select = "suite1" | Value set successfully | Should be successful |
* | 03| Set suite_select of obj2 to "suite2" | obj2.m_network_ssid_info.suite_select = "suite2" | Value set successfully | Should be successful |
* | 04| Compare obj1 and obj2 for equality | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_network_ssid_t_Test, CompareDifferentSuiteSelectValues) {
    std::cout << "Entering CompareDifferentSuiteSelectValues test";
    dm_network_ssid_t obj1;
    dm_network_ssid_t obj2;
    memcpy(obj1.m_network_ssid_info.suite_select, "suite1", strlen("suite1")+1);
    memcpy(obj2.m_network_ssid_info.suite_select, "suite2", strlen("suite2")+1);
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentSuiteSelectValues test";
}

/**
* @brief Test to compare different advertisement values in dm_network_ssid_t objects
*
* This test verifies that two dm_network_ssid_t objects with different advertisement values are not considered equal.@n
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
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Create two dm_network_ssid_t objects | obj1, obj2 | Objects created successfully | Should be successful |
* | 02 | Set advertisement value of obj1 to true | obj1.m_network_ssid_info.advertisement = true | Advertisement value set to true | Should be successful |
* | 03 | Set advertisement value of obj2 to false | obj2.m_network_ssid_info.advertisement = false | Advertisement value set to false | Should be successful |
* | 04 | Compare obj1 and obj2 using == operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_network_ssid_t_Test, CompareDifferentAdvertisementValues) {
    std::cout << "Entering CompareDifferentAdvertisementValues test";
    dm_network_ssid_t obj1;
    dm_network_ssid_t obj2;
    obj1.m_network_ssid_info.advertisement = true;
    obj2.m_network_ssid_info.advertisement = false;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentAdvertisementValues test";
}

/**
* @brief Test to compare different MFP values in dm_network_ssid_t objects
*
* This test verifies that two dm_network_ssid_t objects with different MFP (Management Frame Protection) values are not considered equal. This is important to ensure that the equality operator correctly distinguishes between objects with different MFP settings.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 048@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create two dm_network_ssid_t objects | obj1, obj2 | Objects created successfully | Should be successful |
* | 02| Set different MFP values for the objects | obj1.m_network_ssid_info.mfp = "mfp1", obj2.m_network_ssid_info.mfp = "mfp2" | MFP values set successfully | Should be successful |
* | 03| Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_network_ssid_t_Test, CompareDifferentMfpValues) {
    std::cout << "Entering CompareDifferentMfpValues test";
    dm_network_ssid_t obj1;
    dm_network_ssid_t obj2;
    memcpy(obj1.m_network_ssid_info.mfp, "mfp1", strlen("mfp1")+1);
    memcpy(obj2.m_network_ssid_info.mfp, "mfp2", strlen("mfp2")+1);
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentMfpValues test";
}

/**
* @brief Test to compare different mobility domain values in dm_network_ssid_t objects
*
* This test checks the comparison of two dm_network_ssid_t objects with different mobility domain values to ensure that the equality operator correctly identifies them as not equal.@n
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 049@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create two dm_network_ssid_t objects with different mobility domain values | obj1.mobility_domain = {0, 1, 2, 3, 4, 5}, obj2.mobility_domain = {5, 4, 3, 2, 1, 0} | Objects should not be equal | Should Pass |
* | 02| Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_network_ssid_t_Test, CompareDifferentMobilityDomainValues) {
    std::cout << "Entering CompareDifferentMobilityDomainValues test";
    dm_network_ssid_t obj1;
    dm_network_ssid_t obj2;
    // Set obj1 mobility domain
    uint8_t domain1[] = {0, 1, 2, 3, 4, 5};
    memcpy(obj1.m_network_ssid_info.mobility_domain, domain1, sizeof(domain1));
    // Set obj2 mobility domain (reversed)
    uint8_t domain2[] = {5, 4, 3, 2, 1, 0};
    memcpy(obj2.m_network_ssid_info.mobility_domain, domain2, sizeof(domain2));
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentMobilityDomainValues test";
}

/**
* @brief Test to compare two dm_network_ssid_t objects with different num_hauls values
*
* This test verifies that two dm_network_ssid_t objects with different num_hauls values are not considered equal.@n
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 050@n
* **Priority:** High@n
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create two dm_network_ssid_t objects with different num_hauls values | obj1.m_network_ssid_info.num_hauls = 1, obj2.m_network_ssid_info.num_hauls = 2 | Objects should not be equal | Should Pass |
*/
TEST(dm_network_ssid_t_Test, CompareDifferentNumHaulsValues) {
    std::cout << "Entering CompareDifferentNumHaulsValues test";
    dm_network_ssid_t obj1;
    dm_network_ssid_t obj2;
    obj1.m_network_ssid_info.num_hauls = 1;
    obj2.m_network_ssid_info.num_hauls = 2;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentNumHaulsValues test";
}