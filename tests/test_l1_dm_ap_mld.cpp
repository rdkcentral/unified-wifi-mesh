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
#include "dm_ap_mld.h"


/**
 * @brief Test decoding a valid JSON object with a valid parent ID
 *
 * This test verifies that the decode function correctly processes a valid JSON object when provided with a valid parent ID.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 001
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Parse a valid JSON string | validJson = cJSON_Parse("{\"key\":\"value\"}") | validJson is parsed successfully | Should be successful |
 * | 02 | Set a valid parent ID | parent_id = 1 | parent_id is set to 1 | Should be successful |
 * | 03 | Call the decode function with valid JSON and parent ID | result = instance.decode(validJson, &parent_id) | result = 0 | Should Pass |
 * | 04 | Assert the result is as expected | ASSERT_EQ(result, 0) | result = 0 | Should Pass |
 * | 05 | Clean up the JSON object | cJSON_Delete(validJson) | validJson is deleted | Should be successful |
 */
TEST(dm_ap_mld_t_Test, DecodeValidJsonObjectWithValidParentID) {
    std::cout << "Entering DecodeValidJsonObjectWithValidParentID test" << std::endl;
    cJSON*validJson = cJSON_Parse("{\"key\":\"value\"}");
    int parent_id = 1;
    dm_ap_mld_t instance;
    int result = instance.decode(validJson, &parent_id);
    ASSERT_EQ(result, 0);
    cJSON_Delete(validJson);
    std::cout << "Exiting DecodeValidJsonObjectWithValidParentID test" << std::endl;
}

/**
 * @brief Test the decoding of a valid JSON object with a null parent ID.
 *
 * This test verifies that the decode function correctly handles a valid JSON object when the parent ID is null. 
 * It ensures that the function returns the expected error code (-1) in this scenario.
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
 * | 01 | Parse a valid JSON object | JSON string: {"key":"value"} | cJSON object created successfully | Should be successful |
 * | 02 | Call the decode function with the valid JSON object and a null parent ID | validJson = {"key":"value"}, parentID = nullptr | Return value should be -1 | Should Pass |
 * | 03 | Delete the cJSON object to clean up | validJson = {"key":"value"} | cJSON object deleted successfully | Should be successful |
 */
TEST(dm_ap_mld_t_Test, DecodeValidJsonObjectWithNullParentID) {
    std::cout << "Entering DecodeValidJsonObjectWithNullParentID test" << std::endl;
    cJSON*validJson = cJSON_Parse("{\"key\":\"value\"}");
    dm_ap_mld_t instance;
    int result = instance.decode(validJson, nullptr);
    ASSERT_EQ(result, -1);
    cJSON_Delete(validJson);
    std::cout << "Exiting DecodeValidJsonObjectWithNullParentID test" << std::endl;
}   

/**
 * @brief Test decoding a null JSON object with a valid parent ID
 *
 * This test verifies that the decode function correctly handles a null JSON object when provided with a valid parent ID. The expected behavior is that the function should return an error code (-1) indicating the failure to decode a null JSON object.
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
 * | 01 | Call the decode function with a null JSON object and a valid parent ID | json = nullptr, parent_id = 1 | result = -1 | Should Pass |
 * | 02 | Verify the result of the decode function | result = -1 | result == -1 | Should be successful |
 */
TEST(dm_ap_mld_t_Test, DecodeNullJsonObjectWithValidParentID) {
    std::cout << "Entering DecodeNullJsonObjectWithValidParentID test" << std::endl;
    int parent_id = 1;
    dm_ap_mld_t instance;
    int result = instance.decode(nullptr, &parent_id);
    ASSERT_EQ(result, -1);
    std::cout << "Exiting DecodeNullJsonObjectWithValidParentID test" << std::endl;
}   

/**
 * @brief Test the decoding of an invalid JSON object with a valid parent ID.
 *
 * This test verifies that the decode function correctly handles an invalid JSON object while providing a valid parent ID. The expected behavior is that the function should return an error code indicating failure.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 004@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Parse an invalid JSON string to create a cJSON object. | JSON string: "{key:value}" | cJSON object created | Should be successful |
 * | 02 | Call the decode function with the invalid JSON object and a valid parent ID. | invalidJson = cJSON object, parent_id = 1 | Result = -1 | Should Pass |
 * | 03 | Assert that the result of the decode function is -1. | result = -1 | Assertion passed | Should be successful |
 * | 04 | Clean up the cJSON object. | cJSON object | cJSON object deleted | Should be successful |
 */
TEST(dm_ap_mld_t_Test, DecodeInvalidJsonObjectWithValidParentID) {
    std::cout << "Entering DecodeInvalidJsonObjectWithValidParentID test" << std::endl;
    cJSON*invalidJson = cJSON_Parse("{key:value}");
    int parent_id = 1;
    dm_ap_mld_t instance;
    int result = instance.decode(invalidJson, &parent_id);
    ASSERT_EQ(result, -1);
    cJSON_Delete(invalidJson);
    std::cout << "Exiting DecodeInvalidJsonObjectWithValidParentID test" << std::endl;
}   

/**
 * @brief Test the encoding functionality with a valid cJSON object.
 *
 * This test verifies that the encode function of the dm_ap_mld_t class can handle a valid cJSON object without throwing any exceptions.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 005@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a cJSON object and add a string to it | cJSON object with key="key" and value="value" | cJSON object created successfully | Should be successful |
 * | 02 | Call the encode function with the created cJSON object | cJSON object with key="key" and value="value" | No exceptions thrown | Should Pass |
 * | 03 | Delete the cJSON object to clean up | None | cJSON object deleted successfully | Should be successful |
 */
TEST(dm_ap_mld_t_Test, EncodeWithValidCJSONObject) {
    std::cout << "Entering EncodeWithValidCJSONObject test" << std::endl;
    cJSON*obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "key", "value");
    dm_ap_mld_t instance;
    ASSERT_NO_THROW(instance.encode(obj));
    cJSON_Delete(obj);
    std::cout << "Exiting EncodeWithValidCJSONObject test" << std::endl;
}

/**
 * @brief Test the encode function with a null cJSON object
 *
 * This test checks the behavior of the encode function when it is provided with a null cJSON object. 
 * The function is expected to throw an exception in this scenario.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 006@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Set the cJSON object to null | cJSON*obj = nullptr | cJSON object should be null | Should be successful |
 * | 02 | Call the encode function with the null cJSON object | instance.encode(obj) | Should throw an exception | Should Pass |
 */
TEST(dm_ap_mld_t_Test, EncodeWithNullCJSONObject) {
    std::cout << "Entering EncodeWithNullCJSONObject test" << std::endl;
    cJSON*obj = nullptr;
    dm_ap_mld_t instance;
    ASSERT_ANY_THROW(instance.encode(obj));
    std::cout << "Exiting EncodeWithNullCJSONObject test" << std::endl;
}   

/**
 * @brief Test the encoding functionality with an empty cJSON object.
 *
 * This test verifies that the encode function of the dm_ap_mld_t class can handle an empty cJSON object without throwing any exceptions.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 007@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create an empty cJSON object | None | cJSON object created successfully | Should be successful |
 * | 02 | Call the encode function with the empty cJSON object | obj = empty cJSON object | No exceptions thrown | Should Pass |
 * | 03 | Delete the cJSON object | obj = empty cJSON object | cJSON object deleted successfully | Should be successful |
 */
TEST(dm_ap_mld_t_Test, EncodeWithEmptyCJSONObject) {
    std::cout << "Entering EncodeWithEmptyCJSONObject test" << std::endl;
    cJSON*obj = cJSON_CreateObject();
    dm_ap_mld_t instance;
    ASSERT_NO_THROW(instance.encode(obj));
    cJSON_Delete(obj);
    std::cout << "Exiting EncodeWithEmptyCJSONObject test" << std::endl;
}

/**
 * @brief Test encoding of a cJSON object containing special characters
 *
 * This test verifies that the encode function can handle a cJSON object containing special characters without throwing any exceptions.
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
 * | 01 | Create a cJSON object | None | cJSON object created | Should be successful |
 * | 02 | Add a string with special characters to the cJSON object | key = "!@#$%^&*()_+" | String added to cJSON object | Should be successful |
 * | 03 | Call the encode function with the cJSON object | obj = cJSON object with special characters | No exception thrown | Should Pass |
 * | 04 | Delete the cJSON object | obj = cJSON object | cJSON object deleted | Should be successful |
 */
TEST(dm_ap_mld_t_Test, EncodeWithCJSONObjectContainingSpecialCharacters) {
    std::cout << "Entering EncodeWithCJSONObjectContainingSpecialCharacters test" << std::endl;
    cJSON*obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "key", "!@#$%^&*()_+");
    dm_ap_mld_t instance;
    ASSERT_NO_THROW(instance.encode(obj));
    cJSON_Delete(obj);
    std::cout << "Exiting EncodeWithCJSONObjectContainingSpecialCharacters test" << std::endl;
}

/**
 * @brief Test the retrieval of AP MLD information with the valid values.
 *
 * This test verifies that the `get_ap_mld_info` function correctly retrieves the AP MLD information.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 009@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Set few of the m_ap_mld_info member values | instance.m_ap_mld_info.num_affiliated_ap = EM_MAX_AP_MLD, instance.m_ap_mld_info.mac_addr_valid = false, instance.m_ap_mld_info.str = true, instance.m_ap_mld_info.nstr = false, instance.m_ap_mld_info.emlmr = true, instance.m_ap_mld_info.emlsr = false | Value should be set successfully | Should be successful |
 * | 02 | Retrieve the AP MLD information using `get_ap_mld_info` | info = instance.get_ap_mld_info() | `info` should not be nullptr | Should Pass |
 * | 03 | Verify if the values are retrieved same as the set values | info->num_affiliated_ap = EM_MAX_AP_MLD, info->mac_addr_valid = false, info->str = true, info->nstr = false, info->emlmr = true, info->emlsr = false | Should return true | Ensures the value is correctly stored and retrieved |
 */
TEST(dm_ap_mld_t_Test, RetrieveAPMLDInfoWithValidValues) {
    std::cout << "Entering RetrieveAPMLDInfoWithValidValues test" << std::endl;
    EXPECT_NO_THROW({
        dm_ap_mld_t instance;
        instance.m_ap_mld_info.num_affiliated_ap = EM_MAX_AP_MLD;
        instance.m_ap_mld_info.mac_addr_valid = false;
        instance.m_ap_mld_info.str = true;    
        instance.m_ap_mld_info.nstr = false;    
        instance.m_ap_mld_info.emlmr = true;    
        instance.m_ap_mld_info.emlsr = false; 
        em_ap_mld_info_t* info = instance.get_ap_mld_info();
        ASSERT_NE(info, nullptr);
        ASSERT_EQ(info->num_affiliated_ap, EM_MAX_AP_MLD);
        ASSERT_EQ(info->mac_addr_valid, false);
        ASSERT_EQ(info->str, true);   
        ASSERT_EQ(info->nstr, false);    
        ASSERT_EQ(info->emlmr, true);   
        ASSERT_EQ(info->emlsr, false);
    });
    std::cout << "Exiting RetrieveAPMLDInfoWithValidValues test" << std::endl;
}

/**
 * @brief Test to retrieve AP MLD information with an invalid MAC address
 *
 * This test verifies the behavior of the `get_ap_mld_info` method when the MAC address is invalid (all FF). 
 * It ensures that the method does not return a null pointer, indicating that it handles invalid input gracefully.
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
 * | 01 | Initialize the MAC address to all FF | mac_addr = "FF:FF:FF:FF:FF:FF" | MAC address initialized | Should be successful |
 * | 02 | Call the `get_ap_mld_info` method | None | Method should return a non-null pointer | Should Pass |
 * | 03 | Verify the returned pointer is not null | info != nullptr | Assertion should pass | Should Pass |
 */
TEST(dm_ap_mld_t_Test, RetrieveAPMLDInfoWithInvalidMacAddr) {
    std::cout << "Entering RetrieveAPMLDInfoWithInvalidMacAddr test" << std::endl;
    dm_ap_mld_t instance;
    memset(&instance.m_ap_mld_info.mac_addr, 0xFF, sizeof(mac_address_t));
    em_ap_mld_info_t* info = instance.get_ap_mld_info();
    ASSERT_NE(info, nullptr);
    for (size_t i = 0; i < sizeof(mac_address_t); ++i) {
        EXPECT_NE(info->mac_addr[i], static_cast<uint8_t>(0xFF));
    }
    std::cout << "Exiting RetrieveAPMLDInfoWithInvalidMacAddr test" << std::endl;
}   

/**
 * @brief Test to initialize m_ap_mld_info structure successfully
 *
 * This test verifies that the m_ap_mld_info structure is initialized successfully by calling the init() method of the dm_ap_mld_t class.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 011@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call the init() method on the instance | result = instance.init() | result should be 0 | Should Pass |
 * | 02 | Verify the result using ASSERT_EQ | ASSERT_EQ(result, 0) | result should be 0 | Should be successful |
 */
TEST(dm_ap_mld_t_Test, Initialize_m_ap_mld_info_structure_successfully) {
    std::cout << "Entering Initialize_m_ap_mld_info_structure_successfully test" << std::endl;
    EXPECT_NO_THROW({
        dm_ap_mld_t instance;
        int result = instance.init();
        ASSERT_EQ(result, 0);
    });
    std::cout << "Exiting Initialize_m_ap_mld_info_structure_successfully test" << std::endl;
}

/**
 * @brief Test the initialization of m_ap_mld_info structure when it is already initialized
 *
 * This test verifies that the m_ap_mld_info structure is correctly initialized even if it has already been initialized previously. This ensures that the initialization function handles re-initialization gracefully without errors.
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
 * | 01 | Call the init function twice | None | Return value is 0 | Should Pass |
 * | 02 | Assert that the return value is 0 | None | Assertion passes | Should Pass |
 */
TEST(dm_ap_mld_t_Test, Initialize_m_ap_mld_info_structure_when_already_initialized) {
    std::cout << "Entering Initialize_m_ap_mld_info_structure_when_already_initialized test" << std::endl;
    EXPECT_NO_THROW({
        dm_ap_mld_t instance;
        int result = instance.init();
        ASSERT_EQ(result, 0);
        result = instance.init();
        ASSERT_EQ(result, 0);
    });
    std::cout << "Exiting Initialize_m_ap_mld_info_structure_when_already_initialized test" << std::endl;
}

/**
 * @brief Test to compare two identical objects of dm_ap_mld_t class
 *
 * This test verifies that two objects of the dm_ap_mld_t class with identical m_ap_mld_info attributes are considered equal using the equality operator.@n
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
 * | 01 | Create two dm_ap_mld_t objects | obj1, obj2 | Objects created successfully | Should be successful |
 * | 02 | Set few parameters of m_ap_mld_info of obj1 to be equal to m_ap_mld_info of obj2 | obj1.m_ap_mld_info = obj2.m_ap_mld_info | m_ap_mld_info attributes are identical | Should be successful |
 * | 03 | Compare obj1 and obj2 using equality operator | obj1 == obj2 | EXPECT_TRUE assertion passes | Should Pass |
 */
TEST(dm_ap_mld_t_Test, CompareIdenticalObjects) {
    std::cout << "Entering CompareIdenticalObjects test";
    dm_ap_mld_t obj1{}, obj2{};
    memset(&obj1.m_ap_mld_info, 0, sizeof(obj1.m_ap_mld_info));
    memset(&obj2.m_ap_mld_info, 0, sizeof(obj2.m_ap_mld_info));
    obj1.m_ap_mld_info.mac_addr_valid = obj2.m_ap_mld_info.mac_addr_valid = true;
    obj1.m_ap_mld_info.str = obj2.m_ap_mld_info.str = true;
    obj1.m_ap_mld_info.emlsr = obj2.m_ap_mld_info.emlsr = false;
    EXPECT_TRUE(obj1 == obj2);
    EXPECT_EQ(obj1.m_ap_mld_info.mac_addr_valid, obj2.m_ap_mld_info.mac_addr_valid);
    EXPECT_EQ(obj1.m_ap_mld_info.str, obj2.m_ap_mld_info.str);
    EXPECT_EQ(obj1.m_ap_mld_info.emlsr, obj2.m_ap_mld_info.emlsr);
    std::cout << "Exiting CompareIdenticalObjects test";
}

/**
 * @brief Test to compare two objects with different MAC address validity
 *
 * This test checks the equality operator for `dm_ap_mld_t` objects when they have different MAC address validity flags.@n
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
 * | 01 | Initialize obj1 with mac_addr_valid = true and obj2 with mac_addr_valid = false | obj1.m_ap_mld_info.mac_addr_valid = true, obj2.m_ap_mld_info.mac_addr_valid = false | Objects should not be equal | Should Pass |
 * | 02 | Compare obj1 and obj2 using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
TEST(dm_ap_mld_t_Test, CompareDifferentMacAddrValid) {
    std::cout << "Entering CompareDifferentMacAddrValid test";
    dm_ap_mld_t obj1{}, obj2{};
    memset(&obj1.m_ap_mld_info, 0, sizeof(obj1.m_ap_mld_info));
    memset(&obj2.m_ap_mld_info, 0, sizeof(obj2.m_ap_mld_info));
    obj1.m_ap_mld_info.mac_addr_valid = true;
    obj2.m_ap_mld_info.mac_addr_valid = false;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentMacAddrValid test";
}

/**
 * @brief Test to compare two different SSIDs
 *
 * This test verifies that two objects of type dm_ap_mld_t with different SSIDs are not considered equal.@n
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
 * | 01 | Create two dm_ap_mld_t objects with different SSIDs | obj1.ssid = "SSID1", obj2.ssid = "SSID2" | Objects should not be equal | Should Pass |
 * | 02 | Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
TEST(dm_ap_mld_t_Test, CompareDifferentSSID) {
    std::cout << "Entering CompareDifferentSSID test";
    dm_ap_mld_t obj1{}, obj2{};
    memset(&obj1.m_ap_mld_info, 0, sizeof(obj1.m_ap_mld_info));
    memset(&obj2.m_ap_mld_info, 0, sizeof(obj2.m_ap_mld_info));
    strcpy(obj1.m_ap_mld_info.ssid, "SSID1");
    strcpy(obj2.m_ap_mld_info.ssid, "SSID2");
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentSSID test";
}

/**
 * @brief Test to compare different MAC addresses in dm_ap_mld_t objects
 *
 * This test verifies that two dm_ap_mld_t objects with different MAC addresses are not considered equal.@n
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
 * | 01 | Initialize two dm_ap_mld_t objects | obj1.m_ap_mld_info.mac_addr[0] = 0x01, obj2.m_ap_mld_info.mac_addr[0] = 0x02 | Objects initialized | Should be successful |
 * | 02 | Compare the two objects with different MAC addresses | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
TEST(dm_ap_mld_t_Test, CompareDifferentMacAddr) {
    std::cout << "Entering CompareDifferentMacAddr test";
    dm_ap_mld_t obj1{}, obj2{};
    memset(&obj1.m_ap_mld_info, 0, sizeof(obj1.m_ap_mld_info));
    memset(&obj2.m_ap_mld_info, 0, sizeof(obj2.m_ap_mld_info));
    obj1.m_ap_mld_info.mac_addr[0] = 0x01;
    obj2.m_ap_mld_info.mac_addr[0] = 0x02;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentMacAddr test";
}

/**
 * @brief Test to compare two objects with different 'str' values
 *
 * This test checks the equality operator for the `dm_ap_mld_t` class by comparing two objects with different 'str' values. The objective is to ensure that the equality operator correctly identifies that the two objects are not equal when their 'str' values differ.
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
 * | 01 | Initialize two objects of dm_ap_mld_t | obj1.m_ap_mld_info.str = true, obj2.m_ap_mld_info.str = false | Objects initialized successfully | Should be successful |
 * | 02 | Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
TEST(dm_ap_mld_t_Test, CompareDifferentStr) {
    std::cout << "Entering CompareDifferentStr test";
    dm_ap_mld_t obj1{}, obj2{};
    memset(&obj1.m_ap_mld_info, 0, sizeof(obj1.m_ap_mld_info));
    memset(&obj2.m_ap_mld_info, 0, sizeof(obj2.m_ap_mld_info));
    obj1.m_ap_mld_info.str = true;
    obj2.m_ap_mld_info.str = false;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentStr test";
}

/**
 * @brief Test to compare two dm_ap_mld_t objects with different nstr values
 *
 * This test checks the equality operator for dm_ap_mld_t objects when their nstr values are different. 
 * It ensures that the equality operator correctly identifies that the objects are not equal when their nstr values differ.
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
 * | 01 | Initialize two dm_ap_mld_t objects | obj1.m_ap_mld_info.nstr = true, obj2.m_ap_mld_info.nstr = false | Objects initialized | Should be successful |
 * | 02 | Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
TEST(dm_ap_mld_t_Test, CompareDifferentNstr) {
    std::cout << "Entering CompareDifferentNstr test";
    dm_ap_mld_t obj1{}, obj2{};
    memset(&obj1.m_ap_mld_info, 0, sizeof(obj1.m_ap_mld_info));
    memset(&obj2.m_ap_mld_info, 0, sizeof(obj2.m_ap_mld_info));
    obj1.m_ap_mld_info.nstr = true;
    obj2.m_ap_mld_info.nstr = false;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentNstr test";
}

/**
 * @brief Test to compare two dm_ap_mld_t objects with different emlsr values
 *
 * This test checks the equality operator for dm_ap_mld_t objects when their emlsr values are different. The objective is to ensure that the equality operator correctly identifies that the objects are not equal when their emlsr values differ.
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
 * | 01 | Initialize two dm_ap_mld_t objects | obj1.m_ap_mld_info.emlsr = true, obj2.m_ap_mld_info.emlsr = false | Objects initialized | Should be successful |
 * | 02 | Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
TEST(dm_ap_mld_t_Test, CompareDifferentEmlsr) {
    std::cout << "Entering CompareDifferentEmlsr test";
    dm_ap_mld_t obj1{}, obj2{};
    memset(&obj1.m_ap_mld_info, 0, sizeof(obj1.m_ap_mld_info));
    memset(&obj2.m_ap_mld_info, 0, sizeof(obj2.m_ap_mld_info));
    obj1.m_ap_mld_info.emlsr = true;
    obj2.m_ap_mld_info.emlsr = false;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentEmlsr test";
}

/**
 * @brief Test to compare two dm_ap_mld_t objects with different emlmr values
 *
 * This test checks the equality operator for dm_ap_mld_t objects when their emlmr values are different. 
 * It ensures that the equality operator correctly identifies that the objects are not equal when their emlmr values differ.
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
 * | 01 | Initialize two dm_ap_mld_t objects | obj1.m_ap_mld_info.emlmr = true, obj2.m_ap_mld_info.emlmr = false | Objects initialized | Should be successful |
 * | 02 | Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
TEST(dm_ap_mld_t_Test, CompareDifferentEmlmr) {
    std::cout << "Entering CompareDifferentEmlmr test";
    dm_ap_mld_t obj1{}, obj2{};
    memset(&obj1.m_ap_mld_info, 0, sizeof(obj1.m_ap_mld_info));
    memset(&obj2.m_ap_mld_info, 0, sizeof(obj2.m_ap_mld_info));
    obj1.m_ap_mld_info.emlmr = true;
    obj2.m_ap_mld_info.emlmr = false;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentEmlmr test";
}

/**
 * @brief Test to compare two dm_ap_mld_t objects with different num_affiliated_ap values
 *
 * This test checks the equality operator for dm_ap_mld_t objects when they have different num_affiliated_ap values. 
 * It ensures that the equality operator correctly identifies that the objects are not equal when their num_affiliated_ap values differ.
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
 * | 01 | Initialize two dm_ap_mld_t objects with different num_affiliated_ap values | obj1.num_affiliated_ap = 1, obj2.num_affiliated_ap = 2 | Objects should not be equal | Should Pass |
 * | 02 | Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
TEST(dm_ap_mld_t_Test, CompareDifferentNumAffiliatedAp) {
    std::cout << "Entering CompareDifferentNumAffiliatedAp test";
    dm_ap_mld_t obj1{}, obj2{};
    memset(&obj1.m_ap_mld_info, 0, sizeof(obj1.m_ap_mld_info));
    memset(&obj2.m_ap_mld_info, 0, sizeof(obj2.m_ap_mld_info));
    obj1.m_ap_mld_info.num_affiliated_ap = 1;
    obj2.m_ap_mld_info.num_affiliated_ap = 2;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentNumAffiliatedAp test";
}

/**
 * @brief Test to verify the assignment of a valid object to another object
 *
 * This test checks the assignment operator of the dm_ap_mld_t class by initializing two objects and assigning one to the other. The test ensures that the assignment operator works correctly and that the two objects are equal after the assignment.
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
 * | 01 | Initialize obj1 | obj1.m_ap_mld_info.emlmr = true, obj1.m_ap_mld_info.ssid = "SSID1" | obj1 should be initialized | Should be successful |
 * | 02 | Assign obj2 to obj1 | obj2 = obj1 | obj2 should be equal to obj1 | Should Pass |
 * | 03 | Verify equality | obj1.m_ap_mld_info.emlmr = obj2.m_ap_mld_info.emlmr, obj1.m_ap_mld_info.ssid = obj2.m_ap_mld_info.ssid | obj1 should be equal to obj2 | Should Pass |
 */
TEST(dm_ap_mld_t_Test, AssigningValidObject) {
    std::cout << "Entering AssigningValidObject" << std::endl;
    dm_ap_mld_t obj1{}, obj2{};
    memset(&obj1.m_ap_mld_info, 0, sizeof(obj1.m_ap_mld_info));
    memset(&obj2.m_ap_mld_info, 0, sizeof(obj2.m_ap_mld_info));
    obj1.m_ap_mld_info.emlmr = true;
    strcpy(obj1.m_ap_mld_info.ssid, "SSID1");
    obj2 = obj1;
    ASSERT_EQ(obj1.m_ap_mld_info.emlmr, obj2.m_ap_mld_info.emlmr);
    ASSERT_STREQ(obj1.m_ap_mld_info.ssid, obj2.m_ap_mld_info.ssid);
    std::cout << "Exiting AssigningValidObject" << std::endl;
}

/**
 * @brief Test to verify the assignment of default values between two objects of dm_ap_mld_t class.
 *
 * This test checks if the assignment operator correctly assigns default values from one object to another and ensures that both objects are equal after the assignment.@n
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
 * | 01 | Initialize obj1 with invalid MAC address | obj1.m_ap_mld_info.mac_addr = 0xAA:0xBB:0xDD:0x00:0x00:0x00 | obj1 should be initialized | Should be successful |
 * | 02 | Assign obj2 to obj1 | obj1 = obj2 | obj2 should have the same values as obj1 | Should Pass |
 * | 03 | Check equality of obj1 and obj2 | obj2.m_ap_mld_info.mac_addr = obj1.m_ap_mld_info.mac_addr | obj1 should be equal to obj2 | Should Pass |
 */
TEST(dm_ap_mld_t_Test, AssigningInvalidValues) {
    std::cout << "Entering AssigningInvalidValues" << std::endl;
    dm_ap_mld_t obj1{}, obj2{};
    memset(&obj1.m_ap_mld_info, 0, sizeof(obj1.m_ap_mld_info));
    memset(&obj2.m_ap_mld_info, 0, sizeof(obj2.m_ap_mld_info));
    unsigned char mac[] = {0x0A, 0xBB, 0xDD, 0x00, 0x00, 0x00};
    memcpy(obj1.m_ap_mld_info.mac_addr, mac, sizeof(mac));
    obj2 = obj1;
    for (size_t i = 0; i < sizeof(mac); ++i) {
        ASSERT_EQ(obj2.m_ap_mld_info.mac_addr[i], mac[i]);
    }
    std::cout << "Exiting AssigningInvalidValues" << std::endl;
}

/**
 * @brief Test to validate the AP MLD Information structure initialization and values.
 *
 * This test checks the initialization of the AP MLD Information structure and verifies that the values are correctly set and retrieved.@n
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
 * | 01 | Initialize AP MLD Information structure | mac_addr_valid = true, ssid = "TestSSID", str = true, nstr = false, emlsr = true, emlmr = false, num_affiliated_ap = 1 | Structure should be initialized with given values | Should be successful |
 * | 02 | Create dm_ap_mld_t object with initialized structure | ap_mld_info = initialized structure | Object should be created successfully | Should be successful |
 * | 03 | Verify all the set values | NA  | Set values should be verified by retrieving from the structure | Should Pass |
 *
 */
TEST(dm_ap_mld_t_Test, ValidAPMLDInformation) {
    std::cout << "Entering ValidAPMLDInformation test";
    em_ap_mld_info_t ap_mld_info{};
    memset(&ap_mld_info, 0, sizeof(ap_mld_info));
    ap_mld_info.mac_addr_valid = true;
    strncpy(ap_mld_info.ssid, "TestSSID", sizeof(ap_mld_info.ssid));
    ap_mld_info.str = true;
    ap_mld_info.nstr = false;
    ap_mld_info.emlsr = true;
    ap_mld_info.emlmr = false;
    ap_mld_info.num_affiliated_ap = 1;
    dm_ap_mld_t ap_mld(&ap_mld_info);
    ASSERT_EQ(ap_mld.m_ap_mld_info.mac_addr_valid, true);
    ASSERT_STREQ(ap_mld.m_ap_mld_info.ssid, "TestSSID");
    ASSERT_EQ(ap_mld.m_ap_mld_info.str, true);
    ASSERT_EQ(ap_mld.m_ap_mld_info.nstr, false);
    ASSERT_EQ(ap_mld.m_ap_mld_info.emlsr, true);
    ASSERT_EQ(ap_mld.m_ap_mld_info.emlmr, false);
    ASSERT_EQ(ap_mld.m_ap_mld_info.num_affiliated_ap, 1);
    std::cout << "Exiting ValidAPMLDInformation test";
}

/**
 * @brief Test to verify the behavior of dm_ap_mld_t constructor when provided with a null pointer.
 *
 * This test checks the initialization of the dm_ap_mld_t object when it is constructed with a null pointer for the ap_mld_info parameter. The objective is to ensure that the mac_addr_valid field is correctly set to false in this scenario.
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
 * | 01 | Initialize dm_ap_mld_t with null ap_mld_info | ap_mld_info = nullptr | should not be NULL | Should Pass |
 */
TEST(dm_ap_mld_t_Test, NullAPMLDInformation) {
    std::cout << "Entering NullAPMLDInformation test";
    em_ap_mld_info_t*ap_mld_info = nullptr;
    dm_ap_mld_t ap_mld(ap_mld_info);
    std::cout << "Exiting NullAPMLDInformation test";
}     

/**
 * @brief Test to validate the behavior when an invalid MAC address is provided.
 *
 * This test checks the functionality of the dm_ap_mld_t class when initialized with an invalid MAC address. The objective is to ensure that the mac_addr_valid field is correctly set to false when the MAC address is invalid.
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
 * | 01| Initialize em_ap_mld_info_t with invalid MAC address | mac_addr_valid = true, ssid = "TestSSID", mac_addr = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x00}, str = true, nstr = false, emlsr = true, emlmr = false, num_affiliated_ap = 1 | Initialization should be successful | Should be successful |
 * | 02| Create dm_ap_mld_t object with the initialized em_ap_mld_info_t | ap_mld_info = initialized em_ap_mld_info_t | Object creation should be successful | Should be successful |
 * | 03| Check mac_addr_valid field | ap_mld.m_ap_mld_info.mac_addr_valid | Expected: false | Should Pass |
 */
TEST(dm_ap_mld_t_Test, InvalidMACAddress) {
    std::cout << "Entering InvalidMACAddress test";
    em_ap_mld_info_t ap_mld_info{};
    memset(&ap_mld_info, 0, sizeof(ap_mld_info));
    ap_mld_info.mac_addr_valid = true;
    strncpy(ap_mld_info.ssid, "TestSSID", sizeof(ap_mld_info.ssid));
    uint8_t invalid_mac[6] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x00};
    memcpy(ap_mld_info.mac_addr, invalid_mac, sizeof(invalid_mac));
    ap_mld_info.str = true;
    ap_mld_info.nstr = false;
    ap_mld_info.emlsr = true;
    ap_mld_info.emlmr = false;
    ap_mld_info.num_affiliated_ap = 1;
    dm_ap_mld_t ap_mld(&ap_mld_info);
    for (size_t i = 0; i < sizeof(invalid_mac); ++i) {
        EXPECT_NE(ap_mld.m_ap_mld_info.mac_addr[i], invalid_mac[i]);
    }
    std::cout << "Exiting InvalidMACAddress test";
}

/**
 * @brief Test to verify the behavior when SSID is empty
 *
 * This test checks the behavior of the dm_ap_mld_t class when the SSID is an empty string. It ensures that the class correctly handles and stores an empty SSID, which is a valid edge case scenario.
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
 * | 01| Initialize ap_mld_info with empty SSID | mac_addr_valid = true, ssid = "", mac_addr = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, str = true, nstr = false, emlsr = true, emlmr = false, num_affiliated_ap = 1 | ap_mld_info should be initialized successfully | Should be successful |
 * | 02| Create dm_ap_mld_t object with initialized ap_mld_info | ap_mld_info = initialized object from step 01 | dm_ap_mld_t object should be created successfully | Should be successful |
 * | 03| Verify SSID is empty | ap_mld.m_ap_mld_info.ssid | SSID should be an empty string | Should Pass |
 */
TEST(dm_ap_mld_t_Test, EmptySSID) {
    std::cout << "Entering EmptySSID test";
    em_ap_mld_info_t ap_mld_info{};
    memset(&ap_mld_info, 0, sizeof(ap_mld_info));
    ap_mld_info.mac_addr_valid = true;
    strncpy(ap_mld_info.ssid, "", sizeof(ap_mld_info.ssid));
    uint8_t mac[6] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
    memcpy(ap_mld_info.mac_addr, mac, sizeof(mac));
    ap_mld_info.str = true;
    ap_mld_info.nstr = false;
    ap_mld_info.emlsr = true;
    ap_mld_info.emlmr = false;
    ap_mld_info.num_affiliated_ap = 1;
    dm_ap_mld_t ap_mld(&ap_mld_info);
    ASSERT_STREQ(ap_mld.m_ap_mld_info.ssid, "");
    std::cout << "Exiting EmptySSID test";
}

/**
 * @brief Test to verify the maximum number of affiliated APs
 *
 * This test checks if the dm_ap_mld_t class correctly handles the maximum number of affiliated APs. It ensures that the class can store and retrieve the maximum number of affiliated APs without any issues.
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
 * | 01 | Initialize em_ap_mld_info_t with maximum affiliated APs | mac_addr_valid = true, ssid = "TestSSID", str = true, nstr = false, emlsr = true, emlmr = false, num_affiliated_ap = EM_MAX_AP_MLD | Should initialize successfully | Should be successful |
 * | 02 | Create dm_ap_mld_t object with initialized em_ap_mld_info_t | ap_mld_info = initialized em_ap_mld_info_t | Should create object successfully | Should be successful |
 * | 03 | Verify the number of affiliated APs | ap_mld.m_ap_mld_info.num_affiliated_ap = EM_MAX_AP_MLD | Should be equal to EM_MAX_AP_MLD | Should Pass |
 */
TEST(dm_ap_mld_t_Test, MaximumNumberOfAffiliatedAPs) {
    std::cout << "Entering MaximumNumberOfAffiliatedAPs test";
    em_ap_mld_info_t ap_mld_info{};
    memset(&ap_mld_info, 0, sizeof(ap_mld_info));
    ap_mld_info.mac_addr_valid = true;
    strncpy(ap_mld_info.ssid, "TestSSID", sizeof(ap_mld_info.ssid));
    ap_mld_info.str = true;
    ap_mld_info.nstr = false;
    ap_mld_info.emlsr = true;
    ap_mld_info.emlmr = false;
    ap_mld_info.num_affiliated_ap = EM_MAX_AP_MLD;
    dm_ap_mld_t ap_mld(&ap_mld_info);
    ASSERT_EQ(ap_mld.m_ap_mld_info.num_affiliated_ap, EM_MAX_AP_MLD);
    std::cout << "Exiting MaximumNumberOfAffiliatedAPs test";
}

/**
 * @brief Test to verify the behavior when there are zero affiliated APs.
 *
 * This test checks the initialization and validation of the `dm_ap_mld_t` object when the number of affiliated APs is zero. It ensures that the `num_affiliated_ap` field is correctly set and verified.
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
 * | 01 | Initialize `em_ap_mld_info_t` with zero affiliated APs | mac_addr_valid = true, ssid = "TestSSID", str = true, nstr = false, emlsr = true, emlmr = false, num_affiliated_ap = 0 | Object should be initialized successfully | Should be successful |
 * | 02 | Create `dm_ap_mld_t` object with the initialized `em_ap_mld_info_t` | ap_mld_info = initialized object from step 01 | Object should be created successfully | Should be successful |
 * | 03 | Verify `num_affiliated_ap` field | ap_mld.m_ap_mld_info.num_affiliated_ap | Should be 0 | Should Pass |
 */
TEST(dm_ap_mld_t_Test, ZeroAffiliatedAPs) {
    std::cout << "Entering ZeroAffiliatedAPs test";
    em_ap_mld_info_t ap_mld_info{};
    memset(&ap_mld_info, 0, sizeof(ap_mld_info));
    ap_mld_info.mac_addr_valid = true;
    strncpy(ap_mld_info.ssid, "TestSSID", sizeof(ap_mld_info.ssid));
    ap_mld_info.str = true;
    ap_mld_info.nstr = false;
    ap_mld_info.emlsr = true;
    ap_mld_info.emlmr = false;
    ap_mld_info.num_affiliated_ap = 0;
    dm_ap_mld_t ap_mld(&ap_mld_info);
    ASSERT_EQ(ap_mld.m_ap_mld_info.num_affiliated_ap, 0);
    std::cout << "Exiting ZeroAffiliatedAPs test";
}

/**
 * @brief Test the copy constructor of dm_ap_mld_t with valid values
 *
 * This test verifies that the copy constructor of the dm_ap_mld_t class correctly copies an instance with valid values. It ensures that all fields are accurately duplicated in the new instance.@n
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
 * | 01 | Initialize max_instance with maximum values | m_ap_mld_info.mac_addr_valid = true, m_ap_mld_info.ssid = "MaxSSID", m_ap_mld_info.str = true, m_ap_mld_info.nstr = true, m_ap_mld_info.emlsr = true, m_ap_mld_info.emlmr = true, m_ap_mld_info.num_affiliated_ap = EM_MAX_AP_MLD | max_instance should be initialized with the given values | Should be successful |
 * | 02 | Copy max_instance to copy_instance using copy constructor | copy_instance(max_instance) | copy_instance should be equal to max_instance | Should Pass |
 * | 03 | Assert that copy_instance is equal to max_instance | copy_instance.m_ap_mld_info.str = true, copy_instance.m_ap_mld_info.nstr = true, copy_instance.m_ap_mld_info.emlsr = true, copy_instance.m_ap_mld_info.emlmr = true, copy_instance.m_ap_mld_info.num_affiliated_ap = EM_MAX_AP_MLD | The assertion should pass, confirming the copy was successful | Should Pass |
 */
TEST(dm_ap_mld_t_Test, CopyConstructorWithValidValues) {
    std::cout << "Entering CopyConstructorWithValidValues" << std::endl;
    dm_ap_mld_t max_instance{};
    memset(&max_instance.m_ap_mld_info, 0, sizeof(max_instance.m_ap_mld_info));
    max_instance.m_ap_mld_info.mac_addr_valid = true;
    strncpy(max_instance.m_ap_mld_info.ssid, "MaxSSID", sizeof(max_instance.m_ap_mld_info.ssid));
    max_instance.m_ap_mld_info.str = true;
    max_instance.m_ap_mld_info.nstr = true;
    max_instance.m_ap_mld_info.emlsr = true;
    max_instance.m_ap_mld_info.emlmr = true;
    max_instance.m_ap_mld_info.num_affiliated_ap = EM_MAX_AP_MLD;
    dm_ap_mld_t copy_instance(max_instance);
    ASSERT_EQ(copy_instance.m_ap_mld_info.str, true);
    ASSERT_EQ(copy_instance.m_ap_mld_info.nstr, true);
    ASSERT_EQ(copy_instance.m_ap_mld_info.emlsr, true);
    ASSERT_EQ(copy_instance.m_ap_mld_info.emlmr, true);
    ASSERT_EQ(copy_instance.m_ap_mld_info.num_affiliated_ap, EM_MAX_AP_MLD);
    std::cout << "Exiting CopyConstructorWithValidValues" << std::endl;
}

/**
 * @brief Test the copy constructor of dm_ap_mld_t with a null input
 *
 * This test checks the behavior of the copy constructor when it is provided with a null input. The objective is to ensure that the constructor throws an exception when attempting to copy from a null instance.@n
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
 * | 01 | Attempt to copy construct dm_ap_mld_t with null input | null_instance = nullptr | std::exception should be thrown | Should Pass |
 */
TEST(dm_ap_mld_t_Test, CopyConstructorWithNullInput) {
    std::cout << "Entering CopyConstructorWithNullInput" << std::endl;
    EXPECT_ANY_THROW({
        dm_ap_mld_t* null_instance = nullptr;
        dm_ap_mld_t copy_instance(*null_instance);
    });
    std::cout << "Exiting CopyConstructorWithNullInput" << std::endl;
}     

/**
 * @brief Test to verify that the dm_ap_mld_t default constructor operate without throwing exceptions.
 *
 * This test checks if the dm_ap_mld_t object can be created without any runtime errors. It is designed to track that the default constructor properly initializes the object without issues.
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
 * | Variation / Step | Description                                               | Test Data                                                                    | Expected Result                                                       | Notes         |
 * | :--------------: | --------------------------------------------------------- | ---------------------------------------------------------------------------- | --------------------------------------------------------------------- | ------------- |
 * | 01               | Instantiate dm_ap_mld_t using the default constructor and verify that no exception is thrown during destruction. | No input arguments, output: object instantiation | The API call returns normally without any exceptions being thrown. | Should Pass   |
 */
TEST(dm_ap_mld_t_Test, Constructor) {
    std::cout << "Entering Constructor test" << std::endl;
    EXPECT_NO_THROW({
        dm_ap_mld_t object;
        std::cout << "Invoked dm_ap_mld_t default constructor." << std::endl;
    });
    std::cout << "Exiting Constructor test" << std::endl;
}
/**
 * @brief Verify that the dm_ap_mld_t instance is properly destroyed without throwing exceptions.
 *
 * This test verifies that when a dm_ap_mld_t object is created using the default constructor and then deleted,
 * the destructor cleans up resources without throwing any exceptions. It ensures that resource allocation and
 * deallocation are handled correctly.
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
 * | Variation / Step | Description                                                     | Test Data                                                              | Expected Result                                                                        | Notes         |
 * | :--------------: | --------------------------------------------------------------- | ---------------------------------------------------------------------- | -------------------------------------------------------------------------------------- | ------------- |
 * | 01               | Create a dm_ap_mld_t object using the default constructor.      | No input arguments; output: obj pointer allocated (dm_ap_mld_t instance) | Object is created successfully with resources properly allocated.                    | Should Pass   |
 * | 02               | Delete the dm_ap_mld_t object to invoke its destructor.         | Input: obj pointer; output: resources released                        | No exception thrown during deletion, ensuring destructor invokes resource cleanup cleanly. | Should Pass   |
 */
TEST(dm_ap_mld_t_Test, DestructionOfInstance) {
    std::cout << "Entering DestructionOfInstance test" << std::endl;
    EXPECT_NO_THROW({
        std::cout << "Creating dm_ap_mld_t object using default constructor." << std::endl;
        dm_ap_mld_t* obj = new dm_ap_mld_t();
        std::cout << "Invoking destructor by deleting the dm_ap_mld_t object." << std::endl;
        delete obj;
        std::cout << "Destructor invoked. Resources should have been released cleanly." << std::endl;
    });
    std::cout << "Exiting DestructionOfInstance test" << std::endl;
}