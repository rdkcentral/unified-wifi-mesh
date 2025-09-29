/**
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
#include "dm_bsta_mld.h"

  
/**
 * @brief TEST decoding a valid JSON object with a valid parent ID
 *
 * This TEST verifies that the decode function correctly processes a valid JSON object when provided with a valid parent ID.
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
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Parse a valid JSON string to create a cJSON object | JSON string: "{\"key\":\"value\"}" | cJSON object created successfully | Should be successful |
 * | 02 | Call the decode function with the valid JSON object and a valid parent ID | validJson = cJSON object, parent_id = 1 | Result should be 0 | Should Pass |
 * | 03 | Assert that the result of the decode function is 0 | result = 0 | Assertion should pass | Should Pass |
 * | 04 | Clean up the cJSON object | validJson = cJSON object | cJSON object deleted successfully | Should be successful |
 */
TEST(dm_bsta_mld_Test, DecodeValidJsonObjectWithValidParentID) {
    std::cout << "Entering DecodeValidJsonObjectWithValidParentIDTEST" << std::endl;
    cJSON* validJson = cJSON_Parse("{\"key\":\"value\"}");
    int parent_id = 1;
    dm_bsta_mld_t instance;
    int result = instance.decode(validJson, &parent_id);
    ASSERT_EQ(result, 0);
    cJSON_Delete(validJson);
    std::cout << "Exiting DecodeValidJsonObjectWithValidParentIDTEST" << std::endl;
}
 
/**
 * @brief TEST decoding a valid JSON object with a null parent ID.
 *
 * This TEST verifies that the decode function correctly handles a valid JSON object when the parent ID is null. The expected behavior is that the function should return -1, indicating an error due to the null parent ID.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 002
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Parse a valid JSON object | validJson = cJSON_Parse("{\"key\":\"value\"}") | validJson contains the parsed JSON object | Should be successful |
 * | 02 | Call the decode function with the valid JSON object and null parent ID | result = instance.decode(validJson, nullptr) | result = -1 | Should Pass |
 * | 03 | Assert the result of the decode function | ASSERT_EQ(result, -1) | result is -1 | Should Pass |
 * | 04 | Delete the parsed JSON object | cJSON_Delete(validJson) | validJson is deleted | Should be successful |
 */
/*
TEST(dm_bsta_mld_Test, DecodeValidJsonObjectWithNullParentID) {
    std::cout << "Entering DecodeValidJsonObjectWithNullParentIDTEST" << std::endl;
    cJSON* validJson = cJSON_Parse("{\"key\":\"value\"}");
    dm_bsta_mld_t instance;
    int result = instance.decode(validJson, nullptr);
    ASSERT_EQ(result, -1);
    cJSON_Delete(validJson);
    std::cout << "Exiting DecodeValidJsonObjectWithNullParentIDTEST" << std::endl;
}
*/     
 
/**
 * @brief TEST the decode function with a null JSON object and a valid parent ID.
 *
 * This TEST checks the behavior of the decode function when provided with a null JSON object and a valid parent ID. The expected result is that the function should return an error code (-1) indicating failure to decode.
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
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call the decode function with a null JSON object and a valid parent ID | json_object = nullptr, parent_id = 1 | Result should be -1 | Should Pass |
 */
/* 
TEST(dm_bsta_mld_Test, DecodeNullJsonObjectWithValidParentID) {
    std::cout << "Entering DecodeNullJsonObjectWithValidParentIDTEST" << std::endl;
    int parent_id = 1;
    dm_bsta_mld_t instance;
    int result = instance.decode(nullptr, &parent_id);
    ASSERT_EQ(result, -1);
    std::cout << "Exiting DecodeNullJsonObjectWithValidParentIDTEST" << std::endl;
}
*/    
 
/**
 * @brief TEST to decode an invalid JSON object with a valid parent ID.
 *
 * This TEST checks the behavior of the decode function when provided with an invalid JSON object and a valid parent ID. The objective is to ensure that the function correctly identifies the invalid JSON and returns an error code.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 004
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Parse an invalid JSON object | invalidJson = "{key:value}" | invalidJson should be parsed | Should be successful |
 * | 02 | Call the decode function with invalid JSON and valid parent ID | invalidJson = "{key:value}", parent_id = 1 | result should be -1 | Should Fail |
 * | 03 | Assert the result of the decode function | result = -1 | result should be -1 | Should Fail |
 * | 04 | Delete the invalid JSON object | invalidJson = "{key:value}" | invalidJson should be deleted | Should be successful |
 */
/* 
TEST(dm_bsta_mld_Test, DecodeInvalidJsonObjectWithValidParentID) {
    std::cout << "Entering DecodeInvalidJsonObjectWithValidParentIDTEST" << std::endl;
    cJSON* invalidJson = cJSON_Parse("{key:value}");
    int parent_id = 1;
    dm_bsta_mld_t instance;
    int result = instance.decode(invalidJson, &parent_id);
    ASSERT_EQ(result, -1);
    cJSON_Delete(invalidJson);
    std::cout << "Exiting DecodeInvalidJsonObjectWithValidParentIDTEST" << std::endl;
}
*/    
 
/**
 * @brief TEST decoding a valid JSON object with an invalid parent ID
 *
 * This TEST verifies that the decode function correctly handles a valid JSON object when provided with an invalid parent ID. The expected behavior is that the function should return an error code indicating failure.
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
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Parse a valid JSON object | JSON string: {"key":"value"} | cJSON object created successfully | Should be successful |
 * | 02 | Call the decode function with the valid JSON object and an invalid parent ID | validJson = {"key":"value"}, invalid_parent_id = -1 | Result should be -1 | Should Pass |
 * | 03 | Delete the cJSON object to clean up | validJson = {"key":"value"} | cJSON object deleted successfully | Should be successful |
 */
/* 
TEST(dm_bsta_mld_Test, DecodeValidJsonObjectWithInvalidParentID) {
    std::cout << "Entering DecodeValidJsonObjectWithInvalidParentIDTEST" << std::endl;
    cJSON* validJson = cJSON_Parse("{\"key\":\"value\"}");
    int invalid_parent_id = -1;
    dm_bsta_mld_t instance;
    int result = instance.decode(validJson, &invalid_parent_id);
    ASSERT_EQ(result, -1);
    cJSON_Delete(validJson);
    std::cout << "Exiting DecodeValidJsonObjectWithInvalidParentIDTEST" << std::endl;
}
*/    
 
/**
 * @brief TEST the encoding functionality with a valid cJSON object.
 *
 * This TEST verifies that the encode function of the dm_bsta_mld_t class correctly processes a valid cJSON object. 
 * TheTEST ensures that the object remains valid after encoding and that the function handles various data types correctly.
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
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a cJSON object and add string, number, and boolean values | obj = cJSON_CreateObject(), cJSON_AddStringToObject(obj, "name", "test"), cJSON_AddNumberToObject(obj, "age", 30), cJSON_AddBoolToObject(obj, "is_student", false) | cJSON object is created with specified values | Should be successful |
 * | 02 | Create a nested cJSON object and add it to the main object | nested = cJSON_CreateObject(), cJSON_AddStringToObject(nested, "city", "New York"), cJSON_AddItemToObject(obj, "address", nested) | Nested cJSON object is added to the main object | Should be successful |
 * | 03 | Encode the cJSON object using the instance's encode function | instance.encode(obj) | Object is encoded | Should Pass |
 * | 04 | Verify that the object is still a valid cJSON object | cJSON_IsObject(obj) | Assertion passes | Should Pass |
 * | 05 | Clean up the cJSON object | cJSON_Delete(obj) | Object is deleted | Should be successful |
 */
TEST(dm_bsta_mld_Test, EncodeWithValidCJSONObject) {
    std::cout << "Entering EncodeWithValidCJSONObject" << std::endl;
    EXPECT_NO_THROW({
      cJSON*obj = cJSON_CreateObject();
      cJSON_AddStringToObject(obj, "name", "test");
      cJSON_AddNumberToObject(obj, "age", 30);
      cJSON_AddBoolToObject(obj, "is_student", false);
      cJSON*nested = cJSON_CreateObject();
      cJSON_AddStringToObject(nested, "city", "New York");
      cJSON_AddItemToObject(obj, "address", nested);
      dm_bsta_mld_t instance;
      instance.encode(obj);
      ASSERT_TRUE(cJSON_IsObject(obj));
      cJSON_Delete(obj);
    });
    std::cout << "Exiting EncodeWithValidCJSONObject" << std::endl;
}
 
/**
 * @brief TEST encoding of JSON object with special characters
 *
 * This TEST verifies that the encode function can handle JSON objects containing special characters. It ensures that the function correctly processes and encodes the object without errors.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 007
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a JSON object and add a string with special characters | obj = cJSON_CreateObject(), cJSON_AddStringToObject(obj, "special", "!@#$%^&*()_+") | JSON object created and string added | Should be successful |
 * | 02 | Encode the JSON object using the instance's encode method | instance.encode(obj) | JSON object encoded successfully | Should Pass |
 * | 03 | Verify that the object is still a valid JSON object | cJSON_IsObject(obj) | Assertion passed | Should Pass |
 * | 04 | Clean up the JSON object | cJSON_Delete(obj) | JSON object deleted | Should be successful |
 */
TEST(dm_bsta_mld_Test, EncodeWithSpecialCharacters) {
      std::cout << "Entering EncodeWithSpecialCharacters" << std::endl;
      EXPECT_NO_THROW({
            cJSON*obj = cJSON_CreateObject();
            cJSON_AddStringToObject(obj, "special", "!@#$%^&*()_+");
            dm_bsta_mld_t instance;
            instance.encode(obj);
            ASSERT_TRUE(cJSON_IsObject(obj));
            cJSON_Delete(obj);
      });
      std::cout << "Exiting EncodeWithSpecialCharacters" << std::endl;
}
 
/**
 * @brief TEST the encoding functionality with an empty cJSON object.
 *
 * This TEST verifies that the encode function can handle an empty cJSON object without errors. 
 * It ensures that the object remains a valid cJSON object after encoding.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 008
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create an empty cJSON object | None | cJSON object created | Should be successful |
 * | 02 | Call the encode function with the empty cJSON object | obj = empty cJSON object | None | Should Pass |
 * | 03 | Verify the object is still a valid cJSON object | obj = encoded cJSON object | ASSERT_TRUE(cJSON_IsObject(obj)) | Should Pass |
 * | 04 | Delete the cJSON object | obj = encoded cJSON object | None | Should be successful |
 */
TEST(dm_bsta_mld_Test, EncodeWithEmptyCJSONObject) {
      std::cout << "Entering EncodeWithEmptyCJSONObject" << std::endl;
      EXPECT_NO_THROW({
            cJSON*obj = cJSON_CreateObject();
            dm_bsta_mld_t instance;
            instance.encode(obj);
            ASSERT_TRUE(cJSON_IsObject(obj));
            cJSON_Delete(obj);
      });
      std::cout << "Exiting EncodeWithEmptyCJSONObject" << std::endl;
}
 
/**
 * @brief TEST the encoding function with a null cJSON object
 *
 * This TEST checks the behavior of the encode function when provided with a null cJSON object. 
 * It ensures that the function handles null input gracefully without causing any crashes or unexpected behavior.
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
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize cJSON object to null | cJSON*obj = nullptr | obj is null | Should be successful |
 * | 02 | Call the encode function with the null cJSON object | instance.encode(obj) | Function handles null input gracefully | Should Pass |
 * | 03 | Verify that the cJSON object remains null after encoding | ASSERT_EQ(obj, nullptr) | obj is still null | Should Pass |
 */
/*  
TEST(dm_bsta_mld_Test, EncodeWithNullCJSONObject) {
      std::cout << "Entering EncodeWithNullCJSONObject" << std::endl;
      cJSON*obj = nullptr;
      dm_bsta_mld_t instance;
      EXPECT_ANY_THROW(instance.encode(obj));
      ASSERT_EQ(obj, nullptr);
      std::cout << "Exiting EncodeWithNullCJSONObject" << std::endl;
}
*/      
 
/**
 * @brief TEST the encoding function with an invalid JSON structure.
 *
 * This TEST verifies that the encode function can handle an invalid JSON structure correctly. 
 * Specifically, it checks if the function can process a JSON array containing a string and 
 * ensures that the structure remains an array after encoding.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 010
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a JSON array and add an invalid string item to it | obj = cJSON_CreateArray(); cJSON_AddItemToArray(obj, cJSON_CreateString("invalid")); | JSON array should be created with one string item | Should be successful |
 * | 02 | Call the encode function with the invalid JSON structure | instance.encode(obj) | Function should process the JSON structure | Should Pass |
 * | 03 | Verify that the JSON structure is still an array after encoding | cJSON_IsArray(obj) | Assertion should be true | Should Pass |
 * | 04 | Clean up the JSON object | cJSON_Delete(obj) | JSON object should be deleted successfully | Should be successful |
 */
/* 
TEST(dm_bsta_mld_Test, EncodeWithInvalidJSONStructure) {
    std::cout << "Entering EncodeWithInvalidJSONStructure" << std::endl;
    cJSON* obj = cJSON_CreateArray();
    cJSON_AddItemToArray(obj, cJSON_CreateString("invalid"));
    dm_bsta_mld_t instance;
    EXPECT_ANY_THROW({
        instance.encode(obj);
    });
    cJSON_Delete(obj);
    std::cout << "Exiting EncodeWithInvalidJSONStructure" << std::endl;
}
*/    
 
/**
 * @brief TEST to verify the retrieval of AP MLD information with valid data.
 *
 * This TEST checks the functionality of the `get_bsta_mld_info` method in the `dm_bsta_mld_t` class. 
 * It ensures that the method correctly retrieves and validates the AP MLD information.
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
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Set valid data in `info` | `info` fields set to valid values | Fields in `info` set correctly | Should be successful |
 * | 02 | Retrieve AP MLD info | None | `retrieved_info` should not be nullptr | Should be successful |
 * | 03 | Validate `mac_addr_valid` field | `retrieved_info->mac_addr_valid` | Should be true | Should Pass |
 * | 04 | Validate `ap_mld_mac_addr_valid` field | `retrieved_info->ap_mld_mac_addr_valid` | Should be true | Should Pass |
 * | 05 | Validate `num_affiliated_bsta` field | `retrieved_info->num_affiliated_bsta` | Should be 5 | Should Pass |
 * | 06 | Validate `str` field | `retrieved_info->str` | Should be true | Should Pass |
 * | 07 | Validate `nstr` field | `retrieved_info->nstr` | Should be true | Should Pass |
 * | 08 | Validate `emlsr` field | `retrieved_info->emlsr` | Should be true | Should Pass |
 * | 09 | Validate `emlmr` field | `retrieved_info->emlmr` | Should be true | Should Pass |
 */
TEST(dm_bsta_mld_Test, RetrieveAPMLDInfoWithValidData) {
      std::cout << "Entering RetrieveAPMLDInfoWithValidDataTEST" << std::endl;
      em_bsta_mld_info_t info{};
      info.mac_addr_valid = true;
      info.ap_mld_mac_addr_valid = true;
      info.num_affiliated_bsta = 5;
      info.str = true;
      info.nstr = true;
      info.emlsr = true;
      info.emlmr = true;
      dm_bsta_mld_t instance(&info);
      em_bsta_mld_info_t* retrieved_info = instance.get_bsta_mld_info();
      ASSERT_NE(retrieved_info, nullptr);
      EXPECT_TRUE(retrieved_info->mac_addr_valid);
      EXPECT_TRUE(retrieved_info->ap_mld_mac_addr_valid);
      EXPECT_EQ(retrieved_info->num_affiliated_bsta, 5);
      EXPECT_TRUE(retrieved_info->str);
      EXPECT_TRUE(retrieved_info->nstr);
      EXPECT_TRUE(retrieved_info->emlsr);
      EXPECT_TRUE(retrieved_info->emlmr);
      std::cout << "Exiting RetrieveAPMLDInfoWithValidDataTEST" << std::endl;
}
 
/**
 * @brief TEST to retrieve AP MLD information after null initialization
 *
 * This TEST verifies that the AP MLD information is correctly retrieved after the instance is initialized.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 012
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize the instance to null | dm_bsta_mld_t(nullptr) | Instance initialized successfully | Should be successful |
 * | 02 | Retrieve AP MLD information | info = instance.get_bsta_mld_info() | info != nullptr | Should Pass |
 */
/* 
TEST(dm_bsta_mld_Test, RetrieveAPMLDInfoAfterNullInitialization) {
      std::cout << "Entering RetrieveAPMLDInfoAfterNullInitializationTEST" << std::endl;
      EXPECT_ANY_THROW({
            dm_bsta_mld_t instance(nullptr);
            em_bsta_mld_info_t* info = instance.get_bsta_mld_info();
            ASSERT_NE(info, nullptr);
      });
      std::cout << "Exiting RetrieveAPMLDInfoAfterNullInitializationTEST" << std::endl;
}
*/          
 
/**
 * @brief TEST the initialization of m_bsta_mld_info structure
 *
 * This TEST verifies the initialization of the m_bsta_mld_info structure by calling the init() method of the dm_bsta_mld_t class instance. TheTEST ensures that the initialization is successful and returns the expected result.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 013
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call the init() method on the instance | instance.init() | result = 0 | Should Pass |
 * | 02 | Verify the result of the init() method | ASSERT_EQ(result, 0) | result = 0 | Should Pass |
 */
TEST(dm_bsta_mld_Test, Initialize_m_bsta_mld_info_structure) {
      std::cout << "Entering Initialize_m_bsta_mld_info_structureTEST" << std::endl;
      EXPECT_NO_THROW({
            dm_bsta_mld_t instance;
            int result = instance.init();
            ASSERT_EQ(result, 0);
      });
      std::cout << "Exiting Initialize_m_bsta_mld_info_structureTEST" << std::endl;
}
 
/**
 * @brief TEST the initialization of m_bsta_mld_info structure multiple times
 *
 * This TEST verifies that the m_bsta_mld_info structure can be initialized multiple times without any issues. 
 * It ensures that the init() function can be called more than once and still return a successful result.
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
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call the init() function for the first time | None | result1 = 0 | Should Pass |
 * | 02 | Assert the result of the first init() call | result1 = 0 | Assertion should be true | Should be successful |
 * | 03 | Call the init() function for the second time | None | result2 = 0 | Should Pass |
 * | 04 | Assert the result of the second init() call | result2 = 0 | Assertion should be true | Should be successful |
 */
TEST(dm_bsta_mld_Test, Initialize_m_bsta_mld_info_structure_multiple_times) {
      std::cout << "Entering Initialize_m_bsta_mld_info_structure_multiple_timesTEST" << std::endl;
      EXPECT_NO_THROW({
            dm_bsta_mld_t instance;
            int result1 = instance.init();
            ASSERT_EQ(result1, 0);
            int result2 = instance.init();
            ASSERT_EQ(result2, 0);
      });
      std::cout << "Exiting Initialize_m_bsta_mld_info_structure_multiple_timesTEST" << std::endl;
}
  
/**
 * @brief TEST to verify if two objects of dm_bsta_mld_t are identical
 *
 * This TEST checks if two instances of dm_bsta_mld_t with identical data are considered equal by the equality operator. This is important to ensure that the equality operator is correctly implemented and can accurately compare two objects of the class.
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
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create two identical objects of dm_bsta_mld_t | obj1.m_bsta_mld_info = {true, true, {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, true, true, true, 1} , obj2.m_bsta_mld_info = {true, true, {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, true, true, true, 1} | Objects should be identical | Should Pass |
 * | 02| Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_TRUE(obj1 == obj2) | Should Pass |
 */
TEST(dm_btsa_mld_Test, BothObjectsAreIdentical) {
      std::cout << "Entering BothObjectsAreIdentical" << std::endl;
      dm_bsta_mld_t obj1{}, obj2{};
      auto& info1 = obj1.m_bsta_mld_info;
      auto& info2 = obj2.m_bsta_mld_info;
      memset(&info1, 0, sizeof(info1));
      memset(&info2, 0, sizeof(info2));
      info1.mac_addr_valid = info2.mac_addr_valid = true;
      info1.ap_mld_mac_addr_valid = info2.ap_mld_mac_addr_valid = true;
      uint8_t mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
      memcpy(info1.mac_addr, mac, sizeof(mac));
      memcpy(info2.mac_addr, mac, sizeof(mac));
      uint8_t ap_mac[] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
      memcpy(info1.ap_mld_mac_addr, ap_mac, sizeof(ap_mac));
      memcpy(info2.ap_mld_mac_addr, ap_mac, sizeof(ap_mac));
      info1.str = info2.str = true;
      info1.nstr = info2.nstr = true;
      info1.emlsr = info2.emlsr = true;
      info1.emlmr = info2.emlmr = true;
      info1.num_affiliated_bsta = info2.num_affiliated_bsta = 1;
      EXPECT_TRUE(obj1 == obj2);
      std::cout << "Exiting BothObjectsAreIdentical" << std::endl;
}
 
/**
 * @brief TEST to verify that two objects of dm_bsta_mld_t have different MAC addresses and are not equal.
 *
 * This TEST checks if two instances of dm_bsta_mld_t with different MAC addresses are not considered equal. This is important to ensure that the equality operator correctly identifies objects with different MAC addresses as unequal.
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
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create two instances of dm_bsta_mld_t with different MAC addresses | obj1.m_bsta_mld_info = {true, true, {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, true, true, true, 1}, obj2.m_bsta_mld_info = {false, true, {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, true, true, true, 1} | Instances created successfully | Should be successful |
 * | 02 | Compare the two instances using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
TEST(dm_btsa_mld_Test, ObjectsHaveDifferentMacAddrValid) {
      std::cout << "Entering ObjectsHaveDifferentMacAddrValid" << std::endl;
      dm_bsta_mld_t obj1{}, obj2{};
      auto& info1 = obj1.m_bsta_mld_info;
      auto& info2 = obj2.m_bsta_mld_info;
      memset(&info1, 0, sizeof(info1));
      memset(&info2, 0, sizeof(info2));
      info1.mac_addr_valid = true;
      info2.mac_addr_valid = false;
      info1.ap_mld_mac_addr_valid = info2.ap_mld_mac_addr_valid = true;
      uint8_t mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
      memcpy(info1.mac_addr, mac, sizeof(mac));
      memcpy(info2.mac_addr, mac, sizeof(mac));
      uint8_t ap_mac[] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
      memcpy(info1.ap_mld_mac_addr, ap_mac, sizeof(ap_mac));
      memcpy(info2.ap_mld_mac_addr, ap_mac, sizeof(ap_mac));
      info1.str = info2.str = true;
      info1.nstr = info2.nstr = true;
      info1.emlsr = info2.emlsr = true;
      info1.emlmr = info2.emlmr = true;
      info1.num_affiliated_bsta = info2.num_affiliated_bsta = 1;
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting ObjectsHaveDifferentMacAddrValid" << std::endl;
}
 
/**
 * @brief TEST to verify that two objects of dm_bsta_mld_t have different AP MLD MAC addresses
 *
 * This TEST checks that two instances of dm_bsta_mld_t with different AP MLD MAC addresses are not considered equal.@n
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
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create two instances of dm_bsta_mld_t with different AP MLD MAC addresses | obj1.m_bsta_mld_info = {true, true, {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, true, true, true, 1}, {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}}}}, obj2.m_bsta_mld_info = {true, false, {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, true, true, true, 1} | Two objects should not be equal | Should Pass |
 */
TEST(dm_btsa_mld_Test, ObjectsHaveDifferentApMldMacAddrValid) {
      std::cout << "Entering ObjectsHaveDifferentApMldMacAddrValid" << std::endl;
      dm_bsta_mld_t obj1{}, obj2{};      
      auto& info1 = obj1.m_bsta_mld_info;
      auto& info2 = obj2.m_bsta_mld_info;
      memset(&info1, 0, sizeof(info1));
      memset(&info2, 0, sizeof(info2));
      info1.mac_addr_valid = info2.mac_addr_valid = true;      
      info1.ap_mld_mac_addr_valid = true;
      info2.ap_mld_mac_addr_valid = false;
      uint8_t mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
      memcpy(info1.mac_addr, mac, sizeof(mac));
      memcpy(info2.mac_addr, mac, sizeof(mac));
      uint8_t ap_mac[] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
      memcpy(info1.ap_mld_mac_addr, ap_mac, sizeof(ap_mac));
      memcpy(info2.ap_mld_mac_addr, ap_mac, sizeof(ap_mac));
      info1.str = info2.str = true;
      info1.nstr = info2.nstr = true;
      info1.emlsr = info2.emlsr = true;
      info1.emlmr = info2.emlmr = true;
      info1.num_affiliated_bsta = info2.num_affiliated_bsta = 1;
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting ObjectsHaveDifferentApMldMacAddrValid" << std::endl;
}
 
/**
 * @brief TEST to verify that two objects have different MAC addresses
 *
 * This TEST checks that two instances of `dm_bsta_mld_t` have different MAC addresses and are not considered equal.@n
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
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create two instances of `dm_bsta_mld_t` and set their MAC addresses | obj1.m_bsta_mld_info.mac_addr = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, obj2.m_bsta_mld_info.mac_addr = {0x00, 0x11, 0x22, 0x33, 0x44, 0x56} | Instances should have different MAC addresses | Should Pass |
 * | 02| Compare the two instances using `EXPECT_FALSE` | obj1 == obj2 | The comparison should return false | Should Pass |
 */
TEST(dm_btsa_mld_Test, ObjectsHaveDifferentMacAddr) {
      std::cout << "Entering ObjectsHaveDifferentMacAddr" << std::endl;
      dm_bsta_mld_t obj1{}, obj2{};
      auto& info1 = obj1.m_bsta_mld_info;
      auto& info2 = obj2.m_bsta_mld_info;
      memset(&info1, 0, sizeof(info1));
      memset(&info2, 0, sizeof(info2));
      info1.mac_addr_valid = info2.mac_addr_valid = true;      
      info1.ap_mld_mac_addr_valid = info2.ap_mld_mac_addr_valid = true;
      uint8_t mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
      uint8_t mac1[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x56};
      memcpy(info1.mac_addr, mac, sizeof(mac));
      memcpy(info2.mac_addr, mac1, sizeof(mac1));
      uint8_t ap_mac[] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
      memcpy(info1.ap_mld_mac_addr, ap_mac, sizeof(ap_mac));
      memcpy(info2.ap_mld_mac_addr, ap_mac, sizeof(ap_mac));
      info1.str = info2.str = true;
      info1.nstr = info2.nstr = true;
      info1.emlsr = info2.emlsr = true;
      info1.emlmr = info2.emlmr = true;
      info1.num_affiliated_bsta = info2.num_affiliated_bsta = 1;
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting ObjectsHaveDifferentMacAddr" << std::endl;
}
 
/**
 * @brief TEST to verify that two objects of dm_bsta_mld_t have different AP MLD MAC addresses
 *
 * This TEST checks if two instances of dm_bsta_mld_t have different AP MLD MAC addresses and ensures that the equality operator correctly identifies them as different objects.@n
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
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create two instances of dm_bsta_mld_t and set their m_bsta_mld_info with different AP MLD MAC addresses | obj1.m_bsta_mld_info = {true, true, {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, true, true, true, 1}, obj2.m_bsta_mld_info = {true, true, {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBC}, true, true, true, true, 1} | Objects should be different | Should Pass |
 * | 02| Check if the equality operator identifies them as different | EXPECT_FALSE(obj1 == obj2) |TEST should pass | Should Pass |
 */
TEST(dm_btsa_mld_Test, ObjectsHaveDifferentApMldMacAddr) {
      std::cout << "Entering ObjectsHaveDifferentApMldMacAddr" << std::endl;
      dm_bsta_mld_t obj1{}, obj2{};
      auto& info1 = obj1.m_bsta_mld_info;
      auto& info2 = obj2.m_bsta_mld_info;
      memset(&info1, 0, sizeof(info1));
      memset(&info2, 0, sizeof(info2));
      info1.mac_addr_valid = info2.mac_addr_valid = true;      
      info1.ap_mld_mac_addr_valid = info2.ap_mld_mac_addr_valid = true;
      uint8_t mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
      memcpy(info1.mac_addr, mac, sizeof(mac));
      memcpy(info2.mac_addr, mac, sizeof(mac));
      uint8_t ap_mac[] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
      uint8_t ap_mac1[] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBC};
      memcpy(info1.ap_mld_mac_addr, ap_mac, sizeof(ap_mac));
      memcpy(info2.ap_mld_mac_addr, ap_mac1, sizeof(ap_mac1));
      info1.str = info2.str = true;
      info1.nstr = info2.nstr = true;
      info1.emlsr = info2.emlsr = true;
      info1.emlmr = info2.emlmr = true;
      info1.num_affiliated_bsta = info2.num_affiliated_bsta = 1;
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting ObjectsHaveDifferentApMldMacAddr" << std::endl;
}
 
/**
 * @brief TEST to verify that two objects of dm_bsta_mld_t have different m_bsta_mld_info structures.
 *
 * This TEST checks if two objects of dm_bsta_mld_t have different m_bsta_mld_info structures by comparing them using the equality operator. TheTEST ensures that the equality operator correctly identifies the difference in the structures.
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
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create two objects of dm_bsta_mld_t and set their m_bsta_mld_info structures with different values | obj1.m_bsta_mld_info = {true, true, {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, true, true, true, 1}, obj2.m_bsta_mld_info = {true, true, {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, false, true, true, true, 1} | Objects should have different m_bsta_mld_info structures | Should Pass |
 * | 02| Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
 */
TEST(dm_btsa_mld_Test, ObjectsHaveDifferentStr) {
      std::cout << "Entering ObjectsHaveDifferentStr" << std::endl;
      dm_bsta_mld_t obj1{}, obj2{};
      auto& info1 = obj1.m_bsta_mld_info;
      auto& info2 = obj2.m_bsta_mld_info;
      memset(&info1, 0, sizeof(info1));
      memset(&info2, 0, sizeof(info2));
      info1.mac_addr_valid = info2.mac_addr_valid = true;      
      info1.ap_mld_mac_addr_valid = info2.ap_mld_mac_addr_valid = true;
      uint8_t mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
      memcpy(info1.mac_addr, mac, sizeof(mac));
      memcpy(info2.mac_addr, mac, sizeof(mac));
      uint8_t ap_mac[] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
      memcpy(info1.ap_mld_mac_addr, ap_mac, sizeof(ap_mac));
      memcpy(info2.ap_mld_mac_addr, ap_mac, sizeof(ap_mac));
      info1.str = true;
      info2.str = false;
      info1.nstr = info2.nstr = true;
      info1.emlsr = info2.emlsr = true;
      info1.emlmr = info2.emlmr = true;
      info1.num_affiliated_bsta = info2.num_affiliated_bsta = 1;
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting ObjectsHaveDifferentStr" << std::endl;
}
 
/**
 * @brief TEST to verify that two objects of dm_bsta_mld_t have different nstr values
 *
 * This TEST checks if two objects of dm_bsta_mld_t have different nstr values and ensures that the equality operator correctly identifies them as not equal.@n
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
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create two objects of dm_bsta_mld_t and set their m_bsta_mld_info with different nstr values | obj1.m_bsta_mld_info = {true, true, {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, true, true, true, 1}, obj2.m_bsta_mld_info = {true, true, {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, false, true, true, 1} | Objects should have different nstr values | Should be successful |
 * | 02| Check if the equality operator identifies them as not equal | EXPECT_FALSE(obj1 == obj2) | The objects should not be equal | Should Pass |
 */
TEST(dm_btsa_mld_Test, ObjectsHaveDifferentNstr) {
      std::cout << "Entering ObjectsHaveDifferentNstr" << std::endl;
      dm_bsta_mld_t obj1{}, obj2{};
      auto& info1 = obj1.m_bsta_mld_info;
      auto& info2 = obj2.m_bsta_mld_info;
      memset(&info1, 0, sizeof(info1));
      memset(&info2, 0, sizeof(info2));
      info1.mac_addr_valid = info2.mac_addr_valid = true;      
      info1.ap_mld_mac_addr_valid = info2.ap_mld_mac_addr_valid = true;
      uint8_t mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
      memcpy(info1.mac_addr, mac, sizeof(mac));
      memcpy(info2.mac_addr, mac, sizeof(mac));
      uint8_t ap_mac[] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
      memcpy(info1.ap_mld_mac_addr, ap_mac, sizeof(ap_mac));
      memcpy(info2.ap_mld_mac_addr, ap_mac, sizeof(ap_mac));
      info1.str = info2.str = true;      
      info1.nstr = true;
      info2.nstr = false;
      info1.emlsr = info2.emlsr = true;
      info1.emlmr = info2.emlmr = true;
      info1.num_affiliated_bsta = info2.num_affiliated_bsta = 1;
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting ObjectsHaveDifferentNstr" << std::endl;
}
 
/**
 * @brief TEST to verify that two objects of dm_bsta_mld_t have different Emlsr values
 *
 * This TEST checks that two instances of dm_bsta_mld_t with different Emlsr values are not considered equal.@n
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
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create two instances of dm_bsta_mld_t with different Emlsr values | obj1.m_bsta_mld_info = {true, true, {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, true, true, true, 1}, obj2.m_bsta_mld_info = {true, true, {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, true, false, true, 1} | Instances should not be equal | Should Pass |
 * | 02| Compare the two instances using EXPECT_FALSE | EXPECT_FALSE(obj1 == obj2) | The comparison should return false | Should Pass |
 */
TEST(dm_btsa_mld_Test, ObjectsHaveDifferentEmlsr) {
      std::cout << "Entering ObjectsHaveDifferentEmlsr" << std::endl;
      dm_bsta_mld_t obj1{}, obj2{};
      auto& info1 = obj1.m_bsta_mld_info;
      auto& info2 = obj2.m_bsta_mld_info;
      memset(&info1, 0, sizeof(info1));
      memset(&info2, 0, sizeof(info2));
      info1.mac_addr_valid = info2.mac_addr_valid = true;      
      info1.ap_mld_mac_addr_valid = info2.ap_mld_mac_addr_valid = true;
      uint8_t mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
      memcpy(info1.mac_addr, mac, sizeof(mac));
      memcpy(info2.mac_addr, mac, sizeof(mac));
      uint8_t ap_mac[] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
      memcpy(info1.ap_mld_mac_addr, ap_mac, sizeof(ap_mac));
      memcpy(info2.ap_mld_mac_addr, ap_mac, sizeof(ap_mac));
      info1.str = info2.str = true;      
      info1.nstr = info2.nstr = true;
      info1.emlsr = true;
      info2.emlsr = false;      
      info1.emlmr = info2.emlmr = true;
      info1.num_affiliated_bsta = info2.num_affiliated_bsta = 1;
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting ObjectsHaveDifferentEmlsr" << std::endl;
}
 
/**
 * @brief TEST to verify that two objects of dm_bsta_mld_t have different EMLMR values
 *
 * This TEST checks if two instances of dm_bsta_mld_t with different EMLMR values are not considered equal.@n
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
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create two instances of dm_bsta_mld_t with different EMLMR values | obj1.m_bsta_mld_info = {true, true, {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, true, true, true, 1}, obj2.m_bsta_mld_info = {true, true, {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, true, true, false, 1} | Two objects should not be equal | Should Pass |
 * | 02| Compare the two instances using EXPECT_FALSE | EXPECT_FALSE(obj1 == obj2) | The comparison should return false | Should Pass |
 */
TEST(dm_btsa_mld_Test, ObjectsHaveDifferentEmlmr) {
      std::cout << "Entering ObjectsHaveDifferentEmlmr" << std::endl;
      dm_bsta_mld_t obj1{}, obj2{};
      auto& info1 = obj1.m_bsta_mld_info;
      auto& info2 = obj2.m_bsta_mld_info;
      memset(&info1, 0, sizeof(info1));
      memset(&info2, 0, sizeof(info2));
      info1.mac_addr_valid = info2.mac_addr_valid = true;      
      info1.ap_mld_mac_addr_valid = info2.ap_mld_mac_addr_valid = true;
      uint8_t mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
      memcpy(info1.mac_addr, mac, sizeof(mac));
      memcpy(info2.mac_addr, mac, sizeof(mac));
      uint8_t ap_mac[] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
      memcpy(info1.ap_mld_mac_addr, ap_mac, sizeof(ap_mac));
      memcpy(info2.ap_mld_mac_addr, ap_mac, sizeof(ap_mac));
      info1.str = info2.str = true;      
      info1.nstr = info2.nstr = true;
      info1.emlsr = info2.emlsr = true;          
      info1.emlmr = true;
      info2.emlmr = false;  
      info1.num_affiliated_bsta = info2.num_affiliated_bsta = 1;
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting ObjectsHaveDifferentEmlmr" << std::endl;
}
 
/**
 * @brief TEST to verify that objects with different number of affiliated BSTA are not equal
 *
 * This TEST checks if two objects of type dm_bsta_mld_t with different number of affiliated BSTA are considered not equal.@n
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
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create two objects of dm_bsta_mld_t with different number of affiliated BSTA | obj1.m_bsta_mld_info = {true, true, {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, true, true, true, 1}, obj2.m_bsta_mld_info = {true, true, {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}, true, true, true, true, 2} | Objects should not be equal | Should Pass |
 */
TEST(dm_btsa_mld_Test, ObjectsHaveDifferentNumAffiliatedBsta) {
      std::cout << "Entering ObjectsHaveDifferentNumAffiliatedBsta" << std::endl;
      dm_bsta_mld_t obj1{}, obj2{};
      auto& info1 = obj1.m_bsta_mld_info;
      auto& info2 = obj2.m_bsta_mld_info;
      memset(&info1, 0, sizeof(info1));
      memset(&info2, 0, sizeof(info2));
      info1.mac_addr_valid = info2.mac_addr_valid = true;      
      info1.ap_mld_mac_addr_valid = info2.ap_mld_mac_addr_valid = true;
      uint8_t mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
      memcpy(info1.mac_addr, mac, sizeof(mac));
      memcpy(info2.mac_addr, mac, sizeof(mac));
      uint8_t ap_mac[] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
      memcpy(info1.ap_mld_mac_addr, ap_mac, sizeof(ap_mac));
      memcpy(info2.ap_mld_mac_addr, ap_mac, sizeof(ap_mac));
      info1.str = info2.str = true;      
      info1.nstr = info2.nstr = true;
      info1.emlsr = info2.emlsr = true;          
      info1.emlmr = info2.emlmr = true; 
      info1.num_affiliated_bsta = 1;
      info2.num_affiliated_bsta = 2;
      EXPECT_FALSE(obj1 == obj2);
      std::cout << "Exiting ObjectsHaveDifferentNumAffiliatedBsta" << std::endl;
}
 
/**
 * @brief TEST to verify the assignment of mixed field values between two objects of dm_bsta_mld_t
 *
 * This TEST checks if the assignment operator correctly assigns mixed field values from one object to another object of the same type. It ensures that all fields are copied accurately and the values are preserved after assignment.
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
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create two objects of dm_bsta_mld_t | obj1, obj2 | Objects created successfully | Should be successful |
 * | 02| Assign mixed field values to obj2 | obj2.m_bsta_mld_info.mac_addr_valid = true, obj2.m_bsta_mld_info.ap_mld_mac_addr_valid = false, obj2.m_bsta_mld_info.str = true, obj2.m_bsta_mld_info.nstr = false, obj2.m_bsta_mld_info.emlsr = true, obj2.m_bsta_mld_info.emlmr = false | Fields assigned successfully | Should be successful |
 * | 03| Assign obj2 to obj1 | obj1 = obj2 | Assignment successful | Should Pass |
 * | 04| Verify mac_addr_valid field | obj1.m_bsta_mld_info.mac_addr_valid, obj2.m_bsta_mld_info.mac_addr_valid | ASSERT_EQ(obj1.m_bsta_mld_info.mac_addr_valid, obj2.m_bsta_mld_info.mac_addr_valid) | Should Pass |
 * | 05| Verify ap_mld_mac_addr_valid field | obj1.m_bsta_mld_info.ap_mld_mac_addr_valid, obj2.m_bsta_mld_info.ap_mld_mac_addr_valid | ASSERT_EQ(obj1.m_bsta_mld_info.ap_mld_mac_addr_valid, obj2.m_bsta_mld_info.ap_mld_mac_addr_valid) | Should Pass |
 * | 06| Verify str field | obj1.m_bsta_mld_info.str, obj2.m_bsta_mld_info.str | ASSERT_EQ(obj1.m_bsta_mld_info.str, obj2.m_bsta_mld_info.str) | Should Pass |
 * | 07| Verify nstr field | obj1.m_bsta_mld_info.nstr, obj2.m_bsta_mld_info.nstr | ASSERT_EQ(obj1.m_bsta_mld_info.nstr, obj2.m_bsta_mld_info.nstr) | Should Pass |
 * | 08| Verify emlsr field | obj1.m_bsta_mld_info.emlsr, obj2.m_bsta_mld_info.emlsr | ASSERT_EQ(obj1.m_bsta_mld_info.emlsr, obj2.m_bsta_mld_info.emlsr) | Should Pass |
 * | 09| Verify emlmr field | obj1.m_bsta_mld_info.emlmr, obj2.m_bsta_mld_info.emlmr | ASSERT_EQ(obj1.m_bsta_mld_info.emlmr, obj2.m_bsta_mld_info.emlmr) | Should Pass |
 */
TEST(dm_bsta_mld_Test, AssigningMixedFieldValues) {
      std::cout << "Entering AssigningMixedFieldValuesTEST";
      dm_bsta_mld_t obj1{};
      dm_bsta_mld_t obj2{};
      memset(&obj1.m_bsta_mld_info, 0, sizeof(obj1.m_bsta_mld_info));
      memset(&obj2.m_bsta_mld_info, 0, sizeof(obj2.m_bsta_mld_info));
      obj2.m_bsta_mld_info.mac_addr_valid = true;
      obj2.m_bsta_mld_info.ap_mld_mac_addr_valid = false;
      obj2.m_bsta_mld_info.str = true;
      obj2.m_bsta_mld_info.nstr = false;
      obj2.m_bsta_mld_info.emlsr = true;
      obj2.m_bsta_mld_info.emlmr = false;
      obj1 = obj2;
      ASSERT_EQ(obj1.m_bsta_mld_info.mac_addr_valid, obj2.m_bsta_mld_info.mac_addr_valid);
      ASSERT_EQ(obj1.m_bsta_mld_info.ap_mld_mac_addr_valid, obj2.m_bsta_mld_info.ap_mld_mac_addr_valid);
      ASSERT_EQ(obj1.m_bsta_mld_info.str, obj2.m_bsta_mld_info.str);
      ASSERT_EQ(obj1.m_bsta_mld_info.nstr, obj2.m_bsta_mld_info.nstr);
      ASSERT_EQ(obj1.m_bsta_mld_info.emlsr, obj2.m_bsta_mld_info.emlsr);
      ASSERT_EQ(obj1.m_bsta_mld_info.emlmr, obj2.m_bsta_mld_info.emlmr);
      std::cout << "Exiting AssigningMixedFieldValuesTEST";
}
 
/**
 * @brief TEST to verify the assignment operator for dm_bsta_mld_t class when assigning maximum affiliated BSTA
 *
 * This TEST checks if the assignment operator correctly assigns the maximum number of affiliated BSTA from one object to another@n
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
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize two dm_bsta_mld_t objects | obj1, obj2 | Objects should be initialized | Should be successful |
 * | 02| Set num_affiliated_bsta of obj2 to EM_MAX_AP_MLD | obj2.m_bsta_mld_info.num_affiliated_bsta = EM_MAX_AP_MLD | num_affiliated_bsta of obj2 should be set to EM_MAX_AP_MLD | Should be successful |
 * | 03| Assign obj2 to obj1 | obj1 = obj2 | obj1 should have the same num_affiliated_bsta as obj2 | Should Pass |
 * | 04| Assert that num_affiliated_bsta of obj1 equals num_affiliated_bsta of obj2 | ASSERT_EQ(obj1.m_bsta_mld_info.num_affiliated_bsta, obj2.m_bsta_mld_info.num_affiliated_bsta) | Assertion should pass | Should Pass |
 */
TEST(dm_bsta_mld_Test, AssigningMaxAffiliatedBsta) {
      std::cout << "Entering AssigningMaxAffiliatedBstaTEST";
      dm_bsta_mld_t obj1{};
      dm_bsta_mld_t obj2{};
      memset(&obj1.m_bsta_mld_info, 0, sizeof(obj1.m_bsta_mld_info));
      memset(&obj2.m_bsta_mld_info, 0, sizeof(obj2.m_bsta_mld_info));
      obj2.m_bsta_mld_info.num_affiliated_bsta = EM_MAX_AP_MLD;
      obj1 = obj2;
      ASSERT_EQ(obj1.m_bsta_mld_info.num_affiliated_bsta, obj2.m_bsta_mld_info.num_affiliated_bsta);
      std::cout << "Exiting AssigningMaxAffiliatedBstaTEST";
}
 
/**
 * @brief TEST to verify the assignment operator for dm_bsta_mld_t class
 *
 * This TEST checks if the assignment operator correctly assigns the value of num_affiliated_bsta from one object to another when the value is set to the minimum (0). This is important to ensure that the assignment operator works correctly for edge cases.
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
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize two dm_bsta_mld_t objects | obj1, obj2 | Objects should be initialized | Should be successful |
 * | 02| Set num_affiliated_bsta of obj2 to 0 | obj2.m_bsta_mld_info.num_affiliated_bsta = 0 | num_affiliated_bsta of obj2 should be 0 | Should be successful |
 * | 03| Assign obj2 to obj1 | obj1 = obj2 | obj1.m_bsta_mld_info.num_affiliated_bsta should be equal to obj2.m_bsta_mld_info.num_affiliated_bsta | Should Pass |
 * | 04| Assert the equality of num_affiliated_bsta | ASSERT_EQ(obj1.m_bsta_mld_info.num_affiliated_bsta, obj2.m_bsta_mld_info.num_affiliated_bsta) | Assertion should pass | Should Pass |
 */
TEST(dm_bsta_mld_Test, AssigningMinAffiliatedBsta) {
      std::cout << "Entering AssigningMinAffiliatedBstaTEST";
      dm_bsta_mld_t obj1{};
      dm_bsta_mld_t obj2{};
      memset(&obj1.m_bsta_mld_info, 0, sizeof(obj1.m_bsta_mld_info));
      memset(&obj2.m_bsta_mld_info, 0, sizeof(obj2.m_bsta_mld_info));
      obj2.m_bsta_mld_info.num_affiliated_bsta = 0;
      obj1 = obj2;
      ASSERT_EQ(obj1.m_bsta_mld_info.num_affiliated_bsta, obj2.m_bsta_mld_info.num_affiliated_bsta);
      std::cout << "Exiting AssigningMinAffiliatedBstaTEST";
}
 
/**
 * @brief TEST to validate MLD information with few fields set
 *
 * This TEST verifies that the dm_bsta_mld_t object correctly initializes and stores the MLD information when few fields are set.@n
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
 * | Variation / Step | Description |TEST Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize MLD information with valid values for few fields | mac_addr_valid = true, ap_mld_mac_addr_valid = true, str = false, nstr = false, emlsr = true, emlmr = false, num_affiliated_bsta = 1 | Object should be initialized with the provided values | Should Pass |
 * | 02 | Check if initialized values are retrieved as expected | mac_addr_valid = true, ap_mld_mac_addr_valid = true, str = false, nstr = false, emlsr = true, emlmr = false, num_affiliated_bsta = 1 | Values should be same as initialized values | Should Pass |
 */
TEST(dm_bsta_mld_Test, ValidMLDInformationAllFields) {
      std::cout << "Entering ValidMLDInformationAllFieldsTEST";
      em_bsta_mld_info_t ap_mld_info{};
      memset(&ap_mld_info, 0, sizeof(ap_mld_info));
      ap_mld_info.mac_addr_valid = true;
      ap_mld_info.ap_mld_mac_addr_valid = true;
      ap_mld_info.str = false;
      ap_mld_info.nstr = false;
      ap_mld_info.emlsr = true;
      ap_mld_info.emlmr = false;
      ap_mld_info.num_affiliated_bsta = 1;
      dm_bsta_mld_t obj(&ap_mld_info);
      ASSERT_EQ(obj.m_bsta_mld_info.mac_addr_valid, true);
      ASSERT_EQ(obj.m_bsta_mld_info.ap_mld_mac_addr_valid, true);
      ASSERT_EQ(obj.m_bsta_mld_info.str, false);
      ASSERT_EQ(obj.m_bsta_mld_info.nstr, false);
      ASSERT_EQ(obj.m_bsta_mld_info.emlsr, true);
      ASSERT_EQ(obj.m_bsta_mld_info.emlmr, false);
      ASSERT_EQ(obj.m_bsta_mld_info.num_affiliated_bsta, 1);
      std::cout << "Exiting ValidMLDInformationAllFieldsTEST";
}

/**
 * @brief TEST the copy constructor of dm_bsta_mld_t class with all fields initialized
 *
 * This TEST verifies that the copy constructor of the dm_bsta_mld_t class correctly copies all fields from the original object to the new object. This ensures that the copy constructor works as expected when all fields are initialized.
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
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize original object with all fields | original.m_bsta_mld_info.mac_addr_valid = true, original.m_bsta_mld_info.ap_mld_mac_addr_valid = true, original.m_bsta_mld_info.str = false, original.m_bsta_mld_info.nstr = false, original.m_bsta_mld_info.emlsr = true, original.m_bsta_mld_info.emlmr = false, original.m_bsta_mld_info.num_affiliated_bsta = EM_MAX_AP_MLD | All fields should be initialized correctly | Should be successful |
 * | 02| Invoke copy constructor | dm_bsta_mld_t copy(original) | New object should be created with same field values as original | Should Pass |
 * | 03| Verify copied fields | copy.m_bsta_mld_info.mac_addr_valid = true, copy.m_bsta_mld_info.ap_mld_mac_addr_valid = true, copy.m_bsta_mld_info.str = false, copy.m_bsta_mld_info.nstr = false, copy.m_bsta_mld_info.emlsr = true, copy.m_bsta_mld_info.emlmr = false, copy.m_bsta_mld_info.num_affiliated_bsta = EM_MAX_AP_MLD | All fields in the copied object should match the original | Should Pass |
 */
TEST(dm_bsta_mld_Test, CopyConstructorWithAllFieldsInitialized) {
      std::cout << "Entering CopyConstructorWithAllFieldsInitialized" << std::endl;
      dm_bsta_mld_t original{};
      memset(&original.m_bsta_mld_info, 0, sizeof(original.m_bsta_mld_info));
      original.m_bsta_mld_info.mac_addr_valid = true;
      original.m_bsta_mld_info.ap_mld_mac_addr_valid = true;
      original.m_bsta_mld_info.str = false;
      original.m_bsta_mld_info.nstr = false;
      original.m_bsta_mld_info.emlsr = true;
      original.m_bsta_mld_info.emlmr = false;
      original.m_bsta_mld_info.num_affiliated_bsta = EM_MAX_AP_MLD;
      dm_bsta_mld_t copy(original);
      ASSERT_EQ(original.m_bsta_mld_info.mac_addr_valid, copy.m_bsta_mld_info.mac_addr_valid);
      ASSERT_EQ(original.m_bsta_mld_info.ap_mld_mac_addr_valid, copy.m_bsta_mld_info.ap_mld_mac_addr_valid);
      ASSERT_EQ(original.m_bsta_mld_info.str, copy.m_bsta_mld_info.str);
      ASSERT_EQ(original.m_bsta_mld_info.nstr, copy.m_bsta_mld_info.nstr);
      ASSERT_EQ(original.m_bsta_mld_info.emlsr, copy.m_bsta_mld_info.emlsr);
      ASSERT_EQ(original.m_bsta_mld_info.emlmr, copy.m_bsta_mld_info.emlmr);
      ASSERT_EQ(original.m_bsta_mld_info.num_affiliated_bsta, copy.m_bsta_mld_info.num_affiliated_bsta);
      std::cout << "Exiting CopyConstructorWithAllFieldsInitialized" << std::endl;
}
 
/**
 * @brief TEST the copy constructor of dm_bsta_mld_t with invalid MAC address values
 *
 * This TEST verifies that the copy constructor of the dm_bsta_mld_t class correctly copies the MAC address values even when they are set to invalid values (0xFF). This ensures that the copy constructor handles edge cases properly.
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
 * | Variation / Step | Description |TEST Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create an instance of dm_bsta_mld_t and set MAC addresses to 0xFF | original.m_bsta_mld_info.mac_addr = 0xFF, original.m_bsta_mld_info.ap_mld_mac_addr = 0xFF | MAC addresses set to 0xFF | Should be successful |
 * | 02| Create a copy of the original instance using the copy constructor | dm_bsta_mld_t copy(original) | Copy created successfully | Should be successful |
 * | 03| Compare the MAC addresses of the original and the copy | original.get_bsta_mld_info(), copy.get_bsta_mld_info() | MAC addresses should be equal | Should Pass |
 */
TEST(dm_bsta_mld_Test, CopyConstructorWithInvalidMacAddressValues) {
      std::cout << "Entering CopyConstructorWithInvalidMacAddressValues" << std::endl;
      dm_bsta_mld_t original{};
      memset(&original.m_bsta_mld_info, 0, sizeof(original.m_bsta_mld_info));
      memset(original.m_bsta_mld_info.mac_addr, 0xFF, sizeof(mac_address_t));
      memset(original.m_bsta_mld_info.ap_mld_mac_addr, 0xFF, sizeof(mac_address_t));
      dm_bsta_mld_t copy(original);
      ASSERT_EQ(0, memcmp(original.m_bsta_mld_info.mac_addr, copy.m_bsta_mld_info.mac_addr, sizeof(original.m_bsta_mld_info.mac_addr)));
      ASSERT_EQ(0, memcmp(original.m_bsta_mld_info.ap_mld_mac_addr, copy.m_bsta_mld_info.ap_mld_mac_addr, sizeof(original.m_bsta_mld_info.ap_mld_mac_addr)));
      std::cout << "Exiting CopyConstructorWithInvalidMacAddressValues" << std::endl;
}

/**
 * @brief Test the default constructor of dm_bsta_mld_t for proper object creation and initialization
 *
 * This test verifies that invoking the default constructor of dm_bsta_mld_t does not throw any exceptions and that the object's
 * internal state (m_bsta_mld_info) is initialized with default values. This ensures that the object is properly constructed for future usage.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 031@n
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                   | Test Data                                                                                                                      | Expected Result                                                                                                      | Notes         |
 * | :--------------: | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------- | ------------- |
 * | 01               | Invoke the default constructor of dm_bsta_mld_t and verify no exception is thrown                | Invocation: default constructor (dm_bsta_mld_t obj)                                                                            | Object is created without throwing any exceptions; EXPECT_NO_THROW passes                                             | Should Pass   |
 */
TEST(dm_bsta_mld_t_Test, DefaultConstructorPositiveTest) {
    std::cout << "Entering DefaultConstructorPositiveTest test" << std::endl;
    std::cout << "Invoking default constructor: dm_bsta_mld_t obj;" << std::endl;
    EXPECT_NO_THROW({
        dm_bsta_mld_t obj;
        std::cout << "dm_bsta_mld_t object created successfully." << std::endl;
    });
    std::cout << "Exiting DefaultConstructorPositiveTest test" << std::endl;
}

/**
 * @brief Validates that the default constructed dm_bsta_mld_t object is destructed without throwing exceptions.
 *
 * This test case verifies that creating an instance of dm_bsta_mld_t using the default constructor and then allowing it to go out of scope (thus invoking the destructor) does not throw any exceptions. It also prints internal state information for demonstration purposes.
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
 * | 01 | Invoke default constructor and allow the object to go out of scope to trigger the destructor of dm_bsta_mld_t. | No input parameters; internal state prints: dm_bsta_mld_t obj; m_bsta_mld_info pointer address output; exception check through EXPECT_NO_THROW. | The object should be constructed and destructed without any exception being thrown. | Should Pass |
 */
TEST(dm_bsta_mld_t_Test, Destructor_DefaultConstructed) {
    std::cout << "Entering Destructor_DefaultConstructed test" << std::endl;
    EXPECT_NO_THROW({
        {
            std::cout << "Invoking default constructor for dm_bsta_mld_t." << std::endl;
            dm_bsta_mld_t obj;
            std::cout << "Default constructor invoked successfully." << std::endl;
            std::cout << "About to leave scope, which will invoke the destructor for dm_bsta_mld_t." << std::endl;
        }
    });
    std::cout << "Exiting Destructor_DefaultConstructed test" << std::endl;
}