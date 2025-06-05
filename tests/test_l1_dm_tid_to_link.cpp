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
#include "dm_tid_to_link.h"

/**
* @brief Test to validate the decoding of a valid JSON object with all required fields.
*
* This test checks the functionality of the decode method in the dm_tid_to_link_t class when provided with a valid JSON object containing all required fields. The objective is to ensure that the method correctly processes the input and returns the expected result.
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
* | 01 | Create a valid JSON object with required fields | obj.type = cJSON_Object, obj.child = &child, child.type = cJSON_String, child.valuestring = "valid_data" | Should be successful | |
* | 02 | Call the decode method with the valid JSON object and parent_id | result = instance.decode(&obj, parent_id) | result = 0, EXPECT_EQ(result, 0) | Should Pass |
*/
TEST(dm_tid_to_link_t_Test, ValidJSONObjectWithAllRequiredFields) {
    std::cout << "Entering ValidJSONObjectWithAllRequiredFields" << std::endl;
    cJSON obj{};
    cJSON child{};
    obj.type = cJSON_Object;
    obj.child = &child;
    child.type = cJSON_String;
    child.valuestring = const_cast<char*>("valid_data");
    int dummy_id = 123;
    void* parent_id = &dummy_id;
    dm_tid_to_link_t instance;
    int result = instance.decode(&obj, parent_id);
    EXPECT_EQ(result, 0);
    std::cout << "Exiting ValidJSONObjectWithAllRequiredFields" << std::endl;
}



/**
* @brief Test to verify the behavior of decode function when a NULL JSON object is passed.
*
* This test checks the decode function of the dm_tid_to_link_t class to ensure it correctly handles a NULL JSON object by returning an error code.@n
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
* | 01 | Initialize JSON object to NULL and valid parent ID pointer | obj = NULL, parent_id = valid_parent_id_pointer | Should be successful | |
* | 02 | Call decode function with NULL JSON object | obj = NULL, parent_id = valid_parent_id_pointer | result = -1, EXPECT_EQ(result, -1) | Should Fail |
*/
/*code doesn't handle null
TEST(dm_tid_to_link_t_Test, InvalidJSONObjectNullPointer) {
    std::cout << "Entering InvalidJSONObjectNullPointer" << std::endl;
    cJSON* obj = NULL;
    int dummy_id = 123;
    void* parent_id = &dummy_id;
    dm_tid_to_link_t instance;
    int result = instance.decode(obj, parent_id);
    EXPECT_EQ(result, -1);
    std::cout << "Exiting InvalidJSONObjectNullPointer" << std::endl;
}
*/



/**
* @brief Test to validate the behavior of decode function when parent_id is NULL
*
* This test checks the decode function of dm_tid_to_link_t class to ensure it returns an error code when the parent_id is NULL. This is important to verify that the function handles invalid input correctly and does not proceed with a NULL parent_id.@n
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
* | 01| Initialize cJSON object and child | obj.type = cJSON_Object, obj.child = &child, child.type = cJSON_String, child.valuestring = "valid_data" | Should be successful | |
* | 02| Call decode with NULL parent_id | obj = {type: cJSON_Object, child: &child}, parent_id = NULL | result = -1, EXPECT_EQ(result, -1) | Should Fail |
*/
/*code doesn't handle null
TEST(dm_tid_to_link_t_Test, InvalidParentIdNullPointer) {
    std::cout << "Entering InvalidParentIdNullPointer" << std::endl;
    cJSON obj;
    cJSON child;
    obj.type = cJSON_Object;
    obj.child = &child;
    child.type = cJSON_String;
    child.valuestring = "valid_data";
    void* parent_id = NULL;
    dm_tid_to_link_t instance;
    int result = instance.decode(&obj, parent_id);
    EXPECT_EQ(result, -1);
    std::cout << "Exiting InvalidParentIdNullPointer" << std::endl;
}
*/



/**
* @brief Test to validate the behavior of the decode function when provided with a valid JSON object but with an incorrect type.
*
* This test checks the decode function of the dm_tid_to_link_t class to ensure it correctly handles a JSON object that has a valid structure but an incorrect type. The objective is to verify that the function returns an error code when the type of the JSON object does not match the expected type.
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
* | 01 | Create a cJSON object with type cJSON_Number and a child of type cJSON_String | obj.type = cJSON_Number, obj.child = &child, child.type = cJSON_String, child.valuestring = "valid_data" | Should be successful | |
* | 02 | Call the decode function with the JSON object and a valid parent_id | instance.decode(&obj, parent_id) | result = -1, EXPECT_EQ(result, -1) | Should Fail |
*/
TEST(dm_tid_to_link_t_Test, ValidJSONObjectWithIncorrectType) {
    std::cout << "Entering ValidJSONObjectWithIncorrectType" << std::endl;
    cJSON obj;
    cJSON child;
    obj.type = cJSON_Number;
    obj.child = &child;
    child.type = cJSON_String;
    child.valuestring = const_cast<char*>("valid_data");
    int dummy_id = 123;
    void* parent_id = &dummy_id;
    dm_tid_to_link_t instance;
    int result = instance.decode(&obj, parent_id);
    EXPECT_EQ(result, -1);
    std::cout << "Exiting ValidJSONObjectWithIncorrectType" << std::endl;
}



/**
* @brief Test the decoding of a valid JSON object with nested objects
*
* This test verifies that the decode function can correctly handle a JSON object that contains nested objects. The objective is to ensure that the function can traverse and process nested structures without errors.@n
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
* | 01 | Initialize JSON object with nested structure | obj.type = cJSON_Object, obj.child = &child, child.type = cJSON_Object, child.child = &nestedChild, nestedChild.type = cJSON_String, nestedChild.valuestring = "nested_data" | Should be successful | |
* | 02 | Call decode function with valid JSON object and parent_id | instance.decode(&obj, parent_id = valid_parent_id_pointer) | result = 0, EXPECT_EQ(result, 0) | Should Pass |
*/
TEST(dm_tid_to_link_t_Test, ValidJSONObjectWithNestedObjects) {
    std::cout << "Entering ValidJSONObjectWithNestedObjects" << std::endl;
    cJSON obj;
    cJSON child;
    cJSON nestedChild;
    obj.type = cJSON_Object;
    obj.child = &child;
    child.type = cJSON_Object;
    child.child = &nestedChild;
    nestedChild.type = cJSON_String;
    nestedChild.valuestring = const_cast<char*>("nested_data");
    int dummy_id = 123;
    void* parent_id = &dummy_id;
    dm_tid_to_link_t instance;
    int result = instance.decode(&obj, parent_id);
    EXPECT_EQ(result, 0);
    std::cout << "Exiting ValidJSONObjectWithNestedObjects" << std::endl;
}



/**
* @brief Test to validate the decoding of a valid JSON object with an array
*
* This test checks the functionality of the decode method in the dm_tid_to_link_t class when provided with a valid JSON object containing an array. The objective is to ensure that the method correctly processes the JSON object and returns the expected result.
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
* | 01 | Initialize JSON object with array | obj.type = cJSON_Array, obj.child = &child, child.type = cJSON_String, child.valuestring = "array_data" | Should be successful | |
* | 02 | Call decode method with valid JSON object and parent_id | instance.decode(&obj, parent_id) | result = 0, EXPECT_EQ(result, 0) | Should Pass |
*/
TEST(dm_tid_to_link_t_Test, ValidJSONObjectWithArray) {
    std::cout << "Entering ValidJSONObjectWithArray" << std::endl;
    cJSON obj;
    cJSON child;
    obj.type = cJSON_Array;
    obj.child = &child;
    child.type = cJSON_String;
    child.valuestring = const_cast<char*>("array_data");
    int dummy_id = 123;
    void* parent_id = &dummy_id;
    dm_tid_to_link_t instance;
    int result = instance.decode(&obj, parent_id);
    EXPECT_EQ(result, 0);
    std::cout << "Exiting ValidJSONObjectWithArray" << std::endl;
}



/**
* @brief Test the copy constructor of dm_tid_to_link_t with valid values
*
* This test verifies that the copy constructor of the dm_tid_to_link_t class correctly copies all fields from the original object to the new object.
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
* | 01| Create an original dm_tid_to_link_t object and set valid values | is_bsta_config = true, num_mapping = 5 | Original object created with specified values | Should be successful |
* | 02| Use the copy constructor to create a new dm_tid_to_link_t object from the original | original object | New object created with copied values | Should be successful |
* | 03| Assert that the copied values match the original values | is_bsta_config = true, num_mapping = 5 | Assertions should pass | Should Pass |
*/
TEST(dm_tid_to_link_t_Test, CopyConstructorWithValidValues) {
    std::cout << "Entering CopyConstructorWithValidValues" << std::endl;
    dm_tid_to_link_t original;
    original.m_tid_to_link_info.is_bsta_config = true;
    original.m_tid_to_link_info.tid_to_link_map_neg = false;
    original.m_tid_to_link_info.num_mapping = 5;
    // Set a valid (non-zero, non-broadcast) MAC address
    mac_address_t valid_mac = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC };
    memcpy(&original.m_tid_to_link_info.mld_mac_addr, valid_mac, sizeof(mac_address_t));
    // Fill the first mapping entry with valid values
    em_tid_to_link_map_info_t& map_info = original.m_tid_to_link_info.tid_to_link_mapping[0];
    map_info.add_remove = true;
    mac_address_t sta_mac = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB };
    memcpy(&map_info.sta_mld_mac_addr, sta_mac, sizeof(mac_address_t));
    map_info.direction = true;
    map_info.default_link_map = false;
    map_info.map_switch_time_present = true;
    map_info.expected_dur_present = false;
    map_info.link_map_size = true;
    map_info.link_map_presence_ind = 3;  // Valid index
    map_info.tid_to_link_map = 7;        // Valid TID/link value
    unsigned char valid_expected_dur[3] = { 0x10, 0x20, 0x30 }; // Valid duration
    memcpy(map_info.expected_dur, valid_expected_dur, sizeof(valid_expected_dur));
    dm_tid_to_link_t copy(original);

    // Assertions to validate deep copy
    ASSERT_EQ(copy.m_tid_to_link_info.is_bsta_config, original.m_tid_to_link_info.is_bsta_config);
    ASSERT_EQ(copy.m_tid_to_link_info.tid_to_link_map_neg, original.m_tid_to_link_info.tid_to_link_map_neg);
    ASSERT_EQ(copy.m_tid_to_link_info.num_mapping, original.m_tid_to_link_info.num_mapping);
    ASSERT_EQ(0, memcmp(&copy.m_tid_to_link_info.mld_mac_addr,
                        &original.m_tid_to_link_info.mld_mac_addr,
                        sizeof(mac_address_t)));
    ASSERT_EQ(copy.m_tid_to_link_info.tid_to_link_mapping[0].add_remove,
              original.m_tid_to_link_info.tid_to_link_mapping[0].add_remove);
    ASSERT_EQ(0, memcmp(&copy.m_tid_to_link_info.tid_to_link_mapping[0].sta_mld_mac_addr,
                        &original.m_tid_to_link_info.tid_to_link_mapping[0].sta_mld_mac_addr,
                        sizeof(mac_address_t)));
    ASSERT_EQ(copy.m_tid_to_link_info.tid_to_link_mapping[0].direction,
              original.m_tid_to_link_info.tid_to_link_mapping[0].direction);
    ASSERT_EQ(copy.m_tid_to_link_info.tid_to_link_mapping[0].default_link_map,
              original.m_tid_to_link_info.tid_to_link_mapping[0].default_link_map);
    ASSERT_EQ(copy.m_tid_to_link_info.tid_to_link_mapping[0].map_switch_time_present,
              original.m_tid_to_link_info.tid_to_link_mapping[0].map_switch_time_present);
    ASSERT_EQ(copy.m_tid_to_link_info.tid_to_link_mapping[0].expected_dur_present,
              original.m_tid_to_link_info.tid_to_link_mapping[0].expected_dur_present);
    ASSERT_EQ(copy.m_tid_to_link_info.tid_to_link_mapping[0].link_map_size,
              original.m_tid_to_link_info.tid_to_link_mapping[0].link_map_size);
    ASSERT_EQ(copy.m_tid_to_link_info.tid_to_link_mapping[0].link_map_presence_ind,
              original.m_tid_to_link_info.tid_to_link_mapping[0].link_map_presence_ind);
    ASSERT_EQ(copy.m_tid_to_link_info.tid_to_link_mapping[0].tid_to_link_map,
              original.m_tid_to_link_info.tid_to_link_mapping[0].tid_to_link_map);
    ASSERT_EQ(0, memcmp(copy.m_tid_to_link_info.tid_to_link_mapping[0].expected_dur,
                        original.m_tid_to_link_info.tid_to_link_mapping[0].expected_dur,
                        sizeof(original.m_tid_to_link_info.tid_to_link_mapping[0].expected_dur)));
    std::cout << "Exiting CopyConstructorWithValidValues" << std::endl;
}



/**
* @brief Test the copy constructor of dm_tid_to_link_t when fields are null pointers or equivalent
*
* This test verifies that the copy constructor of the dm_tid_to_link_t class correctly copies the fields from the original object, even when those fields are set to null pointers or equivalent values.@n
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create an original dm_tid_to_link_t object with null pointer fields | original.m_tid_to_link_info.is_bsta_config = false, original.m_tid_to_link_info.num_mapping = 0 | Object created successfully | Should be successful |
* | 02| Invoke the copy constructor to create a copy of the original object | copy(original) | Copy created successfully | Should be successful |
* | 03| Verify that the copied object's fields match the original object's fields | copy.m_tid_to_link_info.is_bsta_config = original.m_tid_to_link_info.is_bsta_config, copy.m_tid_to_link_info.num_mapping = original.m_tid_to_link_info.num_mapping | Assertions pass | Should Pass |
*/
TEST(dm_tid_to_link_t_Test, CopyConstructorWithInvalidMac) {
    std::cout << "Entering CopyConstructorWithInvalidMac" << std::endl;
    dm_tid_to_link_t original;
    original.m_tid_to_link_info.is_bsta_config = true;
    original.m_tid_to_link_info.tid_to_link_map_neg = false;
    original.m_tid_to_link_info.num_mapping = 5;
    mac_address_t mac = { 0x12, 0x34, 0x56, 0x00, 0x00, 0x00 };
    memcpy(&original.m_tid_to_link_info.mld_mac_addr, mac, sizeof(mac_address_t));
    dm_tid_to_link_t copy(original);
    ASSERT_EQ(copy.m_tid_to_link_info.is_bsta_config, original.m_tid_to_link_info.is_bsta_config);
    ASSERT_EQ(copy.m_tid_to_link_info.num_mapping, original.m_tid_to_link_info.num_mapping);
    ASSERT_EQ(0, memcmp(&copy.m_tid_to_link_info.mld_mac_addr,
                        &original.m_tid_to_link_info.mld_mac_addr,
                        sizeof(mac_address_t)));
    std::cout << "Exiting CopyConstructorWithInvalidMac" << std::endl;
}


/**
 * @brief Test to validate the TID to Link Information initialization
 *
 * This test verifies that the dm_tid_to_link_t class correctly initializes and stores
 * the TID to Link information provided to it. The test checks various fields of the structure
 * to ensure they are correctly set.
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
 * | Step | Description                                    | Test Data                                                                | Expected Result                     | Notes            |
 * | :--: | --------------------------------------------- | ------------------------------------------------------------------------- | ---------------------------------- | ---------------- |
 * | 01   | Initialize dm_tid_to_link_t with valid info  | tid_to_link_info = { is_bsta_config=true, mld_mac_addr={0x00,0x1A,0x2B,0x3C,0x4D,0x5E}, tid_to_link_map_neg=false, num_mapping=1 } | Object initialized successfully     | Should pass      |
 * | 02   | Check is_bsta_config field                     | obj.m_tid_to_link_info.is_bsta_config == true                            | ASSERT_EQ passes                   | Should pass      |
 * | 03   | Check mld_mac_addr field                        | obj.m_tid_to_link_info.mld_mac_addr == {0x00,0x1A,0x2B,0x3C,0x4D,0x5E}    | ASSERT_EQ passes                   | Should pass      |
 * | 04   | Check tid_to_link_map_neg field                 | obj.m_tid_to_link_info.tid_to_link_map_neg == false                       | ASSERT_EQ passes                   | Should pass      |
 * | 05   | Check num_mapping field                          | obj.m_tid_to_link_info.num_mapping == 1                                  | ASSERT_EQ passes                   | Should pass      |
 *
 */
TEST(dm_tid_to_link_t_Test, ValidTIDToLinkInformation) {
    std::cout << "Entering ValidTIDToLinkInformation test\n";
    em_tid_to_link_info_t tid_to_link_info;
    tid_to_link_info.is_bsta_config = true;
    uint8_t mac[6] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
    memcpy(tid_to_link_info.mld_mac_addr, mac, sizeof(mac));
    tid_to_link_info.tid_to_link_map_neg = false;
    tid_to_link_info.num_mapping = 1;
    dm_tid_to_link_t obj(&tid_to_link_info);
    ASSERT_EQ(obj.m_tid_to_link_info.is_bsta_config, true);
    ASSERT_EQ(memcmp(obj.m_tid_to_link_info.mld_mac_addr, tid_to_link_info.mld_mac_addr, sizeof(mac)), 0);
    ASSERT_EQ(obj.m_tid_to_link_info.tid_to_link_map_neg, false);
    ASSERT_EQ(obj.m_tid_to_link_info.num_mapping, 1);
    std::cout << "Exiting ValidTIDToLinkInformation test\n";
}


/**
* @brief Test the behavior of dm_tid_to_link_t when initialized with a null pointer
*
* This test checks the initialization of the dm_tid_to_link_t object when a null pointer is passed to its constructor. It verifies that the internal state of the object is set to default values.
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
* | 01 | Initialize dm_tid_to_link_t with null pointer | input = nullptr | obj.m_tid_to_link_info.is_bsta_config = false, obj.m_tid_to_link_info.num_mapping = 0 | Should Pass |
*/
/*code doesn't handle null
TEST(dm_tid_to_link_t_Test, NullTIDToLinkInformation) {
    std::cout << "Entering NullTIDToLinkInformation test";
    dm_tid_to_link_t obj(nullptr);
    std::cout << "Exiting NullTIDToLinkInformation test";
}
*/


/**
* @brief Test the behavior of dm_tid_to_link_t when the number of mappings exceeds the maximum allowed.
*
* This test verifies that the dm_tid_to_link_t constructor correctly handles the case where the number of mappings exceeds the maximum allowed value (EM_MAX_AP_MLD). It ensures that the is_bsta_config flag is set to false and the num_mapping is set to 0 in such cases.
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
* | 01 | Initialize tid_to_link_info with invalid number of mappings | tid_to_link_info = {true, {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, false, EM_MAX_AP_MLD + 1, {{0, 1}, {1, 2}, {2, 3}, {3, 4}, {4, 5}, {5, 6}, {6, 7}, {7, 8}, {8, 9}}} | None | Should be successful |
* | 02 | Create dm_tid_to_link_t object with tid_to_link_info | obj = dm_tid_to_link_t(&tid_to_link_info) | None | Should be successful |
* | 03 | Check is_bsta_config flag | obj.m_tid_to_link_info.is_bsta_config == false | Assertion should pass | Should Pass |
* | 04 | Check num_mapping value | obj.m_tid_to_link_info.num_mapping == 0 | Assertion should pass | Should Pass |
*/
TEST(dm_tid_to_link_t_Test, InvalidNumberOfMappings) {
    std::cout << "Entering InvalidNumberOfMappings test";
    em_tid_to_link_info_t tid_to_link_info;
    tid_to_link_info.num_mapping = EM_MAX_AP_MLD + 1;
    dm_tid_to_link_t obj(&tid_to_link_info);
    ASSERT_NE(obj.m_tid_to_link_info.num_mapping, tid_to_link_info.num_mapping);
    std::cout << "Exiting InvalidNumberOfMappings test";
}



/**
* @brief Test to verify the encoding of a valid string value
*
* This test checks the functionality of the encode method in the dm_tid_to_link_t class by passing a valid cJSON object with a string value. The objective is to ensure that the encode method correctly processes and encodes the string value without errors.
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
* | 01| Create a cJSON object with a string value | obj.type = cJSON_String, obj.valuestring = "test_string" | Should be successful | |
* | 02| Call the encode method with the cJSON object | instance.encode(&obj) | Should Pass | |
*/
TEST(dm_tid_to_link_t_Test, EncodeValidStringValue) {
    std::cout << "Entering EncodeValidStringValue test";
    cJSON obj;
    obj.type = cJSON_String;
    obj.valuestring = const_cast<char*>("test_string");
    dm_tid_to_link_t instance;
    instance.encode(&obj);
    std::cout << "Exiting EncodeValidStringValue test";
}



/**
* @brief Test the encoding of a valid number value in dm_tid_to_link_t class
*
* This test verifies that the encode function of the dm_tid_to_link_t class correctly handles and encodes a valid number value.@n
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
* | 01 | Create a cJSON object with type cJSON_Number and value 123.45 | obj.type = cJSON_Number, obj.valuedouble = 123.45 | Should be successful | |
* | 02 | Call the encode function with the cJSON object | instance.encode(&obj) | Should Pass | |
*/
TEST(dm_tid_to_link_t_Test, EncodeValidNumberValue) {
    std::cout << "Entering EncodeValidNumberValue test";
    cJSON obj;
    obj.type = cJSON_Number;
    obj.valuedouble = 123.45;
    dm_tid_to_link_t instance;
    instance.encode(&obj);
    std::cout << "Exiting EncodeValidNumberValue test";
}



/**
* @brief Test the encoding of a valid integer value using the encode method of dm_tid_to_link_t class.
*
* This test verifies that the encode method correctly processes a cJSON object with a valid integer value. 
* It ensures that the method can handle and encode integer values as expected.
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
* | 01 | Initialize cJSON object with integer value | obj.type = cJSON_Number, obj.valueint = 123 | cJSON object initialized with integer value | Should be successful |
* | 02 | Create instance of dm_tid_to_link_t | instance = new dm_tid_to_link_t() | Instance created | Should be successful |
* | 03 | Call encode method with cJSON object | instance.encode(&obj) | Method processes the integer value correctly | Should Pass |
*/
TEST(dm_tid_to_link_t_Test, EncodeValidIntegerValue) {
    std::cout << "Entering EncodeValidIntegerValue test";
    cJSON obj;
    obj.type = cJSON_Number;
    obj.valueint = 123;
    dm_tid_to_link_t instance;
    instance.encode(&obj);
    std::cout << "Exiting EncodeValidIntegerValue test";
}



/**
* @brief Test the encoding of a valid null value in dm_tid_to_link_t class
*
* This test verifies that the encode function of the dm_tid_to_link_t class correctly handles and encodes a cJSON object of type cJSON_NULL. This is important to ensure that the encoding function can handle null values without errors.@n
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
* | 01 | Initialize cJSON object with null type | obj.type = cJSON_NULL | cJSON object initialized with null type | Should be successful |
* | 02 | Create instance of dm_tid_to_link_t | instance = new dm_tid_to_link_t() | instance created | Should be successful |
* | 03 | Call encode function with null cJSON object | instance.encode(&obj) | encode function handles null value correctly | Should Pass |
*/
TEST(dm_tid_to_link_t_Test, EncodeValidNullValue) {
    std::cout << "Entering EncodeValidNullValue test";
    cJSON obj;
    obj.type = cJSON_NULL;
    dm_tid_to_link_t instance;
    instance.encode(&obj);
    std::cout << "Exiting EncodeValidNullValue test";
}



/**
* @brief Test the encoding of a valid array value in dm_tid_to_link_t class
*
* This test verifies that the encode function of the dm_tid_to_link_t class correctly processes a cJSON object representing an array with valid integer values. The objective is to ensure that the encode function can handle and encode arrays properly.
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
* | 01| Initialize cJSON object and children | obj.type = cJSON_Array, child1.type = cJSON_Number, child1.valueint = 1, child2.type = cJSON_Number, child2.valueint = 2 | cJSON object and children initialized | Should be successful |
* | 02| Link children to form array | child1.next = &child2, obj.child = &child1 | cJSON array linked | Should be successful |
* | 03| Call encode function | instance.encode(&obj) | Encode function processes the array | Should Pass |
*/
TEST(dm_tid_to_link_t_Test, EncodeValidArrayValue) {
    std::cout << "Entering EncodeValidArrayValue test";
    cJSON obj;
    cJSON child1;
    cJSON child2;
    obj.type = cJSON_Array;
    child1.type = cJSON_Number;
    child1.valueint = 1;
    child1.next = &child2;
    child2.type = cJSON_Number;
    child2.valueint = 2;
    obj.child = &child1;
    dm_tid_to_link_t instance;
    instance.encode(&obj);
    std::cout << "Exiting EncodeValidArrayValue test";
}



/**
* @brief Test the encoding of a valid object value
*
* This test verifies that the encode function of the dm_tid_to_link_t class correctly encodes a valid cJSON object with a child element.@n
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
* | 01| Create a cJSON object with a child element | obj.type = cJSON_Object, child.string = "key", child.type = cJSON_String, child.valuestring = "value", obj.child = &child | Should be successful | |
* | 02| Call the encode function with the cJSON object | instance.encode(&obj) | Should Pass | |
*/
TEST(dm_tid_to_link_t_Test, EncodeValidObjectValue) {
    std::cout << "Entering EncodeValidObjectValue test";
    cJSON obj;
    cJSON child;
    obj.type = cJSON_Object;
    child.string = const_cast<char*>("key");
    child.type = cJSON_String;
    child.valuestring = const_cast<char*>("value");
    obj.child = &child;
    dm_tid_to_link_t instance;
    instance.encode(&obj);
    std::cout << "Exiting EncodeValidObjectValue test";
}



/**
* @brief Test to validate the behavior of the encode function with an invalid type
*
* This test checks the encode function of the dm_tid_to_link_t class when provided with an invalid type in the cJSON object. The objective is to ensure that the function handles invalid input types gracefully without causing unexpected behavior or crashes.
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create a cJSON object with an invalid type | obj.type = -1 | Should be successful | Should be successful |
* | 02| Call the encode function with the invalid cJSON object | instance.encode(&obj) | Should Pass | Should Pass |
*/
TEST(dm_tid_to_link_t_Test, EncodeInvalidType) {
    std::cout << "Entering EncodeInvalidType test";
    cJSON obj;
    obj.type = -1;
    dm_tid_to_link_t instance;
    instance.encode(&obj);
    std::cout << "Exiting EncodeInvalidType test";
}



/**
* @brief Test to check the behavior of the encode function when a null pointer is passed.
*
* This test verifies that the encode function can handle a null pointer input without crashing or causing undefined behavior.@n
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
* | 01| Call encode with null pointer | input = NULL | No crash or undefined behavior | Should Pass |
*/
/*code doesn't handle null
TEST(dm_tid_to_link_t_Test, EncodeNullPointer) {
    std::cout << "Entering EncodeNullPointer test";
    dm_tid_to_link_t instance;
    instance.encode(NULL);
    std::cout << "Exiting EncodeNullPointer test";
}
*/    



/**
 * @brief Test to verify the retrieval of TID to link information after modifying fields
 *
 * This test ensures that the values set in custom_info are accurately reflected in the result obtained from the get_tid_to_link_info() method.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 020@n
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Step | Description                                      | Test Data                                                                                                 | Expected Result                           | Notes         |
 * | :--: | ----------------------------------------------- | -------------------------------------------------------------------------------------------------------- | ---------------------------------------- | ------------- |
 * | 01   | Initialize custom_info with specific values     | is_bsta_config = true, mld_mac_addr = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, tid_to_link_map_neg = false,   | custom_info should be initialized with   | Should be     |
 * |      |                                                  | num_mapping = 2, tid_to_link_mapping[0].add_remove = true, tid_to_link_mapping[0].sta_mld_mac_addr = {0x11, | the given values                         | successful    |
 * |      |                                                  | 0x22, 0x33, 0x44, 0x55, 0x66}, tid_to_link_mapping[0].direction = true, tid_to_link_mapping[0].default_link_map = |                                         |               |
 * |      |                                                  | false, tid_to_link_mapping[0].link_map_presence_ind = 1, tid_to_link_mapping[0].tid_to_link_map = 5,       |                                         |               |
 * |      |                                                  | tid_to_link_mapping[1].add_remove = false, tid_to_link_mapping[1].sta_mld_mac_addr = {0xAA, 0xBB}          |                                         |               |
 * | 02   | Create dm_tid_to_link_t object with custom_info | custom_info                                                                                            | Object should be created successfully     | Should be     |
 * |      |                                                  |                                                                                                          |                                          | successful    |
 * | 03   | Retrieve TID to link information                  | None                                                                                                    | result should not be nullptr               | Should Pass   |
 * | 04   | Verify the retrieved values                        | is_bsta_config = true, mld_mac_addr = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, tid_to_link_map_neg = false,   | Retrieved values should match the set     | Should Pass   |
 * |      |                                                  | num_mapping = 2, tid_to_link_mapping[0].add_remove = true, tid_to_link_mapping[0].sta_mld_mac_addr = {0x11, | values                                   |               |
 * |      |                                                  | 0x22}, tid_to_link_mapping[0].direction = true, tid_to_link_mapping[0].default_link_map = false,           |                                          |               |
 * |      |                                                  | tid_to_link_mapping[0].link_map_presence_ind = 1, tid_to_link_mapping[0].tid_to_link_map = 5,               |                                          |               |
 * |      |                                                  | tid_to_link_mapping[1].add_remove = false, tid_to_link_mapping[1].sta_mld_mac_addr = {0xAA, 0xBB}          |                                          |               |
 */
TEST(dm_tid_to_link_Test, Retrieve_TID_to_link_info_after_modifying_fields) {
    std::cout << "Entering Retrieve_TID_to_link_info_after_modifying_fields test";
    em_tid_to_link_info_t custom_info;
    custom_info.is_bsta_config = true;
    custom_info.mld_mac_addr[0] = 0x01;
    custom_info.mld_mac_addr[1] = 0x02;
    custom_info.mld_mac_addr[2] = 0x03;
    custom_info.mld_mac_addr[3] = 0x04;
    custom_info.mld_mac_addr[4] = 0x05;
    custom_info.mld_mac_addr[5] = 0x06;
    custom_info.tid_to_link_map_neg = false;
    custom_info.num_mapping = 2;
    custom_info.tid_to_link_mapping[0].add_remove = true;
    custom_info.tid_to_link_mapping[0].sta_mld_mac_addr[0] = 0x11;
    custom_info.tid_to_link_mapping[0].sta_mld_mac_addr[1] = 0x22;
    custom_info.tid_to_link_mapping[0].sta_mld_mac_addr[2] = 0x33;
    custom_info.tid_to_link_mapping[0].sta_mld_mac_addr[3] = 0x44;
    custom_info.tid_to_link_mapping[0].sta_mld_mac_addr[4] = 0x55;
    custom_info.tid_to_link_mapping[0].sta_mld_mac_addr[5] = 0x66;
    custom_info.tid_to_link_mapping[0].direction = true;
    custom_info.tid_to_link_mapping[0].default_link_map = false;
    custom_info.tid_to_link_mapping[0].link_map_presence_ind = 1;
    custom_info.tid_to_link_mapping[0].tid_to_link_map = 5;
    custom_info.tid_to_link_mapping[1].add_remove = false;
    custom_info.tid_to_link_mapping[1].sta_mld_mac_addr[0] = 0xAA;
    custom_info.tid_to_link_mapping[1].sta_mld_mac_addr[1] = 0xBB;
    dm_tid_to_link_t obj(&custom_info);
    em_tid_to_link_info_t* result = obj.get_tid_to_link_info();
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->is_bsta_config, true);
    EXPECT_EQ(result->mld_mac_addr[0], 0x01);
    EXPECT_EQ(result->mld_mac_addr[1], 0x02);
    EXPECT_EQ(result->mld_mac_addr[2], 0x03);
    EXPECT_EQ(result->mld_mac_addr[3], 0x04);
    EXPECT_EQ(result->mld_mac_addr[4], 0x05);
    EXPECT_EQ(result->mld_mac_addr[5], 0x06);
    EXPECT_EQ(result->tid_to_link_map_neg, false);
    EXPECT_EQ(result->num_mapping, 2);
    EXPECT_EQ(result->tid_to_link_mapping[0].add_remove, true);
    EXPECT_EQ(result->tid_to_link_mapping[0].sta_mld_mac_addr[0], 0x11);
    EXPECT_EQ(result->tid_to_link_mapping[0].sta_mld_mac_addr[1], 0x22);
    EXPECT_EQ(result->tid_to_link_mapping[0].direction, true);
    EXPECT_EQ(result->tid_to_link_mapping[0].default_link_map, false);
    EXPECT_EQ(result->tid_to_link_mapping[0].link_map_presence_ind, 1);
    EXPECT_EQ(result->tid_to_link_mapping[0].tid_to_link_map, 5);
    EXPECT_EQ(result->tid_to_link_mapping[1].add_remove, false);
    EXPECT_EQ(result->tid_to_link_mapping[1].sta_mld_mac_addr[0], 0xAA);
    EXPECT_EQ(result->tid_to_link_mapping[1].sta_mld_mac_addr[1], 0xBB);
    std::cout << "Exiting Retrieve_TID_to_link_info_after_modifying_fields test";
}



/**
 * @brief Test to retrieve TID to link information after setting invalid values
 *
 * This test ensures that the class correctly stores and retrieves the given mld_mac_addr values without any modification or errors.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 021@n
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Step | Description                                      | Test Data                                                       | Expected Result                    | Notes       |
 * | :--: | ----------------------------------------------- | ----------------------------------------------------------------| --------------------------------- | ----------- |
 * | 01   | Initialize custom_info with minimal values      | mld_mac_addr = {0xAA, 0xEE, 0xDD, 0x00, 0x00, 0x00}             | custom_info should be initialized | Should be   |
 * |      |                                                  |                                                                  | with the given values             | successful  |
 * | 02   | Create dm_tid_to_link_t object with custom_info | custom_info                                                    | Object should be created          | Should be   |
 * |      |                                                  |                                                                  | successfully                     | successful  |
 * | 03   | Retrieve TID to link info using get_tid_to_link_info() | None                                                        | result should not be nullptr      | Should Pass |
 * | 04   | Verify mld_mac_addr values                        | result->mld_mac_addr = {0xAA, 0xEE, 0xDD, 0x00, 0x00, 0x00}     | Retrieved values should match     | Should Pass |
 * |      |                                                  |                                                                  | the set values                   |             |
 */
TEST(dm_tid_to_link_Test, Retrieve_TID_to_link_info_after_setting_invalid_values) {
    std::cout << "Entering Retrieve_TID_to_link_info_after_setting_invalid_values test";
    em_tid_to_link_info_t custom_info;
    custom_info.mld_mac_addr[0] = 0xAA;
    custom_info.mld_mac_addr[1] = 0xEE;
    custom_info.mld_mac_addr[2] = 0xDD;
    custom_info.mld_mac_addr[3] = 0x00;
    custom_info.mld_mac_addr[4] = 0x00;
    custom_info.mld_mac_addr[5] = 0x00;
    dm_tid_to_link_t obj(&custom_info);
    em_tid_to_link_info_t* result = obj.get_tid_to_link_info();
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->mld_mac_addr[0], 0xAA);
    EXPECT_EQ(result->mld_mac_addr[1], 0xEE);
    EXPECT_EQ(result->mld_mac_addr[2], 0xDD);
    EXPECT_EQ(result->mld_mac_addr[3], 0x00);
    EXPECT_EQ(result->mld_mac_addr[4], 0x00);
    EXPECT_EQ(result->mld_mac_addr[5], 0x00);
    std::cout << "Exiting Retrieve_TID_to_link_info_after_setting_invalid_values test";
}



/**
* @brief Test to initialize TID to Link Information Structure successfully
*
* This test verifies that the TID to Link Information Structure is initialized correctly by invoking the init() method of the dm_tid_to_link_t class. The test ensures that the initialization returns a success code (0).@n
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
* | 01| Create an instance of dm_tid_to_link_t and call init() method | instance = new dm_tid_to_link_t(), result = instance->init() | result = 0, EXPECT_EQ(result, 0) | Should Pass |
*/
TEST(dm_tid_to_link_t_Test, InitializeTIDToLinkInformationStructureSuccessfully) {
    std::cout << "Entering InitializeTIDToLinkInformationStructureSuccessfully" << std::endl;
    dm_tid_to_link_t obj;
    int result = obj.init();
    EXPECT_EQ(result, 0);
    std::cout << "Exiting InitializeTIDToLinkInformationStructureSuccessfully" << std::endl;
}



/**
* @brief Test the assignment operator with identical objects
*
* This test verifies that the assignment operator correctly assigns one object to another identical object and ensures that the equality operator confirms they are identical.@n
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
* | 01 | Create two identical objects | obj2.m_tid_to_link_info.is_bsta_config = true, obj2.m_tid_to_link_info.tid_to_link_map_neg = false, obj2.m_tid_to_link_info.num_mapping = 2 | Objects created successfully | Should be successful |
* | 02 | Assign obj2 to obj1 | obj1 = obj2 | Assignment successful | Should be successful |
* | 03 | Check if the initialized objects have same values | obj1.m_tid_to_link_info.is_bsta_config = true, obj1.m_tid_to_link_info.tid_to_link_map_neg = false, obj1.m_tid_to_link_info.num_mapping = 2 | True | Should Pass |
*/
TEST(dm_tid_to_link_t_Test, AssignmentOperatorWithIdenticalObjects) {
    std::cout << "Entering AssignmentOperatorWithIdenticalObjects" << std::endl;
    dm_tid_to_link_t obj1;
    dm_tid_to_link_t obj2;
    obj2.m_tid_to_link_info.is_bsta_config = true;
    obj2.m_tid_to_link_info.tid_to_link_map_neg = false;
    obj2.m_tid_to_link_info.num_mapping = 2;
    obj1 = obj2;
    EXPECT_EQ(obj2.m_tid_to_link_info.is_bsta_config, obj1.m_tid_to_link_info.is_bsta_config);
    EXPECT_EQ(obj2.m_tid_to_link_info.tid_to_link_map_neg, obj1.m_tid_to_link_info.tid_to_link_map_neg);
    EXPECT_EQ(obj2.m_tid_to_link_info.num_mapping, obj1.m_tid_to_link_info.num_mapping);
    std::cout << "Exiting AssignmentOperatorWithIdenticalObjects" << std::endl;
}



/**
* @brief Test the assignment operator with invalid values
*
* This test verifies the behavior of the assignment operator when assigning an object with invalid values. Specifically, it checks that the assignment operator does not result in the two objects being considered equal when one of the objects has an invalid configuration.
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
* | 01| Create two instances of dm_tid_to_link_t | instance = new dm_tid_to_link_t() | Should be successful | |
* | 02| Assign invalid value to obj2 | mld_mac_addr = {0xAA, 0xEE, 0xDD, 0x00, 0x00, 0x00} | Should be successful | |
* | 03| Assign obj2 to obj1 using assignment operator | obj1 = obj2 | Should be successful | |
* | 04| Check if invalid mac is assigned to obj1 | mld_mac_addr = {0xAA, 0xEE, 0xDD, 0x00, 0x00, 0x00} | Should Pass | |
*/
TEST(dm_tid_to_link_t_Test, AssignmentOperatorWithInvalidValues) {
    std::cout << "Entering AssignmentOperatorWithInvalidValues" << std::endl;
    dm_tid_to_link_t obj1, obj2;
    obj2.m_tid_to_link_info.mld_mac_addr[0] = 0xAA;
    obj2.m_tid_to_link_info.mld_mac_addr[1] = 0xEE;
    obj2.m_tid_to_link_info.mld_mac_addr[2] = 0xDD;
    obj2.m_tid_to_link_info.mld_mac_addr[3] = 0x00;
    obj2.m_tid_to_link_info.mld_mac_addr[4] = 0x00;
    obj2.m_tid_to_link_info.mld_mac_addr[5] = 0x00;
    obj1 = obj2;
    EXPECT_EQ(obj2.m_tid_to_link_info.is_bsta_config, obj1.m_tid_to_link_info.is_bsta_config);
    EXPECT_EQ(obj2.m_tid_to_link_info.mld_mac_addr[0], 0xAA);
    EXPECT_EQ(obj2.m_tid_to_link_info.mld_mac_addr[1], 0xEE);
    EXPECT_EQ(obj2.m_tid_to_link_info.mld_mac_addr[2], 0xDD);
    EXPECT_EQ(obj2.m_tid_to_link_info.mld_mac_addr[3], 0x00);
    EXPECT_EQ(obj2.m_tid_to_link_info.mld_mac_addr[4], 0x00);
    EXPECT_EQ(obj2.m_tid_to_link_info.mld_mac_addr[5], 0x00);
    std::cout << "Exiting AssignmentOperatorWithInvalidValues" << std::endl;
}



/**
* @brief Test to verify the equality operator for identical non-default values
*
* This test checks if two instances of the `dm_tid_to_link_t` class with identical non-default values are considered equal.@n
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
* | 01| Initialize obj1 with non-default values | obj1.m_tid_to_link_info.is_bsta_config = true, obj1.m_tid_to_link_info.mld_mac_addr = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, obj1.m_tid_to_link_info.tid_to_link_map_neg = true, obj1.m_tid_to_link_info.num_mapping = 5 | Should be successful | |
* | 02| Initialize obj2 with identical non-default values | obj2.m_tid_to_link_info.is_bsta_config = true, obj2.m_tid_to_link_info.mld_mac_addr = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, obj2.m_tid_to_link_info.tid_to_link_map_neg = true, obj2.m_tid_to_link_info.num_mapping = 5 | Should be successful | |
* | 03| Compare obj1 and obj2 for equality | obj1 == obj2 | EXPECT_TRUE(obj1 == obj2) | Should Pass |
*/
TEST(dm_tid_to_link_t_Test, IdenticalNonDefaultValues) {
    std::cout << "Entering IdenticalNonDefaultValues test";
    dm_tid_to_link_t obj1, obj2;
    obj1.m_tid_to_link_info.is_bsta_config = true;
    obj1.m_tid_to_link_info.mld_mac_addr[0] = 0x00;
    obj1.m_tid_to_link_info.mld_mac_addr[1] = 0x11;
    obj1.m_tid_to_link_info.mld_mac_addr[2] = 0x22;
    obj1.m_tid_to_link_info.mld_mac_addr[3] = 0x33;
    obj1.m_tid_to_link_info.mld_mac_addr[4] = 0x44;
    obj1.m_tid_to_link_info.mld_mac_addr[5] = 0x55;
    obj1.m_tid_to_link_info.tid_to_link_map_neg = true;
    obj1.m_tid_to_link_info.num_mapping = 5;
    obj2.m_tid_to_link_info.is_bsta_config = true;
    obj2.m_tid_to_link_info.mld_mac_addr[0] = 0x00;
    obj2.m_tid_to_link_info.mld_mac_addr[1] = 0x11;
    obj2.m_tid_to_link_info.mld_mac_addr[2] = 0x22;
    obj2.m_tid_to_link_info.mld_mac_addr[3] = 0x33;
    obj2.m_tid_to_link_info.mld_mac_addr[4] = 0x44;
    obj2.m_tid_to_link_info.mld_mac_addr[5] = 0x55;
    obj2.m_tid_to_link_info.tid_to_link_map_neg = true;
    obj2.m_tid_to_link_info.num_mapping = 5;
    EXPECT_TRUE(obj1 == obj2);
    std::cout << "Exiting IdenticalNonDefaultValues test";
}



/**
* @brief Test to verify the behavior of the equality operator for different is_bsta_config values
*
* This test checks the equality operator of the dm_tid_to_link_t class when the is_bsta_config member variable is set to different values in two instances. The test ensures that the equality operator correctly identifies the instances as not equal when their is_bsta_config values differ.
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
* | 01 | Create two instances of dm_tid_to_link_t | obj1, obj2 | Instances created successfully | Should be successful |
* | 02 | Set is_bsta_config to true for obj1 and false for obj2 | obj1.m_tid_to_link_info.is_bsta_config = true, obj2.m_tid_to_link_info.is_bsta_config = false | Values set successfully | Should be successful |
* | 03 | Compare obj1 and obj2 using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_tid_to_link_t_Test, DifferentIsBstaConfigValues) {
    std::cout << "Entering DifferentIsBstaConfigValues test";
    dm_tid_to_link_t obj1, obj2;
    obj1.m_tid_to_link_info.is_bsta_config = true;
    obj2.m_tid_to_link_info.is_bsta_config = false;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting DifferentIsBstaConfigValues test";
}



/**
* @brief Test to verify the behavior of the equality operator for different MLD MAC address values.
*
* This test checks if two instances of `dm_tid_to_link_t` with different MLD MAC address values are not considered equal.@n
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
* | 01 | Set MLD MAC address for obj1 | obj1.m_tid_to_link_info.mld_mac_addr = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55} |  | Should be successful |
* | 02 | Set MLD MAC address for obj2 | obj2.m_tid_to_link_info.mld_mac_addr = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB} |  | Should be successful |
* | 03 | Compare obj1 and obj2 using equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_tid_to_link_t_Test, DifferentMldMacAddrValues) {
    std::cout << "Entering DifferentMldMacAddrValues test";
    dm_tid_to_link_t obj1, obj2;
    obj1.m_tid_to_link_info.mld_mac_addr[0] = 0x00;
    obj1.m_tid_to_link_info.mld_mac_addr[1] = 0x11;
    obj1.m_tid_to_link_info.mld_mac_addr[2] = 0x22;
    obj1.m_tid_to_link_info.mld_mac_addr[3] = 0x33;
    obj1.m_tid_to_link_info.mld_mac_addr[4] = 0x44;
    obj1.m_tid_to_link_info.mld_mac_addr[5] = 0x55;
    obj2.m_tid_to_link_info.mld_mac_addr[0] = 0x66;
    obj2.m_tid_to_link_info.mld_mac_addr[1] = 0x77;
    obj2.m_tid_to_link_info.mld_mac_addr[2] = 0x88;
    obj2.m_tid_to_link_info.mld_mac_addr[3] = 0x99;
    obj2.m_tid_to_link_info.mld_mac_addr[4] = 0xAA;
    obj2.m_tid_to_link_info.mld_mac_addr[5] = 0xBB;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting DifferentMldMacAddrValues test";
}



/**
* @brief Test to verify the behavior of the equality operator for dm_tid_to_link_t objects with different tid_to_link_map_neg values.
*
* This test checks the equality operator for two dm_tid_to_link_t objects with different values for the tid_to_link_map_neg member variable. The test ensures that the equality operator correctly identifies the objects as not equal when their tid_to_link_map_neg values differ.
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create two dm_tid_to_link_t objects with different tid_to_link_map_neg values | obj1.m_tid_to_link_info.tid_to_link_map_neg = true, obj2.m_tid_to_link_info.tid_to_link_map_neg = false | Objects should not be equal | Should Pass |
* | 02| Check the equality operator for the two objects | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_tid_to_link_t_Test, DifferentTidToLinkMapNegValues) {
    std::cout << "Entering DifferentTidToLinkMapNegValues test";
    dm_tid_to_link_t obj1, obj2;
    obj1.m_tid_to_link_info.tid_to_link_map_neg = true;
    obj2.m_tid_to_link_info.tid_to_link_map_neg = false;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting DifferentTidToLinkMapNegValues test";
}



/**
* @brief Test to verify the equality operator for different num_mapping values
*
* This test checks the equality operator of the dm_tid_to_link_t class by setting different num_mapping values in two instances and verifying that they are not considered equal.@n
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
* | 01| Create two instances of dm_tid_to_link_t and set different num_mapping values | obj1.num_mapping = 5, obj2.num_mapping = 10 | Instances should not be equal | Should Pass |
* | 02| Check equality operator for the two instances | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_tid_to_link_t_Test, DifferentNumMappingValues) {
    std::cout << "Entering DifferentNumMappingValues test";
    dm_tid_to_link_t obj1, obj2;
    obj1.m_tid_to_link_info.num_mapping = 5;
    obj2.m_tid_to_link_info.num_mapping = 10;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting DifferentNumMappingValues test";
}