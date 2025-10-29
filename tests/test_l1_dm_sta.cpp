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
#include "dm_sta.h"

/**
* @brief Test the decode function with a valid JSON object and valid parent ID
*
* This test checks the decode function of the dm_sta_t class to ensure it correctly processes a valid JSON object and a valid parent ID.@n
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
* | 01| Create a valid JSON object and a valid parent ID | obj = valid JSON object, parent_id = valid parent ID | Successful creation of JSON object and parent ID | Should be successful |
* | 02| Call the decode function with the valid JSON object and parent ID | obj = valid JSON object, parent_id = valid parent ID | result = 0, EXPECT_EQ(result, 0) | Should Pass |
* | 03| Free the allocated parent ID and JSON object | free(parent_id), cJSON_Delete(obj)| Successful deallocation of parent ID and JSON obj| Should be successful |
*/
TEST(dm_sta_t_Test, ValidJsonObjectAndValidParentID) {
    std::cout << "Entering ValidJsonObjectAndValidParentID" << std::endl;
    cJSON* obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "MACAddress", "AA:BB:CC:DD:EE:FF");
    mac_address_t* parent_id = static_cast<mac_address_t*>(malloc(sizeof(mac_address_t)));
    memset(parent_id, 0x11, sizeof(mac_address_t));  // Fill with dummy MAC bytes
    dm_sta_t dm_sta;
    int result = dm_sta.decode(obj, parent_id);
    EXPECT_EQ(result, 0);
    free(parent_id);
    cJSON_Delete(obj);
    std::cout << "Exiting ValidJsonObjectAndValidParentID" << std::endl;
}

/**
* @brief Test to verify the behavior of the decode function when a null JSON object is passed.
*
* This test checks the decode function of the dm_sta_t class to ensure it correctly handles a null JSON object input. 
* The function is expected to return an error code when provided with a null JSON object, which is a negative test scenario.
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
* | 01 | Assign value for parent_id | memset(parent_id, 0x11, sizeof(mac_address_t));| parent_id allocated successfully | Should be successful |
* | 02 | Create an instance of dm_sta_t | dm_sta_t dm_sta | Instance created successfully | Should be successful |
* | 03 | Call decode with null JSON object | json_obj = nullptr, parent_id = parent_id | result = -1 | Should Fail |
* | 04 | Check the result of decode | result = -1 | EXPECT_EQ(result, -1) | Should be successful |
* | 05 | Free allocated memory | free(parent_id) | Memory freed successfully | Should be successful |
*/
TEST(dm_sta_t_Test, NullJsonObject) {
    std::cout << "Entering NullJsonObject" << std::endl;
    mac_address_t* parent_id = static_cast<mac_address_t*>(malloc(sizeof(mac_address_t)));
    memset(parent_id, 0x11, sizeof(mac_address_t));  // Fill with dummy MAC bytes
    dm_sta_t dm_sta;
    int result = dm_sta.decode(nullptr, parent_id);
    EXPECT_EQ(result, -1);
    free(parent_id);
    std::cout << "Exiting NullJsonObject" << std::endl;
}

/**
* @brief Test to verify the behavior of the decode function when a null parent ID is provided.
*
* This test checks the decode function of the dm_sta_t class to ensure it correctly handles a null parent ID. 
* The function is expected to return an error code when the parent ID is null, which is a negative test case.
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
TEST(dm_sta_t_Test, NullParentID) {
    std::cout << "Entering NullParentID" << std::endl;
    cJSON* obj = cJSON_CreateObject();
    dm_sta_t dm_sta;
    int result = dm_sta.decode(obj, nullptr);
    EXPECT_EQ(result, -1);
    cJSON_Delete(obj);
    std::cout << "Exiting NullParentID" << std::endl;
}

/**
* @brief Test to verify the behavior of the decode function when provided with a JSON object of invalid type.
*
* This test checks the decode function of the dm_sta_t class to ensure it correctly handles a JSON object with an invalid type. The objective is to verify that the function returns an error code when the JSON object type is not recognized.
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
* | 01 | Create a JSON object with invalid type | obj->type = -1 | Should be successful | |
* | 02 | Assign value for parent_id | memset(parent_id, 0x11, sizeof(mac_address_t));| Should be successful | |
* | 03 | Call the decode function with invalid JSON object | result = dm_sta.decode(obj, parent_id) | result = -1, EXPECT_EQ(result, -1) | Should Pass |
* | 04 | Free the allocated memory for parent_id and JSON obj | free(parent_id) , cJSON_Delete(obj)| Should be successful | |
*/
TEST(dm_sta_t_Test, JsonObjectWithInvalidType) {
    std::cout << "Entering JsonObjectWithInvalidType" << std::endl;
    cJSON* obj = cJSON_CreateObject();
    obj->type = -1;
    mac_address_t* parent_id = static_cast<mac_address_t*>(malloc(sizeof(mac_address_t)));
    memset(parent_id, 0x11, sizeof(mac_address_t));  // Fill with dummy MAC bytes
    dm_sta_t dm_sta;
    int result = dm_sta.decode(obj, parent_id);
    EXPECT_EQ(result, -1);
    free(parent_id);
    cJSON_Delete(obj);
    std::cout << "Exiting JsonObjectWithInvalidType" << std::endl;
}

/**
* @brief Test the decoding of a JSON object with nested objects
*
* This test verifies the functionality of the `decode` method in the `dm_sta_t` class when provided with a JSON object that contains nested objects. The objective is to ensure that the method can correctly handle and decode such structures without errors.
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
* | 01| Allocate memory for nested JSON object and parent ID | cJSON* nested_obj = cJSON_CreateObject(), memset(parent_id, 0x11, sizeof(mac_address_t));| Memory should be allocated successfully | Should be successful |
* | 02| Invoke the decode method with the JSON object and parent ID | obj, parent_id | result should be 0, EXPECT_EQ(result, 0) | Should Pass |
* | 03| Free allocated memory for nested JSON object and parent ID | cJSON_Delete(obj), free(parent_id) | Memory should be freed successfully | Should be successful |
*/
TEST(dm_sta_t_Test, JsonObjectWithNestedObjects) {
    std::cout << "Entering JsonObjectWithNestedObjects" << std::endl;
    // Create main JSON object
    cJSON* obj = cJSON_CreateObject();
    // Create a nested JSON object
    cJSON* nested_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(nested_obj, "MACAddress", "00:11:22:33:44:55");
    cJSON_AddNumberToObject(nested_obj, "LastDataUplinkRate", 100);
    // Add nested object as a child to main obj with some key
    cJSON_AddItemToObject(obj, "nested_key", nested_obj);
    mac_address_t* parent_id = static_cast<mac_address_t*>(malloc(sizeof(mac_address_t)));
    memset(parent_id, 0x11, sizeof(mac_address_t));  // Fill with dummy MAC bytes
    dm_sta_t dm_sta;
    int result = dm_sta.decode(obj, parent_id);
    EXPECT_EQ(result, 0);
    free(parent_id);
    cJSON_Delete(obj);
    std::cout << "Exiting JsonObjectWithNestedObjects" << std::endl;
}

/**
* @brief Test to verify the decoding of a JSON object with an array type
*
* This test checks the functionality of the decode method in the dm_sta_t class when provided with a JSON object of type array. The objective is to ensure that the method correctly processes the input and returns the expected result.
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create a JSON object of type array | cJSON* obj = cJSON_CreateArray() | Should be successful | |
* | 02| Assign value for parent_id | memset(parent_id, 0x11, sizeof(mac_address_t)); | Should be successful | |
* | 03| Call decode method with JSON object and parent_id | dm_sta.decode(obj, parent_id) | result = 0, EXPECT_EQ(result, 0) | Should Pass |
* | 04| Free allocated memory for parent_id and JSON obj| free(parent_id), cJSON_Delete(obj) | Should be successful | |
*/
TEST(dm_sta_t_Test, JsonObjectWithArray) {
    std::cout << "Entering JsonObjectWithArray" << std::endl;
    cJSON* obj = cJSON_CreateArray();
    mac_address_t* parent_id = static_cast<mac_address_t*>(malloc(sizeof(mac_address_t)));
    memset(parent_id, 0x11, sizeof(mac_address_t));  // Fill with dummy MAC bytes
    dm_sta_t dm_sta;
    int result = dm_sta.decode(obj, parent_id);
    EXPECT_EQ(result, 0);
    free(parent_id);
    cJSON_Delete(obj);
    std::cout << "Exiting JsonObjectWithArray" << std::endl;
}

/**
* @brief Test the decode function with a JSON object containing special characters
*
* This test verifies that the decode function can handle a JSON object with special characters in its value string. This is important to ensure that the function can correctly process and decode JSON objects with various types of characters.
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
* | 01 | Initialize JSON object with special characters | cJSON* obj = cJSON_CreateString("!@#$%^&*()") | Should be successful | |
* | 02 | Assign value for parent_id | memset(parent_id, 0x11, sizeof(mac_address_t)); | Should be successful | |
* | 03 | Call decode function | obj = "!@#$%^&*()", parent_id = allocated memory | result = 0, EXPECT_EQ(result, 0) | Should Pass |
* | 04 | Free allocated memory for obj | cJSON_Delete(obj) | Should be successful | |
* | 05 | Free allocated memory for parent_id | free(parent_id) | Should be successful | |
*/
TEST(dm_sta_t_Test, JsonObjectWithSpecialCharacters) {
    std::cout << "Entering JsonObjectWithSpecialCharacters" << std::endl;
    cJSON* obj = cJSON_CreateString("!@#$%^&*()");
    mac_address_t* parent_id = static_cast<mac_address_t*>(malloc(sizeof(mac_address_t)));
    memset(parent_id, 0x11, sizeof(mac_address_t));  // Fill with dummy MAC bytes
    dm_sta_t dm_sta;
    int result = dm_sta.decode(obj, parent_id);
    EXPECT_EQ(result, 0);
    free(parent_id);
    cJSON_Delete(obj);
    std::cout << "Exiting JsonObjectWithSpecialCharacters" << std::endl;
}

/**
* @brief Test the decoding of beacon report for a station object with multi-band capability and a valid beacon report.
*
* This test verifies that the `decode_beacon_report` function correctly processes a station object that has multi-band capability and a valid beacon report length. The expected result is that the function returns 0, indicating successful decoding.
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
* | 01 | Create a station object with valid values | multi_band_cap = true, beacon_report_len = 10, assosciated = true, last_ul_rate = 1000 | Object should be created successfully | Should be successful |
* | 02 | Call decode_beacon_report on the station object | sta = <created object> | No exception should be thrown. | Should Pass |
*/
TEST(dm_sta_t_Test, StationObjectWithValidValues) {
    std::cout << "Entering StationObjectWithValidValues" << std::endl;
    dm_sta_t *sta = new dm_sta_t();
    sta->m_sta_info.multi_band_cap = true;
    sta->m_sta_info.beacon_report_len = 10;
    sta->m_sta_info.associated = true;
    sta->m_sta_info.last_ul_rate = 1000;
    EXPECT_NO_THROW({
        dm_sta_t::decode_beacon_report(sta);
    });
    delete sta;
    std::cout << "Exiting StationObjectWithValidValues" << std::endl;
}

/**
* @brief Test to verify the behavior of decode_beacon_report when a null station object is passed.
*
* This test checks the decode_beacon_report function to ensure it correctly handles a null station object by returning an error code.@n
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
* | 01 | Set station object to null and call decode_beacon_report | sta = nullptr | Exception should be thrown.| Should Fail |
*/
TEST(dm_sta_t_Test, NullStationObject) {
    std::cout << "Entering NullStationObject" << std::endl;
    dm_sta_t *sta = nullptr;
    EXPECT_ANY_THROW({
        dm_sta_t::decode_beacon_report(sta);
    });
    std::cout << "Exiting NullStationObject" << std::endl;
}

/**
* @brief Test the decode_beacon_report function with a station object having multi-band capability and an empty beacon report.
*
* This test checks the behavior of the decode_beacon_report function when the station object has multi-band capability but the beacon report length is zero. This scenario is important to ensure that the function correctly handles cases where the beacon report is empty, which should result in a specific error code.
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
* | 01 | Create a station object with multi-band capability and empty beacon report | multi_band_cap = true, beacon_report_len = 0 | Station object created successfully | Should be successful |
* | 02 | Call decode_beacon_report with the created station object | sta = station object | No exception should be thrown. | Should Pass |
*/
TEST(dm_sta_t_Test, StationObjectWithMultiBandCapabilityAndEmptyBeaconReport) {
    std::cout << "Entering StationObjectWithMultiBandCapabilityAndEmptyBeaconReport" << std::endl;
    dm_sta_t *sta = new dm_sta_t();
    sta->m_sta_info.multi_band_cap = true;
    sta->m_sta_info.beacon_report_len = 0;
    EXPECT_NO_THROW({
        dm_sta_t::decode_beacon_report(sta);
    });
    delete sta;
    std::cout << "Exiting StationObjectWithMultiBandCapabilityAndEmptyBeaconReport" << std::endl;
}

/**
* @brief Test the StationObjectWithMaximumLengthBeaconReport function
*
* This test verifies that the decode_beacon_report function correctly handles a station object with the maximum length beacon report. It ensures that the function can process the maximum allowed beacon report length without errors.
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
* | 01 | Create a new dm_sta_t instance | instance = new dm_sta_t() | Should be successful | |
* | 02 | Set the beacon report length to maximum | sta->m_sta_info.beacon_report_len = EM_MAX_BEACON_MEASUREMENT_LEN | Should be successful | |
* | 03 | Call decode_beacon_report with the station object | result = dm_sta_t::decode_beacon_report(sta) | No exception should be thrown. | Should Pass |
* | 04 | Delete the dm_sta_t instance | delete sta | Should be successful | |
*/
TEST(dm_sta_t_Test, StationObjectWithMaximumLengthBeaconReport) {
    std::cout << "Entering StationObjectWithMaximumLengthBeaconReport" << std::endl;
    dm_sta_t *sta = new dm_sta_t();
    sta->m_sta_info.beacon_report_len = EM_MAX_BEACON_MEASUREMENT_LEN;
    EXPECT_NO_THROW({
        dm_sta_t::decode_beacon_report(sta);
    });    
    delete sta;
    std::cout << "Exiting StationObjectWithMaximumLengthBeaconReport" << std::endl;
}

/**
* @brief Test to verify the behavior of the decode_beacon_report function with an invalid beacon report length.
*
* This test checks if the decode_beacon_report function correctly handles the scenario where the beacon report length exceeds the maximum allowed length. This is important to ensure that the function can handle invalid input gracefully and return the expected error code.
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
* | 01 | Create a new dm_sta_t instance | instance = new dm_sta_t() | instance should be created successfully | Should be successful |
* | 02 | Set beacon_report_len to an invalid length | sta->m_sta_info.beacon_report_len = EM_MAX_BEACON_MEASUREMENT_LEN + 1 | beacon_report_len should be set to an invalid length | Should be successful |
* | 03 | Call decode_beacon_report with the invalid beacon report length | result = dm_sta_t::decode_beacon_report(sta) | Exception should be thrown. | Should Fail |
* | 04 | Delete the dm_sta_t instance | delete sta | instance should be deleted successfully | Should be successful |
*/
TEST(dm_sta_t_Test, StationObjectWithInvalidBeaconReportLength) {
    std::cout << "Entering StationObjectWithInvalidBeaconReportLength" << std::endl;
    dm_sta_t *sta = new dm_sta_t();
    sta->m_sta_info.beacon_report_len = EM_MAX_BEACON_MEASUREMENT_LEN + 1;
    EXPECT_ANY_THROW({
        dm_sta_t::decode_beacon_report(sta);
    });
    delete sta;
    std::cout << "Exiting StationObjectWithInvalidBeaconReportLength" << std::endl;
}

/**
* @brief Test to verify the behavior of decode_sta_capability when a null STA object is passed.
*
* This test checks the decode_sta_capability function to ensure it handles a null STA object correctly. 
* The objective is to verify that the function does not crash or produce unexpected behavior when given a null pointer.
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Initialize STA object to null | sta = nullptr | Function should handle null input gracefully | Should Pass |
* | 02| Call decode_sta_capability with null STA object | sta = nullptr | Exception should be thrown.| Should Fail |
*/
TEST(dm_sta_t_Test, Null_STA_Object) {
    std::cout << "Entering Null_STA_Object test";
    dm_sta_t *sta = nullptr;
    EXPECT_ANY_THROW({
        dm_sta_t::decode_sta_capability(sta);
    });
    std::cout << "Exiting Null_STA_Object test";
}

/**
* @brief Test to validate the behavior of the STA object with an invalid MAC address.
*
* This test checks the behavior of the `dm_sta_t` object when it is initialized with an invalid MAC address. 
* The objective is to ensure that the `decode_sta_capability` function handles the invalid MAC address correctly.
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
* | 01 | Initialize STA object with invalid MAC address | sta.m_sta_info.id = {0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x00} | STA object initialized with invalid MAC address | Should be successful |
* | 02 | Call decode_sta_capability with the invalid MAC address | sta | Exception should be thrown. | Should Fail |
*/
TEST(dm_sta_t_Test, Valid_STA_Object_With_Invalid_MAC_Address) {
    std::cout << "Entering Valid_STA_Object_With_Invalid_MAC_Address test";
    dm_sta_t sta;
    sta.m_sta_info.id[0] = 0xAA;
    sta.m_sta_info.id[1] = 0xBB;
    sta.m_sta_info.id[2] = 0xCC;
    sta.m_sta_info.id[3] = 0x00;
    sta.m_sta_info.id[4] = 0x00;
    sta.m_sta_info.id[5] = 0x00;
    EXPECT_ANY_THROW({
        dm_sta_t::decode_sta_capability(&sta);
    });
    std::cout << "Exiting Valid_STA_Object_With_Invalid_MAC_Address test";
}

/**
* @brief Test the copy constructor of dm_sta_t with maximum and minimum values.
*
* This test verifies that the copy constructor of the dm_sta_t class correctly copies the values from the original object to the new object, even when the original object contains extreme values (maximum and minimum possible values). This ensures that the copy constructor handles edge cases properly.
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
* | 01 | Initialize original dm_sta_t object with extreme values | associated = true, last_ul_rate = UINT_MAX, last_dl_rate = 0, signal_strength = INT_MIN, rcpi = UCHAR_MAX | Object initialized with given values | Should be successful |
* | 02 | Invoke copy constructor to create a new dm_sta_t object | original object | New object created with copied values | Should be successful |
* | 03 | Verify copied values for 'associated' field | copy.m_sta_info.associated, original.m_sta_info.associated | Values should be equal | Should Pass |
* | 04 | Verify copied values for 'last_ul_rate' field | copy.m_sta_info.last_ul_rate, original.m_sta_info.last_ul_rate | Values should be equal | Should Pass |
* | 05 | Verify copied values for 'last_dl_rate' field | copy.m_sta_info.last_dl_rate, original.m_sta_info.last_dl_rate | Values should be equal | Should Pass |
* | 06 | Verify copied values for 'signal_strength' field | copy.m_sta_info.signal_strength, original.m_sta_info.signal_strength | Values should be equal | Should Pass |
* | 07 | Verify copied values for 'rcpi' field | copy.m_sta_info.rcpi, original.m_sta_info.rcpi | Values should be equal | Should Pass |
*/
TEST(dm_sta_t_Test, CopyConstructor_MaxMinValues) {
    std::cout << "Entering CopyConstructor_MaxMinValues test";
    dm_sta_t original;
    original.m_sta_info.associated = true;
    original.m_sta_info.last_ul_rate = UINT_MAX;
    original.m_sta_info.last_dl_rate = 0;
    original.m_sta_info.signal_strength = INT_MIN;
    original.m_sta_info.rcpi = UCHAR_MAX;
    dm_sta_t copy(original);
    EXPECT_EQ(copy.m_sta_info.associated, original.m_sta_info.associated);
    EXPECT_EQ(copy.m_sta_info.last_ul_rate, original.m_sta_info.last_ul_rate);
    EXPECT_EQ(copy.m_sta_info.last_dl_rate, original.m_sta_info.last_dl_rate);
    EXPECT_EQ(copy.m_sta_info.signal_strength, original.m_sta_info.signal_strength);
    EXPECT_EQ(copy.m_sta_info.rcpi, original.m_sta_info.rcpi);
    std::cout << "Exiting CopyConstructor_MaxMinValues test";
}

/**
* @brief Test the copy constructor of dm_sta_t with invalid values
*
* This test verifies that the copy constructor of the dm_sta_t class correctly copies the member variables even when they are set to invalid values. This ensures that the copy constructor handles edge cases properly.
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
* | 01| Initialize original dm_sta_t object with invalid values | original.frame_body_len=EM_MAX_FRAME_BODY_LEN+1, original.id = {0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x00} | Object initialized with given values | Should be successful |
* | 02| Copy construct dm_sta_t object from original | original | Copy object should have same values as original | Should Pass |
* | 03| Verify copied values for id and frame_body_len | copy.frame_body_len=EM_MAX_FRAME_BODY_LEN+1, copy.id = {0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x00} | Values should be equal | Should Pass |
*/
TEST(dm_sta_t_Test, CopyConstructor_InvalidValues) {
    std::cout << "Entering CopyConstructor_InvalidValues test";
    dm_sta_t original;
    original.m_sta_info.frame_body_len = EM_MAX_FRAME_BODY_LEN + 1;
    original.m_sta_info.id[0] = 0xAA;
    original.m_sta_info.id[1] = 0xBB;
    original.m_sta_info.id[2] = 0xCC;
    original.m_sta_info.id[3] = 0x00;
    original.m_sta_info.id[4] = 0x00;
    original.m_sta_info.id[5] = 0x00;
    dm_sta_t copy(original);
    EXPECT_EQ(copy.m_sta_info.frame_body_len, original.m_sta_info.frame_body_len);
    EXPECT_EQ(copy.m_sta_info.id[0], original.m_sta_info.id[0]);
    EXPECT_EQ(copy.m_sta_info.id[1], original.m_sta_info.id[1]);
    EXPECT_EQ(copy.m_sta_info.id[2], original.m_sta_info.id[2]);
    EXPECT_EQ(copy.m_sta_info.id[3], original.m_sta_info.id[3]);
    EXPECT_EQ(copy.m_sta_info.id[4], original.m_sta_info.id[4]);
    EXPECT_EQ(copy.m_sta_info.id[5], original.m_sta_info.id[5]);
    std::cout << "Exiting CopyConstructor_InvalidValues test";
}

/**
* @brief Test to validate the structure of em_sta_info_t
*
* This test verifies that the dm_sta_t object correctly initializes and retrieves the em_sta_info_t structure when provided with valid data.@n
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
* | 01 | Initialize em_sta_info_t with valid data | associated = true, last_ul_rate = UINT_MAX, last_dl_rate = 0, signal_strength = INT_MIN, rcpi = UCHAR_MAX | Should initialize successfully | Should be successful |
* | 02 | Create dm_sta_t object with valid em_sta_info_t | sta_obj(&valid_sta) | Should create object successfully | Should be successful |
*/
TEST(dm_sta_t_Test, ValidEmStaInfoStructure) {
    std::cout << "Entering ValidEmStaInfoStructure test";
    em_sta_info_t valid_sta;
    valid_sta.associated = true;
    valid_sta.last_ul_rate = UINT_MAX;
    valid_sta.last_dl_rate = 0;
    valid_sta.signal_strength = INT_MIN;
    valid_sta.rcpi = UCHAR_MAX;
    EXPECT_NO_THROW({
        dm_sta_t sta_obj(&valid_sta);
    });
    std::cout << "Exiting ValidEmStaInfoStructure test";
}

/**
* @brief Test to verify the behavior when a null pointer is passed to the constructor of dm_sta_t
*
* This test checks the behavior of the dm_sta_t class when it is initialized with a null pointer. 
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
* | 01| Initialize dm_sta_t with null pointer | null_sta = nullptr | Exception should be thrown.| Should fail |
*/
TEST(dm_sta_t_Test, NullEmStaInfoStructure) {
    std::cout << "Entering NullEmStaInfoStructure test";
    em_sta_info_t *null_sta = nullptr;
    EXPECT_ANY_THROW({
        dm_sta_t sta_obj(null_sta);
    });
    std::cout << "Exiting NullEmStaInfoStructure test";
}

/**
* @brief Test to validate handling of invalid MAC addresses
*
* This test checks the behavior of the dm_sta_t class when initialized with invalid MAC address values. The objective is to ensure that the class correctly handles and stores invalid MAC addresses without crashing or misbehaving.
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
* | 01 | Initialize em_sta_info_t with invalid MAC address values | invalid_mac_sta.id = {0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x00} | Object should be created successfully | Should Pass |
* | 02 | Create dm_sta_t object with invalid MAC address | dm_sta_t sta_obj(&invalid_mac_sta) | Exception should be thrown.| Should Fail |
*/
TEST(dm_sta_t_Test, InvalidMacAddress) {
    std::cout << "Entering InvalidMacAddress test";
    em_sta_info_t invalid_mac_sta;
    invalid_mac_sta.id[0] = 0xAA;
    invalid_mac_sta.id[1] = 0xBB;
    invalid_mac_sta.id[2] = 0xCC;
    invalid_mac_sta.id[3] = 0x00;
    invalid_mac_sta.id[4] = 0x00;
    invalid_mac_sta.id[5] = 0x00;
    EXPECT_ANY_THROW({
        dm_sta_t sta_obj(&invalid_mac_sta);
    });
    std::cout << "Exiting InvalidMacAddress test";
}

/**
* @brief Test to verify handling of nullpointer
*
* This test checks if the `dm_sta_t` object correctly handles null pointer@n
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
* | 01| Initialize `em_sta_info_t` with null pointer | em_sta_info_t *null_sta = nullptr, dm_sta_t sta_obj(null_sta) | Exception should be thrown.| Should Fail|
*/
TEST(dm_sta_t_Test, InitializeWithNullpointer) {
    std::cout << "Entering InitializeWithNullpointer test";
    em_sta_info_t *null_sta = nullptr;
    EXPECT_ANY_THROW({
        dm_sta_t sta_obj(null_sta);
    });
    std::cout << "Exiting InitializeWithNullpointer test";
}

/**
* @brief Test encoding with a valid cJSON object and different reason values.
*
* This test verifies the encoding functionality of the dm_sta_t class using a valid cJSON object and different reason values. The test ensures that the encode method can handle various reasons correctly.
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
* | 01 | Initialize dm_sta_t and cJSON object | dm_sta_t dmSta, cJSON obj | Initialization should be successful | Should be successful |
* | 02 | Encode with reason em_get_sta_list_reason_steer | obj = &obj, reason = em_get_sta_list_reason_steer | Encoding should be successful | Should Pass |
* | 03 | Encode with reason em_get_sta_list_reason_btm | obj = &obj, reason = em_get_sta_list_reason_btm | Encoding should be successful | Should Pass |
* | 04 | Encode with reason em_get_sta_list_reason_disassoc | obj = &obj, reason = em_get_sta_list_reason_disassoc | Encoding should be successful | Should Pass |
* | 05 | Encode with reason em_get_sta_list_reason_neighbors | obj = &obj, reason = em_get_sta_list_reason_neighbors | Encoding should be successful | Should Pass |
* | 06 | Encode with reason em_get_sta_list_reason_none | obj = &obj, reason = em_get_sta_list_reason_none | Encoding should be successful | Should Pass |
*/
TEST(dm_sta_t_Test, EncodeWithValidCJsonObjectAndDifferentReasonValues) {
    std::cout << "Entering EncodeWithValidCJsonObjectAndDifferentReasonValues" << std::endl;
    dm_sta_t dmSta;
    cJSON* obj = cJSON_CreateObject();
    em_get_sta_list_reason_t reasons[] = {
        em_get_sta_list_reason_steer,
        em_get_sta_list_reason_btm,
        em_get_sta_list_reason_disassoc,
        em_get_sta_list_reason_neighbors,
        em_get_sta_list_reason_none
    };
    for (auto reason : reasons) {
        std::cout << "Encoding the reason value " << static_cast<int>(reason) << std::endl;
        EXPECT_NO_THROW({
            dmSta.encode(obj, reason);
        });
    }
    cJSON_Delete(obj);
    std::cout << "Exiting EncodeWithValidCJsonObjectAndDifferentReasonValues" << std::endl;
}

/**
* @brief Test the encoding function with a null JSON object and default reason.
*
* This test checks the behavior of the `encode` method when provided with a null JSON object and the default reason. It ensures that the method handles null input gracefully without crashing or producing unexpected results.@n
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
* | 01| Call encode with null JSON object and default reason | jsonObject = nullptr, reason = em_get_sta_list_reason_none | Exception should be thrown.| Should Fail |
*/
TEST(dm_sta_t_Test, EncodeWithNullCJsonObjectAndDefaultReason) {
    std::cout << "Entering EncodeWithNullCJsonObjectAndDefaultReason" << std::endl;
    dm_sta_t dmSta;
    EXPECT_ANY_THROW({
        dmSta.encode(nullptr, em_get_sta_list_reason_none);
    });
    std::cout << "Exiting EncodeWithNullCJsonObjectAndDefaultReason" << std::endl;
}

/**
* @brief Test the encoding function with an invalid cJSON object and reason steer.
*
* This test checks the behavior of the encode function when provided with a corrupted cJSON object and a specific reason code for steering. The objective is to ensure that the function handles invalid input gracefully and does not cause unexpected behavior or crashes.
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Initialize dm_sta_t object and corrupted cJSON object | dmSta, obj->type = -1 | Object initialized successfully | Should be successful |
* | 02| Call encode function with corrupted cJSON object and reason steer | dmSta.encode(&obj, em_get_sta_list_reason_steer) | Exception should be thrown. | Should Fail |
*/
TEST(dm_sta_t_Test, EncodeWithInvalidCJsonObjectAndReasonSteer) {
    std::cout << "Entering EncodeWithInvalidCJsonObjectAndReasonSteer" << std::endl;
    dm_sta_t dmSta;
    cJSON* obj = cJSON_CreateObject();
    obj->type = -1;
    EXPECT_ANY_THROW({
        dmSta.encode(obj, em_get_sta_list_reason_steer);
    });
    cJSON_Delete(obj);
    std::cout << "Exiting EncodeWithInvalidCJsonObjectAndReasonSteer" << std::endl;
}

/**
* @brief Test the encoding of a beacon report with a valid cJSON object.
*
* This test verifies that the `encode_beacon_report` method of the `dm_sta_t` class correctly encodes a beacon report into a valid cJSON object. The test ensures that the cJSON object is not null after encoding, indicating successful encoding.
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
* | 01 | Create a cJSON object | obj = cJSON_CreateObject() | obj should not be null | Should be successful |
* | 02 | Encode beacon report using the cJSON object | dmSta.encode_beacon_report(obj) | No exception should be thrown. | Should Pass |
*/
TEST(dm_sta_t_Test, EncodeBeaconReportWithValidCJsonObject) {
    std::cout << "Entering EncodeBeaconReportWithValidCJsonObject test" << std::endl;
    cJSON* obj = cJSON_CreateObject();
    dm_sta_t dmSta;
    EXPECT_NO_THROW({
        dmSta.encode_beacon_report(obj);
    });
    cJSON_Delete(obj);
    std::cout << "Exiting EncodeBeaconReportWithValidCJsonObject test" << std::endl;
}

/**
* @brief Test the encoding of a beacon report with a cJSON string
*
* This test verifies that the encode_beacon_report function correctly processes a cJSON string input and ensures that the object is not null after encoding.@n
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
* | 01 | Create cJSON string object | obj = cJSON_CreateString("test_string") | obj should be created successfully | Should be successful |
* | 02 | Instantiate dm_sta_t object | dmSta = dm_sta_t() | dmSta should be instantiated successfully | Should be successful |
* | 03 | Encode beacon report with cJSON string | dmSta.encode_beacon_report(obj) | Exception should be thrown. | Should Fail |
*/
TEST(dm_sta_t_Test, EncodeBeaconReportWithCJsonString) {
    std::cout << "Entering EncodeBeaconReportWithCJsonString test";
    cJSON *obj = cJSON_CreateString("test_string");
    dm_sta_t dmSta;
    EXPECT_ANY_THROW({
        dmSta.encode_beacon_report(obj);
    });
    cJSON_Delete(obj);
    std::cout << "Exiting EncodeBeaconReportWithCJsonString test";
}

/**
* @brief Test the encoding of a beacon report with a cJSON null object
*
* This test verifies the behavior of the encode_beacon_report function when provided with a cJSON null object. The objective is to ensure that the function handles null inputs gracefully and does not crash or produce invalid results.@n
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
* | 01| Create a cJSON null object | obj = cJSON_CreateNull() | obj should be a valid cJSON null object | Should be successful |
* | 02| Instantiate dm_sta_t object | dmSta = dm_sta_t() | dmSta should be a valid instance of dm_sta_t | Should be successful |
* | 03| Call encode_beacon_report with cJSON null object | dmSta.encode_beacon_report(obj) | Exception should be thrown. | Should Fail |
*/
TEST(dm_sta_t_Test, EncodeBeaconReportWithCJsonNull) {
    std::cout << "Entering EncodeBeaconReportWithCJsonNull test";
    cJSON *obj = cJSON_CreateNull();
    dm_sta_t dmSta;
    EXPECT_ANY_THROW({
        dmSta.encode_beacon_report(obj);
    });
    cJSON_Delete(obj);
    std::cout << "Exiting EncodeBeaconReportWithCJsonNull test";
}

/**
* @brief Test to verify the retrieval of station information after initialization
*
* This test checks the default values of the station information structure after the station object is initialized. It ensures that all fields are set to their expected default values, which is crucial for validating the initial state of the station object.
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
* | 01 | Initialize station object with valid values | assosciated=false, last_ul_rate=5, last_dl_rate=1, signal_strength=6, num_beaco_meas_report=9 | None | Should be successful |
* | 02 | Retrieve station info | em_sta_info_t *info = sta.get_sta_info() | info = nullptr | Should be successful |
* | 03 | Check if info is not null | ASSERT_NE(info, nullptr) | info != nullptr | Should Pass |
* | 04 | Check if the initialized value is retrieved | assosciated=false, last_ul_rate=5, last_dl_rate=1, signal_strength=6, num_beaco_meas_report=9 | Values should match | Should Pass |
*/
TEST(dm_sta_t_Test, RetrieveStationInfoAfterInitialization) {
    std::cout << "Entering RetrieveStationInfoAfterInitialization" << std::endl;
    em_sta_info_t *obj = new em_sta_info_t{};
    obj->associated = false;
    obj->last_ul_rate = 5;
    obj->last_dl_rate = 1;
    obj->signal_strength = 6;
    obj->num_beacon_meas_report = 9;
    dm_sta_t sta(obj);
    em_sta_info_t *info = sta.get_sta_info();
    ASSERT_NE(info, nullptr);
    EXPECT_EQ(info->associated, false);
    EXPECT_EQ(info->last_ul_rate, 5);
    EXPECT_EQ(info->last_dl_rate, 1);
    EXPECT_EQ(info->signal_strength, 6);
    EXPECT_EQ(info->num_beacon_meas_report, 9);
    delete obj;
    std::cout << "Exiting RetrieveStationInfoAfterInitialization" << std::endl;
}

/**
* @brief Test to check if the returned pointer is not null
*
* This test verifies that the function `get_sta_info` of the `dm_sta_t` class returns a non-null pointer. This is important to ensure that the function is correctly allocating or returning a valid pointer to `em_sta_info_t` structure.
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
* | 01 | Create an instance of `dm_sta_t` with invalid MAC | None | None | Should be successful |
* | 02 | Call `get_sta_info` method | None | Pointer returned should not be null | Should Pass |
* | 03 | Check if the returned pointer is not null and MAC address should match | info != nullptr | Assertion should pass | Should Pass |
*/
TEST(dm_sta_t_Test, CheckReturnedPointerNotNull) {
    std::cout << "Entering CheckReturnedPointerNotNull" << std::endl;
    em_sta_info_t *obj = new em_sta_info_t();
    uint8_t id[6] = {0xAA, 0xCC, 0xBB, 0x00, 0x00, 0x00};
    memcpy(obj->id, id, sizeof(id));
    dm_sta_t sta(obj);
    em_sta_info_t *info = sta.get_sta_info();
    ASSERT_NE(info, nullptr);
    for (int i = 0; i < 6; ++i) {
        EXPECT_EQ(info->id[i], id[i]);
    }
    delete obj;
    std::cout << "Exiting CheckReturnedPointerNotNull" << std::endl;
}

/**
* @brief Test to verify the successful initialization of STA information structure
*
* This test checks if the STA information structure is initialized correctly by invoking the init method of dm_sta_t class. The test ensures that the initialization returns a success code and the structure is set to its expected default state.
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
* | 01| Create an instance of dm_sta_t and call init method | obj.init() | result = 0 | Should Pass |
*/
TEST(dm_sta_t_Test, Initialize_STA_Information_Structure_Successfully) {
    std::cout << "Entering Initialize_STA_Information_Structure_Successfully test";
    dm_sta_t obj;
    int result = obj.init();
    EXPECT_EQ(result, 0);
    std::cout << "Exiting Initialize_STA_Information_Structure_Successfully test";
}

/**
* @brief Test the assignment operator of dm_sta_t class with maximum and minimum values.
*
* This test verifies that the assignment operator correctly assigns the values from one object to another, 
* even when the values are at their maximum and minimum limits. This ensures that the assignment operator 
* handles edge cases properly.
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
* | 01 | Create obj1 and set max/min values | obj1.m_sta_info.associated = true, obj1.m_sta_info.last_ul_rate = UINT_MAX, obj1.m_sta_info.last_dl_rate = 0, obj1.m_sta_info.signal_strength = INT_MAX, obj1.m_sta_info.rcpi = UCHAR_MAX, obj1.m_sta_info.util_tx = UINT_MAX, obj1.m_sta_info.util_rx = 0 | Object obj1 should be created with specified values | Should be successful |
* | 02 | Assign obj1 to obj2 | obj2 = obj1 | obj2 should have the same values as obj1 | Should be successful |
* | 03 | Verify obj2.m_sta_info.associated | obj2.m_sta_info.associated | Should be true | Should Pass |
* | 04 | Verify obj2.m_sta_info.last_ul_rate | obj2.m_sta_info.last_ul_rate | Should be UINT_MAX | Should Pass |
* | 05 | Verify obj2.m_sta_info.last_dl_rate | obj2.m_sta_info.last_dl_rate | Should be 0 | Should Pass |
* | 06 | Verify obj2.m_sta_info.signal_strength | obj2.m_sta_info.signal_strength | Should be INT_MAX | Should Pass |
* | 07 | Verify obj2.m_sta_info.rcpi | obj2.m_sta_info.rcpi | Should be UCHAR_MAX | Should Pass |
* | 08 | Verify obj2.m_sta_info.util_tx | obj2.m_sta_info.util_tx | Should be UINT_MAX | Should Pass |
* | 09 | Verify obj2.m_sta_info.util_rx | obj2.m_sta_info.util_rx | Should be 0 | Should Pass |
*/
TEST(dm_sta_t_Test, AssigningObjectWithMaxAndMinValues) {
    std::cout << "Entering AssigningObjectWithMaxAndMinValues" << std::endl;
    dm_sta_t obj1;
    obj1.m_sta_info.associated = true;
    obj1.m_sta_info.last_ul_rate = UINT_MAX;
    obj1.m_sta_info.last_dl_rate = 0;
    obj1.m_sta_info.signal_strength = INT_MAX;
    obj1.m_sta_info.rcpi = UCHAR_MAX;
    obj1.m_sta_info.util_tx = UINT_MAX;
    obj1.m_sta_info.util_rx = 0;
    dm_sta_t obj2;
    obj2 = obj1;
    EXPECT_EQ(obj2.m_sta_info.associated, obj1.m_sta_info.associated);
    EXPECT_EQ(obj2.m_sta_info.last_ul_rate, obj1.m_sta_info.last_ul_rate);
    EXPECT_EQ(obj2.m_sta_info.last_dl_rate, obj1.m_sta_info.last_dl_rate);
    EXPECT_EQ(obj2.m_sta_info.signal_strength, obj1.m_sta_info.signal_strength);
    EXPECT_EQ(obj2.m_sta_info.rcpi, obj1.m_sta_info.rcpi);
    EXPECT_EQ(obj2.m_sta_info.util_tx, obj1.m_sta_info.util_tx);
    EXPECT_EQ(obj2.m_sta_info.util_rx, obj1.m_sta_info.util_rx);
    std::cout << "Exiting AssigningObjectWithMaxAndMinValues" << std::endl;
}

/**
* @brief Test to compare two identical objects of dm_sta_t class
*
* This test verifies the equality operator (==) for the dm_sta_t class by comparing two identical objects. The test ensures that the equality operator correctly identifies that two newly created objects of the same class are equal.
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
* | 01| Create two identical objects of dm_sta_t class | obj1, obj2 | Objects should be created successfully | Should be successful |
* | 02| Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_TRUE should pass | Should Pass |
*/
TEST(dm_sta_t_Test, CompareIdenticalObjects) {
    std::cout << "Entering CompareIdenticalObjects test";
    dm_sta_t obj1 {};
    dm_sta_t obj2 {};
    obj1.m_sta_info.last_ul_rate = 100;
    obj2.m_sta_info.last_ul_rate = 100;
    obj1.m_sta_info.last_dl_rate = 200;
    obj2.m_sta_info.last_dl_rate = 200;
    EXPECT_TRUE(obj1 == obj2);
    std::cout << "Exiting CompareIdenticalObjects test";
}

/**
* @brief Test to compare two different MAC addresses
*
* This test verifies that two instances of `dm_sta_t` with different MAC addresses are not considered equal. This is important to ensure that the equality operator for `dm_sta_t` correctly identifies instances with different MAC addresses as unequal.
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
* | 01 | Initialize obj1 with MAC address 00:11:22:33:44:55 | obj1.m_sta_info.id = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55} | Initialization should be successful | Should be successful |
* | 02 | Initialize obj2 with MAC address 66:77:88:99:AA:BB | obj2.m_sta_info.id = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB} | Initialization should be successful | Should be successful |
* | 03 | Compare obj1 and obj2 for equality | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_sta_t_Test, CompareDifferentMacAddress) {
    std::cout << "Entering CompareDifferentMacAddress test";
    dm_sta_t obj1 {};
    dm_sta_t obj2 {};
    obj1.m_sta_info.id[0] = 0x00;
    obj1.m_sta_info.id[1] = 0x11;
    obj1.m_sta_info.id[2] = 0x22;
    obj1.m_sta_info.id[3] = 0x33;
    obj1.m_sta_info.id[4] = 0x44;
    obj1.m_sta_info.id[5] = 0x55;
    obj2.m_sta_info.id[0] = 0x66;
    obj2.m_sta_info.id[1] = 0x77;
    obj2.m_sta_info.id[2] = 0x88;
    obj2.m_sta_info.id[3] = 0x99;
    obj2.m_sta_info.id[4] = 0xAA;
    obj2.m_sta_info.id[5] = 0xBB;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentMacAddress test";
}

/**
* @brief Test to compare the associated status of two dm_sta_t objects
*
* This test verifies that two dm_sta_t objects with different associated statuses are not considered equal.@n
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
* | 01 | Create two dm_sta_t objects | obj1, obj2 | Objects created successfully | Should be successful |
* | 02 | Set associated status of obj1 to true | obj1.m_sta_info.associated = true | Status set successfully | Should be successful |
* | 03 | Set associated status of obj2 to false | obj2.m_sta_info.associated = false | Status set successfully | Should be successful |
* | 04 | Compare obj1 and obj2 using EXPECT_FALSE | EXPECT_FALSE(obj1 == obj2) | EXPECT_FALSE assertion passes | Should Pass |
*/
TEST(dm_sta_t_Test, CompareDifferentAssociatedStatus) {
    std::cout << "Entering CompareDifferentAssociatedStatus test";
    dm_sta_t obj1 {};
    dm_sta_t obj2 {};
    obj1.m_sta_info.associated = true;
    obj2.m_sta_info.associated = false;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentAssociatedStatus test";
}

/**
* @brief Test to compare two dm_sta_t objects with different last_ul_rate values
*
* This test verifies that two dm_sta_t objects with different last_ul_rate values are not considered equal. This is important to ensure that the equality operator correctly identifies differences in the last_ul_rate attribute.
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
* | 01 | Initialize dm_sta_t objects | obj1.m_sta_info.last_ul_rate = 100, obj2.m_sta_info.last_ul_rate = 200 | Objects initialized | Should be successful |
* | 02 | Compare objects with different last_ul_rate | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_sta_t_Test, CompareDifferentLastUlRate) {
    std::cout << "Entering CompareDifferentLastUlRate test";
    dm_sta_t obj1 {};
    dm_sta_t obj2 {};
    obj1.m_sta_info.last_ul_rate = 100;
    obj2.m_sta_info.last_ul_rate = 200;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentLastUlRate test";
}

/**
* @brief Test to compare two dm_sta_t objects with different last_dl_rate values
*
* This test verifies that two dm_sta_t objects with different last_dl_rate values are not considered equal. This is important to ensure that the equality operator correctly identifies differences in the last_dl_rate attribute.
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
* | 01 | Initialize obj1 with last_dl_rate = 100 | obj1.m_sta_info.last_dl_rate = 100 |  | Should be successful |
* | 02 | Initialize obj2 with last_dl_rate = 200 | obj2.m_sta_info.last_dl_rate = 200 |  | Should be successful |
* | 03 | Compare obj1 and obj2 using equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_sta_t_Test, CompareDifferentLastDlRate) {
    std::cout << "Entering CompareDifferentLastDlRate test";
    dm_sta_t obj1 {};
    dm_sta_t obj2 {};
    obj1.m_sta_info.last_dl_rate = 100;
    obj2.m_sta_info.last_dl_rate = 200;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentLastDlRate test";
}

/**
* @brief Test to compare signal strength of two different dm_sta_t objects
*
* This test verifies that two dm_sta_t objects with different signal strengths are not considered equal.@n
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
* | 01 | Create two dm_sta_t objects with different signal strengths | obj1.m_sta_info.signal_strength = -50, obj2.m_sta_info.signal_strength = -60 | Objects should not be equal | Should Pass |
* | 02 | Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_sta_t_Test, CompareDifferentSignalStrength) {
    std::cout << "Entering CompareDifferentSignalStrength test";
    dm_sta_t obj1 {};
    dm_sta_t obj2 {};
    obj1.m_sta_info.signal_strength = -50;
    obj2.m_sta_info.signal_strength = -60;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentSignalStrength test";
}

/**
* @brief Test to compare two dm_sta_t objects with different RCPI values
*
* This test verifies that two dm_sta_t objects with different RCPI values are not considered equal. This is important to ensure that the equality operator for dm_sta_t objects correctly identifies objects with different RCPI values as unequal.
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
* | 01 | Create two dm_sta_t objects with different RCPI values | obj1.m_sta_info.rcpi = 50, obj2.m_sta_info.rcpi = 60 | Objects should not be equal | Should Pass |
* | 02 | Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_sta_t_Test, CompareDifferentRcpi) {
    std::cout << "Entering CompareDifferentRcpi test";
    dm_sta_t obj1 {};
    dm_sta_t obj2 {};
    obj1.m_sta_info.rcpi = 50;
    obj2.m_sta_info.rcpi = 60;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentRcpi test";
}

/**
* @brief Test to compare two dm_sta_t objects with different multi_band_cap values
*
* This test verifies that two dm_sta_t objects with different multi_band_cap values are not considered equal.@n
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
* | 01| Create two dm_sta_t objects with different multi_band_cap values | obj1.m_sta_info.multi_band_cap = true, obj2.m_sta_info.multi_band_cap = false | Objects should not be equal | Should Pass |
* | 02| Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_sta_t_Test, CompareDifferentMultiBandCap) {
    std::cout << "Entering CompareDifferentMultiBandCap test";
    dm_sta_t obj1 {};
    dm_sta_t obj2 {};
    obj1.m_sta_info.multi_band_cap = true;
    obj2.m_sta_info.multi_band_cap = false;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentMultiBandCap test";
}

/**
* @brief Test to compare two dm_sta_t objects with different num_vendor_infos
*
* This test verifies that two dm_sta_t objects with different num_vendor_infos are not considered equal.@n
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
* | 01 | Create two dm_sta_t objects | obj1.num_vendor_infos = 1, obj2.num_vendor_infos = 2 | Objects created successfully | Should be successful |
* | 02 | Set num_vendor_infos for obj1 and obj2 | obj1.num_vendor_infos = 1, obj2.num_vendor_infos = 2 | Values set successfully | Should be successful |
* | 03 | Compare obj1 and obj2 using == operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Fail |
*/
TEST(dm_sta_t_Test, CompareDifferentNumVendorInfos) {
    std::cout << "Entering CompareDifferentNumVendorInfos test";
    dm_sta_t obj1 {};
    dm_sta_t obj2 {};
    obj1.m_sta_info.num_vendor_infos = 1;
    obj2.m_sta_info.num_vendor_infos = 2;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentNumVendorInfos test";
}

/**
* @brief Test to compare two dm_sta_t objects with different SSIDs
*
* This test verifies that two dm_sta_t objects with different SSIDs are not considered equal. This is important to ensure that the equality operator for dm_sta_t correctly distinguishes between objects with different SSIDs.
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
* | 01 | Create two dm_sta_t objects | obj1, obj2 | Objects created successfully | Should be successful |
* | 02 | Set SSID of obj1 to "SSID1" | obj1.m_sta_info.ssid = "SSID1" | SSID set successfully | Should be successful |
* | 03 | Set SSID of obj2 to "SSID2" | obj2.m_sta_info.ssid = "SSID2" | SSID set successfully | Should be successful |
* | 04 | Compare obj1 and obj2 using equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_sta_t_Test, CompareDifferentSsid) {
    std::cout << "Entering CompareDifferentSsid test";
    dm_sta_t obj1 {};
    dm_sta_t obj2 {};
    strcpy(obj1.m_sta_info.ssid, "SSID1");
    strcpy(obj2.m_sta_info.ssid, "SSID2");
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentSsid test";
}

/**
* @brief Test to validate the parsing of correctly formatted MAC addresses from a given key
*
* This test verifies that the function `parse_sta_bss_radio_from_key` correctly parses and extracts
* the STA, BSSID, and Radio MAC addresses from a given key string that is correctly formatted.@n
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
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Enter the function | None | None | Should be successful |
* | 02 | Define the key and MAC address variables | key = "01:23:45:67:89:ab@12:34:56:78:9a:bc@23:45:67:89:ab:cd", sta, bssid, radio | None | Should be successful |
* | 03 | Call parse_sta_bss_radio_from_key | key = "01:23:45:67:89:ab@12:34:56:78:9a:bc@23:45:67:89:ab:cd", sta, bssid, radio | None | Should Pass |
* | 04 | Check STA MAC address | sta = "01:23:45:67:89:ab" | Expected: "01:23:45:67:89:ab" | Should Pass |
* | 05 | Check BSSID MAC address | bssid = "12:34:56:78:9a:bc" | Expected: "12:34:56:78:9a:bc" | Should Pass |
* | 06 | Check Radio MAC address | radio = "23:45:67:89:ab:cd" | Expected: "23:45:67:89:ab:cd" | Should Pass |
*/
TEST(dm_sta_t_Test, ValidKeyWithCorrectlyFormattedMACAddresses) {
    std::cout << "Entering ValidKeyWithCorrectlyFormattedMACAddresses" << std::endl;
    // Use '@' delimiters to match implementation
    const char *key = "01:23:45:67:89:ab@12:34:56:78:9a:bc@23:45:67:89:ab:cd";
    mac_address_t sta, bssid, radio;
    dm_sta_t::parse_sta_bss_radio_from_key(key, sta, bssid, radio);
    const unsigned char expected_sta[6]   = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab};
    const unsigned char expected_bssid[6] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc};
    const unsigned char expected_radio[6] = {0x23, 0x45, 0x67, 0x89, 0xab, 0xcd};
    for (int i = 0; i < 6; ++i) {
        EXPECT_EQ(sta[i], expected_sta[i]) << "STA MAC mismatch at byte " << i;
        EXPECT_EQ(bssid[i], expected_bssid[i]) << "BSSID MAC mismatch at byte " << i;
        EXPECT_EQ(radio[i], expected_radio[i]) << "Radio MAC mismatch at byte " << i;
    }
    std::cout << "Exiting ValidKeyWithCorrectlyFormattedMACAddresses" << std::endl;
}

/**
* @brief Test the parsing of a key with missing MAC addresses
*
* This test checks the behavior of the parse_sta_bss_radio_from_key function when provided with a key that has missing MAC addresses. It ensures that the function correctly identifies and parses the available MAC addresses while handling the missing ones appropriately.
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
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Call parse_sta_bss_radio_from_key with a key having missing MAC addresses | key = "01:23:45:67:89:ab@@23:45:67:89:ab:cd", sta, bssid, radio | sta = "01:23:45:67:89:ab", bssid = "", radio = "23:45:67:89:ab:cd" | Should Pass |
*/
TEST(dm_sta_t_Test, KeyWithMissingMACAddresses) {
    std::cout << "Entering KeyWithMissingMACAddresses" << std::endl;
    // Use '@' as delimiter
    const char *key = "01:23:45:67:89:ab@@23:45:67:89:ab:cd";
    mac_address_t sta, bssid, radio;
    dm_sta_t::parse_sta_bss_radio_from_key(key, sta, bssid, radio);
    const unsigned char expected_sta[6]   = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab};
    const unsigned char expected_bssid[6] = {0, 0, 0, 0, 0, 0};  // all zeros for missing MAC
    const unsigned char expected_radio[6] = {0x23, 0x45, 0x67, 0x89, 0xab, 0xcd};
    for (int i = 0; i < 6; ++i) {
        EXPECT_EQ(sta[i], expected_sta[i]) << "STA MAC mismatch at byte " << i;
        EXPECT_EQ(bssid[i], expected_bssid[i]) << "BSSID MAC mismatch at byte " << i;
        EXPECT_EQ(radio[i], expected_radio[i]) << "Radio MAC mismatch at byte " << i;
    }
    std::cout << "Exiting KeyWithMissingMACAddresses" << std::endl;
}

/**
* @brief Test to verify the parsing of a key with extra delimiters
*
* This test checks the functionality of the parse_sta_bss_radio_from_key function to ensure it correctly parses a key string with extra delimiters into the respective MAC addresses for sta, bssid, and radio.
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
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Define the key with extra delimiters | key = "01:23:45:67:89:ab@12:34:56:78:9a:bc@23:45:67:89:ab:cd@" | None | Should be successful |
* | 02 | Call parse_sta_bss_radio_from_key function | key = "01:23:45:67:89:ab@12:34:56:78:9a:bc@23:45:67:89:ab:cd@", sta, bssid, radio | None | Should Pass |
* | 03 | Check if sta is parsed correctly | sta = "01:23:45:67:89:ab" | EXPECT_STREQ(sta, "01:23:45:67:89:ab") | Should Pass |
* | 04 | Check if bssid is parsed correctly | bssid = "12:34:56:78:9a:bc" | EXPECT_STREQ(bssid, "12:34:56:78:9a:bc") | Should Pass |
* | 05 | Check if radio is parsed correctly | radio = "23:45:67:89:ab:cd" | EXPECT_STREQ(radio, "23:45:67:89:ab:cd") | Should Pass |
*/

TEST(dm_sta_t_Test, KeyWithExtraDelimiters) {
    std::cout << "Entering KeyWithExtraDelimiters" << std::endl;
    const char *key = "01:23:45:67:89:ab@12:34:56:78:9a:bc@23:45:67:89:ab:cd@";
    mac_address_t sta, bssid, radio;
    dm_sta_t::parse_sta_bss_radio_from_key(key, sta, bssid, radio);
    const unsigned char expected_sta[6]   = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab};
    const unsigned char expected_bssid[6] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc};
    const unsigned char expected_radio[6] = {0x23, 0x45, 0x67, 0x89, 0xab, 0xcd};
    for (int i = 0; i < 6; ++i) {
        EXPECT_EQ(sta[i], expected_sta[i]) << "STA MAC mismatch at byte " << i;
        EXPECT_EQ(bssid[i], expected_bssid[i]) << "BSSID MAC mismatch at byte " << i;
        EXPECT_EQ(radio[i], expected_radio[i]) << "Radio MAC mismatch at byte " << i;
    }
    std::cout << "Exiting KeyWithExtraDelimiters" << std::endl;
}

/**
* @brief Test to verify the behavior of parse_sta_bss_radio_from_key when the key is NULL.
*
* This test checks the behavior of the parse_sta_bss_radio_from_key function when it is provided with a NULL key. 
* It ensures that the function handles the NULL input gracefully and sets the output parameters to empty strings.
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
* | 01 | Call parse_sta_bss_radio_from_key with NULL key | key = NULL, sta = "", bssid = "", radio = "" | sta = "", bssid = "", radio = "" | Should Pass |
*/
TEST(dm_sta_t_Test, NullKey) {
    std::cout << "Entering NullKey" << std::endl;
    const char *key = nullptr;
    mac_address_t sta{}, bssid{}, radio{};
    dm_sta_t::parse_sta_bss_radio_from_key(key, sta, bssid, radio);
    for (int i = 0; i < 6; ++i) {
        EXPECT_EQ(sta[i], 0) << "STA MAC should be zero at byte " << i;
        EXPECT_EQ(bssid[i], 0) << "BSSID MAC should be zero at byte " << i;
        EXPECT_EQ(radio[i], 0) << "Radio MAC should be zero at byte " << i;
    }
    std::cout << "Exiting NullKey" << std::endl;
}

/**
 * @brief Verify that dm_sta_t default constructor creates a valid object without throwing exceptions.
 *
 * This test verifies that when invoking the default constructor of dm_sta_t, the constructor does not throw any exceptions
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 045@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
[I * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                           | Test Data                                             | Expected Result                                                                                        | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------- | ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------ | ----------- |
 * | 01               | Invoke dm_sta_t default constructor and verify that no exception is thrown; validate object creation | dm_sta_t instance created using default constructor   | Instance is created successfully without throwing exceptions and internal state is appropriately initialized | Should Pass |
 */
TEST(dm_sta_t_Test, DefaultConstructorCreatesValidObject) {
    std::cout << "Entering DefaultConstructorCreatesValidObject test" << std::endl;
    std::cout << "About to invoke dm_sta_t default constructor" << std::endl;
    EXPECT_NO_THROW({
        dm_sta_t instance;
        std::cout << "dm_sta_t default constructor invoked successfully" << std::endl;
        std::cout << "Internal state: m_sta_info structure instance has been created" << std::endl;
    });
    std::cout << "Exiting DefaultConstructorCreatesValidObject test" << std::endl;
}

/**
 * @brief Verify that dm_sta_t destructor is called without throwing exceptions when the object goes out of scope.
 *
 * This test validates that an instance of dm_sta_t, when constructed using the default constructor, is properly destroyed without throwing any exceptions upon scope exit. The test ensures that the destructor invocation does not lead to any runtime errors.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 046@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                    | Test Data                                       | Expected Result                                     | Notes         |
 * | :---------------:| ---------------------------------------------------------------| ------------------------------------------------| ----------------------------------------------------| --------------|
 * | 01               | Invoke the default constructor of dm_sta_t                     | constructor = default                           | dm_sta_t object is created successfully             | Should Pass   |
 * | 02               | Allow the object to go out of scope to trigger the destructor    | object goes out of scope                        | Destructor is executed without throwing exceptions  | Should Pass   |
 */
TEST(dm_sta_t_Test, dm_sta_t_destructor_default_constructor) {
    std::cout << "Entering dm_sta_t::~dm_sta_t()_start test" << std::endl;
    // Using lambda to create a scope for the dm_sta_t object to ensure destructor execution.
    EXPECT_NO_THROW({
        std::cout << "Invoking default constructor of dm_sta_t" << std::endl;
        {
            dm_sta_t obj;
            std::cout << "dm_sta_t object created successfully using default constructor" << std::endl;
        }
        std::cout << "dm_sta_t object has gone out of scope and destructor should be invoked" << std::endl;
    });
    std::cout << "Exiting dm_sta_t::~dm_sta_t()_end test" << std::endl;
}
