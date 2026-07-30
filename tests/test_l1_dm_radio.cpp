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
#include "dm_radio.h"


/**
* @brief Test to validate the decoding of a JSON object with a valid parent ID
*
* This test checks the functionality of the `decode` method in the `dm_radio_t` class. It ensures that the method correctly decodes a valid JSON object when provided with a valid parent ID.@n
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
* | 01| Create a valid JSON object and a valid parent ID | obj = valid JSON object, parent_id = valid pointer | JSON object should be decoded successfully | Should Pass |
* | 02| Call the decode method with the JSON object and parent ID | radio.decode(obj, parent_id) | Result should be 0 | Should Pass |
* | 03| Verify the result using EXPECT_EQ | result = 0 | Assertion should pass | Should be successful |
*/
TEST(dm_radio_t_Test, ValidJsonObjectWithValidParentID) {
    std::cout << "Entering ValidJsonObjectWithValidParentID" << std::endl;
    cJSON* obj = cJSON_CreateObject();
    char parent_id_str[] = "device1@11:22:33:44:55:66@aa:bb:cc:dd:ee:ff";
    void* parent_id = static_cast<void*>(parent_id_str);
    dm_radio_t radio;
    int result = radio.decode(obj, parent_id);
    EXPECT_EQ(result, 0);
    cJSON_Delete(obj);
    std::cout << "Exiting ValidJsonObjectWithValidParentID" << std::endl;
}

/**
* @brief Test to verify the behavior of the decode function when a null JSON object is passed.
*
* This test checks the decode function of the dm_radio_t class to ensure it correctly handles a null JSON object input. The expected behavior is that the function should return an error code (-1) when provided with a null JSON object, indicating that the input is invalid.
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
* | 01| Assign value for parent_id | const char *parent_id_str = "device1@11:22:33:44:55:66@aa:bb:cc:dd:ee:ff"| Should be successful |
* | 02| Create an instance of dm_radio_t | dm_radio_t radio | Instance should be created successfully | Should be successful |
* | 03| Call decode with null JSON object | json_object = nullptr, parent_id = parent_id | result = -1 | Should Pass |
* | 04| Verify the result of decode | result = -1 | result == -1 | Should Pass |
*/
TEST(dm_radio_t_Test, NullJsonObject) {
    std::cout << "Entering NullJsonObject" << std::endl;
    char parent_id_str[] = "device1@11:22:33:44:55:66@aa:bb:cc:dd:ee:ff";
    void* parent_id = static_cast<void*>(parent_id_str);
    dm_radio_t radio;
    int result = radio.decode(nullptr, parent_id);
    EXPECT_EQ(result, -1);
    std::cout << "Exiting NullJsonObject" << std::endl;
}

/**
* @brief Test to verify the behavior of the decode function when a null parent ID is provided.
*
* This test checks the decode function of the dm_radio_t class to ensure it correctly handles a null parent ID by returning an error code.@n
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
* | 01| Create a dm_radio_t instance and call decode with a null parent ID | obj = cJSON object, parentID = nullptr | result = -1, EXPECT_EQ(result, -1) | Should Fail |
*/
TEST(dm_radio_t_Test, NullParentID) {
    std::cout << "Entering NullParentID" << std::endl;
    cJSON* obj = cJSON_CreateObject();
    dm_radio_t radio;
    int result = radio.decode(obj, nullptr);
    EXPECT_EQ(result, -1);
    cJSON_Delete(obj);
    std::cout << "Exiting NullParentID" << std::endl;
}

/**
* @brief Test to validate the behavior of the decode function when provided with a JSON object of invalid type.
*
* This test checks the decode function of the dm_radio_t class to ensure it correctly handles a JSON object with an invalid type. The objective is to verify that the function returns an error code when the JSON object type is not recognized.
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
* | 01 | Create a JSON object with an invalid type | obj->type = -1 | Should be successful | |
* | 02 | Assign value for parent_id | const char *parent_id_str = "device1@11:22:33:44:55:66@aa:bb:cc:dd:ee:ff"| Should be successful | |
* | 03 | Call the decode function with invalid JSON object | radio.decode(obj, parent_id) | result = -1, EXPECT_EQ(result, -1) | Should Pass |
*/
TEST(dm_radio_t_Test, JsonObjectWithInvalidType) {
    std::cout << "Entering JsonObjectWithInvalidType" << std::endl;
    cJSON* obj = cJSON_CreateObject();
    obj->type = -1;
    char parent_id_str[] = "device1@11:22:33:44:55:66@aa:bb:cc:dd:ee:ff";
    void* parent_id = static_cast<void*>(parent_id_str);
    dm_radio_t radio;
    int result = radio.decode(obj, parent_id);
    EXPECT_EQ(result, -1);
    cJSON_Delete(obj);
    std::cout << "Exiting JsonObjectWithInvalidType" << std::endl;
}

/**
* @brief Test the decoding of a JSON object with nested objects
*
* This test verifies the functionality of the `decode` method in the `dm_radio_t` class when provided with a JSON object that contains nested objects. The objective is to ensure that the method correctly processes nested JSON structures and returns the expected result.
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
* | 01| Create a JSON object with a nested child object | cJSON* config = cJSON_CreateObject();| N/A | Should be successful |
* | 02| Assign value for parent_id |  const char* parent_id_str = "net@11:22:33:44:55:66@aa:bb:cc:dd:ee:ff" | N/A | Should be successful |
* | 03| Invoke the decode method with the JSON object and parent_id | radio.decode(root, parent_id) | result = 0, EXPECT_EQ(result, 0) | Should Pass |
* | 04| Free the allocated memory for JSON | cJSON_Delete(root); | N/A | Should be successful |
*/
TEST(dm_radio_t_Test, JsonObjectWithNestedObjects) {
    std::cout << "Entering JsonObjectWithNestedObjects" << std::endl;
    // Create root object
    cJSON* root = cJSON_CreateObject();
    // Add "ID" key with string value
    cJSON_AddStringToObject(root, "ID", "00:11:22:33:44:55");
    // Create nested object "Config"
    cJSON* config = cJSON_CreateObject();
    cJSON_AddNumberToObject(config, "Noise", -90);
    cJSON_AddBoolToObject(config, "Enabled", true);
    // Add "Config" object to root
    cJSON_AddItemToObject(root, "Config", config);
    // Create parent_id string
    char parent_id_str[] = "device1@11:22:33:44:55:66@aa:bb:cc:dd:ee:ff";
    void* parent_id = static_cast<void*>(parent_id_str);
    dm_radio_t radio;
    int result = radio.decode(root, parent_id);
    EXPECT_EQ(result, 0);
    cJSON_Delete(root);
    std::cout << "Exiting JsonObjectWithNestedObjects" << std::endl;
}

/**
* @brief Test to verify the decoding of a JSON object containing an array
*
* This test checks the functionality of the `decode` method in the `dm_radio_t` class when provided with a JSON object that contains an array. The objective is to ensure that the method correctly processes the input and returns the expected result.
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
* | 01 | Initialize JSON object and array | cJSON* array = cJSON_CreateArray()| N/A | Should be successful |
* | 02 | Assign value for parent_id | const char* parent_id_str = "net@11:22:33:44:55:66@aa:bb:cc:dd:ee:ff" | N/A | Should be successful |
* | 03 | Invoke decode method | radio.decode(obj, parent_id) | result = 0, Assertion: EXPECT_EQ(result, 0) | Should Pass |
* | 04 | Free allocated memory | cJSON_Delete(obj); | N/A | Should be successful |
*/
TEST(dm_radio_t_Test, JsonObjectWithArray) {
    std::cout << "Entering JsonObjectWithArray" << std::endl;
    // Create a JSON object
    cJSON* obj = cJSON_CreateObject();
    // Create an array and add it as a child of obj
    cJSON* array = cJSON_CreateArray();
    cJSON_AddItemToObject(obj, "array_key", array);
    char parent_id_str[] = "net@11:22:33:44:55:66@aa:bb:cc:dd:ee:ff";
    void* parent_id = static_cast<void*>(parent_id_str);
    dm_radio_t radio;
    int result = radio.decode(obj, parent_id);
    EXPECT_EQ(result, 0);
    cJSON_Delete(obj);  // Frees the whole JSON tree
    std::cout << "Exiting JsonObjectWithArray" << std::endl;
}

/**
* @brief Test to verify the behavior of the decode function when provided with an empty JSON object.
*
* This test checks the decode function of the dm_radio_t class to ensure it correctly handles an empty JSON object by returning an error code (-1). This is important to verify that the function can handle edge cases gracefully.
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
* | 01| Initialize an empty JSON object | cJSON* obj = cJSON_CreateObject() | No child elements in JSON object | Should be successful |
* | 02| Allocate memory for parent_id | parent_id = malloc(sizeof(int)) | parent_id allocated | Should be successful |
* | 03| Invoke decode function with empty JSON object | radio.decode(obj, parent_id) | obj = empty, parent_id = valid pointer | result = -1, EXPECT_EQ(result, -1) | Should Pass |
* | 04| Free allocated memory for parent_id and json obj| free(parent_id), cJSON_Delete(obj) | parent_id memory freed | Should be successful |
*/
TEST(dm_radio_t_Test, JsonObjectWithEmptyObject) {
    std::cout << "Entering JsonObjectWithEmptyObject" << std::endl;
    cJSON* obj = cJSON_CreateObject();
    void* parent_id = malloc(sizeof(int));
    dm_radio_t radio;
    int result = radio.decode(obj, parent_id);
    EXPECT_EQ(result, -1);
    free(parent_id);
    cJSON_Delete(obj);
    std::cout << "Exiting JsonObjectWithEmptyObject" << std::endl;
}

/**
* @brief Test the copy constructor of dm_radio_t with a fully initialized object.
*
* This test verifies that the copy constructor of the `dm_radio_t` class correctly performs a deep copy 
* of all relevant fields from a fully initialized source object to a new instance.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 008@n
* **Priority:** High@n
*
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
*
* @n
* **Test Procedure:**@n
* | Step | Description | Test Data | Expected Result | Notes |
* | :--: | ----------- | --------- | ---------------- | ----- |
* | 01   | Create and fully initialize a `dm_radio_t` object with sample values | `radio.m_radio_info` fields set to non-default values | Object is initialized successfully | Baseline for copy |
* | 02   | Use the copy constructor to create a new `dm_radio_t` object | `dm_radio_t copied_radio(radio);` | New object created as a deep copy | Should Pass |
* | 03   | Validate that the `enabled` field matches between the original and copy | `EXPECT_EQ(copied_radio.m_radio_info.enabled, radio.m_radio_info.enabled)` | Values match | Should Pass |
* | 04   | Validate that the `band` field matches | `EXPECT_EQ(copied_radio.m_radio_info.band, radio.m_radio_info.band)` | Values match | Should Pass |
* | 05   | Validate that a few representative array values (e.g., srg_bss_color_bitmap[0]) match | `EXPECT_EQ(copied_radio.m_radio_info.srg_bss_color_bitmap[0], radio.m_radio_info.srg_bss_color_bitmap[0])` | Deep copy confirmed | Should Pass |
*/
TEST(dm_radio_t_Test, CopyConstructorWithFullyInitializedObject) {
    std::cout << "Entering CopyConstructorWithFullyInitializedObject" << std::endl;
    dm_radio_t radio;
    // Properly initialize em_radio_id_t
    strncpy(radio.m_radio_info.id.net_id, "TestNetID", sizeof(radio.m_radio_info.id.net_id));
    memset(radio.m_radio_info.id.dev_mac, 0x01, sizeof(radio.m_radio_info.id.dev_mac));
    memset(radio.m_radio_info.id.ruid, 0x02, sizeof(radio.m_radio_info.id.ruid));
    // Initialize other fields
    radio.m_radio_info.enabled = true;
    radio.m_radio_info.number_of_bss = 3;
    radio.m_radio_info.noise = -90;
    radio.m_radio_info.utilization = 55;
    radio.m_radio_info.traffic_sep_combined_fronthaul = true;
    radio.m_radio_info.channel_util_threshold = 80;
    radio.m_radio_info.srg_bss_color_bitmap[0] = 0xAA;
    // Copy using copy constructor
    dm_radio_t copied_radio(radio);
    // Assertions for em_radio_id_t fields
    EXPECT_STREQ(copied_radio.m_radio_info.id.net_id, radio.m_radio_info.id.net_id);
    EXPECT_TRUE(memcmp(copied_radio.m_radio_info.id.dev_mac, radio.m_radio_info.id.dev_mac, sizeof(radio.m_radio_info.id.dev_mac)) == 0);
    EXPECT_TRUE(memcmp(copied_radio.m_radio_info.id.ruid, radio.m_radio_info.id.ruid, sizeof(radio.m_radio_info.id.ruid)) == 0);
    // Assertions for other fields
    EXPECT_EQ(copied_radio.m_radio_info.enabled, radio.m_radio_info.enabled);
    EXPECT_EQ(copied_radio.m_radio_info.number_of_bss, radio.m_radio_info.number_of_bss);
    EXPECT_EQ(copied_radio.m_radio_info.noise, radio.m_radio_info.noise);
    EXPECT_EQ(copied_radio.m_radio_info.utilization, radio.m_radio_info.utilization);
    EXPECT_EQ(copied_radio.m_radio_info.traffic_sep_combined_fronthaul, radio.m_radio_info.traffic_sep_combined_fronthaul);
    EXPECT_EQ(copied_radio.m_radio_info.channel_util_threshold, radio.m_radio_info.channel_util_threshold);
    EXPECT_EQ(copied_radio.m_radio_info.srg_bss_color_bitmap[0], radio.m_radio_info.srg_bss_color_bitmap[0]);
    std::cout << "Exiting CopyConstructorWithFullyInitializedObject" << std::endl;
}

/**
* @brief Test the copy constructor of dm_radio_t with a null input
*
* This test verifies that the copy constructor of the dm_radio_t class correctly handles a null input by throwing an exception. This is important to ensure that the class does not attempt to dereference a null pointer, which would lead to undefined behavior.@n
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
* | 01| Create a null dm_radio_t pointer | radio = nullptr | None | Should be successful |
* | 02| Attempt to copy construct dm_radio_t with null input | dm_radio_t copied_radio(*radio) | Exception should be thrown | Should Fail. |
*/
TEST(dm_radio_t_Test, CopyConstructorWithNullInput) {
    std::cout << "Entering CopyConstructorWithNullInput" << std::endl;
    dm_radio_t* radio = nullptr;
    EXPECT_ANY_THROW({
        dm_radio_t copied_radio(*radio);
    });
    std::cout << "Exiting CopyConstructorWithNullInput" << std::endl;
}

/**
* @brief Test the copy constructor with invalid data.
*
* This test verifies that the copy constructor correctly copies the entire state of an original
* `dm_radio_t` object even when the object contains invalid or out-of-range values.
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 010@n
* **Priority:** High@n
*
* @n
* **Pre-Conditions:** None@n
* **Dependencies:** None@n
* **User Interaction:** None@n
*
* @n
* **Test Procedure:**@n
* | Step | Description | Test Data | Expected Result | Notes |
* | :--: | ----------- | --------- | --------------- | ----- |
* | 01   | Create and initialize a `dm_radio_t` object | `radio` instance | Successful initialization | Valid baseline |
* | 02   | Assign invalid values to selected fields | e.g., `noise = -9999` | Values assigned without crash | Out-of-range inputs |
* | 03   | Copy original object using copy constructor | `dm_radio_t copied_radio(radio)` | New object created | Should not throw |
* | 04   | Verify copied object's fields match original including invalid values | Compare fields such as `band`, `noise`, `srg_bss_color_bitmap` | EXPECT_EQ passes | Deep copy includes invalid data |
*/
TEST(dm_radio_t_Test, CopyConstructorWithInvalidData) {
    std::cout << "Entering CopyConstructorWithInvalidData" << std::endl;
    dm_radio_t radio;
    // Set invalid data explicitly
    radio.m_radio_info.number_of_bss = static_cast<unsigned int>(-1);  // Invalid unsigned (wrap around to large value)
    radio.m_radio_info.noise = -9999;  // Unrealistic negative noise level
    radio.m_radio_info.utilization = 65535;  // Max for unsigned short, possibly invalid
    memset(radio.m_radio_info.srg_bss_color_bitmap, 0xFF, sizeof(radio.m_radio_info.srg_bss_color_bitmap)); // Invalid bitmap
    // Copy constructor
    dm_radio_t copied_radio(radio);
    // Expect copied values equal the original, including invalid ones
    EXPECT_EQ(copied_radio.m_radio_info.number_of_bss, radio.m_radio_info.number_of_bss);
    EXPECT_EQ(copied_radio.m_radio_info.noise, radio.m_radio_info.noise);
    EXPECT_EQ(copied_radio.m_radio_info.utilization, radio.m_radio_info.utilization);
    EXPECT_TRUE(memcmp(copied_radio.m_radio_info.srg_bss_color_bitmap, radio.m_radio_info.srg_bss_color_bitmap,
                       sizeof(radio.m_radio_info.srg_bss_color_bitmap)) == 0);
    std::cout << "Exiting CopyConstructorWithInvalidData" << std::endl;
}

/**
* @brief Test the initialization of dm_radio_t with valid radio information
*
* This test verifies that the dm_radio_t object is correctly initialized when provided with valid radio information.@n
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
* | 01| Initialize radio_info with valid data | radio_info.id = 1, radio_info.enabled = true, radio_info.noise = -90, radio_info.traffic_sep_combined_fronthaul = true, radio_info.channel_util_threshold = 80, radio_info.srg_bss_color_bitmap[0] = 0xAA | radio_info should be initialized correctly | Should be successful |
* | 02| Create dm_radio_t object with radio_info | radio_instance = new dm_radio_t(&radio_info) | dm_radio_t object should be created successfully | Expect No throw.|
*/

TEST(dm_radio_t_Test, InitializeWithValidRadioInfo) {
    std::cout << "Entering InitializeWithValidRadioInfo" << std::endl;
    em_radio_info_t radio_info;
    strncpy(radio_info.id.net_id, "TestNetID", sizeof(radio_info.id.net_id));
    memset(radio_info.id.dev_mac, 0x01, sizeof(radio_info.id.dev_mac));
    memset(radio_info.id.ruid, 0x02, sizeof(radio_info.id.ruid));
    radio_info.enabled = true;
    radio_info.noise = -90;
    radio_info.traffic_sep_combined_fronthaul = true;
    radio_info.channel_util_threshold = 80;
    radio_info.srg_bss_color_bitmap[0] = 0xAA;

    EXPECT_NO_THROW({
        dm_radio_t radio(&radio_info);
        std::cout << "dm_radio_t initialized successfully with valid radio_info" << std::endl;
    });

    std::cout << "Exiting InitializeWithValidRadioInfo" << std::endl;
}

/**
* @brief Test the initialization of dm_radio_t with a null radio info pointer
*
* This test verifies that the dm_radio_t class correctly handles initialization when provided with a null pointer for the radio info. It ensures that the get_radio_info method returns nullptr in this scenario.
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
* | 01 | Initialize dm_radio_t with null radio info | radio_info = nullptr | get_radio_info() returns nullptr | Expect any error throw. |
*/
TEST(dm_radio_t_Test, InitializeWithNullRadioInfo) {
    std::cout << "Entering InitializeWithNullRadioInfo" << std::endl;
    em_radio_info_t* radio_info = nullptr;
    EXPECT_ANY_THROW({
        dm_radio_t radio(radio_info);
        std::cout << "dm_radio_t initialized with nullptr (unexpected)" << std::endl;
    });
    std::cout << "Exiting InitializeWithNullRadioInfo" << std::endl;
}

/**
* @brief Test the initialization of dm_radio_t with an invalid media type
*
* This test checks the behavior of the dm_radio_t class when initialized with an invalid media type.
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
* | 01| Initialize dm_radio_t with invalid media type | radio_info.intf.media = 9999 | initialization should fail | Should Fail |
*/
TEST(dm_radio_t_Test, InitializeWithInvalidMediaType) {
    std::cout << "Entering InitializeWithInvalidMediaType" << std::endl;

    em_radio_info_t radio_info {};
    memset(&radio_info, 0, sizeof(radio_info));
    
    radio_info.intf.media = static_cast<em_media_type_t>(9999);  // Invalid value

    EXPECT_ANY_THROW({
        dm_radio_t radio(&radio_info);
        std::cout << "dm_radio_t initialized with invalid media type (unexpected)" << std::endl;
    });

    std::cout << "Exiting InitializeWithInvalidMediaType" << std::endl;
}

/**
* @brief Test the DumpRadioInfo function with specific MAC address and name values
*
* This test sets specific values for the MAC address and name of the radio interface and then calls the dump_radio_info function to verify that the function handles these values correctly.
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
* | 01 | Set specific MAC address and name values | mac[0] = 0xFF, mac[1] = 0x00, mac[2] = 0xFF, mac[3] = 0x00, mac[4] = 0xFF, mac[5] = 0x00, name = "TestRadio" | Values should be set correctly | Should Pass |
* | 02 | Call dump_radio_info function | None | Function should execute without errors | Expect No throw.|
*/
TEST(dm_radio_t_Test, DumpRadioInfoWithSpecificValues) {
    std::cout << "Entering DumpRadioInfoWithSpecificValues" << std::endl;
    dm_radio_t radio;
    radio.m_radio_info.intf.mac[0] = 0xFF;
    radio.m_radio_info.intf.mac[1] = 0x00;
    radio.m_radio_info.intf.mac[2] = 0xFF;
    radio.m_radio_info.intf.mac[3] = 0x00;
    radio.m_radio_info.intf.mac[4] = 0xFF;
    radio.m_radio_info.intf.mac[5] = 0x00;
    strcpy(radio.m_radio_info.intf.name, "TestRadio");
    EXPECT_NO_THROW({
        radio.dump_radio_info();
    });
    std::cout << "Exiting DumpRadioInfoWithSpecificValues" << std::endl;
}

/**
* @brief Test the behavior of the dump_radio_info method when the radio info structure is null.
*
* This test checks the dump_radio_info method of the dm_radio_t class to ensure it handles a null radio info structure correctly. The objective is to verify that the method does not crash or produce incorrect output when the radio info structure is zeroed out.
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
* | 01 | Create a dm_radio_t instance | radio_instance = new dm_radio_t() | Instance should be created successfully | Should be successful |
* | 02 | Zero out the radio info structure | memset(&radio.m_radio_info, 0, sizeof(em_radio_info_t)) | Structure should be zeroed out | Should be successful |
* | 03 | Call dump_radio_info method | radio.dump_radio_info() | Method should handle null structure without crashing | Should Pass Expect No throw. |
*/
TEST(dm_radio_t_Test, DumpRadioInfoWithNullStructure) {
    std::cout << "Entering DumpRadioInfoWithNullStructure" << std::endl;
    dm_radio_t radio;
    memset(&radio.m_radio_info, 0, sizeof(em_radio_info_t));
    EXPECT_NO_THROW({
        radio.dump_radio_info();
    });
    std::cout << "Exiting DumpRadioInfoWithNullStructure" << std::endl;
}

/**
* @brief Test the encoding functionality of dm_radio_t with valid cJSON object and different reason values.
*
* This test verifies that the encode function of dm_radio_t correctly handles a valid cJSON object with various reason values. The test iterates through different reason values and ensures that the encode function processes each one without errors.
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
* | 01| Initialize cJSON object and dm_radio_t instance | obj.type = cJSON_Object, radio_instance = new dm_radio_t() | Initialization should be successful | Should be successful |
* | 02| Encode with reason em_get_radio_list_reason_none | obj, reason = em_get_radio_list_reason_none | Encode should process without errors | Should Pass |
* | 03| Encode with reason em_get_radio_list_reason_radio_summary | obj, reason = em_get_radio_list_reason_radio_summary | Encode should process without errors | Should Pass |
* | 04| Encode with reason em_get_radio_list_reason_radio_enable | obj, reason = em_get_radio_list_reason_radio_enable | Encode should process without errors | Should Pass |
* | 05| Encode with reason em_get_radio_list_reason_channel_scan | obj, reason = em_get_radio_list_reason_channel_scan | Encode should process without errors | Should Pass Expect No throw|.
*/
TEST(dm_radio_t_Test, EncodeWithValidCJSONObjectAndDifferentReasonValues) {
    std::cout << "Entering EncodeWithValidCJSONObjectAndDifferentReasonValues test" << std::endl;
    cJSON* obj = cJSON_CreateObject();
    dm_radio_t radio;
    em_get_radio_list_reason_t reasons[] = {
        em_get_radio_list_reason_none,
        em_get_radio_list_reason_radio_summary,
        em_get_radio_list_reason_radio_enable,
        em_get_radio_list_reason_channel_scan
    };
    for (auto reason : reasons) {
        std::cout << "Calling encode method with reason value: " << static_cast<int>(reason) << std::endl;

        EXPECT_NO_THROW({
            radio.encode(obj, reason);
        });
    }
    cJSON_Delete(obj);
    std::cout << "Exiting EncodeWithValidCJSONObjectAndDifferentReasonValues test" << std::endl;
}

/**
* @brief Test the encode function with a null cJSON object and default reason
*
* This test checks the behavior of the encode function when provided with a null cJSON object and the default reason. It ensures that the function handles null input gracefully without crashing or producing unexpected results.@n
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
* | 01| Initialize the dm_radio_t instance | radio_instance = new dm_radio_t() | Should be successful | Should be successful |
* | 02| Call the encode function with null cJSON object and default reason | obj = nullptr, reason = em_get_radio_list_reason_none | Exception should be thrown.| Should Fail. |
*/
TEST(dm_radio_t_Test, EncodeWithNullCJSONObjectAndDefaultReason) {
    std::cout << "Entering EncodeWithNullCJSONObjectAndDefaultReason test" << std::endl;
    cJSON* obj = nullptr;
    dm_radio_t radio;
    EXPECT_ANY_THROW({
        radio.encode(obj, em_get_radio_list_reason_none);
    });
    std::cout << "Exiting EncodeWithNullCJSONObjectAndDefaultReason test" << std::endl;
}

/**
* @brief Test the encoding function with an invalid cJSON object and reason radio summary.
*
* This test checks the behavior of the encode function when provided with an invalid cJSON object. The objective is to ensure that the function handles invalid input gracefully without causing unexpected behavior or crashes.
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
* | 01| Create an invalid cJSON object | obj->type = -1 | Invalid cJSON object created | Should be successful |
* | 02| Call the encode function with the invalid cJSON object and reason radio summary | radio.encode(obj, em_get_radio_list_reason_radio_summary) | Function should handle invalid input gracefully | Expect any throw.|
*/
TEST(dm_radio_t_Test, EncodeWithInvalidCJSONObjectAndReasonRadioSummary) {
    std::cout << "Entering EncodeWithInvalidCJSONObjectAndReasonRadioSummary test" << std::endl;
    cJSON* obj = cJSON_CreateObject();
    obj->type = -1;  // Invalid type
    dm_radio_t radio;
    EXPECT_ANY_THROW({
        radio.encode(obj, em_get_radio_list_reason_radio_summary);
    });
    cJSON_Delete(obj);
    std::cout << "Exiting EncodeWithInvalidCJSONObjectAndReasonRadioSummary test" << std::endl;
}

/**
 * @brief Test to validate the get_dm_orch_type method.
 *
 * This test verifies that the get_dm_orch_type method returns the correct orchestration type for a dm_radio_t object
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
 * | Step | Description | Test Data | Expected Result | Notes |
 * | :--: | ----------- | ---------- | ---------------- | ----- |
 * | 01   | Retrieve the orchestration type based on the radio input | dm_orch_type_t result = radio.get_dm_orch_type(radio) | Returned value should match the expected values | Should Pass |
 */
TEST(dm_radio_t_Test, RetrieveOrchType) {
    std::cout << "Entering RetrieveOrchType" << std::endl;
    dm_radio_t radio, another_radio;
    dm_orch_type_t result = radio.get_dm_orch_type(another_radio);
    std::cout << "The retrieved orch type is: " << static_cast<int>(result) << std::endl;
    EXPECT_TRUE(result == dm_orch_type_db_update || result == dm_orch_type_db_insert || result == dm_orch_type_none);
    std::cout << "Exiting RetrieveOrchType" << std::endl;
}

/**
* @brief Test to verify the retrieval of Radio ID when MAC address is properly initialized using custom constructor
*
* This test checks if the MAC address is correctly initialized and retrieved using the custom constructor of the dm_radio_t class. The test ensures that the MAC address set in the radio_info structure is accurately returned by the get_radio_id() method.
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
* | 01| Initialize radio_info with expected MAC address | radio_info.intf.mac = {0x00, 0x14, 0x22, 0x01, 0x23, 0x45} | MAC address should be set correctly | Should be successful |
* | 02| Create dm_radio_t instance using custom constructor | dm_radio_t radio(&radio_info) | Instance should be created successfully | Should be successful |
* | 03| Retrieve MAC address using get_radio_id() | mac_address = radio.get_radio_id() | mac_address should not be nullptr | Should Pass |
* | 04| Compare retrieved MAC address with expected MAC address | memcmp(mac_address, expected_mac, 6) | Result should be 0 (indicating match) | Should Pass |
*/
TEST(dm_radio_t_Test, RetrieveRadioIDWhenMACAddressIsProperlyInitializedUsingCustomConstructor) {
    std::cout << "Entering RetrieveRadioIDWhenMACAddressIsProperlyInitializedUsingCustomConstructor" << std::endl;
    em_radio_info_t radio_info;
    unsigned char expected_mac[6] = {0x00, 0x14, 0x22, 0x01, 0x23, 0x45};
    memcpy(radio_info.intf.mac, expected_mac, 6);
    dm_radio_t radio(&radio_info);
    unsigned char* mac_address = radio.get_radio_id();
    EXPECT_NE(mac_address, nullptr);
    EXPECT_EQ(memcmp(mac_address, expected_mac, 6), 0);
    std::cout << "Exiting RetrieveRadioIDWhenMACAddressIsProperlyInitializedUsingCustomConstructor" << std::endl;
}

/**
* @brief Test to verify the retrieval of radio information after initialization
*
* This test checks if the radio information can be correctly retrieved after the radio instance is initialized. It ensures that the get_radio_info method returns a non-null pointer and that the returned pointer matches the initialized radio information structure.
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
* | 01| Initialize radio_info structure to zero and create dm_radio_t instance | radio_info = {0}, radio = dm_radio_t(&radio_info) | dm_radio_t instance should be created successfully | Should be successful |
* | 02| Retrieve radio information using get_radio_info method | result = radio.get_radio_info() | result should not be nullptr | Should Pass |
* | 03| Verify the retrieved radio information matches the initialized structure | result == &radio_info | result should be equal to &radio_info | Should Pass |
*/
TEST(dm_radio_t_Test, RetrieveRadioInfoAfterInitialization) {
    std::cout << "Entering RetrieveRadioInfoAfterInitialization" << std::endl;
    em_radio_info_t radio_info;
    strncpy(radio_info.id.net_id, "TestNetID", sizeof(radio_info.id.net_id));
    memset(radio_info.id.dev_mac, 0x01, sizeof(radio_info.id.dev_mac));
    memset(radio_info.id.ruid, 0x02, sizeof(radio_info.id.ruid));
    radio_info.enabled = true;
    radio_info.noise = -90;
    radio_info.traffic_sep_combined_fronthaul = true;
    radio_info.channel_util_threshold = 80;
    radio_info.srg_bss_color_bitmap[0] = 0xAA;
    dm_radio_t radio(&radio_info);
    em_radio_info_t *info = radio.get_radio_info();
    EXPECT_STREQ(info->id.net_id, "TestNetID");    
    EXPECT_TRUE(memcmp(info->id.dev_mac, radio_info.id.dev_mac, sizeof(info->id.dev_mac)) == 0);
    EXPECT_TRUE(memcmp(info->id.ruid, radio_info.id.ruid, sizeof(info->id.ruid)) == 0);
    EXPECT_EQ(radio_info.enabled, info->enabled);
    EXPECT_EQ(radio_info.noise, info->noise);
    EXPECT_EQ(radio_info.traffic_sep_combined_fronthaul, info->traffic_sep_combined_fronthaul);
    EXPECT_EQ(radio_info.channel_util_threshold, info->channel_util_threshold);
    EXPECT_EQ(radio_info.srg_bss_color_bitmap[0], info->srg_bss_color_bitmap[0]);
    std::cout << "Exiting RetrieveRadioInfoAfterInitialization" << std::endl;
}

/**
* @brief Test to verify the retrieval of the radio interface after initialization
*
* This test checks if the radio interface is correctly initialized and retrieved after calling the init() method on the dm_radio_t instance. It ensures that the interface is not null and that its fields are set to their expected default values.
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
* | 01| Initialize the dm_radio_t instance with valid values | radio_instance = new dm_radio_t() | Should be successful | |
* | 02| Retrieve the radio interface using get_radio_interface() | interface = radio_instance->get_radio_interface() | interface should not be null | Should Pass |
* | 04| Check the media field of the interface | interface->media | media == 0 | Should Pass |
* | 05| Check the name field of the interface | interface->name[0] | name[0] == '\0' | Should Pass |
* | 06| Check the mac field of the interface | interface->mac[i] | mac[i] == 0 for i in [0, 5] | Should Pass |
*/
TEST(dm_radio_t_Test, RetrieveRadioInterfaceAfterInitialization) {
    std::cout << "Entering RetrieveRadioInterfaceAfterInitialization" << std::endl;
    dm_radio_t radio;
    // Manually initialize media, name, and mac in radio.m_radio_info.intf
    radio.m_radio_info.intf.media = em_media_type_ieee80211n_5;
    strncpy(radio.m_radio_info.intf.name, "wlan0", sizeof(radio.m_radio_info.intf.name));
    radio.m_radio_info.intf.name[sizeof(radio.m_radio_info.intf.name) - 1] = '\0';
    unsigned char valid_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    memcpy(radio.m_radio_info.intf.mac, valid_mac, sizeof(valid_mac));
    em_interface_t* interface = radio.get_radio_interface();
    EXPECT_NE(interface, nullptr);
    EXPECT_EQ(interface->media, em_media_type_ieee80211n_5);
    EXPECT_STREQ(interface->name, "wlan0");
    for (int i = 0; i < 6; ++i) {
        EXPECT_EQ(interface->mac[i], valid_mac[i]);
    }
    std::cout << "Exiting RetrieveRadioInterfaceAfterInitialization" << std::endl;
}

/**
* @brief Test to verify the MAC address retrieval after setting a specific MAC address.
*
* This test checks if the MAC address set in the radio interface is correctly retrieved by the get_radio_interface_mac() method.@n
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
* | 01| Set specific MAC address in radio interface | expected_mac = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E} | MAC address should be set successfully | Should be successful |
* | 02| Retrieve MAC address using get_radio_interface_mac() | None | MAC address should not be nullptr | Should Pass |
* | 03| Verify each byte of the retrieved MAC address | expected_mac = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, mac = retrieved_mac | Each byte should match the expected MAC address | Should Pass |
*/
TEST(dm_radio_t_Test, RetrieveMACAddressAfterSettingSpecificMACAddress) {
    std::cout << "Entering RetrieveMACAddressAfterSettingSpecificMACAddress" << std::endl;
    unsigned char expected_mac[6] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
    em_radio_info_t radio_info;
    memcpy(radio_info.intf.mac, expected_mac, 6);
    dm_radio_t radio(&radio_info);
    unsigned char* mac = radio.get_radio_interface_mac();
    EXPECT_NE(mac, nullptr);
    for (int i = 0; i < 6; ++i) {
        EXPECT_EQ(mac[i], expected_mac[i]);
    }
    std::cout << "Exiting RetrieveMACAddressAfterSettingSpecificMACAddress" << std::endl;
}

/**
* @brief Test to verify the retrieval of the radio interface name when set to a specific value.
*
* This test checks if the `get_radio_interface_name` method correctly retrieves the name of the radio interface when it is set to a specificValue@n
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
* | 01| Create a dm_radio_t instance and set the interface name to "wlan0" | radio_instance = new dm_radio_t(), radio_instance->m_radio_info.intf.name = "wlan0" | Interface name should be set successfully | Should be successful |
* | 02| Retrieve the radio interface name using get_radio_interface_name method | result = radio_instance->get_radio_interface_name() | result should be "wlan0" | Should Pass |
*/
TEST(dm_radio_t_Test, RetrieveRadioInterfaceNameSpecificValue) {
    std::cout << "Entering RetrieveRadioInterfaceNameSpecificValue" << std::endl;
    dm_radio_t radio;
    strcpy(radio.m_radio_info.intf.name, "wlan0");
    char* result = radio.get_radio_interface_name();
    EXPECT_STREQ(result, "wlan0");
    std::cout << "Exiting RetrieveRadioInterfaceNameSpecificValue" << std::endl;
}

/**
* @brief Test to verify the behavior of retrieving the radio interface name when it is an empty string.
*
* This test checks the functionality of the `get_radio_interface_name` method in the `dm_radio_t` class when the interface name is set to an empty string. It ensures that the method correctly returns an empty string in this scenario.
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
* | 01| Initialize the radio interface name to an empty string | radio.m_radio_info.intf.name = "" | Should be successful | |
* | 02| Retrieve the radio interface name | result = radio.get_radio_interface_name() | result should be "" | Should Pass |
* | 03| Verify the result using assertion | EXPECT_STREQ(result, "") | Assertion should pass | Should Pass |
*/
TEST(dm_radio_t_Test, RetrieveRadioInterfaceNameEmptyString) {
    std::cout << "Entering RetrieveRadioInterfaceNameEmptyString" << std::endl;
    dm_radio_t radio;
    strcpy(radio.m_radio_info.intf.name, "");
    char* result = radio.get_radio_interface_name();
    EXPECT_STREQ(result, "");
    std::cout << "Exiting RetrieveRadioInterfaceNameEmptyString" << std::endl;
}

/**
* @brief Test to verify the retrieval of radio interface name with special characters
*
* This test checks if the `get_radio_interface_name` method correctly retrieves the radio interface name when it contains special characters. This is important to ensure that the method can handle and return names with special characters without any issues.@n
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
* | 01| Set the radio interface name to special characters and retrieve it | input: radio.m_radio_info.intf.name = "!@#$%^&*()_+", output: result | result should be "!@#$%^&*()_+" | Should Pass |
*/
TEST(dm_radio_t_Test, RetrieveRadioInterfaceNameSpecialCharacters) {
    std::cout << "Entering RetrieveRadioInterfaceNameSpecialCharacters" << std::endl;
    dm_radio_t radio;
    strcpy(radio.m_radio_info.intf.name, "!@#$%^&*()_+");
    char* result = radio.get_radio_interface_name();
    EXPECT_STREQ(result, "!@#$%^&*()_+");
    std::cout << "Exiting RetrieveRadioInterfaceNameSpecialCharacters" << std::endl;
}

/**
* @brief Test the successful initialization of the dm_radio_t class
*
* This test verifies that the dm_radio_t class initializes correctly and that the initial state of the radio information is as expected. The test ensures that the init() method returns 0, indicating success, and that the radio information structure is correctly initialized to its default state.
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
* | 01| Create an instance of dm_radio_t and call init() | radio_instance = new dm_radio_t(), result = radio_instance->init() | result should be 0 | Should Pass |
* | 02| Verify the initial state of the radio information | memcmp(&radio_instance->m_radio_info, &expected_info, sizeof(em_radio_info_t)) | result should be 0 | Should Pass |
*/
TEST(dm_radio_t_Test, SuccessfulInitialization) {
    std::cout << "Entering SuccessfulInitialization" << std::endl;
    dm_radio_t radio;
    int result = radio.init();
    EXPECT_EQ(result, 0);
    std::cout << "Exiting SuccessfulInitialization" << std::endl;
}

/**
* @brief Test to verify the assignment operator of dm_radio_t class
*
* This test checks if the assignment operator correctly assigns the values from one dm_radio_t object to another. It ensures that the internal state (m_radio_info) of the objects is identical after the assignment.@n
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
* | 01| Create two dm_radio_t objects and assign valid values to few fields of obj1 | obj1, obj2 | Objects created successfully | Should be successful |
* | 02| Assign obj2 to obj1 | obj2 = obj1 | obj2's m_radio_info should be identical to obj1's m_radio_info | Should Pass |
* | 03| Compare m_radio_info fields of both objects | memcmp(&obj1.m_radio_info, &obj2.m_radio_info, sizeof(em_radio_info_t)) | Result should be 0 | Should Pass |
*/
TEST(dm_radio_t_Test, AssigningDmRadioTObjectWithInitializedValues) {
    std::cout << "Entering AssigningDmRadioTObjectWithInitializedValues" << std::endl;
    dm_radio_t obj1, obj2;
    strncpy(obj1.m_radio_info.id.net_id, "TestNetID", sizeof(obj1.m_radio_info.id.net_id));
    memset(obj1.m_radio_info.id.dev_mac, 0x01, sizeof(obj1.m_radio_info.id.dev_mac));
    memset(obj1.m_radio_info.id.ruid, 0x02, sizeof(obj1.m_radio_info.id.ruid));
    obj1.m_radio_info.enabled = true;
    obj1.m_radio_info.noise = -90;
    obj1.m_radio_info.traffic_sep_combined_fronthaul = true;
    obj1.m_radio_info.channel_util_threshold = 80;
    obj1.m_radio_info.srg_bss_color_bitmap[0] = 0xAA ;  
    obj2 = obj1;
    EXPECT_STREQ(obj2.m_radio_info.id.net_id, "TestNetID");    
    EXPECT_TRUE(memcmp(obj2.m_radio_info.id.dev_mac, obj1.m_radio_info.id.dev_mac, sizeof(obj2.m_radio_info.id.dev_mac)) == 0);
    EXPECT_TRUE(memcmp(obj2.m_radio_info.id.ruid, obj1.m_radio_info.id.ruid, sizeof(obj2.m_radio_info.id.ruid)) == 0);
    EXPECT_EQ(obj1.m_radio_info.enabled, obj2.m_radio_info.enabled);
    EXPECT_EQ(obj1.m_radio_info.noise, obj2.m_radio_info.noise);
    EXPECT_EQ(obj1.m_radio_info.traffic_sep_combined_fronthaul, obj2.m_radio_info.traffic_sep_combined_fronthaul);
    EXPECT_EQ(obj1.m_radio_info.channel_util_threshold, obj2.m_radio_info.channel_util_threshold);
    EXPECT_EQ(obj1.m_radio_info.srg_bss_color_bitmap[0], obj2.m_radio_info.srg_bss_color_bitmap[0]);
    std::cout << "Exiting AssigningDmRadioTObjectWithInitializedValues" << std::endl;
}

/**
* @brief Test to verify the equality operator for dm_radio_t objects
*
* This test checks if two default-constructed dm_radio_t objects are considered equal by the equality operator. This is important to ensure that the equality operator is correctly implemented for the dm_radio_t class.
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
* | 01| Create two initialized dm_radio_t objects with same valid values | obj1, obj2 | Objects should be created successfully | Should be successful |
* | 02| Check if the two objects are equal using the equality operator | obj1 == obj2 | EXPECT_TRUE(obj1 == obj2) should pass | Should Pass |
*/
TEST(dm_radio_t_Test, IdenticalObjects) {
    std::cout << "Entering IdenticalObjects test";
    dm_radio_t obj1, obj2;
    strncpy(obj1.m_radio_info.id.net_id, "TestNetID", sizeof(obj1.m_radio_info.id.net_id));
    memset(obj1.m_radio_info.id.dev_mac, 0x01, sizeof(obj1.m_radio_info.id.dev_mac));
    memset(obj1.m_radio_info.id.ruid, 0x02, sizeof(obj1.m_radio_info.id.ruid));
    strncpy(obj2.m_radio_info.id.net_id, "TestNetID", sizeof(obj2.m_radio_info.id.net_id));
    memset(obj2.m_radio_info.id.dev_mac, 0x01, sizeof(obj2.m_radio_info.id.dev_mac));
    memset(obj2.m_radio_info.id.ruid, 0x02, sizeof(obj2.m_radio_info.id.ruid));
    obj1.m_radio_info.enabled = obj2.m_radio_info.enabled = true;
    obj1.m_radio_info.noise = obj2.m_radio_info.noise = -90;
    obj1.m_radio_info.traffic_sep_combined_fronthaul = obj2.m_radio_info.traffic_sep_combined_fronthaul = true;
    obj1.m_radio_info.channel_util_threshold = obj2.m_radio_info.channel_util_threshold = 80;
    obj1.m_radio_info.srg_bss_color_bitmap[0] = obj2.m_radio_info.srg_bss_color_bitmap[0] = 0xAA;
    EXPECT_TRUE(obj1 == obj2);
    std::cout << "Exiting IdenticalObjects test";
}

/**
* @brief Test to verify that two dm_radio_t objects with different MAC addresses are not considered equal.
*
* This test checks the equality operator for dm_radio_t objects by assigning different MAC addresses to two instances and verifying that they are not equal.@n
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
* | 01| Create two dm_radio_t objects | obj1, obj2 | Objects created successfully | Should be successful |
* | 02| Assign different MAC addresses to the objects | obj1.mac = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, obj2.mac = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB} | MAC addresses assigned successfully | Should be successful |
* | 03| Compare the two objects for equality | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_radio_t_Test, DifferentMACAddresses) {
    std::cout << "Entering DifferentMACAddresses test";
    dm_radio_t obj1 {};
    dm_radio_t obj2 {};
    unsigned char mac1[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    unsigned char mac2[6] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
    memcpy(obj1.m_radio_info.intf.mac, mac1, 6);
    memcpy(obj2.m_radio_info.intf.mac, mac2, 6);
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting DifferentMACAddresses test";
}

/**
* @brief Test to verify that two radio objects with different MAC addresses are not considered equal.
*
* This test checks the equality operator for the `dm_radio_t` class to ensure that two instances with different MAC addresses are not considered equal. This is important to verify the uniqueness of radio instances based on their MAC addresses.
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
* | 01 | Create two `dm_radio_t` objects | obj1, obj2 | Objects created successfully | Should be successful |
* | 02 | Set different MAC addresses for both objects | obj1.m_radio_info.id.dev_mac = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, obj2.m_radio_info.id.dev_mac = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB} | MAC addresses set successfully | Should be successful |
* | 03 | Compare the two objects for equality | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_radio_t_Test, DifferentRadioIDs) {
    std::cout << "Entering DifferentRadioIDs test";
    dm_radio_t obj1 {};
    dm_radio_t obj2 {};
    unsigned char dev_mac1[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    unsigned char dev_mac2[6] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
    memcpy(obj1.m_radio_info.id.dev_mac, dev_mac1, 6);
    memcpy(obj2.m_radio_info.id.dev_mac, dev_mac2, 6);
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting DifferentRadioIDs test";
}

/**
* @brief Test to verify the behavior of the equality operator for different media types
*
* This test checks the equality operator of the dm_radio_t class when two instances have different media types. 
* It ensures that the operator correctly identifies that the two instances are not equal when their media types differ.
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
* | 01| Create two instances of dm_radio_t | obj1, obj2 | Instances created successfully | Should be successful |
* | 02| Set media type of obj1 to em_media_type_ieee80211a_5 | obj1.m_radio_info.intf.media = em_media_type_ieee80211a_5 | Media type set successfully | Should be successful |
* | 03| Set media type of obj2 to em_media_type_ieee80211n_24 | obj2.m_radio_info.intf.media = em_media_type_ieee80211n_24 | Media type set successfully | Should be successful |
* | 04| Compare obj1 and obj2 using equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_radio_t_Test, DifferentMediaTypes) {
    std::cout << "Entering DifferentMediaTypes test";
    dm_radio_t obj1 {};
    dm_radio_t obj2 {};
    obj1.m_radio_info.intf.media = em_media_type_ieee80211a_5;
    obj2.m_radio_info.intf.media = em_media_type_ieee80211n_24;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting DifferentMediaTypes test";
}

/**
* @brief Test to verify the behavior of the equality operator for different band values
*
* This test checks the equality operator of the dm_radio_t class when the band values of two instances are different. The test ensures that the equality operator correctly identifies that two instances with different band values are not equal.@n
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
* | 01| Create two instances of dm_radio_t | obj1, obj2 | Instances created successfully | Should be successful |
* | 02| Set band of obj1 to em_freq_band_24 | obj1.m_radio_info.band = em_freq_band_24 | Band set successfully | Should be successful |
* | 03| Set band of obj2 to em_freq_band_5 | obj2.m_radio_info.band = em_freq_band_5 | Band set successfully | Should be successful |
* | 04| Compare obj1 and obj2 using equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Fail |
*/
TEST(dm_radio_t_Test, DifferentBandValues) {
    std::cout << "Entering DifferentBandValues test";
    dm_radio_t obj1 {};
    dm_radio_t obj2 {};
    obj1.m_radio_info.band = em_freq_band_24;
    obj2.m_radio_info.band = em_freq_band_5;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting DifferentBandValues test";
}

/**
* @brief Test to verify the behavior of the equality operator for different noise values
*
* This test checks the equality operator of the dm_radio_t class by setting different noise values for two instances and ensuring they are not considered equal.@n
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
* | 01 | Create two instances of dm_radio_t | obj1, obj2 | Instances created successfully | Should be successful |
* | 02 | Set noise value of obj1 to -90 | obj1.m_radio_info.noise = -90 | Noise value set successfully | Should be successful |
* | 03 | Set noise value of obj2 to -80 | obj2.m_radio_info.noise = -80 | Noise value set successfully | Should be successful |
* | 04 | Compare obj1 and obj2 using equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_radio_t_Test, DifferentNoiseValues) {
    std::cout << "Entering DifferentNoiseValues test";
    dm_radio_t obj1 {};
    dm_radio_t obj2 {};
    obj1.m_radio_info.noise = -90;
    obj2.m_radio_info.noise = -80;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting DifferentNoiseValues test";
}

/**
* @brief Test to verify the inequality of dm_radio_t objects with different utilization values
*
* This test checks if two dm_radio_t objects with different utilization values are not considered equal.@n
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
* | 01 | Create two dm_radio_t objects | obj1, obj2 | Objects created successfully | Should be successful |
* | 02 | Set utilization of obj1 to 50 | obj1.m_radio_info.utilization = 50 | Utilization set to 50 | Should be successful |
* | 03 | Set utilization of obj2 to 75 | obj2.m_radio_info.utilization = 75 | Utilization set to 75 | Should be successful |
* | 04 | Compare obj1 and obj2 for equality | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_radio_t_Test, DifferentUtilizationValues) {
    std::cout << "Entering DifferentUtilizationValues test";
    dm_radio_t obj1 {};
    dm_radio_t obj2 {};
    obj1.m_radio_info.utilization = 50;
    obj2.m_radio_info.utilization = 75;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting DifferentUtilizationValues test";
}

/**
* @brief Test to verify the behavior of traffic separation policies in dm_radio_t class
*
* This test checks the equality operator of the dm_radio_t class by setting different traffic separation policies for two instances and ensuring they are not considered equal.@n
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
* | 01 | Create two instances of dm_radio_t | obj1, obj2 | Instances created successfully | Should be successful |
* | 02 | Set traffic_sep_combined_fronthaul to true for obj1 | obj1.m_radio_info.traffic_sep_combined_fronthaul = true | Value set successfully | Should be successful |
* | 03 | Set traffic_sep_combined_fronthaul to false for obj2 | obj2.m_radio_info.traffic_sep_combined_fronthaul = false | Value set successfully | Should be successful |
* | 04 | Compare obj1 and obj2 using equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_radio_t_Test, DifferentTrafficSeparationPolicies) {
    std::cout << "Entering DifferentTrafficSeparationPolicies test";
    dm_radio_t obj1 {};
    dm_radio_t obj2 {};
    obj1.m_radio_info.traffic_sep_combined_fronthaul = true;
    obj2.m_radio_info.traffic_sep_combined_fronthaul = false;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting DifferentTrafficSeparationPolicies test";
}

/**
* @brief Test to verify the behavior of the equality operator for different steering policies
*
* This test checks if two dm_radio_t objects with different steering policies are considered unequal.@n
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
* | 01| Create two dm_radio_t objects | obj1, obj2 | Objects created successfully | Should be successful |
* | 02| Set steering policy for obj1 to 1 | obj1.m_radio_info.steering_policy = 1 | Steering policy set to 1 | Should be successful |
* | 03| Set steering policy for obj2 to 2 | obj2.m_radio_info.steering_policy = 2 | Steering policy set to 2 | Should be successful |
* | 04| Compare obj1 and obj2 using equality operator | EXPECT_FALSE(obj1 == obj2) | Objects are not equal | Should Pass |
*/
TEST(dm_radio_t_Test, DifferentSteeringPolicies) {
    std::cout << "Entering DifferentSteeringPolicies test";
    dm_radio_t obj1 {};
    dm_radio_t obj2 {};
    obj1.m_radio_info.steering_policy = 1;
    obj2.m_radio_info.steering_policy = 2;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting DifferentSteeringPolicies test";
}

/**
* @brief Test to verify the behavior of the equality operator for different channel utilization thresholds
*
* This test checks if two dm_radio_t objects with different channel utilization thresholds are considered unequal.@n
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
* | 01| Create two dm_radio_t objects with different channel utilization thresholds | obj1.m_radio_info.channel_util_threshold = 30, obj2.m_radio_info.channel_util_threshold = 40 | Objects should be unequal | Should Pass |
* | 02| Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_radio_t_Test, DifferentChannelUtilizationThresholds) {
    std::cout << "Entering DifferentChannelUtilizationThresholds test";
    dm_radio_t obj1 {};
    dm_radio_t obj2 {};
    obj1.m_radio_info.channel_util_threshold = 30;
    obj2.m_radio_info.channel_util_threshold = 40;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting DifferentChannelUtilizationThresholds test";
}

/**
* @brief Test to verify the behavior of the equality operator for different RCPI steering thresholds
*
* This test checks if two instances of `dm_radio_t` with different RCPI steering thresholds are not considered equal.@n
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
* | 01| Create two instances of dm_radio_t | obj1, obj2 | Instances created | Should be successful |
* | 02| Set RCPI steering threshold for obj1 | obj1.m_radio_info.rcpi_steering_threshold = 60 | Threshold set to 60 | Should be successful |
* | 03| Set RCPI steering threshold for obj2 | obj2.m_radio_info.rcpi_steering_threshold = 70 | Threshold set to 70 | Should be successful |
* | 04| Compare obj1 and obj2 using equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/

TEST(dm_radio_t_Test, DifferentRCPIsteeringThresholds) {
    std::cout << "Entering DifferentRCPIsteeringThresholds test";
    dm_radio_t obj1 {};
    dm_radio_t obj2 {};
    obj1.m_radio_info.rcpi_steering_threshold = 60;
    obj2.m_radio_info.rcpi_steering_threshold = 70;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting DifferentRCPIsteeringThresholds test";
}

/**
* @brief Test to verify the behavior of DifferentAssociatedSTATrafficStatsInclusionPolicies
*
* This test checks the equality operator of dm_radio_t objects with different associated_sta_traffic_stats_inclusion_policy values@n
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
* | 01| Create two dm_radio_t objects with different associated_sta_traffic_stats_inclusion_policy values | obj1.m_radio_info.associated_sta_traffic_stats_inclusion_policy = true, obj2.m_radio_info.associated_sta_traffic_stats_inclusion_policy = false | Objects should not be equal | Should Pass |
* | 02| Check the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_radio_t_Test, DifferentAssociatedSTATrafficStatsInclusionPolicies) {
    std::cout << "Entering DifferentAssociatedSTATrafficStatsInclusionPolicies test";
    dm_radio_t obj1 {};
    dm_radio_t obj2 {};
    obj1.m_radio_info.associated_sta_traffic_stats_inclusion_policy = true;
    obj2.m_radio_info.associated_sta_traffic_stats_inclusion_policy = false;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting DifferentAssociatedSTATrafficStatsInclusionPolicies test";
}

/**
* @brief Test to verify the behavior of the equality operator for different chip vendors
*
* This test checks if two dm_radio_t objects with different chip vendors are considered unequal.@n
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
* | 01 | Create two dm_radio_t objects | obj1, obj2 | Objects created successfully | Should be successful |
* | 02 | Set chip_vendor for obj1 to "VendorA" | obj1.m_radio_info.chip_vendor = "VendorA" | Chip vendor set successfully | Should be successful |
* | 03 | Set chip_vendor for obj2 to "VendorB" | obj2.m_radio_info.chip_vendor = "VendorB" | Chip vendor set successfully | Should be successful |
* | 04 | Compare obj1 and obj2 using equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_radio_t_Test, DifferentChipVendors) {
    std::cout << "Entering DifferentChipVendors test";
    dm_radio_t obj1 {};
    dm_radio_t obj2 {};
    strcpy(obj1.m_radio_info.chip_vendor, "VendorA");
    strcpy(obj2.m_radio_info.chip_vendor, "VendorB");
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting DifferentChipVendors test";
}

/**
* @brief Test to verify the behavior of the equality operator for different transmit power limits
*
* This test checks the equality operator of the dm_radio_t class by setting different transmit power limits for two instances and ensuring they are not considered equal.@n
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
* | 01 | Create two instances of dm_radio_t | obj1, obj2 | Instances created successfully | Should be successful |
* | 02 | Set transmit power limit for obj1 | obj1.m_radio_info.transmit_power_limit = 20 | Transmit power limit set to 20 | Should be successful |
* | 03 | Set transmit power limit for obj2 | obj2.m_radio_info.transmit_power_limit = 30 | Transmit power limit set to 30 | Should be successful |
* | 04 | Compare obj1 and obj2 using equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_radio_t_Test, DifferentTransmitPowerLimits) {
    std::cout << "Entering DifferentTransmitPowerLimits test";
    dm_radio_t obj1 {};
    dm_radio_t obj2 {};
    obj1.m_radio_info.transmit_power_limit = 20;
    obj2.m_radio_info.transmit_power_limit = 30;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting DifferentTransmitPowerLimits test";
}

/**
* @brief Test to verify the behavior of the equality operator for different BSS colors
*
* This test checks if two dm_radio_t objects with different BSS colors are not considered equal.@n
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
* | 01 | Create two dm_radio_t objects | obj1.m_radio_info.bss_color = 1, obj2.m_radio_info.bss_color = 2 | Objects created successfully | Should be successful |
* | 02 | Set different BSS colors for the objects | obj1.m_radio_info.bss_color = 1, obj2.m_radio_info.bss_color = 2 | BSS colors set successfully | Should be successful |
* | 03 | Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_radio_t_Test, DifferentBSSColors) {
    std::cout << "Entering DifferentBSSColors test";
    dm_radio_t obj1 {};
    dm_radio_t obj2 {};
    obj1.m_radio_info.bss_color = 1;
    obj2.m_radio_info.bss_color = 2;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting DifferentBSSColors test";
}

/**
* @brief Test the validity of SRG information in different radio instances
*
* This test checks the equality operator for two different instances of dm_radio_t with different SRG information validity.@n
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create two instances of dm_radio_t | obj1, obj2 | Instances should be created | Should be successful |
* | 02| Set SRG information validity for obj1 to true | obj1.m_radio_info.srg_information_valid = true | SRG information validity set to true | Should be successful |
* | 03| Set SRG information validity for obj2 to false | obj2.m_radio_info.srg_information_valid = false | SRG information validity set to false | Should be successful |
* | 04| Compare obj1 and obj2 using equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_radio_t_Test, DifferentSRGInformationValidity) {
    std::cout << "Entering DifferentSRGInformationValidity test";
    dm_radio_t obj1 {};
    dm_radio_t obj2 {};
    obj1.m_radio_info.srg_information_valid = true;
    obj2.m_radio_info.srg_information_valid = false;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting DifferentSRGInformationValidity test";
}

/**
* @brief Test the parsing of a valid key with correct format
*
* This test verifies that the `parse_radio_id_from_key` function correctly parses a valid key string and returns the expected result.@n
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
* | 01| Create an instance of dm_radio_t and em_radio_id_t | radio_instance = new dm_radio_t(), id = em_radio_id_t() | Instance should be created successfully | Should be successful |
* | 02| Call parse_radio_id_from_key with a valid key string | key = "network@01:23:45:67:89:ab@ab:cd:ef:01:23:45", id = &id | result = 0, EXPECT_EQ(result, 0) | Should Pass |
*/
TEST(dm_radio_t_Test, ValidKeyWithCorrectFormat) {
    std::cout << "Entering ValidKeyWithCorrectFormat test";
    dm_radio_t radio;
    em_radio_id_t id;
    const char* key = "network@01:23:45:67:89:ab@ab:cd:ef:01:23:45";
    int result = radio.parse_radio_id_from_key(key, &id);
    EXPECT_EQ(result, 0);
    std::cout << "Exiting ValidKeyWithCorrectFormat test";
}

/**
* @brief Test to verify the behavior of parse_radio_id_from_key when a null key is provided.
*
* This test checks the parse_radio_id_from_key function to ensure it correctly handles a null key input by returning an error code.@n
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
* | 01| Call parse_radio_id_from_key with null key | key = nullptr, id = &id | result = -1, EXPECT_EQ(result, -1) | Should Fail |
*/
TEST(dm_radio_t_Test, NullKey) {
    std::cout << "Entering NullKey test";
    dm_radio_t radio;
    em_radio_id_t id;
    const char* key = nullptr;
    int result = radio.parse_radio_id_from_key(key, &id);
    EXPECT_EQ(result, -1);
    std::cout << "Exiting NullKey test";
}

/**
* @brief Test to verify the behavior of parse_radio_id_from_key when a null pointer is passed for the ID
*
* This test checks the function parse_radio_id_from_key to ensure it correctly handles the case where a null pointer is passed for the ID parameter. This is important to verify that the function can gracefully handle invalid input and return the expected error code.
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Create an instance of dm_radio_t | radio_instance = new dm_radio_t() | Instance should be created successfully | Should be successful |
* | 02| Call parse_radio_id_from_key with a valid key and null ID pointer | key = "network@01:23:45:67:89:ab@ab:cd:ef:01:23:45", id = nullptr | result = -1, EXPECT_EQ(result, -1) | Should Fail |
*/
TEST(dm_radio_t_Test, NullIdPointer) {
    std::cout << "Entering NullIdPointer test";
    dm_radio_t radio;
    const char* key = "network@01:23:45:67:89:ab@ab:cd:ef:01:23:45";
    int result = radio.parse_radio_id_from_key(key, nullptr);
    EXPECT_EQ(result, -1);
    std::cout << "Exiting NullIdPointer test";
}

/**
* @brief Test to verify the behavior of parse_radio_id_from_key with an empty key string.
*
* This test checks the function parse_radio_id_from_key when provided with an empty key string. 
* It ensures that the function correctly handles this edge case by returning an error code.
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
* | 01| Call parse_radio_id_from_key with an empty key string | key = "", id = <uninitialized> | result = -1, EXPECT_EQ(result, -1) | Should Fail |
*/
TEST(dm_radio_t_Test, EmptyKeyString) {
    std::cout << "Entering EmptyKeyString test";
    dm_radio_t radio;
    em_radio_id_t id;
    const char* key = "";
    int result = radio.parse_radio_id_from_key(key, &id);
    EXPECT_EQ(result, -1);
    std::cout << "Exiting EmptyKeyString test";
}

/**
* @brief Test the behavior of parse_radio_id_from_key with an invalid key format
*
* This test checks the parse_radio_id_from_key function to ensure it correctly handles an invalid key format by returning an error code.@n
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
* | 01| Create dm_radio_t instance | radio_instance = new dm_radio_t() | Instance should be created successfully | Should be successful |
* | 02| Define invalid key format | key = "invalid_key_string" | Key should be defined successfully | Should be successful |
* | 03| Call parse_radio_id_from_key with invalid key | key = "invalid_key_string", id = &id | result = -1, EXPECT_EQ(result, -1) | Should Pass |
*/
TEST(dm_radio_t_Test, KeyWithInvalidFormat) {
    std::cout << "Entering KeyWithInvalidFormat test";
    dm_radio_t radio;
    em_radio_id_t id;
    const char* key = "invalid_key_string";
    int result = radio.parse_radio_id_from_key(key, &id);
    EXPECT_EQ(result, -1);
    std::cout << "Exiting KeyWithInvalidFormat test";
}

/**
* @brief Test the handling of keys with special characters in the parse_radio_id_from_key function.
*
* This test checks if the parse_radio_id_from_key function correctly handles keys that contain special characters. 
* The function is expected to return an error code when such keys are provided, ensuring that only valid keys are processed.
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
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Create a dm_radio_t instance and a key with special characters | key = "key_with_special_chars!@#", id = uninitialized | result = -1, EXPECT_EQ(result, -1) | Should Pass |
*/
TEST(dm_radio_t_Test, KeyWithSpecialCharacters) {
    std::cout << "Entering KeyWithSpecialCharacters test";
    dm_radio_t radio;
    em_radio_id_t id;
    const char* key = "key_with_special_chars!@#";
    int result = radio.parse_radio_id_from_key(key, &id);
    EXPECT_EQ(result, -1);
    std::cout << "Exiting KeyWithSpecialCharacters test";
}

/**
 * @brief Verifies that the default constructor of dm_radio_t creates an object successfully.
 *
 * This test ensures that the default constructor of dm_radio_t does not throw any exceptions and properly initializes the object,
 * including setting up the internal state of the m_radio_info member. It is important because the proper creation and initialization
 * of the dm_radio_t object is critical for subsequent operations that depend on a valid object state.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 051@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                       | Test Data                                                                            | Expected Result                                                                 | Notes           |
 * | :--------------: | --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------- | --------------- |
 * | 01               | Log the entry into the test.                                                      | No input                                                                           | "Entering DefaultConstructionCreatesDmRadio_tObjectSuccessfully test" printed     | Should be successful |
 * | 02               | Invoke the default constructor of dm_radio_t within EXPECT_NO_THROW to check for exceptions. | input: none, output: dm_radio_t object creation invocation                           | dm_radio_t object created without throwing any exceptions                        | Should Pass     |
 * | 03               | Inspect the internal state (address of m_radio_info) of the created dm_radio_t object.         | input: address of radio.m_radio_info; output: memory address information printed      | Valid address printed for m_radio_info indicating proper initialization           | Should be successful |
 * | 04               | Log the exit from the test.                                                       | No input                                                                           | "Exiting DefaultConstructionCreatesDmRadio_tObjectSuccessfully test" printed      | Should be successful |
 */
TEST(dm_radio_t_Test, DefaultConstructionCreatesDmRadio_tObjectSuccessfully)
{
    std::cout << "Entering DefaultConstructionCreatesDmRadio_tObjectSuccessfully test" << std::endl;
    EXPECT_NO_THROW({
        std::cout << "Invoking dm_radio_t default constructor." << std::endl;
        dm_radio_t radio;
        std::cout << "dm_radio_t object created successfully." << std::endl;
    });
    std::cout << "Exiting DefaultConstructionCreatesDmRadio_tObjectSuccessfully test" << std::endl;
}

/**
 * @brief Verify that the default destructor of dm_radio_t completes without throwing exceptions
 *
 * This test verifies that an instance of dm_radio_t, created using the default constructor, is properly destructed without any exceptions. The test checks if the object's destructor is invoked safely when the instance goes out of scope.
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
 * | Variation / Step | Description                                                           | Test Data                                                                                           | Expected Result                                                           | Notes         |
 * | :--------------: | --------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- | ------------- |
 * | 01               | Invoke the default constructor of dm_radio_t to create an instance    | input: none, output: instance created using default constructor                                     | Instance is created without throwing an exception                        | Should Pass   |
 * | 02               | Exit the scope to trigger the destructor of the dm_radio_t instance     | input: instance going out-of-scope, output: destructor invocation                                   | Destructor is invoked successfully without throwing any exception        | Should Pass   |
 */
TEST(dm_radio_t_Test, Destructor_valid_default) {
    std::cout << "Entering Destructor_valid_default test" << std::endl;
    EXPECT_NO_THROW({
        std::cout << "Invoking default constructor of dm_radio_t" << std::endl;
        {
            dm_radio_t instance;
            std::cout << "dm_radio_t instance created using default constructor" << std::endl;
            std::cout << "Instance internal state -- m_radio_info might be default initialized" << std::endl;
            std::cout << "About to exit scope to trigger destructor for dm_radio_t instance" << std::endl;
        }
        std::cout << "Destructor for dm_radio_t instance invoked when object went out of scope" << std::endl;
    });
    std::cout << "Exiting Destructor_valid_default test" << std::endl;
}
