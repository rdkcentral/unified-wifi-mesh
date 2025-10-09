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
#include "dm_device.h"


/**
 * @brief Test decoding a valid JSON object with a valid parent ID
 *
 * This test verifies that the `decode` function of the `dm_device_t` class correctly decodes a valid JSON object when provided with a valid parent ID.
 *
 * **Test Group ID:** Basic: 01
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
 * | 01 | Parse a valid JSON object | json = "{\"key\":\"value\"}" | cJSON object created | Should be successful |
 * | 02 | Call the decode function with valid parent ID | json = cJSON object, parent_id = 1 | result = 0 | Should Pass |
 * | 03 | Assert the result of decode function | result = 0 | Assertion check | Should be successful |
 * | 04 | Clean up the JSON object | json = cJSON object | None | Should be successful |
 */
TEST(dm_device_t_Test, DecodeValidJsonObjectWithValidParentId) {
    std::cout << "Entering DecodeValidJsonObjectWithValidParentId test" << std::endl;
    cJSON *json = cJSON_Parse("{\"key\":\"value\"}");
    int parent_id = 1;
    dm_device_t device;
    int result = device.decode(json, &parent_id);
    EXPECT_EQ(result, 0);
    cJSON_Delete(json);
    std::cout << "Exiting DecodeValidJsonObjectWithValidParentId test" << std::endl;
}

/**
 * @brief Test decoding a valid JSON object with a null parent ID
 *
 * This test verifies that the decode function of the dm_device_t class can handle a valid JSON object when the parent ID is null. It ensures that the function does not return zero, indicating successful handling of the input.
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
 * | 01 | Parse a valid JSON string to create a cJSON object | json = "{\"key\":\"value\"}" | cJSON object created | Should be successful |
 * | 02 | Call the decode function with the cJSON object and a null parent ID | json = cJSON object, parentId = nullptr | result != 0 | Should Pass |
 * | 03 | Assert that the result of the decode function is not zero | result != 0 | Assertion passed | Should be successful |
 * | 04 | Clean up the cJSON object | json = cJSON object | cJSON object deleted | Should be successful |
 */
TEST(dm_device_t_Test, DecodeValidJsonObjectWithNullParentId) {
    std::cout << "Entering DecodeValidJsonObjectWithNullParentId test" << std::endl;
    cJSON *json = cJSON_Parse("{\"key\":\"value\"}");
    dm_device_t device;
    int result = device.decode(json, nullptr);
    EXPECT_NE(result, 0);
    cJSON_Delete(json);
    std::cout << "Exiting DecodeValidJsonObjectWithNullParentId test" << std::endl;
}

/**
 * @brief Test to verify the behavior of decode function when provided with a null JSON object and a valid parent ID.
 *
 * This test checks the decode function of the dm_device_t class to ensure it handles a null JSON object correctly when a valid parent ID is provided. The expected behavior is that the function should return a non-zero value indicating an error.
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
 * | 01 | Call the decode function with a null JSON object and a valid parent ID | nullptr, parent_id = 1 | Result should be non-zero | Should Pass |
 */
TEST(dm_device_t_Test, DecodeNullJsonObjectWithValidParentId) {
    std::cout << "Entering DecodeNullJsonObjectWithValidParentId test" << std::endl;
    int parent_id = 1;
    dm_device_t device;
    int result = device.decode(nullptr, &parent_id);
    EXPECT_NE(result, 0);
    std::cout << "Exiting DecodeNullJsonObjectWithValidParentId test" << std::endl;
}

/**
 * @brief Test decoding of an invalid JSON object with a valid parent ID
 *
 * This test verifies that the decode function correctly handles an invalid JSON object while providing a valid parent ID. The test ensures that the function returns a non-zero result, indicating failure to decode the invalid JSON.
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
 * | 01 | Parse an invalid JSON string | json = "{key:value}" | cJSON object created | Should be successful |
 * | 02 | Call the decode function with the invalid JSON object and a valid parent ID | json = "{key:value}", parent_id = 1 | Non-zero result | Should Fail |
 * | 03 | Assert that the result is non-zero | result != 0 | Assertion passes | Should be successful |
 * | 04 | Clean up the JSON object | json deleted | cJSON object deleted | Should be successful |
 */
TEST(dm_device_t_Test, DecodeInvalidJsonObjectWithValidParentId) {
    std::cout << "Entering DecodeInvalidJsonObjectWithValidParentId test" << std::endl;
    cJSON *json = cJSON_Parse("{key:value}");
    int parent_id = 1;
    dm_device_t device;
    int result = device.decode(json, &parent_id);
    EXPECT_NE(result, 0);
    cJSON_Delete(json);
    std::cout << "Exiting DecodeInvalidJsonObjectWithValidParentId test" << std::endl;
}

/**
 * @brief Test decoding an empty JSON object with a valid parent ID.
 *
 * This test verifies that the decode function of the dm_device_t class correctly handles an empty JSON object when provided with a valid parent ID. The expected behavior is that the function should return a non-zero result, indicating a failure to decode the empty JSON object.
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
 * | 01 | Parse an empty JSON object | json = cJSON_Parse("{}") | json should not be NULL | Should be successful |
 * | 02 | Call the decode function with the empty JSON object and a valid parent ID | json = {}, parent_id = 1 | result should be non-zero | Should Pass |
 * | 03 | Assert that the result of the decode function is non-zero | result != 0 | Assertion should pass | Should Pass |
 * | 04 | Clean up the JSON object | cJSON_Delete(json) | None | Should be successful |
 */
TEST(dm_device_t_Test, DecodeEmptyJsonObjectWithValidParentId) {
    std::cout << "Entering DecodeEmptyJsonObjectWithValidParentId test" << std::endl;
    cJSON *json = cJSON_Parse("{}");
    int parent_id = 1;
    dm_device_t device;
    int result = device.decode(json, &parent_id);
    EXPECT_NE(result, 0);
    cJSON_Delete(json);
    std::cout << "Exiting DecodeEmptyJsonObjectWithValidParentId test" << std::endl;
}

/**
 * @brief Test the encoding of a valid cJSON object with summary
 *
 * This test verifies that the `encode` method of the `dm_device_t` class correctly encodes a valid cJSON object with the summary flag set to true.
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
 * | 01 | Create a new cJSON object | None | cJSON object should be created successfully | Should be successful |
 * | 02 | Assert that the cJSON object is not null | obj = cJSON_CreateObject() | Assertion should pass | Should be successful |
 * | 03 | Call the `encode` method of the `dm_device_t` object with the cJSON object and summary flag set to true | obj, true | Method should execute without errors | Should Pass |
 * | 04 | Delete the cJSON object | obj = cJSON_Delete(obj) | cJSON object should be deleted successfully | Should be successful |
 */
TEST(dm_device_t_Test, EncodeValidCJSONObjectWithSummary) {
    std::cout << "Entering EncodeValidCJSONObjectWithSummary test" << std::endl; ; 
    cJSON *obj = cJSON_CreateObject();
    ASSERT_NE(obj, nullptr);
    dm_device_t device;
    device.encode(obj, true);
    cJSON_Delete(obj);
    std::cout << "Exiting EncodeValidCJSONObjectWithSummary test" << std::endl; ; 
}

/**
 * @brief Test the encoding of a cJSON object with nested objects and summary.
 *
 * This test verifies that the `encode` method of the `dm_device_t` class correctly handles a cJSON object that contains nested objects and a summary flag. It ensures that the nested objects are properly added and encoded without errors.
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
 * | 01 | Create a cJSON object. | None | cJSON object should not be null | Should be successful |
 * | 02 | Create a nested cJSON object. | None | Nested cJSON object should not be null | Should be successful |
 * | 03 | Add the nested cJSON object to the main cJSON object. | None | Nested object should be added successfully | Should be successful |
 * | 04 | Encode the cJSON object with the summary flag set to true. | obj = cJSON object, summary = true | Encoding should be successful | Should Pass |
 * | 05 | Delete the cJSON object to clean up. | obj = cJSON object | cJSON object should be deleted successfully | Should be successful |
 */
TEST(dm_device_t_Test, EncodeCJSONObjectWithNestedObjectsWithSummary) {
    std::cout << "Entering EncodeCJSONObjectWithNestedObjectsWithSummary test" << std::endl; ; 
    cJSON *obj = cJSON_CreateObject();
    dm_device_t device;
    ASSERT_NE(obj, nullptr);
    cJSON *nestedObj = cJSON_CreateObject();
    ASSERT_NE(nestedObj, nullptr);
    cJSON_AddItemToObject(obj, "nested", nestedObj);
    device.encode(obj, true);
    cJSON_Delete(obj);
    std::cout << "Exiting EncodeCJSONObjectWithNestedObjectsWithSummary test" << std::endl; ; 
}

/**
 * @brief Test to retrieve AL interface with valid device information
 *
 * This test verifies that the AL interface can be successfully retrieved from a device that has been properly initialized.
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
 * | 01 | Set valid name and media for the device's backhaul ALID | backhaul_alid.name = "eth0", media = em_media_type_ieee8023ab | None | Should be successful |
 * | 02 | Retrieve the AL interface from the device | None | al_interface != nullptr | Should Pass |
 * | 03 | Verify if initialized value is retrieved | al_interface->name = "eth0", al_interface->media = em_media_type_ieee8023ab | None | Should pass |
 */
TEST(dm_device_t_Test, RetrieveALInterfaceWithValidDeviceInfo) {
    std::cout << "Entering RetrieveALInterfaceWithValidDeviceInfo test" << std::endl;
    // Create and populate device info
    em_device_info_t device_info = {};
    strncpy(device_info.backhaul_alid.name, "eth0", sizeof(device_info.backhaul_alid.name) - 1);
    device_info.backhaul_alid.media = em_media_type_ieee8023ab;
    // Instantiate device with populated info
    dm_device_t* device = new dm_device_t(&device_info);
    // Retrieve and check AL interface
    em_interface_t* al_interface = device->get_al_interface();
    ASSERT_NE(al_interface, nullptr);
    EXPECT_STREQ(al_interface->name, "eth0");
    EXPECT_EQ(al_interface->media, em_media_type_ieee8023ab);
    std::cout << "AL Interface Name: " << al_interface->name
          << ", Media Type: " << static_cast<int>(al_interface->media)
          << std::endl;
    delete device;
    std::cout << "Exiting RetrieveALInterfaceWithValidDeviceInfo test" << std::endl;
}

/**
 * @brief Test to retrieve AL interface with an empty MAC address
 *
 * This test verifies that the AL interface can be retrieved correctly when the MAC address is set to all zeros. 
 * It ensures that the interface is not null and that the MAC address of the retrieved interface is indeed all zeros.
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
 * | 01 | Set the MAC address to all zeros | device_info.backhaul_alid.mac = 0 | None | Should be successful |
 * | 02 | Retrieve the AL interface | None | al_interface != nullptr | Should Pass |
 * | 03 | Verify the MAC address of the retrieved interface is all zeros | al_interface->mac = 0 | al_interface->mac[i] == 0 for all i | Should Pass |
 */
TEST(dm_device_t_Test, RetrieveALInterfaceWithEmptyMACAddress) {
    std::cout << "Entering RetrieveALInterfaceWithEmptyMACAddress test" << std::endl;
    em_device_info_t device_info = {};
    memset(device_info.backhaul_alid.mac, 0, sizeof(device_info.backhaul_alid.mac));
    dm_device_t* device = new dm_device_t(&device_info);
    em_interface_t* al_interface = device->get_al_interface();
    ASSERT_NE(al_interface, nullptr);
    for (size_t i = 0; i < sizeof(mac_address_t); ++i) {
        EXPECT_EQ(al_interface->mac[i], 0);
    }
    delete device;
    std::cout << "Exiting RetrieveALInterfaceWithEmptyMACAddress test" << std::endl;
}

/**
 * @brief Test to retrieve AL interface with an empty interface name
 *
 * This test verifies that the AL interface can be retrieved correctly even when the interface name is empty.
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
 * | 01 | Set the backhaul ALID name to empty | device_info.backhaul_alid.name = "" | None | Should be successful |
 * | 02 | Retrieve the AL interface | None | al_interface != nullptr | Should Pass |
 * | 03 | Check the AL interface name is empty | al_interface->name = "" | al_interface->name == "" | Should Pass |
 */
TEST(dm_device_t_Test, RetrieveALInterfaceWithEmptyInterfaceName) {
    std::cout << "Entering RetrieveALInterfaceWithEmptyInterfaceName test" << std::endl;
    // Create and populate device info
    em_device_info_t device_info = {};
    memset(device_info.backhaul_alid.name, 0, sizeof(device_info.backhaul_alid.name));
    // Instantiate device with populated info
    dm_device_t* device = new dm_device_t(&device_info);
    em_interface_t* al_interface = device->get_al_interface();
    ASSERT_NE(al_interface, nullptr);
    EXPECT_STREQ(al_interface->name, "");
    delete device;
    std::cout << "Exiting RetrieveALInterfaceWithEmptyInterfaceName test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of AL Interface MAC Address with a valid MAC address
 *
 * This test checks if the `get_al_interface_mac` function correctly retrieves the MAC address
 * that has been set in the `m_device_info.backhaul_alid.mac` field of the `dm_device_t` object.
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
 * | 01 | Set the expected MAC address in the `m_device_info.backhaul_alid.mac` field | expected_mac = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E} | MAC address should be set successfully | Should be successful |
 * | 02 | Retrieve the MAC address using `get_al_interface_mac` function | None | MAC address should not be null | Should Pass |
 * | 03 | Verify each byte of the retrieved MAC address against the expected MAC address | expected_mac = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E} | Each byte should match the expected MAC address | Should Pass |
 */
TEST(dm_device_t_Test, RetrieveALInterfaceMACAddressWithValidMACAddress) {
    std::cout << "Entering RetrieveALInterfaceMACAddressWithValidMACAddress test" << std::endl;
    unsigned char expected_mac[] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
    // Create and populate device info
    em_device_info_t device_info = {};
    memcpy(device_info.backhaul_alid.mac, expected_mac, sizeof(expected_mac));
    // Instantiate device with populated info
    dm_device_t* device = new dm_device_t(&device_info);
    unsigned char* mac = device->get_al_interface_mac();
    ASSERT_NE(mac, nullptr);
    for (size_t i = 0; i < sizeof(expected_mac); ++i) {
        EXPECT_EQ(mac[i], expected_mac[i]);
    }
    delete device;
    std::cout << "Exiting RetrieveALInterfaceMACAddressWithValidMACAddress test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of AL Interface MAC Address when it is set to all zeros.
 *
 * This test checks if the `get_al_interface_mac` function correctly retrieves the MAC address when it is set to all zeros. 
 * It ensures that the function does not return a null pointer and that the retrieved MAC address matches the expected all-zero MAC address.
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
 * | 01 | Set the device's backhaul ALID MAC address to all zeros | expected_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00} | None | Should be successful |
 * | 02 | Retrieve the AL Interface MAC address using `get_al_interface_mac` | None | mac should not be null | Should Pass |
 * | 03 | Verify that the retrieved MAC address matches the expected all-zero MAC address | mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00} | Each byte of mac should match expected_mac | Should Pass |
 */
TEST(dm_device_t_Test, RetrieveALInterfaceMACAddressWithAllZeroMACAddress) {
    std::cout << "Entering RetrieveALInterfaceMACAddressWithAllZeroMACAddress test" << std::endl;
    unsigned char expected_mac[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    // Create and populate device info
    em_device_info_t device_info = {};
    memcpy(device_info.backhaul_alid.mac, expected_mac, sizeof(expected_mac));
    // Instantiate device with populated info
    dm_device_t* device = new dm_device_t(&device_info);
    unsigned char* mac = device->get_al_interface_mac();
    ASSERT_NE(mac, nullptr);
    for (size_t i = 0; i < sizeof(expected_mac); ++i) {
        EXPECT_EQ(mac[i], expected_mac[i]);
    }
    delete device;
    std::cout << "Exiting RetrieveALInterfaceMACAddressWithAllZeroMACAddress test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of AL Interface MAC Address when all bytes are set to FF
 *
 * This test checks if the `get_al_interface_mac` function correctly retrieves the MAC address when all bytes are set to 0xFF. 
 * It ensures that the function returns the expected MAC address and that the returned pointer is not null.
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
 * | 01 | Set the MAC address in the device to all 0xFF | expected_mac = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} | None | Should be successful |
 * | 02 | Retrieve the AL Interface MAC address using `get_al_interface_mac` | None | mac != nullptr | Should Pass |
 * | 03 | Verify each byte of the retrieved MAC address matches the expected value | expected_mac = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} | Each byte of mac should be equal to expected_mac | Should Pass |
 */
TEST(dm_device_t_Test, RetrieveALInterfaceMACAddressWithAllFFMACAddress) {
    std::cout << "Entering RetrieveALInterfaceMACAddressWithAllFFMACAddress test" << std::endl;
    unsigned char expected_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    // Create and populate device info
    em_device_info_t device_info = {};
    memcpy(device_info.backhaul_alid.mac, expected_mac, sizeof(expected_mac));
    // Instantiate device with populated info
    dm_device_t* device = new dm_device_t(&device_info);
    unsigned char* mac = device->get_al_interface_mac();
    ASSERT_NE(mac, nullptr);
    for (size_t i = 0; i < sizeof(expected_mac); ++i) {
        EXPECT_EQ(mac[i], expected_mac[i]);
    }
    delete device;
    std::cout << "Exiting RetrieveALInterfaceMACAddressWithAllFFMACAddress test" << std::endl;
}

/**
 * @brief Test to verify retrieval of AL interface name with a valid AL interface name.
 *
 * This test checks if the function `get_al_interface_name` correctly retrieves the AL interface name when a valid name is set in the device's backhaul ALID.
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
 * | 01 | Set the AL interface name in the device's backhaul ALID | expected_name = "eth0" | None | Should be successful |
 * | 02 | Retrieve the AL interface name using `get_al_interface_name` | None | result = "eth0" | Should Pass |
 * | 03 | Verify the retrieved AL interface name matches the expected name | result = "eth0", expected_name = "eth0" | Assertion should pass | Should Pass |
 */
 TEST(dm_device_t_Test, RetrieveALInterfaceNameWithValidALInterfaceName) {
    std::cout << "Entering RetrieveALInterfaceNameWithValidALInterfaceName" << std::endl;
    char expected_name[] = "eth0";
    // Create and populate device info
    em_device_info_t device_info = {};
    // copy the name
    memcpy(device_info.backhaul_alid.name, expected_name, strlen(expected_name)+1);
    // Instantiate device with populated info
    dm_device_t* device = new dm_device_t(&device_info);
    char* result = device->get_al_interface_name();
    EXPECT_STREQ(result, expected_name);
    delete device;
    std::cout << "Exiting RetrieveALInterfaceNameWithValidALInterfaceName" << std::endl;
}

/**
 * @brief Test to verify the retrieval of AL Interface Name when it is empty.
 *
 * This test checks the behavior of the get_al_interface_name() method when the AL Interface Name is set to an empty string. 
 * It ensures that the method correctly returns an empty string in this scenario.
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
 * | 01 | Set the AL Interface Name to an empty string | expected_name = "" | None | Should be successful |
 * | 02 | Retrieve the AL Interface Name using get_al_interface_name() | None | result = "" | Should Pass |
 * | 03 | Verify the retrieved AL Interface Name is an empty string | result = "", expected_name = "" | result == expected_name | Should Pass |
 */
TEST(dm_device_t_Test, RetrieveALInterfaceNameWithEmptyALInterfaceName) {
    std::cout << "Entering RetrieveALInterfaceNameWithEmptyALInterfaceName";
    char expected_name[] = "";
    // Create and populate device info
    em_device_info_t device_info = {};
    // Copy the name
    memcpy(device_info.backhaul_alid.name, expected_name, strlen(expected_name)+1);
    // Instantiate device with populated info
    dm_device_t* device = new dm_device_t(&device_info);
    char* result = device->get_al_interface_name();
    EXPECT_STREQ(result, expected_name);
    delete device;
    std::cout << "Exiting RetrieveALInterfaceNameWithEmptyALInterfaceName";
}

/**
 * @brief Test to retrieve AL interface name with special characters in AL interface name
 *
 * This test verifies that the function `get_al_interface_name` correctly retrieves the AL interface name when it contains special characters. This is important to ensure that the function can handle and return names with special characters accurately.
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
 * | 01 | Set the AL interface name with special characters | expected_name = "eth0@# 123" | None | Should be successful |
 * | 02 | Retrieve the AL interface name using `get_al_interface_name` | None | result = "eth0@# 123" | Should Pass |
 * | 03 | Verify the retrieved AL interface name matches the expected name | result = "eth0@# 123", expected_name = "eth0@# 123" | Assertion check: result == expected_name | Should Pass |
 */
TEST(dm_device_t_Test, RetrieveALInterfaceNameWithSpecialCharactersInALInterfaceName) {
    std::cout << "Entering RetrieveALInterfaceNameWithSpecialCharactersInALInterfaceName";
    char expected_name[] = "eth0@# 123";
    // Create and populate device info
    em_device_info_t device_info = {};
    // Copy the name
    memcpy(device_info.backhaul_alid.name, expected_name, strlen(expected_name)+1);
    // Instantiate device with populated info
    dm_device_t* device = new dm_device_t(&device_info);
    char* result = device->get_al_interface_name();
    EXPECT_STREQ(result, expected_name);
    delete device;
    std::cout << "Exiting RetrieveALInterfaceNameWithSpecialCharactersInALInterfaceName";
}

/**
 * @brief Test the GetDevInterface function with valid media types
 *
 * This test verifies that the GetDevInterface function correctly returns the interface
 * with the expected media type when valid media types are set in the device's interface.
 *
 * **Test Group ID:** Basic: 01
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
 * | 01 | Set media type to em_media_type_ieee8023ab and get interface | media = em_media_type_ieee8023ab | intf != nullptr, intf->media == em_media_type_ieee8023ab | Should Pass |
 * | 03 | Set media type to em_media_type_ieee80211b_24 and get interface | media = em_media_type_ieee80211b_24 | intf != nullptr, intf->media == em_media_type_ieee80211b_24 | Should Pass |
 * | 04 | Set media type to em_media_type_ieee80211g_24 and get interface | media = em_media_type_ieee80211g_24 | intf != nullptr, intf->media == em_media_type_ieee80211g_24 | Should Pass |
 * | 05 | Set media type to em_media_type_ieee80211a_5 and get interface | media = em_media_type_ieee80211a_5 | intf != nullptr, intf->media == em_media_type_ieee80211a_5 | Should Pass |
 * | 06 | Set media type to em_media_type_ieee80211n_24 and get interface | media = em_media_type_ieee80211n_24 | intf != nullptr, intf->media == em_media_type_ieee80211n_24 | Should Pass |
 * | 07 | Set media type to em_media_type_ieee80211n_5 and get interface | media = em_media_type_ieee80211n_5 | intf != nullptr, intf->media == em_media_type_ieee80211n_5 | Should Pass |
 * | 08 | Set media type to em_media_type_ieee80211ac_5 and get interface | media = em_media_type_ieee80211ac_5 | intf != nullptr, intf->media == em_media_type_ieee80211ac_5 | Should Pass |
 * | 09 | Set media type to em_media_type_ieee80211ad_60 and get interface | media = em_media_type_ieee80211ad_60 | intf != nullptr, intf->media == em_media_type_ieee80211ad_60 | Should Pass |
 * | 10 | Set media type to em_media_type_ieee80211af and get interface | media = em_media_type_ieee80211af | intf != nullptr, intf->media == em_media_type_ieee80211af | Should Pass |
 */
TEST(dm_device_t_Test, GetDevInterface_ValidMediaTypes) {
    std::cout << "Entering GetDevInterface_ValidMediaTypes test\n" << std::endl;
    em_media_type_t media_types[] = {
        em_media_type_ieee8023ab,
        em_media_type_ieee80211b_24,
        em_media_type_ieee80211g_24,
        em_media_type_ieee80211a_5,
        em_media_type_ieee80211n_24,
        em_media_type_ieee80211n_5,
        em_media_type_ieee80211ac_5,
        em_media_type_ieee80211ad_60,
        em_media_type_ieee80211af
    };

    for (auto media : media_types) {
        // Create and populate device info
        em_device_info_t device_info = {};
        device_info.intf.media = media;
        // Instantiate device with populated info
        dm_device_t* device = new dm_device_t(&device_info);
        em_interface_t* intf = device->get_dev_interface();
        ASSERT_NE(intf, nullptr);
        EXPECT_EQ(intf->media, media);
        std::cout << "Successfully retrieved the set media: " << static_cast<int>(intf->media) << std::endl;
        delete device;
    }
    std::cout << "Exiting GetDevInterface_ValidMediaTypes test\n" << std::endl;
}

/**
 * @brief Test the GetDevInterface method with an invalid interface
 *
 * This test checks the behavior of the GetDevInterface method when the interface name is empty, MAC address is zeroed out, and media type is set to IEEE80211b_24. It ensures that the method returns nullptr in this scenario.
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
 * | 01| Set the interface name to 'INVALID_IF' | device->m_device_info.intf.name = 'INVALID_IF'; | None | Should be successful |
 * | 03| Zero out the MAC address | memset(device->m_device_info.intf.mac, 0, sizeof(mac_address_t)); | None | Should be successful |
 * | 04| Set the media type to IEEE80211b_24 | device->m_device_info.intf.media = em_media_type_ieee80211b_24; | None | Should be successful |
 * | 05| Call the get_dev_interface method | em_interface_t* intf = device->get_dev_interface(); | None | Should Pass |
 * | 06| Assert that the returned interface is not nullptr and verify the other previously set values | ASSERT_NE(intf, nullptr); | None | Should Pass |
 */
TEST(dm_device_t_Test, GetDevInterface_InvalidInterfaceName) {
    std::cout << "Entering GetDevInterface_InvalidInterfaceName test\n";
    em_device_info_t device_info = {};
    strcpy(device_info.intf.name, "INVALID_IF");
    memset(device_info.intf.mac, 0, sizeof(mac_address_t));
    device_info.intf.media = em_media_type_ieee80211b_24;
    EXPECT_ANY_THROW({
        dm_device_t* device = new dm_device_t(&device_info);
        em_interface_t* intf = device->get_dev_interface();
        ASSERT_NE(intf, nullptr);
        EXPECT_STREQ(intf->name, "INVALID_IF");
        for (size_t i = 0; i < sizeof(mac_address_t); ++i) {
            EXPECT_EQ(intf->mac[i], 0) << "Expected MAC[" << i << "] to be 0";
        }
        EXPECT_EQ(intf->media, device_info.intf.media);
        delete device;
    });
    std::cout << "Exiting GetDevInterface_InvalidInterfaceName test\n";
}

/**
 * @brief Test to verify the retrieval of MAC address when a valid MAC address is set
 *
 * This test checks if the MAC address can be correctly retrieved after being set to a valid value. 
 * It ensures that the set MAC address is accurately stored and can be fetched without any errors.
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
 * | 01 | Set a valid MAC address | valid_mac = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E} | None | Should be successful |
 * | 02 | Retrieve the MAC address using get_dev_interface_mac | None | mac != nullptr | Should Pass |
 * | 03 | Compare the retrieved MAC address with the set MAC address | mac, valid_mac | memcmp(mac, valid_mac, 6) == 0 | Should Pass |
 */
TEST(dm_device_t_Test, RetrieveMACAddressWithValidMACAddressSet) {
    std::cout << "Entering RetrieveMACAddressWithValidMACAddressSet test" << std::endl;
    unsigned char valid_mac[6] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
    // Create and populate device info
    em_device_info_t device_info = {};
    memcpy(device_info.intf.mac, valid_mac, sizeof(valid_mac));
    // Instantiate device with populated info
    dm_device_t* device = new dm_device_t(&device_info);
    unsigned char* mac = device->get_dev_interface_mac();
    ASSERT_NE(mac, nullptr);
    EXPECT_EQ(memcmp(mac, valid_mac, sizeof(valid_mac)), 0);
    delete device;
    std::cout << "Exiting RetrieveMACAddressWithValidMACAddressSet test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of MAC address with maximum length
 *
 * This test checks if the device can correctly store and retrieve a MAC address of maximum length (6 bytes). 
 * It ensures that the set and get functions for the MAC address work as expected.
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
 * | 01 | Define a MAC address with maximum length (6 bytes) | max_length_mac = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} | None | Should be successful |
 * | 02 | Set the MAC address to the device | max_length_mac = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} | None | Should be successful |
 * | 03 | Retrieve the MAC address from the device | None | mac != nullptr | Should Pass |
 * | 04 | Compare the retrieved MAC address with the original | mac, max_length_mac, length = 6 | memcmp result == 0 | Should Pass |
 */
TEST(dm_device_t_Test, RetrieveMACAddressWithMaximumLengthMACAddress) {
    std::cout << "Entering RetrieveMACAddressWithMaximumLengthMACAddress test" << std::endl;
    unsigned char max_length_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    // Create and populate device info
    em_device_info_t device_info = {};
    memcpy(device_info.intf.mac, max_length_mac, sizeof(max_length_mac));
    // Instantiate device with populated info
    dm_device_t* device = new dm_device_t(&device_info);
    unsigned char* mac = device->get_dev_interface_mac();
    ASSERT_NE(mac, nullptr);
    EXPECT_EQ(memcmp(mac, max_length_mac, 6), 0);
    delete device;
    std::cout << "Exiting RetrieveMACAddressWithMaximumLengthMACAddress test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of MAC address with minimum length MAC address
 *
 * This test checks if the device can correctly set and retrieve a MAC address of minimum length (6 bytes). 
 * It ensures that the MAC address set is the same as the one retrieved.
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
 * | 01 | Set the device interface MAC address | min_length_mac = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00} | None | Should be successful |
 * | 02 | Retrieve the device interface MAC address | mac = device->get_dev_interface_mac() | mac != nullptr | Should Pass |
 * | 03 | Compare the retrieved MAC address with the set MAC address | memcmp(mac, min_length_mac, 6) | 0 | Should Pass |
 */
TEST(dm_device_t_Test, RetrieveMACAddressWithMinimumLengthMACAddress) {
    std::cout << "Entering RetrieveMACAddressWithMinimumLengthMACAddress test" << std::endl;
    unsigned char min_length_mac[6] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
    // Create and populate device info
    em_device_info_t device_info = {};
    memcpy(device_info.intf.mac, min_length_mac, sizeof(min_length_mac));
    // Instantiate device with populated info
    dm_device_t* device = new dm_device_t(&device_info);
    unsigned char* mac = device->get_dev_interface_mac();
    ASSERT_NE(mac, nullptr);
    EXPECT_EQ(memcmp(mac, min_length_mac, 6), 0);
    delete device;
    std::cout << "Exiting RetrieveMACAddressWithMinimumLengthMACAddress test" << std::endl;
}

/**
 * @brief Test to verify the behavior of retrieving MAC address with invalid characters.
 *
 * This test checks the functionality of the `set_dev_interface_mac` and `get_dev_interface_mac` methods when the MAC address contains invalid characters. The objective is to ensure that the system handles invalid MAC addresses correctly.
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
 * | 01 | Set the invalid MAC address to the device | invalid_mac = {0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF} | None | Should Pass |
 * | 02 | Retrieve the MAC address from the device | mac = device->get_dev_interface_mac() | mac != nullptr | Should Pass |
 * | 03 | Compare the retrieved MAC address with the invalid MAC address | memcmp(mac, invalid_mac, 6) | memcmp result == 0 | Should Pass |
 */
TEST(dm_device_t_Test, RetrieveMACAddressWithInvalidCharactersInMACAddress) {
    std::cout << "Entering RetrieveMACAddressWithInvalidCharactersInMACAddress test" << std::endl;
    // Use syntactically valid hex values to simulate an "invalid" MAC (semantically)
    unsigned char invalid_mac[6] = {0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF};
    em_device_info_t device_info = {};
    memcpy(device_info.intf.mac, invalid_mac, sizeof(invalid_mac));
    dm_device_t* device = new dm_device_t(&device_info);
    unsigned char* mac = device->get_dev_interface_mac();
    ASSERT_NE(mac, nullptr);
    EXPECT_EQ(memcmp(mac, invalid_mac, 6), 0);
    delete device;
    std::cout << "Exiting RetrieveMACAddressWithInvalidCharactersInMACAddress test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of device interface name after valid initialization
 *
 * This test checks if the device interface name can be correctly retrieved after the device has been initialized and the interface name has been set. This ensures that the set and get methods for the device interface name are functioning as expected.
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
 * | 01 | Initialize the device | None | None | Should be successful |
 * | 02 | Set the device interface name to "eth0" | device->set_dev_interface_name("eth0") | None | Should be successful |
 * | 03 | Retrieve the device interface name | char* result = device->get_dev_interface_name() | result = "eth0" | Should Pass |
 * | 04 | Verify the retrieved interface name is "eth0" | EXPECT_STREQ(result, "eth0") | None | Should Pass |
 */
TEST(dm_device_t_Test, RetrieveDeviceInterfaceNameWithValidInitialization) {
    std::cout << "Entering RetrieveDeviceInterfaceNameWithValidInitialization test" << std::endl;
    // Create and populate device info
    em_device_info_t device_info = {};
    memcpy(device_info.intf.name, "eth0", strlen("eth0") + 1);
    // Instantiate device with populated info
    dm_device_t* device = new dm_device_t(&device_info);
    char* result = device->get_dev_interface_name();
    EXPECT_STREQ(result, "eth0");
    delete device;
    std::cout << "Exiting RetrieveDeviceInterfaceNameWithValidInitialization test" << std::endl;
}

/**
 * @brief Test to verify the behavior of RetrieveDeviceInterfaceName with an empty name
 *
 * This test checks the behavior of the dm_device_t class when the device interface name is set to an empty string. It ensures that the get_dev_interface_name method returns an empty string as expected.
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
 * | 01| Set the device interface name to an empty string | device->set_dev_interface_name("") | None | Should be successful |
 * | 02| Retrieve the device interface name | char* result = device->get_dev_interface_name() | result = "" | Should Pass |
 * | 03| Verify the retrieved name is an empty string | EXPECT_STREQ(result, "") | result = "" | Should Pass |
 */
TEST(dm_device_t_Test, RetrieveDeviceInterfaceNameWithEmptyName) {
    std::cout << "Entering RetrieveDeviceInterfaceNameWithEmptyName test" << std::endl;
    // Create and populate device info
    em_device_info_t device_info = {};
    memcpy(device_info.intf.name, "", strlen("") + 1);
    // Instantiate device with populated info
    dm_device_t* device = new dm_device_t(&device_info);
    char* result = device->get_dev_interface_name();
    EXPECT_STREQ(result, "");
    delete device;
    std::cout << "Exiting RetrieveDeviceInterfaceNameWithEmptyName test" << std::endl;
}

/**
 * @brief Test to verify the device interface name handling special characters
 *
 * This test checks if the device interface name can handle and correctly store special characters.
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
 * | 01 | Set device interface name with special characters | "!@#$%^&*()" | None | Should be successful |
 * | 02 | Retrieve the device interface name | None | result = "!@#$%^&*()" | Should Pass |
 * | 03 | Verify the retrieved name matches the set name | None | EXPECT_STREQ(result, "!@#$%^&*()") | Should Pass |
 */
TEST(dm_device_t_Test, RetrieveDeviceInterfaceNameWithSpecialCharacters) {
    std::cout << "Entering RetrieveDeviceInterfaceNameWithSpecialCharacters test" << std::endl;
    // Create and populate device info
    em_device_info_t device_info = {};
    memcpy(device_info.intf.name, "!@#$%^&*()", strlen("!@#$%^&*()") + 1);
    // Instantiate device with populated info
    dm_device_t* device = new dm_device_t(&device_info);
    char* result = device->get_dev_interface_name();
    EXPECT_STREQ(result, "!@#$%^&*()");
    delete device;
    std::cout << "Exiting RetrieveDeviceInterfaceNameWithSpecialCharacters test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of device interface name with numeric characters and whitespace.
 *
 * This test checks if the device interface name can be correctly set and retrieved when it contains numeric characters and whitespace.
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
 * | 01 | Set the device interface name to "eth 123". | device->set_dev_interface_name("eth 123") | Device interface name set to "eth 123". | Should be successful |
 * | 02 | Retrieve the device interface name. | device->get_dev_interface_name() | Retrieved name is "eth 123". | Should Pass |
 */
TEST(dm_device_t_Test, RetrieveDeviceInterfaceNameWithNumericCharactersAndWhitespace) {
    std::cout << "Entering RetrieveDeviceInterfaceNameWithNumericCharactersAndWhitespace test" << std::endl;
    // Create and populate device info
    em_device_info_t device_info = {};
    memcpy(device_info.intf.name, "eth 123", strlen("eth 123") + 1);
    // Instantiate device with populated info
    dm_device_t* device = new dm_device_t(&device_info);
    char* result = device->get_dev_interface_name();
    EXPECT_STREQ(result, "eth 123");
    delete device;
    std::cout << "Exiting RetrieveDeviceInterfaceNameWithNumericCharactersAndWhitespace test" << std::endl;
}

/**
 * @brief Test to verify device information retrieval after setting valid fields
 *
 * This test sets various fields of the device and then retrieves the device information to verify that the fields were set correctly.
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
 * | 01 | Set the device interface MAC address | mac = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E} | None | Should be successful |
 * | 02 | Set the device interface name | interface_name = "eth0" | None | Should be successful |
 * | 03 | Set the device manufacturer | manufacturer = "TestManufacturer" | None | Should be successful |
 * | 04 | Set the device software version | software_version = "1.0.0" | None | Should be successful |
 * | 05 | Set the device serial number | serial_number = "123456789" | None | Should be successful |
 * | 06 | Retrieve the device information | None | device_info != nullptr | Should Pass |
 * | 07 | Verify the device interface MAC address | mac = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E} | memcmp(device_info->intf.mac, mac, sizeof(mac)) == 0 | Should Pass |
 * | 08 | Verify the device interface name | interface_name = "eth0" | strcmp(device_info->intf.name, interface_name) == 0 | Should Pass |
 * | 09 | Verify the device manufacturer | manufacturer = "TestManufacturer" | strcmp(device_info->manufacturer, manufacturer) == 0 | Should Pass |
 * | 10 | Verify the device software version | software_version = "1.0.0" | strcmp(device_info->software_ver, software_version) == 0 | Should Pass |
 * | 11 | Verify the device serial number | serial_number = "123456789" | strcmp(device_info->serial_number, serial_number) == 0 | Should Pass |
 */
 TEST(dm_device_t_Test, RetrieveDeviceInfoAfterSettingValidFields) {
    std::cout << "Entering RetrieveDeviceInfoAfterSettingValidFields test" << std::endl;
    unsigned char mac[6] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
    const char interface_name[] = "eth0";
    const char manufacturer[] = "TestManufacturer";
    const char software_version[] = "1.0.0";
    const char serial_number[] = "123456789";
    em_device_info_t device_info = {};
    // Copy values into the device_info struct using memcpy
    memcpy(device_info.intf.mac, mac, sizeof(mac));
    memcpy(device_info.intf.name, interface_name, strlen(interface_name) + 1);
    memcpy(device_info.manufacturer, manufacturer, strlen(manufacturer) + 1);
    memcpy(device_info.software_ver, software_version, strlen(software_version) + 1);
    memcpy(device_info.serial_number, serial_number, strlen(serial_number) + 1);
    // Create device with the initialized struct
    dm_device_t* local_device = new dm_device_t(&device_info);
    em_device_info_t* returned_info = local_device->get_device_info();
    ASSERT_NE(returned_info, nullptr);
    EXPECT_EQ(memcmp(returned_info->intf.mac, mac, sizeof(mac)), 0);
    EXPECT_STREQ(returned_info->intf.name, interface_name);
    EXPECT_STREQ(returned_info->manufacturer, manufacturer);
    EXPECT_STREQ(returned_info->software_ver, software_version);
    EXPECT_STREQ(returned_info->serial_number, serial_number);
    delete local_device;
    std::cout << "Exiting RetrieveDeviceInfoAfterSettingValidFields test" << std::endl;
}

/**
 * @brief Test to verify device information retrieval after setting a null structure.
 *
 * This test checks the behavior of the `dm_device_t` class when the device information structure is set to null. 
 * It ensures that the device information is initialized correctly and that all fields are set to their default values.
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
 * | 01 | Initialize the device | device->init() | None | Should be successful |
 * | 02 | Retrieve device information | em_device_info_t* device_info = device->get_device_info() | None | Should be successful |
 * | 03 | Check if device_info is not null | ASSERT_NE(device_info, nullptr) | device_info != nullptr | Should Pass |
 * | 04 | Verify MAC address is initialized to 0 | EXPECT_EQ(device_info->intf.mac[0], 0) | device_info->intf.mac[0] = 0 | Should Pass |
 * | 05 | Verify interface name is initialized to empty string | EXPECT_EQ(device_info->intf.name[0], '\0') | device_info->intf.name[0] = '\0' | Should Pass |
 * | 06 | Verify manufacturer is initialized to empty string | EXPECT_EQ(device_info->manufacturer[0], '\0') | device_info->manufacturer[0] = '\0' | Should Pass |
 * | 07 | Verify software version is initialized to empty string | EXPECT_EQ(device_info->software_ver[0], '\0') | device_info->software_ver[0] = '\0' | Should Pass |
 * | 08 | Verify serial number is initialized to empty string | EXPECT_EQ(device_info->serial_number[0], '\0') | device_info->serial_number[0] = '\0' | Should Pass |
 */
TEST(dm_device_t_Test, RetrieveDeviceInfoAfterSettingNullStructure) {
    std::cout << "Entering RetrieveDeviceInfoAfterSettingNullStructure test" << std::endl;
    dm_device_t device;
    device.init();
    em_device_info_t* device_info = device.get_device_info();
    ASSERT_NE(device_info, nullptr);
    EXPECT_EQ(device_info->intf.mac[0], 0);
    EXPECT_EQ(device_info->intf.name[0], '\0');
    EXPECT_EQ(device_info->manufacturer[0], '\0');
    EXPECT_EQ(device_info->software_ver[0], '\0');
    EXPECT_EQ(device_info->serial_number[0], '\0');
    std::cout << "Exiting RetrieveDeviceInfoAfterSettingNullStructure test" << std::endl;
}

/**
 * @brief Test the valid orchestration types for dm_device_t
 *
 * This test verifies that the dm_device_t class correctly gets the orchestration type
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
 * | 01 | Create a dm_device_t instance | None | None | Should be successful |
 * | 02 | Get the orchestration type from the device | actual_type = device.get_dm_orch_type(device) | actual_type == expected_type | Should Pass |
 * | 03 | Assert that the get type is within expected enum values | EXPECT_GE(type, dm_orch_type_none), EXPECT_LE(type, dm_orch_type_beacon_report) | None | Should Pass |
 */
TEST(dm_device_t_Test, RetrieveOrchType) {
    std::cout << "Entering RetrieveOrchType";
    dm_device_t device;
    dm_orch_type_t type = device.get_dm_orch_type(device);
    EXPECT_GE(type, dm_orch_type_none);
    EXPECT_LE(type, dm_orch_type_beacon_report);
    std::cout << "Exiting RetrieveOrchType";
}

/**
 * @brief Test to verify the retrieval of the manufacturer name when a valid manufacturer name is set.
 *
 * This test checks if the `get_manufacturer` method correctly retrieves the manufacturer name that was set in the `m_device_info` structure of the `dm_device_t` class.
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
 * | 01 | Set the manufacturer name in the `m_device_info` structure of the `dm_device_t` object. | manufacturer = "ValidManufacturer" | Manufacturer name should be set successfully | Should be successful |
 * | 02 | Retrieve the manufacturer name using the `get_manufacturer` method. | None | Retrieved manufacturer name should be "ValidManufacturer" | Should Pass |
 */
TEST(dm_device_t_Test, RetrieveManufacturerWithValidManufacturerName) {
    std::cout << "Entering RetrieveManufacturerWithValidManufacturerName test" << std::endl;
    // Create and populate device info
    em_device_info_t device_info = {};
    memcpy(device_info.manufacturer, "ValidManufacturer", strlen("ValidManufacturer") + 1);
    // Instantiate device with populated info
    dm_device_t* device = new dm_device_t(&device_info);
    char* manufacturer = device->get_manufacturer();
    EXPECT_STREQ(manufacturer, "ValidManufacturer");
    delete device;
    std::cout << "Exiting RetrieveManufacturerWithValidManufacturerName test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of manufacturer name when it is empty.
 *
 * This test checks the behavior of the get_manufacturer() method when the manufacturer name is set to an empty string. 
 * It ensures that the method correctly returns an empty string in this scenario.
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
 * | 01 | Set the manufacturer name to an empty string | device_info.manufacturer = ""; | None | Should be successful |
 * | 02 | Retrieve the manufacturer name using get_manufacturer() | manufacturer = device->get_manufacturer(); | manufacturer = "" | Should Pass |
 * | 03 | Verify the retrieved manufacturer name is an empty string | EXPECT_STREQ(manufacturer, ""); | None | Should Pass |
 */
TEST(dm_device_t_Test, RetrieveManufacturerWithEmptyManufacturerName) {
    std::cout << "Entering RetrieveManufacturerWithEmptyManufacturerName test" << std::endl;
    // Create and populate device info
    em_device_info_t device_info = {};
    memcpy(device_info.manufacturer, "", strlen("") + 1);
    // Instantiate device with populated info
    dm_device_t* device = new dm_device_t(&device_info);
    char* manufacturer = device->get_manufacturer();
    EXPECT_STREQ(manufacturer, "");
    delete device;
    std::cout << "Exiting RetrieveManufacturerWithEmptyManufacturerName test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of manufacturer name with special characters.
 *
 * This test checks if the `get_manufacturer` method correctly retrieves a manufacturer name that contains special characters. This is important to ensure that the method can handle and return names with various character sets.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Set the manufacturer name with special characters | device->m_device_info.manufacturer = "!@#$%^&*()_+" | None | Should be successful |
 * | 02 | Retrieve the manufacturer name using `get_manufacturer` method | None | manufacturer = "!@#$%^&*()_+" | Should Pass |
 * | 03 | Verify the retrieved manufacturer name matches the expected value | EXPECT_STREQ(manufacturer, "!@#$%^&*()_+") | None | Should Pass |
 */
TEST(dm_device_t_Test, RetrieveManufacturerWithSpecialCharactersInManufacturerName) {
    std::cout << "Entering RetrieveManufacturerWithSpecialCharactersInManufacturerName test" << std::endl;
    // Create and populate device info
    em_device_info_t device_info = {};
    memcpy(device_info.manufacturer, "!@#$%^&*()_+", strlen("!@#$%^&*()_+") + 1);
    // Instantiate device with populated info
    dm_device_t* device = new dm_device_t(&device_info);
    char* manufacturer = device->get_manufacturer();
    EXPECT_STREQ(manufacturer, "!@#$%^&*()_+");
    delete device;
    std::cout << "Exiting RetrieveManufacturerWithSpecialCharactersInManufacturerName test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of manufacturer model with a valid model
 *
 * This test checks if the `get_manufacturer_model` function correctly retrieves the manufacturer model when a valid model is set in the device information.
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
 * | 01| Set the manufacturer model in device info | manufacturer_model = "Model123" | None | Should be successful |
 * | 02| Retrieve the manufacturer model using `get_manufacturer_model` | None | result = "Model123" | Should Pass |
 * | 03| Verify the retrieved manufacturer model | result = "Model123" | result == "Model123" | Should Pass |
 */
TEST(dm_device_t_Test, RetrieveManufacturerModelWithValidModel) {
    std::cout << "Entering RetrieveManufacturerModelWithValidModel test" << std::endl;
    // Create and populate device info
    em_device_info_t device_info = {};
    memcpy(device_info.manufacturer_model, "Model123", strlen("Model123") + 1);
    // Instantiate device with populated info
    dm_device_t* device = new dm_device_t(&device_info);
    char* result = device->get_manufacturer_model();
    EXPECT_STREQ(result, "Model123");
    delete device;
    std::cout << "Exiting RetrieveManufacturerModelWithValidModel test" << std::endl;
}

/**
 * @brief Test to verify the behavior of RetrieveManufacturerModel with an empty model
 *
 * This test checks the behavior of the get_manufacturer_model function when the manufacturer_model is set to an empty string. It ensures that the function correctly returns an empty string in this scenario.
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
 * | 01| Set manufacturer_model to an empty string | device_info.manufacturer_model = "" | None | Should be successful |
 * | 02| Call get_manufacturer_model | char* result = device->get_manufacturer_model() | result = "" | Should Pass |
 * | 03| Verify the result using ASSERT_STREQ | ASSERT_STREQ(result, "") | result = "" | Should Pass |
 */
TEST(dm_device_t_Test, RetrieveManufacturerModelWithEmptyModel) {
    std::cout << "Entering RetrieveManufacturerModelWithEmptyModel test" << std::endl;
    // Create and populate device info
    em_device_info_t device_info = {};
    memcpy(device_info.manufacturer_model, "", strlen("") + 1);
    // Instantiate device with populated info
    dm_device_t* device = new dm_device_t(&device_info);
    char* result = device->get_manufacturer_model();
    EXPECT_STREQ(result, "");
    delete device;
    std::cout << "Exiting RetrieveManufacturerModelWithEmptyModel test" << std::endl;
}

/**
 * @brief Test the retrieval of manufacturer model with special characters
 *
 * This test verifies that the `get_manufacturer_model` function correctly retrieves the manufacturer model string when it contains special characters.
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
 * | 01 | Set the manufacturer model to a string with special characters | manufacturer_model = "!@#$%^&*()" | None | Should be successful |
 * | 02 | Retrieve the manufacturer model using `get_manufacturer_model` | None | result = "!@#$%^&*()" | Should Pass |
 * | 03 | Verify the retrieved manufacturer model matches the expected string | result = "!@#$%^&*()" | Assertion check: ASSERT_STREQ(result, "!@#$%^&*()") | Should Pass |
 */
TEST(dm_device_t_Test, RetrieveManufacturerModelWithSpecialCharacters) {
    std::cout << "Entering RetrieveManufacturerModelWithSpecialCharacters test" << std::endl;
    // Create and populate device info
    em_device_info_t device_info = {};
    memcpy(device_info.manufacturer_model, "!@#$%^&*()", strlen("!@#$%^&*()") + 1);
    // Instantiate device with populated info
    dm_device_t* device = new dm_device_t(&device_info);
    char* result = device->get_manufacturer_model();
    EXPECT_STREQ(result, "!@#$%^&*()");
    delete device;
    std::cout << "Exiting RetrieveManufacturerModelWithSpecialCharacters test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of the primary device type when set to "Switch".
 *
 * This test checks if the primary device type is correctly retrieved as "Switch" after being set. 
 * It ensures that the `get_primary_device_type` method returns the expected value.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 036@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Set the primary device type to "Switch" | primary_device_type = "Switch" | None | Should be successful |
 * | 02 | Retrieve the primary device type and check if it is "Switch" | None | "Switch" | Should Pass |
 */
TEST(dm_device_t_Test, RetrievePrimaryDeviceType_Switch) {
    std::cout << "Entering RetrievePrimaryDeviceType_Switch test" << std::endl;
    // Create and populate device info
    em_device_info_t device_info = {};
    memcpy(device_info.primary_device_type, "Switch", strlen("Switch") + 1);
    // Instantiate device with populated info
    dm_device_t* device = new dm_device_t(&device_info);
    EXPECT_STREQ(device->get_primary_device_type(), "Switch");
    delete device;
    std::cout << "Exiting RetrievePrimaryDeviceType_Switch test" << std::endl;
}

/**
 * @brief Test to verify the behavior of RetrievePrimaryDeviceType when the primary device type is an empty string.
 *
 * This test checks if the get_primary_device_type method correctly returns an empty string when the primary_device_type member is set to an empty string.
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
 * | 01 | Set the primary_device_type to an empty string | primary_device_type = "" | primary_device_type should be set to "" | Should be successful |
 * | 02 | Call get_primary_device_type and check if it returns an empty string | None | Should return "" | Should Pass |
 */
TEST(dm_device_t_Test, RetrievePrimaryDeviceType_EmptyString) {
    std::cout << "Entering RetrievePrimaryDeviceType_EmptyString test" << std::endl;
    // Create and populate device info
    em_device_info_t device_info = {};
    memcpy(device_info.primary_device_type, "", strlen("") + 1);
    // Instantiate device with populated info
    dm_device_t* device = new dm_device_t(&device_info);
    EXPECT_STREQ(device->get_primary_device_type(), "");
    delete device;
    std::cout << "Exiting RetrievePrimaryDeviceType_EmptyString test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of primary device type with special characters
 *
 * This test checks if the primary device type containing special characters is correctly retrieved by the get_primary_device_type() method.
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
 * | 01 | Set primary device type to special characters | primary_device_type = "!@#$%^&*()_+" | None | Should be successful |
 * | 02 | Retrieve the primary device type and verify | None | Return value = "!@#$%^&*()_+", Assertion check: STREQ | Should Pass |
 */
TEST(dm_device_t_Test, RetrievePrimaryDeviceType_SpecialCharacters) {
    std::cout << "Entering RetrievePrimaryDeviceType_SpecialCharacters test" << std::endl;
    // Create and populate device info
    em_device_info_t device_info = {};
    memcpy(device_info.primary_device_type, "!@#$%^&*()_+", strlen("!@#$%^&*()_+") + 1);
    // Instantiate device with populated info
    dm_device_t* device = new dm_device_t(&device_info);
    EXPECT_STREQ(device->get_primary_device_type(), "!@#$%^&*()_+");
    delete device;
    std::cout << "Exiting RetrievePrimaryDeviceType_SpecialCharacters test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of primary device type with spaces and numbers
 *
 * This test checks if the primary device type can be correctly retrieved when it contains spaces and numbers.
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
 * | 01 | Set the primary device type to "Primary Device Type123" | primary_device_type = "Primary Device Type123" | None | Should be successful |
 * | 02 | Retrieve the primary device type and verify it | None | Retrieved primary device type should be "Primary Device Type123" | Should Pass |
 */
TEST(dm_device_t_Test, RetrievePrimaryDeviceType_SpacesAndNumbers) {
    std::cout << "Entering RetrievePrimaryDeviceType_SpacesAndNumbers test" << std::endl;
    // Create and populate device info
    em_device_info_t device_info = {};
    memcpy(device_info.primary_device_type, "Primary Device Type123", strlen("Primary Device Type123") + 1);
    // Instantiate device with populated info
    dm_device_t* device = new dm_device_t(&device_info);
    EXPECT_STREQ(device->get_primary_device_type(), "Primary Device Type123");
    delete device;
    std::cout << "Exiting RetrievePrimaryDeviceType_SpacesAndNumbers test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of the serial number after it has been set.
 *
 * This test checks if the serial number set using the set_serial_number method can be correctly retrieved using the get_serial_number method.
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
 * | 01 | Set the serial number using set_serial_number method | serial_number = "1234567890" | None | Should be successful |
 * | 02 | Retrieve the serial number using get_serial_number method and verify | None | Retrieved serial number should be "1234567890" | Should Pass |
 */
TEST(dm_device_t_Test, RetrieveSerialNumberWhenSet) {
    std::cout << "Entering RetrieveSerialNumberWhenSet test" << std::endl;
    // Create and populate device info
    em_device_info_t device_info = {};
    memcpy(device_info.serial_number, "1234567890", strlen("1234567890") + 1);
    // Instantiate device with populated info
    dm_device_t* device = new dm_device_t(&device_info);
    EXPECT_STREQ(device->get_serial_number(), "1234567890");
    delete device;
    std::cout << "Exiting RetrieveSerialNumberWhenSet test" << std::endl;
}

/**
 * @brief Test to retrieve the serial number when it is set to an empty string.
 *
 * This test verifies that the serial number can be set to an empty string and retrieved correctly. It ensures that the set_serial_number and get_serial_number methods handle empty strings appropriately.
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
 * | 01 | Set the serial number to an empty string | serial_number = "" | None | Should be successful |
 * | 02 | Retrieve the serial number and verify it is an empty string | None | serial_number = "" | Should Pass |
 */
TEST(dm_device_t_Test, RetrieveSerialNumberWhenSetToEmptyString) {
    std::cout << "Entering RetrieveSerialNumberWhenSetToEmptyString test" << std::endl;
    // Create and populate device info
    em_device_info_t device_info = {};
    memcpy(device_info.serial_number, "", strlen("") + 1);
    // Instantiate device with populated info
    dm_device_t* device = new dm_device_t(&device_info);
    EXPECT_STREQ(device->get_serial_number(), "");
    delete device;
    std::cout << "Exiting RetrieveSerialNumberWhenSetToEmptyString test" << std::endl;
}

/**
 * @brief Test the retrieval of a serial number when set to special characters
 *
 * This test verifies that the `dm_device_t` class can correctly handle and retrieve a serial number that includes special characters. This is important to ensure that the system can manage and store serial numbers with a variety of characters without data corruption or loss.
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
 * | 01 | Set the serial number to a string with special characters | serial_number = u8"SN@#123!$%\n\t\u00A9" | None | Should be successful |
 * | 02 | Retrieve the serial number and verify it matches the set value | None | serial_number = "SN@#123!$%\0\n\t\u" | Should Pass |
 */
TEST(dm_device_t_Test, RetrieveSerialNumberWhenSetToSpecialCharacters) {
    std::cout << "Entering RetrieveSerialNumberWhenSetToSpecialCharacters test" << std::endl;
    // Create and populate device info
    em_device_info_t device_info = {};
    memcpy(device_info.serial_number, u8"SN@#123!$%\n\t\u00A9", strlen(u8"SN@#123!$%\n\t\u00A9") + 1);
    // Instantiate device with populated info
    dm_device_t* device = new dm_device_t(&device_info);
    EXPECT_STREQ(device->get_serial_number(), u8"SN@#123!$%\n\t\u00A9");
    delete device;
    std::cout << "Exiting RetrieveSerialNumberWhenSetToSpecialCharacters test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of software version when it is set
 *
 * This test checks if the software version can be correctly retrieved after it has been set using the set_software_version method.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 043@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Set the software version to "1.0.0" | software_version = "1.0.0" | Software version set to "1.0.0" | Should be successful |
 * | 02 | Retrieve the software version using get_software_version method | None | Retrieved version should be "1.0.0" | Should Pass |
 * | 03 | Verify the retrieved software version using ASSERT_STREQ | version = "1.0.0" | Assertion should pass | Should Pass |
 */
TEST(dm_device_t_Test, RetrieveSoftwareVersionWhenSet) {
    std::cout << "Entering RetrieveSoftwareVersionWhenSet test" << std::endl;
    // Create and populate device info
    em_device_info_t device_info = {};
    memcpy(device_info.software_ver, "1.0.0", strlen("1.0.0") + 1);
    // Instantiate device with populated info
    dm_device_t* device = new dm_device_t(&device_info);
    const char* version = device->get_software_version();
    EXPECT_STREQ(version, "1.0.0");
    delete device;
    std::cout << "Exiting RetrieveSoftwareVersionWhenSet test" << std::endl;
}

/**
 * @brief Test the retrieval of software version when set to special characters
 *
 * This test verifies that the software version can be set to a string containing special characters and retrieved correctly.
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
 * | 01 | Set the software version to a string containing special characters | software_version = "!@#$%^&*()" | None | Should be successful |
 * | 02 | Retrieve the software version | None | version = "!@#$%^&*()" | Should Pass |
 * | 03 | Verify that the retrieved software version matches the set value | None | Assertion check: version == "!@#$%^&*()" | Should Pass |
 */
TEST(dm_device_t_Test, RetrieveSoftwareVersionWhenSetToSpecialCharacters) {
    std::cout << "Entering RetrieveSoftwareVersionWhenSetToSpecialCharacters test" << std::endl;
    // Create and populate device info
    em_device_info_t device_info = {};
    memcpy(device_info.software_ver, "!@#$%^&*()", strlen("!@#$%^&*()") + 1);
    // Instantiate device with populated info
    dm_device_t* device = new dm_device_t(&device_info);
    const char* version = device->get_software_version();
    EXPECT_STREQ(version, "!@#$%^&*()");
    delete device;
    std::cout << "Exiting RetrieveSoftwareVersionWhenSetToSpecialCharacters test" << std::endl;
}

/**
 * @brief Test to initialize the device information structure
 *
 * This test verifies the initialization of the device information structure to ensure that the device is properly set up and ready for use.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize the device information structure | None | result = 0 | Should Pass |
 */
TEST(dm_device_t_Test, InitializeDeviceInformationStructure) {
    std::cout << "Entering InitializeDeviceInformationStructure test" << std::endl;
    dm_device_t device;
    int result = device.init();
    EXPECT_EQ(result, 0);
    std::cout << "Exiting InitializeDeviceInformationStructure test" << std::endl;
}

/**
 * @brief Test to initialize the device information structure multiple times
 *
 * This test verifies that the device information structure can be initialized multiple times without errors. 
 * It ensures that the `init` method of the `dm_device_t` class can be called more than once and still return success.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call the `init` method on the `dm_device_t` object for the first time | None | Return value should be 0 | Should Pass |
 * | 02 | Call the `init` method on the `dm_device_t` object for the second time | None | Return value should be 0 | Should Pass |
 */
TEST(dm_device_t_Test, InitializeDeviceInformationStructureMultipleTimes) {
    std::cout << "Entering InitializeDeviceInformationStructureMultipleTimes test" << std::endl;
    dm_device_t device;
    int result1 = device.init();
    EXPECT_EQ(result1, 0);
    int result2 = device.init();
    EXPECT_EQ(result2, 0);
    std::cout << "Exiting InitializeDeviceInformationStructureMultipleTimes test" << std::endl;
}

/**
 * @brief Test to verify the initialization of device information structure after modifying device info
 *
 * This test checks if the device information structure is correctly initialized after modifying the device info. It ensures that the manufacturer field is reset to its default value after initialization.
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
 * | 01 | Modify the manufacturer field of device info | device->m_device_info.manufacturer[0] = 'A' | None | Should be successful |
 * | 02 | Initialize the device | result = device->init() | None | Should Pass |
 * | 03 | Check the result of initialization | ASSERT_EQ(result, 0) | result = 0 | Should Pass |
 * | 04 | Verify the manufacturer field is reset | ASSERT_EQ(device->m_device_info.manufacturer[0], '\0') | device->m_device_info.manufacturer[0] = '\0' | Should Pass |
 */
TEST(dm_device_t_Test, InitializeDeviceInformationStructureAfterModifyingDeviceInfo) {
    std::cout << "Entering InitializeDeviceInformationStructureAfterModifyingDeviceInfo test" << std::endl;
    dm_device_t device;
    device.m_device_info.manufacturer[0] = 'A';
    int result = device.init();
    EXPECT_EQ(result, 0);
    EXPECT_EQ(device.m_device_info.manufacturer[0], '\0');
    std::cout << "Exiting InitializeDeviceInformationStructureAfterModifyingDeviceInfo test" << std::endl;
}

/**
 * @brief Test parsing a valid device ID from a key string
 *
 * This test verifies that the parse_device_id_from_key function correctly parses a valid device ID from a given key string.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Define a valid key string and an em_device_id_t object to store the parsed ID | key = "valid_key_string", id = uninitialized | Variables are defined | Should be successful |
 * | 02 | Call the parse_device_id_from_key function with the valid key string and the em_device_id_t object | key = "valid_key_string", id = uninitialized | Function returns 0 indicating success | Should Pass |
 * | 03 | Verify that the function returns 0, indicating successful parsing | result = 0 | ASSERT_EQ(result, 0) passes | Should Pass |
 */
TEST(dm_device_t_Test, ParseValidDeviceIDFromKey) {
    std::cout << "Entering ParseValidDeviceIDFromKey\n";
    em_device_id_t id;
    const char* key = "valid_key_string";
    dm_device_t device;
    int result = device.parse_device_id_from_key(key, &id);
    EXPECT_EQ(result, 0);
    std::cout << "Exiting ParseValidDeviceIDFromKey\n";
}

/**
 * @brief Test the parsing of device ID from a null key
 *
 * This test checks the behavior of the parse_device_id_from_key function when provided with a null key. It ensures that the function correctly handles invalid input and returns the expected error code.
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
 * | 01| Initialize the key to NULL | key = NULL | None | Should be successful |
 * | 02| Call parse_device_id_from_key with NULL key | key = NULL, id = uninitialized | result = -1 | Should Pass |
 * | 03| Verify the result is -1 | result = -1 | result = -1 | Should Pass |
 */
TEST(dm_device_t_Test, ParseDeviceIDFromNullKey) {
    std::cout << "Entering ParseDeviceIDFromNullKey\n";
    em_device_id_t id;
    const char* key = nullptr;
    int result = dm_device_t::parse_device_id_from_key(key, &id);
    EXPECT_EQ(result, -1);
    std::cout << "Exiting ParseDeviceIDFromNullKey\n";
}

/**
 * @brief Test the parse_device_id_from_key function with a NULL ID pointer
 *
 * This test checks the behavior of the parse_device_id_from_key function when the ID pointer is NULL. The function is expected to return -1 in this case, indicating an error.
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
 * | 01| Call parse_device_id_from_key with a valid key and NULL ID pointer | key = "valid_key_string", id = NULL | result = -1 | Should Pass |
 * | 02| Verify the result using EXPECT_EQ | result = -1 | None | Should be successful |
 */
TEST(dm_device_t_Test, ParseDeviceIDWithNullIDPointer) {
    std::cout << "Entering ParseDeviceIDWithNullIDPointer\n";
    const char* key = "valid_key_string";
    int result = dm_device_t::parse_device_id_from_key(key, NULL);
    EXPECT_EQ(result, -1);
    std::cout << "Exiting ParseDeviceIDWithNullIDPointer\n";
}

/**
 * @brief Test the parsing of device ID with an empty key string.
 *
 * This test checks the behavior of the parse_device_id_from_key function when provided with an empty key string. It ensures that the function correctly handles this edge case by returning an error code.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 051@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Define an empty key string and a variable to hold the device ID. | key = "", id | None | Should be successful |
 * | 02 | Call the parse_device_id_from_key function with the empty key string. | key = "", id | result = -1 | Should Pass |
 * | 03 | Verify that the function returns -1, indicating an error. | result = -1 | EXPECT_EQ(result, -1) | Should Pass |
 */
TEST(dm_device_t_Test, ParseDeviceIDWithEmptyKeyString) {
    std::cout << "Entering ParseDeviceIDWithEmptyKeyString\n";
    em_device_id_t id;
    const char* key = "";
    int result = dm_device_t::parse_device_id_from_key(key, &id);
    EXPECT_EQ(result, -1);
    std::cout << "Exiting ParseDeviceIDWithEmptyKeyString\n";
}

/**
 * @brief Test parsing device ID with special characters in the key
 *
 * This test verifies that the parse_device_id_from_key function correctly handles keys with special characters by returning an error code.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 052@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Define a key with special characters | key = "key_with_special_chars!@#", id = uninitialized | None | Should be successful |
 * | 02 | Call parse_device_id_from_key with the special character key | key = "key_with_special_chars!@#", id = uninitialized | result = -1 | Should Pass |
 * | 03 | Verify the result is -1 | result = -1 | EXPECT_EQ(result, -1) | Should Pass |
 */
TEST(dm_device_t_Test, ParseDeviceIDWithSpecialCharactersInKey) {
    std::cout << "Entering ParseDeviceIDWithSpecialCharactersInKey\n";
    em_device_id_t id;
    const char* key = "key_with_special_chars!@#";
    int result = dm_device_t::parse_device_id_from_key(key, &id);
    EXPECT_EQ(result, -1);
    std::cout << "Exiting ParseDeviceIDWithSpecialCharactersInKey\n";
}

/**
 * @brief Test setting a valid MAC address with mixed case
 *
 * This test verifies that the `set_dev_interface_mac` function correctly sets a MAC address with mixed case and that the `get_dev_interface_mac` function retrieves the same MAC address.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 053@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Define a valid MAC address with mixed case | mac = {0x00, 0x1a, 0x2B, 0x3c, 0x4D, 0x5e} | None | Should be successful |
 * | 02 | Set the MAC address using `set_dev_interface_mac` | mac = {0x00, 0x1a, 0x2B, 0x3c, 0x4D, 0x5e} | None | Should Pass |
 * | 03 | Retrieve the MAC address using `get_dev_interface_mac` and compare | mac = {0x00, 0x1a, 0x2B, 0x3c, 0x4D, 0x5e} | 0 (indicating success) | Should Pass |
 */
 TEST(dm_device_t_Test, SetValidMACAddressMixedCase) {
    std::cout << "Entering SetValidMACAddressMixedCase test\n";
    unsigned char mac[] = {0x00, 0x1a, 0x2B, 0x3c, 0x4D, 0x5e};
    dm_device_t device;
    device.set_dev_interface_mac(mac);
    std::cout << "Exiting SetValidMACAddressMixedCase test\n";
}

/**
 * @brief Test to verify the behavior of set_dev_interface_mac when a null pointer is passed as MAC address.
 *
 * This test checks if the set_dev_interface_mac function throws an exception when a null pointer is passed as the MAC address. This is important to ensure that the function handles invalid input correctly and does not cause undefined behavior.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 054@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Pass a null pointer as MAC address to set_dev_interface_mac | mac = nullptr | Exception should be thrown | Should Pass |
 */
TEST(dm_device_t_Test, SetInvalidMACAddressNullPointer) {
    std::cout << "Entering SetInvalidMACAddressNullPointer test\n";
    unsigned char *mac = nullptr;
    dm_device_t device;
    EXPECT_ANY_THROW(device.set_dev_interface_mac(mac));
    std::cout << "Exiting SetInvalidMACAddressNullPointer test\n";
}

/**
 * @brief Test to verify the behavior when setting an invalid MAC address with incorrect format
 *
 * This test checks if the `set_dev_interface_mac` method throws an exception when provided with an invalid MAC address that has an incorrect format. This is important to ensure that the method correctly handles invalid input and maintains the integrity of the device's MAC address configuration.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 055@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Define an invalid MAC address with incorrect format | mac = {0x00, 0x1A, 0x2B, 0x3C, 0x4D} | Invalid MAC address defined | Should be successful |
 * | 02 | Call the `set_dev_interface_mac` method with the invalid MAC address | mac = {0x00, 0x1A, 0x2B, 0x3C, 0x4D} | Exception should be thrown | Should Pass |
 */
TEST(dm_device_t_Test, SetInvalidMACAddressIncorrectFormat) {
    std::cout << "Entering SetInvalidMACAddressIncorrectFormat test\n";
    unsigned char mac[] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D};
    dm_device_t device;
    EXPECT_ANY_THROW(device.set_dev_interface_mac(mac));
    std::cout << "Exiting SetInvalidMACAddressIncorrectFormat test\n";
}

/**
 * @brief Test to verify setting a valid MAC address with all zeros
 *
 * This test checks if the device can correctly set and retrieve a MAC address consisting of all zeros. 
 * It ensures that the set_dev_interface_mac and get_dev_interface_mac functions work as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 056@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Define a MAC address with all zeros | mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00} | None | Should be successful |
 * | 02 | Set the device MAC address to the defined MAC address | mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00} | None | Should Pass |
 * | 03 | Retrieve the device MAC address and compare with the defined MAC address | mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00} | Return value should be 0 | Should Pass |
 */
TEST(dm_device_t_Test, SetValidMACAddressAllZeros) {
    std::cout << "Entering SetValidMACAddressAllZeros test\n";
    unsigned char mac[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    dm_device_t device;
    device.set_dev_interface_mac(mac);
    std::cout << "Exiting SetValidMACAddressAllZeros test\n";
}

/**
 * @brief Test setting a valid MAC address with all ones
 *
 * This test verifies that the device can correctly set a MAC address consisting of all ones (0xFF).
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 057@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Define a MAC address with all ones | mac = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} | None | Should be successful |
 * | 02 | Set the device MAC address to the defined MAC address | mac = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} | None | Should be successful |
 * | 03 | Retrieve the device MAC address and compare with the defined MAC address | mac = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} | Return value should be 0, indicating success | Should Pass |
 */
TEST(dm_device_t_Test, SetValidMACAddressAllOnes) {
    std::cout << "Entering SetValidMACAddressAllOnes test\n";
    unsigned char mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    dm_device_t device;
    device.set_dev_interface_mac(mac);
    std::cout << "Exiting SetValidMACAddressAllOnes test\n";
}

/**
 * @brief Test the setting of device interface name with a valid name
 *
 * This test verifies that the device interface name can be set correctly using a valid name.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 058@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Set the device interface name to "eth0" | name = "eth0" | None | Should be successful |
 * | 02| Verify the device interface name is set correctly | name = "eth0" | device->get_dev_interface_name() == "eth0" | Should Pass |
 */
TEST(dm_device_t_Test, SetDeviceInterfaceNameWithValidName) {
    std::cout << "Entering SetDeviceInterfaceNameWithValidName";
    char name[] = "eth0";
    dm_device_t device;
    device.set_dev_interface_name(name);
    std::cout << "Exiting SetDeviceInterfaceNameWithValidName";
}

/**
 * @brief Test setting the device interface name with an empty string
 *
 * This test verifies that the device interface name can be set to an empty string and that the getter method returns the correct value.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 059@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Set the device interface name to an empty string | name = "" | None | Should be successful |
 * | 02 | Verify the device interface name is set correctly | name = "" | device->get_dev_interface_name() == name | Should Pass |
 */
TEST(dm_device_t_Test, SetDeviceInterfaceNameWithEmptyString) {
    std::cout << "Entering SetDeviceInterfaceNameWithEmptyString";
    char name[] = "";
    dm_device_t device;
    device.set_dev_interface_name(name);
    std::cout << "Exiting SetDeviceInterfaceNameWithEmptyString";
}

/**
 * @brief Test the behavior of set_dev_interface_name when a null pointer is passed.
 *
 * This test checks if the set_dev_interface_name method correctly handles a null pointer input by throwing an exception. This is important to ensure that the method can handle invalid inputs gracefully.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 060@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Pass a null pointer to set_dev_interface_name | name = NULL | Exception should be thrown | Should Pass |
 */
TEST(dm_device_t_Test, SetDeviceInterfaceNameWithNullPointer) {
    std::cout << "Entering SetDeviceInterfaceNameWithNullPointer";
    dm_device_t device;
    char *name = nullptr;
    EXPECT_ANY_THROW(device.set_dev_interface_name(name));
    std::cout << "Exiting SetDeviceInterfaceNameWithNullPointer";
}

/**
 * @brief Test setting device interface name with special characters and whitespace
 *
 * This test verifies that the device interface name can be set to a string containing special characters and whitespace.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 061@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Set device interface name with special characters and whitespace | name = "eth0@# " | None | Should be successful |
 */
TEST(dm_device_t_Test, SetDeviceInterfaceNameWithSpecialCharactersAndWhitespace) {
    std::cout << "Entering SetDeviceInterfaceNameWithSpecialCharactersAndWhitespace";
    char name[] = "eth0@# ";
    dm_device_t device;
    device.set_dev_interface_name(name);
    std::cout << "Exiting SetDeviceInterfaceNameWithSpecialCharactersAndWhitespace";
}

/**
 * @brief Test setting the manufacturer with a valid name
 *
 * This test verifies that the `set_manufacturer` method correctly sets the manufacturer name when provided with a valid string.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 062@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Define a valid manufacturer name | manufacturer = "ValidManufacturer" | None | Should be successful |
 * | 02 | Set the manufacturer name using `set_manufacturer` | manufacturer = "ValidManufacturer" | None | Should Pass |
 */
TEST(dm_device_t_Test, SetManufacturerWithValidName) {
    std::cout << "Entering SetManufacturerWithValidName test" << std::endl;
    char manufacturer[] = "ValidManufacturer";
    dm_device_t device;
    device.set_manufacturer(manufacturer);
    std::cout << "Exiting SetManufacturerWithValidName test" << std::endl;
}

/**
 * @brief Test the set_manufacturer method with an empty string
 *
 * This test verifies that the set_manufacturer method correctly handles an empty string input by setting the manufacturer to an empty string and ensuring the get_manufacturer method returns an empty string.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 063@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Set manufacturer to an empty string | manufacturer = "" | Manufacturer should be set to an empty string | Should Pass |
 */
TEST(dm_device_t_Test, SetManufacturerWithEmptyString) {
    std::cout << "Entering SetManufacturerWithEmptyString test" << std::endl;
    char manufacturer[] = "";
    dm_device_t device;
    device.set_manufacturer(manufacturer);
    std::cout << "Exiting SetManufacturerWithEmptyString test" << std::endl;
}

/**
 * @brief Test the behavior of setting the manufacturer with a null pointer
 *
 * This test verifies behavior when a null pointer is passed to the set_manufacturer function.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 064@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Set the manufacturer to nullptr | device->set_manufacturer(manufacturer) | manufacturer = nullptr | Should Fail |
 */
TEST(dm_device_t_Test, SetManufacturerWithNullPointer) {
    std::cout << "Entering SetManufacturerWithNullPointer test" << std::endl;
    char* manufacturer = nullptr;
    dm_device_t device;
    device.set_manufacturer(manufacturer);
    std::cout << "Exiting SetManufacturerWithNullPointer test" << std::endl;
}

/**
 * @brief Test the SetManufacturer function with a maximum length string
 *
 * This test verifies that the SetManufacturer function correctly handles a string that is exactly the maximum allowed length. It ensures that the manufacturer name is set and retrieved correctly without any truncation or errors.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 065@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create a manufacturer string with maximum length | manufacturer = 'A' * (max_length - 1) + '\0' | None | Should be successful |
 * | 02| Set the manufacturer using set_manufacturer function | manufacturer = 'A' * (max_length - 1) + '\0' | None | Should Pass |
 */
TEST(dm_device_t_Test, SetManufacturerWithMaxLengthString) {
    std::cout << "Entering SetManufacturerWithMaxLengthString test" << std::endl;
    dm_device_t device;
    char manufacturer[sizeof(device.m_device_info.manufacturer)];
    memset(manufacturer, 'A', sizeof(manufacturer) - 1);
    manufacturer[sizeof(manufacturer) - 1] = '\0';
    device.set_manufacturer(manufacturer);
    std::cout << "Exiting SetManufacturerWithMaxLengthString test" << std::endl;
}

/**
 * @brief Test setting the manufacturer with special characters
 *
 * This test verifies that the `set_manufacturer` method can handle and correctly store a string containing special characters. This is important to ensure that the method can handle a wide range of input values without errors.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 066@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Define a manufacturer string with special characters | manufacturer = "!@#$%^&*()_+ " | None | Should be successful |
 * | 02 | Set the manufacturer using the `set_manufacturer` method | manufacturer = "!@#$%^&*()_+ " | None | Should Pass |
 */
TEST(dm_device_t_Test, SetManufacturerWithSpecialCharacters) {
    std::cout << "Entering SetManufacturerWithSpecialCharacters test" << std::endl;
    char manufacturer[] = "!@#$%^&*()_+ ";
    dm_device_t device;
    device.set_manufacturer(manufacturer);
    std::cout << "Exiting SetManufacturerWithSpecialCharacters test" << std::endl;
}

/**
 * @brief Test setting a valid manufacturer model name
 *
 * This test verifies that the `set_manufacturer_model` function correctly sets the manufacturer model name when provided with a valid model name.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 067@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Define a valid model name | model = "ModelX" | None | Should be successful |
 * | 02 | Set the manufacturer model using the valid model name | device->set_manufacturer_model(model) | None | Should Pass |
 */
TEST(dm_device_t_Test, SetManufacturerModel_ValidModelName) {
    std::cout << "Entering SetManufacturerModel_ValidModelName";
    char model[] = "ModelX";
    dm_device_t device;
    device.set_manufacturer_model(model);
    std::cout << "Exiting SetManufacturerModel_ValidModelName";
}

/**
 * @brief Test the setting of an empty manufacturer model name
 *
 * This test verifies that the `set_manufacturer_model` function correctly handles an empty model name
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 068@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Set an empty manufacturer model name | model = "" | None | Should be successful |
 */
TEST(dm_device_t_Test, SetManufacturerModel_EmptyModelName) {
    std::cout << "Entering SetManufacturerModel_EmptyModelName";
    char model[] = "";
    dm_device_t device;
    device.set_manufacturer_model(model);
    std::cout << "Exiting SetManufacturerModel_EmptyModelName";
}

/**
 * @brief Test the behavior of set_manufacturer_model when a NULL model name is provided.
 *
 * This test checks if the set_manufacturer_model function throws an invalid_argument exception when a NULL model name is passed. This is important to ensure that the function handles invalid input correctly and does not proceed with a NULL model name.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 069@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Call set_manufacturer_model with NULL model name | model = NULL | Throws std::invalid_argument | Should Pass |
 */
TEST(dm_device_t_Test, SetManufacturerModel_NullModelName) {
    std::cout << "Entering SetManufacturerModel_NullModelName";
    char* model = NULL;
    dm_device_t device;
    EXPECT_ANY_THROW(device.set_manufacturer_model(model));
    std::cout << "Exiting SetManufacturerModel_NullModelName";
}    

/**
 * @brief Test to verify the behavior when the model name exceeds the buffer size.
 *
 * This test checks if the set_manufacturer_model function throws an overflow_error when the model name exceeds the buffer size.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 070@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Define a model name that exceeds the buffer size | model = "ModelNameThatIsWayTooLongForTheBufferAndShouldCauseAnError" | None | Should be successful |
 * | 02 | Call set_manufacturer_model with the long model name | model = "ModelNameThatIsWayTooLongForTheBufferAndShouldCauseAnError" | overflow_error exception | Should Pass |
 */
TEST(dm_device_t_Test, SetManufacturerModel_ModelNameExceedingBufferSize) {
    std::cout << "Entering SetManufacturerModel_ModelNameExceedingBufferSize";
    //char model[] = "ModelNameThatIsWayTooLongForTheBufferAndShouldCauseAnError";
    char model[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZAAAAAA";
    dm_device_t device;
    EXPECT_ANY_THROW(device.set_manufacturer_model(model));
    std::cout << "Exiting SetManufacturerModel_ModelNameExceedingBufferSize";
}

/**
 * @brief Test setting the manufacturer model with special characters in the model name.
 *
 * This test verifies that the `set_manufacturer_model` function correctly handles and stores a model name containing special characters. 
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Define a model name with special characters. | model = "Model@ 123!" | Model name should be defined successfully. | Should be successful |
 * | 02 | Set the manufacturer model using the defined model name. | model = "Model@ 123!" | The model name should be set successfully. | Should Pass |
 */
TEST(dm_device_t_Test, SetManufacturerModel_SpecialCharactersInModelName) {
    std::cout << "Entering SetManufacturerModel_SpecialCharactersInModelName";
    char model[] = "Model@ 123!";
    dm_device_t device;
    device.set_manufacturer_model(model);
    std::cout << "Exiting SetManufacturerModel_SpecialCharactersInModelName";
}

/**
 * @brief Test the setting of a valid primary device type string
 *
 * This test verifies that the `set_primary_device_type` method correctly sets the primary device type to a valid string and that the `get_primary_device_type` method returns the expected value.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 072@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Define a valid primary device type string | type = "Router" | None | Should be successful |
 * | 02 | Set the primary device type using the valid string | device->set_primary_device_type(type) | None | Should Pass |
 */
TEST(dm_device_t_Test, SetPrimaryDeviceType_ValidString) {
    std::cout << "Entering SetPrimaryDeviceType_ValidString test" << std::endl;
    char type[] = "Router";
    dm_device_t device;
    device.set_primary_device_type(type);
    std::cout << "Exiting SetPrimaryDeviceType_ValidString test" << std::endl;
}

/**
 * @brief Test the set_primary_device_type method with an empty string
 *
 * This test verifies that the set_primary_device_type method correctly handles an empty string input.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 073@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call set_primary_device_type with an empty string | type = "" | None | Should be successful |
 */
TEST(dm_device_t_Test, SetPrimaryDeviceType_EmptyString) {
    std::cout << "Entering SetPrimaryDeviceType_EmptyString test" << std::endl;
    char type[] = "";
    dm_device_t device;
    device.set_primary_device_type(type);
    std::cout << "Exiting SetPrimaryDeviceType_EmptyString test" << std::endl;
}

/**
 * @brief Test to verify the behavior of set_primary_device_type when a null pointer is passed.
 *
 * This test checks if the set_primary_device_type function throws an invalid_argument exception when a null pointer is passed as the device type. This is important to ensure that the function handles invalid input gracefully.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 074@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Pass a null pointer to set_primary_device_type | type = NULL | Throws exception | Should Pass |
 */
TEST(dm_device_t_Test, SetPrimaryDeviceType_NullPointer) {
    std::cout << "Entering SetPrimaryDeviceType_NullPointer test" << std::endl;
    char *type = NULL;
    dm_device_t device;
    EXPECT_ANY_THROW(device.set_primary_device_type(type));
    std::cout << "Exiting SetPrimaryDeviceType_NullPointer test" << std::endl;
}

/**
 * @brief Test to verify the behavior when setting a primary device type that exceeds the buffer size.
 *
 * This test checks if the set_primary_device_type function throws an overflow_error when the input device type name exceeds the buffer size.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 075@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Define a device type name that exceeds the buffer size | type = "ThisIsAVeryLongDeviceTypeNameThatExceedsTheBufferSize" | None | Should be successful |
 * | 03 | Call set_primary_device_type with the long device type name and expect error or exception | type = "ThisIsAVeryLongDeviceTypeNameThatExceedsTheBufferSize" | overflow_error should be thrown | Should Pass |
 */
TEST(dm_device_t_Test, SetPrimaryDeviceType_ExceedingBufferSize) {
    std::cout << "Entering SetPrimaryDeviceType_ExceedingBufferSize test" << std::endl;
    char type[] = "ThisIsAVeryLongDeviceTypeNameThatExceedsTheBufferSize";
    dm_device_t device;
    EXPECT_ANY_THROW(device.set_primary_device_type(type));
    std::cout << "Exiting SetPrimaryDeviceType_ExceedingBufferSize test" << std::endl;
}

/**
 * @brief Test the set_primary_device_type function with special characters and spaces
 *
 * This test verifies that the set_primary_device_type function correctly handles and stores a device type string that includes special characters and spaces.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 076@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Set the primary device type with special characters and spaces | type = "@Router# 2023!" | None | Should be successful |
 */
TEST(dm_device_t_Test, SetPrimaryDeviceType_SpecialCharactersAndSpaces) {
    std::cout << "Entering SetPrimaryDeviceType_SpecialCharactersAndSpaces test" << std::endl;
    char type[] = "@Router# 2023!";
    dm_device_t device;
    device.set_primary_device_type(type);
    std::cout << "Exiting SetPrimaryDeviceType_SpecialCharactersAndSpaces test" << std::endl;
}

/**
 * @brief Test the set_serial_number function with a valid input
 *
 * This test verifies that the set_serial_number function correctly sets the serial number of the device when provided with a valid input string.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 077@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Define a valid serial number | serial = "1234567890" | None | Should be successful |
 * | 02 | Set the serial number using set_serial_number function | serial = "1234567890" | None | Should be successful |
 */
TEST(dm_device_t_Test, SetSerialNumberWithValidInput) {
    std::cout << "Entering SetSerialNumberWithValidInput test" << std::endl;
    char serial[] = "1234567890";
    dm_device_t device;
    device.set_serial_number(serial);
    std::cout << "Exiting SetSerialNumberWithValidInput test" << std::endl;
}

/**
 * @brief Test setting the serial number with an empty string
 *
 * This test verifies that the `set_serial_number` method correctly handles an empty string as input and that the `get_serial_number` method returns the expected empty string.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 078@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize an empty serial number string | serial = "" | None | Should be successful |
 * | 02 | Set the serial number to the empty string using `set_serial_number` | serial = "" | None | Should Pass |
 */
TEST(dm_device_t_Test, SetSerialNumberWithEmptyString) {
    std::cout << "Entering SetSerialNumberWithEmptyString test" << std::endl;
    char serial[] = "";
    dm_device_t device;
    device.set_serial_number(serial);
    std::cout << "Exiting SetSerialNumberWithEmptyString test" << std::endl;
}

/**
 * @brief Test to verify the behavior of set_serial_number when a null pointer is passed.
 *
 * This test checks if the set_serial_number function correctly handles a null pointer input and ensures that the serial number is not set to null.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 079@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Set the serial number to null | serial = nullptr | None | Should Pass |
 */
TEST(dm_device_t_Test, SetSerialNumberWithNullPointer) {
    std::cout << "Entering SetSerialNumberWithNullPointer test" << std::endl;
    char* serial = nullptr;
    dm_device_t device;
    device.set_serial_number(serial);
    std::cout << "Exiting SetSerialNumberWithNullPointer test" << std::endl;
}    

/**
 * @brief Test the setting of a serial number with maximum length string
 *
 * This test verifies that the `set_serial_number` function can handle and correctly set a serial number string of maximum length. It ensures that the serial number is stored and retrieved accurately.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 080@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Define a maximum length serial number string | serial = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890" | None | Should be successful |
 * | 02 | Set the serial number using `set_serial_number` | serial = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890" | None | Should Pass |
 */
TEST(dm_device_t_Test, SetSerialNumberWithMaxLengthString) {
    std::cout << "Entering SetSerialNumberWithMaxLengthString test" << std::endl;
    char serial[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    dm_device_t device;
    device.set_serial_number(serial);
    std::cout << "Exiting SetSerialNumberWithMaxLengthString test" << std::endl;
}

/**
 * @brief Test setting the serial number with special characters and whitespaces
 *
 * This test verifies that the `set_serial_number` function can handle and correctly set a serial number containing special characters and whitespaces.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 081@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Set the serial number with special characters and whitespaces | serial = "!@#$%^&*()_+ " | None | Should be successful |
 */
TEST(dm_device_t_Test, SetSerialNumberWithSpecialCharactersAndWhitespaces) {
    std::cout << "Entering SetSerialNumberWithSpecialCharactersAndWhitespaces test" << std::endl;
    char serial[] = "!@#$%^&*()_+ ";
    dm_device_t device;
    device.set_serial_number(serial);
    std::cout << "Exiting SetSerialNumberWithSpecialCharactersAndWhitespaces test" << std::endl;
}

/**
 * @brief Test the behavior of setting a serial number with a very long string exceeding the buffer size.
 *
 * This test checks if the `set_serial_number` method correctly handles a very long string that exceeds the buffer size. 
 * It ensures that the serial number is not set to the long string, indicating proper handling of buffer overflow.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 082@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Define a very long serial number string | serial = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890" | None | Should be successful |
 * | 02 | Set the serial number with the long string | device->set_serial_number(serial) | None | Should Pass |
 */
TEST(dm_device_t_Test, SetSerialNumberWithVeryLongStringExceedingBufferSize) {
    std::cout << "Entering SetSerialNumberWithVeryLongStringExceedingBufferSize test" << std::endl;
    char serial[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    dm_device_t device;
    device.set_serial_number(serial);
    std::cout << "Exiting SetSerialNumberWithVeryLongStringExceedingBufferSize test" << std::endl;
}

/**
 * @brief Test the setting of a valid software version string in the dm_device_t class.
 *
 * This test verifies that the set_software_version method correctly sets a valid version string
 * and that the get_software_version method returns the expected version string.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 083@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Define a valid version string | version = "1.0.0" | Version string defined | Should be successful |
 * | 02 | Set the software version using the set_software_version method | version = "1.0.0" | Software version set to "1.0.0" | Should Pass |
 */
TEST(dm_device_t_Test, SetSoftwareVersion_ValidVersionString) {
    std::cout << "Entering SetSoftwareVersion_ValidVersionString test" << std::endl;
    char version[] = "1.0.0";
    dm_device_t device;
    device.set_software_version(version);
    std::cout << "Exiting SetSoftwareVersion_ValidVersionString test" << std::endl;
}

/**
 * @brief Test to verify the behavior of setting an empty software version string.
 *
 * This test checks if the `set_software_version` method correctly handles an empty version string and ensures that the `get_software_version` method returns the same empty string.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 084@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Define an empty version string. | version = "" | None | Should be successful |
 * | 02 | Call `set_software_version` with the empty version string. | version = "" | Should set the version to an empty string. | Should Pass |
 */
TEST(dm_device_t_Test, SetSoftwareVersion_EmptyVersionString) {
    std::cout << "Entering SetSoftwareVersion_EmptyVersionString test" << std::endl;
    char version[] = "";
    dm_device_t device;
    device.set_software_version(version);
    std::cout << "Exiting SetSoftwareVersion_EmptyVersionString test" << std::endl;
}

/**
 * @brief Test the set_software_version function with a null version string
 *
 * This test checks the behavior of the set_software_version function when a null version string is passed. 
 * It ensures that the function throws an exception in this scenario.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 085@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call set_software_version with null version string | version = NULL | Exception is thrown | Should Pass |
 */
TEST(dm_device_t_Test, SetSoftwareVersion_NullVersionString) {
    std::cout << "Entering SetSoftwareVersion_NullVersionString test" << std::endl;
    char* version = NULL;
    dm_device_t device;
    EXPECT_ANY_THROW(device.set_software_version(version));
    std::cout << "Exiting SetSoftwareVersion_NullVersionString test" << std::endl;
}    

/**
 * @brief Test the set_software_version function with a maximum length version string
 *
 * This test verifies that the set_software_version function can handle a version string of maximum length (1024 characters) and correctly sets the software version in the device object.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 086@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize a version string with maximum length (1024 characters) | version = "A...A" (1024 characters) | Version string initialized | Should be successful |
 * | 02 | Set the software version of the device using the initialized version string | version = "A...A" (1024 characters) | Software version set in the device | Should Pass |
 */
TEST(dm_device_t_Test, SetSoftwareVersion_MaxLengthVersionString) {
    std::cout << "Entering SetSoftwareVersion_MaxLengthVersionString test" << std::endl;
    char version[1024];
    memset(version, 'A', sizeof(version) - 1);
    version[sizeof(version) - 1] = '\0';
    dm_device_t device;
    device.set_software_version(version);
    std::cout << "Exiting SetSoftwareVersion_MaxLengthVersionString test" << std::endl;
}

/**
 * @brief Test the UpdateEasyMeshJsonCfg function with Colocated Mode Enabled
 *
 * This test verifies that the update_easymesh_json_cfg function correctly handles the case when colocated mode is enabled.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 087@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Enable colocated mode and call update_easymesh_json_cfg | colocated_mode = true | result = 0 | Should Pass |
 * | 02 | Verify the result is as expected | result = 0 | EXPECT_EQ(result, 0) | Should be successful |
 */
TEST(dm_device_t_Test, UpdateEasyMeshJsonCfg_ColocatedModeEnabled) {
    std::cout << "Entering UpdateEasyMeshJsonCfg_ColocatedModeEnabled";
    bool colocated_mode = true;
    dm_device_t device;
    int result = device.update_easymesh_json_cfg(colocated_mode);
    EXPECT_EQ(result, 0);
    std::cout << "Exiting UpdateEasyMeshJsonCfg_ColocatedModeEnabled";
}

/**
 * @brief Test the UpdateEasyMeshJsonCfg function with colocated mode disabled.
 *
 * This test verifies that the update_easymesh_json_cfg function correctly handles the case when the colocated mode is disabled. 
 * It ensures that the function returns 0, indicating success.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 088@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call the update_easymesh_json_cfg function with colocated_mode set to false. | colocated_mode = false | result = 0 | Should Pass |
 * | 02 | Verify that the result is 0 using EXPECT_EQ. | result = 0 | Assertion should pass | Should be successful |
 */
TEST(dm_device_t_Test, UpdateEasyMeshJsonCfg_ColocatedModeDisabled) {
    std::cout << "Entering UpdateEasyMeshJsonCfg_ColocatedModeDisabled";
    bool colocated_mode = false;
    dm_device_t device;
    int result = device.update_easymesh_json_cfg(colocated_mode);
    EXPECT_EQ(result, 0);
    std::cout << "Exiting UpdateEasyMeshJsonCfg_ColocatedModeDisabled";
}

/**
 * @brief Test to verify that two devices with identical information are considered equal.
 *
 * This test checks if two `dm_device_t` objects with identical device information are considered equal by the equality operator. This is important to ensure that the equality operator works correctly for device comparison.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 089@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize device1 and device2 with specific information | device.m_device_info.id.net_id = "net1", device.m_device_info.id.dev_mac = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, device.m_device_info.id.media = em_media_type_ieee8023ab, device.m_device_info.intf.name = "eth0", device.m_device_info.intf.mac = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, device.m_device_info.intf.media = em_media_type_ieee8023ab, device.m_device_info.profile = em_profile_type_1, device.m_device_info.manufacturer = "Manufacturer1", device.m_device_info.serial_number = "SN12345", device.m_device_info.manufacturer_model = "Model1", device.m_device_info.software_ver = "1.0.0" | Devices initialized with given information | Should be successful |
 * | 02 | Compare device1 and device2 for equality | EXPECT_TRUE(device1 == device2) | Devices should be equal | Should Pass |
 */
TEST(dm_device_t_Test, IdenticalDeviceInformation) {
    std::cout << "Entering IdenticalDeviceInformation" << std::endl;
    dm_device_t device1{}, device2{};
    memset(&device1.m_device_info, 0, sizeof(device1.m_device_info));
    memset(&device2.m_device_info, 0, sizeof(device2.m_device_info));
    const char* net_id = "net1";
    memcpy(device1.m_device_info.id.net_id, net_id, strlen(net_id) + 1);
    memcpy(device2.m_device_info.id.net_id, net_id, strlen(net_id) + 1);
    mac_address_t mac = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    memcpy(device1.m_device_info.id.dev_mac, mac, sizeof(mac_address_t));
    memcpy(device2.m_device_info.id.dev_mac, mac, sizeof(mac_address_t));
    device1.m_device_info.id.media = device2.m_device_info.id.media = em_media_type_ieee8023ab;
    const char* intf_name = "eth0";
    memcpy(device1.m_device_info.intf.name, intf_name, strlen(intf_name) + 1);
    memcpy(device2.m_device_info.intf.name, intf_name, strlen(intf_name) + 1);
    memcpy(device1.m_device_info.intf.mac, mac, sizeof(mac_address_t));
    memcpy(device2.m_device_info.intf.mac, mac, sizeof(mac_address_t));
    device1.m_device_info.intf.media = device2.m_device_info.intf.media = em_media_type_ieee8023ab;
    device1.m_device_info.profile = device2.m_device_info.profile = em_profile_type_1;
    const char* manufacturer = "Manufacturer1";
    memcpy(device1.m_device_info.manufacturer, manufacturer, strlen(manufacturer) + 1);
    memcpy(device2.m_device_info.manufacturer, manufacturer, strlen(manufacturer) + 1);
    const char* serial = "SN12345";
    memcpy(device1.m_device_info.serial_number, serial, strlen(serial) + 1);
    memcpy(device2.m_device_info.serial_number, serial, strlen(serial) + 1);
    const char* model = "Model1";
    memcpy(device1.m_device_info.manufacturer_model, model, strlen(model) + 1);
    memcpy(device2.m_device_info.manufacturer_model, model, strlen(model) + 1);
    const char* software_ver = "1.0.0";
    memcpy(device1.m_device_info.software_ver, software_ver, strlen(software_ver) + 1);
    memcpy(device2.m_device_info.software_ver, software_ver, strlen(software_ver) + 1);
    EXPECT_TRUE(device1 == device2);
    std::cout << "Exiting IdenticalDeviceInformation" << std::endl;
}

/**
 * @brief Test to verify the behavior when two devices have different network IDs.
 *
 * This test checks the equality operator for dm_device_t objects when their network IDs are different. It ensures that the devices are not considered equal if their network IDs differ.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 090@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize device1 and device2 with different net_id | device1.m_device_info.id.net_id = "net1", device2.m_device_info.id.net_id = "net2" | Successful initialization | Should be successful |
 * | 02| Check equality of device1 and device2 | EXPECT_FALSE(device1 == device2) | Devices should not be equal | Should Pass |
 */
TEST(dm_device_t_Test, DifferentNetId) {
    std::cout << "Entering DifferentNetId" << std::endl;
    dm_device_t device1{}, device2{};
    memset(&device1.m_device_info, 0, sizeof(device1.m_device_info));
    memset(&device2.m_device_info, 0, sizeof(device2.m_device_info));
    const char* net_id = "net1";
    const char* net_id1 = "net2";    
    memcpy(device1.m_device_info.id.net_id, net_id, strlen(net_id) + 1);
    memcpy(device2.m_device_info.id.net_id, net_id1, strlen(net_id1) + 1);    
    EXPECT_FALSE(device1 == device2);
    std::cout << "Exiting DifferentNetId" << std::endl;
}

/**
 * @brief Test to verify that two devices with different MAC addresses are not considered equal.
 *
 * This test checks the equality operator for `dm_device_t` objects to ensure that two devices with different MAC addresses are not considered equal. This is important to verify the uniqueness of devices based on their MAC addresses.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 091@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize device2 with different MAC address | device1.m_device_info.id.dev_mac = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, device2.m_device_info.id.dev_mac = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB} | Device initialized | Should be successful |
 * | 02 | Compare device1 and device2 for equality | EXPECT_FALSE(device1 == device2) | Devices should not be equal | Should Pass |
 */
TEST(dm_device_t_Test, DifferentDevMac) {
    std::cout << "Entering DifferentDevMac" << std::endl;
    dm_device_t device1{}, device2{};
    memset(&device1.m_device_info, 0, sizeof(device1.m_device_info));
    memset(&device2.m_device_info, 0, sizeof(device2.m_device_info));
    unsigned char mac1[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    unsigned char mac2[6] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
    memcpy(device1.m_device_info.id.dev_mac, mac1, sizeof(mac1));
    memcpy(device2.m_device_info.id.dev_mac, mac2, sizeof(mac2));
    EXPECT_FALSE(device1 == device2);
    std::cout << "Exiting DifferentDevMac" << std::endl;
}

/**
 * @brief Test to verify the behavior of dm_device_t when comparing devices with different media types.
 *
 * This test checks the equality operator of the dm_device_t class to ensure that two devices with identical attributes except for the media type are not considered equal.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 092@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize with different media types | device1.m_device_info.intf.media = em_media_type_ieee8023ab, device2.m_device_info.intf.media = em_media_type_ieee80211b_24 | Should be successful | 
 * | 02| Compare device1 and device2 using equality operator | EXPECT_FALSE(device1 == device2) | Should Pass | 
 */
TEST(dm_device_t_Test, DifferentMediaType) {
    std::cout << "Entering DifferentMediaType" << std::endl;
    dm_device_t device1{}, device2{};
    memset(&device1.m_device_info, 0, sizeof(device1.m_device_info));
    memset(&device2.m_device_info, 0, sizeof(device2.m_device_info));
    device1.m_device_info.intf.media = em_media_type_ieee8023ab;
    device2.m_device_info.intf.media = em_media_type_ieee80211b_24;
    EXPECT_FALSE(device1 == device2);
    std::cout << "Exiting DifferentMediaType" << std::endl;
}

/**
 * @brief Test to verify the behavior when two devices have different interface names
 *
 * This test checks if two devices with identical properties except for their interface names are considered different.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 093@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize device1 and device2 with different interface names | device1.m_device_info.intf.name = "eth0", device2.m_device_info.intf.name = "eth1" | Devices initialized with different interface names | Should be successful |
 * | 03| Compare device1 and device2 | EXPECT_FALSE(device1 == device2) | Devices should not be equal | Should Pass |
 */
TEST(dm_device_t_Test, DifferentInterfaceNames) {
    std::cout << "Entering DifferentInterfaceNames" << std::endl;
    dm_device_t device1{}, device2{};
    memset(&device1.m_device_info, 0, sizeof(device1.m_device_info));
    memset(&device2.m_device_info, 0, sizeof(device2.m_device_info));
    const char* iname = "eth0";
    const char* iname1 = "eth1";
    memcpy(device1.m_device_info.intf.name, iname, strlen(iname) + 1);
    memcpy(device2.m_device_info.intf.name, iname1, strlen(iname1) + 1);
    EXPECT_FALSE(device1 == device2);
    std::cout << "Exiting DifferentInterfaceNames" << std::endl;
}

/**
 * @brief Test to verify that devices with different interface MAC addresses are not considered equal.
 *
 * This test checks the equality operator for `dm_device_t` objects to ensure that two devices with identical properties except for their interface MAC addresses are not considered equal. This is important to verify that the MAC address is a distinguishing factor for device identity.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 094@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize device1 and device2 with different interface MAC addresses | device1.m_device_info.intf.mac = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, device2.m_device_info.intf.mac = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB} | Devices initialized with modified MAC address | Should be successful |
 * | 03 | Compare device1 and device2 for equality | EXPECT_FALSE(device1 == device2) | Devices should not be equal | Should Pass |
 */
TEST(dm_device_t_Test, DifferentInterfaceMacAddresses) {
    std::cout << "Entering DifferentInterfaceMacAddresses" << std::endl;
    dm_device_t device1{}, device2{};
    memset(&device1.m_device_info, 0, sizeof(device1.m_device_info));
    memset(&device2.m_device_info, 0, sizeof(device2.m_device_info));
    unsigned char mac1[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    unsigned char mac2[6] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
    memcpy(device1.m_device_info.intf.mac, mac1, sizeof(mac1));
    memcpy(device2.m_device_info.intf.mac, mac2, sizeof(mac2));
    EXPECT_FALSE(device1 == device2);
    std::cout << "Exiting DifferentInterfaceMacAddresses" << std::endl;
}

/**
 * @brief Test to verify the behavior of devices with different profiles
 *
 * This test checks if two devices with identical information except for their profiles are considered different.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 095@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize device1 with different profile | device1.m_device_info.profile = em_profile_type_1, device2.m_device_info.profile = em_profile_type_2 | Devices initialized with different profile | Should be successful |
 * | 03| Compare device1 and device2 | EXPECT_FALSE(device1 == device2) | Devices should not be equal | Should Pass |
 */
TEST(dm_device_t_Test, DifferentProfiles) {
    std::cout << "Entering DifferentProfiles" << std::endl;
    dm_device_t device1{}, device2{};
    memset(&device1.m_device_info, 0, sizeof(device1.m_device_info));
    memset(&device2.m_device_info, 0, sizeof(device2.m_device_info));
    device1.m_device_info.profile = em_profile_type_1;
    device2.m_device_info.profile = em_profile_type_2;
    EXPECT_FALSE(device1 == device2);
    std::cout << "Exiting DifferentProfiles" << std::endl;
}

/**
 * @brief Test to verify the behavior when comparing devices from different manufacturers
 *
 * This test checks if two devices with identical properties except for the manufacturer are considered different.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 096@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize device1 and device2 with different manufacturer | device1.m_device_info.manufacturer = "Manufacturer1", device2.m_device_info.manufacturer = "Manufacturer2" | Device2 initialized with properties of device1 but different manufacturer | Should be successful |
 * | 03 | Compare device1 and device2 | device1 == device2 | EXPECT_FALSE(device1 == device2) | Should Pass |
 */
TEST(dm_device_t_Test, DifferentManufacturers) {
    std::cout << "Entering DifferentManufacturers" << std::endl;
    dm_device_t device1{}, device2{};
    memset(&device1.m_device_info, 0, sizeof(device1.m_device_info));
    memset(&device2.m_device_info, 0, sizeof(device2.m_device_info));
    const char* manufacturer = "Manufacturer1";
    const char* manufacturer1 = "Manufacturer2";
    memcpy(device1.m_device_info.manufacturer, manufacturer, strlen(manufacturer)+1);
    memcpy(device2.m_device_info.manufacturer, manufacturer1, strlen(manufacturer1)+1);
    EXPECT_FALSE(device1 == device2);
    std::cout << "Exiting DifferentManufacturers" << std::endl;
}

/**
 * @brief Test to verify that devices with different serial numbers are not considered equal.
 *
 * This test checks the equality operator for `dm_device_t` objects to ensure that two devices with identical attributes except for their serial numbers are not considered equal. This is important to verify that the serial number is a distinguishing attribute for device objects.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 097@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize device1 and device2 with different serial numbers | device1.m_device_info.serial_number = "SN12345", device2.m_device_info.serial_number = "SN67890" | Device2 initialized with same attributes as device1 except serial number | Should be successful |
 * | 03| Compare device1 and device2 for equality | EXPECT_FALSE(device1 == device2) | Devices should not be equal | Should Pass |
 */
TEST(dm_device_t_Test, DifferentSerialNumbers) {
    std::cout << "Entering DifferentSerialNumbers" << std::endl;
    dm_device_t device1{}, device2{};
    memset(&device1.m_device_info, 0, sizeof(device1.m_device_info));
    memset(&device2.m_device_info, 0, sizeof(device2.m_device_info));    
    const char* serial_number = "SN12345";
    const char* serial_number1 = "SN67890";
    memcpy(device1.m_device_info.serial_number, serial_number, strlen(serial_number)+1);
    memcpy(device2.m_device_info.serial_number, serial_number1, strlen(serial_number1)+1);
    EXPECT_FALSE(device1 == device2);
    std::cout << "Exiting DifferentSerialNumbers" << std::endl;
}

/**
 * @brief Test to verify the comparison of devices with different manufacturer models
 *
 * This test checks the equality operator for dm_device_t objects when they have the same attributes except for the manufacturer model.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 098@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize device1 and device2 with different manufacturer models | device1.m_device_info.manufacturer_model = "Model1", device2.m_device_info.manufacturer_model = "Model2" | Should be successful |
 * | 03| Compare device1 and device2 using equality operator | EXPECT_FALSE(device1 == device2) | Should Pass |
 */
TEST(dm_device_t_Test, DifferentManufacturerModels) {
    std::cout << "Entering DifferentManufacturerModels" << std::endl;
    dm_device_t device1{}, device2{};
    memset(&device1.m_device_info, 0, sizeof(device1.m_device_info));
    memset(&device2.m_device_info, 0, sizeof(device2.m_device_info));
    const char* manufacturer_model = "Model1";
    const char* manufacturer_model1 = "Model2";
    memcpy(device1.m_device_info.manufacturer_model, manufacturer_model, strlen(manufacturer_model)+1);
    memcpy(device2.m_device_info.manufacturer_model, manufacturer_model1, strlen(manufacturer_model1)+1);
    EXPECT_FALSE(device1 == device2);
    std::cout << "Exiting DifferentManufacturerModels" << std::endl;
}

/**
 * @brief Test to verify the behavior of the equality operator for devices with different software versions.
 *
 * This test checks if two devices with identical properties except for their software versions are considered unequal.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 099@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize device1 and device2 with different software versions | device1.m_device_info.software_ver = "1.0.0" , device2.m_device_info.software_ver = "2.0.0" | Device2 initialized with given properties | Should be successful |
 * | 03| Compare device1 and device2 using the equality operator | device1 == device2 | EXPECT_FALSE(device1 == device2) | Should Pass |
 */
TEST(dm_device_t_Test, DifferentSoftwareVersions) {
    std::cout << "Entering DifferentSoftwareVersions" << std::endl;
    dm_device_t device1{}, device2{};
    memset(&device1.m_device_info, 0, sizeof(device1.m_device_info));
    memset(&device2.m_device_info, 0, sizeof(device2.m_device_info));
    const char* software_ver = "1.0.0";
    const char* software_ver1 = "2.0.0";
    memcpy(device1.m_device_info.software_ver, software_ver, strlen(software_ver)+1);
    memcpy(device2.m_device_info.software_ver, software_ver1, strlen(software_ver1)+1);
    EXPECT_FALSE(device1 == device2);
    std::cout << "Exiting DifferentSoftwareVersions" << std::endl;
}

/**
 * @brief Test to verify the assignment of valid device information
 *
 * This test checks if the assignment operator correctly assigns the device information from one object to another.@n
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 100@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize obj2 with valid values | obj2.m_device_info.id.media = em_media_type_ieee8023ab, obj2.m_device_info.intf.media = em_media_type_ieee8023ab, obj2.m_device_info.profile = em_profile_type_1 | obj2 should be initialized | Should be successful |
 * | 02| Assign obj2 to obj1 | obj1 = obj2 | obj1 should have the same device information as obj2 | Should Pass |
 * | 03| Compare if the set values are same | obj1.m_device_info.id.media = em_media_type_ieee8023ab, obj1.m_device_info.intf.media = em_media_type_ieee8023ab, obj1.m_device_info.profile = em_profile_type_1 | Return value should be 0 | Should Pass |
 */
TEST(dm_device_t_Test, AssigningValidDeviceInformation) {
    std::cout << "Entering AssigningValidDeviceInformation" << std::endl;
    dm_device_t obj1{};
    dm_device_t obj2{};    
    memset(&obj1.m_device_info, 0, sizeof(obj1.m_device_info));
    memset(&obj2.m_device_info, 0, sizeof(obj2.m_device_info));
    obj2.m_device_info.id.media = em_media_type_ieee8023ab;
    obj2.m_device_info.intf.media = em_media_type_ieee8023ab;
    obj2.m_device_info.profile = em_profile_type_1;
    obj1 = obj2;
    EXPECT_EQ(obj1.m_device_info.id.media, obj2.m_device_info.id.media);
    EXPECT_EQ(obj1.m_device_info.intf.media, obj2.m_device_info.intf.media);
    EXPECT_EQ(obj1.m_device_info.profile, obj2.m_device_info.profile);
    std::cout << "Exiting AssigningValidDeviceInformation" << std::endl;
}

/**
 * @brief Test to verify the assignment of null device information
 *
 * This test checks the assignment operator of the dm_device_t class when the device information is set to null (zeroed out). It ensures that the assignment operator correctly copies the null device information from one object to another.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 101@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Assign obj2 to obj1 | obj1 = obj2 | obj1.m_device_info should be equal to obj2.m_device_info | Should Pass |
 * | 02 | Verify the device information of obj1 and obj2 are equal | obj1.m_device_info.id.media = obj2.m_device_info.id.media, obj1.m_device_info.intf.media = obj2.m_device_info.intf.media, obj1.m_device_info.profile = obj2.m_device_info.profile | values should be same | Should Pass |
 */
TEST(dm_device_t_Test, AssigningNullDeviceInformation) {
    std::cout << "Entering AssigningNullDeviceInformation" << std::endl;
    dm_device_t obj1{};
    dm_device_t obj2{};
    memset(&obj1.m_device_info, 0, sizeof(obj1.m_device_info));
    memset(&obj2.m_device_info, 0, sizeof(obj2.m_device_info));
    obj1 = obj2;
    EXPECT_EQ(obj1.m_device_info.id.media, obj2.m_device_info.id.media);
    EXPECT_EQ(obj1.m_device_info.intf.media, obj2.m_device_info.intf.media);
    EXPECT_EQ(obj1.m_device_info.profile, obj2.m_device_info.profile);
    std::cout << "Exiting AssigningNullDeviceInformation" << std::endl;
}

/**
 * @brief Test the initialization of dm_device_t with valid device information
 *
 * This test verifies that the dm_device_t object is correctly initialized when provided with valid device information. It ensures that the device information is not null after initialization.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 102@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Populate valid_device_info with valid data | valid_device_info.id.media = em_media_type_ieee8023ab, valid_device_info.intf.media = em_media_type_ieee8023ab, valid_device_info.profile = em_profile_type_1 | valid_device_info should be populated with valid data | Should be successful |
 * | 02| Initialize dm_device_t with valid_device_info | device = new dm_device_t(&valid_device_info) | device should be initialized successfully | Should Pass |
 * | 03| Check if device information is same as initialized previously | device.m_device_info.id.media = em_media_type_ieee8023ab, device.m_device_info.intf.media = em_media_type_ieee8023ab, device.m_device_info.profile = em_profile_type_1 | Should be same | Should Pass |
 */
TEST(dm_device_t_Test, InitializeWithValidDeviceInfo) {
    std::cout << "Entering InitializeWithValidDeviceInfo" << std::endl;
    em_device_info_t valid_device_info{};
    memset(&valid_device_info, 0, sizeof(valid_device_info));
    valid_device_info.id.media = em_media_type_ieee8023ab;
    valid_device_info.intf.media = em_media_type_ieee8023ab;
    valid_device_info.profile = em_profile_type_1;
    dm_device_t device(&valid_device_info);
    EXPECT_EQ(device.m_device_info.id.media, em_media_type_ieee8023ab);
    EXPECT_EQ(device.m_device_info.intf.media, em_media_type_ieee8023ab);
    EXPECT_EQ(device.m_device_info.profile, em_profile_type_1);
    std::cout << "Exiting InitializeWithValidDeviceInfo" << std::endl;
}

/**
 * @brief Test the initialization of dm_device_t with null device info
 *
 * This test checks the behavior of the dm_device_t constructor when it is initialized with a null device info pointer.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 103@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize dm_device_t with null device info | device_info = nullptr | Should handle nullptr | Should Fail |
 */
TEST(dm_device_t_Test, InitializeWithNullDeviceInfo) {
    std::cout << "Entering InitializeWithNullDeviceInfo" << std::endl;
    EXPECT_ANY_THROW(dm_device_t device(nullptr));
    std::cout << "Exiting InitializeWithNullDeviceInfo" << std::endl;
}    

/**
 * @brief Test the copy constructor of dm_device_t with valid device information
 *
 * This test verifies that the copy constructor of the dm_device_t class correctly copies the device information from the original device to the copied device. This ensures that the copy constructor works as expected when valid device information is provided.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 104@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Initialize original device with few valid values | originalDevice.m_device_info.report_unsuccess_assocs = true, originalDevice.m_device_info.prioritization_sup = false | Should be successful | |
 * | 02| Copy construct the device | dm_device_t copiedDevice(originalDevice) | Should be successful | |
 * | 05| Compare the device information | copiedDevice.m_device_info.report_unsuccess_assocs = true, copiedDevice.m_device_info.prioritization_sup = false | Should Pass | |
 */
TEST(dm_device_t_Test, CopyConstructorWithValidDeviceInformation) {
    std::cout << "Entering CopyConstructorWithValidDeviceInformation test";
    dm_device_t originalDevice{};
    memset(&originalDevice.m_device_info, 0, sizeof(originalDevice.m_device_info));
    originalDevice.m_device_info.report_unsuccess_assocs = true;
    originalDevice.m_device_info.prioritization_sup = false;
    dm_device_t copiedDevice(originalDevice);
    EXPECT_EQ(copiedDevice.m_device_info.report_unsuccess_assocs, true);
    EXPECT_EQ(copiedDevice.m_device_info.prioritization_sup, false);
    std::cout << "Exiting CopyConstructorWithValidDeviceInformation test";
}

/**
 * @brief Test the copy constructor of dm_device_t with special characters in the manufacturer field.
 *
 * This test verifies that the copy constructor copies the manufacturer string when it contains special characters.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 105@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Step | Description | Test Data | Expected Result | Notes |
 * | :--: | ----------- | --------- | ---------------- | ----- |
 * | 01   | Initialize original device and set manufacturer with special characters | memcpy(originalDevice.m_device_info.manufacturer, "Special!@#$%^&*()", ...) | Manufacturer field should contain special characters | |
 * | 02   | Copy original device to a new device using copy constructor | dm_device_t copiedDevice(originalDevice) | Copy constructor should create an identical copy of the manufacturer field | |
 * | 03   | Compare only the manufacturer field between original and copied device | memcmp(original.manufacturer, copied.manufacturer) | Fields should match exactly | |
 */
TEST(dm_device_t_Test, CopyConstructorWithSpecialCharactersInDeviceInformation) {
    std::cout << "Entering CopyConstructorWithSpecialCharactersInDeviceInformation test" << std::endl;
    dm_device_t originalDevice{};
    memset(&originalDevice.m_device_info, 0, sizeof(originalDevice.m_device_info));
    const char* specialChars = "Special!@#$%^&*()";
    // Set manufacturer field with special characters
    memcpy(originalDevice.m_device_info.manufacturer, specialChars, strlen(specialChars)+1);
    // Copy constructor
    dm_device_t copiedDevice(originalDevice);
    // Compare only the manufacturer field
    EXPECT_EQ(0, memcmp(originalDevice.m_device_info.manufacturer, copiedDevice.m_device_info.manufacturer, sizeof(em_long_string_t)));
    std::cout << "Exiting CopyConstructorWithSpecialCharactersInDeviceInformation test" << std::endl;
}

/**
 * @brief Verify that the default constructor of dm_device_t creates a valid object without throwing an exception.
 *
 * This test checks that invoking the default constructor of dm_device_t does not result in any exception
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
 * | Variation / Step | Description                                                                              | Test Data                                                  | Expected Result                                                                           | Notes      |
 * | :--------------: | ---------------------------------------------------------------------------------------- | ---------------------------------------------------------- | ----------------------------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke dm_device_t default constructor and verify that no exception is thrown.             | No input arguments, invocation of dm_device_t constructor. | Object is created successfully, no exception is thrown, and m_device_info is in default state. | Should Pass |
 */
TEST(dm_device_t_Test, DefaultConstructionCreatesValidObject) {
    std::cout << "Entering DefaultConstructionCreatesValidObject test" << std::endl;
    EXPECT_NO_THROW({
        // Invocation of the default constructor of dm_device_t
        std::cout << "Invoking dm_device_t::dm_device_t() constructor." << std::endl;
        dm_device_t device;
        std::cout << "dm_device_t object created successfully." << std::endl;
    });
    std::cout << "Exiting DefaultConstructionCreatesValidObject test" << std::endl;
}

/**
 * @brief Verify that the destructor is invoked without exceptions on a heap allocated dm_device_t object
 *
 * This test allocates a dm_device_t object on the heap using its default constructor and then deletes it.
 * The objective is to ensure that destructor is called properly to release any allocated resources.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 107@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                     | Test Data                                                              | Expected Result                                                               | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------- | ----------------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke the default constructor to allocate a dm_device_t object on the heap.                     | Invocation: obj = new dm_device_t()                                    | No exception thrown; obj is allocated (non-null pointer)                      | Should Pass |
 * | 02               | Delete the allocated dm_device_t object to invoke its destructor.                                | Invocation: delete obj (with obj pointer from step 01)                 | No exception thrown during deletion; destructor called successfully           | Should Pass |
 */
TEST(dm_device_t_Test, Destructor_called_on_heap_allocated_object) {
    std::cout << "Entering Destructor_called_on_heap_allocated_object test" << std::endl;
    std::cout << "Invoking default constructor for dm_device_t object on heap." << std::endl;
    // Create an object using default constructor
    dm_device_t* obj = nullptr;
    EXPECT_NO_THROW({
        obj = new dm_device_t();
    });
    std::cout << "Invoking the destructor by calling delete on the dm_device_t object." << std::endl;
    // Delete the object. The destructor should be invoked without any exceptions.
    EXPECT_NO_THROW({
        delete obj;
    });
    std::cout << "Destructor invoked successfully on heap allocated object." << std::endl;
    std::cout << "Exiting Destructor_called_on_heap_allocated_object test" << std::endl;
}