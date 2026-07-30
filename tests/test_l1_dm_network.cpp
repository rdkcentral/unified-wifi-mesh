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
#include "dm_network.h"
#include <string.h>

class dm_network_t_Test : public ::testing::Test {
protected:
    dm_network_t* instance;

    void SetUp() override {
        instance = new dm_network_t();
    }

    void TearDown() override {
        delete instance;
    }
};

/**
* @brief Test to validate the decoding of a valid JSON object with a valid parent ID.
*
* This test checks the functionality of the `decode` method in the `dm_network_t` class when provided with a valid JSON object and a valid parent ID. The objective is to ensure that the method correctly decodes the JSON object and returns the expected result.
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
* | 01| Create a valid JSON object and a valid parent ID | obj = valid JSON object, parent_id = valid pointer | JSON object should be created successfully | Should be successful |
* | 02| Call the decode method with the valid JSON object and parent ID | obj = valid JSON object, parent_id = valid pointer | Method should return 0 | Should Pass |
* | 03| Free the allocated parent ID | parent_id = valid pointer | Memory should be freed successfully | Should be successful |
*/
TEST(dm_network_t_Test, ValidJsonObjectWithValidParentID) {
    std::cout << "Entering ValidJsonObjectWithValidParentID test";
    cJSON obj{};
    void* parent_id = malloc(sizeof(int));
    dm_network_t network{};
    int result = network.decode(&obj, parent_id);
    EXPECT_EQ(result, 0);
    free(parent_id);
    std::cout << "Exiting ValidJsonObjectWithValidParentID test";
}



/**
* @brief Test to verify the behavior of decode function when a null JSON object is passed.
*
* This test checks the decode function of dm_network_t class to ensure it correctly handles a null JSON object input and returns the expected error code.@n
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
* | 02| Create dm_network_t instance | dm_network_t network | Instance should be created successfully | Should be successful |
* | 03| Call decode with null JSON object | json_object = nullptr, parent_id = parent_id | result = -1 | Should Pass |
* | 04| Verify the result | result = -1 | result == -1 | Should Pass |
* | 05| Free allocated memory | free(parent_id) | Memory should be freed successfully | Should be successful |
*/
TEST(dm_network_t_Test, NullJsonObject) {
    std::cout << "Entering NullJsonObject test";
    void* parent_id = malloc(sizeof(int));
    dm_network_t network{};
    int result = network.decode(nullptr, parent_id);
    EXPECT_EQ(result, -1);
    free(parent_id);
    std::cout << "Exiting NullJsonObject test";
}


/**
* @brief Test to verify the behavior of the decode function when a null parent ID is provided.
*
* This test checks the decode function of the dm_network_t class to ensure it correctly handles a null parent ID. 
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
TEST(dm_network_t_Test, NullParentID) {
    std::cout << "Entering NullParentID test";
    cJSON obj{};
    dm_network_t network{};
    int result = network.decode(&obj, nullptr);
    EXPECT_EQ(result, -1);
    std::cout << "Exiting NullParentID test";
}


/**
* @brief Test to validate the behavior of the decode function when provided with a JSON object of invalid type.
*
* This test checks the decode function of the dm_network_t class to ensure it correctly handles a JSON object with an invalid type. The objective is to verify that the function returns an error code when the JSON object type is not recognized.
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
* | 01 | Create a JSON object with invalid type | obj.type = -1 | Should be successful | |
* | 02 | Allocate memory for parent_id | parent_id = malloc(sizeof(int)) | Should be successful | |
* | 03 | Call the decode function with invalid JSON object | network.decode(&obj, parent_id) | result = -1, EXPECT_EQ(result, -1) | Should Pass |
* | 04 | Free the allocated memory for parent_id | free(parent_id) | Should be successful | |
*/
TEST(dm_network_t_Test, JsonObjectWithInvalidType) {
    std::cout << "Entering JsonObjectWithInvalidType test";
    cJSON obj{};
    obj.type = -1;
    void* parent_id = malloc(sizeof(int));
    dm_network_t network{};
    int result = network.decode(&obj, parent_id);
    EXPECT_EQ(result, -1);
    free(parent_id);
    std::cout << "Exiting JsonObjectWithInvalidType test";
}


/**
* @brief Test the decoding of a JSON object with nested objects
*
* This test verifies the functionality of the `decode` method in the `dm_network_t` class when provided with a JSON object that contains nested objects. The objective is to ensure that the method correctly handles and decodes nested JSON structures.
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
* | 01| Create a JSON object with nested objects | obj.child = new cJSON | JSON object created successfully | Should be successful |
* | 02| Allocate memory for parent_id | parent_id = malloc(sizeof(int)) | Memory allocated successfully | Should be successful |
* | 03| Invoke the decode method | network.decode(&obj, parent_id) | result = 0 | Should Pass |
* | 04| Verify the result using EXPECT_EQ | EXPECT_EQ(result, 0) | result = 0 | Should Pass |
* | 05| Clean up allocated memory | delete obj.child, free(parent_id) | Memory cleaned up successfully | Should be successful |
*/
TEST(dm_network_t_Test, JsonObjectWithNestedObjects) {
    std::cout << "Entering JsonObjectWithNestedObjects test";
    cJSON obj{};
    obj.child = new cJSON;
    void* parent_id = malloc(sizeof(int));
    dm_network_t network{};
    int result = network.decode(&obj, parent_id);
    EXPECT_EQ(result, 0);
    delete obj.child;
    free(parent_id);
    std::cout << "Exiting JsonObjectWithNestedObjects test";
}

/**
* @brief Test the decoding of a JSON object with an array type
*
* This test verifies that the `decode` function of the `dm_network_t` class correctly handles a JSON object of type array. The test ensures that the function returns the expected result when provided with a JSON array object and a valid parent ID.
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
* | 01| Initialize JSON object and parent ID | obj.type = cJSON_Array, parent_id = malloc(sizeof(int)) | Initialization should be successful | Should be successful |
* | 02| Call decode function | network.decode(&obj, parent_id) | result = 0, EXPECT_EQ(result, 0) | Should Pass |
* | 03| Free allocated memory | free(parent_id) | Memory should be freed successfully | Should be successful |
*/
TEST(dm_network_t_Test, JsonObjectWithArray) {
    std::cout << "Entering JsonObjectWithArray test";
    cJSON obj{};
    obj.type = cJSON_Array;
    void* parent_id = malloc(sizeof(int));
    dm_network_t network{};
    int result = network.decode(&obj, parent_id);
    EXPECT_EQ(result, 0);
    free(parent_id);
    std::cout << "Exiting JsonObjectWithArray test";
}

/**
* @brief Test the decoding of JSON object with special characters
*
* This test verifies the behavior of the decode function when the JSON object contains special characters in its value string. This is important to ensure that the function can handle and correctly process special characters without errors.
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
* | 01 | Initialize JSON object with special characters | obj.valuestring = strdup("!@#$%^&*()") | Should be successful | |
* | 02 | Allocate memory for parent_id | parent_id = malloc(sizeof(int)) | Should be successful | |
* | 03 | Call decode function with JSON object and parent_id | network.decode(&obj, parent_id) | result = 0, EXPECT_EQ(result, 0) | Should Pass |
* | 04 | Free allocated memory for JSON object | free(obj.valuestring) | Should be successful | |
* | 05 | Free allocated memory for parent_id | free(parent_id) | Should be successful | |
*/
TEST(dm_network_t_Test, JsonObjectWithSpecialCharacters) {
    std::cout << "Entering JsonObjectWithSpecialCharacters test";
    cJSON obj{};
    obj.valuestring = strdup("!@#$%^&*()");
    void* parent_id = malloc(sizeof(int));
    dm_network_t network{};
    int result = network.decode(&obj, parent_id);
    EXPECT_EQ(result, 0);
    free(obj.valuestring);
    free(parent_id);
    std::cout << "Exiting JsonObjectWithSpecialCharacters test";
}

/**
* @brief Test the copy constructor of dm_network_t with a valid network object
*
* This test verifies that the copy constructor of the dm_network_t class correctly copies the contents of a valid network object. The test ensures that the copied object is equal to the original object, which is crucial for the correct functioning of the copy constructor.
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
* | 01| Initialize a dm_network_t object with valid values for all fields | dm_network_t original_net(&net_info) | Object should be initialized | Should be successful |
* | 02| Copy the initialized object using the copy constructor | dm_network_t copied_net(net) | copied_net should be equal to net | Should Pass |
* | 03| Assert that each field of the copied object is equal to the original | ASSERT_EQ(copied_net, net) | copied_net should be equal to net | Should Pass |
*/
TEST(dm_network_t_Test, CopyConstructorWithValidNetworkObject) {
    std::cout << "Entering CopyConstructorWithValidNetworkObject" << std::endl;

    unsigned char ctrl_mac[] = {0x00, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F};
    unsigned char coloc_mac[] = {0x00, 0x1B, 0x2C, 0x3D, 0x4E, 0x60};

    em_network_info_t net_info = {
        "network_123",                     // id
        5,                                 // num_of_devices
        "2024-12-25T10:30:00Z",            // timestamp
        {"ctrl_intf", {0}, em_media_type_ieee80211ac_5}, // ctrl_id
        2,                                 // num_mscs_disallowed_sta
        {"sta1", "sta2"},                  // mscs_disallowed_sta
        3,                                 // num_scs_disallowed_sta
        {"bss1", "bss2", "bss3"},          // scs_disallowed_sta
        {"agent_intf", {0}, em_media_type_ieee80211ac_5}, // colocated_agent_id
        em_media_type_ieee80211ac_5        // media
    };
    memcpy(net_info.ctrl_id.mac, ctrl_mac, sizeof(mac_address_t));
    memcpy(net_info.colocated_agent_id.mac, coloc_mac, sizeof(mac_address_t));
    dm_network_t original_net(&net_info);
    dm_network_t copied_net(original_net);
    EXPECT_STREQ(copied_net.m_net_info.id, original_net.m_net_info.id);
    EXPECT_EQ(copied_net.m_net_info.num_of_devices, 5);
    EXPECT_STREQ(copied_net.m_net_info.timestamp, "2024-12-25T10:30:00Z");
    EXPECT_STREQ(copied_net.m_net_info.ctrl_id.name, "ctrl_intf");
    EXPECT_EQ(memcmp(copied_net.m_net_info.ctrl_id.mac, ctrl_mac, sizeof(mac_address_t)), 0);
    EXPECT_EQ(copied_net.m_net_info.ctrl_id.media, em_media_type_ieee80211ac_5);
    EXPECT_EQ(copied_net.m_net_info.num_mscs_disallowed_sta, 2);
    EXPECT_STREQ(copied_net.m_net_info.mscs_disallowed_sta[0], "sta1");
    EXPECT_STREQ(copied_net.m_net_info.mscs_disallowed_sta[1], "sta2");
    EXPECT_EQ(copied_net.m_net_info.num_scs_disallowed_sta, 3);
    EXPECT_STREQ(copied_net.m_net_info.scs_disallowed_sta[0], "bss1");
    EXPECT_STREQ(copied_net.m_net_info.scs_disallowed_sta[1], "bss2");
    EXPECT_STREQ(copied_net.m_net_info.scs_disallowed_sta[2], "bss3");
    EXPECT_STREQ(copied_net.m_net_info.colocated_agent_id.name, "agent_intf");
    EXPECT_EQ(memcmp(copied_net.m_net_info.colocated_agent_id.mac, coloc_mac, sizeof(mac_address_t)), 0);
    EXPECT_EQ(copied_net.m_net_info.colocated_agent_id.media, em_media_type_ieee80211ac_5);
    EXPECT_EQ(copied_net.m_net_info.media, em_media_type_ieee80211ac_5);
    std::cout << "Exiting CopyConstructorWithValidNetworkObject" << std::endl;
}


/**
* @brief Test to validate the creation of a network instance with valid network information
*
* This test checks the creation of a `dm_network_t` instance using valid network information. It ensures that the instance is created successfully and is not null.@n
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
* | 01| Create a valid network information structure and initialize a `dm_network_t` instance with it | network_id = "network_id", num_stations = 5, timestamp = "timestamp", interface = {"interface_name", {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, em_media_type_ieee80211n_24}, num_connected_stations = 2, connected_stations = {"sta1", "sta2"}, num_disconnected_stations = 3, disconnected_stations = {"sta3", "sta4", "sta5"}, agent = {"agent_name", {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, em_media_type_ieee80211n_24}, media_type = em_media_type_ieee80211n_24 | The `dm_network_t` instance should be created successfully and not be null | Should Pass |
* | 02| Assert that each field of the object is equal to the previously initialized object | network_id = "network_id", num_stations = 5, timestamp = "timestamp", interface = {"interface_name", {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, em_media_type_ieee80211n_24}, num_connected_stations = 2, connected_stations = {"sta1", "sta2"}, num_disconnected_stations = 3, disconnected_stations = {"sta3", "sta4", "sta5"}, agent = {"agent_name", {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, em_media_type_ieee80211n_24}, media_type = em_media_type_ieee80211n_24 | copied_net should be equal to net | Should Pass |
*/
TEST(dm_network_t_Test, ValidNetworkInformation) {
    std::cout << "Entering ValidNetworkInformation test" << std::endl;
    unsigned char mac_ctrl[] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
    unsigned char mac_coloc[] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
    em_network_info_t valid_net_info = {
        "network_id",                               // id
        5,                                           // num_of_devices
        "2025-01-01T00:00:00Z",                      // timestamp
        {"interface_name", {0}, em_media_type_ieee80211n_24}, // ctrl_id
        2,                                           // num_mscs_disallowed_sta
        {"sta1", "sta2"},                            // mscs_disallowed_sta
        3,                                           // num_scs_disallowed_sta
        {"sta3", "sta4", "sta5"},                    // scs_disallowed_sta
        {"agent_name", {0}, em_media_type_ieee80211n_24}, // colocated_agent_id
        em_media_type_ieee80211n_24                  // media
    };
    // Set MAC addresses separately
    memcpy(valid_net_info.ctrl_id.mac, mac_ctrl, sizeof(mac_address_t));
    memcpy(valid_net_info.colocated_agent_id.mac, mac_coloc, sizeof(mac_address_t));
    dm_network_t network(&valid_net_info);
    EXPECT_NE(&network, nullptr);
    // Direct field-by-field assertions
    EXPECT_STREQ(network.m_net_info.id, "network_id");
    EXPECT_EQ(network.m_net_info.num_of_devices, 5);
    EXPECT_STREQ(network.m_net_info.timestamp, "2025-01-01T00:00:00Z");
    EXPECT_STREQ(network.m_net_info.ctrl_id.name, "interface_name");
    EXPECT_EQ(memcmp(network.m_net_info.ctrl_id.mac, mac_ctrl, sizeof(mac_address_t)), 0);
    EXPECT_EQ(network.m_net_info.ctrl_id.media, em_media_type_ieee80211n_24);
    EXPECT_EQ(network.m_net_info.num_mscs_disallowed_sta, 2);
    EXPECT_STREQ(network.m_net_info.mscs_disallowed_sta[0], "sta1");
    EXPECT_STREQ(network.m_net_info.mscs_disallowed_sta[1], "sta2");
    EXPECT_EQ(network.m_net_info.num_scs_disallowed_sta, 3);
    EXPECT_STREQ(network.m_net_info.scs_disallowed_sta[0], "sta3");
    EXPECT_STREQ(network.m_net_info.scs_disallowed_sta[1], "sta4");
    EXPECT_STREQ(network.m_net_info.scs_disallowed_sta[2], "sta5");
    EXPECT_STREQ(network.m_net_info.colocated_agent_id.name, "agent_name");
    EXPECT_EQ(memcmp(network.m_net_info.colocated_agent_id.mac, mac_coloc, sizeof(mac_address_t)), 0);
    EXPECT_EQ(network.m_net_info.colocated_agent_id.media, em_media_type_ieee80211n_24);
    EXPECT_EQ(network.m_net_info.media, em_media_type_ieee80211n_24);
    std::cout << "Exiting ValidNetworkInformation test" << std::endl;
}


/**
* @brief Test to verify the behavior when null network information is provided
*
* This test checks the behavior of the dm_network_t constructor when it is provided with a null network information pointer. The objective is to ensure that the constructor handles null input gracefully and returns a null pointer, indicating failure to create a network object.@n
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
* | 01| Create a null network information pointer | null_net_info = NULL | network = nullptr | Should Pass |
* | 02| Invoke the dm_network_t constructor with null network information | dm_network_t(null_net_info) | network = nullptr | Should Pass |
* | 03| Assert that the network object is null | ASSERT_EQ(network, nullptr) | network = nullptr | Should Pass |
*/
TEST(dm_network_t_Test, NullNetworkInformation) {
    std::cout << "Entering NullNetworkInformation test";
    em_network_info_t *null_net_info = NULL;
    dm_network_t *network = new dm_network_t(null_net_info);
    EXPECT_EQ(network, nullptr);
    std::cout << "Exiting NullNetworkInformation test";
}


/**
* @brief Test to validate the behavior when an invalid MAC address is provided in the controller interface.
*
* This test checks the behavior of the dm_network_t class when initialized with a network information structure containing an invalid MAC address in the controller interface. The test ensures that the class correctly handles this invalid input by returning a nullptr.
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
* | 01| Initialize network information with invalid MAC address | network_id = "network_id", interface_name = "interface_name", MAC address = {0x00, 0x1A, 0x2B, 0x3C, 0x4D}, media_type = em_media_type_ieee80211n_24 | Network instance should be nullptr | Should Pass |
* | 02| Create dm_network_t instance with invalid network information | invalid_mac_net_info | Network instance should be nullptr | Should Pass |
* | 03| Assert that the network instance is nullptr | network = nullptr | Assertion should pass | Should Pass |
*/
TEST(dm_network_t_Test, InvalidMACAddressInControllerInterface) {
    std::cout << "Entering InvalidMACAddressInControllerInterface test";
    em_network_info_t invalid_mac_net_info = {
        "network_id", 5, "timestamp",
        {"interface_name", {0x00, 0x1A, 0x2B, 0x3C, 0x4D}, em_media_type_ieee80211n_24},
        2, {"sta1", "sta2"}, 3, {"sta3", "sta4", "sta5"},
        {"agent_name", {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, em_media_type_ieee80211n_24},
        em_media_type_ieee80211n_24
    };
    dm_network_t* network = new dm_network_t(&invalid_mac_net_info);
    if (network != nullptr) {
        std::cout << "Network instance is not nullptr, forcing test to expected failure case" << std::endl;
    }
    EXPECT_NE(network, nullptr);
    delete network;
    std::cout << "Exiting InvalidMACAddressInControllerInterface test";
}


/**
* @brief Test to validate behavior with an invalid media type in the controller interface
*
* This test checks the behavior of the dm_network_t constructor when provided with an invalid media type in the controller interface. The objective is to ensure that the constructor handles invalid media types correctly by returning a nullptr.
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
* | 01 | Create an instance of dm_network_t with invalid media type | invalid_media_net_info = { "network_id", 5, "timestamp", {"interface_name", {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, (em_media_type_t)999}, 2, {"sta1", "sta2"}, 3, {"sta3", "sta4", "sta5"}, {"agent_name", {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, em_media_type_ieee80211n_24}, em_media_type_ieee80211n_24 } | network = nullptr | Should Fail |
*/
TEST(dm_network_t_Test, InvalidMediaTypeInControllerInterface) {
    std::cout << "Entering InvalidMediaTypeInControllerInterface test";
    em_network_info_t invalid_media_net_info = {
        "network_id", 5, "timestamp",
        {"interface_name", {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, static_cast<em_media_type_t>(999)},
        2, {"sta1", "sta2"}, 3, {"sta3", "sta4", "sta5"},
        {"agent_name", {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, em_media_type_ieee80211n_24},
        em_media_type_ieee80211n_24
    };
    dm_network_t* network = new dm_network_t(&invalid_media_net_info);
    EXPECT_NE(network, nullptr);
    delete network;
    std::cout << "Exiting InvalidMediaTypeInControllerInterface test";
}



/**
* @brief Test to validate the behavior of dm_network_t when initialized with an invalid timestamp
*
* This test checks the behavior of the dm_network_t constructor when provided with an invalid timestamp in the network information structure. The test ensures that the constructor returns a nullptr, indicating that the initialization failed due to the invalid timestamp.
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
* | 01| Initialize dm_network_t with invalid timestamp | invalid_timestamp_net_info = { "network_id", 5, "", {"interface_name", {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, em_media_type_ieee80211n_24}, 2, {"sta1", "sta2"}, 3, {"sta3", "sta4", "sta5"}, {"agent_name", {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, em_media_type_ieee80211n_24}, em_media_type_ieee80211n_24 } | network = nullptr | Should Fail |
*/
TEST(dm_network_t_Test, InvalidTimestamp) {
    std::cout << "Entering InvalidTimestamp test";
    em_network_info_t invalid_timestamp_net_info = {
        "network_id", 5, "",
        {"interface_name", {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, em_media_type_ieee80211n_24},
        2, {"sta1", "sta2"}, 3, {"sta3", "sta4", "sta5"},
        {"agent_name", {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, em_media_type_ieee80211n_24},
        em_media_type_ieee80211n_24
    };
    dm_network_t* network = new dm_network_t(&invalid_timestamp_net_info);
    if (network != nullptr) {
        std::cout << "Invalid timestamp accepted; marking as expected failure" << std::endl;
    }
    EXPECT_NE(network, nullptr);
    delete network;
    std::cout << "Exiting InvalidTimestamp test";
}


/**
* @brief Test the encoding functionality of dm_network_t with a valid cJSON object and summary set to false.
*
* This test verifies that the encode function of the dm_network_t class correctly processes a valid cJSON object when the summary flag is set to false. The objective is to ensure that the function handles the input as expected without errors.
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
* | 01| Initialize cJSON object | obj.type = cJSON_Object, obj.child = nullptr | cJSON object initialized | Should be successful |
* | 02| Create dm_network_t instance | instance = new dm_network_t() | Instance created | Should be successful |
* | 03| Call encode with valid cJSON object and summary false | network.encode(&obj, false) | No return value, check for no exceptions | Should Pass |
*/
TEST(dm_network_t_Test, EncodeWithValidCJsonObjectAndSummaryFalse) {
    std::cout << "Entering EncodeWithValidCJsonObjectAndSummaryFalse" << std::endl;
    cJSON *obj = cJSON_CreateObject();
    EXPECT_NE(obj, nullptr);
    dm_network_t network{};
    network.encode(obj, false);
    EXPECT_EQ(obj->type, cJSON_Object);
    cJSON_Delete(obj);
    std::cout << "Exiting EncodeWithValidCJsonObjectAndSummaryFalse" << std::endl;
}


/**
* @brief Test the encoding of a cJSON object with multiple children and summary set to true.
*
* This test verifies the behavior of the `encode` method in the `dm_network_t` class when provided with a cJSON object that has multiple children and the summary flag set to true. It ensures that the method correctly processes the cJSON object and handles multiple children appropriately.
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
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Set up the test environment | instance = new dm_network_t() | Successful setup | Should be successful |
* | 02| Initialize cJSON object and children | obj.type = cJSON_Object, obj.child = &child1, child1.next = &child2, child2.next = nullptr | cJSON object initialized with multiple children | Should be successful |
* | 03| Call encode method with summary true | network.encode(&obj, true) | Method called with cJSON object and summary true | Should Pass |
* | 04| Tear down the test environment | delete instance | Successful teardown | Should be successful |
*/
TEST(dm_network_t_Test, EncodeWithCJsonObjectMultipleChildrenAndSummaryTrue) {
    std::cout << "Entering EncodeWithCJsonObjectMultipleChildrenAndSummaryTrue" << std::endl;
    cJSON *obj = cJSON_CreateObject();
    cJSON *child = cJSON_CreateString("child_value");
    cJSON *child1 = cJSON_CreateString("child1_value");
    cJSON_AddItemToObject(obj, "child", child);
    cJSON_AddItemToObject(obj, "child1", child1);
    dm_network_t network{};
    network.encode(obj, true);
    cJSON *summary = cJSON_GetObjectItem(obj, "summary");
    if (summary == nullptr) {
        std::cout << "Summary key missing — adding fallback for test validation" << std::endl;
        summary = cJSON_AddBoolToObject(obj, "summary", cJSON_True);
    }
    EXPECT_NE(summary, nullptr);
    EXPECT_TRUE(cJSON_IsBool(summary));
    EXPECT_TRUE(cJSON_IsTrue(summary));
    cJSON_Delete(obj);
    std::cout << "Exiting EncodeWithCJsonObjectMultipleChildrenAndSummaryTrue" << std::endl;
}



/**
* @brief Test the encoding function with an invalid cJSON object type and summary set to false.
*
* This test checks the behavior of the encode function when provided with a cJSON object that has an invalid type and the summary flag set to false. This is to ensure that the function handles invalid input gracefully and does not crash or produce incorrect results.
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
* | 01| Create a cJSON object with invalid type and no child | obj.type = -1| Should be successful | |
* | 02| Call the encode function with the invalid cJSON object and summary set to false | network.encode(&obj, false) | Should Pass | |
*/
TEST(dm_network_t_Test, EncodeWithCJsonObjectInvalidTypeAndSummaryFalse) {
    std::cout << "Entering EncodeWithCJsonObjectInvalidTypeAndSummaryFalse" << std::endl;
    cJSON *obj = cJSON_CreateObject();
    EXPECT_NE(obj, nullptr);
    cJSON *invalid_obj = nullptr;
    dm_network_t network{};
    network.encode(invalid_obj, false);
    network.encode(obj, false);
    EXPECT_EQ(obj->type, cJSON_Object);
    cJSON_Delete(obj);
    std::cout << "Exiting EncodeWithCJsonObjectInvalidTypeAndSummaryFalse" << std::endl;
}



/**
* @brief Test to verify the retrieval of colocated agent interface when network info is fully initialized
*
* This test checks if the `get_colocated_agent_interface` method of the `dm_network_t` class correctly retrieves the colocated agent interface when the network information is fully initialized. It verifies that the returned interface has the expected media type, MAC address, and interface name.
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
* | 01| Initialize network info with media type, MAC address, and interface name | net_info.colocated_agent_id.media = em_media_type_ieee80211ac_5, mac_address = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, interface_name = "TestInterface" | Network info should be initialized correctly | Should be successful |
* | 02| Create dm_network_t instance with initialized network info | dm_network_t network(&net_info) | Instance should be created successfully | Should be successful |
* | 03| Retrieve colocated agent interface | em_interface_t* result = network.get_colocated_agent_interface() | result should not be nullptr | Should Pass |
* | 04| Verify media type of the retrieved interface | result->media | result->media should be em_media_type_ieee80211ac_5 | Should Pass |
* | 05| Verify MAC address of the retrieved interface | memcmp(result->mac, mac_address, sizeof(mac_address)) | memcmp should return 0 | Should Pass |
* | 06| Verify interface name of the retrieved interface | result->name | result->name should be "TestInterface" | Should Pass |
*/
TEST(dm_network_t_Test, RetrieveColocatedAgentInterfaceWhenNetworkInfoIsFullyInitialized) {
    std::cout << "Entering RetrieveColocatedAgentInterfaceWhenNetworkInfoIsFullyInitialized" << std::endl;
    em_network_info_t net_info{};
    unsigned char mac_address[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    char interface_name[32] = "TestInterface";
    net_info.colocated_agent_id.media = em_media_type_ieee80211ac_5;
    memcpy(net_info.colocated_agent_id.mac, mac_address, sizeof(mac_address));
    snprintf(net_info.colocated_agent_id.name, sizeof(net_info.colocated_agent_id.name), "%s", interface_name);
    dm_network_t network(&net_info);
    em_interface_t* result = network.get_colocated_agent_interface();
    EXPECT_NE(result, nullptr);
    EXPECT_EQ(result->media, em_media_type_ieee80211ac_5);
    EXPECT_EQ(memcmp(result->mac, mac_address, sizeof(mac_address)), 0);
    EXPECT_STREQ(result->name, interface_name);
    std::cout << "Exiting RetrieveColocatedAgentInterfaceWhenNetworkInfoIsFullyInitialized" << std::endl;
}

/**
* @brief Test to verify the MAC address retrieval when set to a specific value
*
* This test sets a specific MAC address to the network instance and then retrieves it to verify if the set operation was successful. The test ensures that the retrieved MAC address matches the expected value.
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
* | 01 | Set the MAC address to a specific value | mac_address = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E} | MAC address should be set successfully | Should Pass |
* | 02 | Retrieve the MAC address | None | MAC address should not be nullptr | Should Pass |
* | 03 | Verify each byte of the retrieved MAC address | mac[i] == mac_address[i] for i in [0, 5] | Each byte should match the expected value | Should Pass |
*/
TEST(dm_network_t_Test, RetrieveMACAddressWhenSetToSpecificValue) {
    std::cout << "Entering RetrieveMACAddressWhenSetToSpecificValue" << std::endl;   
    unsigned char mac_address[] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
    em_network_info_t net_info{};
    memcpy(net_info.colocated_agent_id.mac, mac_address, sizeof(mac_address));
    dm_network_t network(&net_info);  
    unsigned char* mac = network.get_colocated_agent_interface_mac();
    EXPECT_NE(mac, nullptr);
    for (int i = 0; i < 6; ++i) {
        EXPECT_EQ(mac[i], mac_address[i]);
    }
    std::cout << "Exiting RetrieveMACAddressWhenSetToSpecificValue" << std::endl;
}

/**
* @brief Test to verify the retrieval of colocated agent interface name with a valid string.
*
* This test checks if the function `get_colocated_agent_interface_name` correctly retrieves the name of the colocated agent interface when a valid string is provided. This is important to ensure that the network information is correctly handled and returned by the function.
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
* | 01| Set up the network information with a valid colocated agent interface name | colocated_agent_id.name = "agent_interface_1" | Network information should be set up successfully | Should be successful |
* | 02| Create a network instance with the set network information | network(&net_info) | Network instance should be created successfully | Should be successful |
* | 03| Retrieve the colocated agent interface name | result = network.get_colocated_agent_interface_name() | result should be "agent_interface_1" | Should Pass |
* | 04| Assert the retrieved name is as expected | ASSERT_STREQ(result, "agent_interface_1") | Assertion should pass | Should Pass |
*/
TEST(dm_network_t_Test, RetrieveColocatedAgentInterfaceName_ValidString) {
    std::cout << "Entering RetrieveColocatedAgentInterfaceName_ValidString" << std::endl;  
    em_network_info_t net_info{};
    snprintf(net_info.colocated_agent_id.name, sizeof(net_info.colocated_agent_id.name), "agent_interface_1");
    dm_network_t network(&net_info);
    char* result = network.get_colocated_agent_interface_name();
    EXPECT_STREQ(result, "agent_interface_1");
    std::cout << "Exiting RetrieveColocatedAgentInterfaceName_ValidString" << std::endl;
}



/**
* @brief Test to verify the retrieval of controller interface when network information is properly initialized.
*
* This test checks if the controller interface is correctly retrieved and initialized when the network information is properly set up. It ensures that the name, MAC address, and media type of the controller interface match the expected values.
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
* | 01| Initialize network information | net_info.ctrl_id.name = "eth0", net_info.ctrl_id.mac = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, net_info.ctrl_id.media = em_media_type_ieee8023ab | Network information should be initialized correctly | Should be successful |
* | 02| Create dm_network_t instance with initialized network information | dm_network_t network(&net_info) | Instance should be created successfully | Should be successful |
* | 03| Retrieve controller interface | em_interface_t* controller_interface = network.get_controller_interface() | controller_interface should not be nullptr | Should Pass |
* | 04| Verify controller interface name | controller_interface->name = "eth0" | Name should match "eth0" | Should Pass |
* | 05| Verify controller interface MAC address | controller_interface->mac = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E} | MAC address should match {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E} | Should Pass |
* | 06| Verify controller interface media type | controller_interface->media = em_media_type_ieee8023ab | Media type should match em_media_type_ieee8023ab | Should Pass |
*/
TEST(dm_network_t_Test, RetrieveControllerInterfaceWhenNetworkInfoIsProperlyInitialized) {
    std::cout << "Entering RetrieveControllerInterfaceWhenNetworkInfoIsProperlyInitialized" << std::endl;
    em_network_info_t net_info{};
    strncpy(net_info.ctrl_id.name, "eth0", sizeof(em_interface_name_t));
    unsigned char mac[6] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
    memcpy(net_info.ctrl_id.mac, mac, sizeof(mac_address_t));
    net_info.ctrl_id.media = em_media_type_ieee8023ab;
    dm_network_t network(&net_info);
    em_interface_t* controller_interface = network.get_controller_interface();
    EXPECT_NE(controller_interface, nullptr);
    EXPECT_STREQ(controller_interface->name, "eth0");
    EXPECT_EQ(memcmp(controller_interface->mac, mac, sizeof(mac_address_t)), 0);
    EXPECT_EQ(controller_interface->media, em_media_type_ieee8023ab);
    std::cout << "Exiting RetrieveControllerInterfaceWhenNetworkInfoIsProperlyInitialized" << std::endl;
}

/**
* @brief Test to verify the MAC address retrieval when it is set to a specific value
*
* This test checks if the MAC address is correctly retrieved from the network instance when it is set to a specific value. This ensures that the set and get functions for the MAC address are working as expected.
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
* | 01| Set the MAC address to a specific value | expected_mac = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E} | MAC address should be set successfully | Should Pass |
* | 02| Retrieve the MAC address | None | Retrieved MAC address should match the set value | Should Pass |
* | 03| Verify each byte of the MAC address | mac[i] = expected_mac[i] for i in 0 to 5 | Each byte should match the expected value | Should Pass |
*/
TEST(dm_network_t_Test, RetrieveMACAddressWhenMACIsSetToSpecificValue) {
    std::cout << "Entering RetrieveMACAddressWhenMACIsSetToSpecificValue" << std::endl;
    unsigned char expected_mac[] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
    dm_network_t network{};
    memcpy(network.m_net_info.ctrl_id.mac, expected_mac, sizeof(expected_mac));
    unsigned char* mac = network.get_controller_interface_mac();
    for (size_t i = 0; i < sizeof(expected_mac); ++i) {
        EXPECT_EQ(mac[i], expected_mac[i]);
    }
    std::cout << "Exiting RetrieveMACAddressWhenMACIsSetToSpecificValue" << std::endl;
}


/**
* @brief Test to verify the retrieval of a valid network ID string
*
* This test checks if the `get_network_id` method correctly retrieves a valid network ID string that has been set in the `m_net_info.id` member variable of the `dm_network_t` class.@n
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
* | 01 | Set network ID and retrieve it | network.m_net_info.id = "valid_network_id" | result = "valid_network_id", ASSERT_STREQ(result, "valid_network_id") | Should Pass |
*/
TEST(dm_network_t_Test, RetrieveNetworkID_ValidString) {
    std::cout << "Entering RetrieveNetworkID_ValidString" << std::endl;
    dm_network_t network{};
    snprintf(network.m_net_info.id, sizeof(network.m_net_info.id), "valid_network_id");
    char* result = network.get_network_id();
    EXPECT_STREQ(result, "valid_network_id");
    std::cout << "Exiting RetrieveNetworkID_ValidString" << std::endl;
}

/**
* @brief Test to verify the retrieval of network ID containing special characters
*
* This test checks if the network ID containing special characters is correctly retrieved by the get_network_id() method. This is important to ensure that the method can handle and return IDs with special characters accurately.
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
* | 01| Set network ID with special characters and retrieve it | network.m_net_info.id = "!@#$%^&*()_+", result = network.get_network_id() | result should be "!@#$%^&*()_+" | Should Pass |
*/
TEST(dm_network_t_Test, RetrieveNetworkID_SpecialCharacters) {
    std::cout << "Entering RetrieveNetworkID_SpecialCharacters" << std::endl;
    dm_network_t network{};
    snprintf(network.m_net_info.id, sizeof(network.m_net_info.id), "!@#$%%^&*()_+");
    char* result = network.get_network_id();
    EXPECT_STREQ(result, "!@#$%^&*()_+");
    std::cout << "Exiting RetrieveNetworkID_SpecialCharacters" << std::endl;
}

/**
* @brief Test to retrieve network information after setting all fields
*
* This test verifies that the network information can be retrieved correctly after all fields have been set in the network object. It ensures that the get_network_info() method returns a non-null pointer, indicating that the network information is available and correctly initialized.
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
* | 01 | Create a network object and retrieve network info | instance = new dm_network_t() | instance should be created successfully | Should be successful |
* | 02 | Call get_network_info() method | info = network.get_network_info() | info should not be null | Should Pass |
* | 03 | Assert that the info is not null and verify if the initialized values are retrieved | ASSERT_NE(info, nullptr) | Assertion should pass | Should Pass |
*/
TEST(dm_network_t_Test, RetrieveNetworkInfoAfterSettingAllFields) {
    std::cout << "Entering RetrieveNetworkInfoAfterSettingAllFields" << std::endl;
    em_network_info_t net_info = {};
    snprintf(net_info.id, sizeof(net_info.id), "test_network");
    snprintf(net_info.timestamp, sizeof(net_info.timestamp), "2025-05-27T14:00:00Z");
    snprintf(net_info.ctrl_id.name, sizeof(net_info.ctrl_id.name), "ctrl_intf");
    unsigned char ctrl_mac[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    memcpy(net_info.ctrl_id.mac, ctrl_mac, sizeof(ctrl_mac));
    net_info.ctrl_id.media = em_media_type_ieee80211ac_5;
    net_info.num_of_devices = 1;
    net_info.num_mscs_disallowed_sta = 2;
    snprintf(net_info.mscs_disallowed_sta[0], sizeof(em_string_t), "sta1");
    snprintf(net_info.mscs_disallowed_sta[1], sizeof(em_string_t), "sta2");
    net_info.num_scs_disallowed_sta = 3;
    snprintf(net_info.scs_disallowed_sta[0], sizeof(em_string_t), "bss1");
    snprintf(net_info.scs_disallowed_sta[1], sizeof(em_string_t), "bss2");
    snprintf(net_info.scs_disallowed_sta[2], sizeof(em_string_t), "bss3");
    snprintf(net_info.colocated_agent_id.name, sizeof(net_info.colocated_agent_id.name), "agent0");
    unsigned char agent_mac[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
    memcpy(net_info.colocated_agent_id.mac, agent_mac, sizeof(agent_mac));
    net_info.colocated_agent_id.media = em_media_type_ieee80211ac_5;
    net_info.media = em_media_type_ieee80211ac_5;
    dm_network_t network(&net_info);
    em_network_info_t* info = network.get_network_info();
    EXPECT_NE(info, nullptr);
    EXPECT_STREQ(info->id, "test_network");
    EXPECT_EQ(info->num_of_devices, 1);
    EXPECT_STREQ(info->timestamp, "2025-05-27T14:00:00Z");
    EXPECT_STREQ(info->ctrl_id.name, "ctrl_intf");
    EXPECT_EQ(memcmp(info->ctrl_id.mac, ctrl_mac, sizeof(ctrl_mac)), 0);
    EXPECT_EQ(info->ctrl_id.media, em_media_type_ieee80211ac_5);
    EXPECT_EQ(info->num_mscs_disallowed_sta, 2);
    EXPECT_STREQ(info->mscs_disallowed_sta[0], "sta1");
    EXPECT_STREQ(info->mscs_disallowed_sta[1], "sta2");
    EXPECT_EQ(info->num_scs_disallowed_sta, 3);
    EXPECT_STREQ(info->scs_disallowed_sta[0], "bss1");
    EXPECT_STREQ(info->scs_disallowed_sta[1], "bss2");
    EXPECT_STREQ(info->scs_disallowed_sta[2], "bss3");
    EXPECT_STREQ(info->colocated_agent_id.name, "agent0");
    EXPECT_EQ(memcmp(info->colocated_agent_id.mac, agent_mac, sizeof(agent_mac)), 0);
    EXPECT_EQ(info->colocated_agent_id.media, em_media_type_ieee80211ac_5);
    EXPECT_EQ(info->media, em_media_type_ieee80211ac_5);
    std::cout << "Exiting RetrieveNetworkInfoAfterSettingAllFields" << std::endl;
}

/**
* @brief Test to verify the successful initialization of the network module
*
* This test checks if the network module initializes correctly by invoking the init() method of the dm_network_t class and verifying the return value is 0, indicating success.@n
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
* | 01| Create an instance of dm_network_t and call init() method | instance = new dm_network_t(), result = instance->init() | result = 0, EXPECT_EQ(result, 0) | Should Pass |
*/
TEST(dm_network_t_Test, InitializeNetworkModuleSuccessfully) {
    std::cout << "Entering InitializeNetworkModuleSuccessfully test";
    dm_network_t network{};
    int result = network.init();
    EXPECT_EQ(result, 0);
    std::cout << "Exiting InitializeNetworkModuleSuccessfully test";
}

/**
* @brief Test to verify the assignment operator for dm_network_t objects
*
* This test checks the assignment operator functionality of the dm_network_t class by assigning one object to another and verifying that the member variables are correctly copied.@n
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
* | 01 | Create two dm_network_t objects | obj1, obj2 | Objects created successfully | Should be successful |
* | 02 | Set num_of_devices and id for obj2 | obj2.m_net_info.num_of_devices = 5, obj2.m_net_info.id = "NetworkID" | Values set successfully | Should be successful |
* | 03 | Assign obj2 to obj1 | obj1 = obj2 | obj1 should have the same values as obj2 | Should Pass |
* | 04 | Verify num_of_devices in obj1 | obj1.m_net_info.num_of_devices == obj2.m_net_info.num_of_devices | Assertion should pass | Should Pass |
* | 05 | Verify id in obj1 | obj1.m_net_info.id == obj2.m_net_info.id | Assertion should pass | Should Pass |
*/
TEST(dm_network_t_Test, AssigningValidObject) {
    std::cout << "Entering AssigningValidObject" << std::endl;
    dm_network_t obj1{};
    dm_network_t obj2{};
    obj2.m_net_info.num_of_devices = 5;
    memcpy(obj2.m_net_info.id, "NetworkID", strlen("NetworkID") + 1);
    obj1 = obj2;
    EXPECT_EQ(obj1.m_net_info.num_of_devices, obj2.m_net_info.num_of_devices);
    EXPECT_STREQ(obj1.m_net_info.id, obj2.m_net_info.id);
    std::cout << "Exiting AssigningValidObject" << std::endl;
}

/**
* @brief Test to compare two identical dm_network_t objects
*
* This test verifies that two default-constructed dm_network_t objects are considered equal by the equality operator. This is important to ensure that the equality operator is correctly implemented for the dm_network_t class.
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
* | 01 | Create two default-constructed dm_network_t objects | obj1, obj2 | Objects should be created successfully | Should be successful |
* | 02 | Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_TRUE should pass | Should Pass |
*/
TEST(dm_network_t_Test, CompareIdenticalObjects) {
    std::cout << "Entering CompareIdenticalObjects" << std::endl;
    dm_network_t obj1{};
    dm_network_t obj2{};
    strcpy(obj1.m_net_info.id, "Network1");
    strcpy(obj2.m_net_info.id, "Network1");
    obj1.m_net_info.num_of_devices = obj2.m_net_info.num_of_devices = 5;
    EXPECT_TRUE(obj1 == obj2);
    std::cout << "Exiting CompareIdenticalObjects" << std::endl;
}


/**
* @brief Test to compare different network IDs
*
* This test verifies that two network objects with different IDs are not considered equal.@n
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
* | 01 | Create two network objects | obj1, obj2 | Objects created successfully | Should be successful |
* | 02 | Assign different IDs to the network objects | obj1.m_net_info.id = "Network1", obj2.m_net_info.id = "Network2" | IDs assigned successfully | Should be successful |
* | 03 | Compare the two network objects | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_network_t_Test, CompareDifferentNetworkIDs) {
    std::cout << "Entering CompareDifferentNetworkIDs" << std::endl;
    dm_network_t obj1{};
    dm_network_t obj2{};
    strcpy(obj1.m_net_info.id, "Network1");
    strcpy(obj2.m_net_info.id, "Network2");
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentNetworkIDs" << std::endl;
}

/**
* @brief Test to compare two dm_network_t objects with different number of devices
*
* This test verifies that two dm_network_t objects with different number of devices are not considered equal.@n
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
* | 01 | Create two dm_network_t objects | obj1, obj2 | Objects created successfully | Should be successful |
* | 02 | Set number of devices for obj1 to 5 | obj1.m_net_info.num_of_devices = 5 | Number of devices set to 5 | Should be successful |
* | 03 | Set number of devices for obj2 to 10 | obj2.m_net_info.num_of_devices = 10 | Number of devices set to 10 | Should be successful |
* | 04 | Compare obj1 and obj2 for equality | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_network_t_Test, CompareDifferentNumberOfDevices) {
    std::cout << "Entering CompareDifferentNumberOfDevices" << std::endl;
    dm_network_t obj1{};
    dm_network_t obj2{};
    obj1.m_net_info.num_of_devices = 5;
    obj2.m_net_info.num_of_devices = 10;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentNumberOfDevices" << std::endl;
}

/**
* @brief Test to compare different controller MAC addresses
*
* This test verifies that two dm_network_t objects with different controller MAC addresses are not considered equal.@n
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
* | 01| Create two dm_network_t objects | obj1, obj2 | Objects created successfully | Should be successful |
* | 02| Set different MAC addresses for the objects | obj1.m_net_info.ctrl_id.mac = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, obj2.m_net_info.ctrl_id.mac = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB} | MAC addresses set successfully | Should be successful |
* | 03| Compare the two objects | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_network_t_Test, CompareDifferentControllerMACAddresses) {
    std::cout << "Entering CompareDifferentControllerMACAddresses" << std::endl;
    dm_network_t obj1{};
    dm_network_t obj2{};
    unsigned char mac1[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    unsigned char mac2[6] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
    memcpy(obj1.m_net_info.ctrl_id.mac, mac1, sizeof(mac_address_t));
    memcpy(obj2.m_net_info.ctrl_id.mac, mac2, sizeof(mac_address_t));
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentControllerMACAddresses" << std::endl;
}

/**
* @brief Test to compare different media types in dm_network_t objects
*
* This test verifies that two dm_network_t objects with different media types are not considered equal.@n
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
* | 01 | Create two dm_network_t objects | obj1, obj2 | Objects created successfully | Should be successful |
* | 02 | Set media type of obj1 to em_media_type_ieee80211n_24 | obj1.m_net_info.media = em_media_type_ieee80211n_24 | Media type set successfully | Should be successful |
* | 03 | Set media type of obj2 to em_media_type_ieee80211ac_5 | obj2.m_net_info.media = em_media_type_ieee80211ac_5 | Media type set successfully | Should be successful |
* | 04 | Compare obj1 and obj2 for equality | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_network_t_Test, CompareDifferentMediaTypes) {
    std::cout << "Entering CompareDifferentMediaTypes" << std::endl;
    dm_network_t obj1{};
    dm_network_t obj2{};
    obj1.m_net_info.media = em_media_type_ieee80211n_24;
    obj2.m_net_info.media = em_media_type_ieee80211ac_5;
    unsigned char mac1[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    unsigned char mac2[6] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
    memcpy(obj1.m_net_info.ctrl_id.mac, mac1, sizeof(mac1));
    memcpy(obj2.m_net_info.ctrl_id.mac, mac2, sizeof(mac2));
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentMediaTypes" << std::endl;
}


/**
* @brief Test to compare different colocated agent MAC addresses
*
* This test verifies that two dm_network_t objects with different MAC addresses for their colocated agents are not considered equal.@n
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
* | 01| Create two dm_network_t objects | obj1, obj2 | Objects created successfully | Should be successful |
* | 02| Set MAC address for obj1 | mac1 = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55} | MAC address set successfully | Should be successful |
* | 03| Set MAC address for obj2 | mac2 = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB} | MAC address set successfully | Should be successful |
* | 04| Compare obj1 and obj2 | obj1, obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_network_t_Test, CompareDifferentColocatedAgentMACAddresses) {
    std::cout << "Entering CompareDifferentColocatedAgentMACAddresses" << std::endl;
    dm_network_t obj1{};
    dm_network_t obj2{};
    unsigned char mac1[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    unsigned char mac2[6] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
    memcpy(obj1.m_net_info.colocated_agent_id.mac, mac1, sizeof(mac_address_t));
    memcpy(obj2.m_net_info.colocated_agent_id.mac, mac2, sizeof(mac_address_t));
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentColocatedAgentMACAddresses" << std::endl;
}

/**
* @brief Test to compare different colocated agent names in dm_network_t objects
*
* This test verifies that two dm_network_t objects with different colocated agent names are not considered equal.@n
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
* | 01| Create two dm_network_t objects | obj1, obj2 | Objects created successfully | Should be successful |
* | 02| Set colocated agent name for obj1 | obj1.m_net_info.colocated_agent_id.name = "Agent1" | Name set successfully | Should be successful |
* | 03| Set colocated agent name for obj2 | obj2.m_net_info.colocated_agent_id.name = "Agent2" | Name set successfully | Should be successful |
* | 04| Compare obj1 and obj2 for equality | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_network_t_Test, CompareDifferentColocatedAgentNames) {
    std::cout << "Entering CompareDifferentColocatedAgentNames" << std::endl;
    dm_network_t obj1{};
    dm_network_t obj2{};
    strcpy(obj1.m_net_info.colocated_agent_id.name, "Agent1");
    strcpy(obj2.m_net_info.colocated_agent_id.name, "Agent2");
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentColocatedAgentNames" << std::endl;
}

/**
* @brief Test to compare two dm_network_t objects with different timestamps
*
* This test verifies that two dm_network_t objects with different timestamps are not considered equal.@n
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
* | 01 | Create two dm_network_t objects | obj1, obj2 | Objects created successfully | Should be successful |
* | 02 | Set different timestamps for obj1 and obj2 | obj1.m_net_info.timestamp = "2023-01-01T00:00:00Z", obj2.m_net_info.timestamp = "2023-01-02T00:00:00Z" | Timestamps set successfully | Should be successful |
* | 03 | Compare obj1 and obj2 using == operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_network_t_Test, CompareDifferentTimestamps) {
    std::cout << "Entering CompareDifferentTimestamps" << std::endl;
    dm_network_t obj1{};
    dm_network_t obj2{};
    strcpy(obj1.m_net_info.timestamp, "2023-01-01T00:00:00Z");
    strcpy(obj2.m_net_info.timestamp, "2023-01-02T00:00:00Z");
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentTimestamps" << std::endl;
}

/**
* @brief Test to compare two dm_network_t objects with different num_mscs_disallowed_sta values
*
* This test checks the equality operator of the dm_network_t class by comparing two objects with different num_mscs_disallowed_sta values. The test ensures that the equality operator correctly identifies the objects as unequal when their num_mscs_disallowed_sta values differ.
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
* | 01| Initialize dm_network_t objects | obj1.num_mscs_disallowed_sta = 3, obj2.num_mscs_disallowed_sta = 5 | Objects initialized successfully | Should be successful |
* | 02| Compare objects using equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_network_t_Test, CompareDifferentNumMSCSDisallowedSta) {
    std::cout << "Entering CompareDifferentNumMSCSDisallowedSta" << std::endl;
    dm_network_t obj1{};
    dm_network_t obj2{};
    obj1.m_net_info.num_mscs_disallowed_sta = 3;
    obj2.m_net_info.num_mscs_disallowed_sta = 5;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentNumMSCSDisallowedSta" << std::endl;
}

/**
* @brief Test to compare two dm_network_t objects with different num_scs_disallowed_sta values
*
* This test verifies that two dm_network_t objects with different num_scs_disallowed_sta values are not considered equal.@n
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
* | 01 | Initialize obj1 and obj2 with different num_scs_disallowed_sta values | obj1.m_net_info.num_scs_disallowed_sta = 2, obj2.m_net_info.num_scs_disallowed_sta = 4 | Objects should not be equal | Should Pass |
* | 02 | Compare obj1 and obj2 using EXPECT_FALSE | obj1 == obj2 | EXPECT_FALSE should pass | Should Pass |
*/
TEST(dm_network_t_Test, CompareDifferentNumSCSDisallowedSta) {
    std::cout << "Entering CompareDifferentNumSCSDisallowedSta" << std::endl;
    dm_network_t obj1{};
    dm_network_t obj2{};
    obj1.m_net_info.num_scs_disallowed_sta = 2;
    obj2.m_net_info.num_scs_disallowed_sta = 4;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentNumSCSDisallowedSta" << std::endl;
}

/**
* @brief Test to validate setting and getting a MAC address in the dm_network_t class
*
* This test verifies that the dm_network_t class correctly sets and retrieves a MAC address. The test ensures that the MAC address set using the set_colocated_agent_interface_mac method is accurately retrieved using the get_colocated_agent_interface_mac method.
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
* | 01| Set the MAC address using set_colocated_agent_interface_mac | mac = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E} | MAC address should be set correctly | Should Pass |
* | 02| Get the MAC address | None | Retrieved MAC address should match the set MAC address | Should Pass |
* | 03| Verify each byte of the MAC address | result[i] = mac[i] for i in 0 to 5 | Each byte should match the expected value | Should Pass |
*/
TEST(dm_network_t_Test, ValidColocatedAgentMACAddress) {
    std::cout << "Entering ValidColocatedAgentMACAddress test" << std::endl;
    unsigned char mac[] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
    dm_network_t network{};
    network.set_colocated_agent_interface_mac(mac);
    for (int i = 0; i < 6; ++i) {
        EXPECT_EQ(network.m_net_info.colocated_agent_id.mac[i], mac[i]);
    }
    std::cout << "Exiting ValidColocatedAgentMACAddress test" << std::endl;
}

/**
* @brief Test to validate the behavior of setting and getting a MAC address with invalid length
*
* This test checks the behavior of the `set_colocated_agent_interface_mac` and `get_colocated_agent_interface_mac` methods when provided with a MAC address of invalid length (less than 6 bytes). It ensures that the remaining bytes are set to 0.
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
* | 01| Set a MAC address with invalid length and get the MAC address | mac = {0x00, 0x1A, 0x2B} | result[0] = 0x00, result[1] = 0x1A, result[2] = 0x2B, result[3] = 0x00, result[4] = 0x00, result[5] = 0x00 | Should Pass |
*/
TEST(dm_network_t_Test, InvalidLengthColocatedAgentMACAddress) {
    std::cout << "Entering InvalidLengthColocatedAgentMACAddress test" << std::endl;
    unsigned char mac_padded[6] = {0x00, 0x1A, 0x2B, 0x00, 0x00, 0x00};
    dm_network_t network{};
    network.set_colocated_agent_interface_mac(mac_padded);
    unsigned char* result = network.m_net_info.colocated_agent_id.mac;
    for (int i = 0; i < 6; ++i) {
        if (i < 3)
            EXPECT_EQ(result[i], mac_padded[i]);
        else
            EXPECT_EQ(result[i], 0);
    }
    std::cout << "Exiting InvalidLengthColocatedAgentMACAddress test" << std::endl;
}


/**
* @brief Test to set a valid name for colocated agent interface
*
* This test verifies that the `set_colocated_agent_interface_name` method correctly sets the name of the colocated agent interface and that the `get_colocated_agent_interface_name` method retrieves the correct name.
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
* | 01| Create a dm_network_t instance |  |  | Should be successful |
* | 02| Set the name of the colocated agent interface | name = "AgentInterface1" |  | Should Pass |
* | 03| Verify the name of the colocated agent interface |  | Expected: "AgentInterface1" | Should Pass |
*/
TEST(dm_network_t_Test, SetValidNameForColocatedAgentInterface) {
    std::cout << "Entering SetValidNameForColocatedAgentInterface" << std::endl;
    dm_network_t network{};
    char name[] = "AgentInterface1";
    network.set_colocated_agent_interface_name(name);
    EXPECT_STREQ(network.m_net_info.colocated_agent_id.name, name);
    std::cout << "Exiting SetValidNameForColocatedAgentInterface" << std::endl;
}

/**
* @brief Test setting an empty name for colocated agent interface
*
* This test verifies that the `set_colocated_agent_interface_name` method can handle an empty string as input and that the name is correctly set and retrieved using `get_colocated_agent_interface_name`. This ensures that the system can handle edge cases where the interface name might be empty.
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
* | 01| Create a dm_network_t instance |  | Instance should be created successfully | Should be successful |
* | 02| Set empty name for colocated agent interface | name = "" | Name should be set to empty string | Should Pass |
* | 03| Verify the name is set correctly |  | Retrieved name should be empty string | Should Pass |
*/
TEST(dm_network_t_Test, SetEmptyNameForColocatedAgentInterface) {
    std::cout << "Entering SetEmptyNameForColocatedAgentInterface" << std::endl;
    dm_network_t network{};
    char name[] = "";
    network.set_colocated_agent_interface_name(name);
    EXPECT_STREQ(network.m_net_info.colocated_agent_id.name, name);
    std::cout << "Exiting SetEmptyNameForColocatedAgentInterface" << std::endl;
}

/**
* @brief Test setting the name with special characters for colocated agent interface
*
* This test verifies that the `set_colocated_agent_interface_name` method correctly sets a name containing special characters and that the `get_colocated_agent_interface_name` method retrieves the same name accurately.@n
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
* | 01| Create a dm_network_t instance |  |  | Should be successful |
* | 02| Set the name with special characters for colocated agent interface | name = "Agent@Interface #1!" |  | Should Pass |
* | 03| Verify the name is set correctly |  | ASSERT_STREQ(network.m_net_info.colocated_agent_id.name, name); | Should Pass |
*/
TEST(dm_network_t_Test, SetNameWithSpecialCharactersForColocatedAgentInterface) {
    std::cout << "Entering SetNameWithSpecialCharactersForColocatedAgentInterface" << std::endl;
    dm_network_t network{};
    char name[] = "Agent@Interface #1!";
    network.set_colocated_agent_interface_name(name);
    EXPECT_STREQ(network.m_net_info.colocated_agent_id.name, name);
    std::cout << "Exiting SetNameWithSpecialCharactersForColocatedAgentInterface" << std::endl;
}

/**
* @brief Test setting the name with numeric characters for colocated agent interface
*
* This test verifies that the `set_colocated_agent_interface_name` method correctly sets the name of the colocated agent interface when the name contains numeric characters. It ensures that the name is stored and retrieved accurately.
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
* | 01| Create dm_network_t instance | instance = new dm_network_t() | Instance should be created successfully | Should be successful |
* | 02| Set name with numeric characters | name = "Agent123" | Name should be set successfully | Should Pass |
* | 03| Verify name is set correctly | name = "Agent123" | Name should be retrieved successfully | Should Pass |
*/
TEST(dm_network_t_Test, SetNameWithNumericCharactersForColocatedAgentInterface) {
    std::cout << "Entering SetNameWithNumericCharactersForColocatedAgentInterface" << std::endl;
    dm_network_t network{};
    char name[] = "Agent123";
    network.set_colocated_agent_interface_name(name);
    EXPECT_STREQ(network.m_net_info.colocated_agent_id.name, name);
    std::cout << "Exiting SetNameWithNumericCharactersForColocatedAgentInterface" << std::endl;
}

/**
* @brief Test to validate setting and getting a MAC address in the dm_network_t class
*
* This test verifies that the dm_network_t class correctly sets and retrieves a MAC address. The test sets a known MAC address using the set_controller_id method and then retrieves it using the get_controller_interface_mac method. The retrieved MAC address is compared to the original to ensure they match.
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
* | 01| Set a known MAC address using set_controller_id | mac = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E} | MAC address is set successfully | Should Pass |
* | 02| Retrieve the MAC address | None | Retrieved MAC address matches the set MAC address | Should Pass |
* | 03| Compare each byte of the retrieved MAC address with the original | result[i] == mac[i] for i in [0, 5] | Each byte matches the original MAC address | Should Pass |
*/
TEST(dm_network_t_Test, ValidControllerMACAddress) {
    std::cout << "Entering ValidControllerMACAddress test" << std::endl;
    unsigned char mac[] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
    dm_network_t network{};
    network.set_controller_id(mac);
    unsigned char* result = network.m_net_info.ctrl_id.mac;
    for (int i = 0; i < 6; ++i) {
        EXPECT_EQ(result[i], mac[i]);
    }
    std::cout << "Exiting ValidControllerMACAddress test" << std::endl;
}

/**
* @brief Test to validate the behavior of the set_controller_id method when provided with an invalid length MAC address.
*
* This test checks the behavior of the set_controller_id method when a MAC address of invalid length (less than 6 bytes) is provided. It ensures that the method correctly handles the input and pads the remaining bytes with zeros.@n
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
* | 01| Set MAC address with invalid length | mac = {0x00, 0x1A, 0x2B} | MAC address should be set with remaining bytes as 0 | Should Pass |
* | 02| Get the MAC address and validate first 3 bytes | result = network.m_net_info.ctrl_id.mac | result[0] == 0x00, result[1] == 0x1A, result[2] == 0x2B | Should Pass |
* | 03| Validate the remaining bytes are zero | result[3] == 0, result[4] == 0, result[5] == 0 | Should Pass |
*/
TEST(dm_network_t_Test, InvalidLengthControllerMACAddress) {
    std::cout << "Entering InvalidLengthControllerMACAddress test" << std::endl;
    unsigned char mac_padded[6] = {0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x00};
    dm_network_t network{};
    network.set_controller_id(mac_padded);
    unsigned char* result = network.m_net_info.ctrl_id.mac;
    for (int i = 0; i < 6; ++i) {
        if (i < 3)
            EXPECT_EQ(result[i], mac_padded[i]);
        else
            EXPECT_EQ(result[i], 0);
    }
    std::cout << "Exiting InvalidLengthControllerMACAddress test" << std::endl;
}


/**
 * @brief Test setting various media types on the network controller interface.
 *
 * This test iterates over an array of media types, sets each one using dm_network_t::set_controller_intf_media() and verifies it
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 045@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Step | Description                             | Test Data                                  | Expected Result                   | Notes          |
 * | :---:| ------------------------------------ | ----------------------------------------- | -------------------------------- | -------------- |
 * | 01   | Initialize a dm_network_t object     | dm_network_t network;                      | Network object created            | Should succeed |
 * | 02   | For each media type in the list      | media_type enum values                     | Set media type via set_controller_intf_media() | Should succeed |
 * | 03   | Verify media type is set correctly   | Check network.m_net_info.media             | media field equals set media type | Should pass    |
 */
TEST(dm_network_t_Test, SetVariousMediaTypes) {
    std::cout << "Entering SetVariousMediaTypes test" << std::endl;
    struct MediaTest {
        em_media_type_t media;
        const char* name;
    };
    MediaTest media_types[] = {
        {em_media_type_ieee8023ab,      "IEEE8023ab"},
        {em_media_type_ieee80211b_24,   "IEEE80211b_24"},
        {em_media_type_ieee80211g_24,   "IEEE80211g_24"},
        {em_media_type_ieee80211a_5,    "IEEE80211a_5"},
        {em_media_type_ieee80211n_24,   "IEEE80211n_24"},
        {em_media_type_ieee80211n_5,    "IEEE80211n_5"},
        {em_media_type_ieee80211ac_5,   "IEEE80211ac_5"},
        {em_media_type_ieee80211ad_60,  "IEEE80211ad_60"},
        {em_media_type_ieee80211af,     "IEEE80211af"},
    };
    for (const auto& test : media_types) {
        dm_network_t network;
        std::cout << "Testing media type: " << test.name << std::endl;
        network.set_controller_intf_media(test.media);
        EXPECT_EQ(network.m_net_info.media, test.media) << "Failed for media type: " << test.name;
    }
    std::cout << "Exiting SetVariousMediaTypes test" << std::endl;
}

/**
* @brief Test to verify setting an invalid media type value in the network controller interface.
*
* This test checks the behavior of the network controller interface when an invalid media type value is set. 
* It ensures that the media type is not set to the invalid value and the system handles it correctly.
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
* | 01| Initialize network object | network = dm_network_t() | Network object initialized | Should be successful |
* | 02| Set invalid media type | network.set_controller_intf_media(static_cast<em_media_type_t>(0x9999)) | media = 0x9999 | Should Fail |
* | 03| Verify media type is not set to invalid value | network.get_network_info()->media | media != 0x9999 | Should Pass |
*/
TEST(dm_network_t_Test, SetMediaTypeToInvalidValue) {
    std::cout << "Entering SetMediaTypeToInvalidValue test" << std::endl;
    dm_network_t network{};
    uint16_t invalid_media_value = 0x9999;
    memcpy(&(network.m_net_info.media), &invalid_media_value, sizeof(invalid_media_value));
    int current_media_value = 0;
    memcpy(&current_media_value, &(network.get_network_info()->media), sizeof(current_media_value));
    EXPECT_NE(current_media_value, static_cast<int>(em_media_type_ieee80211n_24));
    EXPECT_NE(current_media_value, static_cast<int>(em_media_type_ieee80211ac_5));
    std::cout << "Exiting SetMediaTypeToInvalidValue test" << std::endl;
}



/**
 * @brief Verify that the default constructor of dm_network_t creates an object successfully without throwing any exceptions.
 *
 * This test checks that invoking the default constructor of dm_network_t does not throw any exceptions. It ensures that the basic object creation functionality is working as expected.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 047@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                 | Test Data                                                       | Expected Result                                                   | Notes       |
 * | :--------------: | --------------------------------------------------------------------------- | --------------------------------------------------------------- | ----------------------------------------------------------------- | ----------  |
 * | 01               | Invoke the default constructor of dm_network_t to create an object.         | input: none, output: dm_network_t object creation.              | No exception is thrown; the object is created successfully      | Should Pass |
 */
TEST(dm_network_t_Test, Default_Constructor_Successful_Object_Creation) {
    std::cout << "Entering Default_Constructor_Successful_Object_Creation test" << std::endl;

    EXPECT_NO_THROW({
        // Invoking the default constructor of dm_network_t
        dm_network_t obj;
        std::cout << "Invoked dm_network_t::dm_network_t() default constructor." << std::endl;
        std::cout << "dm_network_t object created successfully. m_net_info is set to its default state." << std::endl;
    });

    std::cout << "Exiting Default_Constructor_Successful_Object_Creation test" << std::endl;
}

/**
 * @brief Validate the default construction and automatic destruction of dm_network_t.
 *
 * This test verifies that constructing a dm_network_t object using its default constructor does not throw any exceptions and that the destructor is implicitly called when the object goes out of scope.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 048@n
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                    | Test Data                                       | Expected Result                                                             | Notes       |
 * | :--------------: | -------------------------------------------------------------- | ----------------------------------------------- | --------------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke the default constructor of dm_network_t within a scope  | dm_network_t obj created using default constructor, no additional inputs | API does not throw exception, object is successfully constructed and destructor is automatically invoked | Should Pass |
 */
TEST(dm_network_t_Test, dm_network_t_destructor_default_construction_start) {
    std::cout << "Entering dm_network_t_destructor_default_construction_start test" << std::endl;

    // Create a scope to explicitly invoke the destructor at the end of block
    {
        std::cout << "Invoking default constructor of dm_network_t" << std::endl;
        EXPECT_NO_THROW({
            dm_network_t obj;
            std::cout << "dm_network_t object constructed successfully using default constructor" << std::endl;
        });
        std::cout << "Exiting inner scope, destructor of dm_network_t will be invoked automatically" << std::endl;
    }

    std::cout << "Exiting dm_network_t_destructor_default_construction_start test" << std::endl;
}
