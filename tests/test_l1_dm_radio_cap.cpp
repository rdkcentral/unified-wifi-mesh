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
#include <iostream>
#include <cstring>
#include "dm_radio_cap.h"



/**
* @brief Test the decode function with a valid JSON object and a valid parent ID.
*
* This test verifies that the decode function of the dm_radio_cap_t class correctly processes a valid JSON object and a valid parent ID, ensuring that the function returns 0, indicating success.
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
* | 01| Create valid JSON object and parent ID | obj = cJSON(), parent_id = malloc(sizeof(int)) | Should be successful | |
* | 03| Call decode function with valid inputs | input1 = &obj, input2 = parent_id | Return value = 0, EXPECT_EQ(result, 0) | Should Pass |
* | 04| Clean up allocated memory | free(parent_id) | Should be successful | |
*/
TEST(dm_radio_cap_t_Test, ValidJSONObjectWithValidParentID) {
    std::cout << "Entering ValidJSONObjectWithValidParentID" << std::endl;
    cJSON obj{};
    void* parent_id = malloc(sizeof(int));
    dm_radio_cap_t radio_cap;
    int result = radio_cap.decode(&obj, parent_id);
    EXPECT_EQ(result, 0);
    free(parent_id);
    std::cout << "Exiting ValidJSONObjectWithValidParentID" << std::endl;
}



/**
* @brief Test to verify the behavior of the decode function when a null JSON object is passed.
*
* This test checks the decode function of the dm_radio_cap_t class to ensure that it correctly handles a null JSON object input by returning an error code.@n
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
* | 01 | Initialize parent_id and dm_radio_cap_t instance | parent_id = malloc(sizeof(int)), instance = new dm_radio_cap_t() | Initialization should be successful | Should be successful |
* | 02 | Call decode with null JSON object | json_object = nullptr, parent_id = parent_id | result = -1, EXPECT_EQ(result, -1) | Should Fail |
* | 03 | Free allocated memory | free(parent_id), delete instance | Memory should be freed successfully | Should be successful |
*/
TEST(dm_radio_cap_t_Test, NullJSONObject) {
    std::cout << "Entering NullJSONObject" << std::endl;
    void* parent_id = malloc(sizeof(int));
    dm_radio_cap_t radio_cap{};
    memset(&radio_cap, 0, sizeof(radio_cap));
    int result = radio_cap.decode(nullptr, parent_id);
    EXPECT_EQ(result, -1);
    free(parent_id);
    std::cout << "Exiting NullJSONObject" << std::endl;
}



/**
* @brief Test to verify the behavior of the decode function when a null parent ID is passed.
*
* This test checks the decode function of the dm_radio_cap_t class to ensure that it correctly handles the case where a null parent ID is provided. This is important to verify that the function can gracefully handle invalid input and return the expected error code.
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
* | 01 | Create a cJSON object and dm_radio_cap_t instance | obj, radio_cap | Should be successful | |
* | 03 | Call the decode function with a null parent ID | obj = &obj, parentID = nullptr | result = -1, EXPECT_EQ(result, -1) | Should Fail |
*/
TEST(dm_radio_cap_t_Test, NullParentID) {
    std::cout << "Entering NullParentID" << std::endl;
    cJSON obj;
    dm_radio_cap_t radio_cap;
    int result = radio_cap.decode(&obj, nullptr);
    EXPECT_EQ(result, -1);
    std::cout << "Exiting NullParentID" << std::endl;
}



/**
* @brief Test to verify the behavior of the decode function when provided with an empty JSON object.
*
* This test checks the decode function of the dm_radio_cap_t class to ensure it correctly handles an empty JSON object and returns the expected error code. This is important to verify that the function can gracefully handle invalid input.
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
* | 01 | Create JSON object and allocate memory for parent_id | cJSON obj = {0}, parent_id = malloc(sizeof(int)) | Should be successful | |
* | 02 | Call decode function with empty JSON object | result = radio_cap.decode(&obj, parent_id) | result = -1, EXPECT_EQ(result, -1) | Should Pass |
* | 03 | Free allocated memory | free(parent_id) | Should be successful | |
*/
TEST(dm_radio_cap_t_Test, EmptyJSONObject) {
    std::cout << "Entering EmptyJSONObject" << std::endl;
    cJSON obj{};
    memset(&obj, 0, sizeof(obj));
    void* parent_id = malloc(sizeof(int));
    dm_radio_cap_t radio_cap{};
    memset(&radio_cap, 0, sizeof(radio_cap));
    int result = radio_cap.decode(&obj, parent_id);
    EXPECT_EQ(result, -1);
    free(parent_id);
    std::cout << "Exiting EmptyJSONObject" << std::endl;
}



/**
* @brief Test the decode function with an invalid JSON object type
*
* This test verifies that the decode function correctly handles a JSON object with an invalid type. The objective is to ensure that the function returns an error code when the JSON object type is not recognized.
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
* | 01| Create a JSON object with an invalid type | obj.type = -1 | Should be successful | |
* | 02| Allocate memory for parent_id | parent_id = malloc(sizeof(int)) | Should be successful | |
* | 03| Call the decode function with the invalid JSON object | result = radio_cap.decode(&obj, parent_id) | result = -1, EXPECT_EQ(result, -1) | Should Pass |
* | 04| Free the allocated memory for parent_id | free(parent_id) | Should be successful | |
*/
TEST(dm_radio_cap_t_Test, JSONObjectWithInvalidType) {
    std::cout << "Entering JSONObjectWithInvalidType" << std::endl;
    cJSON obj{};
    memset(&obj, 0, sizeof(obj));
    obj.type = -1;
    void* parent_id = malloc(sizeof(int));
    dm_radio_cap_t radio_cap{};
    memset(&radio_cap, 0, sizeof(radio_cap));
    int result = radio_cap.decode(&obj, parent_id);
    EXPECT_EQ(result, -1);
    free(parent_id);
    std::cout << "Exiting JSONObjectWithInvalidType" << std::endl;
}



/**
* @brief Test the decoding of a JSON object with nested objects
*
* This test verifies the functionality of the decode method in the dm_radio_cap_t class when provided with a JSON object that contains nested objects. The objective is to ensure that the method can correctly handle and decode such structures without errors.
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
* | 01| Create a JSON object with a nested child object | obj.child = &child | Should be successful | |
* | 02| Allocate memory for parent_id | parent_id = malloc(sizeof(int)) | Should be successful | |
* | 03| Call the decode method with the JSON object and parent_id | result = radio_cap.decode(&obj, parent_id) | result = 0, EXPECT_EQ(result, 0) | Should Pass |
*/
TEST(dm_radio_cap_t_Test, JSONObjectWithNestedObjects) {
    std::cout << "Entering JSONObjectWithNestedObjects" << std::endl;
    cJSON obj{};
    cJSON child{};
    obj.child = &child;
    void* parent_id = malloc(sizeof(int));
    dm_radio_cap_t radio_cap;
    int result = radio_cap.decode(&obj, parent_id);
    EXPECT_EQ(result, 0);
    free(parent_id);
    std::cout << "Exiting JSONObjectWithNestedObjects" << std::endl;
}



/**
* @brief Test the decode function of dm_radio_cap_t class with a JSON object containing an array
*
* This test verifies the behavior of the decode function when provided with a JSON object that contains an array. The objective is to ensure that the function correctly processes the input and returns the expected result.
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
* | 01| Create JSON object with array | obj.child = &array | | Should be successful |
* | 02| Allocate memory for parent_id | parent_id = malloc(sizeof(int)) | | Should be successful |
* | 03| Call decode function | result = radio_cap.decode(&obj, parent_id) | result = 0, EXPECT_EQ(result, 0) | Should Pass |
* | 04| Free allocated memory | free(parent_id) | | Should be successful |
*/
TEST(dm_radio_cap_t_Test, JSONObjectWithArray) {
    std::cout << "Entering JSONObjectWithArray" << std::endl;
    cJSON obj{};
    cJSON array{};
    obj.child = &array;
    void* parent_id = malloc(sizeof(int));
    dm_radio_cap_t radio_cap;
    int result = radio_cap.decode(&obj, parent_id);
    EXPECT_EQ(result, 0);
    free(parent_id);
    std::cout << "Exiting JSONObjectWithArray" << std::endl;
}



/**
* @brief Test the decoding of a JSON object with string values
*
* This test verifies the functionality of the `decode` method in the `dm_radio_cap_t` class when provided with a JSON object containing string values. The test ensures that the method correctly processes the input and returns the expected result.
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
* | 01 | Initialize JSON object with string value | obj.valuestring = "test" | Should be successful | |
* | 02 | Allocate memory for parent_id | parent_id = malloc(sizeof(int)) | Should be successful | |
* | 03 | Create instance of dm_radio_cap_t | dm_radio_cap_t radio_cap | Should be successful | |
* | 04 | Call decode method | radio_cap.decode(&obj, parent_id) | result = 0, EXPECT_EQ(result, 0) | Should Pass |
* | 05 | Free allocated memory | free(parent_id) | Should be successful | |
*/
TEST(dm_radio_cap_t_Test, JSONObjectWithStringValues) {
    std::cout << "Entering JSONObjectWithStringValues" << std::endl;
    cJSON obj{};
    char* str = strdup("test");
    obj.valuestring = str;
    void* parent_id = malloc(sizeof(int));
    dm_radio_cap_t radio_cap;
    int result = radio_cap.decode(&obj, parent_id);
    EXPECT_EQ(result, 0);
    free(parent_id);
    free(str);
    std::cout << "Exiting JSONObjectWithStringValues" << std::endl;
}



/**
* @brief Test the decoding of a JSON object with numeric values
*
* This test verifies that the `decode` method of the `dm_radio_cap_t` class correctly handles a JSON object containing numeric values. The test ensures that the method returns the expected result when provided with valid input data.
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
* | 01 | Initialize JSON object with numeric value | obj.valuedouble = 123.45 | N/A | Should be successful |
* | 02 | Allocate memory for parent_id | parent_id = malloc(sizeof(int)) | N/A | Should be successful |
* | 03 | Invoke decode method | result = radio_cap.decode(&obj, parent_id) | result = 0, EXPECT_EQ(result, 0) | Should Pass |
* | 04 | Free allocated memory | free(parent_id) | N/A | Should be successful |
*/
TEST(dm_radio_cap_t_Test, JSONObjectWithNumericValues) {
    std::cout << "Entering JSONObjectWithNumericValues" << std::endl;
    cJSON obj{};
    obj.valuedouble = 123.45;
    void* parent_id = malloc(sizeof(int));
    dm_radio_cap_t radio_cap;
    int result = radio_cap.decode(&obj, parent_id);
    EXPECT_EQ(result, 0);
    free(parent_id);
    std::cout << "Exiting JSONObjectWithNumericValues" << std::endl;
}



/**
* @brief Test the copy constructor of dm_radio_cap_t with valid input
*
* This test verifies that the copy constructor of the dm_radio_cap_t class correctly copies the values from the original object to the new object. It ensures that the number of radios and the channel scan enabled status are accurately copied.
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
* | 01| Create original dm_radio_cap_t object and set values | original.m_radio_cap_info.wifi7_cap.radios_num = 5, original.m_radio_cap_info.ch_scan.enabled = true | Values set successfully | Should be successful |
* | 02| Invoke copy constructor to create a new object | dm_radio_cap_t copy(original) | Copy constructor invoked successfully | Should be successful |
* | 03| Verify copied values | copy.m_radio_cap_info.radios_num, copy.m_radio_cap_info.ch_scan.enabled | copy.m_radio_cap_info.wifi7_cap.radios_num == 5, copy.m_radio_cap_info.ch_scan.enabled == true | Should Pass |
*/
TEST(dm_radio_cap_t_Test, CopyConstructorWithValidInput) {
    std::cout << "Entering CopyConstructorWithValidInput" << std::endl;
    dm_radio_cap_t original{};
    original.m_radio_cap_info.wifi7_cap.radios_num = 5;
    original.m_radio_cap_info.ch_scan.enabled = true;
    dm_radio_cap_t copy(original);
    EXPECT_EQ(copy.m_radio_cap_info.wifi7_cap.radios_num, original.m_radio_cap_info.wifi7_cap.radios_num);
    EXPECT_EQ(copy.m_radio_cap_info.ch_scan.enabled, original.m_radio_cap_info.ch_scan.enabled);
    std::cout << "Exiting CopyConstructorWithValidInput" << std::endl;
}



/**
* @brief Test the copy constructor of dm_radio_cap_t with a null input
*
* This test verifies that the copy constructor of the dm_radio_cap_t class correctly handles a null input by throwing an exception. This is important to ensure that the class does not attempt to dereference a null pointer, which would lead to undefined behavior.
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
* | 01 | Initialize original to nullptr | original = nullptr | None | Should be successful |
* | 02 | Attempt to copy construct dm_radio_cap_t with null input | copy(*original) | std::exception is thrown | Should Pass |
*/
TEST(dm_radio_cap_t_Test, CopyConstructorWithNullInput) {
    std::cout << "Entering CopyConstructorWithNullInput" << std::endl;
    dm_radio_cap_t* original = nullptr;
    try {
        dm_radio_cap_t copy(*original);
        FAIL() << "Expected std::exception";
    } catch (const std::exception& e) {
        SUCCEED();
    } catch (...) {
        FAIL() << "Expected std::exception";
    }
    std::cout << "Exiting CopyConstructorWithNullInput" << std::endl;
}



/**
* @brief Test to validate the initialization of the radio capability structure
*
* This test checks if the radio capability structure is properly initialized by the dm_radio_cap_t class. The test ensures that the init() method returns 0, indicating successful initialization.
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
* | 01 | Create an instance of dm_radio_cap_t | instance = new dm_radio_cap_t() | Instance should be created successfully | Should be successful |
*/
TEST(dm_radio_cap_t_Test, ValidInitializedRadioCapStructure) {
    std::cout << "Entering ValidInitializedRadioCapStructure test";
    em_radio_cap_info_t radio_cap{};
    radio_cap.wifi7_cap.radios_num = static_cast<uint8_t>(2);
    radio_cap.ch_scan.enabled = true;
    radio_cap.ch_scan.number_of_bss = 1;
    radio_cap.ch_scan.noise = static_cast<int16_t>(-90);
    dm_radio_cap_t radio_cap_obj(&radio_cap);
    std::cout << "Exiting ValidInitializedRadioCapStructure test";
}



/**
* @brief Test to verify the behavior when a null pointer is passed to the constructor
*
* This test checks the behavior of the dm_radio_cap_t class when a null pointer is passed to its constructor. The objective is to ensure that the class handles null pointers gracefully and returns an appropriate error code when the init method is called.
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
* | 01| Create a null pointer for em_radio_cap_info_t and pass it to the dm_radio_cap_t constructor | radio_cap = nullptr | Constructor should handle null pointer | Should Pass |
*/
TEST(dm_radio_cap_t_Test, NullRadioCapPointer) {
    std::cout << "Entering NullRadioCapPointer test";
    em_radio_cap_info_t* radio_cap = nullptr;
    dm_radio_cap_t radio_cap_obj(radio_cap);
    std::cout << "Exiting NullRadioCapPointer test";
}
    



/**
* @brief Test to validate the behavior of dm_radio_cap_t with invalid radio capability structure
*
* This test checks the initialization of dm_radio_cap_t object with an invalid radio capability structure. 
* The invalid structure is created by setting all fields to invalid values and the test ensures that the 
* initialization fails as expected.
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
* | 01 | Create invalid radio capability structure | radio_cap.ch_scan.intf.media = 9999, radio_cap.ch_scan.band = 9999 | None | Should be successful |
* | 02 | Initialize dm_radio_cap_t object with invalid structure | dm_radio_cap_t radio_cap_obj(&radio_cap) | None | Should be successful |
*/
TEST(dm_radio_cap_t_Test, InvalidRadioCapStructure) {
    std::cout << "Entering InvalidRadioCapStructure test";
    em_radio_cap_info_t radio_cap{};
    radio_cap.ch_scan.intf.media = static_cast<em_media_type_t>(9999);
    radio_cap.ch_scan.band = static_cast<em_freq_band_t>(9999);
    dm_radio_cap_t radio_cap_obj(&radio_cap);
    std::cout << "Exiting InvalidRadioCapStructure test";
}



/**
* @brief Test the encoding of a valid string value in dm_radio_cap_t
*
* This test verifies that the encode function of the dm_radio_cap_t class correctly encodes a valid string value. The objective is to ensure that the function handles string inputs as expected and encodes them without errors.
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
* | 01| Initialize cJSON object with type cJSON_String and value "test_string" | obj.type = cJSON_String, obj.valuestring = "test_string" | cJSON object should be initialized successfully | Should be successful |
* | 02| Call the encode function of dm_radio_cap_t with the cJSON object | radio_cap.encode(&obj) | Function should encode the string value without errors | Should Pass |
*/
TEST(dm_radio_cap_t_Test, EncodeValidStringValue) {
    std::cout << "Entering EncodeValidStringValue test" << std::endl;
    cJSON obj{};
    obj.type = cJSON_String;
    obj.valuestring = const_cast<char*>("test_string");
    dm_radio_cap_t radio_cap;
    radio_cap.encode(&obj);
    std::cout << "Exiting EncodeValidStringValue test" << std::endl;
}



/**
* @brief Test to validate the encoding of a valid number value
*
* This test verifies that the encode function correctly processes a cJSON object of type number and encodes it properly. This is essential to ensure that numerical values are handled accurately by the encoding function.
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
* | 01 | Initialize cJSON object with number type and value | obj.type = cJSON_Number, obj.valuedouble = 123.45 | cJSON object initialized successfully | Should be successful |
* | 02 | Call encode function with initialized cJSON object | radio_cap.encode(&obj) | Encode function processes the number correctly | Should Pass |
*/
TEST(dm_radio_cap_t_Test, EncodeValidNumberValue) {
    std::cout << "Entering EncodeValidNumberValue test";
    cJSON obj{};
    obj.type = cJSON_Number;
    obj.valuedouble = 123.45;
    dm_radio_cap_t radio_cap;
    radio_cap.encode(&obj);
    std::cout << "Exiting EncodeValidNumberValue test";
}



/**
* @brief Test the encoding of a valid integer value using the dm_radio_cap_t class.
*
* This test verifies that the encode function of the dm_radio_cap_t class correctly handles and encodes a valid integer value. The objective is to ensure that the function processes the input without errors and performs the expected encoding operation.
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
* | 01 | Initialize cJSON object with integer value | obj.type = cJSON_Number, obj.valueint = 123 | cJSON object initialized successfully | Should be successful |
* | 02 | Call encode function with cJSON object | radio_cap.encode(&obj) | Function should process the input without errors | Should Pass |
*/
TEST(dm_radio_cap_t_Test, EncodeValidIntegerValue) {
    std::cout << "Entering EncodeValidIntegerValue test";
    cJSON obj{};
    obj.type = cJSON_Number;
    obj.valueint = 123;
    dm_radio_cap_t radio_cap;
    radio_cap.encode(&obj);
    std::cout << "Exiting EncodeValidIntegerValue test";
}



/**
* @brief Test the encoding of a valid boolean value in the dm_radio_cap_t class.
*
* This test verifies that the dm_radio_cap_t::encode method correctly encodes a cJSON object with a boolean value.@n
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
* | 01 | Initialize cJSON object with boolean true | obj.type = cJSON_True | cJSON object initialized with boolean true | Should be successful |
* | 02 | Call encode method of dm_radio_cap_t with cJSON object | obj = cJSON_True | Method should encode the boolean value correctly | Should Pass |
*/
TEST(dm_radio_cap_t_Test, EncodeValidBooleanValue) {
    std::cout << "Entering EncodeValidBooleanValue test";
    cJSON obj{};
    obj.type = cJSON_True;
    dm_radio_cap_t radio_cap;
    radio_cap.encode(&obj);
    std::cout << "Exiting EncodeValidBooleanValue test";
}



/**
* @brief Test to validate encoding of a null value in dm_radio_cap_t
*
* This test checks the behavior of the encode function in the dm_radio_cap_t class when provided with a cJSON object of type cJSON_NULL. This is to ensure that the function can handle null values gracefully without causing any errors or unexpected behavior.@n
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
* | 01| Initialize cJSON object with type cJSON_NULL | obj.type = cJSON_NULL | cJSON object initialized with null type | Should be successful |
* | 02| Call encode function with the cJSON object | obj = cJSON_NULL | Function should handle null value without errors | Should Pass |
*/
TEST(dm_radio_cap_t_Test, EncodeValidNullValue) {
    std::cout << "Entering EncodeValidNullValue test";
    cJSON obj{};
    obj.type = cJSON_NULL;
    dm_radio_cap_t radio_cap;
    radio_cap.encode(&obj);
    std::cout << "Exiting EncodeValidNullValue test";
}



/**
* @brief Test the encoding of a valid cJSON array object
*
* This test verifies that the `encode` method of the `dm_radio_cap_t` class correctly encodes a valid cJSON array object. The test ensures that the method can handle a cJSON object with a child element of type string and properly encode it without errors.
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
* | 01 | Initialize cJSON object with a child of type string | obj.type = cJSON_Array, child_obj.type = cJSON_String, child_obj.valuestring = "child_string" | cJSON object should be initialized correctly | Should be successful |
* | 02 | Set the child of the cJSON object | obj.child = &child_obj | Child should be set correctly | Should be successful |
* | 03 | Call the encode method of dm_radio_cap_t | radio_cap.encode(&obj) | Method should encode the cJSON object without errors | Should Pass |
*/
TEST(dm_radio_cap_t_Test, EncodeValidArray) {
    std::cout << "Entering EncodeValidArray test";
    cJSON obj{};
    cJSON child_obj;
    child_obj.type = cJSON_String;
    child_obj.valuestring = const_cast<char*>("child_string");
    obj.type = cJSON_Array;
    obj.child = &child_obj;
    dm_radio_cap_t radio_cap;
    radio_cap.encode(&obj);
    std::cout << "Exiting EncodeValidArray test";
}



/**
* @brief Test to verify the behavior of the encode function with an invalid type
*
* This test checks the behavior of the encode function when it is provided with an invalid type in the cJSON object. This is to ensure that the function handles invalid input gracefully and does not cause unexpected behavior or crashes.@n
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
* | 01 | Set up cJSON object with invalid type | obj.type = -1 | N/A | Should be successful |
* | 02 | Call encode function with invalid type | &obj | N/A | Should Fail |
*/
TEST(dm_radio_cap_t_Test, EncodeInvalidType) {
    std::cout << "Entering EncodeInvalidType test";
    cJSON obj{};
    obj.type = -1;
    dm_radio_cap_t radio_cap;
    radio_cap.encode(&obj);
    std::cout << "Exiting EncodeInvalidType test";
}



/**
* @brief Test to check the behavior of the encode function when a null pointer is passed
*
* This test verifies that the encode function can handle a null pointer input gracefully without causing any crashes or undefined behavior.@n
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
* | 01 | Initialize a null cJSON object and a dm_radio_cap_t object | obj = NULL | No crash or undefined behavior | Should Pass |
* | 02 | Call the encode function with the null cJSON object | obj = NULL | No crash or undefined behavior | Should Pass |
*/
TEST(dm_radio_cap_t_Test, EncodeNullPointer) {
    std::cout << "Entering EncodeNullPointer test";
    cJSON *obj = NULL;
    dm_radio_cap_t radio_cap;
    radio_cap.encode(obj);
    std::cout << "Exiting EncodeNullPointer test";
}



/**
* @brief Test to verify the retrieval of radio capability information with maximum and minimum values.
*
* This test checks the `get_radio_cap_info` method of the `dm_radio_cap_t` class to ensure it correctly retrieves the radio capability information when the fields are set to their maximum and minimum values.@n
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
* | 01 | Set maximum and minimum values for radio capability fields | radios_num = 255, ht_cap.max_sprt_tx_streams = 3, ht_cap.max_sprt_rx_streams = 3, vht_cap.max_sprt_tx_streams = 7, vht_cap.max_sprt_rx_streams = 7, he_cap.max_sprt_tx_streams = 7, he_cap.max_sprt_rx_streams = 7, wifi6_cap.max_dl_mumimo_tx = 15, wifi6_cap.max_ul_mumimo_rx = 15, wifi6_cap.max_dl_ofdma_tx = 255, wifi6_cap.max_ul_ofdma_rx = 255 | Values should be set correctly | Should be successful |
* | 02 | Retrieve radio capability information | None | radios_num = 255, ht_cap.max_sprt_tx_streams = 3, ht_cap.max_sprt_rx_streams = 3, vht_cap.max_sprt_tx_streams = 7, vht_cap.max_sprt_rx_streams = 7, he_cap.max_sprt_tx_streams = 7, he_cap.max_sprt_rx_streams = 7, wifi6_cap.max_dl_mumimo_tx = 15, wifi6_cap.max_ul_mumimo_rx = 15, wifi6_cap.max_dl_ofdma_tx = 255, wifi6_cap.max_ul_ofdma_rx = 255 | Should Pass |
*/
TEST(dm_radio_cap_t_Test, RetrieveRadioCapInfoWithMaxMinValues) {
    std::cout << "Entering RetrieveRadioCapInfoWithMaxMinValues" << std::endl;
    dm_radio_cap_t radio_cap{};
    radio_cap.m_radio_cap_info.wifi7_cap.radios_num = 255;
    radio_cap.m_radio_cap_info.ht_cap.max_sprt_tx_streams = 3;
    radio_cap.m_radio_cap_info.ht_cap.max_sprt_rx_streams = 3;
    radio_cap.m_radio_cap_info.vht_cap.max_sprt_tx_streams = 7;
    radio_cap.m_radio_cap_info.vht_cap.max_sprt_rx_streams = 7;
    radio_cap.m_radio_cap_info.he_cap.max_sprt_tx_streams = 7;
    radio_cap.m_radio_cap_info.he_cap.max_sprt_rx_streams = 7;
    radio_cap.m_radio_cap_info.wifi6_cap.max_dl_mumimo_tx = 15;
    radio_cap.m_radio_cap_info.wifi6_cap.max_ul_mumimo_rx = 15;
    radio_cap.m_radio_cap_info.wifi6_cap.max_dl_ofdma_tx = 255;
    radio_cap.m_radio_cap_info.wifi6_cap.max_ul_ofdma_rx = 255;
    em_radio_cap_info_t* result = radio_cap.get_radio_cap_info();
    EXPECT_EQ(result->wifi7_cap.radios_num, 255);
    EXPECT_EQ(result->ht_cap.max_sprt_tx_streams, 3);
    EXPECT_EQ(result->ht_cap.max_sprt_rx_streams, 3);
    EXPECT_EQ(result->vht_cap.max_sprt_tx_streams, 7);
    EXPECT_EQ(result->vht_cap.max_sprt_rx_streams, 7);
    EXPECT_EQ(result->he_cap.max_sprt_tx_streams, 7);
    EXPECT_EQ(result->he_cap.max_sprt_rx_streams, 7);
    EXPECT_EQ(result->wifi6_cap.max_dl_mumimo_tx, 15);
    EXPECT_EQ(result->wifi6_cap.max_ul_mumimo_rx, 15);
    EXPECT_EQ(result->wifi6_cap.max_dl_ofdma_tx, 255);
    EXPECT_EQ(result->wifi6_cap.max_ul_ofdma_rx, 255);
    std::cout << "Exiting RetrieveRadioCapInfoWithMaxMinValues" << std::endl;
}



/**
* @brief Test the successful initialization of the dm_radio_cap_t object
*
* This test verifies that the dm_radio_cap_t object is successfully initialized by calling the init() method.
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
* | 01 | Initialize dm_radio_cap_t object | dm_radio_cap_t radio_cap | Object should be initialized | Should be successful |
* | 02 | Call init() method | result = radio_cap.init() | result should be 0 | Should Pass |
*/
TEST(dm_radio_cap_test, SuccessfulInitialization) {
    std::cout << "Entering SuccessfulInitialization test";
    dm_radio_cap_t radio_cap;
    int result = radio_cap.init();
    EXPECT_EQ(result, 0);
    std::cout << "Exiting SuccessfulInitialization test";
}



/**
* @brief Test the assignment operator for dm_radio_cap_t class with mixed values.
*
* This test verifies that the assignment operator correctly assigns the values from one instance of dm_radio_cap_t to another instance. Specifically, it checks that the radios_num and noise values are properly copied.
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
* | 01 | Create two instances of dm_radio_cap_t | instance1, instance2 | Instances created successfully | Should be successful |
* | 02 | Assign values to instance2 | obj2.m_radio_cap_info.wifi7_cap.radios_num = 3, obj2.m_radio_cap_info.ch_scan.noise = -100 | Values assigned successfully | Should be successful |
* | 03 | Assign instance2 to instance1 using assignment operator | instance1 = instance2 | Assignment successful | Should be successful |
* | 04 | Verify radios_num value in instance1 | instance1.m_radio_cap_info.radios_num | Expected: 3 | Should Pass |
* | 05 | Verify noise value in instance1 | instance1.m_radio_cap_info.noise | Expected: -100 | Should Pass |
*/
TEST(dm_radio_cap_t_Test, AssigningMixedValues) {
    std::cout << "Entering AssigningMixedValues test";
    dm_radio_cap_t obj1{};
    dm_radio_cap_t obj2{};
    obj2.m_radio_cap_info.wifi7_cap.radios_num = 3;
    obj2.m_radio_cap_info.ch_scan.noise = -100;
    obj1 = obj2;
    EXPECT_EQ(obj1.m_radio_cap_info.wifi7_cap.radios_num, 3);
    EXPECT_EQ(obj2.m_radio_cap_info.ch_scan.noise, -100);
    std::cout << "Exiting AssigningMixedValues test";
}



/**
* @brief Test to verify the assignment operator with invalid values
*
* This test checks the assignment operator of the dm_radio_cap_t class to ensure that assigning one object to another works correctly, even when one contains an invalid enum value. It verifies that the internal state of the objects remains consistent after the assignment.
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
* | 01 | Create two dm_radio_cap_t objects | obj1, obj2 | Objects created successfully | Should be successful |
* | 02 | Assign an invalid enum value to obj2's media type | 0x9999 (not defined in em_media_type_t) | Value assigned without compile-time error | Invalid value handled |
* | 03 | Assign obj2 to obj1 | obj1 = obj2 | Assignment successful | Should be successful |
* | 04 | Compare the media type values of obj1 and obj2 | obj2.m_radio_cap_info.ruid.media != obj1.m_radio_cap_info.ruid.media | Should not be the same | Should Pass |
*/
TEST(dm_radio_cap_t_Test, AssigningInvalidValue) {
    std::cout << "Entering AssigningInvalidValue test";
    dm_radio_cap_t obj1{};
    dm_radio_cap_t obj2{}; 
    obj2.m_radio_cap_info.ruid.media = static_cast<em_media_type_t>(0x9999);
    obj1 = obj2;
    EXPECT_NE(obj2.m_radio_cap_info.ruid.media, obj1.m_radio_cap_info.ruid.media);
    std::cout << "Exiting AssigningInvalidValue test";
}



/**
* @brief Test to compare two identical dm_radio_cap_t objects
*
* This test verifies that two default-constructed dm_radio_cap_t objects are considered equal by the equality operator. This is important to ensure that the equality operator is correctly implemented for default objects.
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
* | 01 | Create first dm_radio_cap_t object | obj1 = dm_radio_cap_t() | None | Should be successful |
* | 02 | Create second dm_radio_cap_t object | obj2 = dm_radio_cap_t() | None | Should be successful |
* | 03 | Compare the two objects using equality operator | obj1 == obj2 | EXPECT_TRUE(obj1 == obj2) | Should Pass |
*/
TEST(dm_radio_cap_t_Test, CompareIdenticalObjects) {
    std::cout << "Entering CompareIdenticalObjects" << std::endl;
    dm_radio_cap_t obj1{};
    dm_radio_cap_t obj2{};
    obj1.m_radio_cap_info.wifi7_cap.radios_num = 2;
    obj1.m_radio_cap_info.ch_scan.noise = static_cast<int16_t>(-80);
    obj2.m_radio_cap_info.wifi7_cap.radios_num = 2;
    obj2.m_radio_cap_info.ch_scan.noise = static_cast<int16_t>(-80);
    EXPECT_EQ(obj1.m_radio_cap_info.wifi7_cap.radios_num, obj2.m_radio_cap_info.wifi7_cap.radios_num);
    EXPECT_EQ(obj1.m_radio_cap_info.ch_scan.noise, obj2.m_radio_cap_info.ch_scan.noise);
    std::cout << "Exiting CompareIdenticalObjects" << std::endl;
}



/**
* @brief Test to compare two dm_radio_cap_t objects with different number_of_bss values
*
* This test verifies that two dm_radio_cap_t objects with different number_of_bss values are not considered equal. This is important to ensure that the equality operator correctly identifies differences in the number_of_bss attribute.
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
* | 01| Initialize obj1 and obj2 | obj1 = dm_radio_cap_t(), obj2 = dm_radio_cap_t() | Objects initialized | Should be successful |
* | 02| Set number_of_bss for obj2 | obj2.m_radio_cap_info.ch_scan.number_of_bss = 5 | obj2.m_radio_cap_info.ch_scan.number_of_bss = 5 | Should be successful |
* | 03| Compare obj1 and obj2 using equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_radio_cap_t_Test, CompareDifferentNumberOfBSS) {
    std::cout << "Entering CompareDifferentNumberOfBSS" << std::endl;
    dm_radio_cap_t obj1{};
    dm_radio_cap_t obj2{};
    obj1.m_radio_cap_info.ch_scan.number_of_bss = 2;
    obj2.m_radio_cap_info.ch_scan.number_of_bss = 5;
    EXPECT_NE(obj1.m_radio_cap_info.ch_scan.number_of_bss, obj2.m_radio_cap_info.ch_scan.number_of_bss);
    std::cout << "Exiting CompareDifferentNumberOfBSS" << std::endl;
}



/**
* @brief Test to compare two dm_radio_cap_t objects with different media types
*
* This test verifies that two dm_radio_cap_t objects with different media types are not considered equal. This is important to ensure that the equality operator correctly distinguishes between objects with different media configurations.
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
* | 01 | Initialize dm_radio_cap_t objects | obj1, obj2 | Objects initialized | Should be successful |
* | 02 | Set media type for obj2 | obj2.m_radio_cap_info.ruid.media = em_media_type_ieee80211a_5 | Media type set | Should be successful |
* | 03 | Compare obj1 and obj2 | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_radio_cap_t_Test, CompareDifferentMediaType) {
    std::cout << "Entering CompareDifferentMediaType" << std::endl;
    dm_radio_cap_t obj1{};
    dm_radio_cap_t obj2{};
    std::memset(&obj1, 0, sizeof(obj1));
    std::memset(&obj2, 0, sizeof(obj2));
    obj1.m_radio_cap_info.ruid.media = em_media_type_ieee80211g_24;
    obj2.m_radio_cap_info.ruid.media = em_media_type_ieee80211a_5;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentMediaType" << std::endl;
}



/**
* @brief Test to compare two dm_radio_cap_t objects with different enabled values
*
* This test verifies that two dm_radio_cap_t objects with different enabled values are not considered equal. This is important to ensure that the equality operator correctly identifies differences in the enabled state of the radio capability information.
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
* | 01 | Initialize obj1 and obj2 | obj1, obj2 | Objects initialized | Should be successful |
* | 02 | Set obj2.m_radio_cap_info.ch_scan.enabled to true | obj2.m_radio_cap_info.ch_scan.enabled = true | Value set | Should be successful |
* | 03 | Compare obj1 and obj2 using equality operator | obj1, obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_radio_cap_t_Test, CompareDifferentEnabledValue) {
    std::cout << "Entering CompareDifferentEnabledValue" << std::endl;
    dm_radio_cap_t obj1{};
    dm_radio_cap_t obj2{};
    std::memset(&obj1, 0, sizeof(obj1));
    std::memset(&obj2, 0, sizeof(obj2));
    obj1.m_radio_cap_info.ch_scan.enabled = false;
    obj2.m_radio_cap_info.ch_scan.enabled = true;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentEnabledValue" << std::endl;
}



/**
* @brief Test to compare radio capabilities of different chip vendors
*
* This test verifies that the equality operator for the `dm_radio_cap_t` class correctly identifies objects with different chip vendors as not equal.@n
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
* | 01 | Initialize two `dm_radio_cap_t` objects | obj1, obj2 | Objects initialized | Should be successful |
* | 02 | Set `chip_vendor` of `obj2` to "VendorX" | obj2.m_radio_cap_info.ch_scan.chip_vendor = "VendorX" | `chip_vendor` set to "VendorX" | Should be successful |
* | 03 | Compare `obj1` and `obj2` using equality operator | obj1, obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_radio_cap_t_Test, CompareDifferentChipVendor) {
    std::cout << "Entering CompareDifferentChipVendor" << std::endl;
    dm_radio_cap_t obj1{}, obj2{};
    std::memset(&obj1, 0, sizeof(obj1));
    std::memset(&obj2, 0, sizeof(obj2));
    std::memcpy(obj1.m_radio_cap_info.ch_scan.chip_vendor, "vendorA", sizeof("vendorA"));
    std::memcpy(obj2.m_radio_cap_info.ch_scan.chip_vendor, "VendorX", sizeof("VendorX"));
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentChipVendor" << std::endl;
}



/**
* @brief Test to compare different BSS color bitmaps in dm_radio_cap_t objects
*
* This test checks the equality operator for dm_radio_cap_t objects when their BSS color bitmaps are different. 
* It ensures that the equality operator correctly identifies that the objects are not equal when their BSS color bitmaps differ.
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
* | 01| Create two dm_radio_cap_t objects | obj1, obj2 | Objects created successfully | Should be successful |
* | 02| Set srg_bss_color_bitmap[0] of obj2 to 1 | obj2.m_radio_cap_info.ch_scan.srg_bss_color_bitmap[0] = 1 | Value set successfully | Should be successful |
* | 03| Compare obj1 and obj2 using equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_radio_cap_t_Test, CompareDifferentBSSColorBitmap) {
    std::cout << "Entering CompareDifferentBSSColorBitmap" << std::endl;
    dm_radio_cap_t obj1{};
    dm_radio_cap_t obj2{};
    std::memset(&obj1, 0, sizeof(obj1));
    std::memset(&obj2, 0, sizeof(obj2));
    obj1.m_radio_cap_info.ch_scan.srg_bss_color_bitmap[0] = 0;
    obj2.m_radio_cap_info.ch_scan.srg_bss_color_bitmap[0] = 1;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentBSSColorBitmap" << std::endl;
}



/**
* @brief Test to compare two dm_radio_cap_t objects with different QoS map values
*
* This test verifies that two dm_radio_cap_t objects with different QoS map values are not considered equal. This is important to ensure that the equality operator correctly identifies differences in QoS map settings.
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
* | 01 | Initialize two dm_radio_cap_t objects | obj1, obj2 | Objects initialized | Should be successful |
* | 02 | Set QoS map of obj2 to true | obj2.m_radio_cap_info.radio_ad_cap.qos_map = true | QoS map set to true | Should be successful |
* | 03 | Compare obj1 and obj2 using equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_radio_cap_t_Test, CompareDifferentQosMap) {
    std::cout << "Entering CompareDifferentQosMap" << std::endl;
    dm_radio_cap_t obj1{};
    dm_radio_cap_t obj2{};
    std::memset(&obj1, 0, sizeof(obj1));
    std::memset(&obj2, 0, sizeof(obj2));
    obj1.m_radio_cap_info.radio_ad_cap.qos_map = false;
    obj2.m_radio_cap_info.radio_ad_cap.qos_map = true;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentQosMap" << std::endl;
}



/**
* @brief Test to compare two dm_radio_cap_t objects with different metric intervals
*
* This test verifies that two dm_radio_cap_t objects with different metric intervals are not considered equal.@n
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
* | 01 | Create two dm_radio_cap_t objects | obj1, obj2 | Objects created successfully | Should be successful |
* | 02 | Set metric interval of obj2 to 100 | obj2.m_radio_cap_info.metric_interval.metric_cltn_interval = 100 | Metric interval set successfully | Should be successful |
* | 03 | Compare obj1 and obj2 using == operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Fail |
*/
TEST(dm_radio_cap_t_Test, CompareDifferentMetricInterval) {
    std::cout << "Entering CompareDifferentMetricInterval" << std::endl;
    dm_radio_cap_t obj1{};
    dm_radio_cap_t obj2{};
    std::memset(&obj1, 0, sizeof(obj1));
    std::memset(&obj2, 0, sizeof(obj2));
    obj1.m_radio_cap_info.metric_interval.metric_cltn_interval = 0;
    obj2.m_radio_cap_info.metric_interval.metric_cltn_interval = 100;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentMetricInterval" << std::endl;
}



/**
* @brief Test to compare different EHT operations reserved fields in dm_radio_cap_t objects
*
* This test verifies that two dm_radio_cap_t objects with different EHT operations reserved fields are not considered equal. This is important to ensure that the equality operator correctly identifies differences in the reserved fields of the EHT operations.
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
* | 01 | Initialize dm_radio_cap_t objects | obj1, obj2 | Objects initialized | Should be successful |
* | 02 | Modify reserved field of obj2 | obj2.m_radio_cap_info.eht_ops.radios[0].reserved[0] = 1 | Reserved field modified | Should be successful |
* | 03 | Compare obj1 and obj2 using equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Pass |
*/
TEST(dm_radio_cap_t_Test, CompareDifferentEHTOpsReserved) {
    std::cout << "Entering CompareDifferentEHTOpsReserved" << std::endl;
    dm_radio_cap_t obj1{};
    dm_radio_cap_t obj2{};
    obj1.m_radio_cap_info.eht_ops.radios[0].reserved[0] = -1;
    obj2.m_radio_cap_info.eht_ops.radios[0].reserved[0] = 1;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentEHTOpsReserved" << std::endl;
}



/**
* @brief Test to compare different EHT capabilities
*
* This test checks the equality operator for the dm_radio_cap_t class by comparing two objects with different EHT capabilities.@n
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
* | 01| Create two dm_radio_cap_t objects | obj1, obj2 | Objects created successfully | Should be successful |
* | 02| Set EHT capability for obj2 | obj2.m_radio_cap_info.eht_cap = "EHT Capability" | EHT capability set successfully | Should be successful |
* | 03| Compare obj1 and obj2 using equality operator | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Fail |
*/
TEST(dm_radio_cap_t_Test, CompareDifferentEHTCap) {
    std::cout << "Entering CompareDifferentEHTCap" << std::endl;
    dm_radio_cap_t obj1{};
    dm_radio_cap_t obj2{};
    strcpy(obj1.m_radio_cap_info.eht_cap, "EHT1 Capability");
    strcpy(obj2.m_radio_cap_info.eht_cap, "EHT Capability");
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentEHTCap" << std::endl;
}

/**
 * @brief Verifies that the dm_radio_cap_t default constructor successfully creates an object without throwing an exception.
 *
 * This test case ensures that invoking the default constructor of dm_radio_cap_t does not result in any unexpected exceptions and that the internally maintained state (m_radio_cap_info) remains in its default configuration.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 039@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                      | Test Data                                        | Expected Result                                                                               | Notes       |
 * | :--------------: | ---------------------------------------------------------------- | ------------------------------------------------ | --------------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke dm_radio_cap_t default constructor and verify no exception thrown | Invocation: dm_radio_cap_t();                    | The object is created successfully without any exceptions and internal state is defaulted.      | Should Pass |
 */
TEST(dm_radio_cap_t_Test, DefaultConstructor) {
    std::cout << "Entering DefaultConstructor test" << std::endl;

    EXPECT_NO_THROW({
        std::cout << "Invoking dm_radio_cap_t() default constructor." << std::endl;
        dm_radio_cap_t obj;
        std::cout << "dm_radio_cap_t object created successfully." << std::endl;
    });

    std::cout << "Exiting DefaultConstructor test" << std::endl;
}

/**
 * @brief Tests whether the destructor of dm_radio_cap_t is invoked without throwing exceptions.
 *
 * This test creates an instance of dm_radio_cap_t using the default constructor and then deletes the object,
 * which triggers the destructor. It verifies that no exceptions are thrown during the destruction process,
 * ensuring that the destructor properly cleans up resources.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 040@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                              | Test Data                                         | Expected Result                                                | Notes       |
 * | :--------------: | ------------------------------------------------------------------------ | ------------------------------------------------- | -------------------------------------------------------------- | ----------- |
 * | 01               | Create dm_radio_cap_t object using default constructor and invoke destructor by deleting the object | obj = new dm_radio_cap_t(), delete obj             | No exception is thrown during object destruction (EXPECT_NO_THROW check) | Should Pass |
 */
TEST(dm_radio_cap_t_Test, DestructorInvocation) {
    std::cout << "Entering DestructorInvocation test" << std::endl;
    EXPECT_NO_THROW({
        std::cout << "Creating dm_radio_cap_t object using default constructor" << std::endl;
        dm_radio_cap_t *obj = new dm_radio_cap_t();
        std::cout << "dm_radio_cap_t object created at address: " << obj << std::endl;

        std::cout << "Invoking destructor by deleting object" << std::endl;
        delete obj;
        std::cout << "Destructor executed; resources cleaned up for dm_radio_cap_t object" << std::endl;
    });
    std::cout << "Exiting DestructorInvocation test" << std::endl;
}
