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
#include "dm_ieee_1905_security.h"

/**
 * @brief Test the decoding of a valid cJSON object
 *
 * This test verifies that the decode function of the dm_ieee_1905_security_t class correctly processes a valid cJSON object.@n
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
 * | 01 | Create a valid cJSON object | type = cJSON_Object, valuestring = "valid_string", valueint = 123, valuedouble = 123.45, string = "valid_name" | cJSON object should be created successfully | Should be successful |
 * | 02 | Call the decode function with the valid cJSON object | obj = valid cJSON object | Return value should be 0, EXPECT_EQ(result, 0) | Should Pass |
 */
TEST(dm_ieee_1905_security_t_Test, DecodeValidCJsonObject) {
    std::cout << "Entering DecodeValidCJsonObject" << std::endl;
    cJSON obj = {};
    obj.type = cJSON_Object;
    obj.valuestring = const_cast<char*>("valid_string");
    obj.valueint = 123;
    obj.valuedouble = 123.45;
    obj.string = const_cast<char*>("valid_name");
    dm_ieee_1905_security_t security;
    int result = security.decode(&obj);
    EXPECT_EQ(result, 0);
    std::cout << "Exiting DecodeValidCJsonObject" << std::endl;
}

/**
 * @brief Test the decoding of a cJSON object with an invalid type
 *
 * This test verifies that the decode function of the dm_ieee_1905_security_t class correctly handles a cJSON object with an invalid type. The objective is to ensure that the function returns a non-zero value indicating failure when the type is invalid.
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
 * | 01 | Create a cJSON object with an invalid type | type = -1, valuestring = "valid_string", valueint = 123, valuedouble = 123.45, string = "valid_name" | cJSON object created | Should be successful |
 * | 02 | Call the decode function with the invalid cJSON object | obj = &obj | result != 0 | Should Fail |
 */
TEST(dm_ieee_1905_security_t_Test, DecodeCJsonObjectWithInvalidType) {
    std::cout << "Entering DecodeCJsonObjectWithInvalidType" << std::endl;
    cJSON obj = {};
    obj.type = -1;
    obj.valuestring = const_cast<char*>("valid_string");
    obj.valueint = 123;
    obj.valuedouble = 123.45;
    obj.string = const_cast<char*>("valid_name");
    dm_ieee_1905_security_t security;
    int result = security.decode(&obj);
    EXPECT_NE(result, 0);
    std::cout << "Exiting DecodeCJsonObjectWithInvalidType" << std::endl;
}

/**
 * @brief Test the decoding of a cJSON object with a null child
 *
 * This test verifies the behavior of the decode function when provided with a cJSON object that has a null child. This is important to ensure that the function can handle such cases gracefully without crashing or producing incorrect results.
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
 * | 01| Create a cJSON object with a null child and call the decode function | cJSON obj = { .type = cJSON_Object, .valuestring = "valid_string", .valueint = 123, .valuedouble = 123.45, .string = "valid_name", .child = NULL }, instance->decode(&obj) | result = 0, EXPECT_EQ(result, 0) | Should Pass |
 */
TEST(dm_ieee_1905_security_t_Test, DecodeCJsonObjectWithNullChild) {
    std::cout << "Entering DecodeCJsonObjectWithNullChild" << std::endl;
    cJSON obj = {};
    obj.type = cJSON_Object;
    obj.valuestring = const_cast<char*>("valid_string");
    obj.valueint = 123;
    obj.valuedouble = 123.45;
    obj.string = const_cast<char*>("valid_name");
    obj.child = NULL;
    dm_ieee_1905_security_t security;
    int result = security.decode(&obj);
    EXPECT_EQ(result, 0);
    std::cout << "Exiting DecodeCJsonObjectWithNullChild" << std::endl;
}

/**
 * @brief Test the decoding of a cJSON object with null next and prev pointers
 *
 * This test verifies the behavior of the decode function when provided with a cJSON object that has null next and prev pointers. This is to ensure that the function can handle such cases without errors and returns the expected result.
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
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Create a cJSON object with null next and prev pointers | type = cJSON_Object, valuestring = "valid_string", valueint = 123, valuedouble = 123.45, string = "valid_name", next = NULL, prev = NULL | cJSON object created successfully | Should be successful |
 * | 02| Call the decode function with the created cJSON object | obj = &cJSON object | result = 0 | Should Pass |
 * | 03| Verify the result of the decode function | result = 0 | EXPECT_EQ(result, 0) | Should Pass |
 */
TEST(dm_ieee_1905_security_t_Test, DecodeCJsonObjectWithNullNextAndPrev) {
    std::cout << "Entering DecodeCJsonObjectWithNullNextAndPrev" << std::endl;
    cJSON obj = {};
    obj.type = cJSON_Object;
    obj.valuestring = const_cast<char*>("valid_string");
    obj.valueint = 123;
    obj.valuedouble = 123.45;
    obj.string = const_cast<char*>("valid_name");
    obj.next = NULL;
    obj.prev = NULL;
    dm_ieee_1905_security_t security;
    int result = security.decode(&obj);
    EXPECT_EQ(result, 0);
    std::cout << "Exiting DecodeCJsonObjectWithNullNextAndPrev" << std::endl;
}

/**
 * @brief Test the decoding of a cJSON object with type array
 *
 * This test verifies the functionality of the decode method in the dm_ieee_1905_security_t class when provided with a cJSON object of type array. The objective is to ensure that the decode method correctly processes the input and returns the expected result.
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
 * | 01 | Create a cJSON object with type array and valid values | type = cJSON_Array, valuestring = "valid_string", valueint = 123, valuedouble = 123.45, string = "valid_name" | cJSON object created successfully | Should be successful |
 * | 02 | Call the decode method with the created cJSON object | obj = &cJSON object | result = 0 | Should Pass |
 * | 03 | Verify the result of the decode method | result = 0 | EXPECT_EQ(result, 0) | Should Pass |
 */
TEST(dm_ieee_1905_security_t_Test, DecodeCJsonObjectWithTypeArray) {
    std::cout << "Entering DecodeCJsonObjectWithTypeArray" << std::endl;
    cJSON obj = {};
    obj.type = cJSON_Array;
    obj.valuestring = const_cast<char*>("valid_string");
    obj.valueint = 123;
    obj.valuedouble = 123.45;
    obj.string = const_cast<char*>("valid_name");
    dm_ieee_1905_security_t security;
    int result = security.decode(&obj);
    EXPECT_EQ(result, 0);
    std::cout << "Exiting DecodeCJsonObjectWithTypeArray" << std::endl;
}

/**
 * @brief Test the decoding of a cJSON object with type string
 *
 * This test verifies the functionality of the decode method in the dm_ieee_1905_security_t class when provided with a cJSON object of type string. It ensures that the method correctly processes the input and returns the expected result.
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
 * | 01| Initialize cJSON object with type string | type = cJSON_String, valuestring = "valid_string", valueint = 123, valuedouble = 123.45, string = "valid_name" | cJSON object initialized | Should be successful |
 * | 02| Invoke decode method on dm_ieee_1905_security_t instance | obj = &cJSON object | result = 0 | Should Pass |
 * | 03| Verify the result using EXPECT_EQ | result = 0 | EXPECT_EQ(result, 0) | Should Pass |
 */
TEST(dm_ieee_1905_security_t_Test, DecodeCJsonObjectWithTypeString) {
    std::cout << "Entering DecodeCJsonObjectWithTypeString" << std::endl;
    cJSON obj = {};
    obj.type = cJSON_String;
    obj.valuestring = const_cast<char*>("valid_string");
    obj.valueint = 123;
    obj.valuedouble = 123.45;
    obj.string = const_cast<char*>("valid_name");
    dm_ieee_1905_security_t security;
    int result = security.decode(&obj);
    EXPECT_EQ(result, 0);
    std::cout << "Exiting DecodeCJsonObjectWithTypeString" << std::endl;
}

/**
 * @brief Test the decoding of a cJSON object with type number
 *
 * This test verifies that the decode function of the dm_ieee_1905_security_t class correctly handles a cJSON object of type number. The test ensures that the function returns the expected result when provided with valid input data.
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
 * | 01 | Create a cJSON object with type number and valid values | type = cJSON_Number, valuestring = "valid_string", valueint = 123, valuedouble = 123.45, string = "valid_name" | cJSON object created successfully | Should be successful |
 * | 02 | Call the decode function with the created cJSON object | obj = &cJSON object | result = 0 | Should Pass |
 * | 03 | Verify the result of the decode function | result = 0 | EXPECT_EQ(result, 0) | Should Pass |
 */
TEST(dm_ieee_1905_security_t_Test, DecodeCJsonObjectWithTypeNumber) {
    std::cout << "Entering DecodeCJsonObjectWithTypeNumber" << std::endl;
    cJSON obj = {};
    obj.type = cJSON_Number;
    obj.valuestring = const_cast<char*>("valid_string");
    obj.valueint = 123;
    obj.valuedouble = 123.45;
    obj.string = const_cast<char*>("valid_name");
    dm_ieee_1905_security_t security;
    int result = security.decode(&obj);
    EXPECT_EQ(result, 0);
    std::cout << "Exiting DecodeCJsonObjectWithTypeNumber" << std::endl;
}

/**
 * @brief Test the decoding of a cJSON object with type Raw
 *
 * This test verifies that the `decode` method of the `dm_ieee_1905_security_t` class correctly decodes a cJSON object of type Raw. The test ensures that the method returns 0, indicating successful decoding.
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
 * | 01 | Create a cJSON object with type Raw and valid values | type = cJSON_Raw, valuestring = "valid_string", valueint = 123, valuedouble = 123.45, string = "valid_name" | cJSON object created successfully | Should be successful |
 * | 02 | Call the decode method with the created cJSON object | obj = {type = cJSON_Raw, valuestring = "valid_string", valueint = 123, valuedouble = 123.45, string = "valid_name"} | Method returns 0 | Should Pass |
 * | 03 | Verify the result of the decode method | result = 0 | EXPECT_EQ(result, 0) | Should Pass |
 */
TEST(dm_ieee_1905_security_t_Test, DecodeCJsonObjectWithTypeRaw) {
    std::cout << "Entering DecodeCJsonObjectWithTypeRaw" << std::endl;
    cJSON obj = {};
    obj.type = cJSON_Raw;
    obj.valuestring = const_cast<char*>("valid_string");
    obj.valueint = 123;
    obj.valuedouble = 123.45;
    obj.string = const_cast<char*>("valid_name");
    dm_ieee_1905_security_t security;
    int result = security.decode(&obj);
    EXPECT_EQ(result, 0);
    std::cout << "Exiting DecodeCJsonObjectWithTypeRaw" << std::endl;
}

/**
 * @brief Test to verify the behavior of the decode function when a NULL input is provided.
 *
 * This test checks the decode function of the dm_ieee_1905_security_t class to ensure that it correctly handles a NULL input. The function is expected to return a non-zero value indicating an error when a NULL input is passed.
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
 * | 01| Call decode with NULL input | input = NULL | result != 0 | Should Fail |
 */
TEST(dm_ieee_1905_security_t_Test, DecodeNullCJsonObject) {
    std::cout << "Entering DecodeNullCJsonObject" << std::endl;
    dm_ieee_1905_security_t security;
    int result = security.decode(NULL);
    EXPECT_NE(result, 0);
    std::cout << "Exiting DecodeNullCJsonObject" << std::endl;
}

/**
 * @brief Test the copy constructor of dm_ieee_1905_security_t with valid initialized input.
 *
 * This test verifies that the copy constructor performs a deep copy of the internal 
 * security info structure and maintains data integrity.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 010@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** A valid dm_ieee_1905_security_t object must exist.@n
 * **Dependencies:** dm_ieee_1905_security_t class definition with a valid copy constructor@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**@n
 * | Step | Description | Expected Result |
 * |------|-------------|------------------|
 * | 01 | Create and initialize an original object | info = { {0x11, 0x22, 0x33, 0x44, 0x55, 0x66}, {1, 2, 3} } | Object is correctly initialized |
 * | 02 | Use copy constructor to create a new object | dm_ieee_1905_security_t copy(original); | New object is created |
 * | 03 | Compare internal fields using EXPECT_EQ | copy.m_ieee_1905_security_info.id[i]=original.m_ieee_1905_security_info.id[i], copy.m_ieee_1905_security_info.sec_cap.onboarding_proto=original.m_ieee_1905_security_info.sec_cap.onboarding_proto, copy.m_ieee_1905_security_info.sec_cap.integrity_algo=original.m_ieee_1905_security_info.sec_cap.integrity_algo, copy.m_ieee_1905_security_info.sec_cap.encryption_algo=original.m_ieee_1905_security_info.sec_cap.encryption_algo | All fields should match |
 */
TEST(dm_ieee_1905_security_t_Test, CopyConstructorWithValidInitializedInput) {
    std::cout << "Entering CopyConstructorWithValidInitializedInput" << std::endl;
    em_ieee_1905_security_info_t info = {{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}, {1, 2, 3}};
    dm_ieee_1905_security_t original(&info);
    dm_ieee_1905_security_t copy(original);
    for (size_t i = 0; i < sizeof(mac_address_t); ++i) {
        EXPECT_EQ(copy.m_ieee_1905_security_info.id[i], original.m_ieee_1905_security_info.id[i]);
    }
    EXPECT_EQ(copy.m_ieee_1905_security_info.sec_cap.onboarding_proto, original.m_ieee_1905_security_info.sec_cap.onboarding_proto);
    EXPECT_EQ(copy.m_ieee_1905_security_info.sec_cap.integrity_algo, original.m_ieee_1905_security_info.sec_cap.integrity_algo);
    EXPECT_EQ(copy.m_ieee_1905_security_info.sec_cap.encryption_algo, original.m_ieee_1905_security_info.sec_cap.encryption_algo);
    std::cout << "Exiting CopyConstructorWithValidInitializedInput" << std::endl;
}


/**
 * @brief Test the copy constructor with a null input
 *
 * This test verifies that the copy constructor of the dm_ieee_1905_security_t class handles a null input correctly by throwing an exception.@n
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
 * | 01 | Attempt to copy construct with a null input | original = nullptr | std::exception should be thrown | Should Pass |
 */
TEST(dm_ieee_1905_security_t_Test, CopyConstructorWithNullInput) {
    std::cout << "Entering CopyConstructorWithNullInput" << std::endl;
    dm_ieee_1905_security_t* original = nullptr;
    EXPECT_ANY_THROW(dm_ieee_1905_security_t copy(*original));
    std::cout << "Exiting CopyConstructorWithNullInput" << std::endl;
}    

/**
 * @brief Test to validate the network SSID information in the security object
 *
 * This test verifies that the network SSID information is correctly set and retrieved from the security object.
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
 * | 01| Initialize network SSID information | net_ssid = { {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, {1, 2, 3} } | Should be successful | Should be successful |
 * | 02| Create security object with network SSID | dm_ieee_1905_security_t security_obj(&net_ssid) | Should be successful | Should be successful |
 * | 03| Verify SSID bytes 0 to 5 | EXPECT_EQ(security_obj.m_ieee_1905_security_info.id[i], net_ssid.id[i]); | Should be equal | Should Pass |
 * | 04| Verify onboarding protocol | security_obj.m_ieee_1905_security_info.sec_cap.onboarding_proto == 1 | Should be 1 | Should Pass |
 * | 05| Verify integrity algorithm | security_obj.m_ieee_1905_security_info.sec_cap.integrity_algo == 2 | Should be 2 | Should Pass |
 * | 06| Verify encryption algorithm | security_obj.m_ieee_1905_security_info.sec_cap.encryption_algo == 3 | Should be 3 | Should Pass |
 */
TEST(dm_ieee_1905_security_t_Test, ValidNetworkSSIDInformation) {
    std::cout << "Entering ValidNetworkSSIDInformation test\n";
    em_ieee_1905_security_info_t net_ssid = {{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, {1, 2, 3}};
    dm_ieee_1905_security_t security_obj(&net_ssid);
    for (size_t i = 0; i < sizeof(mac_address_t); ++i) {
        EXPECT_EQ(security_obj.m_ieee_1905_security_info.id[i], net_ssid.id[i]);
    }
    EXPECT_EQ(security_obj.m_ieee_1905_security_info.sec_cap.onboarding_proto, 1);
    EXPECT_EQ(security_obj.m_ieee_1905_security_info.sec_cap.integrity_algo, 2);
    EXPECT_EQ(security_obj.m_ieee_1905_security_info.sec_cap.encryption_algo, 3);
    std::cout << "Exiting ValidNetworkSSIDInformation test\n";
}

/**
 * @brief Test the behavior of dm_ieee_1905_security_t when initialized with a null network SSID information.
 *
 * This test verifies that the dm_ieee_1905_security_t object correctly handles a null network SSID information by checking the default values of the security information and capabilities.
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
 * | 01 | Initialize security object with null SSID | net_ssid = nullptr | Object should be initialized | Should Pass |
 * | 02 | Check if it handles gracefully | ASSERT_ANY_THROW(dm_ieee_1905_security_t security_obj(net_ssid)); | Should not crash | Should Pass |
 */
TEST(dm_ieee_1905_security_t_Test, NullNetworkSSIDInformation) {
    std::cout << "Entering NullNetworkSSIDInformation test";
    em_ieee_1905_security_info_t *net_ssid = nullptr;
    EXPECT_ANY_THROW(dm_ieee_1905_security_t security_obj(net_ssid));
    std::cout << "Exiting NullNetworkSSIDInformation test";
}    

/**
 * @brief Test the NetworkSSIDWithAllZeroMACAddress functionality
 *
 * This test verifies that the dm_ieee_1905_security_t class correctly handles a network SSID with an all-zero MAC address. It ensures that the security information and capabilities are correctly set and retrieved.
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
 * | 01| Create a network SSID with all-zero MAC address and specific security capabilities | net_ssid = { {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, {1, 2, 3} } | Object should be created successfully | Should be successful |
 * | 02| Initialize dm_ieee_1905_security_t object with the created network SSID | security_obj(&net_ssid) | Object should be initialized successfully | Should be successful |
 * | 03| Verify SSID bytes 0 to 5 | EXPECT_EQ(security_obj.m_ieee_1905_security_info.id[i], net_ssid.id[i]); | Should be equal | Should Pass |
 * | 04| Verify onboarding protocol | security_obj.m_ieee_1905_security_info.sec_cap.onboarding_proto == 1 | Should be 1 | Should Pass |
 * | 05| Verify integrity algorithm | security_obj.m_ieee_1905_security_info.sec_cap.integrity_algo == 2 | Should be 2 | Should Pass |
 * | 06| Verify encryption algorithm | security_obj.m_ieee_1905_security_info.sec_cap.encryption_algo == 3 | Should be 3 | Should Pass |
 */
TEST(dm_ieee_1905_security_t_Test, NetworkSSIDWithAllZeroMACAddress) {
    std::cout << "Entering NetworkSSIDWithAllZeroMACAddress test";
    em_ieee_1905_security_info_t net_ssid = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, {1, 2, 3}};
    dm_ieee_1905_security_t security_obj(&net_ssid);
    for (size_t i = 0; i < sizeof(mac_address_t); ++i) {
        EXPECT_EQ(security_obj.m_ieee_1905_security_info.id[i], net_ssid.id[i]);
    }
    EXPECT_EQ(security_obj.m_ieee_1905_security_info.sec_cap.onboarding_proto, 1);
    EXPECT_EQ(security_obj.m_ieee_1905_security_info.sec_cap.integrity_algo, 2);
    EXPECT_EQ(security_obj.m_ieee_1905_security_info.sec_cap.encryption_algo, 3);
    std::cout << "Exiting NetworkSSIDWithAllZeroMACAddress test";
}

/**
 * @brief Test the NetworkSSIDWithMaximumValuesInMACAddress function
 *
 * This test verifies that the dm_ieee_1905_security_t class correctly handles a network SSID with maximum values in the MAC address. It ensures that the security information and capabilities are correctly set and retrieved.
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
 * | 01 | Create a network SSID with maximum MAC address values and initialize the security object | net_ssid = { {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, {1, 2, 3} } | Security object should be initialized successfully | Should be successful |
 * | 02 | Verify SSID bytes 0 to 5 | ASSERT_EQ(security_obj.m_ieee_1905_security_info.id[i], net_ssid.id[i]); | Should be equal | Should Pass |
 * | 03| Verify onboarding protocol | security_obj.m_ieee_1905_security_info.sec_cap.onboarding_proto == 1 | Should be 1 | Should Pass |
 * | 04| Verify integrity algorithm | security_obj.m_ieee_1905_security_info.sec_cap.integrity_algo == 2 | Should be 2 | Should Pass |
 * | 05| Verify encryption algorithm | security_obj.m_ieee_1905_security_info.sec_cap.encryption_algo == 3 | Should be 3 | Should Pass |
 */
TEST(dm_ieee_1905_security_t_Test, NetworkSSIDWithMaximumValuesInMACAddress) {
    std::cout << "Entering NetworkSSIDWithMaximumValuesInMACAddress test";
    em_ieee_1905_security_info_t net_ssid = {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, {1, 2, 3}};
    dm_ieee_1905_security_t security_obj(&net_ssid);
    for (size_t i = 0; i < sizeof(mac_address_t); ++i) {
        EXPECT_EQ(security_obj.m_ieee_1905_security_info.id[i], net_ssid.id[i]);
    }
    EXPECT_EQ(security_obj.m_ieee_1905_security_info.sec_cap.onboarding_proto, 1);
    EXPECT_EQ(security_obj.m_ieee_1905_security_info.sec_cap.integrity_algo, 2);
    EXPECT_EQ(security_obj.m_ieee_1905_security_info.sec_cap.encryption_algo, 3);
    std::cout << "Exiting NetworkSSIDWithMaximumValuesInMACAddress test";
}

/**
 * @brief Test the encoding of a valid string value in the dm_ieee_1905_security_t class
 *
 * This test verifies that the encode function of the dm_ieee_1905_security_t class correctly handles a valid string input. The objective is to ensure that the function can process and encode a string value without errors.@n
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
 * | 01 | Create a cJSON object with type cJSON_String and value "test_string" | obj.type = cJSON_String, obj.valuestring = "test_string" | Should be successful | |
 * | 02 | Call the encode function with the cJSON object | instance.encode(obj) | Should Pass | |
 */
TEST(dm_ieee_1905_security_t_Test, EncodeValidStringValue) {
    std::cout << "Entering EncodeValidStringValue" << std::endl;
    cJSON* obj = cJSON_CreateString("test_string");
    ASSERT_NE(obj, nullptr);
    dm_ieee_1905_security_t instance;
    EXPECT_NO_THROW(instance.encode(obj));
    cJSON_Delete(obj);
    std::cout << "Exiting EncodeValidStringValue" << std::endl;
}

/**
 * @brief Test the encoding of a valid number value in a cJSON object.
 *
 * This test verifies that the `encode` method of the `dm_ieee_1905_security_t` class correctly handles a cJSON object with a number type and a valid double value. The objective is to ensure that the encoding process works as expected for numeric values.
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
 * | 01 | Initialize cJSON object with number type and value | obj.type = cJSON_Number, obj.valuedouble = 123.45 | cJSON object initialized with number type and value | Should be successful |
 * | 02 | Call encode method with cJSON object | instance.encode(obj) | Method should process the cJSON object without errors | Should Pass |
 */
TEST(dm_ieee_1905_security_t_Test, EncodeValidNumberValue) {
    std::cout << "Entering EncodeValidNumberValue" << std::endl;
    cJSON* obj = cJSON_CreateNumber(123.45);
    ASSERT_NE(obj, nullptr);
    dm_ieee_1905_security_t instance;
    EXPECT_NO_THROW(instance.encode(obj));
    cJSON_Delete(obj);
    std::cout << "Exiting EncodeValidNumberValue" << std::endl;
}   

/**
 * @brief Test the encoding of a valid integer value using dm_ieee_1905_security_t class.
 *
 * This test verifies that the encode method of the dm_ieee_1905_security_t class correctly handles and encodes a valid integer value.@n
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
 * | 01| Set up the test environment | instance = new dm_ieee_1905_security_t() | Successful setup | Should be successful |
 * | 02| Create a cJSON object with type cJSON_Number and value 123 | obj.type = cJSON_Number, obj.valueint = 123 | Object created successfully | Should be successful |
 * | 03| Call the encode method with the cJSON object | instance.encode(obj) | Method should execute without errors | Should Pass |
 * | 04| Tear down the test environment | delete instance | Successful teardown | Should be successful |
 */
TEST(dm_ieee_1905_security_t_Test, EncodeValidIntegerValue) {
    std::cout << "Entering EncodeValidIntegerValue" << std::endl;
    cJSON* obj = cJSON_CreateNumber(123);
    ASSERT_NE(obj, nullptr);
    dm_ieee_1905_security_t instance;
    EXPECT_NO_THROW(instance.encode(obj));
    cJSON_Delete(obj);
    std::cout << "Exiting EncodeValidIntegerValue" << std::endl;
}

/**
 * @brief Test the encoding of a valid boolean true value
 *
 * This test verifies that the encode function correctly handles a cJSON object with a boolean true value. The objective is to ensure that the encode function can process and encode boolean true values without errors.@n
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
 * | 01| Create a cJSON object with boolean true value | obj.type = cJSON_True | cJSON object created successfully | Should be successful |
 * | 02| Call the encode function with the cJSON object | instance.encode(obj) | Encode function processes the boolean true value without errors | Should Pass |
 */
TEST(dm_ieee_1905_security_t_Test, EncodeValidBooleanTrueValue) {
    std::cout << "Entering EncodeValidBooleanTrueValue" << std::endl;
    cJSON* obj = cJSON_CreateTrue();
    ASSERT_NE(obj, nullptr);
    dm_ieee_1905_security_t instance;
    EXPECT_NO_THROW(instance.encode(obj));
    cJSON_Delete(obj);
    std::cout << "Exiting EncodeValidBooleanTrueValue" << std::endl;
}   

/**
 * @brief Test the encoding of a valid null value in the dm_ieee_1905_security_t class
 *
 * This test checks the behavior of the encode function when it is provided with a cJSON object of type NULL. This is important to ensure that the function can handle null values gracefully without causing any errors or unexpected behavior.
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
 * | 01 | Create a cJSON object of type NULL | obj.type = cJSON_NULL | cJSON object created successfully | Should be successful |
 * | 02 | Call the encode function with the NULL cJSON object | instance.encode(obj) | Function should handle the null value without errors | Should Pass |
 */
TEST(dm_ieee_1905_security_t_Test, EncodeValidNullValue) {
    std::cout << "Entering EncodeValidNullValue" << std::endl;
    cJSON* obj = cJSON_CreateNull();
    ASSERT_NE(obj, nullptr);
    dm_ieee_1905_security_t instance;
    EXPECT_NO_THROW(instance.encode(obj));
    cJSON_Delete(obj);
    std::cout << "Exiting EncodeValidNullValue" << std::endl;
}

/**
 * @brief Test the encoding of a valid array value in a cJSON object.
 *
 * This test verifies that the encode function of the dm_ieee_1905_security_t class correctly processes a cJSON object with a valid array value. The objective is to ensure that the function handles the array type and its child elements properly.
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
 * | 01 | Initialize cJSON object with array and child string | obj.type = cJSON_Array, child_obj.type = cJSON_String, child_obj.valuestring = "child_string", obj.child = &child_obj | cJSON object initialized | Should be successful |
 * | 02 | Call encode function with initialized cJSON object | instance.encode(obj) | Encode function processes the array and child string correctly | Should Pass |
 */
TEST(dm_ieee_1905_security_t_Test, EncodeValidArrayValue) {
    std::cout << "Entering EncodeValidArrayValue" << std::endl;
    cJSON* obj = cJSON_CreateArray();
    ASSERT_NE(obj, nullptr);
    cJSON_AddItemToArray(obj, cJSON_CreateString("child_string"));
    dm_ieee_1905_security_t instance;
    EXPECT_NO_THROW(instance.encode(obj));
    cJSON_Delete(obj);
    std::cout << "Exiting EncodeValidArrayValue" << std::endl;
}   

/**
 * @brief Test the encoding of a valid cJSON object value
 *
 * This test verifies that the encode function correctly processes a valid cJSON object with a child string value.@n
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
 * | 01| Set up the test environment | instance = new dm_ieee_1905_security_t() | Successful setup | Should be successful |
 * | 02| Initialize cJSON object and child object | obj.type = cJSON_Object, child_obj.type = cJSON_String, child_obj.valuestring = "child_string", obj.child = &child_obj | Correct initialization | Should be successful |
 * | 03| Call the encode function with the initialized cJSON object | instance.encode(obj) | Successful encoding | Should Pass |
 * | 04| Tear down the test environment | delete instance | Successful teardown | Should be successful |
 */
TEST(dm_ieee_1905_security_t_Test, EncodeValidObjectValue) {
    std::cout << "Entering EncodeValidObjectValue" << std::endl;
    cJSON* obj = cJSON_CreateObject();
    ASSERT_NE(obj, nullptr);
    cJSON_AddStringToObject(obj, "key", "child_string");
    dm_ieee_1905_security_t instance;
    EXPECT_NO_THROW(instance.encode(obj));
    cJSON_Delete(obj);
    std::cout << "Exiting EncodeValidObjectValue" << std::endl;
}   

/**
 * @brief Test to verify the behavior of the encode function when provided with an invalid type.
 *
 * This test checks the encode function of the dm_ieee_1905_security_t class to ensure it handles invalid input types correctly. The objective is to verify that the function can gracefully handle and report errors when an invalid type is passed to it.
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
 * | 01| Set up the test environment | instance = new dm_ieee_1905_security_t() | Should be successful | |
 * | 02| Create a cJSON object with an invalid type | obj.type = -1 | Should be successful | |
 * | 03| Call the encode function with the invalid cJSON object | instance.encode(&obj) | Should Pass | |
 * | 04| Tear down the test environment | delete instance | Should be successful | |
 */
TEST(dm_ieee_1905_security_t_Test, EncodeInvalidType) {
    std::cout << "Entering EncodeInvalidType" << std::endl;
    cJSON* obj = cJSON_CreateObject();
    ASSERT_NE(obj, nullptr);
    obj->type = -1;
    dm_ieee_1905_security_t instance;
    EXPECT_NO_THROW(instance.encode(obj));
    obj->type = cJSON_Object;
    cJSON_Delete(obj);
    std::cout << "Exiting EncodeInvalidType" << std::endl;
}

/**
 * @brief Test to verify the behavior of the encode function when a null pointer is passed.
 *
 * This test checks the encode function of the dm_ieee_1905_security_t class to ensure it handles a null pointer input correctly. This is important to verify that the function can gracefully handle invalid inputs without causing crashes or undefined behavior.
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
 * | 01| Initialize the test instance | instance = new dm_ieee_1905_security_t() | Should be successful | Should be successful |
 * | 02| Call encode with null pointer | obj = NULL, instance.encode(obj) | Should not crash or cause undefined behavior | Should Pass |
 * | 03| Clean up the test instance | delete instance | Should be successful | Should be successful |
 */
TEST(dm_ieee_1905_security_t_Test, EncodeNullPointer) {
    std::cout << "Entering EncodeNullPointer" << std::endl;
    cJSON *obj = NULL;
    dm_ieee_1905_security_t instance;
    EXPECT_NO_THROW(instance.encode(obj));
    std::cout << "Exiting EncodeNullPointer" << std::endl;
}

/**
 * @brief Test to retrieve security capabilities after setting specific values
 *
 * This test verifies that the security capabilities are correctly retrieved after setting specific values for onboarding protocol, integrity algorithm, and encryption algorithm in the security object.
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
 * | 01| Initialize security object and set specific values for security capabilities | onboarding_proto = 1, integrity_algo = 2, encryption_algo = 3 | Values should be set correctly | Should be successful |
 * | 02| Retrieve security capabilities from the security object | None | sec_cap should not be nullptr | Should Pass |
 * | 03| Verify onboarding protocol value | onboarding_proto = 1 | onboarding_proto should be 1 | Should Pass |
 * | 04| Verify integrity algorithm value | integrity_algo = 2 | integrity_algo should be 2 | Should Pass |
 * | 05| Verify encryption algorithm value | encryption_algo = 3 | encryption_algo should be 3 | Should Pass |
 */
TEST(dm_ieee_1905_security_t_Test, RetrieveSecurityCapabilitiesAfterSettingSpecificValues) {
    std::cout << "Entering RetrieveSecurityCapabilitiesAfterSettingSpecificValues" << std::endl;
    dm_ieee_1905_security_t security_obj{};
    memset(&security_obj.m_ieee_1905_security_info, 0, sizeof(security_obj.m_ieee_1905_security_info));
    security_obj.m_ieee_1905_security_info.sec_cap.onboarding_proto = 1;
    security_obj.m_ieee_1905_security_info.sec_cap.integrity_algo = 2;
    security_obj.m_ieee_1905_security_info.sec_cap.encryption_algo = 3;
    em_ieee_1905_security_cap_t* sec_cap = security_obj.get_ieee_1905_security_cap();
    ASSERT_NE(sec_cap, nullptr);
    EXPECT_EQ(sec_cap->onboarding_proto, 1);
    EXPECT_EQ(sec_cap->integrity_algo, 2);
    EXPECT_EQ(sec_cap->encryption_algo, 3);
    std::cout << "Exiting RetrieveSecurityCapabilitiesAfterSettingSpecificValues" << std::endl;
}

/**
 * @brief Test to verify the retrieval of security information after setting specific values.
 *
 * This test sets specific values to the security information fields and then retrieves the security information to verify if the set values are correctly retrieved.@n
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
 * | 01| Set specific values to the security information fields | id[0] = 0x01, onboarding_proto = 0x02, integrity_algo = 0x03, encryption_algo = 0x04 | Values should be set successfully | Should be successful |
 * | 02| Retrieve the security information | None | result != nullptr | Should Pass |
 * | 03| Verify the id[0] value | result->id[0] = 0x01 | Should Pass |
 * | 04| Verify the onboarding_proto value | result->sec_cap.onboarding_proto = 0x02 | Should Pass |
 * | 05| Verify the integrity_algo value | result->sec_cap.integrity_algo = 0x03 | Should Pass |
 * | 06| Verify the encryption_algo value | result->sec_cap.encryption_algo = 0x04 | Should Pass |
 */
TEST(dm_ieee_1905_security_t_Test, RetrieveSecurityInfoAfterSettingSpecificValues) {
    std::cout << "Entering RetrieveSecurityInfoAfterSettingSpecificValues" << std::endl;
    dm_ieee_1905_security_t security_obj{};
    memset(&security_obj.m_ieee_1905_security_info, 0, sizeof(security_obj.m_ieee_1905_security_info));
    security_obj.m_ieee_1905_security_info.id[0] = 0x01;
    security_obj.m_ieee_1905_security_info.sec_cap.onboarding_proto = 0x02;
    security_obj.m_ieee_1905_security_info.sec_cap.integrity_algo = 0x03;
    security_obj.m_ieee_1905_security_info.sec_cap.encryption_algo = 0x04;
    em_ieee_1905_security_info_t* result = security_obj.get_ieee_1905_security_info();
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->id[0], 0x01);
    EXPECT_EQ(result->sec_cap.onboarding_proto, 0x02);
    EXPECT_EQ(result->sec_cap.integrity_algo, 0x03);
    EXPECT_EQ(result->sec_cap.encryption_algo, 0x04);
    std::cout << "Exiting RetrieveSecurityInfoAfterSettingSpecificValues" << std::endl;
}

/**
 * @brief Test the initialization of the dm_ieee_1905_security_t object
 *
 * This test verifies that the init() method of the dm_ieee_1905_security_t class initializes the object correctly and returns 0, indicating success.@n
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
 * | 01| Create an instance of dm_ieee_1905_security_t and call init() method | instance = new dm_ieee_1905_security_t(), result = instance->init() | result = 0, EXPECT_EQ(result, 0) | Should Pass |
 */
TEST(dm_ieee_1905_security_t_Test, Init_Start) {
    std::cout << "Entering Init_Start" << std::endl;
    dm_ieee_1905_security_t security_obj{};
    int result = 0;
    EXPECT_NO_THROW(result = security_obj.init());
    EXPECT_EQ(result, 0);
    std::cout << "Exiting Init_Start" << std::endl;
}

/**
 * @brief Test the assignment operator with identical objects
 *
 * This test verifies that the assignment operator correctly assigns one object to another when both objects are identical. This ensures that the assignment operator works as expected and that the objects remain equal after the assignment.
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
 * | 01| Create two identical objects | obj1, obj2 | Objects created successfully | Should be successful |
 * | 02| Assign obj2 to obj1 using assignment operator | obj1 = obj2 | obj1 should be equal to obj2 | Should Pass |
 * | 03| Assert that the set parameters of obj2 is equal to obj1 | obj2.m_ieee_1905_security_info.id[0]=obj1.m_ieee_1905_security_info.id[0], obj2.m_ieee_1905_security_info.sec_cap.encryption_algo=obj1.m_ieee_1905_security_info.sec_cap.encryption_algo, obj2.m_ieee_1905_security_info.id[0]=obj1.m_ieee_1905_security_info.id[0] | Assertion should pass | Should Pass |
 */
TEST(dm_ieee_1905_security_t_Test, AssigningNullSecurityInformation) {
    std::cout << "Entering AssigningNullSecurityInformation" << std::endl;
    dm_ieee_1905_security_t obj1{};
    dm_ieee_1905_security_t obj2{};
    memset(&obj1.m_ieee_1905_security_info, 0, sizeof(obj1.m_ieee_1905_security_info));
    memset(&obj2.m_ieee_1905_security_info, 0, sizeof(obj2.m_ieee_1905_security_info));
    obj1 = obj2;
    ASSERT_EQ(obj2.m_ieee_1905_security_info.id[0], obj1.m_ieee_1905_security_info.id[0]);
    ASSERT_EQ(obj2.m_ieee_1905_security_info.sec_cap.encryption_algo, obj1.m_ieee_1905_security_info.sec_cap.encryption_algo);
    ASSERT_EQ(obj2.m_ieee_1905_security_info.id[0], obj1.m_ieee_1905_security_info.id[0]);
    std::cout << "Exiting AssigningNullSecurityInformation" << std::endl;
}

/**
 * @brief Test the assignment operator with valid security objects
 *
 * This test verifies that the assignment operator correctly copies the contents of one object to another object of the same class. It ensures that after assignment, both objects are equal.
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
 * | 01 | Create two objects of dm_ieee_1905_security_t | obj1, obj2 | Objects created successfully | Should be successful |
 * | 02 | Modify obj2's id field | obj2.m_ieee_1905_security_info.id[0] = 1 | obj2's id field modified | Should be successful |
 * | 03 | Assign obj2 to obj1 | obj2.m_ieee_1905_security_info.id[0]=obj1.m_ieee_1905_security_info.id[0], obj2.m_ieee_1905_security_info.sec_cap.encryption_algo=obj1.m_ieee_1905_security_info.sec_cap.encryption_algo, obj2.m_ieee_1905_security_info.id[0]=obj1.m_ieee_1905_security_info.id[0] | obj1 should be equal to obj2 | Should Pass |
 */
TEST(dm_ieee_1905_security_t_Test, AssigningValidSecurityInformation) {
    std::cout << "Entering AssigningValidSecurityInformation" << std::endl;
    dm_ieee_1905_security_t obj1{};
    dm_ieee_1905_security_t obj2{};
    memset(&obj1.m_ieee_1905_security_info, 0, sizeof(obj1.m_ieee_1905_security_info));
    memset(&obj2.m_ieee_1905_security_info, 0, sizeof(obj2.m_ieee_1905_security_info));
    obj2.m_ieee_1905_security_info.id[0] = 1;
    obj2.m_ieee_1905_security_info.sec_cap.encryption_algo = 2;
    obj1 = obj2;
    ASSERT_EQ(obj2.m_ieee_1905_security_info.id[0], obj1.m_ieee_1905_security_info.id[0]);
    ASSERT_EQ(obj2.m_ieee_1905_security_info.sec_cap.encryption_algo, obj1.m_ieee_1905_security_info.sec_cap.encryption_algo);
    std::cout << "Exiting AssigningValidSecurityInformation" << std::endl;
}

/**
 * @brief Test to compare two identical objects of dm_ieee_1905_security_t class
 *
 * This test checks if two newly created objects of the dm_ieee_1905_security_t class are identical by using the equality operator. This is important to ensure that the default constructor initializes objects to a consistent state.
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
 * | 01| Create two objects of dm_ieee_1905_security_t class | obj1, obj2 | Objects should be created successfully | Should be successful |
 * | 02| Compare the two objects using the equality operator | obj1 == obj2 | EXPECT_TRUE should pass | Should Pass |
 */
TEST(dm_ieee_1905_security_t_Test, CompareIdenticalObjects) {
    std::cout << "Entering CompareIdenticalObjects" << std::endl;
    dm_ieee_1905_security_t obj1{};
    dm_ieee_1905_security_t obj2{};
    memset(&obj1.m_ieee_1905_security_info, 0, sizeof(obj1.m_ieee_1905_security_info));
    memset(&obj2.m_ieee_1905_security_info, 0, sizeof(obj2.m_ieee_1905_security_info));
    obj1.m_ieee_1905_security_info.id[0] = obj2.m_ieee_1905_security_info.id[0] = 0x01;
    obj1.m_ieee_1905_security_info.sec_cap.onboarding_proto = obj2.m_ieee_1905_security_info.sec_cap.onboarding_proto = 0x02;
    obj1.m_ieee_1905_security_info.sec_cap.integrity_algo = obj2.m_ieee_1905_security_info.sec_cap.integrity_algo = 0x03;
    obj1.m_ieee_1905_security_info.sec_cap.encryption_algo = obj2.m_ieee_1905_security_info.sec_cap.encryption_algo = 0x04;
    EXPECT_TRUE(obj1 == obj2);
    std::cout << "Exiting CompareIdenticalObjects" << std::endl;
}

/**
 * @brief Test to compare different MAC addresses in dm_ieee_1905_security_t objects
 *
 * This test verifies that two dm_ieee_1905_security_t objects with different MAC addresses are not considered equal.@n
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
 * | 01| Create two dm_ieee_1905_security_t objects with different MAC addresses | obj1.m_ieee_1905_security_info.id = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, obj2.m_ieee_1905_security_info.id = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB} | Objects should not be equal | Should Pass |
 * | 02| Compare the two objects using EXPECT_FALSE | obj1 == obj2 | EXPECT_FALSE should pass | Should Pass |
 */
TEST(dm_ieee_1905_security_t_Test, CompareDifferentMACAddresses) {
    std::cout << "Entering CompareDifferentMACAddresses" << std::endl;
    dm_ieee_1905_security_t obj1{};
    dm_ieee_1905_security_t obj2{};
    memset(&obj1.m_ieee_1905_security_info, 0, sizeof(obj1.m_ieee_1905_security_info));
    memset(&obj2.m_ieee_1905_security_info, 0, sizeof(obj2.m_ieee_1905_security_info));
    obj1.m_ieee_1905_security_info.id[0] = 0x00;
    obj1.m_ieee_1905_security_info.id[1] = 0x11;
    obj1.m_ieee_1905_security_info.id[2] = 0x22;
    obj1.m_ieee_1905_security_info.id[3] = 0x33;
    obj1.m_ieee_1905_security_info.id[4] = 0x44;
    obj1.m_ieee_1905_security_info.id[5] = 0x55;
    obj2.m_ieee_1905_security_info.id[0] = 0x66;
    obj2.m_ieee_1905_security_info.id[1] = 0x77;
    obj2.m_ieee_1905_security_info.id[2] = 0x88;
    obj2.m_ieee_1905_security_info.id[3] = 0x99;
    obj2.m_ieee_1905_security_info.id[4] = 0xAA;
    obj2.m_ieee_1905_security_info.id[5] = 0xBB;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentMACAddresses" << std::endl;
}

/**
 * @brief Test to compare different onboarding protocols in dm_ieee_1905_security_t class
 *
 * This test verifies that two instances of dm_ieee_1905_security_t with different onboarding protocols are not considered equal.@n
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
 * | 01 | Create two instances of dm_ieee_1905_security_t | instance1, instance2 | Instances created successfully | Should be successful |
 * | 02 | Set different onboarding protocols for the instances | instance1.onboarding_proto = 1, instance2.onboarding_proto = 2 | Onboarding protocols set successfully | Should be successful |
 * | 03 | Compare the two instances | instance1 == instance2 | EXPECT_FALSE should pass | Should Pass |
 */
TEST(dm_ieee_1905_security_t_Test, CompareDifferentOnboardingProtocols) {
    std::cout << "Entering CompareDifferentOnboardingProtocols" << std::endl;
    dm_ieee_1905_security_t obj1{};
    dm_ieee_1905_security_t obj2{};
    memset(&obj1.m_ieee_1905_security_info, 0, sizeof(obj1.m_ieee_1905_security_info));
    memset(&obj2.m_ieee_1905_security_info, 0, sizeof(obj2.m_ieee_1905_security_info));
    obj1.m_ieee_1905_security_info.sec_cap.onboarding_proto = 1;
    obj2.m_ieee_1905_security_info.sec_cap.onboarding_proto = 2;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentOnboardingProtocols" << std::endl;
}

/**
 * @brief Test to compare different integrity algorithms in dm_ieee_1905_security_t class
 *
 * This test verifies that two instances of dm_ieee_1905_security_t with different integrity algorithms are not considered equal.@n
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
 * | 01 | Create two instances of dm_ieee_1905_security_t | instance1, instance2 | Instances created successfully | Should be successful |
 * | 02 | Set integrity_algo of instance1 to 1 | instance1.integrity_algo = 1 | Integrity algorithm set to 1 | Should be successful |
 * | 03 | Set integrity_algo of instance2 to 2 | instance2.integrity_algo = 2 | Integrity algorithm set to 2 | Should be successful |
 * | 04 | Compare instance1 and instance2 for equality | instance1 == instance2 | EXPECT_FALSE(instance1 == instance2) | Should Pass |
 */
TEST(dm_ieee_1905_security_t_Test, CompareDifferentIntegrityAlgorithms) {
    std::cout << "Entering CompareDifferentIntegrityAlgorithms" << std::endl;
    dm_ieee_1905_security_t obj1{};
    dm_ieee_1905_security_t obj2{};
    memset(&obj1.m_ieee_1905_security_info, 0, sizeof(obj1.m_ieee_1905_security_info));
    memset(&obj2.m_ieee_1905_security_info, 0, sizeof(obj2.m_ieee_1905_security_info));
    obj1.m_ieee_1905_security_info.sec_cap.integrity_algo = 1;
    obj2.m_ieee_1905_security_info.sec_cap.integrity_algo = 2;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentIntegrityAlgorithms" << std::endl;
}

/**
 * @brief Test to compare different encryption algorithms in dm_ieee_1905_security_t class
 *
 * This test verifies that two instances of dm_ieee_1905_security_t with different encryption algorithms are not considered equal.@n
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
 * | 01| Create two instances of dm_ieee_1905_security_t | instance1, instance2 | Instances created | Should be successful |
 * | 02| Set different encryption algorithms for both instances | instance1.encryption_algo = 1, instance2.encryption_algo = 2 | Encryption algorithms set | Should be successful |
 * | 03| Compare the two instances | instance1 == instance2 | EXPECT_FALSE(instance1 == instance2) | Should Pass |
 */
TEST(dm_ieee_1905_security_t_Test, CompareDifferentEncryptionAlgorithms) {
    std::cout << "Entering CompareDifferentEncryptionAlgorithms" << std::endl;
    dm_ieee_1905_security_t obj1{};
    dm_ieee_1905_security_t obj2{};
    memset(&obj1.m_ieee_1905_security_info, 0, sizeof(obj1.m_ieee_1905_security_info));
    memset(&obj2.m_ieee_1905_security_info, 0, sizeof(obj2.m_ieee_1905_security_info));
    obj1.m_ieee_1905_security_info.sec_cap.encryption_algo = 1;
    obj2.m_ieee_1905_security_info.sec_cap.encryption_algo = 2;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareDifferentEncryptionAlgorithms" << std::endl;
}

/**
 * @brief Test to compare two objects with all fields identical except one
 *
 * This test verifies that two objects of type dm_ieee_1905_security_t are not considered equal when all fields are identical except one field. This ensures that the equality operator correctly identifies differences in object fields.
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
 * | 01 | Create two objects of dm_ieee_1905_security_t | obj1, obj2 | Objects created successfully | Should be successful |
 * | 02 | Set identical id fields for both objects | obj1.id = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, obj2.id = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55} | Fields set successfully | Should be successful |
 * | 03 | Set identical onboarding_proto fields for both objects | obj1.onboarding_proto = 1, obj2.onboarding_proto = 1 | Fields set successfully | Should be successful |
 * | 04 | Set identical integrity_algo fields for both objects | obj1.integrity_algo = 1, obj2.integrity_algo = 1 | Fields set successfully | Should be successful |
 * | 05 | Set different encryption_algo fields for both objects | obj1.encryption_algo = 1, obj2.encryption_algo = 2 | Fields set successfully | Should be successful |
 * | 06 | Compare the two objects | obj1 == obj2 | EXPECT_FALSE(obj1 == obj2) | Should Fail |
 */
TEST(dm_ieee_1905_security_t_Test, CompareAllFieldsIdenticalExceptOne) {
    std::cout << "Entering CompareAllFieldsIdenticalExceptOne" << std::endl;
    dm_ieee_1905_security_t obj1{};
    dm_ieee_1905_security_t obj2{};
    memset(&obj1.m_ieee_1905_security_info, 0, sizeof(obj1.m_ieee_1905_security_info));
    memset(&obj2.m_ieee_1905_security_info, 0, sizeof(obj2.m_ieee_1905_security_info));
    obj1.m_ieee_1905_security_info.id[0] = 0x00;
    obj1.m_ieee_1905_security_info.id[1] = 0x11;
    obj1.m_ieee_1905_security_info.id[2] = 0x22;
    obj1.m_ieee_1905_security_info.id[3] = 0x33;
    obj1.m_ieee_1905_security_info.id[4] = 0x44;
    obj1.m_ieee_1905_security_info.id[5] = 0x55;
    obj2.m_ieee_1905_security_info.id[0] = 0x00;
    obj2.m_ieee_1905_security_info.id[1] = 0x11;
    obj2.m_ieee_1905_security_info.id[2] = 0x22;
    obj2.m_ieee_1905_security_info.id[3] = 0x33;
    obj2.m_ieee_1905_security_info.id[4] = 0x44;
    obj2.m_ieee_1905_security_info.id[5] = 0x55;
    obj1.m_ieee_1905_security_info.sec_cap.onboarding_proto = obj2.m_ieee_1905_security_info.sec_cap.onboarding_proto = 1;
    obj1.m_ieee_1905_security_info.sec_cap.integrity_algo = obj2.m_ieee_1905_security_info.sec_cap.integrity_algo = 1;
    obj1.m_ieee_1905_security_info.sec_cap.encryption_algo = 1;
    obj2.m_ieee_1905_security_info.sec_cap.encryption_algo = 2;
    EXPECT_FALSE(obj1 == obj2);
    std::cout << "Exiting CompareAllFieldsIdenticalExceptOne" << std::endl;
}

/**
 * @brief Verify that the default constructor of dm_ieee_1905_security_t successfully initializes the internal state without throwing exceptions.
 *
 * This test checks that creating an instance of dm_ieee_1905_security_t using its default constructor does not throw any exceptions and that the object’s internal state is initialized to the expected default values.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 036@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke the default constructor of dm_ieee_1905_security_t to create an instance. | input: None, output: object with default initialization values | Object is successfully created with the default constructor without throwing any exceptions. | Should Pass |
 */
TEST(dm_ieee_1905_security_t_Test, DefaultConstructorInitializesObjectSuccessfully) {
    std::cout << "Entering DefaultConstructorInitializesObjectSuccessfully test" << std::endl;
    EXPECT_NO_THROW({
        dm_ieee_1905_security_t obj;
        std::cout << "Invoked dm_ieee_1905_security_t default constructor successfully." << std::endl;
    });
    std::cout << "Exiting DefaultConstructorInitializesObjectSuccessfully test" << std::endl;
}

/**
 * @brief Test default construction and destruction of dm_ieee_1905_security_t object.
 *
 * This test verifies that the default constructor of dm_ieee_1905_security_t correctly initializes an object and that the destructor properly releases the allocated resources without throwing any exceptions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 037@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                         | Test Data                                                       | Expected Result                                                | Notes      |
 * | :--------------: | ------------------------------------------------------------------- | --------------------------------------------------------------- | -------------------------------------------------------------- | ---------- |
 * | 01               | Invoke default constructor for dm_ieee_1905_security_t.             | constructor = dm_ieee_1905_security_t(), no arguments             | Object is created successfully without throwing exceptions.  | Should Pass|
 * | 02               | Invoke destructor to delete the created object.                     | input = pointer to dm_ieee_1905_security_t instance, delete operator invoked | Object is deleted successfully without throwing exceptions.  | Should Pass|
 */
TEST(dm_ieee_1905_security_t_Test, DefaultConstructorDestruction) {
    std::cout << "Entering DefaultConstructorDestruction test" << std::endl;
    EXPECT_NO_THROW({
        std::cout << "Invoking default constructor dm_ieee_1905_security_t()" << std::endl;
        dm_ieee_1905_security_t* obj = new dm_ieee_1905_security_t();
        std::cout << "Object created successfully using default constructor" << std::endl;
        std::cout << "Invoking destructor for dm_ieee_1905_security_t()" << std::endl;
        delete obj;
        std::cout << "Destructor invoked successfully" << std::endl;
    });
    std::cout << "Exiting DefaultConstructorDestruction test" << std::endl;
}