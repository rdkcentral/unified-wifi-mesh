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
#include "em_onewifi.h"

/**
* @brief Test to validate the network interface name
*
* This test checks if the function `mac_address_from_name` correctly retrieves the MAC address for a valid network interface name. This is important to ensure that the function can handle standard network interface names and return the expected results.
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
* | 01 | Initialize test and create object | ifname = "erouter0", mac = {0} | Object should be created successfully | Should be successful |
* | 02 | Call mac_address_from_name with valid interface name | ifname = "erouter0", mac = {0} | result = 0, EXPECT_EQ(result, 0) | Should Pass |
*/
TEST(em_onewifi_t, ValidNetworkInterfaceName) {
    std::cout << "Entering ValidNetworkInterfaceName test" << std::endl;
    em_onewifi_t obj;
    mac_address_t mac = {0};
    const char* ifname = "erouter0";
    int result = obj.mac_address_from_name(ifname, mac);
    EXPECT_EQ(result, 0);
    std::cout << "Exiting ValidNetworkInterfaceName test" << std::endl;
}

/**
* @brief Test to validate behavior with an invalid network interface name
*
* This test checks the behavior of the `mac_address_from_name` method when provided with an invalid network interface name. The method is expected to return an error code indicating failure.
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
* | 01 | Initialize test and create `em_onewifi_t` object | ifname = "invalid_ifname", mac = {0} | Object should be created successfully | Should be successful |
* | 02 | Call `mac_address_from_name` with invalid interface name | ifname = "invalid_ifname", mac = {0} | Return value should be -1, EXPECT_EQ(result, -1) | Should Fail |
*/
TEST(em_onewifi_t, InvalidNetworkInterfaceName) {
    std::cout << "Entering InvalidNetworkInterfaceName test" << std::endl;
    em_onewifi_t obj;
    mac_address_t mac = {0};
    const char* ifname = "invalid_ifname";
    int result = obj.mac_address_from_name(ifname, mac);
    EXPECT_EQ(result, -1);
    std::cout << "Exiting InvalidNetworkInterfaceName test" << std::endl;
}

/**
* @brief Test to verify the behavior of mac_address_from_name when provided with a null network interface name.
*
* This test checks the function mac_address_from_name to ensure it correctly handles a null network interface name input. 
* The function is expected to return an error code when the network interface name is null, which is a negative test case.
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
* | 01 | Call mac_address_from_name with null network interface name | ifname = nullptr, mac = {0} | result = -1, EXPECT_EQ(result, -1) | Should Fail |
*/
TEST(em_onewifi_t, NullNetworkInterfaceName) {
    std::cout << "Entering NullNetworkInterfaceName test" << std::endl;
    em_onewifi_t obj;
    mac_address_t mac = {0};
    const char* ifname = nullptr;
    int result = obj.mac_address_from_name(ifname, mac);
    EXPECT_EQ(result, -1);
    std::cout << "Exiting NullNetworkInterfaceName test" << std::endl;
}

/**
* @brief Test the behavior of mac_address_from_name with an empty network interface name
*
* This test checks the function mac_address_from_name when provided with an empty string as the network interface name. 
* It ensures that the function correctly handles this edge case by returning an error code.
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
* | 01| Initialize mac_address_t and set ifname to empty string | ifname = "", mac = {0} | Initialization should be successful | Should be successful |
* | 02| Call mac_address_from_name with empty ifname | ifname = "", mac = {0} | result = -1, EXPECT_EQ(result, -1) | Should Fail |
*/
TEST(em_onewifi_t, EmptyNetworkInterfaceName) {
    std::cout << "Entering EmptyNetworkInterfaceName test" << std::endl;
    em_onewifi_t obj;
    mac_address_t mac = {0};
    const char* ifname = "";
    int result = obj.mac_address_from_name(ifname, mac);
    EXPECT_EQ(result, -1);
    std::cout << "Exiting EmptyNetworkInterfaceName test" << std::endl;
}

/**
* @brief Test to validate handling of network interface names with special characters
*
* This test checks the behavior of the mac_address_from_name function when provided with a network interface name that contains special characters. The function is expected to handle such cases gracefully and return an error code.
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
* | 01| Initialize test and create em_onewifi_t object |  |  | Should be successful |
* | 02| Define network interface name with special characters | ifname = "erouter0@123" |  | Should be successful |
* | 03| Call mac_address_from_name with special character interface name | ifname = "erouter0@123", mac = {0} | result = -1, EXPECT_EQ(result, -1) | Should Fail |
*/
TEST(em_onewifi_t, NetworkInterfaceNameWithSpecialCharacters) {
    std::cout << "Entering NetworkInterfaceNameWithSpecialCharacters test" << std::endl;
    em_onewifi_t obj;
    mac_address_t mac = {0};
    const char* ifname = "erouter0@123";
    int result = obj.mac_address_from_name(ifname, mac);
    EXPECT_EQ(result, -1);
    std::cout << "Exiting NetworkInterfaceNameWithSpecialCharacters test" << std::endl;
}

/**
* @brief Test to convert a valid MAC address to a string format
*
* This test verifies the functionality of converting a valid MAC address byte array to its corresponding string representation. This is essential to ensure that the MAC address conversion utility works correctly and returns the expected string format.
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
* | 01 | Initialize MAC address and string buffer | mac = {0x1C, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, string = "" | Initialization should be successful | Should be successful |
* | 02 | Convert MAC address to string | mac = {0x1C, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, string = "" | result = "00:1A:2B:3C:4D:5E" | Should Pass |
* | 03 | Verify the converted string | result = "00:1A:2B:3C:4D:5E" | EXPECT_STRCASEEQ(result, "00:1A:2B:3C:4D:5E") | Should Pass |
*/
TEST(em_onewifi_t, ConvertValidMacAddressToString) {
    std::cout << "Entering ConvertValidMacAddressToString test" << std::endl;
    em_onewifi_t obj;
    mac_address_t mac = {0x1C, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
    char string[18];
    char* result = obj.macbytes_to_string(mac, string);
    EXPECT_STRCASEEQ(result, "1C:1A:2B:3C:4D:5E");
    std::cout << "Exiting ConvertValidMacAddressToString test" << std::endl;
}

/**
* @brief Test the conversion of a MAC address with all zeros to a string representation.
*
* This test verifies that the function `macbytes_to_string` correctly converts a MAC address consisting of all zeros to its string representation. This is important to ensure that the function handles edge cases properly.
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
* | 01 | Initialize MAC address with all zeros | mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, string = "" | N/A | Should be successful |
* | 02 | Convert MAC address to string | mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, string = "" | result = "00:00:00:00:00:00" | Should Pass |
* | 03 | Verify the string representation | result = "00:00:00:00:00:00" | EXPECT_STREQ(result, "00:00:00:00:00:00") | Should Pass |
*/
TEST(em_onewifi_t, ConvertMacAddressWithAllZerosToString) {
    std::cout << "Entering ConvertMacAddressWithAllZerosToString test" << std::endl;
    em_onewifi_t obj;
    mac_address_t mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    char string[18];
    char* result = obj.macbytes_to_string(mac, string);
    EXPECT_STREQ(result, "00:00:00:00:00:00");
    std::cout << "Exiting ConvertMacAddressWithAllZerosToString test" << std::endl;
}

/**
* @brief Test to validate the conversion of MAC address with invalid length
*
* This test checks the behavior of the macbytes_to_string function when provided with a MAC address of invalid length. The objective is to ensure that the function handles such cases gracefully without causing undefined behavior or errors.
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
* | 01| Initialize the test and create an instance of em_onewifi_t | obj = em_onewifi_t() | Should be successful | |
* | 02| Define a MAC address with invalid length and prepare a string buffer | mac = {0x1C, 0x1A, 0x2B, 0x3C}, string[18] | Should be successful | |
* | 03| Call macbytes_to_string with the invalid MAC address | result = obj.macbytes_to_string(mac, string) | result should be nullptr | Should Fail |
*/
TEST(em_onewifi_t, ConvertMacAddressWithInvalidLength) {
    std::cout << "Entering ConvertMacAddressWithInvalidLength test" << std::endl;
    em_onewifi_t obj;
    mac_address_t mac = {0x1C, 0x1A, 0x2B, 0x3C};
    char string[18];
    char* result = obj.macbytes_to_string(mac, string);
    ASSERT_EQ(result, nullptr);
    std::cout << "Exiting ConvertMacAddressWithInvalidLength test" << std::endl;
}

/**
* @brief Test the conversion of a valid MAC address string to byte array
*
* This test verifies that the function `string_to_macbytes` correctly converts a valid MAC address string to its corresponding byte array representation. This is essential to ensure that MAC address strings are properly parsed and stored in the expected format.
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
* | 01 | Initialize test and create em_onewifi_t object |  |  | Should be successful |
* | 02 | Define valid MAC address string and initialize byte array | key = "01:23:45:67:89:AB", bmac = {0} |  | Should be successful |
* | 03 | Convert MAC address string to byte array | key = "01:23:45:67:89:AB", bmac = {0} |  | Should Pass |
* | 04 | Verify each byte of the converted MAC address | bmac[i] = expected_bmac[i] for i in 0 to 5 | Each byte should match the expected value | Should Pass |
*/
TEST(em_onewifi_t, ValidMACAddressString) {
    std::cout << "Entering ValidMACAddressString test" << std::endl;
    em_onewifi_t obj;
    char key[] = "01:23:45:67:89:AB";
    mac_address_t bmac = {0};
    em_onewifi_t::string_to_macbytes(key, bmac);
    mac_address_t expected_bmac = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB};
    for (int i = 0; i < 6; ++i) {
        EXPECT_EQ(bmac[i], expected_bmac[i]);
    }
    std::cout << "Exiting ValidMACAddressString test" << std::endl;
}

/**
* @brief Test to validate the behavior of string_to_macbytes function with an invalid MAC address string of incorrect length.
*
* This test checks the string_to_macbytes function to ensure it correctly handles an invalid MAC address string that has an incorrect length. The function should convert the string to a MAC address byte array and the test verifies that the resulting byte array is as expected (all zeros in this case).@n
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
* | 01 | Initialize em_onewifi_t object and define invalid MAC address string | key = "01:23:45:67", bmac = {0} | Object initialized, key and bmac defined | Should be successful |
* | 02 | Call string_to_macbytes with invalid MAC address string | key = "01:23:45:67", bmac = {0} | Exception should be thrown.| Should Fail |
*/
TEST(em_onewifi_t, InvalidMACAddressStringIncorrectLength) {
    std::cout << "Entering InvalidMACAddressStringIncorrectLength test" << std::endl;
    em_onewifi_t obj;
    char key[] = "01:23:45:67";   // Invalid MAC: only 4 bytes (should be 6)
    mac_address_t bmac = {0};
    EXPECT_ANY_THROW({
        em_onewifi_t::string_to_macbytes(key, bmac);
    });
    std::cout << "Exiting InvalidMACAddressStringIncorrectLength test" << std::endl;
}

/**
* @brief Test to verify the conversion of an empty MAC address string to byte array
*
* This test checks the behavior of the string_to_macbytes function when provided with an empty MAC address string. 
* It ensures that the function correctly converts an empty string to a byte array of zeros.
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
* | 01| Initialize test and create em_onewifi_t object |  |  | Should be successful |
* | 02| Define empty MAC address string and initialize byte array | key = "", bmac = {0} |  | Should be successful |
* | 03| Call string_to_macbytes with empty string | key = "", bmac = {0} | Exception should be thrown. | Should Fail |
*/
TEST(em_onewifi_t, EmptyMACAddressString) {
    std::cout << "Entering EmptyMACAddressString test" << std::endl;
    em_onewifi_t obj;
    char key[] = "";
    mac_address_t bmac = {0};
    EXPECT_ANY_THROW({
        em_onewifi_t::string_to_macbytes(key, bmac);
    });
    std::cout << "Exiting EmptyMACAddressString test" << std::endl;
}

/**
 * @brief Test default instantiation of em_onewifi_t using the default constructor.
 *
 * This test validates that instantiating an em_onewifi_t object using its default constructor does not throw any exceptions.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 012@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke the default constructor of em_onewifi_t | Input: None, Constructor call: em_onewifi_t() | The default constructor should not throw an exception | Should Pass |
 */
TEST(em_onewifi_t, Constructor_DefaultInstantiation) {
    std::cout << "Entering Constructor_DefaultInstantiation test" << std::endl;
    // Log the invocation of the default constructor
    std::cout << "Invoking em_onewifi_t default constructor." << std::endl;
    EXPECT_NO_THROW({
        em_onewifi_t obj;
        std::cout << "em_onewifi_t object instantiated successfully." << std::endl;
    });
    std::cout << "Exiting Constructor_DefaultInstantiation test" << std::endl;
}

/**
 * @brief Validate that an em_onewifi_t object can be created on the heap and properly deleted.
 *
 * This test verifies that the default constructor of the em_onewifi_t class does not throw any exception when creating an object on the heap and that the destructor is invoked correctly upon deletion without any exception. The test ensures proper memory management for the object.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 013@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                                  | Test Data                                                  | Expected Result                                                | Notes        |
 * | :--------------: | ---------------------------------------------------------------------------- | ---------------------------------------------------------- | -------------------------------------------------------------- | ------------ |
 * | 01               | Invoke default constructor to create em_onewifi_t object on heap.            | No input, output: obj pointer allocated (non-null)         | The object is created successfully with no exception thrown.   | Should Pass  |
 * | 02               | Invoke delete to trigger the destructor of the em_onewifi_t object.          | Input: obj pointer (valid instance)                        | The destructor is invoked successfully with no exception thrown. | Should Pass  |
 */
TEST(em_onewifi_t, ObjectCreationOnHeapAndProperDeletion)
{
    std::cout << "Entering ObjectCreationOnHeapAndProperDeletion test" << std::endl;
    // Create an object of em_onewifi_t on heap using default constructor
    em_onewifi_t *obj = nullptr;
    std::cout << "Invoking default constructor for em_onewifi_t." << std::endl;
    EXPECT_NO_THROW(obj = new em_onewifi_t());
    std::cout << "em_onewifi_t object created successfully on heap." << std::endl;
    // Invoke the destructor via delete and ensure no throw occurs.
    std::cout << "Invoking destructor for em_onewifi_t by calling delete." << std::endl;
    EXPECT_NO_THROW(delete obj);
    std::cout << "em_onewifi_t destructor invoked successfully upon deletion." << std::endl;
    std::cout << "Exiting ObjectCreationOnHeapAndProperDeletion test" << std::endl;
}
