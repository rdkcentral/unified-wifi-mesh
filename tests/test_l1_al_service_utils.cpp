
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
#include <cstdint>
#include <vector>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/socket.h>
#include "al_service_utils.h"



/**
 * @brief Test to verify that areMacsEqual returns true for two identical MAC addresses
 *
 * This test case checks the functionality of the areMacsEqual API by verifying that two identical MAC addresses
 * are compared equal. It confirms the basic behavior of MAC address comparison and ensures that the API returns true
 * when both input MAC addresses are identical.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 001@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                   | Test Data                                                                                                             | Expected Result                                                    | Notes      |
 * | :--------------: | --------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ | ---------- |
 * | 01               | Initialize two identical MAC addresses and invoke areMacsEqual to compare them                | input: first = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, second = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}; output: result            | API returns true and assertion EXPECT_TRUE(result) passes          | Should Pass |
 */
TEST(al_service_utils_t, areMacsEqual_PositiveIdenticalMAC) {
    std::cout << "Entering areMacsEqual_PositiveIdenticalMAC test" << std::endl;
    std::array<uint8_t, 6> first = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    std::array<uint8_t, 6> second = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    std::cout << "Invoking areMacsEqual with first MAC: { ";
    for (auto byte : first)
        std::cout << "0x" << std::hex << static_cast<int>(byte) << " ";
    std::cout << "} and second MAC: { ";
    for (auto byte : second)
        std::cout << "0x" << std::hex << static_cast<int>(byte) << " ";
    std::cout << "}" << std::endl;
    bool result = areMacsEqual(first, second);
    std::cout << "Result returned: " << std::boolalpha << result << std::endl;
    EXPECT_TRUE(result);
    std::cout << "Exiting areMacsEqual_PositiveIdenticalMAC test" << std::endl;
}
/**
 * @brief Verify areMacsEqual correctly identifies non-matching MAC addresses
 *
 * This test checks that the areMacsEqual API correctly returns false when two MAC addresses differ in one byte. It validates the proper functioning of the MAC address comparison logic, ensuring that even a minor difference is detected.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 002
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize two MAC addresses with one differing last byte, invoke areMacsEqual function, and validate the result | first = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, second = {0x00, 0x11, 0x22, 0x33, 0x44, 0x56} | Function returns false and EXPECT_FALSE assertion confirms the API detects the difference | Should Fail |
 */
TEST(al_service_utils_t, areMacsEqual_NegativeOneDifferingByteAtEnd) {
    std::cout << "Entering areMacsEqual_NegativeOneDifferingByteAtEnd test" << std::endl;
    std::array<uint8_t, 6> first = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    std::array<uint8_t, 6> second = {0x00, 0x11, 0x22, 0x33, 0x44, 0x56};
    std::cout << "Invoking areMacsEqual with first MAC: { ";
    for (auto byte : first)
        std::cout << "0x" << std::hex << static_cast<int>(byte) << " ";
    std::cout << "} and second MAC: { ";
    for (auto byte : second)
        std::cout << "0x" << std::hex << static_cast<int>(byte) << " ";
    std::cout << "}" << std::endl;
    bool result = areMacsEqual(first, second);
    std::cout << "Result returned: " << std::boolalpha << result << std::endl;
    EXPECT_FALSE(result);
    std::cout << "Exiting areMacsEqual_NegativeOneDifferingByteAtEnd test" << std::endl;
}
/**
 * @brief Verify that areMacsEqual returns false when provided with two completely different MAC addresses
 *
 * This test verifies that the areMacsEqual API correctly identifies two MAC addresses as not equal when all bytes are different. It tests the negative scenario to ensure that the function returns false when the input MAC addresses do not match.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 003@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                               | Test Data                                                                                                  | Expected Result                                            | Notes       |
 * | :--------------: | ----------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- | ----------- |
 * | 01               | Invoke areMacsEqual with two MAC addresses that are completely different                   | input: first = {0xff,0xff,0xff,0xff,0xff,0xff}, second = {0x00,0x00,0x00,0x00,0x00,0x00}, output: false | Function returns false and assertion (EXPECT_FALSE) passes | Should Fail |
 */
TEST(al_service_utils_t, areMacsEqual_NegativeAllBytesDifferent) {
    std::cout << "Entering areMacsEqual_NegativeAllBytesDifferent test" << std::endl;
    std::array<uint8_t, 6> first = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    std::array<uint8_t, 6> second = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    std::cout << "Invoking areMacsEqual with first MAC: { ";
    for (auto byte : first)
        std::cout << "0x" << std::hex << static_cast<int>(byte) << " ";
    std::cout << "} and second MAC: { ";
    for (auto byte : second)
        std::cout << "0x" << std::hex << static_cast<int>(byte) << " ";
    std::cout << "}" << std::endl;
    bool result = areMacsEqual(first, second);
    std::cout << "Result returned: " << std::boolalpha << result << std::endl;
    EXPECT_FALSE(result);
    std::cout << "Exiting areMacsEqual_NegativeAllBytesDifferent test" << std::endl;
}
/**
 * @brief Test to verify that areMacsEqual returns true when both MAC addresses are all zeros.
 *
 * This test checks the functionality of the areMacsEqual API by providing two MAC addresses,
 * both containing all zeros. The test verifies that the API correctly identifies the MACs as equal.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 004@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                      | Test Data                                                                                                          | Expected Result                                               | Notes      |
 * | :--------------: | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------- | ---------- |
 * | 01               | Initialize two MAC address arrays with all zero values and invoke areMacsEqual | first = {0x00,0x00,0x00,0x00,0x00,0x00}, second = {0x00,0x00,0x00,0x00,0x00,0x00} | API returns true and EXPECT_TRUE verifies the result as true    | Should Pass |
 */
TEST(al_service_utils_t, areMacsEqual_PositiveAllZeros) {
    std::cout << "Entering areMacsEqual_PositiveAllZeros test" << std::endl;
    std::array<uint8_t, 6> first = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    std::array<uint8_t, 6> second = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    std::cout << "Invoking areMacsEqual with first MAC: { ";
    for (auto byte : first)
        std::cout << "0x" << std::hex << static_cast<int>(byte) << " ";
    std::cout << "} and second MAC: { ";
    for (auto byte : second)
        std::cout << "0x" << std::hex << static_cast<int>(byte) << " ";
    std::cout << "}" << std::endl;
    bool result = areMacsEqual(first, second);
    std::cout << "Result returned: " << std::boolalpha << result << std::endl;
    EXPECT_TRUE(result);
    std::cout << "Exiting areMacsEqual_PositiveAllZeros test" << std::endl;
}
/**
 * @brief Verify that areMacsEqual returns true when provided with two identical MAC addresses.
 *
 * This test ensures that when two MAC addresses with exactly the same mixed hexadecimal values are provided,
 * the areMacsEqual function correctly identifies them as equal. It validates both the function's logic and
 * the diagnostic logging during execution.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 005@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize two MAC addresses with identical values | first = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, second = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF} | Both MAC address arrays are correctly set with identical values | Should be successful |
 * | 02 | Invoke areMacsEqual API with initialized MAC addresses and verify the output | Input: first = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, second = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}; Output: result = true | Function returns true and EXPECT_TRUE(result) passes | Should Pass |
 */
TEST(al_service_utils_t, areMacsEqual_PositiveMixedValues) {
    std::cout << "Entering areMacsEqual_PositiveMixedValues test" << std::endl;
    std::array<uint8_t, 6> first = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    std::array<uint8_t, 6> second = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    std::cout << "Invoking areMacsEqual with first MAC: { ";
    for (auto byte : first)
        std::cout << "0x" << std::hex << static_cast<int>(byte) << " ";
    std::cout << "} and second MAC: { ";
    for (auto byte : second)
        std::cout << "0x" << std::hex << static_cast<int>(byte) << " ";
    std::cout << "}" << std::endl;
    bool result = areMacsEqual(first, second);
    std::cout << "Result returned: " << std::boolalpha << result << std::endl;
    EXPECT_TRUE(result);
    std::cout << "Exiting areMacsEqual_PositiveMixedValues test" << std::endl;
}
/**
 * @brief Verify that areMacsEqual returns false when the MAC addresses have different first bytes.
 *
 * This test verifies that the areMacsEqual function correctly identifies two MAC addresses as unequal when their first bytes differ. The objective is to ensure that the comparison logic properly handles negative scenarios where at least one corresponding byte between the two arrays does not match.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 006@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                       | Test Data                                                                                                                                                                                                                                  | Expected Result                  | Notes      |
 * | :--------------: | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------- | ---------- |
 * | 01               | Invoke areMacsEqual with two MAC addresses where the first byte of each MAC is different         | first[0]=0x11, first[1]=0x11, first[2]=0x22, first[3]=0x33, first[4]=0x44, first[5]=0x55, second[0]=0x22, second[1]=0x11, second[2]=0x22, second[3]=0x33, second[4]=0x44, second[5]=0x55                                                                           | API returns false, EXPECT_FALSE(result) | Should Fail |
 */
TEST(al_service_utils_t, areMacsEqual_NegativeDifferentFirstByte) {
    std::cout << "Entering areMacsEqual_NegativeDifferentFirstByte test" << std::endl;
    std::array<uint8_t, 6> first = {0x11, 0x11, 0x22, 0x33, 0x44, 0x55};
    std::array<uint8_t, 6> second = {0x22, 0x11, 0x22, 0x33, 0x44, 0x55};
    std::cout << "Invoking areMacsEqual with first MAC: { ";
    for (auto byte : first)
        std::cout << "0x" << std::hex << static_cast<int>(byte) << " ";
    std::cout << "} and second MAC: { ";
    for (auto byte : second)
        std::cout << "0x" << std::hex << static_cast<int>(byte) << " ";
    std::cout << "}" << std::endl;
    bool result = areMacsEqual(first, second);
    std::cout << "Result returned: " << std::boolalpha << result << std::endl;
    EXPECT_FALSE(result);
    std::cout << "Exiting areMacsEqual_NegativeDifferentFirstByte test" << std::endl;
}
/**
 * @brief Verify the conversion of a byte vector to a 32-bit unsigned integer.
 *
 * This test validates that the convert_bytes_into_u32 function correctly converts a predefined byte sequence
 * ({0x00, 0x00, 0x01, 0x02}) into its corresponding 32-bit unsigned integer representation (258u).
 * The test ensures that the API performs as expected for a basic positive test scenario.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 007@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                                           | Test Data                                           | Expected Result                                                                                        | Notes        |
 * | :--------------: | ----------------------------------------------------------------------------------------------------- | --------------------------------------------------- | ------------------------------------------------------------------------------------------------------ | ------------ |
 * | 01               | Invoke convert_bytes_into_u32 with a defined byte vector to convert it into a 32-bit unsigned integer. | inputBytes = {0x00, 0x00, 0x01, 0x02}, output = 258u | Return value equals 258u and the EXPECT_EQ assertion passes.                                            | Should Pass  |
 */
TEST(al_service_utils_t, convert_bytes_into_u32_basic_positive_case) {
    std::cout << "Entering convert_bytes_into_u32_basic_positive_case test" << std::endl;

    std::vector<unsigned char> inputBytes = {0x00, 0x00, 0x01, 0x02};
    std::cout << "Invoking convert_bytes_into_u32 with input vector: {0x00, 0x00, 0x01, 0x02}" << std::endl;

    uint32_t result = convert_bytes_into_u32(inputBytes);
    std::cout << "Returned value: " << result << std::endl;

    EXPECT_EQ(result, 258u);

    std::cout << "Exiting convert_bytes_into_u32_basic_positive_case test" << std::endl;
}
/**
 * @brief Test conversion of a zero value into a byte vector.
 *
 * This test verifies that calling convert_u32_into_bytes with an input of 0 correctly returns a byte vector of four zeroed bytes. It confirms that the conversion function handles the zero input scenario by checking both the size of the returned vector and each individual byte.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 008
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                        | Test Data                                           | Expected Result                                               | Notes             |
 * | :--------------: | -------------------------------------------------- | --------------------------------------------------- | ------------------------------------------------------------- | ----------------- |
 * | 01               | Initialize input with zero value                   | input = 0                                           | Variable input correctly initialized to 0                     | Should be successful |
 * | 02               | Invoke convert_u32_into_bytes with the input value | input = 0                                           | Function returns a vector of 4 bytes: {0x00, 0x00, 0x00, 0x00} | Should Pass       |
 * | 03               | Compare returned vector with the expected vector   | expected = {0x00, 0x00, 0x00, 0x00}                   | Returned vector size equals expected size and each element matches | Should Pass       |
 */
TEST(al_service_utils_t, convert_u32_into_bytes_ConvertZeroValue) {
    std::cout << "Entering convert_u32_into_bytes_ConvertZeroValue test" << std::endl;
    uint32_t input = 0;
    std::cout << "Invoking convert_u32_into_bytes with input value: " << input << std::endl;
    std::vector<unsigned char> result = convert_u32_into_bytes(input);
    std::cout << "Returned vector values: ";
    for (size_t i = 0; i < result.size(); ++i) {
        std::cout << "0x" << std::hex << static_cast<int>(result[i]);
        if(i != result.size() - 1)
            std::cout << ", ";
    }
    std::cout << std::dec << std::endl;
    std::vector<unsigned char> expected = {0x00, 0x00, 0x00, 0x00};
    EXPECT_EQ(result.size(), expected.size());
    for(size_t i = 0; i < expected.size(); ++i) {
        EXPECT_EQ(result[i], expected[i]);
    }
    std::cout << "Exiting convert_u32_into_bytes_ConvertZeroValue test" << std::endl;
}
/**
 * @brief Verify that convert_u32_into_bytes correctly converts a small positive integer into its 4-byte representation.
 *
 * This test validates that the function convert_u32_into_bytes correctly converts a given uint32_t value (a small positive value) into a std::vector<unsigned char> that represents the corresponding bytes in big-endian order. It confirms that the returned vector matches the expected 4-byte sequence: 0x00, 0x00, 0x00, 0x01.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 009@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call convert_u32_into_bytes with an input value of 1 and verify the returned vector matches the expected byte sequence | input = 1, expected output = {0x00, 0x00, 0x00, 0x01} | The returned vector should have a size of 4 and the content should be: 0x00, 0x00, 0x00, 0x01; all assertions should pass | Should Pass |
 */
TEST(al_service_utils_t, convert_u32_into_bytes_ConvertSmallPositiveValue) {
    std::cout << "Entering convert_u32_into_bytes_ConvertSmallPositiveValue test" << std::endl;
    uint32_t input = 1;
    std::cout << "Invoking convert_u32_into_bytes with input value: " << input << std::endl;
    std::vector<unsigned char> result = convert_u32_into_bytes(input);
    std::cout << "Returned vector values: ";
    for (size_t i = 0; i < result.size(); ++i) {
        std::cout << "0x" << std::hex << static_cast<int>(result[i]);
        if(i != result.size() - 1)
            std::cout << ", ";
    }
    std::cout << std::dec << std::endl;
    std::vector<unsigned char> expected = {0x00, 0x00, 0x00, 0x01};
    EXPECT_EQ(result.size(), expected.size());
    for (size_t i = 0; i < expected.size(); ++i) {
        EXPECT_EQ(result[i], expected[i]);
    }
    std::cout << "Exiting convert_u32_into_bytes_ConvertSmallPositiveValue test" << std::endl;
}
/**
 * @brief Verify conversion of a positive uint32_t into its corresponding byte vector representation.
 *
 * Validate that the convert_u32_into_bytes API correctly converts a positive 32-bit integer (0x12345678) into a vector of unsigned char values representing its bytes.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 010
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                        | Test Data                                                    | Expected Result                                             | Notes            |
 * | :--------------: | ------------------------------------------------------------------ | ------------------------------------------------------------ | ----------------------------------------------------------- | ---------------- |
 * | 01               | Initialize input value and log entry into test                     | input = 305419896 (0x12345678)                                 | Logging of test start message                               | Should be successful |
 * | 02               | Invoke convert_u32_into_bytes API with given input                  | input = 305419896 (0x12345678)                                 | API returns a vector of bytes                                | Should Pass      |
 * | 03               | Verify the returned vector size equals the expected size (4)        | output vector size = result.size(), expected size = 4          | result.size() equals 4                                       | Should Pass      |
 * | 04               | Compare each byte of the returned vector with expected values       | output bytes = result[i], expected bytes = {0x12,0x34,0x56,0x78} | Each byte matches the corresponding expected byte            | Should Pass      |
 * | 05               | Log the exit of the test                                           | None                                                         | Logging of test exit message                                | Should be successful |
 */
TEST(al_service_utils_t, convert_u32_into_bytes_ConvertArbitraryPositiveValue) {
    std::cout << "Entering convert_u32_into_bytes_ConvertArbitraryPositiveValue test" << std::endl;
    uint32_t input = 305419896; // 0x12345678
    std::cout << "Invoking convert_u32_into_bytes with input value: " << input << std::endl;
    std::vector<unsigned char> result = convert_u32_into_bytes(input);
    std::cout << "Returned vector values: ";
    for (size_t i = 0; i < result.size(); ++i) {
        std::cout << "0x" << std::hex << static_cast<int>(result[i]);
        if(i != result.size() - 1)
            std::cout << ", ";
    }
    std::cout << std::dec << std::endl;
    std::vector<unsigned char> expected = {0x12, 0x34, 0x56, 0x78};
    EXPECT_EQ(result.size(), expected.size());
    for (size_t i = 0; i < expected.size(); ++i) {
        EXPECT_EQ(result[i], expected[i]);
    }
    std::cout << "Exiting convert_u32_into_bytes_ConvertArbitraryPositiveValue test" << std::endl;
}
/**
 * @brief Validate conversion of maximum unsigned 32-bit integer into a byte vector.
 *
 * This test verifies that the function convert_u32_into_bytes correctly converts the maximum uint32_t value (4294967295 / 0xFFFFFFFF) into a std::vector<unsigned char> containing exactly 4 bytes of value 0xFF each. It confirms the size of the output and the byte-by-byte correctness.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 011@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Set input as maximum uint32_t and invoke convert_u32_into_bytes with this input. | input = 4294967295, expected = {0xFF,0xFF,0xFF,0xFF} | Function returns a vector where size equals 4 and each byte equals 0xFF. | Should Pass |
 */
TEST(al_service_utils_t, convert_u32_into_bytes_ConvertMaximumValue) {
    std::cout << "Entering convert_u32_into_bytes_ConvertMaximumValue test" << std::endl;
    uint32_t input = 4294967295; // UINT32_MAX, 0xFFFFFFFF
    std::cout << "Invoking convert_u32_into_bytes with input value: " << input << std::endl;
    std::vector<unsigned char> result = convert_u32_into_bytes(input);
    std::cout << "Returned vector values: ";
    for (size_t i = 0; i < result.size(); ++i) {
        std::cout << "0x" << std::hex << static_cast<int>(result[i]);
        if(i != result.size() - 1)
            std::cout << ", ";
    }
    std::cout << std::dec << std::endl;
    std::vector<unsigned char> expected = {0xFF, 0xFF, 0xFF, 0xFF};
    EXPECT_EQ(result.size(), expected.size());
    for (size_t i = 0; i < expected.size(); ++i) {
        EXPECT_EQ(result[i], expected[i]);
    }
    std::cout << "Exiting convert_u32_into_bytes_ConvertMaximumValue test" << std::endl;
}
/**
 * @brief Test createUDPClientAddress API with a valid IPv4 address and standard port
 *
 * This test verifies that the createUDPClientAddress function correctly initializes a sockaddr_in structure when provided with a valid IPv4 address ("192.168.0.1") and a standard port (80). It ensures that the returned structure has the expected sin_family, sin_port (in network byte order), and sin_addr.s_addr values.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 012
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                         | Test Data                                                                                           | Expected Result                                                                              | Notes         |
 * | :--------------: | ------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | ------------- |
 * | 01               | Initialize variables with valid IP and port values                  | ip = "192.168.0.1", port = 80                                                                         | Variables initialized with the specified values                                              | Should be successful  |
 * | 02               | Invoke createUDPClientAddress API with the initialized parameters      | input ip = "192.168.0.1", input port = 80, output sockaddr_in                                        | Returned sockaddr_in structure with sin_family set to AF_INET                                  | Should Pass   |
 * | 03               | Verify the returned sockaddr_in fields using assertions                | expected sin_family = AF_INET, sin_port = htons(80), sin_addr.s_addr = inet_addr("192.168.0.1")       | EXPECT_EQ assertions pass verifying sin_family, sin_port, and sin_addr.s_addr                   | Should Pass   |
 */
TEST(al_service_utils_t, createUDPClientAddress_ValidIPv4AddressAndStandardPort) {
    std::cout << "Entering createUDPClientAddress_ValidIPv4AddressAndStandardPort test" << std::endl;
    std::string ip = "192.168.0.1";
    int port = 80;
    std::cout << "Invoking createUDPClientAddress with ip: " << ip << " and port: " << port << std::endl;
    struct sockaddr_in addr = createUDPClientAddress(ip, port);
    std::cout << "Returned sockaddr_in values: "
              << "sin_family: " << addr.sin_family
              << ", sin_port: " << addr.sin_port
              << ", sin_addr.s_addr: " << addr.sin_addr.s_addr << std::endl;
    EXPECT_EQ(addr.sin_family, AF_INET);
    EXPECT_EQ(addr.sin_port, htons(port));
    EXPECT_EQ(addr.sin_addr.s_addr, inet_addr(ip.c_str()));
    std::cout << "Exiting createUDPClientAddress_ValidIPv4AddressAndStandardPort test" << std::endl;
}
/**
 * @brief Validates the creation of a UDP client address with a valid loopback IPv4 address and port set to zero.
 *
 * This test invokes the createUDPClientAddress API using the loopback IP "127.0.0.1" and a port value of 0.
 * It verifies that the returned sockaddr_in structure has the correct address family (AF_INET),
 * port (htons(0)), and IP address (inet_addr("127.0.0.1")). This confirms that the API correctly handles the
 * cases with minimal port value while supporting loopback IP.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :--------------: | ----------- | --------- | ------------- | ----- |
 * | 01 | Initialize test variables for IP and port. | ip = "127.0.0.1", port = 0 | Variables are set before calling the API. | Should be successful |
 * | 02 | Invoke createUDPClientAddress API with the initialized IP and port. | input ip = "127.0.0.1", port = 0 | Returns a sockaddr_in structure with sin_family = AF_INET, sin_port = htons(0), sin_addr.s_addr = inet_addr("127.0.0.1"). | Should Pass |
 * | 03 | Validate the returned sockaddr_in structure using assertions. | output sin_family = AF_INET, sin_port = htons(0), sin_addr.s_addr = inet_addr("127.0.0.1") | All EXPECT_EQ assertions pass. | Should Pass |
 */
TEST(al_service_utils_t, createUDPClientAddress_ValidLoopbackIPv4AddressAndPortZero) {
    std::cout << "Entering createUDPClientAddress_ValidLoopbackIPv4AddressAndPortZero test" << std::endl;
    std::string ip = "127.0.0.1";
    int port = 0;
    std::cout << "Invoking createUDPClientAddress with ip: " << ip << " and port: " << port << std::endl;
    struct sockaddr_in addr = createUDPClientAddress(ip, port);
    std::cout << "Returned sockaddr_in values: "
              << "sin_family: " << addr.sin_family
              << ", sin_port: " << addr.sin_port
              << ", sin_addr.s_addr: " << addr.sin_addr.s_addr << std::endl;
    EXPECT_EQ(addr.sin_family, AF_INET);
    EXPECT_EQ(addr.sin_port, htons(port));
    EXPECT_EQ(addr.sin_addr.s_addr, inet_addr(ip.c_str()));
    std::cout << "Exiting createUDPClientAddress_ValidLoopbackIPv4AddressAndPortZero test" << std::endl;
}
/**
 * @brief Test to verify creation of UDP client address using valid IPv4 broadcast address and high port.
 *
 * This test checks that calling createUDPClientAddress with a broadcast IP (255.255.255.255) and a high port (65535)
 * returns a sockaddr_in structure with the correct address family, port, and IP address. It ensures that the API handles
 * edge boundary IP values and port numbers correctly.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 014@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                     | Test Data                                                                                                                     | Expected Result                                                                                              | Notes      |
 * | :--------------: | --------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ | ---------- |
 * | 01               | Invoke createUDPClientAddress with valid IPv4 broadcast IP and high port value | ip = 255.255.255.255, port = 65535, expected sin_family = AF_INET, expected sin_port = htons(65535), expected sin_addr.s_addr = inet_addr("255.255.255.255") | Returns sockaddr_in with sin_family = AF_INET, sin_port = htons(65535), sin_addr.s_addr = inet_addr(ip) | Should Pass |
 */
TEST(al_service_utils_t, createUDPClientAddress_ValidIPv4BroadcastAddressAndHighPort) {
    std::cout << "Entering createUDPClientAddress_ValidIPv4BroadcastAddressAndHighPort test" << std::endl;
    std::string ip = "255.255.255.255";
    int port = 65535;
    std::cout << "Invoking createUDPClientAddress with ip: " << ip << " and port: " << port << std::endl;
    struct sockaddr_in addr = createUDPClientAddress(ip, port);
    std::cout << "Returned sockaddr_in values: "
              << "sin_family: " << addr.sin_family
              << ", sin_port: " << addr.sin_port
              << ", sin_addr.s_addr: " << addr.sin_addr.s_addr << std::endl;
    EXPECT_EQ(addr.sin_family, AF_INET);
    EXPECT_EQ(addr.sin_port, htons(port));
    EXPECT_EQ(addr.sin_addr.s_addr, inet_addr(ip.c_str()));
    std::cout << "Exiting createUDPClientAddress_ValidIPv4BroadcastAddressAndHighPort test" << std::endl;
}
/**
 * @brief Validate UDP client address creation with edge IPv4 values.
 *
 * This test verifies that the createUDPClientAddress API correctly handles the edge case of an IPv4 address "0.0.0.0" with port 0. It ensures that the API properly initializes the sockaddr_in structure with expected values.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 015
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke createUDPClientAddress with ip "0.0.0.0" and port 0. | ip = "0.0.0.0", port = 0, expected sin_family, sin_port, sin_addr.s_addr | sin_family should be AF_INET, sin_port should be htons(0), sin_addr.s_addr should be inet_addr("0.0.0.0") | Should Pass |
 */
TEST(al_service_utils_t, createUDPClientAddress_EdgeIPv4AddressAndPortZero) {
    std::cout << "Entering createUDPClientAddress_EdgeIPv4AddressAndPortZero test" << std::endl;
    std::string ip = "0.0.0.0";
    int port = 0;
    std::cout << "Invoking createUDPClientAddress with ip: " << ip << " and port: " << port << std::endl;
    struct sockaddr_in addr = createUDPClientAddress(ip, port);
    std::cout << "Returned sockaddr_in values: "
              << "sin_family: " << addr.sin_family
              << ", sin_port: " << addr.sin_port
              << ", sin_addr.s_addr: " << addr.sin_addr.s_addr << std::endl;
    EXPECT_EQ(addr.sin_family, AF_INET);
    EXPECT_EQ(addr.sin_port, htons(port));
    EXPECT_EQ(addr.sin_addr.s_addr, inet_addr(ip.c_str()));
    std::cout << "Exiting createUDPClientAddress_EdgeIPv4AddressAndPortZero test" << std::endl;
}
/**
 * @brief Verify that createUDPClientAddress correctly handles an IPv4 address that is out of range.
 *
 * This test ensures that when an invalid IPv4 address ("256.256.256.256") is provided along with a valid port number (80), the createUDPClientAddress function returns a sockaddr_in structure with sin_family set to AF_INET, sin_port set to htons(port), and sin_addr.s_addr set to INADDR_NONE, indicating the failure to resolve the IP address.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 016@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call createUDPClientAddress with an out-of-range IPv4 address ("256.256.256.256") and a valid port (80) to validate error handling for IP address resolution. | ip = 256.256.256.256, port = 80, output: sockaddr_in structure | sockaddr_in.sin_family equals AF_INET, sockaddr_in.sin_port equals htons(80), sockaddr_in.sin_addr.s_addr equals INADDR_NONE | Should Pass |
 */
TEST(al_service_utils_t, createUDPClientAddress_InvalidIPv4AddressOutOfRange) {
    std::cout << "Entering createUDPClientAddress_InvalidIPv4AddressOutOfRange test" << std::endl;
    std::string ip = "256.256.256.256";
    int port = 80;
    std::cout << "Invoking createUDPClientAddress with ip: " << ip << " and port: " << port << std::endl;
    struct sockaddr_in addr = createUDPClientAddress(ip, port);
    std::cout << "Returned sockaddr_in values: "
              << "sin_family: " << addr.sin_family
              << ", sin_port: " << addr.sin_port
              << ", sin_addr.s_addr: " << addr.sin_addr.s_addr << std::endl;
    EXPECT_EQ(addr.sin_family, AF_INET);
    EXPECT_EQ(addr.sin_port, htons(port));
    EXPECT_EQ(addr.sin_addr.s_addr, INADDR_NONE);
    std::cout << "Exiting createUDPClientAddress_InvalidIPv4AddressOutOfRange test" << std::endl;
}
/**
 * @brief Validates the createUDPClientAddress function with an empty IPv4 address and a valid port.
 *
 * Tests the createUDPClientAddress function by providing an empty string as the IPv4 address and a valid port number. It verifies that the returned sockaddr_in structure contains the AF_INET family, the port is correctly converted to network byte order, and the IP address is set to INADDR_NONE.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 017
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                 | Test Data                                      | Expected Result                                                                                             | Notes       |
 * | :--------------: | --------------------------------------------------------------------------- | ---------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Initialize test variables with an empty IPv4 address and a valid port number. | ip = "", port = 1234                           | Variables are initialized with ip as an empty string and port as 1234.                                      | Should Pass |
 * | 02               | Invoke createUDPClientAddress with the initialized ip and port values.       | input: ip = "", port = 1234, output: sockaddr_in | Function returns a sockaddr_in structure with sin_family = AF_INET, sin_port = htons(1234), sin_addr = INADDR_NONE. | Should Pass |
 * | 03               | Validate the returned sockaddr_in structure using assertions.               | Expected: sin_family = AF_INET, sin_port = htons(1234), sin_addr.s_addr = INADDR_NONE | Assertions confirm that the returned structure values match AF_INET, converted port number, and INADDR_NONE.   | Should Pass |
 */
TEST(al_service_utils_t, createUDPClientAddress_EmptyIPv4AddressWithValidPort) {
    std::cout << "Entering createUDPClientAddress_EmptyIPv4AddressWithValidPort test" << std::endl;
    std::string ip = "";
    int port = 1234;
    std::cout << "Invoking createUDPClientAddress with ip: \"" << ip << "\" and port: " << port << std::endl;
    struct sockaddr_in addr = createUDPClientAddress(ip, port);
    std::cout << "Returned sockaddr_in values: "
              << "sin_family: " << addr.sin_family
              << ", sin_port: " << addr.sin_port
              << ", sin_addr.s_addr: " << addr.sin_addr.s_addr << std::endl;
    EXPECT_EQ(addr.sin_family, AF_INET);
    EXPECT_EQ(addr.sin_port, htons(port));
    EXPECT_EQ(addr.sin_addr.s_addr, INADDR_NONE);
    std::cout << "Exiting createUDPClientAddress_EmptyIPv4AddressWithValidPort test" << std::endl;
}
/**
 * @brief Test createUDPServerAddress with a valid typical port value (8080)
 *
 * This test verifies that the createUDPServerAddress function correctly creates a UDP server address structure
 * when provided with a typical port number. It checks that the returned structure's family, port, and address fields
 * are correctly set to AF_INET, htons(port), and INADDR_ANY respectively.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 018@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize test, set port to 8080 and log entry message | port = 8080 | Port variable is correctly initialized and entry message is logged | Should be successful |
 * | 02 | Invoke createUDPServerAddress API with port 8080 | input: port = 8080 | Function returns a sockaddr_in structure with valid values | Should Pass |
 * | 03 | Validate sin_family field of returned structure | output: sin_family from sockaddr_in | Field equals AF_INET | Should Pass |
 * | 04 | Validate sin_port field of returned structure | input: port = 8080, output: sin_port from sockaddr_in | Field equals htons(8080) | Should Pass |
 * | 05 | Validate sin_addr.s_addr field of returned structure | output: sin_addr.s_addr from sockaddr_in | Field equals INADDR_ANY | Should Pass |
 * | 06 | Log exit message of the test | None | Exit message is printed indicating test completion | Should be successful |
 */
TEST(al_service_utils_t, createUDPServerAddress_valid_typical_port) {
    std::cout << "Entering createUDPServerAddress_valid_typical_port test" << std::endl;
    int port = 8080;
    std::cout << "Invoking createUDPServerAddress with port: " << port << std::endl;
    struct sockaddr_in addr = createUDPServerAddress(port);
    std::cout << "Returned structure values:" << std::endl;
    std::cout << "sin_family: " << addr.sin_family << std::endl;
    std::cout << "sin_port: " << addr.sin_port << " (expected: " << htons(port) << ")" << std::endl;
    std::cout << "sin_addr.s_addr: " << addr.sin_addr.s_addr << " (expected: " << INADDR_ANY << ")" << std::endl;
    EXPECT_EQ(addr.sin_family, AF_INET);
    EXPECT_EQ(addr.sin_port, htons(port));
    EXPECT_EQ(addr.sin_addr.s_addr, INADDR_ANY);
    std::cout << "Exiting createUDPServerAddress_valid_typical_port test" << std::endl;
}
/**
 * @brief Validates createUDPServerAddress API with a system assigned port
 *
 * This test verifies that the createUDPServerAddress function returns a valid sockaddr_in structure when invoked with a system assigned port (port = 0). It checks that the structure's sin_family, sin_port, and sin_addr.s_addr fields are appropriately set.
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
 * | Variation / Step | Description                                                       | Test Data                                                                           | Expected Result                                                                                      | Notes       |
 * | :--------------: | ----------------------------------------------------------------- | ----------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke createUDPServerAddress with port value 0                   | port = 0, expected sin_family = AF_INET, expected sin_port = htons(0), expected sin_addr.s_addr = INADDR_ANY | Function returns a valid sockaddr_in structure with the expected values using the system assigned port | Should Pass |
 */
TEST(al_service_utils_t, createUDPServerAddress_valid_system_assigned_port) {
    std::cout << "Entering createUDPServerAddress_valid_system_assigned_port test" << std::endl;
    int port = 0;
    std::cout << "Invoking createUDPServerAddress with port: " << port << std::endl;
    struct sockaddr_in addr = createUDPServerAddress(port);
    std::cout << "Returned structure values:" << std::endl;
    std::cout << "sin_family: " << addr.sin_family << std::endl;
    std::cout << "sin_port: " << addr.sin_port << " (expected: " << htons(port) << ")" << std::endl;
    std::cout << "sin_addr.s_addr: " << addr.sin_addr.s_addr << " (expected: " << INADDR_ANY << ")" << std::endl;
    EXPECT_EQ(addr.sin_family, AF_INET);
    EXPECT_EQ(addr.sin_port, htons(port));
    EXPECT_EQ(addr.sin_addr.s_addr, INADDR_ANY);
    std::cout << "Exiting createUDPServerAddress_valid_system_assigned_port test" << std::endl;
}
/**
 * @brief Validate createUDPServerAddress API with maximum port value.
 *
 * This test verifies that calling createUDPServerAddress with the maximum valid port number (65535) returns a sockaddr_in structure with the proper configuration. It checks that the sin_family is set to AF_INET, the sin_port is correctly converted using htons, and the sin_addr.s_addr is set to INADDR_ANY.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 020@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                                              | Test Data                                                              | Expected Result                                                                                           | Notes       |
 * | :--------------: | ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke createUDPServerAddress API with port set to 65535                                   | port = 65535, expected sin_family = AF_INET, expected sin_port = htons(65535), expected sin_addr.s_addr = INADDR_ANY | The function should return a sockaddr_in structure with sin_family equal to AF_INET, sin_port equal to htons(65535), and sin_addr.s_addr equal to INADDR_ANY | Should Pass |
 */
TEST(al_service_utils_t, createUDPServerAddress_valid_maximum_port) {
    std::cout << "Entering createUDPServerAddress_valid_maximum_port test" << std::endl;
    int port = 65535;
    std::cout << "Invoking createUDPServerAddress with port: " << port << std::endl;
    struct sockaddr_in addr = createUDPServerAddress(port);
    std::cout << "Returned structure values:" << std::endl;
    std::cout << "sin_family: " << addr.sin_family << std::endl;
    std::cout << "sin_port: " << addr.sin_port << " (expected: " << htons(port) << ")" << std::endl;
    std::cout << "sin_addr.s_addr: " << addr.sin_addr.s_addr << " (expected: " << INADDR_ANY << ")" << std::endl;
    EXPECT_EQ(addr.sin_family, AF_INET);
    EXPECT_EQ(addr.sin_port, htons(port));
    EXPECT_EQ(addr.sin_addr.s_addr, INADDR_ANY);
    std::cout << "Exiting createUDPServerAddress_valid_maximum_port test" << std::endl;
}
/**
 * @brief Validate the typical scenario for Unix socket address creation using a standard path
 *
 * Validate that the createUnixSocketAddress function correctly populates the sockaddr_un structure when given a valid Unix socket path. The test ensures that the sun_family field is set to AF_UNIX and the sun_path field properly reflects the input value.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 021@n
 * **Priority:** High@n
 * @n
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * @n
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call createUnixSocketAddress with a typical Unix socket path | input = MyUnixSocket, output.sun_family = AF_UNIX, output.sun_path = MyUnixSocket | Returned sockaddr_un structure has sun_family equal to AF_UNIX and sun_path equal to "MyUnixSocket" | Should Pass |
 */
TEST(al_service_utils_t, createUnixSocketAddress_TypicalPath) {
    std::cout << "Entering createUnixSocketAddress_TypicalPath test" << std::endl;
    std::string input = "MyUnixSocket";
    std::cout << "Invoking createUnixSocketAddress with path: " << input << std::endl;
    struct sockaddr_un addr = createUnixSocketAddress(input);
    std::cout << "Returned sun_family: " << addr.sun_family << std::endl;
    std::cout << "Returned sun_path: " << addr.sun_path << std::endl;
    EXPECT_EQ(addr.sun_family, AF_UNIX);
    EXPECT_STREQ(addr.sun_path, input.c_str());
    std::cout << "Exiting createUnixSocketAddress_TypicalPath test" << std::endl;
}
/**
 * @brief Test the creation of a Unix socket address with an empty path.
 *
 * This test verifies that when an empty string is provided as the path to createUnixSocketAddress,
 * the returned sockaddr_un structure has its sun_family field correctly set to AF_UNIX and its sun_path
 * field exactly equal to the empty string. This ensures that the API handles empty input gracefully.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 022@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                               | Test Data                                               | Expected Result                                                                                       | Notes       |
 * | :--------------: | ----------------------------------------------------------------------------------------- | ------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | ----------- |
 * |       01       | Invoke createUnixSocketAddress API with an empty path and validate the output fields.       | input = ""; output: sun_family, sun_path                | Returned structure with sun_family equals AF_UNIX and sun_path equals ""; assertions must pass.       | Should Pass |
 */
TEST(al_service_utils_t, createUnixSocketAddress_EmptyPath) {
    std::cout << "Entering createUnixSocketAddress_EmptyPath test" << std::endl;
    std::string input = "";
    std::cout << "Invoking createUnixSocketAddress with an empty path: \"" << input << "\"" << std::endl;
    struct sockaddr_un addr = createUnixSocketAddress(input);
    std::cout << "Returned sun_family: " << addr.sun_family << std::endl;
    std::cout << "Returned sun_path: \"" << addr.sun_path << "\"" << std::endl;
    EXPECT_EQ(addr.sun_family, AF_UNIX);
    EXPECT_STREQ(addr.sun_path, input.c_str());
    std::cout << "Exiting createUnixSocketAddress_EmptyPath test" << std::endl;
}
/**
 * @brief Test the createUnixSocketAddress function with the maximum allowed Unix socket address path.
 *
 * This test validates that when a string of 107 characters (representing the maximum path length) is provided to createUnixSocketAddress, 
 * the function properly initializes the sockaddr_un structure by setting the sun_family to AF_UNIX and copying the input string into sun_path.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 023
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a string of length 107 composed of 'A' characters. | input = "AAAAAAAAA... (107 times)" | String is created successfully with 107 characters. | Should be successful |
 * | 02 | Invoke createUnixSocketAddress with the max length path string. | input = string (107 'A's) | Returns a sockaddr_un structure with sun_family set to AF_UNIX and sun_path containing the input string. | Should Pass |
 * | 03 | Validate the returned sockaddr_un structure. | output: sun_family and sun_path from the returned structure | sun_family equals AF_UNIX and sun_path equals the input string. | Should Pass |
 */
TEST(al_service_utils_t, createUnixSocketAddress_MaxLengthPath) {
    std::cout << "Entering createUnixSocketAddress_MaxLengthPath test" << std::endl;
    std::string input(107, 'A');
    std::cout << "Invoking createUnixSocketAddress with max length path: " << input << std::endl;
    struct sockaddr_un addr = createUnixSocketAddress(input);
    std::cout << "Returned sun_family: " << addr.sun_family << std::endl;
    std::cout << "Returned sun_path: " << addr.sun_path << std::endl;
    EXPECT_EQ(addr.sun_family, AF_UNIX);
    EXPECT_EQ(std::string(addr.sun_path, strnlen(addr.sun_path, sizeof(addr.sun_path))), input);
    std::cout << "Exiting createUnixSocketAddress_MaxLengthPath test" << std::endl;
}
/**
 * @brief Verify that macAddressToString returns the correct string representation for an input MAC address with all bytes set to maximum value.
 *
 * This test verifies that the function macAddressToString converts an input MAC address containing all maximum byte values (0xff) into its correct string representation "ff:ff:ff:ff:ff:ff". It ensures that the conversion handles each byte properly in hexadecimal format and concatenates them with colons.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 024@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                       | Test Data                                                                                   | Expected Result                                                                     | Notes         |
 * | :--------------: | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- | ------------- |
 * | 01               | Set input MAC address with all bytes as 0xff and invoke macAddressToString                        | input = 0xff,0xff,0xff,0xff,0xff,0xff, output = "ff:ff:ff:ff:ff:ff"                          | Returned value equals "ff:ff:ff:ff:ff:ff" as verified by EXPECT_EQ assertion          | Should Pass   |
 */
TEST(al_service_utils_t, macAddressToString_allMaxBytes) {
    std::cout << "Entering macAddressToString_allMaxBytes test" << std::endl;
    std::array<uint8_t, 6> input = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    std::cout << "Invoking macAddressToString with input: ";
    for (auto byte : input) {
        std::cout << "0x" << std::hex << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << std::endl;
    std::string result = macAddressToString(input);
    std::cout << "Returned value: " << result << std::endl;
    EXPECT_EQ(result, "ff:ff:ff:ff:ff:ff");
    std::cout << "Exiting macAddressToString_allMaxBytes test" << std::endl;
}
/**
 * @brief Verify the correct conversion of a MAC address array to its string representation
 *
 * This test verifies that the macAddressToString function correctly converts an array of MAC address bytes into a colon-separated string following the expected format. The input array is populated with incremental byte values from 0x00 to 0x05 to ensure proper byte conversion and formatting.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 025
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                              | Test Data                                                                   | Expected Result                                                                      | Notes              |
 * | :--------------: | -------------------------------------------------------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ | ------------------ |
 * | 01               | Log the beginning of the test case execution             | No input data                                                               | Entry message "Entering macAddressToString_incrementalBytes test" is logged            | Should be successful |
 * | 02               | Create an input array with incremental byte values       | input = 0x00, 0x01, 0x02, 0x03, 0x04, 0x05                                   | Array is created with the values [0x00, 0x01, 0x02, 0x03, 0x04, 0x05]                | Should be successful |
 * | 03               | Log the input to be used for conversion                  | Printed byte values from the input array                                    | Each input byte is logged in hexadecimal format                                      | Should be successful |
 * | 04               | Invoke macAddressToString with the provided input array    | input array as above                                                        | Function returns "00:01:02:03:04:05"                                                 | Should Pass        |
 * | 05               | Verify the returned string matches the expected output     | result = output from function, expected = "00:01:02:03:04:05"                | EXPECT_EQ assertion confirms that the result is "00:01:02:03:04:05"                    | Should Pass        |
 * | 06               | Log the end of the test case execution                   | No input data                                                               | Exit message "Exiting macAddressToString_incrementalBytes test" is logged               | Should be successful |
 */
TEST(al_service_utils_t, macAddressToString_incrementalBytes) {
    std::cout << "Entering macAddressToString_incrementalBytes test" << std::endl;
    std::array<uint8_t, 6> input = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
    std::cout << "Invoking macAddressToString with input: ";
    for (auto byte : input) {
        std::cout << "0x" << std::hex << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << std::endl;
    std::string result = macAddressToString(input);
    std::cout << "Returned value: " << result << std::endl;
    EXPECT_EQ(result, "00:01:02:03:04:05");
    std::cout << "Exiting macAddressToString_incrementalBytes test" << std::endl;
}
/**
 * @brief Verify conversion of MAC address to formatted string for mixed input values
 *
 * This test checks that the macAddressToString function correctly converts an array of uint8_t representing a MAC address in mixed values to the expected colon-separated hexadecimal string format. The test validates functionality when the input includes a mix of low and typical numeric values.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 026@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                          | Test Data                                               | Expected Result                                                            | Notes      |
 * | :----:           | :------------------------------------------------------------------- | :------------------------------------------------------ | :------------------------------------------------------------------------- | :--------- |
 * | 01               | Invoke macAddressToString with a mixed values input array              | input = {0, 1, 10, 16, 127, 128}, output expected = "00:01:0a:10:7f:80" | Returned value is "00:01:0a:10:7f:80" verified using EXPECT_EQ              | Should Pass |
 */
TEST(al_service_utils_t, macAddressToString_mixedValues) {
    std::cout << "Entering macAddressToString_mixedValues test" << std::endl;
    std::array<uint8_t, 6> input = {0, 1, 10, 16, 127, 128};
    std::cout << "Invoking macAddressToString with input: ";
    for (auto byte : input) {
        std::cout << "0x" << std::hex << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << std::endl;
    std::string result = macAddressToString(input);
    std::cout << "Returned value: " << result << std::endl;
    EXPECT_EQ(result, "00:01:0a:10:7f:80");
    std::cout << "Exiting macAddressToString_mixedValues test" << std::endl;
}
/**
 * @brief Test macAddressToString API to verify conversion to lowercase format
 *
 * This test verifies that the macAddressToString function correctly converts a MAC address,
 * given as an array of uint8_t values, into a lowercase formatted string with colon delimiters.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 027
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                                  | Test Data                                                                                 | Expected Result                                              | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------- | ------------------------------------------------------------ | ----------- |
 * | 01               | Invoke macAddressToString with valid MAC address array and verify that the output string format is lowercase. | input = {0xab, 0xcd, 0xef, 0x12, 0x34, 0x56}, output = "ab:cd:ef:12:34:56"               | The API returns "ab:cd:ef:12:34:56" and EXPECT_EQ assertion passes. | Should Pass |
 */
TEST(al_service_utils_t, macAddressToString_lowercaseFormat) {
    std::cout << "Entering macAddressToString_lowercaseFormat test" << std::endl;
    std::array<uint8_t, 6> input = {0xab, 0xcd, 0xef, 0x12, 0x34, 0x56};
    std::cout << "Invoking macAddressToString with input: ";
    for (auto byte : input) {
        std::cout << "0x" << std::hex << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << std::endl;
    std::string result = macAddressToString(input);
    std::cout << "Returned value: " << result << std::endl;
    EXPECT_EQ(result, "ab:cd:ef:12:34:56");
    std::cout << "Exiting macAddressToString_lowercaseFormat test" << std::endl;
}
/**
 * @brief Verify that printByteStream correctly handles an empty byte stream input.
 *
 * This test verifies that when an empty vector is passed to printByteStream, the function correctly outputs a newline character as expected. It is important to ensure that the API gracefully handles empty inputs without errors.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 028@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                 | Test Data                                          | Expected Result                                                   | Notes          |
 * | :--------------: | --------------------------------------------------------------------------- | -------------------------------------------------- | ----------------------------------------------------------------- | -------------- |
 * | 01               | Initialize an empty byte stream vector and start capturing stdout           | byteStream = {}                                    | Stdout capture initiated (no output before API call)              | Should be successful |
 * | 02               | Invoke printByteStream with the empty byte stream and verify that the output is "\n" | input: byteStream = {}, output: expected = "\n"      | Function returns output "\n" and assertion verifies equality       | Should Pass    |
 */
TEST(al_service_utils_t, printByteStream_EmptyByteStream) {
#ifdef DEBUG_MODE	
    std::cout << "Entering printByteStream_EmptyByteStream test" << std::endl;
    std::vector<unsigned char> byteStream = {};
    std::cout << "Invoking printByteStream with input vector: {}" << std::endl;
    testing::internal::CaptureStdout();
    printByteStream(byteStream);
    std::string output = testing::internal::GetCapturedStdout();
    std::cout << "Captured output: \"" << output << "\"" << std::endl;
    EXPECT_EQ(output, "\n");
    std::cout << "Exiting printByteStream_EmptyByteStream test" << std::endl;
#else
    GTEST_SKIP() << "DEBUG_MODE not enabled and so test is skipped";
#endif
}
/**
 * @brief Tests printByteStream with a single-byte vector input.
 *
 * This test verifies that the printByteStream function correctly processes a vector containing a single byte (0xAB)
 * and outputs its hexadecimal value in lowercase followed by a space and newline. The test captures the standard output
 * and asserts that the printed value exactly matches the expected output. This ensures proper handling of minimal valid input.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 029@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                        | Test Data                           | Expected Result                                               | Notes      |
 * | :--------------: | -------------------------------------------------------------------------------------------------- | ----------------------------------- | ------------------------------------------------------------- | ---------- |
 * |       01         | Initialize a vector with a single byte (0xAB), invoke printByteStream, and capture the output.     | byteStream = { 0xAB }               | Captured output equals "ab \n" as verified by the EXPECT_EQ check. | Should Pass |
 */
TEST(al_service_utils_t, printByteStream_SingleByte) {
#ifdef DEBUG_MODE
    std::cout << "Entering printByteStream_SingleByte test" << std::endl;
    std::vector<unsigned char> byteStream = { 0xAB };
    std::stringstream inputLog;
    inputLog << std::hex;
    inputLog << "0x" << static_cast<int>(byteStream[0]);
    std::cout << "Invoking printByteStream with input vector: { " << inputLog.str() << " }" << std::endl;
    testing::internal::CaptureStdout();
    printByteStream(byteStream);
    std::string output = testing::internal::GetCapturedStdout();
    std::cout << "Captured output: \"" << output << "\"" << std::endl;
    EXPECT_EQ(output, "ab \n");
    std::cout << "Exiting printByteStream_SingleByte test" << std::endl;
#else
    GTEST_SKIP() << "DEBUG_MODE not enabled and so test is skipped";
#endif
}
/**
 * @brief Verify printByteStream function prints byte stream in expected hexadecimal format
 *
 * This test case verifies that the printByteStream function converts a vector of unsigned char bytes into a properly formatted hexadecimal string with lower case letters separated by spaces and ends with a newline. It ensures that the function behaves as expected in a positive scenario.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 030@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * |01| Initialize a vector with multiple bytes and set up the logging mechanism. | byteStream = 0x00,0xFF,0x1A,0x2B | Vector correctly initialized and logging prepared | Should be successful |
 * |02| Invoke printByteStream to print the byte stream and capture the output. | input: byteStream = 0x00,0xFF,0x1A,0x2B, output: expected string = "0 ff 1a 2b \n" | Captured output matches expected string "0 ff 1a 2b \n" | Should Pass |
 */
TEST(al_service_utils_t, printByteStream_MultipleByte) {
#ifdef DEBUG_MODE
    std::cout << "Entering printByteStream_MultipleByte test" << std::endl;
    std::vector<unsigned char> byteStream = { 0x00, 0xFF, 0x1A, 0x2B };
    std::stringstream inputLog;
    inputLog << std::hex;
    inputLog << "0x" << static_cast<int>(byteStream[0]) << ", "
             << "0x" << static_cast<int>(byteStream[1]) << ", "
             << "0x" << static_cast<int>(byteStream[2]) << ", "
             << "0x" << static_cast<int>(byteStream[3]);
    std::cout << "Invoking printByteStream with input vector: { " << inputLog.str() << " }" << std::endl;
    testing::internal::CaptureStdout();
    printByteStream(byteStream);
    std::string output = testing::internal::GetCapturedStdout();
    std::cout << "Captured output: \"" << output << "\"" << std::endl;
    EXPECT_EQ(output, "0 ff 1a 2b \n");
    std::cout << "Exiting printByteStream_MultipleByte test" << std::endl;
#else
    GTEST_SKIP() << "DEBUG_MODE not enabled and so test is skipped";
#endif

}
/**
 * @brief Tests printByteStream function with boundary input values
 *
 * This test aims to ensure that the printByteStream function correctly processes and prints a byte stream containing the boundary values of 0x00 and 0xFF. The function is expected to properly convert the bytes to a hexadecimal representation and output them in the specified format.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 031
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                 | Test Data                                                  | Expected Result                           | Notes           |
 * | :--------------: | --------------------------------------------------------------------------- | ---------------------------------------------------------- | ----------------------------------------- | --------------- |
 * | 01               | Initialize the test by constructing the boundary value vector and formatting log message | input: byteStream = {0x00, 0xFF}                             | Test vector is correctly prepared         | Should be successful |
 * | 02               | Capture the stdout, invoke printByteStream, and validate the printed output   | input: byteStream = {0x00, 0xFF}, output: expected = "0 ff \n" | API returns printed string matching "0 ff \n" | Should Pass     |
 */
TEST(al_service_utils_t, printByteStream_BoundaryValues) {
#ifdef DEBUG_MODE
    std::cout << "Entering printByteStream_BoundaryValues test" << std::endl;
    std::vector<unsigned char> byteStream = { 0x00, 0xFF };
    std::stringstream inputLog;
    inputLog << std::hex;
    inputLog << "0x" << static_cast<int>(byteStream[0]) << ", "
             << "0x" << static_cast<int>(byteStream[1]);
    std::cout << "Invoking printByteStream with input vector: { " << inputLog.str() << " }" << std::endl;
    testing::internal::CaptureStdout();
    printByteStream(byteStream);
    std::string output = testing::internal::GetCapturedStdout();
    std::cout << "Captured output: \"" << output << "\"" << std::endl;
    EXPECT_EQ(output, "0 ff \n");
    std::cout << "Exiting printByteStream_BoundaryValues test" << std::endl;
#else
    GTEST_SKIP() << "DEBUG_MODE not enabled and so test is skipped";
#endif
}
/**
 * @brief Verifies that printByteStream outputs the expected formatted byte stream in release mode.
 *
 * This test ensures that printByteStream, when provided with a byte vector containing specific hexadecimal values,
 * prints the byte stream in lowercase hexadecimal format with a trailing newline. The test captures the stdout output
 * and compares it against the expected string "1c 2d 3e \n" to confirm the function's correct behavior in release mode.@n
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
 * | Variation / Step | Description                                                                  | Test Data                                               | Expected Result                                   | Notes              |
 * | :--------------: | ---------------------------------------------------------------------------- | ------------------------------------------------------- | ------------------------------------------------- | ------------------ |
 * | 01               | Initialize the byte stream vector and setup the expected hex formatted log   | input: byteStream = {0x1C, 0x2D, 0x3E}                  | Byte stream is initialized correctly              | Should be successful |
 * | 02               | Invoke printByteStream and capture the stdout output                         | input: byteStream = {0x1C, 0x2D, 0x3E}, output: expected = "1c 2d 3e \n" | API outputs the formatted byte stream as "1c 2d 3e \n" | Should Pass        |
 * | 03               | Validate the captured output using EXPECT_EQ to confirm correctness            | captured output, expected output = "1c 2d 3e \n"         | The captured output matches the expected result   | Should be successful |
 */
TEST(al_service_utils_t, printByteStream_ReleaseMode) {
#ifdef DEBUG_MODE
    std::cout << "Entering printByteStream_ReleaseMode test" << std::endl;
    std::vector<unsigned char> byteStream = { 0x1C, 0x2D, 0x3E };
    std::stringstream inputLog;
    inputLog << std::hex;
    inputLog << "0x" << static_cast<int>(byteStream[0]) << ", "
             << "0x" << static_cast<int>(byteStream[1]) << ", "
             << "0x" << static_cast<int>(byteStream[2]);
    std::cout << "Invoking printByteStream with input vector: { " << inputLog.str() << " }" << std::endl;
    testing::internal::CaptureStdout();
    printByteStream(byteStream);
    std::string output = testing::internal::GetCapturedStdout();
    std::cout << "Captured output: \"" << output << "\"" << std::endl;
    EXPECT_EQ(output, "1c 2d 3e \n");
    std::cout << "Exiting printByteStream_ReleaseMode test" << std::endl;
#else
    GTEST_SKIP() << "DEBUG_MODE not enabled and so test is skipped";
#endif

}
/**
 * @brief Validate the correct output of printByteStream() function for a large byte stream input
 *
 * This test validates that printByteStream correctly processes a large vector of 1024 bytes (each with the value 0xAA) by printing a space-separated hexadecimal string that ends with a newline. The test captures the standard output and compares it against an expected string composed of "aa " repeated 1024 times followed by a newline. This ensures that the function output meets the expected formatting requirements.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 033
 * **Priority:** (High) High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Invoke printByteStream with a vector of 1024 bytes filled with 0xAA and capture its output | input: byteStream = vector of size 1024 with each element = 0xAA, output: expectedOutput = "aa " repeated 1024 times followed by a newline | The function output must exactly match expectedOutput and the assertion (EXPECT_EQ) should pass | Should Pass |
 */
TEST(al_service_utils_t, printByteStream_LargeByteStream) {
#ifdef DEBUG_MODE
    std::cout << "Entering printByteStream_LargeByteStream test" << std::endl;
    const int size = 1024;
    std::vector<unsigned char> byteStream(size, 0xAA);
    std::cout << "Invoking printByteStream with input vector of size: " << size << std::endl;
    testing::internal::CaptureStdout();
    printByteStream(byteStream);
    std::string output = testing::internal::GetCapturedStdout();
    std::stringstream expectedStream;
    for (int i = 0; i < size; i++) {
        expectedStream << "aa ";
    }
    expectedStream << "\n";
    std::string expectedOutput = expectedStream.str();
    std::cout << "Captured output length: " << output.size() << std::endl;
    std::cout << "Captured output starts with: \"" << output.substr(0, 20) << "...\"" << std::endl;
    EXPECT_EQ(output, expectedOutput);
    std::cout << "Exiting printByteStream_LargeByteStream test" << std::endl;
#else
    GTEST_SKIP() << "DEBUG_MODE not enabled and so test is skipped";
#endif
}
/**
 * @brief Verify that remove_length_delimited_part correctly processes an input vector with exactly 4 bytes.
 *
 * This test validates that when remove_length_delimited_part is called with a vector containing a 4-byte value representing the length-delimited part, it correctly removes that part, resulting in an empty vector. The test confirms proper functionality using EXPECT_TRUE on the resulting vector.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 034@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call remove_length_delimited_part with a 4-byte input vector representing a length-delimited part | input = {0x00, 0x00, 0x00, 0x05} | API returns an empty vector and EXPECT_TRUE(result.empty()) passes | Should Pass |
 */
TEST(al_service_utils_t, remove_length_delimited_part_valid_exactly_4bytes) {
    std::cout << "Entering remove_length_delimited_part_valid_exactly_4bytes test" << std::endl;
    std::vector<unsigned char> input = {0x00, 0x00, 0x00, 0x05};
    std::cout << "Invoking remove_length_delimited_part with input vector of size: " << input.size() << std::endl;
    auto result = remove_length_delimited_part(input);
    std::cout << "Returned vector size: " << result.size() << std::endl;
    EXPECT_TRUE(result.empty());
    std::cout << "Exiting remove_length_delimited_part_valid_exactly_4bytes test" << std::endl;
}
/**
 * @brief Tests the remove_length_delimited_part function with a valid payload.
 *
 * This test verifies that the remove_length_delimited_part function correctly extracts the data payload from a vector,
 * where the first four bytes represent the length of the payload. It ensures that the returned vector contains only the payload data.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 035
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                  | Test Data                                                                                      | Expected Result                                                      | Notes       |
 * | :--------------: | ------------------------------------------------------------ | ---------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- | ----------- |
 * | 01               | Initialize the input vector, invoke remove_length_delimited_part, and validate the output. | input = {0x00, 0x00, 0x00, 0x05, a, b, c, d, e}                                               | Returned vector equals {'a', 'b', 'c', 'd', 'e'} using EXPECT_EQ check | Should Pass |
 */
TEST(al_service_utils_t, remove_length_delimited_part_valid_with_payload) {
    std::cout << "Entering remove_length_delimited_part_valid_with_payload test" << std::endl;
    std::vector<unsigned char> input = {0x00, 0x00, 0x00, 0x05, 'a', 'b', 'c', 'd', 'e'};
    std::cout << "Invoking remove_length_delimited_part with input vector of size: " << input.size() << std::endl;
    auto result = remove_length_delimited_part(input);
    std::cout << "Returned vector size: " << result.size() << std::endl;
    std::vector<unsigned char> expected = {'a', 'b', 'c', 'd', 'e'};
    EXPECT_EQ(result, expected);
    std::cout << "Exiting remove_length_delimited_part_valid_with_payload test" << std::endl;
}
/**
 * @brief Verifies that remove_length_delimited_part correctly removes the initial length delimited part from an input vector when provided arbitrary bytes.
 *
 * This test assesses whether the remove_length_delimited_part API extracts the correct tail segment from an input vector containing arbitrary bytes. The function is expected to remove the first part of the vector and return the remaining bytes.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 036
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                                     | Test Data                                                                                                  | Expected Result                                                             | Notes      |
 * | :--------------: | ---------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ---------- |
 * | 01               | Initialize input vector with arbitrary bytes, invoke remove_length_delimited_part, and compare the result.       | input = {0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22, 0x33, 0x44}, expected = {0x11, 0x22, 0x33, 0x44}         | Returned vector matches expected vector (i.e., {0x11, 0x22, 0x33, 0x44})     | Should Pass |
 */
TEST(al_service_utils_t, remove_length_delimited_part_valid_arbitrary_bytes) {
    std::cout << "Entering remove_length_delimited_part_valid_arbitrary_bytes test" << std::endl;
    std::vector<unsigned char> input = {0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22, 0x33, 0x44};
    std::cout << "Invoking remove_length_delimited_part with input vector of size: " << input.size() << std::endl;
    auto result = remove_length_delimited_part(input);
    std::cout << "Returned vector size: " << result.size() << std::endl;
    std::vector<unsigned char> expected = {0x11, 0x22, 0x33, 0x44};
    EXPECT_EQ(result, expected);
    std::cout << "Exiting remove_length_delimited_part_valid_arbitrary_bytes test" << std::endl;
}
/**
 * @brief Test remove_length_delimited_part with an input vector of less than 4 bytes.
 *
 * This test verifies that remove_length_delimited_part handles input vectors with less than 4 bytes appropriately by either returning a result or throwing an exception, which is the expected behavior when provided with insufficient data.
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
 * | 01 | Invoke remove_length_delimited_part with an input vector containing less than 4 bytes to validate error handling | input = {0x00, 0x00, 0x00} | Function executes without crashing; either returns a vector or throws an exception as expected | Should Pass |
 */
TEST(al_service_utils_t, remove_length_delimited_part_negative_less_than_4_bytes) {
    std::cout << "Entering remove_length_delimited_part_negative_less_than_4_bytes test" << std::endl;
    std::vector<unsigned char> input = {0x00, 0x00, 0x00};
    std::cout << "Invoking remove_length_delimited_part with input vector of size: " << input.size() << std::endl;
    try {
        auto result = remove_length_delimited_part(input);
        std::cout << "Returned vector size: " << result.size() << std::endl;
        SUCCEED() << "Function executed without crashing on input size less than 4 bytes.";
    } catch (...) {
        std::cout << "Exception caught during remove_length_delimited_part invocation" << std::endl;
        SUCCEED() << "Exception thrown as expected for input size less than 4 bytes.";
    }
    std::cout << "Exiting remove_length_delimited_part_negative_less_than_4_bytes test" << std::endl;
}
/**
 * @brief Validate the behavior of remove_length_delimited_part when provided with an empty input vector
 *
 * This test checks how the remove_length_delimited_part function handles an empty vector as input.
 * It ensures that the function either returns an empty vector or throws an expected exception,
 * thereby not causing a crash or any undefined behavior during execution.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 038@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                           | Test Data                      | Expected Result                                                                                  | Notes       |
 * | :--------------: | --------------------------------------------------------------------- | ------------------------------ | ------------------------------------------------------------------------------------------------ | ----------- |
 * | 01               | Invoke remove_length_delimited_part with an empty input vector          | input vector = {}              | Either returns an empty vector (with size 0) or throws an exception as expected for invalid input | Should Fail |
 */
TEST(al_service_utils_t, remove_length_delimited_part_negative_empty_vector) {
    std::cout << "Entering remove_length_delimited_part_negative_empty_vector test" << std::endl;
    std::vector<unsigned char> input = {};
    std::cout << "Invoking remove_length_delimited_part with empty input vector" << std::endl;
    try {
        auto result = remove_length_delimited_part(input);
        std::cout << "Returned vector size: " << result.size() << std::endl;
        SUCCEED() << "Function executed without crashing on empty input vector.";
    } catch (...) {
        std::cout << "Exception caught during remove_length_delimited_part invocation" << std::endl;
        SUCCEED() << "Exception thrown as expected for empty input vector.";
    }
    std::cout << "Exiting remove_length_delimited_part_negative_empty_vector test" << std::endl;
}
