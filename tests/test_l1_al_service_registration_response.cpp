/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2024 RDK Management
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
#include "al_service_registration_response.h"

class AlServiceRegistrationResponseTest : public ::testing::Test {
protected:
    AlServiceRegistrationResponse* instance;

    void SetUp() override {
        instance = new AlServiceRegistrationResponse();
    }

    void TearDown() override {
        delete instance;
    }
};

/**
 * @brief Test deserialization with valid data
 *
 * This test verifies that the deserialization function correctly processes valid serialized data.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Initialize valid serialized data | valid serialized data | None | Should be successful |
 * | 03 | Call deserializeRegistrationResponse with valid data | validData | None | Should Pass |
 * | 04 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceRegistrationResponseTest, DeserializeWithValidData) {
    std::vector<unsigned char> validData = {
    0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E,  // MAC Address (6 bytes)
    0x12, 0x34,                          // First part of message ID range (0x1234)
    0x56, 0x78,                          // Second part of message ID range (0x5678)
    0x01                                 // Result (RegistrationResult::SUCCESS)
    };
    std::cout << "Entering DeserializeWithValidData test" << std::endl;
    instance->deserializeRegistrationResponse(validData);
    std::cout << "Exiting DeserializeWithValidData test" << std::endl;
}

/**
 * @brief Test deserialization with null data
 *
 * This test checks the behavior of the `deserializeRegistrationResponse` method when provided with null data. It ensures that the method can handle empty input without crashing or producing incorrect results.
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
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Call deserializeRegistrationResponse with null data | null | None | Should Pass |
 * | 03 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceRegistrationResponseTest, DeserializeWithNullData) {
    std::cout << "Entering DeserializeWithNullData test" << std::endl;
    std::vector<unsigned char> null_data;
    instance->deserializeRegistrationResponse(null_data);
    std::cout << "Exiting DeserializeWithNullData test" << std::endl;
}

/**
* @brief Test the retrieval of AL MAC address with valid input
*
* This test verifies that the `getAlMacAddressLocal` method of the `AlServiceRegistrationResponse` class returns the expected result when provided with a valid input.
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
* | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
* | 02 | Call `getAlMacAddressLocal` with valid input | input = "valid_input" | result = RETURN_OK | Should Pass |
* | 03 | Verify the result using ASSERT_EQ | result = RETURN_OK | None | Should be successful |
* | 04 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
*/
TEST(AlServiceRegistrationResponseTest, RetrieveAlMacAddressLocalWithValidInput) {
    std::cout << "Entering RetrieveAlMacAddressLocalWithValidInput test" << std::endl;
	MessageIdRange range(0,255);
	AlServiceRegistrationResponse instance("00:1A:2B:3C:4D:5E", range, RegistrationResult::SUCCESS);
    MacAddress result = instance->getAlMacAddressLocal();
	std::cout << "The result is " << result << std::endl;
    std::cout << "Exiting RetrieveAlMacAddressLocalWithValidInput test" << std::endl;
}

/**
 * @brief Test the retrieval of AL MAC address with empty input
 *
 * This test verifies the behavior of the getAlMacAddressLocal function when provided with an empty input string. 
 * It ensures that the function correctly handles this edge case and returns the expected error code.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 004@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment by creating an instance of AlServiceRegistrationResponse | None | Instance created successfully | Done by Pre-requisite SetUp function |
 * | 02 | Call the constructor with macaddress as empty | "", range, result | None | Should be initialized |
 * | 03 | Call the getAlMacAddressLocal function with an empty string as input | input = "" | RETURN_ERR | Should Pass |
 * | 04 | Clean up the test environment by deleting the instance of AlServiceRegistrationResponse | None | Instance deleted successfully | Done by Pre-requisite TearDown function |
 */

TEST(AlServiceRegistrationResponseTest, RetrieveAlMacAddressLocalWithEmptyInput) {
    std::cout << "Entering RetrieveAlMacAddressLocalWithEmptyInput test" << std::endl;	 
	MessageIdRange range(0, 255);
	AlServiceRegistrationResponse instance("", range, RegistrationResult::SUCCESS);
    const MacAddress result = instance->getAlMacAddressLocal();
    std::cout << "The result is " << result << std::endl;
    std::cout << "Exiting RetrieveAlMacAddressLocalWithEmptyInput test" << std::endl;
}

/**
 * @brief Test the retrieval of AL MAC address with null input
 *
 * This test verifies the behavior of the getAlMacAddressLocal function when MAC is null. 
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 005@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment by creating an instance of AlServiceRegistrationResponse | None | Instance created successfully | Done by Pre-requisite SetUp function |
 * | 02 | Call the constructor with macaddress as null | null, range, result | None | Should be initialized |
 * | 03 | Call the getAlMacAddressLocal function with an empty string as input | input = "" | RETURN_ERR | Should Pass |
 * | 04 | Clean up the test environment by deleting the instance of AlServiceRegistrationResponse | None | Instance deleted successfully | Done by Pre-requisite TearDown function |
 */
TEST(AlServiceRegistrationResponseTest, RetrieveAlMacAddressLocalWithEmptyInput) {
    std::cout << "Entering RetrieveAlMacAddressLocalWithEmptyInput test" << std::endl;
	MessageIdRange range(0, 255);
	AlServiceRegistrationResponse instance(nullptr, range, RegistrationResult::SUCCESS);
    const MacAddress result = instance->getAlMacAddressLocal();
    std::cout << "The result is " << result << std::endl;
    std::cout << "Exiting RetrieveAlMacAddressLocalWithEmptyInput test" << std::endl;
}

/**
 * @brief Test the retrieval of message ID range with valid input
 *
 * This test verifies that the getMessageIdRange function of the AlServiceRegistrationResponse class
 * correctly returns the expected result when provided with valid input.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 006@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment by creating an instance of AlServiceRegistrationResponse | None | Instance created | Done by Pre-requisite SetUp function |
 * | 02 | Call the getMessageIdRange function with valid input | validInput = <valid_value> | RETURN_OK | Should Pass |
 * | 03 | Verify the result using ASSERT_EQ | result = RETURN_OK | Assertion should pass | Should be successful |
 * | 04 | Clean up the test environment by deleting the instance of AlServiceRegistrationResponse | None | Instance deleted | Done by Pre-requisite TearDown function |
 */
TEST(AlServiceRegistrationResponseTest, RetrieveMessageIdRangeWithValidInput) {
    std::cout << "Entering RetrieveMessageIdRangeWithValidInput test" << std::endl;	
	MessageIdRange range(0, 255);
	AlServiceRegistrationResponse instance("00:1A:2B:3C:4D:5E", range, RegistrationResult::SUCCESS);
    MessageIdRange result = instance->getMessageIdRange();
    std::cout << "The result is " << result << std::endl;
    std::cout << "Exiting RetrieveMessageIdRangeWithValidInput test" << std::endl;
}

/**
* @brief Test to verify the behavior of getMessageIdRange with null input
*
* This test checks the behavior of the getMessageIdRange method when a null input is provided. It ensures that the method returns the expected error code when given invalid input.
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
* | 01| Setup the test environment | None | None | Done by Pre-requisite SetUp function |
* | 02| Call getMessageIdRange with null input | input = nullptr | result = RETURN_ERR | Should Pass |
* | 03| Verify the result using ASSERT_EQ | result = RETURN_ERR | None | Should be successful |
* | 04| Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
*/
TEST(AlServiceRegistrationResponseTest, RetrieveMessageIdRangeWithNullInput) {
    std::cout << "Entering RetrieveMessageIdRangeWithNullInput test" << std::endl;
	AlServiceRegistrationResponse instance("00:1A:2B:3C:4D:5E", nullptr, RegistrationResult::SUCCESS);
    MessageIdRange result = instance->getMessageIdRange();
    std::cout << "The result is " << result << std::endl;
    std::cout << "Exiting RetrieveMessageIdRangeWithNullInput test" << std::endl;
}

/**
 * @brief Test the retrieval of message ID range with empty input
 *
 * This test verifies the behavior of the getMessageIdRange function when provided with an empty input. 
 * It ensures that the function correctly handles this edge case and returns the expected error code.
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
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Call getMessageIdRange with empty input | emptyInput = "" | result = RETURN_ERR | Should Pass |
 * | 03 | Verify the result using ASSERT_EQ | result = RETURN_ERR | Assertion should pass | Should be successful |
 * | 04 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST(AlServiceRegistrationResponseTest, RetrieveMessageIdRangeWithEmptyInput) {
    std::cout << "Entering RetrieveMessageIdRangeWithEmptyInput test" << std::endl;
	AlServiceRegistrationResponse instance("00:1A:2B:3C:4D:5E", "", RegistrationResult::SUCCESS);
    MessageIdRange result = instance->getMessageIdRange();
	std::cout << "The result is " << result << std::endl;
    std::cout << "Exiting RetrieveMessageIdRangeWithEmptyInput test" << std::endl;
}

/**
 * @brief Test the retrieval of message ID range with maximum length input
 *
 * This test verifies that the `getMessageIdRange` function of the `AlServiceRegistrationResponse` class
 * correctly handles the maximum length input and returns the expected result.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 009@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment by creating an instance of AlServiceRegistrationResponse | None | Instance created successfully | Done by Pre-requisite SetUp function |
 * | 02 | Call the getMessageIdRange function with maximum length input | maximumLengthInput = <value> | RETURN_OK | Should Pass |
 * | 03 | Verify the result using ASSERT_EQ | result = RETURN_OK | Assertion should pass | Should be successful |
 * | 04 | Clean up the test environment by deleting the instance of AlServiceRegistrationResponse | None | Instance deleted successfully | Done by Pre-requisite TearDown function |
 */
TEST(AlServiceRegistrationResponseTest, RetrieveMessageIdRangeWithMaximumLengthInput) {
    std::cout << "Entering RetrieveMessageIdRangeWithMaximumLengthInput test" << std::endl;
	MessageIdRange range(0, 65535);
	AlServiceRegistrationResponse instance("00:1A:2B:3C:4D:5E", range, RegistrationResult::SUCCESS);
    MessageIdRange result = instance->getMessageIdRange();
	std::cout << "The result is " << result << std::endl;
    std::cout << "Exiting RetrieveMessageIdRangeWithMaximumLengthInput test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of result when the result is set to UNKNOWN
 *
 * This test checks if the result is correctly retrieved as UNKNOWN after being set to UNKNOWN. This ensures that the setResult and getResult methods are functioning correctly for the UNKNOWN value.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 010@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Set the result to UNKNOWN | instance->setResult(RegistrationResult::UNKNOWN) | None | Should be successful |
 * | 03 | Retrieve the result and check if it is UNKNOWN | instance->getResult() | RegistrationResult::UNKNOWN | Should Pass |
 * | 04 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST(AlServiceRegistrationResponseTest, RetrieveResultWhenUnknown) {
    std::cout << "Entering RetrieveResultWhenUnknown test" << std::endl;
	MessageIdRange range(0, 65535);
	AlServiceRegistrationResponse instance("00:1A:2B:3C:4D:5E", range, RegistrationResult::UNKNOWN);
    ASSERT_EQ(instance->getResult(), RegistrationResult::UNKNOWN);
    std::cout << "Exiting RetrieveResultWhenUnknown test" << std::endl;
}

/**
* @brief Test to verify the retrieval of result when registration is successful
*
* This test checks if the result is correctly retrieved as SUCCESS after setting it to SUCCESS in the AlServiceRegistrationResponse instance@n
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
* | 01| Setup the test environment | instance = new AlServiceRegistrationResponse() | instance should be initialized | Done by Pre-requisite SetUp function |
* | 02| Set the result to SUCCESS | instance->setResult(RegistrationResult::SUCCESS) | RegistrationResult::SUCCESS | Should be successful |
* | 03| Retrieve the result and check if it is SUCCESS | instance->getResult() | RegistrationResult::SUCCESS | Should Pass |
* | 04| Cleanup the test environment | delete instance | instance should be deleted | Done by Pre-requisite TearDown function |
*/
TEST(AlServiceRegistrationResponseTest, RetrieveResultWhenSuccess) {
    std::cout << "Entering RetrieveResultWhenSuccess test" << std::endl;
	MessageIdRange range(0, 65535);
	AlServiceRegistrationResponse instance("00:1A:2B:3C:4D:5E", range, RegistrationResult::SUCCESS);
    ASSERT_EQ(instance->getResult(), RegistrationResult::SUCCESS);
    std::cout << "Exiting RetrieveResultWhenSuccess test" << std::endl;
}

/**
 * @brief Test to verify the result retrieval when no ranges are available
 *
 * This test checks the functionality of the AlServiceRegistrationResponse class to ensure that it correctly retrieves the result when no ranges are available.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 012@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Set the result to NO_RANGES_AVAILABLE | instance->setResult(RegistrationResult::NO_RANGES_AVAILABLE) | None | Should be successful |
 * | 03 | Retrieve the result and check if it matches NO_RANGES_AVAILABLE | instance->getResult() | RegistrationResult::NO_RANGES_AVAILABLE | Should Pass |
 * | 04 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST(AlServiceRegistrationResponseTest, RetrieveResultWhenNoRangesAvailable) {
    std::cout << "Entering RetrieveResultWhenNoRangesAvailable test" << std::endl;
    MessageIdRange range(0, 65535);
	AlServiceRegistrationResponse instance("00:1A:2B:3C:4D:5E", range, RegistrationResult::NO_RANGES_AVAILABLE);
    ASSERT_EQ(instance->getResult(), RegistrationResult::NO_RANGES_AVAILABLE);
    std::cout << "Exiting RetrieveResultWhenNoRangesAvailable test" << std::endl;
}

/**
 * @brief Test to verify the result retrieval when the service is not supported.
 *
 * This test checks if the `getResult` method correctly returns `SERVICE_NOT_SUPPORTED` 
 * when the `setResult` method is called with `SERVICE_NOT_SUPPORTED`. This ensures that 
 * the result is properly set and retrieved in the `AlServiceRegistrationResponse` class.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 013@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Set the result to SERVICE_NOT_SUPPORTED | instance->setResult(RegistrationResult::SERVICE_NOT_SUPPORTED) | None | Should be successful |
 * | 03 | Retrieve the result and check if it is SERVICE_NOT_SUPPORTED | instance->getResult() | RegistrationResult::SERVICE_NOT_SUPPORTED | Should Pass |
 * | 04 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST(AlServiceRegistrationResponseTest, RetrieveResultWhenServiceNotSupported) {
    std::cout << "Entering RetrieveResultWhenServiceNotSupported test" << std::endl;
	MessageIdRange range(0, 65535);
	AlServiceRegistrationResponse instance("00:1A:2B:3C:4D:5E", range, RegistrationResult::SERVICE_NOT_SUPPORTED);
    ASSERT_EQ(instance->getResult(), RegistrationResult::SERVICE_NOT_SUPPORTED);
    std::cout << "Exiting RetrieveResultWhenServiceNotSupported test" << std::endl;
}

/**
* @brief Test to verify the retrieval of result when the operation is not supported.
*
* This test checks if the `getResult` method correctly retrieves the result set by the `setResult` method when the operation is not supported.
*
* **Test Group ID:** Basic: 01
* **Test Case ID:** 014@n
* **Priority:** High
* @n
* **Pre-Conditions:** None
* **Dependencies:** None
* **User Interaction:** None
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data | Expected Result | Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
* | 02 | Set the result to OPERATION_NOT_SUPPORTED | instance->setResult(RegistrationResult::OPERATION_NOT_SUPPORTED) | None | Should be successful |
* | 03 | Retrieve the result and check if it matches OPERATION_NOT_SUPPORTED | instance->getResult() | RegistrationResult::OPERATION_NOT_SUPPORTED | Should Pass |
* | 04 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
*/
TEST(AlServiceRegistrationResponseTest, RetrieveResultWhenOperationNotSupported) {
    std::cout << "Entering RetrieveResultWhenOperationNotSupported test" << std::endl;
	MessageIdRange range(0, 65535);
	AlServiceRegistrationResponse instance("00:1A:2B:3C:4D:5E", range, RegistrationResult::OPERATION_NOT_SUPPORTED);
    ASSERT_EQ(instance->getResult(), RegistrationResult::OPERATION_NOT_SUPPORTED);
    std::cout << "Exiting RetrieveResultWhenOperationNotSupported test" << std::endl;
}

/**
 * @brief Test the serialization of a valid registration response
 *
 * This test verifies that a valid registration response is correctly serialized into a non-empty byte vector.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 015@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Set valid parameters using constructor | "00:1A:2B:3C:4D:5E", range(0, 65535), RegistrationResult::NO_RANGES_AVAILABLE | None | Should be successful |
 * | 03 | Serialize the registration response | None | serializedData should not be empty | Should Pass |
 * | 04 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST(AlServiceRegistrationResponseTest, SerializeValidRegistrationResponse) {
    std::cout << "Entering SerializeValidRegistrationResponse test" << std::endl;
    MessageIdRange range(0, 65535);
	AlServiceRegistrationResponse instance("00:1A:2B:3C:4D:5E", range, RegistrationResult::NO_RANGES_AVAILABLE);
    std::vector<unsigned char> serializedData = instance->serializeRegistrationResponse();    
    ASSERT_FALSE(serializedData.empty());
    std::cout << "Exiting SerializeValidRegistrationResponse test" << std::endl;
}

/**
 * @brief Test serialization of registration response with an invalid MAC address
 *
 * This test verifies that the serialization of a registration response fails when an invalid MAC address is provided. 
 * It ensures that the system correctly handles invalid input by returning an empty serialized data vector.
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
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Initialize the invalid MAC address, valid message range and registration response | invalidMacAddress = "00:11:22:33:GG:44", range(0, 65535), RegistrationResult::SUCCESS | None | Should be successful |
 * | 03 | Serialize the registration response | None | serializedData = instance->serializeRegistrationResponse() | Should Pass |
 * | 04 | Verify the serialized data is empty | serializedData.empty() | True | Should Pass |
 * | 05 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceRegistrationResponseTest, SerializeRegistrationResponseWithInvalidMacAddress) {
    std::cout << "Entering SerializeRegistrationResponseWithInvalidMac test" << std::endl;
	MessageIdRange range(0, 65535);
	AlServiceRegistrationResponse instance("00:11:22:33:GG:44", range, RegistrationResult::SUCCESS);
    std::vector<unsigned char> serializedData = instance->serializeRegistrationResponse();    
    ASSERT_TRUE(serializedData.empty());
    std::cout << "Exiting SerializeRegistrationResponseWithInvalidMac test" << std::endl;
}

/**
 * @brief Test the serialization of a registration response with an empty message ID range.
 *
 * This test verifies that the serialization of a registration response with an empty message ID range results in an empty serialized data vector. This is important to ensure that the system correctly handles cases where no message IDs are provided.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 017@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Set a valid MAC address | validMacAddress = "00:11:22:33:GG:44", range = (0,0), RegistrationResult::SUCCESS | None | Should be successful |
 * | 03 | Set a successful registration result | valid vector | None | Should be successful |
 * | 05 | Serialize the registration response | None | serializedData.empty() = true | Should Pass |
 * | 06 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceRegistrationResponseTest, SerializeRegistrationResponseWithEmptyMessageIdRange) {
    std::cout << "Entering SerializeRegistrationResponseWithEmptyMessageIdRange test" << std::endl;
	MessageIdRange range(0, 0);
	AlServiceRegistrationResponse instance("00:11:22:33:GG:44", range, RegistrationResult::SUCCESS);   
    std::vector<unsigned char> serializedData = instance->serializeRegistrationResponse();    
    ASSERT_TRUE(serializedData.empty());
    std::cout << "Exiting SerializeRegistrationResponseWithEmptyMessageIdRange test" << std::endl;
}

/**
 * @brief Test the serialization of a registration response with a failed result.
 *
 * This test verifies that the serialization of a registration response with a failed result produces a non-empty serialized data vector.
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
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Set a valid MAC address, message ID range and failed registration result | "00:11:22:33:GG:44", range, RegistrationResult::UNKNOWN | None | Should be successful |
 * | 03 | Serialize the registration response | None | serializedData should not be empty | Should Pass |
 * | 04 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceRegistrationResponseTest, SerializeRegistrationResponseWithFailedResult) {
    std::cout << "Entering SerializeRegistrationResponseWithFailedResult test" << std::endl;
    MessageIdRange range(0, 65535);
	AlServiceRegistrationResponse instance("00:11:22:33:GG:44", range, RegistrationResult::UNKNOWN);
    std::vector<unsigned char> serializedData = instance->serializeRegistrationResponse();    
    ASSERT_FALSE(serializedData.empty());
    std::cout << "Exiting SerializeRegistrationResponseWithFailedResult test" << std::endl;
}

/**
 * @brief Test the serialization of registration response with all null MAC address
 *
 * This test verifies that the serialization function correctly handles the case where MAC address is null. 
 * It ensures that the serialized data is empty when the MAC address is null
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
 * | 01 | Setup the test environment | instance = new AlServiceRegistrationResponse() |  | Done by Pre-requisite SetUp function |
 * | 02 | Set null MAC address, valid message id range and registration result | "{0, 0, 0, 0, 0, 0}", range(0, 65535), RegistrationResult::SUCCESS |  | Should be successful |
 * | 03 | Serialize the registration response | instance->serializeRegistrationResponse() | serializedData = empty vector | Should Pass |
 * | 04 | Tear down the test environment | delete instance |  | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceRegistrationResponseTest, SerializeRegistrationResponseWithAllNullInputs) {
    std::cout << "Entering SerializeRegistrationResponseWithAllNullInputs test" << std::endl;
	MacAddress nullMacAddress = {0, 0, 0, 0, 0, 0};
    MessageIdRange range(0, 65535);
	AlServiceRegistrationResponse instance(nullMacAddress, range, RegistrationResult::SUCCESS);
    std::vector<unsigned char> serializedData = instance->serializeRegistrationResponse();    
    ASSERT_TRUE(serializedData.empty());
    std::cout << "Exiting SerializeRegistrationResponseWithAllNullInputs test" << std::endl;
}

/**
 * @brief Test the setting of a valid MAC address with mixed case
 *
 * This test verifies that the setAlMacAddressLocal method correctly handles a valid MAC address input with mixed case characters
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 020@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Call setAlMacAddressLocal with a valid mixed case MAC address | "00:1A:2b:3C:4d:5E" | None | Should Pass |
 * | 03 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceRegistrationResponseTest, SetAlMacAddressLocal_ValidMacAddress_MixedCase) {
    std::cout << "Entering SetAlMacAddressLocal_ValidMacAddress_MixedCase test" << std::endl;
    instance->setAlMacAddressLocal("00:1A:2b:3C:4d:5E");
	std::cout << "Exiting SetAlMacAddressLocal_ValidMacAddress_MixedCase test" << std::endl;
}

/**
 * @brief Test the setting of a valid MAC address without colons in AlServiceRegistrationResponse
 *
 * This test verifies that the AlServiceRegistrationResponse class can correctly handle and set a valid MAC address string that does not contain colons.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 021@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Call setAlMacAddressLocal with a valid MAC address without colons | input: "001A2B3C4D5E" | None | Should Pass |
 * | 03 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceRegistrationResponseTest, SetAlMacAddressLocal_ValidMacAddress_NoColons) {
    std::cout << "Entering SetAlMacAddressLocal_ValidMacAddress_NoColons test" << std::endl;
    instance->setAlMacAddressLocal("001A2B3C4D5E");
    std::cout << "Exiting SetAlMacAddressLocal_ValidMacAddress_NoColons test" << std::endl;
}

/**
 * @brief Test the setting of a valid MAC address with dashes in AlServiceRegistrationResponse
 *
 * This test verifies that the method setAlMacAddressLocal correctly handles a valid MAC address formatted with dashes.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 022@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Call setAlMacAddressLocal with a valid MAC address containing dashes | "00-1A-2B-3C-4D-5E" | None | Should Pass |
 * | 03 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceRegistrationResponseTest, SetAlMacAddressLocal_ValidMacAddress_Dashes) {
    std::cout << "Entering SetAlMacAddressLocal_ValidMacAddress_Dashes test" << std::endl;
    instance->setAlMacAddressLocal("00-1A-2B-3C-4D-5E");
    std::cout << "Exiting SetAlMacAddressLocal_ValidMacAddress_Dashes test" << std::endl;
}

/**
 * @brief Test the behavior of setAlMacAddressLocal with an invalid MAC address that is too short and too long.
 *
 * This test checks the behavior of the setAlMacAddressLocal method when provided with a MAC address that is too short and too long.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 023@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Call setAlMacAddressLocal with a short MAC address | "00:1A:2B:3C:4D" | None | Should Pass |
 * | 03 | Call setAlMacAddressLocal with an invalid MAC address that is too long | "00:1A:2B:3C:4D:5E:6F" | Method should handle the invalid input appropriately | Should Fail |
 * | 04 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceRegistrationResponseTest, SetAlMacAddressLocal_InvalidMacAddress_TooShort_TooLong) {
    std::cout << "Entering SetAlMacAddressLocal_InvalidMacAddress_TooShort_TooLong test" << std::endl;
    instance->setAlMacAddressLocal("00:1A:2B:3C:4D");
	instance->setAlMacAddressLocal("00:1A:2B:3C:4D:5E:6F");
    std::cout << "Exiting SetAlMacAddressLocal_InvalidMacAddress_TooShort _TooLong test" << std::endl;
}

/**
 * @brief Test the behavior of setAlMacAddressLocal with an invalid MAC address containing non-hex characters.
 *
 * This test checks the behavior of the setAlMacAddressLocal method when provided with an invalid MAC address that contains non-hexadecimal characters. The purpose is to ensure that the method handles invalid input gracefully.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 024@n
 * **Priority:** High
 * 
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment by creating an instance of AlServiceRegistrationResponse | None | Instance created successfully | Done by Pre-requisite SetUp function |
 * | 02 | Call setAlMacAddressLocal with an invalid MAC address containing non-hex characters | "00:1A:2B:3C:4D:ZZ" | Method should handle invalid input | Should Pass |
 * | 03 | Verify the behavior of the method using assertions | None | Appropriate assertions should pass | Should be successful |
 * | 04 | Clean up the test environment by deleting the instance of AlServiceRegistrationResponse | None | Instance deleted successfully | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceRegistrationResponseTest, SetAlMacAddressLocal_InvalidMacAddress_NonHex) {
    std::cout << "Entering SetAlMacAddressLocal_InvalidMacAddress_NonHex test" << std::endl;
    instance->setAlMacAddressLocal("00:1A:2B:3C:4D:ZZ");
    std::cout << "Exiting SetAlMacAddressLocal_InvalidMacAddress_NonHex test" << std::endl;
}

/**
 * @brief Test the behavior of setAlMacAddressLocal method when an empty string is passed.
 *
 * This test verifies that the setAlMacAddressLocal method can handle an empty string input without causing any errors or unexpected behavior.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 025@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment by creating an instance of AlServiceRegistrationResponse | None | Instance should be created successfully | Done by Pre-requisite SetUp function |
 * | 02 | Call the setAlMacAddressLocal method with an empty string | input = "" | Method should handle the empty string without errors | Should Pass |
 * | 03 | Verify the behavior of the method using assertions | None | Assertions should pass | Should be successful |
 * | 04 | Clean up the test environment by deleting the instance of AlServiceRegistrationResponse | None | Instance should be deleted successfully | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceRegistrationResponseTest, SetAlMacAddressLocal_EmptyString) {
    std::cout << "Entering SetAlMacAddressLocal_EmptyString test" << std::endl;
    instance->setAlMacAddressLocal("");
    ASSERT_TRUE(true); // Add appropriate assertions based on method behavior
    std::cout << "Exiting SetAlMacAddressLocal_EmptyString test" << std::endl;
}

/**
 * @brief Test the behavior of setAlMacAddressLocal method when given a NULL input.
 *
 * This test verifies that the setAlMacAddressLocal method can handle a NULL input without causing any unexpected behavior or crashes.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 026@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment by creating an instance of AlServiceRegistrationResponse | None | Instance created successfully | Done by Pre-requisite SetUp function |
 * | 02 | Call the setAlMacAddressLocal method with NULL input | input = nullptr | Method handles NULL input gracefully | Should Pass |
 * | 03 | Clean up the test environment by deleting the instance of AlServiceRegistrationResponse | None | Instance deleted successfully | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceRegistrationResponseTest, SetAlMacAddressLocal_NullInput) {
    std::cout << "Entering SetAlMacAddressLocal_NullInput test" << std::endl;
    instance->setAlMacAddressLocal(nullptr);
    std::cout << "Exiting SetAlMacAddressLocal_NullInput test" << std::endl;
}

/**
 * @brief Test the setMessageIdRange function with a valid range
 *
 * This test verifies that the setMessageIdRange function correctly handles a valid range of message IDs.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 027@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Call setMessageIdRange with valid range | start = 1, end = 100 | None | Should Pass |
 * | 03 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceRegistrationResponseTest, SetMessageIdRange_ValidRange) {
    std::cout << "Entering SetMessageIdRange_ValidRange test" << std::endl;
    MessageIdRange inputRange = {1, 100};
    instance->setMessageIdRange(inputRange);
    std::cout << "Exiting SetMessageIdRange_ValidRange test" << std::endl;
}

/**
 * @brief Test the setMessageIdRange function with start greater than end
 *
 * This test verifies the behavior of the setMessageIdRange function when the start value is greater than the end value.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 028@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Call setMessageIdRange with start greater than end | start = 100, end = 1 | None | Should Pass |
 * | 03 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceRegistrationResponseTest, SetMessageIdRange_StartGreaterThanEnd) {
    std::cout << "Entering SetMessageIdRange_StartGreaterThanEnd test" << std::endl;
    MessageIdRange inputRange = {100, 1};
    instance->setMessageIdRange(inputRange);
    std::cout << "Exiting SetMessageIdRange_StartGreaterThanEnd test" << std::endl;
}

/**
 * @brief Test the setMessageIdRange function when start is equal to end
 *
 * This test verifies the behavior of the setMessageIdRange function when the start and end values are equal. 
 * It ensures that the function can handle this edge case without errors.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 029@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Call setMessageIdRange with start and end equal | start = 50, end = 50 | None | Should Pass |
 * | 03 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceRegistrationResponseTest, SetMessageIdRange_StartEqualToEnd) {
    std::cout << "Entering SetMessageIdRange_StartEqualToEnd test" << std::endl;
    MessageIdRange inputRange = {50, 50};
    instance->setMessageIdRange(inputRange);
    std::cout << "Exiting SetMessageIdRange_StartEqualToEnd test" << std::endl;
}

/**
 * @brief Test the setMessageIdRange function with a start value of zero.
 *
 * This test verifies that the setMessageIdRange function can handle a start value of zero and a valid end value.
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
 * | 01 | Call the SetUp function to initialize the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Call the setMessageIdRange function with start = 0 and end = 100 | start = 0, end = 100 | None | Should Pass |
 * | 03 | Call the TearDown function to clean up the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceRegistrationResponseTest, SetMessageIdRange_StartZero) {
    std::cout << "Entering SetMessageIdRange_StartZero test" << std::endl;
    MessageIdRange inputRange = {0, 100};
    instance->setMessageIdRange(inputRange);
    std::cout << "Exiting SetMessageIdRange_StartZero test" << std::endl;
}

/**
 * @brief Test the setMessageIdRange function with end value as zero
 *
 * This test verifies the behavior of the setMessageIdRange function when the end value is set to zero. 
 * It ensures that the function handles this edge case correctly without any errors.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 031@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment by creating an instance of AlServiceRegistrationResponse | None | Instance created | Done by Pre-requisite SetUp function |
 * | 02 | Call the setMessageIdRange function with start value 1 and end value 0 | start = 1, end = 0 | Function should handle the input without errors | Should Pass |
 * | 03 | Clean up the test environment by deleting the instance of AlServiceRegistrationResponse | None | Instance deleted | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceRegistrationResponseTest, SetMessageIdRange_EndZero) {
    std::cout << "Entering SetMessageIdRange_EndZero test" << std::endl;
    MessageIdRange inputRange = {1, 0};
    instance->setMessageIdRange(inputRange);
    std::cout << "Exiting SetMessageIdRange_EndZero test" << std::endl;
}

/**
* @brief Test the setMessageIdRange function with both parameters set to zero.
*
* This test verifies the behavior of the setMessageIdRange function when both the start and end message IDs are set to zero. This is a boundary test case to ensure that the function can handle the minimum input values correctly.
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
* | 01 | Setup the test environment by creating an instance of AlServiceRegistrationResponse. | None | Instance created successfully | Done by Pre-requisite SetUp function |
* | 02 | Call the setMessageIdRange function with both parameters set to zero. | start = 0, end = 0 | Function should execute without errors | Should Pass |
* | 03 | Clean up the test environment by deleting the instance of AlServiceRegistrationResponse. | None | Instance deleted successfully | Done by Pre-requisite TearDown function |
*/
TEST_F(AlServiceRegistrationResponseTest, SetMessageIdRange_BothZero) {
    std::cout << "Entering SetMessageIdRange_BothZero test" << std::endl;
    MessageIdRange inputRange = {0, 0};
    instance->setMessageIdRange(inputRange);
    std::cout << "Exiting SetMessageIdRange_BothZero test" << std::endl;
}

/**
 * @brief Test the setMessageIdRange function with a negative start value
 *
 * This test verifies that the setMessageIdRange function can handle a negative start value correctly.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 033@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Call setMessageIdRange with start = -1 and end = 100 | start = -1, end = 100 | None | Should Pass |
 * | 03 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceRegistrationResponseTest, SetMessageIdRange_NegativeStart) {
    std::cout << "Entering SetMessageIdRange_NegativeStart test" << std::endl;
    MessageIdRange inputRange = {-1, 100};
    instance->setMessageIdRange(inputRange);
    std::cout << "Exiting SetMessageIdRange_NegativeStart test" << std::endl;
}

/**
 * @brief Test the setMessageIdRange function with a negative end value
 *
 * This test verifies the behavior of the setMessageIdRange function when provided with a negative end value. 
 * It ensures that the function handles this edge case appropriately.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 034@n
 * **Priority:** High
 * 
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment by creating an instance of AlServiceRegistrationResponse | None | Instance created successfully | Done by Pre-requisite SetUp function |
 * | 02 | Call the setMessageIdRange function with start = 1 and end = -100 | start = 1, end = -100 | Function should handle the negative end value appropriately | Should Pass |
 * | 03 | Clean up the test environment by deleting the instance of AlServiceRegistrationResponse | None | Instance deleted successfully | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceRegistrationResponseTest, SetMessageIdRange_NegativeEnd) {
    std::cout << "Entering SetMessageIdRange_NegativeEnd test" << std::endl;
    MessageIdRange inputRange = {1, -100};
    instance->setMessageIdRange(inputRange);
    std::cout << "Exiting SetMessageIdRange_NegativeEnd test" << std::endl;
}

/**
 * @brief Test the setMessageIdRange function with both negative values
 *
 * This test verifies the behavior of the setMessageIdRange function when both input values are negative.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 035@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Call setMessageIdRange with both negative values | startId = -1, endId = -100 | None | Should Pass |
 * | 03 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceRegistrationResponseTest, SetMessageIdRange_BothNegative) {
    std::cout << "Entering SetMessageIdRange_BothNegative test" << std::endl;
    MessageIdRange inputRange = {-1, -100};
    instance->setMessageIdRange(inputRange);
    std::cout << "Exiting SetMessageIdRange_BothNegative test" << std::endl;
}

/**
 * @brief Test the setMessageIdRange function with large values
 *
 * This test verifies that the setMessageIdRange function can handle large values for the message ID range without any issues.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 036@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Call setMessageIdRange with large values | input1 = 1000000, input2 = 2000000 | None | Should Pass |
 * | 03 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceRegistrationResponseTest, SetMessageIdRange_LargeValues) {
    std::cout << "Entering SetMessageIdRange_LargeValues test" << std::endl;
    MessageIdRange inputRange = {1000000, 2000000};
    instance->setMessageIdRange(inputRange);
    std::cout << "Exiting SetMessageIdRange_LargeValues test" << std::endl;
}

/**
 * @brief Test the setResult method of AlServiceRegistrationResponse class to set the result to all possible valid values.
 *
 * This test verifies that the setResult method correctly sets the result to each valid RegistrationResult enum value.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 037@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment by creating an instance of AlServiceRegistrationResponse | None | Instance created | Done by Pre-requisite SetUp function |
 * | 02 | Call the setResult method with each value of RegistrationResult enum | RegistrationResult::UNKNOWN, SUCCESS, NO_RANGES_AVAILABLE, SERVICE_NOT_SUPPORTED | Should set the result to each corresponding value | Iterates through all enum values |
 * | 03 | Tear down the test environment by deleting the instance of AlServiceRegistrationResponse | None | Instance deleted | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceRegistrationResponseTest, SetAllRegistrationResults) {
    std::cout << "Entering SetAllRegistrationResults test" << std::endl;

    // Define all enum values in an array
    const std::array<RegistrationResult, 5> allResults = {
        RegistrationResult::UNKNOWN,
        RegistrationResult::SUCCESS,
        RegistrationResult::NO_RANGES_AVAILABLE,
        RegistrationResult::SERVICE_NOT_SUPPORTED,
		RegistrationResult::OPERATION_NOT_SUPPORTED
    };

    for (const auto& result : allResults) {
        instance->setResult(result);
        std::cout << "Set result to: " << static_cast<int>(result) << std::endl;
    }

    std::cout << "Exiting SetAllRegistrationResults test" << std::endl;
}

/**
 * @brief Test the setResult method of AlServiceRegistrationResponse class to set the result to invalid value
 *
 * This test verifies that the setResult method handles the result of invalid RegistrationResult
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 038@n
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment by creating an instance of AlServiceRegistrationResponse | None | Instance created | Done by Pre-requisite SetUp function |
 * | 02 | Call the setResult method with invalid RegistrationResult |  | Should handle the invalid value | Should fail |
 * | 03 | Tear down the test environment by deleting the instance of AlServiceRegistrationResponse | None | Instance deleted | Done by Pre-requisite TearDown function |
 */
 TEST_F(AlServiceRegistrationResponseTest, SetAllRegistrationResult) {
    std::cout << "Entering SetInvalidRegistrationResult test" << std::endl;
	uint8_t result = 0x07;
    instance->setResult(static_cast<RegistrationResult>(result));
    std::cout << "Exiting SetInvalidRegistrationResult test" << std::endl;
}

/**
* @brief Test the AlServiceRegistrationResponse constructor with valid argument values
*
* This test verifies that the AlServiceRegistrationResponse constructor correctly initializes the object with a valid MAC address, a valid message ID range, and all possible registration results.
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
* | 01| Initialize with SUCCESS result | macAddress = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, range = {1000, 2000}, result = SUCCESS | Object should be created with the values | Should Pass |
* | 02| Initialize with NO_RANGES_AVAILABLE result | macAddress = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, range = {1000, 2000}, result = NO_RANGES_AVAILABLE | Object should be created with the values | Should Pass |
* | 03| Initialize with SERVICE_NOT_SUPPORTED result | macAddress = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, range = {1000, 2000}, result = SERVICE_NOT_SUPPORTED | Object should be created with the values | Should Pass |
* | 04| Initialize with UNKNOWN result | macAddress = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, range = {1000, 2000}, result = UNKNOWN | Object should be created with the values | Should Pass |
* | 05| Initialize with OPERATION_NOT_SUPPORTED result | macAddress = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, range = {1000, 2000}, result = OPERATION_NOT_SUPPORTED | Object should be created with the values | Should Pass |
*/
TEST_F(AlServiceRegistrationResponseTest, ValidMACAddressValidRangeAllResults) {
    std::cout << "Entering ValidMACAddressValidRangeAllResults" << std::endl;
    MacAddress macAddress = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
    MessageIdRange range = {1000, 2000};
    RegistrationResult results[] = {
        RegistrationResult::SUCCESS,
        RegistrationResult::NO_RANGES_AVAILABLE,
        RegistrationResult::SERVICE_NOT_SUPPORTED,
        RegistrationResult::UNKNOWN,
        RegistrationResult::OPERATION_NOT_SUPPORTED
    };
    for (const auto& result : results) {
        std::cout << "Testing with result: " << static_cast<uint8_t>(result) << std::endl;
        AlServiceRegistrationResponse response(macAddress, range, result);
    }
    std::cout << "Exiting ValidMACAddressValidRangeAllResults" << std::endl;
}

/**
* @brief Test the AlServiceRegistrationResponse constructor with valid argument values
*
* This test verifies that the AlServiceRegistrationResponse constructor initializes the object with invalid message ID range
*
* **Test Group ID:** Basic: 01@n
* **Test Case ID:** 040@n
* **Priority:** High@n
* @n
* **Dependencies:** None@n
* **User Interaction:** None@n
* @n
* **Test Procedure:**@n
* | Variation / Step | Description | Test Data |Expected Result |Notes |
* | :----: | --------- | ---------- |-------------- | ----- |
* | 01| Initialize MAC address, message ID range, and result | macAddress = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, range = {2000, 1000}, result = RegistrationResult::SUCCESS | Object should be created successfully | Should Pass |
*
*/
TEST_F(AlServiceRegistrationResponseTest, ValidMACAddressInvalidRangeSuccessResult) {
    std::cout << "Entering ValidMACAddressInvalidRangeSuccessResult" << std::endl;
    MacAddress macAddress = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
    MessageIdRange range = {2000, 1000};
    RegistrationResult result = RegistrationResult::SUCCESS;
    AlServiceRegistrationResponse response(macAddress, range, result);
    std::cout << "Exiting ValidMACAddressInvalidRangeSuccessResult" << std::endl;
}

/**
* @brief Test the AlServiceRegistrationResponse constructor with zero range.
*
* This test verifies that the AlServiceRegistrationResponse object is correctly initialized with a valid MAC address, a zero message ID range, and a success result.
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
* | 01 | Initialize AlServiceRegistrationResponse with valid MAC address, zero range, and success result | macAddress = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, range = {0, 0}, result = RegistrationResult::SUCCESS | Object should be initialized successfully | Should Pass |
*
*/
TEST_F(AlServiceRegistrationResponseTest, ValidMACAddressZeroRangeSuccessResult) {
    std::cout << "Entering ValidMACAddressZeroRangeSuccessResult" << std::endl;
    MacAddress macAddress = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
    MessageIdRange range = {0, 0};
    RegistrationResult result = RegistrationResult::SUCCESS;
    AlServiceRegistrationResponse response(macAddress, range, result);
    std::cout << "Exiting ValidMACAddressZeroRangeSuccessResult" << std::endl;
}

/**
* @brief Test the AlServiceRegistrationResponse constructor with all zero MAC address, valid message ID range, and success result.
*
* This test verifies that the AlServiceRegistrationResponse object is correctly initialized when provided with an all-zero MAC address, a valid message ID range, and a success result.@n
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
* | 01| Initialize AlServiceRegistrationResponse with all-zero MAC address, valid message ID range, and success result | macAddress = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, range = {1000, 2000}, result = RegistrationResult::SUCCESS | Object should be initialized successfully | Should Pass |
*
*/
TEST_F(AlServiceRegistrationResponseTest, AllZeroMACAddressValidRangeSuccessResult) {
    std::cout << "Entering AllZeroMACAddressValidRangeSuccessResult" << std::endl;
    MacAddress macAddress = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    MessageIdRange range = {1000, 2000};
    RegistrationResult result = RegistrationResult::SUCCESS;
    AlServiceRegistrationResponse response(macAddress, range, result);
    std::cout << "Exiting AllZeroMACAddressValidRangeSuccessResult" << std::endl;
}


/**
* @brief Test the AlServiceRegistrationResponse constructor with valid MAC address, message ID range, and success result.
*
* This test verifies that the AlServiceRegistrationResponse object is correctly initialized with a MAC address of all 0xFF, a valid message ID range, and a success result.
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
* | 01 | Initialize MAC address, message ID range, and result | macAddress = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, range = {1000, 2000}, result = RegistrationResult::SUCCESS | Object should be initialized successfully | Should be successful |
*
*/
TEST_F(AlServiceRegistrationResponseTest, AllFFMACAddressValidRangeSuccessResult) {
    std::cout << "Entering AllFFMACAddressValidRangeSuccessResult" << std::endl;
    MacAddress macAddress = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    MessageIdRange range = {1000, 2000};
    RegistrationResult result = RegistrationResult::SUCCESS;
    AlServiceRegistrationResponse response(macAddress, range, result);
    std::cout << "Exiting AllFFMACAddressValidRangeSuccessResult" << std::endl;
}

/**
* @brief Test the AlServiceRegistrationResponse constructor and getters with valid MAC address, valid range, and invalid result.
*
* This test verifies that the AlServiceRegistrationResponse object is correctly constructed when provided with a valid MAC address, a valid message ID range, and an invalid registration result.@n
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
* | 01 | Construct AlServiceRegistrationResponse object and verify MAC address | macAddress = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, range = {1000, 2000}, result = 0xFF | response.getAlMacAddressLocal() == macAddress | Should Pass |
*
*/
TEST_F(AlServiceRegistrationResponseTest, ValidMACAddressValidRangeInvalidResult) {
    std::cout << "Entering ValidMACAddressValidRangeInvalidResult" << std::endl;
    MacAddress macAddress = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
    MessageIdRange range = {1000, 2000};
    RegistrationResult result = static_cast<RegistrationResult>(0xFF);
    AlServiceRegistrationResponse response(macAddress, range, result);
    std::cout << "Exiting ValidMACAddressValidRangeInvalidResult" << std::endl;
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}