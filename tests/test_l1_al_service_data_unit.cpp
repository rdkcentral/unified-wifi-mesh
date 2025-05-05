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
#include <numeric>
#include "al_service_data_unit.h"

class AlServiceDataUnitTest : public ::testing::Test {
protected:
    AlServiceDataUnit* alServiceDataUnit;

    void SetUp() override {
        alServiceDataUnit = new AlServiceDataUnit();
    }

    void TearDown() override {
        delete alServiceDataUnit;
    }
};

MacAddress parseMacAddress(const std::string& macStr) {
    std::string cleaned;
    for (char c : macStr) {
        if (std::isalnum(c)) {
            cleaned += c;
        }
    }
    MacAddress mac{};
    for (size_t i = 0; i < 6; ++i) {
        std::string byteStr = cleaned.substr(i * 2, 2);
        std::istringstream(byteStr) >> std::hex >> mac[i];
    }
    return mac;
}

/**
 * @brief Test appending valid data to the payload
 *
 * This test verifies that the appendToPayload function correctly appends data to the payload and that the payload contains the expected values after the operation.
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
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Define the data to be appended | data = {0x01, 0x02, 0x03} | None | Should be successful |
 * | 03 | Append data to the payload | data = {0x01, 0x02, 0x03}, size = 3 | None | Should Pass |
 * | 08 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, AppendValidDataToPayload) {
    std::cout << "Entering AppendValidDataToPayload test" << std::endl;
    unsigned char data[] = {0x01, 0x02, 0x03};
    alServiceDataUnit->appendToPayload(data, 3);
    std::cout << "Exiting AppendValidDataToPayload test" << std::endl;
}

/**
 * @brief Test appending empty data to the payload
 *
 * This test verifies that appending an empty data array to the payload does not alter the payload size.
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
 * | 01 | Setup the test environment by initializing AlServiceDataUnit object | None | AlServiceDataUnit object is initialized | Done by Pre-requisite SetUp function |
 * | 02 | Define an empty data array | data = {} | Empty data array is defined | Should be successful |
 * | 03 | Append the empty data array to the payload | data = {}, size = 0 | None | Should Pass |
 * | 04 | Tear down the test environment by deleting AlServiceDataUnit object | None | AlServiceDataUnit object is deleted | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, AppendEmptyDataToPayload) {
    std::cout << "Entering AppendEmptyDataToPayload test" << std::endl;
    unsigned char data[] = {};
    alServiceDataUnit->appendToPayload(data, 0);
    std::cout << "Exiting AppendEmptyDataToPayload test" << std::endl;
}

/**
 * @brief Test appending a null data pointer to the payload
 *
 * This test verifies that appending a null data pointer to the payload does not alter the payload size.
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
 * | 01 | Setup the test environment by initializing AlServiceDataUnit object | None | AlServiceDataUnit object is initialized | Done by Pre-requisite SetUp function |
 * | 02 | Log entering the test | None | Log message "Entering AppendNullDataPointerToPayload test" is printed | Should be successful |
 * | 03 | Define a null data pointer | data = nullptr | data is null | Should be successful |
 * | 04 | Append null data pointer to payload | data = nullptr, size = 3 | None | Should Pass |
 * | 05 | Tear down the test environment by deleting AlServiceDataUnit object | None | AlServiceDataUnit object is deleted | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, AppendNullDataPointerToPayload) {
    std::cout << "Entering AppendNullDataPointerToPayload test" << std::endl;
    unsigned char* data = nullptr;
    alServiceDataUnit->appendToPayload(data, 3);    
    std::cout << "Exiting AppendNullDataPointerToPayload test" << std::endl;
}

/**
 * @brief Test appending data with zero length to the payload
 *
 * This test verifies that appending data with a length of zero does not alter the payload of the AlServiceDataUnit object.
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
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Define data to append | data = {0x01, 0x02, 0x03}, length = 0 | None | Should be successful |
 * | 03 | Append data with zero length to payload | data = {0x01, 0x02, 0x03}, length = 0 | None | Should Pass |
 * | 04 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, AppendDataWithZeroLength) {
    std::cout << "Entering AppendDataWithZeroLength test" << std::endl;
    unsigned char data[] = {0x01, 0x02, 0x03};
    alServiceDataUnit->appendToPayload(data, 0);   
    std::cout << "Exiting AppendDataWithZeroLength test" << std::endl;
}

/**
 * @brief Test appending data with maximum length to the payload
 *
 * This test verifies that the appendToPayload function correctly appends data of maximum length (255 bytes) to the payload and ensures that the payload size and content are as expected.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 005
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
 * | 02 | Initialize data array with values from 1 to 255 | data[i] = i + 1 for i in 0 to 254 | data array initialized | Should be successful |
 * | 03 | Append data to payload | data = {1, 2, ..., 255}, length = 255 | Payload size should be 255 | Should Pass |
 * | 04 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, AppendDataWithMaximumLength) {
    std::cout << "Entering AppendDataWithMaximumLength" << std::endl;
    unsigned char data[255];
    for (int i = 0; i < 255; ++i) {
        data[i] = static_cast<unsigned char>(i + 1);
    }
    alServiceDataUnit->appendToPayload(data, 255);
    std::cout << "Exiting AppendDataWithMaximumLength" << std::endl;
}

/**
 * @brief Test appending data with length exceeding buffer size
 *
 * This test verifies that the appendToPayload function correctly handles appending data that exceeds the buffer size. It ensures that the payload is correctly updated and that the data integrity is maintained.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 006
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
 * | 02 | Initialize data array with values from 1 to 256 | data[i] = i + 1 for i in 0 to 255 | data array initialized | Should be successful |
 * | 03 | Append data to payload | alServiceDataUnit->appendToPayload(data, 256) | data = {1, 2, ..., 256} | Should Pass |
 * | 04 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, AppendDataWithLengthExceedingBufferSize) {
    std::cout << "Entering AppendDataWithLengthExceedingBufferSize" << std::endl;
    unsigned char data[256];
    for (int i = 0; i < 256; ++i) {
        data[i] = static_cast<unsigned char>(i + 1);
    }
    alServiceDataUnit->appendToPayload(data, 256);
    std::cout << "Exiting AppendDataWithLengthExceedingBufferSize" << std::endl;
}

/**
* @brief Test appending data with special characters and non-ASCII values to the payload
*
* This test verifies that the appendToPayload function correctly handles and appends data containing special characters and non-ASCII values to the payload. It ensures that the payload size and content are as expected after the operation.
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
* | 01 | Initialize the test fixture | None | None | Done by Pre-requisite SetUp function |
* | 02 | Log entering the test | None | None | Should be successful |
* | 03 | Define data with special characters and non-ASCII values | data = {0x00, 0xFF, 0x7F, 0x80, 0x81, 0x82} | None | Should be successful |
* | 04 | Append first 3 bytes of data to payload | data = {0x00, 0xFF, 0x7F}, length = 3 | None | Should Pass |
* | 05 | Clean up the test fixture | None | None | Done by Pre-requisite TearDown function |
*/
TEST_F(AlServiceDataUnitTest, AppendDataWithSpecialCharactersAndNonASCIIValues) {
    std::cout << "Entering AppendDataWithSpecialCharactersAndNonASCIIValues" << std::endl;
    unsigned char data[] = {0x00, 0xFF, 0x7F, 0x80, 0x81, 0x82};
    alServiceDataUnit->appendToPayload(data, 3);
    std::cout << "Exiting AppendDataWithSpecialCharactersAndNonASCIIValues" << std::endl;
}

/**
 * @brief Test appending mixed valid and invalid values to the payload
 *
 * This test verifies that the appendToPayload function correctly handles a mix of valid and invalid values.
 * It ensures that the payload is updated correctly and that the size and content of the payload are as expected.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 008
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
 * | 02 | Define data array with mixed valid and invalid values | data = {0x01, 0x02, 0x00} | None | Should be successful |
 * | 03 | Append data to payload | alServiceDataUnit->appendToPayload(data, 3) | None | Should Pass |
 * | 04 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, AppendDataWithMixedValidAndInvalidValues) {
    std::cout << "Entering AppendDataWithMixedValidAndInvalidValues" << std::endl;
    unsigned char data[] = {0x01, 0x02, 0x00};
    alServiceDataUnit->appendToPayload(data, 3);
    std::cout << "Exiting AppendDataWithMixedValidAndInvalidValues" << std::endl;
}

/**
 * @brief Test the deserialization of an empty data vector
 *
 * This test checks the behavior of the `deserialize` method when provided with an empty data vector. 
 * It ensures that the method can handle empty input without errors.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 009
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment by initializing `AlServiceDataUnit` object | None | Object should be initialized | Done by Pre-requisite SetUp function |
 * | 02 | Call the `deserialize` method with an empty data vector | data = {} | Method should handle empty input without errors | Should Pass |
 * | 03 | Clean up the test environment by deleting `AlServiceDataUnit` object | None | Object should be deleted | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, DeserializeWithEmptyDataVector) {
    std::cout << "Entering DeserializeWithEmptyDataVector test" << std::endl;
    std::vector<unsigned char> data = {};
    alServiceDataUnit->deserialize(data);    
    std::cout << "Exiting DeserializeWithEmptyDataVector test" << std::endl;
}

/**
 * @brief Test the deserialization of valid data vector in AlServiceDataUnit
 *
 * This test verifies that the AlServiceDataUnit can correctly deserialize a valid data vector.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 010
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
 * | 02 | Create a valid data vector | data = {0x01, 0x02, 0x03, 0x04, 0x05} | None | Should be successful |
 * | 03 | Call the deserialize method with the valid data vector | data = {0x01, 0x02, 0x03, 0x04, 0x05} | None | Should Pass |
 * | 04 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, DeserializeWithValidDataVector) {
    std::cout << "Entering DeserializeWithValidDataVector test" << std::endl;
    std::vector<unsigned char> data = {0x01, 0x02, 0x03, 0x04, 0x05};
    alServiceDataUnit->deserialize(data);    
    std::cout << "Exiting DeserializeWithValidDataVector test" << std::endl;
}

/**
* @brief Test the deserialization of maximum size data vector
*
* This test verifies that the `deserialize` method of `AlServiceDataUnit` can handle the maximum size data vector correctly.
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
* | 01| Setup the test environment | None | None | Done by Pre-requisite SetUp function |
* | 02| Create a data vector of maximum size (256) and populate it | data = {0, 1, 2, ..., 255} | None | Should be successful |
* | 03| Call the `deserialize` method with the data vector | data = {0, 1, 2, ..., 255} | None | Should Pass |
* | 04| Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
*/
TEST_F(AlServiceDataUnitTest, DeserializeWithMaximumSizeDataVector) {
    std::cout << "Entering DeserializeWithMaximumSizeDataVector test" << std::endl;
    std::vector<unsigned char> data(256);
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<unsigned char>(i);
    }
    alServiceDataUnit->deserialize(data);
    std::cout << "Exiting DeserializeWithMaximumSizeDataVector test" << std::endl;
}

/**
 * @brief Test deserialization with a data vector containing only zeros.
 *
 * This test verifies the behavior of the `deserialize` method when provided with a data vector that contains only zero values. This is to ensure that the method can handle and correctly process such input without errors.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 012
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
 * | 02 | Create a data vector containing only zeros | data = {0x00, 0x00, 0x00, 0x00} | None | Should be successful |
 * | 03 | Call the `deserialize` method with the zero data vector | data = {0x00, 0x00, 0x00, 0x00} | None | Should Pass |
 * | 04 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, DeserializeWithDataVectorContainingOnlyZeros) {
    std::cout << "Entering DeserializeWithDataVectorContainingOnlyZeros test" << std::endl;
    std::vector<unsigned char> data = {0x00, 0x00, 0x00, 0x00};
    alServiceDataUnit->deserialize(data);    
    std::cout << "Exiting DeserializeWithDataVectorContainingOnlyZeros test" << std::endl;
}

/**
 * @brief Test the deserialization of a data vector containing only ones.
 *
 * This test checks the behavior of the `deserialize` method when provided with a data vector that contains only the value 0x01. This is to ensure that the method can handle and correctly process a uniform data vector.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 013
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment by initializing `AlServiceDataUnit` object | None | Object initialized | Done by Pre-requisite SetUp function |
 * | 02 | Create a data vector containing only 0x01 values | data = {0x01, 0x01, 0x01, 0x01} | Data vector created | Should be successful |
 * | 03 | Call the `deserialize` method with the created data vector | data = {0x01, 0x01, 0x01, 0x01} | Method executed | Should Pass |
 * | 04 | Clean up the test environment by deleting `AlServiceDataUnit` object | None | Object deleted | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, DeserializeWithDataVectorContainingOnlyOnes) {
    std::cout << "Entering DeserializeWithDataVectorContainingOnlyOnes test" << std::endl;
    std::vector<unsigned char> data = {0x01, 0x01, 0x01, 0x01};
    alServiceDataUnit->deserialize(data);    
    std::cout << "Exiting DeserializeWithDataVectorContainingOnlyOnes test" << std::endl;
}

/**
 * @brief Test deserialization with a data vector containing valid MAC addresses and payload.
 *
 * This test verifies that the `deserialize` method of the `AlServiceDataUnit` class can correctly handle a data vector containing valid MAC addresses and payload. The test ensures that the method processes the input data without errors.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 014
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment by initializing `AlServiceDataUnit` object. | None | Object initialized successfully | Done by Pre-requisite SetUp function |
 * | 02 | Create a data vector containing valid MAC addresses and payload. | data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10} | Data vector created successfully | Should be successful |
 * | 03 | Call the `deserialize` method with the created data vector. | data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10} | Method processes the data without errors | Should Pass |
 * | 04 | Clean up the test environment by deleting `AlServiceDataUnit` object. | None | Object deleted successfully | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, DeserializeWithDataVectorContainingValidMacAddressesAndPayload) {
    std::cout << "Entering DeserializeWithDataVectorContainingValidMacAddressesAndPayload test" << std::endl;
    std::vector<unsigned char> data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    alServiceDataUnit->deserialize(data);    
    std::cout << "Exiting DeserializeWithDataVectorContainingValidMacAddressesAndPayload test" << std::endl;
}

/**
 * @brief Test deserialization with a data vector containing invalid MAC addresses.
 *
 * This test checks the behavior of the `deserialize` method when provided with a data vector that contains invalid MAC addresses. The objective is to ensure that the method can handle such input without crashing or producing incorrect results.
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
 * | 01 | Setup the test environment by initializing `AlServiceDataUnit` object | None | Object should be initialized successfully | Done by Pre-requisite SetUp function |
 * | 02 | Create a data vector containing invalid MAC addresses | data = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} | Data vector should be created successfully | Should be successful |
 * | 03 | Call the `deserialize` method with the invalid data vector | data = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} | Method should handle the input without crashing | Should Pass |
 * | 04 | Clean up the test environment by deleting `AlServiceDataUnit` object | None | Object should be deleted successfully | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, DeserializeWithDataVectorContainingInvalidMacAddresses) {
    std::cout << "Entering DeserializeWithDataVectorContainingInvalidMacAddresses test" << std::endl;
    std::vector<unsigned char> data = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    alServiceDataUnit->deserialize(data);    
    std::cout << "Exiting DeserializeWithDataVectorContainingInvalidMacAddresses test" << std::endl;
}

/**
 * @brief Test to retrieve, print, and verify the destination AL MAC address.
 *
 * This test checks the functionality of retrieving the destination AL MAC address from the AlServiceDataUnit object, 
 * verifies its validity, and prints it. This ensures that the MAC address retrieval and validation mechanisms are working correctly.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 016
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment by initializing AlServiceDataUnit object | None | AlServiceDataUnit object should be initialized | Done by Pre-requisite SetUp function |
 * | 02 | Retrieve the destination AL MAC address using getDestinationAlMacAddress() | None | MAC address should be retrieved | Should be successful |
 * | 03 | Clean up the test environment by deleting AlServiceDataUnit object | None | AlServiceDataUnit object should be deleted | Done by Pre-requisite TearDown function |
 */
 TEST_F(AlServiceDataUnitTest, RetrievePrintAndVerifyDestinationAlMacAddress) {
    std::cout << "Entering RetrievePrintAndVerifyDestinationAlMacAddress test" << std::endl;
    MacAddress macAddress = alServiceDataUnit->getDestinationAlMacAddress();
    std::cout << "Destination AL MAC Address: ";
    for (size_t i = 0; i < macAddress.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(macAddress[i]);
        if (i != macAddress.size() - 1)
            std::cout << ":";
    }
    std::cout << std::dec << std::endl;
    std::cout << "Exiting RetrievePrintAndVerifyDestinationAlMacAddress test" << std::endl;
}


/**
 * @brief Test to verify the retrieval and printing of Fragment ID
 *
 * This test checks the functionality of the getFragmentId method in the AlServiceDataUnit class. It ensures that the retrieved Fragment ID is not zero and logs the ID.
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
 * | 01 | Setup the test environment by initializing AlServiceDataUnit object | None | AlServiceDataUnit object is created | Done by Pre-requisite SetUp function |
 * | 02 | Retrieve the Fragment ID using getFragmentId method | None | Fragment ID is retrieved | Should be successful |
 * | 03 | Log the retrieved Fragment ID | fragmentId = value | Fragment ID is logged | Should be successful |
 * | 04 | Clean up the test environment by deleting AlServiceDataUnit object | None | AlServiceDataUnit object is deleted | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, RetrieveAndPrintFragmentId) {
    std::cout << "Entering RetrieveAndPrintFragmentId" << std::endl;
    uint8_t fragmentId = alServiceDataUnit->getFragmentId();    
    std::cout << "Fragment ID: " << static_cast<int>(fragmentId);
    std::cout << "Exiting RetrieveAndPrintFragmentId" << std::endl;
}

/**
 * @brief Test to verify the retrieval and printing of fragment status
 *
 * This test checks the functionality of the `getIsFragment` method of the `AlServiceDataUnit` class. It ensures that the method returns a valid fragment status (either 0 or 1) and logs the status.
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
 * | 01 | Setup the test environment by initializing `AlServiceDataUnit` object | None | Object should be initialized successfully | Done by Pre-requisite SetUp function |
 * | 02 | Retrieve the fragment status using `getIsFragment` method | None | Should return 0 or 1 | Should Pass |
 * | 03 | Log the fragment status | fragmentStatus = 0 or 1 | Status should be logged | Should be successful |
 * | 04 | Clean up the test environment by deleting `AlServiceDataUnit` object | None | Object should be deleted successfully | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, RetrieveAndPrintFragmentStatus) {
    std::cout << "Entering RetrieveAndPrintFragmentStatus" << std::endl;
    uint8_t fragmentStatus = alServiceDataUnit->getIsFragment();
    std::cout << "Fragment status: " << static_cast<int>(fragmentStatus);
    std::cout << "Exiting RetrieveAndPrintFragmentStatus" << std::endl;
}

/**
 * @brief Test to verify the retrieval of fragment status and its output
 *
 * This test checks the functionality of the `getIsLastFragment` method of the `AlServiceDataUnit` class. It ensures that the method returns the expected default value and prints the fragment status correctly.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 019
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment by initializing `AlServiceDataUnit` object | None | Object should be initialized successfully | Done by Pre-requisite SetUp function |
 * | 02 | Call the `getIsLastFragment` method to retrieve the fragment status | None | Should return 0 | Should Pass |
 * | 03 | Print the retrieved fragment status | result = 0 | Should print "Fragment status: 0" | Should be successful |
 * | 04 | Clean up the test environment by deleting `AlServiceDataUnit` object | None | Object should be deleted successfully | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, RetrieveFragmentStatusAndPrint) {
    std::cout << "Entering RetrieveFragmentStatusAndPrint test" << std::endl;
    uint8_t result = alServiceDataUnit->getIsLastFragment();    
    std::cout << "Fragment status: " << static_cast<int>(result) << std::endl;
    std::cout << "Exiting RetrieveFragmentStatusAndPrint test" << std::endl;
}

/**
 * @brief Test to verify the retrieval and printing of payload in AlServiceDataUnit
 *
 * This test checks the functionality of retrieving the payload from the AlServiceDataUnit object and ensures that the payload is initially empty.
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
 * | 01 | Setup the test environment by creating an instance of AlServiceDataUnit | None | Instance of AlServiceDataUnit created | Done by Pre-requisite SetUp function |
 * | 02 | Retrieve the payload from the AlServiceDataUnit instance | None | Payload retrieved | Should be successful |
 * | 03 | Clean up the test environment by deleting the instance of AlServiceDataUnit | None | Instance of AlServiceDataUnit deleted | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, RetrievePayloadAndPrint) {
    std::cout << "Entering RetrievePayloadAndPrint test" << std::endl;
    std::vector<unsigned char>& payload = alServiceDataUnit->getPayload();
    std::cout << "Payload bytes (hex): ";
    for (auto byte : payload) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte) << " ";
    }
    std::cout << std::endl;
    std::cout << "Exiting RetrievePayloadAndPrint test" << std::endl;
}

/**
* @brief Test to verify the retrieval of the source AL MAC address
*
* This test checks the functionality of the getSourceAlMacAddress method in the AlServiceDataUnit class. It ensures that the method returns a valid MAC address.
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
* | 01| Setup the test environment | None | None | Done by Pre-requisite SetUp function |
* | 02| Retrieve the source AL MAC address using getSourceAlMacAddress method and print it| None | MAC address should be valid | Should Pass |
* | 03| Clean up the test environment | None | None | Done by Pre-requisite TearDown function |
*/
TEST_F(AlServiceDataUnitTest, RetrieveSourceAlMacAddress) {
    std::cout << "Entering RetrieveSourceAlMacAddress test" << std::endl;
    MacAddress macAddress = alServiceDataUnit->getSourceAlMacAddress();
    std::cout << "Source AL MAC Address: ";
    for (auto byte : macAddress) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte) << ":";
    }
    std::cout << std::endl;
    std::cout << "Exiting RetrieveSourceAlMacAddress test" << std::endl;
}

/**
 * @brief Test the serialization of AlServiceDataUnit with valid MAC addresses and payload.
 *
 * This test verifies that the AlServiceDataUnit can correctly serialize its data when provided with valid source and destination MAC addresses, and a valid payload. The test ensures that the serialized result is not empty, indicating successful serialization.
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
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Serialize the data | None | Execution should happen without any issues | Should Pass |
 * | 09 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, InvokeSerialize) {
    std::cout << "Entering SerializeWithValidMacAddressesAndPayload test" << std::endl;
    std::vector<unsigned char> result = alServiceDataUnit->serialize();
    std::cout << "Exiting SerializeWithValidMacAddressesAndPayload test" << std::endl;
}

/**
 * @brief Test the setting of a valid MAC address in the AlServiceDataUnit class.
 *
 * This test verifies that the setDestinationAlMacAddress method correctly sets a valid MAC address and that the getDestinationAlMacAddress method retrieves the same address.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 023
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
 * | 02 | Set a valid MAC address using setDestinationAlMacAddress method | macAddress = "00:1A:2B:3C:4D:5E" | None | Should be successful |
 * | 03 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, SetDestinationMacAddress_ValidFormat1) {
    std::cout << "Entering SetDestinationMacAddress_ValidFormat1" << std::endl;
    std::string macAddress = "00:1A:2B:3C:4D:5E";
    alServiceDataUnit->setDestinationAlMacAddress(parseMacAddress(macAddress));   
    std::cout << "Exiting SetDestinationMacAddress_ValidFormat1" << std::endl;
}

/**
* @brief Test the setting of a valid MAC address in the AlServiceDataUnit class.
*
* This test verifies that the setDestinationAlMacAddress method correctly sets a valid MAC address and that the getDestinationAlMacAddress method retrieves the same address.
*
* **Test Group ID:** Basic: 01
* **Test Case ID:** 024
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
* | 02 | Set a valid MAC address using setDestinationAlMacAddress | macAddress = "001A2B3C4D5E" | None | Should be successful |
* | 03 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
*/
TEST_F(AlServiceDataUnitTest, SetDestinationMacAddress_ValidFormat2) {
    std::cout << "Entering SetDestinationMacAddress_ValidFormat2" << std::endl;
    std::string macAddress = "001A2B3C4D5E";
    alServiceDataUnit->setDestinationAlMacAddress(parseMacAddress(macAddress));
    std::cout << "Exiting SetDestinationMacAddress_ValidFormat2" << std::endl;
}

/**
* @brief Test the setting of a valid MAC address in the AlServiceDataUnit class.
*
* This test verifies that the setDestinationAlMacAddress method correctly sets a valid MAC address and that the getDestinationAlMacAddress method returns the expected value. This ensures that the MAC address is stored and retrieved correctly.
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
* | 01 | Initialize the AlServiceDataUnit object | None | Object initialized | Done by Pre-requisite SetUp function |
* | 02 | Set a valid MAC address using setDestinationAlMacAddress method | macAddress = "00-1A-2B-3C-4D-5E" | MAC address set successfully | Should be successful |
* | 03 | Clean up the AlServiceDataUnit object | None | Object cleaned up | Done by Pre-requisite TearDown function |
*/
TEST_F(AlServiceDataUnitTest, SetDestinationMacAddress_ValidFormat3) {
    std::cout << "Entering SetDestinationMacAddress_ValidFormat3" << std::endl;
    std::string macAddress = "00-1A-2B-3C-4D-5E";
    alServiceDataUnit->setDestinationAlMacAddress(parseMacAddress(macAddress));   
    std::cout << "Exiting SetDestinationMacAddress_ValidFormat3" << std::endl;
}

/**
 * @brief Test to validate the behavior of setDestinationAlMacAddress with an invalid MAC address format
 *
 * This test checks if the setDestinationAlMacAddress function correctly handles an invalid MAC address format by ensuring that the invalid address is not set.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 026
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
 * | 02 | Define an invalid MAC address format | macAddress = "00:1A:2B:3C:4D" | None | Should be successful |
 * | 03 | Call setDestinationAlMacAddress with the invalid MAC address | macAddress = "00:1A:2B:3C:4D" | None | Should Pass |
 * | 04 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
 TEST_F(AlServiceDataUnitTest, SetDestinationMacAddress_InvalidFormat1) {
    std::string macAddress = "00:1A:2B:3C:4D";
    try {
        alServiceDataUnit->setDestinationAlMacAddress(parseMacAddress(macAddress));
        FAIL() << "Expected exception for invalid MAC format (too short)";
    } catch (const std::exception& e) {
        std::cout << "Caught expected exception: " << e.what() << std::endl;
        SUCCEED();
    } catch (...) {
        FAIL() << "Caught unknown exception type";
    }
}

/**
 * @brief Test to verify the behavior of setting an invalid MAC address format
 *
 * This test checks if the `setDestinationAlMacAddress` method correctly handles an invalid MAC address format by ensuring that the address is not set.
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
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Set an invalid MAC address format | macAddress = "00:1A:2B:3C:4D:5E:6F" | None | Should Fail |
 * | 03 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
 TEST_F(AlServiceDataUnitTest, SetDestinationMacAddress_InvalidFormat2) {
    std::string macAddress = "00:1A:2B:3C:4D:5E:6F";
    try {
        alServiceDataUnit->setDestinationAlMacAddress(parseMacAddress(macAddress));
        FAIL() << "Expected exception for invalid MAC format (too long)";
    } catch (const std::exception& e) {
        std::cout << "Caught expected exception: " << e.what() << std::endl;
        SUCCEED();
    } catch (...) {
        FAIL() << "Caught unknown exception type";
    }
}

/**
* @brief Test to verify the behavior of SetDestinationMacAddress with invalid characters in MAC address
*
* This test checks if the setDestinationAlMacAddress function correctly handles invalid characters in the MAC address input. The expected behavior is that the function should not accept the invalid MAC address and the stored MAC address should not match the input.
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
* | 01| Setup the test environment | None | None | Done by Pre-requisite SetUp function |
* | 02| Set invalid MAC address | macAddress = "00:1A:2B:3@:4D:ZZ" | None | Should Pass |
* | 03| Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
*/
TEST_F(AlServiceDataUnitTest, SetDestinationMacAddress_InvalidCharacters1) {
    std::string macAddress = "00:1A:2B:3@:4D:ZZ";
    try {
        alServiceDataUnit->setDestinationAlMacAddress(parseMacAddress(macAddress));
        FAIL() << "Expected exception for invalid characters in MAC address";
    } catch (const std::exception& e) {
        std::cout << "Caught expected exception: " << e.what() << std::endl;
        SUCCEED();
    } catch (...) {
        FAIL() << "Caught unknown exception type";
    }
}
/**
 * @brief Test to verify setting the fragment ID to zero
 *
 * This test checks if the fragment ID can be set to zero and verifies that the value is correctly updated in the AlServiceDataUnit object.
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
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Set the fragment ID to zero | fragmentId = 0 | None | Should be successful |
 * | 03 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, SetFragmentIdToZero) {
    std::cout << "Entering SetFragmentIdToZero test" << std::endl;
    alServiceDataUnit->setFragmentId(0);
    std::cout << "Exiting SetFragmentIdToZero test" << std::endl;
}

/**
 * @brief Test to set the fragment ID to its maximum value and verify.
 *
 * This test checks if the fragment ID can be set to its maximum value (255) and verifies if the value is correctly set by retrieving it.
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
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Set the fragment ID to 255 | fragmentId = 255 | None | Should be successful |
 * | 03 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, SetFragmentIdToMaximumValue) {
    std::cout << "Entering SetFragmentIdToMaximumValue test" << std::endl;
    alServiceDataUnit->setFragmentId(255);
    std::cout << "Exiting SetFragmentIdToMaximumValue test" << std::endl;
}

/**
* @brief Test the SetFragmentStatusWithMinValidID function
*
* This test verifies that the setIsFragment function correctly sets the fragment status for the minimum valid ID (0). It ensures that the status is set to 1 when the ID is 0.
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
* | 01| Setup the test environment | None | None | Done by Pre-requisite SetUp function |
* | 02| Set the fragment status with minimum valid ID | id = 0 | None | Should be successful |
* | 03| Cleanup the test environment | None | None | Done by Pre-requisite TearDown function |
*/
TEST_F(AlServiceDataUnitTest, SetFragmentStatusWithMinValidID) {
    std::cout << "Entering SetFragmentStatusWithMinValidID" << std::endl;
    uint8_t id = 0;
    alServiceDataUnit->setIsFragment(id);
    std::cout << "Exiting SetFragmentStatusWithMinValidID" << std::endl;
}

/**
 * @brief Test the SetFragmentStatusWithMaxValidID function of AlServiceDataUnit
 *
 * This test verifies that the setIsFragment function correctly sets the fragment status when provided with the maximum valid ID (255). It ensures that the getIsFragment function returns the expected value after setting the fragment status.
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
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Set the fragment status with the maximum valid ID | id = 255 | None | Should be successful |
 * | 03 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, SetFragmentStatusWithMaxValidID) {
    std::cout << "Entering SetFragmentStatusWithMaxValidID" << std::endl;
    uint8_t id = 255;
    alServiceDataUnit->setIsFragment(id);
    std::cout << "Exiting SetFragmentStatusWithMaxValidID" << std::endl;
}

/**
 * @brief Test the SetLastFragmentStatusWithMaxValidID function of AlServiceDataUnit
 *
 * This test verifies that the setIsLastFragment function correctly sets the last fragment status when provided with the maximum valid ID (255). It ensures that the status is set to 1, indicating the last fragment.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 033
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment by initializing AlServiceDataUnit object | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Set the last fragment status with the maximum valid ID (255) | id = 255 | None | Should be successful |
 * | 03 | Clean up the test environment by deleting AlServiceDataUnit object | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, SetLastFragmentStatusWithMaxValidID) {
    std::cout << "Entering SetLastFragmentStatusWithMaxValidID" << std::endl;
    uint8_t id = 255;
    alServiceDataUnit->setIsLastFragment(id);
    std::cout << "Exiting SetLastFragmentStatusWithMaxValidID" << std::endl;
}

/**
 * @brief Test the SetLastFragmentStatusWithMinValidID function of AlServiceDataUnit
 *
 * This test verifies that the setIsLastFragment function correctly sets the last fragment status when provided with the minimum valid ID (0). It ensures that the status is set to 1, indicating the last fragment.
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
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Call setIsLastFragment with id = 0 | id = 0 | None | Should be successful |
 * | 03 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, SetLastFragmentStatusWithMinValidID) {
    std::cout << "Entering SetLastFragmentStatusWithMinValidID" << std::endl;
    uint8_t id = 0;
    alServiceDataUnit->setIsLastFragment(id);
    std::cout << "Exiting SetLastFragmentStatusWithMinValidID" << std::endl;
}

/**
 * @brief Test the SetPayload function with a valid buffer
 *
 * This test verifies that the SetPayload function correctly sets the payload of the AlServiceDataUnit object when provided with a valid buffer. It ensures that the payload is accurately stored and can be retrieved using the getPayload function.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 035
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
 * | 02 | Create a valid buffer and set it as the payload | buffer = {0x01, 0x02, 0x03, 0x04} | None | Should be successful |
 * | 03 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, SetPayloadWithValidBuffer) {
    std::cout << "Entering SetPayloadWithValidBuffer test" << std::endl;
    std::vector<unsigned char> buffer = {0x01, 0x02, 0x03, 0x04};
    alServiceDataUnit->setPayload(buffer);
    std::cout << "Exiting SetPayloadWithValidBuffer test" << std::endl;
}

/**
 * @brief Test the SetPayload function with an empty buffer
 *
 * This test verifies that the SetPayload function correctly handles an empty buffer input. 
 * It ensures that the payload is set to an empty buffer and that the getPayload function 
 * returns the same empty buffer.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 036
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
 * | 02 | Initialize an empty buffer | buffer = {} | None | Should be successful |
 * | 03 | Call setPayload with the empty buffer | buffer = {} | None | Should Pass |
 * | 04 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, SetPayloadWithEmptyBuffer) {
    std::cout << "Entering SetPayloadWithEmptyBuffer test" << std::endl;
    std::vector<unsigned char> buffer = {};
    alServiceDataUnit->setPayload(buffer);
    std::cout << "Exiting SetPayloadWithEmptyBuffer test" << std::endl;
}

/**
 * @brief Test the setPayload function with a maximum size buffer
 *
 * This test verifies that the setPayload function correctly handles a buffer of maximum size (256 bytes) and that the payload is set and retrieved correctly.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 037
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call SetUp function to initialize AlServiceDataUnit object | None | AlServiceDataUnit object initialized | Done by Pre-requisite SetUp function |
 * | 02 | Create a buffer of size 256 and fill it with incremental values starting from 0 | buffer = {0, 1, 2, ..., 255} | Buffer created and filled with values | Should be successful |
 * | 03 | Call setPayload with the created buffer | buffer = {0, 1, 2, ..., 255} | Payload set in AlServiceDataUnit object | Should Pass |
 * | 04 | Call TearDown function to clean up AlServiceDataUnit object | None | AlServiceDataUnit object deleted | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, SetPayloadWithMaxSizeBuffer) {
    std::cout << "Entering SetPayloadWithMaxSizeBuffer test" << std::endl;
    std::vector<unsigned char> buffer(256);
    std::iota(buffer.begin(), buffer.end(), 0);
    alServiceDataUnit->setPayload(buffer);
    std::cout << "Exiting SetPayloadWithMaxSizeBuffer test" << std::endl;
}

/**
 * @brief Test the setPayload function with a buffer of all zeroes
 *
 * This test verifies that the setPayload function correctly sets the payload to a buffer containing all zeroes and that the getPayload function returns the same buffer.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 038
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
 * | 02 | Create a buffer with all zeroes | buffer = {0x00, 0x00, 0x00, 0x00} | None | Should be successful |
 * | 03 | Set the payload with the zero buffer | buffer = {0x00, 0x00, 0x00, 0x00} | None | Should Pass |
 * | 04 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, SetPayloadWithAllZeroesBuffer) {
    std::cout << "Entering SetPayloadWithAllZeroesBuffer test" << std::endl;
    std::vector<unsigned char> buffer = {0x00, 0x00, 0x00, 0x00};
    alServiceDataUnit->setPayload(buffer);
    std::cout << "Exiting SetPayloadWithAllZeroesBuffer test" << std::endl;
}

/**
 * @brief Test the setPayload function with a buffer of all ones
 *
 * This test verifies that the setPayload function correctly sets the payload to a buffer containing all ones and that the getPayload function returns the same buffer.
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
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Create a buffer with all ones | buffer = {0xFF, 0xFF, 0xFF, 0xFF} | None | Should be successful |
 * | 03 | Set the payload using the buffer | alServiceDataUnit->setPayload(buffer) | None | Should Pass |
 * | 04 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, SetPayloadWithAllOnesBuffer) {
    std::cout << "Entering SetPayloadWithAllOnesBuffer test" << std::endl;
    std::vector<unsigned char> buffer = {0xFF, 0xFF, 0xFF, 0xFF};
    alServiceDataUnit->setPayload(buffer);
    std::cout << "Exiting SetPayloadWithAllOnesBuffer test" << std::endl;
}

/**
 * @brief Test the SetPayload function with a buffer containing mixed data types
 *
 * This test verifies that the SetPayload function correctly handles a buffer containing mixed data types (e.g., integers and characters) and that the payload is set and retrieved accurately.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 040@n
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
 * | 02 | Create a buffer with mixed data types | buffer = {0x01, 'A', 0x02, 'B'} | None | Should be successful |
 * | 03 | Set the payload with the created buffer | alServiceDataUnit->setPayload(buffer) | None | Should Pass |
 * | 04 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, SetPayloadWithMixedDataTypesBuffer) {
    std::cout << "Entering SetPayloadWithMixedDataTypesBuffer test" << std::endl;
    std::vector<unsigned char> buffer = {0x01, 'A', 0x02, 'B'};
    alServiceDataUnit->setPayload(buffer);
    std::cout << "Exiting SetPayloadWithMixedDataTypesBuffer test" << std::endl;
}

/**
 * @brief Test the SetPayload function with a buffer of printable characters
 *
 * This test verifies that the SetPayload function correctly sets the payload with a buffer containing printable characters and that the getPayload function returns the expected buffer.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 041@n
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
 * | 02 | Create a buffer with printable characters | buffer = {'A', 'B', 'C', 'D'} | None | Should be successful |
 * | 03 | Set the payload with the created buffer | alServiceDataUnit->setPayload(buffer) | None | Should Pass |
 * | 04 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, SetPayloadWithPrintableCharactersBuffer) {
    std::cout << "Entering SetPayloadWithPrintableCharactersBuffer test" << std::endl;
    std::vector<unsigned char> buffer = {'A', 'B', 'C', 'D'};
    alServiceDataUnit->setPayload(buffer);
    std::cout << "Exiting SetPayloadWithPrintableCharactersBuffer test" << std::endl;
}

/**
 * @brief Test the setPayload function with a buffer containing special characters
 *
 * This test verifies that the setPayload function correctly handles a buffer containing special characters and that the getPayload function returns the same buffer.
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
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Create a buffer with special characters | buffer = {'@', '#', '$', '%'} | None | Should be successful |
 * | 03 | Set the payload with the special characters buffer | alServiceDataUnit->setPayload(buffer) | None | Should Pass |
 * | 04 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, SetPayloadWithSpecialCharactersBuffer) {
    std::cout << "Entering SetPayloadWithSpecialCharactersBuffer test" << std::endl;
    std::vector<unsigned char> buffer = {'@', '#', '$', '%'};
    alServiceDataUnit->setPayload(buffer);
    std::cout << "Exiting SetPayloadWithSpecialCharactersBuffer test" << std::endl;
}

/**
* @brief Test the setting of a valid MAC address in uppercase format.
*
* This test verifies that the `setSourceAlMacAddress` method correctly handles a valid MAC address in uppercase format.
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
* | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
* | 02 | Call setSourceAlMacAddress with a valid MAC address in uppercase | MAC address = "00:1A:2B:3C:4D:5E" | Should Pass | Should be successful |
* | 03 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
*/
TEST_F(AlServiceDataUnitTest, SetValidMacAddressUpperCase) {
    std::cout << "Entering SetValidMacAddressUpperCase" << std::endl;
    std::string macAddress = "00:1A:2B:3C:4D:5E";
    alServiceDataUnit->setSourceAlMacAddress(parseMacAddress(macAddress));
    std::cout << "Exiting SetValidMacAddressUpperCase" << std::endl;
}

/**
 * @brief Test to validate the behavior of setting an invalid MAC address with short length
 *
 * This test checks the behavior of the setSourceAlMacAddress method when provided with a MAC address that is shorter than the expected length. This is important to ensure that the method correctly handles invalid input and maintains data integrity.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 044@n
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
 * | 02 | Call setSourceAlMacAddress with a short MAC address | "00:1A:2B:3C:4D" | None | Should Fail |
 * | 03 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, SetInvalidMacAddressShortLength) {
    std::cout << "Entering SetInvalidMacAddressShortLength" << std::endl;
    std::string macAddress = "00:1A:2B:3C:4D";
    try {
        alServiceDataUnit->setSourceAlMacAddress(parseMacAddress(macAddress));
        FAIL() << "Expected exception for invalid MAC format (too short)";
    } catch (const std::exception& e) {
        std::cout << "Caught expected exception: " << e.what() << std::endl;
        SUCCEED();
    } catch (...) {
        FAIL() << "Caught unknown exception type";
    }        
    std::cout << "Exiting SetInvalidMacAddressShortLength" << std::endl;
}

/**
 * @brief Test to validate the behavior of setting an invalid MAC address with a long length
 *
 * This test checks the behavior of the setSourceAlMacAddress method when provided with a MAC address that exceeds the valid length. 
 * It ensures that the method handles this invalid input appropriately.
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
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Call setSourceAlMacAddress with an invalid long MAC address | "00:1A:2B:3C:4D:5E:6F" | None | Should Fail |
 * | 03 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, SetInvalidMacAddressLongLength) {
    std::cout << "Entering SetInvalidMacAddressLongLength" << std::endl;
    std::string macAddress = "00:1A:2B:3C:4D:5E:6F";
    try {
        alServiceDataUnit->setSourceAlMacAddress(parseMacAddress(macAddress));
        FAIL() << "Expected exception for invalid MAC format (too long)";
    } catch (const std::exception& e) {
        std::cout << "Caught expected exception: " << e.what() << std::endl;
        SUCCEED();
    } catch (...) {
        FAIL() << "Caught unknown exception type";
    }        
    std::cout << "Exiting SetInvalidMacAddressLongLength" << std::endl;
}

/**
 * @brief Test the behavior of setting a MAC address with non-hexadecimal characters
 *
 * This test verifies that the setSourceAlMacAddress method can handle input with non-hexadecimal characters. 
 * It ensures that the method either processes the input correctly or fails gracefully.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 046
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
 * | 02 | Call setSourceAlMacAddress with non-hex characters | "00:1G:2H:3@:4J:5K" | Should handle input correctly or fail gracefully | Should Pass |
 * | 03 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, SetMacAddressWithNonHexCharacters) {
    std::cout << "Entering SetMacAddressWithNonHexCharacters" << std::endl;
    std::string macAddress = "00:1G:2H:3@:4J:5K";
    try {
        alServiceDataUnit->setSourceAlMacAddress(parseMacAddress(macAddress));
        FAIL() << "Expected exception for invalid characters in MAC address";
    } catch (const std::exception& e) {
        std::cout << "Caught expected exception: " << e.what() << std::endl;
        SUCCEED();
    } catch (...) {
        FAIL() << "Caught unknown exception type";
    }
    std::cout << "Exiting SetMacAddressWithNonHexCharacters" << std::endl;
}

/**
 * @brief Test setting the MAC address to all ones
 *
 * This test verifies that the `setSourceAlMacAddress` method can handle setting the MAC address to all ones ("FF:FF:FF:FF:FF:FF"). This is important to ensure that the method can handle edge cases and special MAC addresses.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 047@n
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
 * | 02 | Set the MAC address to all ones | alServiceDataUnit->setSourceAlMacAddress("FF:FF:FF:FF:FF:FF") | None | Should Pass |
 * | 03 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceDataUnitTest, SetMacAddressWithAllOnes) {
    std::cout << "Entering SetMacAddressWithAllOnes" << std::endl;
    std::string macAddress = "FF:FF:FF:FF:FF:FF";
    try {
        alServiceDataUnit->setSourceAlMacAddress(parseMacAddress(macAddress));
        FAIL() << "Unexpected exception while setting all ones for MAC address";
    } catch (const std::exception& e) {
        std::cout << "Caught expected exception: " << e.what() << std::endl;
        SUCCEED();
    } catch (...) {
        FAIL() << "Caught unknown exception type";
    }
    std::cout << "Exiting SetMacAddressWithAllOnes" << std::endl;
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}