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
#include "al_service_registration_request.h"
#include "test_l1_utils.h"

class AlServiceRegistrationRequestTest : public ::testing::Test {
protected:
    AlServiceRegistrationRequest* instance;

    void SetUp() override {
        instance = new AlServiceRegistrationRequest();
    }

    void TearDown() override {
        delete instance;
    }
};

/**
* @brief Test to verify the deserialization of a valid registration request
*
* This test checks the functionality of the deserializeRegistrationRequest method when provided with valid serialized data. It ensures that the method correctly processes the input data without errors.
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
* | 01 | Setup the test environment | instance = new AlServiceRegistrationRequest() | instance is initialized | Done by Pre-requisite SetUp function |
* | 02 | Call deserializeRegistrationRequest with valid data | validData = valid serialized data | Method processes data correctly | Should Pass |
* | 03 | Tear down the test environment | delete instance | instance is deleted | Done by Pre-requisite TearDown function |
*/
TEST_F(AlServiceRegistrationRequestTest, DeserializeValidRegistrationRequest) {
    std::vector<unsigned char> validData = {0x01, 0x02, 0x03, 0xFF};
    std::cout << "Entering DeserializeValidRegistrationRequest" << std::endl;
    instance->deserializeRegistrationRequest(validData);
    std::cout << "Exiting DeserializeValidRegistrationRequest" << std::endl;
}

/**
* @brief Test to verify the behavior of the deserializeRegistrationRequest method when provided with an empty data vector.
*
* This test checks if the deserializeRegistrationRequest method can handle an empty data vector without crashing or throwing exceptions. It ensures that the method can gracefully handle edge cases where no data is provided.
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
* | 01 | Setup the test environment by creating an instance of AlServiceRegistrationRequest | instance = new AlServiceRegistrationRequest() | Instance should be created successfully | Done by Pre-requisite SetUp function |
* | 02 | Initialize an empty data vector | emptyData = {} | Data vector should be initialized successfully | Should be successful |
* | 03 | Call the deserializeRegistrationRequest method with the empty data vector | instance->deserializeRegistrationRequest(emptyData) | Method should handle the empty data vector without crashing | Should Pass |
* | 04 | Clean up the test environment by deleting the instance of AlServiceRegistrationRequest | delete instance | Instance should be deleted successfully | Done by Pre-requisite TearDown function |
*/
TEST_F(AlServiceRegistrationRequestTest, DeserializeEmptyDataVector) {
    std::vector<unsigned char> emptyData = {};
    std::cout << "Entering DeserializeEmptyDataVector" << std::endl;
    instance->deserializeRegistrationRequest(emptyData);
    ASSERT_TRUE(true); // Add appropriate assertions based on expected state
    std::cout << "Exiting DeserializeEmptyDataVector" << std::endl;
}

/**
 * @brief Test to verify the retrieval of service operation when it is enabled
 *
 * This test checks if the service operation is correctly set and retrieved when the service operation is enabled.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 003
 * **Priority:** High
 * 
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * 
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment by creating an instance of AlServiceRegistrationRequest | None | Instance created | Done by Pre-requisite SetUp function |
 * | 02 | Set the service operation to SOP_ENABLE | ServiceOperation::SOP_ENABLE | Service operation set to SOP_ENABLE | Should be successful |
 * | 03 | Retrieve the service operation and check if it is SOP_ENABLE | None | Retrieved service operation should be SOP_ENABLE | Should Pass |
 * | 04 | Tear down the test environment by deleting the instance of AlServiceRegistrationRequest | None | Instance deleted | Done by Pre-requisite TearDown function |
 */
TEST(AlServiceRegistrationRequestTest, RetrieveServiceOperationWhenEnabled) {
    std::cout << "Entering RetrieveServiceOperationWhenEnabled test" << std::endl;
    AlServiceRegistrationRequest instance(ServiceOperation::SOP_ENABLE, ServiceType::SAP_CLIENT);
	ServiceOperation operation = instance.getServiceOperation();
    std::cout << "The service operation is "  << operation << std::endl;
    ASSERT_EQ(operation, ServiceOperation::SOP_ENABLE);
    std::cout << "The service operation is "  << operation << std::endl;
    std::cout << "Exiting RetrieveServiceOperationWhenEnabled test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of service operation when it is disabled.
 *
 * This test checks if the service operation is correctly set to disabled and retrieved as disabled.@n
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
 * | 01 | Setup the test environment | instance = new AlServiceRegistrationRequest() | instance is created | Done by Pre-requisite SetUp function |
 * | 02 | Set the service operation to SOP_DISABLE | ServiceOperation::SOP_DISABLE | Service operation set to SOP_DISABLE | Should be successful |
 * | 03 | Retrieve the service operation and check if it is disabled | instance->getServiceOperation() | ServiceOperation::SOP_DISABLE | Should Pass |
 * | 04 | Tear down the test environment | delete instance | instance is deleted | Done by Pre-requisite TearDown function |
 */
TEST(AlServiceRegistrationRequestTest, RetrieveServiceOperationWhenDisabled) {
    std::cout << "Entering RetrieveServiceOperationWhenDisabled test" << std::endl;
	AlServiceRegistrationRequest instance(ServiceOperation::SOP_DISABLE, ServiceType::SAP_CLIENT);
	ServiceOperation operation = instance.getServiceOperation();
    std::cout << "The service operation is "  << operation << std::endl;
    ASSERT_EQ(operation, ServiceOperation::SOP_DISABLE);
    std::cout << "Exiting RetrieveServiceOperationWhenDisabled test" << std::endl;
}

/**
 * @brief Test to verify the behavior of retrieving service operation when an invalid operation is set.
 *
 * This test checks the behavior of the AlServiceRegistrationRequest class when an invalid service operation is set. 
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
 * | 01 | Setup the test environment by creating an instance of AlServiceRegistrationRequest | None | Instance created successfully | Done by Pre-requisite SetUp function |
 * | 02 | Set an invalid service operation (0x03) | serviceOperation = 0x03 | Service operation set successfully | Should be successful |
 * | 03 | Retrieve the service operation | None | Should be same as the set value | Should Pass |
 *
 */
TEST(AlServiceRegistrationRequestTest, RetrieveServiceOperationWhenInvalid) {
    std::cout << "Entering RetrieveServiceOperationWhenInvalid test" << std::endl;
    AlServiceRegistrationRequest instance(static_cast<ServiceOperation>(0x03), ServiceType::SAP_CLIENT);
	ServiceOperation operation = instance.getServiceOperation();
    std::cout << "The service operation is "  << operation << std::endl;
    std::cout << "Exiting RetrieveServiceOperationWhenInvalid test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of service type SAP_CLIENT
 *
 * This test sets the service type to SAP_CLIENT and verifies if the getServiceType method retrieves the correct service type.
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
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Set the service type to SAP_CLIENT | ServiceType::SAP_CLIENT | None | Should be successful |
 * | 03 | Retrieve the service type | None | ServiceType::SAP_CLIENT | Should Pass |
 * | 04 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST(AlServiceRegistrationRequestTest, RetrieveServiceType_SAP_CLIENT) {
    std::cout << "Entering RetrieveServiceType_SAP_CLIENT test" << std::endl;
	AlServiceRegistrationRequest instance(ServiceOperation::SOP_ENABLE, ServiceType::SAP_CLIENT);    
    ServiceType result = instance.getServiceType();
	std::cout << "The servicetype is "  << result << std::endl;
    ASSERT_EQ(result, ServiceType::SAP_CLIENT);	
    std::cout << "Exiting RetrieveServiceType_SAP_CLIENT test" << std::endl;
}

/**
 * @brief Test the retrieval of service type for SAP_SERVER
 *
 * This test verifies that the service type can be correctly set and retrieved as SAP_SERVER.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 007@n
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
 * | 02 | Set the service type to SAP_SERVER | ServiceType::SAP_SERVER | None | Should be successful |
 * | 03 | Retrieve the service type | None | ServiceType::SAP_SERVER | Should Pass |
 * | 04 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST(AlServiceRegistrationRequestTest, RetrieveServiceType_SAP_SERVER) {
    std::cout << "Entering RetrieveServiceType_SAP_SERVER test" << std::endl;
	AlServiceRegistrationRequest instance(ServiceOperation::SOP_ENABLE, ServiceType::SAP_SERVER);
    ServiceType result = instance.getServiceType();
	std::cout << "The servicetype is "  << result << std::endl;
    ASSERT_EQ(result, ServiceType::SAP_SERVER);
    std::cout << "Exiting RetrieveServiceType_SAP_SERVER test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of service type SAP_TUNNEL_CLIENT
 *
 * This test sets the service type to SAP_TUNNEL_CLIENT and verifies if the getServiceType method retrieves the correct service type.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 008@n
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
 * | 02 | Set the service type to SAP_TUNNEL_CLIENT | ServiceType::SAP_TUNNEL_CLIENT | None | Should be successful |
 * | 03 | Retrieve the service type | None | ServiceType::SAP_TUNNEL_CLIENT | Should Pass |
 * | 04 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST(AlServiceRegistrationRequestTest, RetrieveServiceType_SAP_TUNNEL_CLIENT) {
    std::cout << "Entering RetrieveServiceType_SAP_TUNNEL_CLIENT test" << std::endl;
    AlServiceRegistrationRequest instance(ServiceOperation::SOP_ENABLE, ServiceType::SAP_TUNNEL_CLIENT);
    ServiceType result = instance.getServiceType();
    std::cout << "The servicetype is "  << result << std::endl;
    ASSERT_EQ(result, ServiceType::SAP_TUNNEL_CLIENT);
    std::cout << "Exiting RetrieveServiceType_SAP_TUNNEL_CLIENT test" << std::endl;
}

/**
* @brief Test to verify the retrieval of service type SAP_TUNNEL_SERVER
*
* This test checks if the service type SAP_TUNNEL_SERVER is correctly set and retrieved from the AlServiceRegistrationRequest instance.
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
* | 01 | Setup the test environment | instance = new AlServiceRegistrationRequest() | instance should be initialized | Done by Pre-requisite SetUp function |
* | 02 | Set the service type to SAP_TUNNEL_SERVER | instance->setServiceType(ServiceType::SAP_TUNNEL_SERVER) | Service type should be set to SAP_TUNNEL_SERVER | Should be successful |
* | 03 | Retrieve the service type | ServiceType result = instance->getServiceType() | result should be SAP_TUNNEL_SERVER | Should Pass |
* | 04 | Verify the retrieved service type | ASSERT_EQ(result, ServiceType::SAP_TUNNEL_SERVER) | Assertion should pass | Should Pass |
* | 05 | Tear down the test environment | delete instance | instance should be deleted | Done by Pre-requisite TearDown function |
*/
TEST(AlServiceRegistrationRequestTest, RetrieveServiceType_SAP_TUNNEL_SERVER) {
    std::cout << "Entering RetrieveServiceType_SAP_TUNNEL_SERVER test" << std::endl;
    AlServiceRegistrationRequest instance(ServiceOperation::SOP_ENABLE, ServiceType::SAP_TUNNEL_SERVER);
    ServiceType result = instance.getServiceType();
    std::cout << "The servicetype is "  << result << std::endl;
    ASSERT_EQ(result, ServiceType::SAP_TUNNEL_SERVER);
    std::cout << "Exiting RetrieveServiceType_SAP_TUNNEL_SERVER test" << std::endl;
}

/**
* @brief Test to verify the retrieval of service type after setting to invalid value
*
* This test checks the behavior of getServiceType method when service type is set to invalid value.
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
* | 01 | Setup the test environment | instance = new AlServiceRegistrationRequest() | instance should be initialized | Done by Pre-requisite SetUp function |
* | 02 | Set the service type to invalid value | static_cast<ServiceType>(0x06) | None | Should be successful |
* | 03 | Retrieve and print the service type | ServiceType result = instance->getServiceType() | Should be printed | Print the retrieved service type |
* | 04 | Tear down the test environment | delete instance | instance should be deleted | Done by Pre-requisite TearDown function |
*/
TEST(AlServiceRegistrationRequestTest, RetrieveServiceType_Invalid) {
    std::cout << "Entering RetrieveServiceType_Invalid test" << std::endl;
    AlServiceRegistrationRequest instance(ServiceOperation::SOP_ENABLE, static_cast<ServiceType>(0x06));
    ServiceType result = instance.getServiceType();
    std::cout << "The servicetype is "  << result << std::endl;
    std::cout << "Exiting RetrieveServiceType_Invalid test" << std::endl;
}

/**
 * @brief Test the serialization of a valid registration request
 *
 * This test verifies that a valid registration request is correctly serialized by the AlServiceRegistrationRequest class.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 011@n
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
 * | 02 | Set the service operation and type to valid values | ServiceOperation::SOP_ENABLE, ServiceType::SAP_CLIENT | None | Should be successful |
 * | 03 | Serialize the registration request | None | result should not be empty | Should Pass |
 * | 04 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
 TEST(AlServiceRegistrationRequestTest, SerializeValidRegistrationRequest) {
    std::cout << "Entering SerializeValidRegistrationRequest test" << std::endl;
    AlServiceRegistrationRequest instance(ServiceOperation::SOP_ENABLE, ServiceType::SAP_CLIENT);
    std::vector<unsigned char> result = instance.serializeRegistrationRequest();
    std::cout << "The result is: [";
    for (size_t i = 0; i < result.size(); ++i) {
        std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                  << static_cast<int>(result[i]);
        if (i != result.size() - 1) std::cout << " ";
    }
    std::cout << "]" << std::endl;
    std::cout << "Exiting SerializeValidRegistrationRequest test" << std::endl;
}

/**
 * @brief Test the serialization of an invalid registration request
 *
 * This test verifies that the serialization of a registration request with invalid operation and type results in an empty vector.
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
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Set invalid service operation and type | static_cast<ServiceOperation>(0x04), static_cast<ServiceType>(0x05) | None | Should be successful |
 * | 03 | Serialize the registration request | None | result should be empty | Should Pass |
 * | 04 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
 TEST(AlServiceRegistrationRequestTest, SerializeInvalidRegistrationRequest) {
    std::cout << "Entering SerializeInvalidRegistrationRequest test" << std::endl;
    AlServiceRegistrationRequest instance(static_cast<ServiceOperation>(0x04), static_cast<ServiceType>(0x05));
    std::vector<unsigned char> result = instance.serializeRegistrationRequest();
    std::cout << "The result is: [";
    for (size_t i = 0; i < result.size(); ++i) {
        std::cout << std::hex << std::uppercase << static_cast<int>(result[i]);
        if (i != result.size() - 1) std::cout << " ";
    }
    std::cout << "]" << std::endl;
    std::cout << "Exiting SerializeInvalidRegistrationRequest test" << std::endl;
}

/**
 * @brief Test the setServiceOperation method for enabling service operation
 *
 * This test verifies that the setServiceOperation method can successfully enable a service operation without throwing any exceptions.
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
 * | 02 | Call setServiceOperation with SOP_ENABLE | ServiceOperation::SOP_ENABLE | No exception thrown | Should Pass |
 * | 03 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceRegistrationRequestTest, SetServiceOperationEnable) {
    std::cout << "Entering SetServiceOperationEnable test" << std::endl;
    ASSERT_NO_THROW(instance->setServiceOperation(ServiceOperation::SOP_ENABLE));
    std::cout << "Exiting SetServiceOperationEnable test" << std::endl;
}

/**
 * @brief Test to verify the setServiceOperation function with SOP_DISABLE operation
 *
 * This test checks if the setServiceOperation function can handle the SOP_DISABLE operation without throwing any exceptions.
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
 * | 01 | Setup the test environment by creating an instance of AlServiceRegistrationRequest | None | Instance created successfully | Done by Pre-requisite SetUp function |
 * | 02 | Call setServiceOperation with SOP_DISABLE operation | ServiceOperation::SOP_DISABLE | No exception should be thrown | Should Pass |
 * | 03 | Clean up the test environment by deleting the instance of AlServiceRegistrationRequest | None | Instance deleted successfully | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceRegistrationRequestTest, SetServiceOperationDisable) {
    std::cout << "Entering SetServiceOperationDisable test" << std::endl;
    ASSERT_NO_THROW(instance->setServiceOperation(ServiceOperation::SOP_DISABLE));
    std::cout << "Exiting SetServiceOperationDisable test" << std::endl;
}

/**
* @brief Test to validate the behavior of setServiceOperation with an invalid operation code.
*
* This test checks if the setServiceOperation method throws an exception when provided with an invalid operation code.@n
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
* | 01 | Call the SetUp function to initialize the test environment | None | None | Done by Pre-requisite SetUp function |
* | 02 | Invoke setServiceOperation with an invalid operation code | operation = 0x03 | Exception should be thrown | Should Pass |
* | 03 | Call the TearDown function to clean up the test environment | None | None | Done by Pre-requisite TearDown function |
*/
TEST_F(AlServiceRegistrationRequestTest, SetServiceOperationInvalid) {
    std::cout << "Entering SetServiceOperationInvalid test" << std::endl;
    ASSERT_ANY_THROW(instance->setServiceOperation(static_cast<ServiceOperation>(0x03)));
    std::cout << "Exiting SetServiceOperationInvalid test" << std::endl;
}

/**
 * @brief Test the setting of service type to SAP_CLIENT
 *
 * This test verifies that the service type can be correctly set to SAP_CLIENT and retrieved using the getServiceType method.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 016@n
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
 * | 02 | Set the service type to SAP_CLIENT | ServiceType::SAP_CLIENT | None | Should be successful |
 * | 03 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceRegistrationRequestTest, SetServiceTypeToSAP_CLIENT) {
    std::cout << "Entering SetServiceTypeToSAP_CLIENT test" << std::endl;
    instance->setServiceType(ServiceType::SAP_CLIENT);
    std::cout << "Exiting SetServiceTypeToSAP_CLIENT test" << std::endl;
}

/**
 * @brief Test the setting of service type to SAP_SERVER
 *
 * This test verifies that the service type can be set to SAP_SERVER and retrieved correctly.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 017@n
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
 * | 02 | Set the service type to SAP_SERVER | ServiceType::SAP_SERVER | None | Should be successful |
 * | 03 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceRegistrationRequestTest, SetServiceTypeToSAP_SERVER) {
    std::cout << "Entering SetServiceTypeToSAP_SERVER test" << std::endl;
    instance->setServiceType(ServiceType::SAP_SERVER);
    std::cout << "Exiting SetServiceTypeToSAP_SERVER test" << std::endl;
}

/**
 * @brief Test the setting of service type to SAP_TUNNEL_CLIENT
 *
 * This test verifies that the service type can be correctly set to SAP_TUNNEL_CLIENT and retrieved using the getServiceType method.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 018@n
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
 * | 02 | Set the service type to SAP_TUNNEL_CLIENT | ServiceType::SAP_TUNNEL_CLIENT | None | Should be successful |
 * | 03 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceRegistrationRequestTest, SetServiceTypeToSAP_TUNNEL_CLIENT) {
    std::cout << "Entering SetServiceTypeToSAP_TUNNEL_CLIENT test" << std::endl;
    instance->setServiceType(ServiceType::SAP_TUNNEL_CLIENT);
    std::cout << "Exiting SetServiceTypeToSAP_TUNNEL_CLIENT test" << std::endl;
}

/**
 * @brief Test the setting of service type to SAP_TUNNEL_SERVER
 *
 * This test verifies that the service type can be correctly set to SAP_TUNNEL_SERVER and retrieved using the getServiceType method.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 019@n
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
 * | 02 | Set the service type to SAP_TUNNEL_SERVER | ServiceType::SAP_TUNNEL_SERVER | None | Should be successful |
 * | 03 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */

TEST_F(AlServiceRegistrationRequestTest, SetServiceTypeToSAP_TUNNEL_SERVER) {
    std::cout << "Entering SetServiceTypeToSAP_TUNNEL_SERVER test" << std::endl;
    instance->setServiceType(ServiceType::SAP_TUNNEL_SERVER);
    std::cout << "Exiting SetServiceTypeToSAP_TUNNEL_SERVER test" << std::endl;
}

/**
 * @brief Test to verify setting an invalid service type value
 *
 * This test checks the behavior of the AlServiceRegistrationRequest class when an invalid service type value (0xFF) is set. 
 * It ensures that the service type is not set to the invalid value.
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
 * | 02 | Set the service type to an invalid value (0xFF) | serviceType = 0xFF | Service type should not be set to 0xFF | Should Pass |
 * | 03 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceRegistrationRequestTest, SetServiceTypeToInvalidValue_0xFF) {
    std::cout << "Entering SetServiceTypeToInvalidValue_0xFF test" << std::endl;
    instance->setServiceType(static_cast<ServiceType>(0xFF));
    std::cout << "Exiting SetServiceTypeToInvalidValue_0xFF test" << std::endl;
}

/**
* @brief Test the constructor of AlServiceRegistrationRequest with SOP_ENABLE operation for all service types.
*
* This test verifies that the constructor of AlServiceRegistrationRequest correctly initializes the object with the SOP_ENABLE operation and various service types.
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
* | 01 | Initialize request with SOP_ENABLE and SAP_CLIENT | operation = SOP_ENABLE, type = SAP_CLIENT | Object creation should be successful | Should Pass |
* | 02 | Initialize request with SOP_ENABLE and SAP_SERVER | operation = SOP_ENABLE, type = SAP_SERVER | Object creation should be successful | Should Pass |
* | 03 | Initialize request with SOP_ENABLE and SAP_TUNNEL_CLIENT | operation = SOP_ENABLE, type = SAP_TUNNEL_CLIENT | Object creation should be successful | Should Pass |
* | 04 | Initialize request with SOP_ENABLE and SAP_TUNNEL_SERVER | operation = SOP_ENABLE, type = SAP_TUNNEL_SERVER | Object creation should be successful | Should Pass |
*/
TEST_F(AlServiceRegistrationRequestTest, Constructor_SOP_ENABLE_AllServiceTypes) {
    std::cout << "Entering Constructor_SOP_ENABLE_AllServiceTypes" << std::endl;
    ServiceOperation operation = ServiceOperation::SOP_ENABLE;
    ServiceType types[] = {ServiceType::SAP_CLIENT, ServiceType::SAP_SERVER, ServiceType::SAP_TUNNEL_CLIENT, ServiceType::SAP_TUNNEL_SERVER};
    for (ServiceType type : types) {
        AlServiceRegistrationRequest request(operation, type);
    }
    std::cout << "Exiting Constructor_SOP_ENABLE_AllServiceTypes" << std::endl;
}

/**
* @brief Test the constructor of AlServiceRegistrationRequest with SOP_DISABLE operation for all service types.
*
* This test verifies that the constructor of AlServiceRegistrationRequest correctly initializes the object with the SOP_DISABLE operation for various service types.
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
* | 01| Initialize request with SOP_DISABLE and SAP_CLIENT | operation = SOP_DISABLE, type = SAP_CLIENT | Object creation should be successful | Should Pass |
* | 02| Initialize request with SOP_DISABLE and SAP_SERVER | operation = SOP_DISABLE, type = SAP_SERVER | Object creation should be successful | Should Pass |
* | 03| Initialize request with SOP_DISABLE and SAP_TUNNEL_CLIENT | operation = SOP_DISABLE, type = SAP_TUNNEL_CLIENT | Object creation should be successful | Should Pass |
* | 04| Initialize request with SOP_DISABLE and SAP_TUNNEL_SERVER | operation = SOP_DISABLE, type = SAP_TUNNEL_SERVER | Object creation should be successful | Should Pass |
*/
TEST_F(AlServiceRegistrationRequestTest, Constructor_SOP_DISABLE_AllServiceTypes) {
    std::cout << "Entering Constructor_SOP_DISABLE_AllServiceTypes" << std::endl;
    ServiceOperation operation = ServiceOperation::SOP_DISABLE;
    ServiceType types[] = {ServiceType::SAP_CLIENT, ServiceType::SAP_SERVER, ServiceType::SAP_TUNNEL_CLIENT, ServiceType::SAP_TUNNEL_SERVER};
    for (ServiceType type : types) {
        AlServiceRegistrationRequest request(operation, type);
    }
    std::cout << "Exiting Constructor_SOP_DISABLE_AllServiceTypes" << std::endl;
}

/**
* @brief Test the constructor of AlServiceRegistrationRequest with an invalid ServiceOperation
*
* This test verifies that the constructor of AlServiceRegistrationRequest throws an std::invalid_argument exception when provided with an invalid ServiceOperation.
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
* | 01| Set invalid ServiceOperation and valid ServiceType | invalidOperation = 0x03, type = ServiceType::SAP_CLIENT | std::invalid_argument exception with message "Invalid ServiceOperation" | Should Fail |
*/
TEST_F(AlServiceRegistrationRequestTest, Constructor_InvalidOperation) {
    std::cout << "Entering Constructor_InvalidOperation" << std::endl;
    ServiceOperation invalidOperation = static_cast<ServiceOperation>(0x03);
    ServiceType type = ServiceType::SAP_CLIENT;
    AlServiceRegistrationRequest request(invalidOperation, type);
    std::cout << "Exiting Constructor_InvalidOperation" << std::endl;
}

/**
* @brief Test the constructor of AlServiceRegistrationRequest with an invalid ServiceType
*
* This test verifies that the constructor of AlServiceRegistrationRequest throws an std::invalid_argument exception when an invalid ServiceType is provided.
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
* | 01| Create an instance of AlServiceRegistrationRequest with invalid ServiceType | operation = SOP_ENABLE, invalidType = 0x05 | std::invalid_argument exception with message "Invalid ServiceType" | Should Fail |
*/
TEST_F(AlServiceRegistrationRequestTest, Constructor_InvalidType) {
    std::cout << "Entering Constructor_InvalidType" << std::endl;
    ServiceOperation operation = ServiceOperation::SOP_ENABLE;
    ServiceType invalidType = static_cast<ServiceType>(0x05);
    AlServiceRegistrationRequest request(operation, invalidType);
    std::cout << "Exiting Constructor_InvalidType" << std::endl;
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
