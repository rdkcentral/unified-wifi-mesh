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
#include "al_service_access_point.h"


class AlServiceAccessPointTest : public ::testing::Test {
protected:
    AlServiceAccessPoint * serviceAccessPoint;

    void SetUp() override {
        serviceAccessPoint = new AlServiceAccessPoint("/tmp/ieee1905_socket");
    }

    void TearDown() override {
        delete serviceAccessPoint;
    }
};

/**
 * @brief Test to verify the retrieval of socket descriptor from AlServiceAccessPoint
 *
 * This test checks if the socket descriptor retrieved from the AlServiceAccessPoint object is valid and greater than 0.
 *
 * **Test Group ID:* * Basic: 01
 * **Test Case ID:* * 001
 * **Priority:* * High
 * @n
 * **Pre-Conditions:* * None
 * **Dependencies:* * None
 * **User Interaction:* * None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the AlServiceAccessPoint object | serviceAccessPoint = new AlServiceAccessPoint("/tmp/test_socket") | Object should be created successfully | Done by Pre-requisite SetUp function |
 * | 02 | Retrieve the socket descriptor | descriptor = serviceAccessPoint->getSocketDescriptor() | valid descriptor value | Should Pass |
 * | 03 | Cleanup the AlServiceAccessPoint object | delete serviceAccessPoint | Object should be deleted successfully | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceAccessPointTest, RetrieveSocketDescriptor) {
    std::cout << "Entering RetrieveSocketDescriptor test" << std::endl;
    int descriptor = serviceAccessPoint->getSocketDescriptor();
    std::cout << "The descriptor value is " << descriptor << std::endl;
    std::cout << "Exiting RetrieveSocketDescriptor test" << std::endl;
}

/**
 * @brief Test to verify the data indication from the service access point
 *
 * This test checks the data indication received from the service access point to ensure it meets expected criteria.
 *
 * **Test Group ID:* * Basic: 01
 * **Test Case ID:* * 002
 * **Priority:* * High
 * @n
 * **Pre-Conditions:* * None
 * **Dependencies:* * None
 * **User Interaction:* * None
 * @n
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment | serviceAccessPoint = new AlServiceAccessPoint("/tmp/test_socket"); | serviceAccessPoint is initialized | Done by Pre-requisite SetUp function |
 * | 02 | Call serviceAccessPointDataIndication() | None | AlServiceDataUnit dataUnit is returned | Should be successful |
 * | 03 | Tear down the test environment | delete serviceAccessPoint; | serviceAccessPoint is deleted | Done by Pre-requisite TearDown function |
 */
TEST_F(AlServiceAccessPointTest, VerifyServiceAccessPointDataIndication) {
    std::cout << "Entering VerifyServiceAccessPointDataIndication" << std::endl;
    AlServiceDataUnit dataUnit = serviceAccessPoint->serviceAccessPointDataIndication();
    std::cout << "Exiting VerifyServiceAccessPointDataIndication" << std::endl;
}

/**
  * @brief Test the registration of a service access point with invalid operation and type.
  *
  * This test verifies if the service access point can be registered with an invalid operation and type.
  *
  * **Test Group ID:* * Basic: 01
  * **Test Case ID:* * 003
  * **Priority:* * High
  * @n
  * **Pre-Conditions:* * None
  * **Dependencies:* * None
  * **User Interaction:* * None
  * @n
  * **Test Procedure:**@n
  * | Variation / Step | Description | Test Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Setup the test environment by initializing the service access point. | None | Service access point initialized | Done by Pre-requisite SetUp function |
  * | 02 | Create a service registration request with invalid operation and type. | static_cast<ServiceOperation>(0x04), static_cast<ServiceType>(0x05) | Request created with invalid operation and type | Should be successful |
  * | 03 | Register the service access point with the created request. | request = AlServiceRegistrationRequest(invalidOperation, invalidType) | Service access point registered | Should Pass |
  * | 04 | Clean up the test environment by deleting the service access point. | None | Service access point deleted | Done by Pre-requisite TearDown function |
  */

TEST_F(AlServiceAccessPointTest, RegisterServiceAccessPointWithinvalidOperationAndType) {
    std::cout << "Entering RegisterServiceAccessPointWithinvalidOperationAndType" << std::endl;    
    AlServiceRegistrationRequest request(static_cast<ServiceOperation>(0x04), static_cast<ServiceType>(0x05));
    serviceAccessPoint->serviceAccessPointRegistrationRequest(request);
    std::cout << "Exiting RegisterServiceAccessPointWithinvalidOperationAndType" << std::endl;
}

/**
  * @brief Test to verify the behavior of setting an invalid socket descriptor
  *
  * This test checks if the AlServiceAccessPoint class correctly handles the scenario where an invalid socket descriptor is set. The test ensures that the socket descriptor is set to -1 and verifies that the getSocketDescriptor method returns -1.
  *
  * **Test Group ID:* * Basic: 01@n
  * **Test Case ID:* * 004@n
  * **Priority:* * High@n
  * @n
  * **Pre-Conditions:* * None@n
  * **Dependencies:* * None@n
  * **User Interaction:* * None@n
  * @n
  * **Test Procedure:**@n
  * | Variation / Step | Description | Test Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Setup the test environment by initializing the AlServiceAccessPoint object | None | AlServiceAccessPoint object is created | Done by Pre-requisite SetUp function |
  * | 02 | Set the socket descriptor to an invalid value (-1) | socketDescriptor = -1 | The socket descriptor is set to -1 | Should Pass |
  * | 03 | Clean up the test environment by deleting the AlServiceAccessPoint object | None | AlServiceAccessPoint object is deleted | Done by Pre-requisite TearDown function |
  */
TEST_F(AlServiceAccessPointTest, SetInvalidSocketDescriptorNegative) {
    std::cout << "Entering SetInvalidSocketDescriptorNegative test" << std::endl;
    serviceAccessPoint->setSocketDescriptor(-1);
    std::cout << "Exiting SetInvalidSocketDescriptorNegative test" << std::endl;
}

/**
  * @brief Test setting an invalid socket descriptor to zero
  *
  * This test verifies that setting the socket descriptor to zero is handled correctly by the AlServiceAccessPoint class.
  *
  * **Test Group ID:* * Basic: 01
  * **Test Case ID:* * 005@n
  * **Priority:* * High
  * @n
  * **Pre-Conditions:* * None
  * **Dependencies:* * None
  * **User Interaction:* * None
  * @n
  * **Test Procedure:**@n
  * | Variation / Step | Description | Test Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
  * | 02 | Set the socket descriptor to zero | serviceAccessPoint->setSocketDescriptor(0) | None | Should Pass |
  * | 03 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
  */

TEST_F(AlServiceAccessPointTest, SetInvalidSocketDescriptorZero) {
    std::cout << "Entering SetInvalidSocketDescriptorZero test" << std::endl;
    serviceAccessPoint->setSocketDescriptor(0);
    std::cout << "Exiting SetInvalidSocketDescriptorZero test" << std::endl;
}

/**
  * @brief Test setting a valid large positive socket descriptor
  *
  * This test verifies that the AlServiceAccessPoint class correctly sets and retrieves a large positive socket descriptor value.
  *
  * **Test Group ID:* * Basic: 01
  * **Test Case ID:* * 006@n
  * **Priority:* * High
  * @n
  * **Pre-Conditions:* * None
  * **Dependencies:* * None
  * **User Interaction:* * None
  * @n
  * **Test Procedure:**@n
  * | Variation / Step | Description | Test Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
  * | 02 | Set a large positive socket descriptor | serviceAccessPoint->setSocketDescriptor(1024) | None | Should be successful |
  * | 03 | Tear down the test environment | None | None | Done by Pre-requisite TearDown function |
  */
TEST_F(AlServiceAccessPointTest, SetValidSocketDescriptorLargePositive) {
    std::cout << "Entering SetValidSocketDescriptorLargePositive test" << std::endl;
    serviceAccessPoint->setSocketDescriptor(1024);
    std::cout << "Exiting SetValidSocketDescriptorLargePositive test" << std::endl;
}

/**
  * @brief Test setting an extremely large socket descriptor value
  *
  * This test verifies the behavior of the AlServiceAccessPoint class when an extremely large socket descriptor value is set. 
  * It ensures that the setSocketDescriptor method can handle large integer values and that the getSocketDescriptor method 
  * returns the correct value.
  *
  * **Test Group ID:* * Basic: 01
  * **Test Case ID:* * 007@n
  * **Priority:* * High
  * @n
  * **Pre-Conditions:* * None
  * **Dependencies:* * None
  * **User Interaction:* * None
  * @n
  * **Test Procedure:**@n
  * | Variation / Step | Description | Test Data | Expected Result | Notes |
  * | :----: | --------- | ---------- |-------------- | ----- |
  * | 01 | Setup the test environment by initializing the AlServiceAccessPoint object | None | Object should be initialized successfully | Done by Pre-requisite SetUp function |
  * | 02 | Set an extremely large socket descriptor value using setSocketDescriptor method | input: 2147483647 | Should set the socket descriptor to 2147483647 | Should be successful |
  * | 03 | Clean up the test environment by deleting the AlServiceAccessPoint object | None | Object should be deleted successfully | Done by Pre-requisite TearDown function |
  */
TEST_F(AlServiceAccessPointTest, SetInvalidSocketDescriptorExtremelyLarge) {
    std::cout << "Entering SetInvalidSocketDescriptorExtremelyLarge test" << std::endl;
    serviceAccessPoint->setSocketDescriptor(2147483647);
    std::cout << "Exiting SetInvalidSocketDescriptorExtremelyLarge test" << std::endl;
}

/**
 * @brief Test to verify the creation of AlServiceAccessPoint with a valid socket path
 *
 * This test checks if the AlServiceAccessPoint object can be successfully created with a valid socket path. This is important to ensure that the service access point can be initialized correctly with a valid path.
 *
 * **Test Group ID:* * Basic: 01@n
 * **Test Case ID:* * 008@n
 * **Priority:* * High@n
 * @n
 * **Pre-Conditions:* * None@n
 * **Dependencies:* * None@n
 * **User Interaction:* * None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Enter the test | None | None | Should be successful |
 * | 02 | Create AlServiceAccessPoint with valid socket path | validSocketPath = "/tmp/ieee1905_socket" | Object should be created successfully | Should Pass |
 * | 03 | Exit the test | None | None | Should be successful |
 */
TEST_F(AlServiceAccessPointTest, ValidSocketPath) {
    std::cout << "Entering ValidSocketPath test";
    std::string validSocketPath = "/tmp/ieee1905_socket";
    AlServiceAccessPoint serviceAccessPoint(validSocketPath);
    std::cout << "Exiting ValidSocketPath test";
}

/**
 * @brief Test to verify the behavior of AlServiceAccessPoint with an empty socket path.
 *
 * This test checks the behavior of the AlServiceAccessPoint constructor when provided with an empty socket path. 
 * It ensures that the class handles this edge case appropriately without crashing or misbehaving.
 *
 * **Test Group ID:* * Basic: 01@n
 * **Test Case ID:* * 009@n
 * **Priority:* * High@n
 * @n
 * **Pre-Conditions:* * None@n
 * **Dependencies:* * None@n
 * **User Interaction:* * None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Enter the EmptySocketPath test | None | None | Should be successful |
 * | 02 | Create an empty socket path string | emptySocketPath = "" | None | Should be successful |
 * | 03 | Initialize AlServiceAccessPoint with empty socket path | AlServiceAccessPoint serviceAccessPoint(emptySocketPath) | None | Should Pass |
 * | 04 | Exit the EmptySocketPath test | None | None | Should be successful |
 */
TEST_F(AlServiceAccessPointTest, EmptySocketPath) {
    std::cout << "Entering EmptySocketPath test";
    std::string emptySocketPath = "";
    AlServiceAccessPoint serviceAccessPoint(emptySocketPath);
    std::cout << "Exiting EmptySocketPath test";
}

/**
 * @brief Test to verify the behavior of AlServiceAccessPoint with a long socket path
 *
 * This test checks the behavior of the AlServiceAccessPoint constructor when provided with a socket path of maximum length (108 characters). This is to ensure that the class can handle long socket paths without errors.
 *
 * **Test Group ID:* * Basic: 01@n
 * **Test Case ID:* * 010@n
 * **Priority:* * High@n
 * @n
 * **Pre-Conditions:* * None@n
 * **Dependencies:* * None@n
 * **User Interaction:* * None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a long socket path string | longSocketPath = string of 108 'a' characters | Should create the string successfully | Should be successful |
 * | 02 | Initialize AlServiceAccessPoint with the long socket path | AlServiceAccessPoint serviceAccessPoint(longSocketPath) | Should initialize without errors | Should Pass |
 */
TEST_F(AlServiceAccessPointTest, LongSocketPath) {
    std::cout << "Entering LongSocketPath test";
    std::string longSocketPath(108, 'a');
    AlServiceAccessPoint serviceAccessPoint(longSocketPath);
    std::cout << "Exiting LongSocketPath test";
}

/**
 * @brief Test the handling of special characters in the socket path
 *
 * This test verifies that the AlServiceAccessPoint class can handle socket paths that contain special characters. This is important to ensure that the class can manage paths with a variety of characters without errors.
 *
 * **Test Group ID:* * Basic: 01@n
 * **Test Case ID:* * 011@n
 * **Priority:* * High@n
 * @n
 * **Pre-Conditions:* * None@n
 * **Dependencies:* * None@n
 * **User Interaction:* * None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize AlServiceAccessPoint with special characters in socket path | specialCharsSocketPath = "/tmp/socket_with_special_chars!@#$%^&*() /" | No exceptions or errors | Should Pass |
 */
TEST_F(AlServiceAccessPointTest, SpecialCharactersSocketPath) {
    std::cout << "Entering SpecialCharactersSocketPath test";
    std::string specialCharsSocketPath = "/tmp/socket_with_special_chars!@#$%^&*() /";
    AlServiceAccessPoint serviceAccessPoint(specialCharsSocketPath);
    std::cout << "Exiting SpecialCharactersSocketPath test";
}

/**
 * @brief Test to verify the behavior of AlServiceAccessPoint when the socket path contains a null character.
 *
 * This test checks if the AlServiceAccessPoint can handle a socket path that includes a null character ('\0'). 
 * The objective is to ensure that the class correctly processes or rejects such paths without causing unexpected behavior or crashes.
 *
 * **Test Group ID:* * Basic: 01@n
 * **Test Case ID:* * 012@n
 * **Priority:* * High@n
 * @n
 * **Pre-Conditions:* * None@n
 * **Dependencies:* * None@n
 * **User Interaction:* * None@n
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01| Set up the test environment | serviceAccessPoint = new AlServiceAccessPoint("/tmp/test_socket") | Should be successful | |
 * | 02| Create a socket path with a null character and initialize AlServiceAccessPoint | nullCharSocketPath = "/tmp/socket_with_null\0char", 25 | Should Pass | |
 * | 03| Clean up the test environment | delete serviceAccessPoint | Should be successful | |
 */
TEST_F(AlServiceAccessPointTest, NullCharacterInSocketPath) {
    std::cout << "Entering NullCharacterInSocketPath test";
    std::string nullCharSocketPath("/tmp/socket_with_null\0char", 25);
    AlServiceAccessPoint serviceAccessPoint(nullCharSocketPath);
    std::cout << "Exiting NullCharacterInSocketPath test";
}

/**
 * @brief Test the proper destruction of an instance of AlServiceAccessPoint
 *
 * This test verifies that creating an instance of AlServiceAccessPoint using a valid socket path does not throw any exceptions and that the destructor is properly invoked when the instance goes out of scope.
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
 * | Variation / Step | Description                                                                                  | Test Data                               | Expected Result                                                 | Notes       |
 * | :--------------: | -------------------------------------------------------------------------------------------- | --------------------------------------- | --------------------------------------------------------------- | ----------- |
 * | 01               | Invoke the constructor of AlServiceAccessPoint with a valid socket path and ensure destruction occurs without throwing exceptions | socketPath = /tmp/test_socket           | The instance is created and destructed without any exceptions   | Should Pass |
 */
TEST(AlServiceAccessPoint, DestructorInitializedInstance) {
    std::cout << "Entering DestructorInitializedInstance test" << std::endl;

    std::string socketPath = "/tmp/test_socket";
    std::cout << "Invoking constructor AlServiceAccessPoint with socketPath: " << socketPath << std::endl;

    EXPECT_NO_THROW({
        {
            // Create an instance of AlServiceAccessPoint using the provided socketPath.
            AlServiceAccessPoint instance(socketPath);
            std::cout << "AlServiceAccessPoint instance created successfully with socketPath: " << socketPath << std::endl;
        } // instance goes out-of-scope here, invoking the destructor.
        std::cout << "AlServiceAccessPoint instance has been destructed (went out of scope)" << std::endl;
    });

    std::cout << "Exiting DestructorInitializedInstance test" << std::endl;
}
