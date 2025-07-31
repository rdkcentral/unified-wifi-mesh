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
#include "al_service_exception.h"


/**
 * @brief Test to verify the retrieval of primitive error for a failed request
 *
 * This test checks if the AlServiceException correctly retrieves the primitive error when a request fails.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 001
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
 * | 02 | Create an AlServiceException with "Request failed" message and PrimitiveError::RequestFailed | message = "Request failed", error = PrimitiveError::RequestFailed | None | Should be successful |
 * | 03 | Assert that the primitive error retrieved is PrimitiveError::RequestFailed | None | PrimitiveError::RequestFailed | Should Pass |
 * | 04 | Teardown the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST(AlServiceExceptionTest, RetrievePrimitiveErrorForRequestFailed) {
    std::cout << "Entering RetrievePrimitiveErrorForRequestFailed test" << std::endl;
    AlServiceException exception("Request failed", PrimitiveError::RequestFailed);
    ASSERT_EQ(exception.getPrimitiveError(), PrimitiveError::RequestFailed);
    std::cout << "Exiting RetrievePrimitiveErrorForRequestFailed test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of primitive error for indication failure
 *
 * This test checks if the AlServiceException correctly retrieves the primitive error when an indication failure occurs.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 002
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment | N/A | N/A | Done by Pre-requisite SetUp function |
 * | 02 | Create an AlServiceException with "Indication failed" message and PrimitiveError::IndicationFailed | message = "Indication failed", error = PrimitiveError::IndicationFailed | N/A | Should be successful |
 * | 03 | Assert that the primitive error retrieved is PrimitiveError::IndicationFailed | N/A | PrimitiveError::IndicationFailed | Should Pass |
 * | 04 | Teardown the test environment | N/A | N/A | Done by Pre-requisite TearDown function |
 */
TEST(AlServiceExceptionTest, RetrievePrimitiveErrorForIndicationFailed) {
    std::cout << "Entering RetrievePrimitiveErrorForIndicationFailed test" << std::endl;
    AlServiceException exception("Indication failed", PrimitiveError::IndicationFailed);
    ASSERT_EQ(exception.getPrimitiveError(), PrimitiveError::IndicationFailed);
    std::cout << "Exiting RetrievePrimitiveErrorForIndicationFailed test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of primitive error for a connection failure
 *
 * This test checks if the AlServiceException correctly retrieves the primitive error when a connection failure occurs.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 003
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
 * | 02 | Create an AlServiceException with "Connection failed" message and PrimitiveError::ConnectionFailed | message = "Connection failed", error = PrimitiveError::ConnectionFailed | None | Should be successful |
 * | 03 | Assert that the primitive error retrieved is PrimitiveError::ConnectionFailed | None | PrimitiveError::ConnectionFailed | Should Pass |
 * | 04 | Teardown the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST(AlServiceExceptionTest, RetrievePrimitiveErrorForConnectionFailed) {
    std::cout << "Entering RetrievePrimitiveErrorForConnectionFailed test" << std::endl;
    AlServiceException exception("Connection failed", PrimitiveError::ConnectionFailed);
    ASSERT_EQ(exception.getPrimitiveError(), PrimitiveError::ConnectionFailed);
    std::cout << "Exiting RetrievePrimitiveErrorForConnectionFailed test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of primitive error for socket creation failure.
 *
 * This test checks if the AlServiceException correctly retrieves the primitive error when a socket creation failure occurs.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 004
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
 * | 02 | Create an AlServiceException with "Socket creation failed" message and PrimitiveError::SocketCreationFailed | message = "Socket creation failed", error = PrimitiveError::SocketCreationFailed | None | Should be successful |
 * | 03 | Assert that the primitive error retrieved from the exception is PrimitiveError::SocketCreationFailed | None | PrimitiveError::SocketCreationFailed | Should Pass |
 * | 04 | Teardown the test environment | None | None | Done by Pre-requisite TearDown function |
 */

TEST(AlServiceExceptionTest, RetrievePrimitiveErrorForSocketCreationFailed) {
    std::cout << "Entering RetrievePrimitiveErrorForSocketCreationFailed test" << std::endl;
    AlServiceException exception("Socket creation failed", PrimitiveError::SocketCreationFailed);
    ASSERT_EQ(exception.getPrimitiveError(), PrimitiveError::SocketCreationFailed);
    std::cout << "Exiting RetrievePrimitiveErrorForSocketCreationFailed test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of primitive error when the socket is closed.
 *
 * This test checks if the AlServiceException correctly returns the PrimitiveError::SocketClosed when initialized with the "Socket closed" message and PrimitiveError::SocketClosed.
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
 * | 02 | Initialize AlServiceException with "Socket closed" and PrimitiveError::SocketClosed | message = "Socket closed", error = PrimitiveError::SocketClosed | None | Should be successful |
 * | 03 | Verify the primitive error is correctly retrieved | None | PrimitiveError::SocketClosed | Should Pass |
 * | 04 | Teardown the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST(AlServiceExceptionTest, RetrievePrimitiveErrorForSocketClosed) {
    std::cout << "Entering RetrievePrimitiveErrorForSocketClosed test" << std::endl;
    AlServiceException exception("Socket closed", PrimitiveError::SocketClosed);
    ASSERT_EQ(exception.getPrimitiveError(), PrimitiveError::SocketClosed);
    std::cout << "Exiting RetrievePrimitiveErrorForSocketClosed test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of primitive error for an invalid message
 *
 * This test checks if the AlServiceException correctly retrieves the primitive error when initialized with an invalid message.
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
 * | 01 | Setup the test environment | N/A | N/A | Done by Pre-requisite SetUp function |
 * | 02 | Initialize AlServiceException with "Invalid message" and PrimitiveError::InvalidMessage | message = "Invalid message", error = PrimitiveError::InvalidMessage | N/A | Should be successful |
 * | 03 | Assert that the primitive error retrieved is PrimitiveError::InvalidMessage | N/A | PrimitiveError::InvalidMessage | Should Pass |
 * | 04 | Teardown the test environment | N/A | N/A | Done by Pre-requisite TearDown function |
 */
TEST(AlServiceExceptionTest, RetrievePrimitiveErrorForInvalidMessage) {
    std::cout << "Entering RetrievePrimitiveErrorForInvalidMessage test" << std::endl;
    AlServiceException exception("Invalid message", PrimitiveError::InvalidMessage);
    ASSERT_EQ(exception.getPrimitiveError(), PrimitiveError::InvalidMessage);
    std::cout << "Exiting RetrievePrimitiveErrorForInvalidMessage test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of PrimitiveError for a Timeout exception
 *
 * This test checks if the AlServiceException correctly returns the PrimitiveError::Timeout when it is initialized with a "Timeout" message and PrimitiveError::Timeout. This ensures that the exception handling mechanism is working as expected for timeout errors.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 007
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
 * | 02 | Initialize AlServiceException with "Timeout" and PrimitiveError::Timeout | message = "Timeout", error = PrimitiveError::Timeout | None | Should be successful |
 * | 03 | Verify that getPrimitiveError returns PrimitiveError::Timeout | None | PrimitiveError::Timeout | Should Pass |
 * | 04 | Teardown the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST(AlServiceExceptionTest, RetrievePrimitiveErrorForTimeout) {
    std::cout << "Entering RetrievePrimitiveErrorForTimeout test" << std::endl;
    AlServiceException exception("Timeout", PrimitiveError::Timeout);
    ASSERT_EQ(exception.getPrimitiveError(), PrimitiveError::Timeout);
    std::cout << "Exiting RetrievePrimitiveErrorForTimeout test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of primitive error for a service not registered scenario.
 *
 * This test checks if the AlServiceException correctly returns the PrimitiveError::ServiceNotRegistered when the exception is initialized with the "Service not registered" message and the corresponding error code.
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
 * | 01| Setup the test environment | | | Done by Pre-requisite SetUp function |
 * | 02| Initialize AlServiceException with "Service not registered" and PrimitiveError::ServiceNotRegistered | message = "Service not registered", error = PrimitiveError::ServiceNotRegistered | | Should be successful |
 * | 03| Verify the primitive error retrieved from the exception | | PrimitiveError::ServiceNotRegistered | Should Pass |
 * | 04| Teardown the test environment | | | Done by Pre-requisite TearDown function |
 */
TEST(AlServiceExceptionTest, RetrievePrimitiveErrorForServiceNotRegistered) {
    std::cout << "Entering RetrievePrimitiveErrorForServiceNotRegistered test" << std::endl;
    AlServiceException exception("Service not registered", PrimitiveError::ServiceNotRegistered);
    ASSERT_EQ(exception.getPrimitiveError(), PrimitiveError::ServiceNotRegistered);
    std::cout << "Exiting RetrievePrimitiveErrorForServiceNotRegistered test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of primitive error for serialization error
 *
 * This test checks if the AlServiceException correctly retrieves the primitive error when a serialization error occurs.
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
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Create an AlServiceException with a serialization error | "Serialization error", PrimitiveError::SerializationError | None | Should be successful |
 * | 03 | Assert that the primitive error is correctly retrieved | None | PrimitiveError::SerializationError | Should Pass |
 * | 04 | Teardown the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST(AlServiceExceptionTest, RetrievePrimitiveErrorForSerializationError) {
    std::cout << "Entering RetrievePrimitiveErrorForSerializationError test" << std::endl;
    AlServiceException exception("Serialization error", PrimitiveError::SerializationError);
    ASSERT_EQ(exception.getPrimitiveError(), PrimitiveError::SerializationError);
    std::cout << "Exiting RetrievePrimitiveErrorForSerializationError test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of primitive error for deserialization error
 *
 * This test checks if the AlServiceException correctly retrieves the primitive error when a deserialization error occurs.
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
 * | 01 | Setup the test environment | N/A | N/A | Done by Pre-requisite SetUp function |
 * | 02 | Create an AlServiceException with a deserialization error | "Deserialization error", PrimitiveError::DeserializationError | N/A | Should be successful |
 * | 03 | Assert that the primitive error is DeserializationError | N/A | PrimitiveError::DeserializationError | Should Pass |
 * | 04 | Teardown the test environment | N/A | N/A | Done by Pre-requisite TearDown function |
 */
TEST(AlServiceExceptionTest, RetrievePrimitiveErrorForDeserializationError) {
    std::cout << "Entering RetrievePrimitiveErrorForDeserializationError test" << std::endl;
    AlServiceException exception("Deserialization error", PrimitiveError::DeserializationError);
    ASSERT_EQ(exception.getPrimitiveError(), PrimitiveError::DeserializationError);
    std::cout << "Exiting RetrievePrimitiveErrorForDeserializationError test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of primitive error for an unknown error
 *
 * This test checks if the AlServiceException correctly retrieves the primitive error when an unknown error is provided.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 011
 * **Priority:** High
 * @n
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 * @n
 * **Test Procedure:**@n
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Setup the test environment | N/A | N/A | Done by Pre-requisite SetUp function |
 * | 02 | Create an AlServiceException with "Unknown error" and PrimitiveError::UnknownError | error = "Unknown error", primitiveError = PrimitiveError::UnknownError | N/A | Should be successful |
 * | 03 | Assert that the primitive error retrieved is PrimitiveError::UnknownError | N/A | PrimitiveError::UnknownError | Should Pass |
 * | 04 | Teardown the test environment | N/A | N/A | Done by Pre-requisite TearDown function |
 */
TEST(AlServiceExceptionTest, RetrievePrimitiveErrorForUnknownError) {
    std::cout << "Entering RetrievePrimitiveErrorForUnknownError test" << std::endl;
    AlServiceException exception("Unknown error", PrimitiveError::UnknownError);
    ASSERT_EQ(exception.getPrimitiveError(), PrimitiveError::UnknownError);
    std::cout << "Exiting RetrievePrimitiveErrorForUnknownError test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of primitive error for a registration error
 *
 * This test checks if the AlServiceException correctly returns the primitive error when initialized with a registration error.
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
 * | 01 | Setup the test environment |  |  | Done by Pre-requisite SetUp function |
 * | 02 | Initialize AlServiceException with "Registration error" and PrimitiveError::RegistrationError | exception("Registration error", PrimitiveError::RegistrationError) |  | Should be successful |
 * | 03 | Assert that the primitive error is PrimitiveError::RegistrationError | exception.getPrimitiveError() | PrimitiveError::RegistrationError | Should Pass |
 * | 04 | Teardown the test environment |  |  | Done by Pre-requisite TearDown function |
 */
TEST(AlServiceExceptionTest, RetrievePrimitiveErrorForRegistrationError) {
    std::cout << "Entering RetrievePrimitiveErrorForRegistrationError test" << std::endl;
    AlServiceException exception("Registration error", PrimitiveError::RegistrationError);
    ASSERT_EQ(exception.getPrimitiveError(), PrimitiveError::RegistrationError);
    std::cout << "Exiting RetrievePrimitiveErrorForRegistrationError test" << std::endl;
}

/**
 * @brief Test to verify the retrieval of primitive error for fragment out of order
 *
 * This test checks if the AlServiceException correctly retrieves the primitive error when the error is "Fragment out of order".
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
 * | 01 | Setup the test environment | None | None | Done by Pre-requisite SetUp function |
 * | 02 | Create an AlServiceException with "Fragment out of order" error | error = "Fragment out of order", primitiveError = PrimitiveError::FragmentOutOfOrder | None | Should be successful |
 * | 03 | Assert that the primitive error is correctly retrieved | None | exception.getPrimitiveError() == PrimitiveError::FragmentOutOfOrder | Should Pass |
 * | 04 | Teardown the test environment | None | None | Done by Pre-requisite TearDown function |
 */
TEST(AlServiceExceptionTest, RetrievePrimitiveErrorForFragmentOutOfOrder) {
    std::cout << "Entering RetrievePrimitiveErrorForFragmentOutOfOrder test" << std::endl;
    AlServiceException exception("Fragment out of order", PrimitiveError::FragmentOutOfOrder);
    ASSERT_EQ(exception.getPrimitiveError(), PrimitiveError::FragmentOutOfOrder);
    std::cout << "Exiting RetrievePrimitiveErrorForFragmentOutOfOrder test" << std::endl;
}

/**
 * @brief Test the constructor of AlServiceException with an empty message and a specific error code.
 *
 * This test verifies that the AlServiceException constructor correctly initializes the object when provided with an empty message and the PrimitiveError::RequestFailed error code.@n
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
 * | 01 | Create an instance of AlServiceException with an empty message and PrimitiveError::RequestFailed | message = "", error = PrimitiveError::RequestFailed | The message should be empty, and the error code should be PrimitiveError::RequestFailed | Should Pass |
 *
 */
TEST(AlServiceExceptionTest, ConstructorWithEmptyMessageAndRequestFailed) {
    std::cout << "Entering ConstructorWithEmptyMessageAndRequestFailed test" << std::endl;
    try {
        AlServiceException ex("", PrimitiveError::RequestFailed);
        std::cout << "AlServiceException created successfully" << std::endl;
    } catch (const std::exception& e) {
        FAIL() << "Exception thrown: " << e.what();
    } catch (...) {
        FAIL() << "Unknown exception thrown";
    }
    std::cout << "Exiting ConstructorWithEmptyMessageAndRequestFailed test" << std::endl;
}

/**
 * @brief Test the constructor of AlServiceException with an empty message and unknown error.
 *
 * This test verifies that the AlServiceException constructor correctly handles an valid message and an invalid error code.@n
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
 * | 01| Create an instance of AlServiceException with valid message and unknown error | message = "Valid message", error = 15 | Constructor should not initialize the object with valid message and invalid error | Should Fail |
 *
 */
TEST(AlServiceExceptionTest, ConstructorWithValidMessageAndInvalidError) {
    std::cout << "Entering ConstructorWithValidMessageAndInvalidError test" << std::endl;
    try {
        AlServiceException ex("Valid message", static_cast<PrimitiveError>(15));
        std::cout << "AlServiceException created successfully" << std::endl;
    } catch (const std::exception& e) {
        FAIL() << "Exception thrown: " << e.what();
    } catch (...) {
        FAIL() << "Unknown exception thrown";
    }
    std::cout << "Exiting ConstructorWithValidMessageAndInvalidError test" << std::endl;
}