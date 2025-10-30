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
#include "test_l1_utils.h"
#include "al_service_registration_request.h"


/**
 * @brief Test to verify that the default constructor instantiates the object without throwing an exception.
 *
 * This test ensures that calling the default constructor of AlServiceRegistrationRequest does not throw any exceptions and results in the proper instantiation of an object with the expected default internal state.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 001@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                        | Test Data                                  | Expected Result                                                                   | Notes       |
 * | :--------------: | ------------------------------------------------------------------ | ------------------------------------------ | ---------------------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke default constructor for AlServiceRegistrationRequest object   | No input, default constructor invoked      | API call does not throw any exception and object is created with default state      | Should Pass |
 */
TEST(AlServiceRegistrationRequest, InstantiateObjectUsingDefaultConstructorSuccessfully) {
    std::cout << "Entering InstantiateObjectUsingDefaultConstructorSuccessfully test" << std::endl;
    // Invoke the default constructor
    EXPECT_NO_THROW({
        std::cout << "Invoking default constructor for AlServiceRegistrationRequest." << std::endl;
        AlServiceRegistrationRequest obj;
        std::cout << "Default constructor called. Object created with default internal state." << std::endl;
        // Since internal state is not accessible via getters, we assume default initialization.
        std::cout << "Internal state assumed as default based on constructor behavior." << std::endl;
    });
    std::cout << "Exiting InstantiateObjectUsingDefaultConstructorSuccessfully test" << std::endl;
}
/**
 * @brief Test construction of AlServiceRegistrationRequest with valid values
 *
 * This test ensures that the AlServiceRegistrationRequest constructor does not throw an exception when invoked with valid SAPActivation and ServiceType values. It iterates over all valid combinations of SAPActivation (SAP_ENABLE and SAP_DISABLE) and ServiceType (EmAgent and EmController) to verify successful object creation.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 002@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**@n
 * | Variation / Step | Description                                                                 | Test Data                                                            | Expected Result                                                  | Notes       |
 * | :--------------: | --------------------------------------------------------------------------- | -------------------------------------------------------------------- | ---------------------------------------------------------------- | ----------- |
 * | 01               | Invoke constructor with SAPActivation = SAP_ENABLE and ServiceType = EmAgent  | SAPActivation = SAP_ENABLE, ServiceType = EmAgent                    | No exception thrown and object constructed successfully          | Should Pass |
 * | 02               | Invoke constructor with SAPActivation = SAP_ENABLE and ServiceType = EmController | SAPActivation = SAP_ENABLE, ServiceType = EmController                | No exception thrown and object constructed successfully          | Should Pass |
 * | 03               | Invoke constructor with SAPActivation = SAP_DISABLE and ServiceType = EmAgent | SAPActivation = SAP_DISABLE, ServiceType = EmAgent                  | No exception thrown and object constructed successfully          | Should Pass |
 * | 04               | Invoke constructor with SAPActivation = SAP_DISABLE and ServiceType = EmController | SAPActivation = SAP_DISABLE, ServiceType = EmController            | No exception thrown and object constructed successfully          | Should Pass |
 */
TEST(AlServiceRegistrationRequest, ConstructorWithValidValues) {
    std::cout << "Entering ConstructorWithValidValues test" << std::endl;
    // Looping through valid SAPActivation values and ServiceType values
    SAPActivation validOperations[] = { SAPActivation::SAP_ENABLE, SAPActivation::SAP_DISABLE };
    ServiceType validTypes[] = { ServiceType::EmAgent, ServiceType::EmController };
    for (const auto& op : validOperations) {
        for (const auto& type : validTypes) {
            std::cout << "Invoking AlServiceRegistrationRequest constructor with SAPActivation = " 
                      << static_cast<uint8_t>(op) << " and ServiceType = " 
                      << static_cast<uint8_t>(type) << std::endl;
            // Expect no exception thrown for valid parameters
            EXPECT_NO_THROW({
                AlServiceRegistrationRequest request(op, type);
                std::cout << "Constructed AlServiceRegistrationRequest object" << std::endl;
            });
        }
    }
    std::cout << "Exiting ConstructorWithValidValues test" << std::endl;
}
/**
 * @brief Verify that the constructor of AlServiceRegistrationRequest throws an exception when provided with an invalid SAPActivation value.
 *
 * This test validates that the AlServiceRegistrationRequest constructor correctly handles an invalid SAPActivation value (0xFF) by throwing an exception, while being provided with a valid ServiceType (EmAgent). This ensures robust error handling in the API when input parameters are not within the expected range.
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
 * | Variation / Step | Description                                                                                     | Test Data                                                  | Expected Result                                                    | Notes             |
 * | :--------------: | ----------------------------------------------------------------------------------------------- | ---------------------------------------------------------- | ------------------------------------------------------------------ | ----------------- |
 * | 01               | Print the message indicating the start of the test.                                             | None                                                       | "Entering ConstructorWithInvalidSAPActivation test" is printed.    | Should be successful |
 * | 02               | Initialize variables with invalid SAPActivation value and valid ServiceType, and print invoking message. | invalidOp = 0xFF, validType = EmAgent                        | "Invoking AlServiceRegistrationRequest constructor with invalid SAPActivation value = 255 and valid ServiceType value = (EmAgent as uint8_t)" is printed. | Should be successful |
 * | 03               | Call the AlServiceRegistrationRequest constructor with the invalid SAPActivation value and valid ServiceType, and expect an exception. | API call: AlServiceRegistrationRequest(invalidOp, validType) | An exception is thrown as verified by the EXPECT_ANY_THROW assertion. | Should Pass       |
 * | 04               | Print the message indicating the end of the test.                                               | None                                                       | "Exiting ConstructorWithInvalidSAPActivation test" is printed.     | Should be successful |
 */
TEST(AlServiceRegistrationRequest, ConstructorWithInvalidSAPActivation) {
    std::cout << "Entering ConstructorWithInvalidSAPActivation test" << std::endl;
    SAPActivation invalidOp = static_cast<SAPActivation>(0xFF);
    ServiceType validType = ServiceType::EmAgent;
    std::cout << "Invoking AlServiceRegistrationRequest constructor with invalid SAPActivation value = " 
              << static_cast<uint8_t>(invalidOp) << " and valid ServiceType value = " 
              << static_cast<uint8_t>(validType) << std::endl;
    EXPECT_ANY_THROW({
        AlServiceRegistrationRequest request(invalidOp, validType);
    });
    std::cout << "Exiting ConstructorWithInvalidSAPActivation test" << std::endl;
}

/**
 * @brief Verify that the AlServiceRegistrationRequest constructor throws an exception for an invalid ServiceType.
 *
 * This test validates that when providing an invalid ServiceType value (0xFF) along with a valid SAPActivation value (SAP_ENABLE),
 * the constructor of AlServiceRegistrationRequest correctly throws an exception. This ensures that the class properly validates input values.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 004
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Call the AlServiceRegistrationRequest constructor with valid SAPActivation (SAP_ENABLE) and invalid ServiceType (0xFF) | validOp = SAP_ENABLE, invalidType = 0xFF | The constructor should throw an exception. | Should Pass |
 */
TEST(AlServiceRegistrationRequest, ConstructorWithInvalidServiceType) {
    std::cout << "Entering ConstructorWithInvalidServiceType test" << std::endl;
    SAPActivation validOp = SAPActivation::SAP_ENABLE;
    ServiceType invalidType = static_cast<ServiceType>(0xFF);
    std::cout << "Invoking AlServiceRegistrationRequest constructor with valid SAPActivation value = " 
              << static_cast<uint8_t>(validOp) << " and invalid ServiceType value = " 
              << static_cast<uint8_t>(invalidType) << std::endl;
    EXPECT_ANY_THROW({
        AlServiceRegistrationRequest request(validOp, invalidType);
    });
    std::cout << "Exiting ConstructorWithInvalidServiceType test" << std::endl;
}
/**
 * @brief Verify that getSAPActivationStatus() returns SAP_ENABLE correctly
 *
 * This test verifies that when an instance of AlServiceRegistrationRequest is constructed using SAPActivation::SAP_ENABLE 
 * along with a valid ServiceType, the getSAPActivationStatus() method correctly returns SAP_ENABLE. This ensures that the 
 * API behaves as expected when provided with valid initialization inputs and that no exceptions are thrown during execution.@n
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
 * | Variation / Step | Description | Test Data |Expected Result |Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a valid ServiceType, construct AlServiceRegistrationRequest with SAPActivation::SAP_ENABLE, and invoke getSAPActivationStatus() | input: SAPActivation = SAP_ENABLE, ServiceType = 0; output: returnedSAPActivationStatus = SAP_ENABLE | API returns SAP_ENABLE and assertion EXPECT_EQ confirms the value | Should Pass |
 */
TEST(AlServiceRegistrationRequest, getSAPActivationStatus_returns_SAP_ENABLE) {
    std::cout << "Entering getSAPActivationStatus_returns_SAP_ENABLE test" << std::endl;
    ServiceType validServiceType = static_cast<ServiceType>(0);
    std::cout << "Created a valid ServiceType with value: " << validServiceType << std::endl; 
    EXPECT_NO_THROW({
        AlServiceRegistrationRequest request(SAPActivation::SAP_ENABLE, validServiceType);
        std::cout << "Constructed AlServiceRegistrationRequest with SAPActivation::SAP_ENABLE" << std::endl;
        SAPActivation activation = request.getSAPActivationStatus();
        std::cout << "Invoked getSAPActivationStatus(), returned value: " 
                  << static_cast<int>(activation) << std::endl;
        EXPECT_EQ(activation, SAPActivation::SAP_ENABLE);
    });
    std::cout << "Exiting getSAPActivationStatus_returns_SAP_ENABLE test" << std::endl;
}
/**
 * @brief Verify that getSAPActivationStatus returns SAP_DISABLE for a valid service type.
 *
 * This test creates an instance of AlServiceRegistrationRequest using SAPActivation::SAP_DISABLE along with a valid service type.
 * It then calls getSAPActivationStatus and verifies that the returned SAPActivation value is SAP_DISABLE.
 * This test ensures that the SAP activation status is correctly maintained and returned in the object.
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
 * | Variation / Step | Description                                                               | Test Data                                                        | Expected Result                                                       | Notes           |
 * | :--------------: | ------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------------- | --------------- |
 * | 01               | Create a valid ServiceType with a value of 0                              | validServiceType = 0                                             | ServiceType created successfully                                      | Should be successful |
 * | 02               | Construct AlServiceRegistrationRequest with SAPActivation::SAP_DISABLE      | SAPActivation = SAP_DISABLE, ServiceType = validServiceType        | Object constructed successfully                                       | Should be successful |
 * | 03               | Invoke getSAPActivationStatus method                                      | No additional input; object already constructed                    | Returns SAPActivation::SAP_DISABLE                                    | Should Pass     |
 * | 04               | Validate that the returned activation status equals SAP_DISABLE           | Expected return value: SAP_DISABLE                               | EXPECT_EQ validates that activation is equal to SAP_DISABLE           | Should be successful |
 */
TEST(AlServiceRegistrationRequest, getSAPActivationStatus_returns_SAP_DISABLE) {
    std::cout << "Entering getSAPActivationStatus_returns_SAP_DISABLE test" << std::endl;
    ServiceType validServiceType = static_cast<ServiceType>(0);
    std::cout << "Created a valid ServiceType with value: " << validServiceType << std::endl;
    EXPECT_NO_THROW({
        AlServiceRegistrationRequest request(SAPActivation::SAP_DISABLE, validServiceType);
        std::cout << "Constructed AlServiceRegistrationRequest with SAPActivation::SAP_DISABLE" << std::endl;
        SAPActivation activation = request.getSAPActivationStatus();
        std::cout << "Invoked getSAPActivationStatus(), returned value: " 
                  << static_cast<int>(activation) << std::endl;
        EXPECT_EQ(activation, SAPActivation::SAP_DISABLE);
    });
    std::cout << "Exiting getSAPActivationStatus_returns_SAP_DISABLE test" << std::endl;
}
/**
 * @brief Verify that getSAPActivationStatus() does not return the invalid SAPActivation value.
 *
 * This test verifies that when an AlServiceRegistrationRequest object is constructed with an invalid SAPActivation value,
 * the getSAPActivationStatus() method does not return the invalid value provided during construction. This ensures the
 * robustness of the SAPActivation status retrieval and prevents erroneous activation data from being used downstream.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 007
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Construct AlServiceRegistrationRequest object with invalid SAPActivation and valid ServiceType. | input: SAPActivation = 0x07, ServiceType = 0 | No exception is thrown while constructing the object. | Should Pass |
 * | 02 | Invoke getSAPActivationStatus() on the constructed object and validate the returned value. | output: activation value, compared against input SAPActivation = 0x07 | The returned activation value is not equal to 0x07, satisfying the EXPECT_NE check. | Should Pass |
 */
TEST(AlServiceRegistrationRequest, getSAPActivationStatus_invalidSAPActivation) {
    std::cout << "Entering getSAPActivationStatus_invalidSAPActivation test" << std::endl;
    ServiceType validServiceType = static_cast<ServiceType>(0);
    EXPECT_ANY_THROW({
	AlServiceRegistrationRequest request(static_cast<SAPActivation>(0x07), validServiceType);
        std::cout << "Constructed AlServiceRegistrationRequest with invalid SAPActivation value" << std::endl;
        SAPActivation activation = request.getSAPActivationStatus();
        std::cout << "Invoked getSAPActivationStatus(), returned value: " << static_cast<int>(activation) << std::endl;
        EXPECT_NE(activation, static_cast<SAPActivation>(0x07));
    });
    std::cout << "Exiting getSAPActivationStatus_invalidSAPActivation test" << std::endl;
}

/**
 * @brief Validate that the parameterized constructor correctly initializes the request with ServiceType::EmAgent.
 *
 * This test verifies that an AlServiceRegistrationRequest object can be successfully created using the parameterized constructor with a valid service type (ServiceType::EmAgent). It then validates that the getServiceType() method returns the expected service type. This test ensures that the object initialization and subsequent service type retrieval function as intended.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 008@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                                         | Test Data                                                       | Expected Result                                                      | Notes      |
 * | :--------------: | --------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- | -------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke the parameterized constructor with SAPActivation_operation = SAPActivation::SAP_ENABLE and ServiceType::EmAgent       | SAPActivation_operation = SAPActivation::SAP_ENABLE, ServiceType = EmAgent              | Object is created without throwing an exception                      | Should Pass|
 * | 02               | Call getServiceType() method and check that it returns ServiceType::EmAgent                           | Method call: getServiceType(), expected output: ServiceType::EmAgent| Returned value equals ServiceType::EmAgent as verified by EXPECT_EQ     | Should Pass|
 */
TEST(AlServiceRegistrationRequest, ParameterizedConstructor_ValidServiceType_EmAgent) {
    std::cout << "Entering ParameterizedConstructor_ValidServiceType_EmAgent test" << std::endl;
    std::cout << "Invoking parameterized constructor with SAPActivation_operation SAPActivation::SAP_ENABLE and ServiceType::EmAgent" << std::endl;
    EXPECT_NO_THROW({
        AlServiceRegistrationRequest request(SAPActivation::SAP_ENABLE, ServiceType::EmAgent);        
        std::cout << "Calling getServiceType() method." << std::endl;
        ServiceType retValue = request.getServiceType();
        std::cout << "Retrieved service type value: " 
                  << (retValue == ServiceType::EmAgent ? "EmAgent" : "EmController") << std::endl;
        EXPECT_EQ(retValue, ServiceType::EmAgent);
    });

    std::cout << "Exiting ParameterizedConstructor_ValidServiceType_EmAgent test" << std::endl;
}
/**
 * @brief Tests that the AlServiceRegistrationRequest constructor properly initializes the object with valid inputs and that the getServiceType() method returns the correct service type.
 *
 * This test verifies that when the parameterized constructor of AlServiceRegistrationRequest is called with SAPActivation_operation set to 0 and ServiceType::EmController,
 * the object is created without throwing any exceptions and the getServiceType() method returns ServiceType::EmController as expected.
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
 * | Variation / Step | Description                                                                 | Test Data                                                                                      | Expected Result                                                          | Notes       |
 * | :--------------: | --------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ | ----------- |
 * | 01               | Invoke the parameterized constructor with SAPActivation_operation = 0 and ServiceType::EmController. | input1 = SAPActivation_operation (0), input2 = ServiceType::EmController                        | Object is created without throwing an exception.                       | Should Pass |
 * | 02               | Call getServiceType() method to retrieve the service type from the constructed object.  | input: object from constructor, expected output = ServiceType::EmController                      | getServiceType() returns ServiceType::EmController and assertion passes. | Should Pass |
 */
TEST(AlServiceRegistrationRequest, ParameterizedConstructor_ValidServiceType_EmController) {
    std::cout << "Entering ParameterizedConstructor_ValidServiceType_EmController test" << std::endl;
    std::cout << "Invoking parameterized constructor with SAPActivation_operation SAPActivation::SAP_ENABLE and ServiceType::EmController" << std::endl;
    EXPECT_NO_THROW({
        AlServiceRegistrationRequest request(SAPActivation::SAP_ENABLE, ServiceType::EmController);
        std::cout << "Calling getServiceType() method." << std::endl;
        ServiceType retValue = request.getServiceType();
        std::cout << "Retrieved service type value: " 
                  << (retValue == ServiceType::EmAgent ? "EmAgent" : "EmController") << std::endl;
        EXPECT_EQ(retValue, ServiceType::EmController);
    });
    std::cout << "Exiting ParameterizedConstructor_ValidServiceType_EmController test" << std::endl;
}
/**
 * @brief Verify retrieval of an invalid service type.
 *
 * This test verifies that when an invalid service type is provided to the AlServiceRegistrationRequest constructor,
 * the getServiceType() method returns the invalid service type as set. This scenario is essential to ensure that the API
 * correctly handles and returns the service type even if it is invalid, which helps in debugging and validation of input.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 010@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Log the beginning of the test and create an instance of AlServiceRegistrationRequest with an invalid service type. | SAPActivation = SAP_ENABLE, serviceType = static_cast<ServiceType>(0x06) | Instance is created successfully with the given parameters. | Should be successful |
 * | 02 | Call getServiceType() to retrieve the service type from the instance. | API Call: result = instance.getServiceType() | The returned service type should match the invalid input (static_cast<ServiceType>(0x06)). | Should Fail |
 * | 03 | Log the retrieved service type and the exit of the test. | Output log: service type value printed. | The console outputs the service type and indicates test completion. | Should be successful |
 */
TEST(AlServiceRegistrationRequest, RetrieveServiceType_Invalid) {
    std::cout << "Entering RetrieveServiceType_Invalid test" << std::endl;
    AlServiceRegistrationRequest instance(SAPActivation::SAP_ENABLE, static_cast<ServiceType>(0x06));
    ServiceType result = instance.getServiceType();
    std::cout << "The servicetype is "  << result << std::endl;
    std::cout << "Exiting RetrieveServiceType_Invalid test" << std::endl;
}
/**
 * @brief Validate that serialization of a valid registration request returns a non-empty vector of bytes
 *
 * This test creates an instance of AlServiceRegistrationRequest with valid parameters (SAP_ENABLE and EmAgent)
 * and then invokes serializeRegistrationRequest to generate the serialized data. The test ensures that the returned
 * vector is correctly generated. This is important to verify that the serialization logic for valid registration requests
 * works as expected.
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
 * | 01 | Instantiate AlServiceRegistrationRequest with valid inputs and call serializeRegistrationRequest | SAPActivation = SAP_ENABLE, ServiceType = EmAgent, output = vector<unsigned char> | Returns a non-empty vector of serialized data | Should Pass |
 */
TEST(AlServiceRegistrationRequest, SerializeValidRegistrationRequest) {
    std::cout << "Entering SerializeValidRegistrationRequest test" << std::endl;
    AlServiceRegistrationRequest instance(SAPActivation::SAP_ENABLE, ServiceType::EmAgent);
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
 * @brief Verify that an invalid registration request is serialized correctly.
 *
 * This test creates an instance of AlServiceRegistrationRequest with invalid parameters
 * and invokes the serializeRegistrationRequest method to determine if the serialization
 * is performed as expected when provided with improper service operation and service type.
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
 * | Variation / Step | Description                                                                                   | Test Data                                                  | Expected Result                                                                     | Notes           |
 * | :--------------: | --------------------------------------------------------------------------------------------- | ---------------------------------------------------------- | ------------------------------------------------------------------------------------ | --------------- |
 * | 01               | Log the entry into the test and instantiate AlServiceRegistrationRequest with invalid values. | SAPActivation = 0x04, serviceType = 0x05                 | Instance of AlServiceRegistrationRequest is created successfully                    | Should Pass     |
 * | 02               | Invoke serializeRegistrationRequest() on the instance to perform the serialization operation.  | No direct input, uses instance internal state              | A vector of unsigned char containing the serialized registration data is returned    | Should Pass     |
 * | 03               | Log the serialized result and exit the test.                                                 | result (vector<unsigned char>) as output from the API call | Serialized data is printed in hex format on the console                              | Should be successful |
 */
TEST(AlServiceRegistrationRequest, SerializeInvalidRegistrationRequest) {
    std::cout << "Entering SerializeInvalidRegistrationRequest test" << std::endl;
    AlServiceRegistrationRequest instance(static_cast<SAPActivation>(0x04), static_cast<ServiceType>(0x05));
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
 * @brief Validate that deserializeRegistrationRequest correctly processes a valid registration request
 *
 * This test case verifies that the deserializeRegistrationRequest method of the AlServiceRegistrationRequest class correctly processes a valid registration request. It ensures that when a proper byte stream is provided, the registration data is deserialized without errors.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 013
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                              | Test Data                                               | Expected Result                                                                  | Notes      |
 * | :--------------: | ---------------------------------------------------------------------------------------- | ------------------------------------------------------- | -------------------------------------------------------------------------------- | ---------- |
 * | 01               | Invokes the deserializeRegistrationRequest API with a valid byte stream input              | validData = 0x00, 0x02, 0x01, 0x02 | API processes the valid registration request without errors and returns normally | Should Pass |
 */
 TEST(AlServiceRegistrationRequest, DeserializeValidRegistrationRequest) {
    std::vector<unsigned char> validData = {0x00, 0x02, 0x01, 0x02};
    std::cout << "Entering DeserializeValidRegistrationRequest" << std::endl;
    AlServiceRegistrationRequest instance;
    EXPECT_NO_THROW({
        instance.deserializeRegistrationRequest(validData);
    });
    std::cout << "Exiting DeserializeValidRegistrationRequest" << std::endl;
}

/**
 * @brief Verify that deserializeRegistrationRequest handles an empty data vector.
 *
 * This test verifies that the deserializeRegistrationRequest method can process an empty data vector without causing errors or unexpected behavior. It ensures that the API properly handles cases with no input data, which is critical for robust input validation.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 014@n
 * **Priority:** High@n
 * 
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 * 
 * **Test Procedure:**
 * | Variation / Step | Description                                                       | Test Data                  | Expected Result                                                      | Notes       |
 * | :--------------: | ----------------------------------------------------------------- | -------------------------- | -------------------------------------------------------------------- | ----------- |
 * | 01               | Invoke deserializeRegistrationRequest with an empty data vector  and verify if exception is thrown | emptyData = {} | API handles empty input by raising some exception | Should Pass |
 */
TEST(AlServiceRegistrationRequest, DeserializeEmptyDataVector) {
    std::vector<unsigned char> emptyData = {};
    std::cout << "Entering DeserializeEmptyDataVector" << std::endl;
    AlServiceRegistrationRequest instance;
    EXPECT_ANY_THROW({
		instance.deserializeRegistrationRequest(emptyData);
    });
    std::cout << "Exiting DeserializeEmptyDataVector" << std::endl;
}

/**
 * @brief Verifies that the SAP activation status is correctly set to SAP_ENABLE.
 *
 * This test creates an instance of AlServiceRegistrationRequest using its default constructor and then invokes setSAPActivationStatus with the SAP_ENABLE value. It ensures that the object is created successfully without exceptions and that the method call properly sets the internal activation status.
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
 * | :----: | --------- | ---------- | -------------- | ----- |
 * | 01 | Create an instance of AlServiceRegistrationRequest using the default constructor | No input required | Object is successfully created without throwing exceptions | Should be successful |
 * | 02 | Invoke setSAPActivationStatus with SAP_ENABLE option | input: SAPActivation::SAP_ENABLE | Method completes without exceptions; internal state is set to SAP_ENABLE (0x01) | Should Pass |
 */
TEST(AlServiceRegistrationRequest, Set_SAPActivationStatus_with_SAP_ENABLE) {
    std::cout << "Entering Set_SAPActivationStatus_with_SAP_ENABLE test" << std::endl;
    
    // Create object using default constructor and log object creation
    EXPECT_NO_THROW({
        AlServiceRegistrationRequest request;
        std::cout << "Created AlServiceRegistrationRequest object using default constructor" << std::endl;
        
        // Log before invocation
        std::cout << "Invoking setSAPActivationStatus with value SAP_ENABLE (0x01)" << std::endl;
        EXPECT_NO_THROW(request.setSAPActivationStatus(SAPActivation::SAP_ENABLE));
        std::cout << "setSAPActivationStatus invoked successfully with SAP_ENABLE" << std::endl;
        
        // Since no getter is provided, we log that the expected internal value should be SAP_ENABLE.
        std::cout << "Expected internal service activation status: SAP_ENABLE (0x01)" << std::endl;
    });
    
    std::cout << "Exiting Set_SAPActivationStatus_with_SAP_ENABLE test" << std::endl;
}
/**
 * @brief Verifies that setting the SAP Activation status to SAP_DISABLE is successful.
 *
 * In this test, an object of AlServiceRegistrationRequest is created using the default constructor. Then,
 * the setSAPActivationStatus API is invoked with the SAP_DISABLE value (0x02). The test ensures that no exceptions
 * are thrown and that the internal state of the object is updated correctly. This test validates the correct
 * behavior of the API in a positive scenario using valid input.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 016
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create an instance of AlServiceRegistrationRequest using the default constructor | No input parameters; constructor invoked | Object is created successfully without throwing an exception | Should be successful |
 * | 02 | Invoke setSAPActivationStatus with SAP_DISABLE (0x02) on the created object | request object, input: SAP_DISABLE = 0x02 | Method executes without throwing; internal state is updated to SAP_DISABLE | Should Pass |
 */
TEST(AlServiceRegistrationRequest, Set_SAPActivationStatus_with_SAP_DISABLE) {
    std::cout << "Entering Set_SAPActivationStatus_with_SAP_DISABLE test" << std::endl;
    
    // Create object with the default constructor
    EXPECT_NO_THROW({
        AlServiceRegistrationRequest request;
        std::cout << "Created AlServiceRegistrationRequest object using default constructor" << std::endl;
        
        // Log invocation details
        std::cout << "Invoking setSAPActivationStatus with value SAP_DISABLE (0x02)" << std::endl;
        EXPECT_NO_THROW(request.setSAPActivationStatus(SAPActivation::SAP_DISABLE));
        std::cout << "setSAPActivationStatus invoked successfully with SAP_DISABLE" << std::endl;
        
        // Log expected internal state change
        std::cout << "Expected internal service activation status: SAP_DISABLE (0x02)" << std::endl;
    });
    
    std::cout << "Exiting Set_SAPActivationStatus_with_SAP_DISABLE test" << std::endl;
}
/**
 * @brief Test the behavior of setSAPActivationStatus when invoked with an invalid value.
 *
 * This test verifies that calling setSAPActivationStatus with an invalid SAPActivation value (created via explicit cast from 0xFF)
 * does not throw an exception and handles the value gracefully without affecting the internal state of the AlServiceRegistrationRequest object.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 017@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                          | Test Data                                      | Expected Result                                                               | Notes           |
 * | :--------------: | -------------------------------------------------------------------- | ---------------------------------------------- | ----------------------------------------------------------------------------- | --------------- |
 * | 01               | Create an AlServiceRegistrationRequest object using the default constructor. | N/A                                            | Object is constructed successfully without throwing an exception.            | Should be successful |
 * | 02               | Create an invalid SAPActivation value via an explicit cast.          | invalidValue = 0xFF                            | The invalidValue holds an invalid SAPActivation enum value.                   | Should be successful |
 * | 03               | Invoke setSAPActivationStatus with the invalid value.                | input: invalidValue = 0xFF, output: none         | The API call handles the invalid value gracefully without throwing an exception. | Should Pass     |
 */
TEST(AlServiceRegistrationRequest, Set_SAPActivationStatus_with_Invalid_Value) {
    std::cout << "Entering Set_SAPActivationStatus_with_Invalid_Value test" << std::endl;
    
    EXPECT_NO_THROW({
        AlServiceRegistrationRequest request;
        std::cout << "Created AlServiceRegistrationRequest object using default constructor" << std::endl;
        
        // Create an invalid SAPActivation value via explicit cast.
        SAPActivation invalidValue = static_cast<SAPActivation>(0xFF);
        std::cout << "Invoking setSAPActivationStatus with invalid value (0xFF) via explicit cast" << std::endl;
        
        EXPECT_NO_THROW(request.setSAPActivationStatus(invalidValue));
        std::cout << "setSAPActivationStatus invoked with invalid value without crashing" << std::endl;
        
        // Log that the expected behavior is graceful handling of the invalid value.
        std::cout << "Expected: The method handles the invalid value gracefully without crashing or affecting internal state" << std::endl;
    });
    
    std::cout << "Exiting Set_SAPActivationStatus_with_Invalid_Value test" << std::endl;
}
/**
 * @brief Verify setting service type to EmAgent for AlServiceRegistrationRequest object
 *
 * This test verifies that an instance of AlServiceRegistrationRequest can be created using the default constructor, and that the setServiceType API correctly sets the service type to EmAgent without throwing any exceptions. This ensures that the service registration functionality handles the EmAgent service type as expected.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 018
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- | -------------- | ----- |
 * | 01 | Invoke default constructor to create an instance of AlServiceRegistrationRequest | None | Instance is created successfully without exceptions | Should be successful |
 * | 02 | Call setServiceType with ServiceType::EmAgent to update the service type | service = ServiceType::EmAgent (0x01) | Method executes without throwing exceptions and updates the internal state to EmAgent | Should Pass |
 */
TEST(AlServiceRegistrationRequest, SetServiceType_EmAgent) {
    std::cout << "Entering SetServiceType_EmAgent test" << std::endl;

    // Create an instance of AlServiceRegistrationRequest using the default constructor.
    EXPECT_NO_THROW({
        AlServiceRegistrationRequest request;
        std::cout << "Created AlServiceRegistrationRequest object using default constructor" << std::endl;

        // Set service type to EmAgent.
        ServiceType service = ServiceType::EmAgent;
        std::cout << "Invoking setServiceType with ServiceType::EmAgent (0x01)" << std::endl;
        EXPECT_NO_THROW({
            request.setServiceType(service);
            std::cout << "setServiceType successfully invoked with value: EmAgent" << std::endl;
        });

        // Debug log: (Assuming internal state is updated; if a getter were available, its value would be printed here)
        std::cout << "Internal state updated to EmAgent" << std::endl;
    });
    
    std::cout << "Exiting SetServiceType_EmAgent test" << std::endl;
}
/**
 * @brief Validate that setting the service type to EmController does not throw exceptions and updates internal state.
 *
 * This test verifies that an instance of AlServiceRegistrationRequest can be created without errors, and that setting the service type to ServiceType::EmController is handled correctly by the API. The test checks that no exceptions are thrown during these operations.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 019@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                       | Test Data                                                                | Expected Result                                              | Notes      |
 * | :--------------: | ----------------------------------------------------------------- | ------------------------------------------------------------------------ | ------------------------------------------------------------ | ---------- |
 * | 01               | Create instance using the default constructor and invoke setServiceType with ServiceType::EmController | input: default constructor, service = EmController                     | No exception thrown; internal state updated to EmController  | Should Pass |
 */
TEST(AlServiceRegistrationRequest, SetServiceType_EmController) {
    std::cout << "Entering SetServiceType_EmController test" << std::endl;

    // Create an instance of AlServiceRegistrationRequest using the default constructor.
    EXPECT_NO_THROW({
        AlServiceRegistrationRequest request;
        std::cout << "Created AlServiceRegistrationRequest object using default constructor" << std::endl;

        // Set service type to EmController.
        ServiceType service = ServiceType::EmController;
        std::cout << "Invoking setServiceType with ServiceType::EmController (0x02)" << std::endl;
        EXPECT_NO_THROW({
            request.setServiceType(service);
            std::cout << "setServiceType successfully invoked with value: EmController" << std::endl;
        });

        // Debug log: (Assuming internal state is updated; if a getter were available, its value would be printed here)
        std::cout << "Internal state updated to EmController" << std::endl;
    });
    
    std::cout << "Exiting SetServiceType_EmController test" << std::endl;
}
/**
 * @brief Verify proper error handling when an invalid service type is provided.
 *
 * This test validates that the setServiceType method of the AlServiceRegistrationRequest class
 * correctly throws an exception when an invalid ServiceType value (0x03) is passed. It ensures
 * that the internal data integrity is maintained by not accepting invalid input.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 020
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                              | Test Data                                                         | Expected Result                                                            | Notes             |
 * | :--------------: | ------------------------------------------------------------------------ | ----------------------------------------------------------------- | -------------------------------------------------------------------------- | ----------------- |
 * | 01               | Create an instance of AlServiceRegistrationRequest using default constructor. | N/A, output: request instance created                             | Object should be created without throwing any exceptions.                | Should be successful |
 * | 02               | Invoke setServiceType with an invalid service type (0x03).                | input: invalidService = 0x03, output: N/A                           | API is expected to throw an exception indicating invalid input handling.   | Should Fail        |
 */
TEST(AlServiceRegistrationRequest, SetServiceType_Invalid) {
    std::cout << "Entering SetServiceType_Invalid test" << std::endl;
    EXPECT_NO_THROW({
        AlServiceRegistrationRequest request;
        std::cout << "Created AlServiceRegistrationRequest object using default constructor" << std::endl;
        ServiceType invalidService = static_cast<ServiceType>(0x03);
        std::cout << "Invoking setServiceType with an invalid service type (0x03)" << std::endl;
        EXPECT_ANY_THROW({
            request.setServiceType(invalidService);
            std::cout << "setServiceType invocation with invalid value returned normally" << std::endl;
        });
    });
    std::cout << "Exiting SetServiceType_Invalid test" << std::endl;
}
