
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
#include "em_cmd_mld_reconfig.h"


/**
 * @brief Test the default constructor of em_cmd_mld_reconfig_t for successful instantiation
 *
 * This test ensures that invoking the default constructor of the em_cmd_mld_reconfig_t class does not throw any exceptions and that the object can be successfully deinitialized using its deinit method. The test verifies the proper construction and resource cleanup of the object, which is critical for overall functionality.
 *
 * **Test Group ID:** Basic: 01
 * **Test Case ID:** 001
 * **Priority:** High
 *
 * **Pre-Conditions:** None
 * **Dependencies:** None
 * **User Interaction:** None
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                           | Test Data                                                  | Expected Result                                          | Notes       |
 * | :--------------: | ------------------------------------------------------------------------------------- | ---------------------------------------------------------- | -------------------------------------------------------- | ----------- |
 * | 01               | Invoke the default constructor of em_cmd_mld_reconfig_t and call deinit method         | No input, output: object instantiated and deinitialized    | No exception thrown and object is successfully deinitialized | Should Pass |
 */
TEST(em_cmd_mld_reconfig_t, em_cmd_mld_reconfig_t_default_constructor_success)
{
    std::cout << "Entering em_cmd_mld_reconfig_t_default_constructor_success test" << std::endl;
    EXPECT_NO_THROW({
        em_cmd_mld_reconfig_t obj;
        std::cout << "Invoked em_cmd_mld_reconfig_t default constructor" << std::endl;
        obj.deinit();
    });
    std::cout << "Exiting em_cmd_mld_reconfig_t_default_constructor_success test" << std::endl;
}
/**
 * @brief Validates that multiple instances of em_cmd_mld_reconfig_t can be created sequentially without throwing exceptions.
 *
 * This test ensures that two instances of the em_cmd_mld_reconfig_t class are constructed sequentially, and subsequently deinitialized, without any exceptions being thrown. It verifies the safe creation and cleanup behavior of the class under sequential instantiation.
 *
 * **Test Group ID:** Basic: 01@n
 * **Test Case ID:** 002@n
 * **Priority:** High@n
 *
 * **Pre-Conditions:** None@n
 * **Dependencies:** None@n
 * **User Interaction:** None@n
 *
 * **Test Procedure:**
 * | Variation / Step | Description                                                                    | Test Data                                                        | Expected Result                                                  | Notes          |
 * | :--------------: | ------------------------------------------------------------------------------ | ---------------------------------------------------------------- | ---------------------------------------------------------------- | -------------- |
 * | 01               | Invoke the default constructor to create the first instance of em_cmd_mld_reconfig_t. | input: none, output: obj1 instance created                        | No exception; obj1 is successfully created.                      | Should Pass    |
 * | 02               | Invoke the default constructor to create the second instance of em_cmd_mld_reconfig_t. | input: none, output: obj2 instance created                        | No exception; obj2 is successfully created.                      | Should Pass    |
 * | 03               | Call deinit() on the first instance to clean up the object.                   | input: none, output: obj1 deinitialized                             | deinit() executes without throwing exceptions.                   | Should be successful |
 * | 04               | Call deinit() on the second instance to clean up the object.                  | input: none, output: obj2 deinitialized                             | deinit() executes without throwing exceptions.                   | Should be successful |
 */
TEST(em_cmd_mld_reconfig_t, em_cmd_mld_reconfig_t_multiple_instances_sequential)
{
    std::cout << "Entering em_cmd_mld_reconfig_t_multiple_instances_sequential test" << std::endl;
    EXPECT_NO_THROW({
        em_cmd_mld_reconfig_t obj1;
        std::cout << "Invoked default constructor for first instance of em_cmd_mld_reconfig_t" << std::endl;
        em_cmd_mld_reconfig_t obj2;
        std::cout << "Invoked default constructor for second instance of em_cmd_mld_reconfig_t" << std::endl;

	    obj1.deinit();
        obj2.deinit();
    });
    std::cout << "Exiting em_cmd_mld_reconfig_t_multiple_instances_sequential test" << std::endl;
}
