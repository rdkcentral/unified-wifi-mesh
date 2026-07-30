
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
#include "em_cmd_get_radio.h"

/**
 * @brief Verify that the constructor of em_cmd_get_radio_t handles valid inputs correctly.
 *
 * This test validates that when the constructor is provided with valid parameter values, it correctly initializes the object members. The test checks that the type, service, name, and other properties are set as expected, and that the parameters are correctly copied into the object.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Initialize command parameters, including fixed_args and args array, and zero out the structure | param.u.args.fixed_args = "TestFixedArgs", param.u.args.num_args = 1, param.u.args.args[0] = "Arg1" | The param structure is initialized with correct values and padded zeros | Should be successful |
 * | 02 | Invoke the constructor of em_cmd_get_radio_t and verify the object's member initialization | Input: param and dm instances; Expected members: m_type = em_cmd_type_get_radio, m_svc = em_service_type_ctrl, m_name = "get_radio", m_orch_op_idx = 0, m_num_orch_desc = 0, each orch_desc[i].op = 0, orch_desc[i].submit = false, and param members copied correctly | The constructor initializes all members as expected | Should Pass |
 * | 03 | Call the deinit method to clean up the object | Invocation of obj.deinit() | The object's resources are properly released | Should Pass |
 */
TEST(em_cmd_get_radio_t, ConstructorHandlesValidInputs) {
    std::cout << "Entering ConstructorHandlesValidInputs test" << std::endl;
    em_cmd_params_t param;
    memset(&param, 0, sizeof(param));
    const char testFixedArgs[] = "TestFixedArgs";
    strncpy(param.u.args.fixed_args, testFixedArgs, sizeof(param.u.args.fixed_args) - 1);
    param.u.args.fixed_args[sizeof(param.u.args.fixed_args) - 1] = '\0';
    param.u.args.num_args = 1;
    const char testArg[] = "Arg1";
    strncpy(param.u.args.args[0], testArg, sizeof(param.u.args.args[0]) - 1);
    param.u.args.args[0][sizeof(param.u.args.args[0]) - 1] = '\0';
    dm_easy_mesh_t dm;
    em_cmd_get_radio_t obj(param, dm);
    EXPECT_EQ(obj.m_type, em_cmd_type_get_radio);
    EXPECT_EQ(obj.m_svc, em_service_type_ctrl);
    EXPECT_STREQ(obj.m_name, "get_radio");
    EXPECT_EQ(obj.m_orch_op_idx, 0);
    EXPECT_EQ(obj.m_num_orch_desc, 0);
    for (int i = 0; i < EM_MAX_CMD; i++) {
        EXPECT_EQ(obj.m_orch_desc[i].op, 0);      // dm_orch_type_none
        EXPECT_EQ(obj.m_orch_desc[i].submit, false);
    }
    EXPECT_EQ(obj.m_param.u.args.num_args, param.u.args.num_args);
    EXPECT_STREQ(obj.m_param.u.args.fixed_args, param.u.args.fixed_args);
    EXPECT_STREQ(obj.m_param.u.args.args[0], param.u.args.args[0]);
    obj.deinit();
    std::cout << "Exiting ConstructorHandlesValidInputs test" << std::endl;
}
/**
 * @brief Test the behavior of the em_cmd_get_radio_t constructor with empty parameters.
 *
 * This test ensures that the constructor for em_cmd_get_radio_t correctly initializes the object when provided with empty parameters.
 * It verifies that the object's type, name, the number of arguments, and the fixed argument string are set to their expected default values.
 * This test is essential to ensure proper handling of empty parameter inputs.
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
 * | Variation / Step | Description                                                                                                   | Test Data                                                                                     | Expected Result                                                                                                                                       | Notes      |
 * | :----:           | ------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
 * | 01               | Invoke the constructor of em_cmd_get_radio_t with an empty (zeroed) em_cmd_params_t and a default dm_easy_mesh_t    | input1 = param (zeroed using memset), input2 = dm (default initialized)                       | m_type should equal em_cmd_type_get_radio; m_name should equal "get_radio"; num_args should be 0; fixed_args should be an empty string; assertions pass  | Should Pass |
 */
TEST(em_cmd_get_radio_t, ConstructorHandlesEmptyParams)
{
    std::cout << "Entering ConstructorHandlesEmptyParams test" << std::endl;
    em_cmd_params_t param;
    memset(&param, 0, sizeof(param));
    dm_easy_mesh_t dm;
    em_cmd_get_radio_t obj(param, dm);
    EXPECT_EQ(obj.m_type, em_cmd_type_get_radio);
    EXPECT_STREQ(obj.m_name, "get_radio");
    EXPECT_EQ(obj.m_param.u.args.num_args, 0);
    EXPECT_STREQ(obj.m_param.u.args.fixed_args, "");
    obj.deinit();
    std::cout << "Exiting ConstructorHandlesEmptyParams test" << std::endl;
}
