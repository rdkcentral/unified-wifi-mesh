
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
#include "em_cmd_set_ssid.h"



/**
 * @brief Validate construction of em_cmd_set_ssid_t with valid non-empty fixed arguments
 *
 * This test verifies that creating an instance of em_cmd_set_ssid_t using valid parameters (non-empty fixed_args "MySSID" and num_args 1) correctly initializes all command object members.
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
 * | 01 | Construct em_cmd_set_ssid_t with valid parameters and verify the initialization of all data members | num_args = 1, args[0] = "MySSID", fixed_args = "MySSID", dm instance = valid object | Command object m_param, m_type, m_orch_op_idx, m_num_orch_desc, m_orch_desc, m_name, m_svc, and m_data_model are set to expected values and all assertions pass | Should Pass |
 */
TEST(em_cmd_set_ssid_t, em_cmd_set_ssid_t_ConstructValidNonEmptyFixedArgs)
{
    std::cout << "Entering em_cmd_set_ssid_t_ConstructValidNonEmptyFixedArgs test" << std::endl;
    em_cmd_params_t params;
    params.u.args.num_args = 1;
    strncpy(params.u.args.args[0], "MySSID", sizeof(params.u.args.args[0]) );
    strncpy(params.u.args.fixed_args, "MySSID", sizeof(params.u.args.fixed_args));
    dm_easy_mesh_t dm;
    std::cout << "Invoking em_cmd_set_ssid_t with fixed_args: " << params.u.args.fixed_args << std::endl;
    em_cmd_set_ssid_t cmd(params, dm);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "MySSID");
    EXPECT_EQ(cmd.m_param.u.args.num_args, 1);
    EXPECT_STREQ(cmd.m_param.u.args.args[0], "MySSID");
    EXPECT_EQ(cmd.m_type, em_cmd_type_set_ssid);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 3);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_db_cfg);
    EXPECT_EQ(cmd.m_orch_desc[1].op, dm_orch_type_em_update);
    EXPECT_TRUE(cmd.m_orch_desc[1].submit);
    EXPECT_EQ(cmd.m_orch_desc[2].op, dm_orch_type_net_ssid_update);
    EXPECT_STREQ(cmd.m_name, "set_ssid");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_db_cfg);
    cmd.deinit();
    std::cout << "Exiting em_cmd_set_ssid_t_ConstructValidNonEmptyFixedArgs test" << std::endl;
}
/**
 * @brief Verifies the construction of em_cmd_set_ssid_t with empty fixed arguments.
 *
 * This test case validates that when the em_cmd_set_ssid_t constructor is invoked with an empty 
 * fixed arguments string (and num_args set to 0), all properties of the command are correctly initialized. 
 * It checks that the fixed arguments, number of arguments, command type, orchestration indices, 
 * orchestration descriptors, command name, service type, and command context type are set as expected.
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
 * | 01 | Initialize em_cmd_params_t with num_args set to 0 and fixed_args set to an empty string, create dm_easy_mesh_t instance, and invoke the em_cmd_set_ssid_t constructor. | params.u.args.num_args = 0, params.u.args.fixed_args = "", dm instance created | cmd.m_param.u.args.fixed_args equals "", cmd.m_param.u.args.num_args equals 0, cmd.m_type equals em_cmd_type_set_ssid, cmd.m_orch_op_idx equals 0, cmd.m_num_orch_desc equals 3, m_orch_desc[0].op equals dm_orch_type_db_cfg, m_orch_desc[1].op equals dm_orch_type_em_update with submit true, m_orch_desc[2].op equals dm_orch_type_net_ssid_update, cmd.m_name equals "set_ssid", cmd.m_svc equals em_service_type_ctrl, m_cmd_ctx.type equals dm_orch_type_db_cfg | Should Pass |
 */
TEST(em_cmd_set_ssid_t, em_cmd_set_ssid_t_ConstructWithEmptyFixedArgs)
{
    std::cout << "Entering em_cmd_set_ssid_t_ConstructWithEmptyFixedArgs test" << std::endl;
    em_cmd_params_t params;
    params.u.args.num_args = 0;
    strncpy(params.u.args.fixed_args, "", sizeof(params.u.args.fixed_args));
    dm_easy_mesh_t dm;
    std::cout << "Invoking em_cmd_set_ssid_t with fixed_args: \"" << params.u.args.fixed_args << "\"" << std::endl;
    em_cmd_set_ssid_t cmd(params, dm);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "");
    EXPECT_EQ(cmd.m_param.u.args.num_args, 0);
    EXPECT_EQ(cmd.m_type, em_cmd_type_set_ssid);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 3);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_db_cfg);
    EXPECT_EQ(cmd.m_orch_desc[1].op, dm_orch_type_em_update);
    EXPECT_TRUE(cmd.m_orch_desc[1].submit);
    EXPECT_EQ(cmd.m_orch_desc[2].op, dm_orch_type_net_ssid_update);
    EXPECT_STREQ(cmd.m_name, "set_ssid");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_db_cfg);
    cmd.deinit();
    std::cout << "Exiting em_cmd_set_ssid_t_ConstructWithEmptyFixedArgs test" << std::endl;
}
/**
 * @brief Verify construction of em_cmd_set_ssid_t with maximum SSID length
 *
 * This test verifies that the em_cmd_set_ssid_t object is correctly constructed when provided with a maximum length SSID string. It validates that all parameters, including the fixed arguments and command type, are appropriately initialized to meet the defined constraints.
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
 * | Variation / Step | Description | Test Data | Expected Result | Notes |
 * | :----: | --------- | ---------- |-------------- | ----- |
 * | 01 | Create a max length SSID string and initialize command parameters. | maxSsid = 127 'a' characters + '\\0', params.u.args.num_args = 1, params.u.args.args[0] = maxSsid, params.u.args.fixed_args = maxSsid | SSID string created with length 127 and correctly placed in parameters. | Should Pass |
 * | 02 | Invoke the em_cmd_set_ssid_t constructor with initialized parameters and a dm_easy_mesh_t instance. | params (with maxSsid), dm (instance of dm_easy_mesh_t) | Command object is initialized with proper internal state. | Should Pass |
 * | 03 | Validate the command object attributes using assertion checks. | Verification of: strlen(cmd.m_param.u.args.fixed_args) = 127, cmd.m_param.u.args.fixed_args equals maxSsid, cmd.m_param.u.args.num_args = 1, cmd.m_type = em_cmd_type_set_ssid, cmd.m_orch_op_idx = 0, cmd.m_num_orch_desc = 3, cmd.m_orch_desc[0].op = dm_orch_type_db_cfg, cmd.m_orch_desc[1].op = dm_orch_type_em_update, cmd.m_orch_desc[1].submit = true, cmd.m_orch_desc[2].op = dm_orch_type_net_ssid_update, cmd.m_name equals "set_ssid", cmd.m_svc = em_service_type_ctrl, cmd.m_data_model.m_cmd_ctx.type = dm_orch_type_db_cfg | All assertions pass confirming correct state initialization. | Should Pass |
 * | 04 | Cleanup the command object and log test exit. | Invocation of cmd.deinit() | Resources released without error and proper log message printed. | Should be successful |
 */
TEST(em_cmd_set_ssid_t, em_cmd_set_ssid_t_ConstructWithMaxSSIDLength)
{
    std::cout << "Entering em_cmd_set_ssid_t_ConstructWithMaxSSIDLength test" << std::endl;
    char maxSsid[128];
    memset(maxSsid, 'a', 127);
    maxSsid[127] = '\0';
    em_cmd_params_t params;
    params.u.args.num_args = 1;
    strncpy(params.u.args.args[0], maxSsid, sizeof(params.u.args.args[0]));
    strncpy(params.u.args.fixed_args, maxSsid, sizeof(params.u.args.fixed_args));
    dm_easy_mesh_t dm;
    em_cmd_set_ssid_t cmd(params, dm);
    std::cout << "Invoked em_cmd_set_ssid_t with fixed_args of length " << strlen(params.u.args.fixed_args) << std::endl;
    EXPECT_EQ(strlen(cmd.m_param.u.args.fixed_args), 127);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, maxSsid);
    EXPECT_EQ(cmd.m_param.u.args.num_args, 1);
    EXPECT_EQ(cmd.m_type, em_cmd_type_set_ssid);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 3);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_db_cfg);
    EXPECT_EQ(cmd.m_orch_desc[1].op, dm_orch_type_em_update);
    EXPECT_TRUE(cmd.m_orch_desc[1].submit);
    EXPECT_EQ(cmd.m_orch_desc[2].op, dm_orch_type_net_ssid_update);
    EXPECT_STREQ(cmd.m_name, "set_ssid");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_db_cfg);
    cmd.deinit();
    std::cout << "Exiting em_cmd_set_ssid_t_ConstructWithMaxSSIDLength test" << std::endl;
}
/**
 * @brief Test construction of em_cmd_set_ssid_t with a pre-initialized data model.
 *
 * This test verifies that the em_cmd_set_ssid_t object is correctly constructed when provided with valid parameters and a pre-initialized dm_easy_mesh_t object. It checks that the command object's fields are properly initialized and configured.
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
 * | :----: | --------- | ---------- | -------------- | ----- |
 * | 01 | Initialize command parameters by setting num_args = 1, args[0] = "PreInitSSID", and fixed_args = "PreInitSSID" | input: params.u.args.num_args = 1, params.u.args.args[0] = "PreInitSSID", params.u.args.fixed_args = "PreInitSSID" | Parameters are successfully set in the params structure | Should be successful |
 * | 02 | Initialize dm object with the network id "Network123" | input: dm.m_network.m_net_info.id = "Network123" | DM object is prepared with the proper network id | Should be successful |
 * | 03 | Invoke the em_cmd_set_ssid_t constructor with prepared params and dm, then validate returned object's fields | input: params and dm; output: cmd object with: fixed_args = "PreInitSSID", num_args = 1, m_type = em_cmd_type_set_ssid, m_orch_op_idx = 0, m_num_orch_desc = 3, orch_desc[0].op = dm_orch_type_db_cfg, orch_desc[1].op = dm_orch_type_em_update with submit true, orch_desc[2].op = dm_orch_type_net_ssid_update, m_name = "set_ssid", m_svc = em_service_type_ctrl, m_data_model.m_cmd_ctx.type = dm_orch_type_db_cfg | All fields match the expected values and assertions pass | Should Pass |
 * | 04 | Cleanup the cmd object by invoking deinit() | output: cmd.deinit() is called | The command object is successfully deinitialized | Should be successful |
 */
TEST(em_cmd_set_ssid_t, em_cmd_set_ssid_t_ConstructWithInitializedDM)
{
    std::cout << "Entering em_cmd_set_ssid_t_ConstructWithInitializedDM test" << std::endl;
    em_cmd_params_t params;
    params.u.args.num_args = 1;
    strncpy(params.u.args.args[0], "PreInitSSID", sizeof(params.u.args.args[0]));
    strncpy(params.u.args.fixed_args, "PreInitSSID", sizeof(params.u.args.fixed_args));
    dm_easy_mesh_t dm{};
    strncpy(dm.m_network.m_net_info.id, "Network123", sizeof(dm.m_network.m_net_info.id));
    std::cout << "Invoking em_cmd_set_ssid_t with fixed_args: " << params.u.args.fixed_args << " and pre-initialized dm network id: " << dm.m_network.m_net_info.id << std::endl;
    em_cmd_set_ssid_t cmd(params, dm);
    EXPECT_STREQ(cmd.m_param.u.args.fixed_args, "PreInitSSID");
    EXPECT_EQ(cmd.m_param.u.args.num_args, 1);
    EXPECT_EQ(cmd.m_type, em_cmd_type_set_ssid);
    EXPECT_EQ(cmd.m_orch_op_idx, 0);
    EXPECT_EQ(cmd.m_num_orch_desc, 3);
    EXPECT_EQ(cmd.m_orch_desc[0].op, dm_orch_type_db_cfg);
    EXPECT_EQ(cmd.m_orch_desc[1].op, dm_orch_type_em_update);
    EXPECT_TRUE(cmd.m_orch_desc[1].submit);
    EXPECT_EQ(cmd.m_orch_desc[2].op, dm_orch_type_net_ssid_update);
    EXPECT_STREQ(cmd.m_name, "set_ssid");
    EXPECT_EQ(cmd.m_svc, em_service_type_ctrl);
    EXPECT_EQ(cmd.m_data_model.m_cmd_ctx.type, dm_orch_type_db_cfg);
    cmd.deinit();
    std::cout << "Exiting em_cmd_set_ssid_t_ConstructWithInitializedDM test" << std::endl;
}
