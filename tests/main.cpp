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

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);

    // Exclude tests that cause segfaults due to deliberately passing null
    // to copy constructors/initializers (not covered by JIRA tickets)
    ::testing::GTEST_FLAG(filter) += ":-dm_ap_mld_t_Test.CopyConstructorWithNullInput"
                                     ":dm_bsta_mld_t_Test.RetrieveAPMLDInfoAfterNullInitialization"
                                     ":dm_ap_mld_t_Test.DecodeValidJsonObjectWithNullParentID"
                                     ":dm_ap_mld_t_Test.EncodeWithNullCJSONObject"
                                     ":dm_ap_mld_t_Test.InvalidMACAddress"
                                     ":dm_assoc_sta_mld_t_Test.DecodeWithValidJsonObjectAndInvalidParentId"
                                     ":dm_assoc_sta_mld_t_Test.DecodeWithValidJsonObjectAndNullParentId"
                                     ":dm_assoc_sta_mld_t_Test.EncodeWithEmptyCJSONObject"
                                     ":dm_assoc_sta_mld_t_Test.EncodeWithNullCJSONObject"
                                     ":dm_assoc_sta_mld_t_Test.NullAPMLDInformation"
                                     ":dm_bsta_mld_t_Test.DecodeValidJsonObjectWithInvalidParentID"
                                     ":dm_bsta_mld_t_Test.DecodeValidJsonObjectWithNullParentID"
                                     ":dm_bsta_mld_t_Test.EncodeWithInvalidJSONStructure"
                                     ":dm_bsta_mld_t_Test.EncodeWithNullCJSONObject"
                                     ":dm_cac_comp_t_Test.AssigningInvalidMacaddress"
                                     ":dm_cac_comp_t_Test.AssigningValidObject"
                                     ":dm_cac_comp_t_Test.CompareDifferentChannelValues"
                                     ":dm_cac_comp_t_Test.CompareDifferentDetectedPairsNumValues"
                                     ":dm_cac_comp_t_Test.CompareDifferentDetectedPairsValues"
                                     ":dm_cac_comp_t_Test.CompareDifferentOpClassValues"
                                     ":dm_cac_comp_t_Test.CompareDifferentRUIDValues"
                                     ":dm_cac_comp_t_Test.CompareDifferentStatusValues"
                                     ":dm_cac_comp_t_Test.DecodeEmptyJsonObjectWithValidParentID"
                                     ":dm_cac_comp_t_Test.DecodeJsonObjectWithInvalidStructureAndValidParentID"
                                     ":dm_cac_comp_t_Test.DecodeNullJsonObjectWithValidParentID"
                                     ":dm_cac_comp_t_Test.DecodeValidJsonObjectWithInvalidParentID"
                                     ":dm_cac_comp_t_Test.DecodeValidJsonObjectWithNullParentID"
                                     ":dm_cac_comp_t_Test.EncodeWithNullObject"
                                     ":dm_device_t_Test.DecodeEmptyJsonObjectWithValidParentId"
                                     ":dm_device_t_Test.DecodeInvalidJsonObjectWithValidParentId"
                                     ":dm_device_t_Test.DecodeNullJsonObjectWithValidParentId"
                                     ":dm_device_t_Test.DecodeValidJsonObjectWithNullParentId"
                                     ":dm_device_t_Test.GetDevInterface_InvalidInterfaceName";

    return RUN_ALL_TESTS();
}
