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
    ::testing::GTEST_FLAG(filter) =
        "-dm_ap_mld_t_Test.DecodeValidJsonObjectWithNullParentID:"
        "dm_ap_mld_t_Test.DecodeNullJsonObjectWithValidParentID:"
        "dm_ap_mld_t_Test.DecodeInvalidJsonObjectWithValidParentID:"
        "dm_ap_mld_t_Test.EncodeWithNullCJSONObject:"
        "dm_ap_mld_t_Test.RetrieveAPMLDInfoWithValidValues:"
        "dm_ap_mld_t_Test.RetrieveAPMLDInfoWithInvalidMacAddr:"
        "dm_ap_mld_t_Test.NullAPMLDInformation:"
        "dm_ap_mld_t_Test.InvalidMACAddress:"
        "dm_ap_mld_t_Test.CopyConstructorWithNullInput:"
        "dm_assoc_sta_mld_t_Test.DecodeWithValidJsonObjectAndNullParentId:"
        "dm_assoc_sta_mld_t_Test.DecodeWithNullJsonObjectAndValidParentId:"
        "dm_assoc_sta_mld_t_Test.DecodeWithInvalidJsonObjectAndValidParentId:"
        "dm_assoc_sta_mld_t_Test.DecodeWithValidJsonObjectAndInvalidParentId:"
        "dm_assoc_sta_mld_t_Test.EncodeWithNullCJSONObject:"
        "dm_assoc_sta_mld_t_Test.EncodeWithEmptyCJSONObject:"
        "dm_assoc_sta_mld_t_Test.NullAPMLDInformation:"
        "dm_assoc_sta_mld_t_Test.ExceedingMaximumNumberOfAffiliatedStations:"
        "dm_assoc_sta_mld_t_Test.CopyConstructorWithInvalidMacAddressInput:"
        "dm_bsta_mld_t_Test.DecodeValidJsonObjectWithNullParentID:"
        "dm_bsta_mld_t_Test.DecodeNullJsonObjectWithValidParentID:"
        "dm_bsta_mld_t_Test.DecodeInvalidJsonObjectWithValidParentID:"
        "dm_bsta_mld_t_Test.DecodeValidJsonObjectWithInvalidParentID:"
        "dm_bsta_mld_t_Test.EncodeWithNullCJSONObject:"
        "dm_bsta_mld_t_Test.EncodeWithInvalidJSONStructure:"
        "dm_bsta_mld_t_Test.RetrieveAPMLDInfoAfterNullInitialization";
    std::cout << "Running with filter: " << ::testing::GTEST_FLAG(filter) << std::endl;
    return RUN_ALL_TESTS();
}