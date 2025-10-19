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
        "dm_bsta_mld_t_Test.RetrieveAPMLDInfoAfterNullInitialization:"
        "dm_cac_comp_t_Test.DecodeValidJsonObjectWithNullParentID:"
        "dm_cac_comp_t_Test.DecodeNullJsonObjectWithValidParentID:"
        "dm_cac_comp_t_Test.DecodeEmptyJsonObjectWithValidParentID:"
        "dm_cac_comp_t_Test.DecodeJsonObjectWithInvalidStructureAndValidParentID:"
        "dm_cac_comp_t_Test.DecodeValidJsonObjectWithInvalidParentID:"
        "dm_cac_comp_t_Test.EncodeWithNullObject:"
        "dm_cac_comp_t_Test.CompareDifferentRUIDValues:"
        "dm_cac_comp_t_Test.CompareDifferentOpClassValues:"
        "dm_cac_comp_t_Test.CompareDifferentChannelValues:"
        "dm_cac_comp_t_Test.CompareDifferentStatusValues:"
        "dm_cac_comp_t_Test.CompareDifferentDetectedPairsNumValues:"
        "dm_cac_comp_t_Test.CompareDifferentDetectedPairsValues:"
        "dm_cac_comp_t_Test.AssigningValidObject:"
        "dm_cac_comp_t_Test.AssigningInvalidMacaddress:"
        "dm_cac_comp_t_Test.NullCACComponentInformation:"
        "dm_device_t_Test.DecodeValidJsonObjectWithNullParentId:"
        "dm_device_t_Test.DecodeNullJsonObjectWithValidParentId:"
        "dm_device_t_Test.DecodeInvalidJsonObjectWithValidParentId:"
        "dm_device_t_Test.DecodeEmptyJsonObjectWithValidParentId:"
        "dm_device_t_Test.GetDevInterface_InvalidInterfaceName:"
        "dm_device_t_Test.ParseDeviceIDFromNullKey:"
        "dm_device_t_Test.ParseDeviceIDWithNullIDPointer:"
        "dm_device_t_Test.ParseDeviceIDWithEmptyKeyString:"
        "dm_device_t_Test.ParseDeviceIDWithSpecialCharactersInKey:"
        "dm_device_t_Test.SetInvalidMACAddressNullPointer:"
        "dm_device_t_Test.SetInvalidMACAddressIncorrectFormat:"
        "dm_device_t_Test.SetManufacturerModel_NullModelName:"
        "dm_device_t_Test.SetManufacturerModel_ModelNameExceedingBufferSize:"
        "dm_device_t_Test.SetPrimaryDeviceType_NullPointer:"
        "dm_device_t_Test.SetPrimaryDeviceType_ExceedingBufferSize:"
        "dm_device_t_Test.SetSoftwareVersion_NullVersionString:"
        "dm_device_t_Test.SetDeviceInterfaceNameWithNullPointer:"
        "dm_device_t_Test.UpdateEasyMeshJsonCfg_ColocatedModeEnabled:"
        "dm_device_t_Test.UpdateEasyMeshJsonCfg_ColocatedModeDisabled:"
        "dm_device_t_Test.DifferentDevMac:"
        "dm_device_t_Test.DifferentMediaType:"
        "dm_device_t_Test.DifferentProfiles:"
        "dm_device_t_Test.AssigningValidDeviceInformation:"
        "dm_device_t_Test.InitializeWithNullDeviceInfo:"
        "dm_bss_t_Test.AddValidVendorIE:"
        "dm_bss_t_Test.AddVendorIEWIthNullPointer:"
        "dm_bss_t_Test.AddVendorIEWIthMaximumLength:"
        "dm_bss_t_Test.AddVendorIEWIthEmptyPayload:"
	"dm_bss_t_Test.AddVendorIEWIthZeroLength:"
        "dm_bss_t_Test.DecodeNullJsonObjectWithValidParentID:"
        "dm_bss_t_Test.DecodeValidJsonObjectWithNullParentID:"
        "dm_bss_t_Test.DecodeEmptyJsonObjectWithValidParentID:"
        "dm_bss_t_Test.EncodeValidJSONObjectWithoutSummary:"
        "dm_bss_t_Test.EncodeNullJSONObjectWithoutSummary:"
        "dm_bss_t_Test.EncodeJSONObjectWithArraysWithoutSummary:"
        "dm_bss_t_Test.MatchCriteriaWithEmptyCriteriaString:"
        "dm_bss_t_Test.MatchCriteriaWithNullCriteriaString:"
        "dm_bss_t_Test.MatchCriteriaWithSpecialCharacters:"
        "dm_bss_t_Test.MatchCriteriaWithTabAndNewlineCharacters:"
        "dm_bss_t_Test.ParseBssIdFromInvalidKey:"
        "dm_bss_t_Test.ParseBssIdWithNullKey:"
        "dm_bss_t_Test.ParseBssIdWithNullIdPointer:"
        "dm_bss_t_Test.ParseBssIdWithEmptyKeyString:"
        "dm_bss_t_Test.ParseBssIdWithKeyContainingSpecialCharacters:"
        "dm_bss_t_Test.CompareDifferentLastChange:"
        "dm_bss_t_Test.CompareDifferentTimestamp:"
        "dm_bss_t_Test.CompareDifferentUnicastBytesSent:"
        "dm_bss_t_Test.CompareDifferentUnicastBytesRcvd:"
        "dm_bss_t_Test.CompareDifferentNumberOfSta:"
        "dm_bss_t_Test.CompareDifferentByteCounterUnits:"
        "dm_bss_t_Test.CompareDifferentEhtOps:"
        "dm_bss_t_Test.AssigningMixedValues:"
	"dm_bss_t_Test.RemoveVendorIEWIthNullPointer:"
	"dm_bss_t_Test.NullBSSInformation:"
        "dm_network_ssid_t_Test.NullJsonObject:"
        "dm_network_ssid_t_Test.NullParentID:"
        "dm_network_ssid_t_Test.JsonObjectWithInvalidType:"
        "dm_network_ssid_t_Test.JsonObjectWithEmptyObject:"
        "dm_network_ssid_t_Test.CopyConstructorWithNullObject:"
        "dm_network_ssid_t_Test.NullPointerAsInput:"
        "dm_network_ssid_t_Test.EncodeNullPointer";

    return RUN_ALL_TESTS();
}
