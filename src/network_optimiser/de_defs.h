/**
 * Copyright 2023 Comcast Cable Communications Management, LLC
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
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DE_DEFS_H
#define DE_DEFS_H

#define DE       "Device.WiFi.DataElements."

#define NETWORK                 "Network"
#define DE_NETWORK              DE   "Network."
#define DE_NETWORK_ID           DE_NETWORK   "ID"
#define DE_NETWORK_CTRLID       DE_NETWORK   "ControllerID"

#define SERVICES                 "X_RDK_Services"
#define DE_SERVICES             DE_NETWORK  "X_RDK_Services."
#define DE_SERVICES_TABLE       DE_SERVICES "{i}."
#define DE_SERVICES_ANY         DE_SERVICES "*."
#define DE_SERVICES_TYPE        DE_SERVICES_TABLE     "Type"
#define DE_SERVICES_OPERATOR    DE_SERVICES_TABLE     "Operator"
#define DE_SERVICES_URL         DE_SERVICES_TABLE     "URL"
#define DE_SERVICES_ANY_TYPE        DE_SERVICES_ANY     "Type"
#define DE_SERVICES_ANY_OPERATOR    DE_SERVICES_ANY     "Operator"
#define DE_SERVICES_ANY_URL         DE_SERVICES_ANY     "URL"


#define DEVICES                 "DeviceList"
#define DE_DEVICES             DE_NETWORK  "DeviceList."
#define DE_DEVICES_TABLE       DE_DEVICES "{i}."
#define DE_DEVICES_ANY         DE_DEVICES "*."
#define DE_DEVICES_ID        DE_DEVICES_TABLE     "ID"
#define DE_DEVICES_MANUFACTURER    DE_DEVICES_TABLE     "Manufacturer"
#define DE_DEVICES_MODEL         DE_DEVICES_TABLE     "ManufacturerModel"
#define DE_DEVICES_SERIAL    DE_DEVICES_TABLE     "SerialNumber"
#define DE_DEVICES_VERSION         DE_DEVICES_TABLE     "SoftwareVersion"
#define DE_DEVICES_ANY_ID        DE_DEVICES_ANY     "ID"
#define DE_DEVICES_ANY_MANUFACTURER    DE_DEVICES_ANY     "Manufacturer"
#define DE_DEVICES_ANY_MODEL         DE_DEVICES_ANY     "ManufacturerModel"
#define DE_DEVICES_ANY_SERIAL    DE_DEVICES_ANY     "SerialNumber"
#define DE_DEVICES_ANY_VERSION         DE_DEVICES_ANY     "SoftwareVersion"

#define RADIOS                 "RadioList"
#define DE_RADIOS               DE_DEVICES_TABLE  "RadioList."
#define DE_RADIOS_TABLE         DE_RADIOS "{i}."
#define DE_RADIOS_ANY           DE_RADIOS "*."
#define DE_RADIOS_ID        DE_RADIOS_TABLE     "ID"
#define DE_RADIOS_NOISE        DE_RADIOS_TABLE     "Noise"
#define DE_RADIOS_UTIL        DE_RADIOS_TABLE     "Utilization"
#define DE_RADIOS_ID        DE_RADIOS_TABLE     "ID"
#define DE_RADIOS_ENABLED        DE_RADIOS_TABLE     "Enabled"
#define DE_RADIOS_ANY_ID        DE_RADIOS_ANY     "ID"
#define DE_RADIOS_ANY_ENABLED        DE_RADIOS_ANY     "Enabled"

#define CURR_OP_CLASSES                 "CurrentOperatingClasses"
#define DE_CURR_OP_CLASSES             DE_RADIOS_TABLE  "CurrentOperatingClasses."
#define DE_CURR_OP_CLASSES_TABLE       DE_CURR_OP_CLASSES "{i}."
#define DE_CURR_OP_CLASSES_ANY         DE_CURR_OP_CLASSES "*."
#define DE_CURR_OP_CLASSES_CLASS       DE_CURR_OP_CLASSES_TABLE     "Class"
#define DE_CURR_OP_CLASSES_TXPOWER     DE_CURR_OP_CLASSES_TABLE     "TxPower"
#define DE_CURR_OP_CLASSES_CHANNEL     DE_CURR_OP_CLASSES_TABLE     "Channel"
#define DE_CURR_OP_CLASSES_ANY_CLASS       DE_CURR_OP_CLASSES_ANY     "Class"
#define DE_CURR_OP_CLASSES_ANY_TXPOWER     DE_CURR_OP_CLASSES_ANY     "TxPower"
#define DE_CURR_OP_CLASSES_ANY_CHANNEL     DE_CURR_OP_CLASSES_ANY     "Channel"

#define CAPS                           "Capabilities"
#define DE_CAPS                        DE_RADIOS_TABLE  "Capabilities."
#define DE_CAPS_NUM_OP_CLASS           DE_CAPS     "NumberOfOpClass"
#define DE_CAPS_HT_CAP                 DE_CAPS     "HTCapabilities"

#define OP_CLASSES                     "OperatingClasses"
#define DE_OP_CLASSES                  DE_CAPS  "OperatingClasses."
#define DE_OP_CLASSES_TABLE            DE_OP_CLASSES "{i}."
#define DE_OP_CLASSES_ANY              DE_OP_CLASSES "*."
#define DE_OP_CLASSES_CLASS            DE_OP_CLASSES_TABLE     "Class"
#define DE_OP_CLASSES_MAX_TX_POWER     DE_OP_CLASSES_TABLE     "MaxTxPower"
#define DE_OP_CLASSES_NUM_NON_OP       DE_OP_CLASSES_TABLE     "NumberOfNonOperChan"

#define BSSS                 "BSSList"
#define DE_BSSS               DE_RADIOS_TABLE  "BSSList."
#define DE_BSSS_TABLE         DE_BSSS "{i}."
#define DE_BSSS_ANY           DE_BSSS "*."
#define DE_BSSS_BSSID        DE_BSSS_TABLE     "BSSID"
#define DE_BSSS_SSID        DE_BSSS_TABLE     "SSID"
#define DE_BSSS_ENABLED        DE_BSSS_TABLE     "Enabled"
#define DE_BSSS_TXBSSID        DE_BSSS_TABLE     "TransmittedBSSID"
#define DE_BSSS_FRONT        DE_BSSS_TABLE     "FronthaulUse"
#define DE_BSSS_BACK        DE_BSSS_TABLE     "BackhaulUse"
#define DE_BSSS_ANY_ID        DE_BSSS_ANY     "ID"
#define DE_BSSS_ANY_ENABLED        DE_BSSS_ANY     "Enabled"

#define STAS                 "STAList"
#define DE_STAS               DE_BSSS_TABLE  "STAList."
#define DE_STAS_TABLE         DE_STAS "{i}."
#define DE_STAS_ANY           DE_STAS "*."
#define DE_STAS_MAC           DE_STAS_TABLE     "MACAddress"
#define DE_STAS_RSSI           DE_STAS_TABLE     "SignalStrength"
#define DE_STAS_UL_RATE           DE_STAS_TABLE     "LastDataUplinkRate"
#define DE_STAS_DL_RATE           DE_STAS_TABLE     "LastDataDownlinkRate"
#define DE_STAS_RETRANS           DE_STAS_TABLE     "RetransCount"
#define DE_STAS_PKTS_RX           DE_STAS_TABLE     "PacketsReceived"
#define DE_STAS_PKTS_TX           DE_STAS_TABLE     "PacketsSent"
#define DE_STAS_BYTES_RX           DE_STAS_TABLE     "BytesReceived"
#define DE_STAS_BYTES_TX           DE_STAS_TABLE     "BytesSent"
#define DE_STAS_CAP           DE_STAS_TABLE     "ClientCapabilities"
#define DE_STAS_WIFI6_CAP           DE_STAS_TABLE     "WiFi6Capabilities"
#define DE_STAS_HT_CAP           DE_STAS_TABLE     "HTCapabilities"
#define DE_STAS_VHT_CAP           DE_STAS_TABLE     "VHTCapabilities"
#define DE_STAS_HE_CAP           DE_STAS_TABLE     "HECapabilities"
#define DE_STAS_SEC_ASSOC           DE_STAS_TABLE     "SecurityAssociation"

#define NET_SSIDS           "NetworkSSIDList"
#define DE_NET_SSIDS          DE_NETWORK  "NetworkSSIDList."
#define DE_NET_SSIDS_TABLE         DE_NET_SSIDS "{i}."
#define DE_NET_SSIDS_ANY           DE_NET_SSIDS "*."
#define DE_NET_SSIDS_SSID          DE_NET_SSIDS_TABLE     "SSID"
#define DE_NET_SSIDS_ENABLED          DE_NET_SSIDS_TABLE     "Enable"
#define DE_NET_SSIDS_ADV_ENABLED          DE_NET_SSIDS_TABLE     "AdvertisementEnabled"
#define DE_NET_SSIDS_MFP          DE_NET_SSIDS_TABLE     "MFPConfig"
#define DE_NET_SSIDS_MOB_DOM          DE_NET_SSIDS_TABLE     "MobilityDomain"

typedef enum {
    optimizer_type_comcast,
    optimizer_type_vodafone,
    optimizer_type_dt,
    optimizer_type_generic,
    optimizer_type_none
} optimizer_type_t;

#endif
