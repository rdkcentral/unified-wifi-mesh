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

#ifndef TR_181_H
#define TR_181_H

#include "bus.h"
#include "dm_easy_mesh.h"
#include <string>
#include <memory>
#include <cjson/cJSON.h>
#include <unistd.h>

#define DEVICE_WIFI_DATAELEMENTS_NETWORK_COLOCATEDAGENTID   "Device.WiFi.DataElements.Network.ColocatedAgentID"
#define DEVICE_WIFI_DATAELEMENTS_NETWORK_CONTROLLERID       "Device.WiFi.DataElements.Network.ControllerID"
//#define DEVICE_WIFI_DATAELEMENTS_NETWORK_SETSSID_CMD "Device.WiFi.DataElements.Network.SetSSID()"
#define DEVICE_WIFI_DATAELEMENTS_NETWORK_SETSSID_CMD        "Device.WiFi.DataElements.Network.SetSSID"
//Orchestrator
#define DEVICE_WIFI_DATAELEMENTS_NETWORK_TOPOLOGY           "Device.WiFi.DataElements.Network.Topology"
#define DEVICE_WIFI_DATAELEMENTS_NETWORK_NODE_SYNC          "Device.WiFi.DataElements.Network.NodeSynchronize"
#define DEVICE_WIFI_DATAELEMENTS_NETWORK_NODE_CFG_POLICY    "Device.WiFi.DataElements.Network.NodeConfigurePolicy"

#define LIST_OF_DEFINITION_NAME "List_Of_Def"
#define MAX_NUM_OF_OBJECTS_NAME "Num_Of_Objects"

typedef struct {
    uint32_t id;
    bus_error_t rc;
} bus_resp_get_t;
typedef struct bus_data_cb_func {
    char                  *cb_table_name;
    bus_callback_table_t  cb_func;
} bus_data_cb_func_t;


// #define DATAELEMS_NETWORK       "Device.WiFi.DataElements.Network."
#define DATAELEMS_NETWORK       "Network."

#define MAX_INSTANCE_LEN        32
#define MAX_CAPS_STR_LEN        32
#define ARRAY_SIZE(a)           (sizeof(a) / sizeof(a[0]))

/* Device.WiFi.DataElements.Network */
#define DE_NETWORK_ID           DATAELEMS_NETWORK       "ID"
#define DE_NETWORK_CTRLID       DATAELEMS_NETWORK       "ControllerID"
#define DE_NETWORK_COLAGTID     DATAELEMS_NETWORK       "ColocatedAgentID"
// #define DE_NETWORK_DEVNOE       DATAELEMS_NETWORK       "DeviceNumberOfEntries"NumberOfDevices
#define DE_NETWORK_DEVNOE       DATAELEMS_NETWORK       "NumberOfDevices"
#define DE_NETWORK_SETSSID      DATAELEMS_NETWORK       "SetSSID()"
/* Device.WiFi.DataElements.Network.SSID */
// #define DE_NETWORK_SSID         DATAELEMS_NETWORK       "SSID.{i}."
#define DE_NETWORK_SSID         DATAELEMS_NETWORK       "NetworkSSIDList.{i}."
#define DE_SSID_TABLE           DE_NETWORK_SSID
#define DE_SSID_SSID            DE_NETWORK_SSID         "SSID"
#define DE_SSID_BAND            DE_NETWORK_SSID         "Band"
#define DE_SSID_ENABLE          DE_NETWORK_SSID         "Enable"
#define DE_SSID_AKMALLOWE       DE_NETWORK_SSID         "AKMsAllowed"
#define DE_SSID_SUITESEL        DE_NETWORK_SSID         "SuiteSelector"
#define DE_SSID_ADVENABLED      DE_NETWORK_SSID         "AdvertisementEnabled"
#define DE_SSID_MFPCONFIG       DE_NETWORK_SSID         "MFPConfig"
#define DE_SSID_MOBDOMAIN       DE_NETWORK_SSID         "MobilityDomain"
#define DE_SSID_HAULTYPE        DE_NETWORK_SSID         "HaulType"
/* Device.WiFi.DataElements.Network.Device */
// #define DE_NETWORK_DEVICE       DATAELEMS_NETWORK       "Device.{i}."
#define DE_NETWORK_DEVICE       DATAELEMS_NETWORK       "DeviceList.{i}."
#define DE_DEVICE_TABLE         DE_NETWORK_DEVICE
#define DE_DEVICE_ID            DE_NETWORK_DEVICE       "ID"
#define DE_DEVICE_MAPCAP        DE_NETWORK_DEVICE       "MultiAPCapabilities"
#define DE_DEVICE_NUMRADIO      DE_NETWORK_DEVICE       "NumberOfRadios"
#define DE_DEVICE_COLLINT       DE_NETWORK_DEVICE       "CollectionInterval"
#define DE_DEVICE_RUASSOC       DE_NETWORK_DEVICE       "ReportUnsuccessfulAssociations"
#define DE_DEVICE_MAXRRATE      DE_NETWORK_DEVICE       "MaxReportingRate"
#define DE_DEVICE_MAPPROF       DE_NETWORK_DEVICE       "MultiAPProfile"
#define DE_DEVICE_APMERINT      DE_NETWORK_DEVICE       "APMetricsReportingInterval"
#define DE_DEVICE_MANUFACT      DE_NETWORK_DEVICE       "Manufacturer"
#define DE_DEVICE_SERIALNO      DE_NETWORK_DEVICE       "SerialNumber"
#define DE_DEVICE_MFCMODEL      DE_NETWORK_DEVICE       "ManufacturerModel"
#define DE_DEVICE_SWVERSION     DE_NETWORK_DEVICE       "SoftwareVersion"
#define DE_DEVICE_EXECENV       DE_NETWORK_DEVICE       "ExecutionEnv"
#define DE_DEVICE_LSDSTALIST    DE_NETWORK_DEVICE       "LocalSteeringDisallowedSTAList"
#define DE_DEVICE_BTMSDSTALIST  DE_NETWORK_DEVICE       "BTMSteeringDisallowedSTAList"
#define DE_DEVICE_MAXVIDS       DE_NETWORK_DEVICE       "MaxVIDs"
#define DE_DEVICE_BPRIO         DE_NETWORK_DEVICE       "BasicPrioritization"
#define DE_DEVICE_EPRIO         DE_NETWORK_DEVICE       "EnhancedPrioritization"
#define DE_DEVICE_TSEPPOLI      DE_NETWORK_DEVICE       "TrafficSeparationPolicy"
#define DE_DEVICE_STVMAP        DE_NETWORK_DEVICE       "SSIDtoVIDMapping"
#define DE_DEVICE_DSCPM         DE_NETWORK_DEVICE       "DSCPMap"
#define DE_DEVICE_MAXPRIRULE    DE_NETWORK_DEVICE       "MaxPrioritizationRules"
#define DE_DEVICE_COUNTRCODE    DE_NETWORK_DEVICE       "CountryCode"
#define DE_DEVICE_PRIOSUPP      DE_NETWORK_DEVICE       "PrioritizationSupport"
#define DE_DEVICE_REPINDSCAN    DE_NETWORK_DEVICE       "ReportIndependentScans"
#define DE_DEVICE_TRASEPALW     DE_NETWORK_DEVICE       "TrafficSeparationAllowed"
#define DE_DEVICE_SERPRIOALW    DE_NETWORK_DEVICE       "ServicePrioritizationAllowed"
#define DE_DEVICE_STASDISALW    DE_NETWORK_DEVICE       "STASteeringDisallowed"
#define DE_DEVICE_DFSENABLE     DE_NETWORK_DEVICE       "DFSEnable"
#define DE_DEVICE_MAXUSASSOCREPRATE    DE_NETWORK_DEVICE       "MaxUnsuccessfulAssociationReportingRate"
#define DE_DEVICE_STASSTATE     DE_NETWORK_DEVICE       "STASteeringState"
#define DE_DEVICE_COORCACALW    DE_NETWORK_DEVICE       "CoordinatedCACAllowed"
#define DE_DEVICE_CONOPMODE     DE_NETWORK_DEVICE       "ControllerOperationMode"
#define DE_DEVICE_BHMACADDR     DE_NETWORK_DEVICE       "BackhaulMACAddress"
#define DE_DEVICE_BHDMACADDR    DE_NETWORK_DEVICE       "BackhaulDownMACAddress"
#define DE_DEVICE_BHPHYRATE     DE_NETWORK_DEVICE       "BackhaulPHYRate"
#define DE_DEVICE_TRSEPCAP      DE_NETWORK_DEVICE       "TrafficSeparationCapability"
#define DE_DEVICE_EASYCCAP      DE_NETWORK_DEVICE       "EasyConnectCapability"
#define DE_DEVICE_TESTCAP       DE_NETWORK_DEVICE       "TestCapabilities"
#define DE_DEVICE_BSTAMLDMACLINK    DE_NETWORK_DEVICE       "bSTAMLDMaxLinks"
#define DE_DEVICE_MACNUMMLDS    DE_NETWORK_DEVICE       "MaxNumMLDs"
#define DE_DEVICE_BHALID        DE_NETWORK_DEVICE       "BackhaulALID"
#define DE_DEVICE_TIDLMAP       DE_NETWORK_DEVICE       "TIDLinkMapping"
#define DE_DEVICE_ASSOCSTAREPINT    DE_NETWORK_DEVICE       "AssociatedSTAReportingInterval"
#define DE_DEVICE_BHMEDIATYPE   DE_NETWORK_DEVICE       "BackhaulMediaType"
#define DE_DEVICE_RADIONOE      DE_NETWORK_DEVICE       "RadioNumberOfEntries"
#define DE_DEVICE_CACSTATNOE    DE_NETWORK_DEVICE       "CACStatusNumberOfEntries"
#define DE_DEVICE_BHDOWNNOE     DE_NETWORK_DEVICE       "BackhaulDownNumberOfEntries"
/* Device.WiFi.DataElements.Network.Device.CACStatus */
#define DE_DEVICE_CACSTAT       DE_NETWORK_DEVICE       "CACStatus.{i}."
#define DE_CACSTAT_TABLE        DE_DEVICE_CACSTAT
#define DE_CACSTAT_NONOCCNOE    DE_DEVICE_CACSTAT       "CACNonOccupancyChannelNumberOfEntries"
/* Device.WiFi.DataElements.Network.Device.CACStatus.CACNonOccupancyChannel */
#define DE_CACSTAT_CACNON       DE_DEVICE_CACSTAT       "CACNonOccupancyChannel.{i}."
#define DE_CACNON_TABLE         DE_CACSTAT_CACNON
#define DE_CACNON_OPCLASS       DE_CACSTAT_CACNON       "OpClass"
#define DE_CACNON_CHANNEL       DE_CACSTAT_CACNON       "Channel"
#define DE_CACNON_SECONDS       DE_CACSTAT_CACNON       "Seconds"
/* Device.WiFi.DataElements.Network.Device.BackhaulDown */
#define DE_DEVICE_BHDOWN        DE_NETWORK_DEVICE       "BackhaulDown.{i}."
#define DE_BHDOWN_TABLE         DE_DEVICE_BHDOWN
#define DE_BHDOWN_ALID          DE_DEVICE_BHDOWN        "BackhaulDownALID"
#define DE_BHDOWN_MACADDR       DE_DEVICE_BHDOWN        "BackhaulDownMACAddress"
/* Device.WiFi.DataElements.Network.Device.MultiAPDevice */
#define DE_DEVICE_MAPDEV        DE_NETWORK_DEVICE       "MultiAPDevice."
/* Device.WiFi.DataElements.Network.Device.MultiAPDevice.Backhaul */
#define DE_MAPDEV_BACKHAUL      DE_DEVICE_MAPDEV        "Backhaul."
/* Device.WiFi.DataElements.Network.Device.MultiAPDevice.Backhaul.Stats */
#define DE_MAPDEVBH_STATS       DE_MAPDEV_BACKHAUL      "Stats."
#define DE_MDBHSTATS_BYTESSNT   DE_MAPDEVBH_STATS       "BytesSent"
#define DE_MDBHSTATS_BYTESRCV   DE_MAPDEVBH_STATS       "BytesReceived"
#define DE_MDBHSTATS_PCKTSSNT   DE_MAPDEVBH_STATS       "PacketsSent"
#define DE_MDBHSTATS_PCKTSRCV   DE_MAPDEVBH_STATS       "PacketsReceived"
#define DE_MDBHSTATS_ERRSSNT    DE_MAPDEVBH_STATS       "ErrorsSent"
#define DE_MDBHSTATS_ERRSRCV    DE_MAPDEVBH_STATS       "ErrorsReceived"
#define DE_MDBHSTATS_LINKUTIL   DE_MAPDEVBH_STATS       "LinkUtilization"
#define DE_MDBHSTATS_SIGNALSTR  DE_MAPDEVBH_STATS       "SignalStrength"
#define DE_MDBHSTATS_LSTDTADLR  DE_MAPDEVBH_STATS       "LastDataDownlinkRate"
#define DE_MDBHSTATS_LSTDTAULR  DE_MAPDEVBH_STATS       "LastDataUplinkRate"
/* Device.WiFi.DataElements.Network.Device.Radio */
// #define DE_DEVICE_RADIO         DE_NETWORK_DEVICE       "Radio.{i}."
#define DE_DEVICE_RADIO         DE_NETWORK_DEVICE       "RadioList.{i}."
#define DE_RADIO_TABLE          DE_DEVICE_RADIO
#define DE_RADIO_ID             DE_DEVICE_RADIO         "ID"
#define DE_RADIO_ENABLED        DE_DEVICE_RADIO         "Enabled"
#define DE_RADIO_NUMCUROPCLASS  DE_DEVICE_RADIO         "NumberOfCurrOpClass"
#define DE_RADIO_NOISE          DE_DEVICE_RADIO         "Noise"
#define DE_RADIO_UTILIZATION    DE_DEVICE_RADIO         "Utilization"
#define DE_RADIO_TRANSMIT       DE_DEVICE_RADIO         "Transmit"
#define DE_RADIO_RECEIVESELF    DE_DEVICE_RADIO         "ReceiveSelf"
#define DE_RADIO_RECEIVEOTHER   DE_DEVICE_RADIO         "ReceiveOther"
#define DE_RADIO_CHIPVENDOR     DE_DEVICE_RADIO         "ChipsetVendor"
#define DE_RADIO_CURROPNOE      DE_DEVICE_RADIO         "CurrentOperatingClassProfileNumberOfEntries"
#define DE_RADIO_BSSNOE         DE_DEVICE_RADIO         "NumberOfBSS"
#define DE_RADIO_UNASSCSTALIST  DE_DEVICE_RADIO         "UnassociatedStaList"
#define DE_RADIO_NOUNASSCSTA    DE_DEVICE_RADIO         "NumberOfUnassocSta"
/* Device.WiFi.DataElements.Network.Device.Radio.BackhaulSta */
#define DE_RADIO_BHSTA          DE_DEVICE_RADIO         "BackhaulSta."
#define DE_BHSTA_MACADDR        DE_RADIO_BHSTA          "MACAddress"
/* Device.WiFi.DataElements.Network.Device.Radio.Capabilities */
#define DE_RADIO_CAPS           DE_DEVICE_RADIO         "Capabilities."
#define DE_RCAPS_HTCAPS         DE_RADIO_CAPS           "HTCapabilities"
#define DE_RCAPS_VHTCAPS        DE_RADIO_CAPS           "VHTCapabilities"
#define DE_RCAPS_CAPOPNOE       DE_RADIO_CAPS           "CapableOperatingClassProfileNumberOfEntries"
#define DE_RADIO_AKM_FH         DE_DEVICE_RADIO 	    "AKMFrontHaul"
#define DE_RADIO_AKM_BH         DE_DEVICE_RADIO 	    "AKMBackHaul"
#define DE_RADIO_NUM_OPCLASS    DE_DEVICE_RADIO 	    "NumberOfOpClass"
#define DE_RADIO_DSCP_POLICY    DE_DEVICE_RADIO 	    "DSCPPolicyCapability"
#define DE_RADIO_SCSTRAFDESC    DE_DEVICE_RADIO 	    "SCSTrafficDescriptionCapability"
#define DE_RADIO_MSCS_CAP       DE_DEVICE_RADIO 	    "MSCSCapability"
#define DE_RADIO_SCS_CAP        DE_DEVICE_RADIO 	    "SCSCapability"
#define DE_RADIO_QOSMAP_CAP     DE_DEVICE_RADIO 	    "QoSMapCapability"
/* Device.WiFi.DataElements.Network.Device.Radio.Capabilities.WiFi6APRole */
#define DE_CAPS_WF6AP           DE_RADIO_CAPS           "WiFi6APRole."
#define DE_WF6AP_HE160          DE_CAPS_WF6AP           "HE160"
#define DE_WF6AP_MCSNSS         DE_CAPS_WF6AP           "MCSNSS"
#define DE_RADIO_SU_BFER        DE_DEVICE_RADIO   	    "SUBeamformer"
#define DE_RADIO_SU_BFEE        DE_DEVICE_RADIO   		"SUBeamformee"
#define DE_RADIO_MU_BFER        DE_DEVICE_RADIO   		"MUBeamformer"
#define DE_RADIO_BFEE_80_LESS   DE_DEVICE_RADIO   		"Beamformee80orLess"
#define DE_RADIO_BFEE_ABV_80    DE_DEVICE_RADIO   		"BeamformeeAbove80"
#define DE_RADIO_UL_MUMIMO      DE_DEVICE_RADIO   		"ULMUMIMO"
#define DE_RADIO_UL_OFDMA       DE_DEVICE_RADIO   		"ULOFDMA"
#define DE_RADIO_DL_OFDMA       DE_DEVICE_RADIO   		"DLOFDMA"
#define DE_RADIO_MAX_DL_MUMIMO  DE_DEVICE_RADIO   		"MaxDLMUMIMO"
#define DE_RADIO_MAX_UL_MUMIMO  DE_DEVICE_RADIO   		"MaxULMUMIMO"
#define DE_RADIO_MAX_DL_OFDMA   DE_DEVICE_RADIO   		"MaxDLOFDMA"
#define DE_RADIO_MAX_UL_OFDMA   DE_DEVICE_RADIO   		"MaxULOFDMA"
#define DE_RADIO_RTS            DE_DEVICE_RADIO   		"RTS"
#define DE_RADIO_MU_RTS         DE_DEVICE_RADIO   		"MURTS"
#define DE_RADIO_MULTI_BSSID    DE_DEVICE_RADIO   		"MultiBSSID"
#define DE_RADIO_MUEDCA         DE_DEVICE_RADIO   		"MUEDCA"
#define DE_RADIO_TWT_REQ        DE_DEVICE_RADIO   		"TWTRequestor"
#define DE_RADIO_TWT_RSP        DE_DEVICE_RADIO   		"TWTResponder"
#define DE_RADIO_SPATIAL_REUSE  DE_DEVICE_RADIO   		"SpatialReuse"
#define DE_RADIO_ANT_CH_USAGE   DE_DEVICE_RADIO   		"AnticipatedChannelUsage"
/* Device.WiFi.DataElements.Network.Device.Radio.Capabilities.WiFi6bSTARole */
#define DE_CAPS_WF6BSTA         DE_RADIO_CAPS           "WiFi6bSTARole."
#define DE_WF6BSTA_HE160        DE_CAPS_WF6BSTA         "HE160"
#define DE_WF6BSTA_MCSNSS       DE_CAPS_WF6BSTA         "MCSNSS"
#define DE_RADIO_BSTA_SU_BFER        DE_DEVICE_RADIO   		"SUBeamformer"
#define DE_RADIO_BSTA_SU_BFEE        DE_DEVICE_RADIO   		"SUBeamformee"
#define DE_RADIO_BSTA_MU_BFER        DE_DEVICE_RADIO   		"MUBeamformer"
#define DE_RADIO_BSTA_BFEE_80_LESS   DE_DEVICE_RADIO   		"Beamformee80orLess"
#define DE_RADIO_BSTA_BFEE_ABV_80    DE_DEVICE_RADIO   		"BeamformeeAbove80"
#define DE_RADIO_BSTA_UL_MUMIMO      DE_DEVICE_RADIO   		"ULMUMIMO"
#define DE_RADIO_BSTA_UL_OFDMA       DE_DEVICE_RADIO   		"ULOFDMA"
#define DE_RADIO_BSTA_DL_OFDMA       DE_DEVICE_RADIO   		"DLOFDMA"
#define DE_RADIO_BSTA_MAX_DL_MUMIMO  DE_DEVICE_RADIO   		"MaxDLMUMIMO"
#define DE_RADIO_BSTA_MAX_UL_MUMIMO  DE_DEVICE_RADIO   		"MaxULMUMIMO"
#define DE_RADIO_BSTA_MAX_DL_OFDMA   DE_DEVICE_RADIO   		"MaxDLOFDMA"
#define DE_RADIO_BSTA_MAX_UL_OFDMA   DE_DEVICE_RADIO   		"MaxULOFDMA"
#define DE_RADIO_BSTA_RTS            DE_DEVICE_RADIO   		"RTS"
#define DE_RADIO_BSTA_MU_RTS         DE_DEVICE_RADIO   		"MURTS"
#define DE_RADIO_BSTA_MULTI_BSSID    DE_DEVICE_RADIO   		"MultiBSSID"
#define DE_RADIO_BSTA_MUEDCA         DE_DEVICE_RADIO   		"MUEDCA"
#define DE_RADIO_BSTA_TWT_REQ        DE_DEVICE_RADIO   		"TWTRequestor"
#define DE_RADIO_BSTA_TWT_RSP        DE_DEVICE_RADIO   		"TWTResponder"
#define DE_RADIO_BSTA_SPATIAL_REUSE  DE_DEVICE_RADIO   		"SpatialReuse"
#define DE_RADIO_BSTA_ANT_CH_USAGE   DE_DEVICE_RADIO   		"AnticipatedChannelUsage"
/* Device.WiFi.DataElements.Network.Device.Radio.Capabilities.CapableOperatingClassProfile */
#define DE_CAPS_CAPOP           DE_DEVICE_RADIO         "CapableOperatingClassProfile.{i}."
#define DE_CAPOP_TABLE          DE_CAPS_CAPOP
#define DE_CAPOP_CLASS          DE_CAPS_CAPOP           "Class"
#define DE_CAPOP_MAXTXPOWER     DE_CAPS_CAPOP           "MaxTxPower"
#define DE_CAPOP_NONOPERABLE    DE_CAPS_CAPOP           "NonOperable"
#define DE_CAPOP_NONOPCNT       DE_CAPS_CAPOP           "NumberOfNonOperChan"
/* Device.WiFi.DataElements.Network.Device.Radio.CurrentOperatingClassProfile */
#define DE_RADIO_CUROP          DE_DEVICE_RADIO         "CurrentOperatingClassProfile.{i}."
#define DE_CUROP_TABLE          DE_RADIO_CUROP
#define DE_CUROP_CLASS          DE_RADIO_CUROP          "Class"
#define DE_CUROP_CHANNEL        DE_RADIO_CUROP          "Channel"
#define DE_CUROP_TXPOWER        DE_RADIO_CUROP          "TxPower"
/* Device.WiFi.DataElements.Network.Device.Radio.Capabilities.WiFi7APRole */
#define DE_CAPS_WF7AP            DE_DEVICE_RADIO          "WiFi7APRole."
#define DE_RADIO_7_EMLMR         DE_DEVICE_RADIO 	    "EMLMRSupport"
#define DE_RADIO_7_EMLSR         DE_DEVICE_RADIO 	    "EMLSRSupport"
#define DE_RADIO_7_STR           DE_DEVICE_RADIO 	    "STRSupport"
#define DE_RADIO_7_NSTR          DE_DEVICE_RADIO 	    "NSTRSupport"
#define DE_RADIO_7_TIDMAPNEG     DE_DEVICE_RADIO 	    "TIDLinkMapNegotiation"
/* Device.WiFi.DataElements.Network.Device.Radio.Capabilities.WiFi7bSTARole */
#define DE_CAPS_WF7BSTA          DE_DEVICE_RADIO          "WiFi7bSTARole."
#define DE_RADIO_7BSTA_EMLMR     DE_DEVICE_RADIO        "EMLMRSupport"
#define DE_RADIO_7BSTA_EMLSR     DE_DEVICE_RADIO        "EMLSRSupport"
#define DE_RADIO_7BSTA_STR       DE_DEVICE_RADIO        "STRSupport"
#define DE_RADIO_7BSTA_NSTR      DE_DEVICE_RADIO        "NSTRSupport"
#define DE_RADIO_7BSTA_TIDMAPNEG DE_DEVICE_RADIO        "TIDLinkMapNegotiation"
/* Device.WiFi.DataElements.Network.Device.Radio.Capabilities.ScanCapability */
#define DE_CAPS_SCANCAP          DE_DEVICE_RADIO          "ScanCapability."
#define DE_RADIO_NUM_OPCLSCANS   DE_CAPS_SCANCAP          "NumberOfOpClassScans"
#define DE_RADIO_SCAN_TS         DE_CAPS_SCANCAP          "TimeStamp"
/* Device.WiFi.DataElements.Network.Device.Radio.BSS */
// #define DE_RADIO_BSS            DE_DEVICE_RADIO         "BSS.{i}."
#define DE_RADIO_BSS            DE_DEVICE_RADIO         "BSSList.{i}."
#define DE_BSS_TABLE            DE_RADIO_BSS
#define DE_BSS_BSSID            DE_RADIO_BSS            "BSSID"
#define DE_BSS_SSID             DE_RADIO_BSS            "SSID"
#define DE_BSS_ENABLED          DE_RADIO_BSS            "Enabled"
#define DE_BSS_LASTCHG     		DE_RADIO_BSS 			"LastChange"
#define DE_BSS_TS          		DE_RADIO_BSS 			"TimeStamp"
#define DE_BSS_UCAST_TX    		DE_RADIO_BSS 			"UnicastBytesSent"
#define DE_BSS_UCAST_RX    		DE_RADIO_BSS 			"UnicastBytesReceived"
#define DE_BSS_MCAST_TX    		DE_RADIO_BSS 			"MulticastBytesSent"
#define DE_BSS_MCAST_RX    		DE_RADIO_BSS 			"MulticastBytesReceived"
#define DE_BSS_BCAST_TX    		DE_RADIO_BSS 			"BroadcastBytesSent"
#define DE_BSS_BCAST_RX    		DE_RADIO_BSS 			"BroadcastBytesReceived"
#define DE_BSS_EST_BE      		DE_RADIO_BSS 			"EstServiceParametersBE"
#define DE_BSS_EST_BK      		DE_RADIO_BSS 			"EstServiceParametersBK"
#define DE_BSS_EST_VI      		DE_RADIO_BSS 			"EstServiceParametersVI"
#define DE_BSS_EST_VO      		DE_RADIO_BSS 			"EstServiceParametersVO"
#define DE_BSS_BYTCNTUNITS      DE_RADIO_BSS            "ByteCounterUnits"
#define DE_BSS_PROF1_DIS   		DE_RADIO_BSS 			"Profile1bSTAsDisallowed"
#define DE_BSS_PROF2_DIS   		DE_RADIO_BSS 			"Profile2bSTAsDisallowed"
#define DE_BSS_ASSOC_STAT  		DE_RADIO_BSS 			"AssociationAllowanceStatus"
#define DE_BSS_BHAULUSE         DE_RADIO_BSS            "BackhaulUse"
#define DE_BSS_FHAULUSE         DE_RADIO_BSS            "FronthaulUse"
#define DE_BSS_R1_DIS      		DE_RADIO_BSS 			"R1disallowed"
#define DE_BSS_R2_DIS      		DE_RADIO_BSS 			"R2disallowed"
#define DE_BSS_MULTI_BSSID 		DE_RADIO_BSS 			"MultiBSSID"
#define DE_BSS_TX_BSSID    		DE_RADIO_BSS 			"TransmittedBSSID"
#define DE_BSS_FHAULAKMS        DE_RADIO_BSS            "FronthaulAKMsAllowed"
#define DE_BSS_BHAULAKMS        DE_RADIO_BSS            "BackhaulAKMsAllowed"
#define DE_BSS_QM_DESC     		DE_RADIO_BSS 			"QMDescriptor"
#define DE_BSS_NUM_STA     		DE_RADIO_BSS 			"NumberOfSTA"
#define DE_BSS_LINK_IMM    		DE_RADIO_BSS 			"LinkRemovalImminent"
#define DE_BSS_FH_SUITE    		DE_RADIO_BSS 			"FronthaulSuiteSelector"
#define DE_BSS_BH_SUITE    		DE_RADIO_BSS 			"BackhaulSuiteSelector"
/* Device.WiFi.DataElements.Network.Device.Radio.BSS.STA */
#define DE_BSS_STA              DE_RADIO_BSS            "STA.{i}."
#define DE_STA_TABLE            DE_BSS_STA
#define DE_STA_MACADDR          DE_BSS_STA              "MACAddress"
#define DE_STA_HTCAPS           DE_BSS_STA              "HTCapabilities"
#define DE_STA_VHTCAPS          DE_BSS_STA              "VHTCapabilities"
#define DE_STA_CLIENTCAPS       DE_BSS_STA              "ClientCapabilities"
#define DE_STA_LSTDTADLR        DE_BSS_STA              "LastDataDownlinkRate"
#define DE_STA_LSTDTAULR        DE_BSS_STA              "LastDataUplinkRate"
#define DE_STA_UTILRECV         DE_BSS_STA              "UtilizationReceive"
#define DE_STA_UTILTRMT         DE_BSS_STA              "UtilizationTransmit"
#define DE_STA_ESTMACDTARDL     DE_BSS_STA              "EstMACDataRateDownlink"
#define DE_STA_ESTMACDTARUL     DE_BSS_STA              "EstMACDataRateUplink"
#define DE_STA_SIGNALSTR        DE_BSS_STA              "SignalStrength"
#define DE_STA_LASTCONNTIME     DE_BSS_STA              "LastConnectTime"
#define DE_STA_BYTESSNT         DE_BSS_STA              "BytesSent"
#define DE_STA_BYTESRCV         DE_BSS_STA              "BytesReceived"
#define DE_STA_PCKTSSNT         DE_BSS_STA              "PacketsSent"
#define DE_STA_PCKTSRCV         DE_BSS_STA              "PacketsReceived"
#define DE_STA_ERRSSNT          DE_BSS_STA              "ErrorsSent"
#define DE_STA_ERRSRCV          DE_BSS_STA              "ErrorsReceived"
#define DE_STA_RETRANSCNT       DE_BSS_STA              "RetransCount"
#define DE_STA_IPV4ADDR         DE_BSS_STA              "IPV4Address"
#define DE_STA_IPV6ADDR         DE_BSS_STA              "IPV6Address"
#define DE_STA_HOSTNAME         DE_BSS_STA              "Hostname"
#define DE_STA_PAIRWSAKM        DE_BSS_STA              "PairwiseAKM"
#define DE_STA_PAIRWSCIPHER     DE_BSS_STA              "PairwiseCipher"
#define DE_STA_RSNCAPS          DE_BSS_STA              "RSNCapabilities"
/* Device.WiFi.DataElements.Network.Device.Radio.BSS.STA.WiFi6Capabilities */
#define DE_STA_WIFI6CAPS        DE_BSS_STA              "WiFi6Capabilities."
#define DE_STAWF6CAPS_HE160     DE_STA_WIFI6CAPS        "HE160"
#define DE_STAWF6CAPS_MCSNSS    DE_STA_WIFI6CAPS        "MCSNSS"

#define ELEMENT_DEFAULTS(t)         slow_speed, ZERO_TABLE, {t, false, 0L, 0L, 0U, NULL}
#define CALLBACK_GETTER(f)          {f, NULL, NULL, NULL, NULL, NULL}
#define CALLBACK_METHOD(f)          {NULL, NULL, NULL, NULL, NULL, f}
#define ELEMENT_PROPERTY(n, f, t)   {const_cast<char*>(n), bus_element_type_property, CALLBACK_GETTER(f), ELEMENT_DEFAULTS(t)}
#define ELEMENT_METHOD(n, f, t)     {const_cast<char*>(n), bus_element_type_method, CALLBACK_METHOD(f), ELEMENT_DEFAULTS(t)}
#define ELEMENT_TABLE(n, f, t)      {const_cast<char*>(n), bus_element_type_table, CALLBACK_GETTER(f), ELEMENT_DEFAULTS(t)}

#define CALLBACK_ADD_ROW(f)          {NULL, NULL, f, NULL, NULL, NULL}
#define CB(...)                      (bus_callback_table_t){ __VA_ARGS__ }
#define ELEMENT(n, f)                {const_cast<char*>(n), f}
#define ELEMENT_TABLE_ROW(n, f)      {const_cast<char*>(n), f}

class dm_easy_mesh_ctrl_t;

class tr_181_t {
private:
    bus_handle_t m_bus_handle;

public:

    tr_181_t() {}
    virtual ~tr_181_t() {}
    
    bus_handle_t *get_bus_hdl() { return &m_bus_handle; }
    
    // Delete copy constructor and assignment
    tr_181_t(const tr_181_t&) = delete;
    tr_181_t& operator=(const tr_181_t&) = delete;
    
    // Initialization
    void init(void* ptr);
    
    // WFA DML interface
    int register_wfa_dml();
    int wfa_set_bus_callbackfunc_pointers(const char* full_namespace, bus_callback_table_t* cb_table);
    int wfa_bus_register_namespace(char* full_namespace, 
                                 bus_element_type_t element_type,
                                 bus_callback_table_t cb_table, 
                                 data_model_properties_t data_model_value, 
                                 int num_of_rows);
    bus_error_t raw_data_set(raw_data_t *p_data, bool b);
    bus_error_t raw_data_set(raw_data_t *p_data, int32_t i);
    bus_error_t raw_data_set(raw_data_t *p_data, uint8_t u);
    bus_error_t raw_data_set(raw_data_t *p_data, uint16_t u);
    bus_error_t raw_data_set(raw_data_t *p_data, uint32_t u);
    bus_error_t raw_data_set(raw_data_t *p_data, const char *str);
    bus_error_t raw_data_set(raw_data_t *p_data, mac_address_t mac);
    bus_error_t raw_data_set(raw_data_t *p_data, wifi_ieee80211Variant_t var);
    bus_error_t raw_data_set(raw_data_t *p_data, bus_data_prop_t *property);
    template <typename T> 
    bus_data_prop_t *property_init_value(const char *root, unsigned int idx, const char *param, T value);
    template <typename T> 
    void property_append_tail(bus_data_prop_t **property, const char *root, unsigned int idx, const char *param, T value);

    virtual bus_error_t bus_get_cb_fwd(char *event_name, raw_data_t *p_data, bus_get_handler_t cb) = 0;
    
    //Table callback handlers
    static bus_error_t add_table_row(char const *name, dm_easy_mesh_t *dm);
    bus_error_t reg_table_row(char *name, int index);
    int find_radio(dm_easy_mesh_t *dm);

    // Bus callback handlers
    static bus_error_t default_get_param_value(char* event_name, raw_data_t* p_data, struct bus_user_data* user_data);
    static bus_error_t default_set_param_value(char* event_name, raw_data_t* p_data, struct bus_user_data* user_data);
    static bus_error_t default_table_add_row_handler(const char* tableName, const char* aliasName, uint32_t* instNum);
    static bus_error_t default_table_remove_row_handler(const char* rowName);
    static bus_error_t default_event_sub_handler(char* eventName, bus_event_sub_action_t action, int32_t interval, bool* autoPublish);

    //Network
    static bus_error_t network_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    
    //SSID
    static bus_error_t ssid_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    static bus_error_t ssid_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    static bus_error_t ssid_table_add_row_handler(const char* table_name, const char* alias_name, uint32_t* instance_number);

    //Device Callbacks
    static bus_error_t device_get(char* event_name, raw_data_t* p_data, struct bus_user_data* user_data);
    static bus_error_t device_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    static bus_error_t device_table_add_row_handler(const char* table_name, const char* alias_name, uint32_t* instance_number);

    //Radio
    static bus_error_t radio_get(char* event_name, raw_data_t* p_data, struct bus_user_data* user_data);
    static bus_error_t radio_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    static bus_error_t rbhsta_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    static bus_error_t radio_table_add_row_handler(const char* table_name, const char* alias_name, uint32_t* instance_number);
    static bus_error_t rcaps_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    static bus_error_t curops_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    static bus_error_t curops_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);

    //BSS
    static bus_error_t bss_get(char* event_name, raw_data_t* p_data, struct bus_user_data* user_data);
    static bus_error_t bss_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    static bus_error_t bss_table_add_row_handler(const char* table_name, const char* alias_name, uint32_t* instance_number);

    //STA
    static bus_error_t sta_get(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    static bus_error_t sta_tget(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data);
    static bus_error_t sta_table_add_row_handler(const char* table_name, const char* alias_name, uint32_t* instance_number);

    virtual bus_error_t network_get(char *event_name, raw_data_t *p_data) = 0;
    virtual bus_error_t device_get(char *event_name, raw_data_t *p_data) = 0;
    // virtual bus_error_t radio_tget_impl(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data) = 0;
    // virtual bus_error_t bss_tget_impl(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data) = 0;
    // virtual bus_error_t ssid_tget_impl(char *event_name, raw_data_t *p_data, bus_user_data_t *user_data) = 0;

    // Data model access
    bus_error_t wifi_elem_num_of_table_row(char* event_name, uint32_t* table_row_size);
    
    // File operations
    void generate_namespaces_without_lib_refined(const std::string& filename);
    void register_cjson_namespace(cJSON *node, const std::string &prefix);

    //Data_Elements_JSON_Schema_v3.0 parsing related functions
    cJSON* follow_ref_if_any(cJSON* root, cJSON* node);
    cJSON* resolve_ref(cJSON* root, const char* refStr);
    void parse_property_constraints(cJSON* schemaNode, data_model_properties_t& props);
    void parse_readwrite(cJSON* schemaNode, data_model_properties_t& props);
    void handle_property_node(cJSON* root, const std::string& fullPath, cJSON* propertySchema);
    void traverse_schema(cJSON* root, cJSON* schemaNode, const std::string& basePath);
    bool parse_and_register_schema(const char *filename);
};

template <typename T> bus_data_prop_t *tr_181_t::property_init_value(const char *root, unsigned int idx, const char *param, T value)
{
    bus_data_prop_t *property = static_cast<bus_data_prop_t *>(calloc(1, sizeof(bus_data_prop_t)));

    if (property == NULL) {
        return NULL;
    }

    snprintf(property->name, sizeof(bus_name_string_t), "%s%d.%s", root, idx, param);
    raw_data_set(&property->value, value);
    property->name_len = static_cast<uint32_t>(strlen(property->name));
    property->is_data_set = true;

    return property;
}

template <typename T> void tr_181_t::property_append_tail(bus_data_prop_t **property, const char *root, unsigned int idx, const char *param, T value)
{
    bus_data_prop_t *tail;
    bus_data_prop_t *last;

    if (*property == NULL) {
        *property = property_init_value(root, idx, param, value);
    } else {
        tail = static_cast<bus_data_prop_t *>(calloc(1, sizeof(bus_data_prop_t)));
        snprintf(tail->name, sizeof(bus_name_string_t), "%s%d.%s", root, idx, param);
        raw_data_set(&tail->value, value);
        tail->name_len = static_cast<uint32_t>(strlen(tail->name));
        tail->is_data_set = true;

        last = *property;
        while (last->next_data) {
            last = last->next_data;
        }
        last->next_data = tail;
    }
}

#endif // TR_181_H
