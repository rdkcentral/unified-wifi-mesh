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
#define DE_RADIOS_TABLE         DE_DEVICES_TABLE "{i}."
#define DE_RADIOS_ANY           DE_RADIOS "*."
#define DE_RADIOS_ID        DE_RADIOS_TABLE     "ID"
#define DE_RADIOS_ENABLED        DE_RADIOS_TABLE     "Enabled"
#define DE_RADIOS_ANY_ID        DE_RADIOS_ANY     "ID"
#define DE_RADIOS_ANY_ENABLED        DE_RADIOS_ANY     "Enabled"

typedef enum {
    optimizer_type_comcast,
    optimizer_type_vodafone,
    optimizer_type_dt,
    optimizer_type_generic,
    optimizer_type_none
} optimizer_type_t;

#endif
