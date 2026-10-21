/**
 * Copyright 2026 Comcast Cable Communications Management, LLC
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

#ifndef EM_BASE_COMCAST_H
#define EM_BASE_COMCAST_H

/*
 * Private attribute IDs, analogous to em_base.h's open-source
 * vendor_ext_attr_id_t but for data types introduced under custom/. Add one
 * here for each new private data type instead of extending the open-source
 * enum, so private data types never need public review.
 *
 * These are prefixed onto the payload placed inside the outer
 * vendor_ext_attr_id_wei_data attribute (see em_vendor_data_t in em_base.h),
 * one byte before the actual data, so the receiver knows how to interpret
 * what follows:
 *
 *   em_vendor_data_t.vendor_data = [priv_attr_id (1 byte)][payload bytes...]
 *
 * Written and read by em_vendor_wei_t (uwm-private-ext/src/common/em_vendor_ext.cpp).
 */
typedef enum {
    em_vendor_priv_attr_id_wei_periodic_stats = 1,
    em_vendor_priv_attr_id_wei_disconnect,
    em_vendor_priv_attr_id_wei_rapid_disconnect,
    em_vendor_priv_attr_id_wei_caffinity_event,
} em_vendor_priv_attr_id_t;


typedef enum {
    //comcast vendor extension attributes, 0xcc - 0xFF
    vendor_attr_id_ext_wei_data = 0xcc,

    vendor_attr_id_ext_max
} vendor_attr_id_extended_t;

typedef struct {
    // this is of type vendor_attr_id_extended_t for vendor specific attributes
    unsigned char attr_id;
    unsigned char  vendor_data[0];
} __attribute__((__packed__)) em_vendor_data_t;

#endif /* EM_BASE_COMCAST_H */
