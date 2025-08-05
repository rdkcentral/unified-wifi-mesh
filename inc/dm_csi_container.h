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

#ifndef DM_CSI_CONTAINER_H
#define DM_CSI_CONTAINER_H

#include "em_base.h"

class dm_csi_container_t {
public:
    em_csi_container_t    m_csi_container;

public:
    int init() { memset(&m_csi_container, 0, sizeof(em_csi_container_t)); return 0; }
    em_csi_container_t *get_csi_container() { return &m_csi_container; }
    int decode(const cJSON *obj, void *parent_id);
    void encode(cJSON *obj);
    void encode_data(cJSON *obj);
	
    bool operator == (const dm_csi_container_t& obj);
    void operator = (const dm_csi_container_t& obj);

    static int parse_csi_container_id_from_key(const char *key, em_csi_container_id_t *id);

    dm_csi_container_t(em_csi_container_t *cont);
    dm_csi_container_t(const dm_csi_container_t& cont);
    dm_csi_container_t();
    virtual ~dm_csi_container_t();
};

#endif
