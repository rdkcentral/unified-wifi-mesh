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

#ifndef EM_NETWORK_TOPO_H
#define EM_NETWORK_TOPO_H

#include "em_base.h"
#include "dm_easy_mesh.h"

class em_network_topo_t {

	dm_easy_mesh_t	*m_data_model;
	unsigned int m_num_topologies;	
	em_network_topo_t	*m_topology[EM_MAX_NETWORKS];

public:
	em_network_topo_t *find_topology_by_bh_associated(mac_address_t sta);
	em_network_topo_t *find_topology(dm_easy_mesh_t *dm);
	dm_easy_mesh_t *get_data_model() { return m_data_model; }
	
	void add(dm_easy_mesh_t *dm);
	void remove(dm_easy_mesh_t *dm);

	void add_network_topo(dm_easy_mesh_t *dm);

	void encode(cJSON *obj);

    em_network_topo_t(dm_easy_mesh_t *dm);
    em_network_topo_t();
    ~em_network_topo_t();
};

#endif
