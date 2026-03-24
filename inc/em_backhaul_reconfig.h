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

#ifndef EM_BACKHAUL_RECONFIG_H
#define EM_BACKHAUL_RECONFIG_H

#include <stdint.h>
#include <map>
#include <time.h>

class em_network_topo_t;
class dm_easy_mesh_t;

/**
 * @brief Constants for backhaul reconfiguration flow (EasyMesh v6.0, Section 5.2.5)
 */
#define MAX_EXCHANGE_RETRIES        3
#define MAX_COLOCATED_APPLY_RETRIES 3
#define M1_TIMEOUT                  5       // seconds
#define EXCHANGE_COMPLETE_TIMEOUT   15      // seconds

/**
 * @brief Result enumeration for backhaul reconfiguration operations
 */
typedef enum {
    EM_BACKHAUL_RECONFIG_SUCCESS = 0,
    EM_BACKHAUL_RECONFIG_FAIL = 1,
    EM_BACKHAUL_RECONFIG_TIMEOUT = 2,
    EM_BACKHAUL_RECONFIG_INVALID_INPUT = 3
} em_backhaul_reconfig_result_t;

/**
 * @brief State for tracking backhaul STA reconfiguration per agent
 */
typedef struct {
    dm_easy_mesh_t *agent_dm;               /**< Pointer to agent data model */
    bool exchange_complete;                 /**< M1/M2+M8 exchange completed */
    int retry_count;                        /**< Current retry count for this agent */
    time_t exchange_start_time;             /**< Timestamp when exchange started */
} em_bsta_reconfig_state_t;

/**
 * @brief Backhaul reconfiguration context passed through recursion
 */
typedef struct {
    char *setssid_payload;                  /**< SetSSID JSON payload buffer */
    size_t payload_len;                     /**< Length of SetSSID payload */
    std::map<dm_easy_mesh_t*, bool> pending_exchange;      /**< Pending M1/M2+M8 completion by agent */
    time_t flow_start_time;                 /**< Global flow start time */
} em_backhaul_reconfig_context_t;

#endif /* EM_BACKHAUL_RECONFIG_H */
