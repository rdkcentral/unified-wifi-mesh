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

#include "lq_agent_listener.h"
#include "lq_listener.h"
#include "lq_socket.h"
#include "em_base_comcast.h"
#include "em_agent.h"
#include "em_cmd_agent.h"
#include "util.h"
#include <string.h>

/* Only these message types carry per-station stats_arg_t[] payloads.
 * REGISTER_STA/UNREGISTER_STA (MAC string), REINIT_METRICS (server_arg_t),
 * START/STOP_METRICS, SET_MAX_SNR and SET_SCORE_PARAMS are local
 * control/config messages for the WEI engine with no per-station stats_arg_t
 * equivalent, so they are logged and skipped here. */
static bool lq_msg_type_carries_stats(uint32_t type)
{
    switch (type) {
    case LQ_IPC_MSG_PERIODIC_STATS:
    case LQ_IPC_MSG_DISCONNECT:
    case LQ_IPC_MSG_RAPID_DISCONNECT:
    case LQ_IPC_MSG_CAFFINITY_EVENT:
        return true;
    default:
        return false;
    }
}

/* Only called for types lq_msg_type_carries_stats() accepts. */
static em_vendor_priv_attr_id_t lq_msg_type_to_priv_attr_id(uint32_t type)
{
    switch (type) {
    case LQ_IPC_MSG_DISCONNECT:       return em_vendor_priv_attr_id_wei_disconnect;
    case LQ_IPC_MSG_RAPID_DISCONNECT: return em_vendor_priv_attr_id_wei_rapid_disconnect;
    case LQ_IPC_MSG_CAFFINITY_EVENT:  return em_vendor_priv_attr_id_wei_caffinity_event;
    case LQ_IPC_MSG_PERIODIC_STATS:
    default:                          return em_vendor_priv_attr_id_wei_periodic_stats;
    }
}

/* stats_arg_t (OneWifi wire format sent over the socket) is forwarded as-is;
 * no conversion needed since it's also what the vendor TLV carries. */

/* lq_listener_start() (custom/src/common/lq_listener.cpp) owns the socket
 * bind/parse and hands us the raw payload; this decodes stats_arg_t entries
 * and forwards them into the orchestrator, reusing the existing
 * analyze_wei_app_data()/send_vendor_msg() pipeline that used to be fed by
 * the "Device.WiFi.EM.WEIData" bus event.
 *
 * The payload is always one or more stats_arg_t structs (wifi_base.h) as
 * sent by OneWifi's wifi_linkquality_libs.c/lq_ipc_sender.c for
 * PERIODIC_STATS/DISCONNECT/RAPID_DISCONNECT/CAFFINITY_EVENT. */
static void lq_agent_raw_data_cb(uint32_t msg_type, const uint8_t *payload, size_t len)
{
    if (!lq_msg_type_carries_stats(msg_type)) {
        em_printfout("%s:%d [LQ-LISTEN] Ignoring non-stats msg_type=%s(%u) (len=%zu)",
            __func__, __LINE__, lq_msg_type_str(msg_type), msg_type, len);
        return;
    }

    if ((len % sizeof(stats_arg_t)) != 0) {
        em_printfout("%s:%d [LQ-LISTEN] Unexpected payload size %zu for msg_type=%u (not a multiple of sizeof(stats_arg_t)=%zu)",
            __func__, __LINE__, len, msg_type, sizeof(stats_arg_t));
        return;
    }

    uint32_t count = static_cast<uint32_t>(len / sizeof(stats_arg_t));
    const stats_arg_t *entries = reinterpret_cast<const stats_arg_t *>(payload);

    const em_vendor_priv_attr_id_t priv_attr_id = lq_msg_type_to_priv_attr_id(msg_type);

    for (uint32_t i = 0; i < count; i++) {
        em_printfout("%s:%d [LQ-LISTEN] msg_type=%s(%u) [%u/%u] type=stats_arg_t STA=%s forwarding to orchestrator",
            __func__, __LINE__, lq_msg_type_str(msg_type), msg_type, i + 1, count, entries[i].mac_str);

        /* Prefix with the private attr id so the controller side knows how
         * to interpret what follows (see em_base_comcast.h). */
        unsigned char buf[1 + sizeof(stats_arg_t)];
        buf[0] = static_cast<unsigned char>(priv_attr_id);
        memcpy(buf + 1, &entries[i], sizeof(stats_arg_t));

        g_agent.io_process(em_bus_event_type_wei_app_data, buf, sizeof(buf));
    }
}

void lq_agent_listener_start()
{
    lq_listener_start(lq_agent_raw_data_cb);
}

