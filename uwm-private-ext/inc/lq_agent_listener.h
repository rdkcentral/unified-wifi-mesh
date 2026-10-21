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

#ifndef LQ_AGENT_LISTENER_H
#define LQ_AGENT_LISTENER_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Starts a detached background thread that binds LQ_STATS_SOCKET_PATH
 * (AF_UNIX, SOCK_DGRAM) and listens for lq_tlv_t datagrams already being
 * sent by OneWifi's WEI library (see OneWifi/source/apps/linkquality).
 *
 * For message types that carry per-station stats_arg_t entries
 * (PERIODIC_STATS, DISCONNECT, RAPID_DISCONNECT, CAFFINITY_EVENT), each
 * entry is forwarded as-is (prefixed with a private attr id) straight into
 * the orchestrator via g_agent.io_process(em_bus_event_type_wei_app_data, ...),
 * reusing the existing analyze_wei_app_data()/send_vendor_msg() pipeline
 * that frames it as a vendor-specific TLV to the controller.
 *
 * This replaces the legacy OneWifi "Device.WiFi.EM.WEIData" rbus
 * publish/subscribe mechanism, which duplicated data already available on
 * this socket.
 *
 * Safe to call multiple times; only the first call takes effect.
 */
void lq_agent_listener_start();

#ifdef __cplusplus
}
#endif

#endif /* LQ_AGENT_LISTENER_H */
