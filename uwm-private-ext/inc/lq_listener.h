/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:
  Copyright 2018 RDK Management
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at
  http://www.apache.org/licenses/LICENSE-2.0
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 **************************************************************************/

#ifndef LQ_LISTENER_H
#define LQ_LISTENER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Generic LQ socket receiver, shared by any process that wants to consume
 * datagrams off LQ_STATS_SOCKET_PATH. This layer only understands the
 * lq_tlv_t framing (type + len + raw bytes) — it is deliberately unaware of
 * what the payload means (stats_arg_t, etc.); interpreting the
 * payload is left entirely to the caller's callback.
 */
typedef void (*lq_raw_data_cb_t)(uint32_t msg_type, const uint8_t *payload, size_t len);

/*
 * Starts a detached thread that binds LQ_STATS_SOCKET_PATH (AF_UNIX,
 * SOCK_DGRAM), reads datagrams, validates the lq_tlv_t framing, and invokes
 * `cb` with the raw msg_type/payload/len of each datagram received.
 *
 * Safe to call multiple times; only the first call takes effect. Returns 0
 * on success, -1 on failure to bind/start.
 */
int lq_listener_start(lq_raw_data_cb_t cb);

#ifdef __cplusplus
}
#endif

#endif /* LQ_LISTENER_H */
