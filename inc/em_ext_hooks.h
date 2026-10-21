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

#ifndef EM_EXT_HOOKS_H
#define EM_EXT_HOOKS_H

#include "em_base.h"

class em_t;

/**
 * Extension point for out-of-tree controller and agent behavior.
 * Default implementations preserve stock UWM behavior.
 */
class em_ext_hooks_t {
public:
    virtual ~em_ext_hooks_t() = default;

    // May consume arguments; preserve argv[0], update argc, and keep argv NULL-terminated.
    virtual bool process_cli_args(int *argc, const char *argv[]) { return true; }

    // Appends message-specific TLVs immediately before the end-of-message TLV.
    virtual unsigned int append_tlvs(em_msg_type_t msg_type, unsigned char *buff) { return 0; }

    // Receives each validated TLV from a message.
    virtual void handle_tlv(em_msg_type_t msg_type, unsigned char tlv_type, const unsigned char *val, unsigned short len) {}

    // Return true to consume an agent event instead of forwarding it to OneWifi.
    virtual bool intercept_agent_event(em_t *em, em_bus_event_type_t type, unsigned char *data, unsigned int len) { return false; }

    // Provides the final decision on whether an agent-reported BSS SSID is accepted.
    virtual bool accept_bss_ssid(bool matches_network) { return matches_network; }

};

inline em_ext_hooks_t *&em_ext_hooks_slot()
{
    static em_ext_hooks_t default_hooks;
    static em_ext_hooks_t *current = &default_hooks;
    return current;
}

inline em_ext_hooks_t *em_get_ext_hooks()
{
    return em_ext_hooks_slot();
}

inline void em_register_ext_hooks(em_ext_hooks_t *hooks)
{
    if (hooks != NULL) {
        em_ext_hooks_slot() = hooks;
    }
}

#endif
