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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include "util.h"
#include "de_op_class_scans.h"
#include "optimizer.h"

void de_op_class_scans_t::update(de_op_class_scan_t& op_class, unsigned int dpos, unsigned int rpos, unsigned int spos, unsigned int opos)
{
    em_long_string_t key = {0};
    de_op_class_scan_t *pop_class;

    snprintf(key, sizeof(key), "%s.%d.%s.%d.%s.%d.%s.%d", DEVICES, dpos, RADIOS, rpos, SCAN_RESULT, spos, OP_CLASS_SCAN, opos);
    if ((pop_class = (de_op_class_scan_t *)hash_map_get(m_op_class_map, key)) == NULL) {
        pop_class = new de_op_class_scan_t();
        pop_class->init(key);
        hash_map_put(m_op_class_map, strdup(key), pop_class);
    }

    pop_class->update(op_class);
}


rbusError_t de_op_class_scans_t::add(rbusHandle_t handle, char const* table_name, char const* alias_name, uint32_t* inst_num)
{
    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_op_class_scans_t::remove(rbusHandle_t handle, char const* row_name)
{
    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_op_class_scans_t::get(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* options)
{
    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_op_class_scans_t::set(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* options)
{
    return RBUS_ERROR_SUCCESS;
}

void de_op_class_scans_t::publish(const char *name)
{

}

void de_op_class_scans_t::handler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{

}

int de_op_class_scans_t::init(rbusHandle_t handle)
{
    m_op_class_map = hash_map_create();

    m_de_channel_scans = new de_channel_scans_t(CHANNEL_SCAN, m_provider, m_func);
    if (m_de_channel_scans->init(handle) != 0) {
        printf("%s:%d: Failed to initialize scan results\n", __func__, __LINE__);
        return -1;
    }

    return de_t::init(handle);

}

void de_op_class_scans_t::deinit(bool bus_close)
{
    if (m_de_channel_scans != NULL) {
        m_de_channel_scans->deinit(bus_close);
    }

    if (m_op_class_map != NULL) {
        hash_map_destroy(m_op_class_map);
    }
    de_t::deinit(false);
}

de_op_class_scans_t::de_op_class_scans_t(const char *name, bool provider, notifier_t func)
{
    m_provider = provider;
    strncpy(m_name, name, strlen(name));
    m_func = func;
    m_op_class_map = NULL;
    m_de_channel_scans = NULL;
}
