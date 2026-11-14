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
#include "de_scan_results.h"
#include "optimizer.h"

void de_scan_results_t::update(de_scan_result_t& res, unsigned int dpos, unsigned int rpos, unsigned int spos)
{
    em_long_string_t key = {0};
    de_scan_result_t *pres;
    
    snprintf(key, sizeof(key), "%s.%d.%s.%d.%s.%d", DEVICES, dpos, RADIOS, rpos, SCAN_RESULT, spos);
    if ((pres = (de_scan_result_t *)hash_map_get(m_scan_result_map, key)) == NULL) {
        pres = new de_scan_result_t();
        pres->init(key);
        hash_map_put(m_scan_result_map, strdup(key), pres);
    } 

    pres->update(res);
}


rbusError_t de_scan_results_t::add(rbusHandle_t handle, char const* table_name, char const* alias_name, uint32_t* inst_num)
{
    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_scan_results_t::remove(rbusHandle_t handle, char const* row_name)
{
    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_scan_results_t::get(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* options)
{
    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_scan_results_t::set(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* options)
{
    return RBUS_ERROR_SUCCESS;
}

void de_scan_results_t::publish(const char *name)
{

}

void de_scan_results_t::handler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{

}

int de_scan_results_t::init(rbusHandle_t handle)
{
    m_scan_result_map = hash_map_create();

    m_de_op_class_scans = new de_op_class_scans_t(OP_CLASS_SCAN, m_provider, m_func);
    if (m_de_op_class_scans->init(handle) != 0) {
        printf("%s:%d: Failed to initialize scan results\n", __func__, __LINE__);
        return -1;
    }

    return de_t::init(handle);

}

void de_scan_results_t::deinit(bool bus_close)
{
    if (m_de_op_class_scans != NULL) {
        m_de_op_class_scans->deinit(bus_close);
    }

    if (m_scan_result_map != NULL) {
        hash_map_destroy(m_scan_result_map);
    }

    de_t::deinit(false);
}

de_scan_results_t::de_scan_results_t(const char *name, bool provider, notifier_t func)
{
    m_provider = provider;
    strncpy(m_name, name, strlen(name));
    m_func = func;
    m_scan_result_map = NULL;
    m_de_op_class_scans = NULL;
}
