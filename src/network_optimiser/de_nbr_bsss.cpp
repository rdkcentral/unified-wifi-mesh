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
#include "de_nbr_bsss.h"
#include "optimizer.h"

void de_nbr_bsss_t::update(de_nbr_bss_t& bss, unsigned int dpos, unsigned int rpos, unsigned int spos, unsigned int opos, unsigned int cpos, unsigned int npos)
{
    em_long_string_t key = {0};
    de_nbr_bss_t *pbss;

    snprintf(key, sizeof(key), "%s.%d.%s.%d.%s.%d.%s.%d.%s.%d.%s.%d", DEVICES, dpos, RADIOS, rpos, SCAN_RESULT, spos, OP_CLASS_SCAN, opos, CHANNEL_SCAN, cpos, NBR_BSS, npos);
    if ((pbss = (de_nbr_bss_t *)hash_map_get(m_nbr_bss_map, key)) == NULL) {
        pbss = new de_nbr_bss_t();
        pbss->init(key);
        hash_map_put(m_nbr_bss_map, strdup(key), pbss);
    }

    pbss->update(bss);

}


rbusError_t de_nbr_bsss_t::add(rbusHandle_t handle, char const* table_name, char const* alias_name, uint32_t* inst_num)
{
    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_nbr_bsss_t::remove(rbusHandle_t handle, char const* row_name)
{
    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_nbr_bsss_t::get(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* options)
{
    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_nbr_bsss_t::set(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* options)
{
    return RBUS_ERROR_SUCCESS;
}

void de_nbr_bsss_t::publish(const char *name)
{

}

void de_nbr_bsss_t::handler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{

}

int de_nbr_bsss_t::init(rbusHandle_t handle)
{
    m_nbr_bss_map = hash_map_create();

    return de_t::init(handle);

}

void de_nbr_bsss_t::deinit(bool bus_close)
{
    if (m_nbr_bss_map != NULL) {
        hash_map_destroy(m_nbr_bss_map);
    }

    de_t::deinit(bus_close);
}

de_nbr_bsss_t::de_nbr_bsss_t(const char *name, bool provider, notifier_t func)
{
    m_provider = provider;
    strncpy(m_name, name, strlen(name));
    m_func = func;
    m_nbr_bss_map = NULL;
}
