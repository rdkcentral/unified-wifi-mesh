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
#include "de_nbr_nodes.h"
#include "optimizer.h"

void de_nbr_nodes_t::update(de_nbr_node_t& node)
{
    de_nbr_node_t *pnode;
    em_string_t key;

    snprintf(key, sizeof(em_string_t), "%s.%s", node.m_radio, node.m_bssid);

    if ((pnode = (de_nbr_node_t *)hash_map_get(m_nbr_node_map, key)) == NULL) {
        pnode = new de_nbr_node_t();
        pnode->init(key);
        hash_map_put(m_nbr_node_map, strdup(key), pnode);
    }

    pnode->update(node);
}

void de_nbr_nodes_t::remove(de_nbr_node_t& node)
{
    de_nbr_node_t *pnode;
    em_string_t key;

    snprintf(key, sizeof(em_string_t), "%s.%d", node.m_radio, node.m_bssid);
    if ((pnode = (de_nbr_node_t *)hash_map_remove(m_nbr_node_map, key)) != NULL) {
        delete pnode;
    }
}


rbusError_t de_nbr_nodes_t::add(rbusHandle_t handle, char const* table_name, char const* alias_name, uint32_t* inst_num)
{
    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_nbr_nodes_t::remove(rbusHandle_t handle, char const* row_name)
{
    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_nbr_nodes_t::get(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* options)
{
    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_nbr_nodes_t::set(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* options)
{
    return RBUS_ERROR_SUCCESS;
}

void de_nbr_nodes_t::publish(const char *name)
{

}


void de_nbr_nodes_t::handler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{

}

rbusError_t de_nbr_nodes_t::method(rbusHandle_t handle, char const* name, rbusObject_t in, rbusObject_t out, rbusMethodAsyncHandle_t async)
{
    rbusValue_t value;
    rbusObject_t ob;
    de_nbr_node_t *node;
    em_string_t     key;
    unsigned int index = 0;

    rbusValue_Init(&value);
    rbusValue_SetString(value, "Complete");
    rbusObject_SetValue(out, "Status", value);
    rbusValue_Release(value);

    node = (de_nbr_node_t *)hash_map_get_first(m_nbr_node_map);
    while (node != NULL) {
        snprintf(key, sizeof(key), "Result.%d.", index); 
        rbusObject_Init(&ob, key);

        node->serialize(ob);

        rbusValue_Init(&value);
        rbusValue_SetObject(value, ob);
        rbusObject_Release(ob);

        rbusObject_SetValue(out, key, value);
        rbusValue_Release(value);

        node = (de_nbr_node_t *)hash_map_get_next(m_nbr_node_map, node);
        index++;
    }

    return RBUS_ERROR_SUCCESS;
}

rbusError_t de_nbr_nodes_t::invoke_method(char const* name, void *in, void *out)
{
    de_nbr_node_t node, *pnode;
    rbusObject_t ob, in_obj, out_obj;
    rbusProperty_t prop;
    rbusValue_t value;
    em_string_t key;
    int rc;
    const char *ptr;

    rbusObject_Init(&in_obj, NULL);
    rc = rbusMethod_Invoke(m_bus_handle, NBR_WIFI_DIAG, in_obj, &out_obj);

    prop = rbusObject_GetProperties(out_obj);
    while (prop != NULL) {
        if (strstr(rbusProperty_GetName(prop), "Result.") == NULL) {
            prop = rbusProperty_GetNext(prop);
            continue;
        }

        ob = rbusProperty_GetObject(prop);
       
        node.deserialize(ob);    
        
        snprintf(key, sizeof(em_string_t), "%s.%s", node.m_radio, node.m_bssid);
        if ((pnode = (de_nbr_node_t *)hash_map_get(m_nbr_node_map, key)) == NULL) {
            pnode = new de_nbr_node_t();
            pnode->init(key);
            hash_map_put(m_nbr_node_map, strdup(key), pnode);
        }

        pnode->update(node);
        prop = rbusProperty_GetNext(prop);
    }

    rbusObject_Release(in_obj);
    rbusObject_Release(out_obj);

    return (rbusError_t)rc;
}

void de_nbr_nodes_t::deserialize(rbusObject_t& ob)
{

}

int de_nbr_nodes_t::init()
{
    m_nbr_node_map = hash_map_create();

    m_elems[m_num_elems].name = NBR_WIFI_DIAG;
    m_elems[m_num_elems].type = RBUS_ELEMENT_TYPE_METHOD;
    m_num_elems++;

    return de_t::init(); 
}

void de_nbr_nodes_t::deinit()
{
    if (m_nbr_node_map != NULL) {
        hash_map_destroy(m_nbr_node_map);
    }
    de_t::deinit();
}

de_nbr_nodes_t::de_nbr_nodes_t(const char *name, bool provider, notifier_t func)
{
    m_provider = provider;
    strncpy(m_name, name, strlen(name));
    m_func = func;
    m_nbr_node_map = NULL;
}
