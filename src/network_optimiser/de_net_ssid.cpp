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
#include "de_net_ssid.h"

void de_net_ssid_t::update(de_net_ssid_t& net_ssid)
{
    strncpy(m_ssid, net_ssid.m_ssid, strlen(net_ssid.m_ssid) + 1);
    m_enabled = net_ssid.m_enabled;
    strncpy(m_op, net_ssid.m_op, strlen(net_ssid.m_op) + 1);
    m_advertisement = net_ssid.m_advertisement;
    strncpy(m_mfp_config, net_ssid.m_mfp_config, strlen(net_ssid.m_mfp_config) + 1);
    strncpy(m_mob_domain, net_ssid.m_mob_domain, strlen(net_ssid.m_mob_domain) + 1);
    strncpy(m_passphrase, net_ssid.m_passphrase, strlen(net_ssid.m_passphrase) + 1);
    strncpy(m_band, net_ssid.m_band, strlen(net_ssid.m_band) + 1);
    strncpy(m_akms_allowed, net_ssid.m_akms_allowed, strlen(net_ssid.m_akms_allowed) + 1);
    strncpy(m_suite_selector, net_ssid.m_suite_selector, strlen(net_ssid.m_suite_selector) + 1);
    strncpy(m_haul_type, net_ssid.m_haul_type, strlen(net_ssid.m_haul_type) + 1);
    strncpy(m_type, net_ssid.m_type, strlen(net_ssid.m_type) + 1);
}

void de_net_ssid_t::serialize(rbusObject_t& ob)
{
    rbusValue_t value;

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_ssid);
    rbusObject_SetValue(ob, "SSID", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetBoolean(value, m_enabled);
    rbusObject_SetValue(ob, "Enable", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_op);
    rbusObject_SetValue(ob, "AddRemoveChange", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_passphrase);
    rbusObject_SetValue(ob, "PassPhrase", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_band);
    rbusObject_SetValue(ob, "Band", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_akms_allowed);
    rbusObject_SetValue(ob, "AKMsAllowed", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_suite_selector);
    rbusObject_SetValue(ob, "SuiteSelector", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetBoolean(value, m_advertisement);
    rbusObject_SetValue(ob, "AdvertisementEnabled", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_mfp_config);
    rbusObject_SetValue(ob, "MFPConfig", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_mob_domain);
    rbusObject_SetValue(ob, "MobilityDomain", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_haul_type);
    rbusObject_SetValue(ob, "HaulType", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetString(value, m_type);
    rbusObject_SetValue(ob, "Type", value);
    rbusValue_Release(value);

}

void de_net_ssid_t::deserialize(rbusObject_t& ob)
{
    rbusValue_t value;
    const char *ptr;

    if ((value = rbusObject_GetValue(ob, "SSID")) == NULL) {
        printf("%s:%d: Could not find SSID value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_ssid, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "Enable")) == NULL) {
        printf("%s:%d: Could not find Enable value\n", __func__, __LINE__);
    } else {
        m_enabled = rbusValue_GetBoolean(value);
    }

    if ((value = rbusObject_GetValue(ob, "AddRemoveChange")) == NULL) {
        printf("%s:%d: Could not find AddRemoveChange value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_op, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "PassPhrase")) == NULL) {
        printf("%s:%d: Could not find PassPhrase value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_passphrase, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "Band")) == NULL) {
        printf("%s:%d: Could not find Band value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_band, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "AKMsAllowed")) == NULL) {
        printf("%s:%d: Could not find AKMsAllowed value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_akms_allowed, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "SuiteSelector")) == NULL) {
        printf("%s:%d: Could not find SuiteSelector value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_suite_selector, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "AdvertisementEnabled")) == NULL) {
        printf("%s:%d: Could not find AdvertisementEnabled value\n", __func__, __LINE__);
    } else {
        m_advertisement = rbusValue_GetBoolean(value);
    }

    if ((value = rbusObject_GetValue(ob, "MFPConfig")) == NULL) {
        printf("%s:%d: Could not find MFPConfig value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_mfp_config, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "MobilityDomain")) == NULL) {
        printf("%s:%d: Could not find MobilityDomain value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_mob_domain, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "HaulType")) == NULL) {
        printf("%s:%d: Could not find HaulType value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_haul_type, ptr, strlen(ptr) + 1);
    }

    if ((value = rbusObject_GetValue(ob, "Type")) == NULL) {
        printf("%s:%d: Could not find Type value\n", __func__, __LINE__);
    } else {
        ptr = rbusValue_GetString(value, NULL);
        strncpy(m_type, ptr, strlen(ptr) + 1);
    }

}

void de_net_ssid_t::serialize(cJSON *ob)
{
    cJSON_AddStringToObject(ob, "SSID", m_ssid);
    cJSON_AddBoolToObject(ob, "Enable", m_enabled);
    cJSON_AddBoolToObject(ob, "AdvertisementEnabled", m_advertisement);
    cJSON_AddStringToObject(ob, "MFPConfig", m_mfp_config);
    cJSON_AddStringToObject(ob, "MobilityDomain", m_mob_domain);
    cJSON_AddStringToObject(ob, "Band", m_band);
    cJSON_AddStringToObject(ob, "AKMsAllowed", m_akms_allowed);
    cJSON_AddStringToObject(ob, "SuiteSelector", m_suite_selector);
    cJSON_AddStringToObject(ob, "HaulType", m_haul_type);
    cJSON_AddStringToObject(ob, "Type", m_type);
}

void de_net_ssid_t::deserialize(cJSON *ob)
{
    cJSON *elem;
    const char *str;

    elem = cJSON_GetObjectItem(ob, "SSID");
    str = cJSON_GetStringValue(elem);
    strncpy(m_ssid, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(ob, "Enable");
    m_enabled = cJSON_IsTrue(elem);

    elem = cJSON_GetObjectItem(ob, "AdvertisementEnabled");
    m_advertisement = cJSON_IsTrue(elem);

    elem = cJSON_GetObjectItem(ob, "MFPConfig");
    str = cJSON_GetStringValue(elem);
    strncpy(m_mfp_config, str, strlen(str) + 1);

    elem = cJSON_GetObjectItem(ob, "MobilityDomain");
    str = cJSON_GetStringValue(elem);
    strncpy(m_mob_domain, str, strlen(str) + 1);

    if ((elem = cJSON_GetObjectItem(ob, "AddRemoveChange")) != NULL) {
        str = cJSON_GetStringValue(elem);
        strncpy(m_op, str, strlen(str) + 1);
    }

    if ((elem = cJSON_GetObjectItem(ob, "PassPhrase")) != NULL) {
        str = cJSON_GetStringValue(elem);
        strncpy(m_passphrase, str, strlen(str) + 1);
    }

    if ((elem = cJSON_GetObjectItem(ob, "Band")) != NULL) {
        str = cJSON_GetStringValue(elem);
        strncpy(m_band, str, strlen(str) + 1);
    }

    if ((elem = cJSON_GetObjectItem(ob, "AKMsAllowed")) != NULL) {
        str = cJSON_GetStringValue(elem);
        strncpy(m_akms_allowed, str, strlen(str) + 1);
    }

    if ((elem = cJSON_GetObjectItem(ob, "SuiteSelector")) != NULL) {
        str = cJSON_GetStringValue(elem);
        strncpy(m_akms_allowed, str, strlen(str) + 1);
    }

    if ((elem = cJSON_GetObjectItem(ob, "HaulType")) != NULL) {
        str = cJSON_GetStringValue(elem);
        strncpy(m_haul_type, str, strlen(str) + 1);
    }

    if ((elem = cJSON_GetObjectItem(ob, "Type")) != NULL) {
        str = cJSON_GetStringValue(elem);
        strncpy(m_type, str, strlen(str) + 1);
    }

}

int de_net_ssid_t::init(const char *key)
{
    strncpy(m_key, key, strlen(key) + 1);
    return 0;
}

void de_net_ssid_t::deinit()
{

}

de_net_ssid_t::de_net_ssid_t()
{
    memset(m_key, 0, sizeof(m_key));
    memset(m_ssid, 0, sizeof(m_ssid));
    memset(m_op, 0, sizeof(m_op));
    m_enabled = false;
    m_advertisement = false;
    memset(m_mfp_config, 0, sizeof(m_mfp_config));
    memset(m_mob_domain, 0, sizeof(m_mob_domain));
    memset(m_passphrase, 0, sizeof(m_passphrase));
    memset(m_band, 0, sizeof(m_band));
    memset(m_akms_allowed, 0, sizeof(m_akms_allowed));
    memset(m_suite_selector, 0, sizeof(m_suite_selector));
    memset(m_haul_type, 0, sizeof(m_haul_type));
    memset(m_type, 0, sizeof(m_type));
}

de_net_ssid_t::~de_net_ssid_t()
{

}
