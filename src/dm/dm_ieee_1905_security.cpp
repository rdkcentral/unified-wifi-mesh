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
#include <assert.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <unistd.h>
#include "dm_ieee_1905_security.h"

int dm_ieee_1905_security_t::decode(const cJSON *obj)
{
    cJSON *tmp;

    if ((tmp = cJSON_GetObjectItem(obj, "OnboardingProtocol")) != NULL) {
       	m_ieee_1905_security_info.sec_cap.onboarding_proto = static_cast<unsigned char> (tmp->valuedouble);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "IntegrityAlgorithm")) != NULL) {
       	m_ieee_1905_security_info.sec_cap.integrity_algo = static_cast<unsigned char> (tmp->valuedouble);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "EncryptionAlgorithm")) != NULL) {
       	m_ieee_1905_security_info.sec_cap.encryption_algo = static_cast<unsigned char> (tmp->valuedouble);
    }

    return 0;
}

void dm_ieee_1905_security_t::encode(cJSON *obj)
{
    cJSON_AddNumberToObject(obj, "OnboardingProtocol", m_ieee_1905_security_info.sec_cap.onboarding_proto);
    cJSON_AddNumberToObject(obj, "IntegrityAlgorithm", m_ieee_1905_security_info.sec_cap.integrity_algo);
    cJSON_AddNumberToObject(obj, "EncryptionAlgorithm", m_ieee_1905_security_info.sec_cap.encryption_algo);
}

bool dm_ieee_1905_security_t::operator == (const dm_ieee_1905_security_t& obj)
{

	if (memcmp(m_ieee_1905_security_info.id, obj.m_ieee_1905_security_info.id, sizeof(mac_address_t)) != 0) {
		printf("%s:%d: id is different\n", __func__, __LINE__);
		return false;
	}

	if (m_ieee_1905_security_info.sec_cap.onboarding_proto != obj.m_ieee_1905_security_info.sec_cap.onboarding_proto) {
		printf("%s:%d: number of bands are different\n", __func__, __LINE__);
		return false;
	}

	if (m_ieee_1905_security_info.sec_cap.integrity_algo != obj.m_ieee_1905_security_info.sec_cap.integrity_algo) {
		printf("%s:%d: number of akms are different\n", __func__, __LINE__);
		return false;
	}

	if (m_ieee_1905_security_info.sec_cap.encryption_algo != obj.m_ieee_1905_security_info.sec_cap.encryption_algo) {
		printf("%s:%d: number of akms are different\n", __func__, __LINE__);
		return false;
	}

	return true;
}

void dm_ieee_1905_security_t::operator = (const dm_ieee_1905_security_t& obj)
{
    if (this == &obj) { return; }
    memcpy(&this->m_ieee_1905_security_info.id ,&obj.m_ieee_1905_security_info.id ,sizeof(mac_address_t));
    this->m_ieee_1905_security_info.sec_cap.onboarding_proto = obj.m_ieee_1905_security_info.sec_cap.onboarding_proto;
    this->m_ieee_1905_security_info.sec_cap.integrity_algo = obj.m_ieee_1905_security_info.sec_cap.integrity_algo;
    this->m_ieee_1905_security_info.sec_cap.encryption_algo = obj.m_ieee_1905_security_info.sec_cap.encryption_algo;

}

dm_ieee_1905_security_t::dm_ieee_1905_security_t(em_ieee_1905_security_info_t *ieee_1905_security)
{
    memcpy(&m_ieee_1905_security_info, ieee_1905_security, sizeof(em_ieee_1905_security_info_t));
}

dm_ieee_1905_security_t::dm_ieee_1905_security_t(const dm_ieee_1905_security_t& ieee_1905_security)
{
	memcpy(&m_ieee_1905_security_info, &ieee_1905_security.m_ieee_1905_security_info, sizeof(em_ieee_1905_security_info_t));
}

dm_ieee_1905_security_t::dm_ieee_1905_security_t()
{

}

dm_ieee_1905_security_t::~dm_ieee_1905_security_t()
{

}
