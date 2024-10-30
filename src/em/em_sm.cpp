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
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include "em_sm.h"


bool em_sm_t::validate_sm(em_state_t state)
{
	return true;
}

int em_sm_t::set_state(em_state_t state)
{
	if (validate_sm(state) == true) {
		m_state = state;
		return 0;
	}

	return -1;
}

void em_sm_t::init_sm(em_service_type_t service)
{
	m_state = (service == em_service_type_agent) ? em_state_agent_unconfigured:em_state_ctrl_unconfigured;	
}

em_sm_t::em_sm_t()
{

}

em_sm_t::~em_sm_t()
{

}

