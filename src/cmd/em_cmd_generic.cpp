/**
 * Copyright 2025 Comcast Cable Communications Management, LLC
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
#include <sys/socket.h>
#include <sys/uio.h>
#include <pthread.h>
#include "em_cmd_generic.h"

em_cmd_generic_t::em_cmd_generic_t(uint8_t *raw_buff, int len, dm_easy_mesh_t& dm)
{
    em_cmd_ctx_t ctx;

    m_type = em_cmd_type_generic_data;

    memset(reinterpret_cast<unsigned char *>(&m_orch_desc[0]), 0, EM_MAX_CMD * sizeof(em_orch_desc_t));

    m_orch_op_idx = 0;
    m_num_orch_desc = 1;
    m_orch_desc[0].op = dm_orch_type_wei_data;
    m_orch_desc[0].submit = true;

    strncpy(m_name, "cmd_data", strlen("cmd_data") + 1);
    m_svc = em_service_type_agent;
    init(dm);

    memset(&ctx, 0, sizeof(em_cmd_ctx_t));
    ctx.type = m_orch_desc[0].op;
    m_data_model.set_cmd_ctx(&ctx);

    // Copy raw payload and call private-repo hook if registered.
    if (raw_buff && len > 0) {
        m_raw_data.assign(raw_buff, raw_buff + len);
    }
   // if (s_populate) s_populate(*this, dm);
}
