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
#include "em_cmd_csi.h"

em_cmd_csi_t::em_cmd_csi_t(em_cmd_params_t param, dm_easy_mesh_t &dm)
{
    em_cmd_ctx_t ctx;;

    m_type = em_cmd_type_csi;
    memcpy(&m_param, &param, sizeof(em_cmd_params_t));

    memset(reinterpret_cast<unsigned char *> (&m_orch_desc[0]), 0, EM_MAX_CMD*sizeof(em_orch_desc_t));

    m_orch_op_idx = 0;
    m_num_orch_desc = 1;
    m_orch_desc[0].op = dm_orch_type_ctrl_notify;
    m_orch_desc[0].submit = true;
    //m_orch_desc[1].op = dm_orch_type_csi_commit;
    m_orch_op_idx = 0;
    
    strncpy(m_name, "csi", sizeof(m_name) - 1);
    m_svc = em_service_type_agent;
    init(dm);

    memset(&ctx, 0, sizeof(em_cmd_ctx_t));
    ctx.type = m_orch_desc[0].op;    

    m_data_model.set_cmd_ctx(&ctx);
}
