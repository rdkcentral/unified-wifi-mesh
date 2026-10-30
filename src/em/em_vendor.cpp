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

#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include "em_vendor.h"
#include "em_msg.h"
#include "dm_easy_mesh.h"
#include "em_cmd.h"
#include "em_ext_hooks.h"

int em_vendor_t::handle_vendor_msg(unsigned char *buff, unsigned int len)
{
    em_tlv_t *tlv, *tlv_start;
    size_t tmp_len, base_len;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};

    if (em_msg_t(em_msg_type_topo_vendor, get_profile_type(), buff, len).validate(errors) == 0) {
        em_printfout("Vendor msg validation failed");
        return -1;
    }

    tlv_start = reinterpret_cast<em_tlv_t *>(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    base_len  = static_cast<size_t>(len) - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    tlv     = tlv_start;
    tmp_len = base_len;

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_vendor_specific) {
            em_vendor_specific_t *vendor_tlv = reinterpret_cast<em_vendor_specific_t *> (tlv->value);
            em_printfout("Recvd vendor tlv, tlv->len:%d", ntohs(tlv->len));
            if ((ntohs(tlv->len) > EM_VENDOR_OUI_SIZE) &&
                (memcmp(vendor_tlv->vendor_oui, comcast_vendor_oui, EM_VENDOR_OUI_SIZE) == 0)) {
                // vendor_tlv->data layout: [attr_id (1 byte)][vendor_data...]
                em_printfout("Vendor data attr_id [%d]", vendor_tlv->data[0]);

                handle_vendor_tlv_ext(tlv->value, ntohs(tlv->len), get_data_model());
            }
        }
        tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t>(htons(tlv->len)));
        tlv = reinterpret_cast<em_tlv_t *>(
            reinterpret_cast<unsigned char *>(tlv) + sizeof(em_tlv_t) + htons(tlv->len));
    }

    return 0;
}

int em_vendor_t::handle_vendor_tlv_ext(const unsigned char *tlv_value,
                                        unsigned int         tlv_len,
                                        dm_easy_mesh_t      *dm)
{
    return em_get_ext_hooks()->handle_vendor_tlv_ext(tlv_value, tlv_len, dm);
}

int em_vendor_t::build_vendor_tlv_ext(const unsigned char *raw_data,
                                       unsigned int         raw_len,
                                       unsigned char       *tlv_value,
                                       unsigned int        *tlv_val_len)
{
    return em_get_ext_hooks()->build_vendor_tlv_ext(raw_data, raw_len, tlv_value, tlv_val_len);
}

// Sends the raw stats_arg_t[] bytes from the current vendor-data cmd
// directly as the vendor TLV payload - no dm_sta_ext_t access needed.
int em_vendor_t::send_vendor_msg()
{
    em_cmd_t *cmd = get_current_cmd();
    if (!cmd) {
        return -1;
    }

    const std::vector<uint8_t> *raw = cmd->get_raw_data();
    if (!raw || raw->empty()) {
        // Nothing to send; complete the cmd so it does not hold the radio until timeout
        cmd->processed = true;
        return 0;
    }

    em_printfout("Sending vendor message with raw data size: %zu", raw->size());

    unsigned char buff[MAX_EM_BUFF_SZ * EM_MAX_RADIO_PER_AGENT] = {0};
    unsigned char *tmp = buff;
    size_t len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t  *tlv;
    dm_easy_mesh_t *dm = get_data_model();
    unsigned short type = htons(ETH_P_1905);

    memcpy(tmp, dm->get_ctl_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t); len += sizeof(mac_address_t);

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t); len += sizeof(mac_address_t);

    memcpy(tmp, &type, sizeof(unsigned short));
    tmp += sizeof(unsigned short); len += sizeof(unsigned short);

    cmdu = reinterpret_cast<em_cmdu_t *>(tmp);
    memset(cmdu, 0, sizeof(em_cmdu_t));
    cmdu->type          = htons(em_msg_type_topo_vendor);
    cmdu->id            = htons(get_mgr()->get_next_msg_id());
    cmdu->last_frag_ind = 1;
    tmp += sizeof(em_cmdu_t); len += sizeof(em_cmdu_t);

    /* Vendor-specific TLV: attribute bytes built privately (see build_vendor_tlv_ext) */
    // Reserve room for the vendor TLV header, its maximum value and the end-of-message TLV
    if ((len + 2 * sizeof(em_tlv_t) + EM_VENDOR_TLV_MAX_LEN) > sizeof(buff)) {
        em_printfout("Vendor msg buffer too small; skipping send");
        cmd->processed = true;
        return -1;
    }
    tlv = reinterpret_cast<em_tlv_t *>(tmp);
    tlv->type = em_tlv_type_vendor_specific;
    unsigned int tlv_val_len = 0;
    if (build_vendor_tlv_ext(raw->data(), static_cast<unsigned int>(raw->size()), tlv->value, &tlv_val_len) != 0) {
        em_printfout("No vendor extension available to build vendor TLV; skipping send");
        cmd->processed = true;
        return -1;
    }
    if (tlv_val_len > EM_VENDOR_TLV_MAX_LEN) {
        em_printfout("Vendor TLV value length %u exceeds max %d; skipping send", tlv_val_len, EM_VENDOR_TLV_MAX_LEN);
        cmd->processed = true;
        return -1;
    }
    em_printfout("Vendor TLV value length: %u", tlv_val_len);
    tlv->len = htons(static_cast<unsigned short>(tlv_val_len));
    tmp += sizeof(em_tlv_t) + tlv_val_len;
    len += sizeof(em_tlv_t) + tlv_val_len;

    /* EOM TLV */
    tlv = reinterpret_cast<em_tlv_t *>(tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len  = 0;
    len += sizeof(em_tlv_t);

    int ret = send_frame(buff, static_cast<unsigned int>(len));
    if (ret >= 0) {
        cmd->processed = true;
        em_printfout("Vendor msg sent and processed cmd set to true: %u", tlv_val_len);
    }
    return ret;
}

void em_vendor_t::process_agent_state()
{
    em_cmd_t *cmd = get_current_cmd();
    if (cmd == NULL) {
        em_printfout("Current command is NULL");
        return;
    }

    em_printfout("Vendor data: process_agent_state entered, cmd type:%d processed:%d", cmd->get_type(), cmd->processed.load());

    switch (cmd->get_type()) {
        case em_cmd_type_vendor_data:
            if (cmd->processed == false) {
                em_printfout("Vendor data: calling send_vendor_msg()");
                send_vendor_msg();
            }
            break;

        default:
            break;
    }
}
