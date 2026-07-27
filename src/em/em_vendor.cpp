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

#define EM_LQ_DATA_VENDOR_TLV_ATTR_ID 0x10

// Weak factory fallback: Returns nullptr if custom extension code is omitted
__attribute__((weak)) em_vendor_ext_interface_t* create_em_vendor_ext() {
    return nullptr;
}

unsigned int em_vendor_t::get_vendor_id(unsigned char *buff) 
{
    em_vendor_specific_t *vendor_data = reinterpret_cast<em_vendor_specific_t *> (buff);
    em_printfout("vendor_data->num count [%d]", vendor_data->num);

    em_vendor_data_t *vendor_data_ptr = vendor_data->data;
    em_printfout("vendor_data->attri [%d]", vendor_data_ptr->attr_id);

    return static_cast<unsigned int>(vendor_data_ptr->attr_id);
}

int em_vendor_t::handle_vendor_msg(unsigned char *buff, unsigned int len)
{
    em_tlv_t *tlv, *tlv_start;
    size_t tmp_len, base_len;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};

    if (em_msg_t(em_msg_type_topo_vendor, get_profile_type(), buff, len).validate(errors) == 0) {
        printf("%s:%d: Vendor msg validation failed\n", __func__, __LINE__);
        return -1;
    }

    tlv_start = reinterpret_cast<em_tlv_t *>(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    base_len  = static_cast<size_t>(len) - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    tlv     = tlv_start;
    tmp_len = base_len;
    em_vendor_data_t *vendor_data_ptr = nullptr;

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_vendor_specific) {
            em_vendor_specific_t *vendor_tlv = reinterpret_cast<em_vendor_specific_t *> (tlv->value);
            em_printfout("------->> Recvd vendor tlv, num: %d and tlv->len:%d", vendor_tlv->num, ntohs(tlv->len));
            if ((vendor_tlv->num <= 0) || (ntohs(tlv->len) == 0)) {
                break;
            }

            for(int i = 0; i < vendor_tlv->num; i++) {
                vendor_data_ptr = vendor_tlv->data;
                em_printfout("Vendor data attr_id [%d]", vendor_data_ptr->attr_id);
                 
                if (vendor_data_ptr->attr_id == vendor_ext_attr_id_wei_data) {
                    // Handle the LQ data vendor TLV
                em_printfout("call vendor handler");

                    handle_vendor_tlv_ext(tlv->value, ntohs(tlv->len), get_data_model());
                    // handle_vendor_ext_tlv(tlv->value, ntohs(tlv->len), get_data_model());
                }
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
    if (m_vendor_ext) {
        return m_vendor_ext->handle_vendor_tlv_ext(tlv_value, tlv_len, dm);
    }
    return 0; // Default base fallback
}

// Sends the raw stats_arg_t[] bytes from the current vendor-data cmd
// directly as the vendor TLV payload — no dm_sta_ext_t access needed.
int em_vendor_t::send_vendor_msg()
{
    em_cmd_t *cmd = get_current_cmd();
    if (!cmd) {
        return -1;
    }

    const std::vector<uint8_t> *raw = cmd->get_raw_data();
    if (!raw || raw->empty()) {
        return 0;
    }

    em_printfout("-------> Sending vendor message with raw data size: %zu\n", raw->size());
    // em_printfout("-------> cmdd state: %s", em_t::state_2_str(get_current_cmd()->get_state()));


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

    /* Vendor-specific TLV: OUI + num(1) + attr_id(0x10) + raw bytes */
    tlv = reinterpret_cast<em_tlv_t *>(tmp);
    tlv->type = em_tlv_type_vendor_specific;
    unsigned char *vp = tlv->value;
    memcpy(vp, comcast_vendor_oui, EM_VENDOR_OUI_SIZE);
    vp += EM_VENDOR_OUI_SIZE;
    *vp++ = 1;     // num
    *vp++ = vendor_ext_attr_id_wei_data;
    memcpy(vp, raw->data(), raw->size()); vp += raw->size();
    unsigned int tlv_val_len = static_cast<unsigned int>(vp - tlv->value);
    em_printfout("Vendor TLV value length: %u\n", tlv_val_len);
    tlv->len = htons(static_cast<unsigned short>(tlv_val_len));
    tmp += sizeof(em_tlv_t) + tlv_val_len;
    len += sizeof(em_tlv_t) + tlv_val_len;

    /* EOM TLV */
    tlv = reinterpret_cast<em_tlv_t *>(tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len  = 0;
    len += sizeof(em_tlv_t);

    int ret = send_frame(buff, static_cast<unsigned int>(len));
    if (ret == 0) {
        cmd->processed = true;
        em_printfout("Vendor msg sent and proceesd cmd set to true: %u\n", tlv_val_len);
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

    switch (cmd->get_type()) {
        case em_cmd_type_generic_data:
            if (cmd->processed == false) {
                send_vendor_msg();
            }
            break;

        default:
            break;
    }
}

em_vendor_t::em_vendor_t()
    : m_vendor_ext(create_em_vendor_ext())
{
    // Base initialization logic here
}

em_vendor_t::~em_vendor_t()
{
    // Safe! ~em_vendor_ext_interface_t() is virtual, so delete cleanly destroys
    // the private instance without needing custom headers included here.
    delete m_vendor_ext;
    m_vendor_ext = nullptr;
}
