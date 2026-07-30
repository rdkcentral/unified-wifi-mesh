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
#include <linux/filter.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/rand.h>
#include <assert.h>
#include "em_configuration.h"
#include "em_onewifi.h"
#include "util.h"
#include "em_msg.h"
#include "em_base.h"
#include "em_test_validation.h"

// Few message frames are facing crash: not ready for merge
//printf is used here to print the message list in the console, and to take user response 

void em_testValidation_t::test_validation(em_msg_type_t type, em_profile_type_t profile,unsigned char *buff,unsigned int sz )
{
    char* Errors[EM_MAX_TLV_MEMBERS];

    em_util_info_print(EM_CONF,"%s:%d: entered validation function \n", __func__, __LINE__);

    em_msg_t validateObj(type, profile, buff, sz);

    if (validateObj.validate(Errors)) {

        em_util_info_print(EM_CONF,"%s:%d: validation successful\n", __func__, __LINE__);
        printf("\nValidation Successful\n");
    } else {
        for (int i = 0; i < EM_MAX_TLV_MEMBERS; i++) {

            if (Errors[i] != NULL) {
                printf("validation failed for TLVs:\n%s\n",Errors[i]);
            }
        }

        em_util_info_print(EM_CONF,"%s:%d:validation failed\n", __func__, __LINE__);
    }
}

em_testValidation_t::em_testValidation_t(unsigned char *buff, unsigned int &len){

    em_util_info_print(EM_CONF,"%s:%d: entered header integration funtion\n", __func__, __LINE__);
    //Considering a common cmdu header  for all messages
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff; 
    unsigned short  msg_type = em_msg_type_autoconf_search;
    unsigned short type = htons(ETH_P_1905);
    mac_address_t   multi_addr = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x13};
    mac_address_t   src_addr = {0x02, 0x10, 0xc1, 0x00, 0x00, 0x13};

    memcpy(tmp, (unsigned char *)multi_addr, sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, (unsigned char *)src_addr, sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, (unsigned char *)&type, sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = (em_cmdu_t *)tmp;

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_type);
    cmdu->id = htons(get_mgr()->get_next_msg_id());
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);
    em_util_info_print(EM_CONF,"%s:%d: exiting header integration function\n", __func__, __LINE__);
}


int em_testValidation_t::test_autoconfig_search_msg(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered autoconfig search msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_autoconf_search;

    unsigned char *tmp = (buff+len);

    // AL MAC Address type TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_al_mac_address;
    tlv->len = htons(sizeof(mac_address_t));
    //memcpy(tlv->value,(unsigned char *)get_mac(), sizeof(mac_address_t));

    tmp += (sizeof (em_tlv_t) + sizeof(mac_address_t));
    len += (sizeof (em_tlv_t) + sizeof(mac_address_t));

    //SearchedRole TLV
    if (i==0) {
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_searched_role;
        tlv->len = htons(sizeof(unsigned char));
        // memcpy(&tlv->value, &registrar, sizeof(unsigned char));

        tmp += (sizeof (em_tlv_t) + 1);
        len += (sizeof (em_tlv_t) + 1);
    }

    //autoconf_freq_band TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_autoconf_freq_band;
    tlv->len = htons(sizeof(unsigned char));
    //memcpy(&tlv->value, &config_freq, sizeof(unsigned char));

    tmp += (sizeof (em_tlv_t) + 1);
    len += (sizeof (em_tlv_t) + 1);

    // supported service 17.2.1
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_supported_service;
    tlv->len = htons(sizeof(em_enum_type_t) + 1);
    tlv->value[0] = 1;
    // memcpy(&tlv->value[1], &service_type, sizeof(em_enum_type_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_enum_type_t) + 1);
    len += (sizeof(em_tlv_t) + sizeof(em_enum_type_t) + 1);

    // searched service 17.2.2
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_searched_service;
    tlv->len = htons(sizeof(em_enum_type_t) + 1);
    tlv->value[0] = 1;

    tmp += (sizeof(em_tlv_t) + sizeof(em_enum_type_t) + 1);
    len += (sizeof(em_tlv_t) + sizeof(em_enum_type_t) + 1);

    // One multiAP profile tlv 17.2.47
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_profile;
    tlv->len = htons(sizeof(em_enum_type_t));
    profile = em_profile_type_3;
    //memcpy(tlv->value, &profile, sizeof(em_enum_type_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_enum_type_t));
    len += (sizeof(em_tlv_t) + sizeof(em_enum_type_t));

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of autoconfig search message\n");
    printf("\n============================================\n");
    printf("\nCreated autoconfig search message\n");
    em_util_info_print(EM_CONF,"%s:%d: test_autoconfig_search message creation successful, len = %d\n", __func__, __LINE__,len);
    return len;
}


int em_testValidation_t::test_autoconfig_resp_msg(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered autoconfig response msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_autoconf_resp;
    unsigned char *tmp = (buff+len);    

    //SupportedRole TLV
    if (i==0) {
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_supported_role;
        tlv->len = htons(sizeof(unsigned char));

        tmp += (sizeof (em_tlv_t) + 1);
        len += (sizeof (em_tlv_t) + 1);
    }


    //SupportedFreqBand TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_supported_freq_band;
    tlv->len = htons(sizeof(unsigned char));

    tmp += (sizeof (em_tlv_t) + 1);
    len += (sizeof (em_tlv_t) + 1);

    // supported service tlv 17.2.1
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_supported_service;
    tlv->len = htons(sizeof(em_enum_type_t) + 1);
    //  tlv->value[0] = 1;
    // memcpy(&tlv->value[1], &service_type, sizeof(em_enum_type_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_enum_type_t) + 1);
    len += (sizeof(em_tlv_t) + sizeof(em_enum_type_t) + 1);

    // 1905 layer security capability tlv 17.2.67
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_1905_layer_security_cap;
    tlv->len = htons(sizeof(em_ieee_1905_security_cap_t));
    //memcpy(tlv->value, get_1905_layer_security(), sizeof(em_1905_layer_security_cap_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_ieee_1905_security_cap_t));
    len += (sizeof(em_tlv_t) + sizeof(em_ieee_1905_security_cap_t));

    // One multiAP profile tlv 17.2.47
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_profile;
    tlv->len = htons(sizeof(em_enum_type_t));
    // profile = get_profile_type();
    //memcpy(tlv->value, &profile, sizeof(em_enum_type_t));
    profile = em_profile_type_3;

    tmp += (sizeof(em_tlv_t) + sizeof(em_enum_type_t));
    len += (sizeof(em_tlv_t) + sizeof(em_enum_type_t));

    // One DPP chirp value tlv 17.2.83
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_dpp_chirp_value;
    tlv->len = htons(sizeof(em_dpp_chirp_value_t));
    chirp.presence = 0;
    //memcpy(tlv->value, &chirp, sizeof(em_dpp_chirp_value_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_dpp_chirp_value_t));
    len += (sizeof(em_tlv_t) + sizeof(em_dpp_chirp_value_t));

    // One controller capability tlv 17.2.94
    if (i==0) {
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_ctrl_cap;
        tlv->len = htons(sizeof(em_ctrl_cap_t));
        // memset(&ctrl_cap, 0, sizeof(em_ctrl_cap_t));;
        // memcpy(tlv->value, &ctrl_cap, sizeof(em_ctrl_cap_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_ctrl_cap_t));
        len += (sizeof(em_tlv_t) + sizeof(em_ctrl_cap_t));
    }

    // End of message

    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of autoconfig response message\n");
    printf("\n==============================================\n");
    printf("\nCreated autoconfig response message\n");
    em_util_info_print(EM_CONF,"%s:%d: test_autoconfig_response message creation successful, len = %d\n", __func__, __LINE__,len);

    return len;
}
/*
   int em_testValidation_t::test_autoconfig_wsc_m1(unsigned char *buff,int i,unsigned int len)
   {

   em_util_info_print(EM_CONF,"%s:%d: entered autoconfig wsc m1 msg creation function\n", __func__, __LINE__);
   unsigned short  msg_id = em_msg_type_autoconf_wsc;
   int len=0;int sz=0;
   unsigned char *tmp = (buff + len);

   if (i==0){
//AP Radio Basic Capabilities TLV
tlv = (em_tlv_t *)tmp;
tlv->type = em_tlv_type_ap_radio_basic_cap;
tlv->len = htons(sizeof(em_ap_radio_basic_cap_t));

tmp += (sizeof(em_tlv_t) + sizeof(em_ap_radio_basic_cap_t));
len += (sizeof(em_tlv_t) + sizeof(em_ap_radio_basic_cap_t));
}

// One wsc tlv containing M1
tlv = (em_tlv_t *)tmp;
tlv->type = em_tlv_type_wsc;
sz = em_configuration_t::create_m1_msg(tlv->value);     //create_m1_msg(tlv->value) this is  a private function,hence cannot use
tlv->len = htons(sz);

tmp += (sizeof(em_tlv_t) + sz);
len += (sizeof(em_tlv_t) + sz);

//Profile-2 AP Capability TLV
tlv = (em_tlv_t *)tmp;
tlv->type = em_tlv_type_profile_2_ap_cap;
tlv->len = htons(sizeof(em_profile_2_ap_cap_t));

tmp += (sizeof(em_tlv_t) + sizeof(em_profile_2_ap_cap_t));
len += (sizeof(em_tlv_t) + sizeof(em_profile_2_ap_cap_t));

//AP Radio Advanced Capabilities TLV
tlv = (em_tlv_t *)tmp;
tlv->type = em_tlv_type_ap_radio_advanced_cap;
tlv->len = htons(sizeof(em_ap_radio_advanced_cap_t));

tmp += (sizeof(em_tlv_t) + sizeof(em_ap_radio_advanced_cap_t));
len += (sizeof(em_tlv_t) + sizeof(em_ap_radio_advanced_cap_t));

// End of message
tlv = (em_tlv_t *)tmp;
tlv->type = em_tlv_type_eom;
tlv->len = 0;

tmp += (sizeof (em_tlv_t));
len += (sizeof (em_tlv_t));

printf("\nTest validation of autoconfig wsc m1 message\n");
printf("\n=========================================\n");
printf("\nCreated autoconfig wsc m1\n");
em_util_info_print(EM_CONF,"%s:%d: test_autoconfig_wsc_m1 message creation successful, len = %d\n", __func__, __LINE__,len);

return len;

}

int em_testValidation_t::test_autoconfig_wsc_m2(unsigned char *buff,int i,unsigned int len)
{

em_util_info_print(EM_CONF,"%s:%d: entered autoconfig wsc m2 msg creation function\n", __func__, __LINE__);
unsigned short  msg_id = em_msg_type_autoconf_wsc;
int len=0;int sz=0;
unsigned char *tmp = (buff + len);

//AP Radio Identifier TLV
tlv = (em_tlv_t *)tmp;
tlv->type =  em_tlv_type_radio_id;
tlv->len = htons(sizeof(em_ap_radio_id_t));

tmp += (sizeof(em_tlv_t) + sizeof(em_ap_radio_id_t));
len += (sizeof(em_tlv_t) + sizeof(em_ap_radio_id_t));

// One wsc tlv containing M2
tlv = (em_tlv_t *)tmp;
tlv->type = em_tlv_type_wsc;
sz = em_configuration_t::create_m2_msg(tlv->value); //create_m2_msg(tlv->value): private function,hence cannot use
tlv->len = htons(sz);

tmp += (sizeof(em_tlv_t) + sz);
len += (sizeof(em_tlv_t) + sz);

//Default 802.1Q Settings TLV
tlv = (em_tlv_t *)tmp;
tlv->type =  em_tlv_type_dflt_8021q_settings;
tlv->len = htons(sizeof(em_8021q_settings_t));

tmp += (sizeof(em_tlv_t) + sizeof(em_8021q_settings_t));
len += (sizeof(em_tlv_t) + sizeof(em_8021q_settings_t));

//Traffic Separation Policy TLV
tlv = (em_tlv_t *)tmp;
tlv->type = em_tlv_type_traffic_separation_policy;
tlv->len = htons(sizeof(em_traffic_sep_policy_t));

tmp += (sizeof(em_tlv_t) + sizeof(em_traffic_sep_policy_t));
len += (sizeof(em_tlv_t) + sizeof(em_traffic_sep_policy_t));

// End of message
tlv = (em_tlv_t *)tmp;
tlv->type = em_tlv_type_eom;
tlv->len = 0;

tmp += (sizeof (em_tlv_t));
len += (sizeof (em_tlv_t));

printf("\nTest validation of autoconfig wsc m2 message\n");
printf("\n=========================================\n");
printf("\nCreated autoconfig wsc m2\n");
em_util_info_print(EM_CONF,"%s:%d: test_autoconfig_wsc_m2 message creation successful, len = %d\n", __func__, __LINE__,len);

return len;

}
    */
int em_testValidation_t::test_bss_config_res(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered bss config result msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_bss_config_res;
    unsigned char *tmp = (buff+len);


    if (i==0) {
        // BSS Configuration Report TLV
        em_tlv_t* tlv;
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_bss_conf_rep;
        tlv->len = htons(sizeof(em_bss_config_rprt_t)); 
        // memcpy(&tlv->value[1], &service_type, sizeof(em_enum_type_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_bss_config_rprt_t));
        len += (sizeof(em_tlv_t) + sizeof(em_bss_config_rprt_t));
    }

    em_util_info_print(EM_CONF,"%s:%d: created BSS Configuration Report TLV\n", __func__, __LINE__);


    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of bss config res message\n");
    printf("\n=========================================\n");
    printf("\nCreated bss config res message\n");
    em_util_info_print(EM_CONF,"%s:%d: test_bss_config_res message creation successful, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_direct_encap_dpp(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered direct_encap_dpp msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_direct_encap_dpp;
    unsigned char *tmp = (buff+len);

    if (i==0) {
        // DPP Message TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_dpp_msg;
        tlv->len = htons(sizeof(em_enum_type_t) + 1);

        tmp += (sizeof(em_tlv_t) + sizeof(em_enum_type_t) + 1);
        len += (sizeof(em_tlv_t) + sizeof(em_enum_type_t) + 1);
    }
    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of direct encap dpp message\n");
    printf("\n===========================================\n");
    printf("\nCreated direct encap dpp message\n");
    em_util_info_print(EM_CONF,"%s:%d: test_direct_encap_dpp message creation successful, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_agent_list(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered agent list msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_agent_list;
    unsigned char *tmp = (buff+len);

    if (i==0) {
        // Agent list TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_agent_list;
        tlv->len = htons(sizeof(em_agent_list_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_agent_list_t));
        len += (sizeof(em_tlv_t) + sizeof(em_agent_list_t));
    }
    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of agent list message\n");
    printf("\n=====================================\n");
    printf("\nCreated agent list message\n");
    em_util_info_print(EM_CONF,"%s:%d: test_agent_list message creation successful, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_anticipated_channel_pref(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered anticipated_channel_pref msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id =  em_msg_type_anticipated_channel_pref;
    unsigned char *tmp = (buff+len);

    if (i==0) {
        //anticipated_channel_pref TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_anticipated_channel_pref;
        tlv->len = htons(sizeof(em_anti_channel_pref_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_anti_channel_pref_t));
        len += (sizeof(em_tlv_t) + sizeof(em_anti_channel_pref_t));
    }

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of anticipated channel pref message\n");
    printf("\n===================================================\n");
    printf("\nCreated anticipated channel pref message\n");
    em_util_info_print(EM_CONF,"%s:%d: test_anticipated_channel_pref message creation successful, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_anticipated_channel_usage_rprt(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered anticipated_channel_usage_rprt msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id =  em_msg_type_anticipated_channel_usage_rprt;
    unsigned char *tmp = (buff+len);

    if (i==0) {
        //anticipated channel_usage TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_channel_usage;
        tlv->len = htons(sizeof(em_anti_chan_usage_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_anti_chan_usage_t));
        len += (sizeof(em_tlv_t) + sizeof(em_anti_chan_usage_t));
    }
    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of anticipated channel usage rprt message\n");
    printf("\n=========================================================\n");
    printf("\nCreated anticipated channel usage rprt message\n");
    em_util_info_print(EM_CONF,"%s:%d: test_anticipated_channel_usage_rprt message creation successful, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_qos_mgmt_notif(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered qos_mgmt_notif msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id =  em_msg_type_qos_mgmt_notif;
    unsigned char *tmp = (buff+len);

    if (i==0) {
        //QoS Management Descriptor TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_qos_mgmt_desc;
        tlv->len = htons(sizeof(em_qos_mgmt_des_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_qos_mgmt_des_t));
        len += (sizeof(em_tlv_t) + sizeof(em_qos_mgmt_des_t));
    }
    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of qos mgmt notif message\n");
    printf("\n=========================================\n");
    printf("\nCreated qos mgt notif message\n");
    em_util_info_print(EM_CONF,"%s:%d: test_qos_mgmt_notif message creation successful, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_chirp_notif(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered chirp_notif msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id =  em_msg_type_chirp_notif;
    unsigned char *tmp = (buff+len);

    // One DPP chirp value tlv 
    if (i==0) {
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_dpp_chirp_value;
        tlv->len = htons(sizeof(em_dpp_chirp_value_t));
        chirp.presence = 0;
        // memcpy(tlv->value, &chirp, sizeof(em_dpp_chirp_value_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_dpp_chirp_value_t));
        len += (sizeof(em_tlv_t) + sizeof(em_dpp_chirp_value_t));
    }
    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of chirp notif message\n");
    printf("\n======================================\n");
    printf("\nCreated chirp notif message\n");
    em_util_info_print(EM_CONF,"%s:%d: test_chirp_notif message creation successful, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_dpp_cce_ind(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered dpp_cce_ind msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id =  em_msg_type_dpp_cce_ind;
    unsigned char *tmp = (buff+len);

    if (i==0) {
        //DPP CCE Indication TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_dpp_cce_indication;
        tlv->len = htons(sizeof(em_advertise_cce_t));


        tmp += (sizeof(em_tlv_t) + sizeof(em_advertise_cce_t));
        len += (sizeof(em_tlv_t) + sizeof(em_advertise_cce_t));
    }
    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of dpp cce ind message\n");
    printf("\n======================================\n");
    printf("\nCreated dpp cce ind message\n");
    em_util_info_print(EM_CONF,"%s:%d: test_dpp_cce_ind message creation successful, len = %d\n", __func__, __LINE__,len);


    return len;

}

int em_testValidation_t::test_dpp_bootstrap_uri_notif(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_dpp_bootstrap_uri_notif msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id =  em_msg_type_dpp_bootstrap_uri_notif;
    unsigned char *tmp = (buff+len);

    if (i == 0) {
        //DPP Bootstrapping URI Notification TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type =  em_tlv_type_dpp_bootstrap_uri_notification;
        tlv->len = htons(sizeof(em_dpp_bootstrap_uri_t));


        tmp += (sizeof(em_tlv_t) + sizeof(em_dpp_bootstrap_uri_t));
        len += (sizeof(em_tlv_t) + sizeof(em_dpp_bootstrap_uri_t));
    }
    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of dpp bootstraping uri notif  message\n");
    printf("\n======================================================\n");
    printf("\nCreated dpp bootstraping uri notif message\n");
    em_util_info_print(EM_CONF,"%s:%d: test_dpp_bootstraping_uri_notif message creation successful, len = %d\n", __func__, __LINE__,len);

    return len;

}


int em_testValidation_t::test_i1905_encap_eapol(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered 1905_encap_eapol msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_1905_encap_eapol;
    unsigned char *tmp = (buff+len);

    if (i == 0) {
        //1905 Encap EAPOL TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_1905_encap_eapol;
        tlv->len = htons(sizeof(em_eapol_frame_payload_t) + 1);

        tmp += (sizeof(em_tlv_t) + sizeof(em_eapol_frame_payload_t) + 1);
        len += (sizeof(em_tlv_t) + sizeof(em_eapol_frame_payload_t) + 1);
    }
    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of 1905 encap eapol message\n");
    printf("\n===========================================\n");
    printf("\nCreated 1905 encap eapol message\n");

    em_util_info_print(EM_CONF,"%s:%d: test_i1905_encap_eapol message creation successful, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_proxied_encap_dpp(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered proxied_encap_dpp msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id =  em_msg_type_proxied_encap_dpp;
    unsigned char *tmp = (buff+len);

    if (i == 0) {
        //1905 Encap DPP TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_1905_encap_dpp;
        tlv->len = htons(sizeof(em_encap_dpp_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_encap_dpp_t));
        len += (sizeof(em_tlv_t) + sizeof(em_encap_dpp_t));
    }

    // DPP chirp value tlv
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_dpp_chirp_value;
    tlv->len = htons(sizeof(em_dpp_chirp_value_t));
    chirp.hash_valid = 0;
    chirp.mac_present = 0;
    // memcpy(tlv->value, &chirp, sizeof(em_dpp_chirp_value_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_dpp_chirp_value_t));
    len += (sizeof(em_tlv_t) + sizeof(em_dpp_chirp_value_t));


    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of proxied encap dpp message\n");
    printf("\n============================================\n");
    printf("\nCreated proxied encap dpp message\n");

    em_util_info_print(EM_CONF,"%s:%d: test_proxied_encap_dpp message creation successful, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_i1905_decrypt_fail(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_i1905_decrypt_fail msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_1905_decrypt_fail;
    unsigned char *tmp = (buff+len);

    if (i == 0) {
        // AL MAC Address type TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_al_mac_address;
        tlv->len = htons(sizeof(mac_address_t));
        //  memcpy(tlv->value,(unsigned char *)get_mac(), sizeof(mac_address_t));

        tmp += (sizeof (em_tlv_t) + sizeof(mac_address_t));
        len += (sizeof (em_tlv_t) + sizeof(mac_address_t));
    }
    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of 1905 decrypt failure message\n");
    printf("\n===============================================\n");
    printf("\nCreated 1905 decrypt failure message\n");

    em_util_info_print(EM_CONF,"%s:%d: test_i1905_decrypt_fail message creation successful, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_bh_sta_cap_rprt(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_bh_sta_cap_rprt msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_bh_sta_cap_rprt;
    unsigned char *tmp = (buff+len);

    if (i == 0) {
        //Backhaul STA Radio Capabilities TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_bh_sta_radio_cap;
        tlv->len = htons(sizeof(em_bh_sta_radio_cap_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_bh_sta_radio_cap_t));
        len += (sizeof(em_tlv_t) + sizeof(em_bh_sta_radio_cap_t));
    }

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of backhaul station cap rprt message\n");
    printf("\n====================================================\n");
    printf("\nCreated backhaul station cap rprt message\n");
    em_util_info_print(EM_CONF,"%s:%d: test_bh_sta_cap_rprt message creation successful, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_assoc_status_notif(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_assoc_status_notif msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_assoc_status_notif;
    unsigned char *tmp = (buff+len);

    if ( i == 0) {
        //Association status notif TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_assoc_sts_notif;
        tlv->len = htons(sizeof(em_assoc_sts_notif_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_assoc_sts_notif_t));
        len += (sizeof(em_tlv_t) + sizeof(em_assoc_sts_notif_t));
    }

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of assoc status notif message\n");
    printf("\n=============================================\n");
    printf("\nCreated assoc status notif message\n");

    em_util_info_print(EM_CONF,"%s:%d: test_assoc_status_notif message creation successful, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_topo_query(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_topo_query msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_topo_query;
    unsigned char *tmp = (buff+len);

    if(i==0){
        // One multiAP profile tlv 17.2.47
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_profile;
        tlv->len = htons(sizeof(em_enum_type_t));
        profile = em_profile_type_3;
        //memcpy(tlv->value, &profile, sizeof(em_enum_type_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_enum_type_t));
        len += (sizeof(em_tlv_t) + sizeof(em_enum_type_t));
    }

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of topo query message\n");
    printf("\n=====================================\n");
    printf("\nCreated topo query message\n");

    em_util_info_print(EM_CONF,"%s:%d: test_topo_query message creation successful, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_err_rsp(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_err_rsp msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_err_rsp;
    unsigned char *tmp = (buff+len);

    if(i==0){
        //Profile-2 Error Code TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_profile_2_error_code;
        tlv->len = htons(sizeof(em_prof2_error_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_prof2_error_t));
        len += (sizeof(em_tlv_t) + sizeof(em_prof2_error_t));
    }
    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of error response message\n");
    printf("\n=========================================\n");
    printf("\nCreated error response message\n");

    em_util_info_print(EM_CONF,"%s:%d: test_err_rsp message creation successful, len = %d\n", __func__, __LINE__,len);

    return len;

}


int em_testValidation_t::test_cac_term(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_cac_term msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_cac_term;
    unsigned char *tmp = (buff+len);

    if(i==0){
        //CAC Termination TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_cac_term;
        tlv->len = htons(sizeof(em_cac_term_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_cac_term_t));
        len += (sizeof(em_tlv_t) + sizeof(em_cac_term_t));
    }
    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of cac termination message\n");
    printf("\n==========================================\n");
    printf("\nCreated cac termination message\n");

    em_util_info_print(EM_CONF,"%s:%d: test_cac_term creation successful, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_cac_req(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_cac_req msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_cac_req;
    unsigned char *tmp = (buff+len);

    if(i==0){
        //CAC request TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_cac_req;
        tlv->len = htons(sizeof(em_cac_req_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_cac_req_t));
        len += (sizeof(em_tlv_t) + sizeof(em_cac_req_t));
    }
    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of cac request message\n");
    printf("\n======================================\n");
    printf("\nCreated cac request message\n");

    em_util_info_print(EM_CONF,"%s:%d: test_cac_req creation successful, len = %d\n", __func__, __LINE__,len);

    return len;

}
int em_testValidation_t::test_channel_scan_rprt(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_channel_scan_rprt msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_channel_scan_rprt;
    unsigned char *tmp = (buff+len);

    if(i==0){
        //Timestamp TLV format
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_timestamp;
        tlv->len = htons(sizeof(em_timestamp_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_timestamp_t));
        len += (sizeof(em_tlv_t) + sizeof(em_timestamp_t));
    }

    //Channel Scan Result TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_channel_scan_rslt;
    tlv->len = htons(sizeof(em_channel_scan_result_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_channel_scan_result_t));
    len += (sizeof(em_tlv_t) + sizeof(em_channel_scan_result_t));

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of channel_scan_rprt message\n");
    printf("\n============================================\n");
    printf("\nCreated channel_scan_rprt message\n");

    em_util_info_print(EM_CONF,"%s:%d: test_channel_scan_rprt creation successful, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_channel_scan_req(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_channel_scan_req msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_channel_scan_req;
    unsigned char *tmp = (buff+len);

    if(i==0){
        //Channel Scan Request TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_channel_scan_req;
        tlv->len = htons(sizeof(em_channel_scan_req_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_channel_scan_req_t));
        len += (sizeof(em_tlv_t) + sizeof(em_channel_scan_req_t));
    }
    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of channel scan request message\n");
    printf("\n===============================================\n");
    printf("\nCreated channel scan request message\n");

    em_util_info_print(EM_CONF,"%s:%d: test_channel_scan_req creation successful, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_higher_layer_data(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_higher_layer_data msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_higher_layer_data;
    unsigned char *tmp = (buff+len);

    if(i==0){
        // Higher Layer Data TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_higher_layer_data;
        tlv->len = htons(sizeof(em_higher_layer_data_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_higher_layer_data_t));
        len += (sizeof(em_tlv_t) + sizeof(em_higher_layer_data_t));
    }
    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of higher_layer_data message\n");
    printf("\n============================================\n");
    printf("\nCreated higher_layer_data message\n");

    em_util_info_print(EM_CONF,"%s:%d: test_higher_layer_data creation successful, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_1905_ack(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_1905_ack msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_1905_ack;
    unsigned char *tmp = (buff+len);


    // Error Code TLV 
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_error_code;
    tlv->len = htons(sizeof(em_error_code_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_error_code_t));
    len += (sizeof(em_tlv_t) + sizeof(em_error_code_t));

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of 1905 ack message\n");
    printf("\n===================================\n");
    printf("\nCreated 1905 ack message\n");

    em_util_info_print(EM_CONF,"%s:%d: test_1905_ack creation successful, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_bh_steering_rsp(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_bh_steering_rsp msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_bh_steering_rsp;
    unsigned char *tmp = (buff+len);


    // Error Code TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_error_code;
    tlv->len = htons(sizeof(em_error_code_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_error_code_t));
    len += (sizeof(em_tlv_t) + sizeof(em_error_code_t));

    if(i==0){    
        // Backhaul Steering Response TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type =  em_tlv_type_bh_steering_rsp;
        tlv->len = htons(sizeof(em_bh_steering_resp_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_bh_steering_resp_t));
        len += (sizeof(em_tlv_t) + sizeof(em_bh_steering_resp_t));
    }

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of Backhaul Steering Response message\n");
    printf("\n=====================================================\n");
    printf("\nCreated Backhaul Steering Response\n");

    em_util_info_print(EM_CONF,"%s:%d: test_bh_steering_rep successful, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_bh_steering_req(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_bh_steering_req msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_bh_steering_req;
    unsigned char *tmp = (buff+len);

    if(i==0){
        // Backhaul Steering Request TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type =  em_tlv_type_bh_steering_req;
        tlv->len = htons(sizeof(em_bh_steering_req_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_bh_steering_req_t));
        len += (sizeof(em_tlv_t) + sizeof(em_bh_steering_req_t));
    }

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of Backhaul Steering Request message\n");
    printf("\n====================================================\n");
    printf("\nCreated Backhaul Steering Request\n");

    em_util_info_print(EM_CONF,"%s:%d: test_bh_steering_req successful, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_client_assoc_ctrl_req(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_client_assoc_ctrl_req msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_client_assoc_ctrl_req;
    unsigned char *tmp = (buff+len);

    if(i==0){
        // Client Association Control Request TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_client_assoc_ctrl_req;
        tlv->len = htons(sizeof(em_client_assoc_ctrl_req_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_client_assoc_ctrl_req_t));
        len += (sizeof(em_tlv_t) + sizeof(em_client_assoc_ctrl_req_t));
    }

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of client_assoc_ctrl_req message\n");
    printf("\n================================================\n");
    printf("\nCreated client_assoc_ctrl_req\n");

    em_util_info_print(EM_CONF,"%s:%d: test_client_assoc_ctrl_req, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_client_steering_btm_rprt(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_client_steering_btm_rprt msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_client_steering_btm_rprt;
    unsigned char *tmp = (buff+len);

    if(i==0){
        //  Steering BTM Report TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_steering_btm_rprt;
        tlv->len = htons(sizeof(em_steering_btm_rprt_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_steering_btm_rprt_t));
        len += (sizeof(em_tlv_t) + sizeof(em_steering_btm_rprt_t));
    }

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of steering_btm_rprt message\n");
    printf("\n============================================\n");
    printf("\nCreated steering_btm_rprt\n");

    em_util_info_print(EM_CONF,"%s:%d: test_steering_btm_rprt, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_client_steering_req(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_client_steering_req msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id =  em_msg_type_client_steering_req;
    unsigned char *tmp = (buff+len);

    if(i==0){
        //  Steering Request TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_steering_request;
        tlv->len = htons(sizeof(em_steering_req_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_steering_req_t));
        len += (sizeof(em_tlv_t) + sizeof(em_steering_req_t));
    }

    //Profile-2 Steering Request TLV

    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_profile2_steering_request;
    tlv->len = htons(sizeof(em_profile2_steering_req_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_profile2_steering_req_t));
    len += (sizeof(em_tlv_t) + sizeof(em_profile2_steering_req_t));


    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of client_steering_request message\n");
    printf("\n============================================\n");
    printf("\nCreated client_steering_request\n");

    em_util_info_print(EM_CONF,"%s:%d: test_client_steering_req, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_beacon_metrics_rsp(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_beacon_metrics_rsp msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_beacon_metrics_rsp;
    unsigned char *tmp = (buff+len);

    if(i==0){
        //  Beacon metrics response TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_bcon_metric_rsp;
        tlv->len = htons(sizeof(em_beacon_metrics_resp_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_beacon_metrics_resp_t));
        len += (sizeof(em_tlv_t) + sizeof(em_beacon_metrics_resp_t));
    }

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of beacon_metrics_rsp message\n");
    printf("\n============================================\n");
    printf("\nCreated beacon_metrics_rsp\n");

    em_util_info_print(EM_CONF,"%s:%d: test_beacon_metrics_rsp, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_beacon_metrics_query(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_beacon_metrics_query msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_beacon_metrics_query;
    unsigned char *tmp = (buff+len);

    if(i==0){
        //  Beacon metrics query TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_bcon_metric_query;
        tlv->len = htons(sizeof(em_beacon_metrics_query_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_beacon_metrics_query_t));
        len += (sizeof(em_tlv_t) + sizeof(em_beacon_metrics_query_t));
    }

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of beacon_metrics_query message\n");
    printf("\n============================================\n");
    printf("\nCreated beacon_metrics_query\n");

    em_util_info_print(EM_CONF,"%s:%d: test_beacon_metrics_query, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_unassoc_sta_link_metrics_query(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_unassoc_sta_link_metrics_query msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_unassoc_sta_link_metrics_query;
    unsigned char *tmp = (buff+len);

    if(i==0){
        // Unassociated STA Link Metrics Query TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_unassoc_sta_link_metric_query;
        tlv->len = htons(sizeof(em_unassoc_sta_link_metrics_query_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_unassoc_sta_link_metrics_query_t));
        len += (sizeof(em_tlv_t) + sizeof(em_unassoc_sta_link_metrics_query_t));
    }

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of unassoc_sta_link_metrics_query message\n");
    printf("\n============================================\n");
    printf("\nCreated unassoc_sta_link_metrics_query\n");

    em_util_info_print(EM_CONF,"%s:%d: test_unassoc_sta_link_metrics_query, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_unassoc_sta_link_metrics_rsp(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_unassoc_sta_link_metrics_rsp msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_unassoc_sta_link_metrics_rsp;
    unsigned char *tmp = (buff+len);

    if(i==0){
        // Unassociated STA Link Metrics Response TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_unassoc_sta_link_metric_rsp;
        tlv->len = htons(sizeof(em_unassoc_sta_link_metrics_rsp_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_unassoc_sta_link_metrics_rsp_t));
        len += (sizeof(em_tlv_t) + sizeof(em_unassoc_sta_link_metrics_rsp_t));
    }

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of unassoc_sta_link_metrics_response message\n");
    printf("\n============================================\n");
    printf("\nCreated unassoc_sta_link_metrics_rsp\n");

    em_util_info_print(EM_CONF,"%s:%d: test_unassoc_sta_link_metrics_rsp, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_sta_link_metrics_query(unsigned char *buff,int i,unsigned int len)
{
    em_util_info_print(EM_CONF,"%s:%d: entered test_sta_link_metrics_query msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_assoc_sta_link_metrics_query;
    unsigned char *tmp = (buff+len);

    if(i==0){
        // STA MAC Address type TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type =  em_tlv_type_sta_mac_addr;
        tlv->len = htons(sizeof(em_assoc_sta_mac_addr_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_assoc_sta_mac_addr_t));
        len += (sizeof(em_tlv_t) + sizeof(em_assoc_sta_mac_addr_t));
    }

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of assoc_sta_link_metrics_query message\n");
    printf("\n============================================\n");
    printf("\nCreated sta_link_metrics_query\n");

    em_util_info_print(EM_CONF,"%s:%d: test_sta_link_metrics_query, len = %d\n", __func__, __LINE__,len);

    return len;

}


int em_testValidation_t::test_sta_link_metrics_rsp(unsigned char *buff,int i,unsigned int len)
{
    em_util_info_print(EM_CONF,"%s:%d: entered test_sta_link_metrics_rsp msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_assoc_sta_link_metrics_rsp;
    unsigned char *tmp = (buff+len);

    if(i==0){
        // Associated STA Link Metrics TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_assoc_sta_link_metric;
        tlv->len = htons(sizeof(em_assoc_sta_link_metrics_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_assoc_sta_link_metrics_t));
        len += (sizeof(em_tlv_t) + sizeof(em_assoc_sta_link_metrics_t));
    }

    //  Error Code TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_error_code;
    tlv->len = htons(sizeof(em_error_code_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_error_code_t));
    len += (sizeof(em_tlv_t) + sizeof(em_error_code_t));

    //Associated STA Extended Link Metrics TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_assoc_sta_ext_link_metric;
    tlv->len = htons(sizeof(em_assoc_sta_ext_link_metrics_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_assoc_sta_ext_link_metrics_t));
    len += (sizeof(em_tlv_t) + sizeof(em_assoc_sta_ext_link_metrics_t));

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of assoc_sta_link_metrics_response message\n");
    printf("\n============================================\n");
    printf("\nCreated sta_link_metrics_rsp\n");

    em_util_info_print(EM_CONF,"%s:%d: test_sta_link_metrics_rsp, len = %d\n", __func__, __LINE__,len);

    return len;

}


int em_testValidation_t::test_ap_metrics_query(unsigned char *buff,int i,unsigned int len)
{
    em_util_info_print(EM_CONF,"%s:%d: entered test_ap_metrics_query msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_ap_metrics_query;
    unsigned char *tmp = (buff+len);

    if(i==0){
        // AP Metric Query TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type =  em_tlv_type_ap_metrics_query;
        tlv->len = htons(sizeof(em_ap_metrics_query_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_ap_metrics_query_t));
        len += (sizeof(em_tlv_t) + sizeof(em_ap_metrics_query_t));
    }

    //AP Radio Identifier TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type =  em_tlv_type_radio_id;
    tlv->len = htons(sizeof(em_ap_radio_id_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_ap_radio_id_t));
    len += (sizeof(em_tlv_t) + sizeof(em_ap_radio_id_t));

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of ap_metrics_query message\n");
    printf("\n============================================\n");
    printf("\nCreated ap_metrics_query\n");

    em_util_info_print(EM_CONF,"%s:%d: test_ap_metrics_query, len = %d\n", __func__, __LINE__,len);

    return len;

}


int em_testValidation_t::test_ap_metrics_rsp(unsigned char *buff,int i,unsigned int len)
{
    em_util_info_print(EM_CONF,"%s:%d: entered test_ap_metrics_rsp msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_ap_metrics_rsp;
    unsigned char *tmp = (buff+len);

    if(i==0){
        // AP Metric TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_ap_metrics;
        tlv->len = htons(sizeof(em_ap_metric_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_ap_metric_t));
        len += (sizeof(em_tlv_t) + sizeof(em_ap_metric_t));
    }

    //AP Extended Metrics TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_ap_ext_metric;
    tlv->len = htons(sizeof(em_ap_ext_metric_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_ap_ext_metric_t));
    len += (sizeof(em_tlv_t) + sizeof(em_ap_ext_metric_t));

    //Radio Metrics TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_radio_metric;
    tlv->len = htons(sizeof(em_radio_metric_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_radio_metric_t));
    len += (sizeof(em_tlv_t) + sizeof(em_radio_metric_t));

    //Associated STA Traffic Stats TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_assoc_sta_traffic_sts;
    tlv->len = htons(sizeof(em_assoc_sta_traffic_sts_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_assoc_sta_traffic_sts_t));
    len += (sizeof(em_tlv_t) + sizeof(em_assoc_sta_traffic_sts_t));

    // Associated STA Link Metrics TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_assoc_sta_link_metric;
    tlv->len = htons(sizeof(em_assoc_sta_link_metrics_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_assoc_sta_link_metrics_t));
    len += (sizeof(em_tlv_t) + sizeof(em_assoc_sta_link_metrics_t));

    //Associated STA Extended Link Metrics TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_assoc_sta_ext_link_metric;
    tlv->len = htons(sizeof(em_assoc_sta_ext_link_metrics_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_assoc_sta_ext_link_metrics_t));
    len += (sizeof(em_tlv_t) + sizeof(em_assoc_sta_ext_link_metrics_t));

    //Associated Wi-Fi 6 STA Status Report TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type =  em_tlv_type_assoc_wifi6_sta_rprt;
    tlv->len = htons(sizeof(em_assoc_wifi6_sta_sts_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_assoc_wifi6_sta_sts_t));
    len += (sizeof(em_tlv_t) + sizeof(em_assoc_wifi6_sta_sts_t));


    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of ap_metrics_response message\n");
    printf("\n============================================\n");
    printf("\nCreated ap_metrics_rsp\n");

    em_util_info_print(EM_CONF,"%s:%d: test_ap_metrics_rsp, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_client_cap_query(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_client_cap_query msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_client_cap_query;
    unsigned char *tmp = (buff+len);

    if(i==0){
        // Client Info TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_client_info;
        tlv->len = htons(sizeof(em_client_info_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_client_info_t));
        len += (sizeof(em_tlv_t) + sizeof(em_client_info_t));
    }

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of client_cap_query message\n");
    printf("\n============================================\n");
    printf("\nCreated client_cap_query\n");

    em_util_info_print(EM_CONF,"%s:%d: test_client_cap_query, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_client_cap_rprt(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_client_cap_rprt msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_client_cap_rprt;
    unsigned char *tmp = (buff+len);

    if(i==0){
        // Client Info TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_client_info;
        tlv->len = htons(sizeof(em_client_info_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_client_info_t));
        len += (sizeof(em_tlv_t) + sizeof(em_client_info_t));
    }

    //Client Capability Report TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_client_cap_report;
    tlv->len = htons(sizeof(em_client_cap_rprt_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_client_cap_rprt_t));
    len += (sizeof(em_tlv_t) + sizeof(em_client_cap_rprt_t));

    // Error Code TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_error_code;
    tlv->len = htons(sizeof(em_error_code_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_error_code_t));
    len += (sizeof(em_tlv_t) + sizeof(em_error_code_t));

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of client_cap_rprt message\n");
    printf("\n============================================\n");
    printf("\nCreated client_cap_rprt\n");

    em_util_info_print(EM_CONF,"%s:%d: test_client_cap_rprt, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_op_channel_rprt(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_op_channel_rprt msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_op_channel_rprt;
    unsigned char *tmp = (buff+len);

    if(i==0){
        //Operating Channel Report TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type =  em_tlv_type_op_channel;
        tlv->len = htons(sizeof(em_op_channel_rprt_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_op_channel_rprt_t));
        len += (sizeof(em_tlv_t) + sizeof(em_op_channel_rprt_t));
    }

    //Spatial Reuse Report TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_spatial_reuse_rep;
    tlv->len = htons(sizeof(em_spatial_reuse_rprt_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_spatial_reuse_rprt_t));
    len += (sizeof(em_tlv_t) + sizeof(em_spatial_reuse_rprt_t));

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of op_channel_rprt message\n");
    printf("\n============================================\n");
    printf("\nCreated op_channel_rprt\n");

    em_util_info_print(EM_CONF,"%s:%d: test_op_channel_rprt, len = %d\n", __func__, __LINE__,len);

    return len;

}



int em_testValidation_t::test_channel_sel_rsp(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_channel_sel_rsp msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_channel_sel_rsp;
    unsigned char *tmp = (buff+len);

    if(i==0){
        //Channel Selection Response TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_channel_sel_resp;
        tlv->len = htons(sizeof(em_channel_sel_rsp_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_channel_sel_rsp_t));
        len += (sizeof(em_tlv_t) + sizeof(em_channel_sel_rsp_t));
    }

    //Spatial Reuse Config Response TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type =  em_tlv_type_spatial_reuse_cfg_rsp;
    tlv->len = htons(sizeof(em_spatial_reuse_cfg_rsp_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_spatial_reuse_cfg_rsp_t));
    len += (sizeof(em_tlv_t) + sizeof(em_spatial_reuse_cfg_rsp_t));

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of channel_sel_rsp message\n");
    printf("\n============================================\n");
    printf("\nCreated channel_sel_rsp\n");

    em_util_info_print(EM_CONF,"%s:%d: test_channel_sel_rsp, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_channel_sel_req(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_channel_sel_req msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_channel_sel_req;
    unsigned char *tmp = (buff+len);

    if(i==0){
        //Channel Preference TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_channel_pref;
        tlv->len = htons(sizeof(em_channel_pref_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_channel_pref_t));
        len += (sizeof(em_tlv_t) + sizeof(em_channel_pref_t));
    }

    //Transmit Power Limit TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_tx_power;
    tlv->len = htons(sizeof(em_tx_power_limit_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_tx_power_limit_t));
    len += (sizeof(em_tlv_t) + sizeof(em_tx_power_limit_t));

    //Spatial Reuse Request TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_spatial_reuse_req;
    tlv->len = htons(sizeof(em_spatial_reuse_req_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_spatial_reuse_req_t));
    len += (sizeof(em_tlv_t) + sizeof(em_spatial_reuse_req_t));

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of channel_sel_req message\n");
    printf("\n============================================\n");
    printf("\nCreated channel_sel_req\n");

    em_util_info_print(EM_CONF,"%s:%d: test_channel_sel_req, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_channel_pref_query(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_channel_pref_query msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_channel_pref_query;
    unsigned char *tmp = (buff+len);

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of channel_pref_query message\n");
    printf("\n============================================\n");
    printf("\nCreated channel_pref_query\n");

    em_util_info_print(EM_CONF,"%s:%d: test_channel_pref_query, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_channel_pref_rprt(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_channel_pref_rprt msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_channel_pref_rprt;
    unsigned char *tmp = (buff+len);


    //Channel Preference TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_channel_pref;
    tlv->len = htons(sizeof(em_channel_pref_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_channel_pref_t));
    len += (sizeof(em_tlv_t) + sizeof(em_channel_pref_t));

    em_util_info_print(EM_CONF,"%s:%d: created channel pref tlv\n", __func__, __LINE__);

    //Radio Operation Restriction TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type =   em_tlv_type_radio_op_restriction;
    int sz = htons(sizeof(em_radio_op_restriction_t));
    tlv->len = sz;
    tmp += (sizeof(em_tlv_t) + sizeof(em_radio_op_restriction_t));
    len += (sizeof(em_tlv_t) + sizeof(em_radio_op_restriction_t));
    em_util_info_print(EM_CONF,"%s:%d: created  Radio Operation Restriction tlv\n", __func__, __LINE__);

    //CAC Completion Report TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_cac_cmpltn_rprt;
    tlv->len = htons(sizeof(em_cac_comp_rprt_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_cac_comp_rprt_t));
    len += (sizeof(em_tlv_t) + sizeof(em_cac_comp_rprt_t));
    em_util_info_print(EM_CONF,"%s:%d: created CAC Completion report tlv\n", __func__, __LINE__);

    //CAC Status Report TLV
    if (i==0){
        tlv = (em_tlv_t *)tmp;
        tlv->type =  em_tlv_type_cac_sts_rprt;
        tlv->len = htons(sizeof(em_cac_status_rprt_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_cac_status_rprt_t));
        len += (sizeof(em_tlv_t) + sizeof(em_cac_status_rprt_t));
    }
    em_util_info_print(EM_CONF,"%s:%d: created CAC status report tlv\n", __func__, __LINE__);

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of channel_pref_rprt message\n");
    printf("\n============================================\n");
    printf("\nCreated channel_pref_rprt\n");

    em_util_info_print(EM_CONF,"%s:%d: test_channel_pref_rprt, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_topo_notif(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered topology notification msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_topo_notif;

    unsigned char *tmp = (buff+len);

    // AL MAC Address type TLV
    if (i==0){
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_al_mac_address;
        tlv->len = htons(sizeof(mac_address_t));

        tmp += (sizeof (em_tlv_t) + sizeof(mac_address_t));
        len += (sizeof (em_tlv_t) + sizeof(mac_address_t));
    }

    //Client Association Event TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_client_assoc_event;
    tlv->len = htons(sizeof(em_tlv_client_assoc));

    tmp += (sizeof (em_tlv_t) + sizeof(em_tlv_client_assoc));
    len += (sizeof (em_tlv_t) + sizeof(em_tlv_client_assoc));

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of topology notification message\n");
    printf("\n============================================\n");
    printf("\nCreated topology notification\n");

    em_util_info_print(EM_CONF,"%s:%d: topology notification, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_topo_resp(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered topology response msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_topo_notif;

    unsigned char *tmp = (buff+len);

    // device information type TLV
    if (i==0){
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_device_info;
        tlv->len = htons(sizeof(em_device_info_topo_resp_t));

        tmp += (sizeof (em_tlv_t) + sizeof(em_device_info_topo_resp_t));
        len += (sizeof (em_tlv_t) + sizeof(em_device_info_topo_resp_t));
    }

    //Device bridging capability TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_device_bridging_cap;
    tlv->len = htons(sizeof(em_device_bridge_cap_t));

    tmp += (sizeof (em_tlv_t) + sizeof(em_device_bridge_cap_t));
    len += (sizeof (em_tlv_t) + sizeof(em_device_bridge_cap_t));

    //Non-1905 neighbor device list TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_non1905_neigh_list;
    tlv->len = htons(sizeof(em_non_1905_neigh_device_list_t));

    tmp += (sizeof (em_tlv_t) + sizeof(em_non_1905_neigh_device_list_t));
    len += (sizeof (em_tlv_t) + sizeof(em_non_1905_neigh_device_list_t));

    //1905 neighbor device TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_1905_neigh_list;
    tlv->len = htons(sizeof(em_neigh_device_list_t));

    tmp += (sizeof (em_tlv_t) + sizeof(em_neigh_device_list_t));
    len += (sizeof (em_tlv_t) + sizeof(em_neigh_device_list_t));

    //SupportedService TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_supported_service;
    tlv->len = htons(sizeof(em_supported_service_t));

    tmp += (sizeof (em_tlv_t) + sizeof(em_supported_service_t));
    len += (sizeof (em_tlv_t) + sizeof(em_supported_service_t));

    //AP Operational BSS TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_operational_bss;
    tlv->len = htons(sizeof(em_ap_op_bss_t));

    tmp += (sizeof (em_tlv_t) + sizeof(em_ap_op_bss_t));
    len += (sizeof (em_tlv_t) + sizeof(em_ap_op_bss_t));


    //Associated Clients TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_associated_clients ;
    tlv->len = htons(sizeof(em_assoc_clients_t));

    tmp += (sizeof (em_tlv_t) + sizeof(em_assoc_clients_t));
    len += (sizeof (em_tlv_t) + sizeof(em_assoc_clients_t));

    // One multiAP profile tlv 
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_profile;
    tlv->len = htons(sizeof(em_enum_type_t));
    profile = em_profile_type_3;
    //memcpy(tlv->value, &profile, sizeof(em_enum_type_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_enum_type_t));
    len += (sizeof(em_tlv_t) + sizeof(em_enum_type_t));

    // BSS Configuration Report TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_bss_conf_rep;
    tlv->len = htons(sizeof(em_bss_config_rprt_t));
    // memcpy(&tlv->value[1], &service_type, sizeof(em_enum_type_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_bss_config_rprt_t));
    len += (sizeof(em_tlv_t) + sizeof(em_bss_config_rprt_t));


    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of topology response message\n");
    printf("\n============================================\n");
    printf("\nCreated topology response\n");

    em_util_info_print(EM_CONF,"%s:%d: topology response, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_reconfig_trigger(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_reconfig_trigger msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_reconfig_trigger;
    unsigned char *tmp = (buff+len);

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of reconfig_trigger message\n");
    printf("\n============================================\n");
    printf("\nCreated reconfig_trigger\n");

    em_util_info_print(EM_CONF,"%s:%d: test_reconfig_trigger, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_bh_sta_cap_query(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_bh_sta_cap_query msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_bh_sta_cap_query;
    unsigned char *tmp = (buff+len);

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of bh_sta_cap_query message\n");
    printf("\n============================================\n");
    printf("\nCreated bh_sta_cap_query\n");

    em_util_info_print(EM_CONF,"%s:%d: test_bh_sta_cap_query, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_i1905_rekey_req(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_i1905_rekey_req msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_1905_rekey_req;
    unsigned char *tmp = (buff+len);

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of test_i1905_rekey_req message\n");
    printf("\n============================================\n");
    printf("\nCreated 1905_rekey_req\n");

    em_util_info_print(EM_CONF,"%s:%d: test_i1905_rekey_req, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_steering_complete(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_steering_complete msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_steering_complete;
    unsigned char *tmp = (buff+len);

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of test_steering_complete message\n");
    printf("\n============================================\n");
    printf("\nCreated steering_complete\n");

    em_util_info_print(EM_CONF,"%s:%d: test_steering_complete, len = %d\n", __func__, __LINE__,len);

    return len;
}

int em_testValidation_t::test_ap_cap_query(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_ap_cap_query msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_ap_cap_query;
    unsigned char *tmp = (buff+len);

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of test_ap_cap_query message\n");
    printf("\n============================================\n");
    printf("\nCreated ap_cap_query\n");

    em_util_info_print(EM_CONF,"%s:%d: test_ap_cap_query, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_failed_conn(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_failed_conn msg creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_failed_conn;
    unsigned char *tmp = (buff+len);

    //BSSID TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_bssid ;
    tlv->len = htons(sizeof(em_bssid_t));

    tmp += (sizeof (em_tlv_t) + sizeof(em_bssid_t));
    len += (sizeof (em_tlv_t) + sizeof(em_bssid_t));

    //STA MAC Address Type TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type =  em_tlv_type_sta_mac_addr;
    tlv->len = htons(sizeof(em_assoc_sta_mac_addr_t));

    tmp += (sizeof (em_tlv_t) + sizeof(em_assoc_sta_mac_addr_t));
    len += (sizeof (em_tlv_t) + sizeof(em_assoc_sta_mac_addr_t));

    //Status Code TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type =  em_tlv_type_status_code;
    tlv->len = htons(sizeof(em_status_code_t));

    tmp += (sizeof (em_tlv_t) + sizeof(em_status_code_t));
    len += (sizeof (em_tlv_t) + sizeof(em_status_code_t));

    //Reason Code TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_reason_code;
    tlv->len = htons(sizeof(em_reason_code_t));

    tmp += (sizeof (em_tlv_t) + sizeof(em_reason_code_t));
    len += (sizeof (em_tlv_t) + sizeof(em_reason_code_t));

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of test_failed_conn message\n");
    printf("\n============================================\n");
    printf("\nCreated failed connection\n");

    em_util_info_print(EM_CONF,"%s:%d: test_failed_conn, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_bss_config_rsp(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_bss_config_rsp creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_unassoc_sta_link_metrics_rsp;
    unsigned char *tmp = (buff+len);

    if (i==0){
        //BSS Configuration Response TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_bss_conf_rsp;
        tlv->len = htons(sizeof(em_bss_conf_rsp_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_bss_conf_rsp_t));
        len += (sizeof(em_tlv_t) + sizeof(em_bss_conf_rsp_t));
    }

    //Default 802.1Q Settings TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type =  em_tlv_type_dflt_8021q_settings;
    tlv->len = htons(sizeof(em_8021q_settings_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_8021q_settings_t));
    len += (sizeof(em_tlv_t) + sizeof(em_8021q_settings_t));

    //Traffic Separation Policy TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_traffic_separation_policy;
    tlv->len = htons(sizeof(em_traffic_sep_policy_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_traffic_sep_policy_t));
    len += (sizeof(em_tlv_t) + sizeof(em_traffic_sep_policy_t));

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of test_bss_config_rsp message\n");
    printf("\n============================================\n");
    printf("\nCreated bss_config_rsp\n");

    em_util_info_print(EM_CONF,"%s:%d: test_bss_config_rsp, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_bss_config_req(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_bss_config_req creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_unassoc_sta_link_metrics_rsp;
    unsigned char *tmp = (buff+len);

    if (i==0){
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_profile;
        tlv->len = htons(sizeof(em_enum_type_t));
        profile = em_profile_type_3;
        //memcpy(tlv->value, &profile, sizeof(em_enum_type_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_enum_type_t));
        len += (sizeof(em_tlv_t) + sizeof(em_enum_type_t));
    }

    // supported service tlv 17.2.1
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_supported_service;
    tlv->len = htons(sizeof(em_supported_service_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_supported_service_t));
    len += (sizeof(em_tlv_t) + sizeof(em_supported_service_t));

    //AKM Suite Capabilities TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_akm_suite;
    tlv->len = htons(sizeof(em_akm_suite_info_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_akm_suite_info_t));
    len += (sizeof(em_tlv_t) + sizeof(em_akm_suite_info_t));

    //AP Radio Basic Capabilities TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_ap_radio_basic_cap;
    tlv->len = htons(sizeof(em_ap_radio_basic_cap_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_ap_radio_basic_cap_t));
    len += (sizeof(em_tlv_t) + sizeof(em_ap_radio_basic_cap_t));

    //Backhaul STA Radio Capabilities TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_bh_sta_radio_cap;
    tlv->len = htons(sizeof(em_bh_sta_radio_cap_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_bh_sta_radio_cap_t));
    len += (sizeof(em_tlv_t) + sizeof(em_bh_sta_radio_cap_t));

    //Profile-2 AP Capability TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_profile_2_ap_cap;
    tlv->len = htons(sizeof(em_profile_2_ap_cap_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_profile_2_ap_cap_t));
    len += (sizeof(em_tlv_t) + sizeof(em_profile_2_ap_cap_t));

    //AP Radio Advanced Capabilities TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_ap_radio_advanced_cap;
    tlv->len = htons(sizeof(em_ap_radio_advanced_cap_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_ap_radio_advanced_cap_t));
    len += (sizeof(em_tlv_t) + sizeof(em_ap_radio_advanced_cap_t));

    // BSS Configuration Request TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_bss_conf_req;
    tlv->len = htons(sizeof(em_bss_conf_req_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_bss_conf_req_t));
    len += (sizeof(em_tlv_t) + sizeof(em_bss_conf_req_t));


    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of test_bss_config_req message\n");
    printf("\n============================================\n");
    printf("\nCreated bss_config_req\n");

    em_util_info_print(EM_CONF,"%s:%d: test_bss_config_req, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_svc_prio_req(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_svc_prio_req creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_svc_prio_req;
    unsigned char *tmp = (buff+len);

    //Service Prioritization Rule TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_svc_prio_rule;
    tlv->len = htons(sizeof(em_service_prio_rule_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_service_prio_rule_t));
    len += (sizeof(em_tlv_t) + sizeof(em_service_prio_rule_t));

    //DSCP Mapping Table TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type =  em_tlv_type_dscp_map_tbl;
    tlv->len = htons(sizeof(em_dscp_map_table_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_dscp_map_table_t));
    len += (sizeof(em_tlv_t) + sizeof(em_dscp_map_table_t));

    //QoS Management Descriptor TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_qos_mgmt_desc;
    tlv->len = htons(sizeof(em_qos_mgmt_des_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_qos_mgmt_des_t));
    len += (sizeof(em_tlv_t) + sizeof(em_qos_mgmt_des_t));

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of test_svc_prio_req message\n");
    printf("\n============================================\n");
    printf("\nCreated svc_prio_req\n");

    em_util_info_print(EM_CONF,"%s:%d: test_svc_prio_req, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_client_disassoc_stats(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_client_disassoc_stats creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_client_disassoc_stats;
    unsigned char *tmp = (buff+len);

    if (i==0){
        //STA MAC Address TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_sta_mac_addr;
        tlv->len = htons(sizeof(em_assoc_sta_mac_addr_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_assoc_sta_mac_addr_t));
        len += (sizeof(em_tlv_t) + sizeof(em_assoc_sta_mac_addr_t));
    }

    //Reason Code TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_reason_code;
    tlv->len = htons(sizeof(em_reason_code_t));

    tmp += (sizeof (em_tlv_t) + sizeof(em_reason_code_t));
    len += (sizeof (em_tlv_t) + sizeof(em_reason_code_t));

    //Associated STA Traffic Stats TLV
    tlv->type = em_tlv_type_assoc_sta_traffic_sts;
    tlv->len = htons(sizeof(em_assoc_sta_traffic_stats_t));

    tmp += (sizeof (em_tlv_t) + sizeof(em_assoc_sta_traffic_stats_t));
    len += (sizeof (em_tlv_t) + sizeof(em_assoc_sta_traffic_stats_t));

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of test_client_disassoc_stats message\n");
    printf("\n============================================\n");
    printf("\nCreated client_disassoc_stats\n");

    em_util_info_print(EM_CONF,"%s:%d: test_client_disassoc_stats, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_tunneled(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_tunneled creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_tunneled;
    unsigned char *tmp = (buff+len);

    if (i==0){
        //Source Info TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_src_info;
        tlv->len = htons(sizeof(em_source_info_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_source_info_t));
        len += (sizeof(em_tlv_t) + sizeof(em_source_info_t));
    }

    //Tunneled message type TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_tunneled_msg_type;
    tlv->len = htons(sizeof(em_tunneled_msg_type_t));

    tmp += (sizeof (em_tlv_t) + sizeof(em_tunneled_msg_type_t));
    len += (sizeof (em_tlv_t) + sizeof(em_tunneled_msg_type_t));

    //Tunneled TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_tunneled;
    tlv->len = htons(sizeof(em_tunneled_t));

    tmp += (sizeof (em_tlv_t) + sizeof(em_tunneled_t));
    len += (sizeof (em_tlv_t) + sizeof(em_tunneled_t));

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of test_tunneled message\n");
    printf("\n============================================\n");
    printf("\nCreated tunneled message\n");

    em_util_info_print(EM_CONF,"%s:%d: test_tunneled, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_topo_disc(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_topo_disc creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_topo_disc;
    unsigned char *tmp = (buff+len);

    if (i==0){
        // AL MAC Address type TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_al_mac_address;
        tlv->len = htons(sizeof(mac_address_t));
        //memcpy(tlv->value,(unsigned char *)get_mac(), sizeof(mac_address_t));

        tmp += (sizeof (em_tlv_t) + sizeof(mac_address_t));
        len += (sizeof (em_tlv_t) + sizeof(mac_address_t));
    }

    //MAC address type TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_mac_address;
    tlv->len = htons(sizeof(em_1905_mac_addr_t));

    tmp += (sizeof (em_tlv_t) + sizeof(em_1905_mac_addr_t));
    len += (sizeof (em_tlv_t) + sizeof(em_1905_mac_addr_t));

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of test_topo_disc message\n");
    printf("\n============================================\n");
    printf("\nCreated topology discovery\n");

    em_util_info_print(EM_CONF,"%s:%d: test_topo_disc, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_topo_vendor(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_topo_vendor creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_topo_vendor;
    unsigned char *tmp = (buff+len);

    if (i==0){
        // Vendor specific TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_vendor_specific ;
        tlv->len = htons(sizeof(em_vendor_specific_t));

        tmp += (sizeof (em_tlv_t) + sizeof(em_vendor_specific_t));
        len += (sizeof (em_tlv_t) + sizeof(em_vendor_specific_t));
    }

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of test_topo_vendor message\n");
    printf("\n============================================\n");
    printf("\nCreated topology vendor\n");

    em_util_info_print(EM_CONF,"%s:%d: test_topo_vendor, len = %d\n", __func__, __LINE__,len);

    return len;

}


int em_testValidation_t::test_link_metric_query(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_link_metric_query creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_link_metric_query;
    unsigned char *tmp = (buff+len);

    if (i==0){
        //Link metric query TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_link_metric;
        tlv->len = htons(sizeof(em_link_metric_query_t));

        tmp += (sizeof (em_tlv_t) + sizeof(em_link_metric_query_t));
        len += (sizeof (em_tlv_t) + sizeof(em_link_metric_query_t));
    }

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of test_link_metric_query message\n");
    printf("\n============================================\n");
    printf("\nCreated link_metric_query\n");

    em_util_info_print(EM_CONF,"%s:%d: test_link_metric_query, len = %d\n", __func__, __LINE__,len);

    return len;

}


int em_testValidation_t::test_link_metric_resp(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_link_metric_resp creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_link_metric_resp;
    unsigned char *tmp = (buff+len);

    if (i==0){
        //1905.1 transmitter link metric TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_transmitter_link_metric;
        tlv->len = htons(sizeof(em_tx_link_metric_t));

        tmp += (sizeof (em_tlv_t) + sizeof(em_tx_link_metric_t));
        len += (sizeof (em_tlv_t) + sizeof(em_tx_link_metric_t));
    }

    //1905.1 receiver link metric TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_receiver_link_metric;
    tlv->len = htons(sizeof(em_rx_link_metric_t));

    tmp += (sizeof (em_tlv_t) + sizeof(em_rx_link_metric_t));
    len += (sizeof (em_tlv_t) + sizeof(em_rx_link_metric_t));

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of test_link_metric_resp message\n");
    printf("\n============================================\n");
    printf("\nCreated link_metric_resp\n");

    em_util_info_print(EM_CONF,"%s:%d: test_link_metric_resp, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_autoconfig_renew(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_autoconfig_renew creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_autoconf_renew;
    unsigned char *tmp = (buff+len);

    if (i==0){
        // AL MAC Address type TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_al_mac_address;
        tlv->len = htons(sizeof(mac_address_t));
        //memcpy(tlv->value,(unsigned char *)get_mac(), sizeof(mac_address_t));

        tmp += (sizeof (em_tlv_t) + sizeof(mac_address_t));
        len += (sizeof (em_tlv_t) + sizeof(mac_address_t));
    }

    //SupportedRole TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_supported_role;
    tlv->len = htons(sizeof(unsigned char));

    tmp += (sizeof (em_tlv_t) + 1);
    len += (sizeof (em_tlv_t) + 1);

    //SupportedFreqBand TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_supported_freq_band;
    tlv->len = htons(sizeof(unsigned char));

    tmp += (sizeof (em_tlv_t) + 1);
    len += (sizeof (em_tlv_t) + 1);

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of test_autoconfig_renew message\n");
    printf("\n============================================\n");
    printf("\nCreated test_autoconfig_renew\n");

    em_util_info_print(EM_CONF,"%s:%d: test_autoconfig_renew, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_ap_cap_rprt(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_ap_cap_rprt creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_ap_cap_rprt;
    unsigned char *tmp = (buff+len);

    if (i==0){
        // AP Capability TLV 
        tlv = (em_tlv_t *)tmp;
        tlv->type =  em_tlv_type_ap_cap;
        tlv->len = htons(sizeof(em_ap_capability_t));

        tmp += (sizeof (em_tlv_t) + sizeof(em_ap_capability_t));
        len += (sizeof (em_tlv_t) + sizeof(em_ap_capability_t));
    }

    //AP Radio Basic Capabilities TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_ap_radio_basic_cap;
    tlv->len = htons(sizeof(em_ap_radio_basic_cap_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_ap_radio_basic_cap_t));
    len += (sizeof(em_tlv_t) + sizeof(em_ap_radio_basic_cap_t));

    //AP Radio Advanced Capabilities TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_ap_radio_advanced_cap;
    tlv->len = htons(sizeof(em_ap_radio_advanced_cap_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_ap_radio_advanced_cap_t));
    len += (sizeof(em_tlv_t) + sizeof(em_ap_radio_advanced_cap_t));

    //Device Inventory TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_device_inventory;
    tlv->len = htons(sizeof(em_device_inventory_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_device_inventory_t));
    len += (sizeof(em_tlv_t) + sizeof(em_device_inventory_t));

    //Profile-2 AP Capability TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_profile_2_ap_cap;
    tlv->len = htons(sizeof(em_profile_2_ap_cap_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_profile_2_ap_cap_t));
    len += (sizeof(em_tlv_t) + sizeof(em_profile_2_ap_cap_t));

    // 1905 layer security capability tlv 17.2.67
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_1905_layer_security_cap;
    tlv->len = htons(sizeo(em_ieee_1905_security_cap_t));
    //memcpy(tlv->value, get_1905_layer_security(), sizeof(em_1905_layer_security_cap_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_ieee_1905_security_cap_t));
    len += (sizeof(em_tlv_t) + sizeof(em_ieee_1905_security_cap_t));

    //AP HT Capabilities TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_ht_cap;
    tlv->len = htons(sizeof(em_ap_ht_cap_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_ap_ht_cap_t));
    len += (sizeof(em_tlv_t) + sizeof(em_ap_ht_cap_t));

    //AP VHT Capabilities TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_vht_cap;
    tlv->len = htons(sizeof(em_ap_vht_cap_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_ap_vht_cap_t));
    len += (sizeof(em_tlv_t) + sizeof(em_ap_vht_cap_t));

    //AP HE Capabilities TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_he_cap;
    tlv->len = htons(sizeof(em_ap_he_cap_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_ap_he_cap_t));
    len += (sizeof(em_tlv_t) + sizeof(em_ap_he_cap_t));

    //AP Wi-Fi 6 Capabilities TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_ap_wifi6_cap;
    tlv->len = htons(sizeof(em_ap_wifi6_cap_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_ap_wifi6_cap_t));
    len += (sizeof(em_tlv_t) + sizeof(em_ap_wifi6_cap_t));

    //Channel Scan Capabilities TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type =  em_tlv_type_channel_scan_cap;
    tlv->len = htons(sizeof(em_channel_scan_cap_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_channel_scan_cap_t));
    len += (sizeof(em_tlv_t) + sizeof(em_channel_scan_cap_t));

    //CAC Capabilities TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_cac_cap;
    tlv->len = htons(sizeof(em_cac_cap_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_cac_cap_t));
    len += (sizeof(em_tlv_t) + sizeof(em_cac_cap_t));

    //Metric Collection Interval TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_metric_cltn_interval;
    tlv->len = htons(sizeof(em_metric_cltn_interval_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_metric_cltn_interval_t));
    len += (sizeof(em_tlv_t) + sizeof(em_metric_cltn_interval_t));

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of test_ap_cap_rprt message\n");
    printf("\n============================================\n");
    printf("\nCreated test_ap_cap_rprt\n");

    em_util_info_print(EM_CONF,"%s:%d: test_ap_cap_rpt, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_policy_config_req(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_policy_config_req creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_map_policy_config_req;
    unsigned char *tmp = (buff+len);


    // Steering Policy TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_steering_policy;
    tlv->len = htons(sizeof(em_steering_policy_t));

    tmp += (sizeof (em_tlv_t) + sizeof(em_steering_policy_t));
    len += (sizeof (em_tlv_t) + sizeof(em_steering_policy_t));

    //Metric Reporting Policy TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_metric_reporting_policy;
    tlv->len = htons(sizeof(em_metric_rprt_policy_t));

    tmp += (sizeof (em_tlv_t) + sizeof(em_metric_rprt_policy_t));
    len += (sizeof (em_tlv_t) + sizeof(em_metric_rprt_policy_t));

    //Default 802.1Q Settings TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type =  em_tlv_type_dflt_8021q_settings;
    tlv->len = htons(sizeof(em_8021q_settings_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_8021q_settings_t));
    len += (sizeof(em_tlv_t) + sizeof(em_8021q_settings_t));

    //Traffic Separation Policy TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_traffic_separation_policy;
    tlv->len = htons(sizeof(em_traffic_sep_policy_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_traffic_sep_policy_t));
    len += (sizeof(em_tlv_t) + sizeof(em_traffic_sep_policy_t));

    //Channel Scan Reporting Policy TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_channel_scan_rprt_policy;
    tlv->len = htons(sizeof(em_channel_scan_rprt_policy_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_channel_scan_rprt_policy_t));
    len += (sizeof(em_tlv_t) + sizeof(em_channel_scan_rprt_policy_t));

    //Unsuccessful Association Policy TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_unsucc_assoc_policy;
    tlv->len = htons(sizeof(em_unsuccessful_assoc_policy_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_unsuccessful_assoc_policy_t));
    len += (sizeof(em_tlv_t) + sizeof(em_unsuccessful_assoc_policy_t));

    //Backhaul BSS Configuration TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_backhaul_bss_conf;
    tlv->len = htons(sizeof(em_bh_bss_config_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_bh_bss_config_t));
    len += (sizeof(em_tlv_t) + sizeof(em_bh_bss_config_t));

    //QoS Management Policy TLV
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_qos_mgmt_policy;
    tlv->len = htons(sizeof(em_qos_mgmt_policy_t));

    tmp += (sizeof(em_tlv_t) + sizeof(em_qos_mgmt_policy_t));
    len += (sizeof(em_tlv_t) + sizeof(em_qos_mgmt_policy_t));


    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of test_policy_config_req message\n");
    printf("\n============================================\n");
    printf("\nCreated policy_config_req\n");

    em_util_info_print(EM_CONF,"%s:%d: test_policy_config_req, len = %d\n", __func__, __LINE__,len);

    return len;

}

int em_testValidation_t::test_combined_infra_metrics(unsigned char *buff,int i,unsigned int len)
{

    em_util_info_print(EM_CONF,"%s:%d: entered test_combined_infra_metrics creation function\n", __func__, __LINE__);
    unsigned short  msg_id = em_msg_type_combined_infra_metrics;
    unsigned char *tmp = (buff+len);

    if(i==0){
        // AP Metric TLV
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_ap_metrics;
        tlv->len = htons(sizeof(em_ap_metric_t));

        tmp += (sizeof(em_tlv_t) + sizeof(em_ap_metric_t));
        len += (sizeof(em_tlv_t) + sizeof(em_ap_metric_t));
    }
    // Need modification for the following tlvs.
    //1905.1 transmitter link metric TLV  corresponding to the backhaul STA
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_transmitter_link_metric;
    tlv->len = htons(sizeof(em_tx_link_metric_t));

    tmp += (sizeof (em_tlv_t) + sizeof(em_tx_link_metric_t));
    len += (sizeof (em_tlv_t) + sizeof(em_tx_link_metric_t));

    //1905.1 transmitter link metric TLV   corresponding to the backhaul AP
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_transmitter_link_metric;
    tlv->len = htons(sizeof(em_tx_link_metric_t));

    tmp += (sizeof (em_tlv_t) + sizeof(em_tx_link_metric_t));
    len += (sizeof (em_tlv_t) + sizeof(em_tx_link_metric_t));

    //1905.1 receiver link metric TLV  corresponding to the backhaul STA
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_receiver_link_metric;
    tlv->len = htons(sizeof(em_rx_link_metric_t));

    tmp += (sizeof (em_tlv_t) + sizeof(em_rx_link_metric_t));
    len += (sizeof (em_tlv_t) + sizeof(em_rx_link_metric_t));

    //1905.1 receiver link metric TLV   corresponding to the backhaul AP
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_receiver_link_metric;
    tlv->len = htons(sizeof(em_rx_link_metric_t));

    tmp += (sizeof (em_tlv_t) + sizeof(em_rx_link_metric_t));
    len += (sizeof (em_tlv_t) + sizeof(em_rx_link_metric_t));

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    printf("\nTest validation of test_combined_infra_metrics message\n");
    printf("\n============================================\n");
    printf("\nCreated combined_infra_metrics\n");

    em_util_info_print(EM_CONF,"%s:%d: test_combined_infra_metrics, len = %d\n", __func__, __LINE__,len);

    return len;

}

int main(){

    unsigned char buff[MAX_EM_BUFF_SZ];
    unsigned int sz; 
    int i=0;
    unsigned int len=0;
    int user_type;
    int user_profile;
    em_msg_type_t type;
    em_profile_type_t profile;
    em_testValidation_t objheader(buff,len);

    em_util_info_print(EM_CONF,"%s:%d:buff inside main ,after header:%u\n", __func__, __LINE__,buff);
    //   printf("s buff inside main:%s\n",buff);
    printf("\nplease select the message to be validated:\n1.autoconf_search\n2.autoconf_resp\n3.autoconfig_wsc_m1\n4.autoconfig_wsc_m2\n5.topo_disc\n6.topo_notif\n7.topo_query\n8.topo_resp\n9.topo_vendor\n10.link_metric_query\n11.link_metric_resp\n12.autoconf_renew\n13.ap_cap_query\n14.ap_cap_rprt\n15.map_policy_config_req\n16.channel_pref_query\n17.channel_pref_rprt\n18.channel_sel_req\n19.channel_sel_rsp\n20.op_channel_rprt\n21.client_cap_query\n22.client_steering_req\n23.client_steering_btm_rprt\n24.client_assoc_ctrl_req\n25.steering_complete\n26.higher_layer_data\n27.bh_steering_req\n28.bh_steering_rsp\n29.client_cap_rprt\n30.ap_metrics_query\n31.ap_metrics_rsp\n32.assoc_sta_link_metrics_query\n33.assoc_sta_link_metrics_rsp\n34.unassoc_sta_link_metrics_query\n35.unassoc_sta_link_metrics_rsp\n36.beacon_metrics_query\n37.beacon_metrics_rsp\n38.combined_infra_metrics\n39.channel_scan_req\n40.qos_mgmt_notif\n41.anticipated_channel_usage_rprt\n42.anticipated_channel_pref\n43.agent_list\n44.failed_conn\n45.dpp_bootstrap_uri_notif\n46.1905_encap_eapol\n47.chirp_notif\n48.bss_config_res\n49.bss_config_rsp\n50.bss_config_req\n51.channel_scan_rprt\n52.dpp_cce_ind\n53.1905_rekey_req\n54.1905_decrypt_fail\n55.cac_term\n56.client_disassoc_stats\n57.svc_prio_req\n58.err_rsp\n59.assoc_status_notif\n60.tunneled\n61.bh_sta_cap_query\n62.bh_sta_cap_rprt\n63.proxied_encap_dpp\n64.direct_encap_dpp\n65.reconfig_trigger\n66.cac_req\n67.1905_ack\n");

    scanf("%d",&user_type);
    printf("please enter the profile type: em_profile_type_1:1\nem_profile_type_2:2\nem_profile_type_3:3\n");
    scanf("%d",&user_profile);
    printf("type 0 to validate success case\ntype 1 to validate failure case\n");
    scanf("%d",&i);
    em_util_info_print(EM_CONF,"%s:%d: entering switch case\n", __func__, __LINE__);

    switch (user_profile){

        case 1:
            profile = em_profile_type_1;
            break;

        case 2:
            profile = em_profile_type_2;
            break;

        case 3:
            profile = em_profile_type_3;
            break;
        default:
            printf("user entered invalid profile\n");
            break;
    }

    switch (user_type) {

        case 1:
            sz = objheader.test_autoconfig_search_msg(buff,i,len);
            type = em_msg_type_autoconf_search;
            break;

        case 2:
            sz = objheader.test_autoconfig_resp_msg(buff,i,len);
            type = em_msg_type_autoconf_resp;
            break;

            /*                case 3:
                              sz = objheader.test_autoconfig_wsc_m1(buff,i,len);
                              type = em_msg_type_autoconf_wsc; 
                              break;

                              case 4:
                              sz = objheader.test_autoconfig_wsc_m2(buff,i,len);
                              type = em_msg_type_autoconf_wsc;
                              break;
             */

        case 5:
            sz = objheader.test_topo_disc(buff,i,len);
            type = em_msg_type_topo_disc;
            break;

        case 6:
            sz = objheader.test_topo_notif(buff,i,len);
            type = em_msg_type_topo_notif;
            break;

        case 7:
            sz =  objheader.test_topo_query(buff,i,len);
            type = em_msg_type_topo_query;
            break;

        case 8:
            sz =  objheader.test_topo_resp(buff,i,len);
            type = em_msg_type_topo_resp;
            break;

        case 9:
            sz =  objheader.test_topo_vendor(buff,i,len);
            type = em_msg_type_topo_vendor;
            break;

        case 10:
            sz = objheader.test_link_metric_query(buff,i,len);
            type = em_msg_type_link_metric_query;
            break;

        case 11:
            sz =  objheader.test_link_metric_resp(buff,i,len);
            type = em_msg_type_link_metric_resp;
            break;

        case 12:
            sz =  objheader.test_autoconfig_renew(buff,i,len);
            type = em_msg_type_autoconf_renew;
            break;

        case 13:
            sz =  objheader.test_ap_cap_query(buff,i,len);
            type = em_msg_type_ap_cap_query;
            break;

        case 14:
            sz =  objheader.test_ap_cap_rprt(buff,i,len);
            type = em_msg_type_ap_cap_rprt;
            break;

        case 15:
            sz =  objheader.test_policy_config_req(buff,i,len);
            type = em_msg_type_map_policy_config_req;
            break;

        case 16:
            sz =  objheader.test_channel_pref_query(buff,i,len);
            type = em_msg_type_channel_pref_query;
            break;

        case 17:
            sz =  objheader.test_channel_pref_rprt(buff,i,len);
            type =  em_msg_type_channel_pref_rprt;
            break;

        case 18:
            sz =  objheader.test_channel_sel_req(buff,i,len);
            type = em_msg_type_channel_sel_req;
            break;

        case 19:
            sz =  objheader.test_channel_sel_rsp(buff,i,len);
            type = em_msg_type_channel_sel_rsp;
            break;

        case 20:
            sz =  objheader.test_op_channel_rprt(buff,i,len);
            type = em_msg_type_op_channel_rprt;
            break;

        case 21:
            sz =  objheader.test_client_cap_query(buff,i,len);
            type =  em_msg_type_client_cap_query;
            break;

        case 22:
            sz =  objheader.test_client_steering_req(buff,i,len);
            type = em_msg_type_client_steering_req;
            break;

        case 23:
            sz =  objheader.test_client_steering_btm_rprt(buff,i,len);
            type = em_msg_type_client_steering_btm_rprt;
            break;


        case 24:
            sz =  objheader.test_client_assoc_ctrl_req(buff,i,len);
            type = em_msg_type_client_assoc_ctrl_req;
            break;

        case 25:
            sz =  objheader.test_steering_complete(buff,i,len);
            type = em_msg_type_steering_complete;
            break;


        case 26:
            sz =  objheader.test_higher_layer_data(buff,i,len);
            type = em_msg_type_higher_layer_data;
            break;


        case 27:
            sz =  objheader.test_bh_steering_req(buff,i,len);
            type = em_msg_type_bh_steering_req;
            break;


        case 28:
            sz =  objheader.test_bh_steering_rsp(buff,i,len);
            type = em_msg_type_bh_steering_rsp;
            break;


        case 29:
            sz = objheader.test_client_cap_rprt(buff,i,len);
            type = em_msg_type_client_cap_rprt;
            break;

        case 30:
            sz =  objheader.test_ap_metrics_query(buff,i,len);
            type = em_msg_type_ap_metrics_query;
            break;

        case 31:
            sz =  objheader.test_ap_metrics_rsp(buff,i,len);
            type =  em_msg_type_ap_metrics_rsp;
            break;

        case 32:
            sz =  objheader.test_sta_link_metrics_query(buff,i,len);
            type = em_msg_type_assoc_sta_link_metrics_query;
            break;

        case 33:
            sz =  objheader.test_sta_link_metrics_rsp(buff,i,len);
            type = em_msg_type_assoc_sta_link_metrics_rsp;
            break;

        case 34:
            sz =  objheader.test_unassoc_sta_link_metrics_query(buff,i,len);
            type = em_msg_type_unassoc_sta_link_metrics_query;
            break;

        case 35:
            sz =  objheader.test_unassoc_sta_link_metrics_rsp(buff,i,len);
            type =  em_msg_type_unassoc_sta_link_metrics_rsp;
            break;

        case 36:
            sz =  objheader.test_beacon_metrics_query(buff,i,len);
            type = em_msg_type_beacon_metrics_query;
            break;

        case 37:
            sz =  objheader.test_beacon_metrics_rsp(buff,i,len);
            type = em_msg_type_beacon_metrics_rsp;
            break;

        case 38:
            sz =  objheader.test_combined_infra_metrics(buff,i,len);
            type = em_msg_type_combined_infra_metrics;
            break;


        case 39:
            sz =  objheader.test_channel_scan_req(buff,i,len);
            type = em_msg_type_channel_scan_req;
            break;


        case  40:
            sz =  objheader.test_qos_mgmt_notif(buff,i,len);
            type = em_msg_type_qos_mgmt_notif;
            break;

        case  41:
            sz =  objheader.test_anticipated_channel_usage_rprt(buff,i,len);
            type = em_msg_type_anticipated_channel_usage_rprt;
            break;

        case  42:
            sz =  objheader.test_anticipated_channel_pref(buff,i,len);
            type =  em_msg_type_anticipated_channel_pref;
            break;

        case 43:
            sz =  objheader.test_agent_list(buff,i,len);
            type =  em_msg_type_agent_list;
            break;

        case 44:
            sz =  objheader.test_failed_conn(buff,i,len);
            type = em_msg_type_failed_conn;
            break;

        case 45:
            sz =  objheader.test_dpp_bootstrap_uri_notif(buff,i,len);
            type =  em_msg_type_dpp_bootstrap_uri_notif;
            break;

        case 46:
            sz =  objheader.test_i1905_encap_eapol(buff,i,len);
            type = em_msg_type_1905_encap_eapol;
            break;

        case 47:
            sz =  objheader.test_chirp_notif(buff,i,len);
            type = em_msg_type_chirp_notif;
            break;

        case 48:
            sz =  objheader.test_bss_config_res(buff,i,len);
            type = em_msg_type_bss_config_res;
            break;


        case 49:
            sz =  objheader.test_bss_config_rsp(buff,i,len);
            type = em_msg_type_bss_config_rsp;
            break;

        case 50:
            sz =  objheader.test_bss_config_req(buff,i,len);
            type =  em_msg_type_bss_config_req;
            break;

        case 51:
            sz =  objheader.test_channel_scan_rprt(buff,i,len);
            type =  em_msg_type_channel_scan_rprt;
            break;

        case 52:
            sz =  objheader.test_dpp_cce_ind(buff,i,len);
            type = em_msg_type_dpp_cce_ind;
            break;

        case 53:
            sz =  objheader.test_i1905_rekey_req(buff,i,len);
            type = em_msg_type_1905_rekey_req;
            break;

        case 54:
            sz =  objheader.test_i1905_decrypt_fail(buff,i,len);
            type =  em_msg_type_1905_decrypt_fail;
            break;

        case 55:
            sz =  objheader.test_cac_term(buff,i,len);
            type = em_msg_type_cac_term;
            break;

        case 56:
            sz =  objheader.test_client_disassoc_stats(buff,i,len);
            type = em_msg_type_client_disassoc_stats;
            break;

        case 57:
            sz =  objheader.test_svc_prio_req(buff,i,len);
            type = em_msg_type_svc_prio_req;
            break;

        case 58:
            sz =  objheader.test_err_rsp(buff,i,len);
            type =  em_msg_type_err_rsp;
            break;

        case 59:
            sz =  objheader.test_assoc_status_notif(buff,i,len);
            type = em_msg_type_assoc_status_notif;
            break;

        case 60:
            sz =  objheader.test_tunneled(buff,i,len);
            type = em_msg_type_tunneled;
            break;

        case 61:
            sz =  objheader.test_bh_sta_cap_query(buff,i,len);
            type = em_msg_type_bh_sta_cap_query;
            break;

        case 62:
            sz =  objheader.test_bh_sta_cap_rprt(buff,i,len);
            type = em_msg_type_bh_sta_cap_rprt;
            break;

        case 63:
            sz =  objheader.test_proxied_encap_dpp(buff,i,len);
            type = em_msg_type_proxied_encap_dpp;
            break;

        case 64:
            sz =  objheader.test_direct_encap_dpp(buff,i,len);
            type = em_msg_type_direct_encap_dpp;
            break;

        case 65:
            sz =  objheader.test_reconfig_trigger(buff,i,len);
            type =  em_msg_type_reconfig_trigger;
            break;

        case 66:
            sz = objheader.test_cac_req(buff,i,len);
            type = em_msg_type_cac_req;
            break;

        case 67:
            sz = objheader.test_1905_ack(buff,i,len);
            type = em_msg_type_1905_ack;
            break;

        default:
            printf("user entered invalid message type\n");
            break;
    }

    em_util_info_print(EM_CONF,"%s:%d:calling test validation function ; type: %d;profile: %d; sz = %d; buff= %s\n", __func__, __LINE__,type,profile,sz,buff);


    objheader.test_validation(type,profile,buff,sz);
}

em_testValidation_t::~em_testValidation_t()
{
}


