#include "ec_configurator.h"
#include "em_crypto.h"
#include "ec_util.h"
#include "util.h"

ec_configurator_t::ec_configurator_t(const std::string &al_mac_addr, ec_ops_t& ops, ec_persistent_sec_ctx_t& sec_ctx, bool is_colocated_agent)
    : m_al_mac_addr(al_mac_addr), m_is_colocated_agent(is_colocated_agent),
    m_1905_encrypt_layer(al_mac_addr, ops.send_dir_encap_dpp, ops.send_1905_eapol_encap)
{
    m_send_chirp_notification    = ops.send_chirp;
    m_send_prox_encap_dpp_msg    = ops.send_encap_dpp;
    m_send_dir_encap_dpp_msg     = ops.send_dir_encap_dpp;
    m_send_action_frame          = ops.send_act_frame;
    m_get_backhaul_sta_info      = ops.get_backhaul_sta_info;
    m_get_1905_info              = ops.get_1905_info;
    m_get_fbss_info              = ops.get_fbss_info;
    m_can_onboard_additional_aps = ops.can_onboard_additional_aps;

    EM_ASSERT_NOT_NULL(sec_ctx.C_signing_key, , "C-signing key is NULL! Can not secure 1905 layer!");
    EM_ASSERT_NOT_NULL(sec_ctx.pp_key, , "PPK is NULL! Can not secure 1905 layer!");
    EM_ASSERT_NOT_NULL(sec_ctx.net_access_key, , "NAK is NULL! Can not secure 1905 layer!");
    EM_ASSERT_NOT_NULL(sec_ctx.connector, , "Connector is NULL! Can not secure 1905 layer!");

    m_sec_ctx = sec_ctx;
}

ec_configurator_t::~ec_configurator_t()
{

    for (auto& [_, c_ctx] : m_connections) {
        ec_crypto::free_connection_ctx(&c_ctx);
    }
    // Only write the persistent security context if this is a controller 
    // or an upgraded enrollee with it's own file system and own security keys.
    if (!m_is_colocated_agent) {
        if (!ec_util::write_persistent_sec_ctx("/nvram", m_sec_ctx)){
            em_printfout("Failed to write persistent security context to /nvram");
            em_printfout("All connectected agents will need to perform a full re-onboard on next controller boot (due to difference in C-signing key and PPK)!");
        }
    }
    ec_crypto::free_persistent_sec_ctx(&m_sec_ctx);
}
