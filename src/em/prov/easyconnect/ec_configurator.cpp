#include "ec_configurator.h"
#include "em_crypto.h"
#include "ec_util.h"
#include "util.h"

ec_configurator_t::ec_configurator_t(const std::string &mac_addr, ec_ops_t &ops)
    : m_mac_addr(mac_addr)
{
    m_send_chirp_notification    = ops.send_chirp;
    m_send_prox_encap_dpp_msg    = ops.send_encap_dpp;
    m_send_dir_encap_dpp_msg     = ops.send_dir_encap_dpp;
    m_send_action_frame          = ops.send_act_frame;
    m_get_backhaul_sta_info      = ops.get_backhaul_sta_info;
    m_get_1905_info              = ops.get_1905_info;
    m_get_fbss_info              = ops.get_fbss_info;
    m_can_onboard_additional_aps = ops.can_onboard_additional_aps;
}

ec_configurator_t::~ec_configurator_t()
{

    for (auto& [_, c_ctx] : m_connections) {
        ec_crypto::free_connection_ctx(&c_ctx);
    }
}
