#include "ec_configurator.h"
#include "em_crypto.h"
#include "ec_util.h"
#include "util.h"

ec_configurator_t::ec_configurator_t(
    std::string mac_addr,
    send_chirp_func send_chirp_notification,
    send_encap_dpp_func send_prox_encap_dpp_msg,
    send_act_frame_func send_action_frame,
    get_backhaul_sta_info_func backhaul_sta_info_func,
    get_1905_info_func ieee1905_info_func,
    get_fbss_info_func get_fbss_info_func,
    can_onboard_additional_aps_func can_onboard_func) : m_mac_addr(mac_addr),
    m_send_chirp_notification(send_chirp_notification),
    m_send_prox_encap_dpp_msg(send_prox_encap_dpp_msg),
    m_send_action_frame(send_action_frame),
    m_get_backhaul_sta_info(backhaul_sta_info_func),
    m_get_1905_info(ieee1905_info_func),
    m_get_fbss_info(get_fbss_info_func),
    m_can_onboard_additional_aps(can_onboard_func)
{
}

ec_configurator_t::~ec_configurator_t()
{

    for (auto& [_, c_ctx] : m_connections) {
        ec_crypto::free_connection_ctx(&c_ctx);
    }
}
