#include "ec_configurator.h"
#include "em_crypto.h"

ec_configurator_t::ec_configurator_t(
    std::string mac_addr,
    send_chirp_func send_chirp_notification,
    send_encap_dpp_func send_prox_encap_dpp_msg,
    send_act_frame_func send_action_frame,
    get_backhaul_sta_info_func backhaul_sta_info_func,
    get_1905_info_func ieee1905_info_func,
    can_onboard_additional_aps_func can_onboard_func) : m_mac_addr(mac_addr),
    m_send_chirp_notification(send_chirp_notification),
    m_send_prox_encap_dpp_msg(send_prox_encap_dpp_msg),
    m_send_action_frame(send_action_frame),
    m_get_backhaul_sta_info(backhaul_sta_info_func),
    m_get_1905_info(ieee1905_info_func),
    m_can_onboard_additional_aps(can_onboard_func)
{
}

ec_configurator_t::~ec_configurator_t()
{
    if (m_boot_data.resp_priv_boot_key) {
        BN_free(m_boot_data.resp_priv_boot_key);
    }
    if (m_boot_data.resp_pub_boot_key) {
        EC_POINT_free(m_boot_data.resp_pub_boot_key);
    }
    if (m_boot_data.init_priv_boot_key) {
        BN_free(m_boot_data.init_priv_boot_key);
    }
    if (m_boot_data.init_pub_boot_key) {
        EC_POINT_free(m_boot_data.init_pub_boot_key);
    }
    
    for (auto& conn : m_connections) {
        ec_crypto::free_ephemeral_context(&conn.second.eph_ctx, m_p_ctx.nonce_len, m_p_ctx.digest_len);
    }
}

// TODO: Maybe move to controller
bool ec_configurator_t::start(ec_data_t *ec_data)
{
    memset(&m_boot_data, 0, sizeof(ec_data_t));
    memcpy(&m_boot_data, ec_data, sizeof(ec_data_t));

    // Not all of these will be present but it is better to compute them now.
    m_boot_data.resp_priv_boot_key = em_crypto_t::get_priv_key_bn(m_boot_data.responder_boot_key);
    m_boot_data.resp_pub_boot_key = em_crypto_t::get_pub_key_point(m_boot_data.responder_boot_key);

    m_boot_data.init_priv_boot_key = em_crypto_t::get_priv_key_bn(m_boot_data.initiator_boot_key);    
    m_boot_data.init_pub_boot_key = em_crypto_t::get_pub_key_point(m_boot_data.initiator_boot_key);


    if (m_boot_data.resp_priv_boot_key == NULL) {
        printf("%s:%d Could not get responder bootstrap public key\n", __func__, __LINE__);
        return false;
    }

    printf("Configurator MAC: %s\n", m_mac_addr.c_str());
    return ec_crypto::init_persistent_ctx(m_p_ctx, m_boot_data.responder_boot_key);
}
