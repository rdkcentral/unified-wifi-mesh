#include "ec_configurator.h"

ec_configurator_t::ec_configurator_t(
    std::string mac_addr,
    send_chirp_func send_chirp_notification,
    send_encap_dpp_func send_prox_encap_dpp_msg,
    send_act_frame_func send_action_frame
) : m_mac_addr(mac_addr),
    m_send_chirp_notification(send_chirp_notification),
    m_send_prox_encap_dpp_msg(send_prox_encap_dpp_msg),
    m_send_action_frame(send_action_frame)
{
}

ec_configurator_t::~ec_configurator_t()
{
}

// TODO: Maybe move to controller
bool ec_configurator_t::start(ec_data_t *ec_data)
{
    memset(&m_boot_data, 0, sizeof(ec_data_t));
    memcpy(&m_boot_data, ec_data, sizeof(ec_data_t));

    if (EC_KEY_get0_public_key(m_boot_data.responder_boot_key) == NULL) {
        printf("%s:%d Could not get responder bootstrap public key\n", __func__, __LINE__);
        return false;
    }

    printf("Configurator MAC: %s\n", m_mac_addr.c_str());
    return ec_crypto::init_persistent_ctx(m_p_ctx, m_boot_data.responder_boot_key);
}
