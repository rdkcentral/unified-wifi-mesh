#include "ec_manager.h"
#include "ec_ctrl_configurator.h"

#include "ec_util.h"

#include <memory>

ec_manager_t::ec_manager_t(
    std::string mac_addr,
    send_chirp_func send_chirp,
    send_encap_dpp_func send_encap_dpp,
    send_act_frame_func send_action_frame,
    bool m_is_controller
) : m_is_controller(m_is_controller),
    m_stored_chirp_fn(send_chirp),
    m_stored_encap_dpp_fn(send_encap_dpp),
    m_stored_action_frame_fn(send_action_frame),
    m_stored_mac_addr(mac_addr) {
    
    if (m_is_controller) {
        m_configurator = std::unique_ptr<ec_configurator_t>(
            new ec_ctrl_configurator_t(mac_addr, send_chirp, send_encap_dpp)
        );
    } else {
        m_enrollee = std::unique_ptr<ec_enrollee_t>(
            new ec_enrollee_t(mac_addr, send_action_frame)
        );
    }
}

ec_manager_t::~ec_manager_t()
{
}

bool ec_manager_t::handle_recv_ec_action_frame(ec_frame_t *frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN])
{
    if (!ec_util::validate_frame(frame)) {
        printf("%s:%d: frame validation failed\n", __func__, __LINE__);
        return false;
    }
    switch (frame->frame_type) {
        case ec_frame_type_presence_announcement:
            return m_configurator->handle_presence_announcement(frame, len, src_mac);
        case ec_frame_type_auth_req:
            return m_enrollee->handle_auth_request(frame, len, src_mac);
        case ec_frame_type_auth_rsp:
            return m_configurator->handle_auth_response(frame, len, src_mac);
        case ec_frame_type_auth_cnf:
            return m_enrollee->handle_auth_confirm(frame, len, src_mac);

        default:
            printf("%s:%d: frame type (%d) not handled\n", __func__, __LINE__, frame->frame_type);
            break;
    }
    return true;
}

bool ec_manager_t::handle_recv_gas_pub_action_frame(ec_gas_frame_base_t *frame, size_t len, uint8_t source_addr[ETH_ALEN]) {
    if (!frame) {
        printf("%s:%d: EC manager given a NULL DPP GAS frame!\n", __func__, __LINE__);
        return false;
    }
    printf("%s:%d: Got a GAS frame with %02x action!\n", __func__, __LINE__, frame->action);
    switch (static_cast<dpp_gas_action_type_t>(frame->action)) {
        case dpp_gas_initial_req:
            return m_configurator->handle_cfg_request(reinterpret_cast<uint8_t *> (frame), static_cast<unsigned> (len), source_addr);
        case dpp_gas_initial_resp:
            return m_enrollee->handle_config_response(reinterpret_cast<uint8_t *> (frame), static_cast<unsigned> (len), source_addr);
        case dpp_gas_comeback_req:
        case dpp_gas_comeback_resp:
        default:
            // XXX: handle comeback frames
            printf("%s:%d: unhandled DPP GAS action type=%02x\n", __func__, __LINE__, frame->action);
            break;
    }
    return false;
}

bool ec_manager_t::upgrade_to_onboarded_proxy_agent(toggle_cce_func toggle_cce)
{
    if (m_is_controller) {
        // Only an enrollee agent can be upgraded to a proxy agent
        printf("%s:%d: Can't upgrade a controller to a proxy agent\n", __func__, __LINE__);
        return false;
    }

    // If a configurator is already defined (i.e. the enrollee agent is already upgraded) or somehow it's a controller
    //      return an error
    if (m_configurator && dynamic_cast<ec_ctrl_configurator_t*>(m_configurator.get()) == nullptr) {
        printf("%s:%d: Can't upgrade an already upgraded agent\n", __func__, __LINE__);
        return false;
    }
    if (!m_enrollee) {
        // Can't upgrade an enrollee if it's not defined
        printf("%s:%d: Can't upgrade an enrollee that doesn't exist\n", __func__, __LINE__);
        return false;
    }
    std::string enrollee_mac = m_enrollee->get_mac_addr();
    // Free the enrollee object
    m_enrollee.reset();
    
    // Create a new proxy agent configurator
    m_configurator = std::unique_ptr<ec_pa_configurator_t>(new ec_pa_configurator_t(enrollee_mac, m_stored_chirp_fn, m_stored_encap_dpp_fn, m_stored_action_frame_fn));
    m_configurator->m_toggle_cce = toggle_cce;
    printf("%s:%d: Upgraded enrollee agent to proxy agent\n", __func__, __LINE__);
    return true;
}
