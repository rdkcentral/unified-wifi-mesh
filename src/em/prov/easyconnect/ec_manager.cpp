#include "ec_manager.h"
#include "ec_ctrl_configurator.h"

#include "ec_util.h"

#include <memory>

ec_manager_t::ec_manager_t(std::string mac_addr, send_chirp_func send_chirp, send_encap_dpp_func send_encap_dpp, bool m_is_controller) 
                            : m_is_controller(m_is_controller), m_stored_chirp_fn(send_chirp), m_stored_encap_dpp_fn(send_encap_dpp), m_stored_mac_addr(mac_addr){
    if (m_is_controller) {
        m_configurator = std::unique_ptr<ec_configurator_t>(new ec_ctrl_configurator_t(mac_addr, send_chirp, send_encap_dpp));
    } else {
        m_enrollee = std::unique_ptr<ec_enrollee_t>(new ec_enrollee_t(mac_addr));
    }
}

ec_manager_t::~ec_manager_t()
{
}

bool ec_manager_t::handle_recv_ec_action_frame(ec_frame_t *frame, size_t len)
{
    if (!ec_util::validate_frame(frame)) {
        printf("%s:%d: frame validation failed\n", __func__, __LINE__);
        return false;
    }
    switch (frame->frame_type) {
        case ec_frame_type_presence_announcement:
            return m_configurator->handle_presence_announcement((uint8_t *)frame, len);
        case ec_frame_type_auth_req:
            return m_enrollee->handle_auth_request((uint8_t *)frame, len);
        case ec_frame_type_auth_rsp:
            return m_configurator->handle_auth_response((uint8_t *)frame, len);
        case ec_frame_type_auth_cnf:
            return m_enrollee->handle_auth_confirm((uint8_t *)frame, len);

        default:
            printf("%s:%d: frame type (%d) not handled\n", __func__, __LINE__, frame->frame_type);
            break;
    }
    return true;
}

bool ec_manager_t::upgrade_to_onboarded_proxy_agent(toggle_cce_func toggle_cce)
{
    if (m_is_controller) {
        // Only an enrollee agent can be upgraded to a proxy agent
        return false;
    }

    // If a configurator is already defined (i.e. the enrollee agent is already upgraded) or somehow it's a controller
    //      return an error
    if (m_configurator || dynamic_cast<ec_ctrl_configurator_t*>(m_configurator.get()) == nullptr) {
        return false;
    }
    if (!m_enrollee) {
        // Can't upgrade an enrollee if it's not defined
        return false;
    }
    std::string enrollee_mac = m_enrollee->get_mac_addr();
    // Free the enrollee object
    m_enrollee.reset();
    
    // Create a new proxy agent configurator
    m_configurator = std::unique_ptr<ec_pa_configurator_t>(new ec_pa_configurator_t(enrollee_mac, m_stored_chirp_fn, m_stored_encap_dpp_fn));
    m_configurator->m_toggle_cce = toggle_cce;
    return true;
}
