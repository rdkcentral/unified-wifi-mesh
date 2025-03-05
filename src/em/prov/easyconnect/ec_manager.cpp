#include "ec_manager.h"
#include "ec_ctrl_configurator.h"

#include <memory>

ec_manager_t::ec_manager_t(send_chirp_func send_chirp, send_encap_dpp_func send_encap_dpp, toggle_cce_func toggle_cce, bool is_controller)  : is_controller(is_controller) {
    if (is_controller) {
        m_configurator = std::unique_ptr<ec_configurator_t>(new ec_ctrl_configurator_t(send_chirp, send_encap_dpp));
        m_configurator->m_toggle_cce = toggle_cce;
    } else {
        m_enrollee = std::unique_ptr<ec_enrollee_t>(new ec_enrollee_t());
    }
}

ec_manager_t::~ec_manager_t()
{
}

int ec_manager_t::handle_recv_ec_action_frame(ec_frame_t *frame, size_t len)
{
    if (!ec_util::validate_frame(frame)) {
        printf("%s:%d: frame validation failed\n", __func__, __LINE__);
        return -1;
    }
    switch (frame->frame_type) {
        case ec_frame_type_presence_announcement:
            return m_configurator->handle_presence_announcement((uint8_t *)frame, len);
        default:
            printf("%s:%d: frame type (%d) not handled\n", __func__, __LINE__, frame->frame_type);
            break;
    }
    return 0;
}
