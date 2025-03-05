#ifndef EC_ENROLLEE_H
#define EC_ENROLLEE_H

#include "em_base.h"

#include <map>

class ec_enrollee_t {
public:
    // TODO: Add Send Action Frame
    ec_enrollee_t();
    
    // Destructor
    ~ec_enrollee_t();

    int start(bool do_reconfig);

    int handle_auth_request(uint8_t *buff, unsigned int len);

    int handle_auth_confirm(uint8_t *buff, unsigned int len);

    int handle_config_response(uint8_t *buff, unsigned int len);

    // Disable copy construction and assignment
    // Requires use of references or pointers when working with instances of this class
    ec_enrollee_t(const ec_enrollee_t&) = delete;
    ec_enrollee_t& operator=(const ec_enrollee_t&) = delete;

private:

    // TODO: Send Action Frame

    // TODO: Send GAS Frame

    /**
     * @brief Called when recieving a Authentication Request,
     *         this function checks that the "Responder" (self) is capable of 
     *         supporting the role indicated by the Initiator's capabilities.
     * 
     */
    bool check_supports_init_caps(ec_dpp_capabilities_t caps);

    std::pair<uint8_t*, uint16_t> create_presence_announcement();
    std::pair<uint8_t*, uint16_t> create_recfg_presence_announcement();
    std::pair<uint8_t*, uint16_t> create_auth_response(ec_status_code_t dpp_status);
    std::pair<uint8_t*, uint16_t> create_recfg_auth_response(ec_status_code_t dpp_status);
    std::pair<uint8_t*, uint16_t> create_config_request();
    std::pair<uint8_t*, uint16_t> create_config_result(); 

    ec_persistent_context_t m_p_ctx;

    // Randomized and cleared at the end of the authentication/configuration process
    ec_ephemeral_context_t m_eph_ctx;


};

#endif // EC_ENROLLEE_H