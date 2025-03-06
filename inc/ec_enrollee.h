#ifndef EC_ENROLLEE_H
#define EC_ENROLLEE_H

#include "em_base.h"

#include <map>
#include <string>

class ec_enrollee_t {
public:
    // TODO: Add Send Action Frame, Send GAS Frame
    /**
     * @brief The EasyConnect Enrollee
     * 
     * Broadcasts 802.11 presence announcements, handles 802.11 frames from Proxy Agents and sends 802.11 responses to Proxy Agents.
     * 
     * @param mac_addr The MAC address of the device
     * 
     * @note The default state of an enrollee is non-onboarding. All non-controller devices are started as (non-onboarding) enrollees 
     *      until they are told that they are on the network at which point they can be upgraded to a proxy agent.
     */
    ec_enrollee_t(std::string mac_addr);
    
    // Destructor
    ~ec_enrollee_t();

    /**
     * @brief Start the EC enrollee onboarding
     * 
     * @param do_reconfig Whether to reconfigure/reauth the enrollee
     * @return bool true if successful, false otherwise
     */
    bool start(bool do_reconfig);

    /**
     * @brief Handle an authentication request 802.11 frame, performing the necessary actions and responding with an authentication response via 802.11
     * 
     * @param buff The frame to handle
     * @param len The length of the frame
     * @return bool true if successful, false otherwise
     */
    bool handle_auth_request(uint8_t *buff, unsigned int len);

    /**
     * @brief Handle an authentication confirmation 802.11 frame, performing the necessary actions
     * 
     * @param buff The frame to handle
     * @param len The length of the frame
     * @return bool true if successful, false otherwise
     */
    bool handle_auth_confirm(uint8_t *buff, unsigned int len);

    /**
     * @brief Handle a configuration request 802.11+GAS frame, performing the necessary actions and responding with a configuration result via 802.11
     * 
     * @param buff The frame to handle
     * @param len The length of the frame
     * @return bool true if successful, false otherwise
     */
    bool handle_config_response(uint8_t *buff, unsigned int len);

    inline std::string get_mac_addr() { return m_mac_addr; };

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
     * @param caps The capabilities of the Initiator
     * @return bool true if the Responder supports the Initiator's capabilities, false otherwise 
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

    ec_data_t m_boot_data;

    std::string m_mac_addr;


};

#endif // EC_ENROLLEE_H