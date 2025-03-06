#ifndef EC_CONFIGURATOR_H
#define EC_CONFIGURATOR_H

#include <functional>
#include <map>
#include <string>

#include "em_base.h"
#include "ec_crypto.h"


/**
 * @brief Sends a chirp notification
 * 
 * @param chirp_tlv The chirp TLV to send
 * @param len The length of the chirp TLV
 * @return bool true if successful, false otherwise
 */
using send_chirp_func = std::function<bool(em_dpp_chirp_value_t*, size_t)>;

/**
 * @brief Sends a proxied encapsulated DPP message
 * 
 * @param encap_dpp_tlv The 1905 Encap DPP TLV to include in the message
 * @param encap_dpp_len The length of the 1905 Encap DPP TLV
 * @param chirp_tlv The chirp value to include in the message. If NULL, the message will not include a chirp value
 * @param chirp_len The length of the chirp value
 * @return bool true if successful, false otherwise
 */
using send_encap_dpp_func = std::function<bool(em_encap_dpp_t*, size_t, em_dpp_chirp_value_t*, size_t)>;

/**
* @brief Set the CCE IEs in the beacon and probe response frames
* 
* @param bool Whether to enable or disable the inclusion of CCE IEs in the beacon and probe response frames
* @return bool true if successful, false otherwise
*/
using toggle_cce_func = std::function<bool(bool)>;

class ec_configurator_t {
public:
    /**
     * @brief Construct an EC configurator 
     * 
     * @param send_chirp_notification The function to send a chirp notification
     * @param send_prox_encap_dpp_msg The function to send a proxied encapsulated DPP message
     */
    // TODO: Add send_action_frame and send_gas_frame functions
    ec_configurator_t(std::string mac_addr, send_chirp_func send_chirp_notification, send_encap_dpp_func send_prox_encap_dpp_msg);
    ~ec_configurator_t(); // Destructor

    /**
     * @brief Set the CCE IEs in the beacon and probe response frames
     * 
     * @param bool Whether to enable or disable the inclusion of CCE IEs in the beacon and probe response frames
     * @return bool true if successful, false otherwise
     */
    toggle_cce_func m_toggle_cce;

    /**
     * @brief Start the EC configurator onboarding
     * 
     * @param ec_data The data to use for onboarding (Parsed DPP URI Data)
     * @return bool true if successful, false otherwise
     */
    bool start(ec_data_t* ec_data);

    /**
     * @brief Handles a presence announcement 802.11 frame, performing the necessary actions
     * 
     * @param buff The frame to handle
     * @param len The length of the frame
     * @return bool true if successful, false otherwise
     * 
     * @note Optional to implement because the controller+configurator does not handle 802.11,
     *      but the proxy agent + configurator does.
     */
    virtual bool handle_presence_announcement(uint8_t *buff, unsigned int len) {
        return 0; // Optional to implement
    }

    /**
     * @brief Handles an authentication request 802.11 frame, performing the necessary actions
     * 
     * @param buff The frame to handle
     * @param len The length of the frame
     * @return bool true if successful, false otherwise
     * 
     * @note Optional to implement because the controller+configurator does not handle 802.11,
     *     but the proxy agent + configurator does.
     */
    virtual bool handle_auth_response(uint8_t *buff, unsigned int len) {
        return true; // Optional to implement
    }

    /**
     * @brief Handles an configuration request 802.11+GAS frame, performing the necessary actions
     * 
     * @param buff The frame to handle
     * @param len The length of the frame
     * @return bool true if successful, false otherwise
     * 
     * @note Optional to implement because the controller+configurator does not handle 802.11,
     *     but the proxy agent + configurator does.
     */
    virtual bool handle_cfg_request(uint8_t *buff, unsigned int len) {
        return true; // Optional to implement
    }

    /**
     * @brief Handles an configuration result 802.11+GAS frame, performing the necessary actions
     * 
     * @param buff The frame to handle
     * @param len The length of the frame
     * @return bool true if successful, false otherwise
     * 
     * @note Optional to implement because the controller+configurator does not handle 802.11,
     *     but the proxy agent + configurator does.
     */
    virtual bool handle_cfg_result(uint8_t *buff, unsigned int len) {
        return true; // Optional to implement
    }

    /**
     * @brief Handle a chirp notification msg tlv and direct to the correct place (802.11 or 1905)
     * 
     * @param chirp_tlv The chirp TLV to parse and handle
     * @param tlv_len The length of the chirp TLV
     * @return bool true if successful, false otherwise
     */
    virtual bool process_chirp_notification(em_dpp_chirp_value_t* chirp_tlv, uint16_t tlv_len) = 0;

    /**
     * @brief Handle a proxied encapsulated DPP message TLVs (including chirp value) and direct to the correct place (802.11 or 1905)
     * 
     * @param encap_tlv The 1905 Encap DPP TLV to parse and handle
     * @param encap_tlv_len The length of the 1905 Encap DPP TLV
     * @param chirp_tlv The DPP Chirp Value TLV to parse and handle (NULL if not present)
     * @param chirp_tlv_len The length of the DPP Chirp Value TLV (0 if not present)
     * @return bool true if successful, false otherwise
     */
    virtual bool  process_proxy_encap_dpp_msg(em_encap_dpp_t *encap_tlv, uint16_t encap_tlv_len, em_dpp_chirp_value_t *chirp_tlv, uint16_t chirp_tlv_len) = 0;

    inline std::string get_mac_addr() { return m_mac_addr; };

    // Disable copy construction and assignment
    // Requires use of references or pointers when working with instances of this class
    ec_configurator_t(const ec_configurator_t&) = delete;
    ec_configurator_t& operator=(const ec_configurator_t&) = delete;

protected:
    ec_persistent_context_t m_p_ctx;

    ec_data_t m_boot_data;

    send_chirp_func m_send_chirp_notification;

    send_encap_dpp_func m_send_prox_encap_dpp_msg;

    std::string m_mac_addr;

    // The connections to the Enrollees/Agents
    std::map<std::string, ec_connection_context_t> m_connections;

    inline ec_connection_context_t* get_conn_ctx(const std::string& mac) {
        if (m_connections.find(mac) == m_connections.end()) {
            return NULL;
        }
        return &m_connections[mac];    
    }

    inline ec_ephemeral_context_t* get_eph_ctx(const std::string& mac) {
        static ec_ephemeral_context_t empty_ctx;  // Static fallback for error cases
        auto conn_ctx = get_conn_ctx(mac);
        if (!conn_ctx) {
            printf("%s:%d: Connection context not found for enrollee MAC %s\n", __func__, __LINE__, mac.c_str());
            return NULL;  // Return reference to static empty context
        }
        return &conn_ctx->eph_ctx;
    }

    inline void clear_conn_eph_ctx(const std::string& mac) {
        auto conn = m_connections.find(mac);
        if (conn == m_connections.end()) return;
        auto &eph_ctx = conn->second.eph_ctx;
        ec_crypto::free_ephemeral_context(&eph_ctx, m_p_ctx.nonce_len, m_p_ctx.digest_len);
    }

};

#endif // EC_CONFIGURATOR_H