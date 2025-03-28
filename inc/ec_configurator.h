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
 * @brief Send an action frame. Optional to implement.
 * 
 * @param dest_mac The destination MAC address
 * @param action_frame The action frame to send
 * @param action_frame_len The length of the action frame
 * @param frequency The frequency to send the frame on (0 for current frequency)
 * @return true if successful, false otherwise
 */
using send_act_frame_func = std::function<bool(uint8_t*, uint8_t *, size_t, unsigned int)>;

/**
* @brief Set the CCE IEs in the beacon and probe response frames
* 
* @param bool Whether to enable or disable the inclusion of CCE IEs in the beacon and probe response frames
* @return bool true if successful, false otherwise
*/
using toggle_cce_func = std::function<bool(bool)>;

/**
 * @brief Creates a DPP Configuration Response object for the backhaul STA interface.
 * @param conn_ctx Optional connection context (not needed for Enrollee, needed for Configurator) -- pass nullptr if not needed.
 * @return cJSON * on success, nullptr otherwise
 */
using get_backhaul_sta_info_func = std::function<cJSON*(ec_connection_context_t *)>;

/**
 * @brief Creates a DPP Configuration Response object for the 1905.1 interface.
 * @return cJSON * on success, nullptr otherwise.
 */
using get_1905_info_func = std::function<cJSON*(ec_connection_context_t *)>;

/**
 * @brief Used to determine if an additional AP can be on-boarded or not.
 * @return True if additional APs can be on-boraded into the mesh, false otherwise.
 */
using can_onboard_additional_aps_func = std::function<bool(void)>;

class ec_configurator_t {
public:
    /**
     * @brief Construct an EC configurator 
     * 
     * @param send_chirp_notification The function to send a chirp notification
     * @param send_prox_encap_dpp_msg The function to send a proxied encapsulated DPP message
     */

    ec_configurator_t(std::string mac_addr, send_chirp_func send_chirp_notification, send_encap_dpp_func send_prox_encap_dpp_msg, 
                        send_act_frame_func send_action_frame, get_backhaul_sta_info_func backhaul_sta_info_func, get_1905_info_func ieee1905_info_func,
                        can_onboard_additional_aps_func can_onboard_func);
    virtual ~ec_configurator_t(); // Destructor

    /**
     * @brief Set the CCE IEs in the beacon and probe response frames
     * 
     * @param bool Whether to enable or disable the inclusion of CCE IEs in the beacon and probe response frames
     * @return bool true if successful, false otherwise
     */
    toggle_cce_func m_toggle_cce = {
        [](bool enable) -> bool { return false; }
    };

    /**
     * @brief Start the EC configurator onboarding process for an enrollee
     * 
     * @param bootstrapping_data The data to use for onboarding (Parsed DPP URI Data)
     * @return bool true if successful, false otherwise
     */
    bool onboard_enrollee(ec_data_t* bootstrapping_data);

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
    virtual bool handle_presence_announcement(ec_frame_t *frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN]) {
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
    virtual bool handle_auth_response(ec_frame_t *frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN]) {
        return true; // Optional to implement
    }

    /**
     * @brief Handles an configuration request 802.11+GAS frame, performing the necessary actions
     * 
     * @param buff The frame to handle
     * @param len The length of the frame
     * @param sa The 802.11 source address of the frame (from Enrollee).
     * @return bool true if successful, false otherwise
     * 
     * @note Optional to implement because the controller+configurator does not handle 802.11,
     *     but the proxy agent + configurator does.
     */
    virtual bool handle_cfg_request(uint8_t *buff, unsigned int len, uint8_t sa[ETH_ALEN]) {
        return true; // Optional to implement
    }

    /**
     * @brief Handles an configuration result 802.11+GAS frame, performing the necessary actions
     * 
     * @param buff The frame to handle
     * @param len The length of the frame
     * @param sa The source address of the frame.
     * @return bool true if successful, false otherwise
     * 
     * @note Optional to implement because the controller+configurator does not handle 802.11,
     *     but the proxy agent + configurator does.
     */
    virtual bool handle_cfg_result(ec_frame_t *frame, size_t len, uint8_t sa[ETH_ALEN]) {
        return true; // Optional to implement
    }

    /**
     * @brief Handles Connection Status Result frame.
     * 
     * @param buff The frame.
     * @param len The frame length.
     * @param sa The source address of the frame.
     * @return true on success, otherwise false.
     */
    virtual bool handle_connection_status_result(ec_frame_t *frame, size_t len, uint8_t sa[ETH_ALEN]) {
        return true;
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

    /**
     * @brief Handle a proxied encapsulated DPP Configuration Request frame.
     * 
     * @param encap_frame The DPP Configuration Request frame from an Enrollee.
     * @param encap_frame_len The length of the DPP Configuration Request frame.
     * @param dest_mac The source MAC of this DPP Configuration Request frame (Enrollee).
     * @return true on success, otherwise false.
     * 
     * @note: overridden by subclass.
     */
    virtual bool handle_proxied_dpp_configuration_request(uint8_t *encap_frame, uint16_t encap_frame_len, uint8_t dest_mac[ETH_ALEN]) {
        return true;
    }

    /**
     * @brief Handle a proxied encapsulated DPP Configuration Result frame.
     * 
     * @param encap_frame The DPP Configuration Result frame.
     * @param encap_frame_len Length of the frame.
     * @param dest_mac The source MAC of this DPP Configuration Result frame (Enrollee).
     * @return true on success, otherwise false.
     */
    virtual bool handle_proxied_config_result_frame(uint8_t *encap_frame, uint16_t encap_frame_len, uint8_t dest_mac[ETH_ALEN]) {
        return true;
    }

    /**
     * @brief Handle a proxied encapsulated DPP Connection Status Result frame.
     * 
     * @param encap_frame The DPP Connection Status Result frame.
     * @param encap_frame_len Length of the frame.
     * @param dest_mac The source MAC of this DPP Connection Status Result frame (Enrollee).
     * @return true on success, otherwise false.
     */
    virtual bool handle_proxied_conn_status_result_frame(uint8_t *encap_frame, uint16_t encap_frame_len, uint8_t dest_mac[ETH_ALEN]) {
        return true;
    }

    inline std::string get_mac_addr() { return m_mac_addr; };

    // Disable copy construction and assignment
    // Requires use of references or pointers when working with instances of this class
    ec_configurator_t(const ec_configurator_t&) = delete;
    ec_configurator_t& operator=(const ec_configurator_t&) = delete;

protected:

    std::string m_mac_addr;

    send_chirp_func m_send_chirp_notification;

    send_encap_dpp_func m_send_prox_encap_dpp_msg;

    send_act_frame_func m_send_action_frame;

    get_backhaul_sta_info_func m_get_backhaul_sta_info;

    get_1905_info_func m_get_1905_info;

    can_onboard_additional_aps_func m_can_onboard_additional_aps;

    // The connections to the Enrollees/Agents
    std::map<std::string, ec_connection_context_t> m_connections = {};

    inline ec_connection_context_t* get_conn_ctx(const std::string& mac) {
        if (m_connections.find(mac) == m_connections.end()) {
            return NULL;
        }
        return &m_connections[mac];    
    }

    inline ec_ephemeral_context_t* get_eph_ctx(const std::string& mac) {
        auto conn_ctx = get_conn_ctx(mac);
        if (!conn_ctx) {
            printf("%s:%d: Connection context not found for enrollee MAC %s\n", __func__, __LINE__, mac.c_str());
            return NULL;  // Return reference to static empty context
        }
        return &conn_ctx->eph_ctx;
    }

    inline ec_data_t* get_boot_data(const std::string& mac) {
        auto conn = m_connections.find(mac);
        if (conn == m_connections.end()) {
            printf("%s:%d: Connection context not found for enrollee MAC %s\n", __func__, __LINE__, mac.c_str());
            return NULL;  // Return reference to static empty context
        }
        return &conn->second.boot_data;
    }

    inline void clear_conn_eph_ctx(const std::string& mac) {
        auto conn = m_connections.find(mac);
        if (conn == m_connections.end()) return;
        auto &c_ctx = conn->second;
        ec_crypto::free_ephemeral_context(&c_ctx.eph_ctx, c_ctx.nonce_len, c_ctx.digest_len);
    }

};

#endif // EC_CONFIGURATOR_H