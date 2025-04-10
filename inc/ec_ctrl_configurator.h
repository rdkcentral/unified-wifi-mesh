#ifndef EC_CTRL_CONFIGURATOR_H
#define EC_CTRL_CONFIGURATOR_H

#include "ec_configurator.h"
#include <unordered_map>

// forward decl
struct cJSON;

typedef enum {
    dpp_config_obj_bsta,
    dpp_config_obj_ieee1905,
} dpp_config_obj_type_e;

class ec_ctrl_configurator_t : public ec_configurator_t {
public:
    
	/**!
	 * @brief Constructor for ec_ctrl_configurator_t class.
	 *
	 * Initializes the ec_ctrl_configurator_t object with the provided MAC address and function pointers.
	 *
	 * @param[in] mac_addr The MAC address as a string.
	 * @param[in] send_chirp_notification Function pointer for sending chirp notifications.
	 * @param[in] send_prox_encap_dpp_msg Function pointer for sending encapsulated DPP messages.
	 * @param[in] backhaul_sta_info_func Function pointer to get backhaul station information.
	 * @param[in] ieee1905_info_func Function pointer to get IEEE 1905 information.
	 * @param[in] can_onboard_func Function pointer to check if additional APs can be onboarded.
	 *
	 * @note This constructor initializes the base class ec_configurator_t with the provided parameters.
	 */
	ec_ctrl_configurator_t(std::string mac_addr, send_chirp_func send_chirp_notification, send_encap_dpp_func send_prox_encap_dpp_msg,
        get_backhaul_sta_info_func backhaul_sta_info_func, get_1905_info_func ieee1905_info_func, can_onboard_additional_aps_func can_onboard_func) :
        ec_configurator_t(mac_addr, send_chirp_notification, send_prox_encap_dpp_msg, {}, backhaul_sta_info_func, ieee1905_info_func, can_onboard_func)
        {};
        // No MAC address needed for controller configurator

    
	/**
	 * @brief Handle a chirp notification message TLV and direct it to the 1905 agent.
	 *
	 * This function processes the chirp TLV and performs necessary actions based on its content.
	 *
	 * @param[in] chirp_tlv Pointer to the chirp TLV to parse and handle.
	 * @param[in] tlv_len The length of the chirp TLV.
	 *
	 * @return true if the processing is successful, false otherwise.
	 */
	bool process_chirp_notification(em_dpp_chirp_value_t* chirp_tlv, uint16_t tlv_len) override;

    
	/**
	 * @brief Handle a proxied encapsulated DPP message TLVs (including chirp value) and direct to 1905 agent.
	 *
	 * This function processes the encapsulated DPP message TLVs and directs them to the 1905 agent.
	 *
	 * @param[in] encap_tlv The 1905 Encap DPP TLV to parse and handle.
	 * @param[in] encap_tlv_len The length of the 1905 Encap DPP TLV.
	 * @param[in] chirp_tlv The DPP Chirp Value TLV to parse and handle (NULL if not present).
	 * @param[in] chirp_tlv_len The length of the DPP Chirp Value TLV (0 if not present).
	 *
	 * @return bool True if successful, false otherwise.
	 */
	bool process_proxy_encap_dpp_msg(em_encap_dpp_t *encap_tlv, uint16_t encap_tlv_len, em_dpp_chirp_value_t *chirp_tlv, uint16_t chirp_tlv_len) override;

    
	/**
	 * @brief Handles an authentication response 802.11 frame, performing the necessary actions.
	 *
	 * This function processes an authentication response frame that is unwrapped from the Proxy Encap DPP.
	 * It performs the necessary actions and may pass the frame to 1905 if required.
	 *
	 * @param[in] frame The frame to handle.
	 * @param[in] len The length of the frame.
	 * @param[in] src_mac The source MAC address of the frame.
	 *
	 * @return bool True if the operation is successful, false otherwise.
	 *
	 * @note This function is optional to implement because the controller+configurator does not handle 802.11,
	 *       but the proxy agent + configurator does.
	 */
	bool handle_auth_response(ec_frame_t *frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN]) override;

    
	/**
	 * @brief Handle a proxied encapsulated DPP Configuration Request frame.
	 *
	 * This function processes a DPP Configuration Request frame received from an Enrollee.
	 *
	 * @param[in] encap_frame The DPP Configuration Request frame from an Enrollee.
	 * @param[in] encap_frame_len The length of the DPP Configuration Request frame.
	 * @param[in] dest_mac The source MAC of this DPP Configuration Request frame (Enrollee).
	 *
	 * @return true on success, otherwise false.
	 *
	 * @note Overrides parent implementation.
	 */
	bool handle_proxied_dpp_configuration_request(uint8_t *encap_frame, uint16_t encap_frame_len, uint8_t dest_mac[ETH_ALEN]) override;

    
	/**
	 * @brief Handle a proxied encapsulated DPP Configuration Result frame.
	 *
	 * This function processes a DPP Configuration Result frame that has been
	 * encapsulated and proxied. It extracts necessary information from the frame
	 * and performs required operations based on the configuration result.
	 *
	 * @param[in] encap_frame Pointer to the DPP Configuration Result frame.
	 * @param[in] encap_frame_len Length of the encapsulated frame.
	 * @param[in] dest_mac The source MAC address of the DPP Configuration Result frame (Enrollee).
	 *
	 * @return true if the frame was handled successfully, otherwise false.
	 */
	virtual bool handle_proxied_config_result_frame(uint8_t *encap_frame, uint16_t encap_frame_len, uint8_t dest_mac[ETH_ALEN]) override;

    
	/**
	 * @brief Handle a proxied encapsulated DPP Connection Status Result frame.
	 *
	 * This function processes a DPP Connection Status Result frame that has been
	 * encapsulated and proxied. It extracts necessary information from the frame
	 * and performs required operations based on the connection status.
	 *
	 * @param[in] encap_frame Pointer to the DPP Connection Status Result frame.
	 * @param[in] encap_frame_len Length of the encapsulated frame.
	 * @param[in] dest_mac Source MAC address of the DPP Connection Status Result frame (Enrollee).
	 *
	 * @return true if the frame was handled successfully, otherwise false.
	 */
	virtual bool handle_proxied_conn_status_result_frame(uint8_t *encap_frame, uint16_t encap_frame_len, uint8_t dest_mac[ETH_ALEN]) override;

private:
    // Private member variables can be added here

    const ec_dpp_capabilities_t m_dpp_caps = {{
        .enrollee = 0,
        .configurator = 1,
        .reserved = 0
    }};
    
	/**!
	 * @brief Creates an authentication request for a given enrollee MAC address.
	 *
	 * This function generates an authentication request based on the provided
	 * MAC address of the enrollee. It returns a pair consisting of a pointer
	 * to the request data and the size of the data.
	 *
	 * @param[in] enrollee_mac The MAC address of the enrollee as a string.
	 *
	 * @returns A pair containing:
	 * - A pointer to the authentication request data.
	 * - The size of the request data.
	 *
	 * @note Ensure that the enrollee MAC address is valid and properly formatted.
	 */
	std::pair<uint8_t*, size_t> create_auth_request(std::string enrollee_mac);
    
	/**!
	 * @brief Creates a reconfiguration authentication request.
	 *
	 * This function generates a request for reconfiguration authentication.
	 *
	 * @returns A pair consisting of a pointer to the request data and its size.
	 */
	std::pair<uint8_t*, size_t> create_recfg_auth_request();
    
	/**!
	 * @brief Creates an authentication confirmation message.
	 *
	 * This function generates an authentication confirmation message based on the provided enrollee MAC address,
	 * DPP status, and initial authentication tag.
	 *
	 * @param[in] enrollee_mac The MAC address of the enrollee device.
	 * @param[in] dpp_status The DPP status code indicating the current status of the enrollee.
	 * @param[in] i_auth_tag Pointer to the initial authentication tag.
	 *
	 * @returns A pair consisting of a pointer to the authentication confirmation message and its size.
	 *
	 * @note Ensure that the enrollee MAC address and DPP status are valid before calling this function.
	 */
	std::pair<uint8_t*, size_t> create_auth_confirm(std::string enrollee_mac, ec_status_code_t dpp_status, uint8_t* i_auth_tag);
    
	/**!
	 * @brief Creates a reconfiguration authentication confirmation.
	 *
	 * This function generates a reconfiguration authentication confirmation based on the provided
	 * enrollee MAC address and DPP status code.
	 *
	 * @param[in] enrollee_mac The MAC address of the enrollee as a string.
	 * @param[in] dpp_status The DPP status code as an ec_status_code_t.
	 *
	 * @returns A pair consisting of a pointer to a uint8_t array and its size.
	 *
	 * @note Ensure that the enrollee MAC address is valid and the DPP status code is correctly set.
	 */
	std::pair<uint8_t*, size_t> create_recfg_auth_confirm(std::string enrollee_mac, ec_status_code_t dpp_status);

    
	/**
	 * @brief Creates a DPP Configuration Response frame, wrapped as an Encap DPP TLV.
	 *
	 * This function generates a DPP Configuration Response frame based on the provided
	 * destination MAC address, dialog token, and DPP status. The frame is encapsulated
	 * as a DPP TLV.
	 *
	 * @param[out] dest_mac The destination MAC address of the Enrollee. This should be
	 *                      an array of ETH_ALEN bytes.
	 * @param[in] dialog_token The session dialog token for the Enrollee.
	 * @param[in] dpp_status The status of the DPP Configuration. Use DPP_STATUS_OK for
	 *                       success or DPP_STATUS_CONFIGURATION_FAILURE for failure.
	 *
	 * @return std::pair<uint8_t*, size_t> A pair containing the frame and its length
	 *                                      on success, or nullptr and 0 on failure.
	 *
	 * @note Ensure that the destination MAC address is valid and that the dialog token
	 *       and DPP status are correctly set before calling this function.
	 */
	std::pair<uint8_t*, size_t> create_config_response_frame(uint8_t dest_mac[ETH_ALEN], const uint8_t dialog_token, ec_status_code_t dpp_status);

    
	/**
	 * @brief Finalizes a base DPP Configuration object.
	 *
	 * A base configuration object has all mandatory base fields filled out, including keys
	 * "wi-fi_tech", "discovery", and "cred".
	 *
	 * @param[in,out] base The base JSON object to be finalized.
	 * @param[in] conn_ctx The EC connection context.
	 * @param[in] config_obj_type The type of DPP Configuration object to fill out.
	 *
	 * @return cJSON* DPP Configuration object on success, nullptr otherwise.
	 */
	cJSON *finalize_config_obj(cJSON *base, ec_connection_context_t& conn_ctx, dpp_config_obj_type_e config_obj_type);

    /**
     * @brief Maps Enrollee MAC (as string) to onboarded status. True if onboarded (now a Proxy Agent), false if still onboarding / onboarding failed.
     * 
     */
    std::unordered_map<std::string, bool> m_enrollee_successfully_onboarded = {};
};

#endif // EC_CTRL_CONFIGURATOR_H