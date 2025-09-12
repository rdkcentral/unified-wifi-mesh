#ifndef EC_CTRL_CONFIGURATOR_H
#define EC_CTRL_CONFIGURATOR_H

#include "ec_configurator.h"
#include <unordered_map>

// forward decl
struct cJSON;

typedef enum {
	dpp_config_obj_none = 0,
    dpp_config_obj_bsta,
    dpp_config_obj_ieee1905,
	dpp_config_obj_fbss_sta,
	dpp_config_obj_fbss_ap,
	dpp_config_obj_backhaul_bss
} dpp_config_obj_type_e;

class ec_ctrl_configurator_t : public ec_configurator_t {
public:
    
	/**!
	 * @brief Constructor for ec_ctrl_configurator_t class.
	 *
	 * Initializes the ec_ctrl_configurator_t object with the provided MAC address and function pointers.
	 *
	 * @param[in] al_mac_addr The AL MAC address as a string.
	 * @param[in] ops Callbacks for this Configurator
	 * @param[in] sec_ctx The security context containing C-signing key, PPK, NAK, and Connector.
	 * @note This constructor initializes the base class ec_configurator_t with the provided parameters.
	 */
	ec_ctrl_configurator_t(const std::string& al_mac_addr, ec_ops_t& ops, ec_persistent_sec_ctx_t sec_ctx, handshake_completed_handler handshake_complete);

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
	bool process_chirp_notification(em_dpp_chirp_value_t* chirp_tlv, uint16_t tlv_len, uint8_t src_al_mac[ETH_ALEN]) override;

	/**
	 * @brief Start the EC configurator onboarding process for an enrollee.
	 *
	 * This function initiates the onboarding process using the provided bootstrapping data.
	 *
	 * @param[in] bootstrapping_data The data to use for onboarding (Parsed DPP URI Data).
	 *
	 * @return bool True if the onboarding process is successful, false otherwise.
	 */
	bool onboard_enrollee(ec_data_t* bootstrapping_data) override;
    
	/**
	 * @brief Handle a proxied encapsulated DPP message TLVs (including chirp value) and direct to 1905 agent.
	 *
	 * This function processes the encapsulated DPP message TLVs and directs them to the 1905 agent.
	 *
	 * @param[in] encap_tlv The 1905 Encap DPP TLV to parse and handle.
	 * @param[in] encap_tlv_len The length of the 1905 Encap DPP TLV.
	 * @param[in] chirp_tlv The DPP Chirp Value TLV to parse and handle (NULL if not present).
	 * @param[in] chirp_tlv_len The length of the DPP Chirp Value TLV (0 if not present).
	 * @param[in] src_al_mac The source AL MAC address of this message
	 *
	 * @return bool True if successful, false otherwise.
	 */
	bool process_proxy_encap_dpp_msg(em_encap_dpp_t *encap_tlv, uint16_t encap_tlv_len, em_dpp_chirp_value_t *chirp_tlv, uint16_t chirp_tlv_len, uint8_t src_al_mac[ETH_ALEN]) override;

	/**
	 * @brief Handle a Direct Encapsulated DPP Message (DPP Message TLV)
	 *
	 * @param[in] dpp_frame The frame parsed from the DPP Message TLV
	 * @param[in] dpp_frame_len The length of the frame from the DPP Message TLV
	 * @param[in] src_mac The source MAC address of the DPP frame
	 *
	 * @return bool True if the frame was processed successfully, false otherwise.
	 */
	bool  process_direct_encap_dpp_msg(uint8_t* dpp_frame, uint16_t dpp_frame_len, uint8_t src_mac[ETH_ALEN]) override;

	/**
	 * @brief Handles a chirp found in an Autoconf Search (extended) message.
	 * 
	 * @param chirp The DPP chirp.
	 * @param len The length of the chirp hash (can be 0).
	 * @param src_mac Where it came from (Enrollee).
	 * @return true on success, otherwise false.
	 * 
	 */
	bool handle_autoconf_chirp(em_dpp_chirp_value_t* chirp, size_t len, uint8_t src_mac[ETH_ALEN]) override;

    
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
	bool handle_auth_response(ec_frame_t *frame, size_t len, uint8_t src_mac[ETHER_ADDR_LEN], uint8_t src_al_mac[ETH_ALEN]) override;

    
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
	bool handle_proxied_dpp_configuration_request(uint8_t *encap_frame, uint16_t encap_frame_len, uint8_t dest_mac[ETH_ALEN], uint8_t src_al_mac[ETH_ALEN]) override;

    
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
	bool handle_proxied_config_result_frame(uint8_t *encap_frame, uint16_t encap_frame_len, uint8_t dest_mac[ETH_ALEN], uint8_t src_al_mac[ETH_ALEN]) override;

    
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
	bool handle_proxied_conn_status_result_frame(uint8_t *encap_frame, uint16_t encap_frame_len, uint8_t dest_mac[ETH_ALEN], uint8_t src_al_mac[ETH_ALEN]) override;

	/**
	 * @brief Handles a Reconfiguration Announcement frame
	 * 
	 * If this Reconfiguration Announcement frame is meant for the Configurator that received it
	 * (determined by comparing the C-sign-key hash attribute to the Configurator's C-sign-key),
	 * then create a Reconfiguration Authentication frame and send to the Enrollee
	 * 
	 * @param frame The Reconfiguration Announcement frame
	 * @param len The length of the frame
	 * @param sa The source address (Enrollee)
	 * @return true on success, otherwise false
	 * 
	 * @note Only implemented by the Controller Configurator
	 */
	bool handle_recfg_announcement(ec_frame_t *frame, size_t len, uint8_t sa[ETH_ALEN], uint8_t src_al_mac[ETH_ALEN]) override;

	/**
	 * @brief Handles a Reconfiguration Authentication Response frame
	 * 
	 * @param frame The proxied encapsulated Reconfiguration Authentication Response frame
	 * @param len The length of the frame
	 * @param sa The source address (Enrollee)
	 * @return true on success, otherwise false
	 */
	bool handle_recfg_auth_response(ec_frame_t *frame, size_t len, uint8_t sa[ETH_ALEN], uint8_t src_al_mac[ETH_ALEN]) override;


	/**
	 * @brief Finalizes a base DPP Configuration object.
	 *
	 * A base configuration object has all mandatory base fields filled out, including keys
	 * "wi-fi_tech", "discovery", and "cred".
	 *
	 * @param[in,out] base The base JSON object to be finalized.
	 * @param[in] config_obj_type The type of DPP Configuration object to fill out.
	 * @param[in] sec_ctx The security context containing the Configurator's keys.
	 * @param[in] enrollee_net_access_key The netAccessKey of the Enrollee, used as the netAccessKey in the new DPP Connector
	 *
	 * @return cJSON* DPP Configuration object on success, nullptr otherwise.
	 */
	static cJSON *finalize_dpp_config_obj(cJSON *base, dpp_config_obj_type_e config_obj_type, ec_persistent_sec_ctx_t* sec_ctx, SSL_KEY* enrollee_net_access_key);

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
	 * @param enrollee_mac The MAC of the Enrollee being Reconfigured
	 * @param fc_group_nid The NID of the Finite Cyclic Group used for generating the C-connector NAK
	 *
	 * @returns A pair consisting of a pointer to the request data and its size.
	 */
	std::pair<uint8_t*, size_t> create_recfg_auth_request(const std::string& enrollee_mac, const int fc_group_nid);
    
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
	 * @param enrollee_dpp_status The DPP status code of the Enrollee encoded in the Connection Status JSON object
	 * @param trans_id The transaction ID for this Reconfiguration session
	 *
	 * @returns A pair consisting of a pointer to a uint8_t array and its size.
	 *
	 * @note Ensure that the enrollee MAC address is valid and the DPP status code is correctly set.
	 */
	std::pair<uint8_t*, size_t> create_recfg_auth_confirm(std::string enrollee_mac, ec_status_code_t dpp_status, ec_status_code_t enrollee_dpp_status, uint8_t trans_id);

    
	/**
	 * @brief Creates a DPP Configuration Response frame, wrapped as an Encap DPP TLV.
	 *
	 * This function generates a DPP Configuration Response frame based on the provided
	 * destination MAC address, dialog token, and DPP status. The frame is encapsulated
	 * as a DPP TLV.
	 *
	 * @param[in] dest_mac The destination MAC address of the Enrollee. This should be
	 *                      an array of ETH_ALEN bytes.
	 * @param[in] pa_al_mac The AL MAC address of Proxy Agent that is being used to onboard the Enrollee.
	 * @param[in] dialog_token The session dialog token for the Enrollee.
	 * @param[in] dpp_status The status of the DPP Configuration. Use DPP_STATUS_OK for
	 *                       success or DPP_STATUS_CONFIGURATION_FAILURE for failure.
	 * @param is_sta Optional parameter to indicate if the frame is for a station (default is false). If this is for a STA being onboarded,
	 * we provide fronthaul BSS information and don't issue a DPP Connector (EasyMesh 5.3.11)
	 *
	 * @return std::pair<uint8_t*, size_t> A pair containing the frame and its length
	 *                                      on success, or nullptr and 0 on failure.
	 *
	 * @note Ensure that the destination MAC address is valid and that the dialog token
	 *       and DPP status are correctly set before calling this function.
	 */
	std::pair<uint8_t*, size_t> create_config_response_frame(uint8_t dest_mac[ETH_ALEN], uint8_t pa_al_mac[ETH_ALEN], const uint8_t dialog_token, ec_status_code_t dpp_status, bool is_sta = false);

	/**
	 * @brief Handles a GAS frame embedded in a Direct Encap DPP Message
	 * 
	 * @param frame The GAS frame
	 * @param len The length of the frame
	 * @param src_mac The origin of the frame
	 * @return true on success otherwise false
	 */
	bool process_direct_encap_dpp_gas_msg(uint8_t* frame, uint16_t len, uint8_t src_mac[ETH_ALEN]);

	/**
	 * @brief Finds the connection context based on the enrollee's bootstrapping key hash instead of MAC address
	 * 
	 * This function searches for a connection context that matches the provided enrollee hash.
	 * 
	 * @param enrollee_hash The hash of the enrollee's bootstrapping key.
	 * @param hash_len The length of the enrollee hash.
	 * @return A pair containing the enrollee MAC address as a string and a pointer to the corresponding connection context.
	 *         If no match is found, returns an empty string and nullptr.
	 */
	std::optional<std::pair<std::string, ec_connection_context_t *>> find_conn_ctx(uint8_t* enrollee_hash, uint8_t hash_len);

	/**
	 * @brief Maps Enrollee MAC (as string) to whether or not the Reconfiguration flow has already begun
	 * 
	 * If we hear a Reconfiguration Announcement frame intended for us, but the Enrollee is already undergoing
	 * Reconfiguration, ignore and discard the frame
	 * 
	 */
	std::unordered_map<std::string, bool> m_currently_undergoing_recfg = {};

	// The Group Master Key (GMK) used to securing the 1905 layer
	std::vector<uint8_t> m_gmk;

};

#endif // EC_CTRL_CONFIGURATOR_H
