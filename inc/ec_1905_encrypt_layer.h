#ifndef EC_1905_ENCRYPT_LAYER_H
#define EC_1905_ENCRYPT_LAYER_H

/*
Specification sections referenced according to:
- IEEE 802.11-REVme/D7.0, August 2024
*/


#include "em_base.h"
#include "ec_ops.h"
#include "ec_crypto.h"
#include "em_crypto.h"
#include "util.h"

#include <map>
#include <vector>
#include <stdexcept>

/**
 * @brief Handler for notifying when a 1905 handshake is completed
 * 
 * @param mac MAC address of the peer
 * @param is_group True if the handshake was for a group key, false for pairwise
 */
using handshake_completed_handler = std::function<void(uint8_t[ETH_ALEN], bool)>;

static const uint8_t EAPOL_KDE_OUI_WFA[3] = {0x50, 0x6F, 0x9A};
static const uint8_t EAPOL_KDE_OUI[3] = {0x00, 0x0F, 0xAC};

class ec_1905_encrypt_layer_t {
public:
    /**
     * @brief Constructs 1905 encryption layer instance
     * @param local_al_mac AL MAC address string for local device
     * @param send_direct_encap_dpp_msg Callback for sending DPP frames
     * @param send_1905_eapol_encap_msg Callback for sending EAPOL frames
     * @throws std::invalid_argument if local_al_mac format is invalid
     */
    ec_1905_encrypt_layer_t(std::string local_al_mac, 
                            send_dir_encap_dpp_func send_direct_encap_dpp_msg,
                            send_1905_eapol_encap_func send_1905_eapol_encap_msg,
                            handshake_completed_handler handshake_complete);
    ~ec_1905_encrypt_layer_t() {};

    /**
     * @brief Configures security parameters for 1905 encryption layer
     * @param c_sign_key C-signing key for connector validation
     * @param net_access_key Network access key for PMK derivation
     * @param connector_1905 Local 1905 connector string
     * @param hash_fn Hash function (SHA-256/384/512)
     * @param gmk Group Master Key (controller only)
     * @return true if parameters validated and configured successfully
     * 
     * @note Validates connector format and configures KCK/KEK sizes based on
     *       hash function per EasyConnect 8.4.2.
     */
    bool set_sec_params(SSL_KEY* c_sign_key, SSL_KEY* net_access_key, std::string connector_1905, const EVP_MD *hash_fn, std::vector<uint8_t> gmk = {});

    /**
     * @brief Handles DPP Peer Discovery Request frames
     * @param frame Received EasyConnect frame
     * @param len Frame length
     * @param src_mac Source MAC address
     * @return true if handled successfully and 4-way handshake initiated
     * 
     * @note Validates connector signature (EC 6.6.2), derives PMK/PMKID (EC 6.6.4),
     *        sends DPP Peer Discovery Response, and initiates 4-way handshake.
     */
    bool handle_peer_disc_req_frame(ec_frame_t *frame, uint16_t len, uint8_t src_mac[ETH_ALEN]);

    /**
     * @brief Handles DPP Peer Discovery Response frames
     * @param frame Received EasyConnect frame
     * @param len Frame length
     * @param src_mac Source MAC address
     * @return true if response processed successfully
     * 
     * @note Validates status, transaction ID, and connector (EC 6.6.2). 
     *       Derives PMK/PMKID (EC 6.6.4) for subsequent handshake.
     */
	bool handle_peer_disc_resp_frame(ec_frame_t *frame, uint16_t len, uint8_t src_mac[ETH_ALEN]);

    /**
     * @brief Routes EAPOL-KEY frames to appropriate handshake handlers
     * @param frame Raw EAPOL frame
     * @param len Frame length
     * @param src_mac Source MAC address
     * @return true if frame processed successfully
     * 
     * @note Determines handshake type (pairwise or group) and delegates to specific frame handlers 
     *       based on key type and current handshake state.
     */
	bool handle_eapol_frame(uint8_t *frame, uint16_t len, uint8_t src_mac[ETH_ALEN]);

    /**
     * @brief Initiates secure 1905 layer establishment with peer
     * @param dest_al_mac Destination AL MAC address
     * @return true if peer discovery request sent successfully
     * 
     * @note Creates and sends DPP Peer Discovery Request to begin security establishment process.
     */
	bool start_secure_1905_layer(uint8_t dest_al_mac[ETH_ALEN]);

    /**
     * @brief Rekeys existing PTK with all established peers

     * @return true if all PTK rekey handshakes initiated successfully
     * 
     * @note Requires existing key contexts. Initiates the same 4-way handshake 
     *       as the initial handshake with some minor flags changed.
     */
    bool rekey_1905_layer_ptk();


    /**
     * @brief Rekeys existing PTK with established peer
     * @param dest_al_mac Destination AL MAC address
     * @return true if PTK rekey handshake initiated successfully
     * 
     * @note Requires existing key context. Initiates the same 4-way handshake 
     *       as the initial handshake with some minor flags changed.
     */
    bool rekey_1905_layer_ptk(uint8_t dest_al_mac[ETH_ALEN]);

    /**
     * @brief Rekeys GTK and distributes to all enrolled agents
     * @return true if GTK regenerated and distributed successfully
     * 
     * @note Controller-only operation. Generates new GTK and sends
     *       to all agents (EM 5.4.7.5) via group key handshake (EM 5.3.7.3)
     */
    bool rekey_1905_layer_gtk();


private:
    // Cryptographic key material
    SSL_KEY* m_C_signing_key = nullptr;
    SSL_KEY* m_net_access_key = nullptr;
    std::string m_connector_1905;
    const EVP_MD *m_hash_fn = nullptr;
    
    // Session context and peer management
    std::map<std::string, ec_1905_key_ctx> m_1905_mac_key_mac;
    std::vector<uint8_t> m_al_mac_addr;
    uint8_t m_transaction_id = 0;
    const uint8_t empty_nonce[SHA256_DIGEST_LENGTH] = {0};
    
    // Group key management (controller only)
    std::vector<uint8_t> m_gmk; // Group Master Key
    uint8_t m_gtk[SHA512_DIGEST_LENGTH];
    uint8_t m_gtk_id; // GTK ID (1-3) (2 bits, cannot include 0, as per EasyMesh Table 12)
    uint64_t m_gtk_rekey_counter = 0;
    
    // Key derivation parameters
    uint16_t mic_kck_bits = 0;
    uint16_t kek_bits = 0;
    
    // Callback functions
    send_dir_encap_dpp_func m_send_dir_encap_dpp_msg;
    send_1905_eapol_encap_func m_send_1905_eapol_encap_msg;
    handshake_completed_handler m_handshake_complete;

    // DPP frame creation
    /**
     * @brief Creates DPP Peer Discovery Request frame
     * @param dest_al_mac Destination AL MAC address
     * @return Pair of frame buffer and length, or {nullptr, 0} on error
     * 
     * @note Caller must free returned buffer.
     */
    std::pair<uint8_t*, size_t> create_peer_disc_req(uint8_t dest_al_mac[ETH_ALEN]);

    /**
     * @brief Creates DPP Peer Discovery Response frame
     * @param dest_mac Destination MAC address
     * @param dpp_status DPP status code (OK, NO_MATCH, INVALID_CONNECTOR)
     * @param trans_id Transaction ID from corresponding request
     * @return Pair of frame buffer and length, or {nullptr, 0} on error
     * 
     * @note Caller must free returned buffer.
     */
    std::pair<uint8_t *, size_t> create_peer_disc_resp(uint8_t dest_mac[ETH_ALEN], ec_status_code_t dpp_status, uint8_t trans_id);

    // Handshake management
    /**
     * @brief Initiates 1905 4-way handshake with established peer
     * @param dest_al_mac Destination AL MAC address
     * @param do_rekey True for PTK rekeying, false for initial handshake
     * @return true if first frame sent successfully
     * 
     * @note Requires existing key context with valid PMK/PMKID. Builds and sends
     *       first EAPOL frame to begin handshake process.
     */
    bool begin_1905_4way_handshake(uint8_t dest_al_mac[ETH_ALEN], bool do_rekey);

    // Cryptographic operations
    /**
     * @brief Computes PMK and PMKID from received connector payload
     * @param recv_conn_payload JSON payload from peer's connector
     * @return Pair of PMK and PMKID vectors, or empty vectors on error
     * 
     * @note Implements EasyConnect 6.6.4 derivation: 
     *       - N = nk * PK
     *       - PMK = HKDF(<>, "DPP PMK", N.x)
     *       - PMKID = Truncate-128(SHA-256(min(NK.x, PK.x) | max(NK.x, PK.x)))
     */
    std::pair<std::vector<uint8_t>,std::vector<uint8_t>> compute_pmk_pmkid(cJSON* recv_conn_payload);

    /**
     * @brief Derives the Pairwise Transient Key (PTK) using the KDF
     *
     * @param algo    The hash algorithm to use (ex: EVP_sha256())
     * @param ctx     The context containing PMK, nonces, and other parameters
     * @param aa      The Authenticator's MAC address
     * @param spa     The Supplicant's MAC address
     *
     * @return bool Returns true if the PTK was successfully derived, false otherwise
     */
    bool  compute_ptk(const EVP_MD *algo, ec_1905_key_ctx &ctx, uint8_t aa[ETH_ALEN], uint8_t spa[ETH_ALEN]);

    /**
     * @brief Derives the Group Transient Key (GTK) using the KDF
     *
     * @param algo    The hash algorithm to use (ex: EVP_sha256())
     * @param aa      The Authenticator's MAC address
     *
     * @return std::vector<uint8_t>  Returns the derived PTK as a vector of bytes
     */
    bool  compute_gtk(const EVP_MD *algo, uint8_t aa[ETH_ALEN]);

    // EAPOL frame builders - 4-way handshake
    /**
     * @brief Builds EAPOL frame 1 for 4-way handshake
     * @param ctx Key context for the peer
     * @return Pair of frame buffer and length, or {nullptr, 0} on error
     * 
     * @note Authenticator frame with ANonce and PMKID KDE. No MIC present.
     */
    std::pair<uint8_t*, size_t> build_pw_eapol_frame_1(ec_1905_key_ctx& ctx);

    /**
     * @brief Builds EAPOL frame 2 for 4-way handshake
     * @param ctx Key context for the peer
     * @return Pair of frame buffer and length, or {nullptr, 0} on error
     * 
     * @note Supplicant response with SNonce and MIC for authentication.
     */
    std::pair<uint8_t*, size_t> build_pw_eapol_frame_2(ec_1905_key_ctx& ctx);

    /**
     * @brief Builds EAPOL frame 3 for 4-way handshake
     * @param ctx Key context for the peer
     * @return Pair of frame buffer and length, or {nullptr, 0} on error
     * 
     * @note Authenticator frame with encrypted 1905 GTK KDE per EasyMesh 5.3.7.3.
     *       Includes install flag and MIC.
     */
    std::pair<uint8_t*, size_t> build_pw_eapol_frame_3(ec_1905_key_ctx& ctx);

    /**
     * @brief Builds EAPOL frame 4 for 4-way handshake
     * @param ctx Key context for the peer
     * @return Pair of frame buffer and length, or {nullptr, 0} on error
     * 
     * @note Final supplicant confirmation frame with MIC. No key data.
     */
    std::pair<uint8_t*, size_t> build_pw_eapol_frame_4(ec_1905_key_ctx& ctx);

    // EAPOL frame builders - group key handshake
    /**
     * @brief Builds EAPOL frame 1 for group key handshake
     * @param ctx Key context for the peer
     * @return Pair of frame buffer and length, or {nullptr, 0} on error
     * 
     * @note Authenticator frame with encrypted 1905 GTK KDE for key distribution.
     */
    std::pair<uint8_t*, size_t> build_group_eapol_frame_1(ec_1905_key_ctx& ctx);

    /**
     * @brief Builds EAPOL frame 2 for group key handshake
     * @param ctx Key context for the peer
     * @return Pair of frame buffer and length, or {nullptr, 0} on error
     * 
     * @note Supplicant acknowledgment frame with MIC. No key data.
     */
    std::pair<uint8_t*, size_t> build_group_eapol_frame_2(ec_1905_key_ctx& ctx);

    // EAPOL frame handlers - 4-way handshake
    /**
     * @brief Handles EAPOL frame 1 in 4-way handshake (supplicant side)
     * @param ctx Key context for the peer
     * @param frame Raw EAPOL frame
     * @param len Frame length
     * @param src_mac Source MAC address
     * @return true if frame processed and response sent successfully
     * 
     * @note Validates replay counter, derives PTK, builds and sends frame 2 per IEEE 802.11 12.7.6.2.
     */
    bool handle_pw_eapol_frame_1(ec_1905_key_ctx& ctx, uint8_t *frame, uint16_t len, uint8_t src_mac[ETH_ALEN]);

    /**
     * @brief Handles EAPOL frame 2 in 4-way handshake (authenticator side)
     * @param ctx Key context for the peer
     * @param frame Raw EAPOL frame
     * @param len Frame length
     * @param src_mac Source MAC address
     * @return true if frame processed and response sent successfully
     * 
     * @note Validates MIC, derives PTK, builds and sends frame 3 per IEEE 802.11 12.7.6.3.
     */
    bool handle_pw_eapol_frame_2(ec_1905_key_ctx& ctx, uint8_t *frame, uint16_t len, uint8_t src_mac[ETH_ALEN]);

    /**
     * @brief Handles EAPOL frame 3 in 4-way handshake (supplicant side)
     * @param ctx Key context for the peer
     * @param frame Raw EAPOL frame
     * @param len Frame length
     * @param src_mac Source MAC address
     * @return true if frame processed and response sent successfully
     * 
     * @note Validates MIC, installs PTK + GTK, builds and sends frame 4 per IEEE 802.11 12.7.6.4.
     */
    bool handle_pw_eapol_frame_3(ec_1905_key_ctx& ctx, uint8_t *frame, uint16_t len, uint8_t src_mac[ETH_ALEN]);

    /**
     * @brief Handles EAPOL frame 4 in 4-way handshake (authenticator side)
     * @param ctx Key context for the peer
     * @param frame Raw EAPOL frame
     * @param len Frame length
     * @param src_mac Source MAC address
     * @return true if frame processed successfully
     * 
     * @note Validates MIC and installs PTK per IEEE 802.11 12.7.6.5. Completes handshake.
     */
    bool handle_pw_eapol_frame_4(ec_1905_key_ctx& ctx, uint8_t *frame, uint16_t len, uint8_t src_mac[ETH_ALEN]);

    // EAPOL frame handlers - group key handshake
    /**
     * @brief Handles EAPOL frame 1 in group key handshake (supplicant side)
     * @param ctx Key context for the peer
     * @param frame Raw EAPOL frame
     * @param len Frame length
     * @param src_mac Source MAC address
     * @return true if frame processed and response sent successfully
     * 
     * @note Validates MIC, installs GTK, builds and sends frame 2 per IEEE 802.11 12.7.7.2.
     */
    bool handle_group_eapol_frame_1(ec_1905_key_ctx& ctx, uint8_t *frame, uint16_t len, uint8_t src_mac[ETH_ALEN]);

    /**
     * @brief Handles EAPOL frame 2 in group key handshake (authenticator side)
     * @param ctx Key context for the peer
     * @param frame Raw EAPOL frame
     * @param len Frame length
     * @param src_mac Source MAC address
     * @return true if frame processed successfully
     * 
     * @note Validates MIC and completes group key handshake per IEEE 802.11 12.7.7.3.
     */
    bool handle_group_eapol_frame_2(ec_1905_key_ctx& ctx, uint8_t *frame, uint16_t len, uint8_t src_mac[ETH_ALEN]);

    // EAPOL utility functions
    /**
     * @brief Validates EAPOL frame structure and extracts packet
     * @param ctx Key context for the peer
     * @param eapol_frame Raw EAPOL frame buffer
     * @param eapol_frame_len Frame length
     * @return Pointer to EAPOL packet structure, or nullptr on error
     * 
     * @note Caller must free returned pointer.
     */
    eapol_packet_t* validate_eapol_frame(ec_1905_key_ctx& ctx, uint8_t* eapol_frame, size_t eapol_frame_len);

    /**
     * @brief Allocates and initializes EAPOL frame structure
     * @param is_mic_present True to allocate space for MIC field
     * @return Pair of frame buffer and size, or {nullptr, 0} on error
     * 
     * @note Caller must free returned buffer.
     */
    std::pair<uint8_t*, size_t> alloc_eapol_frame(bool is_mic_present);

    /**
     * @brief Appends KDE to EAPOL frame key data field
     * @param eapol_frame Existing EAPOL frame buffer
     * @param eapol_frame_size Current frame size
     * @param kde KDE data to append
     * @param kde_len KDE length
     * @param perform_inital_expand True to expand frame size for MIC and key data length field
     * @return Pair of new frame buffer and size, or {nullptr, 0} on error
     * 
     * @note Reallocates frame buffer and updates key data length field.
     */
    std::pair<uint8_t*, size_t> append_key_data_buff(uint8_t* eapol_frame, size_t eapol_frame_size, uint8_t* kde, size_t kde_len, bool perform_inital_expand = false);

    // Cryptographic utilities
    /**
     * @brief Calculates EAPOL-Key MIC for frame authentication
     * @param ctx Key context containing PTK-KCK
     * @param eapol_frame EAPOL frame buffer
     * @param eapol_frame_size Frame size
     * @return MIC vector, or empty vector on error
     */
    std::vector<uint8_t> calculate_mic(ec_1905_key_ctx &ctx, uint8_t* eapol_frame, size_t eapol_frame_size);

    /**
     * @brief Verifies EAPOL frame MIC for authentication
     * @param ctx Key context containing PTK-KCK
     * @param eapol_frame EAPOL frame buffer
     * @param eapol_frame_size Frame size
     * @return true if MIC verification successful
     */
    bool verify_mic(ec_1905_key_ctx &ctx, uint8_t *eapol_frame, size_t eapol_frame_size);

    /**
     * @brief Encrypts key data using NIST AES Key Wrap
     * @param ctx Key context containing PTK-KEK
     * @param key_data_plain Plaintext key data
     * @param key_data_len Key data length
     * @return Pair of encrypted buffer and size, or {nullptr, 0} on error
     * 
     * @note Applies padding per IEEE 802.11 12.7.2j before encryption.
     */
    std::pair<uint8_t*, size_t> encrypt_key_data(ec_1905_key_ctx& ctx, uint8_t* key_data_plain, size_t key_data_len);

    /**
     * @brief Decrypts key data using NIST AES Key Unwrap
     * @param ctx Key context containing PTK-KEK
     * @param wrapped_key_data Encrypted key data
     * @param key_data_len Encrypted data length
     * @return Pair of decrypted buffer and size, or {nullptr, 0} on error
     * 
     * @note Caller must free returned buffer
     */
    std::pair<uint8_t*, size_t> decrypt_key_data(ec_1905_key_ctx& ctx, uint8_t* wrapped_key_data, size_t key_data_len);

    // Key installation
    /*
    MLME-SETKEYS.request primitive: 6.5.14.1.2
    */
    bool set_key(uint8_t* key, size_t key_len, uint16_t key_id, bool is_pairwise, uint8_t mac[ETH_ALEN], uint64_t recv_seq_counter);
};

#endif // EC_1905_ENCRYPT_LAYER_H