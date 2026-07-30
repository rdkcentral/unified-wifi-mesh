#ifndef EC_CRYPTO_H
#define EC_CRYPTO_H

#include "em_base.h"
#include "ec_base.h"
#include "em_crypto.h"

#include <utility>
#include <memory>
#include <vector>
#include <optional>
#include <string>
#include <cstring>
#include <unordered_map>

// forward decl
struct cJSON;

namespace easyconnect {


    // Custom deleter for uint8_t arrays
    struct byte_arr_deleter {
        void operator()(uint8_t* p) const { delete[] p; }
    };
    
    // Define a smart pointer type for buffers
    using buff_ptr = ::std::unique_ptr<uint8_t[], byte_arr_deleter>;
    
    // Define easyconnect::hash_buffer_t as a vector of smart pointer/length pairs
    using hash_buffer_t = std::vector<std::pair<buff_ptr, size_t>>;

}

class ec_crypto {
public:

    
	/**!
	 * @brief Derives a key using the HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
	 *
	 * This function performs key derivation using the specified hash function and input keying material (IKM).
	 *
	 * @param[in] h The hash function to use for HKDF.
	 * @param[in] skip_extract A boolean flag indicating whether to skip the extract phase.
	 * @param[in] ikm Pointer to the input keying material.
	 * @param[in] ikmlen Length of the input keying material.
	 * @param[in] salt Pointer to the optional salt value.
	 * @param[in] saltlen Length of the salt value.
	 * @param[in] info Pointer to the optional context and application specific information.
	 * @param[in] infolen Length of the context and application specific information.
	 * @param[out] okm Pointer to the buffer where the output keying material will be stored.
	 * @param[in] okmlen Length of the output keying material to be generated.
	 *
	 * @returns The size of the derived key material.
	 *
	 * @note This function is designed to be used in cryptographic applications where key derivation is required.
	 */
	static size_t hkdf(const EVP_MD *h, bool skip_extract, uint8_t *ikm, size_t ikmlen, 
        uint8_t *salt, size_t saltlen, uint8_t *info, size_t infolen, 
        uint8_t *okm, size_t okmlen);


    
	/**
	 * @brief Compute the hash of the provided key with an optional prefix.
	 *
	 * This function computes the hash of a given key, optionally prepending a prefix to the key before hashing.
	 *
	 * @param[in] key The key to hash.
	 * @param[in] prefix The optional prefix to add to the key before hashing. Defaults to NULL if not provided.
	 * @return uint8_t* A pointer to the buffer containing the computed hash.
	 *
	 * @note The caller is responsible for freeing the returned hash buffer.
	 */
	static uint8_t* compute_key_hash(const SSL_KEY *key, const char *prefix = NULL);
    
    
	/**
	 * @brief Initialize the persistent context parameters using the bootstrapping key's group as a basis.
	 *
	 * @param[out] c_ctx The persistent context to initialize.
	 * @param[in] boot_key The bootstrapping key to use as a basis.
	 *
	 * @return bool True if successful, false otherwise.
	 */
	static bool init_connection_ctx(ec_connection_context_t& c_ctx, const SSL_KEY *boot_key);

	/**
	 * @brief Compute the hash of the provided buffer
	 *
	 * This function takes a buffer of elements and computes its hash using the
	 * specified connection context.
	 *
	 * @param[in] hash_fn The hash function to use for hashing
	 * @param[in] digest_len The length of the hash digest to compute
	 * @param[in] hashing_elements_buffer The buffer containing elements to hash
	 *
	 * @return uint8_t* Pointer to the computed hash of the buffer
	 *
	 * @note The caller is responsible for managing the memory of the returned hash.
	 */
	static uint8_t* compute_hash(const EVP_MD *hash_fn, size_t digest_len, const easyconnect::hash_buffer_t& hashing_elements_buffer);
	
	/**
	 * @brief Compute the hash of the provided buffer
	 *
	 * This function takes a buffer of elements and computes its hash using the
	 * specified connection context.
	 *
	 * @param[in] c_ctx The connection context used for hashing
	 * @param[in] hashing_elements_buffer The buffer containing elements to hash
	 *
	 * @return uint8_t* Pointer to the computed hash of the buffer
	 *
	 * @note The caller is responsible for managing the memory of the returned hash.
	 */
	static uint8_t* compute_hash(ec_connection_context_t& c_ctx, const easyconnect::hash_buffer_t& hashing_elements_buffer);


    
	/**!
	 * @brief Computes the key exchange value.
	 *
	 * This function calculates the key exchange (KE) value using the provided connection and ephemeral contexts.
	 *
	 * @param[in] c_ctx The connection context used for the computation.
	 * @param[in] e_ctx Pointer to the ephemeral context used for the computation.
	 * @param[out] ke_buffer Buffer where the computed key exchange value will be stored.
	 *
	 * @returns The size of the computed key exchange value.
	 *
	 * @note Ensure that the ke_buffer is properly allocated to hold the resulting key exchange value.
	 */
	static size_t compute_ke(ec_connection_context_t& c_ctx, ec_ephemeral_context_t* e_ctx, uint8_t *ke_buffer);

    
	/**
	 * @brief Abstracted HKDF computation that handles both simple and complex inputs.
	 *
	 * This function provides a unified interface for HKDF computations, handling both
	 * simple single-input operations and more complex operations with multiple inputs.
	 * It properly formats BIGNUMs with appropriate padding based on prime length.
	 *
	 * @param[in] c_ctx The connection context used for the computation.
	 * @param[out] key_out Buffer to store the output key (must be pre-allocated).
	 * @param[in] key_out_len Length of the output key.
	 * @param[in] info_str Information string for HKDF.
	 * @param[in] x_val_inputs Array of BIGNUMs to use as IKM.
	 * @param[in] x_val_count Number of BIGNUMs in the array.
	 * @param[in] raw_salt Raw salt buffer (can be NULL).
	 * @param[in] raw_salt_len Length of raw salt buffer.
	 *
	 * @returns Length of the output key on success, 0 on failure.
	 *
	 * @note Ensure that the key_out buffer is sufficiently large to hold the output key.
	 */
	static size_t compute_hkdf_key(ec_connection_context_t& c_ctx, uint8_t *key_out, size_t key_out_len, const char *info_str,
        const BIGNUM **x_val_inputs, int x_val_count, 
        uint8_t *raw_salt, size_t raw_salt_len);

	/**
	 * @brief Abstracted HKDF computation that handles both simple and complex inputs.
	 *
	 * This function provides a unified interface for HKDF computations, handling both
	 * simple single-input operations and more complex operations with multiple inputs.
	 * It properly formats BIGNUMs with appropriate padding based on prime length.
	 *
	 * @param[in] prime The prime number used for padding and formatting BIGNUMs.
	 * @param[in] hash_fn The hash function to use for HKDF.
	 * @param[out] key_out Buffer to store the output key (must be pre-allocated).
	 * @param[in] key_out_len Length of the output key.
	 * @param[in] info_str Information string for HKDF.
	 * @param[in] x_val_inputs Array of BIGNUMs to use as IKM.
	 * @param[in] x_val_count Number of BIGNUMs in the array.
	 * @param[in] raw_salt Raw salt buffer (can be NULL).
	 * @param[in] raw_salt_len Length of raw salt buffer.
	 *
	 * @returns Length of the output key on success, 0 on failure.
	 *
	 * @note Ensure that the key_out buffer is sufficiently large to hold the output key.
	 */
	static size_t compute_hkdf_key(const BIGNUM* prime, const EVP_MD * hash_fn, uint8_t *key_out, size_t key_out_len, const char *info_str,
        const BIGNUM **x_val_inputs, int x_val_count, 
        uint8_t *raw_salt, size_t raw_salt_len);


	/**!
	 * @brief Calculates the x-coordinate of L = ((b_R + p_R) modulo q) * B_I.
	 *
	 * This function performs elliptic curve calculations to derive the x-coordinate
	 * of the point L, which is computed using the provided keys and elliptic curve group.
	 *
	 * @param[in] c_ctx The connection context containing the elliptic curve group.
	 * @param[in] bR Private Responder Bootstrapping Key.
	 * @param[in] pR Private Responder Protocol Key.
	 * @param[in] BI Public Initiator Bootstrapping Key.
	 *
	 * @returns BIGNUM* The calculated x-coordinate of the L point, or NULL on failure.
	 * Caller must free the returned BIGNUM with BN_free().
	 *
	 * @note Ensure that the elliptic curve group in c_ctx is properly initialized
	 * before calling this function.
	 */
	static BIGNUM* calculate_Lx(ec_connection_context_t& c_ctx, const BIGNUM* bR, const BIGNUM* pR, const EC_POINT* BI);

	/**!
	 * @brief Retrieves the x and y coordinates of an elliptic curve point.
	 *
	 * This function extracts the affine coordinates (x, y) of a given elliptic curve point and group
	 *
	 * @param[in] group The group of the elliptic curve where the point is located
	 * @param[in] point The elliptic curve point from which to extract the coordinates.
	 *
	 * @returns A pair of BIGNUM pointers representing the x and y coordinates.
	 * @retval std::pair<BIGNUM *, BIGNUM *> A pair containing the x and y coordinates if successful.
	 * @retval std::pair<BIGNUM *, BIGNUM *> An empty pair if the point is null or if the coordinates cannot be retrieved.
	 *
	 * @note The caller is responsible for freeing the BIGNUM pointers returned in the pair.
	 */
	static std::pair<BIGNUM *, BIGNUM *> get_ec_x_y(const EC_GROUP* group, const EC_POINT *point, BN_CTX *bn_ctx = NULL) {
        if (!point) return {};
		if (!group) return {};

        BIGNUM *x = BN_new(), *y = BN_new();
        if (EC_POINT_get_affine_coordinates(group, point,
            x, y, bn_ctx) == 0) {
            printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
            BN_free(x);
            BN_free(y);
            return {};
        }
        return {x, y};
    }

	/**!
	 * @brief Retrieves the X coordinate of an elliptic curve point.
	 *
	 * This function extracts the X coordinate from the given elliptic curve point
	 * using the provided connection context.
	 *
	 * @param[in] group The elliptic curve group to which the point belongs.
	 * @param[in] point The elliptic curve point from which to retrieve the X coordinate.
	 *
	 * @returns A pointer to a BIGNUM representing the X coordinate of the elliptic curve point.
	 *
	 * @note The Y coordinate is freed after extraction.
	 */
	static inline BIGNUM* get_ec_x(const EC_GROUP* group, const EC_POINT *point, BN_CTX *bn_ctx = NULL) {
        auto [x, y] = get_ec_x_y(group, point, bn_ctx);
        BN_free(y);
        return x;
    }

	/**!
	 * @brief Retrieves the Y coordinate of an elliptic curve point.
	 *
	 * This function extracts the Y coordinate from a given elliptic curve point
	 * using the provided connection context.
	 *
	 * @param[in] group The elliptic curve group to which the point belongs.
	 * @param[in] point The elliptic curve point from which the Y coordinate is extracted.
	 *
	 * @returns A pointer to a BIGNUM representing the Y coordinate of the point.
	 *
	 * @note The caller is responsible for managing the memory of the returned BIGNUM and The X coordinate is freed after extraction.
	 */
	static inline BIGNUM* get_ec_y(const EC_GROUP* group, const EC_POINT *point, BN_CTX *bn_ctx = NULL) {
        auto [x, y] = get_ec_x_y(group, point, bn_ctx);
        BN_free(x);
        return y;
    }

	/**!
	 * @brief Retrieves the x and y coordinates of an elliptic curve point.
	 *
	 * This function extracts the affine coordinates (x, y) of a given elliptic curve point.
	 *
	 * @param[in] c_ctx The elliptic curve connection context containing the group and BN context.
	 * @param[in] point The elliptic curve point from which to extract the coordinates.
	 *
	 * @returns A pair of BIGNUM pointers representing the x and y coordinates.
	 * @retval std::pair<BIGNUM *, BIGNUM *> A pair containing the x and y coordinates if successful.
	 * @retval std::pair<BIGNUM *, BIGNUM *> An empty pair if the point is null or if the coordinates cannot be retrieved.
	 *
	 * @note The caller is responsible for freeing the BIGNUM pointers returned in the pair.
	 */
	static std::pair<BIGNUM *, BIGNUM *> get_ec_x_y(ec_connection_context_t& c_ctx, const EC_POINT *point) {
        return get_ec_x_y(c_ctx.group, point, c_ctx.bn_ctx);
    }
    
	/**!
	 * @brief Retrieves the X coordinate of an elliptic curve point.
	 *
	 * This function extracts the X coordinate from the given elliptic curve point
	 * using the provided connection context.
	 *
	 * @param[in] c_ctx The elliptic curve connection context.
	 * @param[in] point The elliptic curve point from which to retrieve the X coordinate.
	 *
	 * @returns A pointer to a BIGNUM representing the X coordinate of the elliptic curve point.
	 *
	 * @note The Y coordinate is freed after extraction.
	 */
	static inline BIGNUM* get_ec_x(ec_connection_context_t& c_ctx, const EC_POINT *point) {
        return get_ec_x(c_ctx.group, point, c_ctx.bn_ctx);
    }
    
	/**!
	 * @brief Retrieves the Y coordinate of an elliptic curve point.
	 *
	 * This function extracts the Y coordinate from a given elliptic curve point
	 * using the provided connection context.
	 *
	 * @param[in] c_ctx The elliptic curve connection context used for the operation.
	 * @param[in] point The elliptic curve point from which the Y coordinate is extracted.
	 *
	 * @returns A pointer to a BIGNUM representing the Y coordinate of the point.
	 *
	 * @note The caller is responsible for managing the memory of the returned BIGNUM and The X coordinate is freed after extraction.
	 */
	static inline BIGNUM* get_ec_y(ec_connection_context_t& c_ctx, const EC_POINT *point) {
        return get_ec_y(c_ctx.group, point, c_ctx.bn_ctx);
    }

    
	/**!
	 * @brief Converts a BIGNUM to a vector of bytes.
	 *
	 * This function takes a BIGNUM and converts it into a vector of bytes in
	 * big-endian order.
	 *
	 * @param[in] bn Pointer to the BIGNUM to be converted.
	 *
	 * @returns A vector of bytes representing the BIGNUM in big-endian order.
	 * @retval An empty vector if the input BIGNUM is null.
	 *
	 * @note Ensure that the BIGNUM is not null before calling this function.
	 */
	static std::vector<uint8_t> BN_to_vec(const BIGNUM *bn) {
        if (!bn) return {};

        int num_bytes = BN_num_bytes(bn);
        
		std::vector<uint8_t> buffer(static_cast<size_t>(num_bytes));
    
        BN_bn2bin(bn, buffer.data()); // Convert BIGNUM to big-endian byte array
        return buffer;
    }

	/**
	 * @brief Converts a vector of bytes to a BIGNUM.
	 * 
	 * This function takes a vector of bytes and converts it into a BIGNUM.
	 * The bytes are interpreted as a big-endian integer.
	 * 
	 * @param[in] vec The vector of bytes to convert.
	 * @return BIGNUM* A pointer to the newly created BIGNUM, or NULL on failure.
	 *
	 * @note The caller is responsible for freeing the returned BIGNUM with BN_free().
	 */
	static BIGNUM* vec_to_BN(const std::vector<uint8_t>& vec) {
		if (vec.empty()) return NULL;

		BIGNUM *bn = BN_new();
		if (!bn) return NULL;

		if (BN_bin2bn(vec.data(), static_cast<int>(vec.size()), bn) == NULL) {
			BN_free(bn);
			return NULL;
		}
		return bn;
	}
    
	/**
	 * @brief Encode an EC point into a protocol key buffer.
	 *
	 * This function encodes an elliptic curve (EC) point into a protocol key buffer.
	 *
	 * @param[in] c_ctx The persistent context containing the EC group.
	 * @param[in] point The EC point to encode.
	 *
	 * @return scoped_buff The encoded protocol key buffer, or NULL on failure.
	 *
	 * @note The caller must free the returned buffer with free().
	 */
	static scoped_buff encode_ec_point(ec_connection_context_t& c_ctx, const EC_POINT *point);

	/**
	 * @brief Encode an EC point into a protocol key buffer.
	 * 
	 * This function encodes an elliptic curve (EC) point into a protocol key buffer.
	 * 
	 * @param group The EC group defining the elliptic curve.
	 * @param point The EC point to encode.
	 * @param prime The prime number defining the field of the elliptic curve, if NULL will be derived from the group.
	 * @param bn_ctx The BN context to use for encoding (optional, can be NULL).
	 * @return scoped_buff 
	 */
	static scoped_buff encode_ec_point(const EC_GROUP* group, const EC_POINT *point, const BIGNUM* prime = NULL, BN_CTX* bn_ctx = NULL);
    
	/**!
	 * @brief Decode a protocol key buffer into an EC point
	 *
	 * @param[in] c_ctx The persistent context containing the EC group
	 * @param[in] protocol_key_buff The encoded protocol key buffer
	 * @return EC_POINT* The decoded EC point, or NULL on failure. Caller must free with EC_POINT_free()
	 */
	static EC_POINT* decode_ec_point(ec_connection_context_t& c_ctx, const uint8_t* protocol_key_buff);


	/**!
	 * @brief Decode a protocol key buffer into an EC point
	 *
	 * @param[in] group The EC group defining the elliptic curve
	 * @param[in] key_buff The encoded protocol key buffer
	 * @param[in] bn_ctx The BN context to use for decoding (optional, can be NULL)
	 * @return EC_POINT* The decoded EC point, or NULL on failure. Caller must free with EC_POINT_free()
	 */
	static EC_POINT* decode_ec_point(const EC_GROUP* group, const uint8_t *key_buff, BN_CTX* bn_ctx = NULL);
    
	/**
	 * @brief Compute the shared secret X coordinate for an EC key pair.
	 *
	 * This function calculates the X coordinate of the shared secret using
	 * the provided private and public keys.
	 *
	 * @param[in] c_ctx The EC connection context containing the group and bn_ctx.
	 * @param[in] priv The private key (for example p_I, p_R, or b_R).
	 * @param[in] pub The public key (for example P_I, B_R, or P_R).
	 *
	 * @return BIGNUM* The X coordinate of the shared secret, or NULL on failure.
	 * Caller must free with BN_free().
	 *
	 * @note Ensure that the EC connection context is properly initialized
	 * before calling this function.
	 */
	static inline BIGNUM* compute_ec_ss_x(const EC_GROUP* group, const BIGNUM* priv, const EC_POINT* pub, BN_CTX* bn_ctx = NULL) {
        EC_POINT *ss = EC_POINT_new(group);
        if (EC_POINT_mul(group, ss, NULL, pub, priv, bn_ctx) == 0) {
            printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
            return NULL;
        }
        return get_ec_x(group, ss, bn_ctx);
    }

	/**
	 * @brief Compute the shared secret X coordinate for an EC key pair.
	 *
	 * This function calculates the X coordinate of the shared secret using
	 * the provided private and public keys.
	 *
	 * @param[in] c_ctx The EC connection context containing the group and bn_ctx.
	 * @param[in] priv The private key (for example p_I, p_R, or b_R).
	 * @param[in] pub The public key (for example P_I, B_R, or P_R).
	 *
	 * @return BIGNUM* The X coordinate of the shared secret, or NULL on failure.
	 * Caller must free with BN_free().
	 *
	 * @note Ensure that the EC connection context is properly initialized
	 * before calling this function.
	 */
	static inline BIGNUM* compute_ec_ss_x(ec_connection_context_t& c_ctx, const BIGNUM* priv, const EC_POINT* pub) {
        if (!c_ctx.group) return NULL;
		if (!priv || !pub) return NULL;

		return compute_ec_ss_x(c_ctx.group, priv, pub, c_ctx.bn_ctx);
    }

	/**
	* @brief Generate a protocol key pair for the given EC curve.
	*
	* This function generates a key pair consisting of a private and a public key for the specified
	* elliptic curve context.
	*
	* @param[in] c_ctx The persistent context containing the EC curve.
	*
	* @return std::pair<const BIGNUM*, const EC_POINT*>
	* A pair containing both the private and public keys.
	*
	* @retval NULL on failure.
	*
	* @warning The caller must free the BIGNUM and EC_POINT with BN_free() and EC_POINT_free() respectively.
	*/
	static std::pair<const BIGNUM*, const EC_POINT*> generate_proto_keypair(ec_connection_context_t& c_ctx);

        
	/**!
	 * @brief Add a buffer to the hash elements.
	 *
	 * Copies data given into a new temporary buffer. Modifications to the original data will not affect the hash elements.
	 *
	 * @param[out] buffer The hash buffer to which the data will be added.
	 * @param[in] data Pointer to the data to be copied into the hash buffer.
	 * @param[in] len The length of the data to be copied.
	 *
	 * @note Ensure that the data pointer is not null before calling this function.
	 */
	static inline void add_to_hash(easyconnect::hash_buffer_t& buffer, const uint8_t* data, size_t len) {
        if (data != nullptr) {
            // Create a copy of the data with the correct deleter
            easyconnect::buff_ptr data_copy(new uint8_t[len]);
            memcpy(data_copy.get(), data, len);
            buffer.emplace_back(std::move(data_copy), len);
        }
    }

    
	/**!
	 * @brief Adds data to the hash buffer.
	 *
	 * This function adds the specified data to the given hash buffer.
	 *
	 * @param[out] buffer The hash buffer to which data will be added.
	 * @param[in] data Pointer to the data to be added to the hash buffer.
	 * @param[in] len Length of the data to be added.
	 *
	 * @note This function is an inline wrapper that casts the length to size_t.
	 */
	static inline void add_to_hash(easyconnect::hash_buffer_t& buffer, const uint8_t* data, uint16_t len) {
        add_to_hash(buffer, data, static_cast<size_t>(len));
    }

    
	/**!
	 * @brief Add a BIGNUM to the hash elements.
	 *
	 * This function takes a BIGNUM and adds its binary representation to the hash buffer.
	 *
	 * @param[out] buffer The hash buffer where the BIGNUM data will be added.
	 * @param[in] bn The BIGNUM to be added to the hash buffer. If nullptr, the function does nothing.
	 *
	 * @note The function allocates memory for the BIGNUM data and moves it into the buffer.
	 */
	static inline void add_to_hash(easyconnect::hash_buffer_t& buffer, const BIGNUM* bn) {
        if (bn != nullptr) {
            // Allocate memory for BIGNUM data
            int bn_size = BN_num_bytes(bn);
            easyconnect::buff_ptr bn_buf(new uint8_t[bn_size]);
            int bn_len = BN_bn2bin(bn, bn_buf.get());
            
            // Add to hash elements
            buffer.emplace_back(std::move(bn_buf), bn_len);
        }
    }

    
	/**
	 * @brief Add a single octet to the hash elements.
	 *
	 * This function adds a single byte (octet) to the hash buffer.
	 *
	 * @param[out] buffer The hash buffer to which the octet will be added.
	 * @param[in] octet The octet to be added to the hash buffer.
	 *
	 * @note This function uses a smart pointer to manage the memory of the octet.
	 */
	static inline void add_to_hash(easyconnect::hash_buffer_t& buffer, uint8_t octet) {
        easyconnect::buff_ptr octet_buf(new uint8_t[1]);
        octet_buf[0] = octet;
        
        buffer.emplace_back(std::move(octet_buf), 1);
    }


    
	/**
	 * @brief Get the TLS group ID from an NID.
	 *
	 * This function retrieves the TLS group ID corresponding to a given NID (Numerical Identifier).
	 *
	 * Reference: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
	 *
	 * @param[in] nid The NID to get the ID from.
	 *
	 * @return uint16_t The TLS group ID, or UINT16_MAX if the group is unknown or unsupported.
	 */
	static inline uint16_t get_tls_group_id_from_nid(int nid) {

        switch (nid) {
            case NID_X9_62_prime256v1:  /* same as NID_secp256r1 */
                return 23;  /* secp256r1 (NIST P-256) */
            case NID_secp384r1:
                return 24;  /* secp384r1 (NIST P-384) */
            case NID_secp521r1:
                return 25;  /* secp521r1 (NIST P-521) */
            case NID_X9_62_prime192v1:  /* same as NID_secp192r1 */
                return 19;  /* secp192r1 */
            case NID_secp224r1:
                return 21;  /* secp224r1 */
            case NID_brainpoolP256r1:
                return 26;  /* brainpoolP256r1 */
            case NID_brainpoolP384r1:
                return 27;  /* brainpoolP384r1 */
            case NID_brainpoolP512r1:
                return 28;  /* brainpoolP512r1 */
            case NID_X25519:
                return 29;  /* x25519 */
            case NID_X448:
                return 30;  /* x448 */
            default:
                return UINT16_MAX;  /* Unknown or unsupported curve */
        }
    }

    
	/**
	 * @brief Get the TLS group ID from an EC_GROUP.
	 *
	 * This function retrieves the TLS group ID associated with a given EC_GROUP.
	 *
	 * Reference: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
	 *
	 * @param[in] group The EC_GROUP to get the ID from.
	 *
	 * @return uint16_t The TLS group ID, or UINT16_MAX if the group is unknown or unsupported.
	 */
	static inline uint16_t get_tls_group_id_from_ec_group(const EC_GROUP *group) {
        int nid = EC_GROUP_get_curve_name(group);
        
        return get_tls_group_id_from_nid(nid);
    }

	/**
	 * @brief Get the OpenSSL nid for a given TLS group ID.
	 * 
	 * Reference: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
	 * 
	 * @param tls_group_id The TLS group ID to get the EC_GROUP for.
	 * 
	 * @return int The OpenSSL nid corresponding to the TLS group ID, or NID_undef if the group is unknown or unsupported.
	 */
	static inline int get_nid_from_tls_group_id(uint16_t tls_group_id) {
		switch (tls_group_id) {
			case 23:  /* secp256r1 (NIST P-256) */
				return NID_X9_62_prime256v1;
			case 24:  /* secp384r1 (NIST P-384) */
				return NID_secp384r1;
			case 25:  /* secp521r1 (NIST P-521) */
				return NID_secp521r1;
			case 19:  /* secp192r1 */
				return NID_X9_62_prime192v1;
			case 21:  /* secp224r1 */
				return NID_secp224r1;
			case 26:  /* brainpoolP256r1 */
				return NID_brainpoolP256r1;
			case 27:  /* brainpoolP384r1 */
				return NID_brainpoolP384r1;
			case 28:  /* brainpoolP512r1 */
				return NID_brainpoolP512r1;
			case 29:  /* x25519 */
				return NID_X25519;
			case 30:  /* x448 */
				return NID_X448;
			default:
				return NID_undef;
		}
	}

    
	/**!
	 * @brief Prints the given big number.
	 *
	 * This function takes a BIGNUM pointer and prints its value.
	 *
	 * @param[in] bn Pointer to the BIGNUM to be printed.
	 *
	 * @note Ensure that the BIGNUM pointer is not null before calling this function.
	 */
	static void print_bignum (BIGNUM *bn);
    
	/**!
	 * @brief Prints an elliptic curve point.
	 *
	 * This function outputs the details of an elliptic curve point using the specified group and context.
	 *
	 * @param[in] group The elliptic curve group to which the point belongs.
	 * @param[in] bnctx A BN_CTX structure used for temporary variables.
	 * @param[in] point The elliptic curve point to be printed.
	 *
	 * @note Ensure that the group and point are properly initialized before calling this function.
	 */
	static void print_ec_point (const EC_GROUP *group, BN_CTX *bnctx, EC_POINT *point);

    
	/**!
	 * @brief Securely frees a buffer after zeroing its contents.
	 *
	 * This function ensures that the buffer is zeroed out before being freed to prevent any sensitive data from being left in memory.
	 *
	 * @param[in,out] buff Pointer to the buffer to be zeroed and freed.
	 * @param[in] len Length of the buffer in bytes.
	 *
	 * @note If `buff` is NULL, the function returns immediately without performing any operations.
	 */
	static inline void rand_zero_free(uint8_t *buff, size_t len) {
        if (buff == NULL) return;
        RAND_bytes(buff, static_cast<int>(len));
        memset(buff, 0, len);
        free(buff);
    };


	/**!
	 * @brief Securely frees a C string after zering its contents
	 *
	 * This function ensures that the buffer is zeroed out before being freed to prevent any sensitive data from being left in memory.
	 *
	 * @param[in,out] str Pointer to the string to be zeroed and freed.
	 *
	 * @note If `buff` is NULL, the function returns immediately without performing any operations.
	 */
	static inline void rand_zero_free(const char* str) {
		if (str == NULL) return;
        rand_zero_free(const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(str)), strlen(str));
    };

    
	/**!
	 * @brief Sets the buffer to zero after filling it with random bytes.
	 *
	 * This function fills the provided buffer with random bytes and then
	 * sets the entire buffer to zero.
	 *
	 * @param[out] buff Pointer to the buffer that will be filled with random bytes.
	 * @param[in] len Size of the buffer.
	 *
	 * @note If the buffer is NULL, the function returns immediately without
	 * performing any operations.
	 */
	static inline void rand_zero(uint8_t *buff, size_t len) {
        if (buff == NULL) return;
        RAND_bytes(buff, static_cast<int>(len));
        memset(buff, 0, len);
    };

    
	/**
	 * @brief Free an ephemeral context by randomizing, zeroing, and freeing all memory.
	 *
	 * This function does not attempt to free the `ctx` pointer which may be statically allocated.
	 *
	 * @param[in,out] ctx The ephemeral context to free. Must not be null.
	 * @param[in] nonce_len The length of the nonces in the context.
	 * @param[in] digest_len The length of the digests/keys in the context.
	 *
	 * @note This function ensures that all sensitive data is securely erased before freeing.
	 */
	static inline void free_ephemeral_context(ec_ephemeral_context_t* ctx, uint16_t nonce_len, uint16_t digest_len) {

        if (!ctx) return;

        if (ctx->public_init_proto_key) EC_POINT_free(ctx->public_init_proto_key);
        if (ctx->public_resp_proto_key) EC_POINT_free(ctx->public_resp_proto_key);
        if (ctx->priv_init_proto_key) BN_free(ctx->priv_init_proto_key);
        if (ctx->priv_resp_proto_key) BN_free(ctx->priv_resp_proto_key);
        if (ctx->E_Id) EC_POINT_free(ctx->E_Id);
        if (ctx->m) BN_free(ctx->m);
        if (ctx->n) BN_free(ctx->n);
        if (ctx->l) BN_free(ctx->l);
        if (ctx->i_nonce) rand_zero_free(ctx->i_nonce, static_cast<size_t> (nonce_len));
        if (ctx->r_nonce) rand_zero_free(ctx->r_nonce, static_cast<size_t> (nonce_len));
        if (ctx->e_nonce) rand_zero_free(ctx->e_nonce, static_cast<size_t> (nonce_len));
        if (ctx->c_nonce) rand_zero_free(ctx->c_nonce, static_cast<size_t> (nonce_len));
        if (ctx->k1) rand_zero_free(ctx->k1, static_cast<size_t> (digest_len));
        if (ctx->k2) rand_zero_free(ctx->k2, static_cast<size_t> (digest_len));
        if (ctx->ke) rand_zero_free(ctx->ke, static_cast<size_t> (digest_len));
        if (ctx->bk) rand_zero_free(ctx->bk, static_cast<size_t> (digest_len));
        if (ctx->net_access_key) em_crypto_t::free_key(ctx->net_access_key);

        rand_zero(reinterpret_cast<uint8_t*>(ctx), sizeof(ec_ephemeral_context_t));
    }

    
	/**!
	 * @brief Frees the resources associated with the given connection context.
	 *
	 * This function releases all allocated memory and cryptographic keys
	 * associated with the provided `ec_connection_context_t` structure.
	 *
	 * @param[in] ctx Pointer to the connection context to be freed.
	 * If `ctx` is NULL, the function returns immediately.
	 *
	 * @note This function ensures that all sensitive data is zeroed out
	 * before freeing the memory to prevent any potential data leakage.
	 */
	static inline void free_connection_ctx(ec_connection_context_t* ctx) {
        if (!ctx) return;

		free_ephemeral_context(&ctx->eph_ctx, ctx->nonce_len, ctx->digest_len);

        if (ctx->boot_data.resp_pub_boot_key) EC_POINT_free(ctx->boot_data.resp_pub_boot_key);
        if (ctx->boot_data.init_pub_boot_key) EC_POINT_free(ctx->boot_data.init_pub_boot_key);
        if (ctx->boot_data.resp_priv_boot_key) BN_free(ctx->boot_data.resp_priv_boot_key);
        if (ctx->boot_data.init_priv_boot_key) BN_free(ctx->boot_data.init_priv_boot_key);
        if (ctx->boot_data.responder_boot_key) em_crypto_t::free_key(const_cast<SSL_KEY*>(ctx->boot_data.responder_boot_key));
        if (ctx->boot_data.initiator_boot_key) em_crypto_t::free_key(const_cast<SSL_KEY*>(ctx->boot_data.initiator_boot_key));

        if (ctx->group) EC_GROUP_free(const_cast<EC_GROUP*>(ctx->group));
        if (ctx->order) BN_free(ctx->order);
        if (ctx->prime) BN_free(ctx->prime);
        if (ctx->bn_ctx) BN_CTX_free(ctx->bn_ctx);

		rand_zero(reinterpret_cast<uint8_t*>(ctx), sizeof(ec_connection_context_t));
    }

	static inline void free_persistent_sec_ctx(ec_persistent_sec_ctx_t* ctx) {
		if (!ctx) return;

		if (ctx->C_signing_key) em_crypto_t::free_key(const_cast<SSL_KEY*>(ctx->C_signing_key));
		if (ctx->net_access_key) em_crypto_t::free_key(const_cast<SSL_KEY*>(ctx->net_access_key));
		if (ctx->pp_key) em_crypto_t::free_key(const_cast<SSL_KEY*>(ctx->pp_key));
		if (ctx->connector) rand_zero_free(ctx->connector);

		rand_zero(reinterpret_cast<uint8_t*>(ctx), sizeof(ec_persistent_sec_ctx_t));
	}

// START: Connector methods
  
	/**
	 * @brief Split and decode a connector into its constituent parts. 
	 * If the signing_key is provided, it will also verify the signature.
	 *
	 * @param[in] conn The connector to split and decode.
	 * @param[in] signing_key If provided, signature verification will be performed using this key.
	 *
	 * @return std::optional<std::tuple<cJSON*, cJSON*, std::vector<uint8_t>> A tuple consisting of the decoded/validated parts, or std::nullopt on failure.
	 * Indices: 0 -> JWS Header, 1 -> JWS Payload, 2 -> JWS Signature.
	 *
	 * @note The caller is responsible for freeing the cJSON objects.
	 */
	static std::optional<std::tuple<cJSON*, cJSON*, std::vector<uint8_t>>> split_decode_connector(const char* conn, std::optional<SSL_KEY*> signing_key = std::nullopt);

	/**
	 * @brief Split a Connector into its constituent parts without base64 decoding
	 * 
	 * @param conn The connector to split
	 * @return std::optional<std::vector<std::string>> A vector of strings containing the split parts of the connector, or std::nullopt on failure.
	 * Indices: 0 -> JWS Header, 1 -> JWS Payload, 2 -> JWS Signature
	 */
	static std::optional<std::vector<std::string>> split_connector(const char* conn);

	static bool validate_jws_header(const cJSON* jws_header, std::string type);

	static bool validate_jws_payload(const cJSON* jws_payload, bool check_expired=true);

	/**
	 * @brief Concatenate multiple nonces into a single byte vector. Will be concatenating in the order they are provided
	 * 
	 * @param nonces Input list of nonces
	 * @return std::vector<uint8_t> Concatenated nonce, empty on failure
	 */
	static std::vector<uint8_t> concat_nonces(const std::vector<std::vector<uint8_t>>& nonces);

	/**
	 * @brief Decode a JWK from a JSON object and return the EC_POINT.
	 * 
	 * @param ctx The connection context containing the BN context
	 * @param json_web_key cJSON blob 
	 * Example:
	 *        {
	 *            "kty":"EC",
	 *            "crv":"P-256",
	 *            "x":"Xj-zV2iEiH8XwyA9ijpsL6xyLvDiIBthrHO8ZVxwmpA",
	 *            "y":"LUsDBmn7nv-LCnn6fBoXKsKpLGJiVpY_knTckGgsgeU"
	 *        },
	 * 	
	 * @return EC_POINT* on success, nullptr otherwise
	 */
	static EC_POINT *decode_jwk_ec_point(ec_connection_context_t& ctx, cJSON *json_web_key);

	/**
	 * @brief Decode a JWK from a JSON object and return the EC_POINT.
	 * 
	 * @param json_web_key cJSON blob 
	 * @param bn_ctx The BN_CTX to used to optimize decoding (optional, can be NULL) 
	 * Example:
	 *        {
	 *            "kty":"EC",
	 *            "crv":"P-256",
	 *            "x":"Xj-zV2iEiH8XwyA9ijpsL6xyLvDiIBthrHO8ZVxwmpA",
	 *            "y":"LUsDBmn7nv-LCnn6fBoXKsKpLGJiVpY_knTckGgsgeU"
	 *        },
	 * 	
	 * @return EC_POINT* on success, nullptr otherwise
	 */
	static EC_POINT *decode_jwk_ec_point(cJSON *json_web_key, BN_CTX* bn_ctx = NULL);



	/**
	 * @brief Decode a JWK from a JSON object and return the EC_GROUP (crv) and EC_POINT.
	 * 
	 * @param json_web_key cJSON blob 
	 * @param bn_ctx The BN_CTX to used to optimize decoding (optional, can be NULL) 
	 * Example:
	 *        {
	 *            "kty":"EC",
	 *            "crv":"P-256",
	 *            "x":"Xj-zV2iEiH8XwyA9ijpsL6xyLvDiIBthrHO8ZVxwmpA",
	 *            "y":"LUsDBmn7nv-LCnn6fBoXKsKpLGJiVpY_knTckGgsgeU"
	 *        },
	 * 	
	 * @return EC_POINT* on success, nullptr otherwise
	 */
	static std::pair<EC_GROUP*, EC_POINT*> decode_jwk(cJSON *json_web_key, BN_CTX* bn_ctx = NULL);
    
	/**
	 * @brief Generate a connector from JWS header, payload, and the key to create the signature with.
	 *
	 * This function generates a connector by signing the concatenation of the base64url encodings of the JWS Protected Header and the JWS Payload, separated by a dot.
	 *
	 * @param[in] jws_header The JWS Protected Header.
	 * @param[in] jws_payload The JWS Payload.
	 * @param[in] sign_key The key to sign the connector with (creating 'sig').
	 *
	 * @return std::optional<std::string> The generated connector, nullopt on failure
	 *
	 * @paragraph EasyConnect 4.2.1.1 Digital Signature Computation
	 * The procedures to compute the digital signature of a Connector and the procedure to verify such signature are described
	 * in FIPS-186-4 [19] and are specified in this section. The curve used for the signature may be different from the one used in DPP Bootstrapping and DPP Authentication protocols.
	 * The signature is performed over the concatenation of the base64url encodings of both the JWS Protected Header and the JWS Payload, separated by a dot (“.”), see section 5.1 of [14].
	 * The data passed to the signature algorithm is:
	 *
	 * base64url(UTF8(JWS Protected Header)) | ‘.’ | base64url(JWS Payload)
	 *
	 * where UTF8(s) is the UTF8 representation of the string “s”.
	 * If “sig” is the result of the signature, the Connector is then:
	 * base64url(UTF8(JWS Protected Header)) | ‘.’ | base64url(JWS Payload) | ‘.’ | base64url(sig)
	 */
	static std::optional<std::string> generate_connector(const cJSON* jws_header, const cJSON* jws_payload, SSL_KEY* sign_key);

    
	/**
	 * @brief Get the JWS Protected Header from a connector
	 *
	 * This function extracts the JWS Protected Header from the given connector.
	 *
	 * @param[in] conn The connector to extract the header from.
	 * @param[in] signing_key Optional signing key for signature verification.
	 *
	 * @return std::optional<cJSON*> The JWS Protected Header, or std::nullopt on failure.
	 *
	 * @note The caller is responsible for freeing the cJSON object.
	 */
	static inline std::optional<cJSON*> get_jws_header(const char* conn, std::optional<SSL_KEY*> signing_key = std::nullopt) {
        auto parts = split_decode_connector(conn, signing_key);
        if (!parts.has_value()) return std::nullopt;
        return std::get<0>(parts.value()); // JWS header is the first part
    }

    
	/**
	 * @brief Get the JWS Payload from a connector
	 *
	 * This function extracts the JWS payload from the given connector string.
	 *
	 * @param[in] conn The connector string from which the payload is extracted.
	 * @param[in] signing_key Optional signing key for signature verification.
	 *
	 * @returns std::optional<cJSON*> The JWS Payload wrapped in an optional, or std::nullopt on failure.
	 *
	 * @note The caller is responsible for freeing the cJSON object if the payload is successfully extracted.
	 */
	static inline std::optional<cJSON*> get_jws_payload(const char* conn, std::optional<SSL_KEY*> signing_key = std::nullopt) {
        auto parts = split_decode_connector(conn, signing_key);
        if (!parts.has_value()) return std::nullopt;
        return std::get<1>(parts.value()); // JWS payload is the second part
    }

    
	/**
	 * @brief Performs connector validation and gets the JWS Signature from a connector.
	 *
	 * This function takes a connector string, validates it, and extracts the JWS signature.
	 *
	 * @param[in] conn The connector string to extract the signature from.
	 *
	 * @return std::optional<cJSON*> The JWS Signature, or std::nullopt on failure.
	 *
	 * @note The caller is responsible for freeing the cJSON object if a valid signature is returned.
	 */
	static inline std::optional<std::vector<uint8_t>> get_jws_signature(const char* conn) {
        auto parts = split_decode_connector(conn);
        if (!parts.has_value()) return std::nullopt;
        return std::get<2>(parts.value()); // JWS signature is the third part
    }

    
	/**
	 * @brief Generate a PSK from SSID and passphrase.
	 *
	 * This function generates a Pre-Shared Key (PSK) using the provided SSID and passphrase.
	 *
	 * @param[in] pass The passphrase used for generating the PSK.
	 * @param[in] ssid The SSID for which the PSK is generated.
	 *
	 * @return std::vector<uint8_t> A vector containing the PSK on success, or an empty vector if the generation fails.
	 *
	 * @note Ensure that both the passphrase and SSID are valid and non-empty to successfully generate a PSK.
	 */
	static std::vector<uint8_t> gen_psk(const std::string& pass, const std::string& ssid);

    
	/**
	 * @brief Create a JWS header
	 *
	 * This function generates a JSON Web Signature (JWS) header using the provided type and signing key.
	 *
	 * @param[in] type The "typ" key, representing the type of the JWS.
	 * @param[in] c_signing_key The Configurator Signing Key from which the "kid" (Key ID) is derived.
	 *
	 * @return cJSON* A pointer to a cJSON object on success, or nullptr on failure.
	 *
	 * @note The caller is responsible for freeing the returned cJSON object.
	 *
	 * Example return (EasyConnect 4.2.2):
	 *
	 * @code{.json}
	 * {
	 *     "typ":"dppCon",
	 *     "kid":"kMcegDBPmNZVakAsBZOzOoCsvQjkr_nEAp9uF-EDmVE",
	 *     "alg":"ES256"
	 * }
	 * @endcode
	 */
	static cJSON* create_jws_header(const std::string& type, const SSL_KEY *c_signing_key);

    
	/**
	 * @brief Create a JWS Payload
	 *
	 * This function generates a JSON Web Signature (JWS) payload using the provided context,
	 * groups, and network access key. The payload includes an optional expiry date.
	 *
	 * @param[in] groups List of "key":"value" pairs to be included in the "groups" array.
	 *                   Possible keys are "groupID" and "netRole".
	 * @param[in] net_access_key The network access key used for encryption.
	 * @param[in] expiry Optional expiry date for the payload in ISO 8601 format.
	 * @param version Conditionally included DPP Version number (only used for Reconfiguration C-Connector generation) according to EC
	 *
	 * @return cJSON* Pointer to the created JWS payload on success, nullptr otherwise.
	 *
	 * @note Caller must free the returned cJSON object.
	 *
	 * Example return (EasyConnect 4.2.2):
	 * Expiry is optional.
	 *    {
	 *        "groups":
	 *        [
	 *            {"groupId":"home","netRole":"sta"},
	 *            {"groupId":"cottage","netRole":"sta"}
	 *        ],
	 *        "netAccessKey":
	 *        {
	 *            "kty":"EC",
	 *            "crv":"P-256",
	 *            "x":"Xj-zV2iEiH8XwyA9ijpsL6xyLvDiIBthrHO8ZVxwmpA",
	 *            "y":"LUsDBmn7nv-LCnn6fBoXKsKpLGJiVpY_knTckGgsgeU"
	 *        },
	 *        "expiry":"2019-01-31T22:00:00+02:00",
	 * 	  	  "version": 2
	 *   }
	 */
	static cJSON* create_jws_payload(const std::vector<std::unordered_map<std::string, std::string>>& groups, SSL_KEY* net_access_key, std::optional<std::string> expiry = std::nullopt, std::optional<uint8_t> version = std::nullopt);

    
	/**
	 * @brief Create a csign object.
	 *
	 * This function creates a csign object, which is part of the "cred" object in EasyConnect 4.5.3.
	 *
	 * @param[in] c_signing_key Configurator Signing Key.
	 *
	 * @return cJSON* Pointer to the created csign object on success, nullptr otherwise.
	 *
	 * @note Example of a csign object:
	 * "csign":
	 * {
	 * "kty":"EC",
	 * "crv":"P-256",
	 * "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
	 * "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
	 * "kid":"kMcegDBPmNZVakAsBZOzOoCsvQjkr_nEAp9uF-EDmVE"
	 * },
	 */
	static cJSON* create_csign_object(SSL_KEY *c_signing_key);

    
	/**
	 * @brief Derive public ppKey from Configurator Signing Key (must share the same key group)
	 *
	 * This function takes a Configurator Signing Key and derives the corresponding
	 * public ppKey. The keys must belong to the same key group for the operation
	 * to be successful.
	 *
	 * @param[in] c_signing_key Configurator Signing Key used for deriving the public key.
	 *
	 * @return EC_POINT* Pointer to the derived public key on success, nullptr otherwise.
	 *
	 * @note Ensure that the c_signing_key is valid and belongs to the correct key group.
	 */
	static EC_POINT* create_ppkey_public(SSL_KEY *c_signing_key);

	/**
	 * @brief Adds the fields present in all JSON Web Key (JWK) objects to the provided JSON object.
	 * 
	 * Edits the provided JSON object in-place
	 *
	 * @param[in] json_obj The JSON object to which the common JWK fields will be added.
	 * @param[in] key The key containing the information to be added.
	 *
	 * @return true if the fields were successfully added, false otherwise.
	 *
	 * @note RFC 7517 defines many possible fields for JWK objects, but this function only adds the common fields:
	 * 			- "kty" 
	 * 			- "crv"
	 * 			- "x" 
	 * 			- "y"
	 *
	 * @code
	 * {
	 *   "kty":"EC",
	 *   "crv":"P-256",
	 *   "x":"XX_ZuJR9nMDSb54C_okhGiJ7OjCZOlWOU9m8zAxgUrU",
	 *   "y":"Fekm5hyGii80amM_REV5sTOG3-sl1H6MDpZ8TSKnb7c"
	 * }
	 * @endcode
	 */
	static bool add_common_jwk_fields(cJSON* json_obj, const SSL_KEY *key);

	/**
	 * @brief Adds the fields present in all JSON Web Key (JWK) objects to the provided JSON object.
	 * 
	 * Edits the provided JSON object in-place
	 *
	 * @param[in] json_obj The JSON object to which the common JWK fields will be added.
	 * @param[in] key_group The EC_GROUP of the curve the point is on
	 * @param[in] key_point The EC_POINT containing the information to be added.
	 *
	 * @return true if the fields were successfully added, false otherwise.
	 *
	 * @note RFC 7517 defines many possible fields for JWK objects, but this function only adds the common fields:
	 * 			- "kty" 
	 * 			- "crv"
	 * 			- "x" 
	 * 			- "y"
	 *
	 * @code
	 * {
	 *   "kty":"EC",
	 *   "crv":"P-256",
	 *   "x":"XX_ZuJR9nMDSb54C_okhGiJ7OjCZOlWOU9m8zAxgUrU",
	 *   "y":"Fekm5hyGii80amM_REV5sTOG3-sl1H6MDpZ8TSKnb7c"
	 * }
	 * @endcode
	 */
	static bool add_common_jwk_fields(cJSON *json_obj, const EC_GROUP* key_group, const EC_POINT *key_point);
};

#endif // EC_CRYPTO_H
