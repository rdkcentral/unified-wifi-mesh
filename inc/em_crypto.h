/**
 * Copyright 2023 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef EM_CRYPTO_H
#define EM_CRYPTO_H

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/dh.h>
#include "em_base.h"
#include <openssl/evp.h>



#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/param_build.h>
#include <openssl/types.h>
#include <openssl/core_names.h>
#endif

#include <optional>
#include <vector>
#include <utility>
#include <string>
#include <memory>

#include <string.h>

#define SHA256_MAC_LEN 32
#define AES_BLOCK_SIZE 16
 /* Keys sizes */
#define WPS_AUTHKEY_LEN    32
#define WPS_KEYWRAPKEY_LEN 16
#define WPS_EMSK_LEN       32

class em_crypto_t {

private:
    em_crypto_info_t m_crypto_info;
    em_nonce_t e_nonce;
    uuid_t e_uuid;

    
	/**
	 * @brief Securely frees multiple BIGNUM objects.
	 *
	 * This function takes pointers to BIGNUM objects and securely frees them.
	 * If any of the pointers are NULL, they are simply ignored.
	 *
	 * @param[in] p Pointer to a BIGNUM object to free. Can be NULL.
	 * @param[in] g Pointer to a BIGNUM object to free. Can be NULL.
	 * @param[in] priv Pointer to a BIGNUM object to free. Can be NULL.
	 * @param[in] pub Pointer to a BIGNUM object to free. Can be NULL.
	 *
	 * @note This function ensures that the memory is securely cleared before being freed.
	 */
	static void cleanup_bignums(BIGNUM *p, BIGNUM *g, BIGNUM *priv, BIGNUM *pub);

    
	/**
	 * @brief Helper function to compute a Diffie-Hellman shared secret using version-specific OpenSSL APIs.
	 *
	 * This function computes the shared secret based on the provided prime modulus, generator, local private key,
	 * and remote public key. It allocates the output buffer for the shared secret within the function.
	 *
	 * @param[in] p Prime modulus as BIGNUM.
	 * @param[in] g Generator as BIGNUM.
	 * @param[in] bn_priv Local private key as BIGNUM.
	 * @param[in] bn_pub Remote public key as BIGNUM.
	 * @param[out] shared_secret Output buffer for computed shared secret (allocated within function).
	 * @param[out] secret_len Length of computed shared secret.
	 *
	 * @return 1 on success, 0 on failure.
	 *
	 * @note For OpenSSL < 3.0: Uses legacy DH APIs.
	 * @note For OpenSSL >= 3.0: Uses modern EVP APIs.
	 */
	static uint8_t compute_secret_internal(BIGNUM *p, BIGNUM *g, BIGNUM *bn_priv,  BIGNUM *bn_pub, uint8_t **shared_secret, size_t *secret_len);
public:
    static uint8_t g_dh1536_g[];
    static uint8_t g_dh1536_p[];

    
	/**!
	 * @brief Initializes the cryptographic module.
	 *
	 * This function sets up the necessary environment for the cryptographic operations.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure that the module is not already initialized before calling this function.
	 */
	int init();

    /**
     * @brief Computes an HMAC hash using OpenSSL for multiple input elements
     *
     * This function calculates an HMAC hash using a specified hashing algorithm and key,
     * supporting multiple input elements. It's compatible with different OpenSSL versions
     * (pre-1.1.0, 1.1.0+, and 3.0.0+) through conditional compilation.
     *
     * @param hashing_algo The OpenSSL message digest algorithm to use (e.g., EVP_sha256())
     * @param key         Pointer to the key used for HMAC calculation
     * @param keylen      Length of the key in bytes
     * @param num_elem    Number of elements to be hashed
     * @param addr        Array of pointers to input data elements
     * @param len         Array of lengths corresponding to each input element
     * @param hmac        Output buffer where the computed HMAC will be stored
     *
     * @return uint8_t    Returns 1 on success, 0 on failure
     *
     * @note The hmac buffer must be pre-allocated with sufficient space for the output
     *       (32 bytes for SHA-256)
     */
    static uint8_t platform_hmac_hash(const EVP_MD * hashing_algo, uint8_t *key, size_t keylen, uint8_t num_elem, uint8_t **addr, size_t *len, uint8_t *hmac);

    /**
    * @brief Convenience wrapper to compute HMAC-SHA256 hash for multiple input elements
    *
    * @param key      Key used for HMAC calculation
    * @param keylen   Length of the key in bytes  
    * @param num_elem Number of elements to hash
    * @param addr     Array of pointers to input data elements
    * @param len      Array of lengths for each input element
    * @param hmac     Output buffer for computed HMAC
    *
    * @return 1 on success, 0 on failure
    */
    inline static uint8_t platform_hmac_SHA256(uint8_t *key, size_t keylen, uint8_t num_elem, uint8_t **addr, size_t *len, uint8_t *hmac){
        return platform_hmac_hash(EVP_sha256(), key, keylen, num_elem, addr, len, hmac);
    }
    
    
	/**
	 * @brief Computes a cryptographic hash of multiple input elements using OpenSSL.
	 *
	 * This function takes multiple input elements and computes their cryptographic hash
	 * using the specified OpenSSL message digest algorithm.
	 *
	 * @param[in] hashing_algo OpenSSL message digest algorithm to use (e.g., EVP_sha256()).
	 * @param[in] num_elem Number of elements to hash.
	 * @param[in] addr Array of pointers to input data elements.
	 * @param[in] len Array of lengths for each input element.
	 * @param[out] digest Output buffer for computed hash value.
	 *
	 * @return 1 on success, 0 on failure.
	 */
	static uint8_t platform_hash(const EVP_MD * hashing_algo, uint8_t num_elem, uint8_t **addr, size_t *len, uint8_t *digest);

    
	/**
	 * @brief Convenience wrapper to compute SHA-256 hash for multiple input elements.
	 *
	 * This function computes the SHA-256 hash for a given number of input elements.
	 *
	 * @param[in] num_elem Number of elements to hash.
	 * @param[in] addr Array of pointers to input data elements.
	 * @param[in] len Array of lengths for each input element.
	 * @param[out] digest Output buffer for computed hash.
	 *
	 * @return 1 on success, 0 on failure.
	 */
	inline static uint8_t platform_SHA256(uint8_t num_elem, uint8_t **addr, size_t *len, uint8_t *digest){
        return platform_hash(EVP_sha256(), num_elem, addr, len, digest);
    }

	/**
	 * @brief Convenience wrapper to compute SHA-256 hash for a single input element.
	 *
	 * @param[in] secret Pointer to the input data element.
	 * @param[in] secret_len Length of the input data element.
	 * @param[out] digest Output buffer for computed hash.
	 *
	 * @return 1 on success, 0 on failure.
	 */
	inline static uint8_t platform_SHA256(uint8_t *secret, size_t secret_len, uint8_t *digest){
		uint8_t *addr[1];
		size_t length[1];
		addr[0] = secret;
    	length[0] = secret_len;
        return platform_hash(EVP_sha256(), 1, addr, length, digest);
    }

	/**
	 * @brief Convenience wrapper to compute SHA-256 hash for a single input element.
	 *
	 * @param[in] secret Pointer to the input data element.
	 * @param[in] secret_len Length of the input data element.
	 *
	 * @return std::vector<uint8_t> A vector containing the computed SHA-256 hash.
	 */
	inline static std::vector<uint8_t> platform_SHA256(uint8_t *secret, size_t secret_len){
		uint8_t *addr[1];
		size_t length[1];
		addr[0] = secret;
    	length[0] = secret_len;

		std::vector<uint8_t> digest(SHA256_MAC_LEN);
		if (platform_hash(EVP_sha256(), 1, addr, length, digest.data()) == 0) {
			return {};
		}
		return digest;
    }
    

    
	/**
	 * @brief Appends a 32-bit value in network byte order to a buffer and advances the pointer.
	 *
	 * This function takes a 32-bit integer, converts it to network byte order, and appends it to the specified buffer.
	 * The buffer pointer is then advanced by 4 bytes to accommodate the appended value.
	 *
	 * @param[in] memory_pointer Pointer to the 32-bit value to append (already in network byte order).
	 * @param[in,out] packet_ppointer Pointer to the buffer pointer, which will be advanced by 4 bytes.
	 *
	 * @note Ensure that the buffer has enough space to accommodate the additional 4 bytes.
	 */
	static void append_u32_net (const uint32_t *memory_pointer, uint8_t **packet_ppointer);

    
	/**
	 * @brief Key Derivation Function used in WPS (Wi-Fi Protected Setup)
	 *
	 * Generates cryptographic key material using HMAC-SHA256.
	 *
	 * @param[in] key HMAC key.
	 * @param[in] label_prefix Binary prefix for the label.
	 * @param[in] label_prefix_len Length of the label prefix.
	 * @param[in] label ASCII label string.
	 * @param[out] res Output buffer for generated key material.
	 * @param[in] res_len Length of requested key material in bytes.
	 *
	 * @return 1 on success, 0 on HMAC failure.
	 */
	static uint8_t wps_key_derivation_function(uint8_t *key, uint8_t *label_prefix, size_t label_prefix_len, char *label, uint8_t *res, uint32_t res_len);

    
	/**
	 * @brief Decrypts data using OpenSSL cipher in place.
	 *
	 * This function decrypts the given data buffer using the specified cipher type.
	 * The decryption is performed in place, meaning the input buffer is overwritten
	 * with the decrypted plaintext.
	 *
	 * @param[in] cipher_type Type of cipher to use (e.g., EVP_aes_256_cbc()).
	 * @param[in] key Decryption key.
	 * @param[in] iv Initialization vector.
	 * @param[in,out] data Buffer containing ciphertext, also used for plaintext output.
	 * @param[in] data_len Length of input ciphertext.
	 *
	 * @return 1 on success, 0 on failure.
	 *
	 * @note Padding is disabled. Input length must be a multiple of the block size.
	 */
	static uint8_t platform_cipher_decrypt(const EVP_CIPHER *cipher_type, uint8_t *key, uint8_t *iv, uint8_t *data, uint32_t data_len);

    
	/**
	 * @brief Encrypts data using OpenSSL cipher in place.
	 *
	 * This function encrypts the given plaintext using the specified cipher type,
	 * encryption key, and initialization vector. The result is stored in the
	 * provided ciphertext buffer.
	 *
	 * @param[in] cipher_type Type of cipher to use (e.g., EVP_aes_256_cbc()).
	 * @param[in] key Encryption key.
	 * @param[in] iv Initialization vector.
	 * @param[in] plain Input plaintext buffer.
	 * @param[in] plain_len Length of input plaintext.
	 * @param[out] cipher_text Output buffer for ciphertext.
	 * @param[out] cipher_len Output parameter for length of ciphertext.
	 *
	 * @return 1 on success, 0 on failure.
	 *
	 * @note Padding is disabled. Input length must be multiple of block size.
	 */
	static uint8_t platform_cipher_encrypt(const EVP_CIPHER *cipher_type, uint8_t *key, uint8_t *iv, uint8_t *plain, uint32_t plain_len, uint8_t *cipher_text, uint32_t *cipher_len);

    
	/**
	 * @brief Decrypts data using AES-128 in CBC mode (in-place)
	 *
	 * This function decrypts the provided data using the AES-128 algorithm in
	 * Cipher Block Chaining (CBC) mode. The decryption is performed in-place,
	 * meaning the input data is overwritten with the resulting plaintext.
	 *
	 * @param[in] key 128-bit AES key used for decryption.
	 * @param[in] iv Initialization vector used for the CBC mode.
	 * @param[in,out] data Data to decrypt, which will be overwritten with the plaintext.
	 * @param[in] data_len Length of the data to be decrypted.
	 *
	 * @return 1 on success, 0 on failure.
	 *
	 * @note Ensure that the key and iv are correctly set before calling this function.
	 */
	static uint8_t platform_aes_128_cbc_decrypt(uint8_t *key, uint8_t *iv, uint8_t *data, uint32_t data_len){
        return platform_cipher_decrypt(EVP_aes_128_cbc(), key, iv, data, data_len);
    }
    
    
	/**
	 * @brief Encrypts data using AES-128 in CBC mode.
	 *
	 * This function encrypts the given plaintext using the AES-128 algorithm in CBC mode.
	 *
	 * @param[in] key 128-bit AES key.
	 * @param[in] iv Initialization vector.
	 * @param[in] plain Input plaintext.
	 * @param[in] plain_len Length of plaintext.
	 * @param[out] cipher_text Output ciphertext buffer.
	 * @param[out] cipher_len Output ciphertext length.
	 *
	 * @return 1 on success, 0 on failure.
	 */
	static uint8_t platform_aes_128_cbc_encrypt(uint8_t *key, uint8_t *iv, uint8_t *plain, uint32_t plain_len, uint8_t *cipher_text, uint32_t *cipher_len){
        return platform_cipher_encrypt(EVP_aes_128_cbc(), key, iv, plain, plain_len, cipher_text, cipher_len);
    }

    
	/**
	 * @brief Creates a DH (Diffie-Hellman) key using OpenSSL 3.0+ APIs.
	 *
	 * This function generates a Diffie-Hellman key pair using the provided prime modulus and generator.
	 * Optionally, a private and public key component can be specified.
	 *
	 * @param[in] p Prime modulus.
	 * @param[in] g Generator.
	 * @param[in] bn_priv Private key component (optional, can be NULL).
	 * @param[in] bn_pub Public key component (optional, can be NULL).
	 *
	 * @return EVP_PKEY* Object containing the DH key on success, NULL on failure.
	 *
	 * @note Requires OpenSSL 3.0 or later.
	 */
	static EVP_PKEY* create_dh_pkey(BIGNUM *p, BIGNUM *g, BIGNUM *bn_priv, BIGNUM *bn_pub);


    
	/**
	 * @brief Computes the Diffie-Hellman shared secret using the local private key and remote public key.
	 *
	 * This function uses a 1536-bit DH group (RFC 3526) to compute a shared secret.
	 * It supports both legacy OpenSSL (<3.0.0) and modern OpenSSL (>=3.0.0) implementations.
	 *
	 * @param[out] shared_secret Pointer to buffer pointer where the computed shared secret will be stored.
	 * Memory is allocated by the function and must be freed by the caller.
	 * @param[out] shared_secret_len Pointer to store the length of the computed shared secret.
	 * @param[in] remote_pub Remote party's public key buffer.
	 * @param[in] remote_pub_len Length of the remote public key.
	 * @param[in] local_priv Local party's private key buffer.
	 * @param[in] local_priv_len Length of the local private key.
	 *
	 * @return 1 on success, 0 on failure.
	 * If the function returns 0, any allocated memory is freed and output parameters are set to NULL/0.
	 *
	 * @warning Input parameters must not be NULL.
	 * @warning Caller is responsible for freeing the allocated shared_secret buffer **on success**.
	 */
	static uint8_t platform_compute_shared_secret(uint8_t **shared_secret, uint16_t *shared_secret_len,
        uint8_t *remote_pub, uint16_t remote_pub_len,
        uint8_t *local_priv, uint8_t local_priv_len);

    
	/**
	* @brief Encodes binary data using standard Base64 encoding.
	*
	* This function takes binary data and encodes it into a Base64 string.
	*
	* @param[in] input Binary data to encode.
	* @param[in] length Length of the input data.
	*
	* @returns Base64 encoded string.
	* @retval "" (empty string) on failure.
	*
	* @note Ensure that the input data is valid and the length is correctly specified.
	*/
	static std::string base64_encode(const uint8_t *input, size_t length);

    
	/**
	 * @brief Encodes binary data using Base64URL encoding (URL-safe variant).
	 *
	 * Replaces '+' with '-', '/' with '_', and removes padding '=' characters.
	 *
	 * @param[in] input Binary data to encode
	 * @param[in] length Length of the input data
	 * @returns Base64URL encoded string or empty string on failure
	 */
	static std::string base64url_encode(const uint8_t *input, size_t length);

    
	/**
	 * @brief Encodes string data using standard Base64 encoding.
	 *
	 * This function takes a string as input and returns its Base64 encoded equivalent.
	 *
	 * @param[in] input String data to encode.
	 * @return Base64 encoded string or an empty string on failure.
	 */
	static inline std::string base64_encode(const std::string &input)
    {
        return base64_encode(reinterpret_cast<const uint8_t *>(input.data()), input.length());
    }

    
	/**
	 * @brief Encodes string data using Base64URL encoding (URL-safe variant).
	 *
	 * This function takes a string input and encodes it using the Base64URL
	 * encoding scheme, which is a URL-safe variant of Base64 encoding.
	 *
	 * @param[in] input String data to encode.
	 *
	 * @returns A Base64URL encoded string. If the encoding fails, an empty
	 * string is returned.
	 */
	static inline std::string base64url_encode(const std::string &input)
    {
        return base64url_encode(reinterpret_cast<const uint8_t *>(input.data()), input.length());
    }

    
	/**
	 * @brief Encodes string data using standard Base64 encoding.
	 *
	 * This function takes a vector of bytes and encodes it into a Base64 string.
	 *
	 * @param[in] input Byte data to encode.
	 *
	 * @return Base64 encoded string. Returns an empty string on failure.
	 */
	static inline std::string base64_encode(const std::vector<uint8_t> &input)
    {
        return base64_encode(input.data(), input.size());
    }

    
	/**
	 * @brief Encodes string data using Base64URL encoding (URL-safe variant).
	 *
	 * This function takes a vector of bytes and encodes it into a Base64URL
	 * encoded string. Base64URL is a variant of Base64 encoding that is
	 * URL-safe, meaning it replaces '+' and '/' with '-' and '_', respectively.
	 *
	 * @param[in] input Byte data to encode.
	 *
	 * @return Base64URL encoded string. Returns an empty string on failure.
	 */
	static inline std::string base64url_encode(const std::vector<uint8_t> &input)
    {
        return base64url_encode(input.data(), input.size());
    }

    
	/**
	 * @brief Decodes standard Base64 encoded data.
	 *
	 * This function takes a Base64 encoded string and decodes it into its original binary form.
	 *
	 * @param[in] input Base64 encoded string.
	 *
	 * @return std::optional<std::vector<uint8_t>> containing the decoded data. If decoding fails, the optional will be empty.
	 *
	 * @note The caller is responsible for handling the optional and using the decoded data appropriately.
	 */
	static std::optional<std::vector<uint8_t>> base64_decode(const std::string &input);

    
	/**
	* @brief Decodes Base64URL encoded data (URL-safe variant).
	*
	* Handles '-' instead of '+', '_' instead of '/', and missing padding.
	*
	* @param[in] input Base64URL encoded string
	* @returns std::optional<std::vector<uint8_t>> containing the decoded data.
	* Returns an empty optional on failure.
	*
	* @note The caller is responsible for managing the memory of the returned data.
	*/
	static std::optional<std::vector<uint8_t>> base64url_decode(const std::string &input);

    
	/**
	 * @brief Signs data using the provided private key and hashing algorithm with ECDSA.
	 *
	 * This function takes a data string and signs it using the specified private key and
	 * digest method. The default digest method is SHA-256.
	 *
	 * @param[in] data_to_sign The data string to be signed.
	 * @param[in] private_key OpenSSL EVP_PKEY pointer containing the private key.
	 * @param[in] md Digest method to use (defaults to SHA-256).
	 *
	 * @return std::optional<std::vector<uint8_t>> containing the signature as a vector of bytes.
	 * @retval std::nullopt on failure.
	 *
	 * @note Ensure that the private key is valid and properly initialized before calling this function.
	 */
	static std::optional<std::vector<uint8_t>>
    sign_data_ecdsa(const std::vector<uint8_t>& data_to_sign, EVP_PKEY *private_key,
                    const EVP_MD *md = EVP_sha256());

    
	/**
	 * @brief Verifies a digital signature using OpenSSL's EVP API
	 *
	 * This function verifies that the provided signature was created from the given message
	 * using the private key corresponding to the provided public key.
	 *
	 * @param[in] message The original message data that was signed
	 * @param[in] signature The signature to verify
	 * @param[in] pkey The public key (EVP_PKEY*) to use for verification
	 * @param[in] hash_function The hash function (e.g., EVP_sha256()) used during signing
	 *
	 * @return true if the signature is valid, false otherwise
	 *
	 * @note This function uses OpenSSL's high-level EVP interface which works with
	 *       OpenSSL 1.1.x and 3.0+
	 */
	static bool verify_signature(const std::vector<uint8_t> &message,
                                 const std::vector<uint8_t> &signature, EVP_PKEY *pkey,
                                 const EVP_MD *hash_function);

#if OPENSSL_VERSION_NUMBER < 0x30000000L

    
	/**
	 * @brief Signs data using the provided private key and hashing algorithm with ECDSA.
	 *
	 * This function provides a convenient interface for signing data with EC_KEY objects,
	 * which is useful for code that needs to work with pre-OpenSSL 3.0 versions. It internally
	 * converts the EC_KEY to an EVP_PKEY and delegates to the primary signing function.
	 *
	 * @param[in] data_to_sign The data string to be signed.
	 * @param[in] private_key OpenSSL EC_KEY pointer containing the private key.
	 * @param[in] md Digest method to use (defaults to SHA-256).
	 *
	 * @return std::optional containing the signature as a vector of bytes, or std::nullopt on failure.
	 */
	static std::optional<std::vector<uint8_t>> sign_data_ecdsa(const std::vector<uint8_t> &data_to_sign, 
                                                               EC_KEY *private_key, 
                                                               const EVP_MD *md = EVP_sha256());

    
	/**
	 * @brief Verifies a digital signature using an EC_KEY (for pre-OpenSSL 3.0 compatibility)
	 *
	 * This overloaded function provides a convenient interface for verifying signatures
	 * with EC_KEY objects, which is useful for code that needs to work with 
	 * pre-OpenSSL 3.0 versions. It internally converts the EC_KEY to an EVP_PKEY
	 * and delegates to the primary verification function.
	 *
	 * @param[in] message The original message data that was signed
	 * @param[in] signature The signature to verify
	 * @param[in] ec_key The elliptic curve public key (EC_KEY*) to use for verification
	 * @param[in] hash_function The hash function (e.g., EVP_sha256()) used during signing
	 *
	 * @return true if the signature is valid, false otherwise
	 */
	static bool verify_signature(const std::vector<uint8_t> &message,
                                 const std::vector<uint8_t> &signature, EC_KEY *ec_key,
                                 const EVP_MD *hash_function);
#endif
    
	/**
	 * @brief Creates an OpenSSL EC_KEY from a base64-encoded DER public key.
	 *
	 * This function converts a base64-encoded DER public key into an OpenSSL EC_KEY.
	 *
	 * @param[in] base64_der_pubkey A null-terminated string containing the base64-encoded DER public key.
	 *
	 * @return SSL_KEY* A pointer to the created EC_KEY on success, or NULL on failure.
	 *
	 * @note The returned EC_KEY must be freed by the caller using EC_KEY_free().
	 * @note This function assumes the input is a valid base64-encoded DER format EC public key.
	 */
	static SSL_KEY* ec_key_from_base64_der(const std::string& base64_der_pubkey);

    
	/**!
	 * @brief Converts an EC key to a Base64 DER encoded string.
	 *
	 * This function takes an elliptic curve (EC) key and converts it into a Base64 encoded DER format string.
	 *
	 * @param[in] key Pointer to the SSL_KEY structure representing the EC key.
	 *
	 * @returns A std::string containing the Base64 DER encoded representation of the EC key.
	 *
	 * @note Ensure that the key is valid and properly initialized before calling this function.
	 */
	static std::string ec_key_to_base64_der(const SSL_KEY* key);

    
	/**!
	 * @brief Creates an EC key from given coordinates.
	 *
	 * This function generates an elliptic curve key using the provided x and y coordinates.
	 * Optionally, a private key can be specified.
	 *
	 * @param[in] x_bin The x-coordinate in binary form.
	 * @param[in] y_bin The y-coordinate in binary form.
	 * @param[in] priv_key_bytes Optional private key bytes. Defaults to std::nullopt.
	 * @param[in] group_name The name of the elliptic curve group. Defaults to "P-256".
	 *
	 * @returns A pointer to the generated SSL_KEY structure.
	 *
	 * @note Ensure that the provided coordinates and group name are valid for the intended cryptographic operations.
	 */
	static SSL_KEY* create_ec_key_from_coordinates(const std::vector<uint8_t>& x_bin, 
                                                   const std::vector<uint8_t>& y_bin, 
                                                   const std::optional<std::vector<uint8_t>>& priv_key_bytes = std::nullopt,
                                                   const std::string& group_name = "P-256");

    
    
	/**
	 * @brief Get the group of the key
	 *
	 * This function retrieves the EC_GROUP associated with a given SSL_KEY.
	 *
	 * @param[in] key The SSL_KEY object containing the key.
	 *
	 * @return Pointer to the EC_GROUP object representing the key group.
	 */
	static EC_GROUP* get_key_group(const SSL_KEY* key);

    
	/**
	 * @brief Get the private key as a BIGNUM object
	 *
	 * This function retrieves the private key from the given SSL_KEY object
	 * and returns it as a BIGNUM object.
	 *
	 * @param[in] key The SSL_KEY object containing the key
	 *
	 * @return Pointer to the BIGNUM object representing the private key
	 *
	 * @note Ensure that the SSL_KEY object is properly initialized before
	 * calling this function.
	 */
	static BIGNUM* get_priv_key_bn(const SSL_KEY* key);

    
	/**
	 * @brief Get the public key as an EC_POINT object.
	 *
	 * This function retrieves the public key from the given SSL_KEY object and returns it as an EC_POINT object. Optionally, a specific EC_GROUP can be provided.
	 *
	 * @param[in] key The SSL_KEY object containing the key.
	 * @param[in] key_group Optional EC_GROUP object representing the key group (can be NULL).
	 * @return Pointer to the EC_POINT object representing the public key.
	 */
	static EC_POINT* get_pub_key_point(const SSL_KEY* key, EC_GROUP* key_group=NULL);

    
	/**
	* @brief Generate an SSL_KEY using a specified EC_GROUP.
	*
	* This function generates an SSL_KEY object by utilizing the provided\n 
	* EC_GROUP. The generated key is essential for establishing secure
	* communication channels.
	*
	* @param[in] group The EC_GROUP to use for key generation.
	*
	* @returns Pointer to the generated SSL_KEY object.
	*
	* @note Ensure that the EC_GROUP provided is properly initialized
	* before calling this function to avoid unexpected behavior.
	*/
	static SSL_KEY* generate_ec_key(EC_GROUP *group);

    
	/**
	 * @brief Generate an SSL_KEY with a specified NID (curve type).
	 *
	 * This function generates an elliptic curve key based on the provided
	 * curve type identifier (NID). It returns a pointer to the newly
	 * created SSL_KEY object.
	 *
	 * @param[in] nid The NID of the curve to use.
	 *
	 * @return Pointer to the generated SSL_KEY object.
	 * @retval NULL if the key generation fails.
	 *
	 * @note Ensure that the NID provided is valid and supported by the
	 * underlying cryptographic library.
	 */
	static SSL_KEY* generate_ec_key(int nid);

    
	/**
	 * @brief Free an SSL_KEY object.
	 *
	 * This function releases the memory allocated for an SSL_KEY object.
	 *
	 * @param[in] key Pointer to the SSL_KEY object to be freed.
	 *
	 * @note Ensure that the key is not used after this function is called.
	 */
	static void free_key(SSL_KEY* key);

    
	/**
	 * @brief Write an SSL_KEY to a PEM file
	 *
	 * This function writes the provided SSL_KEY object to a specified PEM file.
	 *
	 * @param[in] key The SSL_KEY object to write.
	 * @param[in] file_path The path to the PEM file.
	 *
	 * @return true on success, false on failure.
	 *
	 * @note Ensure that the file path is accessible and writable.
	 */
	static bool write_keypair_to_pem(const SSL_KEY* key, const std::string& file_path);

    
	/**
	 * @brief Read an SSL_KEY from a PEM file.
	 *
	 * This function reads an SSL_KEY from a specified PEM file and returns a pointer to the SSL_KEY object.
	 *
	 * @param[in] file_path The path to the PEM file.
	 *
	 * @return Pointer to the read SSL_KEY object, or NULL on failure.
	 *
	 * @note Ensure the file path is correct and the file is accessible.
	 */
	static SSL_KEY* read_keypair_from_pem(const std::string& file_path);


    
	/**!
	 * @brief Generates an initialization vector (IV) of specified length.
	 *
	 * This function fills the provided buffer with random bytes to be used as an IV.
	 *
	 * @param[out] iv Pointer to the buffer where the generated IV will be stored.
	 * @param[in] len The length of the IV to be generated.
	 *
	 * @returns uint8_t
	 * @retval 0 If the IV generation fails.
	 * @retval 1 If the IV generation is successful.
	 *
	 * @note This function uses the RAND_bytes function to generate random bytes.
	 */
	static inline uint8_t generate_iv(unsigned char *iv, unsigned int len) { if (!RAND_bytes(iv, static_cast<int>(len))) { return 0; } else { return 1; } }
    
	/**!
	 * @brief Generates a nonce using a cryptographic random number generator.
	 *
	 * This function fills the provided nonce buffer with cryptographically
	 * secure random bytes.
	 *
	 * @param[out] nonce The buffer where the generated nonce will be stored.
	 *
	 * @returns uint8_t Returns 1 on success, 0 on failure.
	 *
	 * @note This function uses RAND_bytes to generate random bytes.
	 */
	static inline uint8_t generate_nonce(em_nonce_t nonce) { if (!RAND_bytes(nonce, sizeof(em_nonce_t))) { return 0; } else { return 1; } }

    // START: Object getters and setters
    
	/**!
	 * @brief Retrieves the cryptographic information.
	 *
	 * This function returns a pointer to the cryptographic information structure.
	 *
	 * @returns A pointer to the `em_crypto_info_t` structure containing cryptographic information.
	 */
	inline em_crypto_info_t *get_crypto_info() { return &m_crypto_info; }

    
	/**!
	 * @brief Retrieves the e_uuid.
	 *
	 * This function copies the e_uuid into the provided buffer.
	 *
	 * @param[out] uuid Buffer where the e_uuid will be copied.
	 *
	 * @returns The size of the UUID copied.
	 * @retval sizeof(uuid_t) The size of the UUID type.
	 *
	 * @note Ensure that the buffer is large enough to hold the UUID.
	 */
	inline unsigned int get_e_uuid(unsigned char *uuid) { memcpy(uuid, reinterpret_cast<unsigned char *>(&m_crypto_info.e_uuid), sizeof(uuid_t)); return sizeof(uuid_t); }
    
	/**!
	 * @brief Retrieves the random UUID.
	 *
	 * This function copies the random UUID from the internal crypto information
	 * to the provided buffer.
	 *
	 * @param[out] uuid A pointer to a buffer where the UUID will be copied.
	 *
	 * @returns The size of the UUID copied.
	 * @retval sizeof(uuid_t) The size of the UUID type.
	 *
	 * @note Ensure that the buffer pointed to by `uuid` is large enough to hold
	 * the UUID.
	 */
	inline unsigned int get_r_uuid(unsigned char *uuid) { memcpy(uuid, reinterpret_cast<unsigned char *>(&m_crypto_info.r_uuid), sizeof(uuid_t)); return sizeof(uuid_t); }
    
	/**!
	 * @brief Copies the e_nonce value into the provided buffer.
	 *
	 * This function retrieves the e_nonce from the m_crypto_info structure and copies it into the buffer pointed to by nonce.
	 *
	 * @param[out] nonce A pointer to the buffer where the e_nonce will be copied.
	 *
	 * @returns The size of the e_nonce copied.
	 *
	 * @note Ensure that the buffer pointed to by nonce is large enough to hold the e_nonce value.
	 */
	inline unsigned int get_e_nonce(unsigned char *nonce) { memcpy(nonce, reinterpret_cast<unsigned char *>(&m_crypto_info.e_nonce), sizeof(em_nonce_t)); return sizeof(em_nonce_t); }
    
	/**!
	 * @brief Retrieves the random nonce value.
	 *
	 * This function copies the random nonce value into the provided buffer.
	 *
	 * @param[out] nonce Pointer to the buffer where the nonce will be copied.
	 *
	 * @returns The size of the nonce copied.
	 *
	 * @note Ensure that the buffer pointed by `nonce` is large enough to hold the nonce value.
	 */
	inline unsigned int get_r_nonce(unsigned char *nonce) { memcpy(nonce, reinterpret_cast<unsigned char *>(&m_crypto_info.r_nonce), sizeof(em_nonce_t)); return sizeof(em_nonce_t); }

    
	/**!
	 * @brief Retrieves the e_nonce value.
	 *
	 * This function returns a pointer to the e_nonce value stored in m_crypto_info.
	 *
	 * @returns A pointer to the e_nonce value.
	 */
	inline unsigned char *get_e_nonce() { return reinterpret_cast<unsigned char *>(&m_crypto_info.e_nonce); }
    
	/**!
	 * @brief Retrieves the r_nonce value.
	 *
	 * This function returns a pointer to the r_nonce value stored in the m_crypto_info structure.
	 *
	 * @returns A pointer to the r_nonce value as an unsigned char.
	 */
	inline unsigned char *get_r_nonce() { return reinterpret_cast<unsigned char *>(&m_crypto_info.r_nonce); }

    
	/**!
	 * @brief Sets the e_uuid value.
	 *
	 * This function copies the provided UUID into the e_uuid member of the m_crypto_info structure.
	 *
	 * @param[in] uuid Pointer to the UUID to be set.
	 * @param[in] len Length of the UUID.
	 *
	 * @note Ensure that the length of the UUID does not exceed the size of e_uuid in m_crypto_info.
	 */
	inline void set_e_uuid(unsigned char *uuid, unsigned int len) { memcpy(reinterpret_cast<unsigned char *>(&m_crypto_info.e_uuid), uuid, len); }
    
	/**!
	 * @brief Sets the UUID for the crypto information.
	 *
	 * This function copies the provided UUID into the internal crypto information structure.
	 *
	 * @param[in] uuid Pointer to the UUID to be set.
	 * @param[in] len Length of the UUID.
	 *
	 * @note Ensure that the length of the UUID does not exceed the allocated space in the internal structure.
	 */
	inline void set_r_uuid(unsigned char *uuid, unsigned int len) { memcpy(reinterpret_cast<unsigned char *>(&m_crypto_info.r_uuid), uuid, len); }
    
	/**!
	 * @brief Sets the encryption nonce.
	 *
	 * This function copies the provided nonce into the internal encryption nonce structure.
	 *
	 * @param[in] nonce Pointer to the nonce data to be set.
	 * @param[in] len Length of the nonce data.
	 *
	 * @note Ensure that the nonce data is of the correct length before calling this function.
	 */
	inline void set_e_nonce(unsigned char *nonce, unsigned int len) { memcpy(reinterpret_cast<unsigned char *>(&m_crypto_info.e_nonce), nonce, len); }
    
	/**!
	 * @brief Sets the r_nonce value.
	 *
	 * This function copies the provided nonce into the r_nonce member of m_crypto_info.
	 *
	 * @param[in] nonce Pointer to the nonce data to be set.
	 * @param[in] len Length of the nonce data.
	 *
	 * @note Ensure that the nonce data is valid and the length is appropriate before calling this function.
	 */
	inline void set_r_nonce(unsigned char *nonce, unsigned int len) { memcpy(reinterpret_cast<unsigned char *>(&m_crypto_info.r_nonce), nonce, len); }

    
	/**!
	 * @brief Retrieves the public encryption key.
	 *
	 * @returns A pointer to the public encryption key.
	 */
	inline unsigned char *get_e_public() { return m_crypto_info.e_pub; }
    
	/**!
	 * @brief Retrieves the length of the public exponent.
	 *
	 * This function returns the length of the public exponent used in the cryptographic operations.
	 *
	 * @returns The length of the public exponent.
	 *
	 * @note This is an inline function for quick access to the public exponent length.
	 */
	inline unsigned int get_e_public_len() { return m_crypto_info.e_pub_len; }
    
	/**!
	 * @brief Retrieves the private key for encryption.
	 *
	 * This function returns a pointer to the private key used for encryption.
	 *
	 * @returns A pointer to the private key.
	 *
	 * @note Ensure that the returned pointer is handled securely to prevent unauthorized access.
	 */
	inline unsigned char *get_e_private() { return m_crypto_info.e_priv; }
    
	/**!
	 * @brief Retrieves the length of the private key for 'e'.
	 *
	 * This function returns the length of the private key associated with 'e'.
	 *
	 * @returns The length of the private key for 'e'.
	 */
	inline unsigned int get_e_private_len() { return m_crypto_info.e_priv_len; }
    
	/**!
	 * @brief Retrieves the public key.
	 *
	 * This function returns a pointer to the public key stored in the
	 * `m_crypto_info` structure.
	 *
	 * @returns A pointer to the public key.
	 *
	 * @note Ensure that the returned pointer is not modified.
	 */
	inline unsigned char *get_r_public() { return m_crypto_info.r_pub; }
    
	/**!
	 * @brief Retrieves the length of the public key.
	 *
	 * @returns The length of the public key as an unsigned integer.
	 */
	inline unsigned int get_r_public_len() { return m_crypto_info.r_pub_len; }
    
	/**!
	 * @brief Retrieves the private key.
	 *
	 * This function returns a pointer to the private key stored in the
	 * m_crypto_info structure.
	 *
	 * @returns A pointer to the private key.
	 *
	 * @note Ensure that the returned pointer is handled securely to prevent
	 * unauthorized access to the private key.
	 */
	inline unsigned char *get_r_private() { return m_crypto_info.r_priv; }
    
	/**!
	 * @brief Retrieves the length of the private key.
	 *
	 * This function returns the length of the private key stored in the
	 * `m_crypto_info` structure.
	 *
	 * @returns The length of the private key as an unsigned integer.
	 */
	inline unsigned int get_r_private_len() { return m_crypto_info.r_priv_len; }

    
	/**!
	 * @brief Sets the public key for encryption.
	 *
	 * This function copies the provided public key into the internal storage.
	 *
	 * @param[in] pub Pointer to the public key data.
	 * @param[in] len Length of the public key data.
	 *
	 * @note Ensure that the length of the public key data does not exceed the allocated space.
	 */
	inline void set_e_public(unsigned char *pub, unsigned int len) { memcpy(m_crypto_info.e_pub, pub, len); }
    
	/**!
	 * @brief Sets the public key.
	 *
	 * This function copies the provided public key into the internal structure.
	 *
	 * @param[in] pub Pointer to the public key data.
	 * @param[in] len Length of the public key data.
	 *
	 * @note Ensure that the length of the public key does not exceed the buffer size.
	 */
	inline void set_r_public(unsigned char *pub, unsigned int len) { memcpy(m_crypto_info.r_pub, pub, len); }

    
	/**!
	 * @brief Retrieves the e_mac value.
	 *
	 * @returns Pointer to the e_mac value.
	 */
	inline unsigned char *get_e_mac() { return m_crypto_info.e_mac; }
    
	/**!
	 * @brief Retrieves the MAC address.
	 *
	 * @returns A pointer to the MAC address.
	 */
	inline unsigned char *get_r_mac() { return m_crypto_info.r_mac; }

    
	/**!
	 * @brief Sets the E-MAC address.
	 *
	 * This function copies the provided MAC address into the internal
	 * E-MAC storage of the crypto information structure.
	 *
	 * @param[in] mac Pointer to the MAC address to be set.
	 *
	 * @note Ensure that the MAC address provided is of the correct size
	 *       as expected by the system.
	 */
	inline void set_e_mac(unsigned char *mac) { memcpy(m_crypto_info.e_mac, mac, sizeof(mac_address_t)); }
    
	/**!
	 * @brief Sets the R_MAC address.
	 *
	 * This function copies the MAC address from the provided input to the
	 * internal R_MAC storage.
	 *
	 * @param[in] mac Pointer to the MAC address to be set.
	 *
	 * @note The size of the MAC address is assumed to be sizeof(mac_address_t).
	 */
	inline void set_r_mac(unsigned char *mac) { memcpy(m_crypto_info.r_mac, mac, sizeof(mac_address_t)); }

	/**
	 * @brief Convert a hash to a hex string
	 *
	 * This function takes a hash and its length, converting it into a
	 * hexadecimal string representation.
	 *
	 * @param[in] hash The hash to convert
	 * @param[in] hash_len The length of the hash
	 * @return std::string The hex string representation of the hash
	 */
	static std::string hash_to_hex_string(const uint8_t *hash, size_t hash_len);

    
	/**
	 * @brief Convert a hash to a hex string.
	 *
	 * This function takes a vector of bytes representing a hash and converts it
	 * into a hexadecimal string representation.
	 *
	 * @param[in] hash Vector containing the hash to convert.
	 *
	 * @returns std::string The hex string representation of the hash.
	 */
	static std::string hash_to_hex_string(const std::vector<uint8_t>& hash);
    
	/**!
	 * @brief Constructor for the em_crypto_t class.
	 *
	 * Initializes a new instance of the em_crypto_t class.
	 *
	 * @note This constructor does not take any parameters and does not return any values.
	 */
	em_crypto_t();
    
	/**!
	 * @brief Destructor for the em_crypto_t class.
	 *
	 * This destructor is responsible for cleaning up resources used by the em_crypto_t instance.
	 *
	 * @note Ensure that all resources are properly released before the object is destroyed.
	 */
	~em_crypto_t() {}
};


// Custom deleters for OpenSSL objects to use with std::unique_ptr
struct BIODeleter {
    void operator()(BIO* bio) const { if (bio) BIO_free(bio); }
};

struct BNDeleter {
    void operator()(BIGNUM* bn) const { if (bn) BN_free(bn); }
};

struct ECPointDeleter {
    void operator()(EC_POINT* point) const { if (point) EC_POINT_free(point); }
};

struct ECGroupDeleter {
    void operator()(EC_GROUP* group) const { if (group) EC_GROUP_free(group); }
};

struct SSLKeyDeleter {
    void operator()(SSL_KEY* key) const { if (key) em_crypto_t::free_key(key); }
};

struct BuffDeleter {
    void operator()(uint8_t* buff) const { if (buff) OPENSSL_free(buff); }
};


using scoped_ssl_key = std::unique_ptr<SSL_KEY, SSLKeyDeleter>;
using scoped_bio = std::unique_ptr<BIO, BIODeleter>;
using scoped_bn = std::unique_ptr<BIGNUM, BNDeleter>;
using scoped_ec_point = std::unique_ptr<EC_POINT, ECPointDeleter>;
using scoped_ec_group = std::unique_ptr<EC_GROUP, ECGroupDeleter>;
using scoped_buff = std::unique_ptr<uint8_t, BuffDeleter>;
#endif
