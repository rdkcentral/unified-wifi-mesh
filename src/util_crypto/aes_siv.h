/*
 * Copyright (c) The Industrial Lounge, 2007
 *
 *  Copyright holder grants permission for redistribution and use in source 
 *  and binary forms, with or without modification, provided that the 
 *  following conditions are met:
 *     1. Redistribution of source code must retain the above copyright
 *        notice, this list of conditions, and the following disclaimer
 *        in all source files.
 *     2. Redistribution in binary form must retain the above copyright
 *        notice, this list of conditions, and the following disclaimer
 *        in the documentation and/or other materials provided with the
 *        distribution.
 *     3. All advertising materials and documentation mentioning features
 *      or use of this software must display the following acknowledgement:
 *
 *        "This product includes software written by
 *         Dan Harkins (dharkins at lounge dot org)"
 *
 *  "DISCLAIMER OF LIABILITY
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE INDUSTRIAL LOUNGE ``AS IS'' 
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
 *  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR 
 *  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INDUSTRIAL LOUNGE BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 *  SUCH DAMAGE."
 *
 * This license and distribution terms cannot be changed. In other words,
 * this code cannot simply be copied and put under another distribution
 * license (including the GNU public license).
 */

/*
 * Modifications by CableLabs for Comcast.
 *     - Enhanced Documentation
 *     - OpenSSL 3.0+ Compatability
 *         - Added `SIV_KEY_CTX` macro and temporary `ctr_key` storage in `siv_ctx`
 * Copyright 2025 Comcast Cable Communications Management, LLC
 */

#ifndef _SIV_H_
#define _SIV_H_

#include <openssl/aes.h>

#if OPENSSL_VERSION_NUMBER < 0x30000000L
#define SIV_KEY_CTX AES_KEY
#else
#include <openssl/evp.h>
#define SIV_KEY_CTX EVP_CIPHER_CTX*
#endif

/*
 * stolen from openssl's aes_locl.h
 */
#if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_AMD64) || defined(_M_X64))
# define SWAP(x) (_lrotl(x, 8) & 0x00ff00ff | _lrotr(x, 8) & 0xff00ff00)
# define GETU32(p) SWAP(*((u32 *)(p)))
# define PUTU32(ct, st) { *((u32 *)(ct)) = SWAP((st)); }
#else
# define GETU32(pt) (((u32)(pt)[0] << 24) ^ ((u32)(pt)[1] << 16) ^ ((u32)(pt)[2] <<  8) ^ ((u32)(pt)[3]))
# define PUTU32(ct, st) { (ct)[0] = (u8)((st) >> 24); (ct)[1] = (u8)((st) >> 16); (ct)[2] = (u8)((st) >>  8); (ct)[3] = (u8)(st); }
#endif
#ifdef AES_LONG
typedef unsigned long u32;
#else
typedef unsigned int u32;
#endif
typedef unsigned short u16;
typedef unsigned char u8;

typedef struct _siv_ctx {
    unsigned char K1[AES_BLOCK_SIZE];
    unsigned char K2[AES_BLOCK_SIZE];
    unsigned char T[AES_BLOCK_SIZE];
    unsigned char benchmark[AES_BLOCK_SIZE];
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    // Store raw keys for OpenSSL 3.0 ctr
    unsigned char ctr_key[AES_BLOCK_SIZE*2]; // Up to 256 bits
    int ctr_key_bits;                        // Key size in bits
#endif
    SIV_KEY_CTX ctr_sched;
    SIV_KEY_CTX s2v_sched;
} siv_ctx;

#define AES_128_BYTES    16
#define AES_192_BYTES    24
#define AES_256_BYTES    32
#define SIV_256         256
#define SIV_384         384
#define SIV_512         512

/*
 * non-exported APIs needed for a more full-throated SIV implementation
void aes_cmac (siv_ctx *, const unsigned char *, int, unsigned char *);
void siv_reset(siv_ctx *);
void s2v_benchmark(siv_ctx *);
void s2v_add(siv_ctx *, const unsigned char *);
void s2v_update(siv_ctx *, const unsigned char *, int);
int s2v_final(siv_ctx *, const unsigned char *, int, unsigned char *);
void siv_restart(siv_ctx *);
void siv_aes_ctr(siv_ctx *, const unsigned char *, const int, unsigned char *, 
                 const unsigned char *);
 */

/*
 * exported APIs
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * siv_init()
 *    Initializes a SIV context with the provided key material.
 *    Sets up the AES key schedules and CMAC subkeys required for SIV operations.
 *
 *    @param ctx     Pointer to the SIV context to initialize
 *    @param key     Pointer to the key material
 *    @param keylen  Length of the key material in bits (must be SIV_256, SIV_384, or SIV_512)
 *    @return        1 on success, -1 on invalid key length
 */
int siv_init(siv_ctx *, const unsigned char *, int);

/*
 * siv_encrypt()
 *    Performs SIV encryption on plaintext with associated data.
 *    Generates a synthetic IV that serves as both MAC tag and counter IV.
 *
 *    @param ctx        Pointer to the SIV context
 *    @param p          Pointer to the plaintext
 *    @param c          Pointer to the ciphertext output buffer (must be at least len bytes)
 *    @param len        Length of the plaintext/ciphertext in bytes
 *    @param counter    Output buffer for the synthetic IV (must be AES_BLOCK_SIZE bytes)
 *    @param nad        Number of associated data items
 *    @param ...        Variable arguments: pairs of (data_ptr, data_len) for each AD item
 *    @return           1 on success, negative on failure
 */
int siv_encrypt(siv_ctx *, const unsigned char *, unsigned char *, 
                const int, unsigned char *, const int, ... );

/*
 * siv_decrypt()
 *    Performs SIV decryption on ciphertext and verifies the synthetic IV.
 *    Decrypts the ciphertext and validates the authentication tag.
 *
 *    @param ctx        Pointer to the SIV context
 *    @param c          Pointer to the ciphertext
 *    @param p          Pointer to the plaintext output buffer (must be at least len bytes)
 *    @param len        Length of the plaintext/ciphertext in bytes
 *    @param counter    Pointer to the synthetic IV for verification (must be AES_BLOCK_SIZE bytes)
 *    @param nad        Number of associated data items
 *    @param ...        Variable arguments: pairs of (data_ptr, data_len) for each AD item
 *    @return           1 on successful decryption and authentication, -1 on verification failure
 */
int siv_decrypt(siv_ctx *, const unsigned char *, unsigned char *,
                const int, unsigned char *, const int, ... );

/*
 * siv_free()
 *    Frees the SIV context and its associated resources.
 *
 *    @param ctx        Pointer to the SIV context
 */
void siv_free (siv_ctx *ctx);

#ifdef __cplusplus
}
#endif

//#undef SIV_KEY_CTX

#endif /* _SIV_H_ */

