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
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include "aes_siv.h"

/*
 * This is an implementation of Synthetic Initialization Vector (SIV) mode
 * and the S2V operation as defined in "Deterministic Authenticated Encryption,
 * A Provable-Security Treatment of the Key-Wrap Problem" by Phil Rogaway and 
 * Tom Shrimpton.
 *
 * SIV provides deterministic authenticated encryption with associated data.
 * It uses the S2V construction as a PRF to derive an initialization vector
 * which serves both as a MAC tag and as a synthetic IV for CTR mode encryption.
 *
 * Reference: http://www.cs.ucdavis.edu/~rogaway/papers/keywrap.pdf
 */

#define Rb        0x87  /* Constant for doubling operation - x^128 + x^7 + x^2 + x + 1 */

#define AES_BLOCKS      4

#define AES_128_BYTES    16  /* Size of 128-bit AES key in bytes */
#define AES_192_BYTES    24  /* Size of 192-bit AES key in bytes */
#define AES_256_BYTES    32  /* Size of 256-bit AES key in bytes */
#define SIV_256         256  /* SIV with a pair of 128-bit keys (256 bits total) */
#define SIV_384         384  /* SIV with a pair of 192-bit keys (384 bits total) */
#define SIV_512         512  /* SIV with a pair of 256-bit keys (512 bits total) */

/* Zero block used for initialization and padding operations */
unsigned char zero[AES_BLOCK_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/*
 * Compatibility layer for OpenSSL 1.1 and 3.0
 */
static void aes_encrypt_block(const unsigned char *in, unsigned char *out, SIV_KEY_CTX *ctx)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (*ctx == NULL) {
        // EVP_CIPHER_CTX provided was never initialized
        return;
    }
    
    int outlen = 0;
    // Use the context directly to encrypt just one block
    if (1 != EVP_EncryptUpdate(*ctx, out, &outlen, in, AES_BLOCK_SIZE)) {
        return;
    }
    
    int final_len = 0;
    if (1 != EVP_EncryptFinal_ex(*ctx, out + outlen, &final_len)) {
        return;
    }
#else
    AES_encrypt(in, out, ctx);
#endif
}

static int aes_init(const unsigned char *key, const int bits, SIV_KEY_CTX *ctx)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (*ctx != NULL) {
        EVP_CIPHER_CTX_free(*ctx);
        *ctx = NULL;
    }
    *ctx = EVP_CIPHER_CTX_new();
    if (*ctx == NULL) {
        return -1; // Memory allocation failed
    }

    const EVP_CIPHER* cipher = NULL;
    // Use ECB mode which is equivalent to what AES_encrypt does
    switch (bits) {
        case 128:
            cipher = EVP_aes_128_ecb();
            break;
        case 192:
            cipher = EVP_aes_192_ecb();
            break;
        case 256:
            cipher = EVP_aes_256_ecb();
            break;
        default:
            EVP_CIPHER_CTX_free(*ctx);
            *ctx = NULL;
            return -1; // Unsupported key size
    }

    if (1 != EVP_EncryptInit_ex(*ctx, cipher, NULL, key, NULL)) {
        EVP_CIPHER_CTX_free(*ctx);
        *ctx = NULL;
        return -1; // Initialization failed
    }

    // Disable padding since we're encrypting a single block
    EVP_CIPHER_CTX_set_padding(*ctx, 0);

    return 0; // Success
#else
    return AES_set_encrypt_key(key, bits, ctx);
#endif
}


/*
 * xor()
 *    Performs an XOR operation on two blocks of AES_BLOCK_SIZE bytes.
 *    
 *    @param output  Pointer to the output block, which is XORed in-place
 *    @param input   Pointer to the input block to XOR with the output
 */
static void
xor (unsigned char *output, const unsigned char *input)
{
    int i;

    i = AES_BLOCK_SIZE - 1;
    do {
        output[i] ^= input[i];
        i--;
    } while (i >= 0);
    return;
}

/*
 * times_two()
 *    Computes the product of 2 and "input" as a polynomial multiplication
 *    modulo the prime polynomial x^128 + x^7 + x^2 + x + 1.
 *    This is the doubling operation used in various CMAC and S2V operations.
 *
 *    @param output  Pointer to store the doubled value result
 *    @param input   Pointer to the input value to be doubled
 */
static void
times_two (unsigned char *output, unsigned char *input)
{
    int i;
    unsigned char *out = output, *in = input;
    unsigned char carry = 0;

    out = output + AES_BLOCK_SIZE - 1;
    in = input + AES_BLOCK_SIZE - 1;
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        *(out--) = (*in << 1) | carry;
        carry = (*(in--) & 0x80) ? 1 : 0;
    }

    if (carry) {
        output[AES_BLOCK_SIZE-1] ^= Rb;
    }
    return;
}

/*
 * pad()
 *    Pads a buffer to AES_BLOCK_SIZE bytes using the 10^* padding scheme.
 *    Adds a 1 bit followed by as many 0 bits as needed to reach block size.
 *
 *    @param buf  Buffer to be padded (must have space for AES_BLOCK_SIZE bytes)
 *    @param len  Current length of data in the buffer
 */
static void
pad (unsigned char *buf, int len)
{
    int i;

    i = len;
    buf[i++] = 0x80;
    if (i < AES_BLOCK_SIZE) {
        memset(buf + i, 0, AES_BLOCK_SIZE - i);
    }
}

/*
 * aes_cmac()
 *    Performs the CMAC mode of AES operation per NIST SP 800-38B.
 *    Computes a secure message authentication code using AES.
 *
 *    @param ctx   Pointer to the SIV context containing keys and schedules
 *    @param msg   Pointer to the message to authenticate
 *    @param mlen  Length of the message in bytes
 *    @param C     Output buffer for the computed CMAC (must be AES_BLOCK_SIZE bytes)
 */
void
aes_cmac (siv_ctx *ctx, const unsigned char *msg, int mlen, unsigned char *C)
{
    int n, i, slop;
    unsigned char Mn[AES_BLOCK_SIZE], *ptr;

    memcpy(C, zero, AES_BLOCK_SIZE);

    /*
     * n is the number of block-length blocks
     */
    n = (mlen+(AES_BLOCK_SIZE-1))/AES_BLOCK_SIZE;

    /*
     * CBC mode for first n-1 blocks
     */
    ptr = (unsigned char *)msg;
    for (i = 0; i < (n-1); i++) {
        xor(C, ptr);
        aes_encrypt_block(C, C, &ctx->s2v_sched);
        ptr += AES_BLOCK_SIZE;
    }

    /*
     * if last block is whole then (M ^ K1)
     * else (M || 10* ^ K2)
     */
    memset(Mn, 0, AES_BLOCK_SIZE);
    if ((slop = (mlen % AES_BLOCK_SIZE)) != 0) {
        memcpy(Mn, ptr, slop);
        pad(Mn, slop);
        xor(Mn, ctx->K2);
    } else {
        if (msg != NULL && mlen != 0) {
            memcpy(Mn, ptr, AES_BLOCK_SIZE);
            xor(Mn, ctx->K1);
        } else {
            pad(Mn, 0);
            xor(Mn, ctx->K2);
        }
    }
    /*
     * and do CBC with that xor'd and possibly padded block
     */
    xor(C, Mn);
    aes_encrypt_block(C, C, &ctx->s2v_sched);
    return;
}

/*
 * s2v_final()
 *    Processes the final input block into the S2V construction and outputs the digest.
 *    This completes the S2V operation after all associated data has been processed.
 *
 *    @param ctx      Pointer to the SIV context
 *    @param X        Pointer to the final data block
 *    @param xlen     Length of the final data block in bytes
 *    @param digest   Output buffer for the S2V digest result (must be AES_BLOCK_SIZE bytes)
 *    @return         0 on success, negative value on failure
 */
int
s2v_final (siv_ctx *ctx, const unsigned char *X, int xlen, unsigned char *digest)
{
    unsigned char T[AES_BLOCK_SIZE], C[AES_BLOCK_SIZE];
    unsigned char padX[AES_BLOCK_SIZE], *ptr;
    int blocks, i, slop;

    if (xlen < AES_BLOCK_SIZE) {
        /*
         * if it's less than the block size of the sPRF then
         * do another x2 of our running total and pad the
         * input before the final xor and sPRF.
         */
        memcpy(padX, X, xlen);
        pad(padX, xlen);

        times_two(T, ctx->T);
        xor(T, padX);
        aes_cmac(ctx, T, AES_BLOCK_SIZE, digest);
    } else {
        if (xlen == AES_BLOCK_SIZE) {
            /*
             * the final buffer is exactly the block size
             */
            memcpy(T, X, AES_BLOCK_SIZE);
            xor(T, ctx->T);
            aes_cmac(ctx, T, AES_BLOCK_SIZE, digest);
        } else {
            /*
             * -1 because the last 2 blocks get special treatment
             * and there's another -1 in the for loop below where
             * we AES-CMAC the buffer.
             */
            blocks = (xlen+(AES_BLOCK_SIZE-1))/AES_BLOCK_SIZE - 1;
            ptr = (unsigned char *)X;
            memcpy(C, zero, AES_BLOCK_SIZE);
            if (blocks > 1) {
                /*
                 * do AES-CMAC on all the buffers up to the last 2 blocks
                 */
                for (i = 0; i < (blocks-1); i++) {
                    xor(C, ptr);
                    aes_encrypt_block(C, C, &ctx->s2v_sched);
                    ptr += AES_BLOCK_SIZE;
                }
            }
            memcpy(T, ptr, AES_BLOCK_SIZE);
            slop = xlen % AES_BLOCK_SIZE;
            if (slop) {
                /*
                 * if there's slop then do the xor-end onto this block
                 */
                for (i = 0; i < AES_BLOCK_SIZE - slop; i++) {
                    T[i + slop] ^= ctx->T[i];
                }
                /*
                 * continue with AES-CMAC on this partially xor'd buffer
                 */
                xor(C, T);
                aes_encrypt_block(C, C, &ctx->s2v_sched);
                ptr += AES_BLOCK_SIZE;
                /*
                 * now the final block is small so xor the end then pad and xor
                 */
                memset(T, 0, AES_BLOCK_SIZE);
                memcpy(T, ptr, slop);
                for (i = 0; i < slop; i++) {
                    T[i] ^= ctx->T[(AES_BLOCK_SIZE-slop)+i];
                }
                pad(T, slop);
                xor(T, ctx->K2);
            } else {
                /*
                 * otherwise there's no slop so just AES-CMAC the next whole block
                 */
                xor(C, ptr);
                aes_encrypt_block(C, C, &ctx->s2v_sched);
                ptr += AES_BLOCK_SIZE;
                /*
                 * xor-end the entire last block...
                 */
                memcpy(T, ptr, AES_BLOCK_SIZE);
                xor(T, ctx->T);
                /*
                 * and treat it as the last (whole) block in AES-CMAC
                 */
                xor(T, ctx->K1);
            }
            /*
             * a final CBC finishes AES-CMAC
             */
            xor(C, T);
            aes_encrypt_block(C, digest, &ctx->s2v_sched);
        }

    }
    return 0;
}

/*
 * s2v_add()
 *    Adds a preprocessed block to the current S2V state.
 *    Used to incorporate already-processed (via AES-CMAC) data into the S2V construction.
 *
 *    @param ctx  Pointer to the SIV context
 *    @param Y    Pointer to the preprocessed block (must be AES_BLOCK_SIZE bytes)
 */
void
s2v_add (siv_ctx *ctx, const unsigned char *Y)
{
    unsigned char T[AES_BLOCK_SIZE];

    memcpy(T, ctx->T, AES_BLOCK_SIZE);
    times_two(ctx->T, T);
    xor(ctx->T, Y);
}

/*
 * s2v_update()
 *    Adds a raw data string to the S2V construction.
 *    Computes the AES-CMAC of the input data and adds it to the S2V state.
 *
 *    @param ctx   Pointer to the SIV context
 *    @param X     Pointer to the input data
 *    @param xlen  Length of the input data in bytes
 */
void
s2v_update (siv_ctx *ctx, const unsigned char *X, int xlen)
{
    unsigned char Y[AES_BLOCK_SIZE];

    aes_cmac(ctx, X, xlen, Y);
    s2v_add(ctx, Y);
}

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
int
siv_init (siv_ctx *ctx, const unsigned char *key, int keylen)
{
    unsigned char L[AES_BLOCK_SIZE];

    memset((char *)ctx, 0, sizeof(siv_ctx));
    switch (keylen) {
        case SIV_512:   /* a pair of 256 bit keys */
            aes_init(key, 256, &ctx->s2v_sched);
            aes_init(key+AES_256_BYTES, 256, &ctx->ctr_sched);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
            // Store the raw keys for OpenSSL 3.0
            ctx->ctr_key_bits = 256;
            memcpy(ctx->ctr_key, key+AES_256_BYTES, AES_256_BYTES);
#endif
            break;
        case SIV_384:   /* a pair of 192 bit keys */
            aes_init(key, 192, &ctx->s2v_sched);
            aes_init(key+AES_192_BYTES, 192, &ctx->ctr_sched);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
            // Store the raw keys for OpenSSL 3.0
            ctx->ctr_key_bits = 192;
            memcpy(ctx->ctr_key, key+AES_192_BYTES, AES_192_BYTES);
#endif
            break;
        case SIV_256:   /* a pair of 128 bit keys */
            aes_init(key, 128, &ctx->s2v_sched);
            aes_init(key+AES_128_BYTES, 128, &ctx->ctr_sched);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
            // Store the raw keys for OpenSSL 3.0
            ctx->ctr_key_bits = 128;
            memcpy(ctx->ctr_key, key+AES_128_BYTES, AES_128_BYTES);
#endif
            break;
        default:
            return -1;
    }

    /*
     * compute CMAC subkeys
     */
    aes_encrypt_block(zero, L, &ctx->s2v_sched);
    times_two(ctx->K1, L);
    times_two(ctx->K2, ctx->K1);

    memset(ctx->benchmark, 0, AES_BLOCK_SIZE);
    aes_cmac(ctx, zero, AES_BLOCK_SIZE, ctx->T);
    return 1;
} 

/*
 * siv_restart()
 *    Resets a SIV context to its initial state while preserving key material.
 *    Used to prepare the context for a new encryption/decryption operation.
 *
 *    @param ctx  Pointer to the SIV context to restart
 */
void
siv_restart (siv_ctx *ctx)
{
    memset(ctx->benchmark, 0, AES_BLOCK_SIZE);
    memset(ctx->T, 0, AES_BLOCK_SIZE);
    aes_cmac(ctx, zero, AES_BLOCK_SIZE, ctx->T);
}

/*
 * s2v_benchmark()
 *    Saves the current state of S2V for later reuse.
 *    Used to optimize processing of similar inputs.
 *
 *    @param ctx  Pointer to the SIV context
 */ 
void
s2v_benchmark (siv_ctx *ctx)
{
    memcpy(ctx->benchmark, ctx->T, AES_BLOCK_SIZE);
}

/*
 * s2v_reset()
 *    Restores the S2V state from a saved benchmark.
 *    Used in conjunction with s2v_benchmark to resume from a saved state.
 *
 *    @param ctx  Pointer to the SIV context
 */
void
s2v_reset (siv_ctx *ctx)
{
    memcpy(ctx->T, ctx->benchmark, AES_BLOCK_SIZE);
}

/*
 * siv_aes_ctr()
 *    Performs AES encryption in counter mode using the provided IV.
 *    Used internally by SIV for the encryption/decryption operations.
 *
 *    @param ctx  Pointer to the SIV context
 *    @param p    Pointer to the plaintext input
 *    @param lenp Length of the plaintext in bytes
 *    @param c    Pointer to the output buffer (must be at least lenp bytes)
 *    @param iv   Pointer to the initialization vector (must be AES_BLOCK_SIZE bytes)
 */
void
siv_aes_ctr (siv_ctx *ctx, const unsigned char *p, const int lenp,
        unsigned char *c, const unsigned char *iv)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    // For OpenSSL 3.0, we need a dedicated CTR mode context
    EVP_CIPHER_CTX *ctr_ctx = EVP_CIPHER_CTX_new();
    if (!ctr_ctx) {
        return;
    }
    
    // Select the appropriate CTR cipher based on key size
    const EVP_CIPHER *cipher = NULL;
    switch (ctx->ctr_key_bits) {
        case 128:
            cipher = EVP_aes_128_ctr();
            break;
        case 192:
            cipher = EVP_aes_192_ctr();
            break;
        case 256:
            cipher = EVP_aes_256_ctr();
            break;
        default:
            EVP_CIPHER_CTX_free(ctr_ctx);
            return;
    }
    
    // Make a copy of the IV with the same constraints as in original code
    unsigned char ctr_iv[AES_BLOCK_SIZE];
    memcpy(ctr_iv, iv, AES_BLOCK_SIZE);
    ctr_iv[12] &= 0x7f;
    ctr_iv[8] &= 0x7f;
    
    // Initialize with CTR mode
    if (1 != EVP_EncryptInit_ex(ctr_ctx, cipher, NULL, ctx->ctr_key, ctr_iv)) {
        EVP_CIPHER_CTX_free(ctr_ctx);
        return;
    }
    
    // No padding needed
    EVP_CIPHER_CTX_set_padding(ctr_ctx, 0);
    
    // Process data in one go
    int outlen = 0;
    if (1 != EVP_EncryptUpdate(ctr_ctx, c, &outlen, p, lenp)) {
        EVP_CIPHER_CTX_free(ctr_ctx);
        return;
    }
    
    // Finalize (should be a no-op with no padding)
    int final_len = 0;
    if (1 != EVP_EncryptFinal_ex(ctr_ctx, c + outlen, &final_len)) {
        EVP_CIPHER_CTX_free(ctr_ctx);
        return;
    }
    
    EVP_CIPHER_CTX_free(ctr_ctx);
#else
    int i, j;
    unsigned char ctr[AES_BLOCK_SIZE], ecr[AES_BLOCK_SIZE];
    unsigned long inc;

    memcpy(ctr, iv, AES_BLOCK_SIZE);
    ctr[12] &= 0x7f; ctr[8] &= 0x7f;
    inc = GETU32(ctr + 12);
    for (i = 0; i < lenp; i+=AES_BLOCK_SIZE) {
        AES_encrypt(ctr, ecr, &ctx->ctr_sched);
        for (j = 0; j < AES_BLOCK_SIZE; j++) {
            if ((i + j) == lenp) {
                return;
            }
            c[i+j] = p[i+j] ^ ecr[j];
        }
        inc++; inc &= 0xffffffff;
        PUTU32(ctr + 12, inc);
    }
#endif
}

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
int
siv_encrypt (siv_ctx *ctx, const unsigned char *p, unsigned char *c,
        const int len, unsigned char *counter, 
        const int nad, ...)
{
    va_list ap;
    unsigned char *ad;
    int adlen, numad = nad;
    unsigned char ctr[AES_BLOCK_SIZE];

    if (numad) {
        va_start(ap, nad);
        while (numad) {
            ad = (unsigned char *)va_arg(ap, char *);
            adlen = va_arg(ap, int);
            s2v_update(ctx, ad, adlen);
            numad--;
        }
    }
    s2v_final(ctx, p, len, ctr);
    memcpy(counter, ctr, AES_BLOCK_SIZE);
    siv_aes_ctr(ctx, p, len, c, ctr);
    /*
     * the only part of the context that is carried along with 
     * subsequent calls to siv_encrypt() are the keys, so reset
     * everything else.
     */
    siv_restart(ctx);
    return 1;
}

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
int
siv_decrypt (siv_ctx *ctx, const unsigned char *c, unsigned char *p,
        const int len, unsigned char *counter, 
        const int nad, ...)
{
    va_list ap;
    unsigned char *ad;
    int adlen, numad = nad;
    unsigned char ctr[AES_BLOCK_SIZE];

    memcpy(ctr, counter, AES_BLOCK_SIZE);
    siv_aes_ctr(ctx, c, len, p, ctr);
    if (numad) {
        va_start(ap, nad);
        while (numad) {
            ad = (unsigned char *)va_arg(ap, char *);
            adlen = va_arg(ap, int);
            s2v_update(ctx, ad, adlen);
            numad--;
        }
    }
    s2v_final(ctx, p, len, ctr);

    /*
     * the only part of the context that is carried along with 
     * subsequent calls to siv_decrypt() are the keys, so reset
     * everything else.
     */
    siv_restart(ctx);
    if (memcmp(ctr, counter, AES_BLOCK_SIZE)) {
        memset(p, 0, len);
        return -1;      /* FAIL */
    } else {
        return 1;
    }
}


/*
 * siv_free()
 *    Frees the SIV context and its associated resources.
 *
 *    @param ctx        Pointer to the SIV context
 */
void siv_free (siv_ctx *ctx)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (ctx->s2v_sched != NULL) {
        EVP_CIPHER_CTX_free(ctx->s2v_sched);
        ctx->s2v_sched = NULL;
    }
    if (ctx->ctr_sched != NULL) {
        EVP_CIPHER_CTX_free(ctx->ctr_sched);
        ctx->ctr_sched = NULL;
    }
#endif
    memset(ctx, 0, sizeof(siv_ctx));
}