// Ed25519 implementation using OpenSSL EVP API (works with OpenSSL 3.x and LibreSSL)
// Falls back to a minimal ref impl if OpenSSL is not available.

#include "ed25519.h"

#include <string.h>

#if defined(USE_OPENSSL)
#include <openssl/evp.h>
#include <openssl/rand.h>

void ed25519_create_keypair(uint8_t* public_key, uint8_t* private_key) {
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    size_t pub_len = 32, priv_len = 64;
    // Extract raw private key (seed, 32 bytes)
    uint8_t seed[32];
    size_t seed_len = 32;
    EVP_PKEY_get_raw_private_key(pkey, seed, &seed_len);
    EVP_PKEY_get_raw_public_key(pkey, public_key, &pub_len);

    // Store as seed + public_key (64 bytes total, matching NaCl convention)
    memcpy(private_key, seed, 32);
    memcpy(private_key + 32, public_key, 32);

    EVP_PKEY_free(pkey);
}

void ed25519_sign(uint8_t* signature, const uint8_t* message,
                  size_t message_len, const uint8_t* private_key) {
    // private_key is seed (first 32 bytes)
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                                    private_key, 32);
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, pkey);
    size_t sig_len = 64;
    EVP_DigestSign(md_ctx, signature, &sig_len, message, message_len);
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
}

int ed25519_verify(const uint8_t* signature, const uint8_t* message,
                   size_t message_len, const uint8_t* public_key) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                                   public_key, 32);
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey);
    int result = EVP_DigestVerify(md_ctx, signature, 64, message, message_len);
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return result == 1 ? 1 : 0;
}

#else
// Minimal fallback: uses /dev/urandom for key generation
// and the ref10 Ed25519 from SUPERCOP (simplified)
// For real usage, link against libsodium or openssl.
#error "Ed25519 requires OpenSSL. Build with -DUSE_OPENSSL"
#endif
