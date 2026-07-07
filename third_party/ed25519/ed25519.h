// Minimal Ed25519 header - wraps OpenSSL or provides fallback
#ifndef LIVING_WEB_ED25519_H_
#define LIVING_WEB_ED25519_H_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Generate an Ed25519 keypair.
// public_key: 32 bytes output
// private_key: 64 bytes output
void ed25519_create_keypair(uint8_t* public_key, uint8_t* private_key);

// Sign a message.
// signature: 64 bytes output
// message: message bytes
// message_len: length of message
// private_key: 64 bytes
void ed25519_sign(uint8_t* signature, const uint8_t* message,
                  size_t message_len, const uint8_t* private_key);

// Verify a signature. Returns 1 if valid, 0 if invalid.
int ed25519_verify(const uint8_t* signature, const uint8_t* message,
                   size_t message_len, const uint8_t* public_key);

#ifdef __cplusplus
}
#endif

#endif  // LIVING_WEB_ED25519_H_
