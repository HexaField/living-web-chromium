#ifndef LIVING_WEB_SHA256_H_
#define LIVING_WEB_SHA256_H_

#include <string>
#include <cstdint>

#if defined(USE_OPENSSL)
#include <openssl/sha.h>
#endif

namespace crypto {

inline std::string SHA256HashString(const std::string& input) {
#if defined(USE_OPENSSL)
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const uint8_t*>(input.data()),
           input.size(), hash);
    return std::string(reinterpret_cast<const char*>(hash), SHA256_DIGEST_LENGTH);
#else
#error "SHA256 requires OpenSSL"
#endif
}

}  // namespace crypto

#endif  // LIVING_WEB_SHA256_H_
