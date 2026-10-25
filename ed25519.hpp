// Ed25519 over OpenSSL EVP. Keys are reference-counted so they copy freely.
// Red25519 (I2P's blinded signature for encrypted LeaseSet2) is not here: the
// blinding transform is I2P-specific and must be ported from a router before blinded
// records are trusted.
#pragma once
#include <memory>
#include <openssl/evp.h>

#include "darcraw/hash.hpp"

namespace darcraw {

class Ed25519 {
public:
    Ed25519() = default;

    static Ed25519 generate() {
        EVP_PKEY* k = nullptr;
        EVP_PKEY_CTX* c = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
        EVP_PKEY_keygen_init(c);
        EVP_PKEY_keygen(c, &k);
        EVP_PKEY_CTX_free(c);
        return Ed25519(k);
    }

    static Ed25519 from_seed(const Bytes& seed32) {
        return Ed25519(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
                                                    seed32.data(), seed32.size()));
    }

    bool valid() const { return (bool)pkey_; }

    Bytes public_bytes() const {
        Bytes p(32);
        size_t n = 32;
        EVP_PKEY_get_raw_public_key(pkey_.get(), p.data(), &n);
        p.resize(n);
        return p;
    }

    Bytes sign(const Bytes& msg) const {
        Bytes sig(64);
        size_t n = 64;
        EVP_MD_CTX* c = EVP_MD_CTX_new();
        EVP_DigestSignInit(c, nullptr, nullptr, nullptr, pkey_.get());
        EVP_DigestSign(c, sig.data(), &n, msg.data(), msg.size());
        EVP_MD_CTX_free(c);
        sig.resize(n);
        return sig;
    }

private:
    explicit Ed25519(EVP_PKEY* k) : pkey_(k, EVP_PKEY_free) {}
    std::shared_ptr<EVP_PKEY> pkey_;
};

inline bool ed25519_verify(const Bytes& pub, const Bytes& msg, const Bytes& sig) {
    EVP_PKEY* vk = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pub.data(), pub.size());
    if (!vk) return false;
    EVP_MD_CTX* c = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(c, nullptr, nullptr, nullptr, vk);
    int r = EVP_DigestVerify(c, sig.data(), sig.size(), msg.data(), msg.size());
    EVP_MD_CTX_free(c);
    EVP_PKEY_free(vk);
    return r == 1;
}

}  // namespace darcraw
