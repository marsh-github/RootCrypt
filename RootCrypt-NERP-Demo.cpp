// RootCrypt-NERP Hybrid Encryption
// Combines quantum-safe NERP-based key exchange with AES-256-GCM authenticated encryption
// This code was not completely revised for actual use and only serves as a demonstration, ignore some sloppy coding mistakes.
// Dependencies: OpenSSL (for AES-GCM and HKDF)
// Author: Marshall Ta
// Date: 2025-07-10T21:15:56Z (UTC Format)

#include <iostream>
#include <array>
#include <vector>
#include <random>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <cstring>

constexpr int kDim = 8;
constexpr int kKeySize = 256;
constexpr int kAesKeyLen = 32;
constexpr int kGcmIVLen = 12;
constexpr int kGcmTagLen = 16;
using Vec = std::array<int32_t, kDim>;

/*
    Internal definitions
*/

std::mt19937_64 rng(1337); // Obviously replace "1337" with a better seed

struct PublicKey {
    std::vector<Vec> projections;
};

struct PrivateKey {
    uint64_t seed;
    std::vector<Vec> preimages;
};

struct CipherText {
    int index;
};

struct HybridCiphertext {
    CipherText root_ct;
    std::vector<unsigned char> iv;
    std::vector<unsigned char> aes_ciphertext;
    std::vector<unsigned char> tag;
    std::vector<unsigned char> salt;
};

/*
    Internal Utility/Gadgets
*/
static Vec EncodeMessageToVec(const std::string& kMessage) {
    Vec output_vector = {};

    for (int i = 0; i < kDim && i < kMessage.size(); ++i) {
        output_vector[i] = static_cast<int32_t>(kMessage[i]);
    }

    return output_vector;
}

static Vec AddNoise(const Vec& kVector, int32_t deviation = 4) {
    std::normal_distribution<double> noise(0.0, deviation);
    Vec output_vector = kVector;

    for (auto& i : output_vector) {
        i += static_cast<int32_t>(noise(rng));
    }

    return output_vector;
}

static Vec SimpleRingMap(const Vec& kInput, uint64_t seed) {
    std::mt19937_64 local_rng(seed);
    Vec input_vector = kInput;

    for (int round = 0; round < 2; ++round) {
        for (int i = 0; i < input_vector.size(); ++i) { // Sorry for the nesting here
            input_vector[i] = (
                input_vector[i]
                * 17 
                + input_vector[(i + 1) % kDim] 
                * 31
                + seed % 9973
            ) % 65536;
        }
    }

    return input_vector;
}

static int32_t CalcVectorHammingDist(
      const Vec& kVectorA,
      const Vec& kVectorB) {
    int32_t output = 0;

    for (int i = 0; i < kDim; ++i) {
        output += std::abs(kVectorA[i] - kVectorB[i]);
    }

    return output;
}

static uint64_t GenerateRandom64BitHex() {
    static std::random_device random_device;
    static std::mt19937_64 rng(random_device());
    static std::uniform_int_distribution<uint64_t> distribution;

    return distribution(rng);
}

/*
    For public use
*/

/**
 * Builds a full public/private keyset of size kKeySize.
 *
 * @param seed           – Master seed for ring mapping
 * @param public_key     – Output buffer for a 'PublicKey' struct containing a 32-byte AES Public key along with metadata
 * @param private_key    – Output buffer for a 'PrivateKey' struct containing a 32-byte AES Private key along with metadata
 *
 * @return
 *   N/A
 */
void GenerateKeyset(uint64_t seed,
                    PublicKey& public_key,
                    PrivateKey& private_key) {
    std::uniform_int_distribution<int32_t> key_dist(-1024, 1024);
    private_key.seed = seed;
    public_key.projections.clear();
    private_key.preimages.clear();

    public_key.projections.reserve(kKeySize);
    private_key.preimages.reserve(kKeySize);

    for (int i = 0; i < kKeySize; ++i) {
        Vec preimage;
        for (auto& xi : preimage) {
            xi = key_dist(rng);
        }

        Vec mapped = SimpleRingMap(preimage, seed);
        Vec projection = AddNoise(mapped);

        private_key.preimages.push_back(std::move(preimage));
        public_key.projections.push_back(std::move(projection));
    }
}

/**
 * Derives a 256-bit AES key using HKDF-SHA256.
 *
 * @param kVectorData    - a Vec of int32 values to be packed into the HKDF input keying material
 * @param kSalt          - a byte vector used as the HKDF salt
 *
 * @return
 *  A 32-byte vector containing the derived AES key, or an empty vector on failure.
 */
std::vector<uint8_t> DeriveAesKey(
      const Vec& kVectorData,
      const std::vector<uint8_t>& kSalt) {
    std::vector<uint8_t> input;
    input.reserve(kVectorData.size() * sizeof(int32_t));
    for (int32_t v : kVectorData) {
        input.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
        input.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        input.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        input.push_back(static_cast<uint8_t>(v & 0xFF));
    }

    std::vector<uint8_t> key(kAesKeyLen);
    size_t out_len = key.size();

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ctx) {
        return {};
    }

    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, kSalt.data(), kSalt.size()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx, input.data(), input.size()) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(
            ctx,
            reinterpret_cast<const uint8_t*>("rootcrypt"),
            sizeof("rootcrypt") - 1) <= 0 ||
        EVP_PKEY_derive(ctx, key.data(), &out_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    EVP_PKEY_CTX_free(ctx);
    return key;
}

/**
 * Encrypts data using AES-256-GCM.
 *
 * @param kKey          - A 32-byte AES key.
 * @param kPlainText    - The input plaintext to encrypt.
 * @param iv            - Output buffer for the randomly generated IV (size = kGcmIVLen).
 * @param cipher_text   - Output buffer for the ciphertext (will be resized to plain_text.size()).
 * @param tag           - Output buffer for the authentication tag (size = kGcmTagLen).
 * 
 * @return
 *  True on successful encryption, false on error.
 */
bool AesGCMEncrypt(
      const std::vector<unsigned char>& kKey,
      const std::string& kPlainText,
      std::vector<unsigned char>& iv,
      std::vector<unsigned char>& cipher_text,
      std::vector<unsigned char>& tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    iv.resize(kGcmIVLen);
    RAND_bytes(iv.data(), kGcmIVLen);

    cipher_text.resize(kPlainText.size());
    tag.resize(kGcmTagLen);

    int len = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kGcmIVLen, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, kKey.data(), iv.data());

    EVP_EncryptUpdate(
        ctx,
        cipher_text.data(),
        &len,
        reinterpret_cast<const unsigned char*>(kPlainText.data()),
        kPlainText.size()
    );
    int cipher_text_len = len;

    EVP_EncryptFinal_ex(ctx, cipher_text.data() + len, &len);
    cipher_text_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kGcmTagLen, tag.data());

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

/**
 * Decrypts ciphertext using AES-256-GCM.
 *
 * @param kKey               - A 32-byte AES key.
 * @param iv                 - The input randomly generated IV (size = kGcmIVLen).
 * @param kCipherText        - The input ciphertext to decrypt.
 * @param tag                - The input authentication tag (size = kGcmTagLen).
 * @param plain_text_out     - Output buffer for the decrypted ciphertext (will be reasigned with the size of kCipherText).
 *
 * @return
 *  True on successful decryption, false on error.
 */
bool AesGCMDecrypt(
      const std::vector<unsigned char>& kKey,
      std::vector<unsigned char> iv,
      const std::vector<unsigned char> kCipherText,
      std::vector<unsigned char> tag,
      std::string& plain_text_out) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    iv.resize(kGcmIVLen);
    tag.resize(kGcmTagLen);

    std::vector<unsigned char> plain_text(kCipherText.size());
    int len = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kGcmIVLen, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, kKey.data(), iv.data());

    EVP_DecryptUpdate(
        ctx,
        plain_text.data(),
        &len,
        kCipherText.data(),
        kCipherText.size()
    );

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kGcmTagLen, const_cast<unsigned char*>(tag.data()));
    int ret = EVP_DecryptFinal_ex(ctx, plain_text.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plain_text_out.assign(plain_text.begin(), plain_text.end());
        return true;
    }
    return false;
}

/**
 * Encrypts plaintext using RootCrypt and AES-256-GCM.
 *
 * @param kMessage           - The Input plaintext to encrypt.
 * @param kPublicKey         - A 'PublicKey' struct containing a 32-byte AES Public key along with metadata
 * @param kPrivateKey        - A 'PrivateKey' struct containing a 32-byte AES Private key along with metadata
 *
 * @return
 *  A 'HybridCiphertext' struct containing the output
 */
HybridCiphertext HybridEncrypt(
      const std::string& kMessage,
      const PublicKey& kPublicKey,
      const PrivateKey& kPrivateKey) {
    Vec message_vector = EncodeMessageToVec(kMessage);

    int best_index = 0;
    int32_t best_distance = INT32_MAX;
    for (int i = 0; i < kPublicKey.projections.size(); ++i) {
        int32_t distance = CalcVectorHammingDist(
            kPublicKey.projections[i],
            message_vector
        );

        if (distance > best_distance) {
            continue;
        }
        best_distance = distance;
        best_index = i;
    }

    Vec pre_vector = kPrivateKey.preimages[best_index];
    Vec mapped = SimpleRingMap(pre_vector, kPrivateKey.seed);

    std::vector<unsigned char> salt(16);
    RAND_bytes(salt.data(), salt.size());

    std::vector<unsigned char> aes_key = DeriveAesKey(mapped, salt);

    HybridCiphertext out;
    out.root_ct.index = best_index;
    out.salt = salt;
    AesGCMEncrypt(
        aes_key,
        kMessage,
        out.iv,
        out.aes_ciphertext,
        out.tag
    );
    return out;
}

/**
 * Decrypts ciphertext using RootCrypt and AES-256-GCM.
 *
 * @param kCt                - The Input ciphertext to decrypt.
 * @param kPrivateKey        - A 'PrivateKey' struct containing a 32-byte AES Private key along with metadata
 *
 * @return
 *  An 'std::string' containing the decrypted ciphertext
 */
std::string HybridDecrypt(
      const HybridCiphertext& kCt,
      const PrivateKey& kPrivateKey) {
    Vec pre_vector = kPrivateKey.preimages[kCt.root_ct.index];
    Vec mapped = SimpleRingMap(pre_vector, kPrivateKey.seed);
    std::vector<unsigned char> aes_key = DeriveAesKey(mapped, kCt.salt);

    std::string decrypted;
    AesGCMDecrypt(
        aes_key,
        kCt.iv,
        kCt.aes_ciphertext,
        kCt.tag,
        decrypted
    );
    return decrypted;
}

/*
    Example usage
*/
int main() {
    uint64_t seed = GenerateRandom64BitHex();
    PublicKey public_key;
    PrivateKey private_key;
    GenerateKeyset(seed, public_key, private_key);

    std::string message = "Quantum-safe AES hybrid encryption using RootCrypt!";
    HybridCiphertext ct = HybridEncrypt(message, public_key, private_key);

    std::string recovered = HybridDecrypt(ct, private_key);

    std::cout << "\nOriginal Message:\n" << message;
    std::cout << "\n\nDecrypted Message:\n" << recovered << "\n";
    return 0;
}
