#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <iostream>

class SECP256R1Crypto {
private:
    static std::string bytesToHex(const unsigned char* data, size_t len) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (size_t i = 0; i < len; i++) {
            ss << std::setw(2) << static_cast<int>(data[i]);
        }
        return ss.str();
    }

    static std::vector<unsigned char> hexToBytes(const std::string& hex) {
        std::vector<unsigned char> bytes;
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
            bytes.push_back(byte);
        }
        return bytes;
    }

public:
    // 시크릿키 생성 (64자리 16진수 문자열 반환)
    static std::string generatePrivateKey() {
        unsigned char privateKey[32];
        EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (!key) {
            throw std::runtime_error("Failed to create EC_KEY");
        }

        if (!EC_KEY_generate_key(key)) {
            EC_KEY_free(key);
            throw std::runtime_error("Failed to generate private key");
        }

        const BIGNUM* priv = EC_KEY_get0_private_key(key);
        BN_bn2binpad(priv, privateKey, 32);
        EC_KEY_free(key);

        return bytesToHex(privateKey, 32);
    }

    // 공개키 파생 (16진수 문자열 반환)
    static std::string derivePublicKey(const std::string& privateKeyHex) {
        EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (!key) {
            throw std::runtime_error("Failed to create EC_KEY");
        }

        BIGNUM* priv = BN_new();
        std::vector<unsigned char> privateKeyBytes = hexToBytes(privateKeyHex);
        BN_bin2bn(privateKeyBytes.data(), privateKeyBytes.size(), priv);

        if (!EC_KEY_set_private_key(key, priv)) {
            BN_free(priv);
            EC_KEY_free(key);
            throw std::runtime_error("Failed to set private key");
        }

        const EC_GROUP* group = EC_KEY_get0_group(key);
        EC_POINT* pub = EC_POINT_new(group);
        if (!EC_POINT_mul(group, pub, priv, nullptr, nullptr, nullptr)) {
            EC_POINT_free(pub);
            BN_free(priv);
            EC_KEY_free(key);
            throw std::runtime_error("Failed to compute public key");
        }

        EC_KEY_set_public_key(key, pub);

        unsigned char publicKey[65];
        size_t len = EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED,
                                      publicKey, 65, nullptr);

        EC_POINT_free(pub);
        BN_free(priv);
        EC_KEY_free(key);

        return bytesToHex(publicKey, len);
    }
    
    // 서명 생성
        static std::string sign(const std::string& message, const std::string& privateKeyHex) {
            EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
            BIGNUM* priv = BN_new();
            std::vector<unsigned char> privateKeyBytes = hexToBytes(privateKeyHex);
            BN_bin2bn(privateKeyBytes.data(), privateKeyBytes.size(), priv);
            EC_KEY_set_private_key(key, priv);

            // 메시지 해시 생성
            unsigned char hash[32];
            EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
            EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
            EVP_DigestUpdate(mdctx, message.c_str(), message.length());
            EVP_DigestFinal_ex(mdctx, hash, nullptr);
            EVP_MD_CTX_free(mdctx);

            // 서명 생성
            ECDSA_SIG* signature = ECDSA_do_sign(hash, sizeof(hash), key);
            if (!signature) {
                BN_free(priv);
                EC_KEY_free(key);
                throw std::runtime_error("Failed to create signature");
            }

            // 서명을 DER 형식으로 변환
            unsigned char *der = nullptr;
            int derLen = i2d_ECDSA_SIG(signature, &der);
            std::string signatureHex = bytesToHex(der, derLen);

            OPENSSL_free(der);
            ECDSA_SIG_free(signature);
            BN_free(priv);
            EC_KEY_free(key);

            return signatureHex;
        }

        // 서명 검증
        static bool verify(const std::string& signatureHex, const std::string& message,
                          const std::string& publicKeyHex) {
            EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
            const EC_GROUP* group = EC_KEY_get0_group(key);
            EC_POINT* pub = EC_POINT_new(group);

            // 공개키 설정
            std::vector<unsigned char> publicKeyBytes = hexToBytes(publicKeyHex);
            EC_POINT_oct2point(group, pub, publicKeyBytes.data(),
                              publicKeyBytes.size(), nullptr);
            EC_KEY_set_public_key(key, pub);

            // 메시지 해시 생성
            unsigned char hash[32];
            EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
            EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
            EVP_DigestUpdate(mdctx, message.c_str(), message.length());
            EVP_DigestFinal_ex(mdctx, hash, nullptr);
            EVP_MD_CTX_free(mdctx);

            // 서명 변환
            std::vector<unsigned char> sigBytes = hexToBytes(signatureHex);
            const unsigned char* sigData = sigBytes.data();
            ECDSA_SIG* signature = d2i_ECDSA_SIG(nullptr, &sigData, sigBytes.size());

            // 검증
            int result = ECDSA_do_verify(hash, sizeof(hash), signature, key);

            ECDSA_SIG_free(signature);
            EC_POINT_free(pub);
            EC_KEY_free(key);

            return result == 1;
        }

};



int main() {
    try {
        // 개인키 생성
        std::string privateKey = SECP256R1Crypto::generatePrivateKey();
        std::cout << "Private Key: " << privateKey << std::endl;

        // 공개키 파생
        std::string publicKey = SECP256R1Crypto::derivePublicKey(privateKey);
        std::cout << "Public Key: " << publicKey << std::endl;
        
        // 3. 메시지 서명
        std::string message = "Hello, World!";
        std::string signature = SECP256R1Crypto::sign(message, privateKey);
        std::cout << "Signature: " << signature << std::endl;

        // 4. 서명 검증
        bool isValid = SECP256R1Crypto::verify(signature, message, publicKey);
        std::cout << "Signature Valid: " << (isValid ? "Yes" : "No") << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    
    
    try {
        // 실패 테스트
        std::cout << "실패 테스트" << std::endl;
        // 1. 개인키 생성
        std::string privateKey = SECP256R1Crypto::generatePrivateKey();
        std::cout << "Private Key: " << privateKey << std::endl;

        // 2. 공개키 파생
        std::string publicKey = SECP256R1Crypto::derivePublicKey(privateKey);
        std::cout << "Public Key: " << publicKey << std::endl;

        // 3. 메시지 서명
        std::string message = "Hello, World!";
        std::string signature = "304402206caa7f734d7ed1abdf6295922daf47e32efa849fbf8fd8128291f59135ad176302200a529b628f534083c400c80822c64a68f08a188e7375c9b129a7a8a7d37d4542";
        std::cout << "Signature: " << signature << std::endl;

        // 4. 서명 검증
        bool isValid = SECP256R1Crypto::verify(signature, message, publicKey);
        std::cout << "Signature Valid: " << (isValid ? "Yes" : "No") << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    
    return 0;
}
