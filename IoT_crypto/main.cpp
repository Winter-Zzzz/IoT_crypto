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
};



int main() {
    try {
        // 개인키 생성
        std::string privateKey = SECP256R1Crypto::generatePrivateKey();
        std::cout << "Private Key: " << privateKey << std::endl;

        // 공개키 파생
        std::string publicKey = SECP256R1Crypto::derivePublicKey(privateKey);
        std::cout << "Public Key: " << publicKey << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    
    return 0;
}
