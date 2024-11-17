#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>

class MatterTunnel {
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
    
    static std::string getTypeString(uint16_t types) {
            std::string result;
            // 상위 14비트에서 7개의 2비트 패턴 처리 (인자)
            for (int i = 6; i >= 0; i--) {
                uint16_t argType = (types >> (i * 2 + 2)) & 0x03;
                if (argType == 0x00) break; // void는 더 이상의 인자가 없음을 의미
                
                if (result.length() > 0) result += ",";
                
                switch(argType) {
                    case 0x01: result += "string"; break;
                    case 0x02: result += "number"; break;
                    case 0x03: result += "Boolean"; break;
                }
            }
        
        result += ")";
            
            // 하위 2비트 처리 (반환값)
            std::string returnType;
            switch(types & 0x03) {
                case 0x00: returnType = "void"; break;
                case 0x01: returnType = "string"; break;
                case 0x02: returnType = "number"; break;
                case 0x03: returnType = "Boolean"; break;
            }
            
            return result + "->" + returnType;
        }
    
    // 데이터 리스트 직렬화를 위한 메서드
        static std::vector<unsigned char> serializeDataList(const std::vector<std::string>& dataList) {
            std::vector<unsigned char> serialized;
            
            for (const auto& data : dataList) {
                // 데이터 길이를 1바이트로 추가
                unsigned char length = static_cast<unsigned char>(data.length());
                serialized.push_back(length);
                
                // 데이터 추가
                serialized.insert(serialized.end(), data.begin(), data.end());
            }
            
            return serialized;
        }
    
    // 직렬화된 데이터를 문자열 리스트로 변환하는 새로운 메서드
       static std::vector<std::string> deserializeDataList(const std::string& serializedData) {
           std::vector<std::string> result;
           size_t pos = 0;
           
           while (pos < serializedData.length()) {
               // 데이터 길이 읽기 (1바이트)
               unsigned char length = static_cast<unsigned char>(serializedData[pos++]);
               
               // 데이터 추출
               if (pos + length <= serializedData.length()) {
                   result.push_back(serializedData.substr(pos, length));
                   pos += length;
               } else {
                   break;  // 잘못된 형식이면 중단
               }
           }
           
           return result;
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

            // R, S 값 추출
            const BIGNUM *r, *s;
            ECDSA_SIG_get0(signature, &r, &s);
            
            // R, S 값을 32바이트 고정 길이로 변환
            unsigned char rBytes[32] = {0};
            unsigned char sBytes[32] = {0};
            BN_bn2binpad(r, rBytes, 32);
            BN_bn2binpad(s, sBytes, 32);

            // R과 S를 연결하여 64바이트 시그니처 생성
            std::string signatureHex;
            signatureHex.reserve(128); // 64바이트 * 2
            signatureHex += bytesToHex(rBytes, 32);
            signatureHex += bytesToHex(sBytes, 32);

            ECDSA_SIG_free(signature);
            BN_free(priv);
            EC_KEY_free(key);

            return signatureHex;
        }

        // 서명 검증
    static bool verify(const std::string& signatureHex, const std::string& message,
                          const std::string& publicKeyHex) {
            if (signatureHex.length() != 128) { // 64바이트 시그니처 (R: 32바이트, S: 32바이트)
                throw std::runtime_error("Invalid signature length");
            }

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

            // R, S 값 추출 및 ECDSA_SIG 구조체 생성
            std::string rHex = signatureHex.substr(0, 64);
            std::string sHex = signatureHex.substr(64, 64);
            std::vector<unsigned char> rBytes = hexToBytes(rHex);
            std::vector<unsigned char> sBytes = hexToBytes(sHex);

            ECDSA_SIG* signature = ECDSA_SIG_new();
            BIGNUM* r = BN_new();
            BIGNUM* s = BN_new();
            BN_bin2bn(rBytes.data(), rBytes.size(), r);
            BN_bin2bn(sBytes.data(), sBytes.size(), s);
            ECDSA_SIG_set0(signature, r, s); // r, s 소유권이 signature로 이전됨

            // 검증
            int result = ECDSA_do_verify(hash, sizeof(hash), signature, key);

            ECDSA_SIG_free(signature); // 내부적으로 r, s도 해제됨
            EC_POINT_free(pub);
            EC_KEY_free(key);

            return result == 1;
        }
    
    // 공유키 생성
    static std::string getSharedKey(const std::string& secretKeyHex, const std::string& publicKeyHex) {
            EC_KEY* privateKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
            if (!privateKey) {
                throw std::runtime_error("Failed to create EC_KEY for private key");
            }

            // 개인키 설정
            BIGNUM* priv = BN_new();
            std::vector<unsigned char> secretKeyBytes = hexToBytes(secretKeyHex);
            BN_bin2bn(secretKeyBytes.data(), secretKeyBytes.size(), priv);
            if (!EC_KEY_set_private_key(privateKey, priv)) {
                BN_free(priv);
                EC_KEY_free(privateKey);
                throw std::runtime_error("Failed to set private key");
            }

            // 공개키 포인트 생성
            const EC_GROUP* group = EC_KEY_get0_group(privateKey);
            EC_POINT* pub = EC_POINT_new(group);
            std::vector<unsigned char> publicKeyBytes = hexToBytes(publicKeyHex);
            
            if (!EC_POINT_oct2point(group, pub, publicKeyBytes.data(), publicKeyBytes.size(), nullptr)) {
                EC_POINT_free(pub);
                BN_free(priv);
                EC_KEY_free(privateKey);
                throw std::runtime_error("Failed to create public key point");
            }

            // 공유 비밀 계산
            unsigned char sharedSecret[32];
            BIGNUM* sharedSecretBN = BN_new();
            EC_POINT* sharedPoint = EC_POINT_new(group);
            
            // 공유 포인트 계산: publicKey * privateKey
            if (!EC_POINT_mul(group, sharedPoint, nullptr, pub, priv, nullptr)) {
                BN_free(sharedSecretBN);
                EC_POINT_free(sharedPoint);
                EC_POINT_free(pub);
                BN_free(priv);
                EC_KEY_free(privateKey);
                throw std::runtime_error("Failed to compute shared point");
            }

            // x 좌표만 추출
            if (!EC_POINT_get_affine_coordinates(group, sharedPoint, sharedSecretBN, nullptr, nullptr)) {
                BN_free(sharedSecretBN);
                EC_POINT_free(sharedPoint);
                EC_POINT_free(pub);
                BN_free(priv);
                EC_KEY_free(privateKey);
                throw std::runtime_error("Failed to get shared secret");
            }

            // BIGNUM을 바이트 배열로 변환
            BN_bn2binpad(sharedSecretBN, sharedSecret, 32);

            // 정리
            BN_free(sharedSecretBN);
            EC_POINT_free(sharedPoint);
            EC_POINT_free(pub);
            BN_free(priv);
            EC_KEY_free(privateKey);

            return bytesToHex(sharedSecret, 32);
        }
    
    // 암호화
    static std::string encrypt(const std::string& key, const std::string& msg) {
            unsigned char nonce[12];
            if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
                throw std::runtime_error("Failed to generate nonce");
            }

            unsigned char keyHash[32];
            EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
            EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
            EVP_DigestUpdate(mdctx, key.c_str(), key.length());
            EVP_DigestFinal_ex(mdctx, keyHash, nullptr);
            EVP_MD_CTX_free(mdctx);

            unsigned char tag[16];
            
            std::vector<unsigned char> ciphertext(msg.length());
            int ciphertext_len;

            // CCM 컨텍스트 초기화
            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) {
                throw std::runtime_error("Failed to create cipher context");
            }

            // CCM 모드 초기화
            if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), nullptr, nullptr, nullptr)) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Failed to initialize CCM mode");
            }

            // CCM 파라미터 설정
            if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, sizeof(nonce), nullptr) ||
                !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, sizeof(tag), nullptr)) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Failed to set CCM parameters");
            }

            // 키와 nonce로 암호화 초기화
            if (!EVP_EncryptInit_ex(ctx, nullptr, nullptr, keyHash, nonce)) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Failed to initialize encryption");
            }

            // 평문 길이 설정
            if (!EVP_EncryptUpdate(ctx, nullptr, &ciphertext_len, nullptr, msg.length())) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Failed to set message length");
            }

            // 암호화 수행
            if (!EVP_EncryptUpdate(ctx, ciphertext.data(), &ciphertext_len,
                                  reinterpret_cast<const unsigned char*>(msg.c_str()), msg.length())) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Failed to encrypt message");
            }

            // 암호화 종료 및 태그 얻기
            if (!EVP_EncryptFinal_ex(ctx, ciphertext.data() + ciphertext_len, &ciphertext_len)) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Failed to finalize encryption");
            }

            if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, 16, tag)) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Failed to get tag");
            }

            EVP_CIPHER_CTX_free(ctx);

            // nonce(12) + ciphertext + tag(16)를 하나의 문자열로 결합
            std::string result;
            result.reserve(12 + msg.length() + 16);
            result.append(reinterpret_cast<char*>(nonce), 12);
            result.append(reinterpret_cast<char*>(ciphertext.data()), msg.length());
            result.append(reinterpret_cast<char*>(tag), 16);

            return bytesToHex(reinterpret_cast<const unsigned char*>(result.c_str()), result.length());
        }
    
        // 복호화
        static std::string decrypt(const std::string& key, const std::string& encryptedHex) {
            // 16진수 문자열을 바이트로 변환
            std::vector<unsigned char> encrypted = hexToBytes(encryptedHex);
            if (encrypted.size() < 28) { // 최소 nonce(12) + tag(16) 필요
                throw std::runtime_error("Invalid encrypted data length");
            }

            // 키 해시 생성
            unsigned char keyHash[32];
            EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
            EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
            EVP_DigestUpdate(mdctx, key.c_str(), key.length());
            EVP_DigestFinal_ex(mdctx, keyHash, nullptr);
            EVP_MD_CTX_free(mdctx);

            // nonce, ciphertext, tag 분리
            unsigned char* nonce = encrypted.data();
            size_t ciphertext_len = encrypted.size() - 28;
            unsigned char* ciphertext = encrypted.data() + 12;
            unsigned char* tag = encrypted.data() + encrypted.size() - 16;

            // 복호화할 평문 버퍼
            std::vector<unsigned char> plaintext(ciphertext_len);
            int plaintext_len;

            // CCM 컨텍스트 초기화
            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) {
                throw std::runtime_error("Failed to create cipher context");
            }

            // CCM 모드 초기화
            if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), nullptr, nullptr, nullptr)) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Failed to initialize CCM mode");
            }

            // CCM 파라미터 설정
            if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 12, nullptr) ||
                !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 16, tag)) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Failed to set CCM parameters");
            }

            // 키와 nonce로 복호화 초기화
            if (!EVP_DecryptInit_ex(ctx, nullptr, nullptr, keyHash, nonce)) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Failed to initialize decryption");
            }

            // 암호문 길이 설정
            if (!EVP_DecryptUpdate(ctx, nullptr, &plaintext_len, nullptr, ciphertext_len)) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Failed to set ciphertext length");
            }

            // 복호화 수행
            if (!EVP_DecryptUpdate(ctx, plaintext.data(), &plaintext_len, ciphertext, ciphertext_len)) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Failed to decrypt message or tag verification failed");
            }

            EVP_CIPHER_CTX_free(ctx);

            return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
        }
    
    // 디바이스 정보 추출
    static std::string ExtractDeviceInfo(const std::vector<unsigned char>& data) {
            if (data.size() < 49) { // 최소 크기: publicKey(33) + passcode(16)
                throw std::runtime_error("Invalid data size");
            }

            // 1. Public Key 처리
            std::vector<unsigned char> compressedKey(data.begin(), data.begin() + 33);
            
            // compressed public key를 uncompressed form으로 변환
            EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
            const EC_GROUP* group = EC_KEY_get0_group(key);
            EC_POINT* point = EC_POINT_new(group);
            
            if (!EC_POINT_oct2point(group, point, compressedKey.data(), compressedKey.size(), nullptr)) {
                EC_POINT_free(point);
                EC_KEY_free(key);
                throw std::runtime_error("Failed to decompress public key");
            }

            unsigned char uncompressedKey[65];
            size_t uncompressedLen = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                                                       uncompressedKey, 65, nullptr);

            // 2. Passcode 처리
            std::vector<unsigned char> passcode(data.begin() + 33, data.begin() + 49);

            // 3. Functions 처리
            std::vector<std::string> functions;
            size_t pos = 49;
            
            while (pos + 20 <= data.size()) {
                // Function name (18 bytes)
                std::string funcName;
                for (size_t i = 0; i < 18; i++) {
                    if (data[pos + i] != 0) {
                        funcName += static_cast<char>(data[pos + i]);
                    }
                }
                
                // Function types (2 bytes)
                uint16_t types = (data[pos + 18] << 8) | data[pos + 19];
                
                // Function signature 생성
                std::string funcSig = funcName + "(" + getTypeString(types);
                functions.push_back(funcSig);
                
                pos += 20;
            }

            // JSON 형식의 출력 생성
            std::stringstream json;
            json << "{\"publicKey\":\"" << bytesToHex(uncompressedKey, uncompressedLen)
                 << "\",\"passcode\":\"" << bytesToHex(passcode.data(), passcode.size())
                 << "\",\"functions\":[";
            
            for (size_t i = 0; i < functions.size(); i++) {
                if (i > 0) json << ",";
                json << "\"" << functions[i] << "\"";
            }
            json << "]}";

            EC_POINT_free(point);
            EC_KEY_free(key);

            return json.str();
        }
    
    static std::vector<unsigned char> makeTX(const std::string& funcName,
                                               const std::string& src_priv,
                                               const std::string& dest_pub,
                                               const std::vector<std::string>& data_list) {
            std::vector<unsigned char> result;
            
            // 1. 공유키 생성
            std::string sharedKey = getSharedKey(src_priv, dest_pub);
            
            // 2. src_pub 파생
            std::string src_pub = derivePublicKey(src_priv);
            
            // 압축된 공개키로 변환 (uncompressed -> compressed)
            std::vector<unsigned char> uncompressedPubBytes = hexToBytes(src_pub);
            EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
            const EC_GROUP* group = EC_KEY_get0_group(key);
            EC_POINT* point = EC_POINT_new(group);
            EC_POINT_oct2point(group, point, uncompressedPubBytes.data(), uncompressedPubBytes.size(), nullptr);
            
            unsigned char compressedKey[33];
            EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, compressedKey, 33, nullptr);
            
            // 3. 데이터 직렬화
            std::vector<unsigned char> serializedData = serializeDataList(data_list);
            
            // 4. 직렬화된 데이터 암호화
            std::string encryptedData = encrypt(sharedKey,
                std::string(serializedData.begin(), serializedData.end()));
            std::vector<unsigned char> encryptedBytes = hexToBytes(encryptedData);
            
            // 5. 현재 타임스탬프 얻기
            auto now = std::chrono::system_clock::now();
            auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                now.time_since_epoch()).count();
            
            // 6. TX 데이터 조합
            // 6.1 Function name (18 bytes)
            std::string paddedFuncName = funcName;
            paddedFuncName.resize(18, '\0');
            result.insert(result.end(), paddedFuncName.begin(), paddedFuncName.end());
            
            // 6.2 Compressed public key (33 bytes)
            result.insert(result.end(), compressedKey, compressedKey + 33);
            
            // 6.3 Timestamp (8 bytes)
            for(int i = 0; i < 8; i++) {
                result.push_back(static_cast<unsigned char>((timestamp >> (i * 8)) & 0xFF));
            }
            
            // 6.4 Encrypted data
            result.insert(result.end(), encryptedBytes.begin(), encryptedBytes.end());
            
            // 7. 서명 생성 및 추가
            std::string signature = sign(std::string(result.begin(), result.end()), src_priv);
            std::vector<unsigned char> signatureBytes = hexToBytes(signature);
            
            // 최종 결과: signature + TX data
            std::vector<unsigned char> finalResult;
            finalResult.insert(finalResult.end(), signatureBytes.begin(), signatureBytes.end());
            finalResult.insert(finalResult.end(), result.begin(), result.end());
            
            // 정리
            EC_POINT_free(point);
            EC_KEY_free(key);
            
            return finalResult;
        }
    
    static std::string extractTXData(const std::string& privateKey,
                                           const std::vector<unsigned char>& txBytes) {
                if (txBytes.size() < 71) { // 최소 크기: signature(64) + funcName(18) + compressed pubkey(33) + timestamp(8)
                    throw std::runtime_error("Invalid TX data size");
                }

                // 1. 서명과 데이터 분리
                std::vector<unsigned char> signature(txBytes.begin(), txBytes.begin() + 64);
                std::vector<unsigned char> txData(txBytes.begin() + 64, txBytes.end());
                
                // 2. 서명 검증
                std::string signatureHex = bytesToHex(signature.data(), signature.size());
                std::string txDataStr(txData.begin(), txData.end());
                
                // compressed public key 추출 (33바이트)
                std::vector<unsigned char> compressedPubKey(txData.begin() + 18, txData.begin() + 51);
                
                // compressed public key를 uncompressed form으로 변환
                EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
                const EC_GROUP* group = EC_KEY_get0_group(key);
                EC_POINT* point = EC_POINT_new(group);
                
                if (!EC_POINT_oct2point(group, point, compressedPubKey.data(), compressedPubKey.size(), nullptr)) {
                    EC_POINT_free(point);
                    EC_KEY_free(key);
                    throw std::runtime_error("Failed to decompress public key");
                }

                unsigned char uncompressedKey[65];
                size_t uncompressedLen = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                                                           uncompressedKey, 65, nullptr);
                
                std::string srcPub = bytesToHex(uncompressedKey, uncompressedLen);
                
                if (!verify(signatureHex, txDataStr, srcPub)) {
                    EC_POINT_free(point);
                    EC_KEY_free(key);
                    throw std::runtime_error("Invalid signature");
                }
                
                // 3. 데이터 파싱
                // 3.1 Function name (18바이트)
                std::string funcName(txData.begin(), txData.begin() + 18);
                // null 문자 제거
                funcName = funcName.substr(0, funcName.find('\0'));
                
                // 3.2 Source public key는 이미 추출됨 (33바이트)
                
                // 3.3 Timestamp (8바이트)
                uint64_t timestamp = 0;
                for(int i = 0; i < 8; i++) {
                    timestamp |= static_cast<uint64_t>(txData[51 + i]) << (i * 8);
                }
                
                // 3.4 암호화된 데이터
                std::vector<unsigned char> encryptedData(txData.begin() + 59, txData.end());
                std::string encryptedHex = bytesToHex(encryptedData.data(), encryptedData.size());
                
                // 4. 공유키 생성 및 복호화
                std::string sharedKey = getSharedKey(privateKey, srcPub);
                std::string decryptedData = decrypt(sharedKey, encryptedHex);
                
                // 5. 복호화된 데이터 역직렬화
                std::vector<std::string> dataList = deserializeDataList(decryptedData);
                
                // 6. JSON 형식으로 결과 생성
                std::stringstream json;
                json << "{\"funcName\":\"" << funcName << "\","
                     << "\"srcPub\":\"" << srcPub << "\","
                     << "\"timeStamp\":\"" << timestamp << "\","
                     << "\"data\":[";
                
                for (size_t i = 0; i < dataList.size(); i++) {
                    if (i > 0) json << ",";
                    json << "\"" << dataList[i] << "\"";
                }
                json << "]}";
                
                EC_POINT_free(point);
                EC_KEY_free(key);
                
                return json.str();
            }
};

std::string bytesToHexForTest(const unsigned char* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; i++) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

int main() {
    try {
        // 개인키 생성
        std::string privateKey = MatterTunnel::generatePrivateKey();
        std::cout << "Private Key: " << privateKey << std::endl;

        // 공개키 파생
        std::string publicKey = MatterTunnel::derivePublicKey(privateKey);
        std::cout << "Public Key: " << publicKey << std::endl;
        
        // 3. 메시지 서명
        std::string message = "Hello, World!!!!!!!!";
        std::string signature = MatterTunnel::sign(message, privateKey);
        std::cout << "Signature: " << signature << std::endl;

        // 4. 서명 검증
        bool isValid = MatterTunnel::verify(signature, message, publicKey);
        std::cout << "Signature Valid: " << (isValid ? "Yes" : "No") << std::endl;
        
        // 5. 공유키 생성
        std::string alicePrivateKey = MatterTunnel::generatePrivateKey();
        std::string alicePublicKey = MatterTunnel::derivePublicKey(alicePrivateKey);

        std::string bobPrivateKey = MatterTunnel::generatePrivateKey();
        std::string bobPublicKey = MatterTunnel::derivePublicKey(bobPrivateKey);

        std::string sharedKey1 = MatterTunnel::getSharedKey(alicePrivateKey, bobPublicKey);
        std::string sharedKey2 = MatterTunnel::getSharedKey(bobPrivateKey, alicePublicKey);
        
        std::cout << "SharedKey Value: " << sharedKey1 << std::endl;
        std::cout << "SharedKey Valid: " << (sharedKey1 == sharedKey2 ? "Yes" : "No") << std::endl;
        
        // 6. 암호화 및 복호화

        // 암호화
        std::string encrypted = MatterTunnel::encrypt(sharedKey1, message);
        std::cout << "Encrypted: " << encrypted << std::endl;

        // 복호화
        std::string decrypted = MatterTunnel::decrypt(sharedKey2, encrypted);
        std::cout << "Decrypted: " << decrypted << std::endl;
        
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    
    
    try {
        // 서명 검증 실패 테스트
        std::cout << "------------------------" << std::endl << std::endl;
        std::cout << "실패 테스트" << std::endl;
        // 1. 개인키 생성
        std::string privateKey = MatterTunnel::generatePrivateKey();
        std::cout << "Private Key: " << privateKey << std::endl;

        // 2. 공개키 파생
        std::string publicKey = MatterTunnel::derivePublicKey(privateKey);
        std::cout << "Public Key: " << publicKey << std::endl;

        // 3. 메시지 서명
        std::string message = "Hello, World!";
        std::string signature = "304402206caa7f734d7ed1abdf6295922daf47e32efa849fbf8fd8128291f59135ad176302200a529b628f534083c400c80822c64a68f08a188e7375c9b129a7a8a7d37d4542";
        std::cout << "Signature: " << signature << std::endl;

        // 4. 서명 검증
        bool isValid = MatterTunnel::verify(signature, message, publicKey);
        std::cout << "Signature Valid: " << (isValid ? "Yes" : "No") << std::endl;
        std::cout << "Signature Valid: " << (isValid ? "실패 테스트 실패" : "실패 테스트 성공") << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    
    try{
        std::cout << "------------------------" << std::endl << std::endl;
        std::cout << "디바이스 정보 추출 테스트" << std::endl;
        
        // 디바이스 정보 추출
        std::vector<unsigned char> deviceData = {
           // 33bytes compressed public key
           0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
           0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
           0x20, 0x21, 0x22,
           
           // 16bytes passcode
           0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
           
           // 20bytes function 1 - getTemp() -> number
           'g','e','t','T','e','m','p',0,0,0,0,0,0,0,0,0,0,0,
           0x00, 0x02,  // no args, returns number
           
           // 20bytes function 2 - setLED(number,Boolean) -> void
           's','e','t','L','E','D',0,0,0,0,0,0,0,0,0,0,0,0,
           0x8C, 0x00   // number,Boolean args, returns void
        };
        
        std::string deviceInfo = MatterTunnel::ExtractDeviceInfo(deviceData);
        std::cout << deviceInfo << std::endl;
    }catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    
    try{
        std::cout << "------------------------" << std::endl << std::endl;
        std::cout << "트랜잭션 생성 및 추출 테스트" << std::endl;
        
        std::string alicePrivateKey = MatterTunnel::generatePrivateKey();
        std::string alicePublicKey = MatterTunnel::derivePublicKey(alicePrivateKey);

        std::string bobPrivateKey = MatterTunnel::generatePrivateKey();
        std::string bobPublicKey = MatterTunnel::derivePublicKey(bobPrivateKey);
        
        std::vector<std::string> data_list = {"data1", "longer data2"};
        std::vector<unsigned char> tx = MatterTunnel::makeTX("testFunction", alicePrivateKey,
                                                             bobPublicKey, data_list);
        
        std::cout<< bytesToHexForTest(tx.data(), tx.size()) << std::endl;
        
        std::cout<< MatterTunnel::extractTXData(bobPrivateKey, tx) << std::endl;
        
    }catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    
    return 0;
}
