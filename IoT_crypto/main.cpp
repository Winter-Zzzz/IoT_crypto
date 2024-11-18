#include <string>
#include <iostream>
#include "./matter_tunnel.cpp"

std::string bytesToHexForTest(const unsigned char *data, size_t len)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; i++)
    {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

int main()
{
    try
    {
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
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    try
    {
        // 서명 검증 실패 테스트
        std::cout << "------------------------" << std::endl
                  << std::endl;
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
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    try
    {
        std::cout << "------------------------" << std::endl
                  << std::endl;
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
            'g', 'e', 't', 'T', 'e', 'm', 'p', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0x00, 0x02, // no args, returns number

            // 20bytes function 2 - setLED(number,Boolean) -> void
            's', 'e', 't', 'L', 'E', 'D', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0x8C, 0x00 // number,Boolean args, returns void
        };

        std::string deviceInfo = MatterTunnel::ExtractDeviceInfo(deviceData);
        std::cout << deviceInfo << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    try
    {
        std::cout << "------------------------" << std::endl
                  << std::endl;
        std::cout << "트랜잭션 생성 및 추출 테스트" << std::endl;

        std::string alicePrivateKey = MatterTunnel::generatePrivateKey();
        std::string alicePublicKey = MatterTunnel::derivePublicKey(alicePrivateKey);

        std::string bobPrivateKey = MatterTunnel::generatePrivateKey();
        std::string bobPublicKey = MatterTunnel::derivePublicKey(bobPrivateKey);

        std::vector<std::string> data_list = {"data1", "longer data2"};
        std::vector<unsigned char> tx = MatterTunnel::makeTX("testFunction", alicePrivateKey,
                                                             bobPublicKey, data_list);

        std::cout << bytesToHexForTest(tx.data(), tx.size()) << std::endl;

        std::cout << MatterTunnel::extractTXData(bobPrivateKey, tx) << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}
