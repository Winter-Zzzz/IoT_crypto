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

std::vector<unsigned char> hexToBytesForTest(const std::string &hex)
{
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2)
    {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
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
        std::cout <<"alice private: "<< alicePrivateKey << std::endl;
        std::cout <<"alice public: "<< alicePublicKey << std::endl;

        std::string bobPrivateKey = MatterTunnel::generatePrivateKey();
        std::string bobPublicKey = MatterTunnel::derivePublicKey(bobPrivateKey);
        std::cout <<"bob private: "<< bobPrivateKey << std::endl;

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
            0xb0, 0x00 // number,Boolean args, returns void
        };

        std::string deviceInfo = MatterTunnel::extractDeviceInfo(deviceData);
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
    
    try{
        // wasm test
        std::cout << "------------------------" << std::endl
                  << std::endl;
        std::cout << "wasm 테스트" << std::endl;
        
        std::string alicePrivateKey = "7ebaa28dda4dea71f38f942a3ef25d3f201f668fcb7b4833f4091940ba6dd470";
        std::string alicePublicKey = "04750bfae2e57e7160cb5ead399ab37afdb4a1451a0b96b08764296dbe8490d946f1312034836474ccf7070b44d3e98f03dca538d148aff42fce155f58243de60d";
        
        std::string bobPrivateKey = "6088369319a1d6ab53f5a55a071f65522a08a5d7d3429bb938fad5626e01abea";
        std::string bobPublicKey = "04992a9a2eb063fc4cd45c5b67a1aecebcb87ea8358de73eef0ccf7d58c3c3ff7e382661df97cdfa48fede1ad2b767b95268bc810e11637234bb353085e37c32c7";
        
        std::string sharedKey = MatterTunnel::getSharedKey(alicePrivateKey, bobPublicKey);
        std::cout << "sharedKey: " << sharedKey << std::endl;
        
        
        std::string msg = "하이요";
        std::string wasmSig = "7bdf79bb300c79572b32d65ed90d3362953b594be2cf2f189bb7a52f55e8130658a7738a2fb091864554a130f136226a00348af0d5c51def7a8135cb7f0675fb";
        bool isValid = MatterTunnel::verify(wasmSig, msg, alicePublicKey);
        std::string validMessage = isValid ? "서명 검증 성공" : "서명 검증 실패";
        std::cout << "verify:" << validMessage << std::endl;
        
        std::string sig = MatterTunnel::sign(msg, alicePrivateKey);
        std::cout << sig << std::endl;
        
        std::string encMessage = "01e7154c18aa4f67dfad4494dbfbb833cfcb0d3a0fcf7059cca6cf706c8092f4";
        std::string decMessage = MatterTunnel::decrypt(sharedKey, encMessage);
        std::cout << "message:" << decMessage << std::endl;
        
        std::vector<unsigned char> txData = {
            68, 150, 157, 228, 96, 7, 193, 46, 80, 246, 139, 168, 98, 128, 200, 9,
            11, 49, 152, 245, 122, 198, 35, 202, 178, 31, 155, 191, 50, 215, 118, 42,
            206, 135, 18, 22, 127, 3, 10, 255, 216, 189, 96, 65, 29, 158, 61, 49,
            144, 37, 191, 183, 237, 215, 152, 115, 190, 206, 126, 73, 199, 42, 204, 167,
            116, 101, 115, 116, 70, 117, 110, 99, 116, 105, 111, 110, 0, 0, 0, 0,
            0, 0, 3, 117, 11, 250, 226, 229, 126, 113, 96, 203, 94, 173, 57, 154,
            179, 122, 253, 180, 161, 69, 26, 11, 150, 176, 135, 100, 41, 109, 190, 132,
            144, 217, 70, 245, 190, 61, 103, 245, 190, 61, 103, 199, 2, 56, 212, 215,
            109, 73, 24, 52, 83, 202, 74, 62, 4, 50, 84, 141, 96, 24, 150, 7,
            169, 83, 67, 127, 17, 188, 25, 185, 14, 62, 227, 251, 10, 42, 83, 250,
            122, 155, 87, 4, 248, 206, 187, 243, 36, 158, 129
        };

        std::cout << MatterTunnel::extractTXData(bobPrivateKey, txData) << std::endl;
        
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    
    return 0;
}
