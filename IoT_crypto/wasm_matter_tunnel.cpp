#include <emscripten/bind.h>
#include <emscripten/val.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include "./matter_tunnel.cpp"

using namespace emscripten;

// JavaScript에 전달할 수 있는 형태로 vector<uint8_t>를 변환
val uint8ArrayToJS(const std::vector<unsigned char>& data) {
    return val(typed_memory_view(data.size(), data.data()));
}

// JavaScript Uint8Array를 C++ vector<uint8_t>로 변환
std::vector<unsigned char> jsArrayToVector(const val& array) {
    const auto length = array["length"].as<unsigned>();
    std::vector<unsigned char> result(length);
    val memoryView = val::global("Uint8Array").new_(typed_memory_view(length, result.data()));
    memoryView.call<void>("set", array);
    return result;
}

// JavaScript Array<string>을 C++ vector<string>으로 변환
std::vector<std::string> jsStringArrayToVector(const val& array) {
    const auto length = array["length"].as<unsigned>();
    std::vector<std::string> result;
    result.reserve(length);
    
    for (unsigned i = 0; i < length; ++i) {
        result.push_back(array[i].as<std::string>());
    }
    return result;
}

// WASM 바인딩을 위한 래퍼 클래스
class WasmMatterTunnel {
public:
    // 시크릿키 생성
    static std::string generatePrivateKey() {
        return MatterTunnel::generatePrivateKey();
    }

    // 공개키 파생
    static std::string derivePublicKey(const std::string& privateKey) {
        return MatterTunnel::derivePublicKey(privateKey);
    }

    // 서명 생성
    static std::string sign(const std::string& message, const std::string& privateKey) {
        return MatterTunnel::sign(message, privateKey);
    }

    // 서명 검증
    static bool verify(const std::string& signature, const std::string& message, const std::string& publicKey) {
        return MatterTunnel::verify(signature, message, publicKey);
    }

    // 공유키 생성
    static std::string getSharedKey(const std::string& secretKey, const std::string& publicKey) {
        return MatterTunnel::getSharedKey(secretKey, publicKey);
    }

    // 암호화
    static std::string encrypt(const std::string& key, const std::string& message) {
        return MatterTunnel::encrypt(key, message);
    }

    // 복호화
    static std::string decrypt(const std::string& key, const std::string& encrypted) {
        return MatterTunnel::decrypt(key, encrypted);
    }

    // 디바이스 정보 추출 (Uint8Array를 입력으로 받음)
    static std::string extractDeviceInfo(const val& data) {
        std::vector<unsigned char> vecData = jsArrayToVector(data);
        return MatterTunnel::ExtractDeviceInfo(vecData);
    }

    // TX 생성 (결과를 Uint8Array로 반환)
    static val makeTX(const std::string& funcName,
                     const std::string& srcPriv,
                     const std::string& destPub,
                     const val& dataList) {
        std::vector<std::string> vecDataList = jsStringArrayToVector(dataList);
        std::vector<unsigned char> result = MatterTunnel::makeTX(funcName, srcPriv, destPub, vecDataList);
        return uint8ArrayToJS(result);
    }

    // TX 데이터 추출 (Uint8Array를 입력으로 받음)
    static std::string extractTXData(const std::string& privateKey, const val& txData) {
        std::vector<unsigned char> vecTxData = jsArrayToVector(txData);
        return MatterTunnel::extractTXData(privateKey, vecTxData);
    }
};

// WASM 바인딩 설정
EMSCRIPTEN_BINDINGS(matter_tunnel) {
    class_<WasmMatterTunnel>("MatterTunnel")
        .class_function("generatePrivateKey", &WasmMatterTunnel::generatePrivateKey)
        .class_function("derivePublicKey", &WasmMatterTunnel::derivePublicKey)
        .class_function("sign", &WasmMatterTunnel::sign)
        .class_function("verify", &WasmMatterTunnel::verify)
        .class_function("getSharedKey", &WasmMatterTunnel::getSharedKey)
        .class_function("encrypt", &WasmMatterTunnel::encrypt)
        .class_function("decrypt", &WasmMatterTunnel::decrypt)
        .class_function("extractDeviceInfo", &WasmMatterTunnel::extractDeviceInfo)
        .class_function("makeTX", &WasmMatterTunnel::makeTX)
        .class_function("extractTXData", &WasmMatterTunnel::extractTXData);
}
