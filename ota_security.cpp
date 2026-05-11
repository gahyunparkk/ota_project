#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// 에러 메시지 출력을 위한 함수
void printOpenSSLErrors() {
    ERR_print_errors_fp(stderr);
}

// 파일을 읽어 바이트 벡터로 반환하는 헬퍼 함수
std::vector<unsigned char> readFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return {};

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<unsigned char> buffer(size);
    if (!file.read((char*)buffer.data(), size)) return {};

    return buffer;
}

/**
 * ECDSA 서명 검증 함수
 * @param addr ECU 주소 (예: "1234")
 * @param version 버전 (예: "1.1")
 * @param publicKeyPath 로컬 공개키 경로 ("public.pem")
 */
bool verifyFirmwareSecurity(const std::string& addr, const std::string& version, const std::string& publicKeyPath) {
    // 1. 파일명 규칙 적용: [주소]_[버전].hex / .sig
    std::string hexFilename = addr + "_" + version + ".hex";
    std::string sigFilename = addr + "_" + version + ".sig";

    std::cout << ">> [Security] Verifying: " << hexFilename << " with " << sigFilename << std::endl;

    // 2. 데이터 로드 (HEX 데이터 및 서명 데이터)
    std::vector<unsigned char> firmwareData = readFile(hexFilename);
    std::vector<unsigned char> signature = readFile(sigFilename);

    if (firmwareData.empty() || signature.empty()) {
        std::cerr << ">> [Error] Failed to load firmware or signature file." << std::endl;
        return false;
    }

    // 3. 공개키 로드 (public.pem)
    FILE* pubKeyFile = fopen(publicKeyPath.c_str(), "r");
    if (!pubKeyFile) {
        std::cerr << ">> [Error] Cannot open public key: " << publicKeyPath << std::endl;
        return false;
    }

    EVP_PKEY* pkey = PEM_read_PUBKEY(pubKeyFile, NULL, NULL, NULL);
    fclose(pubKeyFile);

    if (!pkey) {
        std::cerr << ">> [Error] Failed to read public key." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    // 4. ECDSA 검증 컨텍스트 생성 (SHA-256 사용)
    EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
    bool isSuccess = false;

    if (EVP_DigestVerifyInit(mdCtx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        std::cerr << ">> [Error] DigestVerifyInit failed." << std::endl;
    } else {
        // 5. 해시 계산 및 검증 (EVP_DigestVerifyUpdate 내부에서 해시 계산 수행)
        if (EVP_DigestVerifyUpdate(mdCtx, firmwareData.data(), firmwareData.size()) <= 0) {
            std::cerr << ">> [Error] DigestVerifyUpdate failed." << std::endl;
        } else {
            // 6. 서명 최종 확인
            int result = EVP_DigestVerifyFinal(mdCtx, signature.data(), signature.size());
            if (result == 1) {
                std::cout << "✅ [Success] ECDSA Verification Passed for " << hexFilename << "!" << std::endl;
                isSuccess = true;
            } else if (result == 0) {
                std::cerr << "❌ [Critical] Signature Mismatch! File may be corrupted or tampered." << std::endl;
            } else {
                std::cerr << ">> [Error] Error during verification final." << std::endl;
                printOpenSSLErrors();
            }
        }
    }

    // 자원 해제
    EVP_MD_CTX_free(mdCtx);
    EVP_PKEY_free(pkey);

    return isSuccess;
}
