#include <iostream>
#include <fstream>
#include <vector>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <string>

// --- 전역 상수 ---
const int DOIP_PORT = 13400;
const uint16_t RPI_SA = 0x0E00; // RPi 논리 주소

struct HexRecord {
    uint8_t len;
    uint32_t addr;
    uint8_t type;
    std::vector<uint8_t> data;
};

struct DataChunk {
    uint32_t address;
    std::vector<uint8_t> data;
};

// --- [헬퍼 함수] ---

// HEX 파싱용 문자열 변환
uint8_t hstob(const std::string& hex) { return (uint8_t)std::stoul(hex, nullptr, 16); }

// 단순 합산 체크섬 계산 (0x31 전송용)
uint32_t calculateChunkChecksum(const std::vector<uint8_t>& data) {
    uint32_t sum = 0;
    for (uint8_t b : data) sum += b;
    return sum;
}

// --- [DoIP/UDS 전송 핵심 함수] ---

/**
 * DoIP Diagnostic Message (0x8001) 캡슐화 전송
 */
void sendUdsPacket(int sock, uint16_t targetAddr, uint8_t sid, const std::vector<uint8_t>& payload) {
    uint32_t udsLen = payload.size() + 1;  // SID(1) + Data
    uint32_t doipPayloadLen = udsLen + 4;  // SA(2) + TA(2) + UDS

    std::vector<uint8_t> pkt;
    // 1. DoIP Header (8 bytes)
    pkt.push_back(0x02); pkt.push_back(0xFD); // Protocol Version & Inverse
    pkt.push_back(0x80); pkt.push_back(0x01); // Payload Type: Diagnostic Message
    pkt.push_back(0x00); pkt.push_back(0x00); // Length High
    pkt.push_back((doipPayloadLen >> 8) & 0xFF); pkt.push_back(doipPayloadLen & 0xFF); // Length Low

    // 2. Logical Address (4 bytes)
    pkt.push_back((RPI_SA >> 8) & 0xFF); pkt.push_back(RPI_SA & 0xFF);
    pkt.push_back((targetAddr >> 8) & 0xFF); pkt.push_back(targetAddr & 0xFF);

    // 3. UDS Data
    pkt.push_back(sid);
    pkt.insert(pkt.end(), payload.begin(), payload.end());

    send(sock, pkt.data(), pkt.size(), 0);
}

// --- [UDS 시퀀스 개별 서비스] ---

// DoIP Routing Activation (0x0005)
bool routingActivation(int sock) {
    uint8_t actReq[11] = {0x02, 0xFD, 0x00, 0x05, 0x00, 0x00, 0x00, 0x03, 0x0E, 0x00, 0x00};
    send(sock, actReq, sizeof(actReq), 0);
    uint8_t res[32];
    int len = recv(sock, res, sizeof(res), 0);
    return (len >= 8 && res[2] == 0x00 && res[3] == 0x06); // 0x0006 확인
}

// UDS 0x10: Diagnostic Session Control
bool enterProgrammingSession(int sock, uint16_t targetAddr) {
    sendUdsPacket(sock, targetAddr, 0x10, {0x02}); // 0x02: Programming Session
    uint8_t res[64];
    int len = recv(sock, res, sizeof(res), 0);
    return (len >= 13 && res[12] == 0x50); // Positive Response 0x50
}

// UDS 0x34: Request Download
bool requestDownload(int sock, uint16_t targetAddr, uint32_t addr, uint32_t size) {
    std::vector<uint8_t> p = { 0x00, 0x44, // DataFormat, AddrLenFormat
        (uint8_t)(addr >> 24), (uint8_t)(addr >> 16), (uint8_t)(addr >> 8), (uint8_t)addr,
        (uint8_t)(size >> 24), (uint8_t)(size >> 16), (uint8_t)(size >> 8), (uint8_t)size };
    sendUdsPacket(sock, targetAddr, 0x34, p);
    uint8_t res[64];
    return (recv(sock, res, sizeof(res), 0) >= 13 && res[12] == 0x74);
}

// UDS 0x37: Request Transfer Exit
bool exitTransfer(int sock, uint16_t targetAddr) {
    sendUdsPacket(sock, targetAddr, 0x37, {});
    uint8_t res[64];
    return (recv(sock, res, sizeof(res), 0) >= 13 && res[12] == 0x77);
}

// UDS 0x31: Routine Control (Integrity Check)
bool verifyIntegrity(int sock, uint16_t targetAddr, uint32_t checksum) {
    std::vector<uint8_t> p = { 0x01, 0xFF, 0x01, // StartRoutine, RoutineID(0xFF01)
        (uint8_t)(checksum >> 24), (uint8_t)(checksum >> 16), (uint8_t)(checksum >> 8), (uint8_t)checksum };
    sendUdsPacket(sock, targetAddr, 0x31, p);
    uint8_t res[64];
    return (recv(sock, res, sizeof(res), 0) >= 13 && res[12] == 0x71);
}

// --- [메인 엔진 함수] ---

/**
 * 최종 전송 엔진
 * @param targetAddrStr ECU 주소 문자열 (예: "1234")
 * @param version 버전 문자열 (예: "1.1")
 * @param gatewayIp 게이트웨이 IP
 */
bool startOtaTransfer(const std::string& targetAddrStr, const std::string& version, const std::string& gatewayIp) {
    uint16_t targetAddr = (uint16_t)std::stoul(targetAddrStr, nullptr, 16);
    std::string hexPath = targetAddrStr + "_" + version + ".hex";

    // 1. HEX 파일 다시 파싱 (이미 검증된 파일)
    std::ifstream file(hexPath);
    if (!file.is_open()) return false;

    std::vector<DataChunk> chunks;
    uint32_t baseAddr = 0; std::string line;
    while (std::getline(file, line)) {
        if (line[0] != ':') continue;
        uint8_t len = hstob(line.substr(1, 2));
        uint16_t offset = (hstob(line.substr(3, 2)) << 8) | hstob(line.substr(5, 2));
        uint8_t type = hstob(line.substr(7, 2));

        if (type == 0x00) { // Data
            uint32_t fullAddr = baseAddr + offset;
            std::vector<uint8_t> d;
            for (int i = 0; i < len; i++) d.push_back(hstob(line.substr(9 + (i * 2), 2)));
            
            if (!chunks.empty() && chunks.back().address + chunks.back().data.size() == fullAddr)
                chunks.back().data.insert(chunks.back().data.end(), d.begin(), d.end());
            else chunks.push_back({fullAddr, d});
        } else if (type == 0x04) { // Extended Address
            baseAddr = (hstob(line.substr(9, 2)) << 24) | (hstob(line.substr(11, 2)) << 16);
        }
    }
    file.close();

    // 2. 소켓 연결 및 시퀀스 시작
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET; serv_addr.sin_port = htons(DOIP_PORT);
    inet_pton(AF_INET, gatewayIp.c_str(), &serv_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) return false;

    std::cout << ">> [UDS] Connected to Gateway. Starting DoIP Activation..." << std::endl;
    if (!routingActivation(sock)) return false;

    std::cout << ">> [UDS] Entering Programming Session (0x10)..." << std::endl;
    if (!enterProgrammingSession(sock, targetAddr)) return false;

    // 3. 청크 단위 전송 루프
    for (auto& chunk : chunks) {
        std::cout << ">> [UDS] Requesting Download (0x34) for Addr: 0x" << std::hex << chunk.address << std::dec << std::endl;
        if (!requestDownload(sock, targetAddr, chunk.address, chunk.data.size())) return false;

        uint8_t sn = 1; // Sequence Number
        uint32_t offset = 0;
        while (offset < chunk.data.size()) {
            uint32_t currLen = (chunk.data.size() - offset > 1024) ? 1024 : (chunk.data.size() - offset);
            std::vector<uint8_t> udsPayload = { sn };
            udsPayload.insert(udsPayload.end(), chunk.data.begin() + offset, chunk.data.begin() + offset + currLen);

            sendUdsPacket(sock, targetAddr, 0x36, udsPayload);
            
            uint8_t res[1500];
            int rLen = recv(sock, res, sizeof(res), 0);
            if (rLen >= 13 && res[12] == 0x76) { // 0x76 확인
                offset += currLen;
                sn = (sn == 0xFF) ? 0x00 : sn + 1;
            } else {
                std::cerr << ">> [Error] Transfer Data (0x36) Failed." << std::endl;
                return false;
            }
        }

        if (!exitTransfer(sock, targetAddr)) return false;

        // 4. 무결성 검사 (0x31)
        uint32_t checksum = calculateChunkChecksum(chunk.data);
        if (verifyIntegrity(sock, targetAddr, checksum)) {
            std::cout << "✅ [UDS] Section Integrity Verified! (Sum: 0x" << std::hex << checksum << std::dec << ")" << std::endl;
        } else {
            std::cerr << "❌ [UDS] Integrity Check Failed." << std::endl;
            return false;
        }
    }

    std::cout << ">> [UDS] Update Sequence Finished for 0x" << targetAddrStr << std::endl;
    close(sock);
    return true;
}
