#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <iostream>
#include <winsock2.h>
#include <chrono>

#pragma comment(lib, "ws2_32.lib")

constexpr int ICMP_HEADER_LEN = 8;
constexpr int ICMP_TOT_LEN = 40;
constexpr int IP_HEADER_LEN = 20;

constexpr char GOOGLE_DNS_ADDR[] = "8.8.8.8";

void PrintPacketInfo(char *recvBuffer) {
    int recv_sn = 0;
    memcpy(&recv_sn, &recvBuffer[IP_HEADER_LEN + 6], sizeof(char) * 2);
    int sn = ntohs(recv_sn);

    std::cout << "[SN: " << sn << "]\n";
    for (int i = IP_HEADER_LEN; i < IP_HEADER_LEN + ICMP_TOT_LEN; i++) {
        std::cout << std::hex << static_cast<int>(static_cast<unsigned char>(recvBuffer[i])) << std::dec << " ";
    }
    std::cout << '\n';
}

uint16_t computeChecksum(char *sendBuffer) {
    uint32_t sum = 0;
    uint16_t *data = (uint16_t*) sendBuffer;

    size_t length = ICMP_TOT_LEN;

    while (length > 1) {
        sum += *data++;
        length -= 2;
    }

    if (length > 0) {
        sum += *((uint8_t*) data);
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

int main() {
    // Initialize Winsock
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed to initialize Winsock.\n";
        return 1;
    }

    // Create a socket
    SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Failed to create socket.\n";
        WSACleanup();
        return 1;
    }

    // Set up target host
    sockaddr_in targetAddr;
    targetAddr.sin_family = AF_INET;
    targetAddr.sin_addr.s_addr = inet_addr(GOOGLE_DNS_ADDR);

    uint16_t seqnum = 1;

    std::chrono::system_clock::time_point start_time, end_time;

    while (true) {
        // Create an ICMP Echo Request packet
        char icmpPacket[ICMP_TOT_LEN]; // Adjust the size as needed
        memset(&icmpPacket, 0, sizeof(icmpPacket));

        // 1. type = 8 (request)
        icmpPacket[0] = 0x08;

        // 2. code = 0 (always 0)
        icmpPacket[1] = 0x00;

        // 3. identifier
        icmpPacket[4] = 0x00;
        icmpPacket[5] = 0x01;

        // 4. sequence number
        uint16_t r_seqnum = htons(seqnum);
        memcpy(&icmpPacket[6], &r_seqnum, sizeof(char) * 2);
        seqnum++;

        // 5. data (padding)
        char data[] = "abcdefghijklmnopqrstuvwabcdefghi";
        memcpy(&icmpPacket[8], &data, sizeof(data) - 1);

        // 6. checksum
        uint16_t checksum = computeChecksum(icmpPacket);
        memcpy(&icmpPacket[2], &checksum, sizeof(char) * 2);

        // Send the packet
        long bytesSent = sendto(sock, icmpPacket, sizeof(icmpPacket), 0,
                (struct sockaddr*) &targetAddr, sizeof(targetAddr));

        start_time = std::chrono::system_clock::now();

        if (bytesSent == SOCKET_ERROR) {
            std::cerr << "Failed to send ICMP packet.\n";
            closesocket(sock);
            WSACleanup();
            return 1;
        }

        // Receive ICMP Echo Reply
        char recvBuffer[ICMP_TOT_LEN + IP_HEADER_LEN]; // Adjust the size as needed
        memset(&recvBuffer, 0, sizeof(recvBuffer));

        sockaddr_in senderAddr;

        int senderAddrLen = sizeof(senderAddr);
        long bytesReceived = recvfrom(sock, recvBuffer, sizeof(recvBuffer), 0,
                (struct sockaddr*) &senderAddr, &senderAddrLen);

        if (bytesReceived == SOCKET_ERROR) {
            std::cerr << "Failed to receive ICMP reply.\n";
        }
        else {
            end_time = std::chrono::system_clock::now();
            std::chrono::milliseconds time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

            uint16_t ttl = static_cast<uint16_t>(static_cast<unsigned char>(recvBuffer[8]));

            std::cout  << "Reply from " << inet_ntoa(senderAddr.sin_addr)
                    << ": bytes=" << bytesReceived - IP_HEADER_LEN - ICMP_HEADER_LEN
                    << " time" << (time.count() == 0 ? "<" : "=") << (time.count() == 0 ? 1 : time.count())
                    << "ms TTL=" << ttl << '\n';

            //PrintPacketInfo(recvBuffer);
        }

        Sleep(1000);
    }

    // Clean up
    closesocket(sock);
    WSACleanup();
    return 0;
}
