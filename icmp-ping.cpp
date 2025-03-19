#include <iostream>
#include <chrono>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <cstring>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

constexpr int ICMP_HEADER_LEN = 8;
constexpr int ICMP_TOT_LEN = 40;
constexpr int IP_HEADER_LEN = 20;

constexpr char GOOGLE_DNS_ADDR[] = "8.8.8.8";

void printPacketInfo(char *recvBuffer) {
    for (int i = IP_HEADER_LEN; i < IP_HEADER_LEN + ICMP_TOT_LEN; i++) {
        std::cout << std::hex << static_cast<int>(static_cast<unsigned char>(recvBuffer[i])) << std::dec << " ";
    }
    std::cout << '\n';
}

void printPingResult(char *recvBuffer, long bytesReceived, sockaddr_in senderAddr, std::chrono::duration<double, std::milli> duration) {
    int r_recv_sn = 0;
    memcpy(&r_recv_sn, &recvBuffer[IP_HEADER_LEN + 6], sizeof(char) * 2);
    int recv_sn = ntohs(r_recv_sn);

    uint16_t ttl = static_cast<uint16_t>(static_cast<unsigned char>(recvBuffer[8]));

    std::cout.precision(3);
    std::cout  << bytesReceived - IP_HEADER_LEN - ICMP_HEADER_LEN << " bytes from " << inet_ntoa(senderAddr.sin_addr)
            << ": icmp_seq=" << recv_sn << " ttl=" << ttl << " time=" << duration.count() << " ms\n";
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

int openSocket() {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed.\n";
        return -1;
    }
#endif

    int sock = -1;
#ifdef __APPLE__
    // On macOS, use DGRAM instead of RAW socket for testing purposes
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
#else
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
#endif
    return sock;
}

void closeSocket(int sock) {
#ifdef _WIN32
    closesocket(sock);
    WSACleanup();
#else
    close(sock);
#endif
    return;
}

void sleepOneSec() {
#ifdef _WIN32
    Sleep(1000);
#else
    sleep(1);
#endif
    return;
}

void setICMPPacket(char *icmp_packet, size_t packet_size, uint16_t &seqnum) {
    memset(icmp_packet, 0, packet_size);

    // 1. type = 8 (request)
    icmp_packet[0] = 0x08;

    // 2. code = 0 (always 0)
    icmp_packet[1] = 0x00;

    // 3. identifier
    uint16_t id = 0x0001;
    uint16_t r_id = htons(id);
    memcpy(&icmp_packet[4], &r_id, sizeof(char) * 2);

    // 4. sequence number
    uint16_t r_seqnum = htons(seqnum);
    memcpy(&icmp_packet[6], &r_seqnum, sizeof(char) * 2);
    seqnum++;

    // 5. data (padding)
    char data[] = "abcdefghijklmnopqrstuvwabcdefghi"; // Windows-based data (32 bytes)
    memcpy(&icmp_packet[8], &data, sizeof(data) - 1);

    // 6. checksum
    uint16_t checksum = computeChecksum(icmp_packet);
    memcpy(&icmp_packet[2], &checksum, sizeof(char) * 2);
    return;
}

int main() {
    int sock = openSocket();
    if (sock == -1) {
        std::cerr << "Failed to create socket.\n";
#ifdef _WIN32
        WSACleanup();
#endif
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
        setICMPPacket(icmpPacket, ICMP_TOT_LEN, seqnum);

        // Send the packet
        long bytesSent = sendto(sock, icmpPacket, sizeof(icmpPacket), 0,
                (struct sockaddr*) &targetAddr, sizeof(targetAddr));

        start_time = std::chrono::system_clock::now();

        if (bytesSent == -1) {
            std::cerr << "Failed to send ICMP packet.\n";
            closeSocket(sock);
            return 1;
        }

        // Receive ICMP Echo Reply
        char recvBuffer[ICMP_TOT_LEN + IP_HEADER_LEN]; // Adjust the size as needed
        memset(&recvBuffer, 0, sizeof(recvBuffer));

        sockaddr_in senderAddr;
        socklen_t senderAddrLen = sizeof(senderAddr);

        long bytesReceived = recvfrom(sock, recvBuffer, sizeof(recvBuffer), 0,
                (struct sockaddr*) &senderAddr, &senderAddrLen);

        if (bytesReceived == -1) {
            std::cerr << "Failed to receive ICMP reply.\n";
        }
        else {
            end_time = std::chrono::system_clock::now();
            std::chrono::duration<double, std::milli> duration = end_time - start_time;

            printPingResult(recvBuffer, bytesReceived, senderAddr, duration);
            //printPacketInfo(recvBuffer);
        }

        sleepOneSec();
    }

    // Clean up
    closeSocket(sock);
    return 0;
}
