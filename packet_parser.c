#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// 定义网络数据包的结构体
typedef struct NetworkPacket {
    char srcMac[18];
    char dstMac[18];
    char srcIP[16];
    char dstIP[16];
    unsigned short srcPort;
    unsigned short dstPort;
    char protocol[8];
    size_t payloadSize;
    char *payload;
    time_t timestamp;
} NetworkPacket;

// 初始化网络数据包
NetworkPacket* initializePacket() {
    NetworkPacket *packet = (NetworkPacket*)malloc(sizeof(NetworkPacket));
    if (!packet) {
        perror("Failed to allocate memory for NetworkPacket");
        exit(EXIT_FAILURE);
    }
    memset(packet, 0, sizeof(NetworkPacket));
    return packet;
}

// 解析以太网帧头
void parseEthernetHeader(const unsigned char *frame, NetworkPacket *packet) {
    snprintf(packet->srcMac, sizeof(packet->srcMac), "%02x:%02x:%02x:%02x:%02x:%02x",
             frame[6], frame[7], frame[8], frame[9], frame[10], frame[11]);
    snprintf(packet->dstMac, sizeof(packet->dstMac), "%02x:%02x:%02x:%02x:%02x:%02x",
             frame[0], frame[1], frame[2], frame[3], frame[4], frame[5]);
    printf("[DEBUG] Parsed Ethernet Header - Src MAC: %s, Dst MAC: %s\n", packet->srcMac, packet->dstMac);
}

// 解析IP头
void parseIPHeader(const unsigned char *packetData, NetworkPacket *packet) {
    snprintf(packet->srcIP, sizeof(packet->srcIP), "%d.%d.%d.%d",
             packetData[12], packetData[13], packetData[14], packetData[15]);
    snprintf(packet->dstIP, sizeof(packet->dstIP), "%d.%d.%d.%d",
             packetData[16], packetData[17], packetData[18], packetData[19]);
    packet->protocol[0] = packetData[9];
    printf("[DEBUG] Parsed IP Header - Src IP: %s, Dst IP: %s, Protocol: %d\n",
           packet->srcIP, packet->dstIP, packet->protocol[0]);
}

// 解析传输层头
void parseTransportLayer(const unsigned char *packetData, NetworkPacket *packet) {
    packet->srcPort = (packetData[0] << 8) | packetData[1];
    packet->dstPort = (packetData[2] << 8) | packetData[3];
    printf("[DEBUG] Parsed Transport Layer - Src Port: %d, Dst Port: %d\n",
           packet->srcPort, packet->dstPort);
}

// 解析应用层数据
void parsePayload(const unsigned char *data, size_t size, NetworkPacket *packet) {
    packet->payload = (char *)malloc(size);
    if (!packet->payload) {
        perror("Failed to allocate memory for payload");
        exit(EXIT_FAILURE);
    }
    memcpy(packet->payload, data, size);
    packet->payloadSize = size;
    printf("[DEBUG] Parsed Payload - Size: %zu bytes\n", size);
}

// 打印网络数据包
void printPacketInfo(const NetworkPacket *packet) {
    printf("Timestamp: %ld\n", packet->timestamp);
    printf("Source MAC: %s, Destination MAC: %s\n", packet->srcMac, packet->dstMac);
    printf("Source IP: %s, Destination IP: %s\n", packet->srcIP, packet->dstIP);
    printf("Source Port: %d, Destination Port: %d\n", packet->srcPort, packet->dstPort);
    printf("Payload Size: %zu bytes\n", packet->payloadSize);
}

// 数据解析与组织的主流程
void processNetworkData(const unsigned char *rawData, size_t length) {
    NetworkPacket *packet = initializePacket();
    time(&packet->timestamp);

    // 模拟链路层、网络层、传输层解析
    parseEthernetHeader(rawData, packet);
    parseIPHeader(rawData + 14, packet);  // 以太网帧头长14字节
    parseTransportLayer(rawData + 34, packet);  // IP头+偏移量
    parsePayload(rawData + 54, length - 54, packet);  // 偏移量

    // 打印解析结果
    printPacketInfo(packet);

    // 清理动态内存
    free(packet->payload);
    free(packet);
}

int main() {
    // 模拟捕获的原始数据
    unsigned char mockData[100] = { /* 模拟的网络数据流 */ };
    size_t dataLength = sizeof(mockData);

    // 调用解析流程
    processNetworkData(mockData, dataLength);

    return 0;
}
