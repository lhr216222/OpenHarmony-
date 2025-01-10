#include "lwip/netif.h"
#include "lwip/ip.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/etharp.h"
#include "lwip/pbuf.h"
#include "lwip/prot/ip4.h"
#include "lwip/prot/tcp.h"
#include "lwip/prot/udp.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

// 定义数据包捕获的结构体
typedef struct {
    char timestamp[32];          // 时间戳
    char src_mac[18];            // 源MAC地址
    char dst_mac[18];            // 目标MAC地址
    char src_ip[16];             // 源IP地址
    char dst_ip[16];             // 目标IP地址
    uint16_t src_port;           // 源端口号
    uint16_t dst_port;           // 目标端口号
    char protocol[8];            // 协议类型（TCP/UDP/ICMP）
    uint16_t payload_length;     // 数据载荷长度
    char payload[512];           // 数据载荷（部分存储）
    uint8_t ip_header[20];       // 原始IP头
    uint8_t transport_header[20];// 原始传输层头
} NetworkPacket;

// 定义全局统计变量
typedef struct {
    uint64_t packet_count;
    uint64_t tcp_count;
    uint64_t udp_count;
    uint64_t icmp_count;
    uint64_t dropped_count;
    uint64_t total_payload_size;
} TrafficStats;

TrafficStats g_stats = {0};

// 日志记录功能
void LogNetworkPacket(const NetworkPacket *packet) {
    printf("=== Packet Captured ===\n");
    printf("Timestamp: %s\n", packet->timestamp);
    printf("Src MAC: %s, Dst MAC: %s\n", packet->src_mac, packet->dst_mac);
    printf("Src IP: %s, Src Port: %d\n", packet->src_ip, packet->src_port);
    printf("Dst IP: %s, Dst Port: %d\n", packet->dst_ip, packet->dst_port);
    printf("Protocol: %s, Payload Length: %d\n", packet->protocol, packet->payload_length);
    printf("Payload (Partial): %.512s\n", packet->payload);
    printf("=======================\n");
}

// 提取以太网头信息
void ExtractEthernetHeader(struct pbuf *p, NetworkPacket *packet) {
    struct eth_hdr *ethhdr = (struct eth_hdr *)p->payload;
    snprintf(packet->src_mac, sizeof(packet->src_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             ethhdr->src.addr[0], ethhdr->src.addr[1], ethhdr->src.addr[2],
             ethhdr->src.addr[3], ethhdr->src.addr[4], ethhdr->src.addr[5]);
    snprintf(packet->dst_mac, sizeof(packet->dst_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             ethhdr->dest.addr[0], ethhdr->dest.addr[1], ethhdr->dest.addr[2],
             ethhdr->dest.addr[3], ethhdr->dest.addr[4], ethhdr->dest.addr[5]);
}

// 提取IP头信息
void ExtractIPHeader(struct ip_hdr *iphdr, NetworkPacket *packet) {
    ip4addr_ntoa_r(&iphdr->src, packet->src_ip, sizeof(packet->src_ip));
    ip4addr_ntoa_r(&iphdr->dest, packet->dst_ip, sizeof(packet->dst_ip));
    memcpy(packet->ip_header, iphdr, sizeof(packet->ip_header));
}

// 提取传输层头信息
void ExtractTransportHeader(struct pbuf *p, NetworkPacket *packet, uint8_t protocol) {
    if (protocol == IP_PROTO_TCP) {
        struct tcp_hdr *tcphdr = (struct tcp_hdr *)((uint8_t *)p->payload + IP_HLEN);
        packet->src_port = lwip_ntohs(tcphdr->src);
        packet->dst_port = lwip_ntohs(tcphdr->dest);
        strncpy(packet->protocol, "TCP", sizeof(packet->protocol));
        memcpy(packet->transport_header, tcphdr, sizeof(packet->transport_header));
        g_stats.tcp_count++;
    } else if (protocol == IP_PROTO_UDP) {
        struct udp_hdr *udphdr = (struct udp_hdr *)((uint8_t *)p->payload + IP_HLEN);
        packet->src_port = lwip_ntohs(udphdr->src);
        packet->dst_port = lwip_ntohs(udphdr->dest);
        strncpy(packet->protocol, "UDP", sizeof(packet->protocol));
        memcpy(packet->transport_header, udphdr, sizeof(packet->transport_header));
        g_stats.udp_count++;
    } else if (protocol == IP_PROTO_ICMP) {
        strncpy(packet->protocol, "ICMP", sizeof(packet->protocol));
        g_stats.icmp_count++;
    } else {
        strncpy(packet->protocol, "OTHER", sizeof(packet->protocol));
    }
}

// 捕获和解析数据包
void CapturePacket(struct pbuf *p) {
    if (!p) {
        g_stats.dropped_count++;
        return;
    }

    NetworkPacket packet = {0};

    // 时间戳记录
    time_t t = time(NULL);
    strftime(packet.timestamp, sizeof(packet.timestamp), "%Y-%m-%d %H:%M:%S", localtime(&t));

    // 提取以太网头
    ExtractEthernetHeader(p, &packet);

    // 提取IP头
    struct ip_hdr *iphdr = (struct ip_hdr *)((uint8_t *)p->payload + SIZEOF_ETH_HDR);
    ExtractIPHeader(iphdr, &packet);

    // 提取传输层信息
    ExtractTransportHeader(p, &packet, IPH_PROTO(iphdr));

    // 提取数据载荷
    packet.payload_length = pbuf_copy_partial(p, packet.payload, sizeof(packet.payload), IP_HLEN);
    g_stats.total_payload_size += packet.payload_length;

    // 存储日志
    LogNetworkPacket(&packet);
    g_stats.packet_count++;
}

// 钩子函数扩展网络数据捕获
void CustomHook(struct netif *netif, struct pbuf *p) {
    CapturePacket(p);
}

// 显示统计信息
void ShowTrafficStats() {
    printf("==== Traffic Stats ====\n");
    printf("Total Packets: %llu\n", g_stats.packet_count);
    printf("TCP Packets: %llu\n", g_stats.tcp_count);
    printf("UDP Packets: %llu\n", g_stats.udp_count);
    printf("ICMP Packets: %llu\n", g_stats.icmp_count);
    printf("Dropped Packets: %llu\n", g_stats.dropped_count);
    printf("Total Payload Size: %llu bytes\n", g_stats.total_payload_size);
    printf("=======================\n");
}

// 主函数
int main() {
    printf("Initializing network traffic capture...\n");
    struct netif my_netif;

    // 配置自定义钩子函数
    my_netif.input = CustomHook;

    printf("Network traffic capture started...\n");
    while (1) {
        // 模拟流量捕获的运行环境
        sleep(10); // 模拟捕获间隔
        ShowTrafficStats();
    }

    return 0;
}
