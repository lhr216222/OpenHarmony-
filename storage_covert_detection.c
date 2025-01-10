#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include "lwip/ip.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/inet.h"

// 数据包特征结构体
typedef struct {
    uint16_t ip_id;
    uint8_t tos;         // IP TOS 字段
    uint8_t ttl;         // IP TTL 字段
    uint32_t seq_num;    // TCP 序列号
    uint16_t src_port;   // 源端口
    uint16_t dst_port;   // 目标端口
    char payload[128];   // 数据载荷摘要
} PacketFeatures;

// 先验知识库特征
typedef struct {
    uint16_t valid_ttl;
    uint8_t valid_tos_range[2];
    bool (*validate_seq_num)(uint32_t seq_num);
    uint16_t allowed_ports[10];
} PrioriKnowledge;

// 检测结果结构体
typedef struct {
    bool is_anomalous;
    char reason[256];
} DetectionResult;

// 初始化先验知识
PrioriKnowledge initialize_knowledge() {
    PrioriKnowledge knowledge = {
        .valid_ttl = 64,
        .valid_tos_range = {0, 63},
        .validate_seq_num = [](uint32_t seq_num) {
            return seq_num % 4 == 0; // 示例规则：序列号为4的倍数合法
        },
        .allowed_ports = {80, 443, 53, 22, 21} // 允许的常见端口
    };
    return knowledge;
}

// 提取数据包特征
PacketFeatures extract_features(struct pbuf *p, struct ip_hdr *iphdr) {
    PacketFeatures features = {0};
    features.ip_id = ntohs(IPH_ID(iphdr));
    features.tos = IPH_TOS(iphdr);
    features.ttl = IPH_TTL(iphdr);

    if (IPH_PROTO(iphdr) == IP_PROTO_TCP) {
        struct tcp_hdr *tcphdr = (struct tcp_hdr *)((uint8_t *)iphdr + IPH_HL(iphdr) * 4);
        features.seq_num = ntohl(tcphdr->seqno);
        features.src_port = ntohs(tcphdr->src);
        features.dst_port = ntohs(tcphdr->dest);
        memcpy(features.payload, (uint8_t *)tcphdr + TCPH_HDRLEN(tcphdr) * 4, sizeof(features.payload) - 1);
    } else if (IPH_PROTO(iphdr) == IP_PROTO_UDP) {
        struct udp_hdr *udphdr = (struct udp_hdr *)((uint8_t *)iphdr + IPH_HL(iphdr) * 4);
        features.src_port = ntohs(udphdr->src);
        features.dst_port = ntohs(udphdr->dest);
        memcpy(features.payload, (uint8_t *)udphdr + sizeof(struct udp_hdr), sizeof(features.payload) - 1);
    }

    return features;
}

// 验证端口号是否合法
bool validate_ports(uint16_t src_port, uint16_t dst_port, const PrioriKnowledge *knowledge) {
    for (int i = 0; i < sizeof(knowledge->allowed_ports) / sizeof(knowledge->allowed_ports[0]); i++) {
        if (src_port == knowledge->allowed_ports[i] || dst_port == knowledge->allowed_ports[i]) {
            return true;
        }
    }
    return false;
}

// 数据包检测逻辑
DetectionResult detect_anomalies(PacketFeatures *features, PrioriKnowledge *knowledge) {
    DetectionResult result = {false, ""};

    // 检查 TTL 值是否合法
    if (features->ttl != knowledge->valid_ttl) {
        result.is_anomalous = true;
        snprintf(result.reason, sizeof(result.reason), "TTL value %d is invalid.", features->ttl);
        return result;
    }

    // 检查 TOS 值是否合法
    if (features->tos < knowledge->valid_tos_range[0] || features->tos > knowledge->valid_tos_range[1]) {
        result.is_anomalous = true;
        snprintf(result.reason, sizeof(result.reason), "TOS value %d is outside the valid range.", features->tos);
        return result;
    }

    // 检查 TCP 序列号是否合法
    if (!knowledge->validate_seq_num(features->seq_num)) {
        result.is_anomalous = true;
        snprintf(result.reason, sizeof(result.reason), "TCP sequence number %u is invalid.", features->seq_num);
        return result;
    }

    // 检查端口是否合法
    if (!validate_ports(features->src_port, features->dst_port, knowledge)) {
        result.is_anomalous = true;
        snprintf(result.reason, sizeof(result.reason), "Port %d or %d is not allowed.", features->src_port, features->dst_port);
        return result;
    }

    snprintf(result.reason, sizeof(result.reason), "Packet is normal.");
    return result;
}

// 数据包处理回调函数
void process_packet(struct pbuf *p) {
    struct ip_hdr *iphdr = (struct ip_hdr *)p->payload;

    // 提取特征
    PacketFeatures features = extract_features(p, iphdr);

    // 初始化先验知识
    PrioriKnowledge knowledge = initialize_knowledge();

    // 检测异常
    DetectionResult result = detect_anomalies(&features, &knowledge);

    // 输出检测结果
    printf("Packet Detection Result: %s\n", result.reason);
    if (result.is_anomalous) {
        printf("Intercepting anomalous traffic...\n");
    }
}

// 网络流捕获主函数
void capture_network_traffic() {
    printf("Starting network traffic capture...\n");

    // 模拟接收数据包
    struct pbuf *p;
    while ((p = simulate_receive_packet())) {
        process_packet(p);
    }

    printf("Network traffic capture completed.\n");
}

// 模拟接收数据包（测试用）
struct pbuf *simulate_receive_packet() {
    static int count = 0;
    if (count++ > 10) return NULL;

    // 模拟生成数据包
    struct pbuf *p = (struct pbuf *)malloc(sizeof(struct pbuf));
    struct ip_hdr *iphdr = (struct ip_hdr *)malloc(sizeof(struct ip_hdr));
    iphdr->tos = count % 64; // 示例数据
    iphdr->ttl = 64;         // 示例数据
    p->payload = iphdr;

    return p;
}

int main() {
    capture_network_traffic();
    return 0;
}
