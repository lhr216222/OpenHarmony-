#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include "lwip/inet.h"
#include "lwip/ip.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/pbuf.h"
#include "lwip/netif.h"

// 定义异常流标志
typedef struct {
    ip_addr_t src_ip;
    ip_addr_t dest_ip;
    u16_t src_port;
    u16_t dest_port;
    u8_t protocol; // IPPROTO_TCP, IPPROTO_UDP, etc.
    char anomaly_type[32];
} AnomalyEntry;

// 异常流拦截规则列表
#define MAX_ANOMALY_ENTRIES 100
AnomalyEntry anomaly_list[MAX_ANOMALY_ENTRIES];
int anomaly_count = 0;

// 添加异常规则
void add_anomaly_rule(ip_addr_t src_ip, ip_addr_t dest_ip, u16_t src_port, u16_t dest_port, u8_t protocol, const char *anomaly_type) {
    if (anomaly_count >= MAX_ANOMALY_ENTRIES) {
        printf("[ERROR] Anomaly list is full.\n");
        return;
    }
    anomaly_list[anomaly_count].src_ip = src_ip;
    anomaly_list[anomaly_count].dest_ip = dest_ip;
    anomaly_list[anomaly_count].src_port = src_port;
    anomaly_list[anomaly_count].dest_port = dest_port;
    anomaly_list[anomaly_count].protocol = protocol;
    strncpy(anomaly_list[anomaly_count].anomaly_type, anomaly_type, sizeof(anomaly_list[anomaly_count].anomaly_type) - 1);
    anomaly_count++;
}

// 检查是否匹配异常规则
int is_anomalous(ip_addr_t src_ip, ip_addr_t dest_ip, u16_t src_port, u16_t dest_port, u8_t protocol) {
    for (int i = 0; i < anomaly_count; i++) {
        if (ip_addr_cmp(&anomaly_list[i].src_ip, &src_ip) &&
            ip_addr_cmp(&anomaly_list[i].dest_ip, &dest_ip) &&
            anomaly_list[i].src_port == src_port &&
            anomaly_list[i].dest_port == dest_port &&
            anomaly_list[i].protocol == protocol) {
            return 1;
        }
    }
    return 0;
}

// 日志记录
void log_anomaly(ip_addr_t src_ip, ip_addr_t dest_ip, u16_t src_port, u16_t dest_port, const char *protocol, const char *anomaly_type) {
    printf("[ALERT] Anomalous traffic detected and blocked:\n");
    printf("  Source IP: %s\n", ipaddr_ntoa(&src_ip));
    printf("  Destination IP: %s\n", ipaddr_ntoa(&dest_ip));
    printf("  Source Port: %u\n", src_port);
    printf("  Destination Port: %u\n", dest_port);
    printf("  Protocol: %s\n", protocol);
    printf("  Anomaly Type: %s\n", anomaly_type);
}

// 重写 TCP 输入函数以实现拦截
err_t custom_tcp_input(struct pbuf *p, struct netif *inp) {
    struct ip_hdr *iphdr = (struct ip_hdr *)p->payload;
    struct tcp_hdr *tcphdr = (struct tcp_hdr *)((char *)iphdr + IPH_HL(iphdr) * 4);
    ip_addr_t src_ip, dest_ip;

    ip_addr_copy(src_ip, iphdr->src);
    ip_addr_copy(dest_ip, iphdr->dest);

    u16_t src_port = ntohs(tcphdr->src);
    u16_t dest_port = ntohs(tcphdr->dest);

    if (is_anomalous(src_ip, dest_ip, src_port, dest_port, IP_PROTO_TCP)) {
        log_anomaly(src_ip, dest_ip, src_port, dest_port, "TCP", "Detected anomaly");
        tcp_rst(NULL, src_ip, dest_ip, src_port, dest_port); // 发送RST包中止连接
        pbuf_free(p); // 丢弃数据包
        return ERR_OK;
    }

    return tcp_input(p, inp); // 调用原始TCP处理逻辑
}

// 重写 UDP 输入函数以实现拦截
err_t custom_udp_input(struct pbuf *p, struct netif *inp) {
    struct ip_hdr *iphdr = (struct ip_hdr *)p->payload;
    struct udp_hdr *udphdr = (struct udp_hdr *)((char *)iphdr + IPH_HL(iphdr) * 4);
    ip_addr_t src_ip, dest_ip;

    ip_addr_copy(src_ip, iphdr->src);
    ip_addr_copy(dest_ip, iphdr->dest);

    u16_t src_port = ntohs(udphdr->src);
    u16_t dest_port = ntohs(udphdr->dest);

    if (is_anomalous(src_ip, dest_ip, src_port, dest_port, IP_PROTO_UDP)) {
        log_anomaly(src_ip, dest_ip, src_port, dest_port, "UDP", "Detected anomaly");
        pbuf_free(p); // 丢弃数据包
        return ERR_OK;
    }

    return udp_input(p, inp); // 调用原始UDP处理逻辑
}

// 初始化拦截模块
void init_intercept_module() {
    printf("[INFO] Initializing covert channel interception module...\n");

    // 注册自定义输入函数
    tcp_input = custom_tcp_input;
    udp_input = custom_udp_input;

    // 添加测试规则
    ip_addr_t test_src, test_dest;
    ipaddr_aton("192.168.1.100", &test_src);
    ipaddr_aton("8.8.8.8", &test_dest);
    add_anomaly_rule(test_src, test_dest, 12345, 53, IP_PROTO_TCP, "Test Rule");

    printf("[INFO] Interception module initialized.\n");
}

int main() {
    init_intercept_module();
    printf("[INFO] Interception module is running.\n");
    return 0;
}
