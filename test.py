from scapy.all import sniff, DNS, DNSQR
from collections import defaultdict, Counter
from math import log2

# 初始化全局变量
feature_data = {
    "domain_lengths": [],
    "unique_domains": set(),
    "non_A_AAAA_count": 0,
    "total_queries": 0,
    "all_domains_concat": "",
    "A_AAAA_queries": 0
}

def calculate_entropy(data):
    """计算字符串的熵值"""
    if not data:
        return 0
    counter = Counter(data)
    length = len(data)
    return -sum((count / length) * log2(count / length) for count in counter.values())

def extract_features(pkt):
    """从DNS请求包中提取特征"""
    global feature_data
    if DNS in pkt and pkt[DNS].qr == 0:  # DNS查询包
        query = pkt[DNSQR].qname.decode() if DNSQR in pkt else ""
        qtype = pkt[DNSQR].qtype if DNSQR in pkt else 0
        
        # 子域名长度
        feature_data["domain_lengths"].append(len(query))
        # 子域名集合
        feature_data["unique_domains"].add(query)
        # 拼接所有子域名
        feature_data["all_domains_concat"] += query
        # 查询类型统计
        feature_data["total_queries"] += 1
        if qtype in [1, 28]:  # A或AAAA查询类型
            feature_data["A_AAAA_queries"] += 1
        else:
            feature_data["non_A_AAAA_count"] += 1

def analyze_features():
    """分析时间窗口内的特征值并输出检测结果"""
    global feature_data
    if feature_data["total_queries"] == 0:
        print("没有有效的DNS请求数据。")
        return

    # 计算特征值
    avg_domain_length = sum(feature_data["domain_lengths"]) / len(feature_data["domain_lengths"])
    unique_domain_ratio = len(feature_data["unique_domains"]) / feature_data["total_queries"]
    avg_entropy = sum(calculate_entropy(domain) for domain in feature_data["unique_domains"]) / len(feature_data["unique_domains"])
    concat_entropy = calculate_entropy(feature_data["all_domains_concat"])
    non_A_AAAA_count = feature_data["non_A_AAAA_count"]
    A_AAAA_ratio = feature_data["A_AAAA_queries"] / feature_data["total_queries"]

    # 输出特征值
    print(f"子域名平均长度: {avg_domain_length:.2f}")
    print(f"唯一子域名数量: {len(feature_data['unique_domains'])}")
    print(f"唯一子域名所占比例: {unique_domain_ratio:.2%}")
    print(f"子域名平均熵: {avg_entropy:.2f}")
    print(f"所有子域名连接熵值: {concat_entropy:.2f}")
    print(f"查询类型非A/AAAA的数量: {non_A_AAAA_count}")
    print(f"查询类型中A/AAAA所占比例: {A_AAAA_ratio:.2%}")

    # 简单规则检测
    if avg_domain_length > 50 or unique_domain_ratio < 0.1 or avg_entropy > 4.0:
        print("[ALERT] 检测到可能的隐蔽通信行为！")

def capture_dns_traffic(timeout=30):
    """捕获DNS流量并分析"""
    print("开始捕获DNS流量...")
    sniff(filter="udp port 53", prn=extract_features, timeout=timeout)
    analyze_features()

if __name__ == "__main__":
    capture_dns_traffic()
