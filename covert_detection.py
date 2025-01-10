from scapy.all import sniff, DNS, DNSQR
import numpy as np

# 初始化存储标志位的数据结构
flag_data = {
    "Opcode": [],
    "AA": [],
    "TC": [],
    "RD": [],
    "RA": []
}

# 提取DNS包中的标志位并存储
def extract_flags(pkt):
    """从DNS包中提取标志位并存储"""
    if DNS in pkt and pkt[DNS].qr == 0:  # 仅处理DNS查询包
        # 提取标志位字段
        opcode = pkt[DNS].opcode
        aa = pkt[DNS].aa
        tc = pkt[DNS].tc
        rd = pkt[DNS].rd
        ra = pkt[DNS].ra
        
        # 存储标志位数据
        flag_data["Opcode"].append(opcode)
        flag_data["AA"].append(aa)
        flag_data["TC"].append(tc)
        flag_data["RD"].append(rd)
        flag_data["RA"].append(ra)

# 计算五维特征向量
def compute_feature_vector():
    """计算五维特征向量"""
    total_queries = len(flag_data["Opcode"])
    total_responses = len(flag_data["AA"])  # AA、TC、RA等响应特征数量

    f1 = flag_data["Opcode"].count(0) / total_queries  # Opcode = 0
    f2 = flag_data["AA"].count(1) / total_responses    # AA = 1
    f3 = flag_data["TC"].count(0) / total_responses    # TC = 0 (未被截断)
    f4 = flag_data["RD"].count(1) / total_queries      # RD = 1
    f5 = flag_data["RA"].count(1) / total_responses    # RA = 1
    
    return [f1, f2, f3, f4, f5]

# 计算加权绝对差值和进行异常判断
def detect_anomalies():
    """根据加权绝对差值判断是否存在异常"""
    features = compute_feature_vector()

    # 定义加权系数
    weights = [1, 1.5, 2, 1, 1.2]  # 设定加权系数

    # 计算加权绝对差值和
    anomaly_score = sum(weights[i] * abs(features[i] - ideal_value) 
                        for i, ideal_value in enumerate([0.99, 0.9, 0.01, 0.95, 0.9]))

    # 定义阈值
    threshold = 3.5  # 根据实际情况调整阈值

    # 判断是否异常
    if anomaly_score > threshold:
        print(f"检测到异常DNS通信，异常得分: {anomaly_score}")
    else:
        print(f"未检测到异常，异常得分: {anomaly_score}")

def capture_dns_traffic(timeout=30):
    """捕获DNS流量并提取标志位"""
    print("开始捕获DNS流量...")
    sniff(filter="udp port 53", prn=extract_flags, timeout=timeout)
    detect_anomalies()

if __name__ == "__main__":
    capture_dns_traffic()

