from scapy.all import sniff, DNS, DNSQR
import matplotlib.pyplot as plt
import numpy as np

# 初始化存储标志位的数据结构
flag_data = {
    "Opcode": [],
    "AA": [],
    "TC": [],
    "RD": [],
    "RA": []
}

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

def visualize_flags():
    """可视化标志位数据"""
    # 将数据转换为numpy数组，便于处理
    flag_types = ["Opcode", "AA", "TC", "RD", "RA"]
    data = [flag_data[flag] for flag in flag_types]

    # 对Opcode进行分组：0 -> 标准查询，1 -> 反向查询，2 -> 服务器状态请求，大于3 -> 其他扩展
    opcode_bins = [0, 1, 2, 3]
    opcode_counts = [0, 0, 0, 0]  # 分别统计Opcode为0, 1, 2, 和 >3 的数量
    
    for opcode in flag_data["Opcode"]:
        if opcode == 0:
            opcode_counts[0] += 1
        elif opcode == 1:
            opcode_counts[1] += 1
        elif opcode == 2:
            opcode_counts[2] += 1
        else:
            opcode_counts[3] += 1

    # 计算每个标志位的0和1的计数
    counts = [np.bincount(np.array(flags), minlength=2) for flags in data]

    # 可视化
    fig, ax = plt.subplots(figsize=(12, 6))  # 更宽的图形，避免重叠
    bar_width = 0.12  # 调整条形宽度
    index = np.arange(len(flag_types))  # 更新索引值为[0, 1, 2, 3, 4]

    opacity = 0.8

    # 绘制每个flag的条形图
    for i, count in enumerate(counts):
        if i == 0:  # 特别处理Opcode（对其0和1的值进行标签）
            ax.bar(index[i] - bar_width, count[1], bar_width, alpha=opacity, color='b', label='1')
            ax.bar(index[i] + bar_width, count[0], bar_width, alpha=opacity, color='r', label="0")
        else:
            ax.bar(index[i] - bar_width, count[1], bar_width, alpha=opacity, color='b')
            ax.bar(index[i] + bar_width, count[0], bar_width, alpha=opacity, color='r')

    # 绘制Opcode的四个分组
    ax.bar(index[0] - 2 * bar_width, opcode_counts[0], bar_width, alpha=opacity, color='g', label="Opcode: 0")
    ax.bar(index[0] - bar_width, opcode_counts[1], bar_width, alpha=opacity, color='y', label="Opcode: 1")
    ax.bar(index[0], opcode_counts[2], bar_width, alpha=opacity, color='c', label="Opcode: 2")
    ax.bar(index[0] + bar_width, opcode_counts[3], bar_width, alpha=opacity, color='m', label="Opcode > 2")

    ax.set_xlabel('Flags')
    ax.set_ylabel('Counts')
    ax.set_title('DNS Flag Distribution')
    
    # 设置横坐标为flag_types，确保是Opcode, AA, TC, RD, RA
    ax.set_xticks(index)
    ax.set_xticklabels(flag_types)
    
    # 设置图例，显示每个类别的图例
    handles, labels = ax.get_legend_handles_labels()
    ax.legend(handles=handles, labels=labels, loc='upper right')

    plt.tight_layout()
    plt.show()

def capture_dns_traffic(timeout=120):
    """捕获DNS流量并提取标志位"""
    print("开始捕获DNS流量...")
    sniff(filter="udp port 53", prn=extract_flags, timeout=timeout)
    visualize_flags()

if __name__ == "__main__":
    capture_dns_traffic()
