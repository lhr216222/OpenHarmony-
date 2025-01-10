from scapy.all import sniff, DNS, DNSQR, IP, UDP, send
import matplotlib.pyplot as plt
import numpy as np
import random
import time
import threading

# 初始化存储标志位的数据结构
flag_data = {
    "Opcode": [],
    "AA": [],
    "TC": [],
    "RD": [],
    "RA": []
}

# 模拟正常的DNS查询流量
def generate_dns_queries(target_ip, num_queries=1000):
    """生成大量的正常DNS查询请求到目标DNS服务器"""
    domain_list = [
        "example.com", "google.com", "yahoo.com", "wikipedia.org", "github.com",
        "amazon.com", "twitter.com", "facebook.com", "linkedin.com", "bing.com",
        "microsoft.com", "apple.com", "instagram.com", "netflix.com", "baidu.com",
        "weibo.com", "t.co", "pinterest.com", "snapchat.com", "twitch.tv",
        "spotify.com", "wordpress.com", "reddit.com", "tumblr.com", "vimeo.com",
        "medium.com", "dropbox.com", "paypal.com", "airbnb.com", "wordpress.org",
        "cnn.com", "bbc.com", "nytimes.com", "theguardian.com", "forbes.com",
        "usatoday.com", "businessinsider.com", "theverge.com", "techcrunch.com", "cnbc.com",
        "bloomberg.com", "wsj.com", "ft.com", "reuters.com", "aljazeera.com",
        "sciencedaily.com", "live.com", "icloud.com", "wikimedia.org", "cloudflare.com",
        "dropbox.com", "office.com", "etsy.com", "quora.com", "gizmodo.com",
        "slate.com", "newsweek.com", "time.com", "pewresearch.org", "huffpost.com",
        "mashable.com", "businessweek.com", "wsj.com", "guardian.co.uk", "bbc.co.uk",
        "washingtonpost.com", "theatlantic.com", "chicagotribune.com", "theeconomist.com",
        "bbc.com", "un.org", "who.int", "nyu.edu", "mit.edu",
        "stanford.edu", "harvard.edu", "yale.edu", "ox.ac.uk", "cam.ac.uk",
        "imperial.ac.uk", "oxfordjournals.org", "jstor.org", "sciencedirect.com", "springer.com",
        "wiley.com", "cambridge.org", "elsevier.com", "arxiv.org", "pubmed.ncbi.nlm.nih.gov",
        "sciencedaily.com", "nature.com", "tandfonline.com", "scopus.com", "researchgate.net",
        "sloanreview.mit.edu", "computing.co.uk", "techradar.com", "zdnet.com", "networkworld.com",
        "computerworld.com", "infoworld.com", "bgr.com", "cnet.com", "wired.com",
        "gizmodo.com", "lifehacker.com", "howtogeek.com", "makeuseof.com", "techspot.com",
        "pcmag.com", "tomshardware.com", "anandtech.com", "pcworld.com", "thesslstore.com"
    ]

    for i in range(num_queries):
        # 随机选择一个域名进行查询
        domain = random.choice(domain_list)
        # 构造DNS查询请求包
        dns_query = IP(dst=target_ip) / UDP(dport=53) / DNS(qr=0, opcode="QUERY", qd=DNSQR(qname=domain))
        send(dns_query, verbose=False)  # 不打印发送的包
        print(f"发送查询包 {i+1}/{num_queries} 到 {target_ip}.")
        time.sleep(0.01)  # 发送间隔，避免过快发送

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
    index = np.arange(len(flag_types))

    opacity = 0.8

    # 绘制每个flag的条形图
    for i, count in enumerate(counts):
        if i == 1:
            ax.bar(index[i] - bar_width, count[1], bar_width, alpha=opacity, color='b', label='1')
            ax.bar(index[i] + bar_width, count[0], bar_width, alpha=opacity, color='r', label="0")
        elif i > 1:
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
    ax.set_xticks(index)
    ax.set_xticklabels(flag_types)
    
    # 设置图例，显示每个类别的图例
    handles, labels = ax.get_legend_handles_labels()
    ax.legend(handles=handles, labels=labels, loc='upper right')

    plt.tight_layout()
    plt.show()

def capture_dns_traffic(timeout=30, target_ip="8.8.8.8"):
    """捕获DNS流量并提取标志位"""
    print("开始模拟并捕获DNS流量...")

    # 创建一个线程来捕获DNS流量
    sniff_thread = threading.Thread(target=sniff, kwargs={"filter": "udp port 53", "prn": extract_flags, "timeout": timeout})
    sniff_thread.start()

    # 生成模拟的DNS查询流量
    generate_dns_queries(target_ip, num_queries=500)  # 生成500个DNS查询包

    # 等待sniff线程结束
    sniff_thread.join()
    
    # 可视化统计数据
    visualize_flags()

if __name__ == "__main__":
    capture_dns_traffic(timeout=30, target_ip="8.8.8.8")

