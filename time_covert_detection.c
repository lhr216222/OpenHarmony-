#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <string.h>

#define MAX_PACKETS 1000

typedef struct {
    double intervals[MAX_PACKETS];
    int count;
} TimeIntervalList;

// 初始化时间间隔列表
void initialize_time_interval_list(TimeIntervalList *list) {
    list->count = 0;
}

// 添加时间间隔到列表
void add_time_interval(TimeIntervalList *list, double interval) {
    if (list->count < MAX_PACKETS) {
        list->intervals[list->count++] = interval;
    }
}

// 计算CDF
void calculate_cdf(const double *data, int size, double *cdf) {
    for (int i = 0; i < size; i++) {
        cdf[i] = (i + 1) / (double)size;
    }
}

// Kolmogorov-Smirnov 检测
int ks_test(const double *observed, int observed_size, const double *expected, int expected_size) {
    double max_diff = 0.0;
    double cdf_observed[MAX_PACKETS], cdf_expected[MAX_PACKETS];

    calculate_cdf(observed, observed_size, cdf_observed);
    calculate_cdf(expected, expected_size, cdf_expected);

    for (int i = 0; i < observed_size && i < expected_size; i++) {
        double diff = fabs(cdf_observed[i] - cdf_expected[i]);
        if (diff > max_diff) {
            max_diff = diff;
        }
    }

    double threshold = 0.2; // 示例阈值，需根据实验调整
    return max_diff > threshold;
}

// 计算标准差
double calculate_standard_deviation(const TimeIntervalList *list) {
    double sum = 0.0, mean, variance = 0.0;
    for (int i = 0; i < list->count; i++) {
        sum += list->intervals[i];
    }
    mean = sum / list->count;

    for (int i = 0; i < list->count; i++) {
        double diff = list->intervals[i] - mean;
        variance += diff * diff;
    }
    return sqrt(variance / list->count);
}

// 规律性检测
int regularity_test(const TimeIntervalList *list) {
    double stddev = calculate_standard_deviation(list);
    return stddev > 0.05; // 示例阈值，需根据实验调整
}

// 计算熵
double calculate_entropy(const double *data, int size) {
    int bucket[10] = {0}; // 将数据分成10个区间
    for (int i = 0; i < size; i++) {
        int index = (int)(data[i] * 10); // 简单量化
        if (index >= 0 && index < 10) {
            bucket[index]++;
        }
    }
    double entropy = 0.0;
    for (int i = 0; i < 10; i++) {
        if (bucket[i] > 0) {
            double p = bucket[i] / (double)size;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

// 熵检测
int entropy_test(const TimeIntervalList *list) {
    double entropy = calculate_entropy(list->intervals, list->count);
    return entropy > 4.0; // 示例阈值，需根据实验调整
}

// 捕获网络数据包并检测隐蔽信道
void capture_and_detect() {
    TimeIntervalList observed_intervals;
    initialize_time_interval_list(&observed_intervals);

    TimeIntervalList expected_intervals;
    initialize_time_interval_list(&expected_intervals);

    struct timespec prev_time, curr_time;

    // 模拟期望分布
    for (int i = 0; i < MAX_PACKETS; i++) {
        add_time_interval(&expected_intervals, 0.1); // 假设期望分布为固定间隔
    }

    // 模拟数据包接收和时间间隔记录
    for (int i = 0; i < MAX_PACKETS; i++) {
        clock_gettime(CLOCK_REALTIME, &curr_time);

        if (i > 0) {
            double interval = (curr_time.tv_sec - prev_time.tv_sec) +
                              (curr_time.tv_nsec - prev_time.tv_nsec) / 1e9;
            add_time_interval(&observed_intervals, interval);
        }
        prev_time = curr_time;

        // 模拟延迟
        usleep(rand() % 100000); // 随机延迟 (0-100ms)
    }

    // 执行检测方法
    if (ks_test(observed_intervals.intervals, observed_intervals.count,
                expected_intervals.intervals, expected_intervals.count)) {
        printf("[ALERT] Detected time-based covert channel using KS Test.\n");
    }

    if (regularity_test(&observed_intervals)) {
        printf("[ALERT] Detected time-based covert channel using Regularity Test.\n");
    }

    if (entropy_test(&observed_intervals)) {
        printf("[ALERT] Detected time-based covert channel using Entropy Test.\n");
    }
}

int main() {
    srand(time(NULL)); // 初始化随机种子
    printf("[INFO] Starting time-based covert channel detection...\n");
    capture_and_detect();
    printf("[INFO] Detection completed.\n");
    return 0;
}
