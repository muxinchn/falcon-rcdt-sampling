/*
 * Falcon K-分段多提议 RCDT 采样性能基准测试
 *
 * 测量内容：
 *   第一部分：隔离采样子模块测试（仅采样逻辑，不含 NTT/哈希/范数检查/编码）
 *     - 批量生成 n 个系数的总时间
 *     - 批量采样过程的峰值工作内存
 *   第二部分：完整 Falcon 算法全流程测量
 *     - 密钥生成：时间 + 峰值内存
 *     - 签名：时间 + 峰值内存
 *     - 验签：时间 + 峰值内存
 *
 * 对比对象：基线 BaseSampler (K=1) 与 K=2..16 的多提议分段 RCDT 采样
 * 约束：不启用 SIMD（使用 int 实现），相同密钥/消息集合，多轮重复输出均值+标准差
 *
 * 编译时通过 FALCON_LOGN 宏区分 Falcon-512 (9) 和 Falcon-1024 (10)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif

#include "inner.h"
#include "api.h"

/* ==================================================================== */
/* NIST API 所需的随机数生成函数（使用固定种子保证可复现）               */
/* ==================================================================== */

static unsigned char rng_state[32] = {0};
static int rng_inited = 0;

/**
 * 生成 xlen 字节的随机数，写入 x
 * 使用确定性 PRNG（基于 SHAKE256），保证实验可复现
 */
void randombytes(unsigned char *x, unsigned long long xlen)
{
	if (!rng_inited) {
		/* 用固定种子初始化 */
		rng_state[0] = 0x42;
		rng_state[1] = 0x13;
		rng_inited = 1;
	}
	{
		inner_shake256_context sc;
		inner_shake256_init(&sc);
		inner_shake256_inject(&sc, rng_state, sizeof(rng_state));
		inner_shake256_flip(&sc);
		inner_shake256_extract(&sc, x, xlen);
		/* 更新状态 */
		inner_shake256_extract(&sc, rng_state, sizeof(rng_state));
	}
}

/**
 * NIST API 初始化函数（空实现）
 */
void randombytes_init(unsigned char *entropy_input,
	unsigned char *personalization_string, int security_strength)
{
	(void)entropy_input;
	(void)personalization_string;
	(void)security_strength;
	rng_inited = 0;
}

/* ==================================================================== */
/* fpr 与 double 互转（与 sign.c 中 fpr_of_double 保持一致）             */
/* ==================================================================== */

/**
 * 将 double 转换为 fpr（IEEE-754 binary64 位精确拷贝）
 */
static inline fpr
fpr_of_double(double d)
{
	fpr result;
	memcpy(&result, &d, sizeof result);
	return result;
}

/* Falcon 内部函数调用宏（Zf 前缀化） */
#define FN_set_k            Zf(set_k)
#define FN_set_default_k    Zf(set_default_k)
#define FN_sampler          Zf(sampler)
#define FN_prng_init        Zf(prng_init)

/* ==================================================================== */
/* 高精度 CPU 计时器                                                    */
/* ==================================================================== */

#ifdef _WIN32
static LARGE_INTEGER perf_freq;
static int perf_inited = 0;

/**
 * 初始化高精度计时器（获取性能计数器频率）
 */
static void timer_init(void)
{
	if (!perf_inited) {
		QueryPerformanceFrequency(&perf_freq);
		perf_inited = 1;
	}
}

/**
 * 获取当前高精度时间戳（纳秒）
 */
static uint64_t timer_ns(void)
{
	LARGE_INTEGER cnt;
	timer_init();
	QueryPerformanceCounter(&cnt);
	return (uint64_t)((double)cnt.QuadPart * 1e9 / (double)perf_freq.QuadPart);
}
#else
/**
 * 获取当前高精度 CPU 时间戳（纳秒），使用进程 CPU 时间
 */
static uint64_t timer_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
#endif

/* ==================================================================== */
/* 内存测量辅助                                                          */
/* ==================================================================== */

/**
 * 计算 Falcon-512/1024 密钥生成阶段的峰值工作内存（bytes）
 * 统计 crypto_sign_keypair 中同时存活的所有临时缓冲区
 */
static size_t mem_keygen(unsigned logn)
{
	size_t n = (size_t)1 << logn;
	size_t keygen_temp = (logn == 9) ? FALCON_KEYGEN_TEMP_9 : FALCON_KEYGEN_TEMP_10;
	size_t total = 0;

	/* tmp union: FALCON_KEYGEN_TEMP_* bytes */
	total += keygen_temp;
	/* f, g, F: 各 n 个 int8_t */
	total += 3 * n * sizeof(int8_t);
	/* h: n 个 uint16_t */
	total += n * sizeof(uint16_t);
	/* seed: 48 bytes */
	total += 48;
	/* rng: inner_shake256_context */
	total += sizeof(inner_shake256_context);

	return total;
}

/**
 * 计算签名阶段的峰值工作内存（bytes）
 * 统计 crypto_sign 中同时存活的所有临时缓冲区
 */
static size_t mem_sign(unsigned logn)
{
	size_t n = (size_t)1 << logn;
	size_t total = 0;

	/* tmp union: 72 * n bytes */
	total += 72 * n;
	/* f, g, F, G: 各 n 个 int8_t */
	total += 4 * n * sizeof(int8_t);
	/* r union: max(sig[n]*2, hm[n]*2) = 2*n bytes (取较大者) */
	total += 2 * n * sizeof(int16_t);
	/* seed + nonce */
	total += 48 + 40;
	/* esig: CRYPTO_BYTES - 2 - 40 */
	total += CRYPTO_BYTES - 2 - 40;
	/* sc: inner_shake256_context */
	total += sizeof(inner_shake256_context);

	return total;
}

/**
 * 计算验签阶段的峰值工作内存（bytes）
 * 统计 crypto_sign_open 中同时存活的所有临时缓冲区
 */
static size_t mem_vrfy(unsigned logn)
{
	size_t n = (size_t)1 << logn;
	size_t total = 0;

	/* tmp union: 2 * n bytes */
	total += 2 * n;
	/* h, hm: 各 n 个 uint16_t */
	total += 2 * n * sizeof(uint16_t);
	/* sig: n 个 int16_t */
	total += n * sizeof(int16_t);
	/* sc: inner_shake256_context */
	total += sizeof(inner_shake256_context);

	return total;
}

/**
 * 计算批量采样阶段的峰值工作内存（bytes）
 * 包含输出系数数组 + sampler_context 结构体
 */
static size_t mem_batch_sampler(unsigned logn)
{
	size_t n = (size_t)1 << logn;
	size_t total = 0;

	/* 输出系数数组: n 个 int16_t */
	total += n * sizeof(int16_t);
	/* sampler_context 结构体 */
	total += sizeof(sampler_context);

	return total;
}

/* ==================================================================== */
/* 统计辅助：均值与标准差                                                */
/* ==================================================================== */

/**
 * 计算 double 数组的均值
 */
static double mean_double(const double *arr, int n)
{
	double s = 0.0;
	int i;
	for (i = 0; i < n; i++) {
		s += arr[i];
	}
	return s / n;
}

/**
 * 计算 double 数组的标准差（总体标准差）
 */
static double std_double(const double *arr, int n, double m)
{
	double s = 0.0;
	int i;
	for (i = 0; i < n; i++) {
		double d = arr[i] - m;
		s += d * d;
	}
	return sqrt(s / n);
}

/* ==================================================================== */
/* 第一部分：隔离采样子模块测试                                          */
/* ==================================================================== */

/**
 * 批量采样性能测量
 *
 * 对给定 K 值的采样器，批量生成 n 个系数，测量总时间。
 * 仅包含采样逻辑，不含 NTT、哈希、范数检查、签名编码。
 * 同时统计拒绝采样的接受率 p = 接受次数 / 总采样尝试次数。
 *
 * 参数:
 *   n             多项式系数个数 (512 或 1024)
 *   k             分段数 K (1=基线, 2..16)
 *   repeat_rounds 重复轮数
 *   out_time_us   输出: 每轮批量采样时间数组 (微秒)
 *   out_accept_rate 输出: 每轮接受率 p 数组 (accept_count / total_count)
 *   out_peak_mem  输出: 峰值工作内存 (bytes, 各轮相同)
 */
static void measure_batch_sampler_perf(unsigned logn, int k, int repeat_rounds,
	double *out_time_us, double *out_accept_rate, size_t *out_peak_mem)
{
	size_t n = (size_t)1 << logn;
	int16_t *coeffs;
	sampler_context spc;
	inner_shake256_context rng;
	int round, i;

	coeffs = (int16_t *)malloc(n * sizeof(int16_t));

	for (round = 0; round < repeat_rounds; round++) {
		uint64_t t0, t1;

		/* 初始化采样上下文（在计时外，避免计入初始化开销） */
		FN_set_k(&spc, k, logn);
		inner_shake256_init(&rng);
		/* 用固定种子确保可复现 */
		{
			uint8_t seed[48];
			memset(seed, 0, sizeof(seed));
			seed[0] = (uint8_t)k;
			seed[1] = (uint8_t)round;
			inner_shake256_inject(&rng, seed, sizeof(seed));
		}
		inner_shake256_flip(&rng);
		FN_prng_init(&spc.p, &rng);

		/* ===== 计时开始：仅包裹批量采样逻辑 ===== */
		t0 = timer_ns();
		for (i = 0; i < (int)n; i++) {
			/* 使用固定 mu 和 isigma，模拟签名中的典型采样参数 */
			fpr mu = fpr_of(i % 16) / fpr_of(8);  /* 0.0 .. 1.875 */
			fpr isigma = fpr_inv(fpr_of_double(1.5));
			coeffs[i] = (int16_t)FN_sampler(&spc, mu, isigma);
		}
		t1 = timer_ns();
		/* ===== 计时结束 ===== */

		out_time_us[round] = (double)(t1 - t0) / 1000.0;

		/* 读取本轮拒绝采样的接受率 p = 接受次数 / 总尝试次数 */
		if (spc.total_count > 0) {
			out_accept_rate[round] = (double)spc.accept_count / (double)spc.total_count;
		} else {
			out_accept_rate[round] = 0.0;
		}
	}

	*out_peak_mem = mem_batch_sampler(logn);
	free(coeffs);
}

/* ==================================================================== */
/* 第二部分：完整 Falcon 算法全流程测量                                   */
/* ==================================================================== */

/**
 * 密钥生成性能测量
 *
 * 参数:
 *   pk            输出公钥缓冲区
 *   sk            输出私钥缓冲区
 *   out_time_us   输出: 密钥生成时间 (微秒)
 *   out_peak_mem  输出: 峰值工作内存 (bytes)
 */
static void measure_keygen_perf(unsigned char *pk, unsigned char *sk,
	double *out_time_us, size_t *out_peak_mem)
{
	uint64_t t0, t1;

	/* ===== 计时开始：仅包裹密钥生成逻辑 ===== */
	t0 = timer_ns();
	crypto_sign_keypair(pk, sk);
	t1 = timer_ns();
	/* ===== 计时结束 ===== */

	*out_time_us = (double)(t1 - t0) / 1000.0;
	*out_peak_mem = mem_keygen(FALCON_LOGN);
}

/**
 * 签名性能测量（含验签正确性检查）
 *
 * 参数:
 *   sm            输出签名+消息缓冲区
 *   smlen         输出签名+消息长度
 *   m             消息
 *   mlen          消息长度
 *   sk            私钥
 *   out_time_us   输出: 签名时间 (微秒)
 *   out_peak_mem  输出: 峰值工作内存 (bytes)
 * 返回: 0=验签通过, 非0=验签失败(本组数据应丢弃)
 */
static int measure_sign_perf(unsigned char *sm, unsigned long long *smlen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *sk, const unsigned char *pk,
	double *out_time_us, size_t *out_peak_mem)
{
	uint64_t t0, t1;
	unsigned char m_out[4096];
	unsigned long long mlen_out;
	int ret;

	/* ===== 计时开始：仅包裹签名逻辑 ===== */
	t0 = timer_ns();
	ret = crypto_sign(sm, smlen, m, mlen, sk);
	t1 = timer_ns();
	/* ===== 计时结束 ===== */

	if (ret != 0) {
		return -1;
	}

	*out_time_us = (double)(t1 - t0) / 1000.0;
	*out_peak_mem = mem_sign(FALCON_LOGN);

	/* 验签正确性检查：失败则本组数据丢弃 */
	if (crypto_sign_open(m_out, &mlen_out, sm, *smlen, pk) != 0) {
		return -2;
	}
	if (mlen_out != mlen || memcmp(m_out, m, mlen) != 0) {
		return -3;
	}

	return 0;
}

/**
 * 验签性能测量
 *
 * 参数:
 *   m_out         输出消息缓冲区
 *   mlen_out      输出消息长度
 *   sm            签名+消息
 *   smlen         签名+消息长度
 *   pk            公钥
 *   out_time_us   输出: 验签时间 (微秒)
 *   out_peak_mem  输出: 峰值工作内存 (bytes)
 */
static void measure_vrfy_perf(unsigned char *m_out, unsigned long long *mlen_out,
	const unsigned char *sm, unsigned long long smlen,
	const unsigned char *pk,
	double *out_time_us, size_t *out_peak_mem)
{
	uint64_t t0, t1;

	/* ===== 计时开始：仅包裹验签逻辑 ===== */
	t0 = timer_ns();
	crypto_sign_open(m_out, mlen_out, sm, smlen, pk);
	t1 = timer_ns();
	/* ===== 计时结束 ===== */

	*out_time_us = (double)(t1 - t0) / 1000.0;
	*out_peak_mem = mem_vrfy(FALCON_LOGN);
}

/* ==================================================================== */
/* 主程序                                                                */
/* ==================================================================== */

#define NUM_SIGN_ROUNDS  1000   /* 每种 K 值签名 1000 次 */
#define SAMPLER_ROUNDS   100    /* 批量采样重复轮数 */
#define MSG_LEN          64     /* 消息长度 */

int main(void)
{
	unsigned logn = FALCON_LOGN;
	size_t n = (size_t)1 << logn;
	const char *test_case = (logn == 9) ? "Falcon-512" : "Falcon-1024";
	int k_values[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
	int num_k = (int)(sizeof(k_values) / sizeof(k_values[0]));
	int ki;

	printf("=== Falcon K-分段采样性能基准测试: %s (n=%zu, logn=%u) ===\n",
		test_case, n, logn);
	printf("签名轮数: %d, 批量采样轮数: %d\n\n", NUM_SIGN_ROUNDS, SAMPLER_ROUNDS);

	/* CSV 表头 */
	printf("test_case,sampler_type,batch_n,batch_time_us_mean,batch_time_us_std,"
		"batch_peak_mem_bytes_mean,accept_rate_mean,accept_rate_std,"
		"kg_time_us_mean,kg_time_us_std,"
		"kg_peak_mem_bytes_mean,sign_time_us_mean,sign_time_us_std,"
		"sign_peak_mem_bytes_mean,vrfy_time_us_mean,vrfy_time_us_std,"
		"vrfy_peak_mem_bytes_mean\n");

	for (ki = 0; ki < num_k; ki++) {
		int k = k_values[ki];
		char sampler_type[32];
		double *batch_times;
		double *accept_rates;
		double *kg_times;
		double *sign_times;
		double *vrfy_times;
		size_t batch_peak_mem, kg_peak_mem, sign_peak_mem, vrfy_peak_mem;
		double batch_mean, batch_std, acc_mean, acc_std, kg_mean, kg_std;
		double sign_mean, sign_std, vrfy_mean, vrfy_std;
		int valid_sign = 0, valid_vrfy = 0;
		int round;

		if (k == 1) {
			snprintf(sampler_type, sizeof(sampler_type), "baseline_BaseSampler");
		} else {
			snprintf(sampler_type, sizeof(sampler_type), "RCDT_K%d", k);
		}

		fprintf(stderr, "[%s] 正在测试 K=%d ...\n", test_case, k);

		batch_times = (double *)malloc(SAMPLER_ROUNDS * sizeof(double));
		accept_rates = (double *)malloc(SAMPLER_ROUNDS * sizeof(double));
		kg_times = (double *)malloc(NUM_SIGN_ROUNDS * sizeof(double));
		sign_times = (double *)malloc(NUM_SIGN_ROUNDS * sizeof(double));
		vrfy_times = (double *)malloc(NUM_SIGN_ROUNDS * sizeof(double));

		/* ---- 第一部分：隔离采样子模块测试 ---- */
		FN_set_default_k(k);
		measure_batch_sampler_perf(logn, k, SAMPLER_ROUNDS,
			batch_times, accept_rates, &batch_peak_mem);
		batch_mean = mean_double(batch_times, SAMPLER_ROUNDS);
		batch_std = std_double(batch_times, SAMPLER_ROUNDS, batch_mean);
		acc_mean = mean_double(accept_rates, SAMPLER_ROUNDS);
		acc_std = std_double(accept_rates, SAMPLER_ROUNDS, acc_mean);

		/* ---- 第二部分：完整算法全流程测试 ---- */
		/* 为每个 K 值使用相同的密钥集合和消息集合 */
		for (round = 0; round < NUM_SIGN_ROUNDS; round++) {
			unsigned char pk[CRYPTO_PUBLICKEYBYTES];
			unsigned char sk[CRYPTO_SECRETKEYBYTES];
			unsigned char sm[CRYPTO_BYTES + MSG_LEN];
			unsigned char m_out[4096];
			unsigned char msg[MSG_LEN];
			unsigned long long smlen, mlen_out;
			double kg_t, sign_t, vrfy_t;
			size_t kg_mem, sign_mem, vrfy_mem;
			int sign_ret;

			/* 构造固定消息（基于轮数，确保各组消息相同） */
			memset(msg, 0, sizeof(msg));
			msg[0] = (unsigned char)(round & 0xFF);
			msg[1] = (unsigned char)((round >> 8) & 0xFF);

			/* 密钥生成 */
			FN_set_default_k(k);
			measure_keygen_perf(pk, sk, &kg_t, &kg_mem);
			kg_times[round] = kg_t;
			kg_peak_mem = kg_mem;

			/* 签名（含验签检查） */
			FN_set_default_k(k);
			sign_ret = measure_sign_perf(sm, &smlen, msg, MSG_LEN,
				sk, pk, &sign_t, &sign_mem);
			if (sign_ret == 0) {
				sign_times[valid_sign] = sign_t;
				sign_peak_mem = sign_mem;
				valid_sign++;

				/* 验签（仅对有效签名测量） */
				measure_vrfy_perf(m_out, &mlen_out, sm, smlen, pk,
					&vrfy_t, &vrfy_mem);
				vrfy_times[valid_vrfy] = vrfy_t;
				vrfy_peak_mem = vrfy_mem;
				valid_vrfy++;
			}
			/* 验签失败的轮次数据被丢弃 */
		}

		/* 计算统计量（仅基于有效数据） */
		kg_mean = mean_double(kg_times, NUM_SIGN_ROUNDS);
		kg_std = std_double(kg_times, NUM_SIGN_ROUNDS, kg_mean);

		if (valid_sign > 0) {
			sign_mean = mean_double(sign_times, valid_sign);
			sign_std = std_double(sign_times, valid_sign, sign_mean);
		} else {
			sign_mean = sign_std = 0.0;
		}

		if (valid_vrfy > 0) {
			vrfy_mean = mean_double(vrfy_times, valid_vrfy);
			vrfy_std = std_double(vrfy_times, valid_vrfy, vrfy_mean);
		} else {
			vrfy_mean = vrfy_std = 0.0;
		}

		/* 输出 CSV 行 */
		printf("%s,%s,%zu,%.3f,%.3f,%zu,%.6f,%.6f,%.3f,%.3f,%zu,%.3f,%.3f,%zu,%.3f,%.3f,%zu\n",
			test_case, sampler_type, n,
			batch_mean, batch_std, batch_peak_mem,
			acc_mean, acc_std,
			kg_mean, kg_std, kg_peak_mem,
			sign_mean, sign_std, sign_peak_mem,
			vrfy_mean, vrfy_std, vrfy_peak_mem);

		fprintf(stderr, "  有效签名: %d/%d, 有效验签: %d/%d, 接受率 p=%.4f±%.4f\n",
			valid_sign, NUM_SIGN_ROUNDS, valid_vrfy, NUM_SIGN_ROUNDS,
			acc_mean, acc_std);

		free(batch_times);
		free(accept_rates);
		free(kg_times);
		free(sign_times);
		free(vrfy_times);
	}

	fprintf(stderr, "\n测试完成。\n");
	return 0;
}
