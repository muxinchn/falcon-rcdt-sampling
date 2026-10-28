# Falcon-Round3 K-分段多提议 RCDT 采样

本仓库是 [Falcon](https://falcon-sign.info/) 官方 Round3 C 参考实现的扩展版本，移植了 **K-分段多提议（Multi-Proposal）离散高斯采样** 改进，用于研究和实验。

## 这是什么

Falcon 是 NIST 选定的后量子数字签名算法（基于 NTRU 格）。其签名过程需要从离散高斯分布中采样，官方实现使用 **单一提议宽度 σ_max = 1.8205** 的拒绝采样。

本仓库的改进将 σ 的取值范围 [σ_min, σ_max] 划分为 **K 段**，每段使用自己的提议宽度 τ_j 和 RCDT 表，从而降低拒绝率、提高采样效率：

| 项 | 原始 Falcon (K=1) | K-分段 (K>1) |
|---|---|---|
| 提议宽度 | 固定 σ_max = 1.8205 | 段 j 使用 τ_j（该段上界） |
| 拒绝缩放 ccs | σ_min / σ | ℓ_j / σ（ℓ_j 为段下界） |
| 提议分布参数 | 1/(2σ_max²) | 1/(2τ_j²) |
| RCDT 表 | 1 张（σ_max） | K 张（每段一张） |

**关键性质：K=1 与原始 Falcon 完全等价**（使用相同的 RCDT 表、相同的 ccs 和 inv_2σ²），可作为回归基线。

## 目录结构

```
.
├── Falcon-Round3/
│   └── Falcon/falcon-round3/
│       ├── Reference_Implementation/      # ← K-分段改进移植在此
│       │   ├── falcon512/falcon512int/    # Falcon-512 参考实现
│       │   │   ├── sign.c                 # 采样器核心（含 K-分段逻辑）
│       │   │   ├── inner.h                # sampler_context 结构体定义
│       │   │   └── falcon512_rcdt_tables.h # K=1..16 的 RCDT 表（自动生成）
│       │   └── falcon1024/falcon1024int/  # Falcon-1024 参考实现（同上）
│       ├── Optimized_Implementation/      # 官方优化实现（未改动）
│       ├── KAT/generator/                 # NIST KAT 生成器
│       └── Supporting_Documentation/      # 官方规格文档
├── gen_rcdt_tables.py                     # RCDT 表生成脚本
├── optimal_boundaries.py                  # Falcon-512 的 K 分段最优边界
└── optimal_boundaries_1024.py             # Falcon-1024 的 K 分段最优边界
```

> **注意**：K-分段改进目前仅移植到 `Reference_Implementation/falcon{512,1024}int/`。`Optimized_Implementation/` 和 `Extra/c/` 保持官方原样。

## 编译

需要 C 编译器（gcc / clang / mingw 均可）。以 Falcon-512 为例：

```bash
cd Falcon-Round3/Falcon/falcon-round3/Reference_Implementation/falcon512/falcon512int
mkdir -p build

# 编译所有目标文件
for f in codec common fft fpr keygen nist rng shake sign vrfy; do
  gcc -W -Wall -O2 -c -o build/$f.o $f.c
done

# 编译 KAT 生成器
KAT=../../../KAT/generator
gcc -W -Wall -O2 -I . -DALGNAME=falcon512int -c -o build/PQCgenKAT_sign.o $KAT/PQCgenKAT_sign.c
gcc -W -Wall -O2 -I . -c -o build/katrng.o $KAT/katrng.c

# 链接
gcc -o build/kat512int build/*.o
```

Falcon-1024 同理（将 `512` 替换为 `1024`）。

## 使用 K-分段采样

### 方式一：全局设置 K 值（推荐）

在调用签名之前，通过 `set_default_k(k)` 设置全局段数。后续所有 `crypto_sign()` 调用都会使用该 K 值。

```c
#include "api.h"
#include "inner.h"

int main(void) {
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char sm[CRYPTO_BYTES + 64];
    unsigned char m_out[128];
    unsigned char msg[] = "hello world";
    unsigned long long smlen, mlen;

    // 生成密钥对
    crypto_sign_keypair(pk, sk);

    // 设置 K=4 分段采样（K=1 为原始 Falcon）
    set_default_k(4);

    // 签名
    crypto_sign(sm, &smlen, msg, sizeof(msg) - 1, sk);

    // 验证
    crypto_sign_open(m_out, &mlen, sm, smlen, pk);
    return 0;
}
```

### 方式二：逐上下文设置 K 值

如果需要对不同签名使用不同的 K 值，可直接操作 `sampler_context`：

```c
#include "inner.h"

sampler_context spc;
set_k(&spc, 8, 9);   // K=8, logn=9 (Falcon-512)
prng_init(&spc.p, &rng);
// 然后将 &spc 作为 samp_ctx 传给 do_sign_tree / do_sign_dyn
```

### 可用的 K 值

支持 K = 1, 2, 3, ..., 16。K=1 即原始 Falcon。

## 运行正确性测试

编译 KAT 程序后直接运行，会生成 `.req` 和 `.rsp` 文件，程序内部会自动验证签名：

```bash
./build/kat512int    # K=1 时应与官方 KAT 向量一致
```

也可以自行编写测试，对不同 K 值做签名+验证：

```c
for (int k = 1; k <= 16; k++) {
    set_default_k(k);
    crypto_sign(sm, &smlen, msg, mlen, sk);
    int ret = crypto_sign_open(m_out, &mlen, sm, smlen, pk);
    // ret == 0 表示验证通过
}
```

## 重新生成 RCDT 表

如果修改了边界值，可重新生成 RCDT 表：

```bash
python gen_rcdt_tables.py
```

脚本会读取 `optimal_boundaries.py` 和 `optimal_boundaries_1024.py`，生成 `falcon512_rcdt_tables.h` 和 `falcon1024_rcdt_tables.h`，覆盖到对应的实现目录。

## 核心 API 速查

| 函数 | 说明 |
|---|---|
| `set_default_k(int k)` | 设置全局 K 值，返回旧值。影响 `sign_tree`/`sign_dyn` |
| `set_k(sampler_context *spc, int k, unsigned logn)` | 配置单个采样上下文的 K 值和边界 |
| `sampler(void *ctx, fpr mu, fpr isigma)` | 离散高斯采样器（K-分段版本） |
| `gaussian0_sampler(prng *p)` | 半高斯采样（σ_max，向后兼容） |
| `crypto_sign_keypair` / `crypto_sign` / `crypto_sign_open` | NIST 标准签名 API |

## 许可证

基于 Falcon 官方 MIT 许可证。详见各源文件头部。
