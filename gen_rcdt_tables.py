"""
生成 Falcon K-分段采样所需的 RCDT 表 C 头文件。

为 Falcon-512 和 Falcon-1024 各生成 K=1..16 的 RCDT 表，
输出为 C 静态数组，格式与官方 gaussian0_sampler 的 dist[] 一致：
每个条目用 3 个 24-bit limbs 表示 72 位精度的 RCDT 值。
"""
import math
import os

# Falcon 参数
FALCON_PARAMS = {
    512: {
        "sigmin": 1.2778336969128337,
        "sigmax": 1.8205,
        "boundaries_file": r"D:\PythonScripts\temp_20261011_01\falcon_original\optimal_boundaries.py",
    },
    1024: {
        "sigmin": 1.298280334344292,
        "sigmax": 1.8205,
        "boundaries_file": r"D:\PythonScripts\temp_20261011_01\falcon_original\optimal_boundaries_1024.py",
    },
}

RCDT_PREC = 72       # 与官方一致: 72 位精度
RCDT_LEN = 18        # 表长度 (z = 0..17)

# 官方 Falcon 精确的 sigma_max=1.8205 RCDT 表 (3 x 24-bit limbs per entry)
# 直接来自 Falcon 官方 sign.c 的 dist[] 数组
OFFICIAL_DIST_LIMBS = [
    (10745844, 3068844, 3741698),
    (5559083, 1580863, 8248194),
    (2260429, 13669192, 2736639),
    (708981, 4421575, 10046180),
    (169348, 7122675, 4136815),
    (30538, 13063405, 7650655),
    (4132, 14505003, 7826148),
    (417, 16768101, 11363290),
    (31, 8444042, 8086568),
    (1, 12844466, 265321),
    (0, 1232676, 13644283),
    (0, 38047, 9111839),
    (0, 870, 6138264),
    (0, 14, 12545723),
    (0, 0, 3104126),
    (0, 0, 28824),
    (0, 0, 198),
    (0, 0, 1),
]


def generate_rcdt(sigma, prec=RCDT_PREC, length=RCDT_LEN):
    """
    为宽度为 sigma 的半高斯生成反向累积分布表 (RCDT)。

    RCDT[i] = floor(2^prec * sum_{j>i} P(j))
    其中 P(j) = exp(-j^2 / (2*sigma^2)) / S, S = sum_{k>=0} exp(-k^2/(2*sigma^2))
    """
    probs = []
    for k in range(length + 2):
        probs.append(math.exp(-k * k / (2.0 * sigma * sigma)))
    S = sum(probs)
    probs = [p / S for p in probs]
    scale = 1 << prec
    rcdt = []
    for i in range(length):
        tail = sum(probs[i + 1:])
        rcdt.append(int(tail * scale))
    return rcdt


def rcdt_to_c_limbs(rcdt_value):
    """
    将单个 RCDT 值 (72 位整数) 拆分为 3 个 24-bit limbs。
    存储顺序与官方 dist[] 一致: {high, mid, low}
    """
    low = rcdt_value & 0xFFFFFF
    mid = (rcdt_value >> 24) & 0xFFFFFF
    high = (rcdt_value >> 48) & 0xFFFFFF
    return (high, mid, low)


def load_boundaries(filepath, n):
    """
    从 optimal_boundaries.py 文件加载 K=1..16 的边界值。
    """
    boundaries = {}
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    # 简单解析 OPTIMAL_BOUNDARIES 字典
    import ast
    tree = ast.parse(content)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "OPTIMAL_BOUNDARIES":
                    boundaries = ast.literal_eval(node.value)
    return boundaries


def generate_c_tables(n, params):
    """
    为指定 Falcon 参数 (n=512 或 1024) 生成 C 代码字符串。
    """
    boundaries = load_boundaries(params["boundaries_file"], n)
    sigmin = params["sigmin"]
    sigmax = params["sigmax"]

    lines = []
    lines.append("/*")
    lines.append(f" * Falcon-{n} K-分段多提议采样 RCDT 表")
    lines.append(f" * 由 gen_rcdt_tables.py 自动生成，请勿手动修改。")
    lines.append(f" * sigmin = {sigmin}, sigmax = {sigmax}")
    lines.append(" */")
    lines.append("")
    lines.append(f"#ifndef FALCON{n}_RCDT_TABLES_H")
    lines.append(f"#define FALCON{n}_RCDT_TABLES_H")
    lines.append("")
    lines.append("#include <stdint.h>")
    lines.append("")
    lines.append("#define FALCON_MAX_K 16")
    lines.append(f"#define FALCON{n}_RCDT_LEN 18")
    lines.append("")

    # 为每个 K 值生成所有段的 RCDT 表
    for k in range(1, 17):
        bnds = boundaries[k]
        # 段 j 的上界 tau_j = bnds[j+1]
        taus = [bnds[j + 1] for j in range(k)]
        for j in range(k):
            tau = taus[j]
            table_name = f"falcon{n}_rcdt_k{k}_seg{j}"
            lines.append(f"/* K={k}, 段 {j}, tau={tau:.12f} */")
            lines.append(f"static const uint32_t {table_name}[] = {{")
            if abs(tau - sigmax) < 1e-9:
                # sigma_max 段使用官方精确表，确保 K=1 与原始完全一致
                limbs_list = OFFICIAL_DIST_LIMBS
            else:
                rcdt = generate_rcdt(tau)
                limbs_list = [rcdt_to_c_limbs(val) for val in rcdt]
            for idx, (high, mid, low) in enumerate(limbs_list):
                if idx == len(limbs_list) - 1:
                    lines.append(f"\t{high}u, {mid}u, {low}u")
                else:
                    lines.append(f"\t{high}u, {mid}u, {low}u,")
            lines.append("};")
            lines.append("")

    # 生成边界数组 (fpr 值需要用 double 表示，运行时转换)
    lines.append(f"/* Falcon-{n} 各 K 值的段边界 (double 格式，运行时转为 fpr) */")
    for k in range(1, 17):
        bnds = boundaries[k]
        arr_name = f"falcon{n}_boundaries_k{k}"
        vals = ", ".join([f"{b:.12f}" for b in bnds])
        lines.append(f"static const double {arr_name}[] = {{ {vals} }};")
    lines.append("")

    # 生成 K -> 边界数组指针 的查找表
    lines.append(f"/* K -> 边界数组指针 */")
    lines.append(f"static const double *falcon{n}_boundaries_tables[FALCON_MAX_K + 1] = {{")
    lines.append("\tNULL,  /* K=0 未使用 */")
    for k in range(1, 17):
        lines.append(f"\tfalcon{n}_boundaries_k{k},")
    lines.append("};")
    lines.append("")

    # 生成 K -> RCDT 表指针数组 (每个 K 有 k 张表)
    lines.append(f"/* K -> RCDT 表指针数组 */")
    for k in range(1, 17):
        arr_name = f"falcon{n}_rcdt_tables_k{k}"
        lines.append(f"static const uint32_t *{arr_name}[{k}] = {{")
        for j in range(k):
            comma = "," if j < k - 1 else ""
            lines.append(f"\tfalcon{n}_rcdt_k{k}_seg{j}{comma}")
        lines.append("};")
    lines.append("")

    lines.append(f"/* K -> RCDT 表指针数组的查找表 */")
    lines.append(f"static const uint32_t **falcon{n}_rcdt_tables_all[FALCON_MAX_K + 1] = {{")
    lines.append("\tNULL,  /* K=0 未使用 */")
    for k in range(1, 17):
        lines.append(f"\tfalcon{n}_rcdt_tables_k{k},")
    lines.append("};")
    lines.append("")

    lines.append(f"#endif /* FALCON{n}_RCDT_TABLES_H */")
    lines.append("")

    return "\n".join(lines)


def main():
    out_dir = r"D:\PythonScripts\temp_20261011_01"
    for n, params in FALCON_PARAMS.items():
        c_code = generate_c_tables(n, params)
        out_path = os.path.join(out_dir, f"falcon{n}_rcdt_tables.h")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(c_code)
        print(f"[INFO] 已生成 {out_path}")


if __name__ == "__main__":
    main()
