# Falcon K-分段采样性能基准测试 Makefile
#
# 编译 Falcon-512 和 Falcon-1024 的基准测试程序
# 使用 Reference_Implementation 中的 int 实现（不启用 SIMD）
#
# 用法:
#   make          编译两个版本
#   make run      运行测试并输出 CSV
#   make clean    清理编译产物

CC      = gcc
CFLAGS  = -W -Wall -O2
LDFLAGS = -lm

# Falcon 源码目录
FALCON512_DIR  = ../Falcon-Round3/Falcon/falcon-round3/Reference_Implementation/falcon512/falcon512int
FALCON1024_DIR = ../Falcon-Round3/Falcon/falcon-round3/Reference_Implementation/falcon1024/falcon1024int

# 源文件列表
SRCS = codec.c common.c fft.c fpr.c keygen.c nist.c rng.c shake.c sign.c vrfy.c

.PHONY: all clean run

all: bench512.exe bench1024.exe

# Falcon-512 基准测试 (logn=9)
bench512.exe: bench_falcon.c
	$(CC) $(CFLAGS) -DFALCON_LOGN=9 -I$(FALCON512_DIR) -o $@ bench_falcon.c \
		$(addprefix $(FALCON512_DIR)/,$(SRCS)) $(LDFLAGS)

# Falcon-1024 基准测试 (logn=10)
bench1024.exe: bench_falcon.c
	$(CC) $(CFLAGS) -DFALCON_LOGN=10 -I$(FALCON1024_DIR) -o $@ bench_falcon.c \
		$(addprefix $(FALCON1024_DIR)/,$(SRCS)) $(LDFLAGS)

# 运行测试并保存 CSV 输出
run: bench512.exe bench1024.exe
	./bench512.exe > falcon512_bench.csv
	./bench1024.exe > falcon1024_bench.csv

clean:
	rm -f bench512.exe bench1024.exe *.o *.csv
