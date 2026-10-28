# Falcon-Round3 K-Segment Multi-Proposal RCDT Sampling

This repository is an extended version of the official [Falcon](https://falcon-sign.info/) Round3 C reference implementation, with a **K-segment multi-proposal discrete Gaussian sampling** improvement ported for research and experimentation.

## What Is This

Falcon is a NIST-selected post-quantum digital signature algorithm (based on NTRU lattices). Its signing process requires sampling from a discrete Gaussian distribution. The official implementation uses rejection sampling with a **single proposal width σ_max = 1.8205**.

The improvement in this repository partitions the σ range [σ_min, σ_max] into **K segments**, each using its own proposal width τ_j and RCDT table, reducing the rejection rate and improving sampling efficiency:

| Item | Original Falcon (K=1) | K-Segment (K>1) |
|---|---|---|
| Proposal width | Fixed σ_max = 1.8205 | Segment j uses τ_j (segment upper bound) |
| Rejection scale ccs | σ_min / σ | ℓ_j / σ (ℓ_j is segment lower bound) |
| Proposal distribution param | 1/(2σ_max²) | 1/(2τ_j²) |
| RCDT tables | 1 (for σ_max) | K (one per segment) |

**Key property: K=1 is exactly equivalent to the original Falcon** (same RCDT table, same ccs, same inv_2σ²), serving as the regression baseline.

## Directory Structure

```
.
├── Falcon-Round3/
│   └── Falcon/falcon-round3/
│       ├── Reference_Implementation/      # ← K-segment improvement ported here
│       │   ├── falcon512/falcon512int/    # Falcon-512 reference implementation
│       │   │   ├── sign.c                 # Sampler core (with K-segment logic)
│       │   │   ├── inner.h                # sampler_context struct definition
│       │   │   └── falcon512_rcdt_tables.h # K=1..16 RCDT tables (auto-generated)
│       │   └── falcon1024/falcon1024int/  # Falcon-1024 reference implementation (same as above)
│       ├── Optimized_Implementation/      # Official optimized implementations (unchanged)
│       ├── KAT/generator/                 # NIST KAT generator
│       └── Supporting_Documentation/      # Official specification
├── gen_rcdt_tables.py                     # RCDT table generation script
├── optimal_boundaries.py                  # Optimal K-segment boundaries for Falcon-512
└── optimal_boundaries_1024.py             # Optimal K-segment boundaries for Falcon-1024
```

> **Note**: The K-segment improvement is currently only ported to `Reference_Implementation/falcon{512,1024}int/`. `Optimized_Implementation/` and `Extra/c/` remain as the official originals.

## Building

Requires a C compiler (gcc / clang / mingw). Example for Falcon-512:

```bash
cd Falcon-Round3/Falcon/falcon-round3/Reference_Implementation/falcon512/falcon512int
mkdir -p build

# Compile all object files
for f in codec common fft fpr keygen nist rng shake sign vrfy; do
  gcc -W -Wall -O2 -c -o build/$f.o $f.c
done

# Compile KAT generator
KAT=../../../KAT/generator
gcc -W -Wall -O2 -I . -DALGNAME=falcon512int -c -o build/PQCgenKAT_sign.o $KAT/PQCgenKAT_sign.c
gcc -W -Wall -O2 -I . -c -o build/katrng.o $KAT/katrng.c

# Link
gcc -o build/kat512int build/*.o
```

Same for Falcon-1024 (replace `512` with `1024`).

## Using K-Segment Sampling

### Method 1: Set K globally (recommended)

Before signing, set the global segment count via `set_default_k(k)`. All subsequent `crypto_sign()` calls will use that K value.

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

    // Generate key pair
    crypto_sign_keypair(pk, sk);

    // Set K=4 segment sampling (K=1 is original Falcon)
    set_default_k(4);

    // Sign
    crypto_sign(sm, &smlen, msg, sizeof(msg) - 1, sk);

    // Verify
    crypto_sign_open(m_out, &mlen, sm, smlen, pk);
    return 0;
}
```

### Method 2: Set K per context

If different signatures need different K values, operate on `sampler_context` directly:

```c
#include "inner.h"

sampler_context spc;
set_k(&spc, 8, 9);   // K=8, logn=9 (Falcon-512)
prng_init(&spc.p, &rng);
// Then pass &spc as samp_ctx to do_sign_tree / do_sign_dyn
```

### Available K values

K = 1, 2, 3, ..., 16 are supported. K=1 is the original Falcon.

## Running Correctness Tests

After building the KAT program, run it directly. It generates `.req` and `.rsp` files and internally verifies signatures:

```bash
./build/kat512int    # With K=1, output should match official KAT vectors
```

You can also write your own test to sign+verify for different K values:

```c
for (int k = 1; k <= 16; k++) {
    set_default_k(k);
    crypto_sign(sm, &smlen, msg, mlen, sk);
    int ret = crypto_sign_open(m_out, &mlen, sm, smlen, pk);
    // ret == 0 means verification passed
}
```

## Regenerating RCDT Tables

If you modify the boundary values, regenerate the RCDT tables:

```bash
python gen_rcdt_tables.py
```

The script reads `optimal_boundaries.py` and `optimal_boundaries_1024.py`, then generates `falcon512_rcdt_tables.h` and `falcon1024_rcdt_tables.h` into the corresponding implementation directories.

## Core API Reference

| Function | Description |
|---|---|
| `set_default_k(int k)` | Set global K value, returns old value. Affects `sign_tree`/`sign_dyn` |
| `set_k(sampler_context *spc, int k, unsigned logn)` | Configure K and boundaries for a single sampler context |
| `sampler(void *ctx, fpr mu, fpr isigma)` | Discrete Gaussian sampler (K-segment version) |
| `gaussian0_sampler(prng *p)` | Half-Gaussian sampler (σ_max, for backward compatibility) |
| `crypto_sign_keypair` / `crypto_sign` / `crypto_sign_open` | NIST standard signature API |

## License

Based on the official Falcon MIT license. See the header of each source file for details.
