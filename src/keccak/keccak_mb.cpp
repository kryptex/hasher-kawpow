#include "keccak_mb.h"

#include <include/keccak.h>
#include <stdlib.h>
#include <string.h>

#if defined(__x86_64__) && defined(__GNUC__)

#pragma GCC push_options
#pragma GCC target("avx2")
namespace mb4 {
constexpr int LANES = 4;
typedef uint64_t VEC __attribute__((vector_size(32)));
#include "keccak_mb.inc"
}  // namespace mb4
#pragma GCC pop_options

// 4 lanes on 256-bit registers, but with the 32-register file and single-instruction
// rotates of AVX-512VL: on Zen 4 the 512-bit datapath is double-pumped, so this can
// rival the 8-lane kernel while avoiding spills entirely.
#pragma GCC push_options
#pragma GCC target("avx512f,avx512vl")
namespace mb4v {
constexpr int LANES = 4;
typedef uint64_t VEC __attribute__((vector_size(32)));
#include "keccak_mb.inc"
}  // namespace mb4v
#pragma GCC pop_options

#pragma GCC push_options
#pragma GCC target("avx512f")
namespace mb8 {
constexpr int LANES = 8;
typedef uint64_t VEC __attribute__((vector_size(64)));
#include "keccak_mb.inc"
}  // namespace mb8
#pragma GCC pop_options

#endif

// Scalar fallback and non-x86 path: the same chain through the one-shot keccak.
static void merkle_roots_scalar(const uint8_t* prefix, size_t prefix_len, size_t extra_len,
                                const uint8_t* extras, const uint8_t* rct,
                                const uint8_t* branch, size_t branch_nodes,
                                size_t count, uint8_t* out)
{
    uint8_t buf[4096];
    uint8_t cat[96];
    memcpy(buf, prefix, prefix_len);
    for (size_t i = 0; i < count; i++) {
        memcpy(buf + prefix_len - extra_len, extras + i * extra_len, extra_len);
        union ethash_hash256 h = ethash_keccak256(buf, prefix_len);
        memcpy(cat, h.bytes, 32);
        memcpy(cat + 32, rct, 32);
        memset(cat + 64, 0, 32);
        h = ethash_keccak256(cat, 96);
        for (size_t b = 0; b < branch_nodes; b++) {
            memcpy(cat, h.bytes, 32);
            memcpy(cat + 32, branch + b * 32, 32);
            h = ethash_keccak256(cat, 64);
        }
        memcpy(out + i * 32, h.bytes, 32);
    }
}

void keccak_merkle_roots_mb(const uint8_t* prefix, size_t prefix_len, size_t extra_len,
                            const uint8_t* extras, const uint8_t* rct,
                            const uint8_t* branch, size_t branch_nodes,
                            size_t count, uint8_t* out)
{
#if defined(__x86_64__) && defined(__GNUC__)
    // KAWPOW_MB_FORCE pins a kernel for benchmarks and tests: avx512, avx512vl4, avx2 or scalar.
    // Read per call so a test process can switch kernels; a batch call runs for far longer
    // than one getenv.
    const char* force = getenv("KAWPOW_MB_FORCE");
    if (!force || !*force) {
        if (__builtin_cpu_supports("avx512f"))
            return mb8::merkle_roots(prefix, prefix_len, extra_len, extras, rct, branch, branch_nodes, count, out);
        if (__builtin_cpu_supports("avx2"))
            return mb4::merkle_roots(prefix, prefix_len, extra_len, extras, rct, branch, branch_nodes, count, out);
    } else if (!strcmp(force, "avx512") && __builtin_cpu_supports("avx512f")) {
        return mb8::merkle_roots(prefix, prefix_len, extra_len, extras, rct, branch, branch_nodes, count, out);
    } else if (!strcmp(force, "avx512vl4") && __builtin_cpu_supports("avx512vl")) {
        return mb4v::merkle_roots(prefix, prefix_len, extra_len, extras, rct, branch, branch_nodes, count, out);
    } else if (!strcmp(force, "avx2") && __builtin_cpu_supports("avx2")) {
        return mb4::merkle_roots(prefix, prefix_len, extra_len, extras, rct, branch, branch_nodes, count, out);
    }
#endif
    merkle_roots_scalar(prefix, prefix_len, extra_len, extras, rct, branch, branch_nodes, count, out);
}
