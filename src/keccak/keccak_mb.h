// Batched Monero merkle roots over multi-buffer keccak-256.
// extras holds `count` packed extra-nonce blobs of extra_len bytes each; every miner shares
// prefix/rct/branch. out receives count*32 bytes. Dispatches 8-way AVX-512 / 4-way AVX2 /
// scalar at runtime. Callers must enforce prefix_len <= 4096 and extra_len <= prefix_len.
#pragma once

#include <stddef.h>
#include <stdint.h>

void keccak_merkle_roots_mb(const uint8_t* prefix, size_t prefix_len, size_t extra_len,
                            const uint8_t* extras, const uint8_t* rct,
                            const uint8_t* branch, size_t branch_nodes,
                            size_t count, uint8_t* out);
