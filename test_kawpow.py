import os
import random
import unittest
import kawpow
import timeit

class TestEthash(unittest.TestCase):
    def test_keccak(self):
        hash_empty = (
            'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')

        h = kawpow.keccak_256(b'').hex()
        
        self.assertEqual(h, hash_empty)

    def test_keccak_merkle_root(self):
        prefix = bytes(range(96))
        extra = bytes.fromhex('3282000104f3a2b1')
        rct = kawpow.keccak_256(b'rct')
        branch = [kawpow.keccak_256(bytes([i])) for i in range(6)]

        spliced = prefix[:-len(extra)] + extra
        expected = kawpow.keccak_256(kawpow.keccak_256(spliced) + rct + bytes(32))
        for node in branch:
            expected = kawpow.keccak_256(expected + node)

        got = kawpow.keccak_merkle_root(prefix, extra, rct, b''.join(branch))
        self.assertEqual(got, expected)

    def test_keccak_merkle_root_no_extra_no_branch(self):
        prefix = b'\xab' * 43
        expected = kawpow.keccak_256(kawpow.keccak_256(prefix) + bytes(32) + bytes(32))
        self.assertEqual(kawpow.keccak_merkle_root(prefix, b'', bytes(32), b''), expected)

    def test_keccak_merkle_root_rejects_bad_lengths(self):
        with self.assertRaises(ValueError):
            kawpow.keccak_merkle_root(b'abc', b'abcd', bytes(32), b'')
        with self.assertRaises(ValueError):
            kawpow.keccak_merkle_root(b'abc', b'', bytes(31), b'')
        with self.assertRaises(ValueError):
            kawpow.keccak_merkle_root(b'abc', b'', bytes(32), bytes(33))

    def test_keccak_merkle_roots_batch_matches_single(self):
        rnd = random.Random(1234)
        for count in (1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 64):
            for prefix_len, extra_len, nodes in (
                    (96, 8, 6), (135, 8, 6), (136, 16, 1), (200, 8, 0), (272, 1, 12), (407, 32, 7)):
                prefix = rnd.randbytes(prefix_len)
                rct = rnd.randbytes(32)
                branch = rnd.randbytes(32 * nodes)
                extras = [rnd.randbytes(extra_len) for _ in range(count)]

                roots = kawpow.keccak_merkle_roots(prefix, b''.join(extras), extra_len, rct, branch)

                self.assertEqual(len(roots), count * 32)
                for i, extra in enumerate(extras):
                    expected = kawpow.keccak_merkle_root(prefix, extra, rct, branch)
                    self.assertEqual(roots[i * 32:(i + 1) * 32], expected,
                                     f'count={count} prefix_len={prefix_len} extra_len={extra_len} '
                                     f'nodes={nodes} miner={i}')

    def test_keccak_merkle_roots_every_kernel_matches(self):
        # A kernel the CPU does not support silently falls back to scalar, which still
        # has to produce the same bytes, so forcing each name is safe everywhere.
        rnd = random.Random(4321)
        prefix, rct = rnd.randbytes(96), rnd.randbytes(32)
        branch = rnd.randbytes(32 * 6)
        extras = b''.join(rnd.randbytes(8) for _ in range(37))
        expected = [kawpow.keccak_merkle_root(prefix, extras[i * 8:(i + 1) * 8], rct, branch)
                    for i in range(37)]
        for force in ('scalar', 'avx2', 'avx512vl4', 'avx512'):
            os.environ['KAWPOW_MB_FORCE'] = force
            try:
                roots = kawpow.keccak_merkle_roots(prefix, extras, 8, rct, branch)
            finally:
                del os.environ['KAWPOW_MB_FORCE']
            self.assertEqual([roots[i * 32:(i + 1) * 32] for i in range(37)], expected, force)

    def test_keccak_merkle_roots_rejects_bad_lengths(self):
        ok = dict(prefix=bytes(96), extras=bytes(16), extra_len=8, rct=bytes(32), branch=bytes(64))
        for bad in (dict(extra_len=0), dict(extra_len=97), dict(extras=bytes(15)),
                    dict(rct=bytes(33)), dict(branch=bytes(31)), dict(prefix=b'')):
            kw = {**ok, **bad}
            with self.assertRaises(ValueError):
                kawpow.keccak_merkle_roots(kw['prefix'], kw['extras'], kw['extra_len'], kw['rct'], kw['branch'])

    def test_pow(self):
        block_height = 2543241
        nonce = int.to_bytes(0xc9b1000029c69813, 8, 'little', signed=False)
        header_hash = bytes.fromhex(
            '0565cd49085a5b50b783aa1ba12b7fc73fffd6dc5345de1fb5389b0977e4caa2')
        mix_hash = bytes.fromhex(
            '7e8b16f02604df24780ddcc56297fa66c062c2db26a8d54e102ef8c53111e15b')
        final_hash = bytes.fromhex(
            '3755265d35ae6bd9b205850a6b9166a67cd7880bd49bc5ba832d21c583ff90d4')

        f, m = kawpow.pow(header_hash, nonce, block_height)

        self.assertEqual(m, mix_hash)
        self.assertEqual(f, final_hash)

    def test_pow_light(self):
        block_height = 2543241
        nonce = int.to_bytes(0xc9b1000029c69813, 8, 'little', signed=False)
        header_hash = bytes.fromhex(
            '0565cd49085a5b50b783aa1ba12b7fc73fffd6dc5345de1fb5389b0977e4caa2')
        mix_hash = bytes.fromhex(
            '7e8b16f02604df24780ddcc56297fa66c062c2db26a8d54e102ef8c53111e15b')
        final_hash = bytes.fromhex(
            '3755265d35ae6bd9b205850a6b9166a67cd7880bd49bc5ba832d21c583ff90d4')

        f = kawpow.pow_light(header_hash, nonce, block_height, mix_hash)

        self.assertEqual(f, final_hash)