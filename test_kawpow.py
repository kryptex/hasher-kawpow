import unittest
import kawpow
import timeit

class TestEthash(unittest.TestCase):
    def test_keccak(self):
        hash_empty = (
            'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')

        h = kawpow.keccak_256(b'').hex()
        
        self.assertEqual(h, hash_empty)

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