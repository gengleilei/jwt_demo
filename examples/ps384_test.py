import base64
import unittest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from ps384 import generate_ps384_jwks  # 假设函数位于名为ps384的模块中
from ps384 import generate_rsa_key

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
    load_pem_private_key,
    load_pem_public_key
)

import hashlib
from cryptography.hazmat.primitives import hashes

class TestGeneratePS384JWKS(unittest.TestCase):
    def setUp(self):
        # 生成RSA密钥对供测试
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.kid = "test_key_id"
        self.use = "sig"
        self.algorithm = "PS384"

    def test_generate_ps384_jwks_valid_use(self):
        # 测试当use参数为"sig"时的情况
        jwks = generate_ps384_jwks(self.public_key, self.kid, self.use, self.algorithm)
        self.assertEqual(jwks['kty'], "RSA")
        self.assertEqual(jwks['kid'], self.kid)
        self.assertEqual(jwks['use'], self.use)
        self.assertEqual(jwks['alg'], self.algorithm)
    
    def test_generate_ps384_jwks_invalid_use(self):
        # 测试当use参数为无效值时应该抛出ValueError异常
        with self.assertRaises(ValueError):
            generate_ps384_jwks(self.public_key, self.kid, "invalid_use", self.algorithm)
    
    def test_generate_ps384_jwks_correct_n_and_e(self):
        # 测试生成的JWKS中的n和e字段是否正确
        jwks = generate_ps384_jwks(self.public_key, self.kid, self.use, self.algorithm)
        print(f"jwks value: {jwks}")
        n_expected = self.public_key.public_numbers().n.to_bytes(
            (self.public_key.public_numbers().n.bit_length() + 7) // 8, byteorder='big'
        )
        e_expected = self.public_key.public_numbers().e.to_bytes(
            (self.public_key.public_numbers().e.bit_length() + 7) // 8, byteorder='big'
        )
        n_encoded_expected = base64.urlsafe_b64encode(n_expected).decode('utf8').rstrip('=')
        e_encoded_expected = base64.b64encode(e_expected).decode()

        print(f"The expected encoded n value: {n_encoded_expected}")
        print(f"The expected encoded e value: {e_encoded_expected}")

        self.assertEqual(jwks['n'], n_encoded_expected)
        self.assertEqual(jwks['e'], e_encoded_expected)

class TestRSAKeyGeneration(unittest.TestCase):

    def test_key_generation(self):
        private_key, private_key_pem, public_key, public_key_pem = generate_rsa_key()
        print(f"private key value: {private_key_pem}")

        # 解析私钥PEM格式
        pem_lines = private_key_pem.splitlines()
        ending_marker = '-----END PRIVATE KEY-----'

        # 检查私钥PEM是否包含结束标记，并且该标记在最后一行
        self.assertIn(ending_marker, pem_lines)
        self.assertEqual(pem_lines[-1], ending_marker)

        # 尝试解密并加载私钥
        try:
            loaded_private_key = load_pem_private_key(
                bytes(private_key_pem, 'utf-8'),
                password=None,
                backend=default_backend()
            )
        except Exception as e:
            self.fail(f"Failed to load generated private key: {e}")

        # 检查公钥PEM格式
        pem_lines = public_key_pem.splitlines()
        ending_public_marker = '-----END PUBLIC KEY-----'
        self.assertIn(ending_public_marker, pem_lines)
        self.assertEqual(pem_lines[-1], ending_public_marker)

        # 加载公钥
        try:
            loaded_public_key = load_pem_public_key(
                bytes(public_key_pem, 'utf-8'),
                backend=default_backend()
            )
        except Exception as e:
            self.fail(f"Failed to load generated public key: {e}")

        # 验证原始公钥与加载的公钥的公共数字是否相同
        # 直接提取和比较公共模数n和欧拉指数e
        original_public_numbers = public_key.public_numbers()
        loaded_public_numbers = loaded_public_key.public_numbers()

        self.assertEqual(original_public_numbers.n, loaded_public_numbers.n)
        self.assertEqual(original_public_numbers.e, loaded_public_numbers.e)

        # 如果你确实需要哈希值来进行某种形式的比较，你可以选择序列化这些数字：
        # 注意，这并不是标准做法，只是为了确保内容一致性
        serialized_original = original_public_numbers.n.to_bytes((original_public_numbers.n.bit_length() + 7) // 8, byteorder='big') + original_public_numbers.e.to_bytes((original_public_numbers.e.bit_length() + 7) // 8, byteorder='big')
        serialized_loaded = loaded_public_numbers.n.to_bytes((loaded_public_numbers.n.bit_length() + 7) // 8, byteorder='big') + loaded_public_numbers.e.to_bytes((loaded_public_numbers.e.bit_length() + 7) // 8, byteorder='big')

        # 计算两个序列化的哈希值
        original_hash = hashlib.sha256(serialized_original).digest()
        loaded_hash = hashlib.sha256(serialized_loaded).digest()

        self.assertEqual(original_hash, loaded_hash)

# 运行测试
if __name__ == '__main__':
    unittest.main()