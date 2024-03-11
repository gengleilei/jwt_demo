# -*- coding: utf-8 -*-
# 使用curl测试命名示例如下：
# curl -v http://xxxxx/headers -H "Authorization:Bearer 生成的Token"

# 1、JWT 是 JSON Web Tokens 的缩写，是目前最流行的跨域认证解决方案，是一个开放式标准(RFC 7519)，用于在各方之间以JSON对象安全传输信息。
# 2、JWT 包含了认证信息，请妥善保管！我们不记录和存储你的JWT信息，所有验证和调试都在客户端上进行！
# 3、Payload 用来存放实际需要传递的数据，JWT 规定的7个官方字段，供选用：
#    iss (Issuer)：签发者
#    sub (Subject)：主题
#    aud (Audience)：接收者
#    exp (Expiration time)：过期时间
#    nbf (Not Before)：生效时间
#    iat (Issued At)：签发时间
#    jti (JWT ID)：编号

import base64
import datetime
import json
import jwt
import requests
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_rsa_key():
    # 生成RSA密钥对
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # 生成pem格式私钥
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # 获取公钥
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key, private_key_pem.decode('utf-8'), public_key, public_key_pem.decode('utf-8')

def generate_ps256_jwks(public_key, kid, use, algorithm):
    if use != "enc" and use != "sig":
        raise ValueError("Invalid use value")

    # 获取公钥的模数
    n = public_key.public_numbers().n
    # 将模数转换为字节串
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
    # 对字节进行Base64编码  
    n_base64_bytes = base64.urlsafe_b64encode(n_bytes)
    # 将Base64编码转换为字符串  
    n_base64_str = n_base64_bytes.decode('utf8')
    # 去除Base64编码末尾的'='字符  
    n_base64_url = n_base64_str.rstrip('=')

    # 获取公钥的指数
    e = public_key.public_numbers().e
    e_base64_encoded = base64.b64encode(e.to_bytes((e.bit_length() + 7) // 8, 'big')).decode()

    data = {
        "kty": "RSA",
        "n": n_base64_url,
        "e": e_base64_encoded,
        "alg": algorithm,
        "kid": kid, 
        "use": use,
    }
    return data
    return json.dumps(data, indent=4)

def generate_jwt_token(private_key_pem, payload_data, algorithm):
    return jwt.encode(payload=payload_data, key=private_key_pem, algorithm=algorithm)

def test(jwt_token):
    print("********* test jwt token ********")

    # 设置请求头
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Authorization": "Bearer " + jwt_token
    }

    # 发送GET测试请求，URL请根据测试情况调整
    response = requests.get("http://xx.xx.xx.xx/headers", headers=headers)

    if response.status_code == 200:
        print("success")
    else:
        print("fail")

    return response.text

def main():
    # 创建rsa公私钥
    private_key, private_key_pem, public_key, public_key_pem = generate_rsa_key()

    # 构建Jwt token
    payload = {
        'iss': 'test',
        'sub': 'test',
        'name': 'Jessica Temporal',
        'nickname': 'Jess',
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }
    algorithm = 'PS384'
    token = generate_jwt_token(private_key_pem, payload, 'PS384')

    # 构建JWKS配置
    timestamp = time.time()
    kid = str(timestamp)
    jwk = generate_ps256_jwks(public_key, kid, "sig", algorithm)
    jwks = {
        "keys": [jwk]
    }

    # 输出 token
    print("JWT Token(PS384): ", "\n", token)

    # 输出PEM格式公私钥
    print("RSA Private Key(PEM): ", "\n", private_key_pem)
    print("RSA Public Key(PEM): ", "\n", public_key_pem)

    # 打印JWKS配置
    print("jwks: ", "\n", json.dumps(jwks, indent=4))

    # 打印响应内容
    # print(test(token))


if __name__ == '__main__':
    main()