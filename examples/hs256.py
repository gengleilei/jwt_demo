# 需要安装jwt与requests
# pip install PyJWT
# pip install requests

# 使用curl测试命名示例如下：
# curl -v http://xxxx/headers -H "Authorization:Bearer 生成的Token"

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
import json
import jwt
import requests

# 定义 payload，也就是要包含在 token 中的信息，Higress必须配置iss与sub
payload = {
    'iss': 'test',
    'sub': 'test'
}

def generate_hs256_token():
    # 设置你的密钥，这是一个随机生成的字符串，需要保存好，用于验证 token
    secret_key = 'my test secret key'

    # 对私钥进行base64编码，在Higress配置中需要
    base64_key = base64.b64encode(secret_key.encode("utf-8"))

    # 使用密钥生成token
    token = jwt.encode(payload, secret_key, algorithm="HS256")
    
    # 输出 token
    # print("JWT Token(HS256): " + token)

    return token, base64_key.decode()

def generate_hs256_jwks():
    token, base64_key = generate_hs256_token()

    data = {
        "keys":[
            {
                "kty":"oct",
                "alg": "HS256",
                "k": base64_key
            }
        ]
    }

    jwks = json.dumps(data, indent=4)
    return token, jwks

def test(jwt_token):
    # 设置请求头
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Authorization": "Bearer " + jwt_token
    }

    # 发送GET测试请求，URL请根据测试情况调整
    response = requests.get("http://47.97.61.65/headers", headers=headers)

    if response.status_code == 200:
        print("success")
    else:
        print("fail")

    return response.text


def main():
    token, jwks = generate_hs256_jwks()

    # 输出 token
    print("JWT Token(HS256): " + token + "\n")

    # 输出 jwks
    print("jwks: \n" + jwks)

    print("********* test jwt token ********")

    # 打印响应内容
    # print(test(token))


if __name__ == '__main__':
    main()