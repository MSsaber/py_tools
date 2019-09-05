# py_tools
for protocaol

#安全校验及数据协议分析工具
为方便密码学测验和tlv数据协议所写的测试工具，支持功能如下：
1.各主要算法的密钥生成和导出 tKey.py

2.非对称密钥（RSA， ECC， SM2）的签名和验签 tCrypto.py

3.数据加解密和密钥交换 (DH, ECDH) tCipher.py

4.杂凑和散列计算 tHash.py

5.x509证书的解析，以及直接使用证书验签操作 tCrypto.py

6.tlv数据的解析 tTlvParser.py

7.各种格式数据的转换 tFormat.py