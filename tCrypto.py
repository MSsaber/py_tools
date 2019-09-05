# !/usr/bin/python
# -*- coding: utf-8 -*-

try:
    import OpenSSL
except Exception as e:
    import os
    print(e)
    print("Download OpenSSL moduel")
    os.system("pip install pyopenssl")

try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec, utils
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
except Exception as e:
    import os
    print(e)
    print('Download cryptograpk')
    os.system('pip install cryptography')

try:
    from Crypto.PublicKey import RSA
    from Crypto.Hash import SHA256
except Exception as e:
    import os
    import platform
    print(e)
    print("Download Crypt moduel")
    os.system("pip install pycrypto")
    if platform.system() == 'Windows':
        os.system("pip install winrandom")

try:
    import tFormat
    import tHash
    import sm.sm2 as s2
    from sm import func
except Exception as e:
    print(e)

def get_pk_from_x509(cert_data, isPem):
    if isPem:
        flag = OpenSSL.crypto.FILETYPE_PEM
        buf = cert_data
    else:
        flag = OpenSSL.crypto.FILETYPE_ASN1
        buf = tFormat.hexstr_to_byte(tFormat.base64_to_hexstr(cert_data, False))
    cert = OpenSSL.crypto.load_certificate(flag, buf)
    pk = {}
    pk_buf = OpenSSL.crypto.dump_publickey(flag, cert.get_pubkey())
    if isPem:
        pk['key'] = pk_buf.decode('utf-8')
    else:
        pk['key'] = pk_buf
    pk['length'] = cert.get_pubkey().bits()
    return pk

def verify_by_rsa(key, data, sign, mode):
    pk = serialization.load_pem_public_key(key, backend = default_backend)
    try:
        pk.verify(sign, tHash.cal_hash(data, mode), 
                  padding.PSS(mgf = padding.MGF1(tHash.get_hash_handle(mode)),
                                                 salt_length=padding.PSS.MAX_LENGTH()),
                  tHash.get_hash_handle(mode))
        print('verify success')
    except Exception as e:
        print('verify failed')

def sign_by_rsa(key, data, mode):
    prik = serialization.load_pem_private_key(key, password=None, backend = default_backend)
    return prik.sign(tHash.cal_hash(data, mode),
                    padding.PSS(mgf = padding.MGF1(tHash.get_hash_handle(mode)),
                                salt_length = padding.PSS.MAX_LENGTH()))

def verify_by_ecdsa(key, data, sign, mode):
    pk = serialization.load_pem_public_key(key, backend = default_backend)
    try:
        pk.verify(sign, tHash.cal_hash(data, mode), utils.Prehashed(ec.ECDSA(tHash.get_hash_handle(mode))))
        print('verify success')
    except Exception as e:
        print('verify failed')

def sign_by_ecdsa(key, data, mode):
    prik = serialization.load_pem_private_key(key, password = None, backend = default_backend)
    return prik.sign(tHash.cal_hash(data, mode), utils.Prehashed(ec.ECDSA(tHash.get_hash_handle(mode))))

def verify_by_sm2(key, data, sign, mode):
    verifier = s2.CryptSM2(private_key = None, public_key = key)
    if verifier.verify(sign, tHash.cal_hash(data, tHash.sm3)):
        print('verify success')
    else:
        print('verify failed')

def sign_by_sm2(key, data, mode):
    import random
    sign = s2.CryptSM2(private_key = key, public_key = None)
    k = func.random_hex(sign.para_len)
    return sign.sign(tHash.cal_hash(data, tHash.sm3), k)

def crypto_args():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--alg', required = True, help = 'Algorithm : rsa, ec, sm2')
    parser.add_argument('--fk', required = False, help = "key file")
    parser.add_argument('--bk', required = False, help = "key buffer")
    parser.add_argument('--fc', required = False, help = "cert file")
    parser.add_argument('--bc', required = False, help = "cert buffer")
    return parser.parse_args()

def crypto_func():
    print("123123")
    args = crypto_args()

if __name__ == "__main__":
    crypto_func()