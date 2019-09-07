# !/usr/bin/python
# -*- coding: utf-8 -*-

try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec, utils
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography import x509
except Exception as e:
    import os
    print(e)
    print('Download cryptograpk')
    os.system('pip install cryptography')

try:
    import tFormat
    import tHash
    import sm.sm2 as s2
    from sm import func
except Exception as e:
    print(e)

PEM = 0x01
DER = 0x02

RSA = 0x01
ECC = 0x02
SM2 = 0x03

def parse_x509(cert_data, isPem):
    if isPem:
        cert = cert_data.encode('ascii')
        crt = x509.load_pem_x509_certificate(data = cert, backend = default_backend())
    else:
        crt = x509.load_der_x509_certificate(cert_data, default_backend())
    print('')
    print('证书版本 : ' + str(crt.version))
    print('证书序列号 : ' + str(crt.serial))
    print('证书颁发时间 : ' + str(crt.not_valid_before))
    print('证书截止时间 : ' + str(crt.not_valid_after))
    print('证书签名的hash类型 : ' + str(crt.signature_hash_algorithm.name))
    print('证书签名算法类型oid : ' + str(crt.serial_number))
    print('证书子项 : ')
    for sub in crt.subject.rdns:
        print('\t' + str(sub))
    print('证书签名 : ' + tFormat.byte_to_hexstr(crt.signature))
    print('公钥 : ' + str(crt.public_key().public_bytes(serialization.Encoding.PEM,
                                                        serialization.PublicFormat.SubjectPublicKeyInfo)))
    print('指纹 : ' + tFormat.byte_to_hexstr(crt.fingerprint(hashes.SHA256())))
    print('证书扩展项 : ' + str(crt.extensions))
    print('证书发行方 : ')
    for sub in crt.issuer.rdns:
        print('\t' + str(sub))
    #crt.tbs_certificate_bytes

def get_pk_from_x509(cert_data, isPem, pkFmt):
    if isPem:
        cert = cert_data.encode('ascii')
        crt = x509.load_pem_x509_certificate(data = cert, backend = default_backend())
    else:
        crt = x509.load_der_x509_certificate(cert_data, default_backend())
    pk = {}
    if pkFmt == PEM:
        flag = serialization.Encoding.PEM
    elif pkFmt == DER:
        flag = serialization.Encoding.DER
 
    pk['key'] = crt.public_key().public_bytes(flag, serialization.PublicFormat.SubjectPublicKeyInfo)
    pk['length'] = crt.public_key().key_size
    return pk

def verify_by_rsa(key, data, sign, mode, isPem):
    if isPem:
        pk = serialization.load_pem_public_key(key, backend = default_backend())
    else:
        pk = serialization.load_der_public_key(key, backend = default_backend())
    try:
        print('digest :' + tFormat.byte_to_hexstr(tHash.cal_hash(data, mode)))
        print('sign :' + tFormat.byte_to_hexstr(sign))
        pk.verify(sign, data, padding.PKCS1v15(), tHash.get_hash_handle(mode))
        print('verify success')
    except Exception as e:
        print('verify failed')

def sign_by_rsa(key, data, mode):
    prik = serialization.load_pem_private_key(key, password=None, backend = default_backend())
    return prik.sign(data, padding.PKCS1v15(), tHash.get_hash_handle(mode))

def verify_by_ecdsa(key, data, sign, mode):
    pk = serialization.load_pem_public_key(key, backend = default_backend())
    try:
        pk.verify(sign, data, ec.ECDSA(tHash.get_hash_handle(mode)))
        print('verify success')
    except Exception as e:
        print('verify failed')

def sign_by_ecdsa(key, data, mode):
    prik = serialization.load_pem_private_key(key, password = None, backend = default_backend())
    return prik.sign(data, ec.ECDSA(tHash.get_hash_handle(mode)))

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
    parser.add_argument('--alg', required = False, help = 'Algorithm : rsa, ec, sm2')
    parser.add_argument('--fk', required = False, help = "key file")
    parser.add_argument('--bk', required = False, help = "key buffer")
    parser.add_argument('--fc', required = False, help = "cert file")
    parser.add_argument('--bc', required = False, help = "cert buffer")
    parser.add_argument('--sign', required = False, help = 'sign data')
    parser.add_argument('--data', required = False, help = 'src data')
    return parser.parse_args()

def crypto_func():
    args = crypto_args()
    cert = tFormat.format_data(args.fc, True, tFormat.NONE, tFormat.NONE)
    data = tFormat.format_data(args.data, False, tFormat.BASE64, tFormat.NONE)
    sign = tFormat.format_data(args.sign, False, tFormat.BASE64, tFormat.NONE)
    pk = get_pk_from_x509(cert, True, PEM)
    verify_by_rsa(pk['key'],
                  tFormat.format_data(args.data, False, tFormat.BASE64, tFormat.NONE),
                  tFormat.format_data(args.sign, False, tFormat.BASE64, tFormat.NONE),
                  tHash.sha256, True)
    parse_x509(cert, True)

if __name__ == "__main__":
    crypto_func()