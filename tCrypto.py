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
    from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
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
except Exception as e:
    raise e

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
        pk.verify(sign,  tFormat.byte_to_hexstr(tHash.cal_hash(data, mode)), 
                  padding.PSS(mgf = padding.MGF1(tHash.get_hash_handle(mode)),
                                                 salt_length=padding.PSS.MAX_LENGTH()),
                  tHash.get_hash_handle(mode))
        print('verify success')
    except Exception as e:
        print('verify failed')

def sign_by_rsa(key, data, mode):
    prik = serialization.load_pem_private_key(key, password=None, backend = default_backend)
    return prik.sign(tFormat.byte_to_hexstr(tHash.cal_hash(data, mode),
                                            padding.PSS(mgf = padding.MGF1(tHash.get_hash_handle(mode)),
                                                        salt_length = padding.PSS.MAX_LENGTH())))

def verify_by_ecdsa():
    return 0