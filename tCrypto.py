# !/usr/bin/python
# -*- coding: utf-8 -*-

try:
    import OpenSSL
except Exception as e:
    import os
    print(e)
    print("Download OpenSSL moduel")
    os.system("pip3 install pyopenssl")

try:
    from Crypto.PublicKey import RSA
    from Crypto.Hash import SHA256
except Exception as e:
    import os
    import platform
    print(e)
    print("Download Crypt moduel")
    os.system("pip3 install pycrypto")
    if platform.system() == 'Windows':
        os.system("pip3 install winrandom")

try:
    import tFormat
except Exception as e:
    raise e

def get_pk_from_x509(cert_data, isPem):
    if isPem:
        flag = OpenSSL.crypto.FILETYPE_PEM
        buf = cert_data
    else:
        flag = OpenSSL.crypto.FILETYPE_ASN1
        buf = tFormat.hexStr2byte(tFormat.base642hexStr(cert_data, False))
    cert = OpenSSL.crypto.load_certificate(flag, buf)
    pk = {}
    pk_buf = OpenSSL.crypto.dump_publickey(flag, cert.get_pubkey())
    if isPem:
        pk['key'] = pk_buf.decode('utf-8')
    else:
        pk['key'] = pk_buf
    pk['length'] = cert.get_pubkey().bits()
    return pk