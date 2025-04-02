# !/usr/bin/python
# -*- coding: utf-8 -*-
# generate key : aes, hmac, rsa, ecc, sm2, dh, ecdh

try:
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, dh
    from cryptography.hazmat.primitives.ciphers import algorithms
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
except Exception as e:
    import os
    print(e)
    print('Download cryptograpk')
    os.system('python -m pip install cryptography')

import os
import tFormat
import sm.sm2 as s2
import sm.func

def generate_aes_key(len):
    if len != 16 and len != 24 and len != 32:
        raise Exception('Invalid key length')
    return os.urandom(len)

def generate_hmac_key(len):
    return os.urandom(len)

def generate_iv(len):
    return os.urandom(len)

def generate_rsa_prikey(len, e = 65537):
    try:
        prik = rsa.generate_private_key(public_exponent = e,
                                        key_size = len,
                                        backend = default_backend())
        return prik.private_bytes(encoding = serialization.Encoding.PEM,
                                  format = serialization.PrivateFormat.PKCS8,
                                  encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword'))
    except Exception as e:
        print(e)
        quit()

def generate_ec_prikey(curve):
    try:
        prik = ec.generate_private_key(curve = curve, backend = default_backend())
        return prik.private_bytes(encoding = serialization.Encoding.PEM,
                                  format = serialization.PrivateFormat.PKCS8,
                                  encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword'))
    except Exception as e:
        raise e

def generate_sm2_prikey():
    return generate_ec_prikey(ec.SECP256R1)

print(generate_rsa_prikey(len = 4096))