# !/usr/bin/python
# -*- coding: utf-8 -*-

import hmac
import argparse
import sm.sm3 as s3

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import openssl
except Exception as e:
    import os
    print(e)
    print('Download cryptograpk')
    os.system('python -m pip install cryptography')

md5 = 0x01
sha1 = 0x02
sha224 = 0x03
sha256 = 0x04
sha384 = 0x05
sha512 = 0x06
sm3 = 0x07
none = 0x08

def get_hash_handle(mode):
    if mode ==md5:
        return hashes.MD5()
    elif mode == sha1:
        return hashes.SHA1()
    elif mode == sha224:
        return hashes.SHA224()
    elif mode == sha256:
        return hashes.SHA256()
    elif mode == sha384:
        return hashes.SHA384()
    elif mode == sha512:
        return hashes.SHA512()

def cal_hash(data, mode):
    backend = openssl.backend
    if mode == sha256:
        m =  hashes.SHA256()
    elif mode == md5:
        m = hashes.MD5()
    elif mode == sha1:
        m = hashes.SHA1()
    elif mode == sha224:
        m = hashes.SHA224()
    elif mode == sha384:
        m = hashes.SHA384()
    elif mode == sha512:
        m = hashes.SHA512()
    elif mode == sm3:
        return s3.sm3_hash(data)
    else:
        raise Exception('no support hash type')
    h = hashes.Hash(m, backend = backend)
    h.update(data)
    return h.finalize()

''' key and data, format must decode utf-8 '''
def cal_hmac(key, data, mode):
    if mode == md5:
        hm = 'MD5'
    elif mode == sha1:
        hm = 'SHA1'
    elif mode == sha224:
        hm = 'SHA224'
    elif mode == sha256:
        hm = 'SHA256'
    elif mode == sha384:
        hm = 'SHA384'
    elif mode == sha512:
        hm = 'SHA512'
    return hmac.new(key, data, hm).digest()

def hmac_verify(key, data, sign, mode):
    digest = cal_hmac(key, data, mode)
    return hmac.compare_digest(digest, sign)

def get_hash_algorithm(s):
    if s == 'MD5':
        return md5
    elif s == 'SHA1':
        return sha1
    elif s == 'SHA224':
        return sha224
    elif s == 'SHA256':
        return sha256
    elif s == 'SHA384':
        return sha384
    elif s == 'SHA512':
        return sha512
    else:
        raise Exception('Invalid hash algorithm')

def hash_args(parser):
    parser.add_argument('--bk', required = False, help = 'Hmac key Buffer')
    parser.add_argument('--fk', required = False, help = 'Hmac key File')
    parser.add_argument('--ht', required = True, help = 'Hash Algorithm : MD5, SHA1, SHA224, SHA256, SHA384, SHA512')
    parser.add_argument('--bd', required = False, help = 'Hash buffer  data' )
    parser.add_argument('--fd', required = False, help = 'Hash file  data' )
    parser.add_argument('--bs', required = False, help = 'Sign buffer data' )
    parser.add_argument('--fs', required = False, help = 'Sign file data' )
    parser.add_argument('--fmt', required = True, help = 'Data format : hex[h], binary[b], base64[b64], urlbase64[ub64] ')
    return parser

HV = 0x10 #hmac verify
HS = 0x11 #hmac signature
CH = 0x12 #cal hash

def hash_func(args):
    import tFormat
    if args.bs or args.fs:
        m = HV
    elif args.bk or args.fk:
        m = HS
    else:
        m =CH
    fmt = tFormat.get_format_type(args.fmt)
    if args.bk:
        key = tFormat.format_data(args.bk, False, fmt,  tFormat.NONE)
    elif args.fk:
        key = tFormat.format_data(args.fk, True, fmt, tFormat.NONE)

    if args.bd:
        data = tFormat.format_data(args.bd, False,fmt,  tFormat.NONE)
    elif args.fd:
        data = tFormat.format_data(args.fd, True, fmt, tFormat.NONE)

    if args.bs:
        sign = tFormat.format_data(args.bs, False,fmt,  tFormat.NONE)
    elif args.fs:
        sign = tFormat.format_data(args.fs, True, fmt, tFormat.NONE)

    fg = get_hash_algorithm(args.ht)
    if m == HV:
        print(hmac_verify(key, data, sign, fg))
    elif m == HS:
        print(tFormat.format_data(cal_hmac(key,data, fg), False, tFormat.NONE, tFormat.HEXSTR))
    elif m == CH:
        print(tFormat.format_data(cal_hash(data, fg), False, tFormat.NONE, tFormat.HEXSTR))
    else:
        raise Exception('Invalid hash method')

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    args = hash_args(parser).parse_args()
    hash_func(args)
