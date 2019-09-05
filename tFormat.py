# !/usr/bin/python
# -*- coding: utf-8 -*-

import base64
import binascii

NONE = 0x00
HEXSTR = 0x01
BINARYSTR = 0x02
BASE64 = 0x03
URLB64 = 0x04

def hexstr_to_byte(hs):
    return bytes.fromhex(hs)

def byte_to_hexstr(buf):
    return ''.join(['%02x' % b for b in buf])

def binarystr_to_byte(b):
    return int(b,2).to_bytes(len(s)//8, byteorder='big')

def hexstr_to_base64(hs, isUrl):
    buf = hexstr_to_byte(hs)
    if isUrl:
        return base64.urlsafe_b64encode(buf)
    else:
        return base64.b64encode(buf)

def base64_to_hexstr(b64_str, isUrl):
    if isUrl:
        buf = base64.urlsafe_b64decode(b64_str)
    else:
        buf = base64.b64decode(b64_str)
    return byte_to_hexstr(buf)

def get_format_type(s):
    if s == 'h':
        return HEXSTR
    elif s == 'b':
        return BINARYSTR
    elif s == 'b64':
        return BASE64
    elif s == 'ub64':
        return URLB64
    elif s == 'n':
        return NONE
    else:
        raise Exception('Invalid format type')

def format_data(buf, isFile, sf, tf):
    if isFile:
        f = open(buf)
        data = f.read()
        close(f)
    else:
        data = buf

    if sf == NONE:
        s = data
    elif sf == HEXSTR:
        s = hexstr_to_byte(data)
    elif sf == BINARYSTR:
        s = binarystr_to_byte(data)
    elif sf == BASE64:
        s = base64.b64decode(data)
    elif sf == URLB64:
        s = base64.urlsafe_b64decode(data)

    if tf == NONE:
        return s
    elif tf == HEXSTR:
        return byte_to_hexstr(s)
    elif tf == BINARYSTR:
        return s
    elif tf == BASE64:
        return base64.b64encode(s)
    elif tf == URLB64:
        return base64.urlsafe_b64encode(s)

def format_args():
    import argparse
    parse = argparse.ArgumentParser()
    parse.add_argument('--buffer', required = False, help = 'data buffer')
    parse.add_argument('--file', required = False, help = 'file anem')
    parse.add_argument('--sf',required = True, help = 'source data format : hex[h], binary[b], base64[b64], urlbase64[ub64]')
    parse.add_argument('--tf',required = True, help = 'target data format : hex[h], binary[b], base64[b64], urlbase64[ub64')
    parse.add_argument('--out',required = False, help = 'out file name')
    return parse.parse_args()

def format_func():
    args = format_args()
    if args.buffer:
        source = args.buffer
    else:
        f = open(args.file)
        source = f.read()
        close(f)

    flag = get_format_type(args.tf)
    sflag = get_format_type(args.sf)

    res = format_data(source, False, sflag, flag)
    print(res)
    if args.out:
        out = open(args.out, 'w')
        out.write(res)

if __name__ == '__main__':
    format_func()