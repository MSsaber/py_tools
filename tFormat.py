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

def format_data(buf, isFile, sf, tf):
    if isFile:
        data = open(buf).read()
    else:
        data = buf

    if sf == NONE:
        s = data
    elif tf == HEXSTR:
        s = hexstr_to_byte(data)
    elif tf == BINARYSTR：
        s = data
    elif tf == BASE64:
        s = base64.b64decode(data)
    elif tf == URLB64:
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
    parse.add_argument('--buffer', requested = False, help = 'data buffer')
    parse.add_argument('--file', requested = False, help = 'file anem')
    parse.add_argument('--sf',requested = True, help = 'source data format : hex[h], binary[b], base64[b64], urlbase64[ub64]')
    parse.add_argument('--tf',requested = True, help = 'target data format : hex[h], binary[b], base64[b64], urlbase64[ub64')
    parse.add_argument('--out',requested = False, help = 'out file name')

def format_func():
    args = format_args()
    if args.buffer:
        source = args.buffer
    else:
        source = open(args.file).read()

    if args.tf == 'h':
        flag = HEXSTR
    elif args.tf == 'b':
        flag = BINARYSTR
    elif args.tf == 'b64':
        flag = BASE64
    elif args.tf == 'ub64':
        flag = URLB64
    elif args.tf == 'n':
        flag = NONE

    if args.sf != 'h' and args.sf != 'b':
        if args.sf == 'b64':
            buf = base64.b64decode(source)
        elif args.sf == 'ub64':
            buf = base64.urlsafe_b64decode(source)
        return format_data(buf, False, flag)

    if args.sf == 'n':
        return format_data(source, False, flag)
    if args.sf == 'h':
        buf = hexstr_to_byte(source)
        
        return format()