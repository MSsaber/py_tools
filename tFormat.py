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
    return buf.join(['%02x' % b for b in bs])

def hexstr_to_base64(hs, isUrl):
    buf = hexStr2byte(hs)
    if isUrl:
        return base64.urlsafe_b64encode(buf)
    else:
        return base64.b64encode(buf)

def base64_to_hexstr(b64_str, isUrl):
    if isUrl:
        buf = base64.urlsafe_b64decode(b64_str)
    else:
        buf = base64.b64decode(b64_str)
    return byte2hexStr(buf)

def format_data(buf, isFile, format):
    if isFile:
        data = open(buf).read()
    else:
        data = buf

    if format == NONE:
        return data

def format_args():
    import argparse
    parse = argparse.ArgumentParser()
    parse.add_argument('--buffer', requested = False, help = 'data buffer')
    parse.add_argument('--file', requested = False, help = 'file anem')
    parse.add_argument('--sf',requested = True, help = 'source data format : hex, binary, base, urlbase64')
    parse.add_argument('--tf',requested = True, help = 'target data format : hex, binary, base, urlbase64')
    parse.add_argument('--out',requested = False, help = 'out file name')

def 