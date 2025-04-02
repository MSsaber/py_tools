# !/usr/bin/python
# -*- coding: utf-8 -*-

import struct
import binascii
import tFormat
import argparse

def buffer_to_int(buf):
    num = struct.unpack('i', buf)
    return num

def parse_tlv(buf, flag = '>h', lens = [2, 2, 0]):
    #print(buf)
    tlv_data_lens = lens
    tlv_data = []
    move_length = 0
    while move_length < len(buf):
        tlv_ele = {}
        for i in range(0,3):
            move = move_length+tlv_data_lens[i]
            if i == 0:
                (tlv_ele['tag'],) = struct.unpack(flag, buf[move_length : move])
                move_length = move
                #print(tlv_ele['tag'])
            elif i == 1:
                (tlv_ele['len'],) = struct.unpack(flag, buf[move_length : move])
                move_length = move
                #rint(tlv_ele['len'])
            elif i == 2:
                data_size = str(tlv_ele['len'])
                data_size += 's'
                (tlv_ele['data'],) = struct.unpack(data_size, buf[move_length : move_length + tlv_ele['len']])
                tlv_ele['data'] = tFormat.byte_to_hexstr(tlv_ele['data'])
                move_length = move_length + tlv_ele['len']
                tlv_data.append(tlv_ele)
    return tlv_data

def tlv_args(parser : argparse.ArgumentParser):
    parser.add_argument('--buffer', required = False, help = 'buffer data')
    parser.add_argument('--file', required = False, help = 'file data')
    parser.add_argument('--fmt', required = True,  help = 'Data format : hex[h], binary[b], base64[b64], urlbase64[ub64]')
    parser.add_argument('--ed', required = True, help = 'Endian : BigEndian[be] , LittleEndian[le]')
    parser.add_argument('--tl', required = False, help = 'tlv tag/len length : 1[1], 2[2], 4[4]')
    return  parser

def tlv_func(args):
    if args.buffer:
        tlv = args.buffer
        flag = False
    elif args.file:
        tlv = args.file
        flag = True
    if args.ed == 'be':
        ed = '>h'
    elif args.ed == 'le':
        ed = '<h'
    lens = [2, 2, 0]
    if args.tl:
        lens = [int(args.tl),int(args.tl),0]
    fmt = tFormat.get_format_type(args.fmt)
    buf = tFormat.format_data(tlv, flag,  fmt, tFormat.NONE)
    for ele in parse_tlv(buf, ed, lens):
        print(ele)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    args = tlv_args(parser).parse_args()
    tlv_func(args)
