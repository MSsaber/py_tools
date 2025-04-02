'''
@File    : main.py
@TIME    : 2025/04/01 13:35:59
@Author  : xiao bai
@Version : 1.0
@Contact : bai.xiao@auto-mems.com
@Bref here
'''
#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import argparse
import tHash
import tFormat
import tTlvParser

def build_arg_parser():
    parser = argparse.ArgumentParser()
    #parser.add_argument("--method", "-m", action="store_true", help="全局详细模式")
    subparsers = parser.add_subparsers(dest="command", help="子命令帮助")
    # Method hash
    parser_hash = subparsers.add_parser("hash", help="hash计算")
    tHash.hash_args(parser_hash)
    # Method tlv
    parser_tlv = subparsers.add_parser("tlv", help="tlv解析")
    tTlvParser.tlv_args(parser_tlv)
    # Method crypto
    # Method format
    parser_format = subparsers.add_parser("format", help="数据格式转换")
    tFormat.format_args(parser_format)
    return parser.parse_args()

def select_func(args):
    if args.command == 'crypto':
        import tCrypto
        tCrypto.crypto_func()
    elif args.command == 'hash':
        tHash.hash_func(args)
    elif args.command == 'format':
        tFormat.format_func(args)
    elif args.command == 'tlv':
        tTlvParser.tlv_func(args)

if __name__ == '__main__':
    args = build_arg_parser()
    select_func(args)