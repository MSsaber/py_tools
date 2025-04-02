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
import tCrypto

def build_arg_parser():
    parser = argparse.ArgumentParser()
    #parser.add_argument("--method", "-m", action="store_true", help="全局详细模式")
    subparsers = parser.add_subparsers(dest="command", help="List of supported commands")
    # Method hash
    parser_hash = subparsers.add_parser("hash", help="Hash algorithm,\r\n\
                                                    supported hash mode:\n\
                                                        1. MD5\n\
                                                        2. SHA1\n\
                                                        3. SHA224\n\
                                                        4. SHA256\n\
                                                        5. SHA384\n\
                                                        6. SHA512\n\
                                                        7. SM3\n\
                                                        8. HMAC\n"
                                        )
    tHash.hash_args(parser_hash)
    # Method tlv
    parser_tlv = subparsers.add_parser("tlv", help="Tlv data parser\r\n")
    tTlvParser.tlv_args(parser_tlv)
    # Method crypto
    parser_crypto = subparsers.add_parser("crypto", help="Asymmetric algorithm and certificates\r\n")
    tCrypto.crypto_args(parser_crypto)
    # Method format
    parser_format = subparsers.add_parser("format", help="Data format\r\n")
    tFormat.format_args(parser_format)
    return parser.parse_args()

def select_func(args):
    if args.command == 'crypto':
        tCrypto.crypto_func(args)
    elif args.command == 'hash':
        tHash.hash_func(args)
    elif args.command == 'format':
        tFormat.format_func(args)
    elif args.command == 'tlv':
        tTlvParser.tlv_func(args)

if __name__ == '__main__':
    args = build_arg_parser()
    select_func(args)