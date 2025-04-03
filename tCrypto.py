# !/usr/bin/python
# -*- coding: utf-8 -*-
import argparse

try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec, utils
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography import x509
except Exception as e:
    import os
    print(e)
    print('Download cryptograpk')
    os.system('python -m pip install cryptography')

try:
    import tFormat
    import tHash
    import sm.sm2 as s2
    from sm import func
except Exception as e:
    print(e)

PEM = 0x01
DER = 0x02
NONE = 0x03

RSA = 0x01
ECC = 0x02
SM2 = 0x03

OP_SIGN = "sign"
OP_VERIFY = "verify"
OP_PARSE_CERT = "parse"

_KEY_TYPES: dict[str, str] = {
    "prime192v1": "prime192v1",
    "prime192v1": "prime192v1",
    "secp192r1": "secp192r1",
    "secp224r1": "secp224r1",
    "secp256r1": "secp256r1",
    "secp384r1": "secp384r1",
    "secp521r1": "secp521r1",
    "secp256k1": "secp256k1",
    "sect163k1": "sect163k1",
    "sect233k1": "sect233k1",
    "sect283k1": "sect283k1",
    "sect409k1": "sect409k1",
    "sect571k1": "sect571k1",
    "sect163r2": "sect163r2",
    "sect233r1": "sect233r1",
    "sect283r1": "sect283r1",
    "sect409r1": "sect409r1",
    "sect571r1": "sect571r1",
    "brainpoolP256r1": "brainpoolP256r1",
    "brainpoolP384r1": "brainpoolP384r1",
    "brainpoolP512r1": "brainpoolP512r1",
    "rsa-1024": "1024",
    "rsa-2048": "2048",
    "rsa-3072": "3072",
    "rsa-4096": "4096",
}

def parse_x509(cert_data, isPem):
    try:
        if isPem:
            cert = cert_data.encode('ascii')
            crt = x509.load_pem_x509_certificate(data = cert, backend = default_backend())
        else:
            crt = x509.load_der_x509_certificate(cert_data, default_backend())
        print('')
        print('证书版本 : ' + str(crt.version))
        print('证书序列号 : ' + str(crt.serial_number))
        print('证书颁发时间 : ' + str(crt.not_valid_before_utc))
        print('证书截止时间 : ' + str(crt.not_valid_after_utc))
        print('证书签名的hash类型 : ' + str(crt.signature_hash_algorithm.name))
        print('证书签名算法类型oid : ' + str(crt.signature_algorithm_oid))
        print('证书子项 : ')
        for sub in crt.subject.rdns:
            print('\t' + str(sub))
        print('证书签名 : ' + tFormat.byte_to_hexstr(crt.signature))
        print('公钥 : ' + str(crt.public_key().public_bytes(serialization.Encoding.PEM,
                                                            serialization.PublicFormat.SubjectPublicKeyInfo)))
        print('指纹 : ' + tFormat.byte_to_hexstr(crt.fingerprint(hashes.SHA256())))
        print('证书扩展项 : ' + str(crt.extensions))
        print('证书发行方 : ')
        for sub in crt.issuer.rdns:
            print('\t' + str(sub))
        print("证书链  : " + str(crt.tbs_certificate_bytes))
        print("证书链[前] : " + str(crt.tbs_precertificate_bytes))
    except Exception as e:
        print(e)

def get_pk_from_x509(cert_data, isPem, pkFmt):
    if isPem:
        cert = cert_data.encode('ascii')
        crt = x509.load_pem_x509_certificate(data = cert, backend = default_backend())
    else:
        crt = x509.load_der_x509_certificate(cert_data, default_backend())
    pk = {}
    if pkFmt == PEM:
        flag = serialization.Encoding.PEM
    elif pkFmt == DER:
        flag = serialization.Encoding.DER

    pk['key'] = crt.public_key().public_bytes(flag, serialization.PublicFormat.SubjectPublicKeyInfo)
    pk['length'] = crt.public_key().key_size
    return pk

def verify_by_rsa(key, data, sign, mode, isPem):
    if isPem:
        pk = serialization.load_pem_public_key(key, backend = default_backend())
    else:
        pk = serialization.load_der_public_key(key, backend = default_backend())
    try:
        print('digest :' + tFormat.byte_to_hexstr(tHash.cal_hash(data, mode)))
        print('sign :' + tFormat.byte_to_hexstr(sign))
        pk.verify(sign, data, padding.PKCS1v15(), tHash.get_hash_handle(mode))
        print('verify success')
    except Exception as e:
        print('verify failed')

def sign_by_rsa(key, data, mode, isPem):
    if isPem:
        prik = serialization.load_pem_private_key(key, password=None, backend = default_backend())
    else:
        prik = serialization.load_der_private_key(key, password=None, backend = default_backend())
    return prik.sign(data, padding.PKCS1v15(), tHash.get_hash_handle(mode))

def verify_by_ecdsa(key, data, sign, mode, isPem):
    if isPem:
        pk = serialization.load_pem_public_key(key, backend = default_backend())
    else:
        pk = serialization.load_der_public_key(key, backend = default_backend())
    try:
        print(tFormat.byte_to_hexstr(pk.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )))
        print("sign :" + tFormat.byte_to_hexstr(sign))
        print("data :" + tFormat.byte_to_hexstr(data))
        pk.verify(build_dss_signature(sign), data, ec.ECDSA(tHash.get_hash_handle(mode)))
        print('verify success')
    except Exception as e:
        print('verify failed')

def sign_by_ecdsa(key, data, mode, isPem):
    if isPem:
        prik = serialization.load_pem_private_key(key, password = None, backend = default_backend())
    else:
        prik = serialization.load_der_private_key(key, password = None, backend = default_backend())
    return prik.sign(data, ec.ECDSA(tHash.get_hash_handle(mode)))

def verify_by_sm2(key, data, sign, mode):
    if mode != tHash.sm3:
        print("sm2 just support sm3")
    verifier = s2.CryptSM2(private_key = None, public_key = key)
    if verifier.verify(sign, tHash.cal_hash(data, tHash.sm3)):
        print('verify success')
    else:
        print('verify failed')

def sign_by_sm2(key, data, mode):
    if mode != tHash.sm3:
        print("sm2 just support sm3")
    sign = s2.CryptSM2(private_key = key, public_key = None)
    k = func.random_hex(sign.para_len)
    return sign.sign(tHash.cal_hash(data, tHash.sm3), k)

def build_dss_signature(data):
    if int(len(data)) % 2 != 0:
        raise ValueError("Invalid signature length")

    r_bytes = data[0:int(len(data)/2)]
    s_bytes = data[int(len(data)/2):int(len(data))]

    r = int.from_bytes(r_bytes, "big")
    s = int.from_bytes(s_bytes, "big")

    return utils.encode_dss_signature(r, s)

def build_pem_key(key_type : str, key : bytes, fmt, isPri : bool):
    data = tFormat.format_data(key, False, fmt, tFormat.BASE64).decode('utf-8')
    if isPri:
        return ('-----BEGIN ENCRYPTED PRIVATE KEY-----\n' + data + '\n-----END ENCRYPTED PRIVATE KEY-----').encode()
    else:
        if int(len(key)) % 2 == 0:
            key = bytearray(b'\x04') + bytearray(key)
            key = bytes(key)
        # 分解 X 和 Y 坐标
        prefix = key[0]
        if prefix != 0x04:
            raise ValueError("非压缩公钥应以 0x04 开头")

        x_bytes = key[1:int((len(key)-1)/2 + 1)]
        y_bytes = key[int((len(key)-1)/2 + 1):int(len(key))]
        x = int.from_bytes(x_bytes, "big")
        y = int.from_bytes(y_bytes, "big")
        print("x : " + str(x))
        print("y : " + str(y))

        curve = ec._CURVE_TYPES[key_type]
        public_numbers = ec.EllipticCurvePublicNumbers(x, y, curve)
        public_key = public_numbers.public_key()

        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return pem

def crypto_args(parser : argparse.ArgumentParser):
    subparsers = parser.add_subparsers(dest="operation", required=True, help = 'Operation : sign, verify, parse')
    #parse cert
    parser_cert = subparsers.add_parser('parse', help = 'parse cert')
    parser_cert.add_argument('--fc', required = False, help = "cert file")
    parser_cert.add_argument('--bc', required = False, help = "cert buffer")
    parser_cert.add_argument('--cf', required = True, help = 'cert format : PEM, DER')
    #verify
    parser_verify = subparsers.add_parser('verify', help = 'verify data by key or cert')
    parser_verify.add_argument('--alg', required = True, help = 'Algorithm : rsa, ec, sm2')
    parser_verify.add_argument('--kt', required=True, help='key type : ' + str(_KEY_TYPES.keys()))
    parser_verify.add_argument('--kf', required = True, help = 'key format : PEM, DER, hex[h], binary[b], base64[b64], urlbase64[ub64]')
    parser_verify.add_argument('--fk', required = False, help = "key file")
    parser_verify.add_argument('--bk', required = False, help = "key buffer")
    parser_verify.add_argument('--cf', required = False, help = 'cert format : PEM, DER')
    parser_verify.add_argument('--fc', required = False, help = "cert file")
    parser_verify.add_argument('--bc', required = False, help = "cert buffer")
    parser_verify.add_argument('--sign', required = True, help = 'sign data')
    parser_verify.add_argument('--data', required = True, help = 'src data')
    parser_verify.add_argument('--ht', required = True, help = 'Hash Algorithm : MD5, SHA1, SHA224, SHA256, SHA384, SHA512, SM3')
    parser_verify.add_argument('--fmt', required = True, help = 'Data format : hex[h], binary[b], base64[b64], urlbase64[ub64]')
    #signature
    parser_sign = subparsers.add_parser('sign', help = 'signature data by key')
    parser_sign.add_argument('--alg', required = True, help = 'Algorithm : rsa, ec, sm2')
    parser_sign.add_argument('--kt', required=True, help='key type : ' + str(_KEY_TYPES.keys()))
    parser_sign.add_argument('--kf', required = True, help = 'key format : PEM, DER, HEXSTR[h], BASE64[b64], BINARY[b]')
    parser_sign.add_argument('--fk', required = False, help = "key file")
    parser_sign.add_argument('--bk', required = False, help = "key buffer")
    parser_sign.add_argument('--data', required = True, help = 'src data')
    parser_sign.add_argument('--ht', required = True, help = 'Hash Algorithm : MD5, SHA1, SHA224, SHA256, SHA384, SHA512, SM3')
    parser_sign.add_argument('--fmt', required = True, help = 'Data format : hex[h], binary[b], base64[b64], urlbase64[ub64]')
    return parser

def crypto_func(args):
    def std_key_data(args):
        fmt = tFormat.get_format_type(args.fmt)
        if args.fk:
            key_data = tFormat.format_data(args.fk, True, fmt, tFormat.NONE)
        elif args.bk:
            key_data = tFormat.format_data(args.bk, False, fmt, tFormat.NONE)
        return key_data
    def crypto_parse(args):
        if args.fc:
            cert = tFormat.format_data(args.fc, True, tFormat.NONE, tFormat.NONE)
        elif args.bc:
            cert = tFormat.format_data(args.bc, False, tFormat.NONE, tFormat.NONE)
        if args.cf == "PEM":
            is_pem = True
        elif args.cf == "DER":
            is_pem = False
        if cert is None:
            raise Exception("No cert input")
        parse_x509(cert, is_pem)
    def crypto_sign(args):
        key=None
        is_pem = True
        fmt = tFormat.get_format_type(args.fmt)
        hash_mode = tHash.get_hash_algorithm(args.ht)
        data = tFormat.format_data(args.data, False, fmt, tFormat.NONE)
        if args.kf == 'PEM' or args.kf == 'DER':
            if args.kf == 'PEM':
                is_pem = True
            elif args.kf == 'DER':
                is_pem = False
            key = std_key_data(args)
        else:
            is_pem = True
            key = build_pem_key(std_key_data(args), tFormat.get_format_type(args.kf), True)
        if args.alg == 'rsa':
            sign_by_rsa(key, data, hash_mode, is_pem)
        elif args.alg == 'ec':
            sign_by_ecdsa(key, data, hash_mode, is_pem)
        elif args.alg == 'sm2':
            pass
    def crypto_verify(args):
        cert=None
        key=None
        is_pem = True
        fmt = tFormat.get_format_type(args.fmt)
        hash_mode = tHash.get_hash_algorithm(args.ht)
        sign = tFormat.format_data(args.sign, False, fmt, tFormat.NONE)
        data = tFormat.format_data(args.data, False, fmt, tFormat.NONE)
        if args.fc:
            cert = tFormat.format_data(args.fc, True, fmt, tFormat.NONE)
        elif args.bc:
            cert = tFormat.format_data(args.bc, False, fmt, tFormat.NONE)
        if cert is not None:
            if args.kf != "PEM" and args.kf != "DER":
                raise Exception("cert format just support PEM or DER")
            key = get_pk_from_x509(cert, True if args.cf == 'PEM'  else False, PEM if args.kf == 'PEM' else DER)
        else:
            if args.kf == 'PEM':
                is_pem = True
                key_data = std_key_data(args)
            elif args.kf == 'DER':
                is_pem = False
                key_data = std_key_data(args)
            else:
                is_pem = True
                key_data = std_key_data(args)
                key_data = build_pem_key(args.kt, key_data, tFormat.get_format_type('n'), False)
            key = key_data
        if args.alg == 'rsa':
            verify_by_rsa(key, data, sign, hash_mode, is_pem)
        elif args.alg == 'ec':
            verify_by_ecdsa(key, data, sign, hash_mode, is_pem)
        elif args.alg == 'sm2':
            pass

    if args.operation == 'sign':
        crypto_sign(args)
    elif args.operation == 'verify':
        crypto_verify(args)
    elif args.operation == 'parse':
        crypto_parse(args)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    args = crypto_args(parser).parse_args()
    crypto_func(args)