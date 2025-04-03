'''
@File    : test.py
@TIME    : 2025/04/02 10:54:25
@Author  : xiao bai
@Version : 1.0
@Contact : bai.xiao@auto-mems.com
@Bref here
'''
#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import subprocess

print("test hash command")

cmd = ["python",
       "./command.py",
       "hash",
       "cal",
       "--bd",
       "1FA400441F93000800000195CB2B89A31F940010AD1FB78466D94CC2979E5BCC64B06E5C1F950020AACFB58DEDA01354A6D9C5820254AE3F738D0ED40E75002623B45A89F3043541",
       "--fmt",
       "h",
       "--ht",
       "SM3"]
print(subprocess.check_output(cmd).decode("utf-8").strip())

print("test tlv parser command")

cmd = ["python",
       "./command.py",
       "tlv",
       "--buffer",
       "1F93000800000195CB2B89A31F940010AD1FB78466D94CC2979E5BCC64B06E5C1F950020AACFB58DEDA01354A6D9C5820254AE3F738D0ED40E75002623B45A89F3043541",
       "--fmt",
       "h",
       "--ed",
       "be"]
print(subprocess.check_output(cmd).decode("utf-8").strip())

print("test crypto command")
print("verify ...")
cmd = ["python",
       "./command.py",
       "crypto",
       "verify",
       "--alg",
       "ec",
       "--kf",
       "h",
       "--bk",
       "6D46BADC929A0CFDD95032C64B6058B55CD4C31B2348076E5662D0E93F90B7B3399C382E066FF8123F23E88D7453F89AD83C5E821DDE6D9C2658186B2D18AF7D",
       "--sign",
       "C1FF7A5D18E41CC4111631C42BF880DE6F48250186ABA876D51BCF9137E1FF60BD2CF35CA419BCFEB67253C936581B1491F812C854089C004DD2BC9E34081B67",
       "--data",
       "1FA400441F93000800000195EA8A5C4D1F940010D6EA13F39BE044D38B01E3581DDBC8451F950020131F8EA04EACB9FFCEC4220E17C9E948F2E3EC2AD11908531A8925F3DE695A491F4200409274C7B938D59FD8D682E58009B5C8B3A0622C90C059BD36F617B3719AAAC804768544C716DAA3E85A8F172321FA121DB88B94B67FFE9FB411C0E5125303DFD9",
       "--fmt",
       "h",
       "--ht",
       "SHA256"
       ]
print(subprocess.check_output(cmd).decode())
