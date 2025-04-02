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