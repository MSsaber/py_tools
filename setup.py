'''
@File    : setup.py
@TIME    : 2025/04/02 16:56:28
@Author  : xiao bai
@Version : 1.0
@Contact : bai.xiao@auto-mems.com
@Bref here
'''
#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import sys
import subprocess

cmd = ['pyinstaller', '-n', '安全算法工具',
       '--hidden-import', 'PyQt6.QtCore', '--hidden-import', 'PyQt6.QtGui',
       '-F', './app/main.py', '--add-data', './app/gui/*.py;gui']
print(subprocess.check_output(cmd).decode("utf-8").strip())