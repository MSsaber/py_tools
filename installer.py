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
import os
import shutil
import zipfile
from pathlib import Path
import subprocess
PROJECT_NAME = "安全算法工具"
RESOURCE_DIRS = ['tCipher.py', 'tCrypto.py', 'command.py', 'tFormat.py', 'tHash.py', 'tTlvParser.py', 'sm']
EXCLUDE_FILES = ["*.log"]    # 需要排除的文件列表

def install_exe():
       python = 'python' if sys.platform.startswith('win') else 'python3'
       cmd = [python, '-m', 'PyInstaller', '-n', '安全算法工具',
              '--hidden-import', 'PyQt6.QtCore', '--hidden-import', 'PyQt6.QtGui',
              '-F', './app/main.py', '--add-data', './app/gui/*.py;gui']
       print(subprocess.check_output(cmd).decode("utf-8").strip())

def package_app():
    # 获取当前工作目录
    base_dir = Path(__file__).parent
    dist_dir = base_dir / "dist"
    build_dir = base_dir / "build"

    # 创建临时打包目录
    package_dir = base_dir / f"{PROJECT_NAME}"
    package_dir.mkdir(exist_ok=True)

    package_bin = base_dir / f"{PROJECT_NAME}" / "bin"
    package_bin.mkdir(exist_ok=True)

    # 步骤1: 复制exe文件
    exe_file = dist_dir / f"{PROJECT_NAME}.exe"
    if exe_file.exists():
        shutil.copy(exe_file, package_bin)
        print(f"✅ EXE 文件已复制到 {package_bin}")
    else:
        raise FileNotFoundError("EXE文件不存在，请先执行PyInstaller打包")

    # 步骤2: 复制资源文件
    for resource in RESOURCE_DIRS:
        src = base_dir / resource
        if src.exists():
            dest = package_dir / resource
            if src.is_dir():
                shutil.copytree(src, dest, dirs_exist_ok=True)
            else:
                shutil.copy(src, dest)
            print(f"✅ 资源 {resource} 已复制")

    # 步骤3: 创建ZIP压缩包
    zip_path = base_dir / f"{PROJECT_NAME}.zip"
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(package_dir):
            for file in files:
                if file in EXCLUDE_FILES:
                    continue
                file_path = Path(root) / file
                arcname = file_path.relative_to(package_dir.parent)
                zipf.write(file_path, arcname)

    print(f"🎉 打包完成！ZIP文件路径：{zip_path}")

    # 步骤4: 清理临时文件（可选）
    shutil.rmtree(package_dir)
    shutil.rmtree(build_dir)
    (base_dir / f"{PROJECT_NAME}.spec").unlink(missing_ok=True)

if __name__ == '__main__':
       install_exe()
       package_app()