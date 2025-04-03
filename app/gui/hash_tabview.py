'''
@File    : hash_tabview.py
@TIME    : 2025/04/03 12:59:03
@Author  : xiao bai
@Version : 1.0
@Contact : bai.xiao@auto-mems.com
@Bref here
'''
#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import sys
import subprocess
from PyQt6.QtWidgets import (QWidget,
                             QGridLayout,
                             QComboBox,
                             QTextEdit,
                             QLineEdit,
                             QHBoxLayout,
                             QVBoxLayout,
                             QMessageBox,
                             QPushButton)

class HashTabView(QWidget):
    format_list = ['hexstring', 'base64', 'urlbase64', 'binary']
    format_dict = {
        'hexstring': 'h',
        'base64': 'b64',
        'urlbase64': 'ub64',
        'binary': 'b'
    }
    hash_list = ['SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512', 'MD5', 'SM3']
    operation_list = ['签名', '验签', '摘要计算']
    operation_dict = {
        '签名' : 'sign',
        '验签' : 'verify',
        '摘要计算' : 'cal'
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_setup_ui()

    def _init_setup_ui(self):
        grid_layout = QGridLayout(self)
        self.setLayout(grid_layout)

        vbox_layout = QVBoxLayout()
        grid_layout.addLayout(vbox_layout, 0, 0, 1, 2)

        hbox_layout1 = QHBoxLayout()
        vbox_layout.addLayout(hbox_layout1)

        self.hash_operation = QComboBox(self)
        self.hash_operation.setObjectName("hash_operation")
        self.hash_operation.setPlaceholderText("Hash操作")
        self.hash_operation.addItems(HashTabView.operation_list)
        hbox_layout1.addWidget(self.hash_operation)

        self.hash_list = QComboBox(self)
        self.hash_list.setObjectName("hash_list")
        self.hash_list.setPlaceholderText("Hash算法")
        self.hash_list.addItems(HashTabView.hash_list)
        hbox_layout1.addWidget(self.hash_list)

        self.fmt = QComboBox(self)
        self.fmt.setObjectName("fmt")
        self.fmt.setPlaceholderText("数据格式")
        self.fmt.addItems(HashTabView.format_list)
        hbox_layout1.addWidget(self.fmt)

        self.run = QPushButton(self)
        self.run.setObjectName("run")
        self.run.setText("运行")
        self.run.clicked.connect(self.run_hash)
        hbox_layout1.addWidget(self.run)

        hbox_layout2 = QHBoxLayout()
        vbox_layout.addLayout(hbox_layout2)

        self.key_file = QLineEdit(self)
        self.key_file.setObjectName("key_file")
        self.key_file.setPlaceholderText("密钥文件(格式同数据格式)")
        hbox_layout2.addWidget(self.key_file, 1)

        self.key = QLineEdit(self)
        self.key.setObjectName("key")
        self.key.setPlaceholderText("密钥(格式同数据格式)")
        hbox_layout2.addWidget(self.key, 2)

        hbox_layout3 = QHBoxLayout()
        vbox_layout.addLayout(hbox_layout3)

        self.sign_file = QLineEdit(self)
        self.sign_file.setObjectName("sign_file")
        self.sign_file.setPlaceholderText("签名文件(格式同数据格式)")
        hbox_layout3.addWidget(self.sign_file, 1)

        self.sign = QLineEdit(self)
        self.sign.setObjectName("sign")
        self.sign.setPlaceholderText("签名(格式同数据格式)")
        hbox_layout3.addWidget(self.sign, 2)

        vbox_layout_data = QVBoxLayout()
        grid_layout.addLayout(vbox_layout_data, 1, 0, 1, 1)
        self.data_file = QLineEdit(self)
        self.data_file.setObjectName("data_file")
        self.data_file.setPlaceholderText("数据文件(格式同数据格式)")
        vbox_layout_data.addWidget(self.data_file, 1)

        self.input = QTextEdit(self)
        self.input.setObjectName("input")
        self.input.setPlaceholderText("输入")
        vbox_layout_data.addWidget(self.input, 4)

        self.output = QTextEdit(self)
        self.output.setObjectName("output")
        self.output.setPlaceholderText("输出")
        grid_layout.addWidget(self.output, 1, 1, 1, 1)

    def run_hash(self):
        op = self.hash_operation.currentText()
        if len(op) == 0:
            QMessageBox.warning(self, "Warning", "请选择操作")
            return
        hash_algorithm = self.hash_list.currentText()
        fmt = self.fmt.currentText()
        key = self.key.text()
        key_file = self.key_file.text()
        sign = self.sign.text()
        sign_file = self.sign_file.text()
        input_data = self.input.toPlainText()
        input_file = self.data_file.text()
        operation = HashTabView.operation_dict[op]
        print(f"operation: {operation}, hash_algorithm: {hash_algorithm}, fmt: {fmt}, key: {key}, key_file: {key_file}, sign: {sign}, sign_file: {sign_file}, input_data: {input_data}, input_file: {input_file}")
        if operation == 'sign' or operation == 'verify':
            if len(key) == 0 and len(key_file) == 0:
                QMessageBox.warning(self, "Warning", "请输入密钥或密钥文件")
                return
            if len(key) > 0 and len(key_file) > 0:
                QMessageBox.warning(self, "Warning", "只能输入密钥或密钥文件")
                return
        if operation == 'verify':
            if len(sign) == 0 and len(sign_file) == 0:
                QMessageBox.warning(self, "Warning", "请输入签名或签名文件")
                return
            if len(sign) > 0 and len(sign_file) > 0:
                QMessageBox.warning(self, "Warning", "只能输入签名或签名文件")
                return
        if len(input_data) == 0 and len(input_file) == 0:
            QMessageBox.warning(self, "Warning", "请输入数据或数据文件")
            return
        if len(input_data) > 0 and len(input_file) > 0:
            QMessageBox.warning(self, "Warning", "只能输入数据或数据文件")
            return
        if len(fmt) == 0:
            QMessageBox.warning(self, "Warning", "请选择数据格式")
            return
        if len(hash_algorithm) == 0:
            QMessageBox.warning(self, "Warning", "请选择Hash算法")
            return
        python = 'python' if sys.platform.startswith('win') else 'python3'
        cmd = [
            python,
            '../command.py',
            'hash',
            operation,
            '--fmt',
            HashTabView.format_dict[fmt],
            '--ht',
            hash_algorithm,
        ]
        if len(input_data) > 0:
            cmd.append('--bd')
            cmd.append(input_data)
        if len(input_file) > 0:
            cmd.append('--fd')
            cmd.append(input_file)
        if len(key) > 0:
            cmd.append('--bk')
        if len(key_file) > 0:
            cmd.append('--fk')
            cmd.append(key_file)
        if len(sign) > 0:
            cmd.append('--bs')
        if len(sign_file) > 0:
            cmd.append('--fs')
            cmd.append(sign_file)
        output_data = subprocess.check_output(cmd).decode("utf-8").strip()
        self.output.setPlainText(output_data)

