'''
@File    : crypto_tabview.py
@TIME    : 2025/04/03 13:30:26
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

class CryptoTabView(QWidget):
    format_list = ['hexstring', 'base64', 'urlbase64', 'binary']
    format_dict = {
        'hexstring': 'h',
        'base64': 'b64',
        'urlbase64': 'ub64',
        'binary': 'b'
    }
    hash_list = ['SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512', 'MD5', 'SM3']
    operation_list = ['签名', '验签', '解析证书']
    operation_dict = {
        '签名' : 'sign',
        '验签' : 'verify',
        '解析证书' : 'parse'
    }
    algorithm_list = ['RSA', 'ECDSA', 'SM2']
    algorithm_dict = {
        'RSA': 'rsa',
        'ECDSA': 'ec',
        'SM2': 'sm2'
    }
    key_list = [
        "prime192v1",
        "prime256v1",
        "secp192r1",
        "secp224r1",
        "secp256r1",
        "secp384r1",
        "secp521r1",
        "secp256k1",
        "sect163k1",
        "sect233k1",
        "sect283k1",
        "sect409k1",
        "sect571k1",
        "sect163r2",
        "sect233r1",
        "sect283r1",
        "sect409r1",
        "sect571r1",
        "brainpoolP256r1",
        "brainpoolP384r1",
        "brainpoolP512r1",
        'rsa-1024',
        'rsa-2048',
        'rsa-3072',
        'rsa-4096',
    ]
    cert_format = [ 'PEM', "DER", 'hexstring', 'base64', 'urlbase64', 'binary']
    cert_dict = {
        'PEM' : 'PEM',
        'DER' : 'DER',
        'hexstring' : 'h',
        'binary' : 'b',
        'base64' : 'b64',
        'urlbase64' : 'ub64',
    }
    key_fmt_list = cert_format
    key_fmt_dict = cert_dict
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

        self.operation = QComboBox(self)
        self.operation.setObjectName("operation")
        self.operation.setPlaceholderText("操作")
        self.operation.addItems(CryptoTabView.operation_list)
        hbox_layout1.addWidget(self.operation)

        self.alg = QComboBox(self)
        self.alg.setObjectName("alg")
        self.alg.setPlaceholderText("密钥算法")
        self.alg.addItems(CryptoTabView.algorithm_list)
        hbox_layout1.addWidget(self.alg)

        self.key_list = QComboBox(self)
        self.key_list.setObjectName("key_list")
        self.key_list.setPlaceholderText("密钥类型")
        self.key_list.addItems(CryptoTabView.key_list)
        hbox_layout1.addWidget(self.key_list)

        self.hash_list = QComboBox(self)
        self.hash_list.setObjectName("hash_list")
        self.hash_list.setPlaceholderText("Hash算法")
        self.hash_list.addItems(CryptoTabView.hash_list)
        hbox_layout1.addWidget(self.hash_list)

        self.fmt = QComboBox(self)
        self.fmt.setObjectName("fmt")
        self.fmt.setPlaceholderText("数据格式")
        self.fmt.addItems(CryptoTabView.format_list)
        hbox_layout1.addWidget(self.fmt)

        self.run = QPushButton(self)
        self.run.setObjectName('run')
        self.run.setText('运行')
        self.run.clicked.connect(self.run_crypto)
        hbox_layout1.addWidget(self.run)

        hbox_layout2 = QHBoxLayout()
        vbox_layout.addLayout(hbox_layout2)

        self.cert_format = QComboBox(self)
        self.cert_format.setObjectName('cert_format')
        self.cert_format.setPlaceholderText('证书格式')
        self.cert_format.addItems(CryptoTabView.cert_format)
        hbox_layout2.addWidget(self.cert_format,1)

        self.cert_file = QLineEdit(self)
        self.cert_file.setObjectName("cert_file")
        self.cert_file.setPlaceholderText("证书文件")
        hbox_layout2.addWidget(self.cert_file,1)

        self.cert = QLineEdit(self)
        self.cert.setObjectName("cert")
        self.cert.setPlaceholderText("证书")
        hbox_layout2.addWidget(self.cert,3)

        hbox_layout3 = QHBoxLayout()
        vbox_layout.addLayout(hbox_layout3)

        self.key_fmt = QComboBox(self)
        self.key_fmt.setObjectName('key_fmt')
        self.key_fmt.setPlaceholderText("密钥格式")
        self.key_fmt.addItems(CryptoTabView.key_fmt_list)
        hbox_layout3.addWidget(self.key_fmt,1)

        self.key_file = QLineEdit(self)
        self.key_file.setObjectName("key_file")
        self.key_file.setPlaceholderText("密钥文件")
        hbox_layout3.addWidget(self.key_file,1)

        self.key = QLineEdit(self)
        self.key.setObjectName("key")
        self.key.setPlaceholderText("密钥")
        hbox_layout3.addWidget(self.key,3)

        hbox_layout4 = QHBoxLayout()
        vbox_layout.addLayout(hbox_layout4)
        self.sign = QLineEdit(self)
        self.sign.setObjectName("sign")
        self.sign.setPlaceholderText("签名")
        hbox_layout4.addWidget(self.sign)

        self.input = QTextEdit(self)
        self.input.setObjectName('input')
        self.input.setPlaceholderText('输入')
        grid_layout.addWidget(self.input, 1, 0, 1, 1)

        self.output = QTextEdit(self)
        self.output.setObjectName('output')
        self.output.setPlaceholderText('输出')
        grid_layout.addWidget(self.output, 1, 1, 1, 1)

    def run_crypto(self):
        input = self.input.toPlainText()
        op = self.operation.currentText()
        alg = self.alg.currentText()
        key_type = self.key_list.currentText()
        hash_alg = self.hash_list.currentText()
        fmt = self.fmt.currentText()
        cert_fmt = self.cert_format.currentText()
        cert_file = self.cert_file.text()
        cert = self.cert.text()
        key_fmt = self.key_fmt.currentText()
        key_file = self.key_file.text()
        sign = self.sign.text()
        key = self.key.text()
        operation = CryptoTabView.operation_dict[op]
        if len(input) == 0:
            QMessageBox.warning(self, "Warning", "只能输入数据")
            return
        if len(fmt) == 0:
            QMessageBox.warning(self, "Warning", "请选择数据格式")
            return
        if len(hash_alg) == 0:
            QMessageBox.warning(self, "Warning", "请选择Hash算法")
            return
        if operation == 'sign' or operation == 'verify':
            if len(key) == 0 and len(key_file) == 0:
                QMessageBox.warning(self, "Warning", "请输入密钥或者密钥文件")
                return
            if len(key) > 0 and len(key_file) > 0:
                QMessageBox.warning(self, "Warning", "只输入密钥或者密钥文件")
                return
        python = 'python' if sys.platform.startswith('win') else 'python3'
        cmd = [
            python,
            '../command.py',
            'crypto',
            operation,
            '--fmt',
            CryptoTabView.format_dict[fmt],
            '--ht',
            hash_alg,
        ]
        if len(input) > 0:
            cmd.append('--data')
            cmd.append(input)
        if len(alg) > 0:
            cmd.append('--alg')
            cmd.append(CryptoTabView.algorithm_dict[alg])
        if len(key_type) > 0:
            cmd.append('--kt')
            cmd.append(key_type)
        if len(cert_fmt) > 0:
            cmd.append('--cf')
            cmd.append(CryptoTabView.cert_dict[cert_fmt])
        if len(cert_file) > 0:
            cmd.append('--fc')
            cmd.append(cert_file)
        if len(cert) > 0:
            cmd.append('--bc')
            cmd.append(cert)
        if len(key_fmt) > 0:
            cmd.append('--kf')
            cmd.append(CryptoTabView.key_fmt_dict[key_fmt])
        if len(key_file) > 0:
            cmd.append('--fk')
            cmd.append(key_file)
        if len(key) > 0:
            cmd.append('--bk')
            cmd.append(key)
        if len(sign) > 0:
            cmd.append('--sign')
            cmd.append(sign)
        output_data = subprocess.check_output(cmd).decode("utf-8").strip()
        self.output.setPlainText(output_data)