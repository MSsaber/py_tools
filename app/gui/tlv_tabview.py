'''
@File    : tlv_tabview.py
@TIME    : 2025/04/03 11:32:23
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
                             QHBoxLayout,
                             QMessageBox,
                             QPushButton)

class TlvTabView(QWidget):
    format_list = ['hexstring', 'base64', 'urlbase64', 'binary']
    format_dict = {
        'hexstring': 'h',
        'base64': 'b64',
        'urlbase64': 'ub64',
        'binary': 'b'
    }
    endian = ['bigedian', 'littledian']
    endian_dict = {
        'bigedian': 'be',
        'littledian': 'le'
    }
    length_fmt_list = ['1byte', '2bytes', '4bytes']
    length_fmt_dict = {
        '1byte': '1',
        '2bytes': '2',
        '4bytes': '4'
    }
    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_setup_ui()
    def _init_setup_ui(self):
        grid_layout = QGridLayout(self)
        self.setLayout(grid_layout)

        hbox_layout = QHBoxLayout()
        grid_layout.addLayout(hbox_layout, 0, 0, 1, 1)

        self.data_fmt = QComboBox(self)
        self.data_fmt.setObjectName("data_fmt")
        self.data_fmt.setPlaceholderText("数据格式")
        self.data_fmt.addItems(TlvTabView.format_list)
        hbox_layout.addWidget(self.data_fmt)

        self.endian = QComboBox(self)
        self.endian.setObjectName("endian")
        self.endian.setPlaceholderText("字节序")
        self.endian.addItems(TlvTabView.endian)
        hbox_layout.addWidget(self.endian)

        self.length_fmt = QComboBox(self)
        self.length_fmt.setObjectName("length_fmt")
        self.length_fmt.setPlaceholderText("长度格式")
        self.length_fmt.addItems(TlvTabView.length_fmt_list)
        hbox_layout.addWidget(self.length_fmt)

        self.parse_button = QPushButton(self)
        self.parse_button.setObjectName("parse_button")
        self.parse_button.setText("解析")
        self.parse_button.clicked.connect(self.parse)
        hbox_layout.addWidget(self.parse_button)

        self.input = QTextEdit(self)
        self.input.setObjectName("input")
        self.input.setPlaceholderText("输入")
        grid_layout.addWidget(self.input, 1, 0, 1, 1)

        self.output = QTextEdit(self)
        self.output.setObjectName("output")
        self.output.setPlaceholderText("输出")
        grid_layout.addWidget(self.output, 1, 1, 1, 1)

    def parse(self):
        input_data = self.input.toPlainText()
        input_fmt = self.data_fmt.currentText()
        endian = self.endian.currentText()
        length_fmt = self.length_fmt.currentText()
        print(f"input_data: {input_data}, input_fmt: {input_fmt}, endian: {endian}, length_fmt: {length_fmt}")
        if len(input_data) == 0:
            QMessageBox.warning(self, "Warning", "请输入数据")
            return
        if len(input_fmt) == 0:
            QMessageBox.warning(self, "Warning", "请选择输入格式")
            return
        if len(endian) == 0:
            QMessageBox.warning(self, "Warning", "请选择字节序")
            return
        python = 'python' if sys.platform.startswith('win') else 'python3'
        cmd = [
            python,
            '../command.py',
            'tlv',
            '--buffer',
            input_data,
            '--fmt',
            TlvTabView.format_dict[input_fmt],
            '--ed',
            TlvTabView.endian_dict[endian],
        ]
        if len(length_fmt) > 0:
            cmd.insert(3, '--tl')
            cmd.insert(4, TlvTabView.length_fmt_dict[length_fmt])
        output_data = subprocess.check_output(cmd).decode("utf-8").strip()
        self.output.setPlainText(output_data)
