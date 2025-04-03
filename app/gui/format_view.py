'''
@File    : format_view.py
@TIME    : 2025/04/03 10:53:42
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
                             QMessageBox,
                             QPushButton)
class FormatView(QWidget):
    format_list = ['hexstring', 'base64', 'urlbase64', 'binary']
    format_dict = {
        'hexstring': 'h',
        'base64': 'b64',
        'urlbase64': 'ub64',
        'binary': 'b'
    }
    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_setup_ui()

    def _init_setup_ui(self):
        # Initialize the UI components for the format view here
        grid_layout = QGridLayout(self)
        self.setLayout(grid_layout)

        hbox_layout = QHBoxLayout()
        grid_layout.addLayout(hbox_layout, 0, 0, 1, 1)
        self.fmt_button = QPushButton(self)
        self.fmt_button.setObjectName("fmt_button")
        self.fmt_button.setText("格式化")
        self.fmt_button.clicked.connect(self.format)

        self.file_name = QLineEdit(self)
        self.file_name.setObjectName("file_name")
        self.file_name.setPlaceholderText("文件名")
        hbox_layout.addWidget(self.file_name)
        hbox_layout.addWidget(self.fmt_button)

        self.input_fmt_list = QComboBox(self)
        self.input_fmt_list.setObjectName("input_fmt_list")
        self.input_fmt_list.setPlaceholderText("输入格式")
        self.input_fmt_list.addItems(FormatView.format_list)
        grid_layout.addWidget(self.input_fmt_list, 1, 0, 1, 1)

        self.output_fmt_list = QComboBox(self)
        self.output_fmt_list.setObjectName("output_fmt_list")
        self.output_fmt_list.setPlaceholderText("输出格式")
        self.output_fmt_list.addItems(FormatView.format_list)
        grid_layout.addWidget(self.output_fmt_list, 1, 1, 1, 1)

        self.input = QTextEdit(self)
        self.input.setObjectName("input")
        self.input.setPlaceholderText("输入")
        grid_layout.addWidget(self.input, 2, 0, 1, 1)

        self.output = QTextEdit(self)
        self.output.setObjectName("output")
        self.output.setPlaceholderText("输出")
        grid_layout.addWidget(self.output, 2, 1, 1, 1)

    def format(self):
        input_data = self.input.toPlainText()
        input_fmt = self.input_fmt_list.currentText()
        output_fmt = self.output_fmt_list.currentText()
        file_name = self.file_name.text()
        print(f"input_data: {input_data}, input_fmt: {input_fmt}, output_fmt: {output_fmt}, file_name: {file_name}")
        if len(input_data) == 0:
            QMessageBox.warning(self, "Warning", "请输入数据")
            return
        if len(input_fmt) == 0:
            QMessageBox.warning(self, "Warning", "请选择输入格式")
            return
        if len(output_fmt) == 0:
            QMessageBox.warning(self, "Warning", "请选择输出格式")
            return
        python = 'python' if sys.platform.startswith('win') else 'python3'
        cmd = [
            python,
            '../tFormat.py',
            '--buffer',
            input_data,
            '--sf',
            FormatView.format_dict[input_fmt],
            '--tf',
            FormatView.format_dict[output_fmt],
        ]
        if len(file_name) > 0:
            cmd.insert(2, '--out')
            cmd.insert(3, file_name)
        output_data = subprocess.check_output(cmd).decode("utf-8").strip()
        self.output.setPlainText(output_data)