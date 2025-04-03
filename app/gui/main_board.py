'''
@File    : main_board.py
@TIME    : 2025/04/02 16:59:44
@Author  : xiao bai
@Version : 1.0
@Contact : bai.xiao@auto-mems.com
@Bref here
'''
#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from PyQt6.QtWidgets import (QMainWindow,
                             QWidget,
                             QVBoxLayout,
                            )
from .command_tabview import CommandTabView

class MainBoard(QMainWindow):
    def __init__(self):
        print("Initializing the main window...")
        super().__init__()
        print("Setting up the main window...")
        self._init_ui()

    def _init_ui(self):
        self.setWindowTitle("安全工具箱")
        self.setGeometry(100, 100, 800, 600)

        # 创建主控件和布局
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout()
        main_widget.setLayout(main_layout)

        # 创建标签控件
        self.tabs = CommandTabView()
        main_layout.addWidget(self.tabs)

