'''
@File    : main.py
@TIME    : 2025/04/02 16:56:38
@Author  : xiao bai
@Version : 1.0
@Contact : bai.xiao@auto-mems.com
@Bref here
'''
#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import sys
from PyQt6.QtWidgets import QApplication
from gui.main_board import MainBoard

if __name__ == '__main__':
    print("Starting the application...")
    app = QApplication(sys.argv)
    print("Creating the main window...")
    main_board = MainBoard()
    main_board.show()
    sys.exit(app.exec())