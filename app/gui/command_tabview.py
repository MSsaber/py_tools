'''
@File    : command_tabview.py
@TIME    : 2025/04/03 10:44:49
@Author  : xiao bai
@Version : 1.0
@Contact : bai.xiao@auto-mems.com
@Bref here
'''
#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from PyQt6.QtWidgets import QTabWidget
from . import format_view,tlv_tabview,hash_tabview,crypto_tabview

class CommandTabView(QTabWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMovable(True)
        self._init_setup_tab()

    def _init_setup_tab(self):
        tab1 = format_view.FormatView(self)
        self.addTab(tab1, "数据格式化")
        tab2 = tlv_tabview.TlvTabView(self)
        self.addTab(tab2, "TLV解析")
        tab3 = hash_tabview.HashTabView(self)
        self.addTab(tab3, "Hash计算")
        tab4 = crypto_tabview.CryptoTabView(self)
        self.addTab(tab4, "非对称密钥与证书")