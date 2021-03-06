#!/bin/python3
# -*- coding: utf-8 -*-

Popup__auth = 'Lasercata'
Popup__last_update = '14.07.2020'
Popup__version = '1.0'

##-imports
from PyQt5.QtCore import QSize, Qt
from PyQt5.QtGui import QIcon, QPixmap, QCloseEvent, QPalette, QColor
from PyQt5.QtWidgets import (QApplication, QMainWindow, QComboBox, QStyleFactory,
    QLabel, QGridLayout, QLineEdit, QMessageBox, QWidget, QPushButton, QCheckBox,
    QHBoxLayout, QGroupBox, QButtonGroup, QRadioButton, QTextEdit, QFileDialog)


from modules.base.gui.GuiStyle import GuiStyle


##-main
class Popup(QMainWindow):
    '''Class which define a popup.'''

    def __init__(self, title, msg, width=850, height=350, parent=None):
        '''Initiate the popup window.'''

        #------ini
        super().__init__(parent)
        self.setWindowTitle(title)

        self.style = GuiStyle().style_sheet

        #---Central widget
        self.main_wid = QWidget()
        self.setCentralWidget(self.main_wid)

        main_lay = QGridLayout()
        self.main_wid.setLayout(main_lay)

        #---txt
        self.txt = QTextEdit()
        self.txt.setReadOnly(True)
        self.txt.setAcceptRichText(False)
        self.txt.setMinimumSize(width, height)
        self.txt.setStyleSheet(self.style)
        self.txt.setObjectName('orange_border_hover')
        self.txt.setPlainText(msg)
        main_lay.addWidget(self.txt, 0, 0)

        #---bt OK
        self.bt = QPushButton('OK')
        self.bt.clicked.connect(self.close)
        main_lay.addWidget(self.bt, 1, 0, Qt.AlignCenter)

        self.show()