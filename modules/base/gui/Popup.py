#!/bin/python3
# -*- coding: utf-8 -*-

Popup__auth = 'Lasercata'
Popup__last_update = '27.04.2021'
Popup__version = '1.2.1'

##-imports
from PyQt5.QtCore import QSize, Qt
from PyQt5.QtGui import QIcon, QPixmap, QCloseEvent, QPalette, QColor, QFont
from PyQt5.QtWidgets import (QApplication, QMainWindow, QComboBox, QStyleFactory,
    QLabel, QGridLayout, QLineEdit, QMessageBox, QWidget, QPushButton, QCheckBox,
    QHBoxLayout, QGroupBox, QButtonGroup, QRadioButton, QTextEdit, QFileDialog, QDialog)


from modules.base.gui.GuiStyle import GuiStyle


##-main
class Popup(QDialog):
    '''Class which define a popup.'''

    def __init__(self, width=850, height=350, bt_align='center', style='', parent=None):
        '''Initiate the popup window.'''

        if bt_align.lower() == 'center':
            a = Qt.AlignCenter

        elif bt_align.lower() == 'right':
            a = Qt.AlignRight

        else:
            a = Qt.AlignLeft

        #------ini
        super().__init__(parent)

        #---Central widget
        #self.main_wid = QWidget()
        #self.setCentralWidget(self.main_wid)

        self.main_lay = QGridLayout()
        # self.main_wid.setLayout(self.main_lay)
        self.setLayout(self.main_lay)

        #---txt
        #-font
        self.fixed_font = QFont('monospace')
        self.fixed_font.setStyleHint(QFont.TypeWriter)

        #-txt
        self.txt = QTextEdit()
        self.txt.setReadOnly(True)
        self.txt.setMinimumSize(width, height)
        self.txt.setStyleSheet(style)
        self.txt.setObjectName('orange_border_hover')
        self.txt.setFont(self.fixed_font)
        self.main_lay.addWidget(self.txt, 0, 0)

        #---bt OK
        self.bt = QPushButton('OK')
        self.bt.clicked.connect(self.close)
        self.main_lay.addWidget(self.bt, 1, 0, a)


    def pop(self, title, msg, html=False, dialog=True):
        '''
        Show the popup window.

        - title : The popup's title ;
        - msg : the popup's text content ;
        - html : a bool indicating if `msg` is in html format ;
        - dialog : a bool indicating if use `self.exec_()` (with True), or
        `self.show()` to launch the popup.
        '''

        self.setWindowTitle(title)

        if html:
            self.txt.setHtml(msg)

        else:
            self.txt.setPlainText(msg)

        if dialog:
            self.exec_()

        else:
            self.show()


##-run
if __name__ == '__main__':
    import sys

    #app = QApplication(sys.argv)

    win = Popup()
    win.pop('Title', '<b><i>This</i> is the message.</b> Of course.', True)

    #sys.exit(app.exec_())
