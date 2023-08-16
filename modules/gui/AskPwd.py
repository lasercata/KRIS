#!/bin/python3
# -*- coding: utf-8 -*-

AskPwd__auth = 'Lasercata'
AskPwd__ver = '1.1'
AskPwd__last_update = '2023.08.16'

##-import
import sys

try:
    from Languages.lang import translate as tr
    from modules.ciphers.hashes.hasher import Hasher

except ModuleNotFoundError as ept:
    print('\nPut the module' + ' ' + str(ept).strip('No module named') + ' back !!!')
    sys.exit()
    # tr = lambda t: t #TODO: this is just to test.

from PyQt5.QtCore import QSize, Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import (QApplication, QMainWindow, QComboBox, QStyleFactory,
    QLabel, QGridLayout, QLineEdit, QMessageBox, QWidget, QPushButton, QCheckBox,
    QHBoxLayout, QGroupBox, QDialog)


##-main
class AskPwd(QDialog): #QMainWindow):

    def __init__(self, ret_hash=True, h='sha256', parent=None):
        '''
        Create the GUI to ask password.

        - ret_hash  : a boolean indicating if to hash the input ;
        - h         : the hash to use ;
        - parent    : the window parent.
        '''

        self.ret_hash = ret_hash
        self.h = h

        #------ini
        super().__init__(parent)
        self.setWindowTitle(tr('RSA key password') + ' — ' + glb.prog_name)
        self.setWindowIcon(QIcon('Style/KRIS_logo_by_surang.ico'))

        #------widgets
        #---main widget
        # self.main_wid = QWidget()
        # self.setCentralWidget(self.main_wid)

        main_lay = QGridLayout()
        # self.main_wid.setLayout(main_lay)
        self.setLayout(main_lay)

        #---label
        main_lay.addWidget(QLabel(tr('RSA key password :')), 0, 0)

        #---pwd_entry
        self.pwd = QLineEdit()
        self.pwd.setMinimumSize(QSize(200, 0))
        self.pwd.setEchoMode(QLineEdit.Password)
        self.pwd.returnPressed.connect(self.send) # Don't need to press the button : press <enter>

        main_lay.addWidget(self.pwd, 0, 1)

        #---check box
        self.inp_show = QCheckBox(tr('Show password'))
        self.inp_show.toggled.connect(self._show_pwd)

        main_lay.addWidget(self.inp_show, 1, 0, 1, 2, alignment=Qt.AlignCenter | Qt.AlignTop)

        #---button
        self.bt_get = QPushButton('>')
        self.bt_get.setMaximumSize(QSize(40, 50))
        self.bt_get.clicked.connect(self.send)

        main_lay.addWidget(self.bt_get, 0, 2)

        self.the_pwd = None


    def send(self):
        '''Activated when <enter> pressed or when the button is clicked.'''

        text = self.pwd.text()

        if self.ret_hash:
            pwd = Hasher(self.h).hash(text)

        else:
            pwd = text

        self.the_pwd = text
        self.func(pwd)
        self.close()


    def _show_pwd(self):
        '''Show the password or not. Connected with the checkbutton "inp_show"'''

        if self.inp_show.isChecked():
            self.pwd.setEchoMode(QLineEdit.Normal)

        else:
            self.pwd.setEchoMode(QLineEdit.Password)


    def connect(self, function):
        '''
        Call `function` when enter pressed.

        - function : a function that takes one argument, the text that will be returned.
        '''

        self.func = function


    def use(ret_hash=True, h='sha256', parent=None):
        '''Use this function to launch the window. Return the word entered in the window.'''

        def get_pwd(pwd_ret):
            global pwd
            pwd = pwd_ret

        dlg = AskPwd(ret_hash, h, parent)
        dlg.connect(get_pwd)
        dlg.exec_()

        try:
            return pwd

        except NameError:
            return None


##-test
if __name__ == '__main__':

    class Test(QWidget):

        def __init__(self, parent=None):
            super().__init__(parent)

            self.setWindowTitle('Test')
            self.resize(500, 500)

            lay = QGridLayout()
            self.setLayout(lay)

            bt = QPushButton('AskPwd')
            bt.clicked.connect(self.test)
            lay.addWidget(bt)


        def test(self):
            pwd = AskPwd.use()
            print(pwd)

        def show_pwd(self, pwd):
            print(pwd)


    app = QApplication(sys.argv)

    win = Test()
    win.show()

    # w = AskPwd()
    # w.connect(lambda t: print(t))
    # w.show()

    app.exec_()
