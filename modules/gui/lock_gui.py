#!/bin/python3
# -*- coding: utf-8 -*-

lock_gui__auth = 'Lasercata'
lock_gui__ver = '4.1.2'
lock_gui__last_update = '07.03.2021'

##-import
import sys
from time import sleep

# try:
from Languages.lang import translate as tr
from modules.ciphers.hasher import Hasher

# except ModuleNotFoundError as ept:
#     print('\n' + tr('Put the module') + " " + str(ept).strip("No module named") + " " + tr('back') + ' !!!')
#     sys.exit()

from PyQt5.QtCore import QSize, Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import (QApplication, QMainWindow, QComboBox, QStyleFactory,
    QLabel, QGridLayout, QLineEdit, QMessageBox, QWidget, QPushButton, QCheckBox,
    QHBoxLayout, QGroupBox)


##-ini
try:
    with open('version.txt', 'r') as f:
        cracker_version_0 = f.read()
    cracker_version = ""
    for k in cracker_version_0:
        if not ord(k) in (10, 13):
            cracker_version += k

except FileNotFoundError:
    cl_out(c_error, tr('The file "version.txt" was not found. A version will be set but can be wrong.'))
    cracker_version = '3.0.0 ?'

else:
    if len(cracker_version) > 16:
        cl_out(c_error, tr('The file "version.txt" contain more than 16 characters, so it certainly doesn\'t contain the actual version. A version will be set but can be wrong.'))
        cracker_version = '3.0.0 ?'


##-main
class Lock(QWidget):

    def __init__(self, pwd, h='SecHash', loop=512, mx=3, parent=None):
        '''
        Create the GUI lock.

        - pwd : the password hashed with the h hash ;
        - h : the hash used to encrypt the password ;
        - loop : Used if the hash is 'SecHash' ;
        - mx : the maximum number of tries.
        '''

        global locked

        locked = True

        #------ini
        super().__init__(parent)
        self.setWindowTitle(glb.prog_name + ' v' + cracker_version + ' | ' + tr('locked'))
        self.setWindowIcon(QIcon('Style/KRIS_logo_by_surang.ico'))

        self.pwd_hshed = pwd
        self.Hasher = Hasher(h, loop).hash

        self.mx = mx

        self.nb_try = 0

        #------widgets
        #---layout
        main_lay = QGridLayout()
        self.setLayout(main_lay)

        #---label
        main_lay.addWidget(QLabel(tr('Enter your password') + ' :'), 0, 0)

        #---pwd_entry
        self.pwd = QLineEdit()
        self.pwd.setMinimumSize(QSize(200, 0))
        self.pwd.setEchoMode(QLineEdit.Password)
        self.pwd.returnPressed.connect(self.check) # Don't need to press the button : press <enter>

        main_lay.addWidget(self.pwd, 0, 1)

        #---lb wrong
        self.lb_wrong = QLabel(str(mx) + " " + tr('remaining attempts'))
        main_lay.addWidget(self.lb_wrong, 2, 1, 1, 2, alignment=Qt.AlignBottom | Qt.AlignRight)

        #---check box
        self.inp_show = QCheckBox(tr('Show password'))
        self.inp_show.toggled.connect(self._show_pwd)

        main_lay.addWidget(self.inp_show, 1, 0, 1, 2, alignment=Qt.AlignCenter | Qt.AlignTop)

        #---button
        self.bt_get = QPushButton('>')
        self.bt_get.setMaximumSize(QSize(40, 50))
        self.bt_get.clicked.connect(self.check)

        main_lay.addWidget(self.bt_get, 0, 2)


    def check(self):
        '''Check if the typed password is the good.'''

        global locked

        locked = True

        hshed_entry = self.Hasher(self.pwd.text())
        self.nb_try += 1


        if hshed_entry == self.pwd_hshed:
            locked = False

            self.RSA_keys_pwd = Hasher('sha256').hash(self.pwd.text())[:32]

            self.unlock_func()
            self.close()

        elif self.nb_try < self.mx:
            self.pwd.setText('')
            if self.mx - self.nb_try > 1:
                self.lb_wrong.setText(str(self.mx - self.nb_try) + " " + tr('remaining attempts'))
            else:
                self.lb_wrong.setText(tr('Last attempt'))

            if self.mx - self.nb_try == 2:
                self.lb_wrong.setStyleSheet('color: #ff0')
                sleep(0.3)

            elif self.mx - self.nb_try == 1:
                self.lb_wrong.setStyleSheet('color: #f00')
                sleep(1)


            locked = True

        else:
            sleep(1.3)
            QMessageBox.critical(QWidget(), tr('Wrong password')+ ' !', \
                '<h1>' + tr('Wrong password') + ' !!!</h1>\n' + tr('It was your last attempt') + ' !!!')

            sys.exit()


    def is_locked(self):
        '''
        Return the state, i.e :
            True if locked ;
            False if unlocked.

        If the password is wrong, the application has been be closed.
        '''

        global locked

        return locked


    def get_RSA_keys_pwd(self):
        '''Try returning RSA_keys_pwd'''

        try:
            return self.RSA_keys_pwd

        except AttributeError:
            return -1


    def connect(self, function):
        '''Execute the function given in parameter if locked is False. (in check)'''

        self.unlock_func = function


    def _show_pwd(self):
        '''Show the password or not. Connected with the checkbutton "inp_show"'''

        if self.inp_show.isChecked():
            self.pwd.setEchoMode(QLineEdit.Normal)

        else:
            self.pwd.setEchoMode(QLineEdit.Password)


    def closeEvent(self, event):
        '''exit if window is closed'''

        if self.is_locked():
            sys.exit()


    def chk():
        '''Check if locked or not, exit if yes'''

        global locked

        if locked:
            sys.exit()


    def use(pwd, h='sha512', mx=3, lvl_=0):
        '''
        Use this function to launch the GUI.

        pwd : the hashed password ;
        h : the hash in whiwh the password is hashed ;
        mx : number of max tries ;
        lvl : the level. 0 - main ; .
        '''

        app = QApplication(sys.argv)
        locker = Lock(pwd, h, mx)
        locker.connect(Lock.chk)
        locker.show()

        app.exec_()

        #if locker.is_locked():
            #sys.exit()


##-test
if __name__ == '__main__':

    pwd = hasher.hasher('test', 'sha512')
    Lock.use(pwd)

    print(tr('passed') + ' !')
