#!/bin/python3
# -*- coding: utf-8 -*-

'''Launch KRIS with PyQt5 graphical interface. It is a part of Cracker.'''

KRIS_gui__auth = 'Lasercata'
KRIS_gui__last_update = '07.03.2021'
KRIS_gui__version = '1.2.1'

# Note : there are still part of code which are useless here (like DoubleInput)
# and maybe some imported modules too.


##-import
#from modules.base.ini import *
#---------packages
#------gui
from modules.base import glb

from PyQt5.QtCore import QSize, Qt
from PyQt5.QtGui import QIcon, QPixmap, QCloseEvent, QPalette, QColor
from PyQt5.QtWidgets import (QApplication, QMainWindow, QComboBox, QStyleFactory,
    QLabel, QGridLayout, QLineEdit, QMessageBox, QWidget, QPushButton, QCheckBox,
    QHBoxLayout, QVBoxLayout, QGroupBox, QTabWidget, QTableWidget, QFileDialog,
    QRadioButton, QTextEdit, QButtonGroup, QSizePolicy, QSpinBox, QFormLayout,
    QSlider)

#------other
from os import chdir, getcwd
from os.path import isfile
import sys

#from datetime import datetime as dt

from ast import literal_eval #safer than eval

#---------KRIS modules
try:
    from modules.base.base_functions import *
    from modules.base.progress_bars import *

    from modules.base.gui.lock_gui import Lock
    from modules.base.gui.GuiStyle import GuiStyle
    from modules.base.gui.TextEditor import TextEditor
    from modules.base.gui.Popup import Popup

    from modules.ciphers.hashes import hasher
    #from modules.ciphers.crypta import crypta
    from modules.ciphers.kris import AES, RSA, KRIS

    from modules.base.mini_pwd_testor import get_sth

    from Languages.lang import translate as tr
    from Languages.lang import langs_lst, lang


except ModuleNotFoundError as ept:
    err = str(ept).strip("No module named")

    try:
        cl_out(c_error, tr('Put the module {} back !!!').format(err))

    except NameError:
        print('\n' + tr('Put the module {} back !!!').format(err))

    sys.exit()


##-ini
#---------version
try:
    with open('version.txt', 'r') as f:
        kris_version_0 = f.read()
    kris_version = ""
    for k in kris_version_0:
        if not ord(k) in (10, 13):
            kris_version += k

except FileNotFoundError:
    cl_out(c_error, tr('The file "version.txt" was not found. A version will be set but can be wrong.'))
    kris_version = '1.0.0 ?'

else:
    if len(kris_version) > 16:
        cl_out(c_error, tr('The file "version.txt" contain more than 16 characters, so it certainly doesn\'t contain the actual version. A version will be set but can be wrong.'))
        kris_version = '1.0.0 ?'


#---------passwords

#todo: Check if there is a file with this data in ./Data/pwd
#todo + add a salt for passwords ?


pwd_h = 'SecHash'
pwd_loop = 512

try:
    with open('Data/pwd') as f:
        pwd = f.read().strip('\n')

    if len(pwd) != 128:
        raise FileNotFoundError #Set the password to the default

    for k in pwd:
        if k not in '0123456789abcdef':
            raise FileNotFoundError

except FileNotFoundError:
    pwd = '0c0bf58bf97b83c9dd7c260ff3eefea72455d6c7768810cefb41697f266d97f8db06b9bfcce0dd1fa9f3c656b01876bd837f201c9e605ed4d357a22f7aa94cff'

# pwd_h = 'sha512'
# pwd = '6a0cc613e360caf70250b1ddbe169554ddfe9f6edc8b0ec33d61d80d9d0b11090434fcf27d24b40f710bc81e01c05efd78a0086b4673bd042b213e8c7afb4b0c'

# pwd = 'c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec'

admin_h = 'SecHash'
admin_loop = 512
admin_pwd = '164c53d1a85ae8eff014e162af6ee7dfe6d8eaeb0f01cefcf451b6ed2894c3d4f92903449644db163723e4a77cfac881a562e9285b9f76852fea0417c581d934'

# admin_h = 'sha512'
# admin_pwd = '0e1faf4b92c262ea33c915792b3245b890bc9c30efc3aed327ac559b2731355a8531a2ba7a04efc36eefda6aa64fca6e375e123a4c8c84a856c1121429a6357d'


#---------Usefull lists/dicts
lst_encod = ('utf-8', 'ascii', 'latin-1')


ciphers_list = {
    'KRIS' : ('KRIS-AES-256', 'KRIS-AES-192', 'KRIS-AES-128'),

    'AES' : ('AES-256', 'AES-192', 'AES-128'),

    'RSA' : ('RSA', tr('RSA signature')),

    #'Crypta' : tuple(crypta.crypta_ciphers.keys()),

    # tr('analysis') : (tr('Text analysis'), tr('Frequence analysis'), tr('Index of coincidence'), \
    #     tr('Kasiki examination'), tr("Friedman's test")),

    'hash' : hasher.h_str + ('SecHash',)
}

#crack_method_list = (tr('Brute-force'), tr('Dictionary attack'), tr('Advanced brute-force'), tr('Code break'))


# prima_algo_list = {
#     tr('Decomposition') : (tr('Trial division'), tr('Wheel factorization'), tr("Fermat's factorization"), \
#     tr("Pollard's rho"), 'p - 1'),
#
#     tr('Probabilistic') : (tr("Fermat's test"), tr("Miller-Rabin's test")),
#
#     tr('Sieves') : (tr('Sieve of Erathostenes'), tr('Segmented sieve of Erathostenes'))
# }
#
# b_cvrt_alf_list = {
#     'alf_base10': '0123456789',
#     'alf_base16': '0123456789ABCDEF',
#     'alf_base32': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
#     'alf_base32hex': '0123456789ABCDEFGHIJKLMNOPQRSTUV',
#     'alf_base36': '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ',
#     'alf_base62': 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
#     'alf_base64': 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
#     'alf_base140': r'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZαβγδεζηθικλμνξοπρςστυφχψωϊϋόύώϐϑϒϓϔϕϖϗϘϙϚϛϜϝϞϟϠϡϢϣϤϥϦϧϨϩϪϫϬϭϮϯϰϱϲϳϴϵ϶ϷϸϹϺϻϼϽϾϿ'
# }

alf_az = 'abcdefghijklmnopqrstuvwxyz'
alf_az09 = alf_az + '0123456789'
alf_AZ = alf_az.upper()
alf_AZ09 = alf_AZ + '0123456789'
alf_azAZ = alf_az + alf_AZ

alf_wrt = ' .,:;!?"\'-'
alf_usual = alf_azAZ + alf_wrt

alf_25 = alf_az.replace('j', '')
alf_25AZ = alf_AZ.replace('J', '')

crypta_alf_list = {
    'alf_25': alf_25,
    'alf_az': alf_az,
    'alf_az09': alf_az09,
    'alf_25AZ': alf_25AZ,
    'alf_AZ': alf_AZ,
    'alf_AZ09': alf_AZ09
}


##-helpful functions / classes
#---------Double input
class DoubleInput(QWidget):
    '''Class defining a double input.'''

    def __init__(self, type_=QLineEdit, n=2, parent=None):
        '''
        Initiate the DoubleInput object.

        - type_ : The type of the two widgets. Should be QLineEdit, or QSpinBox ;
        - n : the number of inputs.
        '''

        if type_ not in (QLineEdit, QSpinBox):
            raise ValueError(tr('The arg "type_" should be QLineEdit or QSpinBox, but "{}" was found !!!').format(type_))

        if type(n) != int:
            raise ValueError(tr('The arg "n" should be an int !!!'))

        elif n < 1:
            raise ValueError(tr('The arg "n" should be greater or equal to 1 !!!'))

        #------ini
        super().__init__(parent)

        self.type_ = type_
        self.n = n

        #------widgets
        #---layout
        main_lay = QGridLayout()
        self.setLayout(main_lay)

        #---inputs
        self.inp_lst = []

        if type_ == QLineEdit:
            for k in range(n):
                self.inp_lst.append(QLineEdit())

        elif type_ == QSpinBox:
            for k in range(n):
                self.inp_lst.append(QSpinBox())

        for j, w in enumerate(self.inp_lst):
            main_lay.addWidget(w, 0, j)


    def setStyleSheet(self, style):
        '''Apply the stylesheet 'style'.'''

        for w in self.inp_lst:
            w.setStyleSheet(style)


    def setObjectName(self, name):
        '''Set the object's name.'''

        for w in self.inp_lst:
            w.setObjectName(name)


    def setMinimum(self, n):
        '''Set the minimal number in the QSpinBoxes.'''

        for w in self.inp_lst:
            w.setMinimum(n)


    def setMaximum(self, n):
        '''Set the maximal number in the QSpinBoxes.'''

        for w in self.inp_lst:
            w.setMaximum(n)


    def value(self):
        '''Return the value of the inputs, in a tuple.'''

        if self.type_ == QLineEdit:
            ret = [w.text() for w in self.inp_lst]

        elif self.type_ == QSpinBox:
            ret = [w.value() for w in self.inp_lst]

        return tuple(ret)


    def text(self):
        '''Same as self.value()'''

        return self.value()



##-GUI
class KrisGui(QMainWindow):
    '''Class defining KRIS' graphical user interface using PyQt5'''

    def __init__(self, parent=None):
        '''Create the window'''

        #------ini
        super().__init__(parent)
        self.setWindowTitle('KRIS v' + kris_version)
        self.setWindowIcon(QIcon('Style/KRIS_logo_by_surang.ico'))

        #---the QTabWidget
        self.app_widget = QTabWidget()
        self.setCentralWidget(self.app_widget)

        self.path_ent = {} #List of all the QLineEdit in paths bar, by tab index (Ig. : {0 : QLineEdit(), 1 : QLineEdit()})
        self.lst_txt = [] #List of all the TextEditor object, used to reload them when changing directory.

        self.lst_wrdlst_opt = {} #List of all the ComboBox selecting the wordlists, by sender text.
        self.lst_selected_wrdlst = {
            tr('Select a wordlist ...') : [],
            tr('Select a location ...') : []
            } #Dict which contain all the selected wordlists, by sender text.
        self.lst_selected_wrdlst[tr('Select a file ...')] = self.lst_selected_wrdlst[tr('Select a wordlist ...')]

        #self.style = style_test
        self.app_style = GuiStyle()
        self.style = self.app_style.style_sheet

        #------create the tabs
        self.tabs = {
            0 : tr('Ciphers'),
            1 : tr('Settings')
        }

        self.create_ciphers()
        self.create_settings()

        self.app_widget.currentChanged.connect(self.chk_tab)

        #QCloseEvent.ignore()

        #------show
        self.chk_tab(0) #Resize the window and set a mnimum size.
        self.show()


    #---------create cipher tab
    def create_ciphers(self):
        '''Create the "Cipher" tab.'''

        #------ini
        tab_cipher = QWidget()

        tab_cipher_lay = QGridLayout()
        tab_cipher_lay.setColumnStretch(0, 1)
        tab_cipher_lay.setContentsMargins(5, 5, 5, 5)
        tab_cipher.setLayout(tab_cipher_lay)

        #------check functions
        def chk_ciph(cipher):
            '''Check the cipher's combo box and dislable or not some widgets, and change the key's entry.'''

            if cipher in (*ciphers_list['KRIS'], *ciphers_list['RSA']): #RSA
                self.cipher_opt_keys.setHidden(False)
                self.cipher_ledit_keys.setHidden(True)
                self.cipher_nb_key.setHidden(True)
                self.cipher_db_ledit_key.setHidden(True)
                self.cipher_db_nb_key.setHidden(True)

            elif cipher == 'SecHash': #QSpinBox
                self.cipher_nb_key.setHidden(False)
                self.cipher_ledit_keys.setHidden(True)
                self.cipher_opt_keys.setHidden(True)
                self.cipher_db_ledit_key.setHidden(True)
                self.cipher_db_nb_key.setHidden(True)

            else: #QLinEdit
                self.cipher_ledit_keys.setHidden(False)
                self.cipher_opt_keys.setHidden(True)
                self.cipher_nb_key.setHidden(True)
                self.cipher_db_ledit_key.setHidden(True)
                self.cipher_db_nb_key.setHidden(True)


            if cipher == 'RSA signature':
                self.cipher_bt_enc.setText(tr('Si&gn ↓'))
                self.cipher_bt_dec.setText(tr('Chec&k'))

            elif cipher in ciphers_list['hash']:
                self.cipher_bt_enc.setText(tr('H&ash ↓'))

            else:
                self.cipher_bt_enc.setText(tr('&Encrypt ↓'))
                self.cipher_bt_dec.setText(tr('&Decrypt ↑'))


            dis = cipher in ciphers_list['hash'][:-1]
            self.cipher_opt_keys.setDisabled(dis)
            self.cipher_ledit_keys.setDisabled(dis)
            self.cipher_nb_key.setDisabled(dis)
            self.cipher_db_ledit_key.setDisabled(dis)
            self.cipher_db_nb_key.setDisabled(dis)

            self.cipher_opt_alf.setDisabled(True) #cipher not in crypta.ciph_sort['alf'])
            self.cipher_bt_dec.setDisabled(cipher in ciphers_list['hash'])

            self.cipher_nb_key.setRange(-2**16, 2**16)
            key_label.setText(tr('Key :'))

            self.reload_keys()


        #------path bar
        tab_cipher_lay.addWidget(self.create_path_bar(tab=0, mn_size=610), 0, 0, 1, -1)#, alignment=Qt.AlignTop)

        #------widgets
        #---text editor e
        self.txt_e = TextEditor(txt_height=120)
        self.lst_txt.append(self.txt_e) # used to reload when changing directory.
        tab_cipher_lay.addWidget(self.txt_e, 1, 0)


        #---keys
        keys_grp = QGroupBox()
        keys_lay = QGridLayout()
        keys_grp.setLayout(keys_lay)
        tab_cipher_lay.addWidget(keys_grp, 2, 0, 1, 2, alignment=Qt.AlignCenter)

        key_label = QLabel(tr('Key :'))
        keys_lay.addWidget(key_label, 0, 0)

        #-RSA keys' box
        self.cipher_opt_keys = QComboBox()
        self.cipher_opt_keys.setStyleSheet(self.style)
        self.cipher_opt_keys.setObjectName('sec_obj')
        self.cipher_opt_keys.setMinimumSize(200, 0)
        self.cipher_opt_keys.addItem(tr('-- Select a key --'))
        self.cipher_opt_keys.insertSeparator(1)
        self.cipher_opt_keys.addItems(RSA.list_keys('all'))
        keys_lay.addWidget(self.cipher_opt_keys, 0, 1)#, alignment=Qt.AlignLeft)

        #-Line edit key
        self.cipher_ledit_keys = QLineEdit()
        self.cipher_ledit_keys.setStyleSheet(self.style)
        self.cipher_ledit_keys.setObjectName('sec_obj')
        self.cipher_ledit_keys.setMinimumSize(200, 0)
        self.cipher_ledit_keys.setHidden(True)
        keys_lay.addWidget(self.cipher_ledit_keys, 0, 1)#, alignment=Qt.AlignLeft)

        #-Number key
        self.cipher_nb_key = QSpinBox()
        self.cipher_nb_key.setMinimum(-2**16)
        self.cipher_nb_key.setMaximum(2**16)
        self.cipher_nb_key.setStyleSheet(self.style)
        self.cipher_nb_key.setObjectName('sec_obj')
        self.cipher_nb_key.setMinimumSize(200, 0)
        self.cipher_nb_key.setHidden(True)
        keys_lay.addWidget(self.cipher_nb_key, 0, 1)#, alignment=Qt.AlignLeft)

        #-Double line edit
        self.cipher_db_ledit_key = DoubleInput()
        self.cipher_db_ledit_key.setStyleSheet(self.style)
        self.cipher_db_ledit_key.setObjectName('sec_obj')
        self.cipher_db_ledit_key.setMinimumSize(200, 0)
        self.cipher_db_ledit_key.setHidden(True)
        keys_lay.addWidget(self.cipher_db_ledit_key, 0, 1)#, alignment=Qt.AlignLeft)

        #-Double number key
        self.cipher_db_nb_key = DoubleInput(type_=QSpinBox)
        self.cipher_db_nb_key.setMinimum(-2**16)
        self.cipher_db_nb_key.setMaximum(2**16)
        self.cipher_db_nb_key.setStyleSheet(self.style)
        self.cipher_db_nb_key.setObjectName('sec_obj')
        self.cipher_db_nb_key.setMinimumSize(200, 0)
        self.cipher_db_nb_key.setHidden(True)
        keys_lay.addWidget(self.cipher_db_nb_key, 0, 1)#, alignment=Qt.AlignLeft)

        #-Buttons
        self.cipher_bt_enc = QPushButton('&Encrypt ↓')
        self.cipher_bt_enc.setStyleSheet(self.style)
        self.cipher_bt_enc.setObjectName('main_obj')
        self.cipher_bt_enc.setMaximumSize(90, 40)
        keys_lay.addWidget(self.cipher_bt_enc, 0, 2)#, alignment=Qt.AlignLeft)

        self.cipher_bt_dec = QPushButton('&Decrypt ↑')
        self.cipher_bt_dec.setStyleSheet(self.style)
        self.cipher_bt_dec.setObjectName('main_obj')
        self.cipher_bt_dec.setMaximumSize(90, 40)
        keys_lay.addWidget(self.cipher_bt_dec, 0, 3)#, alignment=Qt.AlignLeft)

        keys_lay.setColumnMinimumWidth(4, 20) #Spacing

        #-Alphabets' box
        self.cipher_opt_alf = QComboBox()
        self.cipher_opt_alf.setEditable(True)
        self.cipher_opt_alf.addItem(tr('-- Select an alphabet --'))
        self.cipher_opt_alf.insertSeparator(1)
        self.cipher_opt_alf.addItems(list(crypta_alf_list.values()))
        #keys_lay.addWidget(self.cipher_opt_alf, 0, 5)

        #keys_lay.setColumnMinimumWidth(6, 300) #Spacing

        #-Ciphers' box
        self.cipher_opt_ciphs = QComboBox()
        self.cipher_opt_ciphs.activated[str].connect(chk_ciph)
        self.cipher_opt_ciphs.addItem(tr('-- Select a cipher --'))
        for k in ciphers_list:
            self.cipher_opt_ciphs.insertSeparator(500)
            self.cipher_opt_ciphs.addItems(ciphers_list[k])
        keys_lay.addWidget(self.cipher_opt_ciphs, 0, 7)#, alignment=Qt.AlignLeft)


        #---text editor d
        self.txt_d = TextEditor(txt_height=125)
        #self.txt_d.setMaximumSize(10000, 450)
        self.lst_txt.append(self.txt_d) # used to reload when changing directory.
        tab_cipher_lay.addWidget(self.txt_d, 3, 0)


        #---buttons
        bt_lay = QVBoxLayout()
        tab_cipher_lay.addLayout(bt_lay, 1, 1, 1, -1, alignment=Qt.AlignTop)

        bt_lay.addWidget(QLabel('')) # Spacing

        bt_gen = QPushButton(tr('Generate keys'))
        bt_gen.setStyleSheet(self.style)
        bt_gen.setObjectName('orange_border_hover')
        bt_gen.clicked.connect(lambda: GenKeyWin.use(self.style, parent=self))
        bt_lay.addWidget(bt_gen, alignment=Qt.AlignRight)

        bt_exp = QPushButton(tr('Export public keys'))
        bt_exp.setStyleSheet(self.style)
        bt_exp.setObjectName('orange_border_hover')
        bt_exp.clicked.connect(lambda: ExpKeyWin.use(self.style, parent=self))
        bt_lay.addWidget(bt_exp, alignment=Qt.AlignRight)

        bt_info_k = QPushButton(tr('Show info about keys'))
        bt_info_k.setStyleSheet(self.style)
        bt_info_k.setObjectName('orange_border_hover')
        bt_info_k.clicked.connect(lambda: InfoKeyWin.use(self.style, parent=self))
        bt_lay.addWidget(bt_info_k, alignment=Qt.AlignRight)

        bt_rn_k = QPushButton(tr('Rename keys'))
        bt_rn_k.setStyleSheet(self.style)
        bt_rn_k.setObjectName('orange_border_hover')
        bt_rn_k.clicked.connect(lambda: RenKeyWin.use(self.style, parent=self))
        bt_lay.addWidget(bt_rn_k, alignment=Qt.AlignRight)

        bt_rn_k = QPushButton(tr('Convert keys'))
        bt_rn_k.setStyleSheet(self.style)
        bt_rn_k.setObjectName('orange_border_hover')
        bt_rn_k.clicked.connect(lambda: CvrtKeyWin.use(self.style, parent=self))
        bt_lay.addWidget(bt_rn_k, alignment=Qt.AlignRight)


        bt_quit = QPushButton(tr('&Quit'))
        bt_quit.setObjectName('bt_quit')
        bt_quit.setStyleSheet(self.style)
        bt_quit.setMaximumSize(QSize(50, 35))
        bt_quit.clicked.connect(self.quit)

        tab_cipher_lay.addWidget(bt_quit, 3, 1, alignment=Qt.AlignRight | Qt.AlignBottom)

        #------connection
        use_ciph = UseCipherTab(
            self.txt_e,
            self.txt_d,
            self.cipher_opt_keys,
            self.cipher_ledit_keys,
            self.cipher_nb_key,
            self.cipher_db_ledit_key,
            self.cipher_db_nb_key,
            self.cipher_opt_alf,
            self.cipher_opt_ciphs
        )

        self.cipher_bt_enc.clicked.connect(lambda: use_ciph.encrypt())
        self.cipher_bt_dec.clicked.connect(lambda: use_ciph.decrypt())


        #------show
        chk_ciph(tr('-- Select a cipher --'))

        self.app_widget.addTab(tab_cipher, tr('C&ipher'))



    def create_settings(self):
        '''Create the "Settings" tab.'''

        #------ini
        tab_stng = QWidget()

        tab_stng_lay = QGridLayout()
        tab_stng_lay.setContentsMargins(5, 5, 5, 5)
        tab_stng.setLayout(tab_stng_lay)

        #------widgets
        #---main style
        #-ini
        self.style_grp = QGroupBox('Syle')
        self.style_grp.setMaximumSize(500, 100)
        #self.style_grp.setMinimumSize(500, 200)
        main_style_lay = QHBoxLayout()
        self.style_grp.setLayout(main_style_lay)
        tab_stng_lay.addWidget(self.style_grp, 0, 0, Qt.AlignLeft | Qt.AlignTop)

        self.main_style_palette = QApplication.palette()

        #-combo box
        main_style_lay.addWidget(QLabel('Style :'))

        self.stng_main_style_opt = QComboBox()
        self.stng_main_style_opt.addItems(self.app_style.main_styles)
        self.stng_main_style_opt.activated[str].connect(
            lambda s: self.app_style.set_style(s, self.main_style_std_chkb.isChecked())
        )
        self.stng_main_style_opt.setCurrentText(self.app_style.main_style_name)
        main_style_lay.addWidget(self.stng_main_style_opt)

        #-check box
        self.main_style_std_chkb = QCheckBox("&Use style's standard palette")
        self.main_style_std_chkb.setChecked(True)
        self.main_style_std_chkb.toggled.connect(
            lambda: self.app_style.set_style(
                self.stng_main_style_opt.currentText(),
                self.main_style_std_chkb.isChecked()
            )
        )
        main_style_lay.addWidget(self.main_style_std_chkb)


        #---change password
        #-chk function
        def chk_pwd_shown():
            '''Actualise if the password needs to be shown.'''

            for k in dct_cb:
                if k.isChecked():
                    dct_cb[k].setEchoMode(QLineEdit.Normal)

                else:
                    dct_cb[k].setEchoMode(QLineEdit.Password)

        #-ini
        self.stng_pwd_grp = QGroupBox('Change password')
        self.stng_pwd_grp.setMaximumSize(600, 200)
        self.stng_pwd_grp.setMinimumSize(500, 200)
        stng_pwd_lay = QGridLayout()
        self.stng_pwd_grp.setLayout(stng_pwd_lay)

        tab_stng_lay.addWidget(self.stng_pwd_grp, 0, 1, 2, 1)#, Qt.AlignRight)

        #-form widgets (ask for pwd)
        stng_pwd_form_lay = QFormLayout()
        stng_pwd_lay.addLayout(stng_pwd_form_lay, 0, 0)

        self.stng_old_pwd = QLineEdit()
        self.stng_old_pwd.setMinimumSize(250, 0)
        self.stng_old_pwd.setEchoMode(QLineEdit.Password) # don't print pwd
        stng_pwd_form_lay.addRow('Old password :', self.stng_old_pwd)

        self.stng_pwd1 = QLineEdit()
        self.stng_pwd1.setMinimumSize(250, 0)
        self.stng_pwd1.setEchoMode(QLineEdit.Password) # don't print pwd
        stng_pwd_form_lay.addRow('New password :', self.stng_pwd1)

        self.stng_pwd2 = QLineEdit()
        self.stng_pwd2.setMinimumSize(250, 0)
        self.stng_pwd2.setEchoMode(QLineEdit.Password) # don't print pwd
        stng_pwd_form_lay.addRow('Verify :', self.stng_pwd2)

        #-checkbox widgets (show pwd)
        stng_pwd_cb_lay = QVBoxLayout()
        stng_pwd_cb_lay.setSpacing(15)
        stng_pwd_lay.addLayout(stng_pwd_cb_lay, 0, 1)

        self.stng_old_pwd_cb = QCheckBox()
        stng_pwd_cb_lay.addWidget(self.stng_old_pwd_cb)
        self.stng_old_pwd_cb.toggled.connect(chk_pwd_shown)

        self.stng_pwd1_cb = QCheckBox()
        stng_pwd_cb_lay.addWidget(self.stng_pwd1_cb)
        self.stng_pwd1_cb.toggled.connect(chk_pwd_shown)

        self.stng_pwd2_cb = QCheckBox()
        stng_pwd_cb_lay.addWidget(self.stng_pwd2_cb)
        self.stng_pwd2_cb.toggled.connect(chk_pwd_shown)

        dct_cb = {
            self.stng_old_pwd_cb: self.stng_old_pwd,
            self.stng_pwd1_cb: self.stng_pwd1,
            self.stng_pwd2_cb: self.stng_pwd2
        }

        #-button
        self.stng_pwd_bt = QPushButton('Change password')
        stng_pwd_lay.addWidget(self.stng_pwd_bt, 1, 1, Qt.AlignRight)

        #-connection
        use_c_pwd = UseSettingsTab(self.stng_old_pwd, self.stng_pwd1, self.stng_pwd2)

        self.stng_pwd_bt.clicked.connect(lambda: use_c_pwd.change_pwd())
        self.stng_pwd2.returnPressed.connect(lambda: use_c_pwd.change_pwd())


        #---Change language
        #-function
        def chg_lang():
            '''
            Changing the language (in the text file). The user need to
            close the app and relaunch it manually to apply the new lang.
            '''

            new_lang = self.stng_lang_box.currentText()

            #---test
            if new_lang == lang:
                return -3

            #---write
            with open('Data/lang.txt', 'w') as f:
                f.write(new_lang)

            #---close
            rep = QMessageBox.question(
                None, 'Done !',
                '<h2>The new lang will apply the next time you launch KRIS.</h2>\n<h2>Quit now ?</h2>',
                QMessageBox.No | QMessageBox.Yes,
                QMessageBox.Yes
            )

            if rep == QMessageBox.Yes:
                self.quit()


        #-ini
        self.stng_lang_grp = QGroupBox('Change Language')
        self.stng_lang_grp.setMaximumSize(200, 130)
        # self.stng_lang_grp.setMinimumSize(500, 200)
        stng_lang_lay = QGridLayout()
        self.stng_lang_grp.setLayout(stng_lang_lay)

        tab_stng_lay.addWidget(self.stng_lang_grp, 1, 0)#, Qt.AlignRight)

        #-Langs combo box
        self.stng_lang_box = QComboBox()
        self.stng_lang_box.setMaximumWidth(50)
        self.stng_lang_box.addItems(langs_lst)
        self.stng_lang_box.setCurrentText(lang)
        stng_lang_lay.addWidget(self.stng_lang_box, 0, 0, Qt.AlignLeft)

        #-Button
        self.stng_lang_bt = QPushButton('Apply')
        stng_lang_lay.addWidget(self.stng_lang_bt, 1, 0, Qt.AlignRight)
        self.stng_lang_bt.clicked.connect(chg_lang)

        #------show
        self.app_widget.addTab(tab_stng, 'Setti&ngs')



    #---------Path bar
    def create_path_bar(self, tab, mn_size=700):
        '''Return a QWidget containing a path bar.

        tab : the tab containing the bar 's index.
        '''

        #------ini
        path_bar = QGroupBox()
        path_bar.setObjectName('path_grp')
        path_bar.setStyleSheet(self.style)
        path_bar.setMaximumSize(QSize(7000, 60))

        path_bar_lay = QGridLayout()
        path_bar_lay.setContentsMargins(5, 5, 5, 5)
        path_bar.setLayout(path_bar_lay)

        #------widgets
        path_bar_lay.addWidget(QLabel(tr('Current directory :')), 0 ,0)

        self.path_ent[tab] = QLineEdit()
        self.path_ent[tab].setObjectName('path_entry')
        self.path_ent[tab].setStyleSheet(self.style)
        self.path_ent[tab].setMinimumSize(QSize(mn_size, 20))
        self.path_ent[tab].setText(getcwd())
        self.path_ent[tab].returnPressed.connect(self.change_dir) # Don't need to press the button : press <enter>
        path_bar_lay.addWidget(self.path_ent[tab], 0, 1)

        bt_up = QPushButton('↑')
        bt_up.setMaximumSize(QSize(40, 50))
        bt_up.clicked.connect(self.change_dir_up)
        bt_up.setObjectName('path_bt')
        bt_up.setStyleSheet(self.style)
        path_bar_lay.addWidget(bt_up, 0, 2)

        bt_apply = QPushButton(tr('Apply'))
        bt_apply.clicked.connect(self.change_dir)
        bt_apply.setObjectName('path_bt')
        bt_apply.setStyleSheet(self.style)
        path_bar_lay.addWidget(bt_apply, 0, 3)

        bt_gui = QPushButton(tr('Search'))
        bt_gui.clicked.connect(self.change_dir)
        bt_gui.setObjectName('path_bt')
        bt_gui.setStyleSheet(self.style)
        bt_gui.clicked.connect(self.change_dir_gui)
        path_bar_lay.addWidget(bt_gui, 0, 4)

        return path_bar



    #---------chdir
    def change_dir(self):
        '''Change the current directory according to the path bar'''

        new_dir = self.path_ent[self.app_widget.currentIndex()].text()

        try:
            chdir(new_dir)

        except FileNotFoundError:
            self.path_ent[self.app_widget.currentIndex()].setText(getcwd())
            QMessageBox.about(QWidget(), tr('!!! Directory error !!!'), tr('The directory was NOT found !!!'))
            return False

        for tab in range(1):
            self.path_ent[tab].setText(getcwd()) #actualise every path bar.

        for text_editor in self.lst_txt:
            text_editor.reload() #Reload TextEditors' ComboBox.

        self.reload_keys()


    def change_dir_up(self):
        '''Change the current directory up'''

        chdir('..')
        for tab in range(1):
            self.path_ent[tab].setText(getcwd()) #actualise every path bar.

        for text_editor in self.lst_txt:
            text_editor.reload() #Reload TextEditors' ComboBox.

        self.reload_keys()


    def change_dir_gui(self):
        '''Change the current directory by asking to the user with a popup'''


        new_dir = QFileDialog.getExistingDirectory(self, tr('Select directory'))

        if new_dir:
            try:
                chdir(new_dir)

            except FileNotFoundError:
                self.path_ent[self.app_widget.currentIndex()].setText(getcwd())
                QMessageBox.about(QWidget(), tr('!!! Directory error !!!'), tr('The directory was NOT found !!!'))
                return False

            for tab in range(1):
                self.path_ent[tab].setText(getcwd()) #actualise every path bar.

            for text_editor in self.lst_txt:
                text_editor.reload() #Reload TextEditors' ComboBox.

            self.reload_keys()



    def reload_keys(self):
        '''Reload the RSA keys's box, in the cipher tab.'''

        old_key = self.cipher_opt_keys.currentText()

        keys_list = RSA.list_keys('all')

        self.cipher_opt_keys.clear()

        self.cipher_opt_keys.addItem(tr('-- Select a key --'))
        self.cipher_opt_keys.insertSeparator(1)
        self.cipher_opt_keys.addItems(keys_list)

        if old_key in keys_list:
            self.cipher_opt_keys.setCurrentText(old_key)



    #---------chk_tab
    def chk_tab(self, tab):
        '''Resize the window according to the tab.'''

        self.current_tab = tab

        if tab == 0: #Cipher
            self.setMinimumSize(1030, 730)
            self.resize(1030, 730)
            self.reload_keys()

        elif tab == 1: #Settings
            self.setMinimumSize(900, 250)
            self.resize(900, 250)



    # #---------infos
    # def show_infos(self):
    #     '''Show information about this program using a popup.'''
    #
    #     AboutCracker.use(parent=self)



    #---------lock
    def lock(self, tries=5):
        '''Dislable the widgets and ask for the password.'''

        if tries == False:
            tries = 5

        def chk_lock():
            if not self.locker.is_locked():
                self.setDisabled(False)

                global RSA_keys_pwd
                RSA_keys_pwd = self.locker.get_RSA_keys_pwd()

                RSA.SecureRsaKeys(RSA_keys_pwd, interface='gui').decrypt()

        self.locker = Lock(pwd, pwd_h, pwd_loop, tries)

        self.setDisabled(True)
        self.locker.show()

        self.locker.connect(chk_lock)



    #---------quit
    def quit(self, event=None):
        '''Quit the application. Check if there is text somewhere, and ask confirmation if there is.'''

        global app

        txt_ = False
        txt_tab = []
        if self.txt_e.getText(silent=True, from_='text') != '':
            txt_ = True
            txt_tab.append('Cipher (encrypt)')

        if self.txt_d.getText(silent=True, from_='text') != '':
            txt_ = True
            txt_tab.append('Cipher (decrypt)')


        if txt_:
            if len(txt_tab) == 1:
                title = '!!! There is text in ' + set_prompt(txt_tab) + ' tab !!!'
                msg = '<h2>The text widget in the ' + set_prompt(txt_tab) + \
                ' tab is not empty !</h2>\n<h4>Your text will be lose if not saved !</h4>\nQuit anyway ?'

            else:
                title = '!!! There is text in some tabs !!!'
                msg = '<h2>The text widgets in the ' + set_prompt(txt_tab) + \
                ' tabs is not empty !</h2>\n<h4>Your text will be lose if not saved !</h4>\nQuit anyway ?'


            sure = QMessageBox.question(self, title, msg, \
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

            if sure == QMessageBox.No:
                if event not in (None, True, False):
                    event.ignore()
                return -3

        if event not in (None, True, False):
            RSA.SecureRsaKeys(RSA_keys_pwd, 'gui').rm_clear()
            event.accept()

        else:
            RSA.SecureRsaKeys(RSA_keys_pwd, 'gui').rm_clear()
            app.quit()
            #todo: use app.close() ? what differences ?


    def closeEvent(self, event=None):
        self.quit(event)



    #---------use
    def use(lock=True):
        '''Launch the application.'''

        global app, win

        app = QApplication(sys.argv)
        win = KrisGui()

        #-lock
        if lock:
            win.lock(3)

        #app.setPalette(KrisGuiStyle.dark_style(None))
        #app.aboutToQuit.connect(win.quit)

        sys.exit(app.exec_())



##-Ciphers' keys management
#---------Generate RSA keys
class GenKeyWin(QMainWindow):
    '''Class which define a window which allow to generate RSA keys.'''

    def __init__(self, style, parent=None):
        '''Initiate the GenKeyWin window.'''

        #------ini
        super().__init__(parent)
        self.setWindowTitle('Generate RSA keys — KRIS')

        #---Central widget
        self.main_wid = QWidget()
        self.setCentralWidget(self.main_wid)

        main_lay = QGridLayout()
        self.main_wid.setLayout(main_lay)

        #------Main chooser
        self.cipher_box = QComboBox()
        self.cipher_box.setMaximumSize(150, 35)
        self.cipher_box.activated[str].connect(self._chk)
        self.cipher_box.addItems([tr('-- Select a cipher --'), 'RSA', 'AES-256', 'AES-192', 'AES-128'])
        self.cipher_box.insertSeparator(1)
        self.cipher_box.insertSeparator(3)
        main_lay.addWidget(self.cipher_box, 0, 0)

        #------RSA keys
        self.RSA_wid = QWidget() #QGroupBox('Generate RSA keys')
        main_lay.addWidget(self.RSA_wid, 1, 0)

        RSA_lay = QGridLayout()
        self.RSA_wid.setLayout(RSA_lay)

        #---label
        RSA_lay.addWidget(QLabel("Keys' size :"), 0, 0)

        #---Slider
        self.slider_sz = QSlider(Qt.Horizontal)
        self.slider_sz.setMinimumSize(250, 0)
        self.slider_sz.setMinimum(512)
        self.slider_sz.setMaximum(5120)
        self.slider_sz.setSingleStep(512)
        self.slider_sz.setTickInterval(512)
        self.slider_sz.setTickPosition(QSlider.TicksBelow)

        self.slider_sz.setValue(2048)

        RSA_lay.addWidget(self.slider_sz, 0, 1)

        #---QSpinBox
        self.sb = QSpinBox()
        self.sb.setMaximumSize(70, 35)
        self.sb.setMinimum(512)
        self.sb.setMaximum(5120)
        self.sb.setSingleStep(512)
        self.sb.setValue(2048)

        RSA_lay.addWidget(self.sb, 0, 2)

        #-connection
        self.slider_sz.valueChanged.connect(lambda v: self.sb.setValue(v))
        self.sb.valueChanged.connect(lambda v: self.slider_sz.setValue(v))

        #---name label
        RSA_lay.addWidget(QLabel("Keys' name :"), 1, 0)

        #---line edit
        self.ledt = QLineEdit()
        self.ledt.setMinimumSize(250, 0)
        self.ledt.returnPressed.connect(self.gen)
        RSA_lay.addWidget(self.ledt, 1, 1)

        #---check box hexa
        self.chbt_h = QCheckBox('Store in hexadecimal')
        self.chbt_h.setChecked(True)
        RSA_lay.addWidget(self.chbt_h, 1, 2)


        #------One int arg (Label - QSpinBox)
        #---ini
        self.sp_wid = QWidget() #QGroupBox('Generate string key')
        main_lay.addWidget(self.sp_wid, 1, 0)

        sp_lay = QGridLayout()
        self.sp_wid.setLayout(sp_lay)

        #---widgets
        self.sp_lb = QLabel("Key's length :")
        sp_lay.addWidget(self.sp_lb, 0, 0)

        self.str1_lth = QSpinBox()
        self.str1_lth.setValue(15)
        self.str1_lth.setMinimumSize(150, 35)
        sp_lay.addWidget(self.str1_lth, 0, 1)


        #------buttons
        self.bt_cancel = QPushButton('Cancel')
        self.bt_cancel.setMaximumSize(55, 35)
        self.bt_cancel.clicked.connect(self.close)
        main_lay.addWidget(self.bt_cancel, 2, 0, Qt.AlignRight)

        self.bt_gen = QPushButton('Generate')
        self.bt_gen.setMinimumSize(0, 35)
        self.bt_gen.setStyleSheet(style)
        self.bt_gen.setObjectName('main_obj')
        self.bt_gen.clicked.connect(self.gen)
        main_lay.addWidget(self.bt_gen, 2, 1)


        self.w_lst = (self.RSA_wid, self.sp_wid)
        self._chk('RSA')
        self._chk(tr('-- Select a cipher --'))


    def _chk(self, ciph):
        '''Changes the generation box.'''

        if ciph == tr('-- Select a cipher --'):
            for w in self.w_lst:
                w.setDisabled(True)

        else:
            self.setWindowTitle('Generate {} keys — KRIS'.format(ciph))

            for w in self.w_lst:
                w.setDisabled(False)


        if ciph == 'RSA':
            for w in self.w_lst:
                w.hide()
            self.RSA_wid.show()

        elif 'AES' in ciph:
            for w in self.w_lst:
                w.hide()
            self.sp_wid.show()
            self.sp_lb.setText("Key's size :")



    def gen(self):
        '''Redirect to the good gen method.'''

        ciph = self.cipher_box.currentText()

        if ciph == tr('-- Select a cipher --'):
            QMessageBox.critical(None, '!!! No cipher selected !!!', '<h2>Please select a cipher !!!</h2>')
            return -3

        if ciph == 'RSA':
            ret = self.gen_RSA()

        elif 'AES' in ciph:
            try:
                ret = self._show_key(ciph, KRIS.AES_rnd_key_gen(self.str1_lth.value(), int(ciph[-3:])))

            except ValueError as err:
                QMessageBox.warning(None, 'Key size error', '<h2>{}</h2>'.format(err))
                return -3


        if ret != -3:
            self.close()

        return ret


    def gen_RSA(self):
        '''Collect the infos and give it to RsaKeys to generate the keys.'''

        global win

        name = self.ledt.text()
        if name == '':
            QMessageBox.critical(None, '!!! No name !!!', '<h2>Please enter a name for the RSA keys !!!</h2>')
            return -3 #Abort

        size = self.slider_sz.value()
        md_st = ('dec', 'hexa')[self.chbt_h.isChecked()]

        val = RSA.RsaKeys(name, 'gui').generate(size, md_stored=md_st)

        if val == -2: #The set of keys already exists
            rep = QMessageBox.question(
                None,
                'File error !',
                '<h2>A set of keys named "{}" already exist !</h2>\n<h2>Overwite it !?</h2>\n<h3>This action can NOT be undone !!!</h3>'.format(name),
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )

            if rep == QMessageBox.Yes:
                val = RSA.RsaKeys(name, 'gui').generate(size, md_stored=md_st, overwrite=True)

            else:
                return -2

        win.reload_keys()

        global RSA_keys_pwd
        RSA.RsaKeys(name, 'gui').encrypt(RSA_keys_pwd)


        QMessageBox.about(None, 'Done !', '<h2>Your brand new RSA keys "{}" are ready !</h2>\n<h3>`n` size : {} bits</h3>'.format(name, val[2]))



    def _show_key(self, ciph, key):
        '''Show the key using Popup.'''

        Popup('{} key — KRIS'.format(ciph), str(key), parent=self)


    def use(style, parent=None):
        '''Function which launch this window.'''

        gen_win = GenKeyWin(style, parent)
        gen_win.show()


#---------export RSA keys
class ExpKeyWin(QMainWindow):
    '''Class which define a window which allow to export RSA keys.'''

    def __init__(self, style, parent=None):
        '''Initiate the ExpKeyWin window.'''

        #------ini
        super().__init__(parent)
        self.setWindowTitle('Export RSA keys — KRIS')

        #---Central widget
        self.main_wid = QWidget()
        self.setCentralWidget(self.main_wid)

        main_lay = QGridLayout()
        self.main_wid.setLayout(main_lay)

        #------Widgets
        #---label
        main_lay.addWidget(QLabel("Keys' name :"), 0, 0)

        #---Keys combo box
        self.keys_opt = QComboBox()
        self.keys_opt.setStyleSheet(style)
        self.keys_opt.setObjectName('sec_obj')
        self.keys_opt.setMinimumSize(200, 0)
        self.keys_opt.addItem(tr('-- Select a key --'))
        self.keys_opt.insertSeparator(1)
        self.keys_opt.addItems(RSA.list_keys('pvk_without_pbk'))
        main_lay.addWidget(self.keys_opt, 0, 1)

        #---check box hexa
        self.chbt_h = QCheckBox('Store in hexadecimal')
        self.chbt_h.setChecked(True)
        main_lay.addWidget(self.chbt_h, 1, 2)

        #---buttons
        self.bt_cancel = QPushButton('Cancel')
        self.bt_cancel.setMaximumSize(55, 35)
        self.bt_cancel.clicked.connect(self.close)
        main_lay.addWidget(self.bt_cancel, 2, 2, Qt.AlignRight)

        self.bt_gen = QPushButton('Export')
        self.bt_gen.setStyleSheet(style)
        self.bt_gen.setObjectName('main_obj')
        self.bt_gen.clicked.connect(self.exp)
        main_lay.addWidget(self.bt_gen, 2, 3)


    def exp(self):
        '''Collect the info and export the public RSA keys.'''

        global win

        k_name = self.keys_opt.currentText()
        md_st = ('dec', 'hexa')[self.chbt_h.isChecked()]

        if k_name == tr('-- Select a key --'):
            QMessageBox.critical(None, '!!! No selected key !!!', '<h2>Please select a key !!!</h2>')
            return -3

        ret = RSA.RsaKeys(k_name, 'gui').export(md_st)

        if ret == -1:
            QMessageBox.critical(None, '!!! Key not found !!!', '<h2>The keys were NOT found !!!</h2>')
            return -1

        QMessageBox.about(None, 'Done !', '<h2>The keys "{}" have been be exported.</h2>'.format(k_name))

        self.close()
        win.reload_keys()


    def use(style, parent=None):
        '''Function which launch this window.'''

        exp_win = ExpKeyWin(style, parent)
        exp_win.show()


#---------RSA keys infos
class InfoKeyWin(QMainWindow):
    '''Class which define a window which allow to get info on RSA keys.'''

    def __init__(self, style, parent=None):
        '''Initiate the InfoKeyWin window.'''

        #------ini
        super().__init__(parent)
        self.setWindowTitle('Infos on RSA keys — KRIS')

        #---Central widget
        self.main_wid = QWidget()
        self.setCentralWidget(self.main_wid)

        main_lay = QGridLayout()
        self.main_wid.setLayout(main_lay)

        #------Widgets
        #---label
        main_lay.addWidget(QLabel("Keys' name :"), 0, 0)

        #---Keys combo box
        self.keys_opt = QComboBox()
        self.keys_opt.setStyleSheet(style)
        self.keys_opt.setObjectName('sec_obj')
        self.keys_opt.setMinimumSize(200, 0)
        self.keys_opt.addItem(tr('-- Select a key --'))
        self.keys_opt.insertSeparator(1)
        self.keys_opt.addItems(RSA.list_keys('all'))
        main_lay.addWidget(self.keys_opt, 0, 1)

        #---buttons
        self.bt_cancel = QPushButton('Close')
        self.bt_cancel.setMaximumSize(55, 35)
        self.bt_cancel.clicked.connect(self.close)
        main_lay.addWidget(self.bt_cancel, 1, 1, Qt.AlignRight)

        self.bt_info = QPushButton('Get infos')
        self.bt_info.setMinimumSize(0, 35)
        self.bt_info.setStyleSheet(style)
        self.bt_info.setObjectName('main_obj')
        self.bt_info.clicked.connect(self.info)
        main_lay.addWidget(self.bt_info, 1, 2)


    def info(self):
        '''Collect the infos and get infos on RSA keys.'''

        k_name = self.keys_opt.currentText()
        if k_name == tr('-- Select a key --'):
            QMessageBox.critical(None, '!!! No selected key !!!', '<h2>Please select a key !!!</h2>')
            return -3

        keys = RSA.RsaKeys(k_name, 'gui')

        md_stg = keys.show_keys(get_stg_md=True)

        if md_stg == -1:
            return -1 #File not found

        lst_keys, lst_values, lst_infos = keys.show_keys()

        if len(lst_infos) == 2: #Full keys
            (pbk, pvk), (p, q, n, phi, e, d), (n_strth, date_) = lst_keys, lst_values, lst_infos

            prnt = 'The keys were created the ' + date_
            prnt += '\nThe n\'s strenth : ' + n_strth + ' bytes ;\n'

            prnt += '\n\nValues :\n\tp : ' + str(p) + ' ;\n\tq : ' + str(q) + ' ;\n\tn : ' + str(n)
            prnt += ' ;\n\tphi : ' + str(phi) + ' ;\n\te : ' + str(e) + ' ;\n\td : ' + str(d) + ' ;\n'

            prnt += '\n\tPublic key : ' + str(pbk) + ' ;'
            prnt += '\n\tPrivate key : ' + str(pvk) + '.'

        else: #Public keys
            pbk, (n, e), (n_strth, date_, date_exp) = lst_keys, lst_values, lst_infos

            prnt = 'The keys were created the ' + date_ + '\nAnd exported the ' + date_exp
            prnt += '\nThe n\'s strenth : ' + n_strth + ' bytes ;\n'

            prnt += '\n\nValues :\n\tn : ' + str(n) + ' ;\n\te : ' + str(e) + ' ;\n'

            prnt += '\n\tPublic key : ' + str(pbk) + '.'

        Popup('Info on {}'.format(k_name), prnt, parent=self)


    def use(style, parent=None):
        '''Function which launch this window.'''

        info_win = InfoKeyWin(style, parent)
        info_win.show()


#---------Rename RSA keys
class RenKeyWin(QMainWindow):
    '''Class which define a window which allow to rename RSA keys.'''

    def __init__(self, style, parent=None):
        '''Initiate the RenKeyWin window.'''

        #------ini
        super().__init__(parent)
        self.setWindowTitle('Rename RSA keys — KRIS')

        #---Central widget
        self.main_wid = QWidget()
        self.setCentralWidget(self.main_wid)

        main_lay = QGridLayout()
        self.main_wid.setLayout(main_lay)

        #------Widgets
        #---label
        main_lay.addWidget(QLabel("Keys' name :"), 0, 0)

        #---Keys combo box
        self.keys_opt = QComboBox()
        self.keys_opt.setStyleSheet(style)
        self.keys_opt.setObjectName('sec_obj')
        self.keys_opt.setMinimumSize(200, 0)
        self.keys_opt.addItem(tr('-- Select a key --'))
        self.keys_opt.insertSeparator(1)
        self.keys_opt.addItems(RSA.list_keys('all'))
        main_lay.addWidget(self.keys_opt, 0, 1)

        #---Rename box
        main_lay.addWidget(QLabel('New name :'), 1, 0)

        self.ledit = QLineEdit()
        self.ledit.setMinimumSize(150, 35)
        main_lay.addWidget(self.ledit, 1, 1)

        #---buttons
        self.bt_cancel = QPushButton('Cancel')
        self.bt_cancel.setMaximumSize(55, 35)
        self.bt_cancel.clicked.connect(self.close)
        main_lay.addWidget(self.bt_cancel, 2, 1, Qt.AlignRight)

        self.bt_rn = QPushButton('Rename')
        self.bt_rn.setMinimumSize(0, 35)
        self.bt_rn.setStyleSheet(style)
        self.bt_rn.setObjectName('main_obj')
        self.bt_rn.clicked.connect(self.rn)
        main_lay.addWidget(self.bt_rn, 2, 2)


    def rn(self):
        '''Collect the infos and rename RSA keys.'''

        global win

        k_name = self.keys_opt.currentText()
        new_name = self.ledit.text()

        if k_name == tr('-- Select a key --'):
            QMessageBox.critical(None, '!!! No selected key !!!', '<h2>Please select a key !!!</h2>')
            return -3

        if new_name == '':
            QMessageBox.critical(None, '!!! No name !!!', '<h2>Please enter a new name !</h2>')
            return -3


        keys = RSA.RsaKeys(k_name, 'gui')
        out = keys.rename(new_name)

        if out == -1:
            QMessageBox.critical(None, '!!! Keys not found !!!', '<h2>The set of keys was NOT found !!!</h2>')
            return -1

        QMessageBox.about(None, 'Done !', '<h2>Your keys "{}" have been be renamed "{}" !</h2>'.format(k_name, new_name))

        self.close()
        win.reload_keys()


    def use(style, parent=None):
        '''Function which launch this window.'''

        rn_win = RenKeyWin(style, parent)
        rn_win.show()


#---------Convert RSA keys
class CvrtKeyWin(QMainWindow):
    '''Class which define a window which allow to convert RSA keys.'''

    def __init__(self, style, parent=None):
        '''Initiate the CvrtKeyWin window.'''

        #------ini
        super().__init__(parent)
        self.setWindowTitle('Convert RSA keys — KRIS')

        #---Central widget
        self.main_wid = QWidget()
        self.setCentralWidget(self.main_wid)

        main_lay = QGridLayout()
        self.main_wid.setLayout(main_lay)

        #------Widgets
        #---Radio buttons
        main_lay.addWidget(QLabel("Keys' type :"), 0, 0)

        self.rb_dec = QRadioButton('Decimal')
        self.rb_dec.setChecked(True)
        self.rb_dec.toggled.connect(self._chk)
        main_lay.addWidget(self.rb_dec, 0, 1)

        self.rb_hex = QRadioButton('Hexadecimal')
        self.rb_hex.toggled.connect(self._chk)
        main_lay.addWidget(self.rb_hex, 0, 2)

        #---label
        main_lay.addWidget(QLabel("Keys' name :"), 1, 0)

        #---Keys combo box
        keys_lst = (*RSA.list_keys('pvk'), *RSA.list_keys('pbk'))

        self.keys_opt = QComboBox()
        self.keys_opt.setStyleSheet(style)
        self.keys_opt.setObjectName('sec_obj')
        self.keys_opt.setMinimumSize(200, 0)
        self.keys_opt.addItem(tr('-- Select a key --'))
        self.keys_opt.insertSeparator(1)
        self.keys_opt.addItems(keys_lst)
        main_lay.addWidget(self.keys_opt, 1, 1)

        #---buttons
        self.bt_cancel = QPushButton('Cancel')
        self.bt_cancel.setMaximumSize(55, 35)
        self.bt_cancel.clicked.connect(self.close)
        main_lay.addWidget(self.bt_cancel, 2, 1, Qt.AlignRight)

        self.bt_cvrt = QPushButton('Convert in hexa')
        self.bt_cvrt.setMinimumSize(0, 35)
        self.bt_cvrt.setStyleSheet(style)
        self.bt_cvrt.setObjectName('main_obj')
        self.bt_cvrt.clicked.connect(self.cvrt)
        main_lay.addWidget(self.bt_cvrt, 2, 2)


    def _chk(self):
        '''Check the checked radio button, and actualise the keys combo box.'''

        if self.rb_dec.isChecked():
            keys_lst = (*RSA.list_keys('pvk'), *RSA.list_keys('pbk'))
            self.bt_cvrt.setText('Convert in hexa')

        else:
            keys_lst = (*RSA.list_keys('pvk_hex'), *RSA.list_keys('pbk_hex'))
            self.bt_cvrt.setText('Convert in decimal')

        self.keys_opt.clear()
        self.keys_opt.addItem(tr('-- Select a key --'))
        self.keys_opt.insertSeparator(1)
        self.keys_opt.addItems(keys_lst)


    def cvrt(self):
        '''Collect the infos and convert RSA keys.'''

        k_name = self.keys_opt.currentText()
        exp = ('hexadecimal', 'decimal')[self.rb_dec.isChecked()]

        if k_name == tr('-- Select a key --'):
            QMessageBox.critical(None, '!!! No selected key !!!', '<h2>Please select a key !!!</h2>')
            return -3

        out = RSA.RsaKeys(k_name, 'gui').convert()

        if out == -1:
            QMessageBox.critical(None, '!!! Keys not found !!!', '<h2>The keys were NOT found !!!</h2>')
            return -1

        elif out == -2:
            QMessageBox.critical(None, '!!! Keys already exist !!!', '<h2>The set of keys already exist !!!</h2>\n<h3>You may already have converted them.</h3>')
            return -2

        QMessageBox.about(None, 'Done !', '<h2>Your set of keys has been be converted in "{}" !</h2>'.format(exp))
        self.close()


    def use(style, parent=None):
        '''Function which launch this window.'''

        cvrt_win = CvrtKeyWin(style, parent)
        cvrt_win.show()



##-Classes to use the GUI
#---------Ciphers
class UseCipherTab:
    '''Class which allow to use the Cipher tab.'''

    def __init__(self, txt_e, txt_d, key_opt, key_ledit, key_nb, key_2_str, key_2_nb, alf, cipher):
        '''Create the UseCipherTab object.'''

        self.txt_e = txt_e
        self.txt_d = txt_d
        self.key_opt = key_opt
        self.key_ledit = key_ledit
        self.key_nb = key_nb
        self.key_2_str = key_2_str
        self.key_2_nb = key_2_nb
        self.alf = alf
        self.cipher = cipher


    def _verify(self, md):
        '''
        Verify if the infos are good, warn the user else.
        md : 0 - encrypt : 1 - decrypt.

        Return :
            -3 if  not good ;
            0 otherwise.
        '''

        if md not in (0, 1):
            raise ValueError('"md" not in (0, 1) !!!')

        ciph = self.cipher.currentText()

        if ciph == tr('-- Select a cipher --'):
            QMessageBox.critical(None, 'No cipher selected !!!', '<h2>Please select a cipher !</h2>')
            return -3

        if ciph in (*ciphers_list['KRIS'], *ciphers_list['RSA']):
            if self.key_opt.currentText() == tr('-- Select a key --'):
                QMessageBox.critical(None, 'No key selected !!!', '<h2>Please select a key !</h2>')
                return -3

        elif ciph not in ciphers_list['hash']:
            key = self._get_key(md)

            if key == '':
                QMessageBox.critical(None, 'No key entered !!!', '<h2>Please enter a key !</h2>')
                return -3

        return 0 #Everything is fine


    def _get_key(self, md):
        '''
        Return the usable key.
        md : 0 - encrypt : 1 - decrypt.

        Return :
            -3 if an error occured (with an RSA key) ;
            the key otherwise.
        '''

        if md not in (0, 1):
            raise ValueError('"md" not in (0, 1) !!!')

        ciph = self.cipher.currentText()

        if ciph in (*ciphers_list['KRIS'], *ciphers_list['RSA']):
            try:
                key = RSA.RsaKeys(self.key_opt.currentText(), interface='gui').read(md)

            except Exception as err:
                QMessageBox.critical(None, '!!! Error !!!', '<h2>{}</h2>'.format(err))
                return -3 #Abort

        elif ciph == 'SecHash':
            key = self.key_nb.value()

        else:
            key = self.key_ledit.text()


        return key


    def encrypt(self):
        '''Encrypt the text, using the informations given in init.'''

        #------check
        if self._verify(0) == -3:
            return -3 #Abort

        #------ini
        txt = self.txt_e.getText()
        if txt in (-1, -2, -3):
            return txt #Abort

        ciph = self.cipher.currentText()
        encod = self.txt_d.get_encod()
        bytes_md = self.txt_d.get_bytes()

        if ciph != 'RSA signature':
            key = self._get_key(0)

        else:
            key = self._get_key(1)

        if key == -3:
            return -3 #Abort


        #------encrypt with the good cipher
        if ciph in ciphers_list['KRIS']:
            AES_md = (256, 192, 128)[ciphers_list['KRIS'].index(ciph)]

            C = KRIS.Kris((key, None), AES_md, encod, bytes_md, interface='gui')
            msg_c = C.encrypt(txt)

            msg_c = '{} {}'.format(msg_c[0], msg_c[1])


        elif ciph == 'RSA':
            C = RSA.RSA((key, None), interface='gui')
            msg_c = C.encrypt(txt)


        elif ciph == 'RSA signature':
            C = RSA.RsaSign((None, key), interface='gui')
            msg_c = C.str_sign(txt)


        elif  ciph in ciphers_list['AES']:
            AES_md = (256, 192, 128)[ciphers_list['AES'].index(ciph)]
            md = {'t' : 'str', 'b' : 'bytes'}[bytes_md]

            try:
                C = AES.AES(AES_md, key, False, encod)

            except ValueError as err:
                QMessageBox.critical(None, '!!! Value error !!!', '<h2>{}</h2>'.format(err))
                return -3

            msg_c = C.encryptText(txt, encoding=encod, mode_c='hexa', mode=md)


        elif ciph in ciphers_list['hash'][:-1]:
            try:
                C = hasher.Hasher(ciph)

            except ValueError:
                QMessageBox.critical(None, '!!! Unknown hash !!!', '<h2>The hash "{}" is unknown !!!</h2>'.format(ciph))
                return -3

            msg_c = C.hash(txt)


        elif ciph == 'SecHash':
            try:
                msg_c = hasher.SecHash(txt, key)

            except RecursionError:
                QMessageBox.critical(None, '!!! Too big loop !!!', '<h2>The number of loops is too big !!!</h2>')
                return -3


        self.txt_d.setText(msg_c)


    def decrypt(self):
        '''Decrypt the text, using the informations given in init.'''

        #------check
        if self._verify(1) == -3:
            return -3 #Abort

        #------ini
        txt = self.txt_d.getText()
        if txt in (-1, -2, -3):
            return txt #Abort

        ciph = self.cipher.currentText()
        encod = self.txt_e.get_encod()
        bytes_md = self.txt_e.get_bytes()
        bytes_md_d = self.txt_d.get_bytes()

        if ciph != 'RSA signature':
            key = self._get_key(1)

        else:
            key = self._get_key(0)

        if key == -3:
            return -3 #Abort


        #------decrypt using the good cipher
        if ciph in ciphers_list['KRIS']:
            AES_md = (256, 192, 128)[ciphers_list['KRIS'].index(ciph)]

            C = KRIS.Kris((None, key), AES_md, encod, bytes_md, interface='gui')

            try:
                if bytes_md_d == 't':
                    msg_d = C.decrypt(txt.split(' '))
                else:
                    msg_d = C.decrypt(txt.split(b' '))

            except ValueError:
                return -3 #The error message is printed in Kris.


        elif ciph == 'RSA':
            C = RSA.RSA((None, key), interface='gui')
            msg_d = C.decrypt(txt)


        elif ciph == 'RSA signature':
            C = RSA.RsaSign((key, None), interface='gui')
            if C.str_check(txt):
                QMessageBox.about(None, 'Signature result', '<h2>The signature match to the message.</h2>')

            else:
                QMessageBox.about(None, 'Signature result', '<h2>The signature does not match to the message !</h2>\n<h3>You may not have selected the right RSA key, or the message was modified before you received it !!!</h3>')

            return None


        elif  ciph in ciphers_list['AES']:
            AES_md = (256, 192, 128)[ciphers_list['AES'].index(ciph)]
            md = {'t' : 'str', 'b' : 'bytes'}[bytes_md]

            C = AES.AES(AES_md, key, False, encod)
            msg_d = C.decryptText(txt, encoding=encod, mode_c='hexa', mode=md)

        self.txt_e.setText(msg_d)


#---------Settings
class UseSettingsTab:
    '''Class which allow to use the Settings tab.'''

    def __init__(self, old_pwd, new_pwd1, new_pwd2):
        '''Create the UseBaseConvertTab object.'''

        self.old_pwd = old_pwd
        self.pwd1 = new_pwd1
        self.pwd2 = new_pwd2


    def change_pwd(self):
        '''Change the password which allow to launch KRIS.'''

        global pwd

        old_pwd = self.old_pwd.text()
        pwd1 = self.pwd1.text()
        pwd2 = self.pwd2.text()
        entro = get_sth(pwd1, True)

        if '' in (old_pwd, pwd1, pwd2):
            QMessageBox.critical(None, '!!! Fields empty !!!', '<h2>Please fill the three fields !</h2>')
            return -3

        elif hasher.SecHash(old_pwd) != pwd:
            QMessageBox.critical(None, '!!! Bad password !!!', '<h2>The old password is wrong !</h2>')
            return -3

        elif pwd1 != pwd2:
            QMessageBox.critical(None, '!!! Passwords does not correspond !!!', '<h2>The passwords does not correspond !</h2>')
            return -3

        elif entro < 40:
            QMessageBox.critical(None, '!!! Password too much weak !!!', '<h2>Your new password is too much weak !</h2>\n<h2>It should have an entropy of 40 bits at least, but it has an entropy of {} bits !!!</h2>'.format(round(entro)))
            return -3

        #-good
        pwd = hasher.SecHash(pwd1)
        new_RSA_keys_pwd = hasher.Hasher('sha256').hash(pwd1)[:32]

        try:
            with open('Data/pwd', 'w') as f:
                f.write(pwd)

        except Exception as err:
            QMessageBox.critical(None, '!!! Error !!!', '<h2>{}</h2>'.format(err))
            return -1

        else:
            QMessageBox.about(None, 'Done !', '<h2>Your password has been be changed.</h2>\n<h3>It has an entropy of {} bits.</h3>'.format(round(entro)))

            self.old_pwd.clear()
            self.pwd1.clear()
            self.pwd2.clear()

            global RSA_keys_pwd
            RSA.SecureRsaKeys(new_RSA_keys_pwd, RSA_keys_pwd, 'gui').rm_enc()
            RSA.SecureRsaKeys(new_RSA_keys_pwd, interface='gui').encrypt()



##-run
if __name__ == '__main__':
    #------If first time launched, introduce RSA keys
    chdir(RSA.chd_rsa('.', first=True, interface='gui'))

    #------Launch the GUI
    KrisGui.use()
