#!/bin/python3
# -*- coding: utf-8 -*-

'''Launch KRIS with PyQt5 graphical interface. It is a part of Cracker.'''

KRIS_gui__auth = 'Lasercata'
KRIS_gui__last_update = '13.04.2021'
KRIS_gui__version = '2.0'

# Note : there may still be parts of code which are useless in this file
# and maybe some imported modules too (TextEditor, ...).


##-import
#from modules.base.ini import *
#---------packages
#------gui
from modules.base import glb

from PyQt5.QtCore import QSize, Qt
from PyQt5.QtGui import QIcon, QPixmap, QCloseEvent, QPalette, QColor, QFont
from PyQt5.QtWidgets import (QApplication, QMainWindow, QComboBox, QStyleFactory,
    QLabel, QGridLayout, QLineEdit, QMessageBox, QWidget, QPushButton, QCheckBox,
    QHBoxLayout, QVBoxLayout, QGroupBox, QTabWidget, QTableWidget, QFileDialog,
    QRadioButton, QTextEdit, QButtonGroup, QSizePolicy, QSpinBox, QFormLayout,
    QSlider, QMenuBar, QMenu, QPlainTextEdit, QAction, QToolBar)

#------other
from os import chdir, getcwd
from os.path import isfile
import sys

from ast import literal_eval #safer than eval

#---------KRIS modules
try:

    from Languages.lang import translate as tr
    from Languages.lang import langs_lst, lang

    from modules.base.base_functions import *
    from modules.base.progress_bars import *

    from modules.base.gui.lock_gui import Lock
    from modules.base.gui.GuiStyle import GuiStyle
    from modules.base.gui.Popup import Popup

    from modules.ciphers.hashes import hasher
    from modules.ciphers.kris import AES, RSA, KRIS
    from modules.base.FormatMsg import FormatMsg

    from modules.base.mini_pwd_testor import get_sth

except ModuleNotFoundError as ept:
    err = str(ept).strip("No module named")

    try:
        cl_out(c_error, tr('Put the module {} back !!!').format(err))

    except NameError:
        try:
            print('\n' + tr('Put the module {} back !!!').format(err))

        except NameError:
            print('\n' + 'Put the module {} back !!!'.format(err))

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
    kris_version = '2.0.0 ?'

else:
    if len(kris_version) > 16:
        cl_out(c_error, tr('The file "version.txt" contain more than 16 characters, so it certainly doesn\'t contain the actual version. A version will be set but can be wrong.'))
        kris_version = '2.0.0 ?'


#---------passwords
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


#---------Useful lists/dicts
lst_encod = ('utf-8', 'ascii', 'latin-1')


ciphers_list = {
    'KRIS' : ('KRIS-AES-256', 'KRIS-AES-192', 'KRIS-AES-128'),

    'AES' : ('AES-256', 'AES-192', 'AES-128'),

    'RSA' : ('RSA', tr('RSA signature')),

    'hash' : hasher.h_str + ('SecHash',)
}

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



##-GUI
class KrisGui(QMainWindow):
    '''Class defining KRIS' graphical user interface using PyQt5'''

    def __init__(self, parent=None):
        '''Create the window'''

        #------ini
        super().__init__(parent)
        self.setWindowTitle('KRIS v' + kris_version)
        self.setWindowIcon(QIcon('Style/KRIS_logo_by_surang.ico'))

        #self.style = style_test
        self.app_style = GuiStyle()
        self.style = self.app_style.style_sheet

        #------Widgets
        #---Central widget
        #-font
        self.fixed_font = QFont('monospace')
        self.fixed_font.setStyleHint(QFont.TypeWriter)

        #-The widget
        self.txt_in = QPlainTextEdit()
        self.txt_in.textChanged.connect(self._show_wc)
        self.txt_in.textChanged.connect(lambda: self._txt_changed('in'))
        self.txt_in.setFont(self.fixed_font)
        self.setCentralWidget(self.txt_in)

        #---Statusbar
        self._create_statusbar()

        #---Toolbars
        self.setContextMenuPolicy(Qt.NoContextMenu) #Not be able to hide bar.
        self._create_out_txt()
        self._create_ciph_toolbar()

        #---Menu
        self._create_menu_bar() #The order (statusbar, out_txt, ciph_toolbar, and menu bar) is important (things needs to be created).
        self.txt_in.undoAvailable.connect(self.undo_ac.setEnabled)
        self.txt_in.redoAvailable.connect(self.redo_ac.setEnabled)

        #------File
        self.txt_in_is_saved = False
        self.txt_out_is_saved = False

        self.fn_in = None #Used to remember the file in the one save.
        self.fn_out = None

        #------Show
        self.show()
        self.resize(1100, 600)


    def _create_menu_bar(self):
        '''Create the menu bar.'''

        #------Menu
        menu_bar = QMenuBar(self)
        self.setMenuBar(menu_bar)

        #------The menus
        #---File
        self.file_m = menu_bar.addMenu(tr('&File'))

        #-New
        self.new_ac = QAction(tr('&New'), self)
        self.new_ac.setShortcut('Ctrl+N')
        self.new_ac.triggered.connect(self.new)
        self.file_m.addAction(self.new_ac)

        self.file_m.addSeparator()

        #-Open
        self.open_ac = QAction(tr('&Open ...'), self)
        self.open_ac.setShortcut('Ctrl+O')
        self.open_ac.triggered.connect(self.open)
        self.file_m.addAction(self.open_ac)

        #-Open
        self.open_recent_m = QMenu(tr('Open &Recent'), self)
        self.op_rec_dct = {}
        self.file_m.addMenu(self.open_recent_m)

        self.file_m.addSeparator()

        #-Save
        self.save_ac = QAction(tr('&Save'), self)
        self.save_ac.setShortcut('Ctrl+S')
        self.save_ac.triggered.connect(lambda: self.save('in', False))
        #self.save_ac.setStatusTip("Save editor's text in a file")
        self.file_m.addAction(self.save_ac)

        #-Save As
        self.save_as_ac = QAction(tr('Save &As'), self)
        self.save_as_ac.setShortcut('Ctrl+Shift+S')
        self.save_as_ac.triggered.connect(lambda: self.save('in', True))
        self.file_m.addAction(self.save_as_ac)

        #-Save Output
        self.save_out_ac = QAction(tr('S&ave Output'), self)
        self.save_out_ac.setShortcut('Ctrl+D')
        self.save_out_ac.triggered.connect(lambda: self.save('out', False))
        self.file_m.addAction(self.save_out_ac)

        #-Save Output As
        self.save_out_as_ac = QAction(tr('Sa&ve Output As'), self)
        self.save_out_as_ac.setShortcut('Ctrl+Shift+D')
        self.save_out_as_ac.triggered.connect(lambda: self.save('out', True))
        self.file_m.addAction(self.save_out_as_ac)

        self.file_m.addSeparator()

        #-Exit
        self.exit_ac = QAction(tr('&Quit'), self)
        self.exit_ac.setShortcut('Ctrl+Q')
        self.exit_ac.triggered.connect(self.quit)
        self.file_m.addAction(self.exit_ac)


        #---Edit
        self.edit_m = menu_bar.addMenu(tr('&Edit'))

        #-Undo
        self.undo_ac = QAction(tr('&Undo'), self)
        self.undo_ac.setEnabled(False)
        self.undo_ac.setShortcut('Ctrl+Z')
        self.undo_ac.triggered.connect(self.txt_in.undo)
        self.edit_m.addAction(self.undo_ac)

        #-Redo
        self.redo_ac = QAction(tr('Re&do'), self)
        self.redo_ac.setEnabled(False)
        self.redo_ac.setShortcut('Ctrl+Shift+Z')
        self.redo_ac.triggered.connect(self.txt_in.redo)
        self.edit_m.addAction(self.redo_ac)

        self.edit_m.addSeparator()

        #-Swap texts
        self.swap_txt_ac = QAction(tr('&Swap texts'), self) #Todo: Also swap self.fn_in and self.fn_out ?
        self.swap_txt_ac.setShortcut('Ctrl+W')
        self.swap_txt_ac.setStatusTip(tr('Toggle input text and output text.'))
        self.swap_txt_ac.triggered.connect(self._swap_txt)
        self.edit_m.addAction(self.swap_txt_ac)

        #-Clear output
        self.cls_out_ac = QAction(tr('&Clear output'), self)
        #self.cls_out_ac.setShortcut('')
        self.cls_out_ac.triggered.connect(self._clear_out)
        self.edit_m.addAction(self.cls_out_ac)

        self.edit_m.addSeparator()

        #-Formated output
        self.formated_out_ac = QAction(tr('&Formatted Output'), self, checkable=True)
        #self.formated_out_ac.setShortcut('')
        self.formated_out_ac.setStatusTip(tr('Set the encrypted text in a good form.'))
        self.formated_out_ac.setChecked(True)
        self.edit_m.addAction(self.formated_out_ac)


        #---View
        self.view_m = menu_bar.addMenu(tr('&View'))

        #-Show output
        self.show_out_ac = QAction(tr('&Show Output'), self, checkable=True)
        self.show_out_ac.setShortcut('Ctrl+M')
        self.show_out_ac.triggered.connect(self.out_toolbar.setVisible)
        self.show_out_ac.setChecked(True)
        self.view_m.addAction(self.show_out_ac)

        self.view_m.addSeparator()

        #-Resize original
        self.resize_ac = QAction(tr('&Resize to original size'), self)
        self.resize_ac.triggered.connect(lambda: self.resize(1100, 600))
        self.view_m.addAction(self.resize_ac)


        # #---Encrypt
        # self.enc_m = menu_bar.addMenu('E&ncrypt')
        #
        # #--KRIS menu
        # self.kris_m = QMenu('&KRIS', self)
        # self.enc_m.addMenu(self.kris_m)
        #
        # #-KRIS-AES-256
        # self.kris_aes_256_ac = QAction('&KRIS-AES-256', self)
        # #self.kris_aes_256_ac.setShortcut('')
        # #self.kris_aes_256_ac.triggered.connect()
        # self.kris_m.addAction(self.kris_aes_256_ac)
        #
        # #-KRIS-AES-192
        # self.kris_aes_192_ac = QAction('K&RIS-AES-192', self)
        # #self.kris_aes_192_ac.setShortcut('')
        # #self.kris_aes_192_ac.triggered.connect()
        # self.kris_m.addAction(self.kris_aes_192_ac)
        #
        # #-KRIS-AES-128
        # self.kris_aes_128_ac = QAction('KR&IS-AES-128', self)
        # #self.kris_aes_128_ac.setShortcut('')
        # #self.kris_aes_128_ac.triggered.connect()
        # self.kris_m.addAction(self.kris_aes_128_ac)


        #---Keys
        self.keys_m = menu_bar.addMenu(tr('&Keys'))

        #-Show info
        self.k_info_ac = QAction(tr('&Show informations about keys ...'), self)
        self.k_info_ac.setShortcut('Ctrl+I')
        self.k_info_ac.triggered.connect(lambda: InfoKeyWin.use(self.style, parent=self))
        self.keys_m.addAction(self.k_info_ac)

        #-Generate
        self.gen_k_ac = QAction(tr('&Generate ...'), self)
        self.gen_k_ac.setShortcut('Ctrl+G')
        self.gen_k_ac.triggered.connect(lambda: GenKeyWin.use(self.style, parent=self))
        self.keys_m.addAction(self.gen_k_ac)

        #-Export
        self.exp_k_ac = QAction(tr('&Export ...'), self)
        self.exp_k_ac.setShortcut('Ctrl+E')
        self.exp_k_ac.triggered.connect(lambda: ExpKeyWin.use(self.style, parent=self))
        self.keys_m.addAction(self.exp_k_ac)

        #-Rename
        self.rn_k_ac = QAction(tr('&Rename ...'), self)
        #self.rn_k_ac.setShortcut('Ctrl+R')
        self.rn_k_ac.triggered.connect(lambda: RenKeyWin.use(self.style, parent=self))
        self.keys_m.addAction(self.rn_k_ac)

        #-Convert
        self.cvrt_k_ac = QAction(tr('&Convert ...'), self)
        #self.cvrt_k_ac.setShortcut('Ctrl+R')
        self.cvrt_k_ac.triggered.connect(lambda: CvrtKeyWin.use(self.style, parent=self))
        self.keys_m.addAction(self.cvrt_k_ac)

        #-Reload box
        self.reload_k_ac = QAction(tr('Re&load box'), self)
        #self.reload_k_ac.setShortcut('Ctrl+R')
        self.reload_k_ac.triggered.connect(self.ciph_bar.reload_keys)
        self.keys_m.addAction(self.reload_k_ac)


        #---Settings
        self.settings_m = menu_bar.addMenu(tr('&Settings'))

        #-Configure KRIS
        self.config_ac = QAction(tr('&Configure KRIS ...'), self)
        self.config_ac.setShortcut('Ctrl+R')
        self.config_ac.triggered.connect(lambda: SettingsWin.use(self.style, self.app_style, parent=self))
        self.settings_m.addAction(self.config_ac)

        #Todo: help and about.
        # #---Help
        # self.help_m = menu_bar.addMenu('&Help')
        #
        # #-About
        # self.help_ac = QAction('&Help', self)
        # #self.help_ac.triggered.connect()
        # self.help_m.addAction(self.help_ac)
        #
        # #-About
        # self.about_ac = QAction('&About', self)
        # #self.about_ac.triggered.connect()
        # self.help_m.addAction(self.about_ac)


    def _create_ciph_toolbar(self):
        '''Create the toolbar which contain the encrypt, decrypt buttons, ciphers , keys.'''

        self.ciph_toolbar = QToolBar('Cipher', self)
        self.ciph_toolbar.setMovable(False)
        self.addToolBar(Qt.TopToolBarArea, self.ciph_toolbar) #Qt.BottomToolBarArea

        self.ciph_bar = CipherKeyWidget(self.style, self)
        self.ciph_toolbar.addWidget(self.ciph_bar)

        #------connection
        use_ciph = UseCiphers(
            self.txt_in,
            self.txt_out,
            self.ciph_bar.cipher_opt_keys,
            self.ciph_bar.cipher_ledit_keys,
            self.ciph_bar.cipher_nb_key,
            self.ciph_bar.cipher_opt_ciphs,
            self.encod_box
        )

        self.ciph_bar.cipher_bt_enc.clicked.connect(lambda: use_ciph.encrypt(self.formated_out_ac.isChecked()))
        self.ciph_bar.cipher_bt_dec.clicked.connect(lambda: use_ciph.decrypt())


    def _create_out_txt(self):
        '''Create the output text viewer.'''

        self.out_toolbar = QToolBar('Output', self)
        self.out_toolbar.setMovable(False)
        self.addToolBar(Qt.BottomToolBarArea, self.out_toolbar)

        self.txt_out = QPlainTextEdit()
        self.txt_out.textChanged.connect(self._show_wc)
        self.txt_out.textChanged.connect(lambda: self._txt_changed('out'))
        self.txt_out.setReadOnly(True)
        self.txt_out.setMaximumHeight(180)
        self.txt_out.setFont(self.fixed_font)
        self.out_toolbar.addWidget(self.txt_out)


    def _create_statusbar(self):
        '''Create the status bar.'''

        self.statusbar = self.statusBar()

        #------Widgets
        #---Words count
        self.wc_lb = QLabel()
        self.statusbar.addPermanentWidget(self.wc_lb)

        self.statusbar.addPermanentWidget(QLabel('  ')) #Spacing

        #---Saved
        self.saved_lb = QLabel()
        self.statusbar.addPermanentWidget(self.saved_lb)

        self.statusbar.addPermanentWidget(QLabel('  ')) #Spacing

        #---Encoding
        self.encod_box = QComboBox()
        self.encod_box.addItems(lst_encod)
        self.statusbar.addPermanentWidget(self.encod_box)


    def _clear_out(self):
        '''Clear the output text viewer'''

        if self.txt_out.toPlainText() != '':
            answer = QMessageBox.question(None, 'Sure ?', '<h2>Are you sure ?</h2>', QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)

            if answer == QMessageBox.No:
                return -3 # Abort

        self.txt_out.setPlainText('')


    def _swap_txt(self):
        '''Swap the output text with the input text.'''

        in_txt = self.txt_in.toPlainText()
        out_txt = self.txt_out.toPlainText()

        self.txt_out.setPlainText(in_txt)
        self.txt_in.setPlainText(out_txt)


    def _get_word_count(self, txt):
        '''Return the number of characters and the number of words which are `txt`.'''

        if txt == '':
            return 0, 0

        txt_l = txt.split(' ')

        cc = len(txt.replace('\n', '')) # Char count
        wc = len(txt_l) - txt_l.count('') # Word count (may not be accurate, ';' will be counted as a word for example).

        return cc, wc

    def _show_wc(self, sender=False):
        '''Show the word count in the status bar.'''

        if sender == False:
            txt = self.sender().toPlainText()

        elif sender in (self.txt_in, self.txt_out):
            txt = sender.toPlainText()

        else:
            return -3 #Abort

        cc, wc = self._get_word_count(txt)
        self.wc_lb.setText(tr('{} words, {} chars.').format(format(wc, '_').replace('_', ' '), format(cc, '_').replace('_', ' ')))


    def _set_save_lb_txt(self):
        '''Set the correct text to self.save_lb.'''

        if self.txt_in_is_saved and self.txt_out_is_saved:
            self.saved_lb.setText(tr('Saved'))
            self.saved_lb.setStyleSheet('color: #0f0')

        elif self.txt_in_is_saved:
            self.saved_lb.setText(tr('Output unsaved'))
            self.saved_lb.setStyleSheet('color: #ff0')

        elif self.txt_out_is_saved:
            self.saved_lb.setText(tr('Input unsaved'))
            self.saved_lb.setStyleSheet('color: #ff0')

        else:
            self.saved_lb.setText(tr('Unsaved'))
            self.saved_lb.setStyleSheet('color: #f00')


    def _txt_changed(self, from_='in'):
        '''
        Set the self.txt_[in | out]_is_saved attribute to False. Called when signal 'textChanged' recieved.

        - from_ : In ('in', 'out'). Used to choose from where read text to save it ;
        '''

        #------Test
        if from_ not in ('in', 'out'):
            raise ValueError('The argument `from_` is not in ("in", "out").')

        #------Change attribute value to False
        if from_ == 'in':
            self.txt_in_is_saved = False

        else:
            self.txt_out_is_saved = False

        #Todo: count undos to set it to True if (nb_do - nb_undo) == 0

        #------Set label
        self._set_save_lb_txt()


    def _msg_box_save(self, part='all', title='Quit KRIS'):
        '''
        Check if there are things unsaved (text), and show a QMessageBox question.
        Return a bool indicating if continue (True) or not (False).

        - part : In ('all', 'in', 'out'). Only check that text part ;
        - title : QMessageBox window's title.
        '''

        if part not in ('all', 'in', 'out'):
            raise ValueError('The argument `part` is not in ("all", "in", "out").')


        txt_ = False
        txt_wid = []
        if (not self.txt_in_is_saved) and self.txt_in.toPlainText() != '' and part != 'out':
            txt_ = True
            txt_wid.append('text editor')

        if (not self.txt_out_is_saved) and self.txt_out.toPlainText() != '' and part != 'in':
            txt_ = True
            txt_wid.append('output')


        if txt_:
            if len(txt_wid) == 1:
                msg = tr('The ' + set_prompt(txt_wid) + \
                ' part has been modified.\nDo you want to save your changes or discard them ?')

            else:
                msg = tr('The ' + set_prompt(txt_wid) + \
                ' parts have been modified.\nDo you want to save your changes or discard them ?')


            answer = QMessageBox.question(self, title, msg, \
                QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel, QMessageBox.Save)

            if answer == QMessageBox.Cancel:
                return False

            elif answer == QMessageBox.Save:
                if 'text editor' in txt_wid:
                    ret = self.save('in')

                if 'output' in txt_wid:
                    ret = self.save('out')

                if ret == -3:
                    return False #Canceled

        return True




    def new(self):
        '''Clear the two text editors (input and output).'''

        if self._msg_box_save(title=tr('New - KRIS')):
            self.txt_in.setPlainText('')
            self.txt_out.setPlainText('')

        self.statusbar.showMessage(tr('Text editors cleared !'), 3000)


    def open(self, filename=False):
        '''
        Select, read, and set text from a file to `self.txt_in`.

        - filename : the filename, or False. If it is False, ask the user for it.

        Return :
            -1 if file not found ;
            -2 if encoding error ;
            None otherwise.
        '''

        if not self._msg_box_save(part='in', title=tr('Open - KRIS')):
            return -3

        if filename == False:
            fn = QFileDialog.getOpenFileName(self, tr('Open file') + ' - KRIS')[0]#, getcwd())[0]

            if fn in ((), ''):
                return -3 #Canceled

            if fn not in self.op_rec_dct:
                f = fn.split('/')[-1]
                self.op_rec_dct[fn] = QAction('{} [{}]'.format(f, fn), self)
                self.op_rec_dct[fn].triggered.connect(lambda: self.open(fn))
                self.open_recent_m.addAction(self.op_rec_dct[fn])

        else:
            fn = filename


        try:
            with open(fn, mode='r', encoding=str(self.encod_box.currentText())) as f:
                file_content = f.read()

        except FileNotFoundError:
            QMessageBox.critical(None, '!!! ' + tr('Error') + ' !!!', '<h2>' + tr('The file was NOT found') + ' !!!</h2>')
            return -1 #stop

        except UnicodeDecodeError:
            QMessageBox.critical(None, '!!! ' + tr('Encoding error') + ' !!!', \
                '<h2>' + tr('The file can\'t be decoded with this encoding') + '.</h2>')

            return -2 #stop

        self.txt_in.setPlainText(file_content)
        self.fn_in = fn

        self.statusbar.showMessage('File opened !', 3000)



    def is_saved(self):
        '''Return two bool, (txt_in_is_saved, txt_out_is_saved)'''

        return self.txt_in_is_saved, self.txt_out_is_saved


    def save(self, from_='in', as_=False):
        '''
        Save text into a file.

        - from_ : In ('in', 'out'). Used to choose from where read text to save it ;
        - as_ : a bool which indicates if clicked on 'Save' (True) or 'Save As' (False).

        Return -3 if canceled.
        '''

        #------Tests
        if from_ not in ('in', 'out'):
            raise ValueError('The argument `from_` is not in ("in", "out").')

        if as_ not in (True, False):
            raise ValueError('The argument `as_` is not a bool.')

        #------Get filename (fn) and text (txt)
        if from_ == 'in':
            txt = self.txt_in.toPlainText()

            if self.fn_in == None or as_:
                fn = QFileDialog.getSaveFileName(self, tr('Save file') + ' - KRIS', getcwd(), tr('Text files(*.txt);;All files(*)'))[0]
                self.fn_in = fn

            else:
                fn = self.fn_in

        else:
            txt = self.txt_out.toPlainText()

            if self.fn_out == None or as_:
                fn = QFileDialog.getSaveFileName(self, tr('Save file') + ' - KRIS', getcwd(), tr('Text files(*.txt);;All files(*)'))[0]
                self.fn_out = fn

            else:
                fn = self.fn_out

        if fn in ((), ''):
            return -3 # Canceled

        #------Write
        with open(fn, 'w', encoding=str(self.encod_box.currentText())) as f:
            f.write(txt)

        if from_ == 'in':
            self.txt_in_is_saved = True

        else:
            self.txt_out_is_saved = True

        self._set_save_lb_txt()

        t = {'in': tr('Input text'), 'out': tr('Output text')}[from_]
        self.statusbar.showMessage(tr('{} saved in file "{}" !').format(t, fn.split('/')[-1]), 3000)





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

                #---Show 'Ready' in status bar
                self.statusbar.showMessage(tr('Ready !'), 3000)

        self.locker = Lock(pwd, pwd_h, pwd_loop, tries)

        self.setDisabled(True)
        self.locker.show()

        self.locker.connect(chk_lock)


    #---------quit
    def quit(self, event=None):
        '''Quit the application. Check if there is text unsaved, and ask confirmation if there is.'''

        global app

        if not self._msg_box_save():
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

        app.focusChanged.connect(lambda old, new: win._show_wc(new))

        #-lock
        if lock:
            win.lock(3)

        #app.setPalette(KrisGuiStyle.dark_style(None))
        #app.aboutToQuit.connect(win.quit)

        sys.exit(app.exec_())



##-Widgets / windows
class CipherKeyWidget(QGroupBox):
    '''Defining the bar with the key box, encrypt and decrypt buttons, cipher selection.'''

    def __init__(self, style, parent=None):
        '''Initiate widget.'''

        #------ini
        super().__init__(parent)

        #self.style = style_test
        #self.app_style = GuiStyle()
        self.style = style #self.app_style.style_sheet

        #------Widgets
        #---keys
        keys_lay = QGridLayout()
        self.setLayout(keys_lay)

        self.key_label = QLabel(tr('Key :'))
        keys_lay.addWidget(self.key_label, 0, 0)

        #-RSA keys' box
        self.cipher_opt_keys = QComboBox()
        self.cipher_opt_keys.setStyleSheet(self.style)
        self.cipher_opt_keys.setObjectName('sec_obj')
        self.cipher_opt_keys.setMinimumSize(200, 0)
        #self.cipher_opt_keys.setMinimumContentsLength(30)
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
        self.cipher_nb_key.setMinimum(0)
        self.cipher_nb_key.setMaximum(989)
        self.cipher_nb_key.setStyleSheet(self.style)
        self.cipher_nb_key.setObjectName('sec_obj')
        self.cipher_nb_key.setMinimumSize(200, 0)
        self.cipher_nb_key.setHidden(True)
        keys_lay.addWidget(self.cipher_nb_key, 0, 1)#, alignment=Qt.AlignLeft)

        #-Buttons
        self.cipher_bt_enc = QPushButton(tr('&Encrypt'))
        #self.cipher_bt_enc.setShortcut('Ctrl+K')
        self.cipher_bt_enc.setStyleSheet(self.style)
        self.cipher_bt_enc.setObjectName('main_obj')
        self.cipher_bt_enc.setMaximumSize(90, 40)
        keys_lay.addWidget(self.cipher_bt_enc, 0, 2)#, alignment=Qt.AlignLeft)

        self.cipher_bt_dec = QPushButton(tr('&Decrypt'))
        #self.cipher_bt_enc.setShortcut('Ctrl+Shift+K')
        self.cipher_bt_dec.setStyleSheet(self.style)
        self.cipher_bt_dec.setObjectName('main_obj')
        self.cipher_bt_dec.setMaximumSize(90, 40)
        keys_lay.addWidget(self.cipher_bt_dec, 0, 3)#, alignment=Qt.AlignLeft)

        keys_lay.setColumnMinimumWidth(4, 20) #Spacing

        #-Ciphers' box
        self.cipher_opt_ciphs = QComboBox()
        self.cipher_opt_ciphs.activated[str].connect(self.chk_ciph)
        self.cipher_opt_ciphs.addItem(tr('-- Select a cipher --'))
        for k in ciphers_list:
            self.cipher_opt_ciphs.insertSeparator(500)
            self.cipher_opt_ciphs.addItems(ciphers_list[k])
        keys_lay.addWidget(self.cipher_opt_ciphs, 0, 7)#, alignment=Qt.AlignLeft)

        self.chk_ciph('')



    def chk_ciph(self, cipher):
        '''Check the cipher's combo box and dislable or not some widgets, and change the key's entry.'''

        if cipher in (*ciphers_list['KRIS'], *ciphers_list['RSA']): #RSA
            self.cipher_opt_keys.setHidden(False)
            self.cipher_ledit_keys.setHidden(True)
            self.cipher_nb_key.setHidden(True)

        elif cipher == 'SecHash': #QSpinBox
            self.cipher_nb_key.setHidden(False)
            self.cipher_ledit_keys.setHidden(True)
            self.cipher_opt_keys.setHidden(True)

        else: #QLinEdit
            self.cipher_ledit_keys.setHidden(False)
            self.cipher_opt_keys.setHidden(True)
            self.cipher_nb_key.setHidden(True)


        if cipher == tr('RSA signature'):
            self.cipher_bt_enc.setText(tr('Si&gn'))
            self.cipher_bt_dec.setText(tr('Chec&k'))

        elif cipher in ciphers_list['hash']:
            self.cipher_bt_enc.setText(tr('H&ash'))

        else:
            self.cipher_bt_enc.setText(tr('&Encrypt'))
            self.cipher_bt_dec.setText(tr('&Decrypt'))


        dis = cipher in ciphers_list['hash'][:-1]
        self.cipher_opt_keys.setDisabled(dis)
        self.cipher_ledit_keys.setDisabled(dis)
        self.cipher_nb_key.setDisabled(dis)

        self.cipher_bt_dec.setDisabled(cipher in ciphers_list['hash'])

        self.cipher_nb_key.setRange(0, 989)
        self.key_label.setText(tr('Key :'))

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



class SettingsWin(QMainWindow):
    '''Defining the Settings window.'''

    def __init__(self, style, app_style, parent=None):
        '''Initiate class'''

        #------Ini
        super().__init__(parent)
        self.setWindowTitle('KRIS v' + kris_version + ' | ' + tr('Settings'))
        self.setWindowIcon(QIcon('Style/KRIS_logo_by_surang.ico'))

        self.style = style
        self.app_style = app_style

        self._create_settings()


    def _create_settings(self):
        '''Create the widgets'''

        #------ini
        tab_stng = QWidget()

        tab_stng_lay = QGridLayout()
        tab_stng_lay.setContentsMargins(5, 5, 5, 5)
        tab_stng.setLayout(tab_stng_lay)

        #------widgets
        #---main style
        #-ini
        self.style_grp = QGroupBox('Style')
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
        self.main_style_std_chkb = QCheckBox(tr("&Use style's standard palette"))
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
        self.stng_pwd_grp = QGroupBox(tr('Change password'))
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
        self.stng_old_pwd.setEchoMode(QLineEdit.Password) # don't show pwd
        stng_pwd_form_lay.addRow(tr('Old password :'), self.stng_old_pwd)

        self.stng_pwd1 = QLineEdit()
        self.stng_pwd1.setMinimumSize(250, 0)
        self.stng_pwd1.setEchoMode(QLineEdit.Password)
        stng_pwd_form_lay.addRow(tr('New password :'), self.stng_pwd1)

        self.stng_pwd2 = QLineEdit()
        self.stng_pwd2.setMinimumSize(250, 0)
        self.stng_pwd2.setEchoMode(QLineEdit.Password)
        stng_pwd_form_lay.addRow(tr('Verify :'), self.stng_pwd2)

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
        self.stng_pwd_bt = QPushButton(tr('Change password'))
        stng_pwd_lay.addWidget(self.stng_pwd_bt, 1, 1, Qt.AlignRight)

        #-connection
        use_c_pwd = UseSettings(self.stng_old_pwd, self.stng_pwd1, self.stng_pwd2)

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
                None, tr('Done !'),
                '<h2>' + tr('The new lang will apply the next time you launch KRIS.') + '</h2>\n<h2>' + tr('Quit now ?') + '</h2>',
                QMessageBox.No | QMessageBox.Yes,
                QMessageBox.Yes
            )

            if rep == QMessageBox.Yes:
                win.quit()


        #-ini
        self.stng_lang_grp = QGroupBox(tr('Change Language'))
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
        self.stng_lang_bt = QPushButton(tr('Apply'))
        stng_lang_lay.addWidget(self.stng_lang_bt, 1, 0, Qt.AlignRight)
        self.stng_lang_bt.clicked.connect(chg_lang)

        #---Button close
        self.close_bt = QPushButton(tr('Close'))
        self.close_bt.clicked.connect(self.close)
        tab_stng_lay.addWidget(self.close_bt, 2, 1, Qt.AlignRight)

        #------show
        self.setCentralWidget(tab_stng)


    def use(style, app_style, parent=None):
        '''Function which launch this window.'''

        stg_win = SettingsWin(style, app_style, parent)
        stg_win.show()



##-Ciphers' keys management
#---------Generate RSA keys
class GenKeyWin(QMainWindow):
    '''Class which define a window which allow to generate RSA keys.'''

    def __init__(self, style, parent=None):
        '''Initiate the GenKeyWin window.'''

        #------ini
        super().__init__(parent)
        self.setWindowTitle(tr('Generate RSA keys') + ' — KRIS')

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
        RSA_lay.addWidget(QLabel(tr("Keys' size :")), 0, 0)

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
        RSA_lay.addWidget(QLabel(tr("Keys' name :")), 1, 0)

        #---line edit
        self.ledt = QLineEdit()
        self.ledt.setMinimumSize(250, 0)
        self.ledt.returnPressed.connect(self.gen)
        RSA_lay.addWidget(self.ledt, 1, 1)

        #---check box hexa
        self.chbt_h = QCheckBox(tr('Store in hexadecimal'))
        self.chbt_h.setChecked(True)
        RSA_lay.addWidget(self.chbt_h, 1, 2)


        #------One int arg (Label - QSpinBox)
        #---ini
        self.sp_wid = QWidget() #QGroupBox('Generate string key')
        main_lay.addWidget(self.sp_wid, 1, 0)

        sp_lay = QGridLayout()
        self.sp_wid.setLayout(sp_lay)

        #---widgets
        self.sp_lb = QLabel(tr("Key's length :"))
        sp_lay.addWidget(self.sp_lb, 0, 0)

        self.str1_lth = QSpinBox()
        self.str1_lth.setValue(15)
        self.str1_lth.setMinimumSize(150, 35)
        sp_lay.addWidget(self.str1_lth, 0, 1)


        #------buttons
        self.bt_cancel = QPushButton(tr('Cancel'))
        self.bt_cancel.setMaximumSize(55, 35)
        self.bt_cancel.clicked.connect(self.close)
        main_lay.addWidget(self.bt_cancel, 2, 0, Qt.AlignRight)

        self.bt_gen = QPushButton(tr('Generate'))
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
                QMessageBox.warning(None, tr('Key size error'), '<h2>{}</h2>'.format(err))
                return -3


        if ret != -3:
            self.close()

        return ret


    def gen_RSA(self):
        '''Collect the infos and give it to RsaKeys to generate the keys.'''

        global win

        name = self.ledt.text()
        if name == '':
            QMessageBox.critical(None, '!!! No name !!!', '<h2>' + tr('Please enter a name for the RSA keys !') + '</h2>')
            return -3 #Abort

        size = self.slider_sz.value()
        md_st = ('dec', 'hexa')[self.chbt_h.isChecked()]

        val = RSA.RsaKeys(name, 'gui').generate(size, md_stored=md_st)

        if val == -2: #The set of keys already exists
            rep = QMessageBox.question(
                None,
                'File error !',
                '<h2>' + tr('A set of keys named "{}" already exist !').format(name) + '</h2>\n<h2>' + tr('Overwite it !?') + '</h2>\n<h3>' + tr('This action can NOT be undone !!!') + '</h3>',
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )

            if rep == QMessageBox.Yes:
                val = RSA.RsaKeys(name, 'gui').generate(size, md_stored=md_st, overwrite=True)

            else:
                return -2

        win.ciph_bar.reload_keys()

        global RSA_keys_pwd
        RSA.RsaKeys(name, 'gui').encrypt(RSA_keys_pwd)


        QMessageBox.about(None, 'Done !', '<h2>' + tr('Your brand new RSA keys "{}" are ready !').format(name) + '</h2>\n<h3>' + tr('`n` size : {} bits').format(val[2]) + '</h3>')



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
        win.ciph_bar.reload_keys()


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
        win.ciph_bar.reload_keys()


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
        exp = ('decimal', 'hexadecimal')[self.rb_dec.isChecked()]

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
class UseCiphers:
    '''Class which allow to use the Cipher tab.'''

    def __init__(self, txt_in, txt_out, key_opt, key_ledit, key_nb, cipher, encod):
        '''Create the UseCiphers object.'''

        self.txt_in = txt_in
        self.txt_out = txt_out
        self.key_opt = key_opt
        self.key_ledit = key_ledit
        self.key_nb = key_nb
        self.cipher = cipher
        self.encod = encod


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


    def encrypt(self, formated_out=True):
        '''Encrypt the text, using the informations given in init.'''

        #------check
        if self._verify(0) == -3:
            return -3 #Abort

        #------ini
        txt = self.txt_in.toPlainText()
        if txt in ('', '\n'):
            QMessageBox.critical(None, '!!! No text !!!', '<h2>There is nothing to encrypt.</h2>')
            return -3 #Abort

        ciph = self.cipher.currentText()
        encod = self.encod.currentText()
        #bytes_md = self.txt_d.get_bytes()

        if ciph != 'RSA signature':
            key = self._get_key(0)

        else:
            key = self._get_key(1)

        if key == -3:
            return -3 #Abort


        #------encrypt with the good cipher
        if ciph in ciphers_list['KRIS']:
            AES_md = (256, 192, 128)[ciphers_list['KRIS'].index(ciph)]

            C = KRIS.Kris((key, None), AES_md, encod, interface='gui')
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
            md = 'str' #{'t' : 'str', 'b' : 'bytes'}[bytes_md]

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


        if ciph in (*ciphers_list['KRIS'], *ciphers_list['AES'], *ciphers_list['RSA']) and formated_out:
            msg_f = FormatMsg(msg_c).set(ciph, 'KRIS_v' + kris_version)
            self.txt_out.setPlainText(msg_f)

        else:
            self.txt_out.setPlainText(msg_c)


    def decrypt(self):
        '''Decrypt the text, using the informations given in init.'''

        global win

        #------ini
        raw_txt = self.txt_in.toPlainText()
        if raw_txt in ('', '\n'):
            QMessageBox.critical(None, '!!! No text !!!', '<h2>There is nothing to decrypt.</h2>')
            return -3 #Abort

        #------FormatMsg
        try:
            txt, ciph = FormatMsg(raw_txt).unset()[:-1] #don't take version

        except ValueError:
            txt = raw_txt
            ciph = self.cipher.currentText()

        else:
            if self.cipher.currentText() == tr('-- Select a cipher --'):
                self.cipher.setCurrentText(ciph)
                win.ciph_bar.chk_ciph(ciph)


        #------check
        if self._verify(1) == -3:
            return -3 #Abort

        encod = self.encod.currentText()
        bytes_md = 't' #self.txt_e.get_bytes()
        bytes_md_d = 't' #self.txt_d.get_bytes()

        if ciph != 'RSA signature':
            key = self._get_key(1)

        else:
            key = self._get_key(0)

        if key == -3:
            return -3 #Abort


        try:
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

        except Exception as err:
            QMessageBox.critical(None, '!!! Decryption error !!!', '<h2>An error occured during decryption. Maybe you tried to decrypt clear text, or the cipher text is not good formated.</h2>\n<h3>The text to be decrypted should be in the main text editor.</h3>\n<h4>Error :</h4>{}'.format(err))
            return -3 # Abort

        self.txt_out.setPlainText(msg_d)


#---------Settings
class UseSettings:
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
    chdir(RSA.chd_rsa('.', first=True, interface='gui')) #Todo: improve this (it is not shown since there is already 'elerias' and 'lasercata_3072' keys).

    #------Launch the GUI
    KrisGui.use()
