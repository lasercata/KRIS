#!/bin/python3
# -*- coding: utf-8 -*-

TextEditor__auth = 'lasercata'
TextEditor__last_update = '26.11.2020'
TextEditor__version = '1.3.2'

##-import
import sys
from os import walk, getcwd, chdir

from PyQt5.QtCore import QSize, Qt
from PyQt5.QtWidgets import (QApplication, QMainWindow, QComboBox, QStyleFactory,
    QLabel, QGridLayout, QLineEdit, QMessageBox, QWidget, QPushButton, QCheckBox,
    QHBoxLayout, QGroupBox, QButtonGroup, QRadioButton, QTextEdit, QFileDialog)

#------KRIS' modules
from Languages.lang import translate as tr
from modules.base.base_functions import list_files
from modules.base.gui.GuiStyle import GuiStyle


##-ini
lst_encod = ('utf-8', 'ascii', 'latin-1')


##-main
class TextEditor(QWidget):
    '''Class creating a TextEditor object.'''

    def __init__(self, txt_width=500, txt_height=220, txt_text=tr('Text :'), parent=None):
        '''Create the text.'''

        #------ini
        super().__init__(parent)

        self.fn = tr('-- Select a file --')
        self.lst_f_hist = []

        self.style = GuiStyle().style_sheet

        #------widgets
        #---layout
        main_lay = QGridLayout()
        main_lay.setRowStretch(0, 1)
        self.setLayout(main_lay)

        #---text
        self.rb_txt = QRadioButton(txt_text)
        self.rb_txt.setChecked(True)
        main_lay.addWidget(self.rb_txt, 0, 0)

        self.txt = QTextEdit()
        self.txt.setMinimumSize(txt_width, txt_height)
        self.txt.setAcceptRichText(False)
        self.txt.setStyleSheet(self.style)
        self.txt.setObjectName('orange_border_hover')
        main_lay.addWidget(self.txt, 0, 1, 1, 7)

        #---clear
        self.bt_clear = QPushButton(tr('Clear'))
        self.bt_clear.setMaximumSize(len(tr('Clear'))*13, 50)
        self.bt_clear.clicked.connect(self.clear)
        main_lay.addWidget(self.bt_clear, 0, 0, alignment=Qt.AlignTop)


        #---file
        #-radio button
        self.rb_fn = QRadioButton(tr('File') + ' :')
        main_lay.addWidget(self.rb_fn, 1, 0)

        #-option menu files
        self.lst_f = (tr('-- Select a file --'), *list_files())
        self.opt_fn = QComboBox()
        self.opt_fn.addItems(self.lst_f)
        self.opt_fn.insertSeparator(1)
        self.opt_fn.activated[str].connect(self.select_fn)
        main_lay.addWidget(self.opt_fn, 1, 1, 1, 2)

        #-buttons
        self.bt_select = QPushButton(tr('Select a file ...'))
        self.bt_select.setMaximumSize(len(tr('Select a file ...'))*13, 50)
        self.bt_select.clicked.connect(self.select_fn)
        main_lay.addWidget(self.bt_select, 1, 3)

        self.bt_select_load = QPushButton(tr('Select and load') + ' ▲')
        self.bt_select_load.setMaximumSize((len(tr('Select and load'))+2)*13, 50)
        self.bt_select_load.clicked.connect(self.select_load_fn)
        main_lay.addWidget(self.bt_select_load, 1, 4)

        self.bt_load = QPushButton(tr('Load') + ' ▲')
        self.bt_load.setMaximumSize((len(tr('Load'))+2)*13, 50)
        self.bt_load.clicked.connect(self.load_fn)
        main_lay.addWidget(self.bt_load, 1, 5)

        self.bt_save = QPushButton(tr('Save') + ' ▼')
        self.bt_save.setMaximumSize((len(tr('Save'))+2)*13, 50)
        self.bt_save.clicked.connect(self.save_fn)
        main_lay.addWidget(self.bt_save, 1, 6)

        self.bt_reload = QPushButton(tr('Reload'))
        self.bt_reload.setMaximumSize(len(tr('Reload'))*13, 50)
        self.bt_reload.clicked.connect(self.reload)
        main_lay.addWidget(self.bt_reload, 1, 7, alignment=Qt.AlignRight)

        #-encoding
        self.rb_encod = QRadioButton(tr('Text encoding :'))
        main_lay.addWidget(self.rb_encod, 2, 1)
        self.opt_encod = QComboBox()
        self.opt_encod.addItems(lst_encod)
        main_lay.addWidget(self.opt_encod, 2, 2)

        rb_lay = QHBoxLayout()
        main_lay.addLayout(rb_lay, 2, 3, 1, 3)

        #-binary mode
        self.rb_bin = QRadioButton(tr('Binary mode'))
        rb_lay.addWidget(self.rb_bin)

        #-hexa mode
        self.rb_hexa = QRadioButton(tr('Hexa mode'))
        rb_lay.addWidget(self.rb_hexa)

        #-bytes mode
        self.rb_bytes = QRadioButton(tr('Bytes mode'))
        rb_lay.addWidget(self.rb_bytes)

        self.rb_txt.toggled.connect(self.check_bytes)
        self.rb_fn.toggled.connect(self.check_bytes)
        self.rb_fn.toggled.connect(self.select_fn_rb)
        self.rb_bytes.toggled.connect(self.check_bytes)


        self.rb_bt_grp1 = QButtonGroup()
        self.rb_bt_grp1.addButton(self.rb_txt)
        self.rb_bt_grp1.addButton(self.rb_fn)

        self.rb_bt_grp2 = QButtonGroup()
        self.rb_bt_grp2.addButton(self.rb_encod)
        self.rb_bt_grp2.addButton(self.rb_bin)
        self.rb_bt_grp2.addButton(self.rb_hexa)
        self.rb_bt_grp2.addButton(self.rb_bytes)


        #------show
        self.setMinimumSize(txt_width+100, txt_height+110)

        self.check_bytes()


    #------check
    def check_bytes(self):
        '''
        Check the bytes mode checkbutton's status to dislable or not the encoding menu,
        and check the radiobuttons to dislable or not the bytes checkbuttons.
        '''

        if self.rb_txt.isChecked():
            self.opt_encod.setDisabled(False)
            self.rb_bytes.setDisabled(True)
            self.rb_bytes.setChecked(False)

        elif self.rb_fn.isChecked():
            self.rb_bytes.setDisabled(False)

            if self.rb_bytes.isChecked():
                self.opt_encod.setDisabled(True)

            else:
                self.opt_encod.setDisabled(False)


    #------clear
    def clear(self):
        '''Clear the text widget.'''

        if self.txt.toPlainText() != '':
            sure = QMessageBox.question(self, tr('Sure') + ' ?', '<h2>' + tr('Are you sure ?') + '</h2>', \
                QMessageBox.Yes | QMessageBox.Cancel, QMessageBox.Yes)

            if sure != QMessageBox.Yes:
                return None

            self.txt.clear()


    #------select_fn_rb
    def select_fn_rb(self):
        '''
        Activated when pressing the radio button "plain file".
        If no file is selected, launch select_fn.
        '''

        if self.opt_fn.currentText() == tr('-- Select a file --'):
            self.select_fn()

        self.rb_bytes.setChecked(True)
        self.check_bytes()



    #---------select file "fn"
    def select_fn(self, fn=False):
        '''
        Select a file using the PyQt5 file dialog.

        fn : the filename. It is given when choosing with the combo box.
        '''

        if fn == False:
            fn = QFileDialog.getOpenFileName(self, tr('Open file'), getcwd())[0]

        if fn in ((), ''): #cancel
            fn = tr('-- Select a file --')
            self.fn = fn
            self.rb_txt.setChecked(True)
            self.rb_fn.setChecked(False)
            return None

        self.fn = fn

        f = fn.split('/')[-1]

        if f not in self.lst_f:
            if len(self.lst_f_hist) == 0:
                self.opt_fn.insertSeparator(10000)

            if fn not in self.lst_f_hist:
                self.lst_f_hist.append(fn)

            self.opt_fn.addItem(fn)
            self.opt_fn.setCurrentText(fn)

        else:
            self.opt_fn.setCurrentText(f)


    #------select and load
    def select_load_fn(self):
        '''Uses the functions select and load.'''

        self.select_fn()
        self.load_fn()


    #------load file "fn"
    def load_fn(self):
        '''Load the selected file to the text widget.'''

        #self.fn = self.opt_fn.currentText()

        if self.fn == tr('-- Select a file --'):
            QMessageBox.warning(QWidget(), '!!! ' + tr('No file selected') + ' !!!', \
                '<h1>' + tr('Please select a file') + ' !</h1>\n' + tr('Or use the button "Select and load"'))

            return -3


        try:
            if self.rb_encod.isChecked():
                with open(self.fn, mode='r', encoding=str(self.opt_encod.currentText())) as f:
                    file_content = f.read()

            else:
                with open(self.fn, mode='rb') as f:
                    file_content = f.read()
                if self.rb_hexa.isChecked() or self.rb_bin.isChecked():
                    file_content = file_content.hex()
                    if self.rb_bin.isChecked():
                        d = {'0': '0000', '1': '0001', '2': '0010', '3': '0011', '4': '0100', '5': '0101', '6': '0110', '7': '0111', '8': '1000', '9': '1001', 'a': '1010', 'b': '1011', 'c': '1100', 'd': '1101', 'e': '1110', 'f': '1111'}
                        for k in d:
                            file_content = file_content.replace(k, d[k])


        except FileNotFoundError:
            QMessageBox.critical(QWidget(), '!!! ' + tr('Error') + ' !!!', '<h2>' + tr('The file was NOT found') + ' !!!</h2>')
            return -1 #stop

        except UnicodeDecodeError:
            QMessageBox.critical(QWidget(), '!!! ' + tr('Encoding error') + ' !!!', \
                '<h2>' + tr('The file can\'t be decoded with this encoding') + ' !!!</h2>\n' + tr('Try bytes mode'))

            return -2 #stop

        txt = self.txt.toPlainText()

        if txt != '':
            sure = QMessageBox.question(self, '!!! ' + tr('Erase Text data') + ' !!!', \
                '<h2>' + tr('Text is detected in the box ! Remplace by the file\'s data ?') + '</h2>', \
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

            if sure != QMessageBox.Yes:
                return -3 #stop

        if type(file_content) == str:
            self.txt.setPlainText(file_content)

        elif type(file_content) == bytes:
            try:
                self.txt.setPlainText(file_content.decode())

            except UnicodeDecodeError:
                QMessageBox.critical(None, '!!! ' + tr('Decoding error') + ' !!!', '<h2>' + tr("The file can't be decoded in bytes mode") + '!</h2>')
                return -2


    #------save in file "fn"
    def save_fn(self, data=False):
        '''
        Save the content of the text widget in a file.

        data : the text to write. If False, write text which is in the text widget. Default is False.

        return -3 if canceled or aborted, -2 if an encoding error occur, None otherwise.
        '''

        if self.fn == tr('-- Select a file --'):
            filename = QFileDialog.getSaveFileName(self, tr('Save file'), getcwd())[0]

            if filename in ((), ''):
                return -3 #Canceled
        else:
            filename = self.fn

        try:
            if not self.rb_bytes.isChecked():
                with open(filename, 'r', encoding=str(self.opt_encod.currentText())) as f:
                    line = f.readline()

            else:
                with open(filename, mode='rb') as f:
                    line = f.readline()

        except FileNotFoundError: #the file can be created, it don't exists
            pass

        except UnicodeDecodeError:
            pass

        else:
            if line not in ('', '\n'):
                sure = QMessageBox.question(self, '!!! ' + tr('Erase file data') + ' !!!', \
                    '<h2>' + tr('The selected file is NOT empty') + ' !!!</h2>\n<h3>' + tr('Overwrite with text data ?') + '</h3>', \
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

                if sure != QMessageBox.Yes:
                    return -3 #Aborted

        if data == False:
            txt = self.txt.toPlainText()

        else:
            txt = data

        if txt == '':
            emp = QMessageBox.question(self, tr('Text is empty'), \
                '<h2>' + tr('There is no text in the box') + '.\n' + tr('Write anyway ?') + '</h2>', QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

            if emp != QMessageBox.Yes:
                return -3 #Aborted

        if self.rb_encod.isChecked():
            with open(filename, 'w', encoding=str(self.opt_encod.currentText())) as f:
                if type(txt) == str:
                    f.write(txt)

                else:
                    f.write(txt.decode())

        else:
            try:
                if not self.rb_bytes.isChecked():
                    if self.rb_bin.isChecked():
                        if len(txt) % 8 != 0:
                            QMessageBox.critical(QWidget(), '!!! ' + tr('Value Error') + ' !!!', \
                    '<h2>' + tr('The number of binary digits is not a multiple of 8') + ' !!!</h2>')
                            return -2 #stop

                        else:
                            d = {'0000': '0', '0001': '1', '0010': '2', '0011': '3', '0100': '4', '0101': '5', '0110': '6', '0111': '7', '1000': '8', '1001': '9', '1010': 'a', '1011': 'b', '1100': 'c', '1101': 'd', '1110': 'e', '1111': 'f'}
                            txt2 = ""
                            for k in range(len(txt)//4):
                                if txt[k*4:k*4+4] not in d:
                                    QMessageBox.critical(QWidget(), '!!! ' + tr('Value Error') + ' !!!', \
                                    '<h2>' + tr('A binary number is composed only of 0 and 1') + ' !!!</h2>')
                                    return -2 #stop
                                else:
                                    txt2 += d[txt[k*4:k*4+4]]
                            txt = txt2

                    try:
                        if len(txt) % 2 != 0:
                            QMessageBox.critical(QWidget(), '!!! ' + tr('Value Error') + ' !!!', \
                    "<h2>The number of hexadecimal digits is not a multiple of 2 !!!</h2>")
                            return -2 #stop
                        txt = bytes.fromhex(txt)
                    except ValueError:
                        QMessageBox.critical(QWidget(), '!!! ' + tr('Value Error') + ' !!!', \
                    '<h2>' + tr('Error in the conversion of hexadecimal to bytes') + ' !!!</h2>')
                        return -2 #stop

                with open(filename, mode='wb') as f:
                    if type(txt) == str:
                        f.write(txt.encode(encoding=str(self.opt_encod.currentText())))

                    else:
                        f.write(txt)

            except UnicodeEncodeError:
                QMessageBox.critical(QWidget(), '!!! ' + tr('Encoding error') + ' !!!', \
                    '<h2>' + tr("The file can't be encoded with this encoding") + ' !!!</h2>')
                return -2 #stop


        self.reload()
        QMessageBox.about(QWidget(), tr('Done') + ' !', '<h2>' + tr('Your text has been be wrote') + ' !</h2>')


    #------read_file
    def read_file(self, fn, bytes_md=False, encod='utf-8', silent=True):
        '''
        Read the content of a file and return its content in a string.

        fn : filename ;
        bytes_md : the bytes mode. Should be False for text (default) or True for binary (bytes) ;
        encod : the encoding. Should be "utf-8", "latin-1", "ascii". Default is "utf-8" ;
        silent : should be a bool. If False, show error message box in case if one occur.

        return -1 if the file "fn" was not found, -2 if an encoding error occur, the text otherwise.
        '''

        if bytes_md not in (True, False):
            return 'The bytes_md should be "True" or "False", but "' + str(bytes_md) + '" was found !!!'

        try:
            if not bytes_md: #text
                with open(fn, mode='r', encoding=encod) as file:
                    txt = file.read()

            else:
                with open(fn, mode='rb') as file:
                    txt = file.read()

        except FileNotFoundError:
            if not silent:
                QMessageBox.critical(QWidget(), '!!! ' + tr('File error') + ' !!!', \
                    '<h2>' + tr('The file') + ' "' + str(fn) + '"' + tr(' was NOT found') + ' !!!</h2>')
            return -1

        except UnicodeDecodeError:
            if not silent:
                QMessageBox.critical(QWidget(), '!!! ' + tr('Encoding error') + ' !!!', \
                    '<h2>' + tr('The file can\'t be decoded with this encoding') + ' !!!</h2>')
            return -2

        return txt

    #------reload
    def reload(self):
        '''
        Function which reload the files combo boxes.
        It can be used if a new file was copied while running, for example.
        '''

        self.lst_f = (tr('-- Select a file --'), *list_files(), *self.lst_f_hist)

        self.opt_fn.clear()
        self.opt_fn.addItems((tr('-- Select a file --'), *list_files()))
        self.opt_fn.insertSeparator(1)
        self.opt_fn.insertSeparator(10000)
        if len(self.lst_f_hist) > 0:
            self.opt_fn.addItems(self.lst_f_hist)
            self.opt_fn.insertSeparator(20000)

        if self.fn not in self.lst_f:
            self.fn = tr('-- Select a file --')
            self.opt_fn.setCurrentText(tr('-- Select a file --'))

        else:
            self.opt_fn.setCurrentText(self.fn)


    #------get encoding
    def get_encod(self):
        '''Return the currend selected encoding.'''

        return self.opt_encod.currentText()


    #------get bytes mode
    def get_bytes(self):
        '''Return the bytes, either 't' for text, or 'b' for bytes.'''

        return ('t', 'b')[self.rb_bytes.isChecked()]


    #------getText
    def getText(self, silent=False, from_=None):
        '''
        Return the text selected by the user.

        silent : should be a bool. If False, show popup pointing out the error, if one occur ;
        from_ : where read. Can be None, 'text', 'file'. if None, check the radiobutton. Default is None.

        Return :
            -1 if the file was not found ;
            -2 if an encoding error occur ;
            -3 if aborted ;
            The text otherwise.
        '''

        if from_ not in (None, 'text', 'file'):
            raise ValueError(tr('Parameter "from_" should be None, "text" or "file", but') + ' "' + str(from_) + '" ' + tr('was found') + ' !!!')

        txt_t = self.txt.toPlainText()

        if self.opt_fn.currentText() != tr('-- Select a file --'):
            txt_f = self.read_file(self.opt_fn.currentText(), \
                self.rb_bytes.isChecked(), self.opt_encod.currentText())

        else:
            txt_f = None


        if from_ == 'text':
            return txt_t

        elif from_ == 'file':
            return txt_f


        if self.rb_txt.isChecked(): # Text is in the text widget
            if txt_t == '' and txt_f not in (None, ''):
                rep = QMessageBox.question(self, '!!! ' + tr('Text is empty') + ' !!!', \
                    '<h3>' + tr('The text widget seem to be empty') + '.</h3>\n<h2>' + tr('Read the file ?') + '</h2>', \
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)

                if rep == QMessageBox.Yes:
                    return txt_f

                else:
                    return -3 # Abort

            elif txt_t == '':
                if not silent:
                    QMessageBox.critical(QWidget(), '!!! ' + tr('Text is empty') + ' !!!', \
                        '<h2>' + tr('The text widget is empty') + ' !!!</h2>')
                return -3 #Abort

            return txt_t


        else: # Text is in the file
            if txt_f == -1:
                if not silent:
                    QMessageBox.critical(QWidget(), '!!! ' + tr('File error') + ' !!!', \
                        '<h2>' + tr('The file') + ' "' + str(fn) + '" ' + tr('was NOT found') + ' !!!</h2>')
                return -1

            elif txt_f == -2:
                if not silent:
                    QMessageBox.critical(QWidget(), '!!! ' + tr('Encoding error') + ' !!!', \
                        '<h2>' + tr("The file can't be decoded with this encoding") + ' !!!</h2>')
                return -2


            if txt_f == None and txt_t != '':
                rep = QMessageBox.question(self, '!!! ' + tr('No file selected') + ' !!!', \
                    '<h3>' + tr('You did not select a file') + ' !!!</h3>\n<h2>' + tr('Read the text widget ?') + '</h2>', \
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)

                if rep == QMessageBox.Yes:
                    return txt_t

                else:
                    return -3 # Abort

            elif txt_f == None:
                if not silent:
                    QMessageBox.critical(QWidget(), '!!! ' + tr('No file selected') + ' !!!', \
                        '<h2>' + tr('Please select a file') + ' !</h2>')
                return -3


            if txt_f in ('', b'') and txt_t != '':
                rep = QMessageBox.question(self, '!!! ' + tr('File is empty') + ' !!!', \
                    '<h3>' + tr('The file seem to be empty') + '.</h3>\n<h2>' + tr('Read the text widget ?') + '</h2>', \
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)

                if rep == QMessageBox.Yes:
                    return txt_t

                else:
                    return -3 # Abort

            elif txt_f in ('', b''):
                if not silent:
                    QMessageBox.critical(QWidget(), '!!! ' + tr('File is empty') + ' !!!', '<h2>' + tr('The file is empty') + ' !!!</h2>')
                return -3

            return txt_f




    def setText(self, txt):
        '''Fill the text widget or the file with txt, according to the radiobuttons.'''

        txt_t = self.txt.toPlainText()

        if self.opt_fn.currentText() != tr('-- Select a file --'):
            txt_f = self.read_file(self.opt_fn.currentText(), \
                self.rb_bytes.isChecked(), self.opt_encod.currentText())

        else:
            txt_f = None


        if self.rb_txt.isChecked(): # The text widget is chosen
            if txt_t != '' and txt_f == '':
                rep = QMessageBox.question(self, '!!! ' + tr('Text is not empty') + ' !!!', \
                    '<h2>' + tr('The text widget is not empty, but the file is') + '.</h2>\n<h3>' + tr('Write the file (Yes) or overwrite text (Ignore) ?') + '</h3>', \
                    QMessageBox.Yes | QMessageBox.Ignore | QMessageBox.Cancel, QMessageBox.Ignore)

                if rep == QMessageBox.Yes:
                    self.save_fn(txt)

                elif rep == QMessageBox.Ignore:
                    self.txt.setPlainText(txt)

                else:
                    return -3 # Abort

            else:
                self.txt.setPlainText(txt)


        else: # The file is chosen
            if txt_f == -1:
                rep = QMessageBox.question(self, '!!! ' + tr('File error') + ' !!!', \
                    '<h2>' + tr('The file') + ' "' + str(fn) + '" ' + tr('was NOT found') + ' !!!</h2>\n<h3>' + tr('Write in the text widget ?') + '</h3>', \
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)

                if rep == QMessageBox.Yes:
                    self.txt.setPlainText(txt)

                else:
                    return -1

            else:
                self.save_fn(txt)



##-test
if __name__ == '__main__':

    class Test(QWidget):
        def __init__(self, parent=None):
            #------ini
            super().__init__(parent)
            self.setWindowTitle('Test TextEditor')

            #------widgets
            #---layout
            main_lay = QGridLayout()
            self.setLayout(main_lay)

            #---text_1
            txt_1 = TextEditor()
            main_lay.addWidget(txt_1, 0, 0, 4, 1)

            bt_reload_1 = QPushButton('Reload_1')
            bt_reload_1.clicked.connect(txt_1.reload)
            main_lay.addWidget(bt_reload_1, 0, 1)

            bt_cd = QPushButton('cd ..')
            bt_cd.clicked.connect(lambda: chdir('..'))
            main_lay.addWidget(bt_cd, 1, 1)

            bt_get = QPushButton('Get')
            bt_get.clicked.connect(lambda: print(txt_1.getText()))
            main_lay.addWidget(bt_get, 2, 1)

            bt_set = QPushButton('Set')
            bt_set.clicked.connect(lambda: txt_1.setText('test'))
            main_lay.addWidget(bt_set, 3, 1)


            main_lay.addWidget(QLabel('-'*100), 5, 0, alignment=Qt.AlignCenter)


            txt_2 = TextEditor()
            main_lay.addWidget(txt_2, 6, 0)

            #------show
            self.show()


        def use():
            app = QApplication(sys.argv)
            win = Test()
            sys.exit(app.exec_())


    Test.use() #don't work because 'list_files' is not def and is in ../../base/base_functions.py
