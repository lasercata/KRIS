#!/bin/python3
# -*- coding: utf-8 -*-

GuiStyle__auth = 'Lasercata'
GuiStyle__last_update = '12.04.2021'
GuiStyle__version = '1.0.2'

##-imports
from PyQt5.QtCore import QSize, Qt
from PyQt5.QtGui import QIcon, QPixmap, QCloseEvent, QPalette, QColor
from PyQt5.QtWidgets import (QApplication, QMainWindow, QComboBox, QStyleFactory,
    QLabel, QGridLayout, QLineEdit, QMessageBox, QWidget, QPushButton, QCheckBox,
    QHBoxLayout, QGroupBox, QButtonGroup, QRadioButton, QTextEdit, QFileDialog)


##-main
class GuiStyle:
    '''Class which define a GUI style'''


    default_style = {
        'main_style' : 'Breeze',

        'main' : '#ff4500', 'main_graz' : 'aa2500',
        'second' : '#0ee', 'sec_hover' : '#0fffff',

        'hover_color' : '#000', 'disabled' : 'grey',

        'path_grp' : 'rgba(255, 69, 0, 0.5)', 'path_over' : '#0f0', 'path_bt' : '#0b0', \
        'path_graz_1' : '#0a0', 'path_graz_2' : '#0d0',

        'bt_info' : '#0ee', 'info_graz_1' : '#088', 'info_graz_2' : '#0ff',

        'bt_lock' : 'orange', 'lock_graz' : '#a50',

        'bt_quit' : '#f00', 'quit_graz' : '#800'
    }


    def __init__(self, style_dict=default_style, set_better_style=False):
        '''Create a GUI style.

        - style_dict : the dictonary containing the style colors ;
        - set_better_style : a bool indicating if set by default 'Breeze' if here or 'Dark fusion'.
        '''

        self.style_dict = style_dict
        self.style_sheet = self.to_css(style_dict)

        self.main_styles = (*QStyleFactory.keys(), 'Dark fusion')

        if style_dict['main_style'] not in self.main_styles:
            self.main_style_name = 'Dark fusion'

        else:
            self.main_style_name = style_dict['main_style']


        if set_better_style:
            self.set_style(self.main_style_name)

        #todo: check for file in ~/.Cracker !


    #todo: def save_style
    #todo: def open_style



    def dark_style(self):
        '''Return a dark main style'''

        dark_palette = QPalette() #todo: set better colors !

        dark_palette.setColor(QPalette.Window, QColor(45, 49, 54))
        dark_palette.setColor(QPalette.WindowText, Qt.white)
        dark_palette.setColor(QPalette.Base, QColor(25, 25, 25))
        dark_palette.setColor(QPalette.AlternateBase, QColor(45, 49, 54))
        dark_palette.setColor(QPalette.ToolTipBase, Qt.white)
        dark_palette.setColor(QPalette.ToolTipText, Qt.white)
        dark_palette.setColor(QPalette.Text, Qt.white)
        dark_palette.setColor(QPalette.Button, QColor(45, 49, 54))
        dark_palette.setColor(QPalette.ButtonText, Qt.white)
        dark_palette.setColor(QPalette.BrightText, QColor(255, 69, 0))#Qt.red)
        dark_palette.setColor(QPalette.Link, QColor(255, 69, 0))
        dark_palette.setColor(QPalette.Highlight, QColor(255, 69, 0))
        dark_palette.setColor(QPalette.HighlightedText, Qt.black)

        return dark_palette



    def set_style(self, style_name, std_palette=True, r=True):
        '''Change the GUI style to "style_name".'''

        if r: # Recursive, to run two time this because style don't apply well else.
            self.set_style(style_name, std_palette, False)

        self.main_style_name = style_name

        if style_name == 'Dark fusion':
            palette = self.dark_style()

            QApplication.setStyle("Fusion")
            QApplication.setPalette(palette)

            return None #stop

        self.main_style_palette = QApplication.palette()
        QApplication.setStyle(QStyleFactory.create(style_name))

        if std_palette:
            QApplication.setPalette(QApplication.style().standardPalette())
        else:
            QApplication.setPalette(self.main_style_palette)



    def to_css(self, dct):
        '''Return a css sheet using the dict dct.'''

        css_sheet = '''
/*---------Path bar */
QGroupBox#path_grp {
    border: 1px solid ''' + dct['path_grp'] + ''';
    border-radius: 3px;
}


QLineEdit#path_entry:hover {
    border: 1px solid ''' + dct['path_over'] + ''';
    border-radius: 3px;
}
QLineEdit#path_entry:focus {
    border: 1px solid ''' + dct['path_bt'] + ''';
    border-radius: 3px;
}


QPushButton#path_bt:hover {
    color: ''' + dct['path_over'] + ''';
    border: 1px solid ''' + dct['path_bt'] + ''';
    border-radius: 3px;
}
QPushButton#path_bt:focus {
    color: ''' + dct['hover_color'] + ''';
    background-color: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: 0 ''' + dct['path_graz_1'] + ''', stop: 1 ''' + dct['path_graz_2'] + ''');
    border: 1px solid ''' + dct['path_bt'] + ''';
    border-radius: 3px;
}


/*------Home */
QPushButton#bt_info {
    color: ''' + dct['bt_info'] + ''' ;
}

QPushButton#bt_info:hover {
    background-color: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: 0 ''' + dct['info_graz_1'] + ''', stop: 1 ''' + dct['info_graz_2'] + ''');
    color: ''' + dct['hover_color'] + ''';
    border: 1px solid ''' + dct['bt_info'] + ''';
    border-radius: 3px;
}

QPushButton#bt_info:focus {
    background-color: ''' + dct['bt_info'] + ''';
    color: ''' + dct['hover_color'] + ''';
    border: 1px solid ''' + dct['bt_info'] + ''';
    border-radius: 3px;
}


QPushButton#bt_lock {
    color: ''' + dct['bt_lock'] + ''';
}

QPushButton#bt_lock:hover {
    background-color: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: 0 ''' + dct['lock_graz'] + ''', stop: 1 ''' + dct['bt_lock'] + ''');
    color: ''' + dct['hover_color'] + ''';
    border: 1px solid ''' + dct['bt_lock'] + ''';
    border-radius: 3px;
}

QPushButton#bt_lock:focus {
    background-color: ''' + dct['bt_lock'] + ''';
    color: ''' + dct['hover_color'] + ''';
    border: 1px solid ''' + dct['bt_lock'] + ''';
    border-radius: 3px;
}


QPushButton#bt_quit {
    color: ''' + dct['bt_quit'] + ''';
}

QPushButton#bt_quit:hover {
    background-color: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: 0 ''' + dct['quit_graz'] + ''', stop: 1 ''' + dct['bt_quit'] + ''');
    color: ''' + dct['hover_color'] + ''';
    border: 1px solid ''' + dct['bt_quit'] + ''';
    border-radius: 3px;
}

QPushButton#bt_quit:focus {
    background-color: ''' + dct['bt_quit'] + ''';
    color: ''' + dct['hover_color'] + ''';
    border: 1px solid ''' + dct['bt_quit'] + ''';
    border-radius: 3px;
}

/*---------Main objects */
QPushButton#main_obj {
    color: ''' + dct['main'] + ''';
}
QPushButton#main_obj:hover {
    border: 1px solid ''' + dct['main'] + ''';
    border-radius: 3px;
}
QPushButton#main_obj:focus {
    background-color: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: 0 ''' + dct['main_graz'] + ''', stop: 1 ''' + dct['main'] + ''');
    color: ''' + dct['hover_color'] + ''';
    border: 1px solid ''' + dct['main'] + ''';
    border-radius: 3px;
}

#main_obj:disabled {
    color: ''' + dct['disabled'] + ''';
}


/*------Seconds objects */
QComboBox#sec_obj, QLineEdit#sec_obj {
    color: ''' + dct['second'] + ''';
}
QComboBox#sec_obj:hover, QLineEdit#sec_obj:hover {
    color: ''' + dct['sec_hover'] + ''';
}
QComboBox#sec_obj:disabled, QLineEdit#sec_obj:disabled {
    color: ''' + dct['disabled'] + ''';
}


/*---------others */
#orange_border_hover:hover {
    border: 1px solid ''' + dct['main'] + ''';
    border-radius: 3px;
}
        '''

        return css_sheet
