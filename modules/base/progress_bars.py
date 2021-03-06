#!/bin/python3
# -*- coding: utf-8 -*-

'''This script allow to show the progression, in console like in GUI, using progress bars'''


progress_bars__auth = 'Lasercata'
progress_bars__last_update = '05.03.2021'
progress_bars__version = '1.0_kris'


##-import
import sys
# from os import walk, getcwd, chdir
from datetime import datetime as dt

from modules.base import glb

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (QApplication, QMainWindow, QLabel, QGridLayout,
    QMessageBox, QWidget, QPushButton, QProgressBar)

#------Cracker's modules
# from modules.base.base_functions import list_files
# from modules.base.gui.GuiStyle import GuiStyle

##-Console
class ConsoleProgressBar:
    '''Class creating a console progress bar'''

    def __init__(self, bar_lth=50):
        '''initiate the variables'''

        self.load_lst = ('\b \b|', '\b \b/', '\b \b-', '\b \b\\') #For load.
        self.l_rep = [] #For bar.
        self.bar_lth = bar_lth

        self.i = 0



    def set(self, i, n):
        '''Show a console progress bar.

        i : the actual number ;
        n : the total number.
        '''

        k = round(i / n * self.bar_lth)

        if k not in self.l_rep: #To not slow the program by printing the same
            self.l_rep.append(k)

            if k > 0:
                print('\b'*(self.bar_lth + 2), end='', flush=True)

            print('|' + '#'*k + ' '*(self.bar_lth-k) + '|', end='', flush=True)


    def load(self, i=None, k=1, ret=False):
        '''Show a rotating bar. Return i + k, if ret is True. Usefull in while loops,
        to show that the program is processing, and to increment a number.
        '''
        if i == None:
            i = self.i

        print(self.load_lst[i % len(self.load_lst)], end='', flush=True)

        self.i = i + k
        if ret:
            return i + k


##-GUI
class GuiProgressBar(QWidget):
    '''Class creating a progess bar popup.'''

    def __init__(self, title='Processing ... ― Cracker', undetermined=False, verbose=True, mn=0, parent=None):
        '''Create the GuiProgressBar window.

        - undetermined : Should be True or False. Set it to True if the time duration is undetermined ;
        - verbose : Should be True or False. If True, increase verbosity ;
        - mn : the minimum of i, in set. Default is 0.
        '''

        #------ini
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumSize(500, 150)

        main_lay = QGridLayout()
        self.setLayout(main_lay)

        if undetermined:
            mx = 0

        else:
            mx = 100

        #------widgets
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, mx)
        self.progress_bar.setValue(0)
        main_lay.addWidget(self.progress_bar, 0, 0)

        #self.setCentralWidget(self.progress_bar)

        self.bt_stop = QPushButton('Stop')
        self.bt_stop.clicked.connect(self._stop)
        main_lay.addWidget(self.bt_stop, 1, 0, Qt.AlignRight)

        #------others
        self.lst = []
        self.verbose = verbose
        self.mn = mn


        #------show
        self.show()


    def setTitle(self, title):
        '''Change the window's title.'''

        self.setWindowTitle(title)


    def set(self, i, n):
        '''Set the progress bar to (i / n * 100) %. Close automaticly when i == n.'''

        QApplication.processEvents()

        if i == self.mn and self.verbose:
            self.t0 = dt.now()

        k = round(i / n * 100)

        if k not in self.lst:
            self.lst.append(k)
            self.progress_bar.setValue(k)

        self.lst = []

        if i == n:
            if self.verbose:
                t_end = dt.now() - self.t0
                QMessageBox.about(None, 'Done !', '<h2>Done in ' + str(t_end) + 's !</h2>')

            self.lst = []
            self.close()


    def load(self, i=None, k=1, ret=False):
        '''Increment of k the bar. Usefull with undetermined mode.

        i : the old number. If None, it take the actual bar value ;
        k : the number which increment the bar (bar.set(i + k)) ;
        ret : If True, return i + k
        '''

        QApplication.processEvents()

        if i == None:
            i = self.progress_bar.value()

        self.progress_bar.setValue(i + k)

        if ret:
            return i + k


    def _stop(self):
        self.close()
        if self.verbose:
            QMessageBox.about(None, 'Stoped', '<h1>The action has been be stoped.</h1>')

        raise KeyboardInterrupt('Stoped')


##-Gui Double progress bar
class GuiDoubleProgressBar(QWidget):
    '''Class creating a double progess bar popup.'''

    def __init__(self, title='Processing ... ― Cracker', verbose=True, mn=0, parent=None):
        '''Create the GuiProgressBar window.

        - verbose : Should be True or False. If True, increase verbosity ;
        - mn : the minimum of i, in set. Default is 0.
        '''

        #------ini
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumSize(500, 150)

        main_lay = QGridLayout()
        self.setLayout(main_lay)

        mx = 100

        #------widgets
        self.pb_top = QProgressBar()
        self.pb_top.setRange(0, mx)
        self.pb_top.setValue(0)
        main_lay.addWidget(self.pb_top, 0, 0)

        self.pb_bottom = QProgressBar()
        self.pb_bottom.setRange(0, mx)
        self.pb_bottom.setValue(0)
        main_lay.addWidget(self.pb_bottom, 1, 0)

        self.bt_stop = QPushButton('Stop')
        self.bt_stop.clicked.connect(self._stop)
        main_lay.addWidget(self.bt_stop, 2, 0, Qt.AlignRight)

        #------others
        self.lst_0 = []
        self.lst_1 = []
        self.verbose = verbose
        self.mn = mn


        #------show
        self.show()


    def setTitle(self, title):
        '''Change the window's title.'''

        self.setWindowTitle(title)


    def set(self, i, n, bar=0):
        '''
        Set the progress bar to (i / n * 100) %. Close automaticly when i == n.

        - bar : the bar to set to i/n. Should be 0 for the top, 1 for the bottom.
        '''

        QApplication.processEvents()

        if bar not in (0, 1):
            raise ValueError('The arg "bar" should be in (0, 1), but "{}" was found !!!'.format(bar))

        pb = (self.pb_top, self.pb_bottom)[bar]

        if i == self.mn and self.verbose and bar == 0:
            self.t0 = dt.now()

        k = round(i / n * 100)

        pb.setValue(k)

        if i == n and bar == 0:
            if self.verbose:
                t_end = dt.now() - self.t0
                QMessageBox.about(None, 'Done !', '<h2>Done in ' + str(t_end) + 's !</h2>')

            self.close()

    def load(self, i=None, k=1, ret=False, bar=0):
        '''Increment of k the bar. Usefull with undetermined mode.

        - i : the old number. If None, it take the actual bar value ;
        - k : the number which increment the bar (bar.set(i + k)) ;
        - ret : If True, return i + k ;
        - bar : the bar to increment. Should be 0 for the top, 1 for the bottom.
        '''

        QApplication.processEvents()

        if bar not in (0, 1):
            raise ValueError('The arg "bar" should be in (0, 1), but "{}" was found !!!'.format(bar))

        pb = (self.pb_top, self.pb_bottom)[bar]

        if i == None:
            i = pb.value()

        pb.setValue(i + k)

        if ret:
            return i + k


    def _stop(self):
        self.close()
        if self.verbose:
            QMessageBox.about(None, 'Stoped', '<h1>The action has been be stoped.</h1>')

        raise KeyboardInterrupt('Stoped')


##-test
if __name__ == '__main__':
    from time import sleep

    #------console
    pb = ConsoleProgressBar()
    i = 0
    while i < 50:
        i = pb.load(i, ret=True) #Don't work in the Konsole (on Linux KDE) (is not shown)
        sleep(0.05)

    print('---')

    for k in range(50):
        pb.set(k, 49) #Don't work in the Konsole (on Linux KDE) (is not shown)
        sleep(0.15)


    #input('pause')


    #------GUI
    class Test(QWidget):
        def __init__(self, parent=None):
            super().__init__(parent)

            lay = QGridLayout()
            self.setLayout(lay)
            lay.addWidget(QLabel('<h1>Test !</h1>'), 0, 0)

            bt = QPushButton('Test')
            bt.clicked.connect(self.test_pb)
            lay.addWidget(bt, 1, 0)

            bt2 = QPushButton('Test undetermined')
            bt2.clicked.connect(self.test_pb_2)
            lay.addWidget(bt2, 1, 1)

            bt3 = QPushButton('Test double bar')
            bt3.clicked.connect(self.test_pb_3)
            lay.addWidget(bt3, 1, 2)

            self.show()

        def test_pb(self):
            pb = GuiProgressBar(verbose=True)
            for k in range(0, 51):
                print(k, 50, '---', k/50*100)
                pb.set(k, 50)
                sleep(0.15)


        def test_pb_2(self):
            pb = GuiProgressBar(undetermined=True, verbose=True)

            i = 0
            while i < 100:
                i = pb.load(i, ret=True)
                sleep(0.15)


        def test_pb_3(self):
            pb = GuiDoubleProgressBar()

            for i in range(11):
                pb.set(i, 10, 0)

                for j in range(51):
                    pb.set(j, 50, 1)

                    sleep(0.01)



    app = QApplication(sys.argv)
    win = Test()
    app.exec_()
