#!/bin/python3
# -*- coding: utf-8 -*-

'''This program allow you to encrypt and decrypt with RSA cipher.'''

RSA__auth = 'Lasercata, Elerias'
RSA__last_update = '13.11.2021'
RSA__version = '4.3_kris'


##-import
#---------KRIS' modules
#from modules.base.console.color import color, cl_inp, cl_out, c_error, c_wrdlt, c_output, c_prog, c_succes
from modules.base.base_functions import chd, NewLine
from modules.base.FormatMsg import FormatMsg
from modules.base.progress_bars import *
from modules.ciphers.hashes.hasher import Hasher
from modules.base import glb
from modules.base.arithmetic import mult_inverse
from modules.base.mini_prima import isSurelyPrime
from modules.base.AskPwd import AskPwd
from Languages.lang import translate as tr

from modules.ciphers.kris.AES import AES

#---------packages
import math
from random import randint
from secrets import randbits

from ast import literal_eval #Safer than eval
from getpass import getpass

from datetime import datetime as dt
from time import sleep

from os import chdir, mkdir, getcwd, listdir, rename, remove
from os.path import expanduser, isfile, isdir
from shutil import copy

#if glb.interface == 'gui':
from PyQt5.QtWidgets import QMessageBox

#---------csv
import csv


#------from b_cvrt
def sp_grp(n, grp, sep=' ', rev_lst=True):
    '''Base of space. Return n with spaced groups of grp.
    .n : the number / string to space ;
    .grp : the group size ;
    .sep : the separation (default is a space) ;
    .rev_lst : reverse the string or not. Useful to not reverse it with RSA.
    '''

    lth = len(str(n))
    n_lst = list(n)

    if rev_lst:
        n_lst.reverse()

    i = 0
    for k in range(lth):
        if k % grp == 0 and k != 0:
            n_lst.insert(k + i, sep)
            i += 1

    if rev_lst:
        n_lst.reverse()

    ret = ''
    for k in n_lst:
        ret += k

    return ret

##-ini
alf_36 = '0123456789abcdefghijklmnopkrstuvwxyz'

#---------KRIS version
try:
    with open('version.txt', 'r') as f:
        kris_version_0 = f.read()
    kris_version = ""
    for k in kris_version_0:
        if not ord(k) in (10, 13):
            kris_version += k

except FileNotFoundError:
    tr('The file "version.txt" was not found. A version will be set but can be wrong.')
    kris_version = '2.0.0 ?'

else:
    if len(kris_version) > 16:
        tr('The file "version.txt" contain more than 16 characters, so it certainly doesn\'t contain the actual version. A version will be set but can be wrong.')
        kris_version = '2.0.0 ?'

##-test / base functions
#---------date
def date(verbose=False):
    '''Return the date in the form of
    dd/mm/yyyy, [hh]h[min]:ss,[milliseconds]
    ex : 17/03/2020, 23h15:32,859410
    '''
    now = str(dt.now())
    lst_now = now.split(' ')
    date_ = lst_now[0].split('-')
    time_ = lst_now[1].split(':')
    time_2 = time_[2].split('.')

    year = date_[0]
    month = date_[1]
    day = date_[2]

    hour = time_[0]
    min_ = time_[1]
    sec = time_2[0]
    mili = time_2[1]

    ret = day + '/' + month + '/' + year + ', ' + hour + 'h' + min_ + ":" + sec + ',' + mili

    if verbose:
        return '\n' + '-'*60 + '===RSA__by_lasercata' + '\n' + date() + '\n___\n'

    return ret


#---------chdir
def chd_rsa(home=False):
    '''
    Change current directory to the RSA_keys directory.

    If home is True, the path is `/home/$USER/.RSA_keys` (on Linux) ;
    otherwise, path is `path/to/KRIS/Data/RSA_keys`.

    If directory `[.]RSA_keys` don't exist, it create it.

    Return the old path.
    '''

    old_path = getcwd()

    #------chdir to the parent folder of `[.]RSA_keys`
    if home:
        home_path = expanduser('~')
        chdir(home_path)
        rsa_dir_name = '.RSA_keys'

    else:
        chd('.')
        rsa_dir_name = 'RSA_keys'

    #------chdir to `RSA_keys`
    if not isdir(rsa_dir_name):
        mkdir(rsa_dir_name)
        print('"{}" folder created at "{}" !'.format(rsa_dir_name, getcwd()))

        if home:
            for fn in listdir(glb.KRIS_data_path + '/RSA_keys'):
                copy(glb.KRIS_data_path + '/RSA_keys/' + fn, home_path + '/.RSA_keys/' + fn)

    chdir(rsa_dir_name)

    return old_path


# To create the .RSA_keys folder (pass from home == False to home == True) : `chdir(RSA.chd_rsa(True))`


##-functions
def key_size(n):
    '''Return the byte lenth of n (the number of binary digits).'''

    return len(format(n, 'b'))


#---------restore_encoding
def rest_encod(txt):
    '''This funtion try to reset the caracters after decrypting.'''

    alf_norm = ('☺', '☻', '♥', '♦', '♣', '♠', '•', '◘', '○', '◙', '♂', '♀', '♪', '♫', '☼', '►',
    '◄', '↕', '‼', '¶', '§', '▬', '↨', '↑', '↓', '→', '←', '∟', '↔', '▲', '▼', ' ',
    '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/', '0',
    '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', '@',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'N', 'O', 'P', 'Q',
    'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\', ']', '^', '_', '`', 'a'
    , 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q'
    , 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~', '⌂', 'Ç', 'ü'
    , 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å', 'æ', 'Æ'
    , 'ô', 'ö', 'ò', 'û', 'ù', 'ÿ', 'Ö', 'Ü', 'ø', '×', 'ƒ', 'á', 'í', 'ó', 'ú', 'ñ'
    , 'Ñ', 'ª', 'º', '¿', '®', '¬', '½', '¼', '¡', '«', '»', '░', '▒', '▓', '│', '┤'
    , 'Á', 'Â', 'À', '©', '╣', '║', '╗', '╝', '¢', '¥', '┐', '└', '┴', '┬', '├', '─'
    , '┼', 'ã', 'Ã', '╚', '╔', '╩', '╦', '╠', '═', '╬', '¤', 'ð', 'ð', 'Ð', 'Ê', 'Ë'
    , 'È', 'ı', 'Í', 'Î', 'Ï', '┘', '┌', '█', '▄', '¦', 'Ì', '▀', 'Ó', 'ß', 'Ô', 'Ò'
    , 'õ', 'Õ', 'µ', 'þ', 'Þ', 'Ú', 'Û', 'Ù', 'ý', 'Ý', '¯', '´', '\xad', '±', '‗',
    '¾', '§', '÷', '¸', '°', '¨', '·', '¹', '³', '²', '■', '\xa0')

    alf_bad = ('âº', 'â»', 'â¥', 'â¦', 'â£', 'â ', 'â¢', 'â', 'â', 'â', 'â', 'â', 'âª', 'â«', 'â¼', 'âº',
    'â', 'â', 'â¼', 'Â¶', 'Â§', 'â¬', 'â¨', 'â', 'â', 'â', 'â', 'â', 'â', 'â²', 'â¼', ' ',
    '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/', '0',
    '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', '@',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'N', 'O', 'P', 'Q',
    'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\', ']', '^', '_', '`', 'a'
    , 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q'
    , 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~', 'â', 'Ã', 'Ã¼'
    , 'é', 'Ã¢', 'Ã¤', 'Ã ', 'Ã¥', 'Ã§', 'Ãª', 'Ã«', 'Ã¨', 'Ã¯', 'Ã®', 'Ã¬', 'Ã', 'Ã\', 'Ã¦', 'Ã'
    , 'Ã´', 'Ã¶', 'Ã²', 'Ã»', 'Ã¹', 'Ã¿', 'Ã', 'Ã', 'Ã¸', 'Ã', 'Æ', 'Ã¡', 'Ã­', 'Ã³', 'Ãº', 'Ã±'
    , 'Ã', 'Âª', 'Âº', 'Â¿', 'Â®', 'Â¬', 'Â½', 'Â¼', 'Â¡', 'Â«', 'Â»', 'â', 'â', 'â', 'â', 'â¤'
    , 'Ã', 'Ã', 'Ã', 'Â©', 'â£', 'â', 'â', 'â', 'Â¢', 'Â¥', 'â', 'â', 'â´', 'â¬', 'â', 'â'
    , 'â¼', 'Ã£', 'Ã', 'â', 'â', 'â©', 'â¦', 'â ', 'â', 'â¬', 'Â¤', 'Ã°', 'Ã°', 'Ã', 'Ã', 'Ã'
    , 'Ã', 'Ä±', 'Ã', 'Ã', 'Ã', 'â', 'â', 'â', 'â', 'Â¦', 'Ã', 'â', 'Ã', 'Ã', 'Ã', 'Ã'
    , 'Ãµ', 'Ã', 'Âµ', 'Ã¾', 'Ã', 'Ã', 'Ã', 'Ã', 'Ã½', 'Ã', 'Â¯', 'Â´', '\xad', 'Â±', 'â',
    'Â¾', 'Â§', 'Ã·', 'Â¸', 'Â°', 'Â¨', 'Â·', 'Â¹', 'Â³', 'Â²', 'â ', '\xa0')


    for k in range(len(alf_norm)):
        txt = txt.replace(alf_bad[k], alf_norm[k])

    return txt


#---------rm_lst
def rm_lst(lst, lst_to_rm):
    '''Return the list `lst` without elements from `lst_to_rm`.'''

    ret = []

    for k in lst:
        if k not in lst_to_rm:
            ret.append(k)

    return ret


#---------MsgForm
class MsgForm:
    '''Manages the message form.'''

    def __init__(self, txt):
        '''Initiate some values.
        txt : text to manage.
        '''

        self.txt = txt


    #------chr to ascii
    def encode(self, grp_size):
        '''Return a list of int in string of txt in ascii.

        grp_size : size of the numbers group (length of n - 1).
        '''

        if type(self.txt) != bytes:
            txt = self.txt.encode()

        else:
            txt = self.txt

        #l_txt = list(txt)

        l_txt = []
        for k in self.txt:
            l_txt.append(ord(k))

        #---put a 0 before nb if nb < 100
        l_txt_a2 = []
        for k in l_txt:
            l_txt_a2.append(format(k, '04'))

        #---set group of grp_size
        txt_a = ''
        for k in l_txt_a2:
            txt_a += k

        txt_sp = sp_grp(txt_a, grp_size, rev_lst=False).split(' ')

        while len(txt_sp[-1]) < grp_size:
            txt_sp[-1] = '0' + txt_sp[-1]

        return txt_sp


    #------ascii to chr
    def decode(self):
        '''Return the text from a list of numbers in strings.'''

        #---add '0's to correctly space

        while len(self.txt[-1]) % 4 != 0:
            self.txt[-1] = '0' + self.txt[-1]

        #---set text to a string
        txt = ''
        for k in self.txt: #list
            txt += str(k)

        #---set group of four
        txt3 = sp_grp(txt, 4, rev_lst=False).split(' ')

        if txt3[-1] in ('0', '00', '000', '0000', '\x00'):
            del txt3[-1]

        #---set text
        ret = ''
        for k in txt3:
            ret += chr(int(k))

        return ret



##-RSA
class RSA:
    '''Class which allow to use the RSA cipher.'''

    def __init__(self, keys, interface=None):
        '''Initiate the RSA object.

        .keys : the keys. Should be of the form ((e, n), (d, n)) i.e. (pb_key, pv_key), or 'name' ;
        .interface : the interface using this function. Should be None,
         'gui', or 'console'. Used to choose the progress bar.

        If 'keys' is a string, use RsaKeys to read the keys.
        If a key is unknown, set it to None [i.g. : ((e, n), None)]. Both can't be None.
        '''

        if interface not in (None, 'gui', 'console'):
            raise ValueError('The argument "interface" should be None, "gui", \
                or "console", but {} of type {} was found !!!'.format(interface, type(interface)))

        self.interface = interface
        self.keys_init = keys

        self.keys = {} #will contain the keys

        if type(keys) == str:
            try:
                self.keys['e'] = RsaKeys(keys, interface=self.interface).get_key(0)
                #self.keys['d'] = RsaKeys(keys, interface=self.interface).get_key(1)
                self.keys['d'] = None

            except FileNotFoundError as err:
                if interface == 'console':
                    cl_out(c_error, err)

                elif interface == 'gui':
                    QMessageBox.critical(None, 'Keys not found !!!', '<h2>{}</h2>'.format(err))

                raise FileNotFoundError(err)

            except TypeError: #pbk keys
                self.keys['d'] = None


        elif type(keys) in (tuple, list, set):
            #-check the length
            for j, k in enumerate(keys):
                if k != None:
                    if len(k) != 2:
                        raise ValueError('The argument "keys" should have two lists of length 2, but "{}", with a length of {} was found !!!'.format(k, len(k)))

                if j > 1:
                    raise ValueError('The argument "keys" should have a length of 2, but "{}", with a length of {} was found !!!'.format(keys, len(keys)))

            if keys[0] == keys[1] == None:
                raise ValueError("Both keys can't be None !!!")

            self.keys['e'] = keys[0]
            self.keys['d'] = keys[1]


        else:
            raise TypeError('The argument "keys" should be a string or a list, but "{}" of type "{}" was found !!!'.format(keys, type(keys)))


        self.pb_key = self.keys['e']
        self.pv_key = self.keys['d']


    #---------repr
    def __repr__(self):
        '''represent the RSA object'''

        return "RSA(pb_key='{}', pv_key='{}', interface='{}')".format(
            self.pb_key,
            self.pv_key,
            self.interface
        )


    def type_(self):
        '''Return the keys type, either "all", "pvk" or "pbk".'''

        if self.pv_key == None:
            return 'pbk'

        elif self.pb_key == None:
            return 'pvk'

        else:
            return 'all'



    #---------encrypt
    def encrypt(self, txt):
        '''Return the encrypted text txt with the public key self.pb_key.'''

        if self.pb_key == None:
            msg_err = 'Cannot encrypt with an empty key !!!'

            if self.interface == 'console':
                cl_out(c_error, msg_err)

            elif self.interface == 'gui':
                QMessageBox.critical(None, 'Cannot encrypt !!!', '<h2>{}</h2>'.format(msg_err))

            raise TypeError(msg_err)


        #------ini progress bar
        if self.interface == 'gui':
            pb = GuiProgressBar(title='Encrypting ... | RSA ― KRIS', verbose=True)

        elif self.interface == 'console':
            pb = ConsoleProgressBar()

        #------ini
        e, n = self.pb_key

        grp_size = len(str(n)) - 1
        encoded_txt = MsgForm(txt).encode(grp_size)

        #------crypt
        l_txt_crypted = []
        for j, k in enumerate(encoded_txt):
            i = int(k)

            l_txt_crypted.append(pow(i, e, n)) #todo: try the math.pow speed !

            if self.interface in ('gui', 'console'):
                pb.set(j, len(encoded_txt))

        ret = ''
        for k in l_txt_crypted:
            ret += str(k) + ' '

        ret = ret[:-1] #remove last space.

        return ret


    #---------decrypt
    def decrypt(self, txt):
        '''Return the decrypted text txt with the private key self.pv_key.'''

        if self.pv_key == None:
            try:
                self.keys['d'] = RsaKeys(self.keys_init, interface=self.interface).get_key(1)
                self.pv_key = self.keys['d']

            except TypeError:
                msg_err = 'Cannot decrypt with an empty key !!!'

                if self.interface == 'console':
                    cl_out(c_error, msg_err)

                elif self.interface == 'gui':
                    QMessageBox.critical(None, 'Cannot decrypt !!!', '<h2>{}</h2>'.format(msg_err))

                raise TypeError(msg_err)


        #------ini progress bar
        if self.interface == 'gui':
            pb = GuiProgressBar(title='Decrypting ... | RSA ― KRIS', verbose=True)

        elif self.interface == 'console':
            pb = ConsoleProgressBar()

        #------ini
        d, n = self.pv_key
        grp_size = len(str(n)) - 1

        if type(txt) == str:
            l_txt = txt.split(' ')

        else:
            l_txt = txt.split(b' ')

        #------decrypt
        l_txt_decrypted = []

        for j, k in enumerate(l_txt):
            i = int(k)
            l_txt_decrypted.append(pow(i, d, n)) #todo: use math.pow ?

            #---progress bar
            if self.interface in ('gui', 'console'):
                pb.set(j, len(l_txt)) # len(l_txt) - 1


        for k in range(len(l_txt_decrypted)): #add 0. ex : 111 -> 0111
            l_txt_decrypted[k] = str(l_txt_decrypted[k])

            while len(l_txt_decrypted[k]) < grp_size: #% 4 != 0:
                l_txt_decrypted[k] = '0' + l_txt_decrypted[k]

        decoded_txt = MsgForm(l_txt_decrypted).decode()

        ret = ''
        for k in decoded_txt:
            ret += str(k)

        #print(ret)
        #ret = rest_encod(ret)
        #print(rest_encod(ret))
        #print(ret)
        # #todo: this don't work : the print works well (if you encrypt "é", and decrypt it it will print "é"), but ret is not "é"

        return ret.strip('\x00')


    def encrypt_file(self, fn_in, fn_out):
        '''
        Encrypt the content of `fn_in` and write it in `fn_out`.
        It does NOT check if `fn_out` already exists and will overwrite it.
        '''

        with open(fn_in, 'r') as f:
            txt = f.read()

        txt_c = self.encrypt(txt)

        with open(fn_out, 'w') as f:
            f.write(txt_c)


    def decrypt_file(self, fn_in, fn_out):
        '''
        Decrypt the content of `fn_in` and write it in `fn_out`.
        It does NOT check if `fn_out` already exists and will overwrite it.
        '''

        with open(fn_in, 'r') as f:
            txt = f.read()

        txt_d = self.decrypt(txt)

        with open(fn_out, 'w') as f:
            f.write(txt_d)


    def sign(self, txt):
        '''
        Sign the message 'txt'.
        It encrypt 'txt' using the private key.
        '''

        if self.pv_key == None:
            try:
                self.keys['d'] = RsaKeys(self.keys_init, interface=self.interface).get_key(1)
                self.pv_key = self.keys['d']

            except TypeError:
                msg_err = 'Cannot sign with an empty private key !!!'

                if self.interface == 'console':
                    cl_out(c_error, msg_err)

                elif self.interface == 'gui':
                    QMessageBox.critical(None, 'Cannot sign !!!', '<h2>{}</h2>'.format(msg_err))

                raise TypeError(msg_err)

        return RSA([self.pv_key, self.pb_key], self.interface).encrypt(txt)


    def unsign(self, txt):
        '''
        Unsign the message 'txt'.
        It decrypt 'txt' using the public key.
        '''

        if self.pb_key == None:
            msg_err = 'Cannot unsign with an empty key !!!'

            if self.interface == 'console':
                cl_out(c_error, msg_err)

            elif self.interface == 'gui':
                QMessageBox.critical(None, 'Cannot unsign !!!', '<h2>{}</h2>'.format(msg_err))

            raise TypeError(msg_err)

        return RSA([self.pv_key, self.pb_key], self.interface).decrypt(txt)


class RsaSign:
    '''Class which allow to sign messages' hashes.'''

    def __init__(self, keys, h='sha256', interface=None):
        '''
        Initiate RsaSign.

        - keys : cf RSA's doc (the class just before) ;
        - h : the hash to use.
        '''

        if interface not in (None, 'gui', 'console'):
            raise ValueError('The argument "interface" should be None, "gui", or "console", but {} of type {} was found !!!'.format(interface, type(interface)))

        self.interface = interface

        self.RSA = RSA(keys, interface)
        self.h = h
        self.Hasher = Hasher(h)


    def sign(self, txt):
        '''Sign 'txt'.'''

        txt_h = self.Hasher.hash(txt)

        return self.RSA.sign(txt_h)


    def check(self, msg, sign):
        '''
        Check if the message's sign correspond to the message.

        - msg : the message which was signed ;
        - sign : the message's sign.

        Return :
            True if correspond ;
            False otherwise.
        '''

        msg_h = self.Hasher.hash(msg)
        unsign = self.RSA.unsign(sign)

        return msg_h == unsign


    def str_sign(self, msg):
        '''
        Sign 'txt' and return it, with the message, in a string of this form (the commented lines are set with FormatedMsg, in KRIS_gui.py) :

            #------BEGIN KRIS SIGNED MESSAGE------
            #Version: KRIS_v2.0.0
            #Cipher: RSA signature
            #Hash: sha256
            #Key_name: test
            #---
            #
            This is the signed message.

            ------BEGIN KRIS SIGNATURE------
            943807048734946125391551838892825323881224874134114102624258821
            777497503175465732577498770633243452810041947630081594914335102
            030685948454325645230350182968575318427660604935974297921249620
            145627119142786967888460883779427870903491284297486553549313557
            036484594229863184367664486859688319969288882500317784306881247
            986697247977081407162090788619940533970560140434587970906714139
            290858878587907236987805719455479320536481924920579051146037063
            173431947005158307628367242387336720592701482187812886188311982
            087888289689323511419214457508164027138556866752536079927267033
            1287543493615931451357930596408267945537776650957
            ------END KRIS SIGNATURE------
            #------END KRIS SIGNED MESSAGE------
        '''

        sign = self.sign(msg)

        txt = '{}\n\n------BEGIN KRIS SIGNATURE------\n{}\n------END KRIS SIGNATURE------'.format(msg, NewLine(64).set(sign))


        return txt #FormatMsg(txt, nl=False).set(self.d)


    def str_check(self, txt):
        '''Same as self.check, but for a message formatted by self.str_sign.'''

        begin = txt.find('\n\n------BEGIN KRIS SIGNATURE------\n')
        end = txt.find('\n------END KRIS SIGNATURE------')

        if -1 in (begin, end):
            raise ValueError('The text is not well formatted !!!')

        msg = txt[:begin]
        sign = txt[begin + 35:end].replace('\n', '')

        return self.check(msg, sign)


    #todo: there is a bug when checking in gui with a 512 RSA key : it does not match, but it should (try sign and check a test message, i.g. 'test').



##-RsaKeys
class RsaKeys:
    '''Class which allow to generate RSA keys, and to manipulate them (saving in files, ...)'''

    def __init__(self, keys_name, interface=None):
        '''
        Initiate the RsaKeys object.

        - keys_name : the set of keys' name (without the extention).
        '''

        if interface not in (None, 'gui', 'console'):
            raise ValueError('The argument "interface" should be None, "gui", \
                or "console", but {} of type {} was found !!!'.format(interface, type(interface)))


        self.k_name = keys_name
        self.interface = interface


    def __repr__(self):
        '''Represent the object.'''

        return "RsaKeys('{}', interface='{}')".format(self.k_name, self.interface)



    #---------get prime number p and q
    def _get_p_q(self, size, verbose=False):
        '''Function finding p and q of size `size // 2`.'''

        if verbose:
            print('\nCalculating keys ...\n')
            t1 = dt.now()

        #------ini progress bar
        if self.interface == 'gui':
            pb = GuiProgressBar(title='Generating ... ― KRIS', undetermined=True)

        elif self.interface == 'console':
            pb = ConsoleProgressBar()


        p = 1
        while not isSurelyPrime(p):
            p = randbits(size // 2)

            if self.interface in ('gui', 'console'):
                pb.load()

        print('\b \b', end='')

        if verbose:
            t_p = dt.now() - t1
            msg1 = 'p found in {} s.'.format(t_p)
            cl_out(c_succes, msg1 + '\n')

            t2 = dt.now()

        q = 1
        while not (isSurelyPrime(q) and p != q):
            q = randbits(size // 2)

            if self.interface in ('gui', 'console'):
                pb.load()

        print('\b \b', end='')

        if verbose:
            t_q = dt.now() - t2
            t_t = dt.now() - t1

            msg = 'q found in {} s.\nTime elapsed : {} s.'.format(t_q, t_t)

            if self.interface in (None, 'console'):
                cl_out(c_succes, msg)

            elif verbose:
                QMessageBox.about(None, 'Done !', '<h2>{}</h2>\n<h2>{}</h2>'.format(msg1, msg))


        return p, q


    #---------calc n, phi, e, d with p and q
    def _calc_nb(self, p, q, verbose=False):
        '''
        Return n, phi, e, d.
        p and q are prime numbers.
        '''

        if verbose:
            print('\nCalculating numbers ...')
            t1 = dt.now()

        #------ini progress bar
        if self.interface == 'gui':
            pb = GuiProgressBar(title='Generating ... ― KRIS', undetermined=True)

        elif self.interface == 'console':
            pb = ConsoleProgressBar()

        if p > q:
            p, q = q, p # p will be smaller than q (p < q).

        n = p * q
        phi = (p - 1) * (q - 1)

        if verbose:
            cl_out(c_succes, 'n found !\n')

        i = 0
        # e : p, q < e < phi, pgcd(n, e) = 1
        if verbose:
            print('\nSearching e ...\n')
        e = 0
        while math.gcd(e, phi) != 1:
            e = randint(q, phi)

            if self.interface in ('gui', 'console'):
                pb.load()

        print('\b \b')

        if verbose:
            t_e = dt.now() - t1
            msg1 = 'e found in {} s.'.format(t_e)
            cl_out(c_succes, msg1 + '\n')

            print('\nSearching d ...\n')
            t2 = dt.now()

        d = mult_inverse(e, phi)

        if verbose:
            t_d = dt.now() - t2
            t_t = dt.now() - t1

            msg = 'd found in {} s.\nTime elapsed : {} s.'.format(t_d, t_t)

            cl_out(c_succes, msg)

            if self.interface == 'gui' and verbose:
                QMessageBox.about(None, 'Done !', '<h2>{}</h2>\n<h2>{}</h2>'.format(msg1, msg))

        return n, phi, e, d


    #---------get keys
    def _get_keys(self, p, q):
        '''Return private key, and public key.'''

        n, phi, e, d = self._calc_nb(p, q)

        return (d, n), (e, n)


    #---------get_size_from_strth
    def _gen_p_q(self, size):
        '''
        Retrun (p, q, n), with n of the strenth of size bytes (+/- 4)
        size : the wanted size (in bytes) +/- 4.
        '''

        p, q = self._get_p_q(size + 2)
        n = p * q

        #assert key_size(n) in [k for k in range(size - 4, size + 5)] #check the size of n

        return p, q, n


    #---------generate keys
    def generate(self, size, pwd=None, save=True, overwrite=False, md_stored='hexa'):
        '''
        Function which generate RSA keys.

        Arguments :
            - self.k_name : the name to give for the keys ;

            - size : wanted size for the keys (+/- 4), is an intenger (2048 recomended) ;
            - save : save in files or just return keys, should be in (True, False) ;
            - pwd : The AES key used to encrypt the RSA key. If None, key will be saved in clear ;
            - overwrite : in (True, False). If the dir keys_names already exist, if True, overwrite it,
            return an error msg else ;
            - md_stored : the way how the keys are stored, i.e. in decimal or hexadecimal.
                Should be "hexa" or "dec". Default is "hexa".

        If save is True, the program make two files, in chd_rsa(glb.home), named :
            For the private key :
                '[self.k_name].pvk-h' if md_stored is 'hexa' ;
                '[self.k_name].pvk-d' if md_stored is 'dec' ;
                '[self.k_name].pvk-d.enc' or '[self.k_name].pvk-h.enc' if pwd != None.

            For the public key :
                '[self.k_name].pbk-h' if md_stored is 'hexa' ;
                '[self.k_name].pbk-d' else.

        Return :
            -2 if the set of keys already exist and overwrite is False ;
            pbk, pvk, n_strth otherwise.
        '''


        if save not in (True, False) or overwrite not in (True, False) or md_stored not in ('hexa', 'dec'):
            raise ValueError('The arguments are not correct !')

        if save:
            if md_stored == 'dec':
                fn = str(self.k_name) + '.pvk-d'
                fn_pbk = str(self.k_name) + '.pbk-d'

            else:
                fn = str(self.k_name) + '.pvk-h'
                fn_pbk = str(self.k_name) + '.pbk-h'

            if pwd != None:
                fn += '.enc'

            old_path = chd_rsa(glb.home)

            #---Check if file exists first to not lose your time
            if isfile(fn):
                if not overwrite:
                    chdir(old_path)
                    return -2

                else:
                    remove(fn)

        #------get values
        p, q, n = self._gen_p_q(size)
        pvk, pbk = self._get_keys(p, q)

        n_strth = key_size(n) # size of n

        if save:
            #------Private key
            v = {
                'p' : p,
                'q' : q,
                'n' : n,
                'phi' : (p - 1) * (q - 1),
                'e' : pbk[0],
                'd' : pvk[0],
                'date': date(),
                'n_strenth': n_strth
            }

            if md_stored == 'hexa':
                for k in v:
                    if k != 'date':
                        v[k] = format(v[k], 'x') #convert numbers to hexadecimal

            data = str(v)

            if pwd != None:
                data = AES(256, pwd, hexa=True).encryptText(data, mode_c='hexa')

            #---make file
            with open(fn, 'w') as f:
                f.write(data)


            #------Public key
            v_pbk = {
                'e': v['e'],
                'n': v['n'],
                'date' : v['date'],
                'n_strenth' : v['n_strenth']
            }

            #---make file
            with open(fn_pbk, 'w') as f:
                f.write(str(v_pbk))


            chdir(old_path)


        return pbk, pvk, n_strth



    def read(self, mode='all', also_ret_pwd=False):
        '''
        Try to read the content of the file `[self.k_name] + ext`.

        - mode : the self.get_fn mode. in ('pvk', 'pbk', 'all'). Default is 'all' ;
        - also_ret_pwd : a bool indicating if also return the password. If True, return the password at the end of the return tuple.

        Return :
            (pbk, pvk), (p, q, n, phi, e, d), (n_strth, date_)      if it's a *.pvk-* file ;
            pbk, (n, e), (n_strth, date_)                           if it's a *.pkb-* file ;
            -1                                                      if not found ;
            -2                                                      if file not well formatted ;
            -3                                                      if password is wrong or if canceled.
        '''

        #------other
        def err_not_well_formated():
            msg = tr('The file is not well formatted !')

            if self.interface == 'gui':
                QMessageBox.critical(None, '!!! File error !!!', '<h2>{}</h2>'.format(msg))
            else:
                print('KRIS: RsaKeys: read: ' + msg)

            return -2

        #------Get filename
        try:
            fn, md = self.get_fn(mode, also_ret_md=True)

        except FileNotFoundError:
            msg = tr('File not found !')

            if self.interface == 'gui':
                QMessageBox.critical(None, '!!! Not found !!!', '<h2>{}</h2>'.format(msg))
            else:
                print('KRIS: RsaKeys: read: ' + msg)

            return -1

        #------Read file
        old_path = chd_rsa(glb.home)

        with open(fn, 'r') as f:
            f_content = f.read()

        chdir(old_path)

        #------Decrypt content, if encrypted
        if fn[-4:] == '.enc':
            #---Get password
            if self.interface == 'gui':
                pwd = AskPwd.use()

            elif self.interface == 'console':
                pwd_clear = getpass(tr('RSA key password :'))
                pwd = Hasher('sha256').hash(pwd_clear)

            else:
                pwd_clear = input('RSA key password :')
                pwd = Hasher('sha256').hash(pwd_clear)

            if pwd == None:
                return -3 # Canceled by user

            #---Decrypt
            try:
                f_content_dec = AES(256, pwd, hexa=True).decryptText(f_content, mode_c='hexa')

            except UnicodeDecodeError:
                msg = tr('This is not the good password !')

                if self.interface == 'gui':
                    QMessageBox.critical(None, '!!! Wrong password !!!', '<h2>{}</h2>'.format(msg))
                else:
                    print('KRIS: RsaKeys: read: ' + msg)

                return -3

            except ValueError:
                return err_not_well_formated()

            else:
                f_content = f_content_dec

        else:
            pwd = None

        try:
            infos = literal_eval(f_content)

        except SyntaxError:
            return err_not_well_formated()

        #------Read and return infos
        if md[0] == 'pbk':
            try:
                date_, n_strth = infos['date'], infos['n_strenth']
                e, n = infos['e'], infos['n']

            except KeyError:
                return err_not_well_formated()

            if md[1] == 'hexa': #convert in decimal
                n_strth = str(int(n_strth, 16))
                e, n = str(int(e, 16)), str(int(n, 16))

            pbk = str(e) + ',' + str(n)

            if also_ret_pwd:
                return (pbk,), (n, e), (n_strth, date_), pwd

            return (pbk,), (n, e), (n_strth, date_)


        else:
            try:
                date_, n_strth = infos['date'], infos['n_strenth']
                p, q, n, phi, e, d = infos['p'], infos['q'], infos['n'], infos['phi'], infos['e'], infos['d']

            except KeyError:
                return err_not_well_formated()

            if md[1] == 'hexa': #convert in decimal
                n_strth = str(int(n_strth, 16))
                p, q, n, phi, e, d = str(int(p, 16)), str(int(q, 16)), \
                    str(int(n, 16)), str(int(phi, 16)), str(int(e, 16)), str(int(d, 16))

            pvk = str(d) + ',' + str(n)
            pbk = str(e) + ',' + str(n)

            chdir(old_path)

            if also_ret_pwd:
                return (pbk, pvk), (p, q, n, phi, e, d), (n_strth, date_), pwd

            return (pbk, pvk), (p, q, n, phi, e, d), (n_strth, date_)


    def get_key(self, mode):
        '''
        Return the key to use with RSA.
        Read the keys from the key file created by this program.

        self.k_name : the name given when creating keys ;
        mode : 0 - encrypt (pbk), 1 - decrypt (pvk), used to choose between public and private keys.
        '''

        if mode not in (0, 1):
            raise ValueError('"mode" should be 0 or 1 (int), but "' + str(mode) + '" was found !!!')

        md = ('all', 'pbk')[mode == 0]
        ret = self.read(md)

        if ret in (-1, -2, -3):
            return ret

        keys = ret[0]

        if len(keys) == 1: #pbk
            if mode == 1:
                raise TypeError("Can't read the private key of a pbk set of keys !!!")

            ed, n = keys[0].split(',')

        else:
            ed, n = keys[mode].split(',')

        return int(ed), int(n)


    #
    # #------export_pubic_key
    # def export(self, md_stored_out='hexa'): #Todo: Useless, remove it ? or change the func : copy the file where asked ?
    #     '''
    #     Function which export the public key to a file named :
    #         '[self.k_name].pbk-h' if md_stored_out is 'hexa' ;
    #         '[self.k_name].pbk-d' else.
    #
    #     - md_stored_out : the way how the exported keys will be stored, i.e. in
    #     decimal or hexadecimal. Should be "hexa" or "dec".
    #
    #     return -1 if the file was not found, None otherwise.
    #     '''
    #
    #     if md_stored_out not in ('hexa', 'dec'):
    #         raise ValueError('"md_stored_out" should be "dec" or "hexa", but "' + str(md_stored_out) + '" was found !!!')
    #
    #     try:
    #         (pbk, pvk), (p, q, n, phi, e, d), (n_strth, date_) = self.read()
    #
    #     except ValueError:
    #         return -1
    #
    #     v = {
    #         'e': e,
    #         'n': n,
    #         'date' : date_,
    #         'date_export' : date(),
    #         'n_strenth' : n_strth
    #     }
    #
    #     #---write
    #     if md_stored_out == 'dec':
    #         fn = self.k_name + '.pbk-d'
    #
    #     else:
    #         fn = self.k_name + '.pbk-h'
    #
    #         for k in v:
    #             if k not in ('date', 'date_export'):
    #                 v[k] = format(int(v[k]), 'x') #convert numbers to hexadecimal
    #
    #
    #     old_path = chd_rsa(glb.home)
    #
    #     fdn = tuple(v.keys()) #('e', 'n', 'date', 'date_export', 'n_strenth')
    #     row = (v)
    #     CSV(fn).write(fdn, row)
    #
    #     chdir(old_path)



    #------convert_keys
    def convert(self):
        '''
        Function which convert RSA keys.
        If the keys are stored in decimal, it write them in hexadecimal ;
        it write them in decimal else.

        It remove keys in the old storage mode.

        If the keys were not found, return -1 ;
        if the keys already exists, return -2 ;
        return None else.
        '''

        try:
            lst_keys, lst_values, lst_infos, pwd = self.read(also_ret_pwd=True)
            old_fn, (type_, stg_md) = self.get_fn(also_ret_md=True)

        except ValueError:
            return -1


        if type_ == 'pvk': #pvk
            v = {
                'p' : lst_values[0],
                'q' : lst_values[1],
                'n' : lst_values[2],
                'phi' : lst_values[3],
                'e' : lst_values[4],
                'd' : lst_values[5],
                'date' : lst_infos[1],
                'n_strenth' : lst_infos[0]
            }

            if stg_md == 'hexa': #keys are in hexa, set it in dec
                fn = str(self.k_name) + '.pvk-d'
                fn_pbk = str(self.k_name) + '.pbk-d'

            else:
                fn = str(self.k_name) + '.pvk-h'
                fn_pbk = str(self.k_name) + '.pbk-h'

                for k in v:
                    if k != 'date':
                        v[k] = format(int(v[k]), 'x') #convert numbers to hexadecimal

            pbk = v['e'], v['n']
            pvk = v['d'], v['n']

            if pwd != None:
                fn += '.enc'

            #---check if it not already exists
            old_path = chd_rsa(glb.home)

            if isfile(fn):
                chdir(old_path)
                return -2

            #---make file
            data = str(v)

            if pwd != None:
                data = AES(256, pwd, hexa=True).encryptText(data, mode_c='hexa')

            with open(fn, 'w') as f:
                f.write(data)

            #-Public key
            v_pbk = {
                'e': v['e'],
                'n': v['n'],
                'date' : v['date'],
                'n_strenth' : v['n_strenth']
            }

            #---make file
            with open(fn_pbk, 'w') as f:
                f.write(str(v_pbk))


            old_md = ('d', 'h')[stg_md == 'hexa']

            try:
                if pwd == None:
                    remove(self.k_name + '.pvk-' + old_md)
                else:
                    remove(self.k_name + '.pvk-' + old_md + '.enc')
            except FileNotFoundError:
                pass

            try:
                remove(self.k_name + '.pbk-' + old_md)
            except FileNotFoundError:
                pass

            chdir(old_path)

        else: #pbk
            v = {
                'e' : lst_values[1],
                'n' : lst_values[0],
                'date' : lst_infos[1],
                'n_strenth' : lst_infos[0]
            }
            pbk = v['e'], v['n']

            #---write
            if stg_md == 'hexa': #keys are in hexa, set it in dec
                fn = str(self.k_name) + '.pbk-d'

            else:
                fn = str(self.k_name) + '.pbk-h'

                for k in v:
                    if k not in ('date', 'date_export'):
                        v[k] = format(int(v[k]), 'x') #convert numbers to hexadecimal

            old_path = chd_rsa(glb.home)

            if isfile(fn):
                chdir(old_path)
                return -2

            with open(fn, 'w') as f:
                f.write(str(v))

            old_md = ('d', 'h')[stg_md == 'hexa']
            remove(fn[:-1] + old_md)

            chdir(old_path)



    #------rename
    def rename(self, new_name):
        '''
        Function which can rename a set of keys

        self.k_name : the set of keys' name ;
        new_name : the new set of keys' name.

        Return -1 if the file was not found, None otherwise.
        '''

        fn, (type_, stg_md) = self.get_fn(also_ret_md=True)

        new_name = str(new_name)
        old_path = chd_rsa(glb.home)

        ext = '.' + type_ + ('-h', '-d')[stg_md == 'dec']

        if type_ == 'pvk':
            ext_pbk = '.pbk-' + ('h', 'd')[stg_md == 'dec']

        if fn[-4:] == '.enc':
            ext += '.enc'

        rename(str(self.k_name) + ext, new_name + ext)

        if type_ == 'pvk':
            rename(str(self.k_name) + ext_pbk, new_name + ext_pbk)

        chdir(old_path)


    def get_fn(self, mode='all', also_ret_md=False):
        '''
        Return the filename of the key (with the extention)

        - self.k_name : the RSA key's name ;
        - mode : in ('pvk', 'pbk', 'all'). If 'pvk': only watch for private keys, if 'pbk': only watch for public keys ('*.pbk-*'), if 'all': watch for both ;
        - also_ret_md a bool indicating if also returning the mode, of the form (['pvk' | 'pbk'], ['dec' | 'hexa'])

        Resolution order (to find the good key extention) if mode == 'all' :
            pvk-h ;
            pvk-d ;
            pvk-h.enc ;
            pvk-d.enc ;
            pbk-h ;
            pbk-d.

        It is the same order if 'pvk' or 'pbk', but without the other part.
        '''

        old_path = chd_rsa(glb.home)

        if mode not in ('pvk', 'pbk', 'all'):
            raise ValueError('The mode should be in ("pvk", "pbk", "all"), but "{}" was found !!!'.format(mode))

        if isfile(self.k_name + '.pvk-h') and mode in ('all', 'pvk'):
            fn = self.k_name + '.pvk-h'
            md = ('pvk', 'hexa')

        elif isfile(self.k_name + '.pvk-d') and mode in ('all', 'pvk'):
            fn = self.k_name + '.pvk-d'
            md = ('pvk', 'dec')

        elif isfile(self.k_name + '.pvk-h.enc') and mode in ('all', 'pvk'):
            fn = self.k_name + '.pvk-h.enc'
            md = ('pvk', 'hexa')

        elif isfile(self.k_name + '.pvk-d.enc') and mode in ('all', 'pvk'):
            fn = self.k_name + '.pvk-d.enc'
            md = ('pvk', 'dec')


        elif isfile(self.k_name + '.pbk-h') and mode in ('all', 'pbk'):
            fn = self.k_name + '.pbk-h'
            md = ('pbk', 'hexa')

        elif isfile(self.k_name + '.pbk-d') and mode in ('all', 'pbk'):
            fn = self.k_name + '.pbk-d'
            md = ('pbk', 'dec')

        else:
            chdir(old_path)
            raise FileNotFoundError('The key "{}" does not seem to exists in {} mode !!!'.format(self.k_name, mode))

        chdir(old_path)

        if also_ret_md:
            return fn, md

        return fn


    #------Encrypt key
    def encrypt(self, pwd):
        '''
        Encrypt 'self.k_name' with AES-256-CBC using the password
        `pwd` (Hasher('sha256').hash(clear_pwd)), make a file
        'self.k_name' + ext + '.enc' and remove clear one.

        - pwd : the password.
        '''

        fn = self.get_fn('pvk')

        if fn[-4:] == '.enc':
            raise KeyError(tr('The RSA key is already encrypted !'))

        old_path = chd_rsa(glb.home)

        with open(fn, 'r') as f:
            f_content = f.read()

        f_enc = AES(256, pwd, hexa=True).encryptText(f_content, mode_c='hexa')

        with open(fn + '.enc', 'w') as f:
            f.write(f_enc)

        remove(fn)

        chdir(old_path)


    #------Decrypt key
    def decrypt(self, pwd):
        '''
        Decrypt 'self.k_name' with AES-256-CBC using the password
        `pwd` (Hasher('sha256').hash(clear_pwd)), make a file
        'self.k_name' + ext and remove encrypted one.

        - pwd : the password.
        '''

        fn = self.get_fn('pvk')

        if fn[-4:] != '.enc':
            raise KeyError(tr('The RSA key is not encrypted !'))

        old_path = chd_rsa(glb.home)

        with open(fn, 'r') as f:
            f_content = f.read()

        try:
            f_dec = AES(256, pwd, hexa=True).decryptText(f_content, mode_c='hexa')

        except UnicodeDecodeError:
            msg = tr('This is not the good password !')

            if self.interface == 'gui':
                QMessageBox.critical(None, '!!! Wrong password !!!', '<h2>{}</h2>'.format(msg))
            else:
                print('KRIS: RsaKeys: decrypt: ' + msg)

            chdir(old_path)
            return -3

        except ValueError:
            msg = tr('The file is not well formatted !')

            if self.interface == 'gui':
                QMessageBox.critical(None, '!!! File error !!!', '<h2>{}</h2>'.format(msg))
            else:
                print('KRIS: RsaKeys: decrypt: ' + msg)

            chdir(old_path)
            return -2

        with open(fn[:-4], 'w') as f:
            f.write(f_dec)

        remove(fn)

        chdir(old_path)


    def change_pwd(self, old_pwd, new_pwd):
        '''
        Change the RSA key password for `self.k_name`.

        Return :
            -1      if the RSA key is not encrypted ;
            -2      if the RSA key file is not well formatted ;
            -3      if the old_pwd is wrong ;
            None    otherwise.
        '''

        fn = self.get_fn('pvk')

        if fn[-4:] != '.enc':
            msg = tr('The RSA key is not encrypted !')

            if self.interface == 'gui':
                QMessageBox.critical(None, '!!! Not encrypted !!!', '<h2>{}</h2>'.format(msg))
            else:
                print('KRIS: RsaKeys: change_pwd: ' + msg)

            return -1

        old_path = chd_rsa(glb.home)

        with open(fn, 'r') as f:
            f_content = f.read()

        try:
            f_dec = AES(256, old_pwd, hexa=True).decryptText(f_content, mode_c='hexa')

        except UnicodeDecodeError:
            msg = tr('This is not the good password !')

            if self.interface == 'gui':
                QMessageBox.critical(None, '!!! Wrong password !!!', '<h2>{}</h2>'.format(msg))
            else:
                print('KRIS: RsaKeys: change_pwd: ' + msg)

            chdir(old_path)
            return -3

        except ValueError:
            msg = tr('The file is not well formatted !')

            if self.interface == 'gui':
                QMessageBox.critical(None, '!!! File error !!!', '<h2>{}</h2>'.format(msg))
            else:
                print('KRIS: RsaKeys: change_pwd: ' + msg)

            chdir(old_path)
            return -2

        f_enc = AES(256, new_pwd, hexa=True).encryptText(f_dec, mode_c='hexa')

        with open(fn, 'w') as f:
            f.write(f_enc)

        chdir(old_path)




#------list_keys
def list_keys(mode='any'):
    '''
    Function which lists the existing keys.

    if mode is 'any', return eight tuples :
        - pvk-d ;
        - pbk-d without pvk-d ;
        - pvk-h ;
        - pbk-h without pvk-h ;
        - pbk-* without pvk-* ;
        - all (pvk-d, pvk-h, pbk-d, pbk-h), without duplicates and sorted ;
        - .enc
        - all \ .enc

    mode : what return. Should be "pvk", "pbk", "pvk_hex", "pbk_hex", "pbk_without_pvk", "enc", "dec", "all", or "any".
    '''

    if mode not in ('pvk', 'pbk', 'pvk_hex', 'pbk_hex', 'pbk_without_pvk', 'enc', 'dec', 'all', 'any'):
        raise ValueError('"mode" should be "pvk", "pbk", "pvk_hex", "pbk_hex", "pbk_without_pvk", "enc", "dec", "all" or "any", but "' + str(mode) + '" was found !!!')

    def append_lst(k):
        if k[-6:] == '.pvk-d':
            lst_pvk.append(k[:-6])
            lst_all.append(k[:-6])

        elif k[-6:] == '.pbk-d':
            lst_pbk.append(k[:-6])
            lst_all.append(k[:-6])

        elif k[-6:] == '.pvk-h':
            lst_hex_pvk.append(k[:-6])
            lst_all.append(k[:-6])

        elif k[-6:] == '.pbk-h':
            lst_hex_pbk.append(k[:-6])
            lst_all.append(k[:-6])

        elif k[-4:] == '.enc':
            lst_enc.append(k[:-10])
            lst_all.append(k[:-10])
            append_lst(k[:-4])

    old_path = chd_rsa(glb.home)
    lst_k = listdir()
    chdir(old_path)

    lst_pvk = []
    lst_pbk = []
    lst_hex_pvk = []
    lst_hex_pbk = []
    lst_enc = []
    lst_all = []

    for k in lst_k:
        append_lst(k)

    #---
    lst_pbk = rm_lst(lst_pbk, lst_pvk)
    lst_hex_pbk = rm_lst(lst_hex_pbk, lst_hex_pvk)

    lst_pbk_without_pvk = rm_lst(lst_pbk + lst_hex_pbk, lst_pvk + lst_hex_pvk)
    lst_all_without_enc = sorted(list(set(rm_lst(lst_all, lst_enc))))

    lst_all = list(set(lst_all))
    lst_all.sort()

    if mode == 'all':
        return tuple(lst_all)

    elif mode == 'pvk':
        return tuple(lst_pvk)

    elif mode == 'pbk':
        return tuple(lst_pbk)

    elif mode == 'pvk_hex':
        return tuple(lst_hex_pvk)

    elif mode == 'pbk_hex':
        return tuple(lst_hex_pbk)

    elif mode == 'pbk_without_pvk':
        return tuple(lst_pbk_without_pvk)

    elif mode == 'enc':
        return tuple(lst_enc)

    elif mode == 'dec':
        return tuple(lst_all_without_enc)

    return (
        tuple(lst_pvk),
        tuple(lst_pbk),
        tuple(lst_hex_pvk),
        tuple(lst_hex_pbk),
        tuple(lst_pbk_without_pvk),
        tuple(lst_enc),
        tuple(lst_all_without_enc),
        tuple(lst_all)
    )


# by lasercata and Elerias

# _______        _______  ______ _____ _______ _______
# |______ |      |______ |_____/   |   |_____| |______
# |______ |_____ |______ |    \_ __|__ |     | ______|

#        _______ _______ _______  ______ _______ _______ _______ _______
# |      |_____| |______ |______ |_____/ |       |_____|    |    |_____|
# |_____ |     | ______| |______ |    \_ |_____  |     |    |    |     |
