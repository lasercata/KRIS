#!/bin/python3
# -*- coding: utf-8 -*-

'''This program allow you to encrypt and decrypt with RSA cipher.'''

RSA__auth = 'Lasercata, Elerias'
RSA__last_update = '15.04.2021'
RSA__version = '3.8_kris'


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

from modules.ciphers.kris.AES import AES

#---------packages
import math
from random import randint
from secrets import randbits

from datetime import datetime as dt
from time import sleep

from os import chdir, mkdir, getcwd, listdir, rename, remove
from os.path import expanduser, isfile

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
    cl_out(c_error, tr('The file "version.txt" was not found. A version will be set but can be wrong.'))
    kris_version = '2.0.0 ?'

else:
    if len(kris_version) > 16:
        cl_out(c_error, tr('The file "version.txt" contain more than 16 characters, so it certainly doesn\'t contain the actual version. A version will be set but can be wrong.'))
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
def chd_rsa(path, first=False, interface=None):
    '''
    Change current directory to [cracker]/RSA_keys/[path], where [cracker] is
    the path where cracker is launched.

    If first is True, and if the folder "RSA_keys" don't exist, generate "auto_generated_512" keys.

    If directory "RSA_keys" don't exist, it create it.

    If [path] don't exist, return to last path and raise a FileNotFoundError exeption,
    Return the old path else.
    '''

    old_path = getcwd()

    chd('.') #chdir to cracker's data

    #------cd to 'RSA_keys'
    try:
        chdir('RSA_keys')

    except FileNotFoundError:
        mkdir('RSA_keys')
        print('"RSA_keys" folder created at "{}" !'.format(getcwd()))
        chdir('RSA_keys')

        if first:
            msg1 = 'It seem that it is the first time you launch this application on this computer. New RSA 512 bits keys will be generated, but you should consider to generate yours (at least 2048 bits)'
            msg2 = 'Keys path : {}/RSA_keys'.format(glb.KRIS_data_path)

            if interface == None:
                print(msg1)
                print(msg2)

            elif interface == 'console':
                cl_out(c_output, '{}\n{}'.format(msg1, msg2))

            else:
                QMessageBox.about(None, 'Ciphers info ― KRIS', '<h3>{}</h3>\n<h4>{}</h4>'.format(msg1, msg2))


            RsaKeys('auto_generated_512', interface).generate(512)


    try:
        chdir(path)

    except FileNotFoundError as err:
        chdir(old_path)
        raise FileNotFoundError(err)

    return old_path


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
    '''Remove the list "lst_to_rm" from "lst".'''

    for k in lst:
        if k in lst_to_rm:
            lst.remove(k)

    return lst


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


#---------CSV
class CSV:
    '''Class dealing with csv file.'''

    def __init__(self, fn, delim=','):
        '''Initiate some variables'''

        self.fn = fn
        self.delim = delim

    #------read
    def read(self):
        '''Return a list of dict of the file self.fn.'''

        with open(self.fn) as f_csv:
            table = csv.DictReader(f_csv, delimiter=self.delim)

            lst = []
            for k in table:
                lst.append(k)

        return lst

    #------write
    def write(self, fdnames, row):
        '''Write row in csv file self.fn with fieldnames fdnames.'''

        with open(self.fn, 'w') as f_csv:
            writer = csv.DictWriter(f_csv, fieldnames=fdnames)
            writer.writeheader()
            writer.writerow(row)


    #------get_fieldnames
    def get_fdn(self):
        '''Return the fieldnames in a tuple.'''

        with open(self.fn) as f:
            fdn = f.readline()

        return tuple(fdn.strip('\n').split(self.delim))


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

        self.keys = {} #will contain the keys

        if type(keys) == str:
            try:
                self.keys['e'] = RsaKeys(keys).read(0)
                self.keys['d'] = RsaKeys(keys).read(1)

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


    def sign(self, txt):
        '''
        Sign the message 'txt'.
        It encrypt 'txt' using the private key.
        '''

        if self.pv_key == None:
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
    def generate(self, size, save=True, overwrite=False, md_stored='hexa'):
        '''
        Function which generate RSA keys.

        Arguments :
            .self.k_name : the name to give for the keys ;

            .size : wanted size for the keys (+/- 4), is an intenger (2048 recomended) ;
            .save : save in files or just return keys, should be in (True, False) ;
            .overwrite : in (True, False). If the dir keys_names already exist, if True, overwrite it,
                return an error msg else ;
            .md_stored : the way how the keys are stored, i.e. in decimal or hexadecimal.
                Should be "hexa" or "dec". Default is "hexa".

        If save is True, the program make a file, in chd_rsa('.'), named :
            '[self.k_name].pvk-h' if md_stored is 'hexa' ;
            '[self.k_name].pvk-d' else.

        Return :
            -2 if the set of keys already exist and overwrite is False ;
            pbk, pvk, n_strth otherwise.
        '''


        if save not in (True, False) or overwrite not in (True, False) or md_stored not in ('hexa', 'dec'):
            raise ValueError('The arguments were not the good !!!')

        if save:
            if md_stored == 'dec':
                fn = str(self.k_name) + '.pvk-d'

            else:
                fn = str(self.k_name) + '.pvk-h'

            old_path = chd_rsa('.')

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

            #---make file
            fdn = tuple(v.keys())
            row = v
            CSV(fn).write(fdn, row)

            chdir(old_path)


        return pbk, pvk, n_strth



    def read(self, mode):
        '''
        Return the key to use with RSA.
        Read the keys from the key file created by this program.

        self.k_name : the name given when creating keys ;
        mode : 0 - encrypt (pbk), 1 - decrypt (pvk), used to choose between public and private keys.

        Resolution order (to find the good key extention) :
            pvk-h ;
            pvk-d ;
            pbk-h ;
            pbk-d.
        '''

        if mode not in (0, 1):
            raise ValueError('"mode" should be 0 or 1 (int), but "' + str(mode) + '" was found !!!')

        old_path = chd_rsa('.')

        if isfile(self.k_name + '.pvk-h'):
            fn = self.k_name + '.pvk-h'

        elif isfile(self.k_name + '.pvk-d'):
            fn = self.k_name + '.pvk-d'

        elif mode == 1: #no pvk
            raise TypeError("Can't read the private key of a pbk set of keys !!!")

        elif isfile(self.k_name + '.pbk-h'):
            fn = self.k_name + '.pbk-h'

        elif isfile(self.k_name + '.pbk-d'):
            fn = self.k_name + '.pbk-d'

        else:
            raise FileNotFoundError('The keys "' + str(self.k_name) + '" were NOT found !!!')

        md = ('hexa', 'dec')[('.pvk-d' in fn) or ('.pbk-d' in fn)]


        infos = CSV(fn).read()[0]
        n_ = infos['n']

        if mode == 0:
            ed_ = infos['e']

        else:
            ed_ = infos['d']


        chdir(old_path)

        #------
        if md == 'dec':
            ed, n = int(ed_), int(n_)

        else:
            ed, n = int(ed_, 16), int(n_, 16) #convert to decimal


        return ed, n



    #------export_pubic_key
    def export(self, md_stored_out='hexa'):
        '''
        Function which export the public key to a file named :
            '[self.k_name].pbk-h' if md_stored_out is 'hexa' ;
            '[self.k_name].pbk-d' else.

        - md_stored_out : the way how the exported keys will be stored, i.e. in
        decimal or hexadecimal. Should be "hexa" or "dec".

        return -1 if the file was not found, None otherwise.
        '''

        if md_stored_out not in ('hexa', 'dec'):
            raise ValueError('"md_stored_out" should be "dec" or "hexa", but "' + str(md_stored_out) + '" was found !!!')

        try:
            (pbk, pvk), (p, q, n, phi, e, d), (n_strth, date_) = self.show_keys()

        except ValueError:
            return -1

        v = {
            'e': e,
            'n': n,
            'date' : date_,
            'date_export' : date(),
            'n_strenth' : n_strth
        }

        #---write
        if md_stored_out == 'dec':
            fn = self.k_name + '.pbk-d'

        else:
            fn = self.k_name + '.pbk-h'

            for k in v:
                if k not in ('date', 'date_export'):
                    v[k] = format(int(v[k]), 'x') #convert numbers to hexadecimal


        old_path = chd_rsa('.')

        fdn = tuple(v.keys()) #('e', 'n', 'date', 'date_export', 'n_strenth')
        row = (v)
        CSV(fn).write(fdn, row)

        chdir(old_path)


    #---------show_keys
    def show_keys(self, get_stg_md=False):
        '''
        Return the keys and info about them.

        - self.k_name : the keys' name ;
        - get_stg_md : If True, return only the way how they are stored, i.e. "hexa" or "dec". Should be True or False.

        The way how the keys are stored is automaticly detected.

        Order of the key finding :
            .1 : *.pvk-h ;
            .2 : *.pvk-d ;
            .3 : *.pbk-h ;
            .4 : *.pbk-d.

        Return :
            (pbk, pvk), (p, q, n, phi, e, d), (n_strth, date_) --- if it's a *.pvk-* file ;
            pbk, (n, e), (n_strth, date_, date_exp) --- if it's a *.pkb-* file ;
            md_stored ('hexa' or 'dec') --- if get_stg_md is True ;
            -1 --- if the file was not found.
        '''

        if get_stg_md not in (True, False):
            raise ValueError('"get_stg_md" should be True or False, but "' + str(get_stg_md) + '" was found !!!')

        old_path = chd_rsa('.')

        if isfile(self.k_name + '.pvk-h'):
            fn = self.k_name + '.pvk-h'

        elif isfile(self.k_name + '.pvk-d'):
            fn = self.k_name + '.pvk-d'

        elif isfile(self.k_name + '.pbk-h'):
            fn = self.k_name + '.pbk-h'

        elif isfile(self.k_name + '.pbk-d'):
            fn = self.k_name + '.pbk-d'

        else:
            return -1

        md = (('all', 'pbk')[('.pbk-h' in fn) or ('.pbk-d' in fn)], ('hexa', 'dec')[('.pvk-d' in fn) or ('.pbk-d' in fn)]) #(key_type, md_storage)


        if get_stg_md:
            chdir(old_path)
            return md[1]

        if md[0] == 'pbk': #---RSA pbk
            infos = CSV(fn).read()[0]
            date_, date_exp, n_strth = infos['date'], infos['date_export'], infos['n_strenth']
            e, n = infos['e'], infos['n']

            if md[1] == 'hexa': #convert in decimal
                n_strth = str(int(n_strth, 16))
                e, n = str(int(e, 16)), str(int(n, 16))

            pbk = str(e) + ',' + str(n)

            chdir(old_path)

            return pbk, (n, e), (n_strth, date_, date_exp)


        else: #---RSA_all
            infos = CSV(fn).read()[0]
            date_, n_strth = infos['date'], infos['n_strenth']
            p, q, n, phi, e, d = infos['p'], infos['q'], infos['n'], infos['phi'], infos['e'], infos['d']

            if md[1] == 'hexa': #convert in decimal
                n_strth = str(int(n_strth, 16))
                p, q, n, phi, e, d = str(int(p, 16)), str(int(q, 16)), \
                    str(int(n, 16)), str(int(phi, 16)), str(int(e, 16)), str(int(d, 16))

            pvk = str(d) + ',' + str(n)
            pbk = str(e) + ',' + str(n)

            chdir(old_path)

            return (pbk, pvk), (p, q, n, phi, e, d), (n_strth, date_)



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
            lst_keys, lst_values, lst_infos = self.show_keys()
            stg_md = self.show_keys(True)

        except ValueError:
            return -1


        if len(lst_infos) == 2: #pvk
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

            else:
                fn = str(self.k_name) + '.pvk-h'

                for k in v:
                    if k != 'date':
                        v[k] = format(int(v[k]), 'x') #convert numbers to hexadecimal

            pbk = v['e'], v['n']
            pvk = v['d'], v['n']

            #---check if it not already exists
            old_path = chd_rsa('.')

            if isfile(fn):
                chdir(old_path)
                return -2

            #---make file
            fdn = tuple(v.keys()) #('p', 'q', 'n', 'phi', 'e', 'd', 'date', 'n_strenth')
            row = v
            CSV(fn).write(fdn, row)

            old_md = ('d', 'h')[stg_md == 'hexa']
            remove(fn[:-1] + old_md)

            try:
                remove(fn[:-1] + old_md + '.enc')

            except FileNotFoundError:
                pass

            chdir(old_path)

        else: #pbk
            v = {
                'e' : lst_values[1],
                'n' : lst_values[0],
                'date' : lst_infos[1],
                'date_export' : lst_infos[2],
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

            old_path = chd_rsa('.')

            if isfile(fn):
                chdir(old_path)
                return -2

            fdn = tuple(v.keys()) #('e', 'n', 'date', 'date_export', 'n_strenth')
            row = (v)

            CSV(fn).write(fdn, row)

            old_md = ('d', 'h')[stg_md == 'hexa']
            remove(fn[:-1] + old_md)

            try:
                remove(fn[:-1] + old_md + '.enc')

            except FileNotFoundError:
                pass

            chdir(old_path)



    #------rename
    def rename(self, new_name):
        '''
        Function which can rename a set of keys

        self.k_name : the set of keys' name ;
        new_name : the new set of keys' name.

        Return -1 if the file was not found, None otherwise.
        '''

        try:
            lst_keys, lst_values, lst_infos = self.show_keys()
            stg_md = self.show_keys(True)

        except ValueError:
            return -1

        new_name = str(new_name)
        old_path = chd_rsa('.')

        if len(lst_infos) == 2: #pvk
            ext = ('.pvk-h', '.pvk-d')[stg_md == 'dec']

        else:
            ext = ('.pbk-h', '.pbk-d')[stg_md == 'dec']

        rename(str(self.k_name) + ext, new_name + ext)

        try:
            remove(str(self.k_name) + ext + '.enc')

        except FileNotFoundError:
            pass

        chdir(old_path)


    def get_fn(self, mode='ed'):
        '''
        Return the filename of the key (with the extention)

        - self.k_name : the RSA key's name ;
        - mode : in ('d', 'e', 'ed'). If 'd': only watch decrypted keys, if 'e': only watch encrypted keys, if 'ed': watch both.

        Resolution order (to find the good key extention) if mode == 'ed' :
            pvk-h ;
            pvk-d ;
            pbk-h ;
            pbk-d ;
            pvk-h.enc ;
            pvk-d.enc ;
            pbk-h.enc ;
            pbk-d.enc.

        It is the same order if 'd' or 'e', but without the other part.
        '''

        old_path = chd_rsa('.')

        if mode not in ('d', 'e', 'ed'):
            raise ValueError('The mode should be in ("d", "e", "ed"), but "{}" was found !!!'.format(mode))

        if isfile(self.k_name + '.pvk-h') and mode in ('ed', 'd'):
            fn = self.k_name + '.pvk-h'

        elif isfile(self.k_name + '.pvk-d') and mode in ('ed', 'd'):
            fn = self.k_name + '.pvk-d'

        elif isfile(self.k_name + '.pbk-h') and mode in ('ed', 'd'):
            fn = self.k_name + '.pbk-h'

        elif isfile(self.k_name + '.pbk-d') and mode in ('ed', 'd'):
            fn = self.k_name + '.pbk-d'


        elif isfile(self.k_name + '.pvk-h.enc') and mode in ('ed', 'e'):
            fn = self.k_name + '.pvk-h.enc'

        elif isfile(self.k_name + '.pvk-d.enc') and mode in ('ed', 'e'):
            fn = self.k_name + '.pvk-d.enc'

        elif isfile(self.k_name + '.pbk-h.enc') and mode in ('ed', 'e'):
            fn = self.k_name + '.pbk-h.enc'

        elif isfile(self.k_name + '.pbk-d.enc') and mode in ('ed', 'e'):
            fn = self.k_name + '.pbk-d.enc'

        else:
            chdir(old_path)
            raise FileNotFoundError('The key "{}" does not seem to exists in {} mode !!!'.format(self.k_name, mode))

        chdir(old_path)

        return fn


    #------Encrypt key
    def encrypt(self, key, full=False):
        '''
        Encrypt 'self.k_name' with AES-256-CBC using the password
        `RSA_keys_pwd` (Hasher('sha256').hash(clear_KRIS_pwd)[:32])
        and make a file 'self.k_name' + ext + '.enc'

        - key : the password ;
        - full : a bool which indicates if self.k_name contain the extension.
        '''

        if full:
            fn = self.k_name

        else:
            fn = self.get_fn('d')

        file = '{}/RSA_keys/{}'.format(glb.KRIS_data_path, fn)
        AES(256, key).encryptFile(file, file + '.enc')


    #------Encrypt key
    def decrypt(self, key, full=False):
        '''
        Decrypt self.keys_name with AES-256-CBC using the password
        `RSA_keys_pwd` (Hasher('sha256').hash(clear_KRIS_pwd)[:32])

        - key : the password ;
        - full : a bool which indicates if self.k_name contain the extension.
        '''

        if full:
            fn = self.k_name

        else:
            fn = self.get_fn('e')

        file = '{}/RSA_keys/{}'.format(glb.KRIS_data_path, fn)
        AES(256, key).decryptFile(file, file[:-4])



#------SecureRsaKeys
class SecureRsaKeys:
    '''Class which manages the RSA keys encryption and decription.'''

    def __init__(self, key, old_key=None, interface=None):
        '''
        Initiate class.

        - key : the key used to encrypt the RSA keys (Hasher('sha256').hash(clear_KRIS_pwd)[:32]) ;
        - old_key : the old key (before changing password). Used to decrypt an eventual key which is
        only encrypted in self.rm_enc.
        '''

        if interface not in (None, 'gui', 'console'):
            raise ValueError('The argument "interface" should be None, "gui", or "console", but {} of type {} was found !!!'.format(interface, type(interface)))

        self.key = key
        self.old_key = old_key
        self.interface = interface


    def encrypt(self):
        '''Encrypt all the private RSA keys present in Data/RSA_keys using RsaKeys.encrypt'''

        RSA_keys = self._get_pvk()

        for k in RSA_keys:
            RsaKeys(k, self.interface).encrypt(self.key)


    def decrypt(self):
        '''Decrypt all the private RSA keys present in Data/RSA_keys using RsaKeys.decrypt'''

        RSA_keys = self._get_pvk_enc()

        for k in RSA_keys:
            RsaKeys(k, self.interface).decrypt(self.key)


    def rm_clear(self):
        '''Delete the clear private RSA keys.'''

        enc_keys = self._get_pvk_enc(True)

        for k in self._get_pvk(True):
            if k not in enc_keys:
                RsaKeys(k, self.interface).encrypt(self.key, True)

            remove('{}/RSA_keys/{}'.format(glb.KRIS_data_path, k))


    def rm_enc(self):
        '''Delete the encrypted private RSA keys. Used when changing password.'''

        RSA_keys = self._get_pvk(True)

        for k in self._get_pvk_enc(True):
            if k not in RSA_keys:
                RsaKeys(k, self.interface).decrypt(self.old_key)

            remove('{}/RSA_keys/{}'.format(glb.KRIS_data_path, k))


    def _get_pvk(self, ext=False):
        '''
        Return the list of all the *.pvk-* files.

        - ext : a bool which indicate if keep the extension in the file names.
        '''

        old_path = chd_rsa('.')
        lst_k = listdir()
        chdir(old_path)

        pvk_l = []

        for k in lst_k:
            if k[-6:] in ('.pvk-d', '.pvk-h'):
                if ext:
                    pvk_l.append(k)
                else:
                    pvk_l.append(k[:-6])

        return pvk_l


    def _get_pvk_enc(self, ext=False):
        '''
        Return the list of all the *.pvk-*.enc files, without the extension.

        - ext : a bool which indicate if keep the extension in the file names.
        '''

        old_path = chd_rsa('.')
        lst_k = listdir()
        chdir(old_path)

        pvk_enc_l = []

        for k in lst_k:
            if k[-10:] in ('.pvk-d.enc', '.pvk-h.enc'):
                if ext:
                    pvk_enc_l.append(k)
                else:
                    pvk_enc_l.append(k[:-10])

        return pvk_enc_l




#------list_keys
def list_keys(mode='any'):
    '''
    Function which lists the existing keys.

    if mode is 'any', return seven tuples :
        - pvk-d without pbk-d ;
        - pbk-d ;
        - pvk-h without pbk-h ;
        - pbk-h ;
        - pvk-* without pbk-* ;
        - all (pvk-d, pvk-h, pbk-d, pbk-h, without duplicates), without .enc (but if the .enc is also decrypted, it will be in it) ;
        - .enc

    mode : what return. Should be "pvk", "pbk", "pvk_hex", "pbk_hex", "pvk_without_pbk", "enc", "all", or "any".

    if mode is "any", return :
        pvk, pbk, hex_pvk, hex_pbk, lst_pvk_without_pbk, enc, all

    else return the corresponding value.
    '''

    if mode not in ('pvk', 'pbk', 'pvk_hex', 'pbk_hex', 'pvk_without_pbk', 'enc', 'all', 'any'):
        raise ValueError('"mode" should be "pvk", "pbk", "pvk_hex", "pbk_hex", "pvk_without_pbk", "enc", "all" or "any", but "' + str(mode) + '" was found !!!')

    old_path = chd_rsa('.')
    lst_k = listdir()
    chdir(old_path)

    lst_pvk = []
    lst_pbk = []
    lst_hex_pvk = []
    lst_hex_pbk = []
    lst_enc = []
    lst_all = []

    for k in lst_k:
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

    #---
    lst_pvk = rm_lst(lst_pvk, lst_pbk)
    lst_hex_pvk = rm_lst(lst_hex_pvk, lst_hex_pbk)

    lst_pvk_without_pbk = rm_lst(lst_pvk + lst_hex_pvk, lst_pbk + lst_hex_pbk)

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

    elif mode == 'pvk_without_pbk':
        return tuple(lst_pvk_without_pbk)

    elif mode == 'enc':
        return tuple(lst_enc)

    return (
        tuple(lst_pvk),
        tuple(lst_pbk),
        tuple(lst_hex_pvk),
        tuple(lst_hex_pbk),
        tuple(lst_pvk_without_pbk),
        tuple(lst_all)
    )


# by lasercata and Elerias

# _______        _______  ______ _____ _______ _______
# |______ |      |______ |_____/   |   |_____| |______
# |______ |_____ |______ |    \_ __|__ |     | ______|

#        _______ _______ _______  ______ _______ _______ _______ _______
# |      |_____| |______ |______ |_____/ |       |_____|    |    |_____|
# |_____ |     | ______| |______ |    \_ |_____  |     |    |    |     |
