#!/bin/python3
# -*- coding: utf-8 -*-

'''
KRIS allow you to encrypt and decypt data using the PGP scheme.

It uses the AES (Advanced Encryption Standard) cipher to encrypt messages,
created by Daemen and Rijmen and implemented in C by Elerias ;

and the RSA chipher to encrypt the randomly generated key for AES,
created by Ron Rivest, Adi Shamir, and Leonard Adleman, and implemented in python by Lasercata and Elerias.
'''

KRIS__auth = 'Lasercata'
KRIS__last_update = '2023.08.13'
KRIS__version = '2.0'


##-import
#---------librairies
from math import *
from secrets import choice as schoice

#from datetime import datetime as dt
#from time import sleep

import os
from os import chdir, mkdir, getcwd, listdir, walk
from os.path import expanduser
from shutil import rmtree

from ast import literal_eval #safer than eval

import platform

from PyQt5.QtWidgets import QMessageBox

#---------KRIS' modules
from modules.ciphers.RSA import *
from modules.ciphers.AES import *
from modules.ciphers.hasher import *

#from modules.base.console.color import cl_out, c_error

def cl_out(col, prompt):
    print(prompt)


##-ini
alf_09_az_AZ_spe = (
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',

    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',

    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
    'P', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',

    '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/',
    ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|',
    '}', '~', '£', '§', '¨', '°', '²', 'µ', '’', '€'
)

lat_1 = tuple([chr(k) for k in range(128)])

alf = lat_1
# Used to generate AES key


##-functions
def AES_rnd_key_gen(n, mode=256): #TODO: improve this
    '''
    Return a randomly generated key for AES.

    - n    : the length of the key ;
    - mode : the AES mode, 128, 192 or 256.
    '''

    if mode not in (128, 192, 256):
        raise ValueError('AES cipher can only have a key of 128, 192 or 256 bits, not ' + str(mode))

    if n > mode // 8:
        raise ValueError('Key is too big for an AES ' + str(mode) + ' cipher')

    key = ''.join([schoice(alf) for k in range(n)]) #TODO: use a more secure random generator. Also, consider bytes strings (but may not be handy)

    return key


##-main
class Kris:
    '''Class defining the way how to encrypt and decrypt'''

    def __init__(self, RSA_ciph, AES_mode=256, encod='utf-8', mode='t', interface=None):
        '''Initiate the Kris object.

        - RSA_ciph  : the RSA cipher. Should be the instance of a RSA class with
           at least the methods `encrypt` and `decrypt`. The key is given when
           instantiating the class ;
        - AES_mode  : the AES's mode. Should be 128, 192 or 256. Default is 256 ;
        - encod     : the encoding. Default is utf-8 ;
        - mode      : the bytes mode of the decrypted text (input). Should be "b" or "t". Default is "t" ;
        - interface : the interface using this function. Should be None,
           'gui', or 'console'. Used to choose the progress bar.
        '''

        if interface not in (None, 'gui', 'console'):
            raise ValueError('The argument "interface" should be None, "gui", \
                or "console", but {} of type {} was found !!!'.format(interface, type(interface)))

        self.interface = interface

        if AES_mode not in (256, 192, 128):
            raise ValueError('The argument "AES_mode" should be 128, 192, \
                or 256, but "{}" was found !!!'.format(AES_mode))

        if str(mode).lower() not in ('t', 'b'):
            raise ValueError('The argument "mode" should be "t" or "b", but \
                "{}" was found !!!'.format(mode))

        self.RSA_ciph = RSA_ciph
        self.mode = mode

        self.AES_mode = AES_mode
        self.encod = encod
        self.md = {'t' : 'str', 'b' : 'bytes'}[mode]
        self.interface = interface


    def __repr__(self):
        '''Represent the Kris object.'''

        return "Kris(RSA_ciph='{}', AES_mode='{}', encod='{}', mode='{}', interface='{}')".format(
            self.RSA_ciph,
            self.AES_mode,
            self.encod,
            self.mode,
            self.interface
        )


    #---------encrypt
    def encrypt(self, msg, AES_key_size=16):
        '''
        Return the randomly generated AES key encrypted with RSA, followed by the message, encrypted with the AES key :
            return (AES_key_c, msg_c)

        - msg          : the message to encrypt ;
        - AES_key_size : the size of the AES key to generate. Default is 16 characters.
        '''

        #------AES key
        AES_key = AES_rnd_key_gen(AES_key_size, self.AES_mode)
        AES_key_c = self.RSA_ciph.encrypt(AES_key)
        if type(AES_key_c) == bytes:
            AES_key_c = AES_key_c.decode()

        #------encrypt text
        AES_cipher = AES(self.AES_mode, AES_key, False, self.encod)
        msg_c = AES_cipher.encryptText(msg, encoding=self.encod, mode_c='hexa', mode=self.md)


        return AES_key_c, msg_c


    #---------decrypt
    def decrypt(self, msg_c, rm_padding=False):
        '''
        Return the decrypted message.

        - msg_c      : the encrypted message. Should be a tuple or list of the form (AES_key_c, msg_c) ;
        - rm_padding : Should be a boolean. If True, remove the padding inserted at the end of the message ('\x00').
        '''

        if rm_padding not in (0, 1):
            raise ValueError('The argument "rm_padding" should be a boolean, \
                but "{}" was found !!!'.format(rm_padding))

        if type(msg_c) not in (list, tuple, set):
            raise ValueError('The argument "msg_c" should be a list, tuple or \
                a set, but a "{}" was found !!!'.format(type(msg_c)))

        if len(msg_c) != 2:
            raise ValueError('The argument "msg_c" should have a length of \
                2, but a length of "{}" was found !!!'.format(len(msg_c)))


        #------AES key
        AES_key = self.RSA_ciph.decrypt(msg_c[0])

        #------decrypt text
        try:
            AES_cipher = AES(self.AES_mode, AES_key, False, encoding=self.encod)

        except ValueError as err:
            msg = 'You did NOT selected the right RSA key !!!'
            print_error(msg, title='Bad RSA key !!!', interface=self.interface)

            raise ValueError(msg)

        msg = AES_cipher.decryptText(msg_c[1], mode_c='hexa', encoding=self.encod, mode=self.md)


        if rm_padding:
            return msg.strip('\x00')

        return msg


    #---------encrypt file
    def encryptFile(self, fn_in, fn_out, AES_key_size=16):
        '''
        Encrypt the file `fn_in` with AES using a random key, which is then encrypted with RSA.
        The encrypted AES key is added at the end of the file.

        - fn_in : the name of the file to encrypt ;
        - fn_out : the name of the output encrypted file ;
        - AES_key_size : the size of the AES key to generate. Default is 16 characters.
        '''

        #------AES key
        AES_key = AES_rnd_key_gen(AES_key_size, self.AES_mode)
        AES_key_c = self.RSA_ciph.encrypt(AES_key)

        #------encrypt text
        AES_cipher = AES(self.AES_mode, AES_key, False, self.encod)
        AES_cipher.encryptFile(fn_in, fn_out)

        with open(fn_out, 'ab') as f:
            f.write(b'\n' + AES_key_c)

        return AES_key_c


    #---------decrypt file
    def decryptFile(self, fn_in, fn_out):
        '''
        Decrypt the file `fn_in` which was encrypted with self.encryptFile.

        - fn_in : the name of the file to encrypt ;
        - fn_out : the name of the output encrypted file.
        '''

        #------Read AES key from file and remove it.
        with open(fn_in, 'r+b') as f: #https://stackoverflow.com/a/10289740
            f.seek(0, os.SEEK_END)

            pos = f.tell() - 1

            while pos > 0 and f.read(1) != b'\n':
                pos -= 1
                f.seek(pos, os.SEEK_SET)

            if pos > 0:
                f.seek(pos, os.SEEK_SET)
                AES_key_c = f.read()
                f.seek(pos, os.SEEK_SET)
                f.truncate()

        #------AES key
        try:
            AES_key = self.RSA_ciph.decrypt((AES_key_c.decode()).replace('\n', ''))

        except Exception as err:
            print_error(err, title='Error', interface=self.interface)

            with open(fn_in, 'ab') as f:
                f.write(AES_key_c)

            return -1

        #------decrypt text
        try:
            AES_cipher = AES(self.AES_mode, AES_key, False, encoding=self.encod)

        except ValueError as err:
            msg = 'You did NOT selected the right RSA key !!!'
            print_error(msg, title='Bad RSA key !!!', interface=self.interface)

            raise ValueError(msg)

        AES_cipher.decryptFile(fn_in, fn_out)

        #------Rewrite the key in the file, for future decryptions
        with open(fn_in, 'ab') as f:
            f.write(AES_key_c)



class SignedKRIS:
    '''Defining the SignedKRIS cipher.'''

    def __init__(self, reciver_RSA, sender_RSA, AES_mode=256, encod='utf-8', mode='t', hash_='sha256', interface=None):
        '''
        Initiate the SignedKRIS cipher.

        - reciver_RSA : the RSA cipher used to encrypt / decrypt the message ;
        - sender_RSA  : the RSA cipher used to sign / check the message integrity.

        For more details, and for the others arguments, cf to the Kris and RsaSign documentation.
        '''

        self.Kris = Kris(reciver_RSA, AES_mode, encod, mode, interface)
        self.RsaSign = RsaSign(sender_RSA, hash_, interface=interface)


    def encrypt(self, txt, AES_key_size=16):
        '''
        Encrypt 'txt' with the KRIS cipher.

        Return :
            (AES_key_c, msg_c, msg_s)

            Where :
                - AES_key_c : is the RSA encrypted AES key ;
                - msg_c     : is the message encrypted with the AES key ;
                - msg_s     : is the RSA signature of the clear message.
        '''

        AES_key_c, msg_c = self.Kris.encrypt(txt, AES_key_size)
        msg_s = self.RsaSign.sign(txt)

        return AES_key_c, msg_c, msg_s


    def decrypt(self, txt, rm_padding=False):
        '''
        Decrypt 'txt' using the Kris cipher.

        Return :
            (msg_d, match)

            Where :
                - msg_d : is the decrypted message ;
                - match : is a bool which indicates if the signature match.
        '''

        msg_d = self.Kris.decrypt(txt[:2], rm_padding)
        match = self.RsaSign.check(msg_d, txt[2])

        return msg_d, match


# by lasercata and Elerias

# _______        _______  ______ _____ _______ _______
# |______ |      |______ |_____/   |   |_____| |______
# |______ |_____ |______ |    \_ __|__ |     | ______|

#        _______ _______ _______  ______ _______ _______ _______ _______
# |      |_____| |______ |______ |_____/ |       |_____|    |    |_____|
# |_____ |     | ______| |______ |    \_ |_____  |     |    |    |     |
