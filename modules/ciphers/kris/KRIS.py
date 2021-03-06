#!/bin/python3
# -*- coding: utf-8 -*-

'''
KRIS allow you to encrypt and decypt data using the PGP scheme.

It uses the AES (Advanced Encryption Standard) cipher to crypt messages,
created by Daemen and Rijmen and implemented in python by Elerias ;

and the RSA chipher to crypt the randomly generated key with AES,
created by Ron Rivest, Adi Shamir, and Leonard Adleman, and implemented in python by Lasercata and Elerias.
'''

KRIS__auth = 'Lasercata'
KRIS__last_update = '05.03.2021'
KRIS__version = '1.2_kris'


##-import
#---------librairies
from math import *
from secrets import choice as schoice

#from datetime import datetime as dt
#from time import sleep

from os import chdir, mkdir, getcwd, listdir, walk
from os.path import expanduser
from shutil import rmtree

from ast import literal_eval #safer than eval

import platform

from PyQt5.QtWidgets import QMessageBox

#---------KRIS' modules
from modules.ciphers.kris.RSA import *
from modules.ciphers.kris.AES import *
from modules.ciphers.hashes.hasher import *

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
def AES_rnd_key_gen(n, mode=256): #todo: improve this
    '''
    Return a randomly generated key for AES.

    - n : the length of the key ;
    - mode : the AES mode, 128, 192 or 256.
    '''

    if mode not in (128, 192, 256):
        raise ValueError('AES cipher can only have a key of 128, 192 or 256 bits, not ' + str(mode))

    if n > mode // 8:
        raise ValueError('Key is too big for an AES ' + str(mode) + ' cipher')

    key = ''.join([schoice(alf) for k in range(n)])

    return key


##-main
class Kris:
    '''Class defining the way how to encrypt and decrypt'''

    def __init__(self, key, AES_mode=256, encod='utf-8', mode='t', interface=None):
        '''Initiate the Kris object.

        .key : The RSA key. Cf the the doc of the RSA class (modules/ciphers/kris/RSA.py) ;
        .AES_mode : the AES's mode. Should be 128, 192 or 256. Default is 256 ;
        .encod : the encoding. Default is utf-8 ;
        .mode : the bytes mode of the decrypted text (input). Should be "b" or "t". Default is "t" ;
        .interface : the interface using this function. Should be None,
         'gui', or 'console'. Used to choose the progress bar.
        '''

        self.RSA_ciph = RSA(key, interface) #Create the RSA cipher or raise error if key or interface is wrong.

        if AES_mode not in (256, 192, 128):
            raise ValueError('The argument "AES_mode" should be 128, 192, \
                or 256, but "{}" was found !!!'.format(AES_mode))

        if str(mode).lower() not in ('t', 'b'):
            raise ValueError('The argument "mode" should be "t" or "b", but \
                "{}" was found !!!'.format(mode))


        self.key = key #for __repr__
        self.mode = mode

        self.AES_mode = AES_mode
        self.encod = encod
        self.md = {'t' : 'str', 'b' : 'bytes'}[mode]
        self.interface = interface


    def __repr__(self):
        '''Represent the Kris object.'''

        return "Kris(key='{}', AES_mode='{}', encod='{}', mode='{}', interface='{}')".format(
            self.key,
            self.AES_mode,
            self.encod,
            self.mode,
            self.interface
        )



    #---------encrypt
    def encrypt(self, msg, AES_key_size=16):
        '''
        Return the randomly generated AES key crypted with RSA, followed by the message, crypted with the AES key :
            return (AES_key_c, msg_c)

        - msg : the message to encrypt ;
        - AES_key_size : the size of the AES key to generate. Default is 16 characters.
        '''

        #------AES key
        AES_key = AES_rnd_key_gen(AES_key_size, self.AES_mode)
        AES_key_c = self.RSA_ciph.encrypt(AES_key)

        #------encrypt text
        AES_cipher = AES(self.AES_mode, AES_key, False, self.encod)
        msg_c = AES_cipher.encryptText(msg, encoding=self.encod, mode_c='hexa', mode=self.md)


        return AES_key_c, msg_c


    #---------decrypt
    def decrypt(self, msg_c, rm_padding=False):
        '''
        Return the decrypted message.

        - msg_c : the encrypted message. Should be a tuple or list of the form (AES_key_c, msg_c) ;
        - rm_padding : Should be a boolean. If True, remove the padding inserted at the end of the message ('\x00').
        '''

        if rm_padding not in (0, 1):
            raise ValueError('The argument "rm_padding" should be a boolean, \
                but "{}" was found !!!'.format(rm_padding))

        if type(msg_c) not in (list, tuple, set):
            raise ValueError('The argument "msg_c" should be a list, tuple or \
                a set, but a "{}" was found !!!'.format(type(msg_c)))

        else:
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

            if self.interface == None:
                print(msg)

            elif self.interface == 'console':
                cl_out(c_error, msg)

            else:
                QMessageBox.critical(None, 'Bad RSA key !!!', '<h2>{}</h2>'.format(msg))

            raise ValueError(msg)

        msg = AES_cipher.decryptText(msg_c[1], mode_c='hexa', encoding=self.encod, mode=self.md)


        if rm_padding:
            return msg.strip('\x00')

        return msg


class SignedKRIS:
    '''Defining the SignedKRIS cipher.'''

    def __init__(self, reciver_key, sender_key, AES_mode=256, encod='utf-8', mode='t', hash_='sha256', interface=None):
        '''
        Initiate the SignedKRIS cipher.

        - reciver_key : the public/private key which encrypts/decrypts the message ;
        - sender_key : the private/public key which signs/checks the message's hash.
        For others args, cf to Kris and RsaSign.
        '''

        self.Kris = Kris(reciver_key, AES_mode, encod, mode, interface)
        self.RsaSign = RsaSign(sender_key, hash_, interface=interface)


    def encrypt(self, txt, AES_key_size=16):
        '''
        Encrypt 'txt' with the KRIS cipher.

        Return :
            (AES_key_c, msg_c, msg_s)

            Where :
                - AES_key_c : is the RSA encrypted AES key ;
                - msg_c : is the message encrypted with the AES key ;
                - msg_s : is the RSA signature of the clear message.
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
