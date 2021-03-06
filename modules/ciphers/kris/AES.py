#!/bin/python3
# -*- coding: utf-8 -*-

"""AES (Advanced Encryption Standard) by Daemen and Rijmen"""

auth = 'Elerias'
last_update = '11.08.2020'
version = '2.0.2'
sites = ["https://en.wikipedia.org/wiki/Advanced_Encryption_Standard", "https://en.wikipedia.org/wiki/Rijndael_S-box", "https://en.wikipedia.org/wiki/Rijndael_MixColumns", "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf", "https://fr.wikipedia.org/wiki/Division_d%27un_polyn%C3%B4me", "https://www.samiam.org/galois.html", "https://www.samiam.org/key-schedule.html", "https://en.wikipedia.org/wiki/AES_key_schedule"]

update_notes = """
2.1 <- 2.0      11/08/2020
Adding the Linux dll
2.0 <- 1.2      10/08/2020
The cipher is now a C library !
1.2 :   332 octets chiffrés / s = 20.8 blocs chiffrés / s
        101 octets déchiffrés / s = 6.3 blocs déchiffrés / s
2.0 :   7 728 000 octets chiffrés / s = 483 000 blocs chiffrés / s   soit 23 300 fois plus rapide
        7 423 000 octets déchiffrés / s = 464 000 blocs déchiffrés / s  soit 73 500 fois plus rapide
1.2 <- 1.1      01/05/2020
Adding use menu
1.1 <- 1.0      18/04/2020
Replace gfmul(1, a) by a"""


##-initialisation

import platform
import ctypes
import os


##-library import

global lib_AES, f_initAES, f_encryptBlock, f_decryptBlock, f_encryptTextECB, f_decryptTextECB, f_encryptTextCBC, f_decryptTextCBC, f_encryptFileECB, f_decryptFileECB, f_encryptFileCBC, f_decryptFileCBC

if platform.system() == 'Windows':
    dll_fn = 'AES_win.dll'

else:
    dll_fn = 'AES_unix.dll'

lib_AES = ctypes.cdll.LoadLibrary('{}/modules/ciphers/kris/AES_library/{}'.format(os.getcwd(), dll_fn))

f_initAES = lib_AES.initAES
f_initAES.argtypes = (ctypes.c_int, ctypes.c_char_p)
f_initAES.restype = None

f_encryptBlock = lib_AES.encryptBlock
f_encryptBlock.argtype = ctypes.c_char_p
f_encryptBlock.restype = None

f_decryptBlock = lib_AES.decryptBlock
f_decryptBlock.argtype = ctypes.c_char_p
f_decryptBlock.restype = None

f_encryptTextECB = lib_AES.encryptTextECB
f_encryptTextECB.argtypes = (ctypes.c_char_p, ctypes.c_uint)
f_encryptTextECB.restype = ctypes.c_uint
f_decryptTextECB = lib_AES.decryptTextECB
f_decryptTextECB.argtypes = (ctypes.c_char_p, ctypes.c_uint)
f_decryptTextECB.restype = ctypes.c_uint

f_encryptTextCBC = lib_AES.encryptTextCBC
f_encryptTextCBC.argtypes = (ctypes.c_char_p, ctypes.c_uint)
f_encryptTextCBC.restype = ctypes.c_uint
f_decryptTextCBC = lib_AES.decryptTextCBC
f_decryptTextCBC.argtypes = (ctypes.c_char_p, ctypes.c_uint)
f_decryptTextCBC.restype = ctypes.c_uint

f_encryptFileECB = lib_AES.encryptFileECB
f_encryptFileECB.argtypes = (ctypes.c_char_p, ctypes.c_char_p)
f_encryptFileECB.restype = None
f_decryptFileECB = lib_AES.decryptFileECB
f_decryptFileECB.argtypes = (ctypes.c_char_p, ctypes.c_char_p)
f_decryptFileECB.restype = None

f_encryptFileCBC = lib_AES.encryptFileCBC
f_encryptFileCBC.argtypes = (ctypes.c_char_p, ctypes.c_char_p)
f_encryptFileCBC.restype = None
f_decryptFileCBC = lib_AES.decryptFileCBC
f_decryptFileCBC.argtypes = (ctypes.c_char_p, ctypes.c_char_p)
f_decryptFileCBC.restype = None


##-AES

class AES:

    def __init__(self, mode, key, hexa=False, encoding='utf-8'):
        """Key is string or bytes, if key is in hexadecimal, put hexa=True.
        Mode is 128, 192 or 256."""

        if not int(mode) in (128, 192, 256):
            raise ValueError("AES cipher can only have a key of 128, 192 or 256 bits, not " + str(mode))
        self.mode = ctypes.c_int(mode)

        if hexa:
            key = bytes.fromhex(key)
        elif type(key) is str:
            key = key.encode(encoding)
        if len(key) > mode // 8:
            raise ValueError("Key is too big for an AES " + str(mode) + " cipher")
        else:
            self.key = ctypes.create_string_buffer(key, 32)

    def encryptBlock(self, block):
        """block : block of bytes to encrypt"""

        block = ctypes.c_char_p(block)
        f_initAES(self.mode, self.key)
        f_encryptBlock(block)
        return block.value

    def decryptBlock(self, block):

        block = ctypes.c_char_p(block)
        f_initAES(self.mode, self.key)
        f_decryptBlock(block)
        return block.value

    def encryptText(self, text, mode='str', encoding='utf-8', mode_c='str', op_mode='CBC'):
        if not mode in ('str', 'bytes', 'hexa'):
            raise ValueError("Mode not in ('str', 'bytes', 'hexa')")

        if mode == 'str':
            text = text.encode(encoding)
        elif mode == 'hexa':
            text = bytes.fromhex(text)
        lt = len(text)
        text = ctypes.create_string_buffer(text, (lt//16)*16+16)
        f_initAES(self.mode, self.key)
        if op_mode == 'CBC':
            f_encryptTextCBC(text, lt)
        else:
            f_encryptTextECB(text, lt)
        if mode_c == 'str':
            return text.raw.decode('latin-1')
        elif mode_c == 'hexa':
            return text.raw.hex()
        else:
            return text.raw

    def decryptText(self, text_c, mode_c='hexa', mode='str', encoding='utf-8', op_mode='CBC'):
        if mode_c == 'str':
            text_c = text_c.encode('latin-1')
        elif mode_c == 'hexa':
            text_c = bytes.fromhex(text_c)
        lt = len(text_c)
        text_c = ctypes.create_string_buffer(text_c, lt)
        f_initAES(self.mode, self.key)
        if op_mode == 'CBC':
            n = ctypes.c_uint(f_decryptTextCBC(text_c, lt))
        else:
            n = ctypes.c_uint(f_decryptTextECB(text_c, lt))
        text = text_c.raw[0:n.value]
        if mode == 'str':
            return text.decode(encoding)
        elif mode == 'hexa':
            return text.hex()
        else:
            return text

    def encryptFile(self, f, f_c, op_mode='CBC'):
        """Encrypt the file f in a file f_c"""
        f_initAES(self.mode, self.key)
        if op_mode == 'CBC':
            f_encryptFileCBC(os.path.abspath(f).encode('ascii'), os.path.abspath(f_c).encode('ascii'))
        else:
            f_encryptFileECB(os.path.abspath(f).encode('ascii'), os.path.abspath(f_c).encode('ascii'))

    def decryptFile(self, f_c, f, op_mode='CBC'):
        f_initAES(self.mode, self.key)
        if op_mode == 'CBC':
            f_decryptFileCBC(os.path.abspath(f_c).encode('ascii'), os.path.abspath(f).encode('ascii'))
        else:
            f_decryptFileECB(os.path.abspath(f_c).encode('ascii'), os.path.abspath(f).encode('ascii'))

def use():
    print('\nAES cipher')
    mode = input("Length of the key (128, 192, 256) : ")
    key = input("Key : ")
    hkey = input("Key in hexa ? ")
    if hkey in ('y', 'Y', 'Yes', 'yes', 'YES', 'o', 'O', 'oui', 'Oui', 'OUI'):
        hexa = True
    else:
        hexa = False
        print("Key in utf-8")
    c = AES(mode, key, hexa)
    m = input("Encrypt or decrypt [ed] : ")
    if m == 'e':
        m2 = input("Encrypt file or text [ft] : ")
    else:
        m2 = input("Decrypt file or text [ft] : ")
    if m2 == 'f':
        nf1 = input("Name of the file : ")
        nf2 = input("Name of the new file : ")
        if m == 'e':
            c.encrypt_file(nf1, nf2)
        else:
            c.decrypt_file(nf1, nf2)
    else:
        t = input("Text : ")
        if m == 'e':
            print(c.encrypt(t, mode_c = 'hexa'))
        else:
            print(c.decrypt(t, mode_c = 'hexa'))