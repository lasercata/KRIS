#!/bin/python3
# -*- coding: utf-8 -*-

'''This program allow you to encrypt and decrypt with RSA cipher.'''

RSA__auth = 'Lasercata, Elerias'
RSA__last_update = '2023.08.16'
RSA__version = '5.0_kris'

#TODO: check that all the imports are needed. Then correct the paths.

##-Import
#---------KRIS' modules
#from modules.base.console.color import color, cl_inp, cl_out, c_error, c_wrdlt, c_output, c_prog, c_succes
from modules.base.base_functions import *
from modules.base.text_functions import *
from modules.base.FormatMsg import FormatMsg
from modules.base.progress_bars import *
from modules.ciphers.hasher import Hasher
from modules.base import glb
from modules.base.arithmetic import mult_inverse, isSurelyPrime
from Languages.lang import translate as tr

from modules.ciphers.AES import AES

#---------packages
import math
from random import randint, randbytes
from secrets import randbits

import base64

from ast import literal_eval #Safer than eval
from getpass import getpass

from datetime import datetime as dt
from time import sleep

from os import chdir, mkdir, getcwd, listdir, rename, remove
from os.path import expanduser, isfile, isdir
from shutil import copy

from hashlib import sha256 as hashlib_sha256

#if glb.interface == 'gui':
from PyQt5.QtWidgets import QMessageBox

#---------csv
# import csv


##-ini
# alf_36 = '0123456789abcdefghijklmnopkrstuvwxyz'

#---------KRIS version
try:
    with open('version.txt', 'r') as f:
        kris_version_0 = f.read()
    kris_version = ""
    for k in kris_version_0:
        if k not in ('\n', '\r'):
            kris_version += k

except FileNotFoundError:
    tr('The file "version.txt" was not found. A version will be set but can be wrong.')
    kris_version = '3.0.0 ?'

else:
    if len(kris_version) > 16:
        tr('The file "version.txt" contain more than 16 characters, so it certainly doesn\'t contain the actual version. A version will be set but can be wrong.')
        kris_version = '3.0.0 ?'


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
    '''Return the byte length of n (the number of binary digits).'''

    return len(format(n, 'b'))


#---------rm_lst
def rm_lst(lst, lst_to_rm):
    '''Return the list `lst` without elements from `lst_to_rm`.'''

    ret = []

    for k in lst:
        if k not in lst_to_rm:
            ret.append(k)

    return ret



##-RsaKey
class RsaKey:
    '''Class representing an RSA key, and implementing manipulations on it.'''

    def __init__(self, e=None, d=None, n=None, phi=None, p=None, q=None, date_=None, parent=None, interface=None):
        '''
        - e         : public exponent ;
        - d         : private exponent ;
        - n         : modulus ;
        - p, q      : primes that verify pq = n ;
        - phi       = (p - 1)(q - 1) ;
        - date_     : the date of the key generation ;
        - parent    : the parent for gui progress bars. Used when interface is 'gui' ;
        - interface : in (None, 'gui', 'console'). Used to choose the progress bars and other stuff.
        '''

        if interface not in (None, 'gui', 'console'):
            raise ValueError('The argument "interface" should be None, "gui", \
                or "console", but {} of type {} was found !!!'.format(interface, type(interface)))

        self.interface = interface
        self.parent = parent

        self.e = e
        self.d = d
        self.n = n
        self.phi = phi
        self.p = p
        self.q = q

        if e != None:
            self.e = int(e)

        if d != None:
            self.d = int(d)

        if n != None:
            self.n = int(n)

        if phi != None:
            self.phi = int(phi)

        if p != None:
            self.p = int(p)

        if q != None:
            self.q = int(q)

        self.date = date_

        self.is_private = self.d != None

        if p != None and q != None:
            if self.q < self.q:
                self.p = int(q)
                self.q = int(p)

        self.pb = (self.e, self.n)
        if self.is_private:
            self.pv = (self.d, self.n)

        if n == None:
            self.size = None

        else:
            self.size = round(math.log2(self.n))

        self.k_name = None #Used when saving the key to a file and when reading from a file

    
    def __repr__(self):
        if self.is_private:
            return f'RsaKey private key :\n\tsize : {self.size}\n\te : {self.e}\n\td : {self.d}\n\tn : {self.n}\n\tphi : {self.phi}\n\tp : {self.p}\n\tq : {self.q}'
        
        else:
            return f'RsaKey public key :\n\tsize : {self.size}\n\te : {self.e}\n\tn : {self.n}'
    
    
    def __eq__(self, other):
        '''Return True if the key are of the same type (public / private) and have the same values.'''

        if type(other) != type(self):
            return False
        
        ret = self.is_private == other.is_private

        if not ret:
            return False
        
        if self.is_private:
            ret = ret and (
                self.e == other.e and
                self.d == other.d and
                self.n == other.n and
                self.phi == other.phi
            )
            
            ret = ret and ((self.p == other.p and self.q == other.q) or (self.q == other.p and self.p == other.q))
        
        else:
            ret = ret and (
                self.e == other.e and
                self.n == other.d
            )
        
        return ret
    
    
    def public(self):
        '''Return the public key associated to self in an other RsaKey object.'''
        
        k = RsaKey(e=self.e, n=self.n)
        k.size = self.size
        return k
    

    def _gen_nb(self, size=2048, wiener=False):
        '''
        Generates p, q, and set attributes p, q, phi, n, size.
        
        - size   : the bit size of n ;
        - wiener : If True, generates p, q prime such that q < p < 2q.
        '''

        #------ini progress bar
        if self.interface == 'gui':
            pb = GuiProgressBar(title='Generating ... ― ' + glb.prog_name, undetermined=True, parent=self.parent)

        elif self.interface == 'console':
            pb = ConsoleProgressBar()

        #------Generate numbers
        self.p, self.q = 1, 1

        while not isSurelyPrime(self.q):
            self.q = randbits(size // 2)

            if self.interface in ('gui', 'console'):
                pb.load()
        
        while not (isSurelyPrime(self.p) and ((wiener and self.q < self.p < 2 * self.q) or (not wiener))):
            self.p = randbits(size // 2)

            if self.interface in ('gui', 'console'):
                pb.load()

        if self.interface == 'gui':
            pb.close()

        self.phi = (self.p - 1) * (self.q - 1)
        self.n = self.p * self.q

        self.size = size


    def new(self, size=2048, keep_e=True): #TODO: add progress bars from the old RsaKeys class ?
        '''
        Generate RSA keys of size `size` bits.
        If self.e != None, it keeps it (and ensures that gcd(phi, e) = 1).

        - size : the key size, in bits ;
        - keep_e : a bool indicating if keeping the old e (if not None), or generate a new one.
        '''

        #TODO: ensure that the keys are not in the conditions for wiener's attack. Maybe do this in self._gen_nb ?

        self._gen_nb(size)

        if not keep_e:
            e = None

        while self.e != None and math.gcd(self.e, self.phi) != 1:
            self._gen_nb(size)

        if self.e == None:
            self.e = 0
            while math.gcd(self.e, self.phi) != 1:
                self.e = randint(max(self.p, self.q), self.phi)
        
        elif math.gcd(self.e, self.phi) != 1: #Not possible !
            raise ValueError('RsaKey: new: error: gcd(self.e, self.phi) != 1')
        
        self.d = mult_inverse(self.e, self.phi)

        self.is_private = True

        self.pb = (self.e, self.n)
        self.pv = (self.d, self.n)

        # self.size = size
        self.size = round(math.log2(self.n))

        self.date = date()
    
    
    def new_wiener(self, size=2048):
        '''
        Generate RSA keys of size `size` bits.
        This operation does NOT keep e, even if e != None.
        These key are generated so that the Wiener's attack is possible on them.
        
        - size : the key size, in bits.
        '''
        
        self._gen_nb(size, wiener=True)
        
        self.d = 0
        while math.gcd(self.d, self.phi) != 1: #TODO: shouldn't it be e instead of d ?
            self.d = randint(1, math.floor(isqrt(isqrt(self.n))/3))
        
        self.e = mult_inverse(self.d, self.phi)
        
        self.is_private = True

        self.pb = (self.e, self.n)
        self.pv = (self.d, self.n)

        self.size = size

        self.date = date()


    def new_wiener_large(self, size=2048, only_large=True):
        '''
        Same as `self.new_wiener`, but `d` can be very large.

        - size       : the RSA key size ;
        - only_large : if False, d can be small, or large, and otherwise, d is large.
        '''

        self._gen_nb(size, wiener=True)

        self.d = 0
        while math.gcd(self.d, self.phi) != 1:
            if only_large:
                #ceil(sqrt(6)) = 3
                self.d = randint(int(self.phi - iroot(self.n, 4) // 3), self.phi)

            else:
                self.d = randint(1, self.phi)
                if iroot(self.n, 4) / 3 < self.d or self.d < self.phi - iroot(self.n, 4) / math.sqrt(6): #TODO: Does this works ?
                    self.d = 0 #go to the next iteration

        self.e = mult_inverse(self.d, self.phi)
        self.is_private = True
        self.pb = (self.e, self.n)
        self.pv = (self.d, self.n)

        self.size = size

        self.date = date()


    def save(self, k_name, pwd=None, overwrite=False, md_stored='hexa'):
        '''
        Save the key to a file.

        Arguments :
            - k_name    : the name to give for the keys. This value will overwrite self.k_name ;
            - pwd       : The AES key used to encrypt the RSA key. If using user input, hash it before
                           using it here. If None, key will be saved in clear ;
            - overwrite : in (True, False). If the dir keys_names already exist, if True, overwrite it,
                           return an error msg else ;
            - md_stored : the way how the keys are stored, i.e. in decimal or hexadecimal.
                           Should be "hexa" or "dec". Default is "hexa".

        The program make two files, in chd_rsa(glb.home), named :
            For the private key :
                '[self.k_name].pvk-h' if md_stored is 'hexa' ;
                '[self.k_name].pvk-d' if md_stored is 'dec' ;
                '[self.k_name].pvk-d.enc' or '[self.k_name].pvk-h.enc' if pwd != None.

            For the public key :
                '[self.k_name].pbk-h' if md_stored is 'hexa' ;
                '[self.k_name].pbk-d' else.

        Return :
            -2 if the set of keys already exist and overwrite is False ;
            None otherwise
        '''

        #TODO: add another format : a standard one.

        if overwrite not in (True, False) or md_stored not in ('hexa', 'dec'):
            raise ValueError('Some arguments are not correct !')

        self.k_name = k_name

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

        #------Private key
        v = {
            'p' : self.p,
            'q' : self.q,
            'n' : self.n,
            'phi' : (self.p - 1) * (self.q - 1),
            'e' : self.e,
            'd' : self.d,
            'date': self.date,
            'n_strenth': self.size
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

        self.k_name = k_name



class RsaKeyFile:
    '''Class representing an RSA key file, and implementing manipulations on them.'''

    def __init__(self, keys_name, interface=None):
        '''
        Initiate the RsaKeys object.

        - keys_name : the set of keys' name (without the extension).
        '''

        if interface not in (None, 'gui', 'console'):
            raise ValueError('The argument "interface" should be None, "gui", \
                or "console", but {} of type {} was found !!!'.format(interface, type(interface)))


        self.k_name = keys_name
        self.interface = interface


    def __repr__(self):
        '''Represent the object.'''

        return "RsaKeyFile('{}', interface='{}')".format(self.k_name, self.interface) #Printing self.k_name and not the full filename with the extension as the key can be saved in multiple formats at the same time.


    def read(self, mode='all', also_ret_pwd=False, verbose=True):
        '''
        Try to read the content of the file `[self.k_name] + ext`, and return an RsaKey object.

        - mode         : the self.get_fn mode. in ('pvk', 'pbk', 'all'). Default is 'all' ;
        - also_ret_pwd : a bool indicating if also return the password. If True, return the password at the end of the return tuple ;
        - verbose      : if True, show error messages (before returning -1, -2, or -3).

        Return :
            key         where `key` is an RsaKey object representing the RSA key ;
            key, pwd    if `also_ret_pwd` is True ;
            -1          if not found ;
            -2          if file not well formatted ;
            -3          if password is wrong or if canceled.
        '''

        #------other
        def err_not_well_formated():
            if verbose:
                msg = glb.prog_name + ': RsaKeys: read: ' + tr('The file is not well formatted !')
                print_error(msg, '!!! File error !!!', interface=self.interface)

            return -2

        #------Get filename
        try:
            fn, md = self.get_fn(mode, also_ret_md=True)

        except FileNotFoundError:
            if verbose:
                msg = glb.prog_name + ': RsaKeyFile: read: ' + tr('File not found !')
                print_error(msg, '!!! Not found !!!', interface=self.interface)
            return -1

        #------Read file
        old_path = chd_rsa(glb.home)

        with open(fn, 'r') as f:
            f_content = f.read()

        chdir(old_path)

        #------Decrypt content, if encrypted
        if fn[-4:] == '.enc':
            #---Get password
            pwd = get_pwd(interface=self.interface)

            if pwd == -3:
                return -3 # Canceled by user

            #---Decrypt
            try:
                f_content_dec = AES(256, pwd, hexa=True).decryptText(f_content, mode_c='hexa')

            except UnicodeDecodeError:
                if verbose:
                    msg = glb.prog_name + ': RsaKeyFile: read: ' + tr('This is not the good password !')
                    print_error(msg, '!!! Wrong password !!!', interface=self.interface)

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
                n_strth = int(n_strth, 16)
                e, n = int(e, 16), int(n, 16)

            key = RsaKey(e=e, n=n, date_=date_, interface=self.interface)
            key.k_name = self.k_name

            if also_ret_pwd:
                return key, pwd

            return key


        else:
            try:
                date_, n_strth = infos['date'], infos['n_strenth']
                p, q, n, phi, e, d = infos['p'], infos['q'], infos['n'], infos['phi'], infos['e'], infos['d']

            except KeyError:
                return err_not_well_formated()

            if md[1] == 'hexa': #convert in decimal
                n_strth = int(n_strth, 16)
                p, q, n, phi, e, d = int(p, 16), int(q, 16), \
                    int(n, 16), int(phi, 16), int(e, 16), int(d, 16)

            key = RsaKey(e=e, d=d, n=n, phi=phi, p=p, q=q, date_=date_, interface=self.interface)

            if also_ret_pwd:
                return key, pwd

            return key


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
        key = self.read(md)

        if key in (-1, -2, -3):
            return key

        if key.is_private:
            ed, n = key.d, key.n

        else:
            if mode == 1:
                raise TypeError("Can't read the private key of a pbk set of keys !!!")

            ed, n = key.e, key.n

        return ed, n


    def convert(self):
        '''
        Function which convert RSA keys.
        If the keys are stored in decimal, it write them in hexadecimal ;
        it write them in decimal otherwise.

        It remove keys in the old storage mode.

        Return :
            -1      if the key is not found ;
            -2      if the key already exists in the other mode ;
            None    otherwise.
        '''

        key, pwd = self.read(also_ret_pwd=True)

        if key in (-1, -2, -3):
            return -1

        old_fn, (type_, stg_md) = self.get_fn(also_ret_md=True)

        if type_ == 'pvk': #pvk
            v = {
                'p' : key.p,
                'q' : key.q,
                'n' : key.n,
                'phi' : key.phi,
                'e' : key.e,
                'd' : key.d,
                'date' : key.date,
                'n_strenth' : key.size
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
                'e' : key.e,
                'n' : key.n,
                'date' : key.date,
                'n_strenth' : key.size
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


    def rename(self, new_name, overwrite=False):
        '''
        Function which can rename a set of keys

        - self.k_name : the set of keys' name ;
        - new_name    : the new set of keys' name ;
        - overwrite   : a boolean indicating if overwriting the destination.

        Return :
            -1      if the file was not found ;
            -2      if the 'new_name' set of keys already exist and overwrite is False ;
            None    otherwise.
        '''

        try:
            fn, (type_, stg_md) = self.get_fn(also_ret_md=True)

        except FileNotFoundError as err:
            #TODO: print error message here (or not ?)

            return -1

        new_name = str(new_name)
        old_path = chd_rsa(glb.home)

        ext = '.' + type_ + ('-h', '-d')[stg_md == 'dec']

        if type_ == 'pvk':
            ext_pbk = '.pbk-' + ('h', 'd')[stg_md == 'dec']

        if fn[-4:] == '.enc':
            ext += '.enc'

        #---Check if there is already a `new_name` file
        if isfile(new_name + ext):
            if not overwrite:
                chdir(old_path)
                return -2

            else:
                remove(new_name + ext)


        rename(str(self.k_name) + ext, new_name + ext)

        if type_ == 'pvk':
            rename(str(self.k_name) + ext_pbk, new_name + ext_pbk)

        chdir(old_path)


    def get_fn(self, mode='all', also_ret_md=False):
        '''
        Return the filename of the key (with the extention), along with the modes (if `also_ret_md` is True)

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

        Return :
            fn                     if `also_ret_md` is False ;
            fn, (md, md_stored)    otherwise, where md is in ('pvk', 'pbk'), and md_stored is in ('dec', 'hexa') ;
            FileNotFoundError      if the file is not  found.
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


    def encrypt(self, pwd):
        '''
        Encrypt 'self.k_name' with AES-256-CBC using the password
        `pwd` (Hasher('sha256').hash(clear_pwd)), make a file
        'self.k_name' + ext + '.enc' and remove clear one.

        - pwd : the AES password. Should be passed through sha256 before.
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


    def decrypt(self, pwd):
        '''
        Decrypt 'self.k_name' with AES-256-CBC using the password
        `pwd` (Hasher('sha256').hash(clear_pwd)), make a file
        'self.k_name' + ext and remove encrypted one.

        - pwd : the AES password.
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
                print(glb.prog_name + ': RsaKeys: decrypt: ' + msg)

            chdir(old_path)
            return -3

        except ValueError:
            msg = tr('The file is not well formatted !')

            if self.interface == 'gui':
                QMessageBox.critical(None, '!!! File error !!!', '<h2>{}</h2>'.format(msg))
            else:
                print(glb.prog_name + ': RsaKeys: decrypt: ' + msg)

            chdir(old_path)
            return -2

        with open(fn[:-4], 'w') as f:
            f.write(f_dec)

        remove(fn)

        chdir(old_path)


    def change_pwd(self, old_pwd, new_pwd):
        '''
        Change the RSA key password for `self.k_name`.

        - old_pwd : the old AES password ;
        - new_pwd : the new AES password.

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
                print(glb.prog_name + ': RsaKeys: change_pwd: ' + msg)

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
                print(glb.prog_name + ': RsaKeys: change_pwd: ' + msg)

            chdir(old_path)
            return -3

        except ValueError:
            msg = tr('The file is not well formatted !')

            if self.interface == 'gui':
                QMessageBox.critical(None, '!!! File error !!!', '<h2>{}</h2>'.format(msg))
            else:
                print(glb.prog_name + ': RsaKeys: change_pwd: ' + msg)

            chdir(old_path)
            return -2

        f_enc = AES(256, new_pwd, hexa=True).encryptText(f_dec, mode_c='hexa')

        with open(fn, 'w') as f:
            f.write(f_enc)

        chdir(old_path)


##-Padding
#------Mask generation function
# From https://en.wikipedia.org/wiki/Mask_generation_function
def i2osp(integer: int, size: int = 4) -> bytes:
    return int.to_bytes(integer % 256**size, size, 'big')

def mgf1(input_str: bytes, length: int, hash_func=hashlib_sha256) -> str: #TODO: check that this works nicely.
    '''Mask generation function.'''

    counter = 0
    output = b''
    while len(output) < length:
        C = i2osp(counter, 4)
        output += hash_func(input_str + C).digest()
        # output += hash_func(input_str + C)
        counter += 1

    return output[:length]


#------OAEP padding
class OAEP:
    '''Class implementing the OAEP padding'''

    def __init__(self, block_size, k0=None, k1=0):
        '''
        Initiate OAEP class.
        
        - block_size : the bit size of each block ;
        - k0         : integer (number of bits in the random part). If None, it is set to block_size // 8 ;
        - k1         : integer such that len(block) + k0 + k1 = block_size. Default is 0.
        '''

        self.block_size = block_size #n

        if k0 == None:
            k0 = block_size // 8

        self.k0 = k0
        self.k1 = k1
    
    
    def _encode_block(self, block):
        '''
        Encode a block.
        
        - block : an n - k0 - k1 long bytes string.
        '''

        if len(block) != self.block_size - self.k0 - self.k1:
            raise ValueError('OAEP: _encode_block: `block` should be made of `self.block_size - self.k0 - self.k1` chars !')

        #---Add k1 \0 to block
        block += (b'\0')*self.k1
        
        #---Generate r, a k0 bits random string
        r = randbytes(self.k0)

        X = xor(block, mgf1(r, self.block_size - self.k0))

        Y = xor(r, mgf1(X, self.k0))

        return X + Y
    

    def encode(self, txt):
        '''
        Encode txt.
        
        Entry :
            - txt : the string text to encode.
        
        Output :
            bytes list.
        '''

        if type(txt) != bytes:
            txt = txt.encode()
        
        #---Cut message in blocks of size n - k0 - k1
        blocks = []
        l = self.block_size - self.k0 - self.k1

        blocks = split(txt, l, pad_=b'\0')

        #---Encode blocks
        enc = []
        for k in blocks:
            enc.append(self._encode_block(k))
        
        return enc
    

    def _decode_block(self, block):
        '''Decode a block encoded with self._encode_block.'''

        X = block[:self.block_size - self.k0]
        Y = block[-self.k0:]

        r = xor(Y, mgf1(X, self.k0))

        txt = xor(X, mgf1(r, self.block_size - self.k0))

        while txt[-1] == 0: #Remove padding
            txt = txt[:-1]

        return txt


    def decode(self, enc):
        '''
        Decode a text encoded with self.encode.
        
        - enc : a list of bytes encoded blocks.
        '''

        txt = b''

        for k in enc:
            txt += self._decode_block(k)
        
        return txt


##-RSA
class RSA:
    '''Implementation of the RSA cipher'''

    def __init__(self, key, padding, block_size=None, parent=None, interface=None):
        '''
        - key        : a RsaKey object ;
        - padding    : the padding to use. Possible values are :
            * 'int' : msg is an int, return an int ;
            * 'raw' : msg is a string, simply cut it in blocks ;
            * 'oaep' : OAEP padding ;

        - block_size : the size of encryption blocks. If None, it is set to `key.size // 8 - 1`.
        - parent     : the parent for the gui progress bar (used if interface is 'gui') ;
        - interface  : the interface using this class. Should be None,
           'gui', or 'console'. Used to choose the progress bar.
        '''

        if interface not in (None, 'gui', 'console'):
            raise ValueError('The argument "interface" should be None, "gui", \
                or "console", but {} of type {} was found !!!'.format(interface, type(interface)))

        self.interface = interface
        self.parent = parent

        self.pb = key.pb
        if key.is_private:
            self.pv = key.pv
        
        self.is_private = key.is_private

        if padding.lower() not in ('int', 'raw', 'oaep'):
            raise ValueError('RSA: padding not recognized.')
        
        self.pad = padding.lower()

        if block_size == None:
            self.block_size = key.size // 8 - 1

        else:
            self.block_size = block_size

        self.k_name = key.k_name
        self.key = key


    def __repr__(self):
        '''Represent the object.'''

        if self.k_name != None:
            return f"RSA(key='{self.k_name}', padding='{self.pad}', block_size='{self.block_size}', interface='{self.interface}')"

        else:
            return f"RSA(padding='{self.pad}', block_size='{self.block_size}', interface='{self.interface}')\n\nKey : {self.key}" #TODO: test this !
    

    def encrypt(self, msg):
        '''
        Encrypt `msg` using the key given in init.
        Redirect toward the right method (using the good padding).
        
        - msg     : The string (or int for 'int' padding) to encrypt.
        '''

        try: #TODO: is this try block useful ?
            if self.pad == 'int':
                return self._encrypt_int(msg)
            
            elif self.pad == 'raw':
                return self._encrypt_raw(msg)
            
            else:
                return self._encrypt_oaep(msg)

        except KeyboardInterrupt: #Stopped from gui progress bar (or console).
            return
    
    
    def decrypt(self, msg):
        '''
        Decrypt `msg` using the key given in init, if it is a private one. Otherwise raise a TypeError.
        Redirect toward the right method (using the good padding).
        '''

        if not self.is_private:
            raise TypeError('Can not decrypt using a public key.')

        try:
            if self.pad == 'int':
                return self._decrypt_int(msg)
            
            elif self.pad == 'raw':
                return self._decrypt_raw(msg)
            
            else:
                return self._decrypt_oaep(msg)

        except KeyboardInterrupt: #Stopped from progress bar.
            return
    

    def encrypt_file(self, fn_in, fn_out):
        '''
        Encrypt the file `fn_in` into the file `fn_out` using the key given in init.
        Redirect toward the right method (using the good padding).
        The 'int' padding is not supported. Trying it will raise a ValueError.
        
        - fn_in  : the name of the file to encrypt ;
        - fn_out : the name of the file in which to write the encryption of the previous file.

        The functions do not test if any file exists nor if the file `fn_out` is empty, and will overwrite its potential content.
        '''

        try:
            if self.pad == 'int':
                raise ValueError("Impossible to encrypt a file with the 'int' padding !")
            
            elif self.pad == 'raw':
                return self._encrypt_file_raw(fn_in, fn_out)
            
            else:
                return self._encrypt_file_oaep(fn_in, fn_out)

        except KeyboardInterrupt: #Stopped from progress bar.
            return
    
    
    def decrypt_file(self, fn_in, fn_out):
        '''
        Decrypt the file `fn_in` into the file `fn_out` using the key given in init, if it is a private one.
        Otherwise raise a TypeError.
        Redirect toward the right method (using the good padding).
        The 'int' padding is not supported. Trying it will raise a ValueError.
        
        - fn_in  : the name of the file to decrypt ;
        - fn_out : the name of the file in which to write the decryption of the previous file.

        This function does not test if any file exists nor if the file `fn_out` is empty, and will overwrite it.
        '''

        if not self.is_private:
            raise TypeError('Can not decrypt using a public key.')

        try:
            if self.pad == 'int':
                raise ValueError("Impossible to decrypt a file with the 'int' padding !")
            
            elif self.pad == 'raw':
                return self._decrypt_file_raw(fn_in, fn_out)

            else:
                return self._decrypt_file_oaep(fn_in, fn_out)

        except KeyboardInterrupt: #Stopped from progress bar.
            return
    

    def _encrypt_int(self, msg):
        '''
        RSA encryption in its simplest form.
        
        - msg : an integer to encrypt.
        '''

        e, n = self.pb

        return pow(msg, e, n)
    

    def _decrypt_int(self, msg):
        '''
        RSA decryption in its simplest form.
        Decrypt `msg` using the key given in init if possible, using the 'int' padding.
        
        - msg : an integer.
        '''
        
        d, n = self.pv

        return pow(msg, d, n)
    

    def _encrypt_raw(self, msg):
        '''
        Encrypt `msg` using the key given in init, using the 'raw' padding.
        
        - msg : The string to encrypt.

        This function encrypts `msg` by cutting it in blocks of size `self.block_size`.

        The ciphertext is composed of the encryption of each block, encoded with base64, and the blocks are separated with spaces.
        It returns a bytes string.
        '''

        #---Ini progress bar
        if self.interface == 'gui':
            pb = GuiProgressBar(title='Encrypting ... | RSA ― ' + glb.prog_name, verbose=False, mn=1, parent=self.parent)

        elif self.interface == 'console':
            pb = ConsoleProgressBar()

        #---Ini
        e, n = self.pb

        #---Encode msg
        if type(msg) != bytes:
            msg = msg.encode()

        #---Cut message in blocks
        m_lst = split(msg, self.block_size)
        
        #---Encrypt message
        enc_lst = []
        l = len(m_lst)

        for j, k in enumerate(m_lst):
            enc_lst.append(pow(bytes_to_int(k), e, n))

            if self.interface in ('gui', 'console'): #TODO: check that this bar works correcly.
                pb.set(j + 1, l)

        return b' '.join([base64.b64encode(int_to_bytes(k)) for k in enc_lst])
    

    def _decrypt_raw(self, msg):
        '''Decrypt `msg` using the key given in init if possible, using the 'raw' padding'''
        
        #---Ini progress bar
        if self.interface == 'gui':
            pb = GuiProgressBar(title='Decrypting ... | RSA ― ' + glb.prog_name, verbose=False, mn=1, parent=self.parent)

        elif self.interface == 'console':
            pb = ConsoleProgressBar()

        #---Ini
        d, n = self.pv

        #---Decrypting
        enc_lst = [base64.b64decode(k) for k in msg.split(b' ')]
        l = len(enc_lst)

        c_lst = []
        for j, k in enumerate(enc_lst):
            c_lst.append(pow(bytes_to_int(k), d, n))

            if self.interface in ('gui', 'console'): #TODO: check that this bar works correcly.
                pb.set(j + 1, l)
        
        #---Decoding
        txt = b''
        for k in c_lst:
            txt += int_to_bytes(k)

        return txt.decode()

    
    def _encrypt_file_raw(self, fn_in, fn_out):
        '''
        Encrypt the file `fn_in` into the file `fn_out` using the key given in init, using the 'raw' padding.
        
        - fn_in  : the name of the file to encrypt ;
        - fn_out : the name of the file in which to write the encryption of the previous file.

        This function does not test if any file exists nor if the file `fn_out` is empty, and will overwrite it.

        The encryption is done block by block (file `fn_in` is read chunk by chunk).
        Format of the file `fn_out` : each encrypted block is separated by a newline.
        '''

        #---Ini progress bar
        if self.interface == 'gui':
            pb = GuiProgressBar(title='Encrypting ... | RSA ― ' + glb.prog_name, verbose=False, mn=1, parent=self.parent)

        elif self.interface == 'console':
            pb = ConsoleProgressBar()

        #---Ini
        e, n = self.pb

        #---Encrypt message
        if self.interface in ('console', 'gui'):
            l = FileInfo(fn_in).size() // self.block_size #The number of blocks to encrypt in fn_in

        with open(fn_out, 'wb') as f_out:
            for j, block in enumerate(read_chunks(fn_in, self.block_size)):
                enc_int = pow(bytes_to_int(block), e, n)
                encrypted_block = int_to_bytes(enc_int)
                enc = base64.b64encode(encrypted_block)

                f_out.write(enc)
                f_out.write(b'\n')

                if self.interface in ('gui', 'console'): #TODO: check that this bar works correcly.
                    pb.set(j + 1, l)
    

    def _decrypt_file_raw(self, fn_in, fn_out):
        '''
        Decrypt the file `fn_in` into the file `fn_out` using the key given in init, using the 'raw' padding.
        
        - fn_in  : the name of the file to decrypt ;
        - fn_out : the name of the file in which to write the decryption of the previous file.

        This function does not test if any file exists nor if the file `fn_out` is empty, and will overwrite it.
        '''
        
        #---Ini progress bar
        if self.interface == 'gui':
            pb = GuiProgressBar(title='Decrypting ... | RSA ― ' + glb.prog_name, verbose=False, mn=1, parent=self.parent)

        elif self.interface == 'console':
            pb = ConsoleProgressBar()

        #---Ini
        d, n = self.pv

        #---Decrypting
        if self.interface in ('console', 'gui'):
            l = get_line_count(fn_in) #The number of blocks to decrypt from fn_in

        with open(fn_in, 'rb') as f_in, open(fn_out, 'wb') as f_out:
            for j, block in enumerate(f_in): #Reading line by line
                raw_block = base64.b64decode(block)
                dec_int = pow(bytes_to_int(raw_block), d, n)

                f_out.write(int_to_bytes(dec_int))

                if self.interface in ('gui', 'console'): #TODO: check that this bar works correcly.
                    pb.set(j + 1, l)


    def _encrypt_oaep(self, msg):
        '''Encrypt `msg` using the key given in init, using the 'oaep' padding.'''

        #---Ini progress bar
        if self.interface == 'gui':
            pb = GuiProgressBar(title='Encrypting ... | RSA ― ' + glb.prog_name, mn=1, verbose=False, parent=self.parent)

        elif self.interface == 'console':
            pb = ConsoleProgressBar()

        #---Ini
        e, n = self.pb

        if type(msg) != bytes:
            msg = msg.encode()

        #---Padding
        E = OAEP(self.block_size)
        m_lst = E.encode(msg)
        
        #---Encrypt message
        enc_lst = []
        l = len(m_lst)

        for j, k in enumerate(m_lst):
            enc_lst.append(pow(bytes_to_int(k), e, n))

            if self.interface in ('gui', 'console'): #TODO: check that this bar works correcly.
                pb.set(j + 1, l)
        
        return b' '.join([base64.b64encode(int_to_bytes(k)) for k in enc_lst])

    
    def _decrypt_oaep(self, msg):
        '''Decrypt `msg` using the key given in init if possible, using the 'oaep' padding.'''

        #TODO: improve the doc

        if type(msg) != bytes:
            msg = msg.encode()

        #------Ini progress bar
        if self.interface == 'gui': #TODO: set parent !
            pb = GuiProgressBar(title='Decrypting ... | RSA ― ' + glb.prog_name, verbose=False, mn=1, parent=self.parent)

        elif self.interface == 'console':
            pb = ConsoleProgressBar()

        #---Ini
        d, n = self.pv

        #---Decrypt
        enc_lst = [base64.b64decode(k) for k in msg.split(b' ')]
        c_lst = []
        l = len(enc_lst)

        for j, k in enumerate(enc_lst):
            c_lst.append(pow(bytes_to_int(k), d, n))

            #---progress bar
            if self.interface in ('gui', 'console'): #TODO: check that it works well.
                pb.set(j + 1, l)
        
        #---Decode
        encoded_lst = []
        for k in c_lst:
            encoded_lst.append(pad(int_to_bytes(k), self.block_size, b'\0'))
        
        E = OAEP(self.block_size)

        return E.decode(encoded_lst)

    
    def _encrypt_file_oaep(self, fn_in, fn_out):
        '''
        Encrypt the file `fn_in` into the file `fn_out` using the key given in init, using the 'oaep' padding.
        
        - fn_in  : the name of the file to encrypt ;
        - fn_out : the name of the file in which to write the encryption of the previous file.

        This function does not test if any file exists nor if the file `fn_out` is empty, and will overwrite its potential content.

        The encryption is done block by block (file `fn_in` is read chunk by chunk).
        Format of the file `fn_out` : each encrypted block encoded in base64 and is separated by a newline.
        '''

        #---Ini progress bar
        if self.interface == 'gui':
            pb = GuiProgressBar(title='Encrypting ... | RSA ― ' + glb.prog_name, verbose=False, mn=1, parent=self.parent)

        elif self.interface == 'console':
            pb = ConsoleProgressBar()

        #---Ini
        e, n = self.pb
        E = OAEP(self.block_size)
        
        #---Encrypt message
        if self.interface in ('console', 'gui'):
            l = FileInfo(fn_in).size() // (self.block_size - E.k0 - E.k1) #The number of blocks to encrypt in fn_in

        with open(fn_out, 'wb') as f_out:
            for j, block in enumerate(read_chunks(fn_in, self.block_size - E.k0 - E.k1)):
                block = pad(block, self.block_size - E.k0 - E.k1, b'\0') # for the last block.
                encoded_block = E._encode_block(block)
                enc_int = pow(bytes_to_int(encoded_block), e, n)

                encrypted_block = int_to_bytes(enc_int)

                enc = base64.b64encode(encrypted_block)

                f_out.write(enc)
                f_out.write(b'\n') #Separating blocks with newlines

                if self.interface in ('gui', 'console'):
                    pb.set(j + 1, l)

                # #TODO: this is a test
                # if j >= 2:
                #     break

    
    def _decrypt_file_oaep(self, fn_in, fn_out):
        '''
        Decrypt the file `fn_in` into the file `fn_out` using the key given in init, using the 'oaep' padding.
        
        - fn_in  : the name of the file to decrypt ;
        - fn_out : the name of the file in which to write the decryption of the previous file.

        This function does not test if any file exists nor if the file `fn_out` is empty, and will overwrite it.
        '''

        #------Ini progress bar
        if self.interface == 'gui':
            pb = GuiProgressBar(title='Decrypting ... | RSA ― ' + glb.prog_name, verbose=False, mn=1, parent=self.parent)

        elif self.interface == 'console':
            pb = ConsoleProgressBar()

        #---Ini
        d, n = self.pv
        E = OAEP(self.block_size)

        #---Decrypt
        if self.interface in ('console', 'gui'):
            l = get_line_count(fn_in) #The number of blocks to decrypt from fn_in

        with open(fn_in, 'rb') as f_in, open(fn_out, 'wb') as f_out:
            for j, block in enumerate(f_in): #Reading line by line
                raw_block = base64.b64decode(block)

                # dec_int = pow(bytes_to_int(block), d, n)
                # # encoded = pad(int_to_bytes(dec_int), self.block_size, b'\0')
                # encoded = int_to_bytes(dec_int)
                # decoded = E._decode_block(encoded)

                decoded = E._decode_block(int_to_bytes(pow(bytes_to_int(raw_block), d, n)))

                f_out.write(decoded)

                if self.interface in ('console', 'gui'):
                    pb.set(j + 1, l)


    def sign(self, txt):
        '''
        Sign the message 'txt'.
        It encrypt 'txt' using the private key.
        '''

        if not self.is_private:
            raise TypeError('Can not sign using a public key.')

        e, n = self.pb
        d, n = self.pv
        sign_key = RsaKey(e=d, d=e, n=n)

        S = RSA(sign_key, self.pad, self.block_size)

        return S.encrypt(txt)


    def unsign(self, txt):
        '''
        Unsign the message 'txt'.
        It decrypt 'txt' using the public key.
        '''

        e, n = self.pb
        sign_key = RsaKey(e=None, d=e, n=n)

        S = RSA(sign_key, self.pad, self.block_size)

        return S.decrypt(txt)



class RsaSign: #TODO: add file signature and check.
    '''Class which allow to sign messages' hashes.'''

    def __init__(self, RSA_ciph, h='sha256'):
        '''
        Initiate RsaSign.

        - RSA_ciph : the RSA cipher. Should be the instance of a RSA class with at
                      least the methods `sign` and `unsign`. The key is given
                      when instantiating the class ;
        - h        : the hash to use (a string).
        '''

        self.RSA = RSA_ciph
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
        - sign : the message's signature.

        Return :
            True if correspond ;
            False otherwise.
        '''

        msg_h = self.Hasher.hash(msg)
        unsign = self.RSA.unsign(sign)

        if type(unsign) == bytes:
            msg_h = msg_h.encode()

        return msg_h == unsign


    def str_sign(self, msg, encod='utf-8'):
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

        sign = self.sign(msg).decode(encod)

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


    #todo: there is a bug when checking in gui with a 512 RSA key : it does not match, but it should (try sign and check a test message, e.g. 'test').
    #This is an old todo. Maybe the new RSA will solve this ...



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
