#!/bin/python3
# -*- coding: utf-8 -*-

'''This is the old implementation of RSA (without the OAEP padding, before the version v3.0.0 of KRIS.'''

RSA__auth = 'Lasercata, Elerias'
RSA__last_update = '13.11.2021'
RSA__version = '4.3_kris' #but adapted to the new RsaKey class.


##-import
from modules.ciphers.RSA import *


##-Base
#------from b_cvrt
def sp_grp(n, grp, sep=' ', rev_lst=True): #TODO: move this in base (or some similar file)
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

#---------restore_encoding
def rest_encod(txt): #TODO: will this be still useful ?
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



##-Encoding
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
class RSA_old:
    '''Class which allow to use the RSA cipher.'''

    def __init__(self, key, interface=None): #TODO: for `key`, use only an KsaKey object (from tipe). Make a function `to_RsaKey` that does what is done here.
        '''Initiate the RSA object.

        - key       : the RsaKey key ;
        - interface : the interface using this function. Should be None,
           'gui', or 'console'. Used to choose the progress bar.
        '''

        if interface not in (None, 'gui', 'console'):
            raise ValueError('The argument "interface" should be None, "gui", \
                or "console", but {} of type {} was found !!!'.format(interface, type(interface)))

        self.interface = interface
        self.keys_init = key

        # self.keys = {} #will contain the keys
        #
        # if type(keys) == str:
        #     try:
        #         self.keys['e'] = RsaKeys(keys, interface=self.interface).get_key(0)
        #         #self.keys['d'] = RsaKeys(keys, interface=self.interface).get_key(1)
        #         self.keys['d'] = None
        #
        #     except FileNotFoundError as err:
        #         if interface == 'console':
        #             cl_out(c_error, err)
        #
        #         elif interface == 'gui':
        #             QMessageBox.critical(None, 'Keys not found !!!', '<h2>{}</h2>'.format(err))
        #
        #         raise FileNotFoundError(err)
        #
        #     except TypeError: #pbk keys
        #         self.keys['d'] = None
        #
        #
        # elif type(keys) in (tuple, list, set):
        #     #-check the length
        #     for j, k in enumerate(keys):
        #         if k != None:
        #             if len(k) != 2:
        #                 raise ValueError('The argument "keys" should have two lists of length 2, but "{}", with a length of {} was found !!!'.format(k, len(k)))
        #
        #         if j > 1:
        #             raise ValueError('The argument "keys" should have a length of 2, but "{}", with a length of {} was found !!!'.format(keys, len(keys)))
        #
        #     if keys[0] == keys[1] == None:
        #         raise ValueError("Both keys can't be None !!!")
        #
        #     self.keys['e'] = keys[0]
        #     self.keys['d'] = keys[1]
        #
        #
        # else:
        #     raise TypeError('The argument "keys" should be a string or a list, but "{}" of type "{}" was found !!!'.format(keys, type(keys)))


        self.pb_key = key.pb

        if key.is_private:
            self.pv_key = key.pv

        else:
            self.pv_key = None


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
            msg_err = 'Cannot sign with an empty private key !!!'

            if self.interface == 'console':
                cl_out(c_error, msg_err)

            elif self.interface == 'gui':
                QMessageBox.critical(None, 'Cannot sign !!!', '<h2>{}</h2>'.format(msg_err))

            raise TypeError(msg_err)

        e, n = self.pb_key
        d, n = self.pv_key
        sign_key = RsaKey(e=d, d=e, n=n)

        return RSA(sign_key, self.interface).encrypt(txt)


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

        e, n = self.pb_key
        d, n = self.pv_key
        sign_key = RsaKey(e=d, d=e, n=n)

        return RSA(sign_key, self.interface).decrypt(txt)

