#!/bin/python3
# -*- coding: utf-8 -*-

'''Format output from cryptographic functions.'''

FormatMsg__auth = 'Lasercata'
FormatMsg__last_update = '11.04.2021'
FormatMsg__version = '1.0'

##-import
from modules.base.base_functions import NewLine
from Languages.lang import translate as tr


##-ini
ciphers_list = {
    'KRIS' : ('KRIS-AES-256', 'KRIS-AES-192', 'KRIS-AES-128'),

    'AES' : ('AES-256', 'AES-192', 'AES-128'),

    'RSA' : ('RSA', tr('RSA signature')),
}


##-main
class FormatMsg:
    '''Format output from KRIS ciphers.'''

    def __init__(self, msg):
        '''
        Initiate FormatMsg.

        - msg : the message text.
        '''

        self.msg = msg


    def set(self, cipher_name, kris_version):
        '''Format the message msg.'''

        if cipher_name not in (*ciphers_list['KRIS'], *ciphers_list['AES'], *ciphers_list['RSA']):
            raise ValueError('The argument `cipher_name` is not correct.')

        ret = '------BEGIN KRIS MESSAGE------\nVersion: {}\nCipher: {}\n---\n'.format(kris_version, cipher_name)
        ret += NewLine(64).set(self.msg)
        ret += '\n------END KRIS MESSAGE------'

        return ret


    def unset(self):
        '''
        Get data from formated message
        Return :
            msg, cipher, version
        '''

        if False in [k in self.msg for k in ('------BEGIN KRIS MESSAGE------\n', 'Version: ', 'Cipher: ', '---\n', '\n------END KRIS MESSAGE------')]:
            raise ValueError('FormatMsg: The message is not well formated')

        begin = self.msg.find('------BEGIN KRIS MESSAGE------\n') + len('------BEGIN KRIS MESSAGE------\n')
        end = self.msg.find('\n------END KRIS MESSAGE------')

        msg_body = self.msg[begin:end]

        for k in msg_body.split('\n'):
            if 'Version: ' in k:
                version = k.replace('Version: ', '')

            elif 'Cipher: ' in k:
                ciph = k.replace('Cipher: ', '')

        if ciph not in (*ciphers_list['KRIS'], *ciphers_list['AES'], *ciphers_list['RSA']):
            raise ValueError('FormatMsg: The message is not well formated')

        msg = msg_body[msg_body.find('---\n') + 4:].replace('\n', '')

        return msg, ciph, version































