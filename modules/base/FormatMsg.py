#!/bin/python3
# -*- coding: utf-8 -*-

'''Format output from cryptographic functions.'''

FormatMsg__auth = 'Lasercata'
FormatMsg__last_update = '15.04.2021'
FormatMsg__version = '1.1'

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

    def __init__(self, msg, nl=True, md='msg'):
        '''
        Initiate FormatMsg.

        - msg : the message text ;
        - nl : a bool indicating if use NewLine (False used with RSA signature) ;
        - md : in ('msg', 'sign'). Indicate the BEGIN and END text.
        '''

        if md not in ('msg', 'sign'):
            raise ValueError('The argument `md` is not in ("msg", "sign"). found "{}".'.format(md))

        self.msg = msg
        self.nl = nl

        if md == 'msg':
            self.begin = '------BEGIN KRIS MESSAGE------\n'
            self.end = '\n------END KRIS MESSAGE------'

        else:
            self.begin = '------BEGIN KRIS SIGNED MESSAGE------\n'
            self.end = '\n------END KRIS SIGNED MESSAGE------'


    def set(self, dct):
        '''
        Format the message msg.

        - dct : a dict of the form {'Arg': 'value', ...}
        '''

        if ('Cipher' not in dct) or ('Version' not in dct):
            raise ValueError('The dict `dct` should contain at least "Cipher" and "Version".')

        ret = self.begin

        for k in dct:
            ret += '{}: {}\n'.format(k, dct[k])

        ret += '---\n'
        if self.nl:
            ret += NewLine(64).set(self.msg)

        else:
            ret += self.msg

        ret += self.end

        return ret


    def unset(self):
        '''
        Get data from formated message
        Return :
            msg, dct
        '''

        if False in [k in self.msg for k in ('------BEGIN KRIS MESSAGE------\n', 'Version: ', 'Cipher: ', '---\n', '\n------END KRIS MESSAGE------')]:
            if False not in [k in self.msg for k in ('------BEGIN KRIS SIGNED MESSAGE------\n', 'Version: ', 'Cipher: ', '---\n', '\n------END KRIS SIGNED MESSAGE------')]:
                self.begin = '------BEGIN KRIS SIGNED MESSAGE------\n'
                self.end = '\n------END KRIS SIGNED MESSAGE------'

            else:
                raise ValueError('FormatMsg: The message is not well formatted')

        begin = self.msg.find(self.begin) + len(self.begin)
        end_args = self.msg.find('\n---\n')
        end = self.msg.find(self.end)

        args = self.msg[begin:end_args]
        msg_body = self.msg[begin:end]

        dct = {}
        for k in args.split('\n'):
            a, b = k.split(': ')
            dct[a] = b

        msg = msg_body[msg_body.find('---\n') + 4:]

        if self.nl:
            msg = msg.replace('\n', '')

        return msg, dct

