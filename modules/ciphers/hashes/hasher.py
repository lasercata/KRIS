#!/bin/python3
# -*- coding: utf-8 -*-
'''Module incuding hasher fonctions'''

hasher__auth = 'Lasercata'
hasher__last_update = '05.03.2021'
hasher__version = '4.0_kris'

##-import
from hashlib import *

#from modules.base.console.color import color, cl_out, c_output, cl_inp, c_succes, c_wrdlt, c_error, c_prog, c_ascii
#from modules.base.base_functions import inp_lst, set_prompt


##-ini
h_str = tuple(sorted(algorithms_available)) #needed in others files

##-main
def hasher(txt, h):
    '''Return txt's h hash.'''

    h_str = tuple(algorithms_available)

    if h in h_str:
        try:
            ret = eval(h_str[h_str.index(h)])(txt.encode()).hexdigest()

        except:
            ret = new(h_str[h_str.index(h)], txt.encode()).hexdigest()

    else:
        return -1

    return ret


class Hasher:
    '''Class which define hasher.'''

    def __init__(self, h, loop=512):
        '''
        Initiate the Hasher object.

        - h : the hash to use ;
        - loop : only used if h is 'SecHash'. Cf to the doc of 'SecHash' function.
        '''

        self.h_str = tuple(sorted(algorithms_available))

        if h not in (*self.h_str, 'SecHash'):
            raise ValueError('The argument "h" should be in the list {} !!!'.format(self.h_str))

        self.h = h
        self.loop = loop


    def hash(self, txt):
        '''Return the hash of 'txt'.'''

        if type(txt) == str:
            txt = txt.encode()

        elif type(txt) != bytes:
            raise ValueError('The text "txt" must be a string !!!')


        if self.h != 'SecHash':
            try:
                ret = eval(self.h_str[self.h_str.index(self.h)])(txt)

            except:
                ret = new(self.h_str[self.h_str.index(self.h)], txt)


            if self.h in ('shake_128', 'shake_256'):
                ret = ret.hexdigest(int(self.h[-3:]))

            else:
                ret = ret.hexdigest()

        else:
            ret = SecHash(txt.decode(), self.loop)

        return ret


def SecHash(txt, loop=512):
    '''
    Hash 'txt' with the following schem :
        sha512(sha256(sha512(sha256(sha512(txt*3 + str(loop))))))

    Do this 'loop' times.
    '''

    if type(loop) != int:
        raise ValueError('The arg "loop" should be an intenger !!!')

    txt = txt*3 + str(loop)

    h512 = Hasher('sha512').hash
    h256 = Hasher('sha256').hash

    ret = h512(
        h256(
            h512(
                h256(
                    h512(
                        txt
                    )
                )
            )
        )
    )

    if loop > 0:
        ret = SecHash(ret, loop - 1)

    return ret


#
# #---#
# def use_hasher():
#     '''Use hasher function in console mode.'''
#
#     h_str = tuple(algorithms_available)
#     prompt_h = set_prompt(algorithms_available)
#     prompt = 'Hashes :\n\n ' + prompt_h + '\n\nChoose a hash to hash with :'
#
#     h = inp_lst(prompt, h_str)
#
#     txt = cl_inp('Word to hash :')
#
#     prnt = '=====> ' + hasher(h, txt)
#     cl_out(c_output, prnt)