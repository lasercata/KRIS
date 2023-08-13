#!/bin/python3
# -*- coding: utf-8 -*-

'''Implementation of functions manipulating text.'''

#--------------------------
#
# Last update : 2023.08.10
# Author      : Lasercata
# Version     : v1.0.0
#
#--------------------------

##-Imports
pass

##-set functions
def set_prompt(lst):
    '''
    Return a str organized correctly to print.
    'lst' should be a list, a tuple, or a set.
    '''

    ret = ''
    for k in lst:
        ret += str(k)

        if k != lst[-1]:
            ret += ', '

    return ret


def set_lst(lst, py=False):
    '''
    Same as set_dict, but with a list.

    - lst : the list to process ;
    - py : a boolean which indicates if the result should work in python.
    '''

    if py:
        ret = '('

    else:
        ret = ''

    for k in lst:
        if py:
            ret += '\n\t{},'.format(set_str(k))

        else:
            ret += '\n\t- {} ;'.format(set_str(k))


    if py:
        ret = ret[:-1] + '\n)'

    else:
        ret = ret[:-2] + '.'

    return ret


def set_dict(dct):
    '''
    Return a string representing the dict, with line by line key-value.
    Usefull to set readable dict in your programs
    '''

    ret = '{'

    for k in dct:
        ret += '\n\t{}: {},'.format(set_str(k), set_str(dct[k]))

    ret = ret[:-1] + '\n}'

    return ret


def set_str(obj):
    if type(obj) == str:
        return "'{}'".format(obj)

    return '{}'.format(obj)


##-Spacing
def space(n, grp=3, sep=' ', rev_lst=True):
    '''Return n with spaced groups of grp.
    .n : the number / string to space ;
    .grp : the group size ;
    .sep : the separation (default is a space) ;
    .rev_lst : reverse the string or not. Useful to not reverse it with RSA.
    '''

    lth = len(str(n))
    if type(n) == int:
        n = str(n)

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


def indent(string, c='\t'):
    '''
    Return the string 'string' indented, i.e. with the character 'c' added at
    the begining of every line.
    '''

    return c + string.replace('\n', '\n{}'.format(c))


def newline(string, n=50, nl='\n'):
    '''Return the string with newline every n.'''

    ls = list(string)

    for k in range(len(ls)):
        if k != 0:
            ls.insert(n * k - 1, nl)

    return ''.join(ls).strip(nl)

class NewLine:
    '''Class which manages the text's width.'''

    def __init__(self, width=50, c='\n'):
        '''
        Initiate the NewLine class.

        - width : the text's width ;
        - c : the newline character.
        '''

        self.width = width
        self.c = c


    def set(self, txt):
        '''Add `c` every `width` in 'txt'.'''

        ls = list(txt)

        for k in range(len(ls)):
            if k != 0:
                ls.insert(self.width * k - 1, self.c)

        return ''.join(ls).strip(self.c)

    def unset(self, txt):
        '''Unset txt's width'''

        return txt.replace(self.c, '')


    def text_set(self, txt):
        '''Same as self.set, but only adds `c` in the spaces.'''

        ls = str(txt)
        ret = ''

        for k in range(self.width, len(ls) + self.width, self.width):
            l = ls[k - self.width:self.width * k//self.width]

            d = False
            step = ''

            for j in l[::-1]:
                if j == ' ' and not d:
                    step += self.c[::-1]
                    d = True

                else:
                    step += j

            ret += step[::-1]

        return ret


##-Split function
def split(txt, size, pad_=None):
    '''
    Return a list representing txt by groups of size `size`.

    - txt  : the text to split ;
    - size : the block size ;
    - pad_  : if not None, pad the last block with `pad_` to be `size`length (adding to the end).
    '''

    l = []

    for k in range(len(txt) // size + 1):
        p = txt[k*size : (k+1)*size]

        if p in ('', b''):
            break

        if pad_ != None:
            p = pad(p, size, pad_)

        l.append(p)

    return l


def pad(txt, size, pad=' ', end=True):
    '''
    Pad `txt` to make it `size` long.
    If len(txt) > size, it just returns `txt`.

    - txt  : the string to pad ;
    - size : the final wanted size ;
    - pad  : the character to use to pad ;
    - end  : if True, add to the end, otherwise add to the beginning.
    '''

    while len(txt) < size:
        if end:
            txt += pad

        else:
            txt = pad + txt

    return txt


##-Other
def str_diff(s1, s2, verbose=True, max_len=80):
    '''
    Show difference between strings (or numbers) s1 and s2. Return s1 == s2.

    - s1      : input string to compare ;
    - s2      : output string to compare ;
    - verbose : if True, show input and output message and where they differ if so ;
    - max_len : don't show messages if their length is more than max_len. Default is 80. If negative, always show them.
    '''

    s1 = str(s1)
    s2 = str(s2)

    if verbose:
        if len(s1) <= max_len or max_len == -1:
            print(f'\nEntry message : {s1}')
            print(f'Output        : {s2}')

        for k in range(len(s1)):
            if s1[k] != s2[k]:
                if len(s1) <= max_len or max_len == -1:
                    print(' '*(len('Output        : ') + k) + '^')

                print('Input and output differ from position {}.'.format(k))

                return False

        print('Input and output are identical.')

    return s1 == s2
