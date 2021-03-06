#!/bin/python3
# -*- coding: utf-8 -*-
'''Module including some of P@ssw0rd_Test0r functions.'''

pwd_testor__auth = 'Lasercata'
pwd_testor__date = '05.03.2021'
pwd_testor__version = '1.1_kris'

##-import
from math import *

from Languages.lang import translate as tr

##-ini
alf_0_1 = ('0', '1')
alf_0_9 = ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9')
alf_hex = ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a','b','c','d','e', 'f', 'A', 'B', 'C', 'D', 'E', 'F')
alf_a_z = ('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q', 'r','s','t','u','v','w','x','y','z')
alf_A_Z = ('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
 'O', 'P', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z')

alf_spe = (' ', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-',
'.', '/', ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{',
'|', '}', '~', '£', '§', '¨', '°', '²', 'µ', '’', '€')


freq_pwd = ('!@#$%^&*', '0000', '1111', '111111', '123', '123123', '1234', '12345',
'123456', '1234567', '12345678', '123456789', '1234567890', '222222', '55555',
'654321', '666', '666666', '66666666', '987654321', 'Password', 'abc123', 'admin',
'administrateur', 'administrator', 'azerty', 'azertyuiop', 'dragon', 'football',
'freedom', 'hello', 'iloveyou', 'letmein', 'login', 'master', 'monkey', 'p@ssw0rd',
'p@ssword', 'passw0rd', 'password', 'password1', 'password123', 'qazwsx', 'qwerty',
'qwertyuiop', 'shadow', 'starwars', 'trustno1', 'welcome', 'whatever')


##-functions
#----------------------------------------------------------------------pwd_entro
def pwd_entro(H=None, N=None, L=None):
    '''
    Return the unknown value.
    One and only one of the 3 variables should be None.

    H : entropy of the password ;
    N : alphabet's lenth ;
    L : password's lenth.
    '''

    a = None
    if (H == a and N == a) or (H == a and L == a) or (N == a and L == a) or (H == a and N == a and L == a):
        return '\n' + tr('Only one var should be None !!!')

    elif H == a:
        return log2(N **L)

    elif L == a:
        return round(H / log2(N))

    elif N == a:
        return round(2 **(H / L))

    else:
        return '\n' + tr('At least 1 var should be None !!!')


#---------------------------------------------------------------------------wlth
def wlth(word):
    '''Return the sort list of all differents word's characters, in one occurence.'''

    if type(word) != str:
        raise ValueError(tr('"word" argument should be a string, but "{}", of type "{}" was found !').format(word, type(word)))

    ret = list(set(word))
    ret.sort()
    return ret


#---------------------------------------------------------------------------walf
def walf(word):
    '''
    Function which search the alphabets used in "word".
    Return (alfs_lth, alf), where alfs_lth is the alphabets' length, and alf is a tuple containing the alphabets' names.
    '''

    char = {'09' : [], 'az' : [], 'AZ' : [], 'spe' : []}
    lst_chr = []

    #---------get last alphabet character
    #------sort the word's charaters
    for k in word:
        if k in alf_0_9:
            char['09'].append(k)

        elif k in alf_a_z:
            char['az'].append(k)

        elif k in alf_A_Z:
            char['AZ'].append(k)

        elif k in alf_spe:
            char['spe'].append(k)

    #------get the last character of each alphabet
    for k in char:
        char[k].sort()

        if char[k] != []:
            lst_chr.append(char[k][-1]) #last character


    #---------get alfs
    bi = dec = hex_ = alph = alph_up = spe = False

    for k in lst_chr:
        if k in alf_0_1: #binary
            bi = True

        elif k in alf_0_9[2:]: #decimal
            dec = True

        elif k in alf_hex[10:] and (k not in alf_a_z[6:] and k not in alf_A_Z[6:]): #hexadecimal
            hex_ = True

        elif k in alf_a_z[6:]: #alphabetic lowercases
            alph = True

        elif k in alf_A_Z: #alphabetic uppercases
            alph_up = True

        elif k in alf_spe: #specials
            spe = True


    #---------get the alphabets
    ret_alfs = []
    alf_lth = 0

    if hex_:
        ret_alfs.append(tr('Hexadecimal'))
        alf_lth += 16

    elif dec:
        ret_alfs.append(tr('Decimal'))
        alf_lth += 10

    elif bi:
        ret_alfs.append(tr('Binary'))
        alf_lth += 2


    if alph_up:
        ret_alfs.append(tr('Alphabetic uppercases'))
        alf_lth += 26

    if alph:
        ret_alfs.append(tr('Alphabetic lowercases'))
        alf_lth += 26


    if spe:
        ret_alfs.append(tr('Specials'))
        alf_lth += len(alf_spe)


    return alf_lth, tuple(ret_alfs)


#------------------------------------------------------------------------get_sth
def get_sth(word, ret_entro=True):
    '''
    Print infomations and return word strenth, in bits.

    - word : the word to test ;
    - ret_entro : a boolean which indicates whatever return only the entropy (if True),
    or the normal return (the info string).

    ------Here in KRIS : works only with ret_entro to True.------
    '''

    if word == '':
        print('\n' + tr('You should enter something !!!'))
        return -3 #Abort

    if ret_entro not in (0, 1):
        raise ValueError(tr('ret_entro should be a boolean !!!'))

    entro = None

    #---------get lenths
    lth = len(word) #word's lenth
    lth_occ = len(wlth(word)) #word's lenth of characters in one occurence

    walfs = walf(word)
    lth_alfs = walfs[0]  #pwd's alphabets lenth


    #---------tests
    weak_freq = weak_occ = weak_year = False

    if lth_occ <= 3 and lth > 4: #test if there is less than 3 differents characters in a word with a lenth bigger than 4
        weak_occ = True


    if word in freq_pwd: #test if the password is in the most used ones
        entro = log2(len(freq_pwd))
        weak_freq = True

    elif lth == 4: #test if word is a year in [1900 ; 2100]
        try:
            wd = int(word)

            if 1900 <= wd <= 2100:
                entro = log2(200)
                weak_year = True

            else:
                entro = pwd_entro(None, lth_alfs, lth)

        except:
            entro = pwd_entro(None, lth_alfs, lth)

    else:
        entro = pwd_entro(None, lth_alfs, lth)

    if ret_entro:
        return entro