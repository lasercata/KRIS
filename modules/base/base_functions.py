#!/bin/python3
# -*- coding: utf-8 -*-

'''Base functions of KRIS'''

base_functions__auth = 'Lasercata'
base_functions__last_update = '05.03.2021'
base_functions__version = '2.3,1_kris'


##-import
from datetime import datetime as dt
from os import system, walk, stat
from os import chdir, mkdir, getcwd
from os.path import expanduser
import platform

from modules.base import glb


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


##-Others functions
def date():
    now = str(dt.now())
    lst_now = now.split(' ')
    date = lst_now[0].split('-')
    time_ = lst_now[1].split(':')
    time_2 = time_[2].split('.')

    year = date[0]
    month = date[1]
    day = date[2]

    hour = time_[0]
    min_ = time_[1]
    sec = time_2[0]


    ret = 'Saved the : ' + day + '/' + month + '/' + year + ', at ' + hour + 'h' + min_ + "'" + sec + '"'

    return ret

def date_():
    '''Return a tuple of this format :
        (year, month, day, hour, minute, sec, microsec)
    '''

    now = dt.now()

    return now.year, now.month, now.day, now.hour, now.minute, now.second, now.microsecond

def date_my_format(sec=False):
    '''
    Return the date at this format :
        2020.08.09_23h08, or 2020.08.09_13h08:33 if sec=True.
    '''

    d = date_()
    ret = '{}.{}.{}_{}h{}'.format(*[format(d[k], '02') for k in range(0, 5)])

    if sec:
        ret += ':' + format(d[5], '02')

    return ret

def date_format(sec=False):
    '''
    Return the date at this format :
        2020-08-09_23:08, or 2020-08-09_13:08:33 if sec=True.
    '''

    d = date_()
    ret = '{}-{}-{}_{}:{}'.format(*[format(d[k], '02') for k in range(0, 5)])

    if sec:
        ret += ':' + format(d[5], '02')

    return ret


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



#---------chd
def chd(path):
    '''
    Change current directory to [cracker]/Data/[path], where [cracker] is the path
    where cracker is launched.
    If directory "Data" don't exist, it create it.


    If [path] don't exist, return to last path and raise a FileNotFoundError exeption,
    Return the old path otherwise.
    '''

    old_path = getcwd()

    try:
        chdir(glb.KRIS_running_path + '/Data')

    except FileNotFoundError:
        chdir(glb.KRIS_running_path)
        mkdir('Data')
        chdir('Data')
        print('"Data" folder created in "{}" !'.format(glb.KRIS_running_path))

    #------chdir to [path]
    try:
        chdir(path)

    except FileNotFoundError as err:
        chdir(old_path)
        raise FileNotFoundError(err)

    return old_path


#---------list_dir
def list_files(path='.', ext=None, exclude=None):
    '''
    Return a tuple containing all the filenames at path. Not recursive.

    path : the path where list files. Default is '.' ;
    ext : if not None, lists only files with that extention. Default is None ;
    exclude : filenames to exclude. Should be a list or None. Default is None.
    '''

    if exclude == None:
        exclude = ()

    elif type(exclude) not in (list, tuple, set):
        raise ValueError('"exclude" parameter should be None, list, tuple or set, but "' \
        + str(exclude) + '", type = "' + str(type(exclude)) + '" was found !!!')

    lst = []

    for r, d, f in walk(path):
        for fn in f:
            if r == path and fn not in exclude and ext==None:
                lst.append(fn)

            elif ext != None and fn not in exclude:
                if r == path and ext in fn:
                    lst.append(fn)

    return tuple(lst)



#---------h_size
def h_size(size, bi=None, prec=1):
    '''
    Function which return the size in a readable format.

    - bi : use binary prefix (1024^n) (KiB, MiB, ...). If False, use decimal prefixs (1000^n) (KB, MB, ...)
     If None, check the OS to determine the good one (Linux = True ; Windows = False) ;
    - prec : the precision (decimal places).
    '''

    if bi not in (True, False, None):
        raise ValueError('"bi" arg should be a boolean, or None, but "{}", of type {} was found !!!'.format(bi, type(bi)))

    if bi == None:
        if platform.system() == 'Linux':
            bi = True

        else:
            bi = False

    b = (1000, 1024)[bi]
    p = ('decimal', 'binary')[bi]

    s = size
    i = 0

    while s > b:
        s /= b
        i += 1

    if i >= len(FileInfo.prefix[p]):
        return '{} * 10^{} o'.format(
            round(size / b**i, prec),
            i * 3
        )

    return '{} {}'.format(
        round(size / b**i, prec),
        FileInfo.prefix[p][i]
    )



#---------FileInfo
class FileInfo:
    '''
    Class dealing with files' sizes and dates.
    Inspiration / base source : https://stackoverflow.com/a/39988702 (for the size part)
    '''

    prefix = {
        'binary' : ('B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB', 'YiB'),
        'decimal' : ('B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB')
    }


    def __init__(self, fn):
        '''Initiate the FileInfo object'''

        self.fn = fn

    def __repr__(self):
        '''Represent the FileInfo object'''

        return "FileInfo('{}'), {}, last modified : {}".format(self.fn, self.h_size(), self.h_date())


    #------sizes
    def size(self):
        '''Return the file's size, in bytes.'''

        return stat(self.fn).st_size


    def h_size(self, prec=1, bi=True):
        '''
        Return the file's size, in an human readable format (KiB, MiB, GiB, ... or KB, MB, GB, ...)

        prec : the precision. Used with round(size, prec) ;
        bi : use binary prefix (1024^n) (KiB, MiB, ...). If False, use decimal prefixs (1000^n) (KB, MB, ...).
        '''

        if bi not in (True, False):
            raise ValueError('"bi" arg should be a boolean, but "{}", of type {} was found !!!'.format(bi, type(bi)))

        b = (1000, 1024)[bi]
        p = ('decimal', 'binary')[bi]

        pref_pow = self.get_size_pow(b)
        size = self.size() / b**pref_pow

        return '{} {}'.format(
            round(size, prec),
            FileInfo.prefix[p][pref_pow]
        )


    def get_size_pow(self, b=1024):
        '''
        Function which get the power of the size.

        b : the base. Eg. 1024 for binary, 1000 for decimal.
        '''

        size = self.size()
        i = 0

        while size > b:
            size /= b
            i += 1

        return i


    #------dates
    def _set_date(self, date_):
        '''Return the given date, in a readable string, at the format 'YYYY-MM-DD hh:mm:ss'.'''

        frmt = lambda x, y='02' : format(x, y)

        return '{}-{}-{} {}:{}:{}'.format(
            frmt(date_.year, '04'), frmt(date_.month), frmt(date_.day),
            frmt(date_.hour), frmt(date_.minute), frmt(date_.second))


    def date(self, type_='m'):
        '''
        Return the file's dates, according to "type_" :
            'm' : last_modification ;
            'a' : last_access ;
            'c' : creation.
        '''

        if type_ not in ('m', 'a', 'c'):
            raise ValueError('The argument "type_" should be "m", "a", or "c", but {} of type {} was found !!!'.format(type_, type(type_)))


        st = stat(self.fn)

        if type_ == 'm':
            return dt.fromtimestamp(st.st_mtime)

        elif type_ == 'a':
            return dt.fromtimestamp(st.st_atime)

        else:
            return dt.fromtimestamp(st.st_ctime)


    def h_date(self):
        '''Return the last modification, in a readable string.'''

        md = self.date('m')

        return self._set_date(md)


    def h_dates(self, type_='m'):
        '''Return the three dates in a readable string.'''

        if type_ not in ('m', 'a', 'c'):
            raise ValueError('The argument "type_" should be "m", "a", or "c", but {} of type {} was found !!!'.format(type_, type(type_)))


        if type_ == 'm':
            return self._set_date(self.date('m'))

        elif type_ == 'a':
            return self._set_date(self.date('a'))

        else:
            return self._set_date(self.date('c'))


##-Maths functions

def fact(n:int):
    '''
    Return the factorial of n

    n -> n!
    '''

    if type(n) != int:
        raise ValueError('The number "n" should be an intenger, but "{}", of type"{}" was found !!!'.format(n, type(n)))

    if n in (0, 1):
        return 1

    elif n > 0:
        return n * fact(n - 1)

    else:
        raise ValueError('The number "n" should be a positive number !!!')