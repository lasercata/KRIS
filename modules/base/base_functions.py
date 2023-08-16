#!/bin/python3
# -*- coding: utf-8 -*-

'''Base functions of KRIS'''

base_functions__auth = 'Lasercata'
base_functions__last_update = '2023.08.16'
base_functions__version = '3.0_kris'


##-Import
#---------Packages
from datetime import datetime as dt
from os import system, walk, stat
from os import chdir, mkdir, getcwd
from os.path import expanduser
import platform

from modules.base import glb

#------Kris' modules
from modules.base.AskPwd import AskPwd

##-Date
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


##-chd
def chd(path):
    '''
    Change current directory to [kris]/Data/[path], where [kris] is the path
    where kris is launched.
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


##-list_dir
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


##-Files functions
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
        '''Return the given date, in a readable string, in the format 'YYYY-MM-DD hh:mm:ss'.'''

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


#---------Read file chunk by chunk
def read_chunks(fn, chunk_size):
    '''
    Defines a generator that read a file by chunks.

    - fn         : the file name ;
    - chunk_size : the number of bytes to read at once.

    Usage :
    ```
    for c in read_chunks(fn, size):
        f(c)
    ```
    '''

    with open(fn, 'rb') as f:
        while True:
            ck = f.read(chunk_size)

            if ck:
                yield ck

            else:
                break


#---------Get the number of lines of a file
def get_line_count(fn):
    '''
    Return the number of lines of the file `fn`.

    Inspired from
    https://stackoverflow.com/a/1019572
    '''

    with open("myfile.txt", "rbU") as f:
        num_lines = sum(1 for _ in f)

    return num_lines


##-Xor
def xor(s1, s2):
    '''Return s1 xored with s2 bit per bit.'''

    if (len(s1) != len(s2)):
        raise ValueError('Strings are not of the same length.')

    if type(s1) != bytes:
        s1 = s1.encode()

    if type(s2) != bytes:
        s2 = s2.encode()

    l = [i ^ j for i, j in zip(list(s1), list(s2))]

    return bytes(l)


##-Int and bytes
def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'little')

def bytes_to_int(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, 'little')


##-Input functions
def print_error(err_msg, title='Error !!!', parent=None, interface=None):
    '''
    Show the error message using the right interface.

    - err_msg   : the error message to show ;
    - title     : the title for the QMessageBox popup (used only if interface is 'gui') ;
    - parent    : the parent of the QMessageBox popup (used only if interface is 'gui') ;
    - interface : the interface used by the program. In (None, 'console', 'gui').
    '''

    if interface == None:
        print(err_msg)

    elif interface == 'console':
        cl_out(c_error, err_msg)

    elif interface == 'gui':
        QMessageBox.critical(parent, title, f'<h2>{err_msg}</h2>')

    else:
        raise ValueError('The argument "interface" should be None, "gui", \
            or "console", but {} of type {} was found !!!'.format(interface, type(interface)))


def get_pwd(label='RSA key password :', ret_hash=True, h='sha256', parent=None, interface=None):
    '''
    Ask for a password to the user using the right interface.

    - ret_hash  : a boolean indicating if to hash the input ;
    - h         : the hash to use ;
    - parent    : the parent for the AskPwd window ;
    - interface : the interface used by the program. In (None, 'console', 'gui').

    Return :
        pwd_clear    if ret_hash is False ;
        pwd_h        otherwise ;
        -3           if the user canceled.
    '''

    try:
        if interface == None:
            pwd_clear = input(label)

        elif self.interface == 'console':
            pwd_clear = getpass(tr(label))

        elif self.interface == 'gui':
            pwd_clear = AskPwd.use(ret_hash=False, parent=parent) #TODO: use label also here.

            if pwd_clear == None: #Canceled by user
                raise KeyboardInterrupt

    except KeyboardInterrupt:
        return -3

    if ret_hash:
        pwd_h = Hasher(h).hash(pwd_clear)
        return pwd_h

    else:
        return pwd_clear


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
