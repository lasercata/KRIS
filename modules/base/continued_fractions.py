#!/bin/python3
# -*- coding: utf-8 -*-

'''Implementation of continued fractions'''

#--------------------------
#
# Last update : 2023.08.10
# Author      : Lasercata
# Version     : v1.0.0
#
#--------------------------

##-Imports
from math import floor, isqrt
from fractions import Fraction

##-ContinuedFraction
class ContinuedFraction:
    '''Class representing a continued fraction.'''

    def __init__(self, f):
        '''
        Initialize the class

        - f : the int array representing the continued fraction.
        '''

        if type(f) in (set, list):
            self.f = list(f)

        else:
            raise ValueError('ContinuedFraction: error: `f` should be a list')

        if len(f) == 0:
            raise ValueError('ContinuedFraction: error: `f` should not be empty')

        for j, k in enumerate(f):
            if type(k) != int:
                raise ValueError(f'ContinuedFraction: error: `f` should be a list of int, but `{k}` found at position {j}')


    def __repr__(self):
        '''Return a pretty string representing the fraction.'''

        ret = f'{self.f[-1]}'

        for k in reversed(self.f[:-1]):
            ret = f'{k} + 1/(' + ret + ')'

        return ret


    def __eq__(self, other):
        '''Test the equality between self and the other.'''

        return self.f == other.f


    def eval_rec(self):
        '''Return the evaluation of self.f via a recursive function.'''

        return self._eval_rec(self.f)


    def _eval_rec(self, f_):
        '''The recursive function.'''

        if len(f_) == 1:
            return f_[0]

        return f_[0] + 1/(self._eval_rec(f_[1:]))


    def truncate(self, pos):
        '''
        Return a ContinuedFraction truncated at position `pos` from self.f.

        - pos : the position of the truncation. The element at position `pos` is kept in the result.
        '''

        return ContinuedFraction(self.f[:pos + 1])


    def get_convergents(self):
        '''
        Return two lists, p, q which represents the convergents :
        the n-th convergent is `p[n] / q[n]`.
        '''

        p = [0]*(len(self.f) + 2)
        q = [0]*(len(self.f) + 2)

        p[-1] = 1
        q[-2] = 1

        for k in range(0, len(self.f)):
            p[k] = self.f[k] * p[k - 1] + p[k - 2]
            q[k] = self.f[k] * q[k - 1] + q[k - 2]

        return p, q


    def eval_(self):
        '''Return the evaluation of self.f.'''

        p, q = self.get_convergents()

        return p[len(self.f) - 1] / q[len(self.f) - 1]


    def get_nth_convergent(self, n):
        '''Return the convergent at the index n.'''

        if n >= len(self.f):
            raise ValueError(f'ContinuedFraction: get_nth_convergent: n cannot be greater than {len(self.f) - 1}')

        p, q = self.get_convergents()

        return p[n] / q[n]


##-Calculate continued fractions
def get_continued_fraction(a, b):
    '''Return a ContinuedFraction object, the continued fraction of a/b.'''

    f = []
    d = Fraction(a, b)
    f.append(floor(d))

    while d - floor(d) != 0:
        d = 1/(d - floor(d))
        f.append(floor(d))

    return ContinuedFraction(f)


def get_continued_fraction_real(x):
    '''
    Return a ContinuedFraction object, the continued fraction of x.
    Note that there can be errors because of the float precision with this function.
    '''

    f = []

    d = x
    f.append(floor(x))

    while d - floor(d) != 0:
        d = 1/(d - floor(d))
        f.append(floor(d))

    return ContinuedFraction(f)


def get_continued_fraction_rec(a, b, f=[]):
    '''Return a ContinuedFraction object, the continued fraction of a/b. This is a recursive function.'''

    # euclidean division : a = bq + r
    q = a // b
    r = a % b

    if r == 0:
        return ContinuedFraction(f + [q])

    return get_continued_fraction_rec(b, r, f + [q])
