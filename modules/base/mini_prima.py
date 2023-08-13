#!/bin/python3
# -*- coding: utf-8 -*-
"""Module dealing with prime numbers."""

prima__auth = 'Elerias'
prima__last_update = '05.03.2021'
prima__version = '3.3.1_kris'

##-import
import math
from random import randint


##-Probabilistic primalities test
def isSurelyPrime(n):
    """
    Check if n is prime. Uses Miller Rabin test.
    If n is prime, return True ;
    return False else.
    """

    if n == 1 or n % 2 == 0 or n % 3 == 0 or n % 5 == 0 or n % 7 == 0:
        return False

    if n in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41):
        return True

    elif n in (0, 1, 4, 6, 8, 9, 10, 12, 14, 15, 16, 18, 20):
        return False

    if n > 1027:
        for d in range(7, 1028, 30) :
            if n % d == 0 or n % (d+4) == 0 or n % (d+6) == 0 or n % (d+10) == 0 or n % (d+12) == 0 or n % (d+16) == 0 or n % (d+22) == 0 or n % (d+24) == 0:
                return False

    return miller_rabin(n, 15)

def miller_rabin_witness(a, d, s, n):
    """Return True if a is a Miller-Rabin witness."""

    r = pow(a, d, n)
    if r == 1 or r == n - 1:
        return False
    for k in range(s):
        r = r**2 % n
        if r == n - 1:
            return False
    return True

def miller_rabin(n, k=15) :
    """
    Return the primality of n using the probabilistic test of primality of Miller-Rabin. k is the number of the loops.
    The possible decreases in averages of 75 % by unity if k.

    n : number to determine the primality ;
    k : number of tests (Error = 0.25 ^ number of tests).
    """

    if n in (0, 1):
        return False
    if n == 2:
        return True
    s = 1

    d = n // 2

    while d % 2 == 0:

        s +=  1

        d = d // 2

    for k in range(k) :

        a = randint(2, n - 1)
        if miller_rabin_witness(a, d, s, n):
            return False
    return True

