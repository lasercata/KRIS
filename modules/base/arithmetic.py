#!/bin/python3
# -*- coding: utf-8 -*-

'''Program including useful arithmetic functions.'''

arithmetic__auth = 'Elerias, Lasercata'
arithmetic__last_update = '2023.08.10'
arithmetic__version = '2.0.0'


##-Diophantien equations
def ext_euclid(a: int, b: int) -> (int, (int, int)):
    '''
    Extended Euclidean algorithm.
    Return the greatest common divisor (gcd) and Bezout coefficients (u, v) for (a, b), i.e such that :
        u*a + v*b = gcd(a, b)

    Return (gcd, (u, v)).
    '''

    (old_u, u) = (1, 0)
    (old_v, v) = (0, 1)

    while b != 0:
        q = a // b
        (a, b) = (b, a - q*b)
        (old_u, u) = (u, old_u - q*u)
        (old_v, v) = (v, old_v - q*v)

    if a < 0:
        return -a, (-old_u, -old_v)

    return a, (old_u, old_v)


def bezout(a: int, b: int) -> (int, int):
    '''
    Return Bézout coefficients (u, v) for (a, b).
    u*a + v*b = gcd(a, b)
    '''

    return ext_euclid(a, b)[1]

def solve_bezout_equation(a: int, b: int, c: int):
    '''
    Solve the equation ax + by = c.
    If there is no solution, return (False,), else return (True, ((m, n), (p, q))) with (mk + n, pk + q) the form of a solution.
    '''

    (d, (u, v)) = ext_euclid(a, b)

    if c % d != 0:
        return (False,)

    (a, b, c) = (a // d, b // d, c // d)

    # au + bv = 1
    # ax + by = a(cu) + b(cv)
    # a(x-cu) = -b(y-cv)
    # gcd(a,-b) = 1, we use the lemma of Gauss : y-cv = ak, y = ak + cv
    # ax + b(ak+cv) = a(cu) + b(cv)
    # ax + bak + b(cv) = a(cu) + b(cv)
    # ax = a(cu) - kab
    # x = -bk + cu

    return (True, ((-b, c*u), (a, c*v)))

##-Multiplicative inverse
def mult_inverse(a: int, n: int) -> int:
    '''
    Return the multiplicative inverse u of a modulo n.
    u*a = 1 modulo n
    '''

    (old_r, r) = (a, n)
    (old_u, u) = (1, 0)

    while r != 0:
        q = old_r // r
        (old_r, r) = (r, old_r - q*r)
        (old_u, u) = (u, old_u - q*u)

    if old_r > 1:
        raise ValueError(str(a) + ' is not inversible in the ring Z/' + str(n) + 'Z.')

    if old_u < 0:
        return old_u + n

    else:
        return old_u


##-iroot
def iroot(n, k):
    '''
    Newton's method to find the integer k-th root of n.

    Return floor(n^(1/k))
    '''

    u, s = n, n + 1

    while u < s:
        s = u
        t = (k - 1) * s + n // pow(s, k - 1)
        u = t // k

    return s


##-Max parity
def max_parity(n):
    '''return (t, r) such that n = 2^t * r, where r is odd'''

    t = 0
    r = int(n)
    while r % 2 == 0 and r > 1:
        r //= 2
        t += 1

    return (t, r)


##-Probabilistic prime test
def isSurelyPrime(n):
    '''Check if n is probably prime. Uses Miller Rabin test.'''

    if n == 2:
        return True

    elif n % 2 == 0:
        return False

    return miller_rabin(n, 15)


def miller_rabin_witness(a, d, s, n):
    '''
    Return True if a is a Miller-Rabin witness.

    - a : the base ;
    - d : odd integer verifying n - 1 = 2^s d ;
    - s : positive integer verifying n - 1 = 2^s d ;
    - n : the odd integer to test primality.
    '''

    r = pow(a, d, n)

    if r == 1 or r == n - 1:
        return False

    for k in range(s):
        r = r**2 % n

        if r == n - 1:
            return False

    return True


def miller_rabin(n, k=15) :
    '''
    Return the primality of n using Miller-Rabin probabilistic primality test.

    - n : odd integer to test the primality ;
    - k : number of tests (Error = 4^(-k)).
    '''

    if n in (0, 1):
        return False

    if n == 2:
        return True

    s, d = max_parity(n - 1)

    for i in range(k) :
        a = randint(2, n - 1)

        if miller_rabin_witness(a, d, s, n):
            return False

    return True

