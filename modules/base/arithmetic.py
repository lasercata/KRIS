#!/bin/python3
# -*- coding: utf-8 -*-

"""Program including useful arithmetic functions."""

arithmetic__auth = 'Elerias'
arithmetic__last_update = '03.02.2020'
arithmetic__version = '1.1'


##-functions

def ext_euclid(a: int, b: int) -> (int, (int, int)):
    """
    Extended Euclidean algorithm.
    Return great common divisor (gcd) and Bezout coefficients (u, v) for (a, b).
    u*a + v*b = gcd(a, b)
    Return (gcd, (u, v)).
    """

    (old_u, u) = (1, 0)
    (old_v, v) = (0, 1)

    while b != 0:
        q = a // b
        (a, b) = (b, a - q*b)
        (old_u, u) = (u, old_u - q*u)
        (old_v, v) = (v, old_v - q*v)

    if a<0:
        return -a, (-old_u, -old_v)
    return a, (old_u, old_v)


def bezout(a: int, b: int) -> (int, int):
    """
    Return Bézout coefficients (u, v) for (a, b).
    u*a + v*b = gcd(a, b)
    """

    return ext_euclid(a, b)[1]


def mult_inverse(a: int, n: int) -> int:
    """
    Return multiplicative inverse u of a modulo n.
    u*a = 1 modulo n
    """

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

def solve_bezout_equation(a: int, b: int, c: int):
    """
    Solve the equation ax + by = c.
    If there is no solution, return (False,), else return (True, ((m, n), (p, q))) with (mk + n, pk + q) the form of a solution.
    """

    (d,(u,v)) = ext_euclid(a,b)

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
