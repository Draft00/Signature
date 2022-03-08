#!/usr/bin/python3

from collections import namedtuple
from random import randint
import os

from elliptic_curve import *

from pygost.gost3410 import CURVE_PARAMS
from pygost.utils import bytes2long


Point = namedtuple("Point", "x y")
EllipticCurve = namedtuple("EllipticCurve", "a b")
Origin = None

p = q  = d = 0
#Q = Origin
point = Origin
curve = Origin

'''
def rand(r):
    while True:
        k = randint(1, r - 1)
        if gcd(k, r) == 1:
            return k


def random_point(n):
    x = randint(1, n - 1)
    y = randint(1, n - 1)
    return Point(x, y)


def is_curve_params_correct(a, b):
    return True if 4 * a ** 3 + 27 * b ** 2 != 0 else False


def random_elliptic_curve(n):
    while True:
        point = random_point(n)
        a = randint(1, n - 1)
        b = (point.y ** 2 - point.x ** 3 - a * point.x) % n
        if is_curve_params_correct(a, b) is True:
            break
    return EllipticCurve(a, b), point
'''

def prv_unmarshal(prv):
    """Unmarshal private key

    :param bytes prv: serialized private key
    :rtype: long
    """
    return bytes2long(prv[::-1])


# Генерация параметров
def GenerateParameter():
    p, q, a, b, x, y = CURVE_PARAMS["GostR3410_2012_TC26_ParamSetB"]
    # GostR3410_2012_TC26_ParamSetA
    # GostR3410_2012_TC26_ParamSetB

    #'''
    A = -1
    B = 53520245325288251180656443226770638951803337703360722011463033447827147086694
    p = 57896044625414088412406986721186632159605151965036429316594800028484330862739
    q = 28948022312707044206203493360593316079803694388568974763893400879284219004579
    x = 36066034950041118412594006918367965339490267219250288222432003968962962331642
    y = 54906983586985298119491343295734802658016371303757622466870297979342757624191

    #d = 976043739961367747800255267779012313694061726372563722051319691490645482588
    #'''
    A = A % p

    A = A.to_bytes(len(hex(A)) - 2, 'big')
    B = B.to_bytes(len(hex(B)) - 2, 'big')
    p = p.to_bytes(len(hex(p)) - 2, 'big')
    q = q.to_bytes(len(hex(q)) - 2, 'big')
    x = x.to_bytes(len(hex(x)) - 2, 'big')
    y = y.to_bytes(len(hex(y)) - 2, 'big')

    curve = EllipticCurve(bytes2long(A), bytes2long(B))
    point = Point(bytes2long(x) , bytes2long(y))

    '''
    curve = EllipticCurve(bytes2long(a), bytes2long(b))
    point = Point(bytes2long(x) , bytes2long(y))
    #'''

    p = bytes2long(p)
    q = bytes2long(q)

    d = prv_unmarshal(os.urandom(64)) # закрытый ключ

    #Q = multiply(point, d, curve.a, p)  # открытый ключ

    print('A =' , (curve.a))
    print('B =' , (curve.b))
    print('p =' , (p))
    print('q =' , (q))

    print('x =' , (point.x))
    print('y =' , (point.y))
    print('')
    print('d =' , (d))

    #print('Q.x = ' , hex(Q.x))
    #print('Q.y = ' , hex(Q.y))

    #return p, q, curve, point , d , Q


if __name__ == '__main__':
    GenerateParameter()


