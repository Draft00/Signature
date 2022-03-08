from collections import namedtuple
from sympy import invert


Point = namedtuple("Point", "x y")
EllipticCurve = namedtuple("EllipticCurve", "a b")
Origin = None


# Elliptic multiplication of point by number
def multiply(point, x, a, p):
    if x == 0:
        return None
    x_bin = [int(k) for k in bin(x)[2:]]
    result = Origin
    for k in x_bin:
        result = add(result, result, a, p)
        if k != 0:
            result = add(result, point, a, p)
    return result


# Elliption addition of points
def add(point_a, point_b, a, p):
    if point_a is Origin:
        return point_b
    elif point_b is Origin:
        return point_a

    s = slope(point_a, point_b, a, p)

    if s is None:
        return None
    else:
        s = int(s)
    x = (s ** 2 - point_a.x - point_b.x) % p
    y = (s * (point_a.x - x) - point_a.y) % p
    return Point(x, y)


# Elliptic slope
def slope(point_a, point_b, a, p):
    global tmp
    if point_a.x != point_b.x:
        tmp = point_b.x - point_a.x
        s = (point_b.y - point_a.y) * invert((point_b.x - point_a.x), p)
    elif point_a.y == point_b.y:
        tmp = 2 * point_a.y
        s = (3 * point_a.x ** 2 + a) * invert((2 * point_a.y), p)
    else:
        return None
    return s % p



