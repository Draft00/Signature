
# https://cyberleninka.ru/article/v/analiz-i-sravnenie-algoritmov-elektronnoy-tsifrovoy-podpisi-gost-r-34-10-1994-gost-r-34-10-2001-i-gost-r-34-10-2012

# https://m.habr.com/ru/post/335906/
# https://pycryptodome.readthedocs.io/en/latest/src/signature/dsa.html
# https://pycryptodome.readthedocs.io/en/latest/src/public_key/dsa.html
# https://github.com/pdinges/python-schoof

# C:\Users\%username%\AppData\Local\Programs\Python\Python36\Lib\site-packages\pygost
# gost3410.py

'''

python -m pip install pygost

python gen_params.py > constants.py
python gost.py --sign --file test.txt
python gost.py --check --file test.txt --signature test.txt.sign


#python -m pip  install fastecdsa
#python -m pip install sagemath
#pyschoof

'''


import argparse

from random import randint
from pygost import gost34112012256
from constants import *
from elliptic_curve import *
from sympy import gcd

from asn import encode_file_signature, parse_file


curve = EllipticCurve(A, B)
P = Point(x, y)
Q = multiply(P, d, curve.a, p)


def generate_prime(q):

    while True:
        k = randint(1, q - 1)

        if gcd(k, q) == 1:
            return k


def add_sign(filename, data):

    hash = gost34112012256.new(data).digest()
    print('[+] Hash: {0}'.format(gost34112012256.new(data).hexdigest()))

    alpha = int.from_bytes(hash, byteorder='big')
    e = alpha % q
    if e == 0:
        e = 1

    while True:
        k = generate_prime(q) # ? not necessarily a prime number

        C = multiply(P, k, curve.a, p)
        r = C.x % q
        if r == 0:
            continue

        s = (r * d + k * e) % q
        if s == 0:
            continue

        encoded_bytes = encode_file_signature(Q, p, curve, P, q, r, s)

        with open(filename + '.sign', 'wb') as sign:
            sign.write(encoded_bytes)

        return True


def sign(filename):
    with open(filename, 'rb') as file:
        data = file.read()
    print('[+] Success added signature') if add_sign(filename, data) else print('[-] Wrong')


def verify_sign(filename, file_Signature):

    decoded_values = parse_file(file_Signature)

    s = decoded_values[-1]
    r = decoded_values[-2]
    q = decoded_values[-3]
    Q_x = decoded_values[0]
    Q_y = decoded_values[1]
    p = decoded_values[2]
    a = decoded_values[3]
    P_x = decoded_values[5]
    P_y = decoded_values[6]

    if r <= 0 or r >= q or s <= 0 or s >= q:
        print('[-] Invalid signature')

    with open(filename, 'rb') as file:
        data = file.read()

    hash = gost34112012256.new(data).digest()

    alpha = int.from_bytes(hash, byteorder='big')
    e = alpha % q
    if e == 0:
        e = 1

    v = invert(e, q)

    z_1 = (s * v) % q
    z_2 = (-r * v) % q

    tmp_1 = multiply(Point(P_x, P_y), z_1, a, p)
    tmp_2 = multiply(Point(Q_x, Q_y), z_2, a, p)
    C = add(tmp_1, tmp_2, a, p)
    R = C.x % q

    return True if R == r else False


def createParser():

    parser = argparse.ArgumentParser()

    parser.add_argument("-s", "--sign", help="Add signature", action="store_true")
    parser.add_argument("-c", "--check", help="Check signature", action="store_true")
    parser.add_argument("--file", help="File")
    parser.add_argument("--signature", help="File_Signature")

    return parser


def main():

    parser = createParser()

    args = parser.parse_args()

    print('[ ] a = {0}'.format(str(A)))
    print('[ ] b = {0}'.format(str(B)))
    print('[ ] p = {0}'.format(str(p)))
    print('[ ] q = {0}'.format(str(q)))
    print('[ ] x = {0}'.format(str(x)))
    print('[ ] y = {0}'.format(str(y)))
    print()

    if args.sign:
        sign(args.file)

    if args.check:
        if verify_sign(args.file, args.signature):
            print('[+] Sign is correct')
        else:
            print('[-] Sign is incorrect')


if __name__ == '__main__':
    main()
