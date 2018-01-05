import binascii
import base64
import itertools as it
from pprint import *
import operator as op
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import gensafeprime
import math
import gmpy
import hashlib
import os
import random
import sys
from Crypto.Util.number import getPrime, getStrongPrime

E_RSA = 65537

def modexp_slow(base, exp, mod):
    result = 1
    base = base % mod

    while exp > 0:
        if exp%2 == 1:
            result = base*result % mod
            exp = exp/2
        base = base*base % mod
    return result

def modexp(base, exp, mod):
    result = base
    exp_bin = "{0:b}".format(exp)

    for bit in exp_bin[1:]:
        result = result*result % mod
        if bit == '1':
            result = result * base % mod

    return result


def encrypt(key, iv, msg):
    cipher = Cipher(algorithm = algorithms.AES(key), mode = modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    ctext = encryptor.update(msg) + encryptor.finalize()
    return ctext

def decrypt(key, iv, msg):
    cipher = Cipher(algorithm = algorithms.AES(key), mode = modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    plaintext = decryptor.update(msg) + decryptor.finalize()
    return plaintext

#RSA
def egcd(r0, r1):
    '''
    takes the modulus in r0, and the element in r1
    returns tuple of (gcd, coefficient 1, coefficient 2) s.t. s0*r0 + t0*r1 = gcd
    if first value is a modulus, gcd = 1 and t0 is modinv of r1
    '''
    old_r0, old_r1 = r0, r1
    s0, s1 = 1, 0
    t0, t1 = 0, 1

    while r1 != 0:
        remainder = r0%r1
        q = (r0-remainder)//r1

        assert q*r1 + remainder == r0

        r0, r1 = r1, remainder

        new_s = s0 - q*s1
        new_t = t0 - q*t1

        assert new_s*old_r0 + new_t*old_r1 == remainder

        s0, s1 = s1, new_s
        t0, t1 = t1, new_t

    return (r0, s0, t0)


def modinv(mod, a):
    (gcd, a, b) = egcd(mod, a)

    if gcd != 1:
        raise ValueError
    return b % mod

def rsa_keygen(n):
    # use openssl to generate primes
    p = gensafeprime.generate(n//2)
    q = gensafeprime.generate(n//2)
    N = p*q
    phi = (p-1)*(q-1)

    d = modinv(phi, E_RSA)

    sk = (d, N)
    pk = (E_RSA, N)
    return pk, sk
