import binascii
import base64
from pwn import *
import itertools as it
from pprint import *
import operator as op
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import os
import random


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
