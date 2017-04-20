import binascii
import base64
from pwn import *
import itertools as it
from pprint import *
import operator as op
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import gensafeprime
import hashlib
import os
import random
import sys
sys.path.append('..')

from set5_utils import *


E_RSA = 3

print "5.33 implement Diffie-Hellman"

p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff

g = 2 # generator for group of prime p

# Create secret keys, random values mod p
a = random.randint(0, p)
A = modexp(g, a, p)
b = random.randint(0, p)
B = modexp(g, b, p)

shared_key_a = modexp(A, b, p)
shared_key_b = modexp(B, a, p)
assert shared_key_b == shared_key_a


def egcd(r0, r1):
    '''
    takes the modulus in r0, and the element in r1
    returns tuple of (gcd, coefficient 1, coefficient 2) s.t. s0*r0 + s1*r1 = gcd
    if first value is a modulus, gcd = 1 and t0 is modinv of r1
    '''
    old_r0, old_r1 = r0, r1
    s0, s1 = 1, 0
    t0, t1 = 0, 1

    while r1 != 0:
        remainder = r0%r1
        q = (r0-remainder)/r1

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
        return None
    return b % mod

def rsa_keygen(n):
    # use openssl to generate primes
    p = gensafeprime.generate(512)
    q = gensafeprime.generate(512)

    N = p*q
    phi = (p-1)*(q-1)

    d = modinv(phi, E_RSA)

    sk = (d, N)
    pk = (E_RSA, N)
    return pk, sk

# pk, sk = rsa_keygen(1024)
#
# s = 'hello'
# s = int(binascii.hexlify(s), 16)
#
# ctext = pow(s, pk[0], pk[1])
#
# decrypted_text = pow(ctext, sk[0], sk[1])
#
# decrypted_text = binascii.unhexlify(str(hex(decrypted_text))[2:])
#
# assert decrypted_text == 'hello'

print modinv(67, 3)
