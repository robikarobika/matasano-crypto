import binascii
import base64
from pwn import *
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
sys.path.append('..')

from set5_utils import *
from set6_utils import *

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


print "5.39 Implement RSA"

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


print "5.40 E=3 RSA Broadcast attack"

pk1, sk1 = rsa_keygen(256)
pk2, sk2 = rsa_keygen(256)
pk3, sk3 = rsa_keygen(256)

N1 = pk1[1]
N2 = pk2[1]
N3 = pk3[1]

s = "can't touch this"
s = bytes2int(s)

ctext1 = pow(s, pk1[0], N1)
ctext2 = pow(s, pk2[0], N2)
ctext3 = pow(s, pk3[0], N3)

# Use CRT to decrypt ciphertexts

m_s_1 = N2*N3
y1 = ctext1 * m_s_1 * modinv(N1, m_s_1)

m_s_2 = N1*N3
y2 = ctext2 * m_s_2 * modinv(N2, m_s_2)

m_s_3 = N2*N1
y3 = ctext3 * m_s_3 * modinv(N3, m_s_3)

mod_prod = N1*N2*N3

result = (y1 + y2 + y3) % mod_prod
cube_root = gmpy.mpz(result).root(3)[0].digits()
decrypted_text = int2bytes(int(cube_root))

assert decrypted_text == "can't touch this"
