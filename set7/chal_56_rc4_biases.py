# -*- coding: utf-8 -*-

import binascii
import base64
import itertools as it
from pprint import *
import operator as op
import os
import random
import struct
import sys
import multiprocessing as mp
from Crypto.Cipher import ARC4

secret_cookie = base64.b64decode("QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F").decode("utf-8")

def rc4_oracle(request):
    rand_key = os.urandom(128)

    cipher = ARC4.new(rand_key)
    ptext = request + secret_cookie

    return cipher.encrypt(request + secret_cookie)


# We know that single-byte biases occur towards 0xf0 at Z16
# And a bias towards 0xE0 at Z32
# Pad request with bytes t

for idx in range(1):

    chars = {char: 0 for char in range(256)}
    padding_z16 = "A"*15
    padding_z32 = "A"*31

    pool = mp.Pool(processes = 24) 

    ctexts = pool.map(rc4_oracle, it.repeat(padding_z16, 2**30))
    for ctext in ctexts:
        guess = ctext[16] ^ 0xF0

        chars[guess] += 1 

    ctexts = pool.map(rc4_oracle, it.repeat(padding_z32, 2**20))
    for ctext in ctexts:
        guess = ctext[16] ^ 0xE0

        chars[guess] += 1 


print(chars)
max_char = max(chars.items(), key = op.itemgetter(1))
print(max_char)
print(chr(max_char[0]))



