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
import time


secret_cookie = base64.b64decode("QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F").decode("utf-8")

def rc4_oracle(request):
    # rand_key = os.urandom(128)
    rand_key = bytes(bytearray(random.getrandbits(8) for _ in range(128)))
    cipher = ARC4.new(rand_key)
    ptext = request + secret_cookie

    return cipher.encrypt(ptext)

# We know that single-byte biases occur towards 0xf0 at Z16
# And a bias towards 0xE0 at Z32
# Pad request with bytes t

def attack_byte(idx):

        chars = {char: 0 for char in range(256)}

        padding = 'A'*(15 - idx)

        for i in range(2**24):
            if i % (10**6) == 0:
                print("Iteration: ", i)
            ctext = rc4_oracle(padding)
            guess = ctext[15] ^ 0xf0
            chars[guess]+= 1

        print(chars)
        max_char = max(chars.items(), key = op.itemgetter(1))
        print(max_char)
        print(chr(max_char[0]))
        return chr(max_char[0])



start = time.time()
pool = mp.Pool(processes = 16)
found_cookie = pool.map(attack_byte, range(0, 16))
print("time taken:", time.time()-start)

# found_cookie = ""
# for i in range(16):
    # start = time.time()
    # found_cookie += attack_byte(i)
    # end = time.time()
    # print("time taken:", end - start)
# print("".join(found_cookie))

