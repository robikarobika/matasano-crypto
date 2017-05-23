import binascii
import base64
from pwn import *
import itertools as it
from pprint import *
import operator as op
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import gensafeprime
import gmpy2
import hashlib
import os
import random

import sys
sys.path.append('..')

from set5_utils import *
from set6_utils import *
from set2_utils import *
from set7_utils import *



def padPKCS7semis(x, padto):
	diff = (padto - (len(x)%padto)) % 16

	padded = x + ';'*diff
	return padded


print "Challenge 50 Hashing with CBC-MAC"
js = "alert('MZA who was that?');\n"
js_padded = padPKCS7(js, 16)

iv = '\x00'*16
key = "YELLOW SUBMARINE"

assert binascii.hexlify(CBC_MAC(key, iv, js_padded)) == "296b8d7cb78a243dda4d0a61d33bbdd1"

# Forge this JS snippet, adding a comment so illegal characters after are ignored
forge = "alert('Ayo, the Wu is back!');//"
forge_padded = padPKCS7(forge, 16)

mac = CBC_MAC(key, iv, forge_padded)
concat_forge = forge_padded + xor(mac, js_padded[:16]) + js_padded[16:]
print "concat_forge", repr(concat_forge)

assert binascii.hexlify(CBC_MAC(key, iv, concat_forge)) == "296b8d7cb78a243dda4d0a61d33bbdd1"


print "Challenge 51 Compression Ratio Side-Channel Attacks"
