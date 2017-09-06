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


key = "YELLOW SUBMARINE"

r = remote('localhost', 5000)

msg = "from=1&to=2&amount=1000"
padded = padPKCS7(msg, 16)
print padded

iv = os.urandom(16)

mac = CBC_MAC(key, iv, padded)

print "C->S: Sending Message|IV|MAC"
r.sendline(padded)
r.sendline(iv)
r.sendline(mac)

print "Perform attack by modifying IV"

forged_msg = "from=3&to=2&amount=1000"
forged_padded = padPKCS7(fsetorged_msg, 16)
print forged_padded

# We're xoring the forged message and msg to get the difference between the two, and then applying to the iv
forged_iv = xor(forged_msg[:16], msg[:16], iv)
forged_mac = CBC_MAC(key, forged_iv, forged_padded)

assert forged_mac == mac

print "C->S: Sending Forged Message|IV|MAC"
r.sendline(forged_padded)
r.sendline(forged_iv)
r.sendline(forged_mac)
