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

msg = construct_message("Victim", ("Bob", 1))
padded = padPKCS7(msg, 16)
print padded

iv = '\x00'*16

mac = CBC_MAC(key, iv, padded)

print "C->S: Sending Message + MAC"
r.sendline(padded)
r.sendline(mac)

def construct_message(from_id, *tuples):
    msg = "from=%s&tx_list=" % from_id

    to_list = ";".join([t[0]+":"+t[1] for t in tuples])
    msg += to_list
    return msg


