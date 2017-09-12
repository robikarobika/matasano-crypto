import binascii
import base64
from pwn import *
import itertools as it
import operator as op
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
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
r = remote('localhost', 9999)

def construct_message(from_id, *tuples):
    msg = "from=%s&tx_list=" % from_id

    to_list = ";".join([t[0] + ":" + str(t[1]) for t in tuples])
    msg += to_list
    return msg


normal_msg = construct_message("victim", ("normaluser", 1))
padded = padPKCS7(normal_msg, 16)
print padded

iv = '\x00'*16

normal_mac = CBC_MAC(key, iv, padded)

print "C->S: Sending Message + MAC"
r.sendline(padded)
r.sendline(normal_mac)

# Assume attacker has intercepted the msg above, in which the target is just doing a normal transaction. 

# Attacker can't generate mac for a message not from him
# evil_mac = CBC_MAC(key, iv, padded_evil)
# but he CAN generate a mac for a message from his own account
attacker_valid_msg = construct_message("hello", ("attacker", 10000), ("attacker", 10000))
attacker_padded = padPKCS7(attacker_valid_msg, 16)
attacker_mac = CBC_MAC(key, iv, attacker_padded)

evil_msg = padded + xor(normal_mac, attacker_padded[:16]) + attacker_padded[16:]
print "evil msg", evil_msg

print "C->A->S: Sending Attacker Message + MAC"
r.sendline(evil_msg)
r.sendline(attacker_mac)





