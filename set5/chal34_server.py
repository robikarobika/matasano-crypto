#!/usr/local/bin/python

from pwn import *
import binascii
import base64
from pwn import *
import itertools as it
from pprint import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import os
import random
import sys
sys.path.append('..')


from set1_utils import *
from set2_utils import *
from set5_utils import *

s = listen(2345)

p = int(s.recvline(keepends = False))
print "S: received p ", p
g = int(s.recvline(keepends = False))
print "S: received g ", g
A = int(s.recvline(keepends = False))
print "S: received A ", A

# 2. generate public key B
b = random.randint(0, p)
B = pow(g, b, p)

s.sendline(str(B))

shared_secret = pow(A, b, p)
key = hashlib.sha1(str(shared_secret)).digest()[:16]

# 3.
ctext = s.recvline(keepends = False)
print "S: Received encrypted message "
iv = s.recvline(keepends = False)
print "S: Received iv "

#decrypt received message
msg = decrypt(key, iv, ctext)
print "S: decrypted message: ", msg

print "S: echoing encrypted message"
response = encrypt(key, iv, msg)
s.sendline(response)

print "S: echoing iv "
s.sendline(iv)
