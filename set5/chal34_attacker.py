from pwn import *
import binascii
import base64
from pwn import *
import itertools as it
from pprint import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib

import os
import random
import sys
sys.path.append('..')

from set5_utils import *
from set1_utils import *
from set2_utils import *

attacker_port = 1234
server_port = 2345

l = listen(1234)
r = remote('localhost', 2345)

p = int(l.recvline(keepends = False))
print "C->M: received p ", p
g = int(l.recvline(keepends = False))
print "C->M: received g ", g
A = int(l.recvline(keepends = False))
print "C->M: received A ", A

# Send on mitm parameters to server
print "M->S: sending params "
r.sendline(str(p))
r.sendline(str(g))
r.sendline(str(p))

#wait for B from server
B = int(r.recvline(keepends = False))
print "S->M: received B", B

#send fake pubkey to client
print "M->C: sending fake pubkey p"
l.sendline(str(p))

# 4.
ctext = l.recvline(keepends = False)
print "C->M: Received encrypted message "
iv = l.recvline(keepends = False)
print "C->M: Received iv "

# Relay enc message to server
print "M->S: Sending encrypted message "
r.sendline(ctext)
print "M->S: Sending iv "
r.sendline(iv)

# 5. Receive echo from server
ctext = r.recvline(keepends = False)
print "S->M: Received echoed encrypted message "
iv = r.recvline(keepends = False)
print "S->M: Received echoed iv "

# Relay echo message to client
# print "M->C: Relaying echoed encrypted message "
# l.sendline(ctext)
# print "M->C: relaying echoed iv "
# l.sendline(iv)

# Check that I can decrypt
# key is 0 because p^x mod p = 0
key = hashlib.sha1(str(0)).digest()[:16]
print "Attacker decrypt message:", decrypt(key, iv, ctext)
