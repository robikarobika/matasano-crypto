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

p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff

g = 2 # generator for group of prime p

attacker_port = 1234
r = remote('localhost', attacker_port)

print "C: Sending initial DH params"
r.sendline(str(p))
r.sendline(str(g))

a = random.randint(0, p)
A = pow(g, a, p)

r.sendline(str(A))

#wait for B from server
B = int(r.recvline(keepends = False))
print "C: received B", B

shared_secret = pow(B, a, p)
key = hashlib.sha1(str(shared_secret)).digest()[:16]

# send encrypted message to server
msg = 'yellow submarine'
iv = os.urandom(16)
ctext = encrypt(key, iv, msg)

print "C: Sending encrypted message "
r.sendline(ctext)
print "C: Sending iv "
r.sendline(iv)
