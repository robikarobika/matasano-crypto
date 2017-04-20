from pwn import *
import binascii
import base64
from pwn import *
import itertools as it
from pprint import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import hmac
import os
import random
import sys
sys.path.append('..')

from set5_utils import *

l = listen(1234)

N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff

g = 2 # generator for group of prime p
k = 3
passwd = 'alotofentropy'

salt = os.urandom(16)

x = int(hashlib.sha256(salt+passwd).hexdigest(), 16)

#generate verifier v
v = pow(g, x, N)

# Begin authentication verification
A = int(l.recvline(keepends = False))
print "S: Received A"

# send salt and B
b = random.randint(0, N)
B = k*v + pow(g, b, N)
print "S: Sending salt and B"
l.sendline(str(salt))
l.sendline(str(B))

# Compute scrambling parameter u
u = int(hashlib.sha256(str(A) + str(B)).hexdigest(), 16)

# compute verifier
S = A * pow(v, u, N)
S = pow(S, b, N)
K = hashlib.sha256(str(S)).digest()

server_hmac = hmac.new(salt, str(K), digestmod = hashlib.sha256).digest()

print 'S: Received client auth attempt hmac'
client_hmac = l.recvline(keepends = False)

if server_hmac == client_hmac:
    print 'Password accepted'
else:
    print "Password failed"
